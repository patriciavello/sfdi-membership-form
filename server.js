require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const cors = require('cors');
const PDFDocument = require('pdfkit'); // <-- NEW
const multer = require('multer'); // <-- NEW
const basicAuth = require('express-basic-auth'); // <-- NEW
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');

//Add OCR helpers
const { createWorker } = require('tesseract.js');


// In-memory store of submissions (resets on server restart)
const submissions = []; // <-- NEW


const app = express();
const PORT = process.env.PORT || 3000;
const SFDI_EMAIL = process.env.SFDI_EMAIL

//Secret passwords saved in memory
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-this-secret',
    resave: false,
    saveUninitialized: false
  })
);


// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false } // needed for Render
    : false
});


// Multer: store uploads in memory
const upload = multer({ storage: multer.memoryStorage() });

// ----- SMTP CONFIGURATION (GMAIL + APP PASSWORD) -----
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// test SMTP
transporter.verify((error, success) => {
  if (error) {
    console.log('SMTP verification error:', error);
  } else {
    console.log('SMTP server is ready to take our messages');
  }
});

async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS submissions (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        member_name TEXT,
        member_email TEXT,
        membership_type TEXT,
        application_type TEXT,
        payment_method TEXT,
        payment_amount NUMERIC(10,2),
        under18 TEXT,
        guardian_email TEXT,
        family_admin_email TEXT,
        cert_agency TEXT,
        cert_level TEXT,
        cert_number TEXT,
        phones TEXT,
        cert_file BYTEA,
        cert_file_name TEXT,
        cert_file_mime TEXT,
        insurance_file BYTEA,
        insurance_file_name TEXT,
        insurance_file_mime TEXT,
        dan_id TEXT,
        dan_expiration_date DATE,

        insurance_verified BOOLEAN DEFAULT FALSE,
        certification_verified BOOLEAN DEFAULT FALSE,
        payment_received BOOLEAN DEFAULT FALSE
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS member_accounts (
        id SERIAL PRIMARY KEY,
        submission_id INT REFERENCES submissions(id) ON DELETE CASCADE,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS member_password_tokens (
        email TEXT PRIMARY KEY,
        code TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    console.log('PostgreSQL: submissions, member_accounts, member_password_tokens tables are ready');


  } catch (err) {
    console.error('Error initializing database:', err);
  }
}


app.use(cors());
app.use(bodyParser.json());

// Protect /admin with basic auth
app.use('/admin',
  basicAuth({
    users: {
      // username: password
      admin: process.env.ADMIN_PASSWORD || 'changeme'
    },
    challenge: true,
    realm: 'SFDI Admin Area'
  })
);

// Protect /treasurer with its own login
app.use('/treasurer',
  basicAuth({
    users: {
      treasurer: process.env.TREASURER_PASSWORD || 'changeme'
    },
    challenge: true,
    realm: 'SFDI Treasurer Area'
  })
);

app.use(express.static(__dirname)); // serves index.html, etc.

// Helper: Pick most recent submission that matches that email
async function findSubmissionByEmail(email) {
  const result = await pool.query(
    `
    SELECT *
    FROM submissions
    WHERE member_email = $1
       OR guardian_email = $1
       OR family_admin_email = $1
    ORDER BY created_at DESC
    LIMIT 1
    `,
    [email]
  );
  return result.rows[0] || null;
}

//Helper - Generate a 6-digit code
function generateVerificationCode() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
}


// Helper: format date yyyy-mm-dd -> mm/dd/yyyy
function formatDate(dateStr) {
  if (!dateStr) return '_____________________';
  const d = new Date(dateStr);
  if (isNaN(d)) return dateStr;
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const yyyy = d.getFullYear();
  return `${mm}/${dd}/${yyyy}`;
}

//Helper: Extract info from Insurance using OCR
// ---- OCR SETUP ----
let ocrWorkerPromise = null;

function getOcrWorker() {
  if (!ocrWorkerPromise) {
    ocrWorkerPromise = createWorker('eng');
  }
  return ocrWorkerPromise;
}

async function runOcrOnBuffer(buffer) {
  const worker = await getOcrWorker();
  const { data: { text } } = await worker.recognize(buffer);
  return text;
}

// Normalize names to compare (upper-case, remove extra spaces/punctuation)
function normalizeName(name) {
  if (!name) return '';
  return name
    .toUpperCase()
    .replace(/[^A-Z\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// Try to parse DAN info from OCR text
function parseDanInfoFromText(text) {
  if (!text) return null;

  // Check if it looks like a DAN card at all
  if (!/DAN|DIVERS ALERT NETWORK/i.test(text)) {
    return null;
  }

  // Very generic guesses – you can tweak based on real cards
  const idMatch = text.match(/(?:DAN\s*ID|Member\s*(?:ID|No\.?|Number)|ID\s*#)\s*[:#]?\s*([A-Z0-9\-]+)/i);
  const expMatch = text.match(/(?:Valid\s*Until|Valid\s*Thru|Expires(?:\s*On)?|Exp\.?\s*Date)\s*[:\s]*([0-9]{1,2}[\/\-][0-9]{1,2}[\/\-][0-9]{2,4})/i);
  const nameMatch = text.match(/(?:Name|Member)\s*[:\-]\s*([A-Z ,.'-]{3,})/i);

  const danId = idMatch ? idMatch[1].trim() : null;
  const expirationRaw = expMatch ? expMatch[1].trim() : null;
  const cardName = nameMatch ? nameMatch[1].trim() : null;

  return {
    danId,
    expirationRaw,
    cardName
  };
}

// Convert "MM/DD/YYYY" or "MM-DD-YYYY" to Date object (for Postgres DATE)
function parseExpirationDate(expirationRaw) {
  if (!expirationRaw) return null;
  const match = expirationRaw.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})$/);
  if (!match) return null;
  let [, mm, dd, yyyy] = match;
  if (yyyy.length === 2) {
    // assume 20xx
    yyyy = '20' + yyyy;
  }
  const iso = `${yyyy}-${mm.padStart(2,'0')}-${dd.padStart(2,'0')}`;
  const d = new Date(iso);
  if (isNaN(d)) return null;
  return iso; // let pg parse ISO date
}

// High-level helper: given buffer + memberName → maybe DAN info to store
async function extractDanInfoFromInsurance(buffer, memberName) {
  try {
    const text = await runOcrOnBuffer(buffer);
    const parsed = parseDanInfoFromText(text);
    if (!parsed) {
      console.log('OCR: Not recognized as DAN card.');
      return null;
    }

    const normalizedCardName = normalizeName(parsed.cardName);
    const normalizedMemberName = normalizeName(memberName);

    if (normalizedCardName && normalizedMemberName && normalizedCardName === normalizedMemberName) {
      const expDate = parseExpirationDate(parsed.expirationRaw);
      return {
        danId: parsed.danId || null,
        danExpirationDate: expDate // ISO string or null
      };
    } else {
      console.log('OCR: Name mismatch, not storing DAN info:', {
        cardName: parsed.cardName,
        memberName
      });
      return null;
    }
  } catch (err) {
    console.error('Error during OCR / DAN parsing:', err);
    return null;
  }
}


// Build the filled-in contract text (replacing the ____ fields)
function buildContractText(data) {
  const memberName = data.memberPrintName || data.name || '___________________________';
  const certSince = formatDate(data.certDate);
  const certAgency = data.certAgency || '___________________________';
  const certNumber = data.certCardNumber || '___________________________';
  const certLevel = data.certLevel || '___________________________';

  return `
  SOUTH FLORIDA DIVERS, INC.
  Yearly Membership Agreement & Complete Liability Release

  Section 1
  Paragraph 1.01
  This is a membership agreement between ${memberName} (member) and the South
  Florida Divers, Inc. - Club. It is my intention by signing this document to be contractually
  bound by its provisions, particularly those related to release of liability.

  Paragraph 1.02
  The following terms will apply to this document. The term member will apply to the applicant as
  stated Section 1. Paragraph 1.01. The term club will apply to South Florida Divers, Inc. The term
  members will apply to all other potential members of South Florida Divers, Inc. The term coordinator
  will refer to any of the club members who conduct or organize an event. The term sponsor refers to
  the act or process of organizing, promoting and conducting activities that have been approved by the
  club. The term E-Board refers to the members that have been elected to the executive board of
  director of the club.

  Section 2
  Paragraph 2.01
  I, the member, state that I have been a certified scuba diver since ${certSince}.
  My certification was granted by the ${certAgency} certifying agency which
  assigned certification number ${certNumber}. My highest level of training
  certification is ${certLevel}.

  Paragraph 2.02
  I, the member, agree that I'm responsible for my own actions and state that at no time will I
  knowingly or willfully endanger myself or other members or guests of the club during any diving or
  non-diving related event that the club may sponsor. I acknowledge that by signing this document I
  exempt and release South Florida Divers, Inc., its members, agents, E-Board, and all vessels (whether
  owned, operated, leased or chartered by any member or members of the club) and hold these
  entities harmless from any and all liabilities which may arise as a consequence of any acts or
  omissions on their part, including, but not limited to negligence, or gross negligence of any released
  party for any dive related activities, including but not limited to getting on and off vessels, ladder
  related injuries, and other activities including those which are incidental to scuba diving, snorkeling
  and boating.

  Paragraph 2.03
  I, the member, through my scuba diving training, have been informed that diving is a dangerous
  activity which may result in property damage, personal injury or even death should I not follow all of
  the proper diving procedures which I have been trained through my certification agency as indicated
  in Section 2, Paragraph 2.01.

  Paragraph 2.04
  I expressly assume all risk of injury and will indemnify and hold harmless the Club, E-Board for any
  claims.

  Paragraph 2.05
  I, the member, specifically and expressly release the club from any liability related to my personal
  injury during any event that the club may sponsor.

  Paragraph 2.06
  I, the member, release the coordinator from any obligation for my personal safety or personal injury
  during any event that the club may sponsor.

  Paragraph 2.07
  I, the member, release the E-Board from any obligation for my personal safety or personal injury
  during any event that the club may sponsor.

  Paragraph 2.08
  I, the member, understand that a current dive insurance policy, on file with the club, is mandatory for
  anyone going on club sponsored dives. The club does not in any way provide or sanction any
  individual diving insurance company.

  Paragraph 2.09
  In consideration for being permitted to participate in the club membership and/or club activities, I
  specifically and expressly relinquish my right to bring any type of legal action against the club, its E-
  board, members, vessels and other participants, for any and all damages to property and personal
  injury including death, whether caused by negligence, gross negligence, or otherwise.

  Section 3
  Paragraph 3.01
  I, the member, understand that my yearly membership is a privilege that can be revoked at any time
  by a majority vote of the E-Board, should my conduct be deemed inappropriate of a member of the
  club.

  Paragraph 3.02
  I, the member, understand that my membership is to be renewed yearly effective January 2nd, and
  becomes delinquent if not paid by the conclusion of the scheduled February general meeting.

  Paragraph 3.03
  I, the member, understand that a $5.00 reinstatement fee will be added to the normal membership
  renewal fee for any membership application received after the conclusion of the February general
  meeting.

  Section 4
  Paragraph 4.01
  I, the member, have read this agreement in its entirety and agree to be bound by same.

  THE LIABILITY ASPECT PORTION OF THIS AGREEMENT IS SPECIFICALLY INTENDED TO BE BINDING AS A
  COMPLETE BAR TO LITIGATION.

  Member Name (printed): ${memberName}
  Member Signature: ${data.memberSignature || '___________________________'}
  Date: ${formatDate(data.signatureDate)}

  Under 18: ${data.under18 || 'No'}
  Parent/Guardian Email: ${data.guardianEmail || '___________________________'}
  Parent/Guardian Name (printed): ${data.guardianPrintName || '___________________________'}
  Parent/Guardian Signature: ${data.guardianSignature || '___________________________'}

  Family Administrator Email (if applicable): ${data.familyAdminEmail || '___________________________'}
  `;
}

// Generate a PDF buffer from that text
function generateContractPdf(data) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });
    const chunks = [];

    doc.on('data', chunk => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // Title
    doc.fontSize(16).text('SOUTH FLORIDA DIVERS, INC.', { align: 'center' });
    doc.moveDown(0.5);
    doc.fontSize(14).text('Yearly Membership Agreement & Complete Liability Release', { align: 'center' });
    doc.moveDown();

    // Basic info header
    doc.fontSize(11).text(`Member: ${data.memberPrintName || data.name || ''}`);
    doc.text(`Email: ${data.email || ''}`);
    doc.text(`Phone(s): ${data.phones || ''}`);
    doc.text(`DOB: ${formatDate(data.dob)}`);
    doc.moveDown();

    // Full contract text
    doc.fontSize(11).text(buildContractText(data), {
      align: 'left'
    });

    doc.end();
  });
}

//Treasure route to update payment
app.post('/treasurer/update-payment', async (req, res) => {
  const { id } = req.body;

  if (!id) {
    return res.status(400).json({ success: false, error: 'Missing id' });
  }

  try {
    const result = await pool.query(
      `UPDATE submissions
       SET payment_received = NOT payment_received
       WHERE id = $1
       RETURNING payment_received`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }

    return res.json({ success: true, value: result.rows[0].payment_received });
  } catch (err) {
    console.error('Error updating payment status:', err);
    return res.status(500).json({ success: false, error: 'Database error' });
  }
});


// Route to handle form submission WITH FILES
app.post('/submit-membership',
    upload.fields([
      { name: 'certFile', maxCount: 1 },
      { name: 'insuranceFile', maxCount: 1 }
    ]),
    async (req, res) => {
      const data = req.body; // text fields
      const files = req.files || {};
      const certFile = files.certFile && files.certFile[0] ? files.certFile[0] : null;
      const insuranceFile = files.insuranceFile && files.insuranceFile[0] ? files.insuranceFile[0] : null;

      let danInfo = null;
      if (insuranceFile && insuranceFile.mimetype && insuranceFile.mimetype.startsWith('image/')) {
        danInfo = await extractDanInfoFromInsurance(
          insuranceFile.buffer,
          data.memberPrintName || data.name || ''
        );
      }
  
  
      if (!data.email) {
        return res.status(400).json({ error: 'Member email is required.' });
      }
  
      try {
        const pdfBuffer = await generateContractPdf(data);
        const filenameSafeName = (data.memberPrintName || data.name || 'Member')
          .replace(/[^a-z0-9]/gi, '_');
  
        const emailText = `
          SFDI Membership form submitted.
          
          Member: ${data.memberPrintName || data.name}
          Email: ${data.email}
          Phone(s): ${data.phones}
          Under 18: ${data.under18 || 'No'}
          Parent/Guardian Email: ${data.guardianEmail || 'N/A'}
          Parent/Guardian Name: ${data.guardianPrintName || 'N/A'}
          Parent/Guardian Signature: ${data.guardianSignature || 'N/A'}
          Family Administrator Email: ${data.familyAdminEmail || 'N/A'}
          
          A PDF copy of the signed membership agreement is attached.
          Uploaded documents:
          - Dive Certification Card: ${files.certFile ? files.certFile[0].originalname : 'none'}
          - Proof of Dive Insurance: ${files.insuranceFile ? files.insuranceFile[0].originalname : 'none'}
          `;
          
  
        // Build attachments array
        const attachmentsForClub = [
          {
            filename: `SFDI-Membership-${filenameSafeName}.pdf`,
            content: pdfBuffer
          }
        ];
  
        if (files.certFile && files.certFile[0]) {
          attachmentsForClub.push({
            filename: files.certFile[0].originalname || 'DiveCertification',
            content: files.certFile[0].buffer
          });
        }
  
        if (files.insuranceFile && files.insuranceFile[0]) {
          attachmentsForClub.push({
            filename: files.insuranceFile[0].originalname || 'DiveInsurance',
            content: files.insuranceFile[0].buffer
          });
        }
  
  // Email to SFDI (with all attachments)
  const mailToClub = {
    from: '"SFDI Membership Form" <sfdipvello@gmail.com>',
    to: SFDI_EMAIL,
    subject: `New Membership Form: ${data.memberPrintName || data.name || 'Unknown Member'}`,
    text: emailText,
    attachments: attachmentsForClub
  };
  
  // Email to member (PDF only)
  const mailToMember = {
    from: '"SFDI Membership Form" <sfdipvello@gmail.com>',
    to: data.email,
    subject: 'Your SFDI Membership Agreement (PDF)',
    text: 'Thank you for your membership. Your completed agreement is attached as a PDF.',
    attachments: [
      {
        filename: `SFDI-Membership-${filenameSafeName}.pdf`,
        content: pdfBuffer
      }
    ]
  };
  
  // Email to parent/guardian (PDF only) if provided
  let mailToGuardian = null;
  if (data.guardianEmail && data.guardianEmail.trim() !== '') {
    mailToGuardian = {
      from: '"SFDI Membership Form" <sfdipvello@gmail.com>',
      to: data.guardianEmail.trim(),
      subject: 'SFDI Membership Agreement for Your Child/Dependent (PDF)',
      text: `You are listed as the parent/guardian for ${data.memberPrintName || data.name}.
  A copy of the SFDI Yearly Membership Agreement & Complete Liability Release is attached as a PDF for your records.`,
      attachments: [
        {
          filename: `SFDI-Membership-${filenameSafeName}.pdf`,
          content: pdfBuffer
        }
      ]
    };
  }
  // OPTIONAL: Email to family administrator (PDF only) if provided
  let mailToFamilyAdmin = null;
  if (data.familyAdminEmail && data.familyAdminEmail.trim() !== '') {
    mailToFamilyAdmin = {
      from: '"SFDI Membership Form" <sfdipvello@gmail.com>',
      to: data.familyAdminEmail.trim(),
      subject: 'SFDI Membership Agreement (Family Membership Administrator Copy)',
      text: `You are listed as the family administrator for the SFDI membership of ${data.memberPrintName || data.name}.
  A copy of the SFDI Yearly Membership Agreement & Complete Liability Release is attached as a PDF for your records.`,
      attachments: [
        {
          filename: `SFDI-Membership-${filenameSafeName}.pdf`,
          content: pdfBuffer
        }
      ]
    };
  }
  
  
  // Send emails
  await transporter.sendMail(mailToClub);
  await transporter.sendMail(mailToMember);
  if (mailToGuardian) {
    await transporter.sendMail(mailToGuardian);
  }
  if (mailToFamilyAdmin) {
    await transporter.sendMail(mailToFamilyAdmin);
  }
  
  // Store submission in PostgreSQL for admin dashboard
  try {
    await pool.query(
      `
        INSERT INTO submissions (
          member_name,
          member_email,
          membership_type,
          application_type,
          payment_method,
          payment_amount,
          under18,
          guardian_email,
          family_admin_email,
          cert_agency,
          cert_level,
          cert_number,
          phones,
          cert_file,
          cert_file_name,
          cert_file_mime,
          insurance_file,
          insurance_file_name,
          insurance_file_mime,
          dan_id,
          dan_expiration_date
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
          $17, $18, $19, $20, $21)
      `,
      [
        data.memberPrintName || data.name || '',
        data.email || '',
        data.membershipType || '',
        data.applicationType || '',
        data.paymentMethod || '',
        data.paymentAmount || 0,
        data.under18 || 'No',
        data.guardianEmail || '',
        data.familyAdminEmail || '',
        data.certAgency || '',
        data.certLevel || '',
        data.certCardNumber || '',
        data.phones || '',
        certFile ? certFile.buffer : null,
        certFile ? certFile.originalname : null,
        certFile ? certFile.mimetype : null,
        insuranceFile ? insuranceFile.buffer : null,
        insuranceFile ? insuranceFile.originalname : null,
        insuranceFile ? insuranceFile.mimetype : null,
        // DAN OCR
        danInfo ? danInfo.danId : null,
        danInfo ? danInfo.danExpirationDate : null
      ]
    );
  } catch (dbErr) {
    console.error('Error saving submission to DB:', dbErr);
    // you *could* choose to still respond 200 here, since emails were sent
  }

  res.json({ message: 'Form submitted successfully. PDF contract and uploaded documents have been emailed.' });
 } catch (err) {
        console.error('Error sending email:', err);
        res.status(500).json({ error: 'There was an error sending the email with the PDF and attachments.' });
      }
    }
  );

//Member portal (check if email exists, hash the password, update row in member accounts)
app.post('/member/set-password', bodyParser.urlencoded({ extended: true }), async (req, res) => {
  const { email, password, code } = req.body;

  if (!email || !password || !code) {
    return res.send(`
      <p>Email, verification code, and password are all required.</p>
      <p><a href="/member/login">Back</a></p>
    `);
  }

  try {
    // 1) Verify email belongs to a submission
    const submission = await findSubmissionByEmail(email);
    if (!submission) {
      return res.send(`
        <p>No membership found for this email. Please use the email used on the membership form.</p>
        <p><a href="/member/login">Back</a></p>
      `);
    }

    // 2) Check code in DB
    const tokenResult = await pool.query(
      `
      SELECT * FROM member_password_tokens
      WHERE email = $1
      `,
      [email]
    );

    if (tokenResult.rows.length === 0) {
      return res.send(`
        <p>No verification code found for this email. Please request a new code.</p>
        <p><a href="/member/login">Back</a></p>
      `);
    }

    const token = tokenResult.rows[0];

    const now = new Date();
    const expiresAt = new Date(token.expires_at);

    if (token.code !== code.trim()) {
      return res.send(`
        <p>Invalid verification code. Please check the code and try again.</p>
        <p><a href="/member/login">Back</a></p>
      `);
    }

    if (now > expiresAt) {
      return res.send(`
        <p>This verification code has expired. Please request a new code.</p>
        <p><a href="/member/login">Back</a></p>
      `);
    }

    // 3) Code is valid → hash password and upsert member_accounts
    const passwordHash = await bcrypt.hash(password, 10);

    await pool.query(
      `
      INSERT INTO member_accounts (submission_id, email, password_hash)
      VALUES ($1, $2, $3)
      ON CONFLICT (email)
      DO UPDATE SET
        submission_id = EXCLUDED.submission_id,
        password_hash = EXCLUDED.password_hash,
        updated_at = NOW()
      `,
      [submission.id, email, passwordHash]
    );

    // 4) Optionally delete the used token
    await pool.query(
      'DELETE FROM member_password_tokens WHERE email = $1',
      [email]
    );

    res.send(`
      <p>Password saved successfully for ${email}.</p>
      <p><a href="/member/login">Click here to login</a></p>
    `);
  } catch (err) {
    console.error('Error setting member password with code:', err);
    res.status(500).send(`
      <p>Error saving password.</p>
      <p><a href="/member/login">Back</a></p>
    `);
  }
});

  
//Member portal (Check credentials stores memberAccountID)
app.post('/member/login', bodyParser.urlencoded({ extended: true }), async (req, res) => {
    const { email, password } = req.body;
  
    if (!email || !password) {
      return res.status(400).send('Missing email or password');
    }
  
    try {
      const result = await pool.query(
        'SELECT * FROM member_accounts WHERE email = $1',
        [email]
      );
  
      if (result.rows.length === 0) {
        return res.send(`
          <p>No account found for this email. Please set a password first.</p>
          <p><a href="/member/login">Back</a></p>
        `);
      }
  
      const account = result.rows[0];
      const ok = await bcrypt.compare(password, account.password_hash);
      if (!ok) {
        return res.send(`
          <p>Invalid password.</p>
          <p><a href="/member/login">Back</a></p>
        `);
      }
      // ✅ Login success: store in session
      req.session.memberAccountId = account.id;
  
      res.redirect('/member/profile');
    } catch (err) {
      console.error('Error logging in member:', err);
      res.status(500).send('Error logging in.');
    }
  });


// Member profile - show only member own data
app.get('/member/profile', async (req, res) => {
        if (!req.session.memberAccountId) {
          return res.redirect('/member/login');
        }

        try {
          const accountResult = await pool.query(
            'SELECT * FROM member_accounts WHERE id = $1',
            [req.session.memberAccountId]
          );
          if (accountResult.rows.length === 0) {
            // Session invalid
            req.session.memberAccountId = null;
            return res.redirect('/member/login');
          }

          const account = accountResult.rows[0];

          const subResult = await pool.query(
            'SELECT * FROM submissions WHERE id = $1',
            [account.submission_id]
          );
          if (subResult.rows.length === 0) {
            return res.send('No membership data found for this account.');
          }

          const sub = subResult.rows[0];

          res.send(`
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8" />
              <title>My Membership</title>
              <meta name="viewport" content="width=device-width, initial-scale=1" />
              <style>
                body {
                  font-family: Arial, sans-serif;
                  background: #f5f5f5;
                  margin: 0;
                  padding: 20px;
                }
                .wrapper {
                  max-width: 600px;
                  margin: 0 auto;
                  background: #fff;
                  padding: 20px;
                  box-shadow: 0 0 6px rgba(0,0,0,0.1);
                  border-radius: 8px;
                }
                h1 {
                  text-align: center;
                }
                label {
                  display: block;
                  margin-top: 10px;
                  font-size: 0.9rem;
                }
                input[type="text"],
                input[type="email"] {
                  width: 100%;
                  padding: 8px;
                  border-radius: 4px;
                  border: 1px solid #ccc;
                  margin-top: 4px;
                }
                .readonly {
                  background: #eee;
                }
                button {
                  margin-top: 15px;
                  padding: 8px 12px;
                  border: none;
                  border-radius: 4px;
                  background: #0066cc;
                  color: #fff;
                  cursor: pointer;
                }
                .top-links {
                  text-align: right;
                  font-size: 0.8rem;
                  margin-bottom: 10px;
                }
              </style>
            </head>
            <body>
              <div class="wrapper">
                <div class="top-links">
                  Logged in as <strong>${account.email}</strong> |
                  <a href="/member/logout">Logout</a>
                </div>
                <h1>My Membership</h1>
                <form method="POST" action="/member/profile">
                  <label>Member Name
                    <input type="text" name="member_name" value="${sub.member_name || ''}" />
                  </label>

                  <label>Member Email
                    <input type="email" name="member_email" value="${sub.member_email || ''}" />
                  </label>

                  <label>Guardian Email
                    <input type="email" name="guardian_email" value="${sub.guardian_email || ''}" />
                  </label>

                  <label>Family Admin Email
                    <input type="email" name="family_admin_email" value="${sub.family_admin_email || ''}" />
                  </label>

                  <label>Phones
                    <input type="text" name="phones" value="${sub.phones || ''}" />
                  </label>

                  <label>Certification Agency
                    <input type="text" name="cert_agency" value="${sub.cert_agency || ''}" />
                  </label>

                  <label>Certification Level
                    <input type="text" name="cert_level" value="${sub.cert_level || ''}" />
                  </label>

                  <label>Certification Number
                    <input type="text" name="cert_number" value="${sub.cert_number || ''}" />
                  </label>

                  <button type="submit">Save Changes</button>
                </form>
                <hr style="margin:20px 0;" />

                <h2>Update Documents</h2>
                <p style="font-size:0.85rem; color:#555;">
                  You can upload a new version of your dive certification card or insurance proof.
                </p>

                <form method="POST" action="/member/documents" enctype="multipart/form-data">
                  <label>New Dive Certification Card (optional)
                    <input type="file" name="certFile" accept="image/*,application/pdf" />
                  </label>

                  <label>New Proof of Dive Insurance (optional)
                    <input type="file" name="insuranceFile" accept="image/*,application/pdf" />
                  </label>

                  <button type="submit">Upload Documents</button>
                </form>

              </div>
            </body>
            </html>
          `);
        } catch (err) {
          console.error('Error loading member profile:', err);
          res.status(500).send('Error loading profile.');
        }
      });

//member profile POST (update their own data)
app.post('/member/profile', bodyParser.urlencoded({ extended: true }), async (req, res) => {
  if (!req.session.memberAccountId) {
    return res.redirect('/member/login');
  }

  try {
    const accountResult = await pool.query(
      'SELECT * FROM member_accounts WHERE id = $1',
      [req.session.memberAccountId]
    );
    if (accountResult.rows.length === 0) {
      req.session.memberAccountId = null;
      return res.redirect('/member/login');
    }

    const account = accountResult.rows[0];

    const {
      member_name,
      member_email,
      guardian_email,
      family_admin_email,
      phones,
      cert_agency,
      cert_level,
      cert_number
    } = req.body;

    await pool.query(
      `
      UPDATE submissions
      SET
        member_name = $1,
        member_email = $2,
        guardian_email = $3,
        family_admin_email = $4,
        phones = $5,
        cert_agency = $6,
        cert_level = $7,
        cert_number = $8
      WHERE id = $9
      `,
      [
        member_name || null,
        member_email || null,
        guardian_email || null,
        family_admin_email || null,
        phones || null,
        cert_agency || null,
        cert_level || null,
        cert_number || null,
        account.submission_id
      ]
    );

    res.redirect('/member/profile');
  } catch (err) {
    console.error('Error updating member profile:', err);
    res.status(500).send('Error saving profile.');
  }
});

//Member Documents 
//Member Documents 
app.post(
  '/member/documents',
  upload.fields([
    { name: 'certFile', maxCount: 1 },
    { name: 'insuranceFile', maxCount: 1 }
  ]),
  async (req, res) => {
    if (!req.session.memberAccountId) {
      return res.redirect('/member/login');
    }

    try {
      // 1) Load member account
      const accountResult = await pool.query(
        'SELECT * FROM member_accounts WHERE id = $1',
        [req.session.memberAccountId]
      );

      if (accountResult.rows.length === 0) {
        req.session.memberAccountId = null;
        return res.redirect('/member/login');
      }

      const account = accountResult.rows[0];

      // 2) Load submission row so we have member_name for OCR
      const subResult = await pool.query(
        'SELECT * FROM submissions WHERE id = $1',
        [account.submission_id]
      );

      if (subResult.rows.length === 0) {
        // No submission record – nothing to update
        return res.redirect('/member/profile');
      }

      const submission = subResult.rows[0];

      // 3) Grab uploaded files
      const files = req.files || {};
      const certFile =
        files.certFile && files.certFile[0] ? files.certFile[0] : null;
      const insuranceFile =
        files.insuranceFile && files.insuranceFile[0] ? files.insuranceFile[0] : null;

      // If no files, just go back
      if (!certFile && !insuranceFile) {
        return res.redirect('/member/profile');
      }

      // 4) Build dynamic UPDATE based on which file(s) are present
      const sets = [];
      const values = [];
      let idx = 1;

      // --- Certification file columns ---
      if (certFile) {
        sets.push(`cert_file = $${idx++}`);
        values.push(certFile.buffer);

        sets.push(`cert_file_name = $${idx++}`);
        values.push(certFile.originalname);

        sets.push(`cert_file_mime = $${idx++}`);
        values.push(certFile.mimetype);
      }

      // --- Insurance file columns + OCR ---
      let danInfo = null;

      if (insuranceFile) {
        // Store the raw insurance file
        sets.push(`insurance_file = $${idx++}`);
        values.push(insuranceFile.buffer);

        sets.push(`insurance_file_name = $${idx++}`);
        values.push(insuranceFile.originalname);

        sets.push(`insurance_file_mime = $${idx++}`);
        values.push(insuranceFile.mimetype);

        // If it's an image, try OCR / DAN extraction
        if (
          insuranceFile.mimetype &&
          insuranceFile.mimetype.startsWith('image/')
        ) {
          danInfo = await extractDanInfoFromInsurance(
            insuranceFile.buffer,
            submission.member_name || submission.member_email || ''
          );
        }
      }

      // 5) If OCR found valid DAN info, update those fields too
      if (danInfo) {
        if (danInfo.danId) {
          sets.push(`dan_id = $${idx++}`);
          values.push(danInfo.danId);
        }

        if (danInfo.danExpirationDate) {
          sets.push(`dan_expiration_date = $${idx++}`);
          values.push(danInfo.danExpirationDate);
        }
      }

      // Safety check
      if (!sets.length) {
        return res.redirect('/member/profile');
      }

      // WHERE id = submission_id
      values.push(account.submission_id);

      const sql = `
        UPDATE submissions
        SET ${sets.join(', ')}
        WHERE id = $${idx}
      `;

      await pool.query(sql, values);

      res.redirect('/member/profile');
    } catch (err) {
      console.error('Error updating member documents:', err);
      res.status(500).send('Error updating documents.');
    }
  }
);



//Member logout
app.get('/member/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/member/login');
  });
});

// Admin allow toggling verification field for insurance and certification
app.post('/admin/update-flag', async (req, res) => {
    const { id, field } = req.body;
  
    // Only allow toggling these two fields from the admin page:
    const allowedFields = ['insurance_verified', 'certification_verified'];
    if (!allowedFields.includes(field)) {
      return res.status(400).json({ success: false, error: 'Invalid field' });
    }
  
    try {
      const result = await pool.query(
        `UPDATE submissions
         SET ${field} = NOT ${field}
         WHERE id = $1
         RETURNING ${field}`,
        [id]
      );
  
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, error: 'Submission not found' });
      }
  
      return res.json({
        success: true,
        value: result.rows[0][field]
      });
    } catch (err) {
      console.error('Error updating flag:', err);
      return res.status(500).json({ success: false, error: 'Database error' });
    }
  });
  
// Treasure DASHBOARD
app.get('/treasurer', async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
          id,
          created_at,
          member_name,
          member_email,
          membership_type,
          payment_method,
          payment_amount,
          payment_received
        FROM submissions
        WHERE payment_amount > 0
        ORDER BY created_at DESC`
      );
  
      const rows = result.rows;
  
      const tableRows = rows
        .map(sub => {
          const date = new Date(sub.created_at).toLocaleString('en-US', {
            timeZone: 'America/New_York'
          });
  
          return `
            <tr>
              <td>${date}</td>
              <td>${sub.member_name || ''}</td>
              <td>${sub.member_email || ''}</td>
              <td>${sub.membership_type || ''}</td>
              <td>${sub.payment_method || ''}</td>
              <td>${sub.payment_amount != null ? sub.payment_amount : ''}</td>
              <td>
                <button
                  class="status-btn ${sub.payment_received ? 'status-yes' : 'status-no'}"
                  onclick="togglePayment(${sub.id})"
                >
                  ${sub.payment_received ? '✅ Received' : '❌ Not Confirmed'}
                </button>
              </td>
            </tr>
          `;
        })
        .join('');
  
      res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <title>SFDI Treasurer Portal</title>
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <style>
            body {
              font-family: Arial, sans-serif;
              margin: 0;
              padding: 20px;
              background: #f5f5f5;
            }
            h1 {
              text-align: center;
            }
            table {
              width: 100%;
              border-collapse: collapse;
              background: #fff;
              box-shadow: 0 0 6px rgba(0,0,0,0.1);
            }
            th, td {
              border: 1px solid #ddd;
              padding: 8px;
              font-size: 0.85rem;
            }
            th {
              background: #0066cc;
              color: #fff;
              position: sticky;
              top: 0;
            }
            tr:nth-child(even) {
              background: #f9f9f9;
            }
            .wrapper {
              max-width: 900px;
              margin: 0 auto;
            }
            .meta {
              margin-bottom: 15px;
              font-size: 0.9rem;
              color: #555;
            }
            .status-btn {
              padding: 4px 8px;
              border-radius: 4px;
              border: none;
              cursor: pointer;
              font-size: 0.9rem;
            }
            .status-yes {
              background-color: #d4edda;
            }
            .status-no {
              background-color: #f8d7da;
            }
          </style>
        </head>
        <body>
          <div class="wrapper">
            <h1>SFDI Treasurer Portal</h1>
            <p class="meta">
              Logged in as <strong>${req.auth.user}</strong>.
              Showing ${rows.length} paid submission(s) (amount > 0).
            </p>
            <table>
              <thead>
                <tr>
                  <th>Submitted At</th>
                  <th>Member Name</th>
                  <th>Member Email</th>
                  <th>Membership Type</th>
                  <th>Payment Method</th>
                  <th>Amount (USD)</th>
                  <th>Payment Received?</th>
                </tr>
              </thead>
              <tbody>
                ${tableRows}
              </tbody>
            </table>
          </div>
  
          <script>
            async function togglePayment(id) {
              try {
                const res = await fetch('/treasurer/update-payment', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json'
                  },
                  body: JSON.stringify({ id })
                });
  
                const data = await res.json();
  
                if (!res.ok || !data.success) {
                  console.error('Update failed:', data);
                  alert('Error updating payment status. Please try again.');
                  return;
                }
  
                // Reload page to show updated status
                location.reload();
              } catch (err) {
                console.error('Network error:', err);
                alert('Network error updating payment status.');
              }
            }
          </script>
        </body>
        </html>
      `);
    } catch (err) {
      console.error('Error loading treasurer portal:', err);
      res.status(500).send('Error loading treasurer portal');
    }
  });
  
//Member dashboard (one for reset password and another to login)
app.get('/member/login', (req, res) => {
  if (req.session.memberAccountId) {
    return res.redirect('/member/profile');
  }

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8" />
      <title>Member Login</title>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <style>
        body {
          font-family: Arial, sans-serif;
          background: #f5f5f5;
          margin: 0;
          padding: 20px;
        }
        .wrapper {
          max-width: 420px;
          margin: 0 auto;
          background: #fff;
          padding: 20px;
          box-shadow: 0 0 6px rgba(0,0,0,0.1);
          border-radius: 8px;
        }
        h1 {
          text-align: center;
        }
        form {
          margin-bottom: 20px;
        }
        label {
          display: block;
          margin-bottom: 6px;
          font-size: 0.9rem;
        }
        input[type="email"],
        input[type="password"],
        input[type="text"] {
          width: 100%;
          padding: 8px;
          margin-bottom: 12px;
          border-radius: 4px;
          border: 1px solid #ccc;
        }
        button {
          padding: 8px 12px;
          border: none;
          border-radius: 4px;
          background: #0066cc;
          color: #fff;
          cursor: pointer;
        }
        .link {
          color: #0066cc;
          cursor: pointer;
          font-size: 0.85rem;
          text-decoration: underline;
        }
        .hidden {
          display: none;
        }
        hr {
          margin: 20px 0;
        }
      </style>
    </head>
    <body>
      <div class="wrapper">
        <h1>Member Portal</h1>

        <!-- Login Form -->
        <form method="POST" action="/member/login">
          <label>Email</label>
          <input type="email" name="email" required />
          <label>Password</label>
          <input type="password" name="password" required />
          <button type="submit">Login</button>
        </form>

        <div style="text-align:center;">
          <span class="link" onclick="toggleReset()">Forgot your password?</span>
        </div>

        <!-- Hidden Reset Area -->
        <div id="resetArea" class="hidden">
          <hr />

          <h3>Reset Your Password</h3>

          <p style="font-size:0.85rem; color:#555;">
            1) First request a verification code:
          </p>

          <form method="POST" action="/member/request-code">
            <label>Email</label>
            <input type="email" name="email" required />
            <button type="submit">Send Verification Code</button>
          </form>

          <p style="font-size:0.85rem; color:#555;">
            2) After receiving the code by email, set your new password:
          </p>

          <form method="POST" action="/member/set-password">
            <label>Email</label>
            <input type="email" name="email" required />

            <label>Verification Code</label>
            <input type="text" name="code" required minlength="6" maxlength="6" />

            <label>New Password</label>
            <input type="password" name="password" required minlength="6" />

            <button type="submit">Save New Password</button>
          </form>
        </div>

      </div>

      <script>
        function toggleReset() {
          const section = document.getElementById('resetArea');
          section.classList.toggle('hidden');
        }
      </script>
    </body>
    </html>
  `);
});


//Member: Request verification code
app.post('/member/request-code', bodyParser.urlencoded({ extended: true }), async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.send(`
      <p>Email is required.</p>
      <p><a href="/member/login">Back</a></p>
    `);
  }

  try {
    const submission = await findSubmissionByEmail(email);
    if (!submission) {
      // For privacy, we don't say "no such email" explicitly.
      return res.send(`
        <p>If an account exists for this email, a verification code has been sent.</p>
        <p><a href="/member/login">Back</a></p>
      `);
    }

    const code = generateVerificationCode();

    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes from now

    // Store or update the code
    await pool.query(
      `
      INSERT INTO member_password_tokens (email, code, expires_at)
      VALUES ($1, $2, $3)
      ON CONFLICT (email)
      DO UPDATE SET
        code = EXCLUDED.code,
        expires_at = EXCLUDED.expires_at,
        created_at = NOW()
      `,
      [email, code, expiresAt]
    );

    // Send email with the code
    await transporter.sendMail({
      from: '"SFDI Membership" <sfdipvello@gmail.com>',
      to: email,
      subject: 'SFDI Member Portal Verification Code',
      text: `Your verification code for the SFDI Member Portal is: ${code}

This code is valid for 15 minutes. If you did not request this, you can ignore this email.`
    });

    res.send(`
      <p>If an account exists for ${email}, a verification code has been sent.</p>
      <p>Please check your email, then go back and use the "Set / Reset Password" form with that code.</p>
      <p><a href="/member/login">Back to Member Portal</a></p>
    `);
  } catch (err) {
    console.error('Error requesting verification code:', err);
    res.status(500).send(`
      <p>Error sending verification code.</p>
      <p><a href="/member/login">Back</a></p>
    `);
  }
});

//Admin: Route to serve the insurance image
app.get('/admin/insurance-image/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      `
      SELECT insurance_file, insurance_file_mime
      FROM submissions
      WHERE id = $1
      `,
      [id]
    );

    if (result.rows.length === 0 || !result.rows[0].insurance_file) {
      return res.status(404).send('No insurance file found for this submission.');
    }

    const row = result.rows[0];

    res.setHeader('Content-Type', row.insurance_file_mime || 'application/octet-stream');
    res.send(row.insurance_file);
  } catch (err) {
    console.error('Error fetching insurance image:', err);
    res.status(500).send('Error retrieving insurance file.');
  }
});


// Admin Dashboard (protected by basic auth)
app.get('/admin', async (req, res) => {
    let rows = [];
    try {
      const result = await pool.query(
        `SELECT
          id,  -- needed so we can update a specific row
          created_at,
          member_name,
          member_email,
          membership_type,
          application_type,
          payment_method,
          payment_amount,
          under18,
          guardian_email,
          family_admin_email,
          cert_agency,
          cert_level,
          phones,
          insurance_verified,
          dan_expiration_date,
          payment_received,
          certification_verified,
          insurance_file_mime
        FROM submissions
        ORDER BY created_at DESC`
      );
      
      rows = result.rows;
    } catch (err) {
      console.error('Error loading submissions from DB:', err);
    }
  
    const tableRows = (rows.length
      ? rows
      : [{ created_at: null }]
    )
    .map(sub => {
        if (!sub.created_at) {
          return `<tr><td colspan="13" style="text-align:center;">No submissions yet.</td></tr>`;
        }
  
      const date = new Date(sub.created_at).toLocaleString('en-US', {
        timeZone: 'America/New_York'
      });
  
        return `
          <tr>
            <td>${date}</td>
            <td>${sub.member_name || ''}</td>
            <td>${sub.member_email || ''}</td>
            <td>${sub.membership_type || ''}</td>
            <td>${sub.application_type || ''}</td>
            <td>${sub.payment_method || ''}</td>
            <td>${sub.payment_amount || ''}</td>
            <td>${sub.under18 || ''}</td>
            <td>${sub.guardian_email || ''}</td>
            <td>${sub.family_admin_email || ''}</td>
            <td>${sub.cert_agency || ''}</td>
            <td>${sub.cert_level || ''}</td>
            <td>${sub.phones || ''}</td>
            <td>${sub.danExpirationDate || 'N/A'}</td>
            <!-- NEW: Insurance card thumbnail -->
            <td>
              ${
                sub.insurance_file_mime && sub.insurance_file_mime.startsWith('image/')
                  ? `<a href="/admin/insurance-image/${sub.id}" target="_blank">
                      <img src="/admin/insurance-image/${sub.id}"
                            alt="Insurance card"
                            style="max-width:150px; max-height:100px; object-fit:contain;" />
                    </a>`
                  : (sub.insurance_file_mime
                      ? `<a href="/admin/insurance-image/${sub.id}" target="_blank">View file</a>`
                      : 'No file')
              }
            </td>
            <!-- Insurance: clickable toggle -->
            <td>
              <button
                class="status-btn ${sub.insurance_verified ? 'status-yes' : 'status-no'}"
                onclick="toggleFlag(${sub.id}, 'insurance_verified')"
              >
                ${sub.insurance_verified ? '✅ Yes' : '❌ No'}
              </button>
            </td>
            <!-- Payment: still READ-ONLY on admin -->
            <td>
              ${
                Number(sub.payment_amount) > 0
                  ? (sub.payment_received ? '✅ Received' : '❌ Not Confirmed')
                  : 'N/A'
              }
            </td>
            <!-- Certification: clickable toggle -->
            <td>
              <button
                class="status-btn ${sub.certification_verified ? 'status-yes' : 'status-no'}"
                onclick="toggleFlag(${sub.id}, 'certification_verified')"
              >
                ${sub.certification_verified ? '✅ Yes' : '❌ No'}
              </button>
            </td>
          </tr>
        `;
  })
      .join('');
  
      res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <title>SFDI Admin Dashboard</title>
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <style>
            body {
              font-family: Arial, sans-serif;
              margin: 0;
              padding: 20px;
              background: #f5f5f5;
            }
            h1 {
              text-align: center;
            }
            table {
              width: 100%;
              border-collapse: collapse;
              background: #fff;
              box-shadow: 0 0 6px rgba(0,0,0,0.1);
            }
            th, td {
              border: 1px solid #ddd;
              padding: 8px;
              font-size: 0.85rem;
            }
            th {
              background: #0066cc;
              color: #fff;
              position: sticky;
              top: 0;
            }
            tr:nth-child(even) {
              background: #f9f9f9;
            }
            .wrapper {
              max-width: 1200px;
              margin: 0 auto;
            }
            .meta {
              margin-bottom: 15px;
              font-size: 0.9rem;
              color: #555;
            }
  
            /* NEW: button styles for status */
            .status-btn {
              padding: 4px 8px;
              border-radius: 4px;
              border: none;
              cursor: pointer;
              font-size: 0.9rem;
            }
            .status-yes {
              background-color: #d4edda;
            }
            .status-no {
              background-color: #f8d7da;
            }
          </style>
        </head>
        <body>
          <div class="wrapper">
            <h1>SFDI Membership Admin Dashboard</h1>
            <p class="meta">
              Logged in as <strong>${req.auth.user}</strong>.
              Showing ${rows.length} submission(s) stored in PostgreSQL.
            </p>
            <table>
              <thead>
                <tr>
                  <th>Submitted At</th>
                  <th>Member Name</th>
                  <th>Member Email</th>
                  <th>Membership Type</th>
                  <th>Application Type</th>
                  <th>Payment Method</th>
                  <th>Amount (USD)</th>
                  <th>Under 18?</th>
                  <th>Guardian Email</th>
                  <th>Family Admin Email</th>
                  <th>Cert Agency</th>
                  <th>Cert Level</th>
                  <th>Phones</th>
                  <th> Inrurance exp</th>
                  <th>Insurance Card</th>
                  <!-- NEW -->
                  <th>Insurance OK?</th>
                  <th>Payment Received?</th>
                  <th>Cert OK?</th>
                </tr>
              </thead>
  
              <tbody>
                ${tableRows}
              </tbody>
            </table>
          </div>
  
          <!-- NEW: script for toggling flags -->
          <script>
            async function toggleFlag(id, field) {
              try {
                const res = await fetch('/admin/update-flag', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json'
                  },
                  body: JSON.stringify({ id, field })
                });
  
                const data = await res.json();
  
                if (!res.ok || !data.success) {
                  console.error('Update failed:', data);
                  alert('Error updating status. Please try again.');
                  return;
                }
  
                // Reload to show updated values
                location.reload();
              } catch (err) {
                console.error('Network error:', err);
                alert('Network error updating status.');
              }
            }
          </script>
        </body>
        </html>
      `);
  }); // <-- closes app.get('/admin',...)
  
  
initDb();

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });