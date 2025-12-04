require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const cors = require('cors');
const PDFDocument = require('pdfkit'); // <-- NEW
const multer = require('multer'); // <-- NEW
const basicAuth = require('express-basic-auth'); // <-- NEW
const { Pool } = require('pg');


// In-memory store of submissions (resets on server restart)
const submissions = []; // <-- NEW


const app = express();
const PORT = process.env.PORT || 3000;
const SFDI_EMAIL = process.env.SFDI_EMAIL

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
        phones TEXT,
        -- NEW ADMIN FIELDS
        insurance_verified BOOLEAN DEFAULT FALSE,
        payment_received BOOLEAN DEFAULT FALSE,
        certification_verified BOOLEAN DEFAULT FALSE
      )
    `);
    console.log('PostgreSQL: submissions table is ready');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
}


app.use(cors());
app.use(bodyParser.json());

// Protect /admin with basic auth
app.use(
  '/admin',
  basicAuth({
    users: {
      // username: password
      admin: process.env.ADMIN_PASSWORD || 'changeme'
    },
    challenge: true,
    realm: 'SFDI Admin Area'
  })
);

app.use(express.static(__dirname)); // serves index.html, etc.

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

// 2) Generate a PDF buffer from that text
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

// Route to handle form submission WITH FILES
app.post(
    '/submit-membership',
    upload.fields([
      { name: 'certFile', maxCount: 1 },
      { name: 'insuranceFile', maxCount: 1 }
    ]),
    async (req, res) => {
      const data = req.body; // text fields
      const files = req.files || {};
  
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
          phones
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
        data.phones || ''
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
          payment_received,
          certification_verified
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
  
  
  
  initDb();

  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });