/**
 * CYBERSHIELD - Citizen Cyber Emergency Playbook & Complaint Generator
 */

document.addEventListener('DOMContentLoaded', () => {
  const stepsContainer = document.getElementById('playbook-steps-container');
  const protocolCards = document.querySelectorAll('.protocol-card');
  const bankGrid = document.getElementById('bank-directory-grid');
  const searchBankInput = document.getElementById('search-bank-input');

  const complaintForm = document.getElementById('complaint-generator-form');
  const outputSection = document.getElementById('complaint-output-section');
  const previewBox = document.getElementById('complaint-preview-text');
  const btnCopy = document.getElementById('btn-copy-complaint');
  const btnPrint = document.getElementById('btn-print-complaint');

  // Set default datetime to now
  const compDate = document.getElementById('comp-date');
  if (compDate) {
    const now = new Date();
    now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
    compDate.value = now.toISOString().slice(0, 16);
  }

  // 1. Playbook Protocols Content
  const PROTOCOLS = {
    'upi-loss': {
      title: '💸 Protocol: Unauthorized UPI / Bank Fund Transfer (Golden Hour)',
      steps: [
        {
          num: 1,
          title: 'Dial 1930 Immediately (Golden Hour Window)',
          desc: 'Call 1930 to reach the Citizen Financial Cyber Fraud Reporting System (I4C). Provide your bank name, debit account, transaction UTR, and recipient account/UPI. Police officers will trigger an API lien freeze on the recipient bank account before the money is withdrawn at an ATM.'
        },
        {
          num: 2,
          title: 'Call Your Bank\'s Cyber Cell to Block Mobile Banking',
          desc: 'Contact your bank fraud desk (see directory below). Ask them to place a temporary freeze on your UPI VPAs and netbanking passwords to prevent secondary automated debits.'
        },
        {
          num: 3,
          title: 'Retrieve the 12-Digit Transaction Reference (UTR)',
          desc: 'Open Google Pay, PhonePe, Paytm, or your banking app. Go to transaction history, open the specific payment, and copy the 12-digit UPI Transaction ID / UTR number. This is mandatory for legal recovery.'
        },
        {
          num: 4,
          title: 'File an Official Complaint on cybercrime.gov.in',
          desc: 'Visit cybercrime.gov.in and lodge a complaint under "Financial Fraud". Attach bank statement screenshots and the chat transcript. Keep the acknowledgement number safe.'
        },
        {
          num: 5,
          title: 'Submit the Formal Dispute Letter to Your Bank Branch',
          desc: 'Under RBI rules, reporting unauthorized transactions within 3 days qualifies you for limited/zero liability. Use our Automated Generator below to print and submit this formal notice to your home branch.'
        }
      ]
    },
    'apk-malware': {
      title: '📱 Protocol: Malicious APK / AnyDesk / Screen Sharing App Installed',
      steps: [
        {
          num: 1,
          title: 'Turn On Airplane Mode & Disconnect Wi-Fi Immediately',
          desc: 'Cut off cellular data, SMS, and Wi-Fi instantly. Trojan APKs stream your OTPs and credentials to the attacker\'s Command & Control server over the internet. Severing connectivity halts data exfiltration.'
        },
        {
          num: 2,
          title: 'Revoke Device Administrator & Accessibility Permissions',
          desc: 'Go to Settings → Accessibility and Settings → Security → Device Admin Apps. Look for unfamiliar apps (e.g. "QuickSupport", "AnyDesk", "Electricity Support", "PM Yojna") and turn off permissions.'
        },
        {
          num: 3,
          title: 'Boot into Safe Mode & Uninstall the Rogue Package',
          desc: 'Hold down the Power button, tap and hold "Restart" or "Power Off" until prompted to Reboot in Safe Mode. Safe Mode disables 3rd-party malware so you can navigate to Settings → Apps and uninstall the malicious app.'
        },
        {
          num: 4,
          title: 'From Another Clean Device: Change All Banking & Email Passwords',
          desc: 'Do NOT use the infected phone. From a secure family phone or computer, immediately change your primary email password, netbanking passwords, and log out of all active sessions.'
        },
        {
          num: 5,
          title: 'Factory Data Reset (Nuclear Option)',
          desc: 'If persistent banking trojans (e.g. BrasDex, SpyNote) retain elevated root or SMS permissions, backup your photos and contacts, and perform a full Factory Data Reset.'
        }
      ]
    },
    'otp-compromise': {
      title: '🔑 Protocol: Disclosed OTP, CVV, or Netbanking Credentials',
      steps: [
        {
          num: 1,
          title: 'Instantly Block Your Debit/Credit Card',
          desc: 'Send your bank\'s emergency SMS code (e.g. SMS "BLOCK <last 4 digits>" to your bank\'s shortcode) or use another mobile device to toggle card international and e-commerce usage OFF in the banking app.'
        },
        {
          num: 2,
          title: 'Reset Login and Transaction Passwords',
          desc: 'Log in to official netbanking from a secure browser and change both your login password and transaction/profile passwords. This invalidates active attacker sessions.'
        },
        {
          num: 3,
          title: 'Disable NetBanking & Mobile Banking Access Temporarily',
          desc: 'Call bank customer care and request them to temporarily disable online netbanking channel access until you visit the branch with KYC identification.'
        },
        {
          num: 4,
          title: 'Check for Unauthorized Beneficiary Additions',
          desc: 'Inspect your account\'s "Manage Beneficiaries" section. Attackers who obtain netbanking access often register new third-party accounts for NEFT/IMPS transfers.'
        }
      ]
    },
    'digital-arrest': {
      title: '👮 Protocol: "Digital Arrest" & Video Call Impersonation Extortion',
      steps: [
        {
          num: 1,
          title: 'DISCONNECT THE VIDEO CALL IMMEDIATELY',
          desc: 'Under Indian law (CrPC / Bharatiya Nagarik Suraksha Sanhita), courts and police agencies NEVER conduct arrests, interrogations, or trials via Skype, WhatsApp, or Zoom. "Digital Arrest" is 100% fictional fraud.'
        },
        {
          num: 2,
          title: 'DO NOT TRANSFER ANY "SECURITY DEPOSIT" OR "RBI CLEARANCE FUNDS"',
          desc: 'Scammers will fabricate "Supreme Court clearance orders" or "RBI verification accounts". Legitimate government agencies NEVER demand money transfers to clear criminal accusations.'
        },
        {
          num: 3,
          title: 'Preserve Caller Evidence & Screenshots',
          desc: 'Take screenshots of the Skype/WhatsApp call, the fake warrant PDFs, and caller profile numbers. Do not delete chat logs.'
        },
        {
          num: 4,
          title: 'Report to Dial 1930 and Local Cyber Cell',
          desc: 'Report the video call credentials and caller phone numbers to 1930 and cybercrime.gov.in. The Ministry of Home Affairs (MHA I4C) actively tracks and disables these extortion syndicates.'
        },
        {
          num: 5,
          title: 'Inform Family Members',
          desc: 'Extortionists rely on isolating you in a room through psychological terror. Talk to family or trusted friends immediately — breaking secrecy neutralizes their intimidation.'
        }
      ]
    }
  };

  // Render protocol steps
  function renderProtocol(key) {
    const data = PROTOCOLS[key] || PROTOCOLS['upi-loss'];
    stepsContainer.innerHTML = `
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:24px; border-bottom:1px solid rgba(255,255,255,0.08); padding-bottom:14px; flex-wrap:wrap; gap:10px;">
        <h3 style="font-size:1.25rem; font-weight:700; color:#fff;">${data.title}</h3>
        <span class="badge-risk malicious" style="font-size:0.75rem;">CRITICAL RESPONSE STEPS</span>
      </div>
      <div>
        ${data.steps.map(s => `
          <div class="step-item">
            <div class="step-number">${s.num}</div>
            <div class="step-content">
              <h4>${escapeHtml(s.title)}</h4>
              <p>${escapeHtml(s.desc)}</p>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  }

  // Protocol click handlers
  protocolCards.forEach(card => {
    card.addEventListener('click', () => {
      protocolCards.forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      renderProtocol(card.dataset.protocol);
    });
  });

  // Initial render
  renderProtocol('upi-loss');

  // 2. Direct Bank & Wallet Emergency Directory Data
  const BANK_DIRECTORY = [
    { name: 'State Bank of India (SBI)', phone: '1800 1234 / 1800 2100', sms: 'SMS "BLOCK <last4>" to 567676', portal: 'sbi.co.in' },
    { name: 'HDFC Bank', phone: '1800 202 6161 / 1800 1600', sms: 'Call phone banking to block netbanking', portal: 'hdfcbank.com' },
    { name: 'ICICI Bank', phone: '1800 1080 / 1800 200 3344', sms: 'SMS "BLOCK <last4>" to 9215676766', portal: 'icicibank.com' },
    { name: 'Axis Bank', phone: '1800 419 5959 / 1800 103 5577', sms: 'SMS "BLOCK <last4>" to 56161600', portal: 'axisbank.com' },
    { name: 'Punjab National Bank (PNB)', phone: '1800 180 2222 / 1800 103 2222', sms: 'SMS "HOT <CardNo>" to 5607040', portal: 'pnbindia.in' },
    { name: 'Bank of Baroda', phone: '1800 5700 / 1800 258 4455', sms: 'SMS "BLOCK <last4>" to 8422009988', portal: 'bankofbaroda.in' },
    { name: 'Kotak Mahindra Bank', phone: '1860 266 2666', sms: 'Use Mobile Banking app "Safety Lock"', portal: 'kotak.com' },
    { name: 'Canara Bank', phone: '1800 425 0018', sms: 'SMS "CAN <CardNo>" to 9266623333', portal: 'canarabank.com' },
    { name: 'Google Pay (Tez)', phone: '1800 419 0157', sms: 'Report via app: Profile → Help & Feedback', portal: 'pay.google.com' },
    { name: 'PhonePe', phone: '080-68727374 / 022-68727374', sms: 'support.phonepe.com', portal: 'phonepe.com' },
    { name: 'Paytm Payments Bank', phone: '0120-4456-456', sms: '24x7 Cyber Fraud Desk in Paytm App', portal: 'paytmbank.com' },
    { name: 'National Cyber Helpline', phone: '1930', sms: 'Citizen Financial Cyber Fraud Desk', portal: 'cybercrime.gov.in' }
  ];

  function renderBanks(filter = '') {
    const q = filter.toLowerCase().trim();
    const filtered = BANK_DIRECTORY.filter(b => b.name.toLowerCase().includes(q) || b.phone.includes(q));

    if (filtered.length === 0) {
      bankGrid.innerHTML = `<div style="grid-column: 1/-1; text-align:center; padding:20px; color:var(--text-muted);">No institution found matching "${escapeHtml(filter)}".</div>`;
      return;
    }

    bankGrid.innerHTML = filtered.map(b => `
      <div class="bank-card">
        <div class="bank-name">
          <span>🏦</span> ${escapeHtml(b.name)}
        </div>
        <a href="tel:${b.phone.split('/')[0].trim().replace(/\s+/g, '')}" class="bank-tollfree">
          📞 ${escapeHtml(b.phone)}
        </a>
        <div style="font-size:0.75rem; color:var(--text-muted); line-height:1.4;">
          ${escapeHtml(b.sms)}
        </div>
      </div>
    `).join('');
  }

  if (searchBankInput) {
    searchBankInput.addEventListener('input', (e) => renderBanks(e.target.value));
  }
  renderBanks();

  // 3. Automated Formal Cyber Complaint Generator
  if (complaintForm) {
    complaintForm.addEventListener('submit', (e) => {
      e.preventDefault();

      const name = document.getElementById('comp-name').value.trim();
      const phone = document.getElementById('comp-phone').value.trim();
      const bank = document.getElementById('comp-bank').value.trim();
      const acc = document.getElementById('comp-acc').value.trim();
      const amount = parseFloat(document.getElementById('comp-amount').value) || 0;
      const utr = document.getElementById('comp-utr').value.trim();
      const suspect = document.getElementById('comp-suspect').value.trim();
      const dateVal = document.getElementById('comp-date').value;
      const summary = document.getElementById('comp-summary').value.trim();

      const formattedDate = new Date(dateVal).toLocaleString();
      const today = new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });

      const letterText = `
DATE: ${today}

TO:
1. The Branch Manager / Nodal Cyber Crime Grievance Officer,
   ${bank}.
2. The Station House Officer (Cyber Crime Police Station) / 
   Citizen Financial Cyber Fraud Reporting System (National Portal: cybercrime.gov.in).

SUBJECT: 
FORMAL DISPUTE NOTICE AND REQUEST FOR IMMEDIATE ACCOUNT FREEZING / REVERSAL OF UNAUTHORIZED FRAUDULENT ELECTRONIC TRANSACTION AMOUNTING TO ₹${amount.toLocaleString()} UNDER RBI CIRCULAR DBR.No.Leg.BC.78/09.07.005/2017-18 AND SECTION 66D OF THE INFORMATION TECHNOLOGY ACT, 2000.

Respected Sir / Madam,

I, ${name}, holding registered mobile number ${phone} and maintaining an operational account / card (${acc}) with your esteemed institution (${bank}), hereby lodge an urgent formal complaint regarding an unauthorized and fraudulent transaction orchestrated through cyber criminal deception.

1. INCIDENT & TRANSACTION PARTICULARS:
--------------------------------------------------------------------------------
- Complainant Name       : ${name}
- Complainant Mobile     : ${phone}
- Victim Account/Card    : ${acc} with ${bank}
- Disputed Amount        : INR ₹${amount.toLocaleString()}
- Transaction UTR / Ref  : ${utr}
- Suspect Entity / VPA   : ${suspect}
- Date & Time of Debit   : ${formattedDate}
--------------------------------------------------------------------------------

2. MODUS OPERANDI:
${summary}

The cyber fraudster utilized psychological coercion and social engineering to impersonate an official representative, fraudulently inducing an unintended electronic debit from my account.

3. STATUTORY GROUNDS & RELIEF PRAYED:
A. REVERSAL UNDER RBI GUIDELINES: Pursuant to Reserve Bank of India Circular DBR.No.Leg.BC.78/09.07.005/2017-18 on "Customer Protection – Limiting Liability of Customers in Unauthorised Electronic Banking Transactions", this incident has been promptly reported within the statutory 3-day reporting window. I hereby request complete shadow credit / provisional reimbursement.

B. IMMEDIATE INTER-BANK FREEZING: You are urgently requested to transmit an immediate lien-freeze instruction through the National Payments Corporation of India (NPCI) and the 1930 CFCFRMS portal to the recipient beneficiary bank handling VPA/Account (${suspect}) to freeze the dissipated funds before withdrawal.

C. CRIMINAL OFFENSE: This fraudulent act constitutes a cognizable offense punishable under Section 66C (Identity Theft) and Section 66D (Cheating by Personation using Computer Resource) of the Information Technology Act, 2000, and Section 318(4) of the Bharatiya Nyaya Sanhita, 2023.

I enclose herewith the debit SMS alert, account statement excerpt, and chat transcripts for your urgent investigation and FIR registration.

Yours faithfully,


_________________________
(${name})
Contact: ${phone}
`.trim();

      previewBox.textContent = letterText;
      outputSection.style.display = 'block';
      outputSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      showToast('Formal legal complaint drafted successfully!', 'success');
    });
  }

  // Copy Complaint text
  if (btnCopy) {
    btnCopy.addEventListener('click', () => {
      if (!previewBox) return;
      navigator.clipboard.writeText(previewBox.textContent).then(() => {
        showToast('Complaint letter copied to clipboard!', 'success');
      }).catch(() => {
        showToast('Failed to copy. Please select and copy manually.', 'error');
      });
    });
  }

  // Print Complaint Letter
  if (btnPrint) {
    btnPrint.addEventListener('click', () => {
      const printWindow = window.open('', '_blank');
      printWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Formal Cyber Crime Incident Complaint Letter</title>
          <style>
            body { font-family: 'Times New Roman', serif; line-height: 1.6; margin: 40px; color: #000; }
            pre { font-family: inherit; font-size: 13pt; white-space: pre-wrap; word-break: break-word; }
            @media print { body { margin: 20mm; } }
          </style>
        </head>
        <body>
          <pre>${escapeHtml(previewBox.textContent)}</pre>
          <script>
            window.onload = function() { window.print(); window.close(); };
          </script>
        </body>
        </html>
      `);
      printWindow.document.close();
    });
  }
});
