/**
/**
 * CYBERSHIELD - Interactive Cyber Threat Simulator & Phishing Sandbox
 */

document.addEventListener('DOMContentLoaded', () => {
  const tabs = document.querySelectorAll('.sandbox-tab-btn');
  const urlBar = document.getElementById('sandbox-url-bar');
  const canvas = document.getElementById('sandbox-canvas');
  const forensicTitle = document.getElementById('forensic-title');
  const forensicContainer = document.getElementById('forensic-findings-container');
  const btnToggleHints = document.getElementById('btn-toggle-hints');

  let showHints = true;

  const VECTORS = {
    'banking-spoof': {
      title: 'Vector: Deceptive Banking KYC Credential Harvesting',
      urlDisplay: `
        <span style="color:#ef4444; font-size:0.9rem;">⚠️ Not Secure |</span>
        <span style="color:#94a3b8;">https://onlinesbi.sbi.co.in.</span>
        <strong style="color:#f59e0b; background:rgba(245,158,11,0.2); padding:1px 4px; border-radius:3px;">kyc-verify-portal.xyz</strong>
        <span style="color:#c084fc;">/secure-login</span>
      `,
      canvasHtml: `
        <div style="max-width:500px; margin:0 auto; background:#fff; color:#1e293b; border-radius:8px; padding:24px; box-shadow:0 10px 25px rgba(0,0,0,0.4); font-family:sans-serif;">
          <div style="display:flex; align-items:center; justify-content:space-between; border-bottom:2px solid #0056b3; padding-bottom:12px; margin-bottom:18px;">
            <div style="font-weight:900; font-size:1.4rem; color:#0056b3;">State Bank of India</div>
            <span class="red-flag-hotspot" data-flag="1">
              <span class="red-flag-tag">1</span>
              <span style="background:#e0f2fe; color:#0284c7; padding:4px 8px; border-radius:4px; font-size:0.75rem; font-weight:700;">🔒 256-Bit SSL Secured</span>
            </span>
          </div>

          <div class="red-flag-hotspot" data-flag="2" style="display:block; margin-bottom:16px;">
            <span class="red-flag-tag">2</span>
            <div style="background:#fee2e2; border:1px solid #ef4444; border-radius:6px; padding:10px 14px; font-size:0.82rem; color:#991b1b; display:flex; align-items:center; gap:8px;">
              <span>🚨</span>
              <span><strong>MANDATORY PAN RE-KYC:</strong> Your account will be frozen in <strong id="sim-timer">14:59</strong> minutes!</span>
            </div>
          </div>

          <div style="display:grid; gap:12px; font-size:0.85rem;">
            <div>
              <label style="display:block; font-weight:600; margin-bottom:4px; color:#475569;">NetBanking Username</label>
              <input type="text" style="width:100%; padding:8px 12px; border:1px solid #cbd5e1; border-radius:4px;" value="user_sbi_citizen" disabled>
            </div>
            <div>
              <label style="display:block; font-weight:600; margin-bottom:4px; color:#475569;">Login Password</label>
              <input type="password" style="width:100%; padding:8px 12px; border:1px solid #cbd5e1; border-radius:4px;" value="••••••••••••" disabled>
            </div>

            <div class="red-flag-hotspot" data-flag="3" style="display:block;">
              <span class="red-flag-tag">3</span>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; background:#f8fafc; padding:10px; border-radius:6px; border:1px dashed #cbd5e1;">
                <div>
                  <label style="display:block; font-weight:700; color:#ef4444; font-size:0.75rem;">ATM Card PIN</label>
                  <input type="password" style="width:100%; padding:6px 10px; border:1px solid #ef4444; border-radius:4px;" placeholder="4-digit PIN" disabled>
                </div>
                <div>
                  <label style="display:block; font-weight:700; color:#ef4444; font-size:0.75rem;">Card CVV</label>
                  <input type="password" style="width:100%; padding:6px 10px; border:1px solid #ef4444; border-radius:4px;" placeholder="3-digit CVV" disabled>
                </div>
              </div>
            </div>

            <div class="red-flag-hotspot" data-flag="4" style="display:block;">
              <span class="red-flag-tag">4</span>
              <div>
                <label style="display:block; font-weight:700; color:#ef4444; margin-bottom:4px;">Enter Received SMS OTP to Validate Identity</label>
                <input type="text" style="width:100%; padding:8px 12px; border:2px solid #ef4444; border-radius:4px; font-family:monospace;" placeholder="Enter 6-digit OTP" disabled>
              </div>
            </div>

            <button type="button" style="background:#0056b3; color:#fff; border:none; padding:10px; border-radius:4px; font-weight:700; cursor:not-allowed; opacity:0.8;">
              Update KYC &amp; Prevent Suspension
            </button>
          </div>
        </div>
      `,
      findings: [
        {
          num: '1',
          danger: true,
          title: 'Fake Security Badge on Untrusted Host',
          text: 'The attacker placed a decorative "256-Bit SSL Secured" badge to lull victims into a false sense of security. SSL encrypts transit, but DOES NOT verify whether the receiver is a criminal.'
        },
        {
          num: '2',
          danger: true,
          title: 'Artificial Panic & False Countdown Timer',
          text: 'Utility companies and banks NEVER impose a 15-minute countdown clock to freeze an account. Fear triggers emotional panic, preventing rational inspection of the URL.'
        },
        {
          num: '3',
          danger: true,
          title: 'Subdomain Stacking in URL Bar',
          text: 'Notice the URL: "onlinesbi.sbi.co.in.kyc-verify-portal.xyz". The real registered domain is "kyc-verify-portal.xyz", not State Bank of India.'
        },
        {
          num: '4',
          danger: true,
          title: 'Harvesting Debit Card PIN + CVV on Login Screen',
          text: 'A legitimate bank login NEVER asks for your physical ATM PIN or card CVV on a web login form. This is direct credential theft.'
        }
      ]
    },

    'electricity-apk': {
      title: 'Vector: Electricity Bill Disconnection & Malicious APK Trojan',
      urlDisplay: `
        <span style="color:#ef4444;">⚠️ Raw IP Download |</span>
        <span style="color:#f59e0b; background:rgba(245,158,11,0.2); padding:1px 4px; border-radius:3px;">http://192.168.1.180</span>
        <span style="color:#c084fc;">/bses-power-update.apk</span>
      `,
      canvasHtml: `
        <div style="max-width:440px; margin:0 auto; background:#0f172a; border:2px solid #334155; border-radius:24px; padding:20px; box-shadow:0 12px 30px rgba(0,0,0,0.8); font-family:sans-serif;">
          <div style="text-align:center; font-size:0.75rem; color:#94a3b8; margin-bottom:12px;">SIM 1: SMS Inbox (VK-POWER)</div>
          
          <div class="red-flag-hotspot" data-flag="1" style="display:block; margin-bottom:16px;">
            <span class="red-flag-tag">1</span>
            <div style="background:#1e293b; border-left:3px solid #f59e0b; padding:12px 14px; border-radius:6px; font-size:0.85rem; line-height:1.5; color:#f1f5f9;">
              "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM from the power station because your previous month bill was not updated. Please immediately contact our power officer at <span style="color:#38bdf8; font-weight:700;">+91 9812345678</span>."
            </div>
          </div>

          <div class="red-flag-hotspot" data-flag="2" style="display:block; margin-bottom:16px;">
            <span class="red-flag-tag">2</span>
            <div style="background:rgba(239,68,68,0.1); border:1px solid #ef4444; border-radius:8px; padding:14px; text-align:center;">
              <div style="font-size:2rem; margin-bottom:6px;">📦</div>
              <div style="font-weight:700; color:#fff; font-size:0.95rem;">BSES_SmartMeter_Update.apk</div>
              <div style="font-size:0.75rem; color:#f87171; margin-top:2px;">Unknown Source | Android Application Package</div>
              <button type="button" style="margin-top:12px; background:#ef4444; color:#fff; border:none; padding:8px 18px; border-radius:4px; font-weight:700; font-size:0.82rem; cursor:not-allowed;">
                Install Update APK (Direct)
              </button>
            </div>
          </div>

          <div class="red-flag-hotspot" data-flag="3" style="display:block;">
            <span class="red-flag-tag">3</span>
            <div style="background:#1e293b; padding:10px 14px; border-radius:6px; font-size:0.8rem; color:#cbd5e1; display:flex; align-items:center; gap:8px;">
              <span>⚠️</span>
              <span>Officer instruction: "Allow Accessibility &amp; SMS Reading permissions when prompted."</span>
            </div>
          </div>
        </div>
      `,
      findings: [
        {
          num: '1',
          danger: true,
          title: 'Personal 10-Digit Mobile Number in Threat SMS',
          text: 'Official power distribution companies (BSES, Tata Power, BESCOM) issue statutory paper notices and communicate via registered 6-character sender IDs (e.g. AD-BSESDL), NEVER personal 10-digit mobile numbers.'
        },
        {
          num: '2',
          danger: true,
          title: 'Sideloaded `.apk` File Instead of Play Store',
          text: 'Utility companies never distribute mobile apps via direct `.apk` links hosted on raw IP addresses. These APKs contain Banking Trojans (e.g. SpyNote, BrasDex) that silently forward OTPs to hackers.'
        },
        {
          num: '3',
          danger: true,
          title: 'Request for Accessibility & SMS Permissions',
          text: 'Banking Trojans exploit Android\'s Accessibility Service to view your screen, intercept 2FA codes, and silently approve bank transfers in the background.'
        }
      ]
    },

    'crypto-job': {
      title: 'Vector: Telegram "Like YouTube Videos" Prepaid Task Scam',
      urlDisplay: `
        <span style="color:#10b981;">💬 Telegram Messenger |</span>
        <span style="color:#cbd5e1;">@Global_HR_Task_Director</span>
        <span style="color:#f59e0b; background:rgba(245,158,11,0.2); padding:1px 4px; border-radius:3px;">+62 812-3918-2041</span>
      `,
      canvasHtml: `
        <div style="max-width:480px; margin:0 auto; background:#17212b; border-radius:12px; padding:18px; color:#fff; font-family:sans-serif; box-shadow:0 10px 25px rgba(0,0,0,0.5);">
          <div style="display:flex; align-items:center; gap:12px; border-bottom:1px solid rgba(255,255,255,0.08); padding-bottom:12px; margin-bottom:16px;">
            <div style="width:40px; height:40px; border-radius:50%; background:#0284c7; display:flex; align-items:center; justify-content:center; font-weight:800;">HR</div>
            <div>
              <div style="font-weight:700; font-size:0.95rem;">Recruitment Director Jessica (Sephora Media)</div>
              <div style="font-size:0.75rem; color:#38bdf8;">Online | Recruiter</div>
            </div>
          </div>

          <div class="red-flag-hotspot" data-flag="1" style="display:block; margin-bottom:14px;">
            <span class="red-flag-tag">1</span>
            <div style="background:#242f3d; padding:10px 14px; border-radius:8px 8px 8px 0; font-size:0.85rem; line-height:1.5;">
              "Hello! Our corporate marketing team was impressed by your profile. You can earn ₹3,000 to ₹8,000 daily from home just by clicking 'Like' on YouTube travel videos. No interview required!"
            </div>
          </div>

          <div class="red-flag-hotspot" data-flag="2" style="display:block; margin-bottom:14px;">
            <span class="red-flag-tag">2</span>
            <div style="background:#242f3d; padding:10px 14px; border-radius:8px 8px 8px 0; font-size:0.85rem; line-height:1.5;">
              "Congratulations! You completed Task 1 and 2. We have credited ₹150 trial reward to your Google Pay to prove this is 100% legitimate!"
            </div>
          </div>

          <div class="red-flag-hotspot" data-flag="3" style="display:block;">
            <span class="red-flag-tag">3</span>
            <div style="background:#7f1d1d; border:1px solid #ef4444; padding:12px 14px; border-radius:8px 8px 8px 0; font-size:0.85rem; line-height:1.5;">
              "🔥 <strong>VIP PREPAID TASK 3:</strong> Deposit ₹5,000 into crypto merchant wallet to unlock high-yield commission of ₹8,500. If you do not deposit within 20 mins, previous earnings are forfeited!"
            </div>
          </div>
        </div>
      `,
      findings: [
        {
          num: '1',
          danger: true,
          title: 'Unsolicited Contact from Foreign Country Code (+62 Indonesia)',
          text: 'Legitimate HR recruiters never approach job candidates on Telegram using Indonesian or international burner SIMs without prior job application or interview.'
        },
        {
          num: '2',
          danger: true,
          title: 'The "Bait Payment" Psychological Hook (₹150)',
          text: 'Scammers deliberately send small initial payouts (₹150 to ₹500) to build false confidence and overcome your skepticism.'
        },
        {
          num: '3',
          danger: true,
          title: 'Prepaid Task / Sunk Cost Coercion',
          text: 'The true scam: You are coerced into transferring thousands of rupees to unlock "earned commissions". Once deposited, the scammers demand even larger sums or block you.'
        }
      ]
    },

    'digital-arrest': {
      title: 'Vector: "Digital Arrest" Extortion & Fake CBI Warrant Notice',
      urlDisplay: `
        <span style="color:#ef4444;">📹 Skype Video Call Extortion |</span>
        <span style="color:#f59e0b; background:rgba(245,158,11,0.2); padding:1px 4px; border-radius:3px;">Caller: CBI_Cyber_Cell_Office_09</span>
        <span style="color:#38bdf8;">Encrypted Protocol</span>
      `,
      canvasHtml: `
        <div style="max-width:520px; margin:0 auto; background:#fff; color:#0f172a; border-radius:4px; padding:28px; box-shadow:0 12px 35px rgba(0,0,0,0.6); font-family:serif;">
          <div style="text-align:center; border-bottom:2px solid #000; padding-bottom:12px; margin-bottom:18px;">
            <div style="font-size:1.15rem; font-weight:900; letter-spacing:0.05em;">CENTRAL BUREAU OF INVESTIGATION / CUSTOMS HEADQUARTERS</div>
            <div style="font-size:0.8rem; font-weight:700;">NEW DELHI - FINANCIAL CRIMES BRANCH</div>
          </div>

          <div class="red-flag-hotspot" data-flag="1" style="display:block; margin-bottom:14px;">
            <span class="red-flag-tag">1</span>
            <div style="background:#fee2e2; border:1px solid #ef4444; padding:8px 12px; font-size:0.85rem; font-weight:800; color:#b91c1c; text-align:center;">
              NOTICE OF IMMEDIATE "DIGITAL ARREST" &amp; NON-BAILABLE WARRANT
            </div>
          </div>

          <div style="font-size:0.85rem; line-height:1.6; margin-bottom:16px;">
            This is to inform that Parcel tracking #FEDEX-IN-90823 destined for Taiwan containing 16 Passports, 580g MDMA Narcotics, and illicit bank cards has been intercepted under your Aadhaar number.
          </div>

          <div class="red-flag-hotspot" data-flag="2" style="display:block; margin-bottom:14px;">
            <span class="red-flag-tag">2</span>
            <div style="background:#f1f5f9; padding:10px 14px; border:1px solid #cbd5e1; font-size:0.82rem; font-weight:600; color:#334155;">
              "You are under continuous Digital Arrest. You are strictly forbidden from disconnecting this Skype video call, informing relatives, or leaving your room."
            </div>
          </div>

          <div class="red-flag-hotspot" data-flag="3" style="display:block;">
            <span class="red-flag-tag">3</span>
            <div style="background:#fef3c7; border:1px solid #f59e0b; padding:10px 14px; font-size:0.82rem; color:#92400e;">
              <strong>MANDATORY FUND VERIFICATION:</strong> Transfer 90% of your bank savings into the Supreme Court Verification Account (VPA: rbi-safety-escrow@sbi) for financial clearance. Funds will be refunded in 30 minutes after investigation.
            </div>
          </div>
        </div>
      `,
      findings: [
        {
          num: '1',
          danger: true,
          title: '"Digital Arrest" Does Not Exist in Law',
          text: 'There is zero provision for "Digital Arrest" under the Bharatiya Nagarik Suraksha Sanhita (BNSS), Indian Penal Code, or CrPC. Police and courts NEVER try or arrest citizens over video calls.'
        },
        {
          num: '2',
          danger: true,
          title: 'Isolation & Psychological Terror Tactics',
          text: 'Threatening you not to leave the room or talk to family members is designed to cut you off from objective reality and sound advice.'
        },
        {
          num: '3',
          danger: true,
          title: 'Demand to Transfer Money to "RBI / Court Verification Account"',
          text: 'The dead giveaway: The Supreme Court, CBI, Police, and Reserve Bank of India NEVER demand citizens to transfer funds into "clearance accounts" to prove their innocence.'
        }
      ]
    }
  };

  function renderVector(key) {
    const data = VECTORS[key] || VECTORS['banking-spoof'];
    urlBar.innerHTML = data.urlDisplay;
    canvas.innerHTML = data.canvasHtml;
    forensicTitle.textContent = data.title;

    forensicContainer.innerHTML = data.findings.map(f => `
      <div class="finding-card ${f.danger ? 'danger' : ''}">
        <div style="font-weight:700; color:${f.danger ? '#f87171' : '#38bdf8'}; font-size:0.95rem; margin-bottom:4px; display:flex; align-items:center; gap:8px;">
          <span style="background:${f.danger ? '#ef4444' : 'var(--cyan)'}; color:#fff; font-size:0.75rem; width:20px; height:20px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center;">${f.num}</span>
          ${escapeHtml(f.title)}
        </div>
        <div style="font-size:0.85rem; color:#cbd5e1; line-height:1.5;">${escapeHtml(f.text)}</div>
      </div>
    `).join('');

    // Wire up hotspot clicks
    document.querySelectorAll('.red-flag-hotspot').forEach(el => {
      el.addEventListener('click', () => {
        const flagNum = el.dataset.flag;
        const finding = data.findings.find(f => f.num === flagNum);
        if (finding) {
          showToast(`🚩 Red Flag #${flagNum}: ${finding.title}`, 'error');
        }
      });
    });
  }

  // Tab switching
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      renderVector(tab.dataset.vector);
    });
  });

  // Toggle hints
  if (btnToggleHints) {
    btnToggleHints.addEventListener('click', () => {
      showHints = !showHints;
      document.querySelectorAll('.red-flag-tag').forEach(tag => {
        tag.style.display = showHints ? 'flex' : 'none';
      });
      document.querySelectorAll('.red-flag-hotspot').forEach(spot => {
        spot.style.outline = showHints ? '2px dashed #f59e0b' : 'none';
      });
      btnToggleHints.textContent = showHints ? 'Hide Red Flag Tags' : 'Reveal All Red Flags';
      showToast(showHints ? 'Revealed all deceptive hotspots.' : 'Hotspots hidden. Test your eyes!', 'info');
    });
  }

  // Initial load
  renderVector('banking-spoof');
});
