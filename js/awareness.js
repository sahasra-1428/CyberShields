/**
 * CYBERSHIELD - Cybersecurity Awareness & Defense Tips Hub
 */

document.addEventListener('DOMContentLoaded', async () => {
  // Modules DOM elements
  const container = document.getElementById('awareness-modules-container');
  const progressText = document.getElementById('awareness-progress-text');
  const progressBar = document.getElementById('awareness-progress-bar');

  // Tip of the Day DOM elements
  const totdCategory = document.getElementById('totd-category');
  const totdTitle = document.getElementById('totd-title');
  const totdBody = document.getElementById('totd-body');
  const totdAction = document.getElementById('totd-action');
  const totdCounter = document.getElementById('totd-counter');
  const btnNextTotd = document.getElementById('btn-next-totd');
  const btnCopyTotd = document.getElementById('btn-copy-totd');

  // Tips Library DOM elements
  const tipsGrid = document.getElementById('tips-grid-container');
  const tipsSearchInput = document.getElementById('tips-search-input');
  const filterPillButtons = document.querySelectorAll('#tips-filter-pills button');

  // 18 Curated Actionable Defense Tips
  const DEFENSE_TIPS = [
    {
      id: 1,
      category: 'financial',
      categoryLabel: 'Financial & UPI',
      icon: '💳',
      title: 'The Golden Rule of UPI Transfers',
      scammerTrick: 'Caller says: "I sent you extra money by mistake / claiming lottery refund. Please accept on Google Pay and enter your PIN."',
      goldenRule: 'Entering a UPI PIN is strictly for DEBITING (paying) money. You NEVER need to enter your PIN or scan a QR code to receive funds.',
      actionBadge: 'Rule 01: Never type PIN to receive',
      details: 'Legitimate UPI incoming transfers credit directly to your bank account without any interaction, authentication, or QR scanning.'
    },
    {
      id: 2,
      category: 'social',
      categoryLabel: 'AI & Digital Arrest',
      icon: '⚖️',
      title: 'The "Digital Arrest" Myth',
      scammerTrick: 'Caller in fake police uniform on Skype/WhatsApp claims your Aadhaar is linked to money laundering or banned narcotics parcel.',
      goldenRule: 'There is NO legal concept of "Digital Arrest" in Indian Law. Police, CBI, ED, and judges NEVER conduct trials, interrogations, or arrests via video calls.',
      actionBadge: 'Action: Hang up immediately & dial 1930',
      details: 'Real law enforcement officers issue physical summons or arrive in person with valid judicial warrants. Never isolate yourself in a room on video calls.'
    },
    {
      id: 3,
      category: 'phishing',
      categoryLabel: 'URLs & Phishing',
      icon: '🌐',
      title: 'The Dot-Slash (/) Domain Verification Test',
      scammerTrick: 'Links like https://sbi.bank.account-update.xyz/login designed to mimic genuine state bank portals.',
      goldenRule: 'Always inspect the host characters directly preceding the first single forward slash (/). In the example above, the domain is account-update.xyz, NOT sbi.co.in!',
      actionBadge: 'Check: Host preceding the single /',
      details: 'Subdomain stacking is the #1 visual deception tactic used by credential harvesters. CYBERSHIELD URL Scanner decomposes this automatically.'
    },
    {
      id: 4,
      category: 'emergency',
      categoryLabel: 'Emergency Golden Hour',
      icon: '⏱️',
      title: 'The 1930 Golden Hour Protocol',
      scammerTrick: 'Victims often panic, contact banks through Google searches, or delay reporting by hours or days, allowing money to be laundered.',
      goldenRule: 'If money was fraudulently debited, immediately call 1930 within the first 2 hours. This triggers the I4C automated banking conduit freeze.',
      actionBadge: 'Dial 1930 within 120 minutes',
      details: 'The National Cybercrime Reporting Portal directly bridges 250+ banks, payment gateways, and wallet providers to freeze funds before ATM cash-out.'
    },
    {
      id: 5,
      category: 'mobile',
      categoryLabel: 'WhatsApp & Device',
      icon: '📦',
      title: 'The WhatsApp .APK Trojan Delivery',
      scammerTrick: 'Messages claiming: "Download India-Post-Track.apk to verify your stuck courier" or "PM-Yojana-Apply.apk" sent as WhatsApp attachments.',
      goldenRule: 'NEVER install an .apk file sent via WhatsApp, Telegram, or SMS. Real services only distribute through official app stores (Google Play / Apple App Store).',
      actionBadge: 'Block: Sideloaded .apk files',
      details: 'Malicious APKs register as accessibility services, intercepting incoming OTPs silently and sending screen recordings back to adversary command servers.'
    },
    {
      id: 6,
      category: 'financial',
      categoryLabel: 'Financial & UPI',
      icon: '⚠️',
      title: 'Bank KYC "Expiring Today" SMS Trap',
      scammerTrick: 'SMS: "Dear SBI user, your YONO account will be blocked today due to pending KYC. Update PAN at http://bit.ly/sbi-kyc-fix."',
      goldenRule: 'Banks NEVER threaten instant 24-hour blockades via SMS links. Legitimate KYC updates are handled inside the verified official app or at your home branch.',
      actionBadge: 'Zero Trust: Unofficial SMS links',
      details: 'Notice the sender header. Official Indian bank SMS use registered headers like AD-SBIIN, VK-HDFCBK, never standard 10-digit mobile numbers (+91-9xxxx).'
    },
    {
      id: 7,
      category: 'social',
      categoryLabel: 'AI & Digital Arrest',
      icon: '🎙️',
      title: 'AI Voice Cloning & Family Emergency Hoaxes',
      scammerTrick: 'A crying caller sounding exactly like your child/sibling says: "Dad, I had a car accident / police arrested me, please send ₹50,000 bail right now."',
      goldenRule: 'Create a private family "Safe Word / Passphrase". If someone calls in distress demanding money, demand the secret passphrase before taking action.',
      actionBadge: 'Protocol: Verify via saved contact',
      details: 'With only 3–5 seconds of clear audio from social media videos, generative AI voice clones can reproduce emotional cadence with uncanny fidelity.'
    },
    {
      id: 8,
      category: 'mobile',
      categoryLabel: 'WhatsApp & Device',
      icon: '🖥️',
      title: 'Remote Screen-Sharing Trap (AnyDesk/RustDesk)',
      scammerTrick: 'Fake tech support says: "Sir, download AnyDesk or QuickSupport from Play Store so our executive can assist you with your refund."',
      goldenRule: 'Never install remote desktop software on instructions from an incoming caller. Once installed, they view your OTPs and netbanking screens live.',
      actionBadge: 'Rule: Never install remote view apps',
      details: 'Legitimate customer care executives will never ask you to install third-party screen broadcasting tools to troubleshoot bank transactions.'
    },
    {
      id: 9,
      category: 'phishing',
      categoryLabel: 'URLs & Phishing',
      icon: '📬',
      title: 'India Post / Courier Address Correction SMS',
      scammerTrick: 'SMS: "[India Post] Your package could not be delivered due to an incomplete street address. Update details at: https://indiapost-parcels.com/track."',
      goldenRule: 'India Post uses only official government portals ending in .gov.in (e.g. indiapost.gov.in). Any .top, .com, or .xyz URL is a credential harvester.',
      actionBadge: 'Domain Verify: Must end in .gov.in',
      details: 'The fake site asks for a nominal ₹5 "redelivery fee", capturing your 16-digit debit card number, expiry, CVV, and netbanking OTP in the process.'
    },
    {
      id: 10,
      category: 'financial',
      categoryLabel: 'Financial & UPI',
      icon: '⚡',
      title: 'Electricity Bill Disconnection Panic SMS',
      scammerTrick: 'SMS at 7 PM: "Dear consumer, your electricity will be disconnected tonight at 9:30 PM due to previous month unpaid bill. Contact Officer 9876543210."',
      goldenRule: 'Power distribution companies (DISCOMs) never disconnect power late at night via an individual 10-digit mobile number contact.',
      actionBadge: 'Verify: Contact official DISCOM',
      details: 'The scammer instructs the victim to download a remote desktop app or pay ₹10 via an unverified link to verify the meter, stealing account access.'
    },
    {
      id: 11,
      category: 'mobile',
      categoryLabel: 'WhatsApp & Device',
      icon: '📶',
      title: 'SIM Swap & Abrupt Loss of Signal',
      scammerTrick: 'Your phone abruptly displays "No Service" or "Emergency Calls Only" while you are at home or work, followed by password reset emails.',
      goldenRule: 'If your cellular signal vanishes without explanation, use Wi-Fi or another phone to immediately contact your telecom operator to check for unauthorized SIM swaps.',
      actionBadge: 'Urgent: Alert telecom provider',
      details: 'Fraudsters forge identity documents to transfer your mobile number to a new SIM card under their control, redirecting all bank 2FA SMS tokens.'
    },
    {
      id: 12,
      category: 'social',
      categoryLabel: 'AI & Digital Arrest',
      icon: '💼',
      title: 'Part-Time "YouTube Like / Rating" Job Scam',
      scammerTrick: 'WhatsApp message: "Earn ₹3,000–₹8,000 daily from home by liking YouTube videos and rating hotels on Google Maps."',
      goldenRule: 'Any task-based job that requires YOU to deposit money into a "crypto/trading wallet" to release commissions is a multi-stage Ponzi scam.',
      actionBadge: 'Red Flag: Paying money to earn money',
      details: 'They legitimately pay ₹150–₹500 for the first 2 tasks to build trust, then trap the victim in "prepaid merchant tasks" demanding ₹50,000 to ₹10 Lakhs.'
    },
    {
      id: 13,
      category: 'phishing',
      categoryLabel: 'URLs & Phishing',
      icon: '🔍',
      title: 'Fake Customer Care Numbers on Google Maps',
      scammerTrick: 'Searching "IndiGo refund contact number" on Google Search reveals an SEO-poisoned 10-digit mobile number managed by cybercriminals.',
      goldenRule: 'Never trust phone numbers displayed in Google search previews or image results. Retrieve helpline numbers exclusively from inside the official brand app.',
      actionBadge: 'Source: Official in-app support only',
      details: 'Scammers edit open Google Business Profiles and post fake helpline numbers to impersonate Swiggy, Zomato, airlines, and courier agencies.'
    },
    {
      id: 14,
      category: 'financial',
      categoryLabel: 'Financial & UPI',
      icon: '🏧',
      title: 'ATM Skimmer Wiggle & Keypad Shroud',
      scammerTrick: 'Criminals fit a counterfeit card reader over the genuine ATM slot and install a hidden pinhole camera above the numeric keypad.',
      goldenRule: 'Give the card slot a firm wiggle before inserting your card. If it is loose, mismatched in plastic color, or sticky, do NOT use the ATM.',
      actionBadge: 'Habit: Always cover keypad with hand',
      details: 'Always shield the keypad with your wallet or second hand while typing your 4-digit PIN. Without the PIN, a skimmed magnetic stripe cannot be exploited.'
    },
    {
      id: 15,
      category: 'mobile',
      categoryLabel: 'WhatsApp & Device',
      icon: '🔌',
      title: 'Public USB "Juice Jacking" Data Theft',
      scammerTrick: 'Free public charging kiosks at airports and railway stations may have altered USB ports configured to establish data handshakes with mobile devices.',
      goldenRule: 'Charge devices using standard AC electrical wall plugs with your own adapter brick, or use a "USB Data Blocker" (charge-only adapter).',
      actionBadge: 'Defense: Wall plugs or data blockers',
      details: 'Never tap "Trust This Computer" when plugging your phone into a public charging cable. This popup indicates a device is attempting data access.'
    },
    {
      id: 16,
      category: 'phishing',
      categoryLabel: 'URLs & Phishing',
      icon: '🔤',
      title: 'Homoglyph & Punycode Character Spoofing',
      scammerTrick: 'URLs using international characters that look visually identical to standard ASCII: e.g. "xn--pple-43d.com" rendering as "аpple.com".',
      goldenRule: 'Look for browser warnings showing "xn--" prefixes in the address bar. CYBERSHIELD automatically flags non-ASCII punycode characters in link scans.',
      actionBadge: 'Detection: Automated punycode flags',
      details: 'Attackers substitute Cyrillic "а" (U+0430) for Latin "a" (U+0061). To the naked eye they appear identical, but they route to entirely different servers.'
    },
    {
      id: 17,
      category: 'social',
      categoryLabel: 'AI & Digital Arrest',
      icon: '💔',
      title: 'Matrimonial & Romance "Pig Butchering" Scams',
      scammerTrick: 'An attractive profile on Tinder, Bumble, or Shaadi.com builds weeks of emotional rapport, then casually introduces a "high-yield gold/crypto platform".',
      goldenRule: 'Never transfer money, invest in trading platforms, or purchase cryptocurrency based on recommendations from someone you have never met in real life.',
      actionBadge: 'Rule: Separate romance from investments',
      details: 'The fake investment app displays fabricated exponential profits. When the victim attempts withdrawal, the platform demands heavy "tax clearance fees".'
    },
    {
      id: 18,
      category: 'emergency',
      categoryLabel: 'Emergency Golden Hour',
      icon: '🛡️',
      title: 'Immediate Compromise Containment Checklist',
      scammerTrick: 'Victims often panic and lose critical minutes wondering who to call after entering bank details on a fraudulent page.',
      goldenRule: 'Take these 4 actions in order: 1) Block card via your banking app, 2) Change netbanking passwords, 3) Dial 1930, 4) File report on CYBERSHIELD.',
      actionBadge: 'Containment: 4-Step instant lockdown',
      details: 'Generate your official cyber police complaint dossier directly in the CYBERSHIELD Citizen Emergency Playbook to take to your local police station.'
    }
  ];

  // Initialize Tip of the Day
  let currentTotdIndex = Math.floor(Math.random() * DEFENSE_TIPS.length);
  renderTotd(currentTotdIndex);

  if (btnNextTotd) {
    btnNextTotd.addEventListener('click', () => {
      currentTotdIndex = (currentTotdIndex + 1) % DEFENSE_TIPS.length;
      renderTotd(currentTotdIndex);
    });
  }

  if (btnCopyTotd) {
    btnCopyTotd.addEventListener('click', () => {
      const tip = DEFENSE_TIPS[currentTotdIndex];
      const textToCopy = `🛡️ [CYBERSHIELD CYBER DEFENSE TIP]\n\n📌 ${tip.title}\n\n⚠️ Trick: ${tip.scammerTrick}\n\n✅ Golden Rule: ${tip.goldenRule}\n\n🚨 Action: ${tip.actionBadge}\n\nReport scams immediately on National Cyber Helpline: 1930 | https://cybercrime.gov.in`;
      navigator.clipboard.writeText(textToCopy).then(() => {
        showToast('Tip copied to clipboard! Share it with family & friends.', 'success');
      }).catch(() => {
        showToast('Failed to copy tip text.', 'warning');
      });
    });
  }

  function renderTotd(idx) {
    const tip = DEFENSE_TIPS[idx];
    if (!tip) return;
    if (totdCategory) totdCategory.textContent = tip.categoryLabel;
    if (totdTitle) totdTitle.textContent = `${tip.icon} ${tip.title}`;
    if (totdBody) {
      totdBody.innerHTML = `
        <div style="margin-bottom:8px;"><strong style="color:#f87171;">⚠️ The Scam Trick:</strong> ${escapeHtml(tip.scammerTrick)}</div>
        <div><strong style="color:#10b981;">✅ The Golden Defense:</strong> ${escapeHtml(tip.goldenRule)}</div>
      `;
    }
    if (totdAction) totdAction.textContent = tip.actionBadge;
    if (totdCounter) totdCounter.textContent = `Tip ${idx + 1} of ${DEFENSE_TIPS.length}`;
  }

  // Render Tips Library
  let currentFilter = 'all';
  let currentSearchQuery = '';

  renderTipsCatalog();

  // Category filter handlers
  filterPillButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      filterPillButtons.forEach(b => {
        b.classList.remove('active-pill');
        b.style.background = 'transparent';
        b.style.borderColor = 'rgba(255,255,255,0.15)';
        b.style.color = 'var(--text-secondary)';
      });
      btn.classList.add('active-pill');
      btn.style.background = 'var(--cyan-accent)';
      btn.style.borderColor = 'var(--cyan-accent)';
      btn.style.color = '#000';
      currentFilter = btn.dataset.category || 'all';
      renderTipsCatalog();
    });
  });

  // Search input handler
  if (tipsSearchInput) {
    tipsSearchInput.addEventListener('input', (e) => {
      currentSearchQuery = (e.target.value || '').trim().toLowerCase();
      renderTipsCatalog();
    });
  }

  function renderTipsCatalog() {
    if (!tipsGrid) return;

    const filtered = DEFENSE_TIPS.filter(tip => {
      const matchesCategory = currentFilter === 'all' || tip.category === currentFilter;
      const q = currentSearchQuery;
      const matchesSearch = !q ||
        tip.title.toLowerCase().includes(q) ||
        tip.scammerTrick.toLowerCase().includes(q) ||
        tip.goldenRule.toLowerCase().includes(q) ||
        tip.details.toLowerCase().includes(q) ||
        tip.actionBadge.toLowerCase().includes(q);

      return matchesCategory && matchesSearch;
    });

    if (filtered.length === 0) {
      tipsGrid.innerHTML = `
        <div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: var(--text-muted); background: rgba(255,255,255,0.02); border-radius: 8px;">
          No cyber defense tips found matching "${escapeHtml(currentSearchQuery)}". Try searching for 'UPI', 'police', 'SMS', or 'domain'.
        </div>
      `;
      return;
    }

    tipsGrid.innerHTML = filtered.map(tip => `
      <div class="card" style="display:flex; flex-direction:column; justify-content:space-between; border-top: 3px solid var(--cyan-accent); padding: 18px 20px;">
        <div>
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
            <span style="font-size:1.4rem;">${tip.icon}</span>
            <span class="badge-risk low-risk" style="font-size:0.7rem; text-transform:uppercase;">${escapeHtml(tip.categoryLabel)}</span>
          </div>

          <h4 style="font-size:1.05rem; margin-bottom:10px; color:#fff;">${escapeHtml(tip.title)}</h4>

          <!-- Scammer's Bait -->
          <div style="background:rgba(239, 68, 68, 0.08); border-left:3px solid #ef4444; border-radius:4px; padding:8px 12px; margin-bottom:10px; font-size:0.83rem; color:#fca5a5;">
            <strong>⚠️ Scammer Lure:</strong> ${escapeHtml(tip.scammerTrick)}
          </div>

          <!-- Defensive Countermeasure -->
          <div style="background:rgba(16, 185, 129, 0.08); border-left:3px solid #10b981; border-radius:4px; padding:8px 12px; margin-bottom:12px; font-size:0.84rem; color:#a7f3d0;">
            <strong>🛡️ Golden Rule:</strong> ${escapeHtml(tip.goldenRule)}
          </div>

          <p style="color:var(--text-secondary); font-size:0.82rem; line-height:1.5; margin-bottom:12px;">
            ${escapeHtml(tip.details)}
          </p>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid rgba(255,255,255,0.06); padding-top:10px; margin-top:8px;">
          <span style="font-family:var(--font-mono); font-size:0.75rem; color:var(--cyan-accent);">${escapeHtml(tip.actionBadge)}</span>
          <button class="btn btn-outline btn-sm" onclick="copyIndividualTip(${tip.id})" style="font-size:0.72rem; padding:3px 8px;">Copy</button>
        </div>
      </div>
    `).join('');
  }

  window.copyIndividualTip = (id) => {
    const tip = DEFENSE_TIPS.find(t => t.id === id);
    if (!tip) return;
    const textToCopy = `🛡️ [CYBERSHIELD DEFENSE TIP]\n${tip.icon} ${tip.title}\n\n⚠️ Trick: ${tip.scammerTrick}\n✅ Defense: ${tip.goldenRule}\n\nHelpline: Dial 1930 immediately in financial cyber attacks.`;
    navigator.clipboard.writeText(textToCopy).then(() => {
      showToast(`Copied tip: "${tip.title}"`, 'success');
    }).catch(() => {
      showToast('Failed to copy tip text.', 'warning');
    });
  };

  // Load Curriculum Modules
  await loadModules();

  async function loadModules() {
    if (!container) return;
    container.innerHTML = `<div style="text-align:center; padding:40px; color:var(--text-muted);">Loading cybersecurity education modules...</div>`;

    try {
      const res = await AwarenessAPI.getModules();
      if (!res.success) throw new Error(res.error?.message || 'Failed to load modules.');

      const modules = res.modules || [];
      const completedCount = modules.filter(m => m.isCompleted).length;
      const pct = Math.round((completedCount / (modules.length || 1)) * 100);

      if (progressText) progressText.textContent = `${completedCount} of ${modules.length} Lessons Completed (${pct}%)`;
      if (progressBar) progressBar.style.width = pct + '%';

      renderModules(modules);
    } catch (err) {
      showToast(err.message, 'error');
      container.innerHTML = `<div style="text-align:center; padding:40px; color:#ef4444;">${err.message}</div>`;
    }
  }

  function renderModules(modules) {
    if (!container) return;

    container.innerHTML = modules.map(m => {
      const c = m.content || {};
      const statusBadge = m.isCompleted
        ? `<span class="badge-risk low-risk">✓ Completed</span>`
        : `<span class="badge-risk unknown">Pending</span>`;

      return `
        <div class="card" style="margin-bottom: 24px;" id="module-${m.id}">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px;">
            <div>
              <span style="font-size:0.75rem; text-transform:uppercase; color:var(--cyan-accent); font-weight:700; letter-spacing:0.06em;">Module ${m.id}</span>
              <h3 style="font-size:1.35rem; margin-top:4px;">${escapeHtml(m.title)}</h3>
            </div>
            ${statusBadge}
          </div>

          <!-- What is it -->
          <div style="margin-bottom: 16px;">
            <h4 style="font-size:0.85rem; color:var(--cyan-accent); text-transform:uppercase; margin-bottom:6px;">What is it?</h4>
            <p style="color:#e2e8f0; font-size:0.92rem;">${escapeHtml(c.what_is_it || '')}</p>
          </div>

          <!-- How it works -->
          <div style="margin-bottom: 16px;">
            <h4 style="font-size:0.85rem; color:var(--cyan-accent); text-transform:uppercase; margin-bottom:6px;">How It Works</h4>
            <p style="color:var(--text-secondary); font-size:0.92rem;">${escapeHtml(c.how_it_works || '')}</p>
          </div>

          <!-- Real Example Box -->
          <div style="background:rgba(9, 14, 26, 0.7); border:1px solid rgba(255,255,255,0.08); border-radius:var(--radius-md); padding:14px 18px; margin-bottom:18px;">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#f59e0b; font-weight:700; margin-bottom:4px;">Real-World Example</div>
            <div style="font-family:var(--font-mono); font-size:0.88rem; color:#fde68a;">"${escapeHtml(c.example || '')}"</div>
          </div>

          <!-- Warning Signs -->
          <div style="margin-bottom: 18px;">
            <h4 style="font-size:0.85rem; color:#f87171; text-transform:uppercase; margin-bottom:6px;">Critical Warning Signs</h4>
            <ul style="padding-left:20px; color:#e2e8f0; font-size:0.9rem; display:flex; flex-direction:column; gap:4px;">
              ${(c.warning_signs || []).map(w => `<li>${escapeHtml(w)}</li>`).join('')}
            </ul>
          </div>

          <!-- Action Dos & Don'ts Grid -->
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:16px; margin-bottom:20px;">
            <div style="background:rgba(16, 185, 129, 0.06); border:1px solid rgba(16, 185, 129, 0.25); border-radius:var(--radius-md); padding:14px 16px;">
              <h5 style="color:#10b981; margin-bottom:8px; font-size:0.88rem;">✓ What You Should Do</h5>
              <ul style="padding-left:18px; color:#e2e8f0; font-size:0.85rem; display:flex; flex-direction:column; gap:4px;">
                ${(c.what_to_do || []).map(d => `<li>${escapeHtml(d)}</li>`).join('')}
              </ul>
            </div>
            <div style="background:rgba(239, 68, 68, 0.06); border:1px solid rgba(239, 68, 68, 0.25); border-radius:var(--radius-md); padding:14px 16px;">
              <h5 style="color:#ef4444; margin-bottom:8px; font-size:0.88rem;">✕ What You Must Avoid</h5>
              <ul style="padding-left:18px; color:#e2e8f0; font-size:0.85rem; display:flex; flex-direction:column; gap:4px;">
                ${(c.what_not_to_do || []).map(d => `<li>${escapeHtml(d)}</li>`).join('')}
              </ul>
            </div>
          </div>

          <!-- Completion Button -->
          <div style="display:flex; justify-content:flex-end;">
            ${m.isCompleted
              ? `<button class="btn btn-outline btn-sm" disabled style="opacity:0.7;">✓ Lesson Completed</button>`
              : `<button class="btn btn-primary btn-sm" onclick="markCompleted(${m.id})">Mark as Completed</button>`
            }
          </div>
        </div>
      `;
    }).join('');
  }

  window.markCompleted = async (id) => {
    if (!Auth.isAuthenticated()) {
      showToast('Please log in to save your awareness training progress.', 'warning');
      return;
    }
    try {
      const res = await AwarenessAPI.completeModule(id);
      if (res.success) {
        showToast(res.message, 'success');
        loadModules();
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  };
});
