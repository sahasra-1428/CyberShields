-- CyberShield Database Schema
-- Cyber Scam Protection & Detection Platform

CREATE DATABASE IF NOT EXISTS `cybercrime_db` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `cybercrime_db`;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL,
  `email` VARCHAR(150) NOT NULL UNIQUE,
  `phone` VARCHAR(25) DEFAULT NULL,
  `password_hash` VARCHAR(255) NOT NULL,
  `password` VARCHAR(255) DEFAULT NULL,
  `role` ENUM('user', 'admin') NOT NULL DEFAULT 'user',
  `status` ENUM('active', 'inactive', 'suspended') NOT NULL DEFAULT 'active',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `last_login` DATETIME DEFAULT NULL,
  INDEX `idx_users_email` (`email`),
  INDEX `idx_users_role` (`role`),
  INDEX `idx_users_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Scans Table
CREATE TABLE IF NOT EXISTS `scans` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT DEFAULT NULL,
  `scan_type` ENUM('url', 'message', 'email', 'phone', 'qr') NOT NULL,
  `input_value` TEXT NOT NULL,
  `normalized_value` TEXT DEFAULT NULL,
  `risk_level` ENUM('LOW RISK', 'SUSPICIOUS', 'HIGH RISK', 'MALICIOUS', 'INVALID', 'UNKNOWN / UNABLE TO VERIFY') NOT NULL,
  `risk_score` INT NOT NULL DEFAULT 0,
  `confidence` INT NOT NULL DEFAULT 85,
  `verified` BOOLEAN NOT NULL DEFAULT FALSE,
  `indicators` JSON NOT NULL,
  `recommendations` JSON NOT NULL,
  `source` VARCHAR(100) DEFAULT 'local_security_engine',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_scans_user_id` (`user_id`),
  INDEX `idx_scans_type` (`scan_type`),
  INDEX `idx_scans_risk` (`risk_level`),
  INDEX `idx_scans_created` (`created_at`),
  CONSTRAINT `fk_scans_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Reports Table
CREATE TABLE IF NOT EXISTS `reports` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT DEFAULT NULL,
  `category` ENUM('url', 'phone', 'email', 'message', 'social_media', 'other') NOT NULL,
  `target` VARCHAR(500) NOT NULL,
  `description` TEXT NOT NULL,
  `evidence` TEXT DEFAULT NULL,
  `status` ENUM('Submitted', 'Under Review', 'Verified', 'Resolved', 'Rejected') NOT NULL DEFAULT 'Submitted',
  `agent_unit` VARCHAR(150) DEFAULT 'National Cyber Crime Bureau (I4C / 1930)',
  `urgency` VARCHAR(30) DEFAULT 'HIGH',
  `docket_no` VARCHAR(60) DEFAULT NULL,
  `assigned_agent` VARCHAR(150) DEFAULT NULL,
  `loss_amount` DECIMAL(12,2) DEFAULT 0.00,
  `suspect_phone` VARCHAR(50) DEFAULT NULL,
  `suspect_upi` VARCHAR(120) DEFAULT NULL,
  `action_requested` VARCHAR(150) DEFAULT 'Domain / SIM Takedown & Forensics',
  `admin_notes` TEXT DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_reports_user_id` (`user_id`),
  INDEX `idx_reports_category` (`category`),
  INDEX `idx_reports_status` (`status`),
  INDEX `idx_reports_docket` (`docket_no`),
  INDEX `idx_reports_created` (`created_at`),
  CONSTRAINT `fk_reports_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Awareness Modules Table
CREATE TABLE IF NOT EXISTS `awareness_modules` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `title` VARCHAR(200) NOT NULL,
  `category` VARCHAR(100) NOT NULL,
  `content` JSON NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_awareness_category` (`category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. User Progress Table
CREATE TABLE IF NOT EXISTS `user_progress` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `module_id` INT NOT NULL,
  `completed` BOOLEAN NOT NULL DEFAULT TRUE,
  `score` INT DEFAULT 100,
  `completed_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `unique_user_module` (`user_id`, `module_id`),
  INDEX `idx_progress_user` (`user_id`),
  INDEX `idx_progress_module` (`module_id`),
  CONSTRAINT `fk_progress_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_progress_module` FOREIGN KEY (`module_id`) REFERENCES `awareness_modules` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Security Events Table
CREATE TABLE IF NOT EXISTS `security_events` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT DEFAULT NULL,
  `event_type` VARCHAR(100) NOT NULL,
  `description` TEXT NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_events_user` (`user_id`),
  INDEX `idx_events_type` (`event_type`),
  INDEX `idx_events_created` (`created_at`),
  CONSTRAINT `fk_events_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Audit Logs Table
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `admin_id` INT DEFAULT NULL,
  `action` VARCHAR(100) NOT NULL,
  `target_type` VARCHAR(50) NOT NULL,
  `target_id` INT DEFAULT NULL,
  `details` TEXT DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_audit_admin` (`admin_id`),
  INDEX `idx_audit_action` (`action`),
  INDEX `idx_audit_created` (`created_at`),
  CONSTRAINT `fk_audit_admin` FOREIGN KEY (`admin_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Default Admin Account (password: Admin@123)
INSERT INTO `users` (`name`, `email`, `phone`, `password_hash`, `password`, `role`, `status`)
SELECT 'Security Administrator', 'admin@cybershield.org', '+91 9876543210', '$2b$10$xZS1qUD0FNLOIa0PlauJH.rsjXCFuxQzfkM6JLtCN1eIcxrPJBdw6', '$2b$10$xZS1qUD0FNLOIa0PlauJH.rsjXCFuxQzfkM6JLtCN1eIcxrPJBdw6', 'admin', 'active'
WHERE NOT EXISTS (SELECT 1 FROM `users` WHERE `email` = 'admin@cybershield.org');

-- Seed Awareness Modules if empty
INSERT INTO `awareness_modules` (`id`, `title`, `category`, `content`) VALUES
(1, 'Phishing Attacks', 'phishing', JSON_OBJECT(
  'what_is_it', 'Phishing is a fraudulent practice where cybercriminals impersonate legitimate organizations through spoofed websites and emails to trick victims into revealing sensitive personal data, passwords, or credit card numbers.',
  'how_it_works', 'Attackers create near-identical copies of legitimate login portals (banks, social media, payment gateways), register look-alike domains (e.g., paypa1.com or netfl1x-verify.cc), and send urgent alerts demanding immediate account verification.',
  'warning_signs', JSON_ARRAY('Generic greetings instead of your name', 'Urgent threats of account suspension', 'Mismatched sender domain and display name', 'Deceptive links with typosquatting or excessive subdomains'),
  'example', 'Subject: URGENT: Your PayPal account has been locked. Verify identity within 24 hours at http://paypal-security-auth-check.xyz',
  'what_to_do', JSON_ARRAY('Inspect sender email address and link URLs carefully', 'Navigate directly to the official website by typing the verified URL in your browser', 'Enable Multi-Factor Authentication (MFA) everywhere', 'Report the phishing email to authorities and the impersonated service'),
  'what_not_to_do', JSON_ARRAY('Never click links inside unverified alerts', 'Never download unexpected email attachments', 'Never enter passwords or OTPs on pages opened via suspicious links')
)),
(2, 'OTP & Verification Scams', 'otp_scams', JSON_OBJECT(
  'what_is_it', 'OTP (One-Time Password) fraud involves tricking users into disclosing dynamic single-use authentication codes sent to their phone or authenticator app.',
  'how_it_works', 'Scammers pose as bank representatives, courier agents, or tech support claiming they are processing a refund, reversing an accidental charge, or canceling an unauthorized transaction, asking you to recite or enter the OTP received.',
  'warning_signs', JSON_ARRAY('Caller explicitly requesting your SMS verification code', 'Caller knows some of your basic personal info (name, last 4 digits)', 'High pressure and refusal to let you hang up', 'SMS message clearly stating: DO NOT SHARE THIS OTP WITH ANYONE'),
  'example', 'Hello Sir, I am calling from SBI Fraud Prevention. Someone tried to make a ₹25,000 transaction on your debit card. To block it, please tell me the 6-digit cancellation OTP sent to your phone.',
  'what_to_do', JSON_ARRAY('Remember that no legitimate bank or company representative will EVER ask for your OTP', 'Read the SMS text carefully to see what transaction the OTP actually authorizes', 'Hang up immediately and contact the official customer support line'),
  'what_not_to_do', JSON_ARRAY('Never share OTPs, PINs, or CVVs with anyone over phone, SMS, WhatsApp, or email', 'Do not forward SMS messages received from banking shortcodes')
)),
(3, 'UPI & Payment Gateway Fraud', 'upi_scams', JSON_OBJECT(
  'what_is_it', 'UPI scams exploit misunderstandings of how Unified Payments Interface (UPI) works, specifically the difference between receiving and sending money.',
  'how_it_works', 'Scammers posing as buyers on marketplaces (e.g., OLX) or lottery winners send a "Collect Request" or a QR code claiming: "Scan this QR code or enter your UPI PIN to receive ₹15,000 into your account". Entering your PIN actually debits your account.',
  'warning_signs', JSON_ARRAY('Any instruction requiring you to enter your UPI PIN to RECEIVE payment', 'Buyer willing to pay without bargaining or inspecting items', 'Sending a QR code to transfer money to you', 'Payment collect requests from unfamiliar VPA handles'),
  'example', 'I am purchasing your used sofa. I have sent an approval QR code for ₹8,500 on WhatsApp. Scan it in Google Pay and enter your UPI PIN to accept the cash.',
  'what_to_do', JSON_ARRAY('Always remember: ENTERING UPI PIN ALWAYS SENDS MONEY, NEVER RECEIVES MONEY', 'Verify payment arrival directly in your banking or UPI app balance', 'Decline and report suspicious payment collect requests'),
  'what_not_to_do', JSON_ARRAY('Never enter your UPI PIN or biometric to receive funds', 'Do not scan random QR codes sent by unknown buyers or contest organizers')
)),
(4, 'Banking & Credit Card Scams', 'banking_scams', JSON_OBJECT(
  'what_is_it', 'Scams targeting online banking portals, credit/debit card credentials, CVVs, and net-banking passwords.',
  'how_it_works', 'Fraudsters send spoofed alerts about pending KYC updates, expiring rewards points, or unauthorized debit charges, prompting victims to enter full 16-digit card numbers, expiry dates, and CVVs on fake forms.',
  'warning_signs', JSON_ARRAY('SMS stating "Your bank account / SIM will be blocked today if KYC is not updated immediately"', 'Links redirecting to non-bank domains (e.g., sbi-kyc-portal.online)', 'Requests for net-banking profile passwords or card CVVs'),
  'example', 'Dear customer, your HDFC netbanking access will expire today. Update PAN immediately to avoid suspension: http://hdfc-kyc-verify-portal.in',
  'what_to_do', JSON_ARRAY('Update KYC only through branch visits or verified official mobile apps', 'Verify SSL certificates and lock icons on banking domains', 'Call the official toll-free number printed on the back of your debit card'),
  'what_not_to_do', JSON_ARRAY('Never click KYC update links in SMS messages', 'Never share your 3-digit CVV or netbanking transaction passwords')
)),
(5, 'Fake Job & Work From Home Scams', 'job_scams', JSON_OBJECT(
  'what_is_it', 'Fraudulent schemes offering high-paying remote employment, YouTube video liking tasks, or data entry jobs designed to steal registration fees or crypto.',
  'how_it_works', 'Victims are contacted on Telegram/WhatsApp with offers of ₹3,000-₹10,000/day for liking videos or hotel reviews. Small initial payouts build trust, then victims are coerced into paying large "refundable deposits" or "crypto prepaid tasks" to unlock higher earnings.',
  'warning_signs', JSON_ARRAY('Unsolicited job offers via WhatsApp or Telegram without any formal interview', 'Unrealistically high remuneration for trivial micro-tasks', 'Demands for registration fees, training fees, or prepaid investment tasks', 'Absence of verifiable corporate domain email addresses'),
  'example', 'Part-time hiring: Earn ₹5,000 daily from home by reviewing Google Maps locations. No experience required. Message HR on Telegram @task_director_hr',
  'what_to_do', JSON_ARRAY('Research the company on LinkedIn and verify jobs on their official careers page', 'Insist on corporate email communication (@company.com)', 'Report fraudulent job posters to platform administrators'),
  'what_not_to_do', JSON_ARRAY('Never pay money or buy crypto to secure a job or withdraw "earned commissions"', 'Never share PAN, Aadhaar, or bank details with anonymous Telegram recruiters')
)),
(6, 'Online Shopping & Delivery Scams', 'shopping_scams', JSON_OBJECT(
  'what_is_it', 'Fake e-commerce websites and delivery phishing texts advertising luxury goods at 90% discounts or demanding tiny redelivery fees.',
  'how_it_works', 'Scammers create flash-sale portals advertising expensive electronics for a fraction of market price, collect upfront card payments, and never deliver the items. Or send SMS: "Your parcel cannot be delivered, pay ₹5 redelivery fee" to steal card details.',
  'warning_signs', JSON_ARRAY('Prices too good to be true (e.g., iPhone 15 for ₹12,000)', 'Website created very recently with no physical address, phone number, or return policy', 'Only accepting direct bank transfer, UPI, or gift cards', 'SMS about undelivered courier requiring payment of a tiny fee'),
  'example', 'India Post: Your package could not be delivered due to incomplete address. Please pay ₹12 redelivery fee within 12h: http://indiapost-parcel-tracking.link',
  'what_to_do', JSON_ARRAY('Shop only with reputable established retailers with clear return policies', 'Check domain age using WHOIS before purchasing from unknown storefronts', 'Track packages directly on official courier portals using the original tracking number'),
  'what_not_to_do', JSON_ARRAY('Never pay through direct bank transfers to individual accounts for e-commerce purchases', 'Never click delivery update links in unexpected SMS messages')
)),
(7, 'QR Code Scams (Quishing)', 'qr_scams', JSON_OBJECT(
  'what_is_it', 'Quishing involves malicious QR codes placed on physical surfaces (parking meters, restaurant tables) or embedded in phishing emails to bypass email filters.',
  'how_it_works', 'Because security software cannot easily inspect URLs encoded inside images, scammers place stickers with malicious QR codes over legitimate merchant payment codes, directing unsuspecting users to phishing login pages or malicious APK downloads.',
  'warning_signs', JSON_ARRAY('Physical QR code stickers pasted loosely over existing signs or payment terminals', 'QR codes received via unexpected emails or SMS asking you to scan to view an invoice', 'Scanning a QR code prompts a file download (.apk, .exe) or an unexpected login page'),
  'example', 'Scammer pastes a fake UPI QR code sticker over a petrol pump payment placard, diverting payments to a scammer bank account.',
  'what_to_do', JSON_ARRAY('Use a secure QR scanner like CyberShield to inspect the decoded URL before opening it', 'Check the displayed payee merchant name before authorizing any payment', 'Inspect physical payment placards for tampering or peelable stickers'),
  'what_not_to_do', JSON_ARRAY('Never scan QR codes sent in emails that claim to be document attachments or 2FA setups', 'Never install apps prompted by scanning a public QR code')
)),
(8, 'Password & Credential Security', 'password_security', JSON_OBJECT(
  'what_is_it', 'Best practices for creating, maintaining, and protecting digital account credentials against credential stuffing and brute-force attacks.',
  'how_it_works', 'Cybercriminals obtain leaked databases from compromised websites and use automated bots to attempt the same username/password combinations across hundreds of banking, shopping, and email services.',
  'warning_signs', JSON_ARRAY('Notifications of logins from unfamiliar devices or foreign locations', 'Using the same password across multiple online accounts', 'Passwords based on personal info (birthdays, names, phone numbers)'),
  'example', 'A user uses "Password@123" for both a forum account and their personal email. The forum is hacked, and attackers use the password to take over their email and banking.',
  'what_to_do', JSON_ARRAY('Use unique, strong passwords (minimum 12-16 characters with letters, numbers, symbols) for each account', 'Use a reputable password manager to generate and store complex credentials', 'Enable hardware or app-based 2FA (TOTP) wherever available'),
  'what_not_to_do', JSON_ARRAY('Never reuse passwords across critical accounts', 'Never share passwords in plain text over messaging apps or note files', 'Never click "Remember Me" on shared or public computers')
)),
(9, 'Social Engineering & Impersonation', 'social_engineering', JSON_OBJECT(
  'what_is_it', 'The psychological manipulation of people into performing actions or divulging confidential information, bypassing technical security controls.',
  'how_it_works', 'Attackers exploit cognitive biases—such as fear of authority (police/CBI arrest), urgency (time-limited offers), or sympathy (fake charity/relatives in distress)—to bypass logical skepticism.',
  'warning_signs', JSON_ARRAY('Demands for absolute secrecy ("Do not tell your family or bank manager")', 'Threats of immediate legal action, arrest, or customs seizure', 'Callers masquerading as senior executives, law enforcement, or relatives in emergency'),
  'example', 'Digital Arrest Scam: "This is Deputy Commissioner Sharma from CBI. A parcel addressed in your name containing illegal passports and contraband was intercepted at Mumbai airport. You must remain on video call and transfer verification funds."',
  'what_to_do', JSON_ARRAY('Recognize that legitimate law enforcement NEVER conducts "digital arrests" or demands online payments to clear cases', 'Take a deep breath and verify claims through independent, official contact channels', 'Talk to a trusted friend or family member before making any financial transfer under pressure'),
  'what_not_to_do', JSON_ARRAY('Never allow anyone to pressure you into immediate decisions or money transfers', 'Never install remote screen-sharing apps (AnyDesk, TeamViewer, RustDesk) at a caller instruction')
)),
(10, 'Social Media & Identity Theft', 'social_media', JSON_OBJECT(
  'what_is_it', 'Exploitation of social media profiles to hijack accounts, impersonate friends, or harvest personal data for identity theft and financial extortion.',
  'how_it_works', 'Scammers clone public profiles with stolen photos and message the victim contacts claiming emergency medical needs, or send fake copyright violation notices to account owners with links to phishing portals.',
  'warning_signs', JSON_ARRAY('Direct message from an existing friend asking for urgent financial transfer via UPI', 'Direct messages claiming your Instagram/Facebook account violates copyright policy and will be deleted in 24 hours', 'Quizzes and third-party apps requesting permissions to access your profile data'),
  'example', 'DM from Meta Copyright Team: "Your account violated intellectual property. Appeal within 12 hours or account will be permanently deactivated: http://meta-copyright-review-form.top"',
  'what_to_do', JSON_ARRAY('Verify emergency money requests from friends via a phone call or face-to-face contact', 'Keep social media profiles private and limit public exposure of personal details', 'Check official account center settings directly in the app for legitimate notices'),
  'what_not_to_do', JSON_ARRAY('Never click copyright appeal links sent via direct message', 'Never accept friend requests from duplicate accounts of people you already know without verifying')
))
ON DUPLICATE KEY UPDATE `title` = VALUES(`title`), `category` = VALUES(`category`), `content` = VALUES(`content`);
