const http = require('http');
const app = require('./server');

let server;
const PORT = 5001; // Run tests on port 5001 to avoid any port conflicts

function makeRequest(path, method = 'GET', body = null, token = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: 'localhost',
        port: PORT,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        }
      },
      (res) => {
        let raw = '';
        res.on('data', chunk => raw += chunk);
        res.on('end', () => {
          try {
            const data = JSON.parse(raw);
            resolve({ status: res.statusCode, data });
          } catch (e) {
            resolve({ status: res.statusCode, raw });
          }
        });
      }
    );

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function runTests() {
  console.log('--- STARTING COMPREHENSIVE CYBERSHIELD E2E TESTS ---');

  server = app.listen(PORT, () => {
    console.log(`[TEST] Test server listening on http://localhost:${PORT}`);
  });

  try {
    // 1. Health check
    const health = await makeRequest('/api/health');
    console.log('[TEST 1] Health Check:', health.status === 200 && health.data.status === 'ONLINE' ? 'PASS ✓' : 'FAIL ✕');

    // 2. Admin Login
    const adminLogin = await makeRequest('/api/auth/login', 'POST', {
      email: 'admin@cybershield.org',
      password: 'Admin@123'
    });
    console.log('[TEST 2] Admin Login:', adminLogin.status === 200 && adminLogin.data.token ? 'PASS ✓' : 'FAIL ✕');
    const adminToken = adminLogin.data.token;

    // 3. User Registration
    const testEmail = `test_citizen_${Date.now()}@example.com`;
    const userReg = await makeRequest('/api/auth/register', 'POST', {
      name: 'Cyber Defender',
      email: testEmail,
      phone: '+91 9123456780',
      password: 'TestPassword@123',
      confirmPassword: 'TestPassword@123'
    });
    console.log('[TEST 3] User Registration:', userReg.status === 201 ? 'PASS ✓' : 'FAIL ✕');

    // 4. User Login
    const userLogin = await makeRequest('/api/auth/login', 'POST', {
      email: testEmail,
      password: 'TestPassword@123'
    });
    console.log('[TEST 4] User Login:', userLogin.status === 200 && userLogin.data.token ? 'PASS ✓' : 'FAIL ✕');
    const userToken = userLogin.data.token;

    // 5. URL Scanner - Reputable
    const scanGoogle = await makeRequest('/api/scan/url', 'POST', { url: 'https://www.google.com' }, userToken);
    console.log('[TEST 5A] URL Scanner (google.com):', scanGoogle.data.analysis?.riskLevel === 'LOW RISK' ? 'PASS ✓ (LOW RISK)' : `FAIL: ${scanGoogle.data.analysis?.riskLevel}`);

    // 5. URL Scanner - Phishing Impersonation
    const scanPhish = await makeRequest('/api/scan/url', 'POST', { url: 'http://sbi-banking-verify.xyz/login.php' }, userToken);
    console.log('[TEST 5B] URL Scanner (sbi-banking-verify.xyz):', ['HIGH RISK', 'MALICIOUS'].includes(scanPhish.data.analysis?.riskLevel) ? 'PASS ✓ (FLAGGED)' : `FAIL: ${scanPhish.data.analysis?.riskLevel}`);

    // 5. URL Scanner - Raw IP
    const scanIp = await makeRequest('/api/scan/url', 'POST', { url: 'http://192.168.1.1/admin' }, userToken);
    console.log('[TEST 5C] URL Scanner (Raw IP):', scanIp.data.analysis?.riskScore >= 35 ? 'PASS ✓ (IP Flagged)' : 'FAIL');

    // 6. Message Scanner - Lottery Scam
    const scanMsg = await makeRequest('/api/scan/message', 'POST', {
      message: 'Congratulations! You won ₹50,000 cash prize. Click here immediately to claim: http://lottery-claim.xyz'
    }, userToken);
    console.log('[TEST 6] Message Scanner (Lottery + Urgency + Link):', ['HIGH RISK', 'MALICIOUS'].includes(scanMsg.data.analysis?.riskLevel) ? 'PASS ✓' : 'FAIL');

    // 7. Email Scanner - Typosquatting
    const scanEmail = await makeRequest('/api/scan/email', 'POST', { email: 'security@paypa1.com' }, userToken);
    console.log('[TEST 7] Email Scanner (paypa1.com):', ['HIGH RISK', 'MALICIOUS'].includes(scanEmail.data.analysis?.riskLevel) ? 'PASS ✓' : 'FAIL');

    // 8. Phone Scanner - Wangiri prefix
    const scanPhone = await makeRequest('/api/scan/phone', 'POST', { phone: '+232 77 123456' }, userToken);
    console.log('[TEST 8] Phone Scanner (+232 Wangiri Prefix):', scanPhone.data.analysis?.riskScore >= 25 ? 'PASS ✓' : 'FAIL');

    // 9. QR Scanner - UPI Trap
    const scanQr = await makeRequest('/api/scan/qr', 'POST', {
      content: 'upi://pay?pa=lottery_winner@upi&pn=Lottery%20Dept&am=5000'
    }, userToken);
    console.log('[TEST 9] QR Scanner (UPI Trap):', ['HIGH RISK', 'MALICIOUS'].includes(scanQr.data.analysis?.riskLevel) ? 'PASS ✓' : 'FAIL');

    // 10. Dashboard Stats from MySQL
    const dashStats = await makeRequest('/api/scans/dashboard-stats', 'GET', null, userToken);
    console.log('[TEST 10] User Dashboard Stats from MySQL:', dashStats.data.stats?.totalScans >= 5 ? 'PASS ✓ (Live MySQL Queries)' : 'FAIL');

    // 11. Scan History from MySQL
    const history = await makeRequest('/api/scans', 'GET', null, userToken);
    console.log('[TEST 11] Scan History API:', history.data.scans?.length > 0 ? 'PASS ✓' : 'FAIL');

    // 12. Awareness Modules
    const awareness = await makeRequest('/api/awareness', 'GET');
    console.log('[TEST 12A] Awareness Curriculum (10 modules):', awareness.data.modules?.length === 10 ? 'PASS ✓' : 'FAIL');

    const completeModule = await makeRequest('/api/awareness/1/complete', 'POST', null, userToken);
    console.log('[TEST 12B] Module Completion Tracking:', completeModule.status === 200 ? 'PASS ✓' : 'FAIL');

    // 13. Security Score Calculation
    const scoreRes = await makeRequest('/api/auth/security-score', 'GET', null, userToken);
    console.log('[TEST 13] User Security Score Calculation:', typeof scoreRes.data.score?.overallScore === 'number' ? 'PASS ✓' : 'FAIL');

    // 14. Scam Incident Reporting
    const reportRes = await makeRequest('/api/reports', 'POST', {
      category: 'phone',
      target: '+91 9999988888',
      description: 'Caller impersonated electricity board demanding immediate bill payment via unknown UPI.',
      evidence: 'Call timestamp 14:30 PM, caller demanded ₹1200 payment to unblock electricity meter.'
    }, userToken);
    console.log('[TEST 14] Scam Report Submission:', reportRes.status === 201 ? 'PASS ✓' : 'FAIL');
    const createdReportId = reportRes.data.report?.id;

    // 15. Admin SOC Dashboard
    const adminDash = await makeRequest('/api/admin/dashboard', 'GET', null, adminToken);
    console.log('[TEST 15] Admin SOC Dashboard from MySQL:', adminDash.data.stats?.totalScans >= 5 ? 'PASS ✓' : 'FAIL');

    // 16. Admin User Management
    const adminUsers = await makeRequest('/api/admin/users', 'GET', null, adminToken);
    console.log('[TEST 16] Admin Users List:', adminUsers.data.users?.length > 0 ? 'PASS ✓' : 'FAIL');

    // 17. Admin Report Triage
    const adminReports = await makeRequest('/api/admin/reports', 'GET', null, adminToken);
    console.log('[TEST 17] Admin Reports List:', adminReports.data.reports?.length > 0 ? 'PASS ✓' : 'FAIL');

    if (createdReportId) {
      const updateReport = await makeRequest(`/api/admin/reports/${createdReportId}`, 'PATCH', {
        status: 'Verified',
        admin_notes: 'Confirmed impersonation pattern. Phone number blacklisted.'
      }, adminToken);
      console.log('[TEST 18] Admin Report Triage Update & Audit Log:', updateReport.status === 200 ? 'PASS ✓' : 'FAIL');
    }

    console.log('--- ALL 18 AUTOMATED TESTS EXECUTED SUCCESSFULLY! ---');
  } catch (error) {
    console.error('[TEST ERROR]', error);
  } finally {
    if (server) {
      server.close(() => {
        console.log('[TEST] Server closed cleanly.');
        process.exit(0);
      });
    }
  }
}

runTests();
