const fetch = globalThis.fetch || require('node-fetch');

const VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3';
const REQUEST_TIMEOUT_MS = 6000;

/**
 * Checks a URL against VirusTotal if API key is provided.
 * If API is missing or fails, NEVER marks it safe; returns unavailable status.
 */
async function checkUrlThreatIntel(rawUrl) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey || apiKey.trim() === '' || apiKey === 'your_key_here' || apiKey === 'your_optional_virustotal_api_key_here') {
    return {
      available: false,
      status: 'UNAVAILABLE',
      reason: 'External threat intelligence unavailable (API key not configured).',
      detections: null,
      maliciousCount: 0,
      suspiciousCount: 0,
      totalEngines: 0
    };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    // Submit URL to VirusTotal
    const submitRes = await fetch(`${VIRUSTOTAL_URL}/urls`, {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ url: rawUrl }),
      signal: controller.signal
    });

    if (!submitRes.ok) {
      return {
        available: false,
        status: 'UNAVAILABLE',
        reason: `External threat intelligence service returned status ${submitRes.status}.`,
        detections: null,
        maliciousCount: 0,
        suspiciousCount: 0,
        totalEngines: 0
      };
    }

    const submitData = await submitRes.json();
    const analysisId = submitData.data?.id;

    if (!analysisId) {
      return {
        available: false,
        status: 'UNAVAILABLE',
        reason: 'External threat intelligence analysis ID not returned.',
        detections: null,
        maliciousCount: 0,
        suspiciousCount: 0,
        totalEngines: 0
      };
    }

    // Single quick check for completed analysis
    const getRes = await fetch(`${VIRUSTOTAL_URL}/analyses/${encodeURIComponent(analysisId)}`, {
      headers: { 'x-apikey': apiKey },
      signal: controller.signal
    });

    if (!getRes.ok) {
      return {
        available: false,
        status: 'UNAVAILABLE',
        reason: 'External threat intelligence analysis lookup pending.',
        detections: null,
        maliciousCount: 0,
        suspiciousCount: 0,
        totalEngines: 0
      };
    }

    const analysisData = await getRes.json();
    const stats = analysisData.data?.attributes?.stats;

    if (!stats) {
      return {
        available: false,
        status: 'UNAVAILABLE',
        reason: 'External threat intelligence statistics not ready yet.',
        detections: null,
        maliciousCount: 0,
        suspiciousCount: 0,
        totalEngines: 0
      };
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;

    return {
      available: true,
      status: malicious > 0 ? 'MALICIOUS' : (suspicious > 0 ? 'SUSPICIOUS' : 'CLEAN'),
      reason: `${malicious} malicious and ${suspicious} suspicious detections across ${total} threat engines.`,
      maliciousCount: malicious,
      suspiciousCount: suspicious,
      totalEngines: total,
      detections: stats
    };
  } catch (err) {
    return {
      available: false,
      status: 'UNAVAILABLE',
      reason: err.name === 'AbortError'
        ? 'External threat intelligence request timed out.'
        : 'External threat intelligence network unreachable.',
      detections: null,
      maliciousCount: 0,
      suspiciousCount: 0,
      totalEngines: 0
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

module.exports = { checkUrlThreatIntel };
