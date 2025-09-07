const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// In-memory blocklist (in production, use a database)
const blocklist = [
  'malicious-site.com',
  'phishing-bank.com',
  'fake-login.net',
  'suspicious-domain.xyz'
];

// Additional analysis patterns
const suspiciousPatterns = {
  highRisk: [
    /malicious/i,
    /phishing/i,
    /scam/i,
    /fake/i,
    /suspicious/i
  ],
  mediumRisk: [
    /login/i,
    /secure/i,
    /verify/i,
    /update/i,
    /account/i
  ]
};

// Analyze URL with richer features
function analyzeURL(url, metadata) {
  let riskLevel = 'low';
  let threatType = 'unknown';
  let reason = 'No significant threats detected';
  let target = 'General';

  const hostname = new URL(url).hostname.toLowerCase();

  // Check blocklist
  if (blocklist.some(blocked => hostname.includes(blocked))) {
    riskLevel = 'critical';
    threatType = 'malware';
    reason = 'Domain found in blocklist';
    target = 'Blocked Domain';
  }

  // Check suspicious patterns
  for (const pattern of suspiciousPatterns.highRisk) {
    if (pattern.test(hostname) || pattern.test(url)) {
      riskLevel = 'high';
      threatType = 'phishing';
      reason = 'High-risk pattern detected in URL';
      break;
    }
  }

  if (riskLevel === 'low') {
    for (const pattern of suspiciousPatterns.mediumRisk) {
      if (pattern.test(hostname) || pattern.test(url)) {
        riskLevel = 'medium';
        threatType = 'suspicious';
        reason = 'Medium-risk pattern detected in URL';
        break;
      }
    }
  }

  // Analyze metadata
  if (metadata.hasPasswordFields && metadata.hasLoginForm) {
    if (riskLevel === 'low') riskLevel = 'medium';
    threatType = 'credential_harvest';
    reason += ' | Login form with password fields detected';
  }

  if (metadata.riskScore > 50) {
    riskLevel = 'high';
    reason += ' | High client-side risk score';
  }

  // Check referrer for suspicious patterns
  if (metadata.referrer && suspiciousPatterns.highRisk.some(pattern => pattern.test(metadata.referrer))) {
    riskLevel = 'high';
    reason += ' | Suspicious referrer detected';
  }

  return {
    isThreat: riskLevel !== 'low',
    riskLevel,
    threatType,
    reason,
    target,
    url: hostname,
    analysisTimestamp: new Date().toISOString()
  };
}

// API endpoint for URL analysis
app.post('/analyze', (req, res) => {
  try {
    const { url, riskScore, userAgent, referrer, hasPasswordFields, hasLoginForm, timestamp } = req.body;

    console.log(`Analyzing URL: ${url}, Risk Score: ${riskScore}`);

    const metadata = {
      riskScore,
      userAgent,
      referrer,
      hasPasswordFields,
      hasLoginForm,
      timestamp
    };

    const analysis = analyzeURL(url, metadata);

    res.json(analysis);
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({
      error: 'Analysis failed',
      message: error.message
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    blocklistSize: blocklist.length
  });
});

// Add to blocklist (for admin use)
app.post('/blocklist/add', (req, res) => {
  const { domain } = req.body;
  if (domain && !blocklist.includes(domain)) {
    blocklist.push(domain);
    res.json({ success: true, message: `${domain} added to blocklist` });
  } else {
    res.status(400).json({ error: 'Invalid or duplicate domain' });
  }
});

// Get blocklist (for admin use)
app.get('/blocklist', (req, res) => {
  res.json({ blocklist });
});

app.listen(PORT, () => {
  console.log(`PhishGuard Backend running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});

module.exports = app;
