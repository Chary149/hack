const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());

app.post('/analyze', (req, res) => {
  console.log('Received analysis request from extension:', req.body.url);

  // Placeholder for richer analysis logic
  // For now, let's simulate a threat detection for demonstration
  const isThreat = Math.random() < 0.3; // 30% chance of detecting a threat

  if (isThreat) {
    res.json({
      isThreat: true,
      url: req.body.url,
      target: 'Simulated Threat',
      riskLevel: 'high',
      threatType: 'simulated',
      reason: 'Simulated threat detected by backend analysis'
    });
  } else {
    res.json({
      isThreat: false,
      message: 'URL analyzed, no threat detected by backend.'
    });
  }
});

app.listen(port, () => {
  console.log(`PhishGuard Backend listening at http://localhost:${port}`);
});