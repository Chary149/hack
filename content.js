class PhishGuardProtection {
  constructor() {
    this.keyloggerBlocked = false;
    this.threatInfo = null;
    this.riskScore = 0;
    this.benignData = new Set();
    this.init();
  }

  async init() {
    // Load benign data first
    await this.loadBenignData();

    // Step 1: Compute risk score immediately on page load
    this.computeRiskScore();

    await this.checkCurrentSite();
    this.setupKeyloggerProtection();
    this.setupFormProtection();
    this.monitorDOMChanges();
  }

  async loadBenignData() {
    try {
      const response = await fetch(chrome.runtime.getURL('benign.json'));
      const data = await response.json();
      this.benignData = new Set(data.map(url => new URL(url).hostname));
      console.log('Benign data loaded:', this.benignData.size, 'entries');
    } catch (error) {
      console.error('Failed to load benign data:', error);
      // Fallback to hardcoded
      const fallback = [
        'google.com',
        'youtube.com',
        'facebook.com',
        'amazon.com',
        'wikipedia.org',
        'twitter.com',
        'linkedin.com',
        'instagram.com',
        'reddit.com',
        'netflix.com',
        'paypal.com',
        'ebay.com',
        'craigslist.org',
        'yahoo.com',
        'bing.com',
        'duckduckgo.com',
        'mozilla.org',
        'chrome.google.com',
        'addons.mozilla.org'
      ];
      this.benignData = new Set(fallback);
    }
  }

  // Step 1: Compute risk score from URL lexical features and DOM cues
  computeRiskScore() {
    let score = 0;
    const url = window.location.href;
    const hostname = window.location.hostname;

    // Check if domain is in trusted whitelist
    if (this.isTrustedDomain(hostname)) {
      this.riskScore = 0;
      console.log(`PhishGuard: Trusted domain ${hostname} - risk score: 0`);
      return;
    }

    // URL Lexical Features
    score += this.analyzeURLFeatures(url, hostname);

    // DOM Cues
    score += this.analyzeDOMCues();

    this.riskScore = Math.min(score, 100); // Cap at 100

    console.log(`PhishGuard: Risk score computed: ${this.riskScore}`);

    // Step 2: If score exceeds threshold or sensitive patterns present, check Safe Browsing
    if (this.riskScore >= 50 || this.hasSensitivePatterns()) {
      this.checkSafeBrowsing(url);
    }
  }

  isTrustedDomain(hostname) {
    // Check if hostname matches any benign domain
    return this.benignData.has(hostname) || Array.from(this.benignData).some(domain => hostname.endsWith('.' + domain));
  }

  analyzeURLFeatures(url, hostname) {
    let score = 0;

    // Domain length (longer domains are suspicious)
    if (hostname.length > 25) score += 10;
    if (hostname.length > 35) score += 15;

    // Number of subdomains (reduce penalty for legitimate sites)
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount > 2) score += subdomainCount * 3;

    // Suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.online', '.site', '.store', '.tech', '.live', '.icu', '.work', '.click', '.link'];
    if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) score += 20;

    // Keywords in domain (remove legitimate ones)
    const suspiciousKeywords = ['phish', 'fake', 'scam', 'hack', 'exploit', 'malware', 'virus', 'trojan'];
    if (suspiciousKeywords.some(keyword => hostname.includes(keyword))) score += 15;

    // IP address in URL
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) score += 25;

    // Leet speak
    if (/[a-z]+[0-9]+[a-z]*|[a-z]*[0-9]+[a-z]+/.test(hostname)) score += 10;

    // HTTPS check (significant bonus for HTTPS)
    if (url.startsWith('https://')) score -= 30;

    return score;
  }

  analyzeDOMCues() {
    let score = 0;

    // Password fields
    const passwordFields = document.querySelectorAll('input[type="password"]');
    score += passwordFields.length * 10;

    // Login forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      const inputs = form.querySelectorAll('input');
      let hasUsername = false;
      let hasPassword = false;

      inputs.forEach(input => {
        const type = input.type.toLowerCase();
        const name = input.name?.toLowerCase() || '';
        const placeholder = input.placeholder?.toLowerCase() || '';

        if (type === 'password' || name.includes('pass') || placeholder.includes('password')) hasPassword = true;
        if (type === 'email' || type === 'text' || name.includes('user') || name.includes('email') || placeholder.includes('email') || placeholder.includes('username')) hasUsername = true;
      });

      if (hasUsername && hasPassword) score += 15;
    });

    // Suspicious scripts or iframes
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => {
      const src = script.src.toLowerCase();
      if (src.includes('malicious') || src.includes('suspicious')) score += 10;
    });

    return score;
  }

  hasSensitivePatterns() {
    // Check for sensitive patterns that warrant Safe Browsing check
    const sensitivePatterns = [
      /password/i,
      /login/i,
      /bank/i,
      /credit.*card/i,
      /social.*security/i
    ];

    // Check if document.body exists (DOM might not be ready at document_start)
    if (!document.body) {
      return false;
    }

    return sensitivePatterns.some(pattern => pattern.test(document.body.innerText));
  }

  // Step 2: Check Safe Browsing v4 if risk score is high
  async checkSafeBrowsing(url) {
    const apiKey = 'AIzaSyBRAURluW18zAoKggEcVB16azODh1ohiks';
    const safeBrowsingUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

    const requestBody = {
      client: {
        clientId: "phishguard-extension",
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: url }]
      }
    };

    try {
      const response = await fetch(safeBrowsingUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      const data = await response.json();

      if (data.matches && data.matches.length > 0) {
        // Threat detected by Safe Browsing
        this.threatInfo = {
          phish_id: 'safebrowsing',
          url: hostname,
          target: data.matches[0].threatType,
          verified: 'safebrowsing',
          online: 'yes',
          risk_level: 'critical',
          threat_type: 'malware',
          reason: `Safe Browsing detected: ${data.matches[0].threatType}`
        };
        this.showThreatWarning();
      } else {
        // No threat from Safe Browsing, but high risk score - send to backend for further analysis
        this.sendToBackend(url);
      }
    } catch (error) {
      console.error('Safe Browsing check failed:', error);
      // If Safe Browsing fails, still send to backend
      this.sendToBackend(url);
    }
  }

  // Step 3: Send to backend for richer analysis
  async sendToBackend(url) {
    const backendUrl = 'http://localhost:3001/analyze'; // Local backend URL

    const metadata = {
      url: url,
      riskScore: this.riskScore,
      userAgent: navigator.userAgent,
      referrer: document.referrer,
      hasPasswordFields: document.querySelectorAll('input[type="password"]').length > 0,
      hasLoginForm: this.detectLoginForm(),
      timestamp: Date.now()
    };

    try {
      const response = await fetch(backendUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(metadata)
      });

      const result = await response.json();

      if (result.isThreat) {
        this.threatInfo = {
          phish_id: 'backend',
          url: result.url,
          target: result.target,
          verified: 'backend',
          online: 'yes',
          risk_level: result.riskLevel,
          threat_type: result.threatType,
          reason: result.reason
        };
        this.showThreatWarning();
      }
    } catch (error) {
      console.error('Backend analysis failed:', error);
    }
  }

  detectLoginForm() {
    const forms = document.querySelectorAll('form');
    for (let form of forms) {
      const inputs = form.querySelectorAll('input');
      let hasUsername = false;
      let hasPassword = false;

      inputs.forEach(input => {
        const type = input.type.toLowerCase();
        const name = input.name?.toLowerCase() || '';
        const placeholder = input.placeholder?.toLowerCase() || '';

        if (type === 'password' || name.includes('pass') || placeholder.includes('password')) hasPassword = true;
        if (type === 'email' || type === 'text' || name.includes('user') || name.includes('email') || placeholder.includes('email') || placeholder.includes('username')) hasUsername = true;
      });

      if (hasUsername && hasPassword) return true;
    }
    return false;
  }

  async checkCurrentSite() {
    try {
      // Get current tab id
      const tabId = await this.getTabId();

      // Query background if current URL is phishing
      const response = await new Promise(resolve => {
        chrome.runtime.sendMessage({ type: 'CHECK_URL', url: window.location.href }, resolve);
      });

      if (response && response.threat) {
        this.threatInfo = response.threat;
        await this.showThreatWarning();
        return; // Prevent duplicate warnings
      }

      // Get session threat from background
      const sessionThreatResp = await new Promise(resolve => {
        chrome.runtime.sendMessage({ type: 'GET_SESSION_THREAT', tabId }, resolve);
      });
      if (sessionThreatResp && sessionThreatResp.threat && !this.threatInfo) {
        this.threatInfo = sessionThreatResp.threat;
        await this.showThreatWarning();
      }
    } catch (error) {
      console.error('Site check failed:', error);
    }
  }

  getTabId() {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'GET_TAB_ID' }, response => {
        resolve(response?.tabId || 0);
      });
    });
  }

  setupKeyloggerProtection() {
    const protectedEvents = ['keydown', 'keypress', 'keyup', 'input', 'paste'];
    protectedEvents.forEach(eventType => {
      document.addEventListener(eventType, (event) => {
        if (this.threatInfo && this.detectSuspiciousKeylogging(event)) {
          event.stopImmediatePropagation();
          event.preventDefault();
          this.showKeyloggerBlocked();
          chrome.runtime.sendMessage({
            type: 'REPORT_BLOCKED',
            eventType,
            target: event.target.tagName
          });
        }
      }, true);
    });

    // Show small popup message on any unsecure website
    if (this.threatInfo) {
      this.showMiniWarning();
    }
  }

  showMiniWarning() {
    if (document.getElementById('phishguard-mini-warning')) return;

    const miniWarning = document.createElement('div');
    miniWarning.id = 'phishguard-mini-warning';
    miniWarning.innerHTML = `
      <div class="mini-warning-content">
        ⚠️ You are on an unsafe website. Be cautious with your credentials.
        <button class="mini-close" aria-label="Close warning">&times;</button>
      </div>
    `;

    miniWarning.querySelector('.mini-close').addEventListener('click', () => {
      miniWarning.remove();
    });

    document.body.appendChild(miniWarning);

    // Auto remove after 10 seconds
    setTimeout(() => {
      miniWarning.remove();
    }, 10000);
  }


  detectSuspiciousKeylogging(event, lastEventTime) {
    return (
      event.timeStamp - lastEventTime < 10 ||
      (event.target && event.target.tagName === 'INPUT' && event.target.type === 'password' && !event.isTrusted)
    );
  }

  setupFormProtection() {
    document.querySelectorAll('form').forEach(form => {
      form.addEventListener('submit', event => {
        if (this.threatInfo) {
          event.preventDefault();
          this.showFormProtectionWarning();
        }
      });
    });

    // Detect and alert about credential requests on unsafe websites
    if (this.threatInfo) {
      this.detectCredentialRequests();
    }
  }

  detectCredentialRequests() {
    // Check for password fields
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) {
      this.showCredentialAlert();
    }

    // Check for login forms
    const loginForms = document.querySelectorAll('form');
    loginForms.forEach(form => {
      const inputs = form.querySelectorAll('input');
      let hasUsername = false;
      let hasPassword = false;

      inputs.forEach(input => {
        const type = input.type.toLowerCase();
        const name = input.name?.toLowerCase() || '';
        const id = input.id?.toLowerCase() || '';
        const placeholder = input.placeholder?.toLowerCase() || '';

        if (type === 'password' || name.includes('pass') || id.includes('pass') || placeholder.includes('password')) {
          hasPassword = true;
        }
        if (type === 'email' || type === 'text' || name.includes('user') || name.includes('email') || name.includes('login') ||
            id.includes('user') || id.includes('email') || id.includes('login') ||
            placeholder.includes('email') || placeholder.includes('username') || placeholder.includes('login')) {
          hasUsername = true;
        }
      });

      if (hasUsername && hasPassword) {
        this.showCredentialAlert();
      }
    });
  }

  showCredentialAlert() {
    if (document.getElementById('phishguard-credential-alert')) return;

    const alert = document.createElement('div');
    alert.id = 'phishguard-credential-alert';
    alert.innerHTML = `
      <div class="credential-alert-content">
        🚨 <strong>Credential Request Detected!</strong><br>
        This unsafe website is asking for your login credentials. Do not enter any personal information.
        <button class="credential-alert-close" aria-label="Close alert">&times;</button>
      </div>
    `;

    alert.querySelector('.credential-alert-close').addEventListener('click', () => {
      alert.remove();
    });

    document.body.appendChild(alert);

    // Auto remove after 15 seconds
    setTimeout(() => {
      alert.remove();
    }, 15000);
  }

 async showThreatWarning() {
  // Wait until document.body is ready
  if (!document.body) {
    await new Promise(resolve => {
      if (document.readyState === "complete" || document.readyState === "interactive") {
        resolve();
      } else {
        window.addEventListener('DOMContentLoaded', resolve, { once: true });
      }
    });
  }

  const overlay = this.createOverlay();
  document.body.appendChild(overlay);
  requestAnimationFrame(() => {
    overlay.classList.add('phishguard-show');
  });
}


  createOverlay() {
    const div = document.createElement('div');
    div.className = 'phishguard-threat-overlay';
    const threatDetails = this.getThreatDetails();
    const threatType = this.threatInfo.threat_type || 'suspicious';
    const isMalware = threatType === 'malware' || this.threatInfo.target === 'Malware';
    const riskLevel = this.threatInfo.risk_level || 'high';

    const headerTitle = isMalware ? '🚨 CRITICAL SECURITY THREAT!' : '🚨 POTENTIAL PHISHING ATTACK!';
    const headerDescription = isMalware
      ? 'This site contains MALWARE that can steal your personal data, install viruses, or take control of your device.'
      : 'This website appears to be FAKE and designed to steal your login credentials or personal information.';

    const riskColor = riskLevel === 'critical' ? '#dc3545' : riskLevel === 'high' ? '#fd7e14' : '#ffc107';
    const riskIcon = riskLevel === 'critical' ? '🔴' : riskLevel === 'high' ? '🟠' : '🟡';

    div.innerHTML = `
      <div class="phishguard-modern-warning">
        <div class="phishguard-header-section">
          <div class="phishguard-risk-indicator" style="background: ${riskColor}">
            ${riskIcon}
          </div>
          <div class="phishguard-header-content">
            <h1 class="phishguard-title">${headerTitle}</h1>
            <p class="phishguard-subtitle">${headerDescription}</p>
            <div class="phishguard-url-display">
              <strong>⚠️ Suspicious URL:</strong> ${this.threatInfo.url || window.location.hostname}
            </div>
          </div>
        </div>

        <div class="phishguard-details-section">
          <div class="phishguard-info-grid">
            <div class="phishguard-info-card">
              <h3>🔍 Detection Method</h3>
              <p>${this.threatInfo.verified === 'safebrowsing' ? 'Google Safe Browsing' :
                   this.threatInfo.verified === 'backend' ? 'Advanced AI Analysis' :
                   'Heuristic Analysis'}</p>
            </div>
            <div class="phishguard-info-card">
              <h3>🎯 Attack Type</h3>
              <p>${isMalware ? 'Malware Distribution' : 'Credential Phishing'}</p>
            </div>
            <div class="phishguard-info-card">
              <h3>📊 Risk Assessment</h3>
              <p style="color: ${riskColor}; font-weight: bold;">
                ${riskLevel.toUpperCase()} - ${this.threatInfo.reason || 'Multiple red flags detected'}
              </p>
            </div>
          </div>
        </div>

        <div class="phishguard-threats-section">
          <h3>🚨 What This Fake Site Could Do</h3>
          <div class="phishguard-threat-grid">
            ${threatDetails.slice(0, 4).map(scenario => `
              <div class="phishguard-threat-item">
                <div class="phishguard-threat-icon">${scenario.icon}</div>
                <div class="phishguard-threat-content">
                  <h4>${scenario.title}</h4>
                  <p>${scenario.description}</p>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <div class="phishguard-consequences-section">
          <h3>💔 If You Continue, You Risk:</h3>
          <div class="phishguard-consequences-list">
            <div class="phishguard-consequence-item">
              <span class="phishguard-consequence-icon">💰</span>
              <span>Complete loss of savings and financial ruin</span>
            </div>
            <div class="phishguard-consequence-item">
              <span class="phishguard-consequence-icon">🔐</span>
              <span>Identity theft and permanent personal data compromise</span>
            </div>
            <div class="phishguard-consequence-item">
              <span class="phishguard-consequence-icon">🦠</span>
              <span>Malware infection spreading to all your devices</span>
            </div>
            <div class="phishguard-consequence-item">
              <span class="phishguard-consequence-icon">📧</span>
              <span>Hackers gaining access to all your email accounts</span>
            </div>
            <div class="phishguard-consequence-item">
              <span class="phishguard-consequence-icon">🏦</span>
              <span>Unauthorized access to your bank accounts and transactions</span>
            </div>
          </div>
        </div>

        <div class="phishguard-actions-section">
          <div class="phishguard-action-buttons">
            <button class="phishguard-btn phishguard-btn-leave" id="phishguard-leave">
              🏃‍♂️ Leave This Dangerous Site
            </button>
            <button class="phishguard-btn phishguard-btn-learn" id="phishguard-learn">
              📚 Learn About This Threat
            </button>
          </div>
          <div class="phishguard-secondary-actions">
            <button class="phishguard-btn phishguard-btn-secondary" id="phishguard-report">
              🚨 Report This Site
            </button>
            <button class="phishguard-btn phishguard-btn-outline" id="phishguard-close">
              Continue At Your Own Risk
            </button>
          </div>
        </div>

        <div class="phishguard-footer">
          <p>🛡️ Protected by PhishGuard Pro - Advanced Threat Detection</p>
        </div>
      </div>
    `;

    // Add event listeners
    div.querySelector('#phishguard-close').addEventListener('click', () => {
      div.remove();
    });

    div.querySelector('#phishguard-leave').addEventListener('click', () => {
      window.location.href = 'https://www.google.com';
    });

    div.querySelector('#phishguard-learn').addEventListener('click', () => {
      this.showEducationalContent();
      div.remove();
    });

    div.querySelector('#phishguard-report').addEventListener('click', () => {
      this.reportThreat();
    });

    return div;
  }

  reportThreat() {
    // Report functionality - could send to backend or external service
    alert('Thank you for reporting! This helps protect other users from this threat.');
  }

  getThreatDetails() {
    const target = this.threatInfo.target?.toLowerCase() || 'general';
    const threatType = this.threatInfo.threat_type || 'suspicious';

    const threatScenarios = {
      banking: [
        {
          icon: '💳',
          title: 'Credential Theft',
          description: 'Stealing your bank login credentials to access your accounts'
        },
        {
          icon: '💰',
          title: 'Financial Fraud',
          description: 'Unauthorized transactions and money transfers from your accounts'
        },
        {
          icon: '📱',
          title: 'Account Takeover',
          description: 'Complete control of your banking accounts and personal finances'
        }
      ],
      email: [
        {
          icon: '📧',
          title: 'Email Hijacking',
          description: 'Access to your email to send spam or phishing to your contacts'
        },
        {
          icon: '🔑',
          title: 'Password Reset Attacks',
          description: 'Using your email to reset passwords on other services'
        },
        {
          icon: '🎣',
          title: 'Contact Exploitation',
          description: 'Using your contact list for further phishing campaigns'
        }
      ],
      social: [
        {
          icon: '👥',
          title: 'Identity Theft',
          description: 'Stealing your personal information for fraudulent activities'
        },
        {
          icon: '🔒',
          title: 'Account Compromise',
          description: 'Taking over your social media accounts'
        },
        {
          icon: '📢',
          title: 'Spam Distribution',
          description: 'Using your account to spread malware and scams'
        }
      ],
      malware: [
        {
          icon: '🦠',
          title: 'Malware Installation',
          description: 'Attackers might install harmful software that steals or deletes your passwords, photos, messages, or credit card numbers'
        },
        {
          icon: '💻',
          title: 'Device Compromise',
          description: 'Viruses, ransomware, or spyware could take control of your computer'
        },
        {
          icon: '🔐',
          title: 'Data Encryption',
          description: 'Ransomware might encrypt your files and demand payment for decryption'
        },
        {
          icon: '📡',
          title: 'Remote Access',
          description: 'Hackers could gain unauthorized remote access to your system'
        },
        {
          icon: '💰',
          title: 'Financial Loss',
          description: 'Stolen banking credentials could lead to unauthorized transactions'
        }
      ],
      general: [
        {
          icon: '🦠',
          title: 'Malware Infection',
          description: 'Installing viruses, ransomware, or spyware on your device'
        },
        {
          icon: '🔓',
          title: 'Data Theft',
          description: 'Stealing personal information, passwords, and sensitive data'
        },
        {
          icon: '🎭',
          title: 'Phishing Attacks',
          description: 'Tricking you into revealing confidential information'
        }
      ]
    };

    // Return malware scenarios for malware threats
    if (threatType === 'malware' || target === 'malware') {
      return threatScenarios.malware;
    }

    return threatScenarios[target] || threatScenarios.general;
  }

  showEducationalContent() {
    const educationWindow = window.open('', 'phishguard-education',
      'width=700,height=600,scrollbars=yes,resizable=yes');

    educationWindow.document.write(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>PhishGuard Education</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 650px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
          }
          .content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
          }
          h1 { color: #2c3e50; text-align: center; }
          h2 { color: #e74c3c; margin-top: 30px; }
          .warning { background: #fff3cd; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107; }
          .tip { background: #d1ecf1; padding: 15px; border-radius: 8px; border-left: 4px solid #bee5eb; }
          ul { padding-left: 20px; }
          li { margin-bottom: 8px; }
          .close-btn {
            background: #e74c3c;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            float: right;
            margin-top: 20px;
          }
        </style>
      </head>
      <body>
        <div class="content">
          <h1>🎓 Phishing Awareness Guide</h1>

          <div class="warning">
            <strong>⚠️ Current Threat:</strong> You're viewing information about a ${this.threatInfo?.target || 'phishing'} scam.
          </div>

          <h2>🎣 How Phishing Works</h2>
          <p>Phishing attacks typically involve:</p>
          <ul>
            <li><strong>Fake Websites:</strong> Sites that look legitimate but steal your information</li>
            <li><strong>Social Engineering:</strong> Tricking you into revealing sensitive data</li>
            <li><strong>Malware Distribution:</strong> Infecting your device with harmful software</li>
            <li><strong>Credential Harvesting:</strong> Collecting usernames and passwords</li>
          </ul>

          <h2>🚩 Red Flags to Watch For</h2>
          <ul>
            <li><strong>Unexpected Requests:</strong> Sudden demands for personal information</li>
            <li><strong>Urgent Language:</strong> "Act now or lose access" messages</li>
            <li><strong>Suspicious URLs:</strong> Check for misspellings and unusual domains</li>
            <li><strong>Poor Security:</strong> Sites without HTTPS or lock icon</li>
            <li><strong>Too Good to Be True:</strong> Unrealistic offers or prizes</li>
          </ul>

          <h2>🛡️ Protection Strategies</h2>
          <div class="tip">
            <ul>
              <li><strong>Verify URLs:</strong> Always check the website address carefully</li>
              <li><strong>Use Security Software:</strong> Keep antivirus and anti-phishing tools updated</li>
              <li><strong>Enable 2FA:</strong> Add extra security to your accounts</li>
              <li><strong>Be Skeptical:</strong> Question unexpected requests for information</li>
              <li><strong>Report Suspicious Sites:</strong> Help protect others by reporting threats</li>
            </ul>
          </div>

          <h2>📞 What to Do If Compromised</h2>
          <ul>
            <li>Change passwords immediately on affected accounts</li>
            <li>Contact your bank and financial institutions</li>
            <li>Run a full security scan on your devices</li>
            <li>Monitor your accounts for suspicious activity</li>
            <li>Report the incident to relevant authorities</li>
          </ul>

          <button class="close-btn" onclick="window.close()">Close</button>
        </div>
      </body>
      </html>
    `);
  }

  showKeyloggerBlocked() {
    if (this.keyloggerBlocked) return;
    this.keyloggerBlocked = true;
    const notification = document.createElement('div');
    notification.className = 'phishguard-keylogger-blocked';
    notification.textContent = 'Keylogger Blocked!';
    document.body.appendChild(notification);
    setTimeout(() => {
      notification.remove();
      this.keyloggerBlocked = false;
    }, 3000);
  }

  showFormProtectionWarning() {
    const warning = document.createElement('div');
    warning.className = 'phishguard-form-warning';
    warning.textContent = 'Form submission blocked due to security risk!';
    document.body.appendChild(warning);
    setTimeout(() => warning.remove(), 5000);
  }

  monitorDOMChanges() {
    // Optional: monitor DOM to detect dynamic injections, etc.
  }
}

new PhishGuardProtection();
