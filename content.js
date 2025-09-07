class PhishGuardProtection {
  constructor() {
    this.keyloggerBlocked = false;
    this.threatInfo = null;
    this.init();
  }

  async init() {
    await this.checkCurrentSite();
    this.setupKeyloggerProtection();
    this.setupFormProtection();
    this.monitorDOMChanges();
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

    const headerTitle = isMalware ? '🚨 Dangerous Site Detected!' : '🚨 Phishing Threat Detected!';
    const headerDescription = isMalware
      ? 'Attackers on this site might install harmful software that steals or deletes your passwords, photos, messages, or credit card numbers.'
      : 'This website has been identified as potentially dangerous';

    div.innerHTML = `
      <div class="phishguard-warning-container">
        <div class="phishguard-warning-header">
          <div class="phishguard-warning-icon">⚠️</div>
          <h1>${headerTitle}</h1>
          <p>${headerDescription}</p>
        </div>

        <div class="phishguard-threat-info">
          <h3>📍 Website Information</h3>
          <div class="phishguard-threat-details">
            <div class="threat-detail">
              <span class="label">URL:</span>
              <span class="value">${this.threatInfo.url || 'Unknown'}</span>
            </div>
            <div class="threat-detail">
              <span class="label">Target:</span>
              <span class="value">${this.threatInfo.target || 'General'}</span>
            </div>
            <div class="threat-detail">
              <span class="label">Status:</span>
              <span class="value ${this.threatInfo.verified === 'yes' ? 'verified' : 'unverified'}">
                ${this.threatInfo.verified === 'yes' ? '✓ Verified Threat' : '⚠️ Suspected'}
              </span>
            </div>
            <div class="threat-detail">
              <span class="label">Risk Level:</span>
              <span class="value high-risk">🔴 HIGH</span>
            </div>
          </div>
        </div>

        <div class="phishguard-threat-info">
          <h3>🚨 Potential Threats</h3>
          <div class="attack-scenarios">
            ${threatDetails.map(scenario => `
              <div class="scenario">
                <div class="scenario-icon">${scenario.icon}</div>
                <div class="scenario-content">
                  <h4>${scenario.title}</h4>
                  <p>${scenario.description}</p>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <div class="phishguard-protection-info">
          <h3>🛡️ What Could Happen</h3>
          <ul class="protection-list">
            <li>💰 Financial loss from stolen banking credentials</li>
            <li>🔐 Identity theft and personal data compromise</li>
            <li>🦠 Malware infection on your device</li>
            <li>📧 Unauthorized access to your email accounts</li>
            <li>🔒 Account takeover and unauthorized transactions</li>
          </ul>
        </div>

        <div class="phishguard-warning-actions">
          <button class="phishguard-btn phishguard-btn-danger" id="phishguard-leave">
            🏃‍♂️ Leave This Site
          </button>
          <button class="phishguard-btn phishguard-btn-primary" id="phishguard-learn">
            📚 Learn More
          </button>
          <button class="phishguard-btn phishguard-btn-outline" id="phishguard-close">
            Continue Anyway
          </button>
        </div>
      </div>
    `;

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

    return div;
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
