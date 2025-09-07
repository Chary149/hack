// Popup JavaScript for PhishGuard Pro
class PopupInterface {
  constructor() {
    this.currentTab = null;
    this.threatInfo = null;
    this.stats = {
      threatsBlocked: 0,
      sitesChecked: 0,
      educatedUsers: 0
    };
    this.init();
  }

  async init() {
    await this.getCurrentTab();
    await this.loadStats();
    await this.checkCurrentSite();
    this.setupEventListeners();
    this.setupToggles();
    this.hideLoading();
  }

  async getCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      this.currentTab = tab;
    } catch (error) {
      console.error('Failed to get current tab:', error);
    }
  }

  async loadStats() {
    try {
      const result = await chrome.storage.local.get([
        'threatsBlocked', 
        'sitesChecked', 
        'educationStats'
      ]);
      
      this.stats.threatsBlocked = result.threatsBlocked || 0;
      this.stats.sitesChecked = result.sitesChecked || 0;
      this.stats.educatedUsers = result.educationStats?.totalEducated || 0;
      
      this.updateStatsDisplay();
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  }

  async checkCurrentSite() {
    if (!this.currentTab) return;

    try {
      // Check session storage for threat info
      const sessionData = await chrome.storage.session.get(`threat_${this.currentTab.id}`);
      const threatData = sessionData[`threat_${this.currentTab.id}`];

      if (threatData) {
        this.threatInfo = threatData;
        this.showThreatDetected();
      } else {
        // Send message to background script to check URL
        const response = await chrome.runtime.sendMessage({
          type: 'CHECK_URL',
          url: this.currentTab.url
        });

        if (response.threat) {
          this.threatInfo = response.threat;
          this.showThreatDetected();
        } else {
          this.showSafeStatus();
        }
      }

      // Update sites checked counter
      this.stats.sitesChecked++;
      await chrome.storage.local.set({ sitesChecked: this.stats.sitesChecked });
      this.updateStatsDisplay();

    } catch (error) {
      console.error('Site check failed:', error);
      this.showErrorStatus();
    }
  }

  showThreatDetected() {
    const statusIndicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');
    const statusDetails = document.getElementById('statusDetails');
    const threatInfo = document.getElementById('threatInfo');
    const actionButtons = document.getElementById('actionButtons');
    const threatActions = document.getElementById('threatActions');

    // Update status indicator
    statusIndicator.textContent = '🚨';
    statusIndicator.classList.add('threat');
    
    // Update status text
    statusText.textContent = 'Threat Detected!';
    statusText.style.color = '#c62828';
    statusDetails.textContent = 'This site has been identified as potentially malicious';

    // Show threat information
    document.getElementById('threatTarget').textContent = this.threatInfo.target || 'Unknown';
    document.getElementById('threatStatus').textContent = 
      this.threatInfo.verified === 'yes' ? '✓ Verified' : '⚠️ Suspected';
    document.getElementById('threatRisk').textContent = '🔴 HIGH';
    
    threatInfo.classList.add('show');
    actionButtons.style.display = 'none';
    threatActions.style.display = 'block';

    // Update threat counter
    this.stats.threatsBlocked++;
    chrome.storage.local.set({ threatsBlocked: this.stats.threatsBlocked });
    this.updateStatsDisplay();
  }

  showSafeStatus() {
    const statusIndicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');
    const statusDetails = document.getElementById('statusDetails');

    statusIndicator.textContent = '🛡️';
    statusIndicator.classList.remove('threat');
    statusText.textContent = 'Site is Safe';
    statusText.style.color = '#2e7d32';
    statusDetails.textContent = 'No threats detected on this website';
  }

  showErrorStatus() {
    const statusIndicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');
    const statusDetails = document.getElementById('statusDetails');

    statusIndicator.textContent = '❓';
    statusText.textContent = 'Unable to Check';
    statusText.style.color = '#f57c00';
    statusDetails.textContent = 'Could not analyze this website';
  }

  updateStatsDisplay() {
    document.getElementById('threatsBlocked').textContent = this.stats.threatsBlocked;
    document.getElementById('sitesChecked').textContent = this.stats.sitesChecked;
  }

  setupEventListeners() {
    // Scan current site
    document.getElementById('scanNow').addEventListener('click', async () => {
      this.showLoading();
      await this.checkCurrentSite();
      this.hideLoading();
    });

    // Report site
    document.getElementById('reportSite').addEventListener('click', () => {
      this.reportCurrentSite();
    });

    // Leave site (for threats)
    document.getElementById('leaveSite').addEventListener('click', () => {
      if (this.currentTab) {
        chrome.tabs.update(this.currentTab.id, { url: 'https://www.google.com' });
        window.close();
      }
    });

    // Learn more (for threats)
    document.getElementById('learnMore').addEventListener('click', () => {
      this.showEducationalContent();
    });

    // Toggle switches
    document.getElementById('realTimeToggle').addEventListener('click', (e) => {
      this.toggleSetting(e.target, 'realTimeProtection');
    });

    document.getElementById('keyloggerToggle').addEventListener('click', (e) => {
      this.toggleSetting(e.target, 'keyloggerBlocking');
    });

    document.getElementById('educationToggle').addEventListener('click', (e) => {
      this.toggleSetting(e.target, 'educationalAlerts');
    });
  }

  async setupToggles() {
    try {
      const settings = await chrome.storage.local.get([
        'realTimeProtection',
        'keyloggerBlocking', 
        'educationalAlerts'
      ]);

      // Set default values if not exists
      const defaults = {
        realTimeProtection: true,
        keyloggerBlocking: true,
        educationalAlerts: true
      };

      Object.keys(defaults).forEach(key => {
        if (settings[key] === undefined) {
          settings[key] = defaults[key];
        }
      });

      // Update toggle states
      this.updateToggle('realTimeToggle', settings.realTimeProtection);
      this.updateToggle('keyloggerToggle', settings.keyloggerBlocking);
      this.updateToggle('educationToggle', settings.educationalAlerts);

      // Save defaults
      await chrome.storage.local.set(settings);
    } catch (error) {
      console.error('Failed to setup toggles:', error);
    }
  }

  updateToggle(toggleId, isActive) {
    const toggle = document.getElementById(toggleId);
    if (isActive) {
      toggle.classList.add('active');
    } else {
      toggle.classList.remove('active');
    }
  }

  async toggleSetting(toggle, settingName) {
    toggle.classList.toggle('active');
    const isActive = toggle.classList.contains('active');
    
    try {
      await chrome.storage.local.set({ [settingName]: isActive });
      
      // Send message to content scripts about setting change
      if (this.currentTab) {
        chrome.tabs.sendMessage(this.currentTab.id, {
          type: 'SETTING_CHANGED',
          setting: settingName,
          value: isActive
        }).catch(() => {
          // Ignore errors if content script not loaded
        });
      }
    } catch (error) {
      console.error('Failed to save setting:', error);
    }
  }

  reportCurrentSite() {
    if (!this.currentTab) return;

    // Create report data
    const reportData = {
      url: this.currentTab.url,
      title: this.currentTab.title,
      timestamp: new Date().toISOString(),
      userReport: true,
      threatInfo: this.threatInfo
    };

    // Save to storage for future processing
    chrome.storage.local.get(['userReports'], (result) => {
      const reports = result.userReports || [];
      reports.push(reportData);
      chrome.storage.local.set({ userReports: reports });
    });

    // Show confirmation
    this.showNotification('Site reported successfully! Thank you for helping keep others safe.');
  }

  showEducationalContent() {
    // Create educational popup
    const educationWindow = window.open('', 'education', 
      'width=600,height=800,scrollbars=yes,resizable=yes');
    
    educationWindow.document.write(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>PhishGuard Education</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
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
          <h1>🎓 Phishing Education Center</h1>
          
          <div class="warning">
            <strong>⚠️ Current Threat:</strong> You're viewing information about a ${this.threatInfo?.target || 'phishing'} scam that targets ${this.threatInfo?.target?.toLowerCase() || 'user credentials'}.
          </div>

          <h2>🎣 How This Attack Works</h2>
          <p>This phishing site would have:</p>
          <ul>
            <li>Mimicked a legitimate ${this.threatInfo?.target || 'service'} website</li>
            <li>Stolen your login credentials when entered</li>
            <li>Potentially installed malware on your device</li>
            <li>Used your information for identity theft or fraud</li>
          </ul>

          <h2>🚩 Warning Signs You Should Know</h2>
          <ul>
            <li><strong>Suspicious URLs:</strong> Check for misspellings or unusual domains</li>
            <li><strong>No HTTPS:</strong> Look for the lock icon in your address bar</li>
            <li><strong>Poor Design:</strong> Legitimate sites invest in professional design</li>
            <li><strong>Urgent Threats:</strong> "Act now or lose your account" messages</li>
            <li><strong>Too Good to Be True:</strong> Unrealistic offers or prizes</li>
          </ul>

          <h2>🛡️ How to Stay Protected</h2>
          <div class="tip">
            <ul>
              <li><strong>Always verify URLs</strong> before entering sensitive information</li>
              <li><strong>Use two-factor authentication</strong> whenever possible</li>
              <li><strong>Keep browsers updated</strong> with latest security patches</li>
              <li><strong>Trust your instincts</strong> - if something feels wrong, it probably is</li>
              <li><strong>Use tools like PhishGuard Pro</strong> for real-time protection</li>
            </ul>
          </div>

          <h2>📞 What to Do If You're Victimized</h2>
          <ul>
            <li>Immediately change passwords on affected accounts</li>
            <li>Contact your bank and credit card companies</li>
            <li>Run a full antivirus scan on your device</li>
            <li>Monitor your accounts for suspicious activity</li>
            <li>Report the incident to relevant authorities</li>
          </ul>

          <button class="close-btn" onclick="window.close()">Close</button>
        </div>
      </body>
      </html>
    `);
  }

  showNotification(message) {
    // Create a temporary notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      left: 50%;
      transform: translateX(-50%);
      background: #4caf50;
      color: white;
      padding: 10px 20px;
      border-radius: 5px;
      font-size: 12px;
      z-index: 10000;
      box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.remove();
    }, 3000);
  }

  showLoading() {
    document.getElementById('loading').style.display = 'block';
    document.getElementById('statusSection').style.opacity = '0.5';
  }

  hideLoading() {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('statusSection').style.opacity = '1';
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new PopupInterface();
});