// Modern popup interface with enhanced animations
class ModernPopupInterface {
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
    await this.checkReportedStatus();
    this.setupEventListeners();
    this.setupToggles();
    this.hideLoading();
    this.setupInteractiveElements();
  }

  setupInteractiveElements() {
    // Add ripple effect to buttons
    document.querySelectorAll('.btn').forEach(btn => {
      btn.addEventListener('click', this.createRipple.bind(this));
    });

    // Add hover sound effect simulation
    document.querySelectorAll('.stat-card').forEach(card => {
      card.addEventListener('mouseenter', () => {
        card.style.transform = 'translateY(-6px) scale(1.02)';
      });
      card.addEventListener('mouseleave', () => {
        card.style.transform = 'translateY(0) scale(1)';
      });
    });

    // Animate numbers on load
    this.animateNumbers();
  }

  createRipple(event) {
    const button = event.currentTarget;
    const ripple = document.createElement('span');
    const rect = button.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = event.clientX - rect.left - size / 2;
    const y = event.clientY - rect.top - size / 2;

    ripple.style.cssText = `
      position: absolute;
      width: ${size}px;
      height: ${size}px;
      left: ${x}px;
      top: ${y}px;
      background: rgba(255, 255, 255, 0.5);
      border-radius: 50%;
      transform: scale(0);
      animation: ripple 0.6s linear;
      pointer-events: none;
    `;

    const style = document.createElement('style');
    style.textContent = `
      @keyframes ripple {
        to {
          transform: scale(2);
          opacity: 0;
        }
      }
    `;
    document.head.appendChild(style);

    button.appendChild(ripple);
    setTimeout(() => {
      ripple.remove();
      style.remove();
    }, 600);
  }

  animateNumbers() {
    const animateNumber = (element, target, duration = 1000) => {
      const start = 0;
      const startTime = performance.now();

      const updateNumber = (currentTime) => {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easeOutCubic = 1 - Math.pow(1 - progress, 3);
        const current = Math.floor(easeOutCubic * target);
        
        element.textContent = current;

        if (progress < 1) {
          requestAnimationFrame(updateNumber);
        }
      };

      requestAnimationFrame(updateNumber);
    };

    setTimeout(() => {
      animateNumber(document.getElementById('threatsBlocked'), this.stats.threatsBlocked, 800);
      animateNumber(document.getElementById('sitesChecked'), this.stats.sitesChecked, 1000);
    }, 600);
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
      const response = await new Promise(resolve => {
        chrome.runtime.sendMessage({ type: 'CHECK_URL', url: this.currentTab.url }, resolve);
      });

      if (response && response.threat) {
        this.threatInfo = response.threat;
        this.showThreatDetected();
      } else {
        this.showSafeStatus();
      }

      const result = await chrome.storage.local.get('sitesChecked');
      let sitesChecked = result.sitesChecked || 0;
      sitesChecked++;
      chrome.storage.local.set({ sitesChecked: sitesChecked });
      this.stats.sitesChecked = sitesChecked;

      this.updateStatsDisplay();

    } catch (error) {
      console.error('Site check failed:', error);
      this.showErrorStatus();
    }
  }

  async checkReportedStatus() {
    if (!this.currentTab) return;

    try {
      const result = await chrome.storage.local.get('reportedSites');
      const reportedSites = result.reportedSites || [];
      this.isReported = reportedSites.includes(this.currentTab.url);

      this.updateReportButton();
    } catch (error) {
      console.error('Failed to check reported status:', error);
    }
  }

  showThreatDetected() {
    const statusIndicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');
    const statusDetails = document.getElementById('statusDetails');
    const threatInfo = document.getElementById('threatInfo');
    const actionButtons = document.getElementById('actionButtons');
    const threatActions = document.getElementById('threatActions');

    statusIndicator.textContent = '🚨';
    statusIndicator.classList.add('threat');
    
    statusText.textContent = 'Threat Detected!';
    statusText.style.color = '#dc2626';
    statusDetails.textContent = 'This site has been identified as potentially malicious';

    document.getElementById('threatTarget').textContent = this.threatInfo.target || 'Unknown';
    document.getElementById('threatStatus').textContent = 
      this.threatInfo.verified === 'yes' ? '✓ Verified' : '⚠️ Suspected';
    document.getElementById('threatRisk').textContent = this.threatInfo.risk_level ? this.threatInfo.risk_level.toUpperCase() : 'UNKNOWN';
    
    threatInfo.classList.add('show');
    actionButtons.style.display = 'none';
    threatActions.style.display = 'flex';

    chrome.storage.local.get('threatsBlocked', (result) => {
      let threatsBlocked = result.threatsBlocked || 0;
      threatsBlocked++;
      chrome.storage.local.set({ threatsBlocked: threatsBlocked });
      this.stats.threatsBlocked = threatsBlocked;
      this.updateStatsDisplay();
    });
  }

  showSafeStatus() {
    const statusIndicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');
    const statusDetails = document.getElementById('statusDetails');
    
    // Hide threat info if it was previously visible
    const threatInfo = document.getElementById('threatInfo');
    const actionButtons = document.getElementById('actionButtons');
    const threatActions = document.getElementById('threatActions');

    threatInfo.classList.remove('show');
    actionButtons.style.display = 'flex';
    threatActions.style.display = 'none';

    statusIndicator.textContent = '🛡️';
    statusIndicator.classList.remove('threat');
    statusText.textContent = 'Site is Safe';
    statusText.style.color = '#059669';
    statusDetails.textContent = 'No threats detected on this website';
  }

  showErrorStatus() {
    const statusIndicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');
    const statusDetails = document.getElementById('statusDetails');

    statusIndicator.textContent = '❓';
    statusText.textContent = 'Unable to Check';
    statusText.style.color = '#d97706';
    statusDetails.textContent = 'Could not analyze this website';
  }

  updateStatsDisplay() {
    document.getElementById('threatsBlocked').textContent = this.stats.threatsBlocked;
    document.getElementById('sitesChecked').textContent = this.stats.sitesChecked;
  }

  updateReportButton() {
    const reportBtn = document.getElementById('reportSite') || document.getElementById('unreportSite');
    if (!reportBtn) return; // Safety check
    if (this.isReported) {
      reportBtn.innerHTML = '🚩 Unreport This Site';
      reportBtn.id = 'unreportSite';
    } else {
      reportBtn.innerHTML = '🚩 Report This Site';
      reportBtn.id = 'reportSite';
    }
  }

  setupEventListeners() {
    // Scan current site
    document.getElementById('scanNow')?.addEventListener('click', async () => {
      this.showLoading();
      await this.checkCurrentSite();
      this.hideLoading();
    });

    // Report site
    document.getElementById('reportSite')?.addEventListener('click', () => {
      this.reportCurrentSite();
    });

    // Unreport site
    document.getElementById('unreportSite')?.addEventListener('click', () => {
      this.unreportCurrentSite();
    });

    // Leave site (for threats)
    document.getElementById('leaveSite')?.addEventListener('click', () => {
      if (this.currentTab) {
        // Redirect to a safe page (e.g., new tab with safe URL)
        this.showNotification('Redirecting to a safe page...');
        chrome.tabs.update(this.currentTab.id, { url: 'https://www.google.com' }, () => {
          window.close();
        });
      }
    });

    // Mark as safe (for threats)
    document.getElementById('markSafe')?.addEventListener('click', () => {
      this.markCurrentSiteSafe();
    });

    // Learn more (for threats)
    document.getElementById('learnMore')?.addEventListener('click', () => {
      this.showEducationalContent();
    });

    // Toggle switches
    document.getElementById('realTimeToggle')?.addEventListener('click', (e) => {
      this.toggleSetting(e.target, 'realTimeProtection');
    });

    document.getElementById('keyloggerToggle')?.addEventListener('click', (e) => {
      this.toggleSetting(e.target, 'keyloggerBlocking');
    });

    document.getElementById('educationToggle')?.addEventListener('click', (e) => {
      this.toggleSetting(e.target, 'educationalAlerts');
    });
  }

  async setupToggles() {
    try {
      const result = await chrome.storage.local.get([
        'realTimeProtection', 
        'keyloggerBlocking', 
        'educationalAlerts'
      ]);

      this.updateToggle('realTimeToggle', result.realTimeProtection !== false);
      this.updateToggle('keyloggerToggle', result.keyloggerBlocking !== false);
      this.updateToggle('educationToggle', result.educationalAlerts !== false);
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
    } catch (error) {
      console.error('Failed to save setting:', error);
    }

    // Add haptic feedback simulation
    this.addToggleFeedback(toggle);
    
    // Show notification
    const status = isActive ? 'enabled' : 'disabled';
    this.showNotification(`${settingName.replace(/([A-Z])/g, ' $1').toLowerCase()} ${status}`);
  }

  addToggleFeedback(toggle) {
    toggle.style.transform = 'scale(0.95)';
    setTimeout(() => {
      toggle.style.transform = 'scale(1)';
    }, 150);
  }

  reportCurrentSite() {
    if (!this.currentTab) return;

    // Show reporting animation
    const reportBtn = document.getElementById('reportSite');
    const originalText = reportBtn.innerHTML;
    reportBtn.innerHTML = '⏳ Reporting...';
    reportBtn.disabled = true;

    setTimeout(async () => {
      reportBtn.innerHTML = '✅ Reported';
      await this.addReportedSite(this.currentTab.url);
      this.isReported = true;
      this.updateReportButton();
      setTimeout(() => {
        reportBtn.innerHTML = originalText;
        reportBtn.disabled = false;
      }, 2000);
    }, 1500);

    this.showNotification('Site reported successfully! Thank you for helping keep others safe.');
  }

  showEducationalContent() {
    // Create modern educational modal
    const modal = document.createElement('div');
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.8);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
      animation: fadeIn 0.3s ease;
    `;

    modal.innerHTML = `
      <div style="
        background: white;
        border-radius: 20px;
        padding: 30px;
        max-width: 500px;
        max-height: 80vh;
        overflow-y: auto;
        margin: 20px;
        box-shadow: 0 25px 50px rgba(0,0,0,0.3);
      ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
          <h2 style="margin: 0; color: #1f2937; font-size: 24px;">🎓 Phishing Education</h2>
          <button onclick="this.closest('div').remove()" style="
            background: #ef4444;
            color: white;
            border: none;
            border-radius: 50%;
            width: 32px;
            height: 32px;
            cursor: pointer;
            font-size: 16px;
          ">×</button>
        </div>
        
        <div style="background: #fee2e2; padding: 15px; border-radius: 12px; margin-bottom: 20px; border-left: 4px solid #ef4444;">
          <strong>⚠️ Current Threat:</strong> You're viewing information about a ${this.threatInfo?.target || 'phishing'} scam.
        </div>

        <h3 style="color: #ef4444; margin-bottom: 15px;">🎣 How This Attack Works</h3>
        <ul style="margin-bottom: 20px; line-height: 1.6;">
          <li>Mimicked a legitimate ${this.threatInfo?.target || 'service'} website</li>
          <li>Would steal your login credentials when entered</li>
          <li>Could install malware on your device</li>
          <li>Might use your information for identity theft</li>
        </ul>

        <h3 style="color: #ef4444; margin-bottom: 15px;">🚩 Warning Signs</h3>
        <ul style="margin-bottom: 20px; line-height: 1.6;">
          <li><strong>Suspicious URLs:</strong> Check for misspellings</li>
          <li><strong>No HTTPS:</strong> Look for the lock icon</li>
          <li><strong>Poor Design:</strong> Low-quality graphics</li>
          <li><strong>Urgent Threats:</strong> "Act now" messages</li>
        </ul>

        <div style="background: #d1fae5; padding: 15px; border-radius: 12px; border-left: 4px solid: #10b981;">
          <h3 style="color: #059669; margin: 0 0 10px 0;">🛡️ Stay Protected</h3>
          <ul style="margin: 0; line-height: 1.6;">
            <li>Always verify URLs before entering info</li>
            <li>Use two-factor authentication</li>
            <li>Keep browsers updated</li>
            <li>Trust your instincts</li>
          </ul>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    // Remove modal when clicking outside
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
  }

  showNotification(message) {
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: linear-gradient(135deg, #10b981 0%, #059669 100%);
      color: white;
      padding: 12px 20px;
      border-radius: 12px;
      font-size: 14px;
      font-weight: 600;
      z-index: 10001;
      box-shadow: 0 8px 20px rgba(16, 185, 129, 0.3);
      animation: slideInRight 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      max-width: 300px;
      pointer-events: auto;
      cursor: pointer;
    `;

    const style = document.createElement('style');
    style.textContent = `
      @keyframes slideInRight {
        from {
          transform: translateX(100%);
          opacity: 0;
        }
        to {
          transform: translateX(0);
          opacity: 1;
        }
      }
      @keyframes fadeOut {
        to {
          transform: translateX(100%);
          opacity: 0;
        }
      }
    `;
    document.head.appendChild(style);

    notification.textContent = message;
    document.body.appendChild(notification);

    // Allow user to click to dismiss immediately
    notification.addEventListener('click', () => {
      notification.style.animation = 'fadeOut 0.4s cubic-bezier(0.4, 0, 0.2, 1)';
      setTimeout(() => {
        notification.remove();
        style.remove();
      }, 400);
    });
    
    setTimeout(() => {
      notification.style.animation = 'fadeOut 0.4s cubic-bezier(0.4, 0, 0.2, 1)';
      setTimeout(() => {
        notification.remove();
        style.remove();
      }, 400);
    }, 3000);
  }

  async addReportedSite(url) {
    try {
      const result = await chrome.storage.local.get('reportedSites');
      const reportedSites = result.reportedSites || [];
      if (!reportedSites.includes(url)) {
        reportedSites.push(url);
        await chrome.storage.local.set({ reportedSites });
      }
    } catch (error) {
      console.error('Failed to add reported site:', error);
    }
  }

  async removeReportedSite(url) {
    try {
      const result = await chrome.storage.local.get('reportedSites');
      const reportedSites = result.reportedSites || [];
      const updatedSites = reportedSites.filter(site => site !== url);
      await chrome.storage.local.set({ reportedSites: updatedSites });
    } catch (error) {
      console.error('Failed to remove reported site:', error);
    }
  }

  async addSafeSite(url) {
    try {
      const result = await chrome.storage.local.get('safeSites');
      const safeSites = result.safeSites || [];
      if (!safeSites.includes(url)) {
        safeSites.push(url);
        await chrome.storage.local.set({ safeSites });
      }
    } catch (error) {
      console.error('Failed to add safe site:', error);
    }
  }

  unreportCurrentSite() {
    if (!this.currentTab) return;

    // Show unreporting animation
    const unreportBtn = document.getElementById('unreportSite');
    const originalText = unreportBtn.innerHTML;
    unreportBtn.innerHTML = '⏳ Unreporting...';
    unreportBtn.disabled = true;

    setTimeout(async () => {
      unreportBtn.innerHTML = '✅ Unreported';
      await this.removeReportedSite(this.currentTab.url);
      this.isReported = false;
      this.updateReportButton();
      setTimeout(() => {
        unreportBtn.innerHTML = originalText;
        unreportBtn.disabled = false;
      }, 2000);
    }, 1500);

    this.showNotification('Site unreported successfully!');
  }

  markCurrentSiteSafe() {
    if (!this.currentTab) return;

    // Show marking animation
    const markSafeBtn = document.getElementById('markSafe');
    const originalText = markSafeBtn.innerHTML;
    markSafeBtn.innerHTML = '⏳ Marking...';
    markSafeBtn.disabled = true;

    setTimeout(async () => {
      markSafeBtn.innerHTML = '✅ Marked Safe';
      await this.addSafeSite(this.currentTab.url);
      // Remove from reported if it was reported
      await this.removeReportedSite(this.currentTab.url);
      this.isReported = false;
      this.updateReportButton();
      // Recheck the site status
      await this.checkCurrentSite();
      setTimeout(() => {
        markSafeBtn.innerHTML = originalText;
        markSafeBtn.disabled = false;
      }, 2000);
    }, 1500);

    this.showNotification('Site marked as safe! It will no longer be flagged.');
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
  new ModernPopupInterface();
});