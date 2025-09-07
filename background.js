// background.js for PhishGuard Pro with heuristic + dataset layered check

class PhishingDatabase {
  constructor() {
    this.phishingData = new Map();
    this.loadDatabase();
  }

  async loadDatabase() {
    try {
      // Load phishing dataset from local data.json file
      const response = await fetch(chrome.runtime.getURL('data.json'));
      const data = await response.json();

      this.phishingData = new Map();
      data.forEach(entry => this.phishingData.set(entry.url, entry));

      console.log('Phishing database loaded from local data.json:', this.phishingData.size, 'entries');
    } catch (error) {
      console.error('Failed to load phishing database from local data.json:', error);
      // Optional fallback sample data
      const sampleData = [
        {
          phish_id: 1,
          url: "malicious-bank-site.com",
          phish_detail_url: "http://openphish.com/phish_detail.html?id=1",
          submission_time: "2024-01-01T10:00:00Z",
          verified: "yes",
          verification_time: "2024-01-01T11:00:00Z",
          online: "yes",
          target: "Banking"
        }
      ];
      this.phishingData = new Map();
      sampleData.forEach(entry => this.phishingData.set(entry.url, entry));
      console.log('Sample phishing database loaded');
    }
  }

  async heuristicCheck(hostname, fullUrl) {
    const suspiciousPatterns = [
      /\b(\d{1,3}\.){3}\d{1,3}\b/,               // IP addresses
      /[a-z]+-[a-z]+-[a-z]+\.(tk|ml|ga|cf|xyz|top|club|online|site|store|tech|live|icu|work|click|link)/,    // Suspicious TLDs (expanded)
      /-secure-|security-|verify-|update-|login-|signin-|account-|banking-|paypal-|amazon-|google-/,      // Keywords common in phishing
      /[a-z]{25,}/,                              // Very long subdomains
      /secure\d+/,                               // Numbers in domain names
      /paypa1|goog1e|amaz0n|netfl1x|faceb00k/,   // Leet speak phishing domains
      /login\./,                                 // Direct login subdomains
      /verify\./,                                // Direct verify subdomains
      /secure\./,                                // Direct secure subdomains
      /account\./,                               // Direct account subdomains
      /update\./,                                // Direct update subdomains
      /support\./,                               // Direct support subdomains
      /help\./,                                  // Direct help subdomains
    ];

    // Malware and dangerous site patterns
    const malwarePatterns = [
      /malware|virus|trojan|ransomware|spyware/, // Direct malware keywords
      /download.*\.exe|\.exe.*download/i,        // Executable downloads
      /crack|keygen|patch|hack/i,                // Piracy/crack sites
      /free.*money|easy.*money|get.*rich/i,      // Money scams
      /win.*prize|lucky.*winner/i,               // Prize scams
      /urgent.*action|immediate.*response/i,     // Urgent action scams
      /suspicious|dangerous|threat/i,            // Self-descriptive dangerous sites
      /testsafebrowsing|safebrowsing.*test/i,    // Test sites for safe browsing
      /phishing.*test|test.*phishing/i,          // Phishing test sites
      /malware.*test|test.*malware/i,            // Malware test sites
      /unsafe|infected|hacked/i,                 // Sites that admit to being unsafe
      /drive-by|exploit|vulnerability/i,         // Exploit-related sites
    ];

    // Additional checks for HTTPS sites
    const isHttps = fullUrl.startsWith('https://');
    if (isHttps) {
      const httpsPatterns = [
        /https?:\/\/[^\.]+\.[^\.]+\.[^\.]+/,     // Triple-level domains (suspicious)
        /https?:\/\/.*\d{4,}/,                   // Domains with long numbers
        /https?:\/\/.*-{2,}/,                    // Multiple hyphens
        /https?:\/\/.*\.{2,}/,                   // Multiple dots
        /https?:\/\/.*_/,                        // Underscores in domain
      ];

      suspiciousPatterns.push(...httpsPatterns);
    }

    // Check for recently registered TLDs that are commonly abused
    const recentAbusedTLDs = ['.app', '.dev', '.page', '.site', '.online', '.store', '.tech', '.live', '.icu', '.work', '.click', '.link', '.club', '.top', '.xyz'];
    for (const tld of recentAbusedTLDs) {
      if (hostname.endsWith(tld)) {
        // Additional scrutiny for these TLDs
        if (hostname.length > 15 || hostname.split('.').length > 2) {
          return {
            phish_id: 'heuristic',
            url: hostname,
            target: 'Malware',
            verified: 'heuristic',
            online: 'yes',
            risk_level: 'high',
            threat_type: 'malware',
            reason: `Suspicious TLD with malware indicators: ${tld}`
          };
        }
      }
    }

    // Check malware patterns first (higher priority)
    for (const pattern of malwarePatterns) {
      if (pattern.test(hostname) || pattern.test(fullUrl)) {
        return {
          phish_id: 'heuristic',
          url: hostname,
          target: 'Malware',
          verified: 'heuristic',
          online: 'yes',
          risk_level: 'critical',
          threat_type: 'malware',
          reason: `Malware pattern detected: ${pattern}`
        };
      }
    }

    // Check suspicious patterns
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(hostname) || pattern.test(fullUrl)) {
        return {
          phish_id: 'heuristic',
          url: hostname,
          target: 'Unknown',
          verified: 'heuristic',
          online: 'yes',
          risk_level: 'medium',
          threat_type: 'suspicious',
          reason: `Pattern match: ${pattern}`
        };
      }
    }

    return null;
  }

  async checkUrl(url) {
    try {
      const hostname = new URL(url).hostname;

      // 1) Heuristic check — quickly detect suspicious patterns
      const heuristicThreat = await this.heuristicCheck(hostname, url);
      if (heuristicThreat) return heuristicThreat;

      // 2) Dataset check — exact or subdomain match
      if (this.phishingData.has(hostname)) {
        return this.phishingData.get(hostname);
      }
      for (let [knownUrl, data] of this.phishingData) {
        if (hostname === knownUrl || hostname.endsWith('.' + knownUrl)) {
          return data;
        }
      }

      return null;
    } catch (error) {
      console.error('URL check error:', error);
      return null;
    }
  }
}

const phishingDB = new PhishingDatabase();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId === 0) {
    const threat = await phishingDB.checkUrl(details.url);
    if (threat) {
      await chrome.storage.session.set({
        [`threat_${details.tabId}`]: {
          ...threat,
          currentUrl: details.url,
          timestamp: Date.now(),
        },
      });
    } else {
      // Clear threat data if no threat detected for this URL
      await chrome.storage.session.remove(`threat_${details.tabId}`);
    }
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.type) {
    case 'CHECK_URL':
      phishingDB.checkUrl(request.url)
        .then(result => sendResponse({ threat: result }))
        .catch(error => sendResponse({ error: error.message }));
      return true; // async response

    case 'REPORT_BLOCKED':
      console.log('Keylogger blocked on:', sender.tab?.url);
      break;

    case 'USER_EDUCATED':
      chrome.storage.local.get(['educationStats'], result => {
        let stats = result.educationStats || { totalEducated: 0, byTarget: {} };
        stats.totalEducated++;
        stats.byTarget[request.target] = (stats.byTarget[request.target] || 0) + 1;
        chrome.storage.local.set({ educationStats: stats });
      });
      break;

    case 'GET_SESSION_THREAT':
      chrome.storage.session.get(`threat_${request.tabId}`).then(result => {
        sendResponse({ threat: result[`threat_${request.tabId}`] || null });
      });
      return true;

    case 'GET_TAB_ID':
      sendResponse({ tabId: sender.tab ? sender.tab.id : null });
      return true;

    default:
      break;
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const threat = await chrome.storage.session.get(`threat_${activeInfo.tabId}`);
  if (threat[`threat_${activeInfo.tabId}`]) {
    chrome.action.setBadgeText({ text: '!', tabId: activeInfo.tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#ff4444' });
  } else {
    chrome.action.setBadgeText({ text: '', tabId: activeInfo.tabId });
  }
});
