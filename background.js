// background.js for PhishGuard Pro with heuristic + dataset layered check

class DynamicBenignManager {
  constructor() {
    this.benignData = new Set();
    this.cacheExpiry = 24 * 60 * 60 * 1000; // 24 hours
    // Set your API endpoint and key here:
    this.apiEndpoint = null; // Set to null to use fallback data only
    this.apiKey = 'AIzaSyBRAURluW18zAoKggEcVB16azODh1ohiks'; // Google Safe Browsing API key
  }

  async initialize() {
    await this.loadBenignData();
  }

  async loadBenignData() {
    // Force reload from source (disable cache for debugging)
    console.log('Force loading benign data from source...');
    await this.fetchFromAPI();
  }

  async fetchFromAPI() {
    // If no API endpoint configured, skip API fetch and load fallback
    if (!this.apiEndpoint) {
      console.log('No API endpoint configured, loading fallback data...');
      await this.loadFallbackData();
      return;
    }

    try {
      console.log('Fetching benign data from API...');
      const response = await fetch(this.apiEndpoint, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
          'User-Agent': 'PhishGuard-Extension/1.0'
        }
      });

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();

      if (data && data.websites && Array.isArray(data.websites)) {
        this.benignData = new Set(data.websites.map(url => {
          try {
            return new URL(url).hostname;
          } catch (error) {
            console.warn('Invalid URL in API response:', url);
            return null;
          }
        }).filter(hostname => hostname !== null));

        console.log('Benign data loaded from API:', this.benignData.size, 'entries');

        // Cache the data
        await this.cacheData(data.websites);
      } else {
        throw new Error('Invalid API response format');
      }

    } catch (error) {
      console.error('API fetch failed:', error);
      await this.loadFallbackData();
    }
  }

  async updateFromAPI() {
    // Skip background updates if no API endpoint configured
    if (!this.apiEndpoint) {
      return;
    }

    // Background update without blocking
    try {
      const response = await fetch(`${this.apiEndpoint}?since=${Date.now()}`, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'User-Agent': 'PhishGuard-Extension/1.0'
        }
      });

      if (response.ok) {
        const updates = await response.json();
        if (updates && updates.websites) {
          console.log('Background update received:', updates.websites.length, 'websites');
          await this.applyUpdates(updates);
        }
      }
    } catch (error) {
      // Silent failure for background updates
      console.log('Background update failed, will retry later');
    }
  }

  async applyUpdates(updates) {
    if (updates.websites && Array.isArray(updates.websites)) {
      const newHostnames = updates.websites.map(url => {
        try {
          return new URL(url).hostname;
        } catch (error) {
          return null;
        }
      }).filter(hostname => hostname !== null);

      // Update the set
      this.benignData = new Set([...this.benignData, ...newHostnames]);
      console.log('Applied updates, new benign count:', this.benignData.size);

      // Update cache
      await this.cacheData([...this.benignData]);
    }
  }

  isCacheValid(timestamp) {
    return (Date.now() - timestamp) < this.cacheExpiry;
  }

  async getCachedData() {
    return new Promise(resolve => {
      chrome.storage.local.get(['benignCache'], result => {
        resolve(result.benignCache);
      });
    });
  }

  async cacheData(data) {
    const cacheEntry = {
      data: data,
      timestamp: Date.now()
    };
    await chrome.storage.local.set({ benignCache: cacheEntry });
  }

  async loadFallbackData() {
    console.log('Loading fallback benign data...');

    try {
      // Try to load from benign.json first
      const response = await fetch(chrome.runtime.getURL('benign.json'));
      const data = await response.json();

      if (Array.isArray(data)) {
        // Extract hostnames from URLs and normalize them
        const hostnames = data.map(url => {
          try {
            const hostname = new URL(url).hostname;
            // Remove 'www.' prefix for better matching
            return hostname.replace(/^www\./, '');
          } catch (error) {
            console.warn('Invalid URL in benign.json:', url);
            return null;
          }
        }).filter(hostname => hostname !== null);

        this.benignData = new Set(hostnames);
        console.log('Benign data loaded from benign.json:', this.benignData.size, 'entries');
        console.log('Sample benign domains:', Array.from(this.benignData).slice(0, 5));
        return;
      }
    } catch (error) {
      console.warn('Failed to load benign.json, using hardcoded fallback:', error);
    }

    // Fallback to hardcoded list if benign.json fails
    const fallback = [
      'google.com',
      'youtube.com',
      'facebook.com',
      'amazon.com',
      'wikipedia.org',
      'github.com',
      'microsoft.com',
      'apple.com',
      'twitter.com',
      'instagram.com',
      'linkedin.com',
      'reddit.com',
      'netflix.com'
    ];
    this.benignData = new Set(fallback);
    console.log('Fallback benign data loaded:', this.benignData.size, 'entries');
  }

  async isBenignViaGoogleSafeBrowsing(url) {
    // Google Safe Browsing API v4 endpoint
    const apiKey = this.apiKey;
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    const body = {
      client: {
        clientId: "phishguard-extension",
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (!response.ok) throw new Error('Safe Browsing API error: ' + response.status);
      const result = await response.json();
      // If no matches, treat as benign
      return !result.matches;
    } catch (error) {
      console.error('Safe Browsing API error:', error);
      // On error, fallback to not benign
      return false;
    }
  }

  async isBenign(hostname) {
    if (!hostname) return false;

    // Normalize hostname (remove www. prefix)
    const normalizedHostname = hostname.replace(/^www\./, '');
    const url = `http://${normalizedHostname}`;

    // Use Google Safe Browsing API for verification
    return await this.isBenignViaGoogleSafeBrowsing(url);
  }

  getStats() {
    return {
      totalWebsites: this.benignData.size,
      sample: Array.from(this.benignData).slice(0, 10)
    };
  }
}

class PhishingDatabase {
  constructor() {
    this.phishingData = new Map();
    this.benignManager = new DynamicBenignManager();
    this.loadDatabase();
  }

  async loadDatabase() {
    // Initialize dynamic benign manager
    await this.benignManager.initialize();

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

    // Malware and dangerous site patterns - more specific to avoid false positives
    const malwarePatterns = [
      /malware|virus|trojan|ransomware|spyware|malicious/, // Direct malware keywords in domain
      /download.*\.exe|\.exe.*download/i,        // Executable downloads
      /crack|keygen|patch|hack/i,                // Piracy/crack sites
      /free.*money|easy.*money|get.*rich/i,      // Money scams
      /win.*prize|lucky.*winner/i,               // Prize scams
      /urgent.*action|immediate.*response/i,     // Urgent action scams
      /suspicious|dangerous|threat/i,            // Self-descriptive dangerous sites
      /testsafebrowsing|safebrowsing.*test/i,    // Test sites for safe browsing
      /phishing.*test|test.*phishing/i,          // Phishing test sites
      /malware.*test|test.*malware/i,            // Malware test sites
      /malicious.*test|test.*malicious/i,        // Malicious test sites
      /unsafe|infected|hacked/i,                 // Sites that admit to being unsafe (only in domain)
      /drive-by|exploit|vulnerability/i,         // Exploit-related sites (only in domain)
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

    // Check malware patterns first (higher priority) - only check hostname for content-based patterns
    for (const pattern of malwarePatterns) {
      // For content-based patterns that might cause false positives, only check hostname
      const contentPatterns = [/unsafe|infected|hacked/i, /drive-by|exploit|vulnerability/i];
      const isContentPattern = contentPatterns.some(cp => cp.source === pattern.source);

      if (isContentPattern) {
        // Only flag if the pattern is in the hostname/domain itself, not in the full URL
        if (pattern.test(hostname)) {
          return {
            phish_id: 'heuristic',
            url: hostname,
            target: 'Malware',
            verified: 'heuristic',
            online: 'yes',
            risk_level: 'critical',
            threat_type: 'malware',
            reason: `Malware pattern detected in domain: ${pattern}`
          };
        }
      } else {
        // For other patterns, check both hostname and full URL
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
      // 1) Check if URL uses insecure HTTP (not HTTPS) - flag as unsafe
      if (url.startsWith('http://')) {
        return {
          phish_id: 'protocol',
          url: new URL(url).hostname,
          target: 'Security',
          verified: 'protocol',
          online: 'yes',
          risk_level: 'high',
          threat_type: 'insecure',
          reason: 'Insecure HTTP connection - data transmitted unencrypted'
        };
      }

      const hostname = new URL(url).hostname;

      // 2) Check for suspicious content in benign domains (like Google Play with malware app names)
      const benignButSuspicious = await this.checkBenignDomainSuspiciousContent(hostname, url);
      if (benignButSuspicious) return benignButSuspicious;

      // 3) Check if hostname is in benign dataset - whitelist
      if (this.benignManager.isBenign(hostname)) {
        return null; // Safe
      }

      // 4) For HTTPS URLs: Fast heuristic check — quickly detect obvious threats
      const heuristicThreat = await this.heuristicCheck(hostname, url);
      if (heuristicThreat) return heuristicThreat;

      // 5) Dataset verification — exact hostname match or subdomain match
      if (this.phishingData.has(hostname)) {
        return this.phishingData.get(hostname);
      }

      // Check for subdomain matches (e.g., if data.json has "example.com", match "sub.example.com")
      for (let [knownUrl, data] of this.phishingData) {
        if (hostname === knownUrl || hostname.endsWith('.' + knownUrl)) {
          return data;
        }
      }

      // URL not in dataset and no heuristic match = safe
      return null;
    } catch (error) {
      console.error('URL check error:', error);
      return null;
    }
  }

  async checkBenignDomainSuspiciousContent(hostname, fullUrl) {
    // Check for suspicious app names in Google Play Store URLs
    if (hostname === 'play.google.com' || hostname.endsWith('.play.google.com')) {
      const urlObj = new URL(fullUrl);
      const appId = urlObj.searchParams.get('id');

      if (appId) {
        const suspiciousAppPatterns = [
          /testvirus|testmalware|fakevirus/i,
          /virus|malware|trojan|ransomware/i,
          /hack|crack|keygen/i,
          /spyware|adware/i,
          /fake|dummy|test.*virus/i
        ];

        for (const pattern of suspiciousAppPatterns) {
          if (pattern.test(appId)) {
            return {
              phish_id: 'suspicious_app',
              url: hostname,
              target: 'Android App',
              verified: 'heuristic',
              online: 'yes',
              risk_level: 'high',
              threat_type: 'suspicious_app',
              reason: `Suspicious app name detected in Google Play: ${appId}`
            };
          }
        }
      }
    }

    // Check for suspicious content in other benign domains
    const benignDomainsWithPathChecks = [
      'github.com',
      'gitlab.com',
      'bitbucket.org'
    ];

    if (benignDomainsWithPathChecks.some(domain => hostname === domain || hostname.endsWith('.' + domain))) {
      const suspiciousPathPatterns = [
        /malware|virus|trojan|hacker/i,
        /exploit|vulnerability/i,
        /phishing|scam/i
      ];

      for (const pattern of suspiciousPathPatterns) {
        if (pattern.test(fullUrl)) {
          return {
            phish_id: 'suspicious_content',
            url: hostname,
            target: 'Repository',
            verified: 'heuristic',
            online: 'yes',
            risk_level: 'medium',
            threat_type: 'suspicious_content',
            reason: `Suspicious content detected in repository URL`
          };
        }
      }
    }

    return null;
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
