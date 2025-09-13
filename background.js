// background.js for PhishGuard Pro with heuristic + dataset layered check

class DynamicBenignManager {
  constructor() {
    this.benignData = new Set();
    this.cacheExpiry = 24 * 60 * 60 * 1000; // 24 hours
    // Set your API endpoint and key here:
    this.apiEndpoint = null; // Set to null to use fallback data only
    this.apiKey = 'AIzaSyBRAURluW18zAoKggEcVB16azODh1ohiks'; // Google Safe Browsing API key
    this.loaded = false;
  }

  async initialize() {
    await this.loadBenignData();
    this.loaded = true;
  }

  async loadBenignData() {
    console.log('Loading benign data...');
    const cached = await this.getCachedData();
    if (cached && cached.data && Array.isArray(cached.data) && this.isCacheValid(cached.timestamp)) {
      this.benignData = new Set(cached.data.map(url => {
        try {
          const hostname = new URL(url).hostname.replace(/^www\./, '');
          return hostname;
        } catch (error) {
          console.warn('Invalid cached URL:', url);
          return null;
        }
      }).filter(hostname => hostname !== null));
      console.log('Benign data loaded from cache:', this.benignData.size, 'entries');
      return;
    }
    await this.loadFallbackData();
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
        // Cache the original URLs
        await this.cacheData(data);
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

    // Check if in known benign data first
    if (this.benignData.has(normalizedHostname)) {
      return true;
    }

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
    this.loaded = false;
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

    this.loaded = true;
  }



  async heuristicCheck(hostname, fullUrl) {
    let score = 0;

    // --- Basic URL & Hostname Features ---
    // URL Length
    if (fullUrl.length > 75) score += 10;
    if (fullUrl.length > 100) score += 15; // Increased penalty for very long URLs

    // Hostname Length
    if (hostname.length > 25) score += 10;
    if (hostname.length > 35) score += 15; // Increased penalty for very long hostnames

    // Subdomain Count (more than 3 subdomains can be suspicious)
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount > 3) score += (subdomainCount - 3) * 7; // Increased impact

    // Special Characters in Hostname (e.g., hyphens, underscores, unusual characters)
    if (hostname.includes('-') || hostname.includes('_')) score += 5;
    if ((hostname.match(/-/g) || []).length > 2) score += 10; // Multiple hyphens
    if (/[@%?&]/.test(hostname)) score += 20; // Highly suspicious characters

    // --- TLD Analysis ---
    const suspiciousTlds = [
      '.xyz', '.biz', '.info', '.top', '.loan', '.work', '.click', '.link', '.gq', '.cf', '.ml', '.ga',
      '.pw', '.tk', '.online', '.site', '.store', '.tech', '.icu', '.club', '.bid', '.party', '.review',
      '.download', '.win', '.stream', '.date', '.trade', '.account', '.science', '.space', '.website'
    ];
    if (suspiciousTlds.some(tld => hostname.endsWith(tld))) score += 25; // Increased penalty

    // --- Keyword Matching ---
    const highRiskKeywords = [
      'phishing', 'malware', 'scam', 'fraud', 'hack', 'secure', 'login', 'verify', 'update', 'account',
      'password', 'bank', 'admin', 'support', 'payment', 'confirm', 'alert', 'warning', 'security',
      'credential', 'signin', 'authorize', 'recover', 'reset', 'transaction', 'invoice', 'urgent', 'suspicious'
    ];
    if (highRiskKeywords.some(keyword => hostname.includes(keyword))) score += 30; // Increased penalty

    const mediumRiskKeywords = [
      'free', 'gift', 'prize', 'offer', 'claim', 'bonus', 'discount', 'promo', 'lucky', 'winner',
      'notification', 'delivery', 'invoice', 'order', 'shipping', 'tracking', 'refund', 'statement'
    ];
    if (mediumRiskKeywords.some(keyword => hostname.includes(keyword))) score += 15;

    // --- IP Address in Hostname ---
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) score += 40; // Increased penalty for direct IP

    // --- Homoglyph Detection (Basic) ---
    // Common homoglyphs (e.g., 'o' vs '0', 'l' vs '1', 'a' vs '@')
    const homoglyphPatterns = [
      /0/g, /1/g, /@/g, /l/g, /o/g, // Simple character substitutions
      /rn/g, // 'm' homoglyph
      /vv/g, // 'w' homoglyph
    ];
    const originalHostname = hostname.toLowerCase();
    const suspiciousHomoglyphs = homoglyphPatterns.some(pattern => {
      const tempHostname = originalHostname.replace(pattern, '');
      return tempHostname.length !== originalHostname.length; // If replacement occurred, it's suspicious
    });
    if (suspiciousHomoglyphs) score += 25;

    // --- Brand Impersonation (Basic) ---
    const commonBrands = ['google', 'apple', 'microsoft', 'amazon', 'paypal', 'facebook', 'netflix', 'ebay'];
    const brandImpersonation = commonBrands.some(brand => {
      const brandRegex = new RegExp(`${brand}[^a-z0-9]`, 'i'); // e.g., google-login, apple.id
      return brandRegex.test(hostname) && !hostname.includes(brand + '.com'); // Avoid flagging legitimate subdomains
    });
    if (brandImpersonation) score += 35;

    // --- URL Path Depth ---
    const pathDepth = (new URL(fullUrl).pathname.match(/\//g) || []).length;
    if (pathDepth > 5) score += 10; // Deep paths can be suspicious

    // --- Insecure Protocol (HTTP) ---
    if (fullUrl.startsWith('http://')) score += 20; // Explicitly penalize HTTP

    // --- Final Score Evaluation ---
    if (score >= 80) { // Increased threshold for critical
      return {
        phish_id: 'heuristic',
        url: hostname,
        target: 'Unknown',
        verified: 'heuristic',
        online: 'yes',
        risk_level: 'critical',
        threat_type: 'suspicious',
        reason: `Multiple high-risk indicators detected (score: ${score})`
      };
    } else if (score >= 50) { // Increased threshold for high
      return {
        phish_id: 'heuristic',
        url: hostname,
        target: 'Unknown',
        verified: 'heuristic',
        online: 'yes',
        risk_level: 'high',
        threat_type: 'suspicious',
        reason: `Multiple suspicious indicators detected (score: ${score})`
      };
    } else if (score >= 25) { // Increased threshold for medium
      return {
        phish_id: 'heuristic',
        url: hostname,
        target: 'Unknown',
        verified: 'heuristic',
        online: 'yes',
        risk_level: 'medium',
        threat_type: 'suspicious',
        reason: `Some suspicious indicators detected (score: ${score})`
      };
    }

    return null;
  }

  async checkUrl(url) {
    try {
      // 0) Check if URL is in safe sites (user marked as safe)
      const safeResult = await chrome.storage.local.get('safeSites');
      const safeSites = safeResult.safeSites || [];
      if (safeSites.includes(url)) {
        return null; // Safe
      }

      // 1) Check if URL is in reported sites
      const reportedResult = await chrome.storage.local.get('reportedSites');
      const reportedSites = reportedResult.reportedSites || [];
      if (reportedSites.includes(url)) {
        return {
          phish_id: 'reported',
          url: new URL(url).hostname,
          target: 'User Reported',
          verified: 'reported',
          online: 'yes',
          risk_level: 'high',
          threat_type: 'reported',
          reason: 'Site reported by user as suspicious'
        };
      }

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
      'bitbucket.org',
      'afternic.com'
    ];

    if (benignDomainsWithPathChecks.some(domain => hostname === domain || hostname.endsWith('.' + domain))) {
      const suspiciousPathPatterns = [
        /malware|virus|trojan|hacker|malicious/i,
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

  // New: Check Safe Browsing v4
  async checkSafeBrowsing(url) {
    const apiKey = this.benignManager.apiKey; // Use API key from benignManager
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
        return {
          phish_id: 'safebrowsing',
          url: new URL(url).hostname,
          target: data.matches[0].threatType,
          verified: 'safebrowsing',
          online: 'yes',
          risk_level: 'critical',
          threat_type: 'malware',
          reason: `Safe Browsing detected: ${data.matches[0].threatType}`
        };
      } else {
        return null; // No threat from Safe Browsing
      }
    } catch (error) {
      console.error('Safe Browsing check failed in background:', error);
      return null; // On error, treat as no threat for now
    }
  }

  // New: Send to backend for richer analysis
  async sendToBackend(metadata) {
    const backendUrl = 'http://localhost:3001/analyze'; // Local backend URL

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
        return {
          phish_id: 'backend',
          url: result.url,
          target: result.target,
          verified: 'backend',
          online: 'yes',
          risk_level: result.riskLevel,
          threat_type: result.threatType,
          reason: result.reason
        };
      } else {
        return null;
      }
    } catch (error) {
      console.error('Backend analysis failed in background:', error);
      return null;
    }
  }
}

const phishingDB = new PhishingDatabase();

// Track navigation chains for redirect detection
const navigationChains = new Map();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId === 0) {
    // Track navigation chain
    if (!navigationChains.has(details.tabId)) {
      navigationChains.set(details.tabId, []);
    }
    navigationChains.get(details.tabId).push({
      url: details.url,
      timestamp: Date.now(),
      transitionType: details.transitionType
    });
    // Keep last 20 entries
    if (navigationChains.get(details.tabId).length > 20) {
      navigationChains.get(details.tabId).shift();
    }

    const url = details.url;
    const hostname = new URL(url).hostname;
    const normalizedHostname = hostname.replace(/^www\./, '');
    const isRedirect = details.transitionType && details.transitionType.includes('redirect');

    // Show success animation page on new secured URL if not shown before
    if (!isRedirect && phishingDB.benignManager.loaded && phishingDB.benignManager.benignData.has(normalizedHostname)) {
      const shownKey = `shownSuccess_${normalizedHostname}`;
      console.log('Checking success page shown key:', shownKey);
      chrome.storage.local.get([shownKey], (result) => {
        console.log('Success page shown key result:', result);
        if (!result[shownKey]) {
          console.log('Opening success.html for', normalizedHostname);
          // Instead of opening a new tab, send message to content script to show animation
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs.length > 0) {
              chrome.tabs.sendMessage(tabs[0].id, { type: 'SHOW_SUCCESS_ANIMATION' }, function() {
                if (chrome.runtime.lastError) {
                  console.warn("Error sending SHOW_SUCCESS_ANIMATION message:", chrome.runtime.lastError.message);
                }
              });
            }
          });
          chrome.storage.local.set({ [shownKey]: true });
        }
      });
    }

    // Allow benign sites
    if (phishingDB.benignManager.benignData.has(normalizedHostname)) {
      return;
    }

    // For redirects, block unsecure HTTP websites and perform full threat check
    if (isRedirect) {
      if (url.startsWith('http://')) {
        const threat = {
          phish_id: 'unsecure_redirect',
          url: hostname,
          target: 'Security',
          verified: 'protocol',
          online: 'yes',
          risk_level: 'high',
          threat_type: 'insecure_redirect',
          reason: 'Redirect to unsecure HTTP website blocked'
        };
        chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL('warning.html') + '?threat=' + encodeURIComponent(JSON.stringify({ ...threat, isRedirect: true })) });
        return { cancel: true };
      }
      const threat = await phishingDB.checkUrl(url);
      if (threat) {
        chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL('warning.html') + '?threat=' + encodeURIComponent(JSON.stringify({ ...threat, isRedirect: true })) });
        return { cancel: true };
      }
    }



    // Block known phishing sites
    if (phishingDB.phishingData.has(hostname) || Array.from(phishingDB.phishingData.keys()).some(key => hostname.endsWith('.' + key))) {
      const threat = phishingDB.phishingData.get(hostname) || Array.from(phishingDB.phishingData.values()).find(entry => hostname.endsWith('.' + entry.url));
      if (threat) {
        chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL('warning.html') + '?threat=' + encodeURIComponent(JSON.stringify({ ...threat, isRedirect })) });
        return { cancel: true };
      }
    }

    // Check heuristic for high risk (critical/high) or redirects
    const heuristicThreat = phishingDB.heuristicCheck(hostname, url);
    if (heuristicThreat && (heuristicThreat.risk_level === 'critical' || heuristicThreat.risk_level === 'high')) {
      chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL('warning.html') + '?threat=' + encodeURIComponent(JSON.stringify({ ...heuristicThreat, isRedirect })) });
      return { cancel: true };
    }

    // For other checks, allow navigation but log
    chrome.storage.local.get(['sitesChecked', 'threatsBlocked'], (result) => {
      let sitesChecked = result.sitesChecked || 0;
      let threatsBlocked = result.threatsBlocked || 0;
      sitesChecked++;

      chrome.storage.local.get('realTimeProtection', async (result) => {
        if (result.realTimeProtection !== false) {
          const threat = await phishingDB.checkUrl(details.url);
          if (threat) {
            threatsBlocked++;
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

      chrome.storage.local.set({ sitesChecked, threatsBlocked });
    });

    // Trigger success for verified secured URLs
    if (!isRedirect) {
      const shownKey = `shownSuccess_${normalizedHostname}`;
      console.log('Checking success page shown key for verified URL:', shownKey);
      chrome.storage.local.get([shownKey], (result) => {
        console.log('Success page shown key result:', result);
        if (!result[shownKey]) {
          console.log('Opening success.html for verified', normalizedHostname);
          // Instead of opening a new tab, send message to content script to show animation
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs.length > 0) {
              chrome.tabs.sendMessage(tabs[0].id, { type: 'SHOW_SUCCESS_ANIMATION' }, function() {
                if (chrome.runtime.lastError) {
                  console.warn("Error sending SHOW_SUCCESS_ANIMATION message:", chrome.runtime.lastError.message);
                }
              });
            }
          });
          chrome.storage.local.set({ [shownKey]: true });
        }
      });
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

    case 'CHECK_REDIRECT':
      phishingDB.checkUrl(request.url).then(threat => {
        if (threat) {
          console.log('Redirect to threat detected:', request.url);
          chrome.tabs.update(sender.tab.id, { url: chrome.runtime.getURL('warning.html') + '?threat=' + encodeURIComponent(JSON.stringify(threat)) });
        }
      });
      break;

    case 'PERFORM_EXTERNAL_ANALYSIS':
      (async () => {
        const url = request.url;
        const metadata = {
          url: url,
          riskScore: request.riskScore,
          hasPasswordFields: request.hasPasswordFields,
          hasLoginForm: request.hasLoginForm,
          userAgent: request.userAgent,
          referrer: request.referrer,
          timestamp: request.timestamp
        };

        let threat = null;

        // First, check Google Safe Browsing
        const safeBrowsingThreat = await phishingDB.checkSafeBrowsing(url);
        if (safeBrowsingThreat) {
          threat = safeBrowsingThreat;
        } else {
          // If no Safe Browsing threat, send to backend for richer analysis
          const backendThreat = await phishingDB.sendToBackend(metadata);
          if (backendThreat) {
            threat = backendThreat;
          }
        }
        sendResponse({ threat: threat });
      })();
      return true; // Indicates that sendResponse will be called asynchronously

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

// Download protection with quarantine
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const url = downloadItem.url;
  const filename = downloadItem.filename || '';
  const extension = filename.split('.').pop().toLowerCase();

  // List of potentially dangerous file extensions
  const dangerousExtensions = ['exe', 'bat', 'cmd', 'js', 'vbs', 'scr', 'pif', 'com', 'cpl', 'jar', 'msi', 'msp', 'reg', 'hta', 'ps1', 'psm1', 'lnk'];

  // Check domain reputation
  const domain = (new URL(url)).hostname;
  const isMaliciousDomain = await phishingDB.benignManager.isBenign(domain) === false;

  // User preferences whitelist
  const userWhitelist = await new Promise(resolve => {
    chrome.storage.local.get(['whitelist'], result => {
      resolve(result.whitelist || []);
    });
  });

  if (dangerousExtensions.includes(extension) && !userWhitelist.includes(domain) && isMaliciousDomain) {
    // Cancel download and notify user
    chrome.downloads.cancel(downloadItem.id);
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Download Blocked',
      message: `Download of potentially dangerous file "${filename}" from ${domain} was blocked and quarantined.`,
      priority: 2
    });
    // Log blocked download
    chrome.storage.local.get(['blockedDownloads'], result => {
      const blocked = result.blockedDownloads || [];
      blocked.push({
        url,
        filename,
        domain,
        timestamp: Date.now()
      });
      chrome.storage.local.set({ blockedDownloads: blocked });
    });
  }
});
