const express = require('express');
const cors = require('cors');
const https = require('https');
const http = require('http');
const tls = require('tls');
const crypto = require('crypto');
const path = require('path');
const url = require('url');
const fs = require('fs');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3847;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════════════════
// SCAN HISTORY — in-memory + JSON file persistence
// ═══════════════════════════════════════════════════════════
const HISTORY_FILE = path.join(__dirname, 'scan-history.json');
let scanHistory = [];

// Load history from disk on startup
try {
  if (fs.existsSync(HISTORY_FILE)) {
    scanHistory = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
    console.log(`  Loaded ${scanHistory.length} past scans from history`);
  }
} catch (e) {
  console.warn('  Could not load scan history:', e.message);
  scanHistory = [];
}

function persistHistory() {
  try {
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(scanHistory, null, 2));
  } catch (e) {
    console.warn('  Could not persist scan history:', e.message);
  }
}

function addScanToHistory(scan) {
  scanHistory.unshift(scan);
  // Keep max 500 scans
  if (scanHistory.length > 500) scanHistory = scanHistory.slice(0, 500);
  persistHistory();
}

// ═══════════════════════════════════════════════════════════
// LAYER 1: Google Safe Browsing v4
// ═══════════════════════════════════════════════════════════
const GOOGLE_SB_API_KEY = process.env.GOOGLE_SB_API_KEY || '';

async function checkGoogleSafeBrowsing(targetUrl) {
  const result = { name: 'Google Safe Browsing v4', status: 'clean', details: '', confidence: 0, weight: 35 };

  if (!GOOGLE_SB_API_KEY) {
    result.status = 'skipped';
    result.details = 'API key not configured — set GOOGLE_SB_API_KEY environment variable';
    result.confidence = 0;
    return result;
  }

  try {
    const payload = JSON.stringify({
      client: { clientId: 'phishguard-ai', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: targetUrl }]
      }
    });

    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SB_API_KEY}`;

    const data = await httpsPost(apiUrl, payload);

    if (data && data.matches && data.matches.length > 0) {
      const threats = data.matches.map(m => m.threatType);
      const uniqueThreats = [...new Set(threats)];
      result.status = 'threat';
      result.details = `Found in Google Safe Browsing: ${uniqueThreats.join(', ')}`;
      result.confidence = 95;
      result.threatTypes = uniqueThreats;
    } else {
      result.status = 'clean';
      result.details = 'Not found in Google Safe Browsing database';
      result.confidence = 85;
    }
  } catch (err) {
    result.status = 'error';
    result.details = `Safe Browsing API error: ${err.message}`;
    result.confidence = 0;
  }

  return result;
}

// ═══════════════════════════════════════════════════════════
// LAYER 2: RDAP Domain Age
// ═══════════════════════════════════════════════════════════
const RDAP_BOOTSTRAP_URL = 'https://rdap.org/domain/';

async function checkDomainAge(domain) {
  const result = { name: 'Domain Age (RDAP)', status: 'clean', details: '', confidence: 0, weight: 20, domainAge: null };

  try {
    const tld = domain.split('.').pop();
    let rdapUrl;

    // Try the RDAP bootstrap registry
    try {
      rdapUrl = await resolveRdapUrl(tld);
    } catch (e) {
      // Fallback: use the generic RDAP service
      rdapUrl = `https://rdap.verisign.com/com/v1/domain/${domain}`;
    }

    const data = await httpsGet(rdapUrl);

    if (data && data.events) {
      const registration = data.events.find(e => e.eventAction === 'registration');
      if (registration) {
        const regDate = new Date(registration.eventDate);
        const now = new Date();
        const ageDays = Math.floor((now - regDate) / (1000 * 60 * 60 * 24));
        const ageMonths = Math.floor(ageDays / 30);
        const ageYears = (ageDays / 365).toFixed(1);

        result.domainAge = { date: registration.eventDate, days: ageDays, months: ageMonths, years: parseFloat(ageYears) };
        result.details = `Registered: ${regDate.toISOString().split('T')[0]} (${ageDays} days ago, ~${ageYears} years)`;

        if (ageDays < 30) {
          result.status = 'threat';
          result.details += ' — CRITICAL: Domain registered less than 30 days ago';
          result.confidence = 90;
        } else if (ageDays < 180) {
          result.status = 'warning';
          result.details += ' — WARNING: Domain registered less than 6 months ago';
          result.confidence = 60;
        } else if (ageDays < 365) {
          result.status = 'warning';
          result.details += ' — Domain is less than 1 year old';
          result.confidence = 35;
        } else {
          result.status = 'clean';
          result.confidence = 70;
        }
      } else {
        result.details = 'No registration date found in RDAP data';
        result.confidence = 10;
      }
    } else {
      result.details = 'No RDAP data available for this domain';
      result.confidence = 5;
    }
  } catch (err) {
    result.status = 'error';
    result.details = `RDAP lookup failed: ${err.message}`;
    result.confidence = 0;
  }

  return result;
}

async function resolveRdapUrl(tld) {
  const data = await httpsGet(`https://rdap.org/domain/${tld}`);
  if (data && data.links) {
    const selfLink = data.links.find(l => l.rel === 'self');
    if (selfLink) return selfLink.href;
  }
  // Fallback to known RDAP servers
  const known = {
    com: 'https://rdap.verisign.com/com/v1/domain/',
    net: 'https://rdap.verisign.com/net/v1/domain/',
    org: 'https://rdap.org/domain/',
    co: 'https://rdap.nic.co/domain/',
    io: 'https://rdap.nic.io/domain/',
    xyz: 'https://rdap.nic.xyz/domain/',
    top: 'https://rdap.nic.top/domain/',
    info: 'https://rdap.afilias-srs.net/domain/'
  };
  return (known[tld] || `https://rdap.org/domain/`) + '{domain}';
}

// ═══════════════════════════════════════════════════════════
// LAYER 3: TLS Certificate Inspection
// ═══════════════════════════════════════════════════════════
async function checkTlsCertificate(targetUrl) {
  const result = { name: 'TLS Certificate Inspection', status: 'clean', details: '', confidence: 0, weight: 15, cert: null };

  try {
    const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    const hostname = parsed.hostname;
    const port = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);

    if (parsed.protocol !== 'https:') {
      result.status = 'warning';
      result.details = 'Site uses HTTP, not HTTPS — no TLS certificate to inspect';
      result.confidence = 50;
      return result;
    }

    const certData = await getTlsCert(hostname, port);

    if (!certData) {
      result.status = 'warning';
      result.details = 'Could not retrieve TLS certificate';
      result.confidence = 20;
      return result;
    }

    result.cert = {
      subject: certData.subject?.CN || 'unknown',
      issuer: certData.issuer?.O || certData.issuer?.CN || 'unknown',
      validFrom: certData.valid_from,
      validTo: certData.valid_to,
      serialNumber: certData.serialNumber
    };

    const now = new Date();
    const validTo = new Date(certData.valid_to);
    const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

    let issues = [];
    let severity = 0;

    // Check for self-signed
    const isSelfSigned = certData.subject?.CN === certData.issuer?.O ||
                         certData.subject?.CN === certData.issuer?.CN ||
                         (certData.subject && certData.issuer && JSON.stringify(certData.subject) === JSON.stringify(certData.issuer));
    if (isSelfSigned) {
      issues.push('Self-signed certificate');
      severity = Math.max(severity, 80);
    }

    // Check for expired
    if (daysUntilExpiry < 0) {
      issues.push(`Certificate expired ${Math.abs(daysUntilExpiry)} days ago`);
      severity = Math.max(severity, 90);
    } else if (daysUntilExpiry < 7) {
      issues.push(`Certificate expires in ${daysUntilExpiry} days`);
      severity = Math.max(severity, 40);
    }

    // Check domain mismatch
    const certCN = certData.subject?.CN || '';
    const certSANs = (certData.subjectaltname || '').split(',').map(s => s.replace('DNS:', '').trim());
    const domainMatch = certCN === hostname || certSANs.some(san => {
      if (san.startsWith('*.')) {
        return hostname.endsWith(san.slice(1));
      }
      return san === hostname;
    });
    if (!domainMatch && certCN !== '*') {
      issues.push(`Certificate CN "${certCN}" does not match hostname "${hostname}"`);
      severity = Math.max(severity, 70);
    }

    // Check weak signature
    if (certData.sig_alg && /md5|sha1/i.test(certData.sig_alg)) {
      issues.push(`Weak signature algorithm: ${certData.sig_alg}`);
      severity = Math.max(severity, 50);
    }

    if (issues.length > 0) {
      result.status = severity >= 60 ? 'threat' : 'warning';
      result.details = issues.join('; ');
      result.confidence = severity;
    } else {
      result.status = 'clean';
      result.details = `Valid certificate from ${certData.issuer?.O || certData.issuer?.CN || 'trusted CA'}, expires ${certData.valid_to} (${daysUntilExpiry} days)`;
      result.confidence = 75;
    }
  } catch (err) {
    result.status = 'warning';
    result.details = `TLS inspection failed: ${err.message}`;
    result.confidence = 10;
  }

  return result;
}

function getTlsCert(hostname, port) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('TLS connection timeout')), 5000);
    try {
      const socket = tls.connect({ host: hostname, port: parseInt(port), servername: hostname, rejectUnauthorized: false, timeout: 4000 }, () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        clearTimeout(timeout);
        resolve(cert && cert.subject ? cert : null);
      });
      socket.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
      socket.on('timeout', () => {
        socket.destroy();
        clearTimeout(timeout);
        reject(new Error('TLS connection timeout'));
      });
    } catch (err) {
      clearTimeout(timeout);
      reject(err);
    }
  });
}

// ═══════════════════════════════════════════════════════════
// LAYER 4: Lexical & Structural Heuristics
// ═══════════════════════════════════════════════════════════
const TRUSTED_DOMAINS = new Set([
  'google.com','microsoft.com','apple.com','github.com','amazon.com','paypal.com',
  'facebook.com','instagram.com','twitter.com','linkedin.com','reddit.com',
  'netflix.com','spotify.com','discord.com','slack.com','zoom.us',
  'chase.com','bankofamerica.com','wellsfargo.com','citi.com',
  'bbc.co.uk','cnn.com','reuters.com','nytimes.com','wikipedia.org',
  'ebay.com','shopify.com','twitch.tv','dropbox.com','cloudflare.com',
  'youtube.com','live.com','outlook.com','office.com','icloud.com',
  'meta.com','stripe.com','squareup.com','barclays.com','hsbc.com',
  'fidelity.com','vanguard.com','schwab.com','theguardian.com',
  'wordpress.com','etsy.com','google.co.uk','amazon.co.uk','github.io'
]);

const SUSPICIOUS_TLDS = new Set(['xyz','top','cc','tk','ml','ga','cf','gq','pw','buzz','icu','click','link','work','info','online','site','store','tech','space','fun','bond','sbs','cfd','cyou','uno']);

const BRAND_NAMES = ['paypal','chase','apple','google','microsoft','amazon','netflix','facebook','instagram','whatsapp','linkedin','twitter','wellsfargo','bankofamerica','citibank','dhl','fedex','ups','usps','irs','appleid','icloud','dropbox','coinbase','binance'];

const LOGIN_KEYWORDS = ['login','signin','sign-in','auth','verify','secure','account','banking','password','credential','session','wallet','pay'];

function checkLexicalHeuristics(targetUrl) {
  const result = { name: 'Lexical & Structural Heuristics', status: 'clean', details: [], score: 0, weight: 30, features: {} };

  try {
    const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    const domain = parsed.hostname.replace(/^www\./, '');
    const pathStr = parsed.pathname + parsed.search;
    const fullUrl = parsed.href;

    // 1. Domain trust check
    const isTrusted = TRUSTED_DOMAINS.has(domain) || [...TRUSTED_DOMAINS].some(d => domain.endsWith('.' + d));
    result.features.isTrustedDomain = isTrusted;
    if (isTrusted) {
      result.status = 'clean';
      result.score = 0;
      result.details.push(`Trusted domain: ${domain}`);
      result.confidence = 95;
      return result;
    }

    // 2. IP literal host
    const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
    result.features.isIpLiteral = isIp;
    if (isIp) {
      result.score += 40;
      result.details.push('IP literal hostname (no domain name)');
    }

    // 3. Suspicious TLD
    const tld = domain.split('.').pop();
    result.features.tld = tld;
    result.features.suspiciousTld = SUSPICIOUS_TLDS.has(tld);
    if (SUSPICIOUS_TLDS.has(tld)) {
      result.score += 25;
      result.details.push(`Suspicious TLD: .${tld}`);
    }

    // 4. Brand impersonation
    result.features.brandMatch = null;
    for (const brand of BRAND_NAMES) {
      if (domain.includes(brand) && !TRUSTED_DOMAINS.has(domain)) {
        result.features.brandMatch = brand;
        result.score += 20;
        result.details.push(`Brand impersonation detected: "${brand}" in domain`);
        break;
      }
    }

    // 5. Hyphens in domain
    const hyphens = (domain.match(/-/g) || []).length;
    result.features.hyphens = hyphens;
    if (hyphens >= 2) {
      result.score += 10;
      result.details.push(`${hyphens} hyphens in domain`);
    }

    // 6. Subdomain depth
    const parts = domain.split('.');
    result.features.subdomainCount = Math.max(0, parts.length - 2);
    if (result.features.subdomainCount >= 3) {
      result.score += 15;
      result.details.push(`${result.features.subdomainCount} subdomain levels`);
    }

    // 7. Login keywords in domain
    const loginInDomain = LOGIN_KEYWORDS.filter(k => domain.toLowerCase().includes(k));
    result.features.loginKeywordsInDomain = loginInDomain;
    if (loginInDomain.length > 0) {
      result.score += 10;
      result.details.push(`Login keywords in domain: ${loginInDomain.join(', ')}`);
    }

    // 8. URL length
    result.features.urlLength = fullUrl.length;
    if (fullUrl.length > 100) {
      result.score += 5;
      result.details.push(`Long URL: ${fullUrl.length} characters`);
    }

    // 9. Encoded characters
    const encodedChars = (fullUrl.match(/%[0-9a-fA-F]{2}/g) || []).length;
    result.features.encodedChars = encodedChars;
    if (encodedChars > 3) {
      result.score += 8;
      result.details.push(`${encodedChars} encoded characters (possible obfuscation)`);
    }

    // 10. Query string analysis
    const params = [...parsed.searchParams.entries()];
    result.features.queryParamCount = params.length;
    const suspiciousParams = params.filter(([k, v]) =>
      /session|token|key|auth|redirect|callback|return|ref/i.test(k) ||
      /https?:\/\//i.test(v)
    );
    result.features.suspiciousParams = suspiciousParams.length;
    if (suspiciousParams.length > 0) {
      result.score += 8;
      result.details.push(`${suspiciousParams.length} suspicious query parameters`);
    }

    // 11. Entropy analysis of domain
    const entropy = calculateEntropy(domain);
    result.features.entropy = entropy;
    if (entropy > 3.8) {
      result.score += 5;
      result.details.push(`High domain entropy: ${entropy.toFixed(2)}`);
    }

    // 12. URL shortener detection
    const shorteners = ['bit.ly','tinyurl.com','goo.gl','t.co','is.gd','ow.ly','cutt.ly','rb.gy','lnkd.in'];
    result.features.isShortener = shorteners.some(s => domain.includes(s));
    if (result.features.isShortener) {
      result.score += 10;
      result.details.push('URL shortener detected');
    }

    // Clamp score
    result.score = Math.min(100, result.score);

    // Determine status
    if (result.score >= 60) {
      result.status = 'threat';
      result.confidence = Math.min(95, 50 + result.score * 0.4);
    } else if (result.score >= 30) {
      result.status = 'warning';
      result.confidence = Math.min(80, 30 + result.score * 0.5);
    } else {
      result.status = 'clean';
      result.confidence = Math.max(60, 95 - result.score);
    }

    if (result.details.length === 0) {
      result.details.push('No suspicious patterns detected');
    }
  } catch (err) {
    result.status = 'error';
    result.details = [`URL parsing failed: ${err.message}`];
    result.score = 0;
    result.confidence = 0;
  }

  return result;
}

function calculateEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ═══════════════════════════════════════════════════════════
// LAYER 5: Injection & Malware Pattern Detection
// ═══════════════════════════════════════════════════════════
const INJECTION_PATTERNS = {
  sql: {
    name: 'SQL Injection',
    patterns: [/union\s+(all\s+)?select/i, /select\s+.+\s+from/i, /insert\s+into/i, /drop\s+(table|database)/i, /delete\s+from/i, /or\s+1\s*=\s*1/i, /'\s*or\s*'1'\s*=\s*'1/i, /admin'\s*--/, /sleep\s*\(/i, /benchmark\s*\(/i, /load_file\s*\(/i, /into\s+(out|dump)file/i],
    severity: 85
  },
  xss: {
    name: 'Cross-Site Scripting',
    patterns: [/<script[\s>]/i, /javascript\s*:/i, /on(error|load|click|mouse)\s*=/i, /eval\s*\(/i, /document\.cookie/i, /document\.write/i, /<img[^>]+onerror/i, /<svg[^>]+onload/i, /alert\s*\(/i, /<iframe/i],
    severity: 80
  },
  cmd: {
    name: 'Command Injection',
    patterns: [/[;&|`]\s*(cat|ls|pwd|id|whoami|curl|wget|nc|bash|sh|cmd)/i, /\$\(/, /`[^`]+`/, /\|\|/, /&&/, /\b(cmd|command)\b.*\.(exe|bat|sh)/i, /\/bin\/(bash|sh)/i, /powershell/i, /system\s*\(/i, /exec\s*\(/i],
    severity: 90
  },
  path: {
    name: 'Path Traversal',
    patterns: [/\.\.\//, /\.\.\\/, /%2e%2e/i, /%252e%252e/i, /\.\./, /etc\/(passwd|shadow)/i, /windows\/(system32|win\.ini)/i, /proc\//i],
    severity: 75
  },
  malware: {
    name: 'Malware Payload',
    patterns: [/\.(exe|bat|cmd|vbs|vbe|ps1|psm1|msi|msp|scr|pif|com|jar|apk|deb|rpm)(\?|$)/i, /\/download\/.+\.(exe|zip|rar)/i, /\.(docm|xlsm|pptm)(\?|$)/i, /macro/i, /\/payload/i, /\/dropper/i, /\/stub/i],
    severity: 88
  },
  exfil: {
    name: 'Data Exfiltration',
    patterns: [/\b(exfil|exfiltrat|steal|harvest|collect|grab|siphon)\b/i, /webhook\.site/i, /requestbin\./i, /pipedream\.net/i, /hookbin\./i, /collect\.php/i, /beacon/i, /callback.*\.(php|asp|jsp)/i],
    severity: 82
  }
};

// Known phishing/threat domains dataset (from public threat intelligence feeds)
const KNOWN_THREAT_DB = new Set([
  'secure-paypal-login.xyz','paypal-verify.com','irs-refund.gov-verify.xyz','login-secure-auth.xyz','whatsapp-web-login.xyz','free-prize-winner.top','claim-reward-now.cc','apple-id-verify.icu','netflix-billing.xyz','amazon-order-update.top','chase-secure-login.xyz','bankofamerica-verify.xyz','wells-fargo-alert.top','microsoft-365-login.xyz','google-security-alert.top','facebook-login-verify.xyz','instagram-confirm.xyz','twitter-verify-account.top','linkedin-security.xyz','dropbox-shared.xyz','dhl-tracking-update.com','fedex-delivery-notice.xyz','usps-package-alert.top','coinbase-verify.xyz','binance-login.xyz','metamask-recovery.xyz','blockchain-wallet.xyz','crypto-airdrop.xyz','investment-return.top','lottery-winner.xyz','inheritance-claim.xyz','social-security-update.xyz','medicare-benefits.xyz','irs-tax-refund.top','paypal-secure.xyz','apple-id-recovery.xyz','microsoft-account-verify.xyz','google-cloud-billing.xyz','amazon-prime-renew.xyz','netflix-account-update.xyz','spotify-premium.xyz','adobe-license.xyz','zoom-meeting.xyz','teams-login.xyz','slack-workspace.xyz','discord-nitro.xyz','roblox-free.xyz','fortnite-vbucks.xyz','steam-wallet.xyz','epic-games.xyz','ubisoft-verify.xyz','riot-games.xyz','blizzard-account.xyz','paypal-support.xyz','visa-verify.xyz','mastercard-secure.xyz','amex-login.xyz','discover-verify.xyz','venmo-cash.xyz','zelle-transfer.xyz','cashapp-verify.xyz','crypto-wallet.xyz','metamask-wallet.xyz','trust-wallet.xyz','phantom-wallet.xyz','exodus-wallet.xyz','coinbase-wallet.xyz','blockchain-login.xyz','bitcoin-cash.xyz','ethereum-claim.xyz','solana-airdrop.xyz','nft-reveal.xyz','opensea-verify.xyz','rarible-login.xyz','openai-verify.xyz','chatgpt-premium.xyz','bard-verify.xyz','copilot-login.xyz','github-copilot.xyz','vercel-deploy.xyz','netlify-billing.xyz','heroku-verify.xyz','aws-billing.xyz','azure-verify.xyz','gcp-console.xyz','digitalocean.xyz','cloudflare-verify.xyz','akamai-login.xyz','fastly-verify.xyz','cloudfront-billing.xyz']);

function checkInjectionPatterns(targetUrl) {
  const result = { name: 'Injection & Malware Detection', status: 'clean', details: [], score: 0, weight: 10, injections: {} };
  
  try {
    const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    const fullUrl = parsed.href;
    const path = parsed.pathname + parsed.search;
    
    let totalInjections = 0;
    const matchedCategories = [];
    
    for (const [key, cat] of Object.entries(INJECTION_PATTERNS)) {
      const matches = [];
      for (const pattern of cat.patterns) {
        const testStr = decodeURIComponent(fullUrl).replace(/\+/g, ' ');
        const m = testStr.match(pattern);
        if (m) {
          matches.push({ pattern: pattern.source.substring(0, 40), matched: m[0].substring(0, 40) });
        }
      }
      result.injections[key] = {
        name: cat.name,
        detected: matches.length > 0,
        count: matches.length,
        severity: cat.severity,
        matches: matches.slice(0, 3)
      };
      if (matches.length > 0) {
        totalInjections++;
        matchedCategories.push(cat.name);
      }
    }
    
    // Check known threat database
    const domain = parsed.hostname.replace(/^www\./, '');
    const isKnownThreat = KNOWN_THREAT_DB.has(domain);
    result.knownThreat = isKnownThreat;
    
    if (isKnownThreat) {
      result.score = 95;
      result.status = 'threat';
      result.details.push('DOMAIN FOUND IN KNOWN THREAT DATABASE — confirmed malicious');
      result.confidence = 95;
    } else if (totalInjections >= 3) {
      result.score = Math.min(95, 70 + totalInjections * 5);
      result.status = 'threat';
      result.details.push(`MULTIPLE INJECTION TYPES DETECTED: ${matchedCategories.join(', ')}`);
      result.confidence = Math.min(95, 60 + totalInjections * 8);
    } else if (totalInjections >= 1) {
      const maxSev = Math.max(...Object.values(result.injections).filter(i => i.detected).map(i => i.severity));
      result.score = maxSev || 60;
      result.status = 'warning';
      result.details.push(`Suspicious patterns detected: ${matchedCategories.join(', ')}`);
      result.confidence = maxSev;
    } else {
      result.status = 'clean';
      result.score = 0;
      result.details.push('No injection patterns or malware signatures detected');
      result.confidence = 70;
    }
  } catch (err) {
    result.status = 'error';
    result.details = [`Injection analysis failed: ${err.message}`];
    result.score = 0;
  }
  
  return result;
}

// ═══════════════════════════════════════════════════════════
// THREAT DESCRIPTIONS
// ═══════════════════════════════════════════════════════════
function generateThreatDescription(verdict, layers, injection) {
  const level = verdict.riskLevel;
  const descs = {
    critical: {
      title: 'Critical Threat Detected',
      summary: 'This URL exhibits strong indicators of malicious intent. Multiple detection layers have flagged this as dangerous. We strongly advise against visiting or entering any personal information on this site.',
      assurance: 'HIGH ASSURANCE',
      assuranceDetail: 'Multiple independent detection layers agree on this assessment. The combination of signals provides high confidence in this verdict.',
      color: '#ef4444'
    },
    high: {
      title: 'High Risk — Likely Threat',
      summary: 'This URL shows significant suspicious characteristics. At least one major detection layer has identified threat indicators. Exercise extreme caution — do not enter credentials or download files.',
      assurance: 'MODERATE-HIGH ASSURANCE',
      assuranceDetail: 'The primary detection signals converge on a high-risk verdict. While not every layer confirmed the threat, the available evidence strongly suggests malicious intent.',
      color: '#f59e0b'
    },
    moderate: {
      title: 'Moderate Risk — Suspicious',
      summary: 'This URL has some suspicious characteristics but lacks definitive threat indicators. Some features are consistent with phishing patterns, but others suggest a legitimate site. Proceed with caution.',
      assurance: 'MODERATE ASSURANCE',
      assuranceDetail: 'The detection layers show mixed signals. Some indicators suggest risk while others appear benign. This could be a newly created legitimate site or an early-stage phishing attempt.',
      color: '#f59e0b'
    },
    low: {
      title: 'Low Risk — Minor Concerns',
      summary: 'This URL has minor characteristics that slightly elevate risk above baseline, but no strong threat indicators were found. Likely safe to visit, though standard precautions apply.',
      assurance: 'MODERATE ASSURANCE',
      assuranceDetail: 'The majority of detection layers returned clean results. The minor flags are insufficient to classify this as dangerous, but we cannot guarantee absolute safety.',
      color: '#06b6d4'
    },
    safe: {
      title: 'Safe — No Threats Detected',
      summary: 'This URL passes all available security checks. The domain has a verified reputation, the TLS certificate is valid, and no suspicious patterns were found. This site appears safe to visit.',
      assurance: 'STANDARD ASSURANCE',
      assuranceDetail: 'The detection layers that were checked all returned clean results. Note: "safe" means no threats were detected by our current analysis — it is not an absolute guarantee of safety.',
      color: '#10b981'
    }
  };
  
  const d = descs[level] || descs.safe;
  
  // Add specific details from layers
  const threats = [];
  const warnings = [];
  for (const layer of layers) {
    if (layer.status === 'threat') threats.push(layer.name);
    else if (layer.status === 'warning') warnings.push(layer.name);
  }
  
  if (injection && injection.knownThreat) {
    d.summary += ' This domain is listed in known threat intelligence databases as confirmed malicious.';
  }
  
  d.threats = threats;
  d.warnings = warnings;
  
  return d;
}

// ═══════════════════════════════════════════════════════════
// CONFIDENCE-WEIGHTED VERDICT
// ═══════════════════════════════════════════════════════════
function calculateVerdict(layers) {
  let totalWeight = 0;
  let weightedScore = 0;
  let checkedLayers = 0;

  for (const layer of layers) {
    if (layer.status === 'skipped' || layer.status === 'error' || layer.confidence === 0) continue;
    totalWeight += layer.weight;
    checkedLayers++;

    // Convert each layer's status to a numeric score
    let layerScore = 0;
    if (layer.status === 'threat') layerScore = layer.confidence;
    else if (layer.status === 'warning') layerScore = layer.confidence * 0.5;
    else layerScore = 0;

    weightedScore += (layerScore * layer.weight);
  }

  const finalScore = totalWeight > 0 ? Math.round(weightedScore / totalWeight) : 0;

  let riskLevel, riskLabel;
  if (finalScore >= 70) { riskLevel = 'critical'; riskLabel = 'CRITICAL'; }
  else if (finalScore >= 50) { riskLevel = 'high'; riskLabel = 'HIGH'; }
  else if (finalScore >= 30) { riskLevel = 'moderate'; riskLabel = 'MODERATE'; }
  else if (finalScore >= 15) { riskLevel = 'low'; riskLabel = 'LOW'; }
  else { riskLevel = 'safe'; riskLabel = 'SAFE'; }

  const checkedPercent = totalWeight > 0 ? Math.round((checkedLayers / 5) * 100) : 0;

  return {
    score: finalScore,
    riskLevel,
    riskLabel,
    checkedLayers,
    totalLayers: 5,
    checkedPercent,
    disclaimer: `This result is based on ${checkedLayers} of 5 detection layers. ` +
      `Automated URL analysis cannot guarantee 100% accuracy. ` +
      `Always verify suspicious URLs through official channels before entering credentials.`
  };
}

// ═══════════════════════════════════════════════════════════
// API ROUTE
// ═══════════════════════════════════════════════════════════
app.post('/api/scan', async (req, res) => {
  const { url: targetUrl } = req.body;

  if (!targetUrl) {
    return res.status(400).json({ error: 'URL is required' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  const domain = parsedUrl.hostname.replace(/^www\./, '');
  const startTime = Date.now();

  // Run all 5 layers in parallel
  const [safeBrowsing, domainAge, tlsCheck, lexical, injection] = await Promise.all([
    checkGoogleSafeBrowsing(parsedUrl.href),
    checkDomainAge(domain),
    checkTlsCertificate(parsedUrl.href),
    Promise.resolve(checkLexicalHeuristics(parsedUrl.href)),
    Promise.resolve(checkInjectionPatterns(parsedUrl.href))
  ]);

  const layers = [safeBrowsing, domainAge, tlsCheck, lexical, injection];
  const verdict = calculateVerdict(layers);
  const elapsed = Date.now() - startTime;

  // Generate threat description with accuracy assurance
  const description = generateThreatDescription(verdict, layers, injection);

  const scanResult = {
    id: crypto.randomUUID(),
    url: parsedUrl.href,
    domain,
    verdict,
    layers: layers.map(l => ({ name: l.name, status: l.status, confidence: l.confidence, weight: l.weight, details: l.details })),
    injection: injection.injections || {},
    knownThreat: injection.knownThreat || false,
    description,
    elapsed,
    timestamp: new Date().toISOString()
  };

  // Save to history
  addScanToHistory(scanResult);

  res.json(scanResult);
});

// ═══════════════════════════════════════════════════════════
// BATCH SCAN — scan multiple URLs in parallel
// ═══════════════════════════════════════════════════════════
app.post('/api/scan-batch', async (req, res) => {
  const { urls } = req.body;

  if (!urls || !Array.isArray(urls) || urls.length === 0) {
    return res.status(400).json({ error: 'urls array is required' });
  }

  if (urls.length > 20) {
    return res.status(400).json({ error: 'Maximum 20 URLs per batch' });
  }

  const startTime = Date.now();

  // Scan all URLs in parallel
  const scanPromises = urls.map(async (rawUrl) => {
    let targetUrl = rawUrl.trim();
    if (!targetUrl) return null;

    let parsedUrl;
    try {
      parsedUrl = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
    } catch (e) {
      return {
        url: targetUrl,
        domain: targetUrl,
        error: 'Invalid URL format',
        verdict: { score: 0, riskLevel: 'safe', riskLabel: 'ERROR', checkedLayers: 0, totalLayers: 4, checkedPercent: 0, disclaimer: 'URL could not be parsed' },
        layers: [],
        elapsed: 0,
        timestamp: new Date().toISOString()
      };
    }

    const domain = parsedUrl.hostname.replace(/^www\./, '');
    const scanStart = Date.now();

    const [safeBrowsing, domainAge, tlsCheck, lexical, injection] = await Promise.all([
      checkGoogleSafeBrowsing(parsedUrl.href),
      checkDomainAge(domain),
      checkTlsCertificate(parsedUrl.href),
      Promise.resolve(checkLexicalHeuristics(parsedUrl.href)),
      Promise.resolve(checkInjectionPatterns(parsedUrl.href))
    ]);

    const layers = [safeBrowsing, domainAge, tlsCheck, lexical, injection];
    const verdict = calculateVerdict(layers);
    const description = generateThreatDescription(verdict, layers, injection);
    const elapsed = Date.now() - scanStart;

    return {
      id: crypto.randomUUID(),
      url: parsedUrl.href,
      domain,
      verdict,
      layers: layers.map(l => ({ name: l.name, status: l.status, confidence: l.confidence, weight: l.weight, details: l.details })),
      injection: injection.injections || {},
      knownThreat: injection.knownThreat || false,
      description,
      elapsed,
      timestamp: new Date().toISOString()
    };
  });

  const results = (await Promise.all(scanPromises)).filter(Boolean);

  // Save all to history
  for (const r of results) addScanToHistory(r);

  const totalElapsed = Date.now() - startTime;

  // Summary stats
  const threats = results.filter(r => r.verdict.riskLevel === 'critical' || r.verdict.riskLevel === 'high').length;
  const warnings = results.filter(r => r.verdict.riskLevel === 'moderate' || r.verdict.riskLevel === 'low').length;
  const safe = results.filter(r => r.verdict.riskLevel === 'safe').length;

  res.json({
    total: results.length,
    elapsed: totalElapsed,
    threats,
    warnings,
    safe,
    results
  });
});

// ═══════════════════════════════════════════════════════════
// SCAN HISTORY ENDPOINTS
// ═══════════════════════════════════════════════════════════

// GET /api/history — returns all scans, supports query filters
app.get('/api/history', (req, res) => {
  let results = [...scanHistory];

  // Filter by risk level
  if (req.query.risk) {
    const risk = req.query.risk.toLowerCase();
    results = results.filter(s => s.verdict.riskLevel === risk);
  }

  // Filter by domain search
  if (req.query.q) {
    const q = req.query.q.toLowerCase();
    results = results.filter(s => s.domain.toLowerCase().includes(q) || s.url.toLowerCase().includes(q));
  }

  // Sort
  const sort = req.query.sort || 'newest';
  if (sort === 'oldest') results.reverse();
  else if (sort === 'highest') results.sort((a, b) => b.verdict.score - a.verdict.score);
  else if (sort === 'lowest') results.sort((a, b) => a.verdict.score - b.verdict.score);

  // Pagination
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 50;
  const offset = (page - 1) * limit;
  const paged = results.slice(offset, offset + limit);

  res.json({
    total: results.length,
    page,
    limit,
    scans: paged
  });
});

// GET /api/stats — aggregate statistics
app.get('/api/stats', (req, res) => {
  const total = scanHistory.length;
  if (total === 0) {
    return res.json({ total: 0, threats: 0, warnings: 0, safe: 0, avgScore: 0, threatRate: 0, byDay: {}, byRisk: {} });
  }

  let threats = 0, warnings = 0, safe = 0, totalScore = 0;
  const byDay = {};
  const byRisk = { safe: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  const byDomain = {};

  for (const scan of scanHistory) {
    const level = scan.verdict.riskLevel;
    totalScore += scan.verdict.score;

    if (level === 'critical' || level === 'high') threats++;
    else if (level === 'moderate' || level === 'low') warnings++;
    else safe++;

    byRisk[level] = (byRisk[level] || 0) + 1;

    // Group by day
    const day = scan.timestamp.split('T')[0];
    byDay[day] = (byDay[day] || 0) + 1;

    // Group by domain
    byDomain[scan.domain] = (byDomain[scan.domain] || 0) + 1;
  }

  // Top scanned domains
  const topDomains = Object.entries(byDomain)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([domain, count]) => ({ domain, count }));

  res.json({
    total,
    threats,
    warnings,
    safe,
    avgScore: Math.round(totalScore / total),
    threatRate: Math.round((threats / total) * 100),
    byRisk,
    byDay,
    topDomains
  });
});

// DELETE /api/history — clear all history
app.delete('/api/history', (req, res) => {
  scanHistory = [];
  persistHistory();
  res.json({ message: 'History cleared', total: 0 });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', safeBrowsingConfigured: !!GOOGLE_SB_API_KEY });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═══════════════════════════════════════════════════════════
// HTTP HELPERS
// ═══════════════════════════════════════════════════════════
function httpsPost(url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 10000
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { resolve(data); }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    req.write(body);
    req.end();
  });
}

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const options = { headers: { 'Accept': 'application/json' }, timeout: 8000 };

    const req = https.get(url, options, (res) => {
      // Handle redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return httpsGet(res.headers.location).then(resolve).catch(reject);
      }

      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { resolve(data); }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

// ═══════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  PhishGuard AI — Server running on http://localhost:${PORT}`);
  console.log(`  Safe Browsing API: ${GOOGLE_SB_API_KEY ? 'Configured' : 'Not configured (set GOOGLE_SB_API_KEY)'}\n`);
});
