// background.js — Service Worker (ES Module)
import { TOP_SITES } from './sites.js';

const _ = (key, ...args) => chrome.i18n.getMessage(key, args.length ? args : undefined) || key;

// Global whitelist set
let _whitelistSet = null;
function getWhitelistSet() {
  if (!_whitelistSet) _whitelistSet = new Set(TOP_SITES);
  return _whitelistSet;
}

// Set of SLDs (second-level domains) from TOP_SITES for TLD mismatch detection
let _sldToDomainMap = null;
function getSldToDomainMap() {
  if (!_sldToDomainMap) {
    _sldToDomainMap = new Map();
    for (const domain of TOP_SITES) {
      const parts = domain.split('.');
      if (parts.length >= 2) {
        // For simple domains like google.com → add 'google' → 'google.com'
        // For multi-TLD like co.uk → add the SLD part
        const last2 = parts.slice(-2).join('.');
        if (MULTI_TLDS.has(last2) && parts.length >= 3) {
          const sld = parts[parts.length - 3].toLowerCase();
          if (!_sldToDomainMap.has(sld)) _sldToDomainMap.set(sld, domain);
        } else {
          const sld = parts[parts.length - 2].toLowerCase();
          if (!_sldToDomainMap.has(sld)) _sldToDomainMap.set(sld, domain);
        }
      }
    }
  }
  return _sldToDomainMap;
}

// In-memory caches
const domainAgeCache = new Map();
const sessionBypass  = new Set();
const AGE_CACHE_TTL  = 60 * 60 * 1000;

// Helpers
function normalizeDomain(h) { return h.replace(/^www\./, '').toLowerCase(); }
function getSLD(h) {
  const parts = h.split('.');
  if (parts.length >= 2) {
    const last2 = parts.slice(-2).join('.');
    if (MULTI_TLDS.has(last2) && parts.length >= 3) {
      return parts[parts.length - 3].toLowerCase();
    }
    return parts[parts.length - 2].toLowerCase();
  }
  return h.toLowerCase();
}

// Multi-level TLD list for accurate root-domain extraction
const MULTI_TLDS = new Set([
  'co.uk','org.uk','me.uk','ac.uk','gov.uk','net.uk',
  'com.au','net.au','org.au','edu.au','gov.au',
  'co.nz','net.nz','org.nz',
  'co.jp','or.jp','ne.jp','ac.jp','go.jp',
  'co.kr','or.kr','ne.kr',
  'com.br','net.br','org.br','gov.br',
  'com.cn','net.cn','org.cn','gov.cn',
  'com.tw','org.tw','net.tw',
  'co.in','net.in','org.in','gov.in',
  'com.mx','org.mx','gob.mx',
  'com.ar','org.ar','gov.ar',
  'co.za','org.za','net.za','gov.za',
  'com.tr','org.tr','net.tr','gov.tr',
  'com.ua','org.ua','net.ua','gov.ua',
  'co.il','org.il','net.il','gov.il',
  'com.sg','org.sg','net.sg','gov.sg',
  'com.hk','org.hk','net.hk','gov.hk',
  'co.th','or.th','in.th','go.th',
  'com.ph','org.ph','net.ph','gov.ph',
  'com.my','org.my','net.my','gov.my',
  'co.id','or.id','go.id','web.id',
  'com.pl','org.pl','net.pl',
  'com.ru','org.ru','net.ru',
]);
function getRootDomain(h) {
  const p = h.split('.');
  if (p.length >= 3) {
    const last2 = p.slice(-2).join('.');
    if (MULTI_TLDS.has(last2)) return p.slice(-3).join('.');
  }
  return p.length >= 2 ? p.slice(-2).join('.') : h;
}

// Detect IP-address hostnames (skip phishing checks for them)
function isIPAddress(h) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h.startsWith('[');
}

//  Sync storage (settings + lists); local storage for stats/cache 
async function syncGet(keys) {
  try { return await chrome.storage.sync.get(keys); }
  catch { return chrome.storage.local.get(keys); }
}
async function syncSet(data) {
  try { await chrome.storage.sync.set(data); }
  catch { await chrome.storage.local.set(data); }
}

//  Lists cache (whitelist + blacklist) 
let _listsCache = null, _listsCacheTs = 0;
const LISTS_CACHE_TTL = 5000;
async function getLists() {
  if (_listsCache && Date.now() - _listsCacheTs < LISTS_CACHE_TTL) return _listsCache;
  const { whitelist = [], blacklist = [] } = await syncGet(['whitelist', 'blacklist']);
  _listsCache = { whitelist, blacklist };
  _listsCacheTs = Date.now();
  return _listsCache;
}
function invalidateListsCache() { _listsCache = null; }


//  Homograph detection 
const CONFUSABLE = {
  '\u0430':'a','\u0435':'e','\u043E':'o','\u0440':'p','\u0441':'c',
  '\u0445':'x','\u0443':'y','\u0432':'b','\u0456':'i','\u0458':'j',
  '\u0410':'A','\u0415':'E','\u041E':'O','\u0420':'P','\u0421':'C',
  '\u0425':'X','\u0423':'Y',
  '\u03BF':'o','\u03B1':'a','\u03B5':'e','\u03B9':'i','\u03BA':'k',
  '\u03BD':'v','\u03C1':'p','\u03C5':'u',
  '\u00F6':'o','\u00FC':'u','\u00E4':'a',
};
function normalizeToAscii(str) {
  let out = '';
  for (const c of str) out += CONFUSABLE[c] ?? c;
  return out;
}
function checkHomograph(hostname) {
  const ascii = normalizeToAscii(hostname);
  if (ascii === hostname) return { isHomograph: false };
  const norm = normalizeDomain(ascii);
  return getWhitelistSet().has(norm) ? { isHomograph: true, lookalike: norm } : { isHomograph: false };
}

//  Levenshtein / typosquatting 
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => i);
  for (let j = 1; j <= n; j++) {
    let prev = dp[0]; dp[0] = j;
    for (let i = 1; i <= m; i++) {
      const tmp = dp[i];
      dp[i] = a[i-1] === b[j-1] ? prev : 1 + Math.min(prev, dp[i-1], dp[i]);
      prev = tmp;
    }
  }
  return dp[m];
}
const BRAND_SLDS = [
  'google','facebook','amazon','microsoft','apple','paypal','netflix',
  'twitter','instagram','linkedin','youtube','ebay','github','dropbox',
  'yahoo','outlook','whatsapp','telegram','discord','steam','roblox',
  'coinbase','binance','metamask','blockchain',
  'sberbank','gosuslugi','tinkoff','raiffeisen','alfabank','ozon','wildberries',
];
function checkTyposquatting(domain) {
  const parts = domain.split('.');
  const sld = parts.length >= 2 ? parts[parts.length - 2] : domain;
  if (sld.length < 4) return { isTyposquat: false };
  for (const brand of BRAND_SLDS) {
    if (sld === brand) continue;
    if (Math.abs(sld.length - brand.length) > 2) continue; // skip before levenshtein
    const d = levenshtein(sld, brand);
    if (d >= 1 && d <= 2) return { isTyposquat: true, lookalike: brand };
  }
  return { isTyposquat: false };
}

// Check if SLD matches a known site but TLD is different (e.g., sberbank.com vs sberbank.ru)
function checkTldMismatch(hostname) {
  const domain = normalizeDomain(hostname);
  const parts = domain.split('.');
  if (parts.length < 2) return { isTldMismatch: false };

  const sld = getSLD(domain);

  // Check if SLD exists in TOP_SITES and get the original domain
  const originalDomain = getSldToDomainMap().get(sld);
  if (originalDomain) {
    // Check if the exact domain is NOT in TOP_SITES
    const rootDomain = getRootDomain(domain);
    if (!getWhitelistSet().has(rootDomain)) {
      return { isTldMismatch: true, originalDomain, currentDomain: rootDomain };
    }
  }
  return { isTldMismatch: false };
}

//  Redirect chain tracking
const tabNavChains = new Map();
const tabPendingChecks = new Map(); // tabId → { hostname, checkedAt, passed }

// Блокируем редиректы на другие домены до завершения проверки
chrome.webNavigation.onBeforeNavigate.addListener(async ({ tabId, url, frameId, timeStamp }) => {
  if (frameId !== 0 || !url.startsWith('http')) return;
  
  // Не блокируем, если это уже страница blocked.html
  if (url.startsWith(chrome.runtime.getURL('blocked.html'))) return;
  
  try {
    const newHostname = new URL(url).hostname;
    const newRoot = getRootDomain(newHostname);
    
    // Проверяем, есть ли незавершённая проверка для этого tab
    const pending = tabPendingChecks.get(tabId);
    if (pending && Date.now() - pending.timestamp < 10000) {
      // Прошло менее 10 секунд — проверка ещё активна
      if (pending.hostname !== newHostname && getRootDomain(pending.hostname) !== newRoot) {
        // Редирект на ДРУГОЙ домен до завершения проверки — блокируем!
        const result = await fastCheck(newHostname, tabId);
        if (result || !pending.passed) {
          // Блокируем если: fastCheck вернул блокировку ИЛИ исходный домен ещё не прошёл проверку
          tabPendingChecks.delete(tabId);
          chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL('blocked.html') +
              `?url=${encodeURIComponent(url)}&reason=${encodeURIComponent(_('reason_redirect_before_check'))}`,
          });
          return;
        }
      }
    }
    
    // Обновляем tracking
    if (!tabNavChains.has(tabId)) {
      tabNavChains.set(tabId, { domains: new Set([newRoot]), firstTs: timeStamp });
    } else {
      const chain = tabNavChains.get(tabId);
      if (timeStamp - chain.firstTs > 3000) {
        tabNavChains.set(tabId, { domains: new Set([newRoot]), firstTs: timeStamp });
      } else {
        chain.domains.add(newRoot);
      }
    }
  } catch { /* ignore */ }
});

// Запоминаем начало проверки при загрузке страницы
chrome.webNavigation.onCommitted.addListener(({ tabId, url, frameId }) => {
  if (frameId !== 0 || !url.startsWith('http')) return;
  if (url.startsWith(chrome.runtime.getURL('blocked.html'))) return;
  
  try {
    const hostname = new URL(url).hostname;
    tabPendingChecks.set(tabId, { hostname, timestamp: Date.now(), passed: false });
  } catch { /* ignore */ }
});

// Отмечаем проверку как завершённую после onCompleted
chrome.webNavigation.onCompleted.addListener(({ tabId, frameId, url }) => {
  if (frameId !== 0) return;
  if (url.startsWith(chrome.runtime.getURL('blocked.html'))) return;
  
  // Помечаем проверку как пройденную (fastCheck уже выполнился в onUpdated)
  const pending = tabPendingChecks.get(tabId);
  if (pending) {
    pending.passed = true;
    // Очищаем через 10 секунд после завершения загрузки
    setTimeout(() => {
      const current = tabPendingChecks.get(tabId);
      if (current === pending) tabPendingChecks.delete(tabId);
    }, 10000);
  }
  
  setTimeout(() => tabNavChains.delete(tabId), 1000);
});

chrome.tabs.onRemoved.addListener(tabId => {
  tabNavChains.delete(tabId);
  tabPendingChecks.delete(tabId);
});

//  RDAP domain age 
let _rdapBootstrap = null, _rdapBootstrapTs = 0;
const BOOTSTRAP_TTL = 24 * 60 * 60 * 1000;
async function getRdapBootstrap() {
  if (_rdapBootstrap && Date.now() - _rdapBootstrapTs < BOOTSTRAP_TTL) return _rdapBootstrap;
  try {
    const r = await fetch('https://data.iana.org/rdap/dns.json');
    _rdapBootstrap = await r.json(); _rdapBootstrapTs = Date.now();
    return _rdapBootstrap;
  } catch { return null; }
}
async function getDomainAge(domain) {
  const c = domainAgeCache.get(domain);
  if (c && Date.now() - c.ts < AGE_CACHE_TTL) return c.days;
  try {
    const bootstrap = await getRdapBootstrap();
    if (!bootstrap) return null;
    const tld = domain.split('.').pop();
    let base = null;
    for (const [tlds, urls] of bootstrap.services) {
      if (tlds.includes(tld)) { base = urls[0]; break; }
    }
    if (!base) return null;
    const r = await fetch(`${base}domain/${domain}`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return null;
    const data = await r.json();
    const reg = data.events?.find(e => e.eventAction === 'registration');
    if (!reg?.eventDate) return null;
    const days = Math.floor((Date.now() - new Date(reg.eventDate).getTime()) / 86400000);
    domainAgeCache.set(domain, { days, ts: Date.now() });
    return days;
  } catch { return null; }
}

//  Structural heuristics 
const FREE_ABUSE_TLDS = new Set(['tk','ml','ga','cf','gq']);
const BRAND_KEYWORDS  = [
  'paypal','amazon','google','microsoft','apple','netflix','facebook',
  'instagram','twitter','youtube','ebay','aliexpress','github','dropbox',
  'yahoo','outlook','whatsapp','telegram','discord','steam','coinbase',
  'binance','metamask','sberbank','tinkoff','vtb','gosuslugi',
  'raiffeisen','alfabank','ozon','wildberries',
];
const SUSPICIOUS_PATH_KW = [
  'login','signin','sign-in','verify','verification',
  'secure','confirm','update','password','banking','credential',
];
// Returns ALL matching structural reasons (not just the first)
function collectSuspiciousPatterns(hostname, domain) {
  const reasons = [];
  const parts = domain.split('.');
  const tld = parts[parts.length - 1];
  const sld = parts[parts.length - 2] || '';
  const withoutTld = parts.slice(0, -1).join('.');
  if (FREE_ABUSE_TLDS.has(tld))                   reasons.push(_('reason_free_tld', `.${tld}`));
  if ((sld.match(/-/g) || []).length >= 3)         reasons.push(_('reason_hyphens'));
  if (sld.length > 25)                             reasons.push(_('reason_long'));
  if (parts.length >= 5)                           reasons.push(_('reason_subdomains', String(parts.length - 2)));
  for (const brand of BRAND_KEYWORDS) {
    // Only flag if the brand name appears but the domain isn't a subdomain of the actual brand
    if (withoutTld.includes(brand) && sld !== brand) {
      reasons.push(_('reason_brand', brand)); break;
    }
  }
  return reasons;
}
// Returns ALL matching URL keyword reasons
function collectUrlKeywords(url) {
  const found = [];
  try {
    const { pathname, search } = new URL(url);
    const path = (pathname + search).toLowerCase();
    for (const kw of SUSPICIOUS_PATH_KW) {
      if (path.includes(kw)) found.push(_('reason_url_kw', kw));
    }
  } catch { /* ignore */ }
  return found;
}
// Join multiple reasons into a single string (separator understood by UI layer)
function joinReasons(arr) { return arr.join('\n'); }

// OpenPhish feed 
let _phishSet = null, _phishLastFetch = 0;
const PHISH_TTL = 60 * 60 * 1000;
async function getPhishSet() {
  if (_phishSet && Date.now() - _phishLastFetch < PHISH_TTL) return _phishSet;
  try {
    const { phishData } = await chrome.storage.local.get('phishData');
    if (phishData && Date.now() - phishData.ts < PHISH_TTL) {
      _phishSet = new Set(phishData.hosts);
      _phishLastFetch = phishData.ts;
      return _phishSet;
    }
    const r = await fetch('https://openphish.com/feed.txt', { signal: AbortSignal.timeout(10000) });
    if (!r.ok) return _phishSet || new Set();
    const text = await r.text();
    const hosts = [];
    for (const line of text.split('\n')) {
      try { const h = new URL(line.trim()).hostname.toLowerCase(); if (h) hosts.push(h); } catch {}
    }
    const unique = [...new Set(hosts)];
    await chrome.storage.local.set({ phishData: { hosts: unique, ts: Date.now() } });
    _phishSet = new Set(unique);
    _phishLastFetch = Date.now();
    return _phishSet;
  } catch { return _phishSet || new Set(); }
}
// Warm the phish list on startup
getPhishSet().catch(() => {});

//  Settings 
const DEFAULT_SETTINGS = {
  enabled: true, domainAgeThreshold: 30, checkHomographs: true, checkDomainAge: true,
  toastEnabled: true, toastDurationSec: 10, toastPosition: 'top-right',
};
let _settingsCache = null, _settingsCacheTs = 0;
const SETTINGS_CACHE_TTL = 5000;
async function getSettings() {
  if (_settingsCache && Date.now() - _settingsCacheTs < SETTINGS_CACHE_TTL) return _settingsCache;
  const { settings } = await syncGet('settings');
  _settingsCache = { ...DEFAULT_SETTINGS, ...settings };
  _settingsCacheTs = Date.now();
  return _settingsCache;
}
function invalidateSettingsCache() { _settingsCache = null; }

//  Statistics 
const TODAY = () => new Date().toDateString();
async function incStat(key) {
  const today = TODAY();
  const stored = await chrome.storage.local.get(key);
  const data = stored[key] || {};
  data[today] = (data[today] || 0) + 1;
  await chrome.storage.local.set({ [key]: data });
}
async function sumStat(key) {
  const stored = await chrome.storage.local.get(key);
  const data = stored[key] || {};
  return {
    today: data[TODAY()] || 0,
    total: Object.values(data).reduce((s, v) => s + v, 0),
  };
}

//  Age string helper 
function ageStr(days) {
  return days === null ? _('age_hidden') : `${days} ${_('age_thresh_unit')}`;
}

//  Fast check (sync-ish, runs on every navigation)
async function fastCheck(hostname, tabId) {
  const domain = normalizeDomain(hostname);
  if (isIPAddress(hostname)) return null;
  
  const settings = await getSettings();
  if (!settings.enabled) return null;
  const { blacklist, whitelist } = await getLists();
  
  // Чёрный список пользователя — проверяется ПЕРВЫМ (пользователь может заблокировать любой сайт)
  const isInBlacklist = blacklist.some(d => normalizeDomain(d) === domain);
  if (isInBlacklist) {
    return { level: 'red', reason: _('reason_blacklist') };
  }
  
  // Early exit для TOP_SITES (sites.js) — если не в чёрном списке, проверяем глобальный белый список
  const rootDomain = getRootDomain(domain);
  const ws = getWhitelistSet();
  if (ws.has(domain) || ws.has(rootDomain)) return null;
  
  // sessionBypass применяется только к сайтам, заблокированным по другим причинам (не чёрный список)
  if (sessionBypass.has(domain)) return null;
  
  // Белый список пользователя
  if (whitelist.some(d => normalizeDomain(d) === domain) || whitelist.includes(rootDomain)) return null;

  const reasons = [];
  if (settings.checkHomographs) {
    const hg = checkHomograph(hostname);
    if (hg.isHomograph) reasons.push(_('reason_homograph', hg.lookalike));
  }
  const typo = checkTyposquatting(domain);
  if (typo.isTyposquat) reasons.push(_('reason_typosquat', typo.lookalike));
  const chain = tabNavChains.get(tabId);
  if (chain && chain.domains.size > 2 &&
      !getWhitelistSet().has(domain) && !getWhitelistSet().has(rootDomain))
    reasons.push(_('reason_redirect', String(chain.domains.size)));
  if (_phishSet && (_phishSet.has(domain) || _phishSet.has(hostname)))
    reasons.push(_('reason_phishtank'));

  if (reasons.length === 0) return null;
  return { level: 'red', reason: joinReasons(reasons) };
}

//  Full check (after DOM scan by content script) 
async function fullCheck(hostname, url, { hasPasswordForm, hasCCForm, hasClickjacking, hasExternalFormAction, hasHiddenSensitiveFields, hasPhishingContent }) {
  const settings = await getSettings();
  const toastMeta = {
    toastEnabled: settings.toastEnabled,
    toastDurationSec: settings.toastDurationSec,
    toastPosition: settings.toastPosition,
  };
  if (!settings.enabled) return { action: 'none', level: 'green', reason: '', days: null, ...toastMeta };
  if (isIPAddress(hostname)) return { action: 'none', level: 'green', reason: '', days: null, ...toastMeta };
  const domain = normalizeDomain(hostname);
  const rootDomain = getRootDomain(domain);
  // Early exit for TOP_SITES — skip all checks and storage reads
  const ws = getWhitelistSet();
  if (ws.has(domain) || ws.has(rootDomain))
    return { action: 'none', level: 'green', reason: _('reason_trusted'), days: null, ...toastMeta };
  const { whitelist } = await getLists();
  const normDomain = normalizeDomain(domain);
  if (whitelist.some(d => normalizeDomain(d) === normDomain) || whitelist.includes(rootDomain)) {
    const days = settings.checkDomainAge ? await getDomainAge(domain) : null;
    return { action: 'none', level: 'green', reason: _('reason_trusted'), days, ...toastMeta };
  }

  const hasForms = hasPasswordForm || hasCCForm;
  const days = settings.checkDomainAge ? await getDomainAge(domain) : null;

  const redReasons    = [];
  const yellowReasons = [];

  //  Age-based checks 
  if (days !== null && days < settings.domainAgeThreshold) {
    redReasons.push(_('reason_age_young', String(days)));
  } else if (days !== null && days < 365) {
    yellowReasons.push(_('reason_age_new', String(days)));
  }

  // Forms on a young / unknown-age domain → escalate to red 
  if (hasForms && (days === null || days < settings.domainAgeThreshold)) {
    redReasons.push(...yellowReasons.splice(0));
    redReasons.push(_('reason_has_forms'));
  }

  //  External form action (form posts sensitive data to another domain) 
  if (hasExternalFormAction) redReasons.push(_('reason_form_action'));

  //  Hidden sensitive fields 
  if (hasHiddenSensitiveFields) yellowReasons.push(_('reason_hidden_fields'));

  //  Phishing keywords in page content
  if (hasPhishingContent) yellowReasons.push(_('reason_page_content'));

  //  Clickjacking
  if (hasClickjacking) yellowReasons.push(_('reason_clickjacking'));

  //  TLD mismatch (e.g., sberbank.com vs sberbank.ru)
  const tldMismatch = checkTldMismatch(hostname);
  if (tldMismatch.isTldMismatch) {
    yellowReasons.push(_('reason_tld_mismatch', tldMismatch.originalDomain));
  }

  //  URL suspicious keywords (collect ALL matches)
  yellowReasons.push(...collectUrlKeywords(url));

  //  Structural patterns (collect ALL) 
  yellowReasons.push(...collectSuspiciousPatterns(hostname, domain));

  //  Decide action 
  if (redReasons.length > 0) {
    return {
      action: 'block', level: 'red',
      reason: joinReasons([...redReasons, ...yellowReasons]),
      days, ...toastMeta,
    };
  }
  if (yellowReasons.length > 0) {
    return { action: 'warn', level: 'yellow', reason: joinReasons(yellowReasons), days, ...toastMeta };
  }
  return { action: 'none', level: 'green', reason: _('reason_passed'), days, ...toastMeta };
}

//  Escalation check 
async function checkEscalation(hostname, { hasPasswordForm, hasCCForm, hasExternalFormAction }) {
  if (!hasPasswordForm && !hasCCForm && !hasExternalFormAction) return { escalate: false };
  const domain = normalizeDomain(hostname);
  const rootDomain = getRootDomain(domain);
  // Early exit for TOP_SITES
  const ws = getWhitelistSet();
  if (ws.has(domain) || ws.has(rootDomain)) return { escalate: false };

  const settings = await getSettings();
  if (!settings.enabled) return { escalate: false };
  const { whitelist } = await getLists();
  const normDomain = normalizeDomain(domain);
  if (whitelist.some(d => normalizeDomain(d) === normDomain) || whitelist.includes(rootDomain)) return { escalate: false };
  // External form action is always an escalation trigger regardless of domain age
  if (hasExternalFormAction) {
    const reasons = [_('reason_form_action')];
    const days = settings.checkDomainAge ? await getDomainAge(domain) : null;
    if (days !== null && days < settings.domainAgeThreshold) reasons.push(_('reason_age_young', String(days)));
    reasons.push(...collectSuspiciousPatterns(hostname, domain));
    return { escalate: true, reason: joinReasons(reasons), days };
  }
  const days = settings.checkDomainAge ? await getDomainAge(domain) : null;
  if (days === null || days < settings.domainAgeThreshold) {
    const reasons = [];
    if (days !== null) reasons.push(_('reason_age_young', String(days)));
    reasons.push(_('reason_has_forms'));
    reasons.push(_('reason_deadly_dyn_ctx'));
    reasons.push(...collectSuspiciousPatterns(hostname, domain));
    return { escalate: true, reason: joinReasons(reasons), days };
  }
  return { escalate: false };
}

//  Tab navigation interception
const _pendingFastChecks = new Map(); // tabId → AbortController
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'loading' || !tab.url?.startsWith('http')) return;

  // Не блокируем, если это уже страница blocked.html
  if (tab.url.startsWith(chrome.runtime.getURL('blocked.html'))) return;

  let hostname;
  try { hostname = new URL(tab.url).hostname; } catch { return; }

  // Debounce: abort previous pending check for this tab
  _pendingFastChecks.get(tabId)?.abort();
  const ac = new AbortController();
  _pendingFastChecks.set(tabId, ac);

  const result = await fastCheck(hostname, tabId);

  // If aborted (newer navigation started), skip
  if (ac.signal.aborted) return;
  _pendingFastChecks.delete(tabId);

  // Помечаем проверку как завершённую (даже если нет блокировки)
  const pending = tabPendingChecks.get(tabId);
  if (pending && pending.hostname === hostname) {
    pending.passed = !result; // passed = true если нет блокировки
  }

  if (!result) return;
  try {
    const current = await chrome.tabs.get(tabId);
    if (current.url === tab.url || current.pendingUrl === tab.url) {
      await incStat('statsBlocked');
      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL('blocked.html') +
          `?url=${encodeURIComponent(tab.url)}&reason=${encodeURIComponent(result.reason)}`,
      });
    }
  } catch { /* tab closed */ }
});

//  Message handler 
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const handle = async () => {
    switch (message.type) {

      case 'PAGE_READY': {
        await incStat('statsChecked');
        const r = await fullCheck(message.hostname, message.url, {
          hasPasswordForm: message.hasPasswordForm,
          hasCCForm: message.hasCCForm,
          hasClickjacking: message.hasClickjacking,
          hasExternalFormAction: message.hasExternalFormAction,
          hasHiddenSensitiveFields: message.hasHiddenSensitiveFields,
          hasPhishingContent: message.hasPhishingContent,
        });
        if (r.action === 'block') await incStat('statsBlocked');
        return r;
      }

      case 'FORMS_DETECTED': {
        const r = await checkEscalation(message.hostname, {
          hasPasswordForm: message.hasPasswordForm,
          hasCCForm: message.hasCCForm,
          hasExternalFormAction: message.hasExternalFormAction,
        });
        if (r.escalate) await incStat('statsBlocked');
        return r;
      }

      case 'CHECK_DOMAIN': {
        const { hostname } = message;
        if (isIPAddress(hostname))
          return { level: 'green', reason: _('reason_passed'), days: null };
        const domain = normalizeDomain(hostname);
        const rootDomain = getRootDomain(domain);
        // Early exit for TOP_SITES
        const _ws = getWhitelistSet();
        if (_ws.has(domain) || _ws.has(rootDomain))
          return { level: 'green', reason: _('reason_trusted'), days: null };
        const settings = await getSettings();
        const { blacklist, whitelist } = await getLists();
        const normDomain = normalizeDomain(domain);
        const days = settings.checkDomainAge ? await getDomainAge(domain) : null;
        if (blacklist.some(d => normalizeDomain(d) === normDomain))
          return { level: 'red', reason: _('reason_blacklist'), days };
        if (whitelist.some(d => normalizeDomain(d) === normDomain) || whitelist.includes(rootDomain))
          return { level: 'green', reason: _('reason_trusted'), days };

        const redReasons    = [];
        const yellowReasons = [];

        const hg = checkHomograph(hostname);
        if (hg.isHomograph) redReasons.push(_('reason_homograph', hg.lookalike));
        const typo = checkTyposquatting(domain);
        if (typo.isTyposquat) redReasons.push(_('reason_typosquat', typo.lookalike));
        if (_phishSet && (_phishSet.has(domain) || _phishSet.has(hostname)))
          redReasons.push(_('reason_phishtank'));
        if (days !== null && days < settings.domainAgeThreshold)
          redReasons.push(_('reason_age_young', String(days)));
        else if (days !== null && days < 365)
          yellowReasons.push(_('reason_age_new', String(days)));

        // TLD mismatch check
        const tldMismatch = checkTldMismatch(hostname);
        if (tldMismatch.isTldMismatch) {
          yellowReasons.push(_('reason_tld_mismatch', tldMismatch.originalDomain));
        }

        yellowReasons.push(...collectSuspiciousPatterns(hostname, domain));

        if (redReasons.length > 0)
          return { level: 'red',    reason: joinReasons([...redReasons, ...yellowReasons]), days };
        if (yellowReasons.length > 0)
          return { level: 'yellow', reason: joinReasons(yellowReasons), days };
        return                     { level: 'green',  reason: _('reason_passed'), days };
      }

      case 'TRUST_SITE': {
        const domain = normalizeDomain(message.hostname);
        const { whitelist, blacklist } = await getLists();
        if (!whitelist.some(d => normalizeDomain(d) === domain)) await syncSet({ whitelist: [...whitelist, domain] });
        if (blacklist.some(d => normalizeDomain(d) === domain))  await syncSet({ blacklist: blacklist.filter(d => normalizeDomain(d) !== domain) });
        invalidateListsCache();
        sessionBypass.add(domain);
        domainAgeCache.delete(domain);
        return { ok: true };
      }

      case 'BLOCK_SITE': {
        const domain = normalizeDomain(message.hostname);
        const { blacklist, whitelist } = await getLists();
        if (!blacklist.some(d => normalizeDomain(d) === domain)) await syncSet({ blacklist: [...blacklist, domain] });
        if (whitelist.some(d => normalizeDomain(d) === domain))  await syncSet({ whitelist: whitelist.filter(d => normalizeDomain(d) !== domain) });
        invalidateListsCache();
        domainAgeCache.delete(domain);
        sessionBypass.delete(domain); // Очистить обход сессии для этого домена
        return { ok: true };
      }

      case 'BYPASS_ONCE': {
        const domain = normalizeDomain(message.hostname);
        // Не позволяем добавить в sessionBypass сайт из чёрного списка
        const { blacklist } = await getLists();
        if (blacklist.some(d => normalizeDomain(d) === domain)) {
          return { ok: false, error: 'blacklisted' };
        }
        sessionBypass.add(domain);
        return { ok: true };
      }

      case 'GET_SETTINGS': return getSettings();
      case 'SET_SETTINGS':
        await syncSet({ settings: message.settings });
        invalidateSettingsCache();
        domainAgeCache.clear();
        return { ok: true };

      case 'GET_STATS': {
        const [checked, blocked] = await Promise.all([sumStat('statsChecked'), sumStat('statsBlocked')]);
        return { todayChecked: checked.today, todayBlocked: blocked.today,
                 totalChecked: checked.total, totalBlocked: blocked.total };
      }

      case 'GET_LISTS': {
        const data = await syncGet(['whitelist', 'blacklist']);
        return { whitelist: data.whitelist || [], blacklist: data.blacklist || [] };
      }

      case 'REMOVE_FROM_LIST': {
        const stored = await syncGet(message.list);
        const normDomain = normalizeDomain(message.domain);
        await syncSet({ [message.list]: (stored[message.list] || []).filter(d => normalizeDomain(d) !== normDomain) });
        invalidateListsCache();
        return { ok: true };
      }

      case 'CLEAR_LIST':
        await syncSet({ [message.list]: [] });
        invalidateListsCache();
        return { ok: true };

      case 'EXPORT_DATA': {
        const { settings, whitelist = [], blacklist = [] } = await syncGet(['settings', 'whitelist', 'blacklist']);
        return { settings: { ...DEFAULT_SETTINGS, ...settings }, whitelist, blacklist };
      }

      case 'IMPORT_DATA': {
        const { data } = message;
        if (data.settings) await syncSet({ settings: { ...DEFAULT_SETTINGS, ...data.settings } });
        if (Array.isArray(data.whitelist)) await syncSet({ whitelist: data.whitelist });
        if (Array.isArray(data.blacklist)) await syncSet({ blacklist: data.blacklist });
        invalidateSettingsCache();
        invalidateListsCache();
        domainAgeCache.clear();
        return { ok: true };
      }

      case 'GET_REPORT': {
        const { hostname, url } = message;
        const domain = normalizeDomain(hostname);
        const criteria = [];

        // SSL/HTTPS check
        const isHttps = url?.startsWith('https://') ?? false;
        criteria.push({
          key: 'rep_ssl_label',
          value: isHttps ? _('rep_ssl_ok') : _('rep_ssl_bad'),
        });

        // Homograph check
        if (message.checkHomographs !== false) {
          const hg = checkHomograph(hostname);
          if (hg.isHomograph) {
            criteria.push({ key: 'rep_homograph_label', value: _('reason_homograph', hg.lookalike) });
          } else {
            criteria.push({ key: 'rep_homograph_label', value: _('rep_homograph_pass') });
          }
        }

        // Typosquatting check
        const typo = checkTyposquatting(domain);
        if (typo.isTyposquat) {
          criteria.push({ key: 'rep_typo_label', value: _('reason_typosquat', typo.lookalike) });
        } else {
          criteria.push({ key: 'rep_typo_label', value: _('rep_typo_pass') });
        }

        // TLD mismatch check
        const tldMismatch = checkTldMismatch(hostname);
        if (tldMismatch.isTldMismatch) {
          criteria.push({ key: 'rep_tld_label', value: _('reason_tld_mismatch', tldMismatch.originalDomain) });
        } else {
          criteria.push({ key: 'rep_tld_label', value: _('rep_tld_pass') });
        }

        // Phishing database check
        const phishSet = await getPhishSet();
        if (phishSet?.has(domain) || phishSet?.has(hostname)) {
          criteria.push({ key: 'rep_phish_label', value: _('reason_phishtank') });
        } else if (phishSet) {
          criteria.push({ key: 'rep_phish_label', value: _('rep_phish_pass') });
        }

        // Domain age check
        const days = await getDomainAge(domain);
        if (days !== null) {
          criteria.push({
            key: 'rep_age_label',
            value: days === 0 ? _('age_today') : `${days} ${_('age_thresh_unit')}`,
          });
        }

        // Geolocation and ISP
        let country = null, isp = null;
        try {
          const r = await fetch(
            `https://ipwho.is/${hostname}`,
            { signal: AbortSignal.timeout(5000) }
          );
          if (r.ok) {
            const d = await r.json();
            if (d.success !== false) {
              country = d.country || null;
              isp     = d.connection?.isp || d.connection?.org || null;
            }
          }
        } catch { /* no network or rate limited */ }

        if (isp) {
          criteria.push({ key: 'rep_host_label', value: isp });
        }
        if (country) {
          criteria.push({ key: 'rep_country_label', value: country });
        }

        // DOM-based checks (provided by content-script via popup)
        if (message.hasExternalFormAction != null) {
          criteria.push({
            key: 'rep_form_action_label',
            value: message.hasExternalFormAction ? _('reason_form_action') : _('rep_form_action_pass'),
          });
        }
        if (message.hasHiddenSensitiveFields != null) {
          criteria.push({
            key: 'rep_hidden_label',
            value: message.hasHiddenSensitiveFields ? _('reason_hidden_fields') : _('rep_hidden_pass'),
          });
        }
        if (message.hasPhishingContent != null) {
          criteria.push({
            key: 'rep_content_label',
            value: message.hasPhishingContent ? _('reason_page_content') : _('rep_content_pass'),
          });
        }

        return { criteria };
      }

      default: return { error: 'Unknown message type' };
    }
  };
  handle().then(sendResponse);
  return true;
});
