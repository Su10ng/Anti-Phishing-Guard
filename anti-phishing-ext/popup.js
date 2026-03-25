// popup.js
const _ = key => chrome.i18n.getMessage(key) || key;
const isRu = chrome.i18n.getUILanguage().toLowerCase().startsWith('ru');

const ICONS = { green:'✅', yellow:'⚠️', red:'🚫', disabled:'🔘' };

// Static i18n labels
document.getElementById('toggle-label').title = _('toggle_hint');
document.getElementById('btn-trust').textContent    = _('btn_add_exception');
document.getElementById('btn-block').textContent    = _('btn_block_access');
document.getElementById('btn-settings').textContent = _('btn_settings');
document.getElementById('btn-report').textContent   = _('btn_report');
document.getElementById('status-domain').textContent = _('loading');
document.getElementById('status-reason').textContent = _('checking_site');

let currentHostname = null;
let currentTabUrl   = null;
let reportLoaded    = false;

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const blockedBase = chrome.runtime.getURL('blocked.html');

  let tabUrl = tab?.url ?? '';
  let blockedReason = null;
  let isPageBlocked = false;

  // Check if on blocked.html page
  if (tabUrl.startsWith(blockedBase)) {
    try {
      const params = new URL(tabUrl).searchParams;
      blockedReason = params.get('reason') || null;
      tabUrl = params.get('url') || '';
    } catch { tabUrl = ''; }
  }

  // Check if current page has an active block overlay (ask content-script)
  if (!blockedReason) {
    try {
      const response = await new Promise(resolve => {
        chrome.tabs.sendMessage(tab.id, { type: 'CHECK_BLOCKED' }, r => resolve(r || null));
      });
      if (response?.isBlocked) {
        blockedReason = response.reason || _('overlay_heading');
        isPageBlocked = true;
      }
    } catch { /* page doesn't support it, continue */ }
  }

  try {
    currentHostname = new URL(tabUrl).hostname;
    currentTabUrl   = tabUrl;
  } catch {
    setStatus({ level: 'green', reason: _('system_page'), days: null });
    document.getElementById('status-domain').textContent = '—';
    disableActions();
    return;
  }

  document.getElementById('status-domain').textContent = currentHostname;

  const settings = await msg({ type: 'GET_SETTINGS' });
  const toggle = document.getElementById('main-toggle');
  toggle.checked = settings.enabled ?? true;
  toggle.addEventListener('change', async () => {
    // Re-fetch settings to avoid overwriting changes made in the dashboard
    const fresh = await msg({ type: 'GET_SETTINGS' });
    msg({ type: 'SET_SETTINGS', settings: { ...fresh, enabled: toggle.checked } });
  });

  // If protection is disabled, show that clearly
  if (!(settings.enabled ?? true)) {
    setStatus({ level: 'disabled', reason: _('status_disabled'), days: null });
    disableActions();
  } else if (blockedReason) {
    // If blocked (either by fastCheck or fullCheck/escalation), show blocking reason
    setStatus({ level: 'red', reason: blockedReason, days: null });
    disableActions(); // Can't trust/block from popup when already blocked
  } else {
    // Otherwise do full check
    const result = await msg({ type: 'CHECK_DOMAIN', hostname: currentHostname });
    setStatus(result);
  }

}

function setStatus(result) {
  if (!result) return;
  const level = result.level ?? 'green';
  document.getElementById('status-card').className = `status-card ${level}`;
  document.getElementById('status-icon').textContent = ICONS[level] ?? '✅';
  const reasonEl = document.getElementById('status-reason');
  const lines = (result.reason ?? '').split('\n').filter(Boolean);
  if (lines.length > 1) {
    reasonEl.innerHTML = lines.map(l => `<span style="display:block">▸ ${esc(l)}</span>`).join('');
  } else {
    reasonEl.textContent = result.reason ?? '';
  }
  document.getElementById('status-age').textContent = formatAge(result.days);
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function disableActions() {
  document.getElementById('btn-trust').disabled = true;
  document.getElementById('btn-block').disabled = true;
}

// ── Age formatting ────────────────────────────────────────────────────────────
function formatAge(days) {
  if (days === null || days === undefined) return '';
  if (isRu) {
    if (days === 0) return '⚡ Создан сегодня!';
    if (days < 30)  return `⚡ Создан ${days} ${ruDays(days)} назад`;
    if (days < 365) { const m = Math.floor(days / 30); return `Возраст: ${m} ${ruMonths(m)}`; }
    const y = Math.floor(days / 365);
    const rem = Math.floor((days % 365) / 30);
    return `Возраст: ${y} ${ruYears(y)}` + (rem ? ` ${rem} мес.` : '');
  } else {
    if (days === 0) return '⚡ Created today!';
    if (days < 30)  return `⚡ Created ${days} day${days === 1 ? '' : 's'} ago`;
    if (days < 365) { const m = Math.floor(days / 30); return `Age: ${m} mo.`; }
    const y = Math.floor(days / 365);
    const rem = Math.floor((days % 365) / 30);
    return `Age: ${y} yr.` + (rem ? ` ${rem} mo.` : '');
  }
}
function ruDays(n)   { return n%10===1&&n%100!==11?'день':[2,3,4].includes(n%10)&&![12,13,14].includes(n%100)?'дня':'дней'; }
function ruMonths(n) { return n%10===1&&n%100!==11?'месяц':[2,3,4].includes(n%10)&&![12,13,14].includes(n%100)?'месяца':'месяцев'; }
function ruYears(n)  { return n%10===1&&n%100!==11?'год':[2,3,4].includes(n%10)&&![12,13,14].includes(n%100)?'года':'лет'; }

// ── Security report ───────────────────────────────────────────────────────────
document.getElementById('btn-report').addEventListener('click', async () => {
  const panel = document.getElementById('report-panel');
  if (!panel.hidden) { panel.hidden = true; return; }
  panel.hidden = false;

  if (reportLoaded || !currentHostname) return;
  reportLoaded = true;

  const container = document.getElementById('report-criteria');
  container.innerHTML = `<div style="text-align:center;padding:10px">${_('rep_loading')}</div>`;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const settings = await msg({ type: 'GET_SETTINGS' });

  // Ask content-script for DOM scan results (may fail on some pages — that's ok)
  let scan = {};
  try {
    scan = await new Promise(resolve => {
      chrome.tabs.sendMessage(tab.id, { type: 'SCAN_PAGE' }, r => resolve(r || {}));
    });
  } catch { /* system page or no content-script */ }

  const rep = await msg({
    type: 'GET_REPORT',
    hostname: currentHostname,
    url: currentTabUrl,
    checkHomographs: settings.checkHomographs ?? true,
    hasExternalFormAction:    scan.hasExternalFormAction    ?? null,
    hasHiddenSensitiveFields: scan.hasHiddenSensitiveFields ?? null,
    hasPhishingContent:       scan.hasPhishingContent       ?? null,
  });

  container.innerHTML = rep.criteria
    .map(c => `<div class="report-row"><span class="report-key">${esc(_(c.key))}</span><span class="report-val">${esc(c.value)}</span></div>`)
    .join('');
});

// ── Buttons ───────────────────────────────────────────────────────────────────
document.getElementById('btn-trust').addEventListener('click', async () => {
  if (!currentHostname) return;
  await msg({ type: 'TRUST_SITE', hostname: currentHostname });
  setStatus({ level: 'green', reason: _('status_added_whitelist'), days: null });
});
document.getElementById('btn-block').addEventListener('click', async () => {
  if (!currentHostname) return;
  await msg({ type: 'BLOCK_SITE', hostname: currentHostname });
  // Перенаправить на blocked.html, чтобы показать экран блокировки
  const blockedUrl = chrome.runtime.getURL('blocked.html') +
    `?url=${encodeURIComponent(currentTabUrl)}&reason=${encodeURIComponent(_('reason_blacklist'))}`;
  chrome.tabs.update({ url: blockedUrl });
});
document.getElementById('btn-settings').addEventListener('click', () =>
  chrome.runtime.openOptionsPage()
);

function msg(payload) {
  return new Promise(resolve => chrome.runtime.sendMessage(payload, resolve));
}

init();
