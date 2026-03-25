// dashboard.js
const _ = key => chrome.i18n.getMessage(key) || key;

// ── i18n static labels ────────────────────────────────────────────────────────
const i18nMap = {
  'dash-subtitle':         'dash_subtitle',
  'section-algorithms':    'section_algorithms',
  'hg-label':              'hg_label',
  'hg-desc':               'hg_desc',
  'age-check-label':       'age_check_label',
  'age-check-desc':        'age_check_desc',
  'age-thresh-label':      'age_thresh_label',
  'age-thresh-desc':       'age_thresh_desc',
  'age-thresh-unit':       'age_thresh_unit',
  'section-notifications': 'section_notifications',
  'toast-on-label':        'toast_on_label',
  'toast-on-desc':         'toast_on_desc',
  'toast-dur-label':       'toast_dur_label',
  'toast-dur-unit':        'toast_dur_unit',
  'toast-pos-label':       'toast_pos_label',
  'pos-tr':                'pos_tr',
  'pos-tl':                'pos_tl',
  'pos-br':                'pos_br',
  'pos-bl':                'pos_bl',
  'sec-lists':             'sec_lists',
  'sec-stats':             'sec_stats',
  'sec-data':              'sec_data',
  'stat-checked-label':    'stat_checked',
  'stat-blocked-label':    'stat_blocked',
  'modal-whitelist-title': 'sec_whitelist',
  'modal-blacklist-title': 'sec_blacklist',
};
for (const [id, key] of Object.entries(i18nMap)) {
  const el = document.getElementById(id);
  if (el) el.textContent = _(key);
}
document.title = 'Anti-Phishing Guard — ' + _('dash_subtitle');
document.getElementById('open-whitelist').textContent    = _('sec_whitelist') + '  →';
document.getElementById('open-blacklist').textContent    = _('sec_blacklist') + '  →';
document.getElementById('whitelist-add').textContent     = _('btn_add_to_list');
document.getElementById('blacklist-add').textContent     = _('btn_add_to_list');
document.getElementById('whitelist-clear').textContent   = _('btn_clear_all');
document.getElementById('blacklist-clear').textContent   = _('btn_clear_all');
document.getElementById('modal-whitelist-back').textContent = _('modal_close');
document.getElementById('modal-blacklist-back').textContent = _('modal_close');
document.getElementById('btn-export').textContent        = _('btn_export');
document.getElementById('btn-import').textContent        = _('btn_import');

function msg(payload) {
  return new Promise(resolve => chrome.runtime.sendMessage(payload, resolve));
}

// Settings 
async function init() {
  const settings = await msg({ type: 'GET_SETTINGS' });

  const homographToggle = document.getElementById('check-homographs');
  const ageToggle       = document.getElementById('check-age');
  const ageInput        = document.getElementById('age-threshold');
  const toastToggle     = document.getElementById('toast-enabled');
  const toastDurInput   = document.getElementById('toast-duration');
  const toastPosSelect  = document.getElementById('toast-position');

  homographToggle.checked = settings.checkHomographs  ?? true;
  ageToggle.checked       = settings.checkDomainAge   ?? true;
  ageInput.value          = settings.domainAgeThreshold ?? 30;
  toastToggle.checked     = settings.toastEnabled     ?? true;
  toastDurInput.value     = settings.toastDurationSec ?? 10;
  toastPosSelect.value    = settings.toastPosition    ?? 'top-right';

  updateToastRowsVisibility(toastToggle.checked);

  const saveSettings = () => {
    const days = Math.max(1, parseInt(ageInput.value, 10) || 30);
    ageInput.value = days;
    const dur = Math.max(2, parseInt(toastDurInput.value, 10) || 10);
    toastDurInput.value = dur;
    msg({
      type: 'SET_SETTINGS',
      settings: {
        enabled:            settings.enabled ?? true,
        checkHomographs:    homographToggle.checked,
        checkDomainAge:     ageToggle.checked,
        domainAgeThreshold: days,
        toastEnabled:       toastToggle.checked,
        toastDurationSec:   dur,
        toastPosition:      toastPosSelect.value,
      },
    });
  };

  homographToggle.addEventListener('change', saveSettings);
  ageToggle.addEventListener('change', saveSettings);
  ageInput.addEventListener('change', saveSettings);
  ageInput.addEventListener('keydown', e => { if (e.key === 'Enter') ageInput.blur(); });
  toastToggle.addEventListener('change', () => { updateToastRowsVisibility(toastToggle.checked); saveSettings(); });
  toastDurInput.addEventListener('change', saveSettings);
  toastDurInput.addEventListener('keydown', e => { if (e.key === 'Enter') toastDurInput.blur(); });
  toastPosSelect.addEventListener('change', saveSettings);

  // Stats
  const stats = await msg({ type: 'GET_STATS' });
  document.getElementById('stat-checked-val').textContent = stats.totalChecked ?? 0;
  document.getElementById('stat-blocked-val').textContent = stats.totalBlocked ?? 0;

  // Modals
  setupModal('whitelist');
  setupModal('blacklist');

  // Export / Import
  document.getElementById('btn-export').addEventListener('click', exportData);
  document.getElementById('btn-import').addEventListener('click', () =>
    document.getElementById('import-file').click()
  );
  document.getElementById('import-file').addEventListener('change', importData);
}

function updateToastRowsVisibility(enabled) {
  document.getElementById('row-toast-dur').style.opacity = enabled ? '' : '0.4';
  document.getElementById('row-toast-pos').style.opacity = enabled ? '' : '0.4';
  document.getElementById('toast-duration').disabled = !enabled;
  document.getElementById('toast-position').disabled = !enabled;
}

// Modal management 
function setupModal(listName) {
  const openBtn  = document.getElementById(`open-${listName}`);
  const modal    = document.getElementById(`modal-${listName}`);
  const backBtn  = document.getElementById(`modal-${listName}-back`);
  const clearBtn = document.getElementById(`${listName}-clear`);
  const addBtn   = document.getElementById(`${listName}-add`);
  const input    = document.getElementById(`${listName}-input`);

  openBtn.addEventListener('click', async () => {
    modal.hidden = false;
    await renderList(listName);
  });
  backBtn.addEventListener('click', () => { modal.hidden = true; });
  modal.addEventListener('click', e => { if (e.target === modal) modal.hidden = true; });

  clearBtn.addEventListener('click', async () => {
    await msg({ type: 'CLEAR_LIST', list: listName });
    await renderList(listName);
  });

  addBtn.addEventListener('click', () => addDomain(listName));
  input.addEventListener('keydown', e => { if (e.key === 'Enter') addDomain(listName); });
}

async function renderList(listName) {
  const { whitelist, blacklist } = await msg({ type: 'GET_LISTS' });
  const items = listName === 'whitelist' ? whitelist : blacklist;
  const container = document.getElementById(`${listName}-items`);
  container.innerHTML = '';
  if (!items.length) {
    container.innerHTML = `<div class="list-empty">${_('list_empty')}</div>`;
    return;
  }
  items.forEach(domain => {
    const item = document.createElement('div');
    item.className = 'list-item';
    item.innerHTML = `
      <span class="list-item-domain">${esc(domain)}</span>
      <button class="btn-delete" title="Delete">🗑</button>
    `;
    item.querySelector('.btn-delete').addEventListener('click', async () => {
      await msg({ type: 'REMOVE_FROM_LIST', list: listName, domain });
      await renderList(listName);
    });
    container.appendChild(item);
  });
}

async function addDomain(listName) {
  const input = document.getElementById(`${listName}-input`);
  const domain = input.value.trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  if (!domain) return;
  const msgType = listName === 'whitelist' ? 'TRUST_SITE' : 'BLOCK_SITE';
  await msg({ type: msgType, hostname: domain });
  input.value = '';
  await renderList(listName);
}

//  Export 
async function exportData() {
  const data = await msg({ type: 'EXPORT_DATA' });
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = `anti-phishing-backup-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

//  Import 
async function importData(e) {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    await msg({ type: 'IMPORT_DATA', data });
    location.reload();
  } catch {
    alert('Invalid JSON file');
  }
  e.target.value = '';
}

function esc(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

init();
