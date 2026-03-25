// blocked.js
const _ = key => chrome.i18n.getMessage(key) || key;

document.title = _('blocked_page_title');
document.getElementById('blocked-heading').textContent = _('blocked_heading');
document.getElementById('btn-back').textContent  = _('btn_close');
document.getElementById('btn-skip').textContent  = _('btn_continue');
document.getElementById('btn-unblock').textContent  = _('btn_unblock');

const params = new URLSearchParams(location.search);
const originalUrl = params.get('url') || '';
const reason = params.get('reason') || '';

let hostname = '';
try {
  hostname = new URL(originalUrl).hostname;
  document.getElementById('domain').textContent = hostname;
} catch {
  document.getElementById('domain').textContent = originalUrl;
}
renderReasons(document.getElementById('reason'), reason);

function renderReasons(el, text) {
  const lines = text.split('\n').filter(Boolean);
  if (lines.length <= 1) { el.textContent = text; return; }
  el.textContent = '';
  const ul = document.createElement('ul');
  ul.style.cssText = 'list-style:none;padding:0;margin:0;text-align:center;';
  lines.forEach(line => {
    const li = document.createElement('li');
    li.style.cssText = 'padding:4px 0;display:flex;gap:8px;align-items:baseline;justify-content:center;';
    li.innerHTML = `<span style="color:#ff6b6b;flex-shrink:0">▸</span><span>${escHtml(line)}</span>`;
    ul.appendChild(li);
  });
  el.appendChild(ul);
}
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Проверяем, находится ли сайт в чёрном списке
async function init() {
  const lists = await chrome.runtime.sendMessage({ type: 'GET_LISTS' });
  const domain = hostname.replace(/^www\./, '').toLowerCase();
  const isInBlacklist = lists.blacklist.some(d => d.replace(/^www\./, '').toLowerCase() === domain);

  const skipBtn = document.getElementById('btn-skip');
  const backBtn = document.getElementById('btn-back');
  const unblockBtn = document.getElementById('btn-unblock');

  // Обработчик кнопки "Закрыть"
  backBtn.addEventListener('click', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (tab) chrome.tabs.remove(tab.id);
    });
  });

  // Обработчик кнопки "Разблокировать" (только если сайт в чёрном списке)
  unblockBtn.addEventListener('click', async () => {
    if (hostname) {
      // Сначала добавляем в whitelist, чтобы fastCheck не заблокировал снова
      await chrome.runtime.sendMessage({ type: 'TRUST_SITE', hostname });
      // Сразу перенаправляем на оригинальный URL
      if (originalUrl) {
        location.href = originalUrl;
      } else {
        chrome.tabs.reload();
      }
    }
  });

  if (isInBlacklist) {
    // Сайт в чёрном списке — скрываем кнопку "Я понимаю риски", показываем "Разблокировать"
    skipBtn.style.display = 'none';
    unblockBtn.style.display = 'block';
  } else {
    skipBtn.style.display = 'block';
    unblockBtn.style.display = 'none';
    skipBtn.addEventListener('click', () => {
      if (!originalUrl) return;
      if (hostname) chrome.runtime.sendMessage({ type: 'BYPASS_ONCE', hostname });
      location.href = originalUrl;
    });
  }
}

init();
