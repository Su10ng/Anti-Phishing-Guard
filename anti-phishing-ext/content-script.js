// content-script.js
(function () {
  if (window.__apgInjected) return;
  window.__apgInjected = true;

  const hostname = location.hostname;
  if (!hostname) return;
  
  // Не запускаем content script на blocked.html
  if (location.href.startsWith(chrome.runtime.getURL('blocked.html'))) return;

  const _ = key => chrome.i18n.getMessage(key) || key;

  // ─── Credit-card selectors ────────────────────────────────────────────────
  const CC_SELECTORS = [
    'input[autocomplete*="cc-number"]', 'input[autocomplete*="cc-exp"]',
    'input[autocomplete*="cc-csc"]', 'input[name*="cardnumber"]',
    'input[name*="card_number"]', 'input[name*="cvv"]', 'input[name*="cvc"]',
    'input[placeholder*="card number" i]', 'input[placeholder*="cvv" i]',
  ];

  function scanForms() {
    return {
      hasPasswordForm: !!document.querySelector('input[type="password"]'),
      hasCCForm: CC_SELECTORS.some(s => !!document.querySelector(s)),
    };
  }

  // ─── Form action domain mismatch ──────────────────────────────────────────
  function scanFormActions() {
    for (const form of document.querySelectorAll('form')) {
      // Only care about forms that have sensitive fields
      const hasSensitive = form.querySelector('input[type="password"]') ||
        CC_SELECTORS.some(s => form.querySelector(s));
      if (!hasSensitive) continue;
      try {
        const action = form.action;
        if (!action) continue;
        const actionHost = new URL(action).hostname;
        if (actionHost && actionHost !== location.hostname) return true;
      } catch { /* ignore */ }
    }
    return false;
  }

  // ─── Hidden sensitive fields detection ───────────────────────────────────
  function scanHiddenSensitiveFields() {
    const selectors = ['input[type="password"]', ...CC_SELECTORS];
    for (const sel of selectors) {
      for (const el of document.querySelectorAll(sel)) {
        try {
          const cs = getComputedStyle(el);
          if (cs.display === 'none' || cs.visibility === 'hidden' ||
              parseFloat(cs.opacity) < 0.1) return true;
        } catch { /* ignore */ }
      }
    }
    return false;
  }

  // ─── Phishing keywords in page content ───────────────────────────────────
  const PHISHING_CONTENT_KW = [
    'verify your account', 'confirm your identity', 'unusual activity detected',
    'account has been suspended', 'account will be locked', 'update your payment',
    'enter your credentials', 'click here to verify', 'security alert',
    'your account will be', 'login has been', 'suspicious activity',
    'подтвердите свою личность', 'необычная активность', 'аккаунт заблокирован',
    'обновите платёжные данные', 'введите пароль', 'предупреждение безопасности',
    'ваш аккаунт будет', 'подозрительная активность',
  ];
  function scanPageContent() {
    try {
      const text = (document.body?.innerText || '').toLowerCase().slice(0, 20000);
      for (const kw of PHISHING_CONTENT_KW) {
        if (text.includes(kw)) return true;
      }
    } catch { /* ignore */ }
    return false;
  }

  // ─── Clickjacking detection: invisible positioned inputs ──────────────────
  function scanClickjacking() {
    const inputs = document.querySelectorAll('input');
    for (const inp of inputs) {
      try {
        const cs = getComputedStyle(inp);
        const rect = inp.getBoundingClientRect();
        if (rect.width < 5 || rect.height < 5) continue;
        const pos = cs.position;
        if (pos !== 'absolute' && pos !== 'fixed') continue;
        const opacity = parseFloat(cs.opacity) || 0;
        if (opacity < 0.05 && cs.pointerEvents !== 'none') return true;
      } catch { /* cross-origin iframe, skip */ }
    }
    return false;
  }

  // ─── Styles ───────────────────────────────────────────────────────────────
  const style = document.createElement('style');
  style.textContent = `
    #apg-overlay {
      position:fixed;inset:0;z-index:2147483647;
      background:rgba(12,0,0,0.95);
      display:flex;align-items:center;justify-content:center;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
      animation:apg-fade 0.3s ease;
    }
    #apg-blur {
      position:fixed;inset:0;z-index:2147483646;
      backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
      pointer-events:none;
    }
    .apg-ov {
      background:rgba(255,255,255,0.04);
      backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
      border:1px solid rgba(255,80,80,0.3);border-radius:24px;
      padding:48px 52px;max-width:520px;width:92%;
      text-align:center;color:#fff;
    }
    .apg-ov-icon{font-size:60px;margin-bottom:14px;}
    .apg-ov h1{font-size:20px;font-weight:800;color:#ff6b6b;margin:0 0 10px;}
    .apg-ov-host{font-size:15px;font-weight:700;margin:0 0 8px;word-break:break-all;}
    .apg-ov-why{font-size:13px;color:rgba(255,255,255,.55);line-height:1.7;margin:0 0 30px;text-align:left;}
    .apg-ov-back{
      display:block;width:100%;padding:13px;
      background:#d93030;color:#fff;border:none;
      border-radius:14px;font-size:15px;font-weight:700;
      cursor:pointer;margin-bottom:10px;transition:background 0.2s;
    }
    .apg-ov-back:hover{background:#be2020;}
    .apg-ov-skip{
      background:none;border:none;color:rgba(255,255,255,.28);
      font-size:12px;cursor:pointer;text-decoration:underline;padding:4px;
    }
    .apg-ov-skip:hover{color:rgba(255,255,255,.6);}

    #apg-toast{
      position:fixed;z-index:2147483647;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    }
    #apg-toast.pos-tr{top:20px;right:20px;animation:apg-from-right 0.45s cubic-bezier(0.34,1.56,0.64,1);}
    #apg-toast.pos-tl{top:20px;left:20px;animation:apg-from-left  0.45s cubic-bezier(0.34,1.56,0.64,1);}
    #apg-toast.pos-br{bottom:24px;right:20px;animation:apg-from-right 0.45s cubic-bezier(0.34,1.56,0.64,1);}
    #apg-toast.pos-bl{bottom:24px;left:20px;animation:apg-from-left  0.45s cubic-bezier(0.34,1.56,0.64,1);}
    .apg-t-inner{
      display:flex;align-items:flex-start;gap:11px;position:relative;
      background:rgba(12,12,20,0.97);
      backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
      border:1px solid rgba(255,196,50,0.38);border-radius:14px;
      padding:14px 15px;max-width:360px;min-width:260px;color:#fff;
      box-shadow:0 8px 36px rgba(0,0,0,.55);
    }
    .apg-t-icon{font-size:22px;flex-shrink:0;margin-top:1px;}
    .apg-t-body{flex:1;min-width:0;}
    .apg-t-title{font-size:13px;font-weight:700;color:#ffd166;margin-bottom:4px;}
    .apg-t-desc{font-size:12px;color:rgba(255,255,255,.55);line-height:1.4;margin-bottom:10px;word-break:break-word;}
    .apg-t-acts{display:flex;gap:6px;}
    .apg-t-btn{padding:6px 11px;border:none;border-radius:8px;font-size:11px;font-weight:600;cursor:pointer;transition:opacity .15s;white-space:nowrap;}
    .apg-t-btn:hover{opacity:.82;}
    .apg-t-block{background:rgba(200,40,40,.85);color:#fff;}
    .apg-t-trust{background:rgba(255,255,255,.1);color:rgba(255,255,255,.8);}
    .apg-t-close{background:none;border:none;color:rgba(255,255,255,.25);cursor:pointer;font-size:14px;line-height:1;padding:0 2px;flex-shrink:0;transition:color .15s;margin-top:1px;}
    .apg-t-close:hover{color:rgba(255,255,255,.65);}
    .apg-t-bar{position:absolute;bottom:0;left:0;right:0;height:3px;background:rgba(255,196,50,.45);border-radius:0 0 14px 14px;transform-origin:left;}

    @keyframes apg-fade      {from{opacity:0}to{opacity:1}}
    @keyframes apg-from-right{from{opacity:0;transform:translateX(120%)}to{opacity:1;transform:translateX(0)}}
    @keyframes apg-from-left {from{opacity:0;transform:translateX(-120%)}to{opacity:1;transform:translateX(0)}}
    @keyframes apg-out-right {to{opacity:0;transform:translateX(120%)}}
    @keyframes apg-out-left  {to{opacity:0;transform:translateX(-120%)}}
    @keyframes apg-bar-anim  {to{transform:scaleX(0)}}
  `;
  (document.head || document.documentElement).appendChild(style);

  let overlayShown = false;
  let toastShown   = false;

  // ─── Red overlay ──────────────────────────────────────────────────────────
  function showRedOverlay(reason) {
    if (overlayShown) return;
    overlayShown = true;
    // Remember that this page was blocked (for popup to detect)
    try { sessionStorage.setItem('__apg_blocked', JSON.stringify({ reason, hostname })); } catch {}
    document.getElementById('apg-toast')?.remove();

    const blur = document.createElement('div');
    blur.id = 'apg-blur';
    document.documentElement.appendChild(blur);

    const overlay = document.createElement('div');
    overlay.id = 'apg-overlay';
    overlay.innerHTML = `
      <div class="apg-ov">
        <div class="apg-ov-icon">🛡️</div>
        <h1>${_('overlay_heading')}</h1>
        <p class="apg-ov-host">${esc(hostname)}</p>
        <div class="apg-ov-why">${formatReason(reason)}</div>
        <button class="apg-ov-back" id="apg-ov-back">${_('btn_go_back')}</button>
        <button class="apg-ov-skip" id="apg-ov-skip">${_('btn_continue')}</button>
      </div>
    `;
    document.documentElement.appendChild(overlay);

    const guard = new MutationObserver(() => {
      if (!document.getElementById('apg-overlay'))
        document.documentElement.appendChild(overlay);
    });
    guard.observe(document.documentElement, { childList: true });

    document.getElementById('apg-ov-back').onclick = () => {
      try { sessionStorage.removeItem('__apg_blocked'); } catch {}
      safeSendMessage({ type: 'BLOCK_SITE', hostname });
      history.back();
    };
    document.getElementById('apg-ov-skip').onclick = () => {
      guard.disconnect();
      overlay.remove(); blur.remove();
      overlayShown = false;
      try { sessionStorage.removeItem('__apg_blocked'); } catch {}
      safeSendMessage({ type: 'TRUST_SITE', hostname });
    };
  }

  // ─── Yellow toast ─────────────────────────────────────────────────────────
  function showYellowToast(reason, durationSec, position) {
    if (toastShown || overlayShown) return;
    toastShown = true;

    const posClass = { 'top-right':'pos-tr','top-left':'pos-tl',
                       'bottom-right':'pos-br','bottom-left':'pos-bl' }[position] || 'pos-tr';
    const isLeft = posClass === 'pos-tl' || posClass === 'pos-bl';

    const toast = document.createElement('div');
    toast.id = 'apg-toast';
    toast.className = posClass;
    toast.innerHTML = `
      <div class="apg-t-inner">
        <span class="apg-t-icon">⚠️</span>
        <div class="apg-t-body">
          <div class="apg-t-title">${_('toast_title')}</div>
          <div class="apg-t-desc">${formatReason(reason)}</div>
          <div class="apg-t-acts">
            <button class="apg-t-btn apg-t-block" id="apg-t-block">${_('btn_block_access')}</button>
            <button class="apg-t-btn apg-t-trust" id="apg-t-trust">${_('btn_add_exception')}</button>
          </div>
        </div>
        <button class="apg-t-close" id="apg-t-close">✕</button>
        <div class="apg-t-bar" id="apg-t-bar" style="animation:apg-bar-anim ${durationSec}s linear forwards"></div>
      </div>
    `;
    document.documentElement.appendChild(toast);

    const outAnim = isLeft ? 'apg-out-left' : 'apg-out-right';
    const TOTAL = durationSec * 1000;
    let remaining = TOTAL, startedAt = Date.now();
    let timerId = setTimeout(() => dismissToast(toast, outAnim), remaining);
    const bar = document.getElementById('apg-t-bar');

    toast.addEventListener('mouseenter', () => {
      clearTimeout(timerId);
      remaining -= Date.now() - startedAt;
      bar.style.animationPlayState = 'paused';
    });
    toast.addEventListener('mouseleave', () => {
      startedAt = Date.now();
      timerId = setTimeout(() => dismissToast(toast, outAnim), Math.max(remaining, 800));
      bar.style.animationPlayState = 'running';
    });
    document.getElementById('apg-t-block').onclick = () => {
      clearTimeout(timerId);
      safeSendMessage({ type: 'BLOCK_SITE', hostname });
      dismissToast(toast, outAnim);
    };
    document.getElementById('apg-t-trust').onclick = () => {
      clearTimeout(timerId);
      safeSendMessage({ type: 'TRUST_SITE', hostname });
      dismissToast(toast, outAnim);
    };
    document.getElementById('apg-t-close').onclick = () => {
      clearTimeout(timerId);
      dismissToast(toast, outAnim);
    };
  }

  function dismissToast(el, outAnim) {
    el.style.animation = `${outAnim} 0.3s ease forwards`;
    setTimeout(() => { el.remove(); toastShown = false; }, 300);
  }

  // ─── MutationObserver for dynamic forms ───────────────────────────────────
  function setupMutationObserver() {
    const root = document.body || document.documentElement;
    let pending = false;
    const observer = new MutationObserver(() => {
      if (pending || overlayShown) return;
      pending = true;
      setTimeout(() => {
        pending = false;
        if (overlayShown) return;
        const { hasPasswordForm, hasCCForm } = scanForms();
        if (!hasPasswordForm && !hasCCForm) return;
        const hasExternalFormAction = scanFormActions();
        safeSendMessage(
          { type: 'FORMS_DETECTED', hostname, hasPasswordForm, hasCCForm, hasExternalFormAction },
          (result) => {
            if (!result?.escalate) return;
            observer.disconnect();
            showRedOverlay(result.reason);
          }
        );
      }, 500);
    });
    observer.observe(root, { childList: true, subtree: true });
  }

  // ─── Entry point ──────────────────────────────────────────────────────────
  function safeSendMessage(msg, cb) {
    try {
      chrome.runtime.sendMessage(msg, (resp) => {
        if (chrome.runtime.lastError) return; // extension context invalidated
        cb?.(resp);
      });
    } catch { /* extension reloaded or uninstalled */ }
  }

  function onDomReady() {
    const { hasPasswordForm, hasCCForm } = scanForms();
    const hasClickjacking = scanClickjacking();
    const hasExternalFormAction = scanFormActions();
    const hasHiddenSensitiveFields = scanHiddenSensitiveFields();
    const hasPhishingContent = scanPageContent();
    safeSendMessage(
      { type: 'PAGE_READY', hostname, url: location.href,
        hasPasswordForm, hasCCForm, hasClickjacking,
        hasExternalFormAction, hasHiddenSensitiveFields, hasPhishingContent },
      (result) => {
        if (!result) return;
        if (result.action === 'block') {
          showRedOverlay(result.reason);
        } else if (result.action === 'warn' && result.toastEnabled !== false) {
          showYellowToast(result.reason, result.toastDurationSec ?? 10, result.toastPosition ?? 'top-right');
        }
        setupMutationObserver();
      }
    );
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onDomReady, { once: true });
  } else {
    onDomReady();
  }

  // ─── Message handler for popup queries ────────────────────────────────────
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === 'SCAN_PAGE') {
      sendResponse({
        hasExternalFormAction:    scanFormActions(),
        hasHiddenSensitiveFields: scanHiddenSensitiveFields(),
        hasPhishingContent:       scanPageContent(),
      });
    } else if (message.type === 'CHECK_BLOCKED') {
      try {
        const blocked = sessionStorage.getItem('__apg_blocked');
        if (blocked) {
          const data = JSON.parse(blocked);
          sendResponse({ isBlocked: true, reason: data.reason });
        } else {
          sendResponse({ isBlocked: false });
        }
      } catch {
        sendResponse({ isBlocked: false });
      }
    }
    return false;
  });

  function esc(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
  // Render multi-line reasons as an HTML bullet list (safe — uses esc())
  function formatReason(reason) {
    const lines = reason.split('\n').filter(Boolean);
    if (lines.length <= 1) return esc(reason);
    return lines.map(l => `<span style="display:block;padding:1px 0">▸ ${esc(l)}</span>`).join('');
  }
})();
