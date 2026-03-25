# 🛡️ Anti-Phishing Guard

**Real-time phishing protection for Chrome** — protects against fake websites using domain age analysis, homograph detection, typosquatting prevention, and more.

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/yourusername/anti-phishing-ext)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Chrome Web Store](https://img.shields.io/badge/Chrome-Extension-red.svg)](https://chrome.google.com/webstore)

---

## 🌟 Features

### 🔒 Core Protection

| Feature | Description |
|---------|-------------|
| **Domain Age Check** | Blocks recently registered domains (< 30 days) via RDAP lookup |
| **Homograph Detection** | Detects character substitution attacks (Cyrillic `а` vs Latin `a`) |
| **Typosquatting** | Catches lookalike domains using Levenshtein distance (≤ 2 chars) |
| **TLD Mismatch** | ⚠️ Warns if domain looks like `sberbank.ru` but uses different TLD |
| **Redirect Blocking** | 🚫 Prevents navigation to other domains before security check completes |
| **OpenPhish Integration** | Auto-downloads phishing database (updated hourly) |

### 🎯 User Features

- **Custom Blacklist/Whitelist** — manage your own trusted/blocked sites
- **Real-time Warnings** — yellow toast for suspicious, red overlay for dangerous
- **Security Report** — detailed analysis (HTTPS, homograph, typosquatting, domain age, hosting, country)
- **Bilingual UI** — Russian 🇷🇺 and English 🇺🇸 support
- **Dark Mode** — modern glassmorphism design
- **Statistics** — track sites checked and threats blocked

---

## 📦 Installation

### From Chrome Web Store (Coming Soon)

1. Visit [Chrome Web Store](https://chrome.google.com/webstore)
2. Search for "Anti-Phishing Guard"
3. Click "Add to Chrome"

### Manual Installation (Development)

1. **Clone or download** this repository:
   ```bash
   git clone https://github.com/yourusername/anti-phishing-ext.git
   ```

2. **Open Chrome Extensions**:
   - Navigate to `chrome://extensions`
   - Enable **"Developer mode"** (toggle in top-right)

3. **Load unpacked extension**:
   - Click **"Load unpacked"**
   - Select the `anti-phishing-ext` folder

4. **Done!** The extension icon 🛡️ should appear in your toolbar.

---

## 🚀 How It Works

### Two-Phase Detection

```
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1: Fast Check (on every navigation)                  │
│  - Blacklist/Whitelist lookup                               │
│  - Homograph detection                                      │
│  - Typosquatting check                                      │
│  - OpenPhish database                                       │
│  ⏱️ ~50ms                                                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  PHASE 2: Full Check (after DOM ready)                      │
│  - Domain age (RDAP)                                        │
│  - Form analysis (password/CC fields)                       │
│  - Clickjacking detection                                   │
│  - Page content scanning                                    │
│  - TLD mismatch warning                                     │
│  ⏱️ ~500-2000ms (network calls)                             │
└─────────────────────────────────────────────────────────────┘
```

### Protection Levels

| Level | Trigger | Action |
|-------|---------|--------|
| 🟢 **Green** | Trusted site, passed all checks | No notification |
| 🟡 **Yellow** | Suspicious (young domain, TLD mismatch, clickjacking) | Toast notification (auto-dismiss) |
| 🔴 **Red** | Dangerous (blacklist, homograph, typosquatting, phishing DB) | Full-page overlay, blocks access |

---

## 📖 Usage

### Popup Window

Click the extension icon 🛡️ to open the popup:

- **Toggle** — enable/disable protection
- **Status Card** — current site status (🟢/🟡/🔴)
- **Quick Actions** — trust or block current site
- **Security Report** — detailed analysis
- **Settings** — manage lists and algorithms

### Dashboard (Settings)

Right-click extension icon → **Options** or click ⚙️ in popup:

- **Protection Algorithms** — toggle homograph/age checks, adjust threshold
- **Notifications** — enable/disable toast, duration, position
- **My Lists** — manage whitelist/blacklist
- **Statistics** — view checked/blocked counts
- **Export/Import** — backup and restore settings

### Blocked Page

When a dangerous site is detected, you'll see:

- **🔴 Red overlay** — page blurred, access blocked
- **Reason** — why the site was blocked
- **Close** — close the tab
- **Unblock** — remove from blacklist (if user-blocked)
- **I understand the risks** — bypass for this session (not available for blacklist)

---

## 🔧 Configuration

### Default Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Protection Enabled | ✅ | Master toggle |
| Homograph Detection | ✅ | Detect character substitution |
| Domain Age Check | ✅ | Warn about young domains |
| Age Threshold | 30 days | Block domains younger than this |
| Toast Notifications | ✅ | Show warnings for suspicious sites |
| Toast Duration | 10 sec | Auto-dismiss time |
| Toast Position | Top-right | Corner position |

### Customization

Edit settings in **Dashboard** → changes sync across Chrome profile.

---

## 🏗️ Architecture

### Key Files

| File | Purpose |
|------|---------|
| `background.js` | Service Worker — all detection logic |
| `content-script.js` | Injected into pages — scans DOM, shows overlays |
| `popup.js/html/css` | Extension popup UI |
| `dashboard.js/html/css` | Settings page UI |
| `blocked.js/html/css` | Blocking page UI |
| `sites.js` | Global whitelist (~705k top sites) |
| `_locales/` | Translations (en, ru) |

### Data Flow

```
User navigates to URL
       │
       ▼
chrome.tabs.onUpdated
       │
       ▼
fastCheck() ────[BLOCKED]───→ blocked.html
       │
       ▼
[PASSED]
       │
       ▼
content-script.js → PAGE_READY
       │
       ▼
fullCheck() ────[RED]───→ Inject overlay
       │
       ├───[YELLOW]──→ Show toast
       │
       └───[GREEN]──→ No action
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for detailed documentation.

---

## 🧪 Testing

### Test Each Protection

| Test | How to Trigger |
|------|----------------|
| **Blacklist** | Settings → Blacklist → add `example.com` → visit it |
| **TLD Mismatch** | Visit `sberbank.com` (if only `sberbank.ru` in sites.js) |
| **Redirect Block** | Create page with meta refresh to suspicious domain |
| **Homograph** | Visit `раураl.com` (Cyrillic `а` in `paypal`) |
| **Typosquatting** | Visit `gooogle.com` (extra `o`) |
| **Young Domain** | Register new domain (< 30 days) |

---

## 🔐 Privacy & Security

### What We Collect

**Nothing.** This extension:
- ❌ Does NOT collect browsing history
- ❌ Does NOT send data to external servers (except RDAP/OpenPhish for lookups)
- ❌ Does NOT use analytics or tracking
- ❌ Does NOT require any permissions beyond what's necessary

### Permissions Used

| Permission | Why |
|------------|-----|
| `storage` | Save settings and lists |
| `tabs` | Detect current tab URL |
| `activeTab` | Access current tab for popup |
| `webNavigation` | Intercept navigation for redirect blocking |
| `<all_urls>` | Inject content script on all HTTP/HTTPS pages |

---

## 🛠️ Development

### Build Process

**No build step required!** This is a vanilla JS extension. Just load the folder in Chrome.

### Debugging

1. **Service Worker**:
   - Go to `chrome://extensions`
   - Find "Anti-Phishing Guard"
   - Click **"Service worker"** link

2. **Content Script**:
   - Open DevTools on any webpage
   - Check Console for logs

3. **Popup**:
   - Right-click popup → **Inspect**

### Code Style

- ES6+ (modules in background.js)
- No external dependencies
- Follows Chrome Extension Manifest V3 guidelines

---

## 📚 API Reference

### Message Types

**From Content Script:**
```javascript
chrome.runtime.sendMessage({ type: 'PAGE_READY', hostname, url, ... })
chrome.runtime.sendMessage({ type: 'FORMS_DETECTED', hostname, ... })
chrome.runtime.sendMessage({ type: 'CHECK_BLOCKED' })
chrome.runtime.sendMessage({ type: 'SCAN_PAGE' })
```

**From Popup/Dashboard:**
```javascript
chrome.runtime.sendMessage({ type: 'CHECK_DOMAIN', hostname })
chrome.runtime.sendMessage({ type: 'TRUST_SITE', hostname })
chrome.runtime.sendMessage({ type: 'BLOCK_SITE', hostname })
chrome.runtime.sendMessage({ type: 'GET_SETTINGS' })
chrome.runtime.sendMessage({ type: 'SET_SETTINGS', settings })
chrome.runtime.sendMessage({ type: 'GET_REPORT', hostname, url })
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for complete API documentation.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Guidelines

- Follow existing code style
- Add tests for new features
- Update documentation
- Keep performance in mind (no blocking operations in content scripts)

---

## 📝 Changelog

### Version 1.0.0 (2026-03-25)

**Added:**
- ✨ TLD Mismatch detection (warns about `sberbank.com` vs `sberbank.ru`)
- 🚫 Redirect blocking (prevents navigation before check completes)
- 🛡️ Unblock button on blocked page
- 📊 Security report with detailed criteria
- 🌐 Bilingual support (Russian/English)
- 📦 OpenPhish integration
- 🎨 Modern glassmorphism UI

**Fixed:**
- 🐛 Blacklist check now uses normalized domains
- 🐛 Text overflow in popup status card
- 🐛 Session bypass for blacklisted sites

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [OpenPhish](https://openphish.com/) — phishing feed
- [RDAP](https://rdap.org/) — domain registration data
- [IANA](https://data.iana.org/rdap/) — RDAP bootstrap servers
- [ipwho.is](https://ipwho.is/) — IP geolocation API

---

<div align="center">

**Made with ❤️ for a safer internet**

[⬆ Back to top](#-anti-phishing-guard)

</div>
