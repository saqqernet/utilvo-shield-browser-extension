# Utilvo Shield — Real-Time Browser Security & Anti-Phishing Extension (`v0.9.0`)

- **Install from Chrome Web Store:** [https://chromewebstore.google.com/detail/utilvo-shield/hafpojbddmohoboonogiplgmbjcekkkc](https://chromewebstore.google.com/detail/utilvo-shield/hafpojbddmohoboonogiplgmbjcekkkc)
- **Official Extension Page:** [https://utilvo.com/shield](https://utilvo.com/shield)

![Utilvo Shield Real-Time Threat & Malware Protection](https://utilvo.com/screenshots/cws-banners/02-threat-protection-banner.png)

## Overview

**Utilvo Shield** is a 100% client-side, zero-telemetry browser security extension available on the [Chrome Web Store](https://chromewebstore.google.com/detail/utilvo-shield/hafpojbddmohoboonogiplgmbjcekkkc) and documented on the [Utilvo Shield Official Page](https://utilvo.com/shield). It defends Chromium and Gecko browsers in real time against deceptive phishing domains, **ClickFix** fake CAPTCHA PowerShell/CLI exploits, clipboard shellcode hijacking, **Magecart** credit-card skimmers, and notification scareware.

---

## Core Protection Engines

### 1. ClickFix & Clipboard Shellcode Quarantine (`MAIN` World)
Neutralizes fake verification prompts (*"Press Win+R, Ctrl+V, Enter"*) by inspecting clipboard writes in the page's `MAIN` execution world before malicious PowerShell, `mshta`, `curl`, or base64 payloads can reach the system clipboard.

![ClickFix & Clipboard Shellcode Defense](https://utilvo.com/screenshots/cws-banners/07-clipboard-shellcode-quarantine-banner.png)

### 2. Credit Card Skimmer & Magecart Defense
Protects checkout forms against silent JavaScript card-skimming injectors and DOM exfiltration hooks on e-commerce websites.

![Credit Card Skimmer Defense](https://utilvo.com/screenshots/cws-banners/06-credit-card-skimmer-guard-banner.png)

### 3. Push Notification Scareware Auto-Deny & GDPR Cookie Auto-Cutter
Silently blocks fake *"Virus Detected"* push notification spam at `document_start` and strips intrusive cookie consent overlays to restore page scrolling.

![Push Notification Scareware Auto-Deny](https://utilvo.com/screenshots/cws-banners/05-notification-spam-defusal-banner.png)

![GDPR Cookie Consent Auto-Cutter](https://utilvo.com/screenshots/cws-banners/04-cookie-cutter-banner.png)

### 4. 100% Client-Side Privacy — Zero Telemetry
All heuristic scoring, domain reputation checks, and declarative network rules execute locally inside the browser sandbox without transmitting browsing history to external servers.

![100% Private Zero-Telemetry Engine](https://utilvo.com/screenshots/cws-banners/10-privacy-zero-telemetry-banner.png)

---

## Official Links
1. **Chrome Web Store Extension:** [https://chromewebstore.google.com/detail/utilvo-shield/hafpojbddmohoboonogiplgmbjcekkkc](https://chromewebstore.google.com/detail/utilvo-shield/hafpojbddmohoboonogiplgmbjcekkkc)
2. **Utilvo Shield Official Website:** [https://utilvo.com/shield](https://utilvo.com/shield)
