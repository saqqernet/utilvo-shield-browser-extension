// ==UserScript==
// @name         Utilvo Shield — Anti-Phishing, ClickFix, Clipboard & Skimmer Guard
// @name:ar      درع يوتيلفو (Utilvo Shield) — الحماية من التصيد واختطاف الحافظة والبطاقات
// @namespace    https://utilvo.com/
// @version      0.9.0
// @description  Real-time browser security guard: neutralizes ClickFix fake CAPTCHA PowerShell payloads, credit-card Magecart skimmers, and notification scareware completely client-side with zero telemetry.
// @description:ar حماية فورية للمتصفح: إبطال هجمات ClickFix وتلغيم الحافظة (Clipboard Shellcode) وسرقة البطاقات البنكية (Magecart Skimmers) وإشعارات التصيد محلياً بالكامل بدون إرسال أي بيانات.
// @author       Utilvo Security (https://utilvo.com)
// @homepageURL  https://utilvo.com/shield
// @supportURL   https://utilvo.com/shield
// @downloadURL  https://utilvo.com/downloads/utilvo-shield.user.js
// @updateURL    https://utilvo.com/downloads/utilvo-shield.user.js
// @icon         https://utilvo.com/favicon.ico
// @match        http://*/*
// @match        https://*/*
// @run-at       document-start
// @grant        none
// @license      MIT
// ==/UserScript==

// Utilvo Shield - Anti-Skimmer Illusion
//
// Magecart-style credit card skimmers commonly self-disable when they detect DevTools
// is open, to avoid being caught by a researcher inspecting the page. This runs in the
// page's own JS context (MAIN world) and plants the same signals those detection checks
// look for — so skimmers believe they're being watched from the moment the page loads,
// even though DevTools was never actually opened. One-time, no polling loop: zero
// ongoing performance cost.

(function () {
  try {
    // Legacy Firebug global — still checked by several public devtools-detect scripts
    // as a proxy for "an inspection tool is present".
    if (!window.Firebug) {
      window.Firebug = { chrome: { isInitialized: true } };
    }
  } catch (e) {}

  try {
    // A docked DevTools panel shrinks the viewport relative to the outer window.
    // Detection scripts commonly check `outerWidth - innerWidth` / `outerHeight - innerHeight`
    // against a threshold (~160px) — report a permanent gap so that check always trips.
    const GAP = 200;
    Object.defineProperty(window, 'outerWidth', {
      get() { return window.innerWidth + GAP; },
      configurable: true
    });
    Object.defineProperty(window, 'outerHeight', {
      get() { return window.innerHeight + GAP; },
      configurable: true
    });
  } catch (e) {}
})();

// Utilvo Shield - Push Notifications Auto-Deny (MAIN world)
// Neutralizes annoying "Allow notifications?" prompts from websites automatically.
// Runs at document_start in the MAIN world to patch the Notification API before any page script executes.

(() => {
  if (window.__utilvoNotificationDenyLoaded) return;
  window.__utilvoNotificationDenyLoaded = true;

  try {
    if (typeof window.Notification !== 'undefined') {
      const originalRequest = window.Notification.requestPermission;
      
      window.Notification.requestPermission = async function () {
        // Dispatch an event so the isolated world content script can log the stat
        try {
          window.dispatchEvent(new CustomEvent('__utilvo_notification_denied__', {
            detail: { timestamp: Date.now(), host: window.location.hostname }
          }));
        } catch (e) {}

        return 'denied';
      };

      // Also ensure navigator.permissions for 'notifications' reflects prompt/denied gracefully
      if (navigator.permissions && navigator.permissions.query) {
        const originalQuery = navigator.permissions.query;
        navigator.permissions.query = async function (parameters) {
          if (parameters && parameters.name === 'notifications') {
            return {
              state: 'denied',
              status: 'denied',
              name: 'notifications',
              onchange: null
            };
          }
          return originalQuery.apply(this, arguments);
        };
      }
    }
  } catch (e) {}
})();

// Utilvo Shield - Advanced Clipboard Guard (MAIN world)
// Intercepts and neutralizes ClickFix / ClearFake attacks and clipboard hijacking.
// Runs at document_start in the page's MAIN world to hook navigator.clipboard
// before any malicious page scripts execute.
(() => {
  if (window.__utilvoClipboardMainLoaded) return;
  window.__utilvoClipboardMainLoaded = true;

  // Whitelist AI chat assistants, developer/code platforms, and local dev
  const curHost = window.location.hostname.toLowerCase();
  const CLIPBOARD_WHITELIST = [
    "google.com", "google.co", "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "anthropic.com", "claude.ai", "copilot.microsoft.com", "perplexity.ai", "deepseek.com",
    "huggingface.co", "github.com", "github.io", "githubusercontent.com", "gitlab.com",
    "stackoverflow.com", "stackexchange.com", "microsoft.com", "reddit.com", "utilvo.com",
    "localhost", "127.0.0.1"
  ];
  if (
    CLIPBOARD_WHITELIST.some(d => curHost === d || curHost.endsWith("." + d)) ||
    curHost.startsWith("127.") || curHost.endsWith(".local") || curHost.endsWith(".internal")
  ) {
    return;
  }

  // EtherHiding / ClearFake vaccine: disarm known malware entry points
  try {
    window['_efc85d16a'] = 1;
    window['_g32b92'] = 1;
    window['__etherhiding_disarmed__'] = true;
  } catch (e) {}

  const CRYPTO_ADDRESS_RE = /(0x[a-fA-F0-9]{40})|(bc1[a-z0-9]{25,39})|(\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b)/;

  // Strict patterns for ClickFix and automated download-and-execute shell commands.
  // Must match actionable command execution pipelines, NOT simple dictionary words like "powershell".
  const MALWARE_COMMAND_PATTERNS = [
    /\b(irm|Invoke-RestMethod|iwr|Invoke-WebRequest)\b[^\n\r|;]+?\|\s*(iex|Invoke-Expression)\b/i,
    /\b(iex|Invoke-Expression)\s*[\(\{]\s*(irm|iwr|Invoke-RestMethod|Invoke-WebRequest|\[Net\.WebClient\]|New-Object\s+Net\.WebClient)/i,
    /\bpowershell(\.exe)?\s+[^\n\r]*?(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{15,}/i,
    /\bpowershell(\.exe)?\s+[^\n\r]*?(-ep|-executionpolicy)\s+bypass/i,
    /\bpowershell(\.exe)?\s+[^\n\r]*?(-w|-windowstyle)\s+hidden/i,
    /\bpowershell(\.exe)?\s+[^\n\r]*?DownloadString\s*\(/i,
    /\bpowershell(\.exe)?\s+[^\n\r]*?DownloadFile\s*\(/i,
    /\bpowershell(\.exe)?\s+[^\n\r]*?\[Convert\]::FromBase64String/i,
    /\bpowershell(\.exe)?\s+[^\n\r]*?-UserAgent\s+['"][^'"]*WUA/i,
    /@\{\s*['"]X-WUA['"]/i,
    /\bcmd(\.exe)?\s+(\/c|\/k)\s+.*?(powershell|mshta|certutil|bitsadmin)/i,
    /\bmshta(\.exe)?\s+https?:/i,
    /\bcertutil(\.exe)?\s+(-urlcache|-split)\s+https?:/i,
    /\bbitsadmin(\.exe)?\s+\/transfer\s+[^\n\r]+?https?:/i,
    /\b(curl|wget)\b[^\n\r|;]+?\|\s*(ba)?sh\b/i,
    /\brundll32(\.exe)?\s+javascript:/i
  ];

  // Resolve user language preference dynamically
  function getLang() {
    const docLang = document.documentElement && document.documentElement.getAttribute("data-utilvo-lang");
    if (docLang === "ar" || docLang === "en") return docLang;
    if (window.__utilvoLang === "ar" || window.__utilvoLang === "en") return window.__utilvoLang;
    const navLang = (navigator.language || "").toLowerCase();
    return navLang.startsWith("ar") ? "ar" : "en";
  }

  window.addEventListener("message", (event) => {
    if (event.data && event.data.__utilvo === "set-language" && event.data.lang) {
      window.__utilvoLang = event.data.lang;
    }
  });

  function getNeutralizedText() {
    if (getLang() === "ar") {
      return "[Utilvo Shield] 🛑 تم حظر أمر سطر أوامر خبيث (PowerShell/CLI) ومنع نسخه للحافظة لحماية جهازك.";
    }
    return "[Utilvo Shield] 🛑 Malicious shell command execution payload was blocked by Utilvo Shield.";
  }

  const GESTURE_WINDOW_MS = 1200;
  let lastUserGesture = 0;

  const markGesture = () => { lastUserGesture = Date.now(); };
  window.addEventListener("pointerdown", markGesture, true);
  window.addEventListener("keydown", markGesture, true);

  function isShellMalware(text) {
    if (typeof text !== "string" || text.trim().length < 10) return false;
    return MALWARE_COMMAND_PATTERNS.some((pattern) => pattern.test(text));
  }

  function flagMalware(method, payload) {
    try {
      window.postMessage({
        __utilvo: "clipboard-malware",
        subtype: "clickfix-shell",
        method,
        evidence: payload.slice(0, 150),
        fullPayload: payload.slice(0, 500)
      }, window.location.origin);
    } catch {
      window.postMessage({
        __utilvo: "clipboard-malware",
        subtype: "clickfix-shell",
        method,
        evidence: payload.slice(0, 150)
      }, "*");
    }
  }

  function flagCryptoHijack(evidence) {
    try {
      window.postMessage({ __utilvo: "clipboard-hijack", evidence }, window.location.origin);
    } catch {
      window.postMessage({ __utilvo: "clipboard-hijack", evidence }, "*");
    }
  }

  // Centered Modal matching official Utilvo Shield design
  function showInPageMalwareAlert(payload) {
    try {
      if (document.getElementById("utilvo-clickfix-modal-overlay")) return;

      const isAr = getLang() === "ar";
      const snippet = String(payload || "").replace(/</g, "&lt;").replace(/>/g, "&gt;").slice(0, 130);

      const overlay = document.createElement("div");
      overlay.id = "utilvo-clickfix-modal-overlay";
      overlay.setAttribute("dir", isAr ? "rtl" : "ltr");
      overlay.style.cssText = [
        "position: fixed !important",
        "inset: 0 !important",
        "width: 100vw !important",
        "height: 100vh !important",
        "background: rgba(15, 23, 42, 0.65) !important",
        "backdrop-filter: blur(8px) !important",
        "-webkit-backdrop-filter: blur(8px) !important",
        "display: flex !important",
        "align-items: center !important",
        "justify-content: center !important",
        "z-index: 2147483647 !important",
        "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Noto Sans Arabic', sans-serif !important",
        "box-sizing: border-box !important",
        "padding: 16px !important",
        "animation: utilvoFadeIn 0.2s ease-out !important"
      ].join("; ");

      const card = document.createElement("div");
      card.style.cssText = [
        "background: #ffffff !important",
        "color: #0f172a !important",
        "border: 1px solid #e2e8f0 !important",
        "box-shadow: 0 25px 60px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(0, 0, 0, 0.05) !important",
        "border-radius: 24px !important",
        "padding: 28px 26px !important",
        "max-width: 500px !important",
        "width: 100% !important",
        "box-sizing: border-box !important",
        "text-align: center !important",
        "animation: utilvoPopIn 0.25s cubic-bezier(0.16, 1, 0.3, 1) !important"
      ].join("; ");

      const titleText = isAr ? "تم إحباط هجوم ClickFix خبيث!" : "ClickFix Malware Attack Blocked!";
      const descText = isAr
        ? "حاول هذا الموقع نسخ أمر تنفيذي خبيث (<strong style='color:#dc2626;'>PowerShell</strong>) إلى حافظتك لتشغيله في Terminal وسرقة كلمات المرور والبيانات الشخصية."
        : "This site attempted to copy a malicious <strong style='color:#dc2626;'>PowerShell</strong> command into your clipboard to execute in Terminal and steal your passwords.";
      const statusText = isAr
        ? "قام Utilvo Shield بمنع الأمر الخبيث وحماية جهازك بنجاح."
        : "Utilvo Shield blocked the malicious command and protected your device.";
      const closeTabBtn = isAr ? "✕ إغلاق التبويب فوراً" : "✕ Close Tab Immediately";
      const dismissBtn = isAr ? "إغلاق التحذير" : "Dismiss";

      card.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 1px solid #f1f5f9;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="#ef4444"><path d="M12 2L3 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6l-9-4zm-2 15l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
            <div style="font-size: 16px; font-weight: 800; letter-spacing: -0.3px; color: #0f172a;">
              Utilvo <span style="color: #cbd5e1; font-weight: 300;">|</span> <span style="color: #ef4444;">shield</span>
            </div>
          </div>
          <button id="utilvo-alert-x-btn" style="background: transparent; border: none; color: #94a3b8; font-size: 20px; cursor: pointer; padding: 4px; line-height: 1;">✕</button>
        </div>

        <div style="width: 70px; height: 70px; border-radius: 50%; background: #ef4444; color: #ffffff; display: flex; align-items: center; justify-content: center; font-size: 40px; font-weight: 900; margin: 0 auto 16px; box-shadow: 0 10px 25px rgba(239, 68, 68, 0.35);">
          !
        </div>

        <div style="font-size: 20px; font-weight: 800; color: #0f172a; margin-bottom: 8px;">
          ${titleText}
        </div>

        <div style="font-size: 13px; color: #64748b; line-height: 1.6; margin-bottom: 16px;">
          ${descText}
        </div>

        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 11px 14px; margin-bottom: 16px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; color: #dc2626; word-break: break-all; direction: ltr; text-align: left;">
          ${snippet}...
        </div>

        <div style="font-size: 13px; color: #059669; font-weight: 600; margin-bottom: 22px; display: flex; align-items: center; justify-content: center; gap: 6px;">
          <span>✓</span> <span>${statusText}</span>
        </div>

        <div style="display: flex; gap: 12px; justify-content: center; align-items: center;">
          <button id="utilvo-alert-dismiss" style="background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; padding: 11px 20px; border-radius: 12px; font-size: 13px; font-weight: 600; cursor: pointer;">
            ${dismissBtn}
          </button>
          <button id="utilvo-alert-closetab" style="background: #2563eb; color: #ffffff; border: none; padding: 11px 24px; border-radius: 12px; font-size: 13px; font-weight: 700; cursor: pointer; box-shadow: 0 4px 14px rgba(37, 99, 235, 0.35);">
            ${closeTabBtn}
          </button>
        </div>
      `;

      overlay.appendChild(card);
      (document.body || document.documentElement).appendChild(overlay);

      document.getElementById("utilvo-alert-x-btn")?.addEventListener("click", () => overlay.remove());
      document.getElementById("utilvo-alert-dismiss")?.addEventListener("click", () => overlay.remove());
      document.getElementById("utilvo-alert-closetab")?.addEventListener("click", () => {
        window.postMessage({ __utilvo: "close-tab-request" }, "*");
        window.location.href = "about:blank";
      });
    } catch (e) {}
  }

  // Hook 1: navigator.clipboard.writeText
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      const originalWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
      Object.defineProperty(navigator.clipboard, "writeText", {
        configurable: true,
        writable: true,
        value: function (text) {
          if (typeof text === "string" && isShellMalware(text)) {
            const userSelection = window.getSelection ? window.getSelection().toString().trim() : "";
            // If the text being written into clipboard is NOT what the user explicitly highlighted on screen,
            // or if the user has nothing selected, this is a ClickFix payload injection!
            if (!userSelection || text.trim() !== userSelection) {
              flagMalware("writeText", text);
              showInPageMalwareAlert(text);
              return originalWriteText(getNeutralizedText());
            }
          }
          if (CRYPTO_ADDRESS_RE.test(text) && Date.now() - lastUserGesture > GESTURE_WINDOW_MS) {
            flagCryptoHijack(text.slice(0, 50));
          }
          return originalWriteText(text);
        }
      });
    }
  } catch (e) {}

  // Hook 2: navigator.clipboard.write
  try {
    if (navigator.clipboard && typeof navigator.clipboard.write === "function" && typeof ClipboardItem !== "undefined") {
      const originalWrite = navigator.clipboard.write.bind(navigator.clipboard);
      Object.defineProperty(navigator.clipboard, "write", {
        configurable: true,
        writable: true,
        value: async function (items) {
          try {
            if (Array.isArray(items)) {
              for (const item of items) {
                if (item.types && item.types.includes("text/plain")) {
                  const blob = await item.getType("text/plain");
                  const clipboardDataText = await blob.text();
                  if (typeof clipboardDataText === "string" && isShellMalware(clipboardDataText)) {
                    const userSelection = window.getSelection ? window.getSelection().toString().trim() : "";
                    if (!userSelection || clipboardDataText.trim() !== userSelection) {
                      flagMalware("write", clipboardDataText);
                      showInPageMalwareAlert(clipboardDataText);
                      const safeItem = new ClipboardItem({
                        "text/plain": new Blob([getNeutralizedText()], { type: "text/plain" })
                      });
                      return originalWrite([safeItem]);
                    }
                  }
                  if (CRYPTO_ADDRESS_RE.test(clipboardDataText) && Date.now() - lastUserGesture > GESTURE_WINDOW_MS) {
                    flagCryptoHijack(clipboardDataText.slice(0, 50));
                  }
                }
              }
            }
          } catch (e) {}
          return originalWrite(items);
        }
      });
    }
  } catch (e) {}

  // Hook 3: document.execCommand('copy')
  try {
    const originalExecCommand = document.execCommand ? document.execCommand.bind(document) : null;
    if (originalExecCommand) {
      document.execCommand = function (command, showUI, value) {
        if (typeof command === "string" && command.toLowerCase() === "copy") {
          const selected = window.getSelection ? window.getSelection().toString().trim() : "";
          if (isShellMalware(selected)) {
            // Check if this was an invisible or newly injected element (hidden textarea trick)
            const activeEl = document.activeElement;
            const isHiddenElement = activeEl && (
              activeEl.offsetWidth === 0 ||
              activeEl.offsetHeight === 0 ||
              (window.getComputedStyle && (
                window.getComputedStyle(activeEl).opacity === "0" ||
                window.getComputedStyle(activeEl).position === "absolute" ||
                window.getComputedStyle(activeEl).position === "fixed"
              ))
            );
            if (isHiddenElement || Date.now() - lastUserGesture > GESTURE_WINDOW_MS) {
              flagMalware("execCommand", selected);
              showInPageMalwareAlert(selected);
              return false;
            }
          }
        }
        return originalExecCommand(command, showUI, value);
      };
    }
  } catch (e) {}

  // Hook 4: Copy event listener — monitor clipboardData.setData for malicious payload injection
  document.addEventListener("copy", (e) => {
    try {
      if (!e.clipboardData || typeof e.clipboardData.setData !== "function") return;
      const originalSetData = e.clipboardData.setData.bind(e.clipboardData);
      const userSelection = window.getSelection ? window.getSelection().toString().trim() : "";

      e.clipboardData.setData = function (format, data) {
        if (typeof format === "string" && format.toLowerCase().includes("text") && typeof data === "string") {
          // If a script attempts to inject a ClickFix shell command into clipboard
          if (isShellMalware(data)) {
            // Only block if the injected data is NOT what the user explicitly highlighted
            if (!userSelection || data.trim() !== userSelection) {
              flagMalware("copyHijack", data);
              showInPageMalwareAlert(data);
              return originalSetData(format, getNeutralizedText());
            }
          }
          if (CRYPTO_ADDRESS_RE.test(data) && userSelection && data.trim() !== userSelection) {
            flagCryptoHijack(data.slice(0, 50));
          }
        }
        return originalSetData(format, data);
      };
    } catch (err) {}
  }, true);
})();
