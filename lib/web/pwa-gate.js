class PwaGate extends HTMLElement {
  static INSTALLED_KEY = "pwa-gate-installed";

  constructor() {
    super();
    this.attachShadow({ mode: "open" });
  }

  connectedCallback() {
    const isStandalone =
      window.matchMedia("(display-mode: standalone)").matches ||
      window.matchMedia("(display-mode: window-controls-overlay)").matches ||
      navigator.standalone === true;

    if (isStandalone) {
      // Mark as installed for future browser visits
      try { localStorage.setItem(PwaGate.INSTALLED_KEY, "1"); } catch {}
      this.shadowRoot.innerHTML = `<slot></slot>`;
      return;
    }

    // Not in PWA — check if it's installed and show the right screen
    this.detectAndRender();
  }

  async detectAndRender() {
    const support = this.detectSupport();
    const installed = await this.checkInstalled();

    if (installed) {
      this.renderOpenApp(support);
    } else {
      this.renderInstallPage(support);
    }
  }

  async checkInstalled() {
    // Check localStorage flag (set when PWA runs)
    try {
      if (localStorage.getItem(PwaGate.INSTALLED_KEY) === "1") return true;
    } catch {}

    // Chromium: getInstalledRelatedApps (requires related_applications in manifest)
    if ("getInstalledRelatedApps" in navigator) {
      try {
        const apps = await navigator.getInstalledRelatedApps();
        if (apps.length > 0) return true;
      } catch {}
    }

    return false;
  }

  detectSupport() {
    const ua = navigator.userAgent;
    const isIOS =
      /iPad|iPhone|iPod/.test(ua) ||
      (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    const isAndroid = /Android/.test(ua);
    const isChrome = /Chrome/.test(ua) && !/Edge|Edg|OPR|Brave/.test(ua);
    const isFirefox = /Firefox/.test(ua);
    const isSafari = /Safari/.test(ua) && !/Chrome|CriOS|FxiOS/.test(ua);
    const isSamsungBrowser = /SamsungBrowser/.test(ua);
    const isEdge = /Edg/.test(ua);

    const hasNotificationAPI = "Notification" in window;
    const hasServiceWorker = "serviceWorker" in navigator;
    const hasPushManager = "PushManager" in window;

    return {
      isIOS, isAndroid, isChrome, isFirefox, isSafari,
      isSamsungBrowser, isEdge,
      hasServiceWorker, hasNotificationAPI, hasPushManager,
    };
  }

  renderOpenApp(s) {
    const appName = this.getAttribute("name") || document.title || "this app";
    const hint = s.isIOS
      ? "Find it on your home screen."
      : s.isAndroid
        ? "Find it in your home screen or app drawer."
        : "Find it in your applications or taskbar.";

    this.shadowRoot.innerHTML = `
      ${this.styles()}
      <div class="container">
        <h1>${this.esc(appName)} is installed</h1>
        <p class="subtitle">Open the installed app for the best experience with push notifications. ${hint}</p>
        <div class="open-hint">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#1a1a1a" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="5" y="2" width="14" height="20" rx="2" ry="2"/>
            <line x1="12" y1="18" x2="12.01" y2="18"/>
          </svg>
          <p>Look for <strong>${this.esc(appName)}</strong> on your device and tap to open it.</p>
        </div>
        <button class="reinstall-link" type="button">Not installed? Show install instructions</button>
      </div>
    `;

    this.shadowRoot.querySelector(".reinstall-link").addEventListener("click", () => {
      try { localStorage.removeItem(PwaGate.INSTALLED_KEY); } catch {}
      this.renderInstallPage(s);
    });
  }

  renderInstallPage(s) {
    const appName = this.getAttribute("name") || document.title || "this app";
    const steps = this.getInstructions(s, appName);

    this.shadowRoot.innerHTML = `
      ${this.styles()}
      <div class="container">
        <h1>Install ${this.esc(appName)}</h1>
        <p class="subtitle">${steps.subtitle}</p>
        <ol class="steps">
          ${steps.items.map((t) => `<li><span>${t}</span></li>`).join("")}
        </ol>
        ${steps.warn ? `<div class="warn">${steps.warn}</div>` : ""}
      </div>
    `;
  }

  styles() {
    return `<style>
      :host {
        display: block;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #1a1a1a;
        background: #f8f8f8;
        min-height: 100vh;
        min-height: 100dvh;
      }
      .container {
        max-width: 480px;
        margin: 0 auto;
        padding: 48px 24px;
      }
      h1 {
        font-size: 22px;
        margin: 0 0 8px;
      }
      .subtitle {
        color: #666;
        margin: 0 0 32px;
        font-size: 15px;
        line-height: 1.4;
      }
      .steps {
        list-style: none;
        padding: 0;
        margin: 0 0 32px;
        counter-reset: step;
      }
      .steps li {
        counter-increment: step;
        display: flex;
        gap: 16px;
        align-items: flex-start;
        padding: 16px 0;
        border-bottom: 1px solid #e5e5e5;
        font-size: 15px;
        line-height: 1.5;
      }
      .steps li::before {
        content: counter(step);
        flex-shrink: 0;
        width: 28px;
        height: 28px;
        border-radius: 50%;
        background: #1a1a1a;
        color: #fff;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 13px;
        font-weight: 600;
      }
      .steps li:last-child {
        border-bottom: none;
      }
      .warn {
        background: #fff3cd;
        border: 1px solid #e6d370;
        border-radius: 8px;
        padding: 12px 16px;
        font-size: 14px;
        line-height: 1.5;
        color: #664d03;
      }
      .open-hint {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
        padding: 32px 0;
        text-align: center;
        font-size: 15px;
        line-height: 1.5;
      }
      .open-hint p {
        margin: 0;
      }
      .reinstall-link {
        background: none;
        border: none;
        color: #666;
        font-size: 14px;
        cursor: pointer;
        padding: 8px 0;
        text-decoration: underline;
        text-underline-offset: 2px;
      }
      .reinstall-link:hover {
        color: #1a1a1a;
      }
    </style>`;
  }

  getInstructions(s, appName) {
    // iOS — wrong browser
    if (s.isIOS && !s.isSafari) {
      return {
        subtitle: "This app needs to be installed from Safari to support push notifications.",
        items: [
          `Open this page in <strong>Safari</strong>. Copy the URL from the address bar and paste it into Safari.`,
          `Tap the <strong>Share</strong> button ${this.shareIcon()} at the bottom of the screen.`,
          `Scroll down and tap <strong>"Add to Home Screen"</strong>.`,
          `Tap <strong>"Add"</strong>, then open ${this.esc(appName)} from your home screen.`,
        ],
        warn: null,
      };
    }

    // iOS Safari
    if (s.isIOS) {
      return {
        subtitle: "Install this app to your home screen to enable push notifications.",
        items: [
          `Tap the <strong>Share</strong> button ${this.shareIcon()} at the bottom of the screen.`,
          `Scroll down and tap <strong>"Add to Home Screen"</strong>.`,
          `Tap <strong>"Add"</strong> to install.`,
          `Open <strong>${this.esc(appName)}</strong> from your home screen.`,
        ],
        warn: "Push notifications on iOS require iOS 16.4 or later and the app must be installed to your home screen.",
      };
    }

    // Android — Firefox (no PWA support)
    if (s.isAndroid && s.isFirefox) {
      return {
        subtitle: "Firefox on Android does not support installing web apps. Please switch to Chrome.",
        items: [
          `Open this page in <strong>Chrome</strong>.`,
          `Tap the <strong>\u22ee menu</strong> in the top right.`,
          `Tap <strong>"Install app"</strong> or <strong>"Add to Home screen"</strong>.`,
          `Open <strong>${this.esc(appName)}</strong> from your home screen.`,
        ],
        warn: null,
      };
    }

    // Android — Samsung Browser
    if (s.isAndroid && s.isSamsungBrowser) {
      return {
        subtitle: "Install this app for push notifications.",
        items: [
          `Tap the <strong>\u2630 menu</strong> in the bottom right.`,
          `Tap <strong>"Add page to"</strong> then <strong>"Home screen"</strong>.`,
          `Open <strong>${this.esc(appName)}</strong> from your home screen.`,
        ],
        warn: "For the best experience, consider using <strong>Chrome</strong> which has full PWA install support.",
      };
    }

    // Android — Chrome / Chromium
    if (s.isAndroid) {
      return {
        subtitle: "Install this app for push notifications.",
        items: [
          `Tap the <strong>\u22ee menu</strong> in the top right corner.`,
          `Tap <strong>"Install app"</strong> or <strong>"Add to Home screen"</strong>.`,
          `Tap <strong>"Install"</strong> to confirm.`,
          `Open <strong>${this.esc(appName)}</strong> from your home screen or app drawer.`,
        ],
        warn: null,
      };
    }

    // Desktop — Chrome / Edge
    if (s.isChrome || s.isEdge) {
      return {
        subtitle: "Install this app for push notifications.",
        items: [
          `Click the <strong>install icon</strong> in the address bar (right side), or open the <strong>\u22ee menu</strong>.`,
          `Click <strong>"Install ${this.esc(appName)}"</strong>.`,
          `The app will open in its own window.`,
        ],
        warn: null,
      };
    }

    // Desktop Safari (macOS)
    if (s.isSafari) {
      return {
        subtitle: "Install this app for push notifications.",
        items: [
          `In the menu bar, click <strong>File \u2192 Add to Dock</strong>.`,
          `The app will appear in your Dock. Open it from there.`,
        ],
        warn: "Requires macOS Sonoma (14.0) or later. On older versions, use <strong>Chrome</strong> or <strong>Edge</strong> instead.",
      };
    }

    // Desktop Firefox
    if (s.isFirefox) {
      return {
        subtitle: "Firefox does not support installing web apps with push notifications.",
        items: [
          `Open this page in <strong>Chrome</strong> or <strong>Edge</strong>.`,
          `Use the browser's install option to add the app.`,
          `Open the installed app for push notification support.`,
        ],
        warn: null,
      };
    }

    // Unknown browser
    return {
      subtitle: "This app works best when installed. Use a supported browser to install it.",
      items: [
        `Open this page in <strong>Chrome</strong>, <strong>Edge</strong>, or <strong>Safari</strong>.`,
        `Use the browser's install or "Add to Home Screen" option.`,
        `Open the installed app for the full experience with push notifications.`,
      ],
      warn: "Your current browser may not support push notifications. Try <strong>Chrome</strong> or <strong>Edge</strong> for the best experience.",
    };
  }

  shareIcon() {
    return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px"><path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg>`;
  }

  esc(str) {
    const el = document.createElement("span");
    el.textContent = str;
    return el.innerHTML;
  }
}

customElements.define("pwa-gate", PwaGate);
