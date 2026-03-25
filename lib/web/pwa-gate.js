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
      this.activate();
      return;
    }

    // Not in PWA — check if it's installed and show the right screen
    this.detectAndRender();

    // Listen for standalone mode activation (covers all browsers)
    const mq = window.matchMedia("(display-mode: standalone)");
    mq.addEventListener("change", (e) => {
      if (e.matches) this.activate();
    });

    // Chrome fires this when the user completes PWA install
    window.addEventListener("appinstalled", () => this.activate());
  }

  activate() {
    try { localStorage.setItem(PwaGate.INSTALLED_KEY, "1"); } catch {}
    this.shadowRoot.innerHTML = `<slot></slot>`;
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
    const isMac = /Mac/.test(navigator.platform) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints <= 1);
    const where = s.isIOS ? "home screen"
      : s.isAndroid ? "home screen or app drawer"
      : isMac ? "Dock or Launchpad"
      : "Dock or taskbar";

    this.shadowRoot.innerHTML = `
      ${this.styles()}
      <div class="container">
        <h1>${this.esc(appName)} is installed</h1>
        <p class="subtitle">Open it from your ${where}.</p>
        <button class="reinstall-link" type="button">Not installed? Reinstall</button>
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
        font-family: system-ui, sans-serif;
        color: var(--text);
        background: var(--bg);
        min-height: 100vh;
        min-height: 100dvh;
      }
      .container {
        max-width: 480px;
        padding: 48px 24px;
      }
      h1 {
        font-size: 22px;
        font-weight: 600;
        color: var(--text-strong);
        margin: 0 0 8px;
      }
      .subtitle {
        color: var(--text-muted);
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
        border-bottom: 1px solid var(--border);
        font-size: 15px;
        line-height: 1.5;
      }
      .steps li::before {
        content: counter(step);
        flex-shrink: 0;
        width: 28px;
        height: 28px;
        border-radius: 50%;
        background: var(--accent);
        color: var(--bg);
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
        background: var(--warn-bg);
        border: 1px solid var(--warn-border);
        border-radius: 8px;
        padding: 12px 16px;
        font-size: 14px;
        line-height: 1.5;
        color: var(--warn-text);
      }
      .reinstall-link {
        background: none;
        border: none;
        color: var(--text-muted);
        font-size: 14px;
        font-family: inherit;
        cursor: pointer;
        padding: 8px 0;
        text-decoration: underline;
        text-underline-offset: 2px;
      }
      .reinstall-link:hover {
        color: var(--text-strong);
      }
    </style>`;
  }

  getInstructions(s, appName) {
    // iOS — wrong browser
    if (s.isIOS && !s.isSafari) {
      return {
        subtitle: "Open this page in <strong>Safari</strong> to install.",
        items: [
          `Tap <strong>Share</strong> ${this.shareIcon()}`,
          `<strong>"Add to Home Screen"</strong>`,
        ],
        warn: null,
      };
    }

    // iOS Safari
    if (s.isIOS) {
      return {
        subtitle: "Add to your home screen for push notifications.",
        items: [
          `Tap <strong>Share</strong> ${this.shareIcon()}`,
          `<strong>"Add to Home Screen"</strong>`,
        ],
        warn: "Requires iOS 16.4+",
      };
    }

    // Android — Firefox (no PWA support)
    if (s.isAndroid && s.isFirefox) {
      return {
        subtitle: "Open this page in <strong>Chrome</strong> to install.",
        items: [
          `Tap <strong>\u22ee</strong> menu`,
          `<strong>"Install app"</strong>`,
        ],
        warn: null,
      };
    }

    // Android — Samsung Browser
    if (s.isAndroid && s.isSamsungBrowser) {
      return {
        subtitle: "Install for push notifications.",
        items: [
          `Tap <strong>\u2630</strong> menu`,
          `<strong>"Add page to" \u2192 "Home screen"</strong>`,
        ],
        warn: null,
      };
    }

    // Android — Chrome / Chromium
    if (s.isAndroid) {
      return {
        subtitle: "Install for push notifications.",
        items: [
          `Tap <strong>\u22ee</strong> menu`,
          `<strong>"Install app"</strong>`,
        ],
        warn: null,
      };
    }

    // Desktop — Chrome / Edge
    if (s.isChrome || s.isEdge) {
      return {
        subtitle: "Install for push notifications.",
        items: [
          `Click the <strong>install icon</strong> in the address bar`,
          `<strong>"Install"</strong>`,
        ],
        warn: null,
      };
    }

    // Desktop Safari (macOS)
    if (s.isSafari) {
      return {
        subtitle: "Install for push notifications.",
        items: [
          `<strong>File \u2192 Add to Dock</strong>`,
        ],
        warn: "Requires macOS Sonoma+",
      };
    }

    // Desktop Firefox
    if (s.isFirefox) {
      return {
        subtitle: "Open in <strong>Chrome</strong> or <strong>Edge</strong> to install.",
        items: [
          `Use the browser's install option`,
        ],
        warn: null,
      };
    }

    // Unknown browser
    return {
      subtitle: "Open in <strong>Chrome</strong>, <strong>Edge</strong>, or <strong>Safari</strong> to install.",
      items: [
        `Use the browser's install or "Add to Home Screen" option`,
      ],
      warn: null,
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
