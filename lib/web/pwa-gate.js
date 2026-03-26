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
    document.body.classList.add("standalone");
    this.style.display = "contents";
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

    // Brave exposes navigator.brave on all platforms including iOS,
    // where its UA string is identical to Safari's.
    const isBrave = !!(navigator.brave && navigator.brave.isBrave);
    // On iOS, only Safari can install PWAs. Detect non-Safari browsers
    // via UA tokens (CriOS, FxiOS) or navigator.brave for Brave.
    const isCriOS = /CriOS/.test(ua);
    const isSafari = isIOS
      ? !isBrave && !isCriOS && !/FxiOS|OPR|Edg/.test(ua)
      : /Safari/.test(ua) && !/Chrome|CriOS|FxiOS|Brave|OPR|Edg/.test(ua);
    const isChrome = /Chrome/.test(ua) && !/Edge|Edg|OPR|Brave/.test(ua);
    const isFirefox = /Firefox|FxiOS/.test(ua);
    const isSamsungBrowser = /SamsungBrowser/.test(ua);
    const isEdge = /Edg/.test(ua);

    const hasServiceWorker = "serviceWorker" in navigator;
    const hasPushManager = "PushManager" in window;
    const canInstall = hasServiceWorker && hasPushManager;

    // Extract iOS version (e.g. "CPU iPhone OS 16_4 like Mac OS X" → 16.4)
    let iosVersion = null;
    if (isIOS) {
      const m = ua.match(/OS (\d+)[._](\d+)/);
      if (m) iosVersion = parseFloat(`${m[1]}.${m[2]}`);
    }

    return {
      isIOS, isAndroid, isSafari, isChrome, isCriOS, isBrave,
      isFirefox, isSamsungBrowser, isEdge, iosVersion,
      hasServiceWorker, hasPushManager, canInstall,
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
        <h1>${this.esc(appName)}</h1>
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
        min-height: 100vh;
        min-height: 100dvh;
      }
      .container {
        max-width: 480px;
        margin: 0 auto;
        padding: 48px 24px;
        text-align: center;
      }
      h1 {
        font-size: 20px;
        font-weight: 600;
        color: var(--text-strong);
        margin: 0 0 6px;
      }
      .subtitle {
        color: var(--text-muted);
        margin: 0 0 32px;
        font-size: 17px;
        line-height: 1.4;
      }
      .steps {
        list-style: none;
        padding: 0;
        margin: 0 0 32px;
        counter-reset: step;
        text-align: left;
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
        text-align: left;
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
    // iOS — any browser other than Safari can't install PWAs
    if (s.isIOS && !s.isSafari) {
      return {
        subtitle: "Install as an app to continue. Open this page in <strong>Safari</strong>.",
        items: [
          `Copy this page's URL`,
          `Open <strong>Safari</strong> and paste it in the address bar`,
          `Tap <strong>\u22ef</strong> (three dots) in the bottom bar, then tap <strong>Share</strong> ${this.shareIcon()}`,
          `Scroll down and tap <strong>"Add to Home Screen"</strong>`,
          `Tap <strong>"Add"</strong> in the top right`,
        ],
        warn: null,
      };
    }

    // iOS Safari
    if (s.isIOS) {
      return {
        subtitle: "Install as an app to continue.",
        items: [
          `Tap <strong>\u22ef</strong> (three dots) in the bottom bar, then tap <strong>Share</strong> ${this.shareIcon()}`,
          `Scroll down and tap <strong>"Add to Home Screen"</strong>`,
          `Tap <strong>"Add"</strong> in the top right`,
        ],
        warn: s.iosVersion !== null && s.iosVersion < 16.4 ? "Requires iOS 16.4+" : null,
      };
    }

    // Android — browser without PWA support
    if (s.isAndroid && !s.canInstall) {
      return {
        subtitle: "Install as an app to continue. Open this page in <strong>Chrome</strong>.",
        items: [
          `Tap <strong>\u22ee</strong> (three dots) in the top right`,
          `Tap <strong>"Install app"</strong>`,
        ],
        warn: null,
      };
    }

    // Android — Samsung Browser
    if (s.isAndroid && s.isSamsungBrowser) {
      return {
        subtitle: "Install as an app to continue.",
        items: [
          `Tap <strong>\u2630</strong> (menu) in the bottom right`,
          `Tap <strong>"Add page to"</strong> then <strong>"Home screen"</strong>`,
        ],
        warn: null,
      };
    }

    // Android — Chrome / Chromium
    if (s.isAndroid) {
      return {
        subtitle: "Install as an app to continue.",
        items: [
          `Tap <strong>\u22ee</strong> (three dots) in the top right`,
          `Tap <strong>"Install app"</strong>`,
        ],
        warn: null,
      };
    }

    // Desktop — browser without install support
    if (!s.canInstall) {
      const suggest = s.isSafari ? "<strong>Chrome</strong> or <strong>Edge</strong>"
        : "<strong>Chrome</strong>, <strong>Edge</strong>, or <strong>Safari</strong>";
      return {
        subtitle: `Install as an app to continue. Open in ${suggest}.`,
        items: [
          `Use the browser's install option`,
        ],
        warn: null,
      };
    }

    // Desktop — Chrome / Edge
    if (s.isChrome || s.isEdge) {
      return {
        subtitle: "Install as an app to continue.",
        items: [
          `Click the <strong>install icon</strong> in the address bar and confirm`,
        ],
        warn: null,
      };
    }

    // Desktop Safari (macOS)
    if (s.isSafari) {
      return {
        subtitle: "Install as an app to continue.",
        items: [
          `Click <strong>File</strong> in the menu bar`,
          `Click <strong>"Add to Dock\u2026"</strong>`,
          `Click <strong>"Add"</strong>`,
        ],
        warn: "Requires macOS Sonoma+",
      };
    }

    // Unknown browser with install support
    return {
      subtitle: "Install as an app to continue.",
      items: [
        `Use the browser's install option`,
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
