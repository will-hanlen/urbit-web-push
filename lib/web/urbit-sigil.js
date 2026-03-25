// <urbit-sigil> custom element (shadow DOM)
// Depends on urbit-sigil-gen.js (window.urbitSigil.sigil)
//
// Attributes: point, size, foreground, background, detail, space

class UrbitSigil extends HTMLElement {
  static get observedAttributes() {
    return ['point', 'size', 'foreground', 'background', 'detail', 'space'];
  }
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.shadowRoot.innerHTML = '<style>:host{display:inline;line-height:0}svg{height:0.65em;vertical-align:middle}</style>';
  }
  connectedCallback() { this._render(); }
  attributeChangedCallback() { this._render(); }
  _render() {
    if (!this.isConnected || !window.urbitSigil) return;
    var point = this.getAttribute('point');
    if (!point) return;
    var old = this.shadowRoot.querySelector('svg');
    if (old) old.remove();
    try {
      var svg = window.urbitSigil.sigil({
        point: point.replace(/^~/, ''),
        size: parseInt(this.getAttribute('size') || '128', 10),
        foreground: this.getAttribute('foreground') || 'currentColor',
        background: this.getAttribute('background') || 'transparent',
        detail: this.getAttribute('detail') || 'none',
        space: this.getAttribute('space') || 'none'
      });
      var tpl = document.createElement('template');
      tpl.innerHTML = svg;
      this.shadowRoot.appendChild(tpl.content);
    } catch(e) {}
  }
}
if (!customElements.get('urbit-sigil')) {
  customElements.define('urbit-sigil', UrbitSigil);
}
