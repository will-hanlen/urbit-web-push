class UrbitPatp extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.shadowRoot.innerHTML = '<style>:host{display:inline-flex;align-items:center;gap:3px;cursor:pointer;color:inherit}:host(:hover) span{text-decoration:underline}urbit-sigil{opacity:0.8}hr{display:none;flex:1;border:none;border-top:1.5px solid;color:inherit;opacity:0.6;margin:0}</style><span></span><hr><slot></slot>';
  }
  connectedCallback() {
    if (this._init) return;
    this._init = true;
    this._patp = this.getAttribute('patp') || this.textContent.trim();
    this._display = this.textContent.trim() || this._patp;
    this._textEl = this.shadowRoot.querySelector('span');
    this._hrEl = this.shadowRoot.querySelector('hr');
    this._textEl.textContent = this._display;
    this.textContent = '';
    if (this._canSigil(this._patp)) {
      var s = document.createElement('urbit-sigil');
      s.setAttribute('point', this._patp);
      s.setAttribute('size', '12');
      s.setAttribute('foreground', 'currentColor');
      s.setAttribute('background', 'transparent');
      s.setAttribute('detail', 'none');
      s.setAttribute('space', 'none');
      this._sigil = s;
      this.shadowRoot.appendChild(s);
    }
    this.addEventListener('click', function() { this._copy(); }.bind(this));
  }
  _copy() {
    navigator.clipboard.writeText(this._patp);
    var w = this.offsetWidth;
    this.style.minWidth = w + 'px';
    this._textEl.textContent = 'copied';
    if (this._sigil) this._sigil.style.display = 'none';
    this._hrEl.style.display = 'block';
    clearTimeout(this._timer);
    this._timer = setTimeout(function() {
      this._textEl.textContent = this._display;
      if (this._sigil) this._sigil.style.display = '';
      this._hrEl.style.display = 'none';
      this.style.minWidth = '';
    }.bind(this), 1000);
  }
  _canSigil(patp) {
    return patp.replace(/^~/, '').split('-').length <= 2;
  }
}
customElements.define('urbit-patp', UrbitPatp);
