class UrbitTime extends HTMLElement {
  connectedCallback() {
    this._update();
    this._iv = setInterval(() => this._update(), 60000);
  }
  disconnectedCallback() { clearInterval(this._iv); }
  _update() {
    var da = this.getAttribute("da");
    if (!da) return;
    var d = this._parse(da);
    if (!d) return;
    var now = new Date();
    var diff = now - d;
    var sec = Math.floor(diff / 1000);
    if (sec < 0) sec = 0;
    this.title = d.toLocaleString();
    if (sec < 86400) {
      if (sec < 60) this.textContent = "just now";
      else if (sec < 3600) this.textContent = Math.floor(sec / 60) + "m ago";
      else this.textContent = Math.floor(sec / 3600) + "h ago";
    } else {
      var y = d.getFullYear();
      var m = String(d.getMonth() + 1).padStart(2, "0");
      var day = String(d.getDate()).padStart(2, "0");
      this.textContent = y + "-" + m + "-" + day;
      clearInterval(this._iv);
    }
  }
  _parse(da) {
    // ~2026.3.25..14.30.00..0000
    var s = da.replace(/^~/, "");
    var parts = s.split("..");
    var date = parts[0].split(".");
    var time = parts[1] ? parts[1].split(".") : [0, 0, 0];
    return new Date(Date.UTC(+date[0], +date[1] - 1, +date[2], +time[0], +time[1], +time[2]));
  }
}
customElements.define("urbit-time", UrbitTime);
