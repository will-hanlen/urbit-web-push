var _swReg;
async function getSWReg() {
  if (!_swReg) _swReg = await navigator.serviceWorker.register("/apps/notifchat/~web-pusher/sw.js");
  return _swReg;
}
function urlB64ToUint8(b64) {
  var pad = "=".repeat((4 - b64.length % 4) % 4);
  var raw = atob((b64 + pad).replace(/-/g, "+").replace(/_/g, "/"));
  var arr = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}
function bufToB64Url(buf) {
  var bytes = new Uint8Array(buf);
  var s = "";
  for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function initNotifState() {
  var sel = document.getElementById("notif-mode");
  if (!sel) return;
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
    sel.disabled = true;
    sel.textContent = "notifs unsupported";
    return;
  }
  try {
    var reg = await getSWReg();
    var sub = await reg.pushManager.getSubscription();
    if (!sub) { _prevMode = "off"; return; }
    var cr = await fetch("/apps/notifchat?action=push-check-sub", {
      method: "POST",
      body: new URLSearchParams({endpoint: sub.endpoint})
    });
    if (!cr.ok) {
      await sub.unsubscribe();
      localStorage.removeItem("push-sub-id");
      _prevMode = "off";
      return;
    }
    var pr = await fetch("/apps/notifchat?action=push-prefs");
    var prefs = await pr.json();
    if (prefs.includes("mention")) _prevMode = "mention";
    else _prevMode = "all";
  } catch(e) { _prevMode = "off"; }
  finally { updateNotifStyle(); }
}
async function ensurePushSub() {
  var reg = await getSWReg();
  if (!reg.active) {
    await new Promise(function(resolve) {
      var sw = reg.installing || reg.waiting;
      sw.addEventListener("statechange", function() {
        if (sw.state === "activated") resolve();
      });
    });
  }
  var sub = await reg.pushManager.getSubscription();
  if (sub) return reg;
  var resp = await fetch("/apps/notifchat/~web-pusher/vapid-key");
  var vapidKey = await resp.text();
  sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlB64ToUint8(vapidKey)
  });
  var p256dh = bufToB64Url(sub.getKey("p256dh"));
  var auth = bufToB64Url(sub.getKey("auth"));
  var id = "b-" + Date.now();
  var r = await fetch("/apps/notifchat?action=push-subscribe", {
    method: "POST",
    body: new URLSearchParams({id: id, endpoint: sub.endpoint, p256dh: p256dh, auth: auth})
  });
  if (!r.ok) throw new Error("subscribe failed");
  localStorage.setItem("push-sub-id", id);
  return reg;
}
async function removePushSub() {
  var reg = await getSWReg();
  var sub = await reg.pushManager.getSubscription();
  if (sub) await sub.unsubscribe();
  var id = localStorage.getItem("push-sub-id");
  if (id) {
    await fetch("/apps/notifchat?action=push-unsubscribe", {
      method: "POST",
      body: new URLSearchParams({id: id})
    });
    localStorage.removeItem("push-sub-id");
  }
}
async function setPrefs(tags) {
  await fetch("/apps/notifchat?action=push-prefs", {
    method: "POST",
    body: new URLSearchParams({tags: tags.join(",")})
  });
}
function showError(msg) {
  var banner = document.getElementById("error-banner");
  if (!banner) return;
  banner.querySelector(".error-msg").textContent = msg;
  banner.style.display = "";
  banner.classList.add("visible");
}
var _notifLabels = {off: "turn on notifs", mention: "\uD83D\uDD14 mentions", all: "\uD83D\uDD14 all"};
function updateNotifStyle() {
  var btn = document.getElementById("notif-mode");
  if (!btn) return;
  btn.classList.remove("init");
  btn.classList.toggle("off", _prevMode === "off");
  btn.textContent = _notifLabels[_prevMode] || _notifLabels.off;
}
var _prevMode = "off";
window.setNotifMode = setNotifMode;
async function setNotifMode(mode) {
  var btn = document.getElementById("notif-mode");
  if (btn) btn.classList.add("loading");
  try {
    if (mode === "off") {
      await removePushSub();
    } else {
      var reg = await ensurePushSub();
      if (mode === "mention") await setPrefs(["mention"]);
      else await setPrefs([]);
      if (_prevMode === "off") reg.showNotification("notifications enabled");
    }
    _prevMode = mode;
  } catch(e) {
    console.error("setNotifMode failed:", e);
    if (e.name === "NotAllowedError") {
      showError("notification permission was denied — check your browser settings");
    } else {
      showError("failed to turn on notifications — try again");
    }
  }
  if (btn) btn.classList.remove("loading");
  updateNotifStyle();
}
initNotifState();
