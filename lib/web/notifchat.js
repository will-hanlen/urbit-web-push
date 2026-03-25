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
function refocusInput() {
  requestAnimationFrame(function() {
    var el = document.getElementById("input");
    if (el) el.focus();
  });
}
function scrollMessages() {
  var el = document.getElementById("messages");
  if (el) el.scrollTop = el.scrollHeight;
}
var appEl = document.getElementById("app");
if (appEl) {
  new MutationObserver(function() {
    scrollMessages();
    refocusInput();
  }).observe(appEl, {childList: true, subtree: true});
  scrollMessages();
}
async function initNotifState() {
  var sel = document.getElementById("notif-mode");
  if (!sel) return;
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
    sel.disabled = true;
    updateNotifStyle();
    return;
  }
  try {
    var reg = await navigator.serviceWorker.register("/apps/notifchat/~web-pusher/sw.js");
    var sub = await reg.pushManager.getSubscription();
    if (!sub) { sel.value = "off"; return; }
    var cr = await fetch("/apps/notifchat?action=push-check-sub", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({endpoint: sub.endpoint})
    });
    if (!cr.ok) {
      await sub.unsubscribe();
      localStorage.removeItem("push-sub-id");
      sel.value = "off";
      return;
    }
    var pr = await fetch("/apps/notifchat?action=push-prefs");
    var prefs = await pr.json();
    if (prefs.includes("mention")) sel.value = "mention";
    else sel.value = "all";
  } catch(e) { sel.value = "off"; }
  finally { updateNotifStyle(); }
}
async function ensurePushSub() {
  var reg = await navigator.serviceWorker.register("/apps/notifchat/~web-pusher/sw.js");
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
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({id: id, endpoint: sub.endpoint, p256dh: p256dh, auth: auth})
  });
  if (!r.ok) throw new Error("subscribe failed");
  localStorage.setItem("push-sub-id", id);
  return reg;
}
async function removePushSub() {
  var reg = await navigator.serviceWorker.register("/apps/notifchat/~web-pusher/sw.js");
  var sub = await reg.pushManager.getSubscription();
  if (sub) await sub.unsubscribe();
  var id = localStorage.getItem("push-sub-id");
  if (id) {
    await fetch("/apps/notifchat?action=push-unsubscribe", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({id: id})
    });
    localStorage.removeItem("push-sub-id");
  }
}
async function setPrefs(tags) {
  await fetch("/apps/notifchat?action=push-prefs", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({tags: tags})
  });
}
function updateNotifStyle() {
  var sel = document.getElementById("notif-mode");
  if (sel) sel.classList.toggle("off", sel.value === "off");
}
var _prevMode = "off";
async function setNotifMode(mode) {
  var sel = document.getElementById("notif-mode");
  try {
    if (mode === "off") {
      await removePushSub();
      await setPrefs([]);
    } else {
      var reg = await ensurePushSub();
      if (mode === "mention") await setPrefs(["mention"]);
      else await setPrefs([]);
      if (_prevMode === "off") reg.showNotification("notifications enabled");
    }
    _prevMode = mode;
  } catch(e) {
    sel.value = _prevMode;
  }
  updateNotifStyle();
}
initNotifState();
