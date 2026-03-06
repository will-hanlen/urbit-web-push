::  app/push: web push notification demo agent
::
::  Wrapped by web-pusher to handle VAPID keys, browser
::  subscriptions, encryption, and delivery tracking.
::  This agent serves the UI and delegates all push
::  operations to the wrapper.
::
/-  push
/+  web-pusher, default-agent, verb, server
::
|%
+$  card  card:agent:gall
+$  versioned-state
  $%  [%0 state-0]
  ==
+$  state-0  ~
--
::
=|  state-0
=*  state  -
::
%+  verb  |
%-  %:  agent:web-pusher
      /apps/push
      'mailto:you@example.com'
      %.y
      200
    ==
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
::
++  on-init   `this
++  on-save   !>(state)
++  on-load
  |=  =vase
  ^-  (quip card _this)
  `this
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  |^
  ?.  ?=(%handle-http-request mark)
    (on-poke:def mark vase)
  =+  !<([eyre-id=@ta =inbound-request:eyre] vase)
  =/  rl  (parse-request-line:server url.request.inbound-request)
  =/  site=path  site.rl
  =/  meth=@t  method.request.inbound-request
  ?.  authenticated.inbound-request
    :_  this
    ?:  =([~ /apps/push] [ext.rl site.rl])
      %+  give-simple-payload:app:server  eyre-id
      (login-redirect:gen:server request.inbound-request)
    (err-cards eyre-id 403 'not authenticated')
  :_  this
  ?:  &(=('GET' meth) =(site /apps/push))
    %+  give-simple-payload:app:server  eyre-id
    (html-response:gen:server page-html)
  ?:  &(=('GET' meth) =(site /apps/push/state))
    (get-state eyre-id)
  ?:  &(=('POST' meth) =(site /apps/push/send))
    (do-send eyre-id body.request.inbound-request)
  (give-simple-payload:app:server eyre-id not-found:gen:server)
  ++  do-send
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (list card)
    ?~  body  (err-cards eyre-id 400 'no body')
    =/  jon=(unit json)  (de:json:html q.u.body)
    ?~  jon  (err-cards eyre-id 400 'invalid json')
    ?.  ?=(%o -.u.jon)  (err-cards eyre-id 400 'expected object')
    =/  obj  p.u.jon
    =/  title-j  (~(get by obj) 'title')
    =/  body-j   (~(get by obj) 'body')
    ?.  ?&  ?=(^ title-j)  ?=(%s -.u.title-j)
            ?=(^ body-j)   ?=(%s -.u.body-j)
        ==
      (err-cards eyre-id 400 'title and body required')
    =/  icon=(unit @t)
      =/  v  (~(get by obj) 'icon')
      ?~(v ~ ?.(?=(%s -.u.v) ~ `p.u.v))
    =/  url=(unit @t)
      =/  v  (~(get by obj) 'url')
      ?~(v ~ ?.(?=(%s -.u.v) ~ `p.u.v))
    =/  tag=(unit @t)
      =/  v  (~(get by obj) 'tag')
      ?~(v ~ ?.(?=(%s -.u.v) ~ `p.u.v))
    =/  msg=push-message:push  [p.u.title-j p.u.body-j icon url tag]
    =/  target  [*(set @p) msg]
    :*  [%pass /notify %agent [our dap]:bowl %poke %push-send !>(target)]
        (ok-cards eyre-id)
    ==
  ++  get-state
    |=  eyre-id=@ta
    ^-  (list card)
    =/  ps=pusher-state:push
      .^(pusher-state:push %gx /(scot %p our.bowl)/[dap.bowl]/(scot %da now.bowl)/web-pusher/state/noun)
    =/  vapid-pub=@t
      ?~  config.ps  ''
      (~(en base64:mimes:html | &) [65 (rev 3 65 public-key.u.config.ps)])
    =/  conf-json=json
      ?~  config.ps  ~
      %-  pairs:enjs:format
      :~  ['sub' [%s sub.u.config.ps]]
          ['public-key' [%s vapid-pub]]
      ==
    =/  subs-json=json
      :-  %a
      %-  zing
      %+  turn  ~(tap by subs.ps)
      |=  [=ship inner=(map @ta subscription:push)]
      %+  turn  ~(tap by inner)
      |=  [id=@ta sub=subscription:push]
      %-  pairs:enjs:format
      :~  ['ship' [%s (scot %p ship)]]
          ['id' [%s id]]
          ['endpoint' [%s endpoint.sub]]
      ==
    =/  sends-json=json
      :-  %a
      %+  murn  send-order.ps
      |=  key=send-key:push
      =/  del  (~(get by sends.ps) key)
      ?~  del  ~
      %-  some
      %-  pairs:enjs:format
      :~  ['ship' [%s (scot %p ship.key)]]
          ['sub-id' [%s sub-id.key]]
          ['title' [%s title.u.del]]
          :-  'sent-at'
          [%n (crip (a-co:co (mul 1.000 (unm:chrono:userlib sent-at.u.del))))]
          ['status' [%s (scot %tas delivery-status.u.del)]]
      ==
    =/  state-json=json
      %-  pairs:enjs:format
      :~  ['config' conf-json]
          ['subs' subs-json]
          ['sends' sends-json]
      ==
    %+  give-simple-payload:app:server  eyre-id
    (json-response:gen:server state-json)
  ++  ok-cards
    |=  eyre-id=@ta
    ^-  (list card)
    %+  give-simple-payload:app:server  eyre-id
    %-  json-response:gen:server
    [%o (~(gas by *(map @t json)) ~[['ok' [%b &]]])]
  ++  err-cards
    |=  [eyre-id=@ta code=@ud msg=@t]
    ^-  (list card)
    =/  bod=json  [%o (~(gas by *(map @t json)) ~[['error' [%s msg]]])]
    %+  give-simple-payload:app:server  eyre-id
    [[code [['content-type' 'application/json'] ~]] `(json-to-octs:server bod)]
  ++  page-html
    ^-  octs
    %-  as-octs:mimes:html
    '''
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Push Notifications - Urbit</title>
    <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 700px;
      margin: 2rem auto; padding: 0 1rem; color: #333; }
    h1 { font-size: 1.4rem; }
    h2 { font-size: 1.1rem; margin-top: 1.5rem; }
    .status { padding: 0.75rem 1rem; margin: 1rem 0; border-radius: 6px;
      font-size: 0.9rem; }
    .ok { background: #d4edda; color: #155724; }
    .err { background: #f8d7da; color: #721c24; }
    .info { background: #cce5ff; color: #004085; }
    button { padding: 0.5rem 1rem; border: 1px solid #ccc; border-radius: 4px;
      cursor: pointer; font-size: 0.9rem; background: #fff; }
    button:disabled { opacity: 0.5; cursor: default; }
    button:hover:not(:disabled) { background: #e9ecef; }
    .btn-row { display: flex; gap: 0.5rem; margin: 1rem 0; }
    fieldset { border: 1px solid #ddd; border-radius: 6px; padding: 1rem;
      margin: 1.5rem 0; }
    legend { font-weight: 600; padding: 0 0.5rem; }
    label { display: block; font-size: 0.85rem; color: #666;
      margin-top: 0.75rem; }
    input, textarea { display: block; width: 100%; padding: 0.5rem;
      border: 1px solid #ccc; border-radius: 4px; font-size: 0.9rem;
      margin-top: 0.25rem; }
    textarea { resize: vertical; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem;
      margin: 0.5rem 0; }
    th, td { text-align: left; padding: 0.4rem 0.6rem;
      border-bottom: 1px solid #e9ecef; }
    th { font-weight: 600; color: #666; }
    td.mono { font-family: monospace; font-size: 0.8rem; }
    .badge { display: inline-block; padding: 0.15rem 0.5rem;
      border-radius: 3px; font-size: 0.75rem; font-weight: 600; }
    .badge-sent { background: #d4edda; color: #155724; }
    .badge-pending { background: #fff3cd; color: #856404; }
    .badge-failed { background: #f8d7da; color: #721c24; }
    .badge-expired { background: #e2e3e5; color: #383d41; }
    .badge-gone { background: #e2e3e5; color: #383d41; }
    .empty { color: #999; font-style: italic; font-size: 0.85rem; }
    #log { font-family: monospace; font-size: 0.8rem; white-space: pre-wrap;
      word-break: break-all; background: #f8f9fa; border: 1px solid #e9ecef;
      border-radius: 4px; padding: 0.75rem; max-height: 200px;
      overflow-y: auto; margin-top: 0.5rem; }
    </style>
    </head>
    <body>
    <h1>Push Notifications</h1>
    <div id="status" class="status info">Checking browser support...</div>
    <div class="btn-row">
    <button id="btn-sub" disabled>Subscribe this browser</button>
    <button id="btn-unsub" disabled>Unsubscribe</button>
    </div>
    <fieldset>
    <legend>Send notification</legend>
    <label>Title</label>
    <input id="n-title" value="Hello from Urbit">
    <label>Body</label>
    <textarea id="n-body" rows="2">This is a test notification</textarea>
    <label>Icon URL (optional)</label>
    <input id="n-icon" placeholder="https://...">
    <label>Click URL (optional)</label>
    <input id="n-url" placeholder="https://...">
    <label>Tag (optional)</label>
    <input id="n-tag" placeholder="e.g. chat-message">
    <div style="margin-top:1rem">
    <button id="btn-send">Send to all subscribers</button>
    </div>
    </fieldset>
    <h2>VAPID Config</h2>
    <div id="vapid-info" class="empty">Loading...</div>
    <h2>Subscribers</h2>
    <div id="subs-info"></div>
    <h2>Delivery Log</h2>
    <div id="sends-info"></div>
    <details>
    <summary style="cursor:pointer;font-size:0.9rem;margin-top:1rem">Debug Log</summary>
    <div id="log"></div>
    </details>
    <script>
    var P = "/apps/push/~web-pusher";
    var logEl = document.getElementById("log");
    var statusEl = document.getElementById("status");
    var subBtn = document.getElementById("btn-sub");
    var unsubBtn = document.getElementById("btn-unsub");
    var sendBtn = document.getElementById("btn-send");
    var swReg = null;
    function log(msg) {
      logEl.textContent += msg + "\n";
      logEl.scrollTop = logEl.scrollHeight;
    }
    function setStatus(msg, cls) {
      statusEl.textContent = msg;
      statusEl.className = "status " + cls;
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
    function esc(s) {
      var d = document.createElement("div");
      d.textContent = s;
      return d.innerHTML;
    }
    function truncate(s, n) {
      return s.length > n ? s.substring(0, n) + "..." : s;
    }
    function badgeClass(status) {
      if (status === "sent") return "badge-sent";
      if (status === "pending") return "badge-pending";
      if (status === "failed") return "badge-failed";
      return "badge-expired";
    }
    function loadState() {
      fetch("/apps/push/state").then(function(r) { return r.json(); })
      .then(function(st) {
        var vi = document.getElementById("vapid-info");
        if (st.config && st.config.sub) {
          vi.innerHTML = '<table><tr><th>Contact</th>' +
            '<td class="mono">' + esc(st.config.sub) + '</td></tr>' +
            '<tr><th>Public Key</th>' +
            '<td class="mono">' + esc(truncate(st.config["public-key"], 40)) +
            '</td></tr></table>';
        } else {
          vi.innerHTML = '<span class="empty">Not configured</span>';
        }
        var si = document.getElementById("subs-info");
        if (st.subs && st.subs.length > 0) {
          var h = '<table><tr><th>Ship</th><th>ID</th><th>Endpoint</th></tr>';
          st.subs.forEach(function(sub) {
            h += '<tr><td class="mono">' + esc(sub.ship) +
              '</td><td class="mono">' + esc(sub.id) +
              '</td><td class="mono">' + esc(truncate(sub.endpoint, 50)) +
              '</td></tr>';
          });
          si.innerHTML = h + '</table>';
        } else {
          si.innerHTML = '<span class="empty">No subscribers</span>';
        }
        var di = document.getElementById("sends-info");
        if (st.sends && st.sends.length > 0) {
          var h = '<table><tr><th>Time</th><th>Title</th>' +
            '<th>Ship</th><th>Sub ID</th><th>Status</th></tr>';
          st.sends.forEach(function(d) {
            var t = new Date(d["sent-at"]).toLocaleString();
            h += '<tr><td>' + esc(t) + '</td>' +
              '<td>' + esc(d.title) + '</td>' +
              '<td class="mono">' + esc(d.ship) + '</td>' +
              '<td class="mono">' + esc(d["sub-id"]) + '</td>' +
              '<td><span class="badge ' + badgeClass(d.status) + '">' +
              esc(d.status) + '</span></td></tr>';
          });
          di.innerHTML = h + '</table>';
        } else {
          di.innerHTML = '<span class="empty">No notifications sent yet</span>';
        }
      }).catch(function(e) { log("State load error: " + e); });
    }
    async function init() {
      if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
        setStatus("Push notifications not supported in this browser", "err");
        return;
      }
      try {
        swReg = await navigator.serviceWorker.register("/apps/push/~web-pusher/sw.js");
        log("Service worker registered");
        var sub = await swReg.pushManager.getSubscription();
        if (sub) {
          var cr = await fetch(P + "/check-sub", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({endpoint: sub.endpoint})
          });
          if (cr.ok) {
            setStatus("This browser is subscribed", "ok");
            unsubBtn.disabled = false;
            log("Active subscription found");
          } else {
            await sub.unsubscribe();
            localStorage.removeItem("push-sub-id");
            setStatus("This browser is not subscribed", "info");
            subBtn.disabled = false;
            log("Stale subscription cleared");
          }
        } else {
          setStatus("This browser is not subscribed", "info");
          subBtn.disabled = false;
        }
        loadState();
      } catch(e) {
        setStatus("Error: " + e.message, "err");
        log("Init error: " + e);
      }
    }
    subBtn.addEventListener("click", async function() {
      try {
        subBtn.disabled = true;
        var resp = await fetch(P + "/vapid-key");
        var vapidKey = await resp.text();
        log("Got VAPID key");
        var sub = await swReg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlB64ToUint8(vapidKey)
        });
        var p256dh = bufToB64Url(sub.getKey("p256dh"));
        var auth = bufToB64Url(sub.getKey("auth"));
        var id = "b-" + Date.now();
        var r = await fetch(P + "/subscribe", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({id: id, endpoint: sub.endpoint,
            p256dh: p256dh, auth: auth})
        });
        if (!r.ok) throw new Error("Server returned " + r.status);
        localStorage.setItem("push-sub-id", id);
        setStatus("This browser is subscribed", "ok");
        unsubBtn.disabled = false;
        log("Subscribed with id: " + id);
        loadState();
      } catch(e) {
        setStatus("Subscribe failed: " + e.message, "err");
        subBtn.disabled = false;
        log("Subscribe error: " + e);
      }
    });
    unsubBtn.addEventListener("click", async function() {
      try {
        unsubBtn.disabled = true;
        var sub = await swReg.pushManager.getSubscription();
        if (sub) await sub.unsubscribe();
        var id = localStorage.getItem("push-sub-id");
        if (id) {
          await fetch(P + "/unsubscribe", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({id: id})
          });
          localStorage.removeItem("push-sub-id");
        }
        setStatus("This browser is not subscribed", "info");
        subBtn.disabled = false;
        log("Unsubscribed");
        loadState();
      } catch(e) {
        setStatus("Unsubscribe error: " + e.message, "err");
        unsubBtn.disabled = false;
        log("Error: " + e);
      }
    });
    sendBtn.addEventListener("click", async function() {
      var msg = {
        title: document.getElementById("n-title").value,
        body: document.getElementById("n-body").value
      };
      var icon = document.getElementById("n-icon").value;
      var url = document.getElementById("n-url").value;
      var tag = document.getElementById("n-tag").value;
      if (icon) msg.icon = icon;
      if (url) msg.url = url;
      if (tag) msg.tag = tag;
      try {
        sendBtn.disabled = true;
        var r = await fetch("/apps/push/send", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(msg)
        });
        if (r.ok) {
          log("Notification sent to all subscribers");
          setTimeout(loadState, 1000);
        } else {
          var t = await r.text();
          log("Send failed: " + r.status + " " + t);
        }
      } catch(e) {
        log("Send error: " + e);
      } finally {
        sendBtn.disabled = false;
      }
    });
    init();
    setInterval(loadState, 5000);
    </script>
    </body>
    </html>
    '''
  --
::
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?+  path  (on-watch:def path)
    [%http-response *]  `this
  ==
::
++  on-leave  on-leave:def
++  on-peek   on-peek:def
++  on-agent  on-agent:def
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  `this
++  on-fail   on-fail:def
--
