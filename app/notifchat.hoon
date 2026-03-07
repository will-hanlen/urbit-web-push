::  app/notifchat: notifchat with push notifications
::
::  Wrapped by web-pusher for VAPID keys, browser
::  subscriptions, encryption, and delivery tracking.
::
/-  notifchat
/+  web-pusher, default-agent, verb, server
::
|%
+$  card  card:agent:gall
+$  versioned-state
  $%  [%0 state-0]
  ==
+$  state-0
  $:  msgs=(list message:notifchat)
  ==
--
::
=|  state-0
=*  state  -
::
%+  verb  |
%-  %:  agent:web-pusher
      /apps/notifchat
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
  `this(state !<(state-0 vase))
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
  =/  sender  src.bowl
  =/  planet-plus  (lte (met 3 sender) 8)
  =/  allowed  |(authenticated.inbound-request planet-plus)
  ::  manifest is public
  ::
  ?:  &(=('GET' meth) =(/apps/notifchat/icon site.rl))
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    (icon-response)
  ?:  &(=('GET' meth) =(/apps/notifchat/manifest site.rl))
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    (manifest-response)
  ::  main page
  ::
  ?:  &(=('GET' meth) =(site /apps/notifchat))
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    ?:  allowed
      (html-response:gen:server (page-html sender))
    (html-response:gen:server login-html)
  ::  everything below requires planet+
  ::
  ?.  allowed
    :_  this
    (err-cards eyre-id 403 'not allowed')
  ::
  ?:  &(=('POST' meth) =(site /apps/notifchat/send))
    (do-send eyre-id sender body.request.inbound-request)
  ?:  &(=('GET' meth) =(site /apps/notifchat/messages))
    :_  this
    (get-messages eyre-id)
  :_  this
  (give-simple-payload:app:server eyre-id not-found:gen:server)
  ::
  ++  icon-response
    |.
    ^-  simple-payload:http
    =/  bod=@t
      '''
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="64" fill="#f0be41"/><text x="256" y="340" text-anchor="middle" font-size="280" font-family="system-ui,sans-serif" fill="#1a1a1a">nc</text></svg>
      '''
    [[200 [['content-type' 'image/svg+xml'] ~]] `(as-octs:mimes:html bod)]
  ::
  ++  manifest-response
    |.
    ^-  simple-payload:http
    =/  bod=@t
      '''
      {"name":"Notifchat","short_name":"Notifchat","start_url":"/apps/notifchat","display":"standalone","background_color":"#ffffff","theme_color":"#333333","icons":[{"src":"/apps/notifchat/icon.svg","sizes":"any","type":"image/svg+xml","purpose":"any"}]}
      '''
    [[200 [['content-type' 'application/manifest+json'] ~]] `(as-octs:mimes:html bod)]
  ::
  ++  login-html
    ^-  octs
    %-  as-octs:mimes:html
    %-  crip
    =/  login-css=@t
      '''
      body { font-family: system-ui, sans-serif; max-width: 400px;
        margin: 4rem auto; padding: 0 1rem; text-align: center; color: #333; background: #fff; }
      form { margin-top: 2rem; }
      input[type="text"] { width: 100%; padding: 0.75rem; border: 1px solid #ddd;
        border-radius: 4px; font-size: 1rem; margin-bottom: 1rem; }
      button { width: 100%; padding: 0.75rem 1.5rem;
        background: #333; color: #fff; border: none; border-radius: 4px;
        font-size: 1rem; cursor: pointer; }
      .admin-link { display: inline-block; margin-top: 1.5rem; font-size: 0.85rem;
        color: #999; text-decoration: none; }
      .admin-link:hover { text-decoration: underline; }
      @media (prefers-color-scheme: dark) {
        body { background: #1a1a1a; color: #e0e0e0; }
        input[type="text"] { background: #333; color: #e0e0e0; border-color: #555; }
        button { background: #e0e0e0; color: #1a1a1a; }
        .admin-link { color: #777; }
      }
      '''
    ;:  welp
      "<!DOCTYPE html>"
    %-  en-xml:html
    ;html
      ;head
        ;meta(charset "utf-8");
        ;meta(name "viewport", content "width=device-width, initial-scale=1");
        ;title: Notifchat
        ;+  ;style: {(trip login-css)}
      ==
      ;body
        ;h1: Notifchat
        ;p: Sign in with your urbit identity
        ;form(method "POST", action "/~/login")
          ;input(type "hidden", name "redirect", value "/apps/notifchat");
          ;input(type "hidden", name "eauth", value "");
          ;input(type "text", name "name", placeholder "~sampel-palnet", required "");
          ;button(type "submit"): Sign In
        ==
        ;a(href "/~/login?redirect=/apps/notifchat", class "admin-link"): login as admin
      ==
    ==
    ==
  ::
  ++  page-html
    |=  sender=@p
    ^-  octs
    %-  as-octs:mimes:html
    %-  crip
    ;:  welp
      "<!DOCTYPE html>"
      (en-xml:html (head-manx page-css))
      "<body>"
      (en-xml:html app-div)
      (en-xml:html install-div)
      "<script>var SENDER=\""
      (trip (scot %p sender))
      "\";\0a"
      (trip page-js)
      "</script></body></html>"
    ==
  ::
  ++  head-manx
    |=  css=@t
    ^-  manx
    ;head
      ;meta(charset "utf-8");
      ;meta(name "viewport", content "width=device-width, initial-scale=1");
      ;title: Notifchat
      ;link(rel "manifest", href "/apps/notifchat/manifest.json");
      ;meta(name "mobile-web-app-capable", content "yes");
      ;+  ;style: {(trip css)}
    ==
  ::
  ++  app-div
    ^-  manx
    ;div(id "app", style "display:none;flex-direction:column;height:100vh;height:100dvh")
      ;header
        ;div(class "header-left")
          ;h1: notifchat
          ;span(id "whoami");
        ==
        ;div(class "header-right")
          ;label(class "notif-label", id "notif-label")
            ;input(type "checkbox", id "notif-toggle", onchange "toggleNotif(this.checked)");
            ;span(class "notif-off"): turn on notifs
            ;span(class "notif-on"): notifs on!
          ==
          ;form(method "GET", action "/~/logout", style "margin:0;padding:0;border:none")
            ;input(type "hidden", name "redirect", value "/apps/notifchat");
            ;button(type "submit", class "logout-btn"): logout
          ==
        ==
      ==
      ;div(id "messages");
      ;form(onsubmit "return sendMsg(event)")
        ;input(id "input", placeholder "message", autocomplete "off");
        ;button(type "submit"): send
      ==
    ==
  ::
  ++  install-div
    ^-  manx
    ;div(id "install", style "display:none")
      ;h2: Install Notifchat
      ;p: To use this app, install it.
      ;p(id "install-instructions");
      ;button(id "install-btn", style "display:none", onclick "doInstall()"): Install App
    ==
  ::
  ++  page-css
    ^-  @t
    '''
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; color: #333; background: #fff;
      display: flex; flex-direction: column; height: 100vh; height: 100dvh; }
    header { display: flex; justify-content: space-between; align-items: center;
      padding: 0.5rem 0.75rem; border-bottom: 1px solid #ddd; gap: 0.5rem; }
    .header-left { display: flex; align-items: baseline; gap: 0.5rem; min-width: 0; }
    .header-left h1 { font-size: 1rem; white-space: nowrap; }
    .header-left span { font-size: 0.8rem; color: #999; overflow: hidden;
      text-overflow: ellipsis; white-space: nowrap; }
    .header-right { display: flex; align-items: center; gap: 0.75rem; flex-shrink: 0; }
    .notif-label { cursor: pointer; font-size: 0.8rem; font-weight: 500;
      padding: 0.3rem 0.6rem; border-radius: 6px; border: 1.5px solid #b08a1a;
      color: #b08a1a; }
    .notif-label:hover { background: rgba(176,138,26,0.08); }
    .notif-label:active { background: rgba(176,138,26,0.15); }
    .notif-label input { display: none; }
    .notif-on { display: none; }
    .notif-label input:checked ~ .notif-off { display: none; }
    .notif-label input:checked ~ .notif-on { display: inline; }
    .notif-label:has(input:checked) { border-color: transparent; color: #999; }
    .notif-label:has(input:checked):hover { background: none; }
    .logout-btn { font-size: 0.8rem; color: #999; background: none; border: none;
      cursor: pointer; padding: 0.35rem 0.5rem; border-radius: 6px; font-family: inherit; }
    .logout-btn:active { background: rgba(0,0,0,0.06); }
    #messages { flex: 1; overflow-y: auto; padding: 0.75rem 1rem; }
    .msg { margin-bottom: 0.5rem; }
    .msg .author { font-weight: 600; font-size: 0.85rem; }
    .msg .text { font-size: 0.9rem; }
    .msg .time { font-size: 0.75rem; color: #999; }
    form { display: flex; gap: 0.5rem; padding: 0.75rem 1rem;
      border-top: 1px solid #ddd; }
    form input { flex: 1; padding: 0.5rem; border: 1px solid #ddd;
      border-radius: 4px; font-size: 0.9rem; }
    form button { padding: 0.5rem 1rem; border: 1px solid #ddd;
      border-radius: 4px; background: #333; color: #fff; cursor: pointer;
      font-size: 0.9rem; }
    #install { display: flex; flex-direction: column; align-items: center;
      justify-content: center; flex: 1; padding: 2rem; text-align: center; }
    #install h2 { margin-bottom: 1rem; }
    #install p { margin-bottom: 0.5rem; color: #666; font-size: 0.9rem; }
    #install button { margin-top: 1rem; padding: 0.75rem 1.5rem; border: 1px solid #ddd;
      border-radius: 4px; background: #333; color: #fff; cursor: pointer; font-size: 0.9rem; }
    @media (prefers-color-scheme: dark) {
      body { background: #1a1a1a; color: #e0e0e0; }
      header { border-bottom-color: #444; }
      .header-left span { color: #777; }
      .notif-label { border-color: #d4a820; color: #d4a820; }
      .notif-label:hover { background: rgba(212,168,32,0.1); }
      .notif-label:active { background: rgba(212,168,32,0.18); }
      .notif-label:has(input:checked) { color: #777; }
      .logout-btn:active { background: rgba(255,255,255,0.1); }
      .logout-btn { color: #777; }
      form { border-top-color: #444; }
      form input { background: #2a2a2a; border-color: #444; color: #e0e0e0; }
      form button { background: #e0e0e0; color: #1a1a1a; border-color: #444; }
      .msg .time { color: #777; }
      #install p { color: #999; }
      #install button { background: #e0e0e0; color: #1a1a1a; border-color: #444; }
    }
    '''
  ::
  ++  page-js
    ^-  @t
    '''
    var pollTimer = null;
    var deferredPrompt = null;
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
    window.addEventListener("beforeinstallprompt", function(e) {
      e.preventDefault();
      deferredPrompt = e;
      var btn = document.getElementById("install-btn");
      if (btn) btn.style.display = "";
    });
    function doInstall() {
      if (!deferredPrompt) return;
      deferredPrompt.prompt();
      deferredPrompt.userChoice.then(function() { deferredPrompt = null; });
    }
    function checkStandalone() {
      return window.matchMedia("(display-mode: standalone)").matches || navigator.standalone;
    }
    function startApp() {
      document.getElementById("install").style.display = "none";
      document.getElementById("app").style.display = "flex";
      loadMessages();
      pollTimer = setInterval(loadMessages, 3000);
      initNotifState();
    }
    function init() {
      document.getElementById("whoami").textContent = SENDER;
      if (checkStandalone()) {
        startApp();
        return;
      }
      document.getElementById("install").style.display = "flex";
      var inst = document.getElementById("install-instructions");
      if (/iPhone|iPad/.test(navigator.userAgent)) {
        inst.textContent = "Tap the Share button, then 'Add to Home Screen'.";
      } else if (/Android/.test(navigator.userAgent)) {
        inst.textContent = "Tap the menu button, then 'Add to Home Screen' or 'Install App'.";
      } else {
        inst.textContent = "In Chrome, click the install icon in the address bar or use Menu > Install.";
      }
      setInterval(function() {
        if (checkStandalone()) startApp();
      }, 100);
    }
    function loadMessages() {
      fetch("/apps/notifchat/messages")
        .then(function(r) { return r.json(); })
        .then(function(msgs) {
          var el = document.getElementById("messages");
          var wasAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 50;
          el.innerHTML = "";
          msgs.forEach(function(m) {
            var d = document.createElement("div");
            d.className = "msg";
            var t = new Date(m["sent-at"]).toLocaleTimeString();
            d.innerHTML = '<span class="author">' + esc(m.author) + '</span> ' +
              '<span class="time">' + esc(t) + '</span>' +
              '<div class="text">' + esc(m.text) + '</div>';
            el.appendChild(d);
          });
          if (wasAtBottom) el.scrollTop = el.scrollHeight;
        })
        .catch(function() {});
    }
    function esc(s) {
      var d = document.createElement("div");
      d.textContent = s;
      return d.innerHTML;
    }
    function sendMsg(e) {
      e.preventDefault();
      var inp = document.getElementById("input");
      var text = inp.value.trim();
      if (!text) return false;
      inp.value = "";
      fetch("/apps/notifchat/send", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({text: text})
      }).then(function() { loadMessages(); });
      return false;
    }
    async function initNotifState() {
      var toggle = document.getElementById("notif-toggle");
      if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
        toggle.disabled = true;
          return;
      }
      try {
        var reg = await navigator.serviceWorker.register("/apps/notifchat/~web-pusher/sw.js");
        var sub = await reg.pushManager.getSubscription();
        if (sub) {
          var cr = await fetch("/apps/notifchat/~web-pusher/check-sub", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({endpoint: sub.endpoint})
          });
          toggle.checked = cr.ok;
          if (!cr.ok) {
            await sub.unsubscribe();
            localStorage.removeItem("push-sub-id");
          }
        }
      } catch(e) {}
    }
    async function toggleNotif(on) {
      var toggle = document.getElementById("notif-toggle");
      try {
        var reg = await navigator.serviceWorker.register("/apps/notifchat/~web-pusher/sw.js");
        if (on) {
          var resp = await fetch("/apps/notifchat/~web-pusher/vapid-key");
          var vapidKey = await resp.text();
          var sub = await reg.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlB64ToUint8(vapidKey)
          });
          var p256dh = bufToB64Url(sub.getKey("p256dh"));
          var auth = bufToB64Url(sub.getKey("auth"));
          var id = "b-" + Date.now();
          var r = await fetch("/apps/notifchat/~web-pusher/subscribe", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({id: id, endpoint: sub.endpoint, p256dh: p256dh, auth: auth})
          });
          if (!r.ok) throw new Error("subscribe failed");
          localStorage.setItem("push-sub-id", id);
          reg.showNotification("notifications enabled");
        } else {
          var sub = await reg.pushManager.getSubscription();
          if (sub) await sub.unsubscribe();
          var id = localStorage.getItem("push-sub-id");
          if (id) {
            await fetch("/apps/notifchat/~web-pusher/unsubscribe", {
              method: "POST",
              headers: {"Content-Type": "application/json"},
              body: JSON.stringify({id: id})
            });
            localStorage.removeItem("push-sub-id");
          }
        }
      } catch(e) {
        toggle.checked = !on;
      }
    }
    init();
    '''
  ::
  ++  do-send
    |=  [eyre-id=@ta sender=@p body=(unit octs)]
    ^-  (quip card _this)
    ?~  body  :_(this (err-cards eyre-id 400 'no body'))
    =/  jon=(unit json)  (de:json:html q.u.body)
    ?~  jon  :_(this (err-cards eyre-id 400 'invalid json'))
    ?.  ?=(%o -.u.jon)  :_(this (err-cards eyre-id 400 'expected object'))
    =/  obj  p.u.jon
    =/  text-j  (~(get by obj) 'text')
    ?.  ?&(?=(^ text-j) ?=(%s -.u.text-j))
      :_(this (err-cards eyre-id 400 'text required'))
    ?:  (gth (met 3 p.u.text-j) 1.024)
      :_(this (err-cards eyre-id 400 'message too long'))
    =/  msg=message:notifchat  [sender p.u.text-j now.bowl]
    =.  msgs.state  (scag 200 `(list message:notifchat)`[msg msgs.state])
    =/  sender-t  (trip (scot %p sender))
  =/  full  "{sender-t}: {(trip p.u.text-j)}"
  =/  title=@t
    ?:  (lte (lent full) 80)  (crip full)
    (crip (weld (scag 77 full) "..."))
  =/  push-msg  [title '' ~ `'/apps/notifchat' `'message']
    :_  this
    :*  [%pass /notify %agent [our dap]:bowl %poke %push-send !>([*(set @p) push-msg])]
        (ok-cards eyre-id)
    ==
  ::
  ++  get-messages
    |=  eyre-id=@ta
    ^-  (list card)
    ::  state is newest-first, reverse for display (oldest-first)
    ::
    =/  msgs  (flop msgs.state)
    =/  arr=json
      :-  %a
      %+  turn  msgs
      |=  m=message:notifchat
      %-  pairs:enjs:format
      :~  ['author' [%s (scot %p author.m)]]
          ['text' [%s text.m]]
          ['sent-at' [%n (crip (a-co:co (mul 1.000 (unm:chrono:userlib sent-at.m))))]]
      ==
    %+  give-simple-payload:app:server  eyre-id
    (json-response:gen:server arr)
  ::
  ++  ok-cards
    |=  eyre-id=@ta
    ^-  (list card)
    %+  give-simple-payload:app:server  eyre-id
    %-  json-response:gen:server
    [%o (~(gas by *(map @t json)) ~[['ok' [%b &]]])]
  ::
  ++  err-cards
    |=  [eyre-id=@ta code=@ud msg=@t]
    ^-  (list card)
    =/  bod=json  [%o (~(gas by *(map @t json)) ~[['error' [%s msg]]])]
    %+  give-simple-payload:app:server  eyre-id
    [[code [['content-type' 'application/json'] ~]] `(json-to-octs:server bod)]
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
