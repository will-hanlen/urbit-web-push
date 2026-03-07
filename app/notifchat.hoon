::  app/notifchat: notifchat with push notifications
::
::  Wrapped by web-pusher for VAPID keys, browser
::  subscriptions, encryption, and delivery tracking.
::
/-  notifchat, push
/+  web-pusher, default-agent, verb, server, datastar
/*  datastar-js  %js  /lib/web/datastar/js
::
|%
+$  card  card:agent:gall
++  max-msgs      200        ::  message history limit
++  max-msg-size  1.024      ::  max message bytes
+$  versioned-state
  $%  [%0 state-0]
      [%1 state-1]
  ==
+$  state-0
  $:  msgs=(list [author=@p text=@t sent-at=@da])
  ==
+$  state-1
  $:  msgs=(list message:notifchat)
  ==
++  parse-segments
  |=  text=@t
  ^-  (list segment:notifchat)
  =/  chars  (trip text)
  =|  acc=(list segment:notifchat)
  =|  buf=tape
  |-
  ?~  chars
    ?~  buf  (flop acc)
    (flop `(list segment:notifchat)`[[%text (crip buf)] acc])
  ?.  =('~' i.chars)  $(buf (snoc buf i.chars), chars t.chars)
  =/  result=(unit [@p tape])  (scan-patp t.chars)
  ?~  result
    $(buf (snoc buf '~'), chars t.chars)
  =/  pre=(list segment:notifchat)  ?~(buf ~ [[%text (crip buf)] ~])
  $(acc [[%mention -.u.result] (welp pre acc)], buf ~, chars +.u.result)
++  scan-patp
  |=  chars=tape
  ^-  (unit [@p tape])
  =|  tok=tape
  |-
  ?:  |(?=(~ chars) =(' ' i.chars) =(',' i.chars) =('.' i.chars))
    =/  name  (slaw %p (crip (weld "~" tok)))
    ?~  name  ~
    `[u.name chars]
  $(tok (snoc tok i.chars), chars t.chars)
--
::
=|  state-1
=*  state  -
=|  requests=(set @ta)
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
++  on-save   !>(`versioned-state`[%1 state])
++  on-load
  |=  =vase
  ^-  (quip card _this)
  ?:  ?=([%1 *] q.vase)
    =/  old  !<(versioned-state vase)
    ?>  ?=(%1 -.old)
    `this(state +.old)
  ::  legacy: untagged state-0
  =/  old  !<(state-0 vase)
  =/  new-msgs=(list message:notifchat)
    %+  turn  msgs.old
    |=  [author=@p text=@t sent-at=@da]
    [author text sent-at (parse-segments text)]
  `this(msgs.state new-msgs)
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  |^
  ?.  ?=(%handle-http-request mark)
    (on-poke:def mark vase)
  =+  !<([eyre-id=@ta =inbound-request:eyre] vase)
  =/  [site=path pams=(map @t @t)]
    (parse-url:datastar url.request.inbound-request)
  =/  meth=@t  method.request.inbound-request
  =/  action  (~(gut by pams) 'action' '')
  =/  who  src.bowl
  =/  allowed  authenticated.inbound-request
  ::  public routes
  ::
  ?:  &(=('GET' meth) =(/apps/notifchat/'icon.svg' site))
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    icon-response
  ?:  &(=('GET' meth) =(/apps/notifchat/'manifest.json' site))
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    manifest-response
  ?:  &(=('GET' meth) =(/apps/notifchat/'datastar.js' site))
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    =/  bod  (as-octs:mimes:html datastar-js)
    =/  hed=(list [@t @t])
      :~  ['content-type' 'application/javascript']
          ['cache-control' 'max-age=604800']
      ==
    [[200 hed] `bod]
  ::  main page
  ::
  ?:  &(=('GET' meth) =(site /apps/notifchat) =('' action))
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    ?:  allowed
      (html-response:gen:server (page-html who))
    (html-response:gen:server login-html)
  ::  everything below requires auth
  ::
  ?.  allowed
    :_  this
    (err-cards eyre-id 403 'not allowed')
  ::  SSE connection
  ::
  ?:  &(=('GET' meth) =('sse' action))
    =.  requests  (~(put in requests) eyre-id)
    :_  this
    %^  open-sse-conn:datastar  eyre-id  ~
    ~[["outer" ~ (messages-manx msgs.state)]]
  ::  send message
  ::
  ?:  &(=('POST' meth) =('send' action))
    =/  sigs
      (datastar-signals:datastar pams body.request.inbound-request)
    =/  text  (~(gut by sigs) 'text' '')
    ?:  =('' text)
      :_(this (give-empty:datastar eyre-id))
    ?:  (gth (met 3 text) max-msg-size)
      :_(this (give-empty:datastar eyre-id))
    =/  parts=(list segment:notifchat)
      (parse-segments text)
    =/  msg=message:notifchat
      [who text now.bowl parts]
    =.  msgs.state
      %+  scag  max-msgs
      `(list message:notifchat)`[msg msgs.state]
    ::  build push notification
    =/  who-t  (trip (scot %p who))
    =/  full  ;:(welp who-t ": " (trip text))
    =/  title=@t
      ?:  (lte (lent full) 80)  (crip full)
      (crip (weld (scag 77 full) "..."))
    =/  push-msg
      [title '' ~ `'/apps/notifchat' `'message']
    ::  extract @p mentions from parts
    =/  mentioned=(set @p)
      %-  ~(gas in *(set @p))
      %+  murn  parts
      |=  s=segment:notifchat
      ?:(?=(%mention -.s) `+.s ~)
    ::  broadcast non-mentioned with %message tag
    =/  excl=(set @p)
      (~(uni in (sy who ~)) mentioned)
    =/  broadcast=push-send:push
      [~ (sy %message ~) excl push-msg]
    ::  targeted send to mentioned ships
    =/  mention-targets=(set @p)
      (~(del in mentioned) who)
    =/  mention-cards=(list card)
      ?:  =(~ mention-targets)  ~
      =/  ms=push-send:push
        [mention-targets ~ ~ push-msg]
      ~[[%pass /mention %agent [our dap]:bowl %poke %push-send !>(ms)]]
    =/  frags
      ~[["outer" ~ (messages-manx msgs.state)]]
    :_  this
    ;:  welp
      ~[[%pass /notify %agent [our dap]:bowl %poke %push-send !>(broadcast)]]
      mention-cards
      (give-sse:datastar eyre-id ~[['text' '']] ~)
      (push-sse-all:datastar requests ~ frags)
    ==
  :_  this
  (give-simple-payload:app:server eyre-id not-found:gen:server)
  ::
  ++  icon-response
    ^-  simple-payload:http
    =/  bod=@t
      '''
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="64" fill="#f0be41"/><text x="256" y="340" text-anchor="middle" font-size="280" font-family="system-ui,sans-serif" fill="#1a1a1a">nc</text></svg>
      '''
    [[200 [['content-type' 'image/svg+xml'] ~]] `(as-octs:mimes:html bod)]
  ::
  ++  manifest-response
    ^-  simple-payload:http
    =/  bod=@t
      '''
      {"name":"Notifchat","short_name":"Notifchat","start_url":"/apps/notifchat","display":"standalone","background_color":"#ffffff","theme_color":"#333333","icons":[{"src":"/apps/notifchat/icon.svg","sizes":"any","type":"image/svg+xml","purpose":"any"}]}
      '''
    [[200 [['content-type' 'application/manifest+json'] ~]] `(as-octs:mimes:html bod)]
  ::
  ++  login-html
    ^-  octs
    %-  as-octt:mimes:html
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
  ++  messages-manx
    |=  msgs=(list message:notifchat)
    ^-  manx
    ;div#messages
      ;*  %+  turn  (flop msgs)
          |=  m=message:notifchat
          ;div.msg
            ;span.author: {(trip (scot %p author.m))}
            ;span.time: {(format-time sent-at.m)}
            ;div.text
              ;*  (render-segments parts.m)
            ==
          ==
    ==
  ::
  ++  render-segments
    |=  segs=(list segment:notifchat)
    ^-  (list manx)
    %+  turn  segs
    |=  s=segment:notifchat
    ?-  -.s
      %text     ;span: {(trip +.s)}
      %mention  ;span.mention: {(trip (scot %p +.s))}
    ==
  ::
  ++  format-time
    |=  t=@da
    ^-  tape
    =/  d  (yore t)
    ;:(welp (zero-pad h.t.d) ":" (zero-pad m.t.d))
  ::
  ++  zero-pad
    |=  n=@
    ^-  tape
    ?:  (lth n 10)  (welp "0" (a-co:co n))
    (a-co:co n)
  ::
  ++  page-html
    |=  who=@p
    ^-  octs
    =/  hr  ~(. href:datastar /apps/notifchat ~)
    %-  as-octt:mimes:html
    %+  welp  "<!DOCTYPE html>"
    %-  en-xml:html
    ;html
      ;head
        ;meta(charset "utf-8");
        ;meta(name "viewport", content "width=device-width, initial-scale=1");
        ;title: Notifchat
        ;+  ;style:(-(trip page-css))
        ;link(rel "manifest", href "/apps/notifchat/manifest.json");
        ;script(type "module", src "/apps/notifchat/datastar.js");
      ==
      ;body
        ;div#app
          =data-signals-text  ""
          =data-init          "{(data-get:hr / [["action" "sse"]]~)}"
          =style              "display:flex;flex-direction:column;height:100vh;height:100dvh"
          ;+  (header-manx who)
          ;div#messages: loading...
          ;form
            =data-signals  "\{'_sending': false}"
            =data-on_submit  (data-post:hr / [["action" "send"]]~)
            =data-indicator  "_sending"
            ;input#input(placeholder "message", autocomplete "off", data-bind_text "", data-attr_disabled "$_sending", data-effect "if(!$_sending) refocusInput()");
            ;button(type "submit", data-attr_disabled "$_sending"): send
          ==
        ==
        ;+  install-div
        ;script:(-(trip page-js))
      ==
    ==
  ::
  ++  header-manx
    |=  who=@p
    ^-  manx
    ;header
      ;div.header-left
        ;h1: notifchat
        ;span: {(trip (scot %p who))}
      ==
      ;div.header-right
        ;select#notif-mode.off(onchange "setNotifMode(this.value)")
          ;option(value "off"): notifs off
          ;option(value "all"): all messages
          ;option(value "mention"): mentions only
        ==
        ;form
          =method  "GET"
          =action  "/~/logout"
          =style   "margin:0;padding:0;border:none"
          ;input(type "hidden", name "redirect", value "/apps/notifchat");
          ;button(type "submit", class "logout-btn"): logout
        ==
      ==
    ==
  ::
  ++  install-div
    ^-  manx
    ;div#install(style "display:none")
      ;h2: Install Notifchat
      ;p: To use this app, install it.
      ;p#install-instructions;
      ;button#install-btn(style "display:none", onclick "doInstall()"): Install App
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
    #notif-mode { font-size: 0.8rem; padding: 0.3rem 0.4rem; border-radius: 6px;
      border: 1.5px solid #999; color: #999; background: transparent;
      font-family: inherit; cursor: pointer; }
    #notif-mode.off { border-color: #b08a1a; color: #b08a1a; }
    .logout-btn { font-size: 0.8rem; color: #999; background: none; border: none;
      cursor: pointer; padding: 0.35rem 0.5rem; border-radius: 6px; font-family: inherit; }
    .logout-btn:active { background: rgba(0,0,0,0.06); }
    #messages { flex: 1; overflow-y: auto; padding: 0.75rem 1rem; }
    .msg { margin-bottom: 0.5rem; }
    .msg .author { font-weight: 600; font-size: 0.85rem; margin-right: 0.5rem; }
    .msg .text { font-size: 0.9rem; }
    .mention { font-weight: 600; color: #2563eb; }
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
      #notif-mode { border-color: #777; color: #777; }
      #notif-mode.off { border-color: #d4a820; color: #d4a820; }
      .logout-btn:active { background: rgba(255,255,255,0.1); }
      .logout-btn { color: #777; }
      form { border-top-color: #444; }
      form input { background: #2a2a2a; border-color: #444; color: #e0e0e0; }
      form button { background: #e0e0e0; color: #1a1a1a; border-color: #444; }
      .msg .time { color: #777; }
      .mention { color: #60a5fa; }
      #install p { color: #999; }
      #install button { background: #e0e0e0; color: #1a1a1a; border-color: #444; }
    }
    '''
  ::
  ++  page-js
    ^-  @t
    '''
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
      initNotifState();
    }
    function init() {
      var install = document.getElementById("install");
      document.body.appendChild(install);
      if (checkStandalone()) {
        startApp();
        return;
      }
      document.getElementById("app").style.display = "none";
      install.style.display = "flex";
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
    new MutationObserver(scrollMessages).observe(
      document.getElementById("app"),
      {childList: true, subtree: true});
    scrollMessages();
    async function initNotifState() {
      var sel = document.getElementById("notif-mode");
      if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
        sel.disabled = true;
        updateNotifStyle();
        return;
      }
      try {
        var reg = await navigator.serviceWorker.register("/apps/notifchat/~web-pusher/sw.js");
        var sub = await reg.pushManager.getSubscription();
        if (!sub) { sel.value = "off"; return; }
        var cr = await fetch("/apps/notifchat/~web-pusher/check-sub", {
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
        var pr = await fetch("/apps/notifchat/~web-pusher/prefs");
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
      var r = await fetch("/apps/notifchat/~web-pusher/subscribe", {
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
        await fetch("/apps/notifchat/~web-pusher/unsubscribe", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({id: id})
        });
        localStorage.removeItem("push-sub-id");
      }
    }
    async function setPrefs(tags) {
      await fetch("/apps/notifchat/~web-pusher/prefs", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({tags: tags})
      });
    }
    function updateNotifStyle() {
      var sel = document.getElementById("notif-mode");
      sel.classList.toggle("off", sel.value === "off");
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
    init();
    '''
  ::
  ++  err-cards
    |=  [eyre-id=@ta code=@ud msg=@t]
    ^-  (list card)
    =/  bod=json  o+(malt ~[['error' s+msg]])
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
++  on-leave
  |=  pax=path
  ^-  (quip card _this)
  ?.  ?=([%http-response @ ~] pax)  `this
  =/  eid=@ta  i.t.pax
  `this(requests (~(del in requests) eid))
::
++  on-peek   on-peek:def
++  on-agent  on-agent:def
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  `this
++  on-fail   on-fail:def
--
