::  app/notifchat: notifchat with push notifications
::
::  Wrapped by web-pusher for VAPID keys, browser
::  subscriptions, encryption, and delivery tracking.
::
/-  notifchat, push
/+  web-pusher, web-push, default-agent, verb, datastar
/*  datastar-js    %js   /lib/web/datastar/js
/*  pwa-gate-js    %js   /lib/web/pwa-gate/js
/*  notifchat-js   %js   /lib/web/notifchat/js
/*  notifchat-css  %css  /lib/web/notifchat/css
::
|%
+$  card  card:agent:gall
++  max-msgs      200        ::  message history limit
++  max-msg-size  1.024      ::  max message bytes
++  keepalive-freq  ~s30     ::  SSE keepalive interval
++  versioned                ::  append ?v={mug} for cache-busting
  |=  [base=tape raw-file=@]
  "{base}?v={(a-co:co (mug raw-file))}"
+$  versioned-state
  $%  [%0 state-0]
  ==
+$  state-0
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
  ?~  chars
    =/  name  (slaw %p (crip (weld "~" tok)))
    ?~  name  ~
    `[u.name chars]
  ?.  |(=(i.chars '-') &((gte i.chars 'a') (lte i.chars 'z')))
    =/  name  (slaw %p (crip (weld "~" tok)))
    ?~  name  ~
    `[u.name chars]
  $(tok (snoc tok i.chars), chars t.chars)
--
::
=|  state-0
=*  state  -
=|  sessions=(set @ta)
::
%+  verb  |
%-  %:  agent:web-pusher
    /apps/notifchat
    'mailto:you@example.com'
    200
  ==
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
    ds    datastar
::
++  on-init   `this
++  on-save   !>(`versioned-state`[%0 state])
++  on-load
  |=  =vase
  ^-  (quip card _this)
  =/  old  (mule |.(!<(versioned-state vase)))
  ?:  ?=(%& -.old)
    ?>  ?=(%0 -.p.old)
    `this(state +.p.old)
  `this
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  |^
  ?:  ?=(%push-test mark)
    ?>  =(our src):bowl
    (process-send our.bowl !<(@t vase))
  ?:  ?=(%wipe mark)
    ?>  =(our src):bowl
    =.  msgs.state  ~
    =/  frags  ~[["outer" ~ (messages-manx msgs.state)]]
    :_  this
    (push-sse-all:ds sessions ~ frags)
  ?.  ?=(%handle-http-request mark)
    (on-poke:def mark vase)
  =+  !<([eyre-id=@ta =inbound-request:eyre] vase)
  =/  [site=path pams=(map @t @t)]
    (parse-url:ds url.request.inbound-request)
  =/  meth=@t  method.request.inbound-request
  =/  action  (~(gut by pams) 'action' '')
  ::  public routes
  ::
  ?:  &(=('GET' meth) =(/apps/notifchat/'icon.svg' site))
    :_(this (payload-cards:ds eyre-id icon-response))
  ?:  &(=('GET' meth) =(/apps/notifchat/'manifest.json' site))
    :_(this (payload-cards:ds eyre-id manifest-response))
  ?:  &(=('GET' meth) =(/apps/notifchat/'datastar.js' site))
    :_(this (resource-payload-cards:ds eyre-id `~d7 'application/javascript' datastar-js))
  ?:  &(=('GET' meth) =(/apps/notifchat/'pwa-gate.js' site))
    :_(this (resource-payload-cards:ds eyre-id `~d7 'application/javascript' pwa-gate-js))
  ?:  &(=('GET' meth) =(/apps/notifchat/'notifchat.js' site))
    :_(this (resource-payload-cards:ds eyre-id `~d7 'application/javascript' notifchat-js))
  ?:  &(=('GET' meth) =(/apps/notifchat/'notifchat.css' site))
    :_(this (resource-payload-cards:ds eyre-id `~d7 'text/css' notifchat-css))
  ::  authenticated routes (moons and above)
  ::
  ?:  =(%pawn (clan:title src.bowl))
    :_(this (err-payload-cards:ds eyre-id 403 'forbidden'))
  ::  main page
  ::
  ?:  &(=('GET' meth) =(site /apps/notifchat) =('' action))
    :_(this (html-payload-cards:ds eyre-id (page-manx src.bowl)))
  ::  SSE connection
  ::
  ?:  &(=('GET' meth) =('sse' action))
    =/  need-timer  =(~ sessions)
    =.  sessions  (~(put in sessions) eyre-id)
    :_  this
    %+  welp
      ?.(need-timer ~ ~[[%pass /keepalive %arvo %b %wait (add now.bowl keepalive-freq)]])
    %^  open-sse-conn:ds  eyre-id  ~
    ~[["outer" ~ (messages-manx msgs.state)]]
  ::  send message
  ::
  ?:  &(=('POST' meth) =('send' action))
    =/  sigs  (datastar-signals:ds pams body.request.inbound-request)
    =/  text  (~(gut by sigs) 'text' '')
    ?:  =('' text)
      :_(this (give-empty:ds eyre-id))
    ?:  (gth (met 3 text) max-msg-size)
      :_(this (give-empty:ds eyre-id))
    =/  [cards=(list card) =_this]  (process-send src.bowl text)
    :_  this
    ;:  welp
      cards
      (give-empty:ds eyre-id)
      (push-sse-all:ds sessions ~[['text' '']] ~)
    ==
  ::  push-subscribe: register browser push subscription
  ::
  ?:  &(=('POST' meth) =('push-subscribe' action))
    =/  form  (form-body:ds body.request.inbound-request)
    =/  id     (~(get by form) 'id')
    =/  ep     (~(get by form) 'endpoint')
    =/  dh-b6  (~(get by form) 'p256dh')
    =/  au-b6  (~(get by form) 'auth')
    ?.  &(?=(^ id) ?=(^ ep) ?=(^ dh-b6) ?=(^ au-b6))
      :_(this (err-payload-cards:ds eyre-id 400 'missing fields'))
    =/  dh-octs=(unit octs)  (de-base64url:web-push u.dh-b6)
    =/  au-octs=(unit octs)  (de-base64url:web-push u.au-b6)
    ?~  dh-octs  :_(this (err-payload-cards:ds eyre-id 400 'invalid p256dh'))
    ?~  au-octs  :_(this (err-payload-cards:ds eyre-id 400 'invalid auth'))
    =/  dh=@  (rev 3 p.u.dh-octs q.u.dh-octs)
    =/  au=@  (rev 3 p.u.au-octs q.u.au-octs)
    =/  sub=subscription:push  [u.ep dh au]
    =/  tags=(set term)  (parse-tags (~(get by form) 'tags'))
    =/  ps=push-subscribe:push  [src.bowl `@ta`u.id sub tags]
    :_  this
    :*  [%pass /push/sub %agent [our dap]:bowl %poke %push-subscribe !>(ps)]
        (give-empty:ds eyre-id)
    ==
  ::  push-unsubscribe: remove browser push subscription
  ::
  ?:  &(=('POST' meth) =('push-unsubscribe' action))
    =/  form  (form-body:ds body.request.inbound-request)
    =/  id  (~(get by form) 'id')
    ?~  id  :_(this (err-payload-cards:ds eyre-id 400 'missing id'))
    =/  ps=push-unsubscribe:push  [src.bowl `@ta`u.id]
    :_  this
    :*  [%pass /push/unsub %agent [our dap]:bowl %poke %push-unsubscribe !>(ps)]
        (give-empty:ds eyre-id)
    ==
  ::  push-check-sub: verify subscription exists on server
  ::
  ?:  &(=('POST' meth) =('push-check-sub' action))
    =/  form  (form-body:ds body.request.inbound-request)
    =/  ep  (~(get by form) 'endpoint')
    ?~  ep  :_(this (err-payload-cards:ds eyre-id 400 'missing endpoint'))
    =/  inner=(map @ta tagged-sub:push)  (~(gut by subs:get-pstate) src.bowl ~)
    =/  found=?
      %+  lien  ~(val by inner)
      |=(ts=tagged-sub:push =(endpoint.sub.ts u.ep))
    :_  this
    ?:  found  (give-empty:ds eyre-id)
    (err-payload-cards:ds eyre-id 404 'subscription not found')
  ::  push-prefs GET: return tags for this user's subscriptions
  ::
  ?:  &(=('GET' meth) =('push-prefs' action))
    =/  inner=(map @ta tagged-sub:push)  (~(gut by subs:get-pstate) src.bowl ~)
    =/  all-tags=(set term)
      %-  ~(rep by inner)
      |=  [[id=@ta ts=tagged-sub:push] acc=(set term)]
      (~(uni in acc) tags.ts)
    =/  arr=json  [%a (turn ~(tap in all-tags) |=(t=term [%s t]))]
    :_(this (json-payload-cards:ds eyre-id arr))
  ::  push-prefs POST: update tags on all subscriptions for this user
  ::
  ?:  &(=('POST' meth) =('push-prefs' action))
    =/  form  (form-body:ds body.request.inbound-request)
    =/  tags=(set term)  (parse-tags (~(get by form) 'tags'))
    =/  inner=(map @ta tagged-sub:push)  (~(gut by subs:get-pstate) src.bowl ~)
    =/  tag-cards=(list card)
      %+  turn  ~(tap by inner)
      |=  [id=@ta ts=tagged-sub:push]
      =/  pt=push-set-tags:push  [src.bowl id tags]
      [%pass /push/tags %agent [our dap]:bowl %poke %push-set-tags !>(pt)]
    :_  this
    (welp tag-cards (give-empty:ds eyre-id))
  ::
  :_(this (not-found-cards:ds eyre-id))
  ::
  ++  process-send
    |=  [who=@p text=@t]
    ^-  (quip card _this)
    =/  parts=(list segment:notifchat)  (parse-segments text)
    =/  msg=message:notifchat  [who text now.bowl parts]
    =.  msgs.state
      (scag max-msgs `(list message:notifchat)`[msg msgs.state])
    =/  who-t  (cite:title who)
    =/  full  ;:(welp who-t ": " (trip text))
    =/  title=@t
      ?:  (lte (lent full) 80)  (crip full)
      (crip (weld (scag 77 full) "..."))
    =/  push-msg=push-message:push
      [title '' `'/apps/notifchat/icon.svg' `'/apps/notifchat' `'message']
    =/  mentioned=(set @p)
      %-  ~(gas in *(set @p))
      %+  murn  parts
      |=  s=segment:notifchat
      ?:(?=(%mention -.s) `+.s ~)
    =/  excl=(set @p)
      (~(uni in (sy who ~)) mentioned)
    =/  broadcast=push-send:push
      [~ (sy %message ~) excl push-msg]
    =/  mention-targets=(set @p)
      (~(del in mentioned) who)
    =/  mention-cards=(list card)
      ?:  =(~ mention-targets)  ~
      =/  ms=push-send:push  [mention-targets ~ ~ push-msg]
      ~[[%pass /mention %agent [our dap]:bowl %poke %push-send !>(ms)]]
    =/  frags
      ~[["outer" ~ (messages-manx msgs.state)]]
    :_  this
    ;:  welp
      ~[[%pass /notify %agent [our dap]:bowl %poke %push-send !>(broadcast)]]
      mention-cards
      (push-sse-all:ds sessions ~ frags)
    ==
  ::
  ++  get-pstate
    ^-  pusher-state:push
    .^(pusher-state:push %gx /(scot %p our.bowl)/[dap.bowl]/(scot %da now.bowl)/web-pusher/state/noun)
  ::
  ++  parse-tags
    |=  tags-t=(unit @t)
    ^-  (set term)
    ?~  tags-t  ~
    ?:  =('' u.tags-t)  ~
    %-  silt
    ^-  (list term)
    %+  murn  (split u.tags-t ',')
    |=(t=@t ?:(=('' t) ~ `t))
  ::
  ++  split
    |=  [txt=@t del=@t]
    ^-  (list @t)
    =|  [acc=(list @t) buf=tape]
    =/  chars  (trip txt)
    |-
    ?~  chars
      (flop ?~(buf acc [(crip buf) acc]))
    ?:  =(i.chars del)
      $(acc [(crip buf) acc], buf ~, chars t.chars)
    $(buf (snoc buf i.chars), chars t.chars)
  ::
  ++  bell-icon
    ^-  manx
    ;svg
      =xmlns  "http://www.w3.org/2000/svg"
      =viewBox  "0 0 20 20"
      =fill  "none"
      =class  "bell-icon"
      =width  "16"
      =height  "16"
      ;path
        =d  "M10 2a5 5 0 0 0-5 5v3l-1.3 2a.75.75 0 0 0 .65 1.12h11.3a.75.75 0 0 0 .65-1.12L15 10V7a5 5 0 0 0-5-5Z"
        =fill  "currentColor"
        =opacity  "0.85";
      ;path
        =d  "M8.5 14.5a1.5 1.5 0 0 0 3 0"
        =stroke  "currentColor"
        =stroke-width  "1.2"
        =stroke-linecap  "round"
        =fill  "none";
    ==
  ::
  ++  icon-response
    ^-  simple-payload:http
    =/  bod=@t
      '''
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="96" fill="#7aadad"/><path d="M128 152c0-22 18-40 40-40h176c22 0 40 18 40 40v144c0 22-18 40-40 40H236l-68 52v-52h-0c-22 0-40-18-40-40Z" fill="#c8dede"/></svg>
      '''
    [[200 [['content-type' 'image/svg+xml'] ~]] `(as-octs:mimes:html bod)]
  ::
  ++  manifest-response
    ^-  simple-payload:http
    =/  bod=@t
      '''
      {
        "id": "/apps/notifchat",
        "name": "Notifchat",
        "short_name": "Notifchat",
        "start_url": "/apps/notifchat",
        "display": "standalone",
        "background_color": "#1f2f2f",
        "theme_color": "#1f2f2f",
        "icons": [
          {
            "src": "/apps/notifchat/icon.svg",
            "sizes": "any",
            "type": "image/svg+xml",
            "purpose": "any"
          }
        ]
      }
      '''
    [[200 [['content-type' 'application/manifest+json'] ~]] `(as-octs:mimes:html bod)]
  ::
  ++  messages-manx
    |=  msgs=(list message:notifchat)
    ^-  manx
    ;div#messages
      ;*  %+  turn  (flop (scag 100 msgs))
          |=  m=message:notifchat
          ;div.msg
            ;div.msg-header
              ;span.author: {(cite:title author.m)}
              ;hr;
              ;span.time: {(format-time sent-at.m)}
            ==
            ;div.text
              ;*  (render-segments parts.m)
            ==
          ==
      ;div(data-scroll-into-view "");
    ==
  ::
  ++  render-segments
    |=  segs=(list segment:notifchat)
    ^-  (list manx)
    %+  turn  segs
    |=  s=segment:notifchat
    ?-  -.s
      %text     ;span: {(trip +.s)}
      %mention
        ;span.mention: {(cite:title +.s)}
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
  ++  head-marl
    ^-  marl
    ;=
      ;meta(charset "utf-8");
      ;meta(name "viewport", content "width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no");
      ;meta(name "theme-color", content "#e8f1f1", media "(prefers-color-scheme: light)");
      ;meta(name "theme-color", content "#1f2f2f", media "(prefers-color-scheme: dark)");
      ;title: Notifchat
      ;link(rel "icon", href "/apps/notifchat/icon.svg", type "image/svg+xml");
      ;link(rel "stylesheet", href (versioned "/apps/notifchat/notifchat.css" notifchat-css));
      ;link(rel "manifest", href "/apps/notifchat/manifest.json");
      ;script(type "module", src (versioned "/apps/notifchat/datastar.js" datastar-js));
      ;script(type "module", src (versioned "/apps/notifchat/pwa-gate.js" pwa-gate-js));
    ==
  ::
  ++  page-manx
    |=  who=@p
    ^-  manx
    =/  hr  ~(. href:ds /apps/notifchat ~)
    ;html
      ;head
        ;*  head-marl
      ==
      ;body
        ;pwa-gate(name "Notifchat")
          ;div#app
            =data-signals  "\{'text': '', '_menuOpen': false}"
            =data-on-load       "{(data-get:hr / [["action" "sse"]]~)}"
            ;+  (header-manx who)
            ;div#error-banner(style "display:none")
              ;span.error-msg;
              ;button.error-dismiss(data-on-click "el.parentElement.classList.remove('visible')"): x
            ==
            ;div#messages;
            ;form
              =data-signals  "\{'_sending': false}"
              =data-on-submit  (data-post:hr / [["action" "send"]]~)
              =data-indicator  "_sending"
              ;div.resize-handle
                ;div.grip;
              ==
              ;button.send-btn
                =type  "submit"
                =data-attr-disabled  "$_sending"
                ;svg
                  =xmlns  "http://www.w3.org/2000/svg"
                  =viewBox  "0 0 20 20"
                  =fill  "currentColor"
                  =width  "20"
                  =height  "20"
                  ;path
                    =fill-rule  "evenodd"
                    =clip-rule  "evenodd"
                    =d  "M3 10a.75.75 0 0 1 .75-.75h10.638".
                        "l-3.96-3.71a.75.75 0 1 1 1.024-1.0".
                        "96l5.25 4.916a.75.75 0 0 1 0 1.096".
                        "l-5.25 4.916a.75.75 0 1 1-1.024-1.".
                        "096l3.96-3.71H3.75A.75.75 0 0 1 3 ".
                        "10Z"
                    ;*  ~
                  ==
                ==
              ==
              ;textarea
                =id  "input"
                =placeholder  "reply..."
                =autocomplete  "off"
                =rows  "4"
                =data-bind-text  ""
                =data-class-sending  "$_sending"
                =data-on-effect  "if(!$_sending) el.focus()"
                ;*  ~
              ==
            ==
          ==
        ==
        ;script(type "module", src (versioned "/apps/notifchat/notifchat.js" notifchat-js));
      ==
    ==
  ::
  ::
  ++  header-manx
    |=  who=@p
    ^-  manx
    =/  login-el=manx
      ;form.user-menu-form(method "GET", action "/~/logout")
        ;input(type "hidden", name "redirect", value "/apps/notifchat");
        ;button(type "submit", class "menu-action"): logout
      ==
    ;header
      ;div.header-left
        ;div.notif-menu
          =data-signals  "\{'_notifOpen': false}"
          ;button#notif-mode.off.init
            =data-on-click  "if(!el.classList.contains('loading')) $_notifOpen = !$_notifOpen"
            =data-class-open  "$_notifOpen"
            ;+  bell-icon
            ;span.notif-label: turn on notifs
          ==
          ;div#notif-dropdown.notif-dropdown
            =data-show  "$_notifOpen"
            ;button.notif-option(data-mode "off")
              =data-on-click  "$_notifOpen = false; setNotifMode('off')"
              ; off
            ==
            ;button.notif-option(data-mode "mention")
              =data-on-click  "$_notifOpen = false; setNotifMode('mention')"
              ; mentions
            ==
            ;button.notif-option(data-mode "all")
              =data-on-click  "$_notifOpen = false; setNotifMode('all')"
              ; all
            ==
          ==
          ;div.menu-backdrop
            =data-show  "$_notifOpen"
            =data-on-click  "$_notifOpen = false"
          ;
          ==
        ==
      ==
      ;div.header-right
        ;div.user-menu
          ;button
            =class  "user-btn"
            =data-on-click  "$_menuOpen = !$_menuOpen"
            =data-class-open  "$_menuOpen"
            ; {(cite:title who)}
          ==
          ;div.user-dropdown
            =data-show  "$_menuOpen"
            ;+  login-el
          ==
          ;div.menu-backdrop
            =data-show  "$_menuOpen"
            =data-on-click  "$_menuOpen = false"
          ;
          ==
        ==
      ==
    ==
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
  `this(sessions (~(del in sessions) eid))
::
++  on-peek   on-peek:def
++  on-agent  on-agent:def
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?+  wire  `this
    [%keepalive ~]
      ?.  ?=([%behn %wake *] sign-arvo)  `this
      ?:  =(~ sessions)  `this
      :_  this
      :*  [%pass /keepalive %arvo %b %wait (add now.bowl keepalive-freq)]
          (keepalive-sse-all:ds sessions)
      ==
  ==
++  on-fail   on-fail:def
--
