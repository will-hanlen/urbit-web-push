::  lib/web-pusher: agent wrapper for web push notifications
::
::  Wraps a Gall agent to handle VAPID key management
::  and encrypted push delivery via iris.
::
::  The wrapper owns a pusher-state alongside the inner agent's
::  state, persisting both through on-save/on-load.
::
::  Usage in the agent file:
::
::    /+  web-pusher, default-agent
::    ...
::    %-  %:  agent:web-pusher
::          /apps/my-app                ::  base path
::          'mailto:admin@example.com'  ::  VAPID mailto
::        ==
::    ^-  agent:gall
::    |_  =bowl:gall
::    ...
::
::  The wrapper intercepts HTTP requests under {base}/~web-pusher:
::
::    GET  {base}/~web-pusher/sw.js       -- default service worker (public)
::    GET  {base}/~web-pusher/vapid-key   -- VAPID public key (public)
::    GET  {base}/~web-pusher/debug       -- debug page (owner only)
::
::  All other HTTP requests pass through to the inner agent.
::
::  The wrapper intercepts pokes (all self-pokes only):
::
::    %push-send        -- encrypt and deliver notifications
::    %push-subscribe   -- store a subscription
::    %push-unsubscribe -- remove a subscription
::    %push-set-tags    -- update tags on a subscription
::    %push-debug       -- set debug tracing on/off (loobean, owner only)
::
::  The inner agent manages subscriptions by poking itself:
::
::    [%pass /push %agent [our dap]:bowl %poke %push-subscribe !>(ps)]
::    [%pass /push %agent [our dap]:bowl %poke %push-unsubscribe !>(pu)]
::    [%pass /push %agent [our dap]:bowl %poke %push-set-tags !>(pt)]
::
::  The inner agent triggers notifications by poking itself:
::
::    =/  =push-send  [targets=~ tags=`(set term)`(sy %chat ~) exclude=~ msg]
::    [%pass /notify %agent [our dap]:bowl %poke %push-send !>(push-send)]
::
::  Peeks on /web-pusher/**:
::
::    /u/web-pusher          -- loob, always %.y
::    /x/web-pusher/state    -- pusher-state noun
::
/+  web-push, server
=,  web-push
=/  default-sw-js=octs
  %-  as-octs:mimes:html
  '''
  self.addEventListener("install", function(event) {
    self.skipWaiting();
  });
  self.addEventListener("activate", function(event) {
    event.waitUntil(self.clients.claim());
  });
  self.addEventListener("push", function(event) {
    var data = {title: "Notification", body: ""};
    try { data = event.data.json(); } catch(e) {}
    event.waitUntil(
      self.registration.showNotification(data.title, {
        body: data.body || "",
        icon: data.icon || "",
        data: {url: data.url || ""}
      })
    );
  });
  self.addEventListener("notificationclick", function(event) {
    event.notification.close();
    var url = (event.notification.data && event.notification.data.url) || "";
    if (!url) return;
    event.waitUntil(
      clients.matchAll({type: "window"}).then(function(list) {
        for (var i = 0; i < list.length; i++) {
          if (list[i].url.indexOf(url) !== -1 && list[i].focus) return list[i].focus();
        }
        return clients.openWindow(url);
      })
    );
  });
  '''
|%
++  agent
  |=  [base=path mailto=@t]
  |=  =agent:gall
  ^-  agent:gall
  =|  pstate=pusher-state
  =|  dbug=_|
  =/  push-base=path  (snoc base '~web-pusher')
  !.
  |_  =bowl:gall
  +*  this  .
      ag    ~(. agent bowl)
      hep   ~(. helper bowl pstate dbug)
  ::
  ++  on-init
    ^-  (quip card:agent:gall agent:gall)
    =.  config.pstate
      (some (generate-vapid-keypair:web-push eny.bowl mailto))
    =^  cards  agent  on-init:ag
    :_  this
    :*  [%pass /web-pusher/eyre %arvo %e %connect [~ base] dap.bowl]
        cards
    ==
  ::
  ++  on-save
    ^-  vase
    !>([%web-pusher %1 pstate on-save:ag])
  ::
  ++  on-load
    |=  old-state=vase
    ^-  (quip card:agent:gall agent:gall)
    ::  try current versioned state
    ::
    =/  cur=(unit [%web-pusher %1 pusher-state vase])
      %-  mole  |.
      !<([%web-pusher %1 pusher-state vase] old-state)
    ?^  cur
      =.  pstate  +>-.u.cur
      =^  cards  agent  (on-load:ag +>+.u.cur)
      :_  this
      :*  [%pass /web-pusher/eyre %arvo %e %connect [~ base] dap.bowl]
          cards
      ==
    ::  unrecognized state -- bunt and let inner agent reload
    ::
    =^  cards  agent  (on-load:ag old-state)
    :_  this
    :*  [%pass /web-pusher/eyre %arvo %e %connect [~ base] dap.bowl]
        cards
    ==
  ::
  ++  on-poke
    |=  [=mark =vase]
    ^-  (quip card:agent:gall agent:gall)
    ::  push-send: encrypt and deliver notifications
    ::
    ?:  ?=(%push-send mark)
      ?>  =(our src):bowl
      =/  =push-send  !<(push-send vase)
      =^  cards  pstate  (send-to-ships:hep push-send)
      [cards this]
    ::  push-subscribe: store a subscription
    ::
    ?:  ?=(%push-subscribe mark)
      ?>  =(our src):bowl
      =/  ps=push-subscribe  !<(push-subscribe vase)
      =/  inner=(map @ta tagged-sub)  (~(gut by subs.pstate) who.ps ~)
      =.  subs.pstate
        (~(put by subs.pstate) who.ps (~(put by inner) id.ps [sub.ps tags.ps]))
      `this
    ::  push-unsubscribe: remove a subscription
    ::
    ?:  ?=(%push-unsubscribe mark)
      ?>  =(our src):bowl
      =/  ps=push-unsubscribe  !<(push-unsubscribe vase)
      =/  inner=(map @ta tagged-sub)  (~(gut by subs.pstate) who.ps ~)
      =/  new-inner  (~(del by inner) id.ps)
      =.  subs.pstate
        ?:  =(~ new-inner)
          (~(del by subs.pstate) who.ps)
        (~(put by subs.pstate) who.ps new-inner)
      `this
    ::  push-set-tags: update tags on a subscription
    ::
    ?:  ?=(%push-set-tags mark)
      ?>  =(our src):bowl
      =/  ps=push-set-tags  !<(push-set-tags vase)
      =/  inner=(map @ta tagged-sub)  (~(gut by subs.pstate) who.ps ~)
      =/  ts=(unit tagged-sub)  (~(get by inner) id.ps)
      ?~  ts  `this
      =.  subs.pstate
        (~(put by subs.pstate) who.ps (~(put by inner) id.ps u.ts(tags tags.ps)))
      `this
    ::  push-debug: toggle debug tracing
    ::
    ?:  ?=(%push-debug mark)
      ?>  =(our src):bowl
      =.  dbug  !<(? vase)
      ~&  [%web-pusher ?:(dbug %tracing-on %tracing-off)]
      `this
    ::
    ?.  ?=(%handle-http-request mark)
      =^  cards  agent  (on-poke:ag mark vase)
      [cards this]
    ::
    =+  !<([eyre-id=@ta =inbound-request:eyre] vase)
    =/  rl  (parse-request-line:server url.request.inbound-request)
    =/  site=path  site.rl
    =/  meth=@t  method.request.inbound-request
    ::  check if the request path starts with {base}/~web-pusher
    ::
    =/  pb-len=@ud  (lent push-base)
    ?.  =(push-base (scag pb-len site))
      ::  not a push route -- pass to inner agent
      ::
      =^  cards  agent  (on-poke:ag mark vase)
      [cards this]
    ::  push route
    ::
    =/  sub-path=path  (slag pb-len site)
    ::  serve default service worker publicly
    ::
    ?:  &(=('GET' meth) =(sub-path /sw))
      :_  this
      %+  give-simple-payload:app:server  eyre-id
      (js-response:gen:server default-sw-js)
    ::  serve VAPID public key publicly
    ::
    ?:  &(=('GET' meth) =(sub-path /vapid-key))
      :_  this
      ?~  config.pstate
        (err-cards:hep eyre-id 500 'not configured')
      %+  give-simple-payload:app:server  eyre-id
      [[200 [['content-type' 'text/plain'] ~]] `(as-octs:mimes:html vapid-pub-b64:hep)]
    ::  debug page (owner only)
    ::
    ?:  &(=('GET' meth) =(sub-path /debug))
      :_  this
      ?.  =(our src):bowl
        (err-cards:hep eyre-id 403 'owner only')
      %+  give-simple-payload:app:server  eyre-id
      %-  html-response:gen:server
      (as-octs:mimes:html (crip (welp "<!DOCTYPE html>" (en-xml:html debug-page:hep))))
    ::  anything else under ~web-pusher is 404
    ::
    :_  this
    (give-simple-payload:app:server eyre-id not-found:gen:server)
  ::
  ++  on-watch
    |=  =path
    ^-  (quip card:agent:gall agent:gall)
    =^  cards  agent  (on-watch:ag path)
    [cards this]
  ::
  ++  on-leave
    |=  =path
    ^-  (quip card:agent:gall agent:gall)
    =^  cards  agent  (on-leave:ag path)
    [cards this]
  ::
  ++  on-peek
    |=  =path
    ^-  (unit (unit cage))
    ?:  ?=([@ %web-pusher *] path)
      ?+  path  [~ ~]
          [%u %web-pusher ~]
        ``noun+!>(&)
          [%x %web-pusher %state ~]
        ``noun+!>(pstate)
      ==
    (on-peek:ag path)
  ::
  ++  on-agent
    |=  [=wire =sign:agent:gall]
    ^-  (quip card:agent:gall agent:gall)
    =^  cards  agent  (on-agent:ag wire sign)
    [cards this]
  ::
  ++  on-arvo
    |=  [=wire =sign-arvo]
    ^-  (quip card:agent:gall agent:gall)
    ?:  ?=([%web-pusher %eyre ~] wire)
      `this
    ?.  ?=([%web-pusher %send @ @ ~] wire)
      =^  cards  agent  (on-arvo:ag wire sign-arvo)
      [cards this]
    =^  cards  pstate  (handle-iris:hep wire sign-arvo)
    [cards this]
  ::
  ++  on-fail
    |=  [=term =tang]
    ^-  (quip card:agent:gall agent:gall)
    =^  cards  agent  (on-fail:ag term tang)
    [cards this]
  --
::
++  helper
  |_  [=bowl:gall pstate=pusher-state dbug=?]
  ::
  ++  vapid-pub-b64
    ^-  @t
    ?~  config.pstate  !!
    (~(en base64:mimes:html | &) [65 (rev 3 65 public-key.u.config.pstate)])
  ::
  ++  send-to-ships
    |=  =push-send
    ^-  (quip card:agent:gall pusher-state)
    ?~  config.pstate  ~|(%push-not-configured !!)
    =/  msg  msg.push-send
    ::  step 1: candidates from targets (empty = all subscribed)
    ::
    =/  targets=(set @p)
      ?:  =(~ targets.push-send)  ~(key by subs.pstate)
      targets.push-send
    ::  step 2: remove excluded ships
    ::
    =.  targets  (~(dif in targets) exclude.push-send)
    =/  payload=octs  (message-to-json:web-push msg)
    =/  exp=@ud  (add (unt:chrono:userlib now.bowl) 86.400)
    ::  collect matching [ship id subscription] triples
    ::  filter by per-subscription tags when push-send has tags
    ::
    =/  trips=(list [=ship id=@ta sub=subscription])
      %-  zing
      %+  turn  ~(tap in targets)
      |=  =ship
      =/  inner=(map @ta tagged-sub)  (~(gut by subs.pstate) ship ~)
      %+  murn  ~(tap by inner)
      |=  [id=@ta ts=tagged-sub]
      ::  if push-send has no tags, send to all subs
      ::  if sub has no tags (empty), it receives everything
      ::  otherwise, sub must have at least one matching tag
      ::
      ?:  =(~ tags.push-send)  `[ship id sub.ts]
      ?:  =(~ tags.ts)  `[ship id sub.ts]
      ?.  =(~ (~(int in tags.ts) tags.push-send))
        `[ship id sub.ts]
      ~
    ~?  dbug  [%web-pusher %sending (lent trips) %notifications]
    =/  cards=(list card:agent:gall)  ~
    |-
    ?~  trips
      [(flop cards) pstate]
    =/  [=ship id=@ta sub=subscription]  i.trips
    ~?  dbug  [%web-pusher %push-to ship id]
    =/  req=request:http
      (send-notification:web-push sub u.config.pstate payload exp eny.bowl)
    %=  $
      trips  t.trips
      cards  :_  cards
        [%pass /web-pusher/send/(scot %p ship)/[id] %arvo %i %request req *outbound-config:iris]
    ==
  ::
  ++  handle-iris
    |=  [=wire =sign-arvo]
    ^-  (quip card:agent:gall pusher-state)
    ?>  ?=([@ @ @ @ ~] wire)
    =/  =ship  (slav %p i.t.t.wire)
    =/  sid=@ta  i.t.t.t.wire
    ?.  ?=([%iris %http-response *] sign-arvo)
      `pstate
    =/  resp=client-response:iris  +>.sign-arvo
    ?.  ?=(%finished -.resp)  `pstate
    =/  status=@ud  status-code.response-header.resp
    ?:  |(=(410 status) =(404 status))
      ::  remove the dead subscription
      ::
      ~?  dbug  [%web-pusher %removing-dead-sub ship sid status]
      =/  inner=(map @ta tagged-sub)  (~(gut by subs.pstate) ship ~)
      =/  new-inner  (~(del by inner) sid)
      ?:  =(~ new-inner)
        `pstate(subs (~(del by subs.pstate) ship))
      `pstate(subs (~(put by subs.pstate) ship new-inner))
    ?:  =(201 status)
      ~?  dbug  [%web-pusher %delivered ship sid]
      `pstate
    ~?  dbug  [%web-pusher %send-failed ship sid status]
    `pstate
  ::
  ++  debug-page
    ^-  manx
    =/  sub-list=(list [@p (map @ta tagged-sub)])
      ~(tap by subs.pstate)
    ::  config section
    ::
    =/  config-body=manx
      ?~  config.pstate
        ;p: not configured
      ;table
        ;tr
          ;td: subject
          ;td: {(trip sub.u.config.pstate)}
        ==
        ;tr
          ;td: public key
          ;td: {(trip vapid-pub-b64)}
        ==
      ==
    ::  subscription items
    ::
    =/  sub-items=(list manx)
      ?~  sub-list
        :~  ;p: no subscriptions
        ==
      %+  turn  sub-list
      |=  [=ship inner=(map @ta tagged-sub)]
      ^-  manx
      =/  inl=(list [@ta tagged-sub])  ~(tap by inner)
      =/  sub-rows=(list manx)
        %+  turn  inl
        |=  [id=@ta ts=tagged-sub]
        ^-  manx
        =/  tags-text=tape
          ?:  =(~ tags.ts)  "all"
          %-  zing
          ^-  (list tape)
          %+  join  ", "
          (turn ~(tap in tags.ts) |=(t=term (trip t)))
        ;details
          ;summary: {(trip id)} (tags: {tags-text})
          ;table
            ;tr
              ;td: endpoint
              ;td: {(trip endpoint.sub.ts)}
            ==
            ;tr
              ;td: p256dh
              ;td(class "muted"): {(scow %ux p256dh.sub.ts)}
            ==
            ;tr
              ;td: auth
              ;td(class "muted"): {(scow %ux auth.sub.ts)}
            ==
          ==
        ==
      ;details
        ;summary: {(scow %p ship)} ({(scow %ud (lent inl))} browsers)
        ;*  sub-rows
      ==
    ::  assemble page
    ::
    =/  css=@t
      '''
      body {
        font-family: monospace;
        max-width: 960px;
        margin: 2em auto;
        padding: 0 1em;
      }
      summary {
        cursor: pointer;
        font-weight: bold;
        padding: 0.3em 0;
      }
      details {
        margin-left: 1em;
        border-left: 2px solid #ccc;
        padding-left: 1em;
      }
      table {
        border-collapse: collapse;
        margin: 0.5em 0;
        width: 100%;
      }
      td, th {
        text-align: left;
        padding: 0.2em 1em 0.2em 0;
      }
      td {
        white-space: nowrap;
      }
      .muted { color: #888; }
      @media (prefers-color-scheme: dark) {
        body {
          background: #1a1a1a;
          color: #ddd;
        }
        details {
          border-left-color: #555;
        }
        .muted { color: #999; }
      }
      '''
    ;html
      ;head
        ;title: web-pusher debug
        ;+  ;style: {(trip css)}
      ==
      ;body
        ;h1: web-pusher debug
        ;details(open "")
          ;summary: config
          ;+  config-body
        ==
        ;details(open "")
          ;summary: subscriptions ({(scow %ud (lent sub-list))} ships)
          ;*  sub-items
        ==
      ==
    ==
  ::
  ++  err-cards
    |=  [eyre-id=@ta code=@ud msg=@t]
    ^-  (list card:agent:gall)
    =/  bod=json  [%o (malt `(list [@t json])`~[['error' [%s msg]]])]
    %+  give-simple-payload:app:server  eyre-id
    [[code [['content-type' 'application/json'] ~]] `(json-to-octs:server bod)]
  --
--
