::  lib/web-pusher: agent wrapper for web push notifications
::
::  Wraps a Gall agent to handle VAPID key management,
::  encrypted push delivery via iris, and delivery tracking.
::
::  The wrapper owns a pusher-state alongside the inner agent's
::  state, persisting both through on-save/on-load.
::
::  Usage in the agent file:
::
::    /+  web-pusher, default-agent
::    ...
::    %-  %:  agent:web-pusher
::          /apps/my-app            ::  base path
::          'mailto:admin@example.com'  ::  VAPID mailto
::          200                     ::  max-sends
::        ==
::    ^-  agent:gall
::    |_  =bowl:gall
::    ...
::
::  The third argument (max-sends) controls how many delivery
::  records to retain in send-order/sends.  When 0, no delivery
::  records are kept.
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
::    /x/web-pusher/sends/@p -- (list delivery) for ship
::    /x/web-pusher/sends/@p/@ta -- (list delivery) for sub
::
/-  push
/+  web-push, server
=,  push
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
  |=  [base=path mailto=@t max-sends=@ud]
  |=  =agent:gall
  ^-  agent:gall
  =|  pstate=pusher-state
  =/  push-base=path  (snoc base '~web-pusher')
  !.
  |_  =bowl:gall
  +*  this  .
      ag    ~(. agent bowl)
      hep   ~(. helper bowl pstate max-sends)
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
    ::  try unversioned pusher-state (pre-versioning)
    ::
    =/  old-uv=(unit [%web-pusher pusher-state vase])
      %-  mole  |.
      !<([%web-pusher pusher-state vase] old-state)
    ?^  old-uv
      =.  pstate  +<.u.old-uv
      =^  cards  agent  (on-load:ag +>.u.old-uv)
      :_  this
      :*  [%pass /web-pusher/eyre %arvo %e %connect [~ base] dap.bowl]
          cards
      ==
    ::  try v0 (subscription without tags, separate prefs map)
    ::
    =/  old-v0=(unit [%web-pusher old-pusher-state vase])
      %-  mole  |.
      !<([%web-pusher old-pusher-state vase] old-state)
    ?~  old-v0
      ::  unrecognized state -- crash rather than silently lose VAPID keys
      ::
      ~|(%web-pusher-unknown-state !!)
    =/  [%web-pusher ops=old-pusher-state inner=vase]  u.old-v0
    ::  migrate: convert subscription -> tagged-sub, merge prefs
    ::
    =/  new-subs=(map @p (map @ta tagged-sub))
      %-  ~(run by subs.ops)
      |=  inner=(map @ta subscription)
      ^-  (map @ta tagged-sub)
      (~(run by inner) |=(s=subscription [sub=s tags=~]))
    ::  apply old prefs to all subscriptions for each ship
    ::
    =.  new-subs
      %-  ~(rep by prefs.ops)
      |=  [[=ship tags=(set term)] acc=(map @p (map @ta tagged-sub))]
      =/  inner=(map @ta tagged-sub)  (~(gut by acc) ship ~)
      %+  ~(put by acc)  ship
      (~(run by inner) |=(ts=tagged-sub ts(tags tags)))
    =.  pstate
      :*  config.ops
          new-subs
          send-order.ops
          sends.ops
          next-id.ops
      ==
    =^  cards  agent  (on-load:ag inner)
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
          [%x %web-pusher %sends @ ~]
        =/  =ship  (slav %p i.t.t.t.path)
        =/  res=(list [send-key delivery])
          %+  murn  send-order.pstate
          |=  key=send-key
          ?.  =(ship.key ship)  ~
          =/  del  (~(get by sends.pstate) key)
          ?~  del  ~
          `[key u.del]
        ``noun+!>(res)
          [%x %web-pusher %sends @ @ ~]
        =/  =ship  (slav %p i.t.t.t.path)
        =/  id=@ta  i.t.t.t.t.path
        =/  res=(list [send-key delivery])
          %+  murn  send-order.pstate
          |=  key=send-key
          ?.  &(=(ship.key ship) =(sub-id.key id))  ~
          =/  del  (~(get by sends.pstate) key)
          ?~  del  ~
          `[key u.del]
        ``noun+!>(res)
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
    ?.  ?=([%web-pusher %send @ @ @ ~] wire)
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
::  old pusher-state for migration
::
+$  old-pusher-state
  $:  config=(unit push-config)
      subs=(map @p (map @ta subscription))
      prefs=(map @p (set term))
      send-order=(list send-key)
      sends=(map send-key delivery)
      next-id=@ud
  ==
::
++  helper
  |_  [=bowl:gall pstate=pusher-state max-sends=@ud]
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
    =/  ps  pstate
    =/  cards=(list card:agent:gall)  ~
    |-
    ?~  trips
      [(flop cards) (trim-sends ps)]
    =/  [=ship id=@ta sub=subscription]  i.trips
    =/  req=request:http
      (send-notification:web-push sub u.config.pstate payload exp eny.bowl)
    ?:  =(0 max-sends)
      %=  $
        trips  t.trips
        cards  :_  cards
          [%pass /web-pusher/send/(scot %p ship)/[id]/(scot %ud 0) %arvo %i %request req *outbound-config:iris]
      ==
    =/  nid=@ud  next-id.ps
    %=  $
      trips  t.trips
      cards  :_  cards
        [%pass /web-pusher/send/(scot %p ship)/[id]/(scot %ud nid) %arvo %i %request req *outbound-config:iris]
      ps  %=  ps
            next-id  +(nid)
            send-order  [[ship id nid] send-order.ps]
            sends  (~(put by sends.ps) [ship id nid] [title.msg now.bowl %pending])
          ==
    ==
  ::
  ++  handle-iris
    |=  [=wire =sign-arvo]
    ^-  (quip card:agent:gall pusher-state)
    ?>  ?=([@ @ @ @ @ ~] wire)
    =/  =ship  (slav %p i.t.t.wire)
    =/  sid=@ta  i.t.t.t.wire
    =/  nid=@ud  (slav %ud i.t.t.t.t.wire)
    =/  key=send-key  [ship sid nid]
    ?.  ?=([%iris %http-response *] sign-arvo)
      `pstate
    =/  resp=client-response:iris  +>.sign-arvo
    ?:  ?=(%cancel -.resp)
      `(update-delivery key %failed)
    ?.  ?=(%finished -.resp)  `pstate
    =/  status=@ud  status-code.response-header.resp
    ?:  =(201 status)
      `(update-delivery key %sent)
    ?:  |(=(410 status) =(404 status))
      =/  ds=delivery-status  ?:(=(410 status) %gone %expired)
      =/  ps  (update-delivery key ds)
      ::  remove the specific subscription
      ::
      =/  inner=(map @ta tagged-sub)  (~(gut by subs.ps) ship ~)
      =/  new-inner  (~(del by inner) sid)
      ?:  =(~ new-inner)
        `ps(subs (~(del by subs.ps) ship))
      `ps(subs (~(put by subs.ps) ship new-inner))
    `(update-delivery key %failed)
  ::
  ++  update-delivery
    |=  [key=send-key ds=delivery-status]
    ^-  pusher-state
    ?.  (~(has by sends.pstate) key)
      pstate
    pstate(sends (~(jab by sends.pstate) key |=(d=delivery d(delivery-status ds))))
  ::
  ++  debug-page
    ^-  manx
    =/  sub-list=(list [@p (map @ta tagged-sub)])
      ~(tap by subs.pstate)
    =/  send-list=(list [send-key delivery])
      %+  murn  send-order.pstate
      |=  key=send-key
      =/  del  (~(get by sends.pstate) key)
      ?~  del  ~
      `[key u.del]
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
    ::  delivery rows
    ::
    =/  sends-body=manx
      ?~  send-list
        ;p: no deliveries
      ;table
        ;tr
          ;th: ship
          ;th: sub
          ;th: title
          ;th: time
          ;th: status
        ==
        ;*  %+  turn  send-list
            |=  [key=send-key d=delivery]
            ^-  manx
            ;tr
              ;td: {(scow %p ship.key)}
              ;td: {(trip sub-id.key)}
              ;td: {(trip title.d)}
              ;td: {(scow %da sent-at.d)}
              ;td(class "{(trip delivery-status.d)}"): {(trip delivery-status.d)}
            ==
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
      .pending { color: #a80; }
      .sent { color: #080; }
      .failed { color: #c00; }
      .expired { color: #888; }
      .gone { color: #c00; font-style: italic; }
      .muted { color: #888; }
      @media (prefers-color-scheme: dark) {
        body {
          background: #1a1a1a;
          color: #ddd;
        }
        details {
          border-left-color: #555;
        }
        .pending { color: #db2; }
        .sent { color: #4b4; }
        .failed { color: #f66; }
        .expired { color: #999; }
        .gone { color: #f66; }
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
        ;details(open "")
          ;summary: deliveries ({(scow %ud (lent send-list))})
          ;+  sends-body
        ==
      ==
    ==
  ::
  ++  trim-sends
    |=  ps=pusher-state
    ^-  pusher-state
    ?:  =(0 max-sends)
      ps(send-order ~, sends ~)
    ?:  (lte (lent send-order.ps) max-sends)
      ps
    =/  kept=(list send-key)  (scag max-sends send-order.ps)
    =/  new-sends=(map send-key delivery)
      %-  ~(gas by *(map send-key delivery))
      %+  murn  kept
      |=  key=send-key
      =/  del  (~(get by sends.ps) key)
      ?~  del  ~
      `[key u.del]
    ps(send-order kept, sends new-sends)
  ::
  ++  err-cards
    |=  [eyre-id=@ta code=@ud msg=@t]
    ^-  (list card:agent:gall)
    =/  bod=json  [%o (malt `(list [@t json])`~[['error' [%s msg]]])]
    %+  give-simple-payload:app:server  eyre-id
    [[code [['content-type' 'application/json'] ~]] `(json-to-octs:server bod)]
  --
--
