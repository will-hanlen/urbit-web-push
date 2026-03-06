::  lib/web-pusher: agent wrapper for web push notifications
::
::  Wraps a Gall agent to transparently handle VAPID key
::  management, browser subscription tracking, encrypted push
::  delivery via iris, and delivery status tracking.
::
::  The wrapper owns a pusher-state alongside the inner agent's
::  state, persisting both through on-save/on-load.
::
::  Usage in the agent file:
::
::    /+  web-pusher, default-agent
::    ...
::    %-  %:  agent:web-pusher
::          /apps/my-app
::          'mailto:admin@example.com'
::          %.y
::        ==
::    ^-  agent:gall
::    |_  =bowl:gall
::    ...
::
::  The third argument (allow-comets) controls whether comet
::  ships may register push subscriptions.
::
::  The fourth argument (max-sends) controls how many delivery
::  records to retain in send-order/sends.  When 0, no delivery
::  records are kept (cards are still sent, just no tracking).
::  Use 0 for production; set higher for debugging.
::
::  The wrapper intercepts HTTP requests under {base}/~web-pusher:
::
::    GET  {base}/~web-pusher/sw.js       -- default service worker (public)
::    GET  {base}/~web-pusher/vapid-key   -- VAPID public key
::    POST {base}/~web-pusher/subscribe   -- add subscription
::    POST {base}/~web-pusher/unsubscribe -- remove subscription
::    POST {base}/~web-pusher/check-sub   -- verify subscription exists
::
::  POST body formats (JSON):
::
::    /subscribe:
::      { "id": "b-1709654321",
::        "endpoint": "https://fcm.googleapis.com/...",
::        "p256dh": "<base64url-encoded public key>",
::        "auth": "<base64url-encoded auth secret>"
::      }
::
::    /unsubscribe:
::      { "id": "b-1709654321" }
::
::    /check-sub:
::      { "endpoint": "https://fcm.googleapis.com/..." }
::
::  The sw.js endpoint is served without authentication so browsers
::  can register it as a service worker from any scope.
::
::  To use the default service worker from your inner agent's JS:
::
::    navigator.serviceWorker.register("{base}/~web-pusher/sw.js")
::
::  The default worker handles push events by parsing the payload
::  as JSON with fields: title, body, icon, url, tag.  It collapses
::  notifications with the same tag and opens the url on click.
::
::  If you need custom behavior, serve your own worker instead.
::
::  All other HTTP requests pass through to the inner agent.
::
::  The wrapper also intercepts:
::
::    - Arvo responses on /web-pusher/** wires (iris callbacks)
::    - Pokes with mark %push-send: [(set @p) push-message]
::      If the set is empty, sends to all ships (broadcast).
::    - Peeks on /web-pusher/**:
::
::        /u/web-pusher          -- loob, always %.y
::        /x/web-pusher/state    -- pusher-state noun
::        /x/web-pusher/sends/@p -- (list delivery) for ship
::        /x/web-pusher/sends/@p/@ta -- (list delivery) for sub
::
::  The inner agent triggers notifications by poking itself:
::
::    =/  target  [(set @p) push-message]
::    [%pass /notify %agent [our dap]:bowl %poke %push-send !>(target)]
::
::  Pass ~ (empty set) to broadcast to all ships.
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
    event.waitUntil(
      self.clients.claim().then(function() {
        return self.registration.pushManager.getSubscription();
      }).then(function(sub) {
        if (!sub) return;
        var base = self.registration.scope.replace(/\/~web-pusher\/$/, "");
        return fetch(base + "/~web-pusher/check-sub", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({endpoint: sub.endpoint})
        }).then(function(res) {
          if (res.status === 404) {
            return sub.unsubscribe().then(function() {
              return self.registration.unregister();
            });
          }
        });
      })
    );
  });
  self.addEventListener("push", function(event) {
    var data = {title: "Notification", body: ""};
    try { data = event.data.json(); } catch(e) {}
    var tag = data.tag || "";
    event.waitUntil(
      (tag ? self.registration.getNotifications({tag: tag}) : Promise.resolve([]))
      .then(function(all) {
        var count = 1;
        if (all.length > 0 && all[0].data && all[0].data.count) {
          count = all[0].data.count + 1;
        }
        var title = data.title;
        var body = data.body || "";
        if (count > 1) {
          body = count + " new";
        }
        return self.registration.showNotification(title, {
          body: body,
          icon: data.icon || "",
          tag: tag,
          renotify: true,
          data: {url: data.url || "", count: count}
        });
      })
    );
  });
  self.addEventListener("notificationclick", function(event) {
    event.notification.close();
    if (event.notification.data && event.notification.data.url) {
      event.waitUntil(clients.openWindow(event.notification.data.url));
    }
  });
  '''
|%
++  agent
  |=  [base=path sub-id=@t allow-comets=? max-sends=@ud]
  |=  =agent:gall
  ^-  agent:gall
  =|  pstate=pusher-state
  =/  push-base=path  (snoc base '~web-pusher')
  !.
  |_  =bowl:gall
  +*  this  .
      ag    ~(. agent bowl)
      hep   ~(. helper bowl pstate allow-comets max-sends)
  ::
  ++  on-init
    ^-  (quip card:agent:gall agent:gall)
    =.  config.pstate
      (some (generate-vapid-keypair:web-push eny.bowl sub-id))
    =^  cards  agent  on-init:ag
    :_  this
    :*  [%pass /web-pusher/eyre %arvo %e %connect [~ base] dap.bowl]
        cards
    ==
  ::
  ++  on-save
    ^-  vase
    !>([%web-pusher pstate on-save:ag])
  ::
  ++  on-load
    |=  old-state=vase
    ^-  (quip card:agent:gall agent:gall)
    =/  old=(unit [%web-pusher pusher-state vase])
      %-  mole  |.
      !<([%web-pusher pusher-state vase] old-state)
    ?~  old
      ::  state doesn't match current schema -- reinitialize
      ::
      on-init
    =/  [%web-pusher ps=pusher-state inner=vase]  u.old
    =.  pstate  ps
    =^  cards  agent  (on-load:ag inner)
    :_  this
    :*  [%pass /web-pusher/eyre %arvo %e %connect [~ base] dap.bowl]
        cards
    ==
  ::
  ++  on-poke
    |=  [=mark =vase]
    ^-  (quip card:agent:gall agent:gall)
    ?:  ?=(%push-send mark)
      ?>  =(our src):bowl
      =/  [ships=(set @p) msg=push-message]
        !<([(set @p) push-message] vase)
      =^  cards  pstate  (send-to-ships:hep ships msg)
      [cards this]
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
    ::  all other push routes require authentication
    ::
    ?.  |(authenticated.inbound-request (lte (met 3 src.bowl) 4))
      :_  this
      (err-cards:hep eyre-id 403 'not authenticated')
    =^  cards  pstate
      (handle-http:hep eyre-id sub-path meth body.request.inbound-request)
    [cards this]
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
++  helper
  |_  [=bowl:gall pstate=pusher-state allow-comets=? max-sends=@ud]
  ::
  ++  vapid-pub-b64
    ^-  @t
    ?~  config.pstate  !!
    (~(en base64:mimes:html | &) [65 (rev 3 65 public-key.u.config.pstate)])
  ::
  ++  send-to-ships
    |=  [ships=(set @p) msg=push-message]
    ^-  (quip card:agent:gall pusher-state)
    ?~  config.pstate  ~|(%push-not-configured !!)
    ::  empty set means broadcast to all ships
    ::
    =/  targets=(set @p)
      ?:  =(~ ships)  ~(key by subs.pstate)
      ships
    =/  payload=octs  (message-to-json:web-push msg)
    =/  exp=@ud  (add (unt:chrono:userlib now.bowl) 86.400)
    ::  collect all [ship id subscription] triples
    ::
    =/  trips=(list [=ship id=@ta sub=subscription])
      %-  zing
      %+  turn  ~(tap in targets)
      |=  =ship
      =/  inner=(map @ta subscription)  (~(gut by subs.pstate) ship ~)
      %+  turn  ~(tap by inner)
      |=  [id=@ta sub=subscription]
      [ship id sub]
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
      =/  ds=delivery-status  ?:(=(410 status) %expired %gone)
      =/  ps  (update-delivery key ds)
      ::  remove the specific subscription
      ::
      =/  inner=(map @ta subscription)  (~(gut by subs.ps) ship ~)
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
  ++  handle-http
    |=  [eyre-id=@ta site=path method=@t body=(unit octs)]
    ^-  (quip card:agent:gall pusher-state)
    ?:  =('GET' method)
      :_  pstate
      ?:  =(site /vapid-key)
        ?~  config.pstate
          (err-cards eyre-id 500 'not configured')
        %+  give-simple-payload:app:server  eyre-id
        [[200 [['content-type' 'text/plain'] ~]] `(as-octs:mimes:html vapid-pub-b64)]
      ?:  =(site /debug)
        ?.  =(our src):bowl
          (err-cards eyre-id 403 'owner only')
        %+  give-simple-payload:app:server  eyre-id
        %-  html-response:gen:server
        (as-octs:mimes:html (crip (welp "<!DOCTYPE html>" (en-xml:html debug-page))))
      (give-simple-payload:app:server eyre-id not-found:gen:server)
    ?:  =('POST' method)
      ?:  =(site /subscribe)
        (do-subscribe eyre-id body)
      ?:  =(site /unsubscribe)
        (do-unsubscribe eyre-id body)
      ?:  =(site /check-sub)
        (do-check-sub eyre-id body)
      [(give-simple-payload:app:server eyre-id not-found:gen:server) pstate]
    [(give-simple-payload:app:server eyre-id not-found:gen:server) pstate]
  ::
  ++  do-subscribe
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card:agent:gall pusher-state)
    ?~  body  [(err-cards eyre-id 400 'no body') pstate]
    ::  reject comets if not allowed
    ::
    ?:  &(!allow-comets ?=(%pawn (clan:title src.bowl)))
      [(err-cards eyre-id 403 'comets not allowed') pstate]
    =/  jon=(unit json)  (de:json:html q.u.body)
    ?~  jon  [(err-cards eyre-id 400 'invalid json') pstate]
    ?.  ?=(%o -.u.jon)  [(err-cards eyre-id 400 'expected object') pstate]
    =/  obj  p.u.jon
    =/  id-j  (~(get by obj) 'id')
    =/  ep-j  (~(get by obj) 'endpoint')
    =/  dh-j  (~(get by obj) 'p256dh')
    =/  au-j  (~(get by obj) 'auth')
    ?.  ?&  ?=(^ id-j)  ?=(%s -.u.id-j)
            ?=(^ ep-j)  ?=(%s -.u.ep-j)
            ?=(^ dh-j)  ?=(%s -.u.dh-j)
            ?=(^ au-j)  ?=(%s -.u.au-j)
        ==
      [(err-cards eyre-id 400 'missing fields') pstate]
    =/  dh-octs=(unit octs)  (de-base64url:web-push p.u.dh-j)
    =/  au-octs=(unit octs)  (de-base64url:web-push p.u.au-j)
    ?~  dh-octs  [(err-cards eyre-id 400 'invalid p256dh') pstate]
    ?~  au-octs  [(err-cards eyre-id 400 'invalid auth') pstate]
    =/  dh=@  (rev 3 p.u.dh-octs q.u.dh-octs)
    =/  au=@  (rev 3 p.u.au-octs q.u.au-octs)
    =/  sub=subscription  [p.u.ep-j dh au]
    =/  id=@ta  `@ta`p.u.id-j
    =/  inner=(map @ta subscription)  (~(gut by subs.pstate) src.bowl ~)
    :-  (ok-cards eyre-id)
    pstate(subs (~(put by subs.pstate) src.bowl (~(put by inner) id sub)))
  ::
  ++  do-unsubscribe
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card:agent:gall pusher-state)
    ?~  body  [(err-cards eyre-id 400 'no body') pstate]
    =/  jon=(unit json)  (de:json:html q.u.body)
    ?~  jon  [(err-cards eyre-id 400 'invalid json') pstate]
    ?.  ?=(%o -.u.jon)  [(err-cards eyre-id 400 'expected object') pstate]
    =/  id-j  (~(get by p.u.jon) 'id')
    ?~  id-j  [(err-cards eyre-id 400 'missing id') pstate]
    ?.  ?=(%s -.u.id-j)  [(err-cards eyre-id 400 'id must be string') pstate]
    =/  id=@ta  `@ta`p.u.id-j
    =/  inner=(map @ta subscription)  (~(gut by subs.pstate) src.bowl ~)
    =/  new-inner  (~(del by inner) id)
    :-  (ok-cards eyre-id)
    ?:  =(~ new-inner)
      pstate(subs (~(del by subs.pstate) src.bowl))
    pstate(subs (~(put by subs.pstate) src.bowl new-inner))
  ::
  ++  do-check-sub
    ::  check if a push endpoint is registered for this user
    ::  returns 200 if found, 404 if not
    ::
    |=  [eyre-id=@ta body=(unit octs)]
    ^-  (quip card:agent:gall pusher-state)
    ?~  body  [(err-cards eyre-id 400 'no body') pstate]
    =/  jon=(unit json)  (de:json:html q.u.body)
    ?~  jon  [(err-cards eyre-id 400 'invalid json') pstate]
    ?.  ?=(%o -.u.jon)  [(err-cards eyre-id 400 'expected object') pstate]
    =/  ep-j  (~(get by p.u.jon) 'endpoint')
    ?~  ep-j  [(err-cards eyre-id 400 'missing endpoint') pstate]
    ?.  ?=(%s -.u.ep-j)  [(err-cards eyre-id 400 'endpoint must be string') pstate]
    =/  ep=@t  p.u.ep-j
    =/  inner=(map @ta subscription)  (~(gut by subs.pstate) src.bowl ~)
    =/  found=?
      %+  lien  ~(val by inner)
      |=(sub=subscription =(endpoint.sub ep))
    :_  pstate
    ?:  found
      (ok-cards eyre-id)
    (err-cards eyre-id 404 'subscription not found')
  ::
  ::
  ::
  ++  debug-page
    ^-  manx
    =/  sub-list=(list [@p (map @ta subscription)])
      ~(tap by subs.pstate)
    =/  send-list=(list [send-key delivery])
      %+  murn  send-order.pstate
      |=  key=send-key
      =/  del  (~(get by sends.pstate) key)
      ?~  del  ~
      `[key u.del]
    ::  build config section content
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
    ::  build subscription items
    ::
    =/  sub-items=(list manx)
      ?~  sub-list
        :~  ;p: no subscriptions
        ==
      %+  turn  sub-list
      |=  [=ship inner=(map @ta subscription)]
      ^-  manx
      =/  inl=(list [@ta subscription])  ~(tap by inner)
      =/  sub-rows=(list manx)
        %+  turn  inl
        |=  [id=@ta sub=subscription]
        ^-  manx
        ;details
          ;summary: {(trip id)}
          ;table
            ;tr
              ;td: endpoint
              ;td: {(trip endpoint.sub)}
            ==
            ;tr
              ;td: p256dh
              ;td(class "muted"): {(scow %ux p256dh.sub)}
            ==
            ;tr
              ;td: auth
              ;td(class "muted"): {(scow %ux auth.sub)}
            ==
          ==
        ==
      ;details
        ;summary: {(scow %p ship)} ({(scow %ud (lent inl))} browsers)
        ;*  sub-rows
      ==
    ::  build delivery rows
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
        overflow-wrap: anywhere;
        word-break: break-all;
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
  ++  ok-cards
    |=  eyre-id=@ta
    ^-  (list card:agent:gall)
    %+  give-simple-payload:app:server  eyre-id
    %-  json-response:gen:server
    [%o (~(gas by *(map @t json)) ~[['ok' [%b &]]])]
  ::
  ::
  ++  err-cards
    |=  [eyre-id=@ta code=@ud msg=@t]
    ^-  (list card:agent:gall)
    =/  bod=json  [%o (~(gas by *(map @t json)) ~[['error' [%s msg]]])]
    %+  give-simple-payload:app:server  eyre-id
    [[code [['content-type' 'application/json'] ~]] `(json-to-octs:server bod)]
  --
--
