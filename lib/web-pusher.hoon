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
::  The wrapper intercepts HTTP requests under {base}/~web-pusher:
::
::    GET  {base}/~web-pusher/vapid-key   -- VAPID public key
::    POST {base}/~web-pusher/subscribe   -- add subscription
::    POST {base}/~web-pusher/unsubscribe -- remove subscription
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
|%
++  agent
  |=  [base=path sub-id=@t allow-comets=?]
  |=  =agent:gall
  ^-  agent:gall
  =|  pstate=pusher-state
  =/  push-base=path  (snoc base '~web-pusher')
  !.
  |_  =bowl:gall
  +*  this  .
      ag    ~(. agent bowl)
      hep   ~(. helper bowl pstate allow-comets)
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
    ::  push route -- require authentication
    ::
    =/  sub-path=path  (slag pb-len site)
    ?.  authenticated.inbound-request
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
        ``noun+!>((skim sends.pstate |=(d=delivery =(ship.d ship))))
          [%x %web-pusher %sends @ @ ~]
        =/  =ship  (slav %p i.t.t.t.path)
        =/  id=@ta  i.t.t.t.t.path
        ``noun+!>((skim sends.pstate |=(d=delivery &(=(ship.d ship) =(sub-id.d id)))))
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
  |_  [=bowl:gall pstate=pusher-state allow-comets=?]
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
    =/  cards=(list card:agent:gall)
      %+  turn  trips
      |=  [=ship id=@ta sub=subscription]
      ^-  card:agent:gall
      =/  req=request:http
        (send-notification:web-push sub u.config.pstate payload exp eny.bowl)
      [%pass /web-pusher/send/(scot %p ship)/[id] %arvo %i %request req *outbound-config:iris]
    =/  new-sends=(list delivery)
      %+  turn  trips
      |=  [=ship id=@ta sub=subscription]
      ^-  delivery
      [ship id title.msg now.bowl %pending]
    [cards pstate(sends (trim-sends (weld new-sends sends.pstate)))]
  ::
  ++  handle-iris
    |=  [=wire =sign-arvo]
    ^-  (quip card:agent:gall pusher-state)
    ?>  ?=([@ @ @ @ ~] wire)
    =/  =ship  (slav %p i.t.t.wire)
    =/  sub-id=@ta  i.t.t.t.wire
    ?.  ?=([%iris %http-response *] sign-arvo)
      `pstate
    =/  resp=client-response:iris  +>.sign-arvo
    ?:  ?=(%cancel -.resp)
      `(update-delivery ship sub-id %failed)
    ?.  ?=(%finished -.resp)  `pstate
    =/  status=@ud  status-code.response-header.resp
    ?:  =(201 status)
      `(update-delivery ship sub-id %sent)
    ?:  |(=(410 status) =(404 status))
      =/  ds=delivery-status  ?:(=(410 status) %expired %gone)
      =/  ps  (update-delivery ship sub-id ds)
      ::  remove the specific subscription
      ::
      =/  inner=(map @ta subscription)  (~(gut by subs.ps) ship ~)
      =/  new-inner  (~(del by inner) sub-id)
      ?:  =(~ new-inner)
        `ps(subs (~(del by subs.ps) ship))
      `ps(subs (~(put by subs.ps) ship new-inner))
    `(update-delivery ship sub-id %failed)
  ::
  ++  update-delivery
    |=  [=ship sub-id=@ta ds=delivery-status]
    ^-  pusher-state
    =-  pstate(sends -)
    =/  found=?  |
    %+  turn  sends.pstate
    |=  d=delivery
    ?:  found  d
    ?.  &(=(ship.d ship) =(sub-id.d sub-id) =(%pending delivery-status.d))
      d
    =.  found  &
    d(delivery-status ds)
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
      (give-simple-payload:app:server eyre-id not-found:gen:server)
    ?:  =('POST' method)
      ?:  =(site /subscribe)
        (do-subscribe eyre-id body)
      ?:  =(site /unsubscribe)
        (do-unsubscribe eyre-id body)
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
  ::
  ::
  ++  trim-sends
    |=  s=(list delivery)
    ^-  (list delivery)
    ?:  (lte (lent s) 200)  s
    (scag 200 s)
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
