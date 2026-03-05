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
::        ==
::    ^-  agent:gall
::    |_  =bowl:gall
::    ...
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
::    - Pokes with mark %push-send and %push-send-to
::    - Peeks on /web-pusher/**:
::
::        /u/web-pusher          -- loob, always %.y
::        /x/web-pusher/state    -- pusher-state noun
::        /x/web-pusher/sends/ID -- (list delivery) for sub ID
::
::  The inner agent triggers notifications by poking itself:
::
::    [%pass /notify %agent [our dap]:bowl %poke %push-send !>(msg)]
::
::  Or to specific subscribers:
::
::    =/  target  [ids=(list @ta) msg=push-message]
::    [%pass /notify %agent [our dap]:bowl %poke %push-send-to !>(target)]
::
/-  push
/+  web-push, server
=,  push
|%
++  agent
  |=  [base=path sub-id=@t]
  |=  =agent:gall
  ^-  agent:gall
  =|  pstate=pusher-state
  =/  push-base=path  (snoc base '~web-pusher')
  !.
  |_  =bowl:gall
  +*  this  .
      ag    ~(. agent bowl)
      hep   ~(. helper bowl pstate)
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
    ?.  ?=([%web-pusher ^] q.old-state)
      ::  first load after wrapping: inner agent state only
      ::
      =.  config.pstate
        (some (generate-vapid-keypair:web-push eny.bowl sub-id))
      =^  cards  agent  (on-load:ag old-state)
      :_  this
      :*  [%pass /web-pusher/eyre %arvo %e %connect [~ base] dap.bowl]
          cards
      ==
    =/  [%web-pusher ps=pusher-state inner=vase]
      !<([%web-pusher pusher-state vase] old-state)
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
      =/  msg=push-message  !<(push-message vase)
      =^  cards  pstate  (send-to-all:hep msg)
      [cards this]
    ::
    ?:  ?=(%push-send-to mark)
      =/  [ids=(list @ta) msg=push-message]
        !<([(list @ta) push-message] vase)
      =^  cards  pstate  (send-to-ids:hep ids msg)
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
        =/  id=@ta  i.t.t.t.path
        ``noun+!>((skim sends.pstate |=(d=delivery =(sub-id.d id))))
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
    ?.  ?=([%web-pusher %send @ ~] wire)
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
  |_  [=bowl:gall pstate=pusher-state]
  ::
  ++  vapid-pub-b64
    ^-  @t
    ?~  config.pstate  !!
    (~(en base64:mimes:html | &) [65 (rev 3 65 public-key.u.config.pstate)])
  ::
  ++  send-to-all
    |=  msg=push-message
    ^-  (quip card:agent:gall pusher-state)
    (send-to-ids ~(tap in ~(key by subs.pstate)) msg)
  ::
  ++  send-to-ids
    |=  [ids=(list @ta) msg=push-message]
    ^-  (quip card:agent:gall pusher-state)
    ?~  config.pstate  ~|(%push-not-configured !!)
    =/  payload=octs  (message-to-json:web-push msg)
    =/  exp=@ud  (add (unt:chrono:userlib now.bowl) 86.400)
    =/  cards=(list card:agent:gall)
      %+  murn  ids
      |=  id=@ta
      ^-  (unit card:agent:gall)
      =/  sub  (~(get by subs.pstate) id)
      ?~  sub  ~
      =/  req=request:http
        (send-notification:web-push u.sub u.config.pstate payload exp eny.bowl)
      `[%pass /web-pusher/send/[id] %arvo %i %request req *outbound-config:iris]
    =/  new-sends=(list delivery)
      %+  weld
        %+  murn  ids
        |=  id=@ta
        ?.  (~(has by subs.pstate) id)  ~
        `[id title.msg now.bowl %pending]
      sends.pstate
    [cards pstate(sends (trim-sends new-sends))]
  ::
  ++  handle-iris
    |=  [=wire =sign-arvo]
    ^-  (quip card:agent:gall pusher-state)
    ?>  ?=([@ @ @ ~] wire)
    =/  sub-id=@ta  i.t.t.wire
    ?.  ?=([%iris %http-response *] sign-arvo)
      `pstate
    =/  resp=client-response:iris  +>.sign-arvo
    ?:  ?=(%cancel -.resp)
      `(update-delivery sub-id %failed)
    ?.  ?=(%finished -.resp)  `pstate
    =/  status=@ud  status-code.response-header.resp
    ?:  =(201 status)
      `(update-delivery sub-id %sent)
    ?:  |(=(410 status) =(404 status))
      =/  ds=delivery-status  ?:(=(410 status) %expired %gone)
      =/  ps  (update-delivery sub-id ds)
      `ps(subs (~(del by subs.ps) sub-id))
    `(update-delivery sub-id %failed)
  ::
  ++  update-delivery
    |=  [sub-id=@ta ds=delivery-status]
    ^-  pusher-state
    =-  pstate(sends -)
    =/  found=?  |
    %+  turn  sends.pstate
    |=  d=delivery
    ?:  found  d
    ?.  &(=(sub-id.d sub-id) =(%pending delivery-status.d))
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
    [(ok-cards eyre-id) pstate(subs (~(put by subs.pstate) `@ta`p.u.id-j sub))]
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
    [(ok-cards eyre-id) pstate(subs (~(del by subs.pstate) `@ta`p.u.id-j))]
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
