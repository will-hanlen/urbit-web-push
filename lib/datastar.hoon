::  lib/datastar: utilities for building Datastar SSE-driven UIs
::
::  Datastar is a JS library that uses Server-Sent Events (SSE) to
::  reactively update the browser DOM from the server. The server
::  sends SSE events containing HTML fragments and/or signal patches,
::  and datastar swaps them into the page.
::
::  This library provides Hoon helpers for:
::  - Parsing datastar signals from HTTP requests
::  - Building SSE response bodies (patch-elements / patch-signals)
::  - Constructing HTTP response cards for datastar
::  - Generating datastar action attributes for HTML
::
::  ## Usage
::
::  /+  datastar
::
::  Check if a request comes from datastar:
::    (is-datastar header-list.request.inbound-request)
::
::  Parse signals from a request:
::    (datastar-signals pams body)
::
::  Build a datastar SSE response:
::    %^  give-sse  eyre-id  ~
::    :~  ["outer" `"#my-el" my-manx]
::    ==
::
|%
::  +$  datastar-fragment: an HTML fragment for datastar to swap in
::
::  mode: "outer" (replace element), "inner" (replace children),
::        "prepend", "append", "before", "after", "remove"
::  selector: CSS selector to target (~ uses the fragment's own id)
::  manx: the HTML to swap in
::
+$  datastar-fragment  [mode=tape selector=(unit tape) =manx]
::
::  +is-datastar: check if an HTTP request was made by datastar
::
::  datastar adds a 'datastar-request: true' header to all requests
::
++  is-datastar
  |=  =header-list:http
  ^-  ?
  .=  `'true'
  (get-header:http 'datastar-request' header-list)
::
::  +datastar-signals: parse datastar signals from request
::
::  datastar sends signals as JSON, either in a 'datastar' query
::  param (GET) or in the request body (POST). returns a flat
::  map of signal-name -> signal-value.
::
++  datastar-signals
  |=  [pams=(map @t @t) body=(unit octs)]
  ^-  (map @t @t)
  %-  json-to-map
  %-  fall  :_  *json
  %-  mole  |.
  %-  need
  %-  de:json:html
  ?^  j=(~(get by pams) 'datastar')  u.j
  ?~  b=body  ''
  +:u.b
::
::  +json-to-map: flatten a single-layer JSON object to a map
::
++  json-to-map
  =|  m=(map @t @t)
  |=  son=json
  ^+  m
  ?~  son  m
  ?>  ?=(%o -.son)
  =/  items  p.son
  %-  malt
  ^-  (list [@t @t])
  %+  turn  ~(tap by items)
  |=  [key=@t s=json]
  :-  key
  ^-  @t
  ?~  s  ''
  ?-  -.s
    %s  p.s
    %b  ?:(p.s 'true' 'false')
    %n  p.s
    %a  ''
    %o  !!
  ==
::
::  +map-to-json: convert a flat map to a JSON object
::
++  map-to-json
  |=  m=(map @t @t)
  ^-  json
  :-  %o
  %-  malt
  %+  turn  ~(tap by m)
  |=  [k=@t v=@t]
  :-  k
  ?:  =(v 'true')   b+&
  ?:  =(v 'false')  b+|
  s+v
::
::  +predent: prefix each line of text with a front string
::
::  used to build multi-line SSE data fields:
::    data: elements <line1>
::    data: elements <line2>
::
++  predent
  |=  [front=tape text=tape]
  ^-  tape
  %-  zing
  %+  turn  (to-wain:format (crip text))
  |=  =cord
  "{front}{(trip cord)}\0a"
::
::  +datastar-response-body: build the SSE event text
::
::  produces the raw text/event-stream content with
::  datastar-patch-signals and datastar-patch-elements events.
::
::  sig-list: list of [key value] signal patches (~ for none)
::  fragments: list of HTML fragments to swap
::
++  datastar-response-body
  |=  [sig-list=(list (pair @t @t)) fragments=(list datastar-fragment)]
  ^-  cord
  %-  crip
  %+  welp
    ^-  tape
    ?~  sig-list  ""
    =/  signals  (map-to-json (malt sig-list))
    %-  zing
    %+  join  "\0a"
    ^-  wall
    :~
      "event: datastar-patch-signals"
      "data: signals {(trip (en:json:html signals))}"
      "\0a\0a"
    ==
  =|  out=tape
  |-
  ^-  tape
  ?~  fragments  out
  =/  fragment  i.fragments
  =.  out
    %+  welp  out
    %-  zing
    %+  join  "\0a"
    ^-  wall
    :~
      "event: datastar-patch-elements"
      ::
      %+  welp  "data: mode {mode.fragment}"
      ?~  selector.fragment  ""
      "\0adata: selector {u.selector.fragment}"
      ::
      ?:  |(=(manx.fragment *manx) =(manx.fragment ;/("")))  ""
      %+  predent  "data: elements "
      (en-xml:html manx.fragment)
      ::
      "\0a\0a"
    ==
  $(fragments t.fragments)
::
::  +give-sse: produce HTTP response cards for a one-shot datastar SSE response
::
::  returns the standard 3-card pattern: header, data, kick.
::  for persistent connections, use open-sse-conn + push-sse instead.
::
++  give-sse
  |=  [eyre-id=@ta sig-list=(list (pair @t @t)) fragments=(list datastar-fragment)]
  ^-  (list card:agent:gall)
  =/  body=cord  (datastar-response-body sig-list fragments)
  =/  =octs  (as-octs:mimes:html body)
  =/  =response-header:http
    :-  200
    :~  ['Content-Type' 'text/event-stream']
    ==
  :~  [%give %fact ~[/http-response/[eyre-id]] [%http-response-header !>(response-header)]]
      [%give %fact ~[/http-response/[eyre-id]] [%http-response-data !>(`octs)]]
      [%give %kick ~[/http-response/[eyre-id]] ~]
  ==
::
::  Persistent SSE connection helpers
::
::  For Datastar's reactive model, the browser opens a long-lived SSE
::  connection via @get. The server holds it open and pushes updates
::  as state changes. These arms manage that lifecycle:
::
::    1. open-sse-conn: send 200 + headers (no kick), store eyre-id
::    2. push-sse:      send fragments/signals to one open connection
::    3. push-sse-all:  send to all connections in a set
::    4. close-sse-conn: kick a connection closed
::
::  +open-sse-conn: send SSE response headers, keeping connection open
::
::  call this when a datastar @get request arrives. returns the header
::  card — store the eyre-id in your agent state for later pushes.
::  optionally sends initial fragments in the same response.
::
++  open-sse-conn
  |=  [eyre-id=@ta sig-list=(list (pair @t @t)) fragments=(list datastar-fragment)]
  ^-  (list card:agent:gall)
  =/  =response-header:http
    :-  200
    :~  ['Content-Type' 'text/event-stream']
        ['Cache-Control' 'no-cache']
    ==
  :-  [%give %fact ~[/http-response/[eyre-id]] [%http-response-header !>(response-header)]]
  ?:  &(=(~ sig-list) =(~ fragments))  ~
  =/  body=cord  (datastar-response-body sig-list fragments)
  =/  =octs  (as-octs:mimes:html body)
  ~[[%give %fact ~[/http-response/[eyre-id]] [%http-response-data !>(`octs)]]]
::
::  +push-sse: push fragments/signals to one open SSE connection
::
::  use this to send updates to a single eyre-id that was previously
::  opened with open-sse-conn.
::
++  push-sse
  |=  [eyre-id=@ta sig-list=(list (pair @t @t)) fragments=(list datastar-fragment)]
  ^-  (list card:agent:gall)
  =/  body=cord  (datastar-response-body sig-list fragments)
  =/  =octs  (as-octs:mimes:html body)
  ~[[%give %fact ~[/http-response/[eyre-id]] [%http-response-data !>(`octs)]]]
::
::  +push-sse-all: push the same update to every connection in a set
::
++  push-sse-all
  |=  [ids=(set @ta) sig-list=(list (pair @t @t)) fragments=(list datastar-fragment)]
  ^-  (list card:agent:gall)
  =/  body=cord  (datastar-response-body sig-list fragments)
  =/  =octs  (as-octs:mimes:html body)
  %+  turn  ~(tap in ids)
  |=  eyre-id=@ta
  ^-  card:agent:gall
  [%give %fact ~[/http-response/[eyre-id]] [%http-response-data !>(`octs)]]
::
::  +close-sse-conn: kick an open SSE connection closed
::
++  close-sse-conn
  |=  eyre-id=@ta
  ^-  card:agent:gall
  [%give %kick ~[/http-response/[eyre-id]] ~]
::
::  +give-empty: produce an empty 200 response (for POST handlers)
::
::  datastar POSTs often don't need a body — the UI update comes
::  via an SSE push on a separate connection.
::
++  give-empty
  |=  eyre-id=@ta
  ^-  (list card:agent:gall)
  =/  =response-header:http  [200 ~]
  :~  [%give %fact ~[/http-response/[eyre-id]] [%http-response-header !>(response-header)]]
      [%give %fact ~[/http-response/[eyre-id]] [%http-response-data !>(~)]]
      [%give %kick ~[/http-response/[eyre-id]] ~]
  ==
::
::  URL + datastar action attribute helpers
::
::  these produce strings for use in data-on_click, data-init, etc.
::  datastar interprets @get(...) and @post(...) as SSE fetch actions.
::
++  href
  |_  [root=path extra=(list [tape tape])]
  ++  as-tape
    |=  [stem=path =pams]
    ^-  tape
    ;:  welp
      (spud (welp root stem))
      (render-query pams)
    ==
  ++  as-cord
    |=  arg=[path pams]
    ^-  cord
    (crip (as-tape arg))
  ++  as-soq-tape
    |=  arg=[path pams]
    "'{(as-tape arg)}'"
  ::  +data-post: datastar @post action string
  ::
  ++  data-post
    |=  [where=path =pams]
    "@post({(as-soq-tape where pams)}, \{openWhenHidden: true})"
  ::  +data-get: datastar @get action string
  ::
  ++  data-get
    |=  [where=path pams=(list [tape tape])]
    "@get({(as-soq-tape where pams)}, \{openWhenHidden: true})"
  ::  +data-post-confirm: @post with a browser confirm() prompt
  ::
  ++  data-post-confirm
    |=  [where=path pams=(list [tape tape]) prompt=tape]
    "if (confirm(`{prompt}`)) \{ @post({(as-soq-tape where pams)}, \{openWhenHidden: true}) }"
  ::  +data-get-confirm: @get with a browser confirm() prompt
  ::
  ++  data-get-confirm
    |=  [where=path pams=(list [tape tape]) prompt=tape]
    "if (confirm('{prompt}')) \{ @get({(as-soq-tape where pams)}, \{openWhenHidden: true}) }"
  ::
  +$  pams  (list [tape tape])
  ++  render-query
    |=  =pams
    %-  tail:en-purl:html
    ^-  quay:eyre
    %+  turn  (welp pams extra)
    |=  [k=tape v=tape]
    [(crip k) (crip v)]
  --
::
::  +parse-url: parse a URL into a path and query params
::
++  parse-url
  |=  url=cord
  ^-  (pair path (map @t @t))
  %-  fall  :_  [/unknown ~]
  %-  mole  |.
  =/  [maybe-trailing=path pams=(list (pair @t @t))]
    %+  rash  url
      ;~  plug
          ;~(pfix fas (more fas smeg:de-purl:html))
          yque:de-purl:html
      ==
  :_  (malt pams)
  ?~  maybe-trailing  /
  =/  last=knot  (rear maybe-trailing)
  ?:  ?=(%$ last)
    (snip `path`maybe-trailing)
  ^-  path
  maybe-trailing
::
::  +form-body: parse a form-encoded request body to a map
::
++  form-body
  |=  body=(unit octs)
  ^-  (map @t @t)
  %-  fall  :_  ~
  %-  mole  |.
  (malt (rash +:(need body) yquy:de-purl:html))
--
