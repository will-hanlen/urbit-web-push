Guidance for building Datastar-powered reactive UIs in Hoon agents.

Datastar is a JS library that uses Server-Sent Events (SSE) to push DOM updates from the server to the browser. The server sends HTML fragments and signal patches via SSE; datastar swaps them into the page without full reloads.

## Key Concepts

- **Signals**: Client-side reactive state. Set via `data-signals`, read/written via `$signalName` in expressions.
- **Actions**: `@get(url)` and `@post(url)` trigger SSE fetches. Used in `data-on_click`, `data-init`, etc.
- **Fragments**: HTML chunks the server sends via SSE to update the DOM. Each has a mode (outer/inner/append/etc.) and optional CSS selector.
- **Indicators**: `data-indicator="_loading"` sets a signal to true during a fetch, enabling loading states.
- **Two-way binding**: `data-bind_name` binds an input's value to a signal.

## Architecture Pattern (SSE + POST)

1. Browser opens an SSE connection via `data-init="@get('?action=sse')"` on the body.
2. User actions trigger `@post(...)` which modifies server state and returns an empty 200.
3. Server state changes cause the agent to push updated HTML fragments to all SSE connections.
4. Datastar swaps the fragments into the DOM.

This means POSTs don't return HTML — they just change state. The SSE connection delivers all UI updates.

## lib/datastar.hoon

This desk includes `lib/datastar.hoon` with these utilities:

### Types
- `datastar-fragment` — `[mode=tape selector=(unit tape) =manx]`

### Request Helpers
- `(is-datastar header-list)` — check if request has `datastar-request: true` header
- `(datastar-signals pams body)` — parse signals from query params or POST body into `(map @t @t)`
- `(form-body body)` — parse form-encoded body to `(map @t @t)`
- `(parse-url url)` — parse URL into `[path (map @t @t)]`

### Response Helpers
- `(give-sse eyre-id sig-list fragments)` — full SSE response cards (header + data + kick)
- `(give-empty eyre-id)` — empty 200 response cards (for POST handlers)
- `(datastar-response-body sig-list fragments)` — raw SSE event text as cord

### JSON Helpers
- `(json-to-map json)` — flatten single-layer JSON object to `(map @t @t)`
- `(map-to-json map)` — convert flat map to JSON object

### URL / Action Helpers (++href door)
```hoon
=/  h  ~(. href:datastar /apps/my-app ~)
(data-post:h /send ~)       ::  "@post('/apps/my-app/send', {openWhenHidden: true})"
(data-get:h /sse ~)         ::  "@get('/apps/my-app/sse', {openWhenHidden: true})"
```

## SSE Response Format

Datastar SSE uses two event types:

```
event: datastar-patch-signals
data: signals {"key":"value"}

event: datastar-patch-elements
data: mode outer
data: selector #my-element
data: elements <div id="my-element">new content</div>
```

## HTML Attribute Reference

Common datastar attributes used in Hoon sail:

```hoon
::  open SSE connection on page load
;body(data-init "@get('?action=sse')")

::  button that POSTs on click
;button(data-on_click "@post('?action=increment')")

::  loading indicator
;button.loader
  =data-on_click  "@post('?action=fetch')"
  =data-indicator  "_loading"
  ;span(data-text "$_loading ? '...' : 'go'");
==

::  two-way input binding
;input(data-bind_url "", placeholder "enter url");

::  conditional show/hide
;div(data-show "$_debug")

::  reactive text
;span(data-text "$count");

::  reactive class
;div(data-class_active "$isActive")
```

## Persistent SSE Connections (Request Map Pattern)

Datastar's reactive model requires long-lived SSE connections. The browser opens a connection via `@get`, the server holds it open and pushes updates as state changes. This is the core pattern for any Datastar agent.

### 1. Add a request map to your agent state

Store active SSE connection IDs so you can push updates later:

```hoon
+$  state-0
  $:  ::  ... your app state ...
      requests=(set @ta)  ::  active SSE eyre-ids
  ==
```

### 2. Open connections on SSE GET requests

When the browser's `data-init="@get('/my-app/sse')"` hits your agent, open the connection and store the eyre-id:

```hoon
::  in on-poke, handle-http-request handler:
?:  &(=('GET' meth) =(site /apps/my-app/sse))
  =.  requests.state  (~(put in requests.state) eyre-id)
  :_  this
  ::  open connection + send initial UI state
  %^  open-sse-conn:datastar  eyre-id  ~
  :~  ["outer" `"#my-el" (render-my-el state)]
  ==
```

`open-sse-conn` sends the 200 + SSE headers but does NOT kick the connection closed. The browser stays connected.

### 3. Push updates to all connections

When state changes (e.g., from a POST), push updated fragments to every open connection:

```hoon
::  after modifying state in a POST handler:
=/  frag=datastar-fragment  ["outer" `"#count" ;p#count: {(a-co:co count.state)}]
:_  this
%+  welp  (give-empty:datastar eyre-id)  ::  respond to the POST
(push-sse-all:datastar requests.state ~ ~[frag])  ::  push to all SSE
```

Or push to a single connection:

```hoon
(push-sse:datastar eyre-id ~ ~[frag])
```

### 4. Clean up on disconnect (on-leave and connection pruning)

**How eyre manages HTTP connections:**

When eyre binds your agent to a URL path, each incoming HTTP request creates a subscription on `/http-response/[eyre-id]`. Your agent holds this subscription open for SSE. When the connection ends — browser tab closed, network drop, SSE reconnect, or explicit `EventSource.close()` — eyre fires `on-leave` on that same path.

This is the ONLY reliable signal that a connection is gone. You MUST use `on-leave` to prune stale eyre-ids from your request set. If you don't:
- `push-sse-all` will produce cards for dead subscriptions
- Eyre will drop those cards silently, but they waste computation
- Your request set grows unboundedly over time

**Implementation:**

```hoon
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?+  path  (on-watch:def path)
    [%http-response *]  `this
  ==
::
++  on-leave
  |=  =path
  ^-  (quip card _this)
  ?+  path  `this
    [%http-response *]
    =/  eyre-id=@ta  i.t.path
    `this(requests.state (~(del in requests.state) eyre-id))
  ==
```

**Key details:**
- `on-watch` MUST accept `/http-response/*` paths or eyre can't deliver responses at all. Always pass through to `default-agent` or return `\`this` for these paths.
- `on-leave` fires per eyre-id. The path is `/http-response/[eyre-id]` — extract the eyre-id from `i.t.path`.
- Datastar auto-reconnects dropped SSE connections. When it reconnects, you'll see a new `handle-http-request` (new eyre-id) followed by an `on-leave` for the old one. This is normal — the old id gets pruned, the new one gets added.
- If your agent crashes during `on-leave`, the stale id stays in state. This is harmless (pushes to it are no-ops) but wastes cycles. Keep `on-leave` simple.

### 5. Full request lifecycle summary

```
Browser                          Hoon Agent
   |                                 |
   |-- @get('/app/sse') ------------>|  open-sse-conn, store eyre-id
   |<---- 200 + headers + initial ---|
   |         (connection held open)  |
   |                                 |
   |-- @post('/app/action') -------->|  modify state, give-empty
   |<---- 200 empty ----------------|
   |                                 |
   |<---- push-sse-all (fragment) ---|  push update to all connections
   |   (DOM updated by datastar)     |
   |                                 |
   |-- (tab closed) ---------------->|  on-leave: remove eyre-id
```

### Available persistent SSE arms in lib/datastar.hoon

- `(open-sse-conn eyre-id sig-list fragments)` — send headers, optionally initial data, keep open
- `(push-sse eyre-id sig-list fragments)` — push to one connection
- `(push-sse-all ids sig-list fragments)` — push to all connections in a `(set @ta)`
- `(close-sse-conn eyre-id)` — kick one connection closed

## Example: One-shot SSE Response

For simple cases where you don't need persistent connections (e.g., responding to a single @get with data and closing):

```hoon
=/  new-el=manx  ;p#count: {(a-co:co count)}
%^  give-sse:datastar  eyre-id  ~
:~  ["outer" `"#count" new-el]
==
```

## Example: Handling a Datastar POST

```hoon
::  parse signals from the request
=/  sigs  (datastar-signals:datastar pams body)
=/  url  (~(gut by sigs) 'url' '')
::  do something with the signal value...
::  return empty response (UI updates come via SSE)
(give-empty:datastar eyre-id)
```

## Including the Datastar JS Library

Serve `datastar-new.js` (Datastar Pro v1.0.0-RC.7) as a static asset and include it:
```hoon
;script(type "module", src "/apps/my-app/datastar.js");
```
The `type "module"` attribute is required.
