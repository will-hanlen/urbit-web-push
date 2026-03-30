# Urbit Web Push

Browser push notifications for Urbit, implemented entirely in Hoon. Ships with a demo chat app and a drop-in agent wrapper so any Gall agent can send push notifications using the W3C Web Push protocol (RFC 8291/8292).

## What it does

- **VAPID authentication** (RFC 8292) -- ES256 JWT signing with P-256 keys
- **ECDH key agreement** -- P-256 Diffie-Hellman with browser subscription keys
- **HKDF key derivation** (RFC 5869) -- SHA-256 extract and expand
- **AES-128-GCM encryption** (RFC 8291) -- content encryption for push payloads
- **Agent wrapper** -- drop-in library that adds push support to any Gall agent
- **Tag-based filtering** -- target notifications by subscriber tags
- **Delivery tracking** -- track pending/sent/failed/expired/gone status per notification
- **Demo app** -- Notifchat, a minimal groupchat with push notifications

## Architecture

```
app/notifchat.hoon       -- Demo agent: chat UI with push notifications
  └─ lib/web-pusher      -- Agent wrapper: VAPID keys, subscription store, delivery engine
       └─ lib/web-push   -- Core protocol: encryption, VAPID headers, key generation
            ├─ lib/jwt       -- ES256 JWT signing/verification (P-256/secp256r1)
            ├─ lib/hkdf      -- HKDF-SHA-256 extract+expand
            └─ lib/aes-gcm   -- AES-128-GCM encrypt/decrypt
```

## Installation

### From a distributor

```
|install ~zod %web-push
```

### Chrome / Brave

Chrome and Brave on desktop don't support web push from self-signed HTTPS or bare HTTP. You have two options:

1. **Serve your ship behind a reverse proxy with a valid TLS certificate** (e.g. via Caddy or nginx with Let's Encrypt).
2. **Allow your ship's origin as an insecure origin** by navigating to `chrome://flags/#unsafely-treat-insecure-origin-as-secure`, adding your ship's URL, and restarting the browser.

### iOS

Push notifications on iOS require your app to be installed as a PWA (added to the home screen). The demo app includes a PWA install gate that guides users through this.

## Usage

### Using the demo app

1. Navigate to `/apps/notifchat` on your ship
2. Subscribe to push notifications when prompted
3. Send messages -- all subscribers receive push notifications

### Adding push to your own agent

Wrap your agent with `web-pusher` to get push support with zero crypto code:

```hoon
/+  web-pusher, default-agent
/-  push

%-  %:  agent:web-pusher
      /apps/my-app              ::  eyre binding path
      'mailto:you@example.com'  ::  VAPID contact
      200                       ::  max delivery records (0 = no tracking)
    ==
^-  agent:gall
|_  =bowl:gall
...
--
```

The wrapper automatically:
- Generates and persists VAPID keys on first load
- Serves `{base}/~web-pusher/vapid-key` for browsers (public)
- Serves `{base}/~web-pusher/sw.js` default service worker (public)
- Serves `{base}/~web-pusher/debug` showing config, subs, deliveries (owner only)
- Passes all other HTTP through to the inner agent
- Encrypts and delivers notifications via iris
- Auto-removes dead subscriptions on 410/404 responses

#### Managing subscriptions

Your inner agent handles browser-facing HTTP (parsing subscription JSON, authenticating users, etc.) and then self-pokes to manage wrapper state:

```hoon
::  register a browser subscription
[%pass /push/sub %agent [our dap]:bowl %poke %push-subscribe !>(ps)]

::  remove a subscription
[%pass /push/unsub %agent [our dap]:bowl %poke %push-unsubscribe !>(pu)]

::  update tags on a subscription
[%pass /push/tags %agent [our dap]:bowl %poke %push-set-tags !>(pt)]
```

Where types are defined in `sur/push.hoon`:

```hoon
+$  push-subscribe    [who=@p id=@ta sub=subscription tags=(set term)]
+$  push-unsubscribe  [who=@p id=@ta]
+$  push-set-tags     [who=@p id=@ta tags=(set term)]
```

#### Sending notifications

Self-poke with `%push-send` to deliver:

```hoon
[%pass /push/send %agent [our dap]:bowl %poke %push-send !>(ps)]
```

Where `ps` is a `push-send`:

```hoon
+$  push-send
  $:  targets=(set @p)    ::  specific ships (empty = all subscribed)
      tags=(set term)     ::  filter by sub tags (empty = no filtering)
      exclude=(set @p)    ::  remove these ships from recipients
      msg=push-message
  ==

+$  push-message
  $:  title=@t
      body=@t
      icon=(unit @t)
      url=(unit @t)
      tag=(unit @t)
  ==
```

Example -- broadcast to everyone:

```hoon
=/  ps=push-send:push
  [~ ~ ~ 'Hello' 'From Urbit' ~ ~ ~]
[%pass /push/send %agent [our dap]:bowl %poke %push-send !>(ps)]
```

#### Scrying wrapper state

The wrapper exposes peeks under `/web-pusher`:

- `/u/web-pusher` -- loob, always `%.y`
- `/x/web-pusher/state` -- full `pusher-state` noun
- `/x/web-pusher/sends/@p` -- deliveries for a ship
- `/x/web-pusher/sends/@p/@ta` -- deliveries for a specific subscription

### Using the low-level library directly

If you need full control, use `lib/web-push` directly:

```hoon
/+  web-push
/-  push

::  generate VAPID keypair (do once, persist in state)
=/  config=push-config:push
  (generate-vapid-keypair:web-push eny.bowl 'mailto:you@example.com')

::  send a notification (returns a request:http for iris)
=/  req=request:http
  %:  send-notification:web-push
    config
    subscription    ::  from browser (subscription:push)
    '{"title":"hi","body":"hello"}'  ::  JSON payload
    eny.bowl
  ==
```

## Development

Requires a running fake `~zod`. The desk source lives in the repo root and is synced into the pier at `zod/web-push/`.

```
::  run all tests
-test /=web-push=/tests

::  run a specific test
-test /=web-push=/tests/lib/jwt/hoon

::  check a file compiles
-build-file %/lib/web-push/hoon
```

## License

MIT
