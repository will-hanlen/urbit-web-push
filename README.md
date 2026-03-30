# Urbit Web Push

Browser push notifications for Urbit, implemented entirely in Hoon. Ships with a demo chat app and a drop-in agent wrapper so any Gall agent can send push notifications using the W3C Web Push protocol (RFC 8291/8292).

## Architecture

```
app/notifchat.hoon       -- Demo agent: chat UI with push notifications
  └─ lib/web-pusher      -- Agent wrapper: VAPID keys, subscription store, delivery engine
       └─ lib/web-push   -- Core protocol: encryption, VAPID headers, key generation
            ├─ lib/jwt       -- ES256 JWT signing/verification (P-256/secp256r1)
            ├─ lib/hkdf      -- HKDF-SHA-256 extract+expand
            └─ lib/aes-gcm   -- AES-128-GCM encrypt/decrypt
```

### Adding push to your own agent

Wrap your agent with `web-pusher` to get push support:

```hoon
/+  web-pusher
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
- Encrypts and delivers notifications
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
