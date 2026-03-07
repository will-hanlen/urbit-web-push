# Urbit Web Push

Web push notifications for Urbit, implemented entirely in Hoon. Delivers browser push notifications from any Gall agent using the W3C Web Push protocol (RFC 8291/8292).

## What it does

- **VAPID authentication** (RFC 8292) -- ES256 JWT signing with P-256 keys
- **ECDH key agreement** -- P-256 Diffie-Hellman with browser subscription keys
- **HKDF key derivation** (RFC 5869) -- SHA-256 extract and expand
- **AES-128-GCM encryption** (RFC 8291) -- content encryption for push payloads
- **Agent wrapper** -- drop-in library that adds push notification support to any Gall agent
- **Demo UI** -- browser interface for subscribing and sending test notifications

## Architecture

```
app/push.hoon          -- Demo agent: serves UI, handles /send endpoint
  └─ lib/web-pusher    -- Agent wrapper: VAPID keys, subscriptions, delivery tracking
       └─ lib/web-push -- Core protocol: encryption, VAPID headers, key generation
            ├─ lib/jwt      -- ES256 JWT signing/verification (P-256/secp256r1)
            ├─ lib/hkdf     -- HKDF-SHA-256 extract+expand
            └─ lib/aes-gcm  -- AES-128-GCM encrypt/decrypt
```

## Installation

Install on your ship from the distributor, or copy the desk manually:

```
|install ~zod %web-push
```

Once installed, the app is available at `http://your-ship/apps/notifchat`.

## Usage

### Using the demo agent

1. Navigate to `/apps/push` on your ship
2. Click **Subscribe this browser** to register for notifications
3. Fill in a title and body, then click **Send to all subscribers**

### Adding push to your own agent

Wrap your agent with `web-pusher` to get push support with zero crypto code:

```hoon
/+  web-pusher, default-agent

%-  %:  agent:web-pusher
      /apps/my-app        ::  eyre binding path
      'mailto:you@example.com'  ::  VAPID contact
    ==
^-  agent:gall
|_  =bowl:gall
...
--
```

The wrapper automatically:
- Generates and persists VAPID keys on first load
- Serves a `/~web-pusher/vapid-key` endpoint for browsers
- Accepts subscription registrations at `/~web-pusher/subscribe`
- Handles unsubscribe at `/~web-pusher/unsubscribe`
- Encrypts and delivers notifications via iris

To send a notification from your inner agent, poke yourself:

```hoon
::  broadcast to all subscribers
[%pass /notify %agent [our dap]:bowl %poke %push-send !>(msg)]

::  send to a specific subscriber
[%pass /notify %agent [our dap]:bowl %poke %push-send-to !>([sub-id msg])]
```

Where `msg` is a `push-message`:

```hoon
:*  'Hello from Urbit'   ::  title
    'Notification body'  ::  body
    ~                    ::  icon (unit @t)
    ~                    ::  url (unit @t)
    ~                    ::  tag (unit @t)
==
```

### Using the low-level library directly

If you need more control, use `lib/web-push` directly:

```hoon
/+  web-push
/-  push

::  generate VAPID keypair (do once, persist in state)
=/  config=push-config:push
  (generate-vapid-keypair:web-push eny.bowl 'mailto:you@example.com')

::  send a notification (returns an iris request card)
=/  =card
  %:  send-notification:web-push
    config
    subscription    ::  from browser
    payload=`'{"title":"hi"}'
    ttl=86.400
    now.bowl
    eny.bowl
  ==
```

## Development

Requires a running fake `~zod`. The desk source lives in the repo root and is synced into the pier at `zod/web-push/`.

```bash
# Run tests
-test /=web-push=/tests

# Run a specific test
-test /=web-push=/tests/lib/jwt/hoon

# Check a file compiles
-build-file %/lib/web-push/hoon
```

## License

MIT
