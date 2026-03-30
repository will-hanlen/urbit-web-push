# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

An Urbit desk (`%web-push`) implementing W3C Web Push (RFC 8291/8292) entirely in Hoon. Provides VAPID authentication, ECDH key agreement, HKDF key derivation, AES-128-GCM encryption, and a demo agent with a browser UI for sending push notifications.

## Development Workflow

A fake ~zod should be running in tmux session `web-push:zod` with the `%web-push` desk mounted at `./zod/web-push/`.

**Compile and test changes:**
Use the `/commit` skill to rsync source into the pier and `|commit %web-push`.

**Run a dojo command:**
Use the `/dojo` skill (e.g., `/dojo -test /=web-push=/tests`).

**Run a single test file:**
```
/dojo -test /=web-push=/tests/lib/jwt/hoon
```

**Check a single file compiles:**
```
/dojo -build-file /=web-push=/lib/web-push/hoon
```

## Architecture

### Byte order convention (critical)
- **byts** (MSB-first): used by all crypto operations (HMAC, HKDF, secp, AES-GCM)
- **octs** (LSB-first): used by HTTP bodies, base64, cords
- Use `rev 3` to convert between them. Getting this wrong silently produces invalid crypto output.

### Layer structure

```
app/notifchat.hoon     -- Demo agent: chat UI, push subscription endpoints, business logic
  └─ lib/web-pusher    -- Agent wrapper: VAPID keys, subscription store, delivery engine
       └─ lib/web-push -- Core protocol: encryption, VAPID headers, key generation
            ├─ lib/jwt      -- ES256 JWT signing/verification (P-256/secp256r1)
            ├─ lib/hkdf     -- HKDF-SHA-256 extract+expand (RFC 5869)
            └─ lib/aes-gcm  -- AES-128-GCM encrypt/decrypt (NIST SP 800-38D)
```

### lib/web-pusher.hoon — Agent wrapper (store + delivery engine)

Wraps any gall agent via `%-  agent:web-pusher`. The wrapper is deliberately simple — it stores data and delivers notifications, but has no business logic about who may subscribe or what preferences are valid.

**HTTP endpoints** (under `{base}/~web-pusher/`):
- `GET /sw.js` — default service worker (public)
- `GET /vapid-key` — VAPID public key (public)
- `GET /debug` — debug page showing config, subs, deliveries (owner only)

All other HTTP passes through to the inner agent.

**Intercepted self-pokes** (from inner agent only):
- `%push-subscribe` — store a `tagged-sub`
- `%push-unsubscribe` — remove a subscription by `[who id]`
- `%push-set-tags` — update tags on an existing subscription
- `%push-send` — encrypt and deliver notifications via iris

**Tag-based filtering**: When `%push-send` includes tags, only subscriptions with matching tags (or empty tags = receive all) get the notification.

**Delivery tracking**: Iris responses update delivery status (pending→sent/failed/expired/gone). 410/404 responses auto-remove dead subscriptions.

**Peeks** on `/web-pusher/**`:
- `/u/web-pusher` — loob, always `%.y`
- `/x/web-pusher/state` — full `pusher-state` noun
- `/x/web-pusher/sends/@p` — deliveries for a ship
- `/x/web-pusher/sends/@p/@ta` — deliveries for a specific subscription

### Inner agent responsibilities

The inner agent owns all user-facing HTTP and business logic. It:
1. Handles browser subscription endpoints (parse JSON, validate auth, base64url decode keys)
2. Self-pokes `%push-subscribe`/`%push-unsubscribe`/`%push-set-tags` to manage wrapper state
3. Self-pokes `%push-send` to trigger notification delivery
4. Scries `/x/web-pusher/state` to check existing subscriptions/tags

Example (notifchat): the `action=push-subscribe` endpoint parses the browser's PushSubscription JSON, converts base64url→MSB-first atoms via `de-base64url:web-push` + `rev 3`, and pokes:
```hoon
[%pass /push/sub %agent [our dap]:bowl %poke %push-subscribe !>(ps)]
```

### lib/web-push.hoon — Types and stateless crypto library

Defines all shared types (`subscription`, `tagged-sub`, `push-config`, `push-message`, `push-send`, `push-subscribe`, `push-unsubscribe`, `push-set-tags`, `pusher-state`, etc.). `+send-notification` is the main entry point; `+encrypt-payload` handles the RFC 8291 encryption pipeline. Also provides `de-base64url` for key decoding.

### lib/jwt.hoon — P-256 / ES256

Defines secp256r1 curve constants and all JWT operations. Exposes curve utilities (`priv-to-pub`, `serialize-point`, `mul-point-scalar`, etc.) via `=,  secp256r1` in web-push.

### Desk metadata
- Kelvin: `[%zuse 413]`
- Ship: `~zod`
- Single agent: `%notifchat`
