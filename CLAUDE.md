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
app/push.hoon          -- Demo agent: serves UI, handles /send endpoint
  └─ lib/web-pusher    -- Agent wrapper: VAPID keys, subscriptions, delivery tracking
       └─ lib/web-push -- Core protocol: encryption, VAPID headers, key generation
            ├─ lib/jwt      -- ES256 JWT signing/verification (P-256/secp256r1)
            ├─ lib/hkdf     -- HKDF-SHA-256 extract+expand (RFC 5869)
            └─ lib/aes-gcm  -- AES-128-GCM encrypt/decrypt (NIST SP 800-38D)
```

- **sur/push.hoon** — Shared types: `subscription`, `push-config`, `push-message`, `delivery`, `pusher-state`
- **lib/web-pusher.hoon** — Agent wrapper pattern: wraps any gall agent via `%-  agent:web-pusher`. Intercepts HTTP on `{base}/~web-pusher/*`, pokes with marks `%push-send`/`%push-send-to`, peeks on `/web-pusher/**`, and iris responses on `/web-pusher/**` wires. Everything else passes through to the inner agent.
- **lib/web-push.hoon** — Stateless library. `+send-notification` is the main entry point; `+encrypt-payload` handles the RFC 8291 encryption pipeline.
- **lib/jwt.hoon** — Defines the P-256 curve constants (`secp256r1`) and all JWT operations. Exposes curve utilities (`priv-to-pub`, `serialize-point`, `mul-point-scalar`, etc.) via `=,  secp256r1` in web-push.

### How the inner agent sends notifications

The inner agent pokes itself with `%push-send` (broadcast) or `%push-send-to` (targeted):
```hoon
[%pass /notify %agent [our dap]:bowl %poke %push-send !>(msg)]
```
The wrapper intercepts this, encrypts, and delivers via iris.

### Desk metadata
- Kelvin: `[%zuse 413]`
- Ship: `~zod`
- Single agent: `%notifchat`
