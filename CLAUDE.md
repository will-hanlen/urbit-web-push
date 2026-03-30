# CLAUDE.md

## Project Overview

An Urbit desk (`%web-push`) implementing W3C Web Push (RFC 8291/8292) entirely in Hoon. See `README.md` for architecture and usage.

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

## Byte order convention (critical)
- **byts** (MSB-first): used by all crypto operations (HMAC, HKDF, secp, AES-GCM)
- **octs** (LSB-first): used by HTTP bodies, base64, cords
- Use `rev 3` to convert between them. Getting this wrong silently produces invalid crypto output.

## Layer structure

```
app/notifchat.hoon     -- Demo agent: chat UI, push subscription endpoints
  └─ lib/web-pusher    -- Agent wrapper: VAPID keys, subscription store, notification sender
       └─ lib/web-push -- Core protocol: types, encryption, VAPID headers
            ├─ lib/jwt      -- ES256 JWT signing/verification (P-256/secp256r1)
            ├─ lib/hkdf     -- HKDF-SHA-256 extract+expand (RFC 5869)
            └─ lib/aes-gcm  -- AES-128-GCM encrypt/decrypt (NIST SP 800-38D)
```

All shared types (`subscription`, `push-config`, `push-message`, `push-send`, `pusher-state`, etc.) are defined in `lib/web-push.hoon`.

## Desk metadata
- Kelvin: `[%zuse 409]`
- Ship: `~zod`
- Single agent: `%notifchat`
