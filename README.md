# Urbit Web Push

An agent wrapper which manages browser push notifications for gall agents.

Ships with a demo chat app. (try it here: https://hawk.computer/apps/notifchat)

## Adding the wrapper to your own agent

Copy the following files into your desk:

```
lib/web-pusher.hoon   -- agent wrapper
lib/web-push.hoon     -- core protocol + types
lib/jwt.hoon          -- ES256 JWT signing (P-256/secp256r1)
lib/hkdf.hoon         -- HKDF-SHA-256 (RFC 5869)
lib/aes-gcm.hoon      -- AES-128-GCM encryption
```

Then wrap your agent with the `web-pusher` core:

```hoon
/+  web-pusher
%-  %:  agent:web-pusher
      ::
      ::  eyre binding path
      ::  NOTE: the agent wrapper handles the bind, so you no longer have to
      ::        send [%pass /bind %arvo %e %connect ...]
      ::        in your on-init
      ::
      /apps/my-app
      ::
      ::  VAPID contact.
      ::
      'mailto:you@example.com'
      ::
      ::  max delivery records (0 = no tracking)
      ::
      200
    ==
^-  agent:gall
|_  =bowl:gall
...
--
```

The wrapper automatically:
- Binds your `{base}` eyre endpoint
- Generates and persists VAPID keys on first load
- Serves `{base}/~web-pusher/vapid-key` for browsers (public)
- Serves `{base}/~web-pusher/sw.js` default service worker (public)
- Serves `{base}/~web-pusher/debug` showing config, subs, deliveries (owner only)
- Passes all other HTTP through to the inner agent
- Encrypts and delivers notifications
- Auto-removes dead subscriptions on 410/404 responses

## Usage

Your inner agent handles browser-facing HTTP (parsing subscription JSON, authenticating users, etc.) and then self-pokes to manage wrapper state:

```hoon
::  register a browser subscription
+$  push-subscribe    [who=@p id=@ta sub=subscription tags=(set term)]
[%pass /push/sub %agent [our dap]:bowl %poke %push-subscribe !>(some-push-subscribe)]

::  remove a subscription
+$  push-unsubscribe  [who=@p id=@ta]
[%pass /push/unsub %agent [our dap]:bowl %poke %push-unsubscribe !>(some-push-unsubscribe)]

::  update tags on a subscription
+$  push-set-tags     [who=@p id=@ta tags=(set term)]
[%pass /push/tags %agent [our dap]:bowl %poke %push-set-tags !>(some-push-set-tags)]

+$  push-send
  $:  targets=(set @p)    ::  specific ships (empty = all subscribed)
      tags=(set term)     ::  filter by sub tags (empty = no filtering)
      exclude=(set @p)    ::  remove these ships from recipients
      msg=push-message
  ==
[%pass /push/send %agent [our dap]:bowl %poke %push-send !>(some-push-send)]
```

## Wrapper scries

The wrapper exposes peeks under `/web-pusher`:

- `/u/web-pusher` -- loob, always `%.y`
- `/x/web-pusher/state` -- full `pusher-state` noun
- `/x/web-pusher/sends/@p` -- deliveries for a ship
- `/x/web-pusher/sends/@p/@ta` -- deliveries for a specific subscription

## License

MIT
