# Urbit Web Push

An agent wrapper which manages browser push notifications for gall agents.

Modern browsers can display native notifications even when the page isn't open, via the [Push API](https://developer.mozilla.org/en-US/docs/Web/API/Push_API). The protocol requires the server to encrypt each message with ECDH on P-256, derive keys with HKDF-SHA-256, encrypt with AES-128-GCM, and sign requests with VAPID JWTs. This end-to-end encryption means only your ship and the user's device can read the notification content — push services like Google's and Apple's only ever see ciphertext. This library implements the full protocol in pure Hoon.

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
%-  %+  agent:web-pusher
      ::
      /apps/my-app    :: eyre binding (handles passing [%pass ... %e %connect ...] in on-init)
    'mailto:you@example.com'  :: VAPID contact
  ::
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
- Serves `{base}/~web-pusher/debug` showing config and subs (owner only)
- Passes all other HTTP through to the inner agent
- Encrypts and delivers notifications
- Auto-removes dead subscriptions on 410/404 responses

### Frontend setup

Push notifications require a PWA (Progressive Web App) context — especially on iOS. You need a manifest, a service worker, and JavaScript to subscribe the browser.

**1. PWA manifest**

Serve a `manifest.json` from your agent and link it in your HTML:

```html
<link rel="manifest" href="/apps/my-app/manifest.json">
```

At minimum it needs:

```json
{
  "id": "/apps/my-app",
  "name": "My App",
  "short_name": "My App",
  "start_url": "/apps/my-app",
  "scope": "/apps/my-app",
  "display": "standalone",
  "icons": [{ "src": "/apps/my-app/icon.svg", "sizes": "any", "type": "image/svg+xml" }]
}
```

**2. Service worker**

The wrapper serves a default service worker at `{base}/~web-pusher/sw.js` that handles push events and notification clicks. Register it from your JavaScript:

```javascript
const reg = await navigator.serviceWorker.register('/apps/my-app/~web-pusher/sw.js');
await navigator.serviceWorker.ready;
```

**3. Subscribe to push**

Fetch the VAPID public key from the wrapper, subscribe via the browser's Push API, and send the subscription to your agent:

```javascript
// fetch VAPID key
const vapidB64 = await fetch('/apps/my-app/~web-pusher/vapid-key').then(r => r.text());
const vapidKey = Uint8Array.from(atob(vapidB64.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));

// subscribe
const sub = await reg.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: vapidKey
});

// send to your agent's endpoint
const id = `b-${Date.now()}`;
await fetch('/apps/my-app?action=push-subscribe', {
  method: 'POST',
  body: JSON.stringify({
    id,
    endpoint: sub.endpoint,
    p256dh: btoa(String.fromCharCode(...new Uint8Array(sub.getKey('p256dh'))))
              .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''),
    auth:   btoa(String.fromCharCode(...new Uint8Array(sub.getKey('auth'))))
              .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')
  })
});
```

Your agent's HTTP handler parses this JSON, decodes the base64url keys to MSB-first atoms (`de-base64url:web-push` then `rev 3`), and self-pokes `%push-subscribe` to store the subscription in the wrapper.

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

## Debug tracing

The wrapper supports a debug tracing mode that prints send and delivery information to the dojo. Toggle it by poking `%push-debug`:

```hoon
[%pass /push/dbug %agent [our dap]:bowl %poke %push-debug !>(&)]
```

When enabled, the dojo will show:
- `[%web-pusher %sending N %notifications]` — number of subscriptions being sent to
- `[%web-pusher %push-to ~ship id]` — each individual send
- `[%web-pusher %delivered ~ship id]` — successful delivery (HTTP 201)
- `[%web-pusher %send-failed ~ship id status]` — failed delivery
- `[%web-pusher %removing-dead-sub ~ship id status]` — subscription removed (HTTP 410/404)

Tracing is off by default and resets on agent reload.

## Wrapper scries

The wrapper exposes peeks under `/web-pusher`:

- `/u/web-pusher` -- loob, always `%.y`
- `/x/web-pusher/state` -- full `pusher-state` noun

## License

MIT
