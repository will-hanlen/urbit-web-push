::  tests/lib/web-push: Web Push encryption and VAPID authentication
::
::  Web Push (RFC 8291) allows an application server to send encrypted
::  messages to a user agent (browser) via a push service (e.g., Firebase
::  Cloud Messaging, Mozilla autopush). The protocol has two main parts:
::
::  1. VAPID Authentication (RFC 8292):
::     Voluntary Application Server Identification. The server signs a
::     JWT with its private key and sends it in the Authorization header.
::     This lets the push service verify which application server is
::     sending the notification without requiring per-user credentials.
::     The JWT contains:
::       - aud: the push service origin (e.g., "https://fcm.googleapis.com")
::       - exp: token expiration timestamp
::       - sub: contact URI (e.g., "mailto:admin@example.com")
::
::  2. Payload Encryption (RFC 8291, aes128gcm):
::     Messages are end-to-end encrypted so the push service cannot read
::     them. The encryption uses:
::       a. ECDH key agreement between the server and subscriber
::       b. HKDF to derive a content-encryption key (CEK) and nonce
::       c. AES-128-GCM to encrypt the message payload
::
::     The subscriber provides three values during subscription:
::       - endpoint: the push service URL to POST to
::       - p256dh: the subscriber's ECDH public key (P-256, uncompressed)
::       - auth: a 16-byte authentication secret
::
::     The encrypted payload format (aes128gcm, RFC 8188) is:
::       salt(16) || rs(4) || idlen(1) || keyid(65) || ciphertext || tag(16)
::     Where:
::       - salt: random 16 bytes, input to HKDF
::       - rs: record size (4096), max bytes per encryption record
::       - idlen: length of the key ID field (65 for uncompressed P-256)
::       - keyid: the ephemeral public key (server generates per-message)
::       - ciphertext: AES-GCM encrypted payload with padding
::       - tag: AES-GCM authentication tag (16 bytes)
::
/-  push
/+  *test, web-push, hkdf, aes-gcm
::
|%
::  ------------------------------------------------------------------
::  Part 1: Origin Extraction
::  ------------------------------------------------------------------
::
::  The VAPID JWT "aud" claim must contain just the origin of the push
::  service endpoint -- scheme + host + port -- not the full URL path.
::  This is required by RFC 8292 Section 2.
::
::  +extract-origin parses a URL and returns scheme://host[:port],
::  omitting default ports (443 for HTTPS, 80 for HTTP).
::
::  --- Test: extract origin from a standard HTTPS URL ---
::
++  test-extract-origin-https
  %+  expect-eq
    !>('https://fcm.googleapis.com')
  !>((extract-origin:web-push 'https://fcm.googleapis.com/fcm/send/abc123'))
::  --- Test: extract origin preserving a non-default port ---
::
::  Port 8443 is non-standard for HTTPS, so it must be included
::  in the origin. Omitting it would cause the push service to
::  reject the VAPID JWT (audience mismatch).
::
++  test-extract-origin-with-port
  %+  expect-eq
    !>('https://push.example.com:8443')
  !>((extract-origin:web-push 'https://push.example.com:8443/push/v1/abc'))
::  ------------------------------------------------------------------
::  Part 2: VAPID Key Generation
::  ------------------------------------------------------------------
::
::  A VAPID key pair is a standard P-256 ECDSA key pair. The server
::  generates it once and reuses it across all subscriptions. The public
::  key is shared with subscribers (so they can verify the server's
::  identity), and the private key is used to sign VAPID JWTs.
::
::  +generate-vapid-keypair derives a deterministic key pair from entropy.
::  It hashes the entropy with a domain tag ('vpid') to produce a private
::  key, then computes the corresponding public key as an uncompressed
::  P-256 point (65 bytes: 0x04 || x || y).
::
::  --- Test: generated keypair is internally consistent ---
::
::  We verify:
::  1. The public key is 64-65 bytes (uncompressed P-256 point)
::  2. The stored public key matches what priv-to-pub derives
::  3. The contact URI (sub) is preserved
::
++  test-generate-vapid-keypair
  =/  eny  0xdead.beef.cafe.babe.1234.5678.abcd.ef01.
            dead.beef.cafe.babe.1234.5678.abcd.ef01
  =/  config  (generate-vapid-keypair:web-push eny 'mailto:test@example.com')
  =/  pub-len  (met 3 public-key.config)
  ::  re-derive the public key from the private key
  =/  derived-pub  (serialize-point:web-push (priv-to-pub:web-push private-key.config))
  ;:  weld
    ::  uncompressed P-256 point: 65 bytes (0x04 prefix + 32 + 32)
    ::  (met may return 64 if the leading 0x04 byte is at the MSB boundary)
    (expect !>(&((gte pub-len 64) (lte pub-len 65))))
    ::  stored public key must match derived public key
    %+  expect-eq  !>(public-key.config)  !>(derived-pub)
    ::  contact URI is stored as-is
    %+  expect-eq  !>('mailto:test@example.com')  !>(sub.config)
  ==
::  ------------------------------------------------------------------
::  Part 3: Message Serialization
::  ------------------------------------------------------------------
::
::  Push notifications carry a JSON payload that the service worker
::  on the client side parses. The push-message structure contains:
::    - title: notification title (required)
::    - body: notification body text (required)
::    - icon: URL to an icon image (optional)
::    - url: URL to open when the notification is clicked (optional)
::    - tag: grouping tag to collapse similar notifications (optional)
::
::  +message-to-json serializes a push-message into a JSON octs.
::
::  --- Test: message fields are correctly serialized to JSON ---
::
++  test-message-to-json
  =/  msg=push-message:push
    ['Test Title' 'Test Body' `'icon.png' `'https://example.com' `'tag1']
  =/  result  (message-to-json:web-push msg)
  ::  parse the JSON back to verify the fields
  =/  jon  (de:json:html q.result)
  ?~  jon  (expect-eq !>(%decode-failed) !>(%should-succeed))
  ?.  ?=(%o -.u.jon)
    (expect-eq !>(%not-object) !>(%should-be-object))
  =/  obj  p.u.jon
  ;:  weld
    %+  expect-eq  !>(`[%s 'Test Title'])  !>((~(get by obj) 'title'))
    %+  expect-eq  !>(`[%s 'Test Body'])   !>((~(get by obj) 'body'))
    %+  expect-eq  !>(`[%s 'icon.png'])    !>((~(get by obj) 'icon'))
    %+  expect-eq  !>(`[%s 'https://example.com'])  !>((~(get by obj) 'url'))
  ==
::  --- Test: special characters in messages produce valid JSON ---
::
::  Push message content may contain double quotes, backslashes, and
::  other characters that must be escaped in JSON. The JSON encoder
::  must handle these correctly; otherwise the client's JSON parser
::  will fail and the notification will be lost.
::
++  test-message-to-json-special-chars
  ::  build a title containing literal double-quote characters
  =/  title=@t  (rap 3 ~['He said ' '"' 'hello' '"'])
  =/  msg=push-message:push
    [title 'body with backslash \\' ~ ~ ~]
  =/  result  (message-to-json:web-push msg)
  ::  must produce valid JSON (parseable) despite special characters
  =/  jon  (de:json:html q.result)
  (expect !>(?=(^ jon)))
::  ------------------------------------------------------------------
::  Part 4: Payload Encryption
::  ------------------------------------------------------------------
::
::  The encryption pipeline (RFC 8291) is the most complex part:
::
::  Step 1 -- ECDH Key Agreement:
::    The server generates an ephemeral P-256 key pair per message.
::    It computes the shared secret: ECDH(eph_priv, subscriber_pub).
::    The x-coordinate of the resulting point is the raw shared secret.
::
::  Step 2 -- Key Derivation (two rounds of HKDF):
::    Round 1: Combine the ECDH secret with the subscriber's auth secret
::      PRK1 = HKDF-Extract(salt=auth, IKM=ecdh_secret)
::      IKM2 = HKDF-Expand(PRK1, info="WebPush: info"||subscriber_pub||eph_pub, 32)
::
::    Round 2: Derive the actual encryption key and nonce
::      PRK2 = HKDF-Extract(salt=message_salt, IKM=IKM2)
::      CEK  = HKDF-Expand(PRK2, info="Content-Encoding: aes128gcm\0", 16)
::      nonce = HKDF-Expand(PRK2, info="Content-Encoding: nonce\0", 12)
::
::  Step 3 -- Padding and Encryption:
::    The plaintext is padded with a 0x02 delimiter byte (and optional
::    zero bytes for length hiding), then encrypted with AES-128-GCM
::    using the derived CEK and nonce.
::
::  Step 4 -- Assemble the HTTP body (aes128gcm format):
::    salt(16) || record_size(4) || id_len(1) || eph_pub(65) || ct || tag(16)
::
::  --- Test: encrypted payload has correct structure and minimum size ---
::
::  The minimum payload size is:
::    16 (salt) + 4 (rs) + 1 (idlen) + 65 (eph_pub) = 86 bytes header
::    + plaintext_len + 1 (padding delimiter) + 16 (tag) = at least 103 bytes
::  For "hello" (5 bytes): 86 + 5 + 1 + 16 = 108 bytes minimum.
::
++  test-encrypt-payload-structure
  =/  priv  0xc9af.a9d8.45ba.75e6.b477.46a2.1ece.b8ec.
              769e.4539.7ea6.e407.1537.7892.a0e3.a8f5
  =/  pub-point  (priv-to-pub:web-push priv)
  =/  pub  (serialize-point:web-push pub-point)
  =/  auth  0x1234.5678.9abc.def0.1234.5678.9abc.def0
  =/  plaintext=octs  (as-octs:mimes:html 'hello')
  =/  eph-priv  0x2
  =/  salt  0xaaaa.bbbb.cccc.dddd.eeee.ffff.0000.1111
  =/  result
    (encrypt-payload:web-push pub auth plaintext eph-priv salt)
  ::  output must be at least 108 bytes (86 header + 5 PT + 1 pad + 16 tag)
  (expect !>((gte p.result 108)))
::  --- Test: encrypt-then-decrypt roundtrip recovers the plaintext ---
::
::  This is the most important test: it proves the entire encryption
::  pipeline is correct by manually re-deriving the CEK and nonce
::  (simulating what the subscriber's browser would do), then decrypting
::  the ciphertext and verifying the plaintext matches.
::
::  The decryption side:
::  1. Parse the header to extract salt, record size, and ephemeral pub
::  2. Perform the same ECDH + HKDF derivation using the subscriber's
::     private key and the ephemeral public key from the header
::  3. Decrypt with AES-128-GCM using the derived CEK and nonce
::  4. Strip the padding delimiter (0x02) to recover the original message
::
++  test-encrypt-payload-roundtrip
  ::  subscriber's key pair (in real usage, the browser generates these)
  =/  ua-priv  0xc9af.a9d8.45ba.75e6.b477.46a2.1ece.b8ec.
                769e.4539.7ea6.e407.1537.7892.a0e3.a8f5
  =/  ua-pub-point  (priv-to-pub:web-push ua-priv)
  =/  ua-pub  (serialize-point:web-push ua-pub-point)
  ::  subscriber's auth secret (16 bytes, shared during subscription)
  =/  ua-auth  0x1234.5678.9abc.def0.1234.5678.9abc.def0
  ::  the message to encrypt
  =/  plaintext=octs  (as-octs:mimes:html 'hello web push')
  ::  server-side ephemeral key (in real usage, generated randomly per message)
  =/  eph-priv  0x3
  =/  salt  0xdead.beef.cafe.babe.1234.5678.abcd.ef01
  ::
  ::  === Encrypt (what the server does) ===
  ::
  =/  result
    (encrypt-payload:web-push ua-pub ua-auth plaintext eph-priv salt)
  ::
  ::  === Parse the encrypted output ===
  ::
  ::  The output is in octs (LSB-first) with layout:
  ::    salt(16) || rs(4) || idlen(1) || eph_pub(65) || ciphertext || tag(16)
  ::
  =/  body  q.result
  =/  body-len  p.result
  ::  ciphertext length = total - 86 (header) - 16 (tag)
  =/  ct-len  (sub body-len 102)
  ::  extract the AES-GCM tag (last 16 bytes in LSB-first order)
  =/  tag-octs  (cut 3 [(sub body-len 16) 16] body)
  =/  tag  (rev 3 16 tag-octs)
  ::  extract the ciphertext (between header and tag)
  =/  ct-octs  (cut 3 [86 ct-len] body)
  =/  ct  (rev 3 ct-len ct-octs)
  ::
  ::  === Re-derive CEK and nonce (what the subscriber does) ===
  ::
  ::  Step 1: ECDH -- subscriber uses their private key + server's ephemeral pub
  ::  (The shared point is the same regardless of which side computes it,
  ::  because ECDH(a, b*G) = ECDH(b, a*G) = a*b*G)
  ::
  =/  eph-pub-point  (priv-to-pub:web-push eph-priv)
  =/  eph-pub  (serialize-point:web-push eph-pub-point)
  =/  shared-point  (mul-point-scalar:web-push ua-pub-point eph-priv)
  =/  ecdh-secret  x.shared-point
  ::
  ::  Step 2a: First HKDF round -- mix ECDH secret with subscriber's auth
  ::  info = "WebPush: info\0" || subscriber_pub || ephemeral_pub
  ::
  =/  info-label=byts  (cord-to-byts-null:web-push 'WebPush: info')
  =/  info-1
    %+  can  3
    :~  [65 eph-pub]
        [65 ua-pub]
        [wid.info-label dat.info-label]
    ==
  =/  prk-1  (extract:hkdf [16 ua-auth] [32 ecdh-secret])
  =/  ikm  (expand:hkdf prk-1 [144 info-1] 32)
  ::
  ::  Step 2b: Second HKDF round -- derive CEK (16 bytes) and nonce (12 bytes)
  ::  using the message salt from the encrypted payload header
  ::
  =/  prk-2  (extract:hkdf [16 salt] [32 ikm])
  =/  cek-info=byts  (cord-to-byts-null:web-push 'Content-Encoding: aes128gcm')
  =/  cek  (expand:hkdf prk-2 cek-info 16)
  =/  nonce-info=byts  (cord-to-byts-null:web-push 'Content-Encoding: nonce')
  =/  nonce  (expand:hkdf prk-2 nonce-info 12)
  ::
  ::  === Decrypt with AES-128-GCM ===
  ::
  =/  decrypted  (de:aes-gcm cek nonce [0 0] [ct-len ct] tag)
  ?~  decrypted
    (expect-eq !>(%decryption-failed) !>(%should-have-succeeded))
  ::
  ::  === Strip padding to recover the original plaintext ===
  ::
  ::  The padded plaintext format is: plaintext || 0x02 (delimiter)
  ::  In MSB-first order, the delimiter is the last (lowest) byte.
  ::  We verify the delimiter is 0x02, then extract the plaintext above it.
  ::
  =/  pt-padded  q.u.decrypted
  =/  pt-len  (dec p.u.decrypted)
  =/  delimiter  (end 3 pt-padded)
  =/  pt-byts  (rsh [3 1] pt-padded)
  ::  convert from byts (MSB-first) back to octs (LSB-first)
  =/  pt-recovered  (rev 3 pt-len pt-byts)
  ;:  weld
    ::  padding delimiter must be 0x02 (RFC 8291 Section 4)
    %+  expect-eq  !>(0x2)  !>(delimiter)
    ::  recovered plaintext must match the original message exactly
    %+  expect-eq
      !>((as-octs:mimes:html 'hello web push'))
    !>([pt-len pt-recovered])
  ==
--
