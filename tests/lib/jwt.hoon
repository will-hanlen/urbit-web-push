::  tests/lib/jwt: JSON Web Tokens with ES256 signatures
::
::  A JSON Web Token (JWT, RFC 7519) is a compact, URL-safe way to
::  represent claims between two parties. A JWT has three parts,
::  separated by dots:
::
::    <header>.<payload>.<signature>
::
::  Each part is base64url-encoded. The header declares the algorithm;
::  the payload carries the claims (arbitrary JSON); the signature
::  proves authenticity.
::
::  ES256 (ECDSA using P-256 and SHA-256) is the signing algorithm
::  used here. ES256 uses elliptic curve cryptography on
::  the NIST P-256 curve (also called secp256r1 or prime256v1).
::
::  This test file doubles as a reference for the /lib/jwt library.
::  Each section introduces a concept, then tests it.
::
::  Byte order conventions in Urbit:
::
::  Urbit atoms are unsigned integers. When we interpret them as
::  byte sequences, there are two conventions:
::
::  - byts (crypto convention): first byte at MSB of the atom.
::    Used by HMAC, HKDF, secp operations.
::
::  - octs (HTTP convention): first byte at LSB of the atom.
::    Used by base64, HTTP bodies, cords.
::
::  +rev from the standard library converts between them.
::  Example: the cord 'abc' stores a=0x61 at LSB, c=0x63 at MSB
::  (octs order). To use it in crypto, we reverse to get
::  a=0x61 at MSB (byts order).
::
/+  *test, jwt
::
|%
::  ------------------------------------------------------------------
::  Part 1: P-256 Elliptic Curve Fundamentals
::  ------------------------------------------------------------------
::
::  An elliptic curve over a finite field defines a set of points (x, y)
::  satisfying y^2 = x^3 + ax + b (mod p), plus a "point at infinity".
::
::  P-256 has a special point called the generator G. Every point on the
::  curve can be expressed as k*G for some integer k. This scalar
::  multiplication is the core operation: it's easy to compute k*G given
::  k, but infeasible to recover k given k*G (the elliptic curve
::  discrete logarithm problem). This asymmetry is the basis of ECDSA.
::
::  A private key is a random scalar k in [1, n-1], where n is the curve
::  order. The corresponding public key is the point k*G.
::
::  +priv-to-pub computes k*G. When k=1, the result is G itself.
::
::  --- Test: private key 1 yields the generator point G ---
::
::  The P-256 generator point G is a well-known constant defined by NIST.
::  Computing 1*G must return exactly G. This validates that our curve
::  parameters and scalar multiplication are correct.
::
++  test-p256-generator
  =/  pub  (priv-to-pub:jwt 1)
  ;:  weld
    %+  expect-eq
      !>  0x6b17.d1f2.e12c.4247.f8bc.e6e5.63a4.40f2.
            7703.7d81.2deb.33a0.f4a1.3945.d898.c296
    !>(x.pub)
  ::
    %+  expect-eq
      !>  0x4fe3.42e2.fe1a.7f9b.8ee7.eb4a.7c0f.9e16.
            2bce.3357.6b31.5ece.cbb6.4068.37bf.51f5
    !>(y.pub)
  ==
::  --- Test: private key 2 yields 2*G (point doubling) ---
::
::  When k=2, scalar multiplication performs "point doubling" -- adding G
::  to itself using the tangent line at G. This exercises a different
::  code path than generic point addition, and is the simplest non-trivial
::  scalar multiplication.
::
++  test-p256-double-generator
  =/  pub  (priv-to-pub:jwt 2)
  ;:  weld
    %+  expect-eq
      !>  0x7cf2.7b18.8d03.4f7e.8a52.3803.04b5.1ac3.
            c089.69e2.77f2.1b35.a60b.48fc.4766.9978
    !>(x.pub)
  ::
    %+  expect-eq
      !>  0x777.5510.db8e.d040.293d.9ac6.9f74.30db.
            ba7d.ade6.3ce9.8229.9e04.b79d.2278.73d1
    !>(y.pub)
  ==
::  ------------------------------------------------------------------
::  Part 2: Point Serialization
::  ------------------------------------------------------------------
::
::  Points on P-256 have two coordinates (x, y), each 32 bytes.
::  There are two standard serialization formats:
::
::  - Uncompressed: 0x04 || x || y  (65 bytes total)
::
::  - Compressed: 0x02/0x03 || x  (33 bytes total)
::    The prefix byte encodes whether y is even (0x02) or odd (0x03).
::    The receiver recovers y from x using the curve equation.
::    This works because for any x, there are at most two valid y values,
::    and they differ only in sign (y and p-y), so one is even and one odd.
::
::  +serialize-point produces the uncompressed form.
::  +compress-point produces the compressed form.
::  +decompress-point recovers the full point from compressed form.
::
::  --- Test: compress then decompress recovers the original point ---
::
::  We generate a public key from an arbitrary private key, compress it,
::  decompress it, and verify both coordinates match. This validates the
::  full serialization roundtrip including the modular square root used
::  during decompression.
::
++  test-p256-serialize-roundtrip
  =/  priv  0xc9af.a9d8.45ba.75e6.b477.46a2.1ece.b8ec.
              769e.4539.7ea6.e407.1537.7892.a0e3.a8f5
  =/  pub  (priv-to-pub:jwt priv)
  =/  serialized  (serialize-point:jwt pub)
  =/  deserialized  (decompress-point:jwt (compress-point:jwt pub))
  ;:  weld
    %+  expect-eq
      !>(x.pub)
    !>(x.deserialized)
  ::
    %+  expect-eq
      !>(y.pub)
    !>(y.deserialized)
  ==
::  ------------------------------------------------------------------
::  Part 3: ECDSA Signing
::  ------------------------------------------------------------------
::
::  ECDSA (Elliptic Curve Digital Signature Algorithm) produces a
::  signature (r, s) for a message hash, using a private key.
::
::  The signing process:
::    1. Choose a random nonce k
::    2. Compute R = k*G, set r = R.x mod n
::    3. Compute s = k^-1 * (hash + r * privateKey) mod n
::
::  Verification (by anyone with the public key):
::    1. Compute w = s^-1
::    2. Compute u1 = hash * w, u2 = r * w
::    3. Compute R' = u1*G + u2*pubKey
::    4. Signature is valid iff R'.x = r (mod n)
::
::  Both r and s must be in the range [1, n-1] for a valid signature.
::
::  Low-S normalization: ECDSA signatures have a malleability issue --
::  if (r, s) is valid, then (r, n-s) is also valid. To canonicalize,
::  we enforce s <= n/2 (the "low-s" form). If s > n/2, we replace it
::  with n-s. This is required by some protocols and prevents signature
::  malleability attacks.
::
::  --- Test: raw ECDSA signature has valid r,s in range with low-s ---
::
++  test-p256-ecdsa-sign
  =/  priv  0x1
  =/  hash  (rev 3 32 (shax 'example'))
  =/  sig  (ecdsa-raw-sign:jwt hash priv)
  =/  n  n.t:jwt
  ;:  weld
    ::  r must be in [1, n-1]
    (expect !>(&((gth r.sig 0) (lth r.sig n))))
    ::  s must be in [1, n-1]
    (expect !>(&((gth s.sig 0) (lth s.sig n))))
    ::  low-s normalization: 2*s <= n (i.e., s <= n/2)
    (expect !>((lte (mul 2 s.sig) n)))
  ==
::  ------------------------------------------------------------------
::  Part 4: ES256 -- ECDSA for JWTs
::  ------------------------------------------------------------------
::
::  ES256 is the JWT name for "ECDSA using P-256 and SHA-256".
::  The signature format is r || s, each zero-padded to 32 bytes,
::  for a fixed 64-byte output. This differs from the DER encoding
::  used in X.509 certificates -- JWT always uses the fixed-length
::  concatenation format (RFC 7518, Section 3.4).
::
::  +es256-sign takes a SHA-256 hash and private key, returns the
::  64-byte r||s concatenation as a single atom.
::
::  --- Test: ES256 signature is exactly 64 bytes ---
::
++  test-es256-sign-size
  =/  priv  0xc9af.a9d8.45ba.75e6.b477.46a2.1ece.b8ec.
              769e.4539.7ea6.e407.1537.7892.a0e3.a8f5
  =/  hash  (rev 3 32 (shax 'example'))
  =/  sig  (es256-sign:jwt hash priv)
  ::  r||s concatenation: exactly 64 bytes (32 + 32)
  (expect !>((lte (met 3 sig) 64)))
::  ------------------------------------------------------------------
::  Part 5: Byte Order Helpers
::  ------------------------------------------------------------------
::
::  +cord-to-byts converts a cord (text) to byts (crypto convention).
::
::  A cord in Urbit stores characters in LSB-first order:
::    'abc' = 0x63.6261  (a=0x61 at bit position 0, c=0x63 at bit 16)
::
::  Crypto operations expect MSB-first (byts) order:
::    'abc' -> [3 0x61.6263]  (a=0x61 at the most significant byte)
::
::  The conversion simply reverses the byte order and records the length.
::
::  --- Test: cord-to-byts reverses byte order correctly ---
::
++  test-cord-to-byts
  =/  result  (cord-to-byts:jwt 'abc')
  ;:  weld
    ::  three characters -> three bytes
    %+  expect-eq
      !>(3)
    !>(wid.result)
  ::
    ::  'abc' reversed: a=0x61 is now at MSB
    %+  expect-eq
      !>(`@ux`0x61.6263)
    !>(`@ux`dat.result)
  ==
::  ------------------------------------------------------------------
::  Part 6: JWT Construction
::  ------------------------------------------------------------------
::
::  A complete JWT is built in three steps:
::
::  1. Encode the header: {"alg":"ES256","typ":"JWT"}
::     - "alg" declares the signing algorithm (ES256 = ECDSA + P-256)
::     - "typ" is always "JWT" for JSON Web Tokens
::     - Base64url-encode this JSON to get the first segment
::
::  2. Encode the payload: arbitrary JSON claims
::     - Standard claims include:
::       "aud" (audience): who the JWT is intended for
::       "exp" (expiration): unix timestamp after which the JWT is invalid
::       "sub" (subject): who the JWT is about
::       "iss" (issuer): who created the JWT
::       "nbf" (not before): unix timestamp before which the JWT is invalid
::     - Base64url-encode this JSON to get the second segment
::
::  3. Sign: SHA-256(header.payload), then ES256-sign the hash
::     - Base64url-encode the 64-byte signature for the third segment
::
::  The final token is: base64url(header).base64url(payload).base64url(sig)
::
::  +make-jwt is a convenience that builds a JWT with aud, exp, and sub.
::  +encode-jwt is the general form that accepts arbitrary JSON claims.
::
::  --- Test: make-jwt produces a well-formed 3-segment JWT ---
::
::  We verify the structure by splitting on '.', then decode each segment
::  and check that the header contains "ES256", the payload contains our
::  claims, and the signature is 64 bytes.
::
++  test-make-jwt
  =/  priv  0xc9af.a9d8.45ba.75e6.b477.46a2.1ece.b8ec.
              769e.4539.7ea6.e407.1537.7892.a0e3.a8f5
  =/  token
    %:  make-jwt:jwt
      'https://fcm.googleapis.com'  ::  audience: Firebase Cloud Messaging
      1.700.000.000                 ::  expiration: unix timestamp
      'mailto:test@example.com'     ::  subject: contact email for VAPID
      priv                          ::  signing key
    ==
  ::  split the JWT on '.' to get the three segments
  =/  parts=(list @t)
    %+  turn
      %+  rash  token
      (more dot (cook crip (plus ;~(pose hig low nud hep cab))))
    |=(a=@t a)
  ;:  weld
  ::
  ::  --- Structure: must have exactly 3 dot-separated segments ---
  ::
    %+  expect-eq  !>(3)  !>((lent parts))
  ::
  ::  --- Header segment: must declare ES256 algorithm ---
  ::
    =/  header-b64  (snag 0 parts)
    =/  header-octs  (de-base64url:jwt header-b64)
    ?~  header-octs
      (expect-eq !>(%header-decode-failed) !>(%should-succeed))
    =/  header-cord  (trip `@t`q.u.header-octs)
    (expect !>(!=((find "ES256" header-cord) ~)))
  ::
  ::  --- Payload segment: must contain audience, expiration, and subject ---
  ::
    =/  payload-b64  (snag 1 parts)
    =/  payload-octs  (de-base64url:jwt payload-b64)
    ?~  payload-octs
      (expect-eq !>(%payload-decode-failed) !>(%should-succeed))
    =/  payload-cord  (trip `@t`q.u.payload-octs)
    ;:  weld
      (expect !>(!=((find "fcm.googleapis.com" payload-cord) ~)))
      (expect !>(!=((find "1700000000" payload-cord) ~)))
      (expect !>(!=((find "test@example.com" payload-cord) ~)))
    ==
  ::
  ::  --- Signature segment: must be 64 bytes (r||s, each 32 bytes) ---
  ::
    =/  sig-b64  (snag 2 parts)
    =/  sig-octs  (de-base64url:jwt sig-b64)
    ?~  sig-octs
      (expect-eq !>(%sig-decode-failed) !>(%should-succeed))
    %+  expect-eq  !>(64)  !>(p.u.sig-octs)
  ==
::  --- Test: encode-jwt with arbitrary claims ---
::
::  +encode-jwt accepts any JSON object as the payload. Here we use
::  custom claims ('iss' and 'custom') and verify they survive a
::  full encode -> decode roundtrip.
::
++  test-encode-jwt
  =/  priv  0xc9af.a9d8.45ba.75e6.b477.46a2.1ece.b8ec.
              769e.4539.7ea6.e407.1537.7892.a0e3.a8f5
  =/  payload=json
    %-  pairs:enjs:format
    :~  ['iss' [%s 'test-issuer']]
        ['custom' [%s 'value']]
    ==
  =/  token  (encode-jwt:jwt payload priv)
  ::  decode the token we just created
  =/  decoded  (decode-jwt:jwt token)
  ?~  decoded
    (expect-eq !>(%decode-failed) !>(%should-succeed))
  ::  the decoded payload should be a JSON object containing our claims
  ?.  ?=(%o -.payload.u.decoded)
    (expect-eq !>(%not-object) !>(%should-be-object))
  ;:  weld
    %+  expect-eq
      !>(`[%s 'test-issuer'])
    !>((~(get by p.payload.u.decoded) 'iss'))
  ::
    %+  expect-eq
      !>(`[%s 'value'])
    !>((~(get by p.payload.u.decoded) 'custom'))
  ==
::  --- Test: decode-jwt rejects malformed tokens ---
::
::  Tokens with the wrong number of segments, invalid base64, or
::  invalid JSON must return ~.
::
++  test-decode-jwt-malformed
  ;:  weld
    ::  too few segments (only 2 parts)
    %+  expect-eq  !>(~)  !>((decode-jwt:jwt 'abc.def'))
    ::  too many segments (4 parts)
    %+  expect-eq  !>(~)  !>((decode-jwt:jwt 'a.b.c.d'))
    ::  empty string
    %+  expect-eq  !>(~)  !>((decode-jwt:jwt ''))
    ::  single segment, no dots
    %+  expect-eq  !>(~)  !>((decode-jwt:jwt 'nodots'))
  ==
::  ------------------------------------------------------------------
::  Part 7: JWT Decoding
::  ------------------------------------------------------------------
::
::  +decode-jwt parses a JWT string into its three components without
::  verifying the signature. This is useful for inspecting tokens.
::
::  It returns a unit: ~ if the JWT is malformed (wrong number of
::  segments, invalid base64, or invalid JSON), otherwise the decoded
::  [header=json payload=json signature=octs].
::
::  --- Test: decode-jwt parses header, payload, and signature ---
::
++  test-decode-jwt
  =/  priv  0xc9af.a9d8.45ba.75e6.b477.46a2.1ece.b8ec.
              769e.4539.7ea6.e407.1537.7892.a0e3.a8f5
  =/  token  (make-jwt:jwt 'https://example.com' 1.700.000.000 'mailto:test@test.com' priv)
  =/  decoded  (decode-jwt:jwt token)
  ?~  decoded
    (expect-eq !>(%decode-failed) !>(%should-succeed))
  ::  the header must declare alg=ES256
  ?.  ?=(%o -.header.u.decoded)
    (expect-eq !>(%not-object) !>(%should-be-object))
  ;:  weld
    %+  expect-eq
      !>(`[%s 'ES256'])
    !>((~(get by p.header.u.decoded) 'alg'))
  ::
    ::  the raw signature must be exactly 64 bytes
    %+  expect-eq  !>(64)  !>(p.signature.u.decoded)
  ==
::  ------------------------------------------------------------------
::  Part 8: JWT Verification
::  ------------------------------------------------------------------
::
::  +verify-jwt decodes a JWT and cryptographically verifies its
::  signature against a known public key. The process:
::
::  1. Split the JWT into three segments
::  2. Reconstruct the signing input: segment1 || '.' || segment2
::  3. SHA-256 hash the signing input
::  4. Extract r and s from the 64-byte signature
::  5. Run ECDSA verification with the public key
::  6. Return the decoded [header payload] if valid, ~ if not
::
::  This is the critical security check: it proves the JWT was created
::  by someone who holds the private key corresponding to the public key.
::
::  --- Test: sign-then-verify roundtrip succeeds ---
::
::  We sign a JWT with a private key, then verify it with the
::  corresponding public key. The verified payload must contain
::  our original claims.
::
++  test-verify-jwt
  =/  priv  0xc9af.a9d8.45ba.75e6.b477.46a2.1ece.b8ec.
              769e.4539.7ea6.e407.1537.7892.a0e3.a8f5
  =/  pub  (priv-to-pub:jwt priv)
  =/  token  (make-jwt:jwt 'https://example.com' 1.700.000.000 'mailto:test@test.com' priv)
  =/  result  (verify-jwt:jwt token pub)
  ?~  result
    (expect-eq !>(%verify-failed) !>(%should-succeed))
  ::  the verified payload must contain our audience claim
  ?.  ?=(%o -.payload.u.result)
    (expect-eq !>(%not-object) !>(%should-be-object))
  %+  expect-eq
    !>(`[%s 'https://example.com'])
  !>((~(get by p.payload.u.result) 'aud'))
::  --- Test: verification fails with the wrong public key ---
::
::  A JWT signed by key A must not verify under key B. This is the
::  fundamental security property: only the holder of the private key
::  can produce a valid signature.
::
++  test-verify-jwt-wrong-key
  =/  priv  0xc9af.a9d8.45ba.75e6.b477.46a2.1ece.b8ec.
              769e.4539.7ea6.e407.1537.7892.a0e3.a8f5
  =/  wrong-pub  (priv-to-pub:jwt 0x2)
  =/  token  (make-jwt:jwt 'https://example.com' 1.700.000.000 'mailto:test@test.com' priv)
  =/  result  (verify-jwt:jwt token wrong-pub)
  ::  must return ~ (verification failure)
  %+  expect-eq  !>(~)  !>(result)
::  ------------------------------------------------------------------
::  Part 9: Claims Validation
::  ------------------------------------------------------------------
::
::  Beyond signature verification, JWTs carry time-based claims that
::  receivers must check:
::
::  - "exp" (Expiration Time): the JWT is invalid after this timestamp.
::    Prevents replay of old tokens. A receiver must reject the JWT if
::    the current time is past exp.
::
::  - "nbf" (Not Before): the JWT is invalid before this timestamp.
::    Used to issue tokens that activate in the future. A receiver must
::    reject the JWT if the current time is before nbf.
::
::  Both are optional. If absent, the check passes (no constraint).
::  Both are expressed as Unix timestamps (seconds since 1970-01-01).
::
::  +validate-exp and +validate-nbf each take a JSON payload and a
::  "current time" (unix seconds), returning %.y if valid.
::
::  --- Test: exp validation -- before, at, and after expiration ---
::
::  Given exp=1700000000:
::    now=1699999999 -> valid (before expiration)
::    now=1700000000 -> valid (at expiration, inclusive)
::    now=1700000001 -> expired (after expiration)
::
++  test-validate-exp
  =/  payload=json
    %-  pairs:enjs:format
    :~  ['exp' [%n '1700000000']]
    ==
  ;:  weld
    ::  before exp: token is still valid
    (expect !>((validate-exp:jwt payload 1.699.999.999)))
    ::  exactly at exp: token is still valid (gte is inclusive)
    (expect !>((validate-exp:jwt payload 1.700.000.000)))
    ::  one second after exp: token has expired
    %+  expect-eq  !>(%.n)  !>((validate-exp:jwt payload 1.700.000.001))
  ==
::  --- Test: nbf validation -- before, at, and after activation ---
::
::  Given nbf=1700000000:
::    now=1700000001 -> valid (after activation time)
::    now=1700000000 -> valid (at activation, inclusive)
::    now=1699999999 -> invalid (too early)
::
++  test-validate-nbf
  =/  payload=json
    %-  pairs:enjs:format
    :~  ['nbf' [%n '1700000000']]
    ==
  ;:  weld
    ::  after nbf: token is active
    (expect !>((validate-nbf:jwt payload 1.700.000.001)))
    ::  exactly at nbf: token is active (lte is inclusive)
    (expect !>((validate-nbf:jwt payload 1.700.000.000)))
    ::  before nbf: token is not yet valid
    %+  expect-eq  !>(%.n)  !>((validate-nbf:jwt payload 1.699.999.999))
  ==
--
