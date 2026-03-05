::  tests/lib/aes-gcm: AES-128-GCM authenticated encryption
::
::  AES-GCM (Galois/Counter Mode) is an authenticated encryption with
::  associated data (AEAD) algorithm. It provides both confidentiality
::  (encryption) and integrity (authentication) in a single operation.
::
::  How AES-GCM works:
::
::  1. ENCRYPTION (AES-CTR):
::     A counter block is initialized from the IV (initialization vector)
::     and incremented for each 16-byte block. Each counter is encrypted
::     with AES to produce a keystream, which is XORed with the plaintext.
::     This makes AES-GCM a stream cipher built from a block cipher.
::
::  2. AUTHENTICATION (GHASH):
::     A polynomial hash over GF(2^128) is computed over:
::       - The additional authenticated data (AAD) -- data that is
::         authenticated but not encrypted (e.g., headers, metadata)
::       - The ciphertext
::       - A length block encoding the bit-lengths of AAD and ciphertext
::     The hash is XORed with an encrypted counter block to produce the
::     authentication tag.
::
::  The result is: ciphertext + 128-bit authentication tag.
::
::  Key properties:
::  - The IV (nonce) must NEVER be reused with the same key. Reuse
::    completely breaks both confidentiality and authenticity.
::  - The tag authenticates both the ciphertext AND the AAD, so any
::    tampering with either is detected during decryption.
::  - Decryption verifies the tag BEFORE returning plaintext, preventing
::    release of unauthenticated data.
::
::  These tests use vectors from NIST SP 800-38D, the defining standard
::  for AES-GCM. Each test case specifies exact inputs and expected
::  outputs, allowing bit-exact verification of the implementation.
::
/+  *test, aes-gcm
::
|%
::  ------------------------------------------------------------------
::  NIST Test Vectors (SP 800-38D)
::  ------------------------------------------------------------------
::
::  --- Test Case 1: All-zero inputs, empty plaintext, empty AAD ---
::
::  The simplest possible case. With no plaintext, there is no ciphertext
::  -- but GHASH still produces an authentication tag over the (empty) data.
::  This tests the core GHASH and tag generation in isolation.
::
::  Key = 0x00000000000000000000000000000000
::  IV  = 0x000000000000000000000000
::  PT  = (empty)
::  AAD = (empty)
::  CT  = (empty)
::  Tag = 0x58e2fccefa7e3061367f1d57a4e7455a
::
++  test-gcm-empty
  =/  key=@uxH  0x0
  =/  iv=@      0x0
  =/  result  (en:aes-gcm key iv [0 0] [0 0])
  ;:  weld
    ::  no plaintext -> no ciphertext (length must be 0)
    %+  expect-eq
      !>(0)
    !>(p.ciphertext.result)
  ::
    ::  tag is still produced from GHASH over the length block
    %+  expect-eq
      !>(`@ux`0x58e2.fcce.fa7e.3061.367f.1d57.a4e7.455a)
    !>(`@ux`tag.result)
  ==
::  --- Test Case 2: 16-byte zero plaintext, empty AAD ---
::
::  One block of all-zero plaintext. The ciphertext reveals the raw
::  AES-CTR keystream (since PT XOR keystream = 0 XOR keystream = keystream).
::  This is useful for verifying that the counter initialization and
::  AES-CTR encryption are correct.
::
::  Key = 0x00000000000000000000000000000000
::  IV  = 0x000000000000000000000000
::  PT  = 0x00000000000000000000000000000000
::  CT  = 0x0388dace60b6a392f328c2b971b2fe78
::  Tag = 0xab6e47d42cec13bdf53a67b21257bddf
::
++  test-gcm-basic
  =/  key=@uxH  0x0
  =/  iv=@      0x0
  =/  result  (en:aes-gcm key iv [0 0] [16 0x0])
  ;:  weld
    ::  ciphertext = AES-CTR keystream (since plaintext is all zeros)
    %+  expect-eq
      !>(`@ux`0x388.dace.60b6.a392.f328.c2b9.71b2.fe78)
    !>(`@ux`q.ciphertext.result)
  ::
    ::  tag now authenticates the non-empty ciphertext
    %+  expect-eq
      !>(`@ux`0xab6e.47d4.2cec.13bd.f53a.67b2.1257.bddf)
    !>(`@ux`tag.result)
  ==
::  --- Test Case 3: Non-trivial key, IV, and 64-byte plaintext ---
::
::  A realistic scenario with non-zero key, IV, and a substantial
::  (4-block) plaintext. No AAD. This exercises multi-block AES-CTR
::  encryption and multi-block GHASH authentication.
::
::  Key = 0xfeffe9928665731c6d6a8f9467308308
::  IV  = 0xcafebabefacedbaddecaf888
::  PT  = 64 bytes (shown below)
::  CT  = 64 bytes (shown below)
::  Tag = 0x4d5c2af327cd64a62cf35abd2ba6fab4
::
++  test-gcm-nonzero
  =/  key=@uxH  0xfeff.e992.8665.731c.6d6a.8f94.6730.8308
  =/  iv=@      0xcafe.babe.face.dbad.deca.f888
  =/  pt=octs
    :-  64
    0xd931.3225.f884.06e5.a559.09c5.aff5.269a.
      86a7.a953.1534.f7da.2e4c.303d.8a31.8a72.
      1c3c.0c95.9568.0953.2fcf.0e24.49a6.b525.
      b16a.edf5.aa0d.e657.ba63.7b39.1aaf.d255
  =/  result  (en:aes-gcm key iv [0 0] pt)
  =/  expected-ct=@
    0x4283.1ec2.2177.7424.4b72.21b7.84d0.d49c.
      e3aa.212f.2c02.a4e0.35c1.7e23.29ac.a12e.
      21d5.14b2.5466.931c.7d8f.6a5a.ac84.aa05.
      1ba3.0b39.6a0a.ac97.3d58.e091.473f.5985
  =/  expected-tag=@uxH
    0x4d5c.2af3.27cd.64a6.2cf3.5abd.2ba6.fab4
  ;:  weld
    %+  expect-eq
      !>(`@ux`expected-ct)
    !>(`@ux`q.ciphertext.result)
  ::
    %+  expect-eq
      !>(`@ux`expected-tag)
    !>(`@ux`tag.result)
  ==
::  --- Test Case 4: Non-trivial inputs WITH additional authenticated data ---
::
::  Same key and IV as Test Case 3, but with 20 bytes of AAD and a
::  shorter (60-byte) plaintext. The AAD is authenticated but NOT
::  encrypted -- it appears in the clear, but any modification is detected
::  by the tag. This models real-world usage where headers or routing
::  information must be readable but tamper-proof.
::
::  Note: the ciphertext prefix matches Test Case 3 (same key/IV/PT prefix)
::  but the tag differs because GHASH now covers the AAD.
::
::  Key = 0xfeffe9928665731c6d6a8f9467308308
::  IV  = 0xcafebabefacedbaddecaf888
::  PT  = 60 bytes
::  AAD = 0xfeedfacedeadbeeffeedfacedeadbeefabaddad2 (20 bytes)
::  CT  = 60 bytes
::  Tag = 0x5bc94fbc3221a5db94fae95ae7121a47
::
++  test-gcm-with-aad
  =/  key=@uxH  0xfeff.e992.8665.731c.6d6a.8f94.6730.8308
  =/  iv=@      0xcafe.babe.face.dbad.deca.f888
  =/  pt=octs
    :-  60
    0xd931.3225.f884.06e5.a559.09c5.aff5.269a.
      86a7.a953.1534.f7da.2e4c.303d.8a31.8a72.
      1c3c.0c95.9568.0953.2fcf.0e24.49a6.b525.
      b16a.edf5.aa0d.e657.ba63.7b39
  =/  aad=octs
    [20 0xfeed.face.dead.beef.feed.face.dead.beef.abad.dad2]
  =/  result  (en:aes-gcm key iv aad pt)
  =/  expected-ct=@
    0x4283.1ec2.2177.7424.4b72.21b7.84d0.d49c.
      e3aa.212f.2c02.a4e0.35c1.7e23.29ac.a12e.
      21d5.14b2.5466.931c.7d8f.6a5a.ac84.aa05.
      1ba3.0b39.6a0a.ac97.3d58.e091
  =/  expected-tag=@uxH
    0x5bc9.4fbc.3221.a5db.94fa.e95a.e712.1a47
  ;:  weld
    %+  expect-eq
      !>(`@ux`expected-ct)
    !>(`@ux`q.ciphertext.result)
  ::
    %+  expect-eq
      !>(`@ux`expected-tag)
    !>(`@ux`tag.result)
  ==
::  ------------------------------------------------------------------
::  Decryption Tests
::  ------------------------------------------------------------------
::
::  Decryption in AES-GCM is not simply "run encryption in reverse".
::  The process is:
::
::  1. Recompute the GHASH over the received ciphertext and AAD
::  2. Derive the expected tag and compare to the received tag
::  3. ONLY if the tag matches, decrypt the ciphertext with AES-CTR
::
::  This "verify-then-decrypt" order is critical: it prevents an attacker
::  from learning anything about modified ciphertext. If the tag doesn't
::  match, +de returns ~ without attempting decryption.
::
::  --- Test Case 5: Non-block-aligned plaintext (7 bytes) ---
::
::  Plaintexts whose length is not a multiple of 16 exercise the
::  partial-block handling in AES-CTR. The last counter block's
::  keystream is truncated to match the remaining plaintext bytes.
::
++  test-gcm-nonaligned
  =/  key=@uxH  0xfeff.e992.8665.731c.6d6a.8f94.6730.8308
  =/  iv=@      0xcafe.babe.face.dbad.deca.f888
  =/  pt=octs   [7 0xd9.3132.25f8.8406]
  =/  result  (en:aes-gcm key iv [0 0] pt)
  ::  ciphertext must be the same length as plaintext
  ;:  weld
    %+  expect-eq  !>(7)  !>(p.ciphertext.result)
    ::  roundtrip must recover original
    =/  decrypted  (de:aes-gcm key iv [0 0] ciphertext.result tag.result)
    %+  expect-eq  !>(`pt)  !>(decrypted)
  ==
::  --- Test: encrypt then decrypt recovers original plaintext ---
::
++  test-gcm-decrypt-roundtrip
  =/  key=@uxH  0xfeff.e992.8665.731c.6d6a.8f94.6730.8308
  =/  iv=@      0xcafe.babe.face.dbad.deca.f888
  =/  pt=octs   [16 0xd931.3225.f884.06e5.a559.09c5.aff5.269a]
  ::  encrypt
  =/  result  (en:aes-gcm key iv [0 0] pt)
  ::  decrypt with the correct tag
  =/  decrypted  (de:aes-gcm key iv [0 0] ciphertext.result tag.result)
  ::  must recover the original plaintext exactly
  %+  expect-eq
    !>(`pt)
  !>(decrypted)
::  --- Test: decryption fails with a corrupted tag ---
::
::  Flipping a single bit in the tag must cause decryption to fail.
::  This demonstrates the authentication guarantee: any tampering --
::  even a single bit -- is detected, and no plaintext is returned.
::
++  test-gcm-decrypt-bad-tag
  =/  key=@uxH  0xfeff.e992.8665.731c.6d6a.8f94.6730.8308
  =/  iv=@      0xcafe.babe.face.dbad.deca.f888
  =/  pt=octs   [16 0xd931.3225.f884.06e5.a559.09c5.aff5.269a]
  ::  encrypt to get valid ciphertext + tag
  =/  result  (en:aes-gcm key iv [0 0] pt)
  ::  corrupt the tag by flipping the lowest bit
  =/  bad-tag=@uxH  (mix tag.result 1)
  ::  decryption must return ~ (authentication failure)
  =/  decrypted  (de:aes-gcm key iv [0 0] ciphertext.result bad-tag)
  %+  expect-eq
    !>(~)
  !>(decrypted)
--
