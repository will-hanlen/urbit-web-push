::  tests/lib/hkdf: HKDF-SHA-256 key derivation
::
::  HKDF (HMAC-based Key Derivation Function, RFC 5869) derives
::  cryptographically strong keying material from a shared secret.
::  It has two phases:
::
::  1. EXTRACT: condense potentially weak input keying material (IKM)
::     into a fixed-length pseudorandom key (PRK) using HMAC.
::
::       PRK = HMAC-SHA256(salt, IKM)
::
::     The salt is optional but recommended. If absent, a string of
::     zero bytes the length of the hash output (32 for SHA-256) is used.
::     The salt acts as a domain separator and helps extract entropy
::     even from non-uniform inputs.
::
::  2. EXPAND: stretch the PRK into output keying material (OKM) of
::     any desired length, using an iterative HMAC construction:
::
::       T(0) = empty string
::       T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
::       OKM  = T(1) || T(2) || ... (truncated to desired length)
::
::     The "info" parameter provides context-specific binding. Different
::     info values produce independent keys from the same PRK. For
::     example, a protocol can derive separate encryption keys and
::     nonces from a single shared secret by using different info strings.
::
::  All values in these tests use the byts convention (MSB-first):
::  the first data byte sits at the most significant byte of the atom.
::
::  Test vectors from RFC 5869, Appendix A.
::
/+  *test, hkdf
::
|%
::  ------------------------------------------------------------------
::  RFC 5869 Test Case 1 (Appendix A.1): Basic extraction and expansion
::  ------------------------------------------------------------------
::
::  Inputs:
::    IKM  = 0x0b0b0b0b0b0b...  (22 bytes of 0x0b)
::    salt = 0x000102030405060708090a0b0c  (13 bytes)
::    info = 0xf0f1f2f3f4f5f6f7f8f9  (10 bytes)
::    L    = 42 bytes of output
::
::  Expected:
::    PRK = 0x077709362c2e32df0ddc3f0dc47bba63
::          90b6c73bb50f9c3122ec844ad7c2b3e5
::    OKM = 0x3cb25f25faacd57a90434f64d0362f2a
::          2d2d0a90cf1a5a4c5db02d56ecc4c5bf
::          34007208d5b887185865
::
::  Byts encoding notes:
::    salt bytes [0x00, 0x01, ..., 0x0c]:
::      MSB = 0x00, so the atom is 0x102.0304.0506.0708.090a.0b0c
::      with wid=13 (the leading zero byte is implicit in the width)
::    IKM: 22 repetitions of 0x0b -> (fil 3 22 0xb)
::
::  --- Test: extract phase -- IKM + salt -> PRK ---
::
++  test-extract-a1
  =/  ikm=byts   [22 (fil 3 22 0xb)]
  =/  salt=byts  [13 0x102.0304.0506.0708.090a.0b0c]
  =/  expected=@
    0x777.0936.2c2e.32df.0ddc.3f0d.c47b.ba63.
      90b6.c73b.b50f.9c31.22ec.844a.d7c2.b3e5
  %+  expect-eq
    !>(expected)
  !>((extract:hkdf salt ikm))
::  --- Test: expand phase -- PRK + info -> OKM ---
::
::  Given the PRK from the extract step above, expand it with the
::  info context string to produce 42 bytes of output keying material.
::  The expand step runs two iterations of HMAC (ceil(42/32) = 2),
::  concatenates the outputs, and truncates to 42 bytes.
::
++  test-expand-a1
  =/  prk=@
    0x777.0936.2c2e.32df.0ddc.3f0d.c47b.ba63.
      90b6.c73b.b50f.9c31.22ec.844a.d7c2.b3e5
  =/  info=byts  [10 0xf0f1.f2f3.f4f5.f6f7.f8f9]
  =/  expected=@
    0x3cb2.5f25.faac.d57a.9043.4f64.d036.2f2a.
      2d2d.0a90.cf1a.5a4c.5db0.2d56.ecc4.c5bf.
      3400.7208.d5b8.8718.5865
  %+  expect-eq
    !>(expected)
  !>((expand:hkdf prk info 42))
::  ------------------------------------------------------------------
::  RFC 5869 Test Case 2 (Appendix A.2): Longer inputs and output
::  ------------------------------------------------------------------
::
::  This test uses longer IKM (80 bytes), salt (80 bytes), info (80 bytes),
::  and output length (82 bytes). The 82-byte output requires 3 HMAC
::  iterations (ceil(82/32) = 3), exercising the multi-iteration
::  expansion path.
::
::  Inputs:
::    IKM  = 0x000102030405...4f  (80 bytes, 0x00 through 0x4f)
::    salt = 0x606162636465...af  (80 bytes, 0x60 through 0xaf)
::    info = 0xb0b1b2b3b4b5...ff  (80 bytes, 0xb0 through 0xff)
::    L    = 82 bytes of output
::
::  --- Test: extract with long salt and IKM ---
::
++  test-extract-a2
  =/  ikm=byts
    :-  80
    0x1.0203.0405.0607.0809.0a0b.0c0d.0e0f.
      1011.1213.1415.1617.1819.1a1b.1c1d.1e1f.
      2021.2223.2425.2627.2829.2a2b.2c2d.2e2f.
      3031.3233.3435.3637.3839.3a3b.3c3d.3e3f.
      4041.4243.4445.4647.4849.4a4b.4c4d.4e4f
  =/  salt=byts
    :-  80
    0x6061.6263.6465.6667.6869.6a6b.6c6d.6e6f.
      7071.7273.7475.7677.7879.7a7b.7c7d.7e7f.
      8081.8283.8485.8687.8889.8a8b.8c8d.8e8f.
      9091.9293.9495.9697.9899.9a9b.9c9d.9e9f.
      a0a1.a2a3.a4a5.a6a7.a8a9.aaab.acad.aeaf
  =/  expected=@
    0x6a6.b88c.5853.361a.0610.4c9c.eb35.b45c.
      ef76.0014.9046.7101.4a19.3f40.c15f.c244
  %+  expect-eq
    !>(expected)
  !>((extract:hkdf salt ikm))
::  --- Test: expand with long info, 82-byte output (3 HMAC iterations) ---
::
++  test-expand-a2
  =/  prk=@
    0x6a6.b88c.5853.361a.0610.4c9c.eb35.b45c.
      ef76.0014.9046.7101.4a19.3f40.c15f.c244
  =/  info=byts
    :-  80
    0xb0b1.b2b3.b4b5.b6b7.b8b9.babb.bcbd.bebf.
      c0c1.c2c3.c4c5.c6c7.c8c9.cacb.cccd.cecf.
      d0d1.d2d3.d4d5.d6d7.d8d9.dadb.dcdd.dedf.
      e0e1.e2e3.e4e5.e6e7.e8e9.eaeb.eced.eeef.
      f0f1.f2f3.f4f5.f6f7.f8f9.fafb.fcfd.feff
  =/  expected=@
    0xb11e.398d.c803.27a1.c8e7.f78c.596a.4934.
      4f01.2eda.2d4e.fad8.a050.cc4c.19af.a97c.
      5904.5a99.cac7.8272.71cb.41c6.5e59.0e09.
      da32.7560.0c2f.09b8.3677.93a9.aca3.db71.
      cc30.c581.79ec.3e87.c14c.01d5.c1f3.434f.
      1d87
  %+  expect-eq
    !>(expected)
  !>((expand:hkdf prk info 82))
::  ------------------------------------------------------------------
::  RFC 5869 Test Case 3 (Appendix A.3): Zero-length salt and info
::  ------------------------------------------------------------------
::
::  This tests the edge case where both salt and info are empty.
::
::  When salt is empty, HKDF uses a string of 32 zero bytes as the
::  HMAC key (per RFC 5869 Section 2.2). This is important because
::  some protocols don't provide a salt.
::
::  When info is empty, expand still works -- the HMAC input is just
::  T(i-1) || counter_byte, with no context binding. In practice,
::  info should always be provided for domain separation.
::
::  Inputs:
::    IKM  = 0x0b0b0b0b0b0b...  (22 bytes of 0x0b)
::    salt = (empty)
::    info = (empty)
::    L    = 42 bytes of output
::
::  Expected:
::    PRK = 0x19ef24a32c717b167f33a91d6f648bdf
::          96596776afdb6377ac434c1c293ccb04
::    OKM = 0x8da4e775a563c18f715f802a063c5a31
::          b8a11f5c5ee1879ec3454e5f3c738d2d
::          9d201395faa4b61a96c8
::
::  --- Test: extract with empty salt ---
::
++  test-extract-a3
  =/  ikm=byts   [22 (fil 3 22 0xb)]
  =/  salt=byts  [0 0]
  =/  expected=@
    0x19ef.24a3.2c71.7b16.7f33.a91d.6f64.8bdf.
      9659.6776.afdb.6377.ac43.4c1c.293c.cb04
  %+  expect-eq
    !>(expected)
  !>((extract:hkdf salt ikm))
::  --- Test: expand with empty info ---
::
++  test-expand-a3
  =/  prk=@
    0x19ef.24a3.2c71.7b16.7f33.a91d.6f64.8bdf.
      9659.6776.afdb.6377.ac43.4c1c.293c.cb04
  =/  info=byts  [0 0]
  =/  expected=@
    0x8da4.e775.a563.c18f.715f.802a.063c.5a31.
      b8a1.1f5c.5ee1.879e.c345.4e5f.3c73.8d2d.
      9d20.1395.faa4.b61a.96c8
  %+  expect-eq
    !>(expected)
  !>((expand:hkdf prk info 42))
--
