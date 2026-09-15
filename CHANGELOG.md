# Release Notes #

<a name="1.0.0"></a>
## 1.0.0 (unreleased)

### Breaking

* The shared library has ABI version 1: it installs as libcjose.so.1 with SONAME libcjose.so.1, its exported symbols carry the CJOSE_1.0 symbol version, and the Debian package is named libcjose1. Programs built against libcjose.so.0 must be rebuilt
* cjose_jwk_get_keydata returns implementation-specific data that must be treated as opaque for RSA, EC and OKP keys; it no longer hands out OpenSSL RSA and EC_KEY objects (#181)
* OpenSSL 3.0.0 or newer is required and only non-deprecated OpenSSL APIs are used (#179, #180, #181)
* The autoconf build is removed; CMake 3.22 or newer is the only build system (#178)
* The library and the tests are built as strict C17 (#182); the tests need Check 0.12.0 or newer (#176)
* A JOSE header that carries a "crit" parameter is refused, wherever it appears and whatever it lists: cjose implements no extension to the JOSE specifications, so every name such a list can carry is either unsupported, which RFC 7515 section 4.1.11 requires a recipient to reject, or defined by the specifications or by JWA, which a producer must not list. A JWE or JWS whose header carried "crit" naming only parameters cjose processes was accepted before and now fails with CJOSE_ERR_INVALID_ARG; the API does not change (#188)

### Update

* Add the A128GCMKW, A192GCMKW and A256GCMKW key encryption algorithms of RFC 7518 section 4.7: the content encryption key is encrypted with AES GCM under an oct key of the size the alg names, and the IV and the authentication tag travel as the "iv" and "tag" header parameters. With a single recipient they go into the protected header, so the compact serialization carries them, and with several into each recipient's own header (#188)
* Add the PBES2-HS256+A128KW, PBES2-HS384+A192KW and PBES2-HS512+A256KW key encryption algorithms of RFC 7518 section 4.8: a key encryption key is derived from the octets of an oct key with PBKDF2 over HMAC SHA-2 and the "p2s" and "p2c" header parameters, and wraps the content encryption key with AES Key Wrap. The salt input is generated for every encryption as section 4.8.1.1 requires; the iteration count bounds and the largest accepted salt input are the CJOSE_JWE_PBES2_* build options (#185)
* Add X25519 and X448 to the ECDH-ES key agreement of RFC 8037 section 3.2: ECDH-ES and ECDH-ES+A128KW, +A192KW and +A256KW accept OKP keys on those two curves next to EC keys, and cjose_jwk_derive_ecdh_ephemeral_key gains them with it. The Ed25519 and Ed448 signature keys are refused for key agreement (#186)
* Add the ML-DSA-44, ML-DSA-65 and ML-DSA-87 signature algorithms of RFC 9964 (US NIST FIPS 204) and the Algorithm Key Pair (AKP) key type they sign with: cjose_jwk_create_AKP_random, cjose_jwk_create_AKP_spec, cjose_jwk_AKP_get_alg and JWK import/export, where "priv" is the 32 octet seed and "alg" is required. They are pure ML-DSA with the empty context string the RFC requires; HashML-DSA is not offered. Behind the CJOSE_ENABLE_ML_DSA build option, off by default and requiring OpenSSL >= 3.5; with the option off the three functions fail with CJOSE_ERR_INVALID_ARG, the treatment CJOSE_ENABLE_RSA1_5 already gives RSA1_5 (#198)
* cjose_jwe_encrypt_multi resolves "alg" from the shared unprotected header as well, where it required the protected or the per-recipient header before; the import path already read it from all three (#188)
* HMAC operations in HKDF and in the JWE authentication tag use the one-shot EVP_Q_mac of OpenSSL 3 (#196)

### Fix

* Enforce the disjointness of the three JWE header locations that RFC 7516 section 7.2.1 requires: the protected, shared unprotected and per-recipient header member names are checked per recipient, on import and on encryption. A repeated name was accepted and resolved by precedence, so an unauthenticated copy overrode the integrity-protected one, which for "alg" is the shape of an algorithm confusion bug (#188)
* Validate the headers a JWE leaves the encryption with, after every recipient has been encrypted to, so cjose_jwe_encrypt* cannot return a JWE that cjose_jwe_import* refuses (#188)
* Refuse a header parameter the algorithm produces itself when the caller supplies it, wherever it sits: "iv" and "tag" for the AES GCM key wrapping algorithms, "epk" for ECDH-ES and "p2s" for PBES2. 0.8.0 silently replaced an "epk" in the protected header with the generated one and left one in the shared or a per-recipient header standing beside it (#185, #188)
* Refuse an "epk" that names a private member at all, whatever its value: RFC 7518 section 4.6.1.1 gives the header the public key parameters of the ephemeral key and nothing else (#186)
* Refuse an RSA JWK whose private member "d", "p", "q", "dp", "dq" or "qi" is present but carries no usable value, an empty string, null, base64url padding only or a value that is zero. The first three were reported the same way an absent member is, so the key imported as a public one; a zero value imported as a private key whose export cjose could not read back (#189, #192, #193)
* Refuse an EC JWK whose "d" is present but carries no usable value instead of reading it as a public key, the rule the RSA members above follow (RFC 7518 section 6.2.2) (#186)
* Refuse an RSA JWK that carries "oth": only two-prime keys are supported, and RFC 7518 section 6.3.2.7 requires a consumer that does not support multi-prime keys not to use such a key, which was silently read as a two-prime key (#190)
* cjose_jwe_decrypt with a NULL cjose_err dereferenced it when decrypting with ECDH-ES+A128KW, ECDH-ES+A192KW or ECDH-ES+A256KW; the trailing cjose_err of the public API may be NULL (#191)

### Compatibility

Beside the "crit" refusal above, these rules refuse JOSE input or calls that 0.8.0 accepted. The disjointness rule refuses a JWE that repeats a member name across two header locations, including a repetition that carries no risk such as "kid", on import and on encryption. Supplying an "epk" of your own to an ECDH-ES encryption is refused rather than overwritten, as is an "iv", "tag" or "p2s" for the algorithms this release adds. An "epk" that names a private member is refused on decryption. An RSA or EC JWK whose private members are present but valueless no longer imports, and neither does an RSA JWK that carries "oth".

<a name="0.8.1"></a>
## [0.8.1](https://github.com/cisco/cjose/0.8.0..0.8.1)  (2026-09-14)

Maintenance release for the 0.8 line, which keeps the OpenSSL 1.0.1 floor, the
autotools build and the libcjose.so.0 ABI. Fixes only, backported from the 1.0
development line.

### Fix

* cjose_jwe_decrypt and cjose_jwe_decrypt_multi no longer dereference a NULL cjose_err when the JWE uses ECDH-ES+A128KW, ECDH-ES+A192KW or ECDH-ES+A256KW; the trailing err argument is optional throughout the public API and decrypting such a JWE with a NULL one crashed ([37adbd938b917de27654b022efa9a78fa6fbdc2d](https://github.com/cisco/cjose/commit/37adbd938b917de27654b022efa9a78fa6fbdc2d))
* An RSA JWK whose "d", "p", "q", "dp", "dq" or "qi" is present but carries no usable value is refused instead of being read as a public key. That covers an empty string, a JSON null, base64url padding on its own, and a value whose octets are all zero; the last of these imported as a private key whose export cjose could not read back ([62bfc486e97a81d7481abf1604282de2074690f5](https://github.com/cisco/cjose/commit/62bfc486e97a81d7481abf1604282de2074690f5), [65ea237a0842128b2b6898849691500cb7f4acd6](https://github.com/cisco/cjose/commit/65ea237a0842128b2b6898849691500cb7f4acd6), [58ca7d2990e368d9f593f83bba34ce88dbc1134b](https://github.com/cisco/cjose/commit/58ca7d2990e368d9f593f83bba34ce88dbc1134b))
* An RSA JWK carrying "oth", a multi-prime key, is refused rather than silently used as if it had two primes ([ee14037f5c58c9cda0ea4080d1052aacce37aa88](https://github.com/cisco/cjose/commit/ee14037f5c58c9cda0ea4080d1052aacce37aa88))
* The "epk" header of an ECDH-ES JWE is refused when it carries a private member, as RFC 7518 section 4.6.1.1 allows public key parameters only ([4aaa2d5dc565c9a01d4d4a6062068346fd8282b4](https://github.com/cisco/cjose/commit/4aaa2d5dc565c9a01d4d4a6062068346fd8282b4))
* An EC JWK whose "d" is present but carries no usable value is refused instead of being read as a public key, the same rule the RSA members above follow (RFC 7518 section 6.2.2; [f18ae38f41a132dbd7de863998e0d57419593c49](https://github.com/cisco/cjose/commit/f18ae38f41a132dbd7de863998e0d57419593c49))
* Supplying your own "epk" to an ECDH-ES encryption is refused wherever it sits, including the protected header. The check looked the parameter up as a string, and "epk" is a JSON object, so it never saw one there ([5e6d8ca1830778b831af3115d375c194ea67b936](https://github.com/cisco/cjose/commit/5e6d8ca1830778b831af3115d375c194ea67b936))
* The member names of the JWE protected header, the shared unprotected header and a per-recipient unprotected header must be disjoint, as RFC 7516 section 7.2.1 requires. They were not checked, and a name is resolved per-recipient first, so a JWE that repeated one had the copy that the content encryption does not authenticate win: a protected "alg" could be shadowed by a per-recipient one ([4aaa2d5dc565c9a01d4d4a6062068346fd8282b4](https://github.com/cisco/cjose/commit/4aaa2d5dc565c9a01d4d4a6062068346fd8282b4), [874606d203df55bab2583bfbd4e68a797d640623](https://github.com/cisco/cjose/commit/874606d203df55bab2583bfbd4e68a797d640623))
* Out-of-tree autotools builds can compile the test binary again; test/Makefile.am passed only the build directory include path ([874606d203df55bab2583bfbd4e68a797d640623](https://github.com/cisco/cjose/commit/874606d203df55bab2583bfbd4e68a797d640623))

### Compatibility

The disjointness rule refuses JOSE input that 0.8.0 accepted, including repetitions of a name that carries no risk, such as "kid". Producing such a JWE is refused as well, and so is supplying an "epk" of your own to an ECDH-ES encryption, which the key agreement overwrote in any case.

Three smaller changes follow from validating the shared unprotected header at encryption time, which 0.8.0 did not do; it validated the per-recipient header twice instead. cjose_jwe_encrypt_multi now refuses a "crit" the shared unprotected header carries and cannot process, which import already refused on 0.8.0; it now accepts an "alg" supplied only in that header, where 0.8.0 required it in the protected or per-recipient one; and a JWK whose EC "d" is present but valueless no longer imports.

Nothing else changes for a caller: no API, no ABI, no algorithm, and no build requirement.

<a name="0.8.0"></a>
## [0.8.0](https://github.com/cisco/cjose/0.7.0..0.8.0)  (2026-09-12)

### Update

* Add the RSA-OAEP-256 key encryption algorithm of RFC 7518 section 4.3 (RSAES OAEP using SHA-256 and MGF1 with SHA-256); needs OpenSSL 1.0.2 ([ce4a3cdab77fbf3979022f587808c5d9385fd5e2](https://github.com/cisco/cjose/commit/ce4a3cdab77fbf3979022f587808c5d9385fd5e2))
* Add the Octet Key Pair (OKP) JWK type of RFC 8037 holding an Ed25519 or Ed448 signature key (RFC 8032) or an X25519 or X448 key agreement key (RFC 7748): cjose_jwk_create_OKP_random, cjose_jwk_create_OKP_spec, cjose_jwk_OKP_get_curve and import/export; needs OpenSSL 1.1.1 ([f2e1d47332de409490a6dcaf888f3432d97ee856](https://github.com/cisco/cjose/commit/f2e1d47332de409490a6dcaf888f3432d97ee856))
* Add the fully-specified EdDSA JWS signing algorithms Ed25519 and Ed448 of RFC 9864 over OKP keys; the polymorphic "EdDSA" identifier of RFC 8037, which RFC 9864 deprecates, is not supported ([f2e1d47332de409490a6dcaf888f3432d97ee856](https://github.com/cisco/cjose/commit/f2e1d47332de409490a6dcaf888f3432d97ee856))
* Add ES256K JWS signing and verification with secp256k1 EC keys ([c4e53e480e95d404dc000a2ce2605dc09f3d812c](https://github.com/cisco/cjose/commit/c4e53e480e95d404dc000a2ce2605dc09f3d812c))

### Fix

* Check the key type before the HMAC digest step: cjose_jws_sign with an HS256, HS384 or HS512 header and an EC or RSA key ran the HMAC over the key structure and past the end of its allocation before failing with CJOSE_ERR_INVALID_ARG ([2c4ba3b395c4a62b880d34c704c5bce9974dc7f0](https://github.com/cisco/cjose/commit/2c4ba3b395c4a62b880d34c704c5bce9974dc7f0))

<a name="0.7.0"></a>
## [0.7.0](https://github.com/cisco/cjose/0.6.3..0.7.0)  (2026-09-09)

### Update

* Add cjose_jwe_encrypt_iv and cjose_jwe_encrypt_multi_iv for a caller-supplied IV ([7edf9d1c4d39f1826794d12d757510a9a2b959f8](https://github.com/cisco/cjose/commit/7edf9d1c4d39f1826794d12d757510a9a2b959f8))
* Compact JWS protected header, stable key order, scalar raw header values ([81a77af47dc16cbc19649f9f03482907bb4e51f9](https://github.com/cisco/cjose/commit/81a77af47dc16cbc19649f9f03482907bb4e51f9))
* Add A128GCM and A192GCM content encryption ([26935516d61cc23bc3684a9fbba90d88159b5126](https://github.com/cisco/cjose/commit/26935516d61cc23bc3684a9fbba90d88159b5126))
* Make RSA1_5 (RSAES-PKCS1-v1_5) key encryption a build-time opt-in, off by default ([8819d3a26ed96765956c3fc009a7ce8c0f188352](https://github.com/cisco/cjose/commit/8819d3a26ed96765956c3fc009a7ce8c0f188352))

### Fix

* Drop the meaningless const from cjose_jwk_EC_get_curve, fix doc contracts ([5242c55c6f52a34268bb6eb643fe7c7455d534c1](https://github.com/cisco/cjose/commit/5242c55c6f52a34268bb6eb643fe7c7455d534c1))
* Cleanup warnings about \param lines in header files ([6a25846d42a408936d6b2abdc039c43706b7fc55](https://github.com/cisco/cjose/commit/6a25846d42a408936d6b2abdc039c43706b7fc55))

<a name="0.6.3"></a>
## [0.6.3](https://github.com/cisco/cjose/0.6.1..0.6.3)  (2026-09-09)

### Update

* Adding an optional salt parameter to cjose_jwk_derive_ecdh_ephemeral_key ([cb36fb8672c27a6d860463436c16bb40cf479793a](https://github.com/cisco/cjose/commit/cb36fb8672c27a6d860463436c16bb40cf479793a))
* Convert public API const char* strings to defines ([a56f3ed2410f295a2f4b6cd3cc76499903ca4136](https://github.com/cisco/cjose/commit/a56f3ed2410f295a2f4b6cd3cc76499903ca4136))
* Migrate the project to CMake ([aa73b48590e82d14a016a628215b2643a92dffbb](https://github.com/cisco/cjose/commit/aa73b48590e82d14a016a628215b2643a92dffbb))

### Fix

* Memory leak cisco/cjose#72; thanks @BilalChughtai ([425dfcfd4a84f646564f69afbbd46e900caa21e9](https://github.com/cisco/cjose/commit/425dfcfd4a84f646564f69afbbd46e900caa21e9))
* Compilation error on Windows in src/concatkdf.c ([254ab05e04cc32d866712bea838990eb4011cbf5](https://github.com/cisco/cjose/commit/254ab05e04cc32d866712bea838990eb4011cbf5))
* Concatkdf failures on big endian architectures ([46d238b7873344c9fa47aa7ede5ee09f9edfcfa4](https://github.com/cisco/cjose/commit/46d238b7873344c9fa47aa7ede5ee09f9edfcfa4))
* Changing error code to CJOSE_ERR_CRYPTO, this error condition is not based on user input. ([0f30d87551f404e275ec3145b87e147c33859d1d](https://github.com/cisco/cjose/commit/0f30d87551f404e275ec3145b87e147c33859d1d))
* Replace calls to free with cjose_get_dealloc() in _cjose_jws_build_hdr ([877a8fa5d4a8e927982a2b31b96eec86dc188e43](https://github.com/cisco/cjose/commit/877a8fa5d4a8e927982a2b31b96eec86dc188e43))
* JWS import allocation handling ([f12e1c5a7a6e45a739761dfc6a087e59c69cb2b7](https://github.com/cisco/cjose/commit/f12e1c5a7a6e45a739761dfc6a087e59c69cb2b7))
* Validate EC inputs before key agreement ([7881496689be3f9974a1db8798df72be42fba656](https://github.com/cisco/cjose/commit/7881496689be3f9974a1db8798df72be42fba656))
* Use OpenSSL constant-time comparisons ([e3113b5db8f1800b2f5ba7b55436d484fa77cf5e](https://github.com/cisco/cjose/commit/e3113b5db8f1800b2f5ba7b55436d484fa77cf5e))
* Guard JWE buffer length calculations ([87537b63401c46b74894b94127cf4ee4a09977db](https://github.com/cisco/cjose/commit/87537b63401c46b74894b94127cf4ee4a09977db))
* Cleanse sensitive buffers before release ([f4106a7b35157183b9e0ed35556b1906dd010c03](https://github.com/cisco/cjose/commit/f4106a7b35157183b9e0ed35556b1906dd010c03))
* Validate critical JOSE headers ([1daa23d0695341e029332c8eed6fa377f98b0a51](https://github.com/cisco/cjose/commit/1daa23d0695341e029332c8eed6fa377f98b0a51))
* Check JOSE algorithms against key types ([1ecb1453661bfacbf4016a7b63a4fe0aee1ea844](https://github.com/cisco/cjose/commit/1ecb1453661bfacbf4016a7b63a4fe0aee1ea844))
* Enforce JOSE IV lengths ([bb9ef93a60a5e08b3279e7bde5ac75e67d2f8278](https://github.com/cisco/cjose/commit/bb9ef93a60a5e08b3279e7bde5ac75e67d2f8278))
* Guard JWK retain count overflow ([b0c9a10ba18463b2d82af59aef41408275597575](https://github.com/cisco/cjose/commit/b0c9a10ba18463b2d82af59aef41408275597575))
* Check base64 decode length bounds ([f4d65be257efa9da032008bc3a1263ff6cb8fe72](https://github.com/cisco/cjose/commit/f4d65be257efa9da032008bc3a1263ff6cb8fe72))
* Check ECDH secret allocation result ([b87064a0f3af83d07c72b8f9a4822f911c611d2b](https://github.com/cisco/cjose/commit/b87064a0f3af83d07c72b8f9a4822f911c611d2b))
* JWE all-zero CEK for AES-CBC-HMAC content encryption ([3b649939c3db4ac6a7eab48034ea9285ef8ff954](https://github.com/cisco/cjose/commit/3b649939c3db4ac6a7eab48034ea9285ef8ff954))
* Use fixed authentication tag length of 16 octets in AES GCM decryption ([24c690e5a05f6a94d7890bae846b821c6cb3a5f1](https://github.com/cisco/cjose/commit/24c690e5a05f6a94d7890bae846b821c6cb3a5f1))
* Heap buffer overflow in AES key unwrap ([f1c3d68f952766e248dd33531aaa9f1b64f986fe](https://github.com/cisco/cjose/commit/f1c3d68f952766e248dd33531aaa9f1b64f986fe))
* Enforce minimum HMAC key length (RFC 7518 section 3.2) ([990f9742a03acf4025d6f8e4c28653007d619a4a](https://github.com/cisco/cjose/commit/990f9742a03acf4025d6f8e4c28653007d619a4a))
* Out-of-bounds OPENSSL_cleanse(SIZE_MAX) after failed RSA decrypt (remote, pre-auth DoS) ([a9bb847a7d44e0d37bc4c5ebc8924e10e2ff07a7](https://github.com/cisco/cjose/commit/a9bb847a7d44e0d37bc4c5ebc8924e10e2ff07a7))
* Check minimum 2048-bit RSA modulus ([1eab879d92ac3b160fb233a0a34ca009d666d43a](https://github.com/cisco/cjose/commit/1eab879d92ac3b160fb233a0a34ca009d666d43a))
* Return correct OOM error ([0fc852d5e2d48ea3ed331fdc985f96acdbf726ab](https://github.com/cisco/cjose/commit/0fc852d5e2d48ea3ed331fdc985f96acdbf726ab))
* Windows build ([1f2953f71ac2f428ebac9cb580861c6c81a5d5af](https://github.com/cisco/cjose/commit/1f2953f71ac2f428ebac9cb580861c6c81a5d5af))
* Warnings (part 1) ([d99913100324939277eabd3ec2164543fcad6323](https://github.com/cisco/cjose/commit/d99913100324939277eabd3ec2164543fcad6323))
* Restore ABI compatibility ([42e079f6d4d4ddfbd11839001893b3250889200a](https://github.com/cisco/cjose/commit/42e079f6d4d4ddfbd11839001893b3250889200a))
* Bounds-check the encode size and replace decode asserts with error returns ([ea627716da0966bc25fb61f9ad676c4bb50530c4](https://github.com/cisco/cjose/commit/ea627716da0966bc25fb61f9ad676c4bb50530c4))
* Heap-allocate and wipe the per-block digest, fix the remaining-bytes underflow ([6f39e5bd54a0979d06e3bd8f111c8c40be8e7ed2](https://github.com/cisco/cjose/commit/6f39e5bd54a0979d06e3bd8f111c8c40be8e7ed2))
* Leaks, NULL dereferences and undefined behaviour on the JWE paths ([5182a7035c7c89ddcb17ec37035847a28bbdda0b](https://github.com/cisco/cjose/commit/5182a7035c7c89ddcb17ec37035847a28bbdda0b))
* Leaks and error handling on import/export, validate the ECDSA signature length ([dc4d28c6f5a0dc1c9a4891f3516b69b9dd104376](https://github.com/cisco/cjose/commit/dc4d28c6f5a0dc1c9a4891f3516b69b9dd104376))
* Leaks and unchecked results in RSA/EC key handling, wipe private key material ([3c73e7f466e65daa134d6dac72c6829ec921fea3](https://github.com/cisco/cjose/commit/3c73e7f466e65daa134d6dac72c6829ec921fea3))
* Bounds-check cjose_err_message, check json_object_set_new, reject an empty crit list ([128a2d2cb7567dcb49089d649d56c706e5334359](https://github.com/cisco/cjose/commit/128a2d2cb7567dcb49089d649d56c706e5334359))
* Parse the shared "unprotected" header in cjose_jwe_import_json ([37d0ef881596fe91b0983e380588c1756e3daf92](https://github.com/cisco/cjose/commit/37d0ef881596fe91b0983e380588c1756e3daf92))
* Pin the RSA-unwrapped CEK to the enc key size and validate the encrypted key segment ([e007f5fdec11703fc9eca10ccab6ef877ecab063](https://github.com/cisco/cjose/commit/e007f5fdec11703fc9eca10ccab6ef877ecab063))

### Build

* Apply clang-format ([f244a85884eb39165bfcb1a91696198c6519128a](https://github.com/cisco/cjose/commit/f244a85884eb39165bfcb1a91696198c6519128a))
* Update function prototypes for current toolchains ([51e8a23a79c13c1ebcf2d2f47eeb5e760344b881](https://github.com/cisco/cjose/commit/51e8a23a79c13c1ebcf2d2f47eeb5e760344b881))
* Define OPENSSL_API_COMPAT=0x10100000L in the default CFLAGS so OpenSSL 3 deprecation warnings for legacy RSA APIs do not fail the build under -Werror. ([4cdd7e2f45ffd9cc9539ec01d796f1ac8c017015](https://github.com/cisco/cjose/commit/4cdd7e2f45ffd9cc9539ec01d796f1ac8c017015))
* Update README.md ([838444e1906dc3d86b8f1584b6b67eb92f62e642](https://github.com/cisco/cjose/commit/838444e1906dc3d86b8f1584b6b67eb92f62e642))
* Remove the FILE_SET API usage ([20a5b2de1b3333665fcf7ddc6ceb5c2bc8ab1461](https://github.com/cisco/cjose/commit/20a5b2de1b3333665fcf7ddc6ceb5c2bc8ab1461))
* Enable tests run on macOS ([52a531983afe4cda470281ac8695aca058d256b1](https://github.com/cisco/cjose/commit/52a531983afe4cda470281ac8695aca058d256b1))
* Small update to README.md to have better printing of the tests results ([dbd8dc11bdb0985838a9753f6175bea3ce06747c](https://github.com/cisco/cjose/commit/dbd8dc11bdb0985838a9753f6175bea3ce06747c))
* Fix out-of-tree builds, add -no-undefined for Cygwin, set ACLOCAL_AMFLAGS ([a94501c182ac38189f0e214b40ed819799106c26](https://github.com/cisco/cjose/commit/a94501c182ac38189f0e214b40ed819799106c26))
* Restore removed test due to merge conflict in #150 ([bc93eb6252d9d484f51519255dbf021456a32559](https://github.com/cisco/cjose/commit/bc93eb6252d9d484f51519255dbf021456a32559))

<a name="0.6.1"></a>
## [0.6.1](https://github.com/cisco/cjose/0.6.0..0.6.1)  (2018-04-12)

### Update

* Better support for AES-CBC-HMAC with other key management algs ([602555ff3fbd34e875bf0e7b88f4d94dc6000e8b](https://github.com/cisco/cjose/commit/602555ff3fbd34e875bf0e7b88f4d94dc6000e8b))

### Fix

* Explicit defined() usage for CJOSE_OPENSSL_11X ([b6665deae2aec3b68d88edb293b1f6c137e624ce](https://github.com/cisco/cjose/commit/b6665deae2aec3b68d88edb293b1f6c137e624ce))
* Bad JWE crashes _cjose_jwe_set_cek_a256gcm ([fb24d6f264fd83d0228a65c2f06e27dba2495ceb](https://github.com/cisco/cjose/commit/fb24d6f264fd83d0228a65c2f06e27dba2495ceb))

<a name="0.6.0"></a>
## [0.6.0](https://github.com/cisco/cjose/0.5.1..0.6.0)  (2018-02-06)

### Update

* support ECDH-ES  ([1250eff10fa178937aea1924887d114c8ba943c2](https://github.com/cisco/cjose/commit/1250eff10fa178937aea1924887d114c8ba943c2))
* compile with LibreSSL  ([8693c22aabf31313a4002838e124e93879bbb50b](https://github.com/cisco/cjose/commit/8693c22aabf31313a4002838e124e93879bbb50b))
* Support multiple recipients and JSON serialization for JWE  ([e569ee824fd5af8654fb0054952f6c7b9d038ce6](https://github.com/cisco/cjose/commit/e569ee824fd5af8654fb0054952f6c7b9d038ce6))


<a name="0.5.1"></a>
## [0.5.1](https://github.com/cisco/cjose/0.5.0..0.5.1) (2017-05-24)

### Fix

* Crash on non string "alg" ([b5daeb66ad603d40da8c7250d9121ef4cc8060c2](https://github.com/cisco/cjose/commit/b5daeb66ad603d40da8c7250d9121ef4cc8060c2))


<a name="0.5.0"></a>
## [0.5.0](https://github.com/cisco/cjose/0.4.1..0.5.0) (2017-05-05)

### Update

* Unexpected release of JWS resources on failure but not success ([ed3cb39cf2fdaf401fbba9b93fd44e6a50b97f62](https://github.com/cisco/cjose/commit/ed3cb39cf2fdaf401fbba9b93fd44e6a50b97f62))

### Fix

* Bad casting of pointers ([5b7ac9a6dfd08aead145dcef7a46bbc52ffb68de](https://github.com/cisco/cjose/commit/5b7ac9a6dfd08aead145dcef7a46bbc52ffb68de))

### Build
* Support for clang-format ([7d0f5566dff5258f4babb1e843715fcec3b03cbe](https://github.com/cisco/cjose/commit/7d0f5566dff5258f4babb1e843715fcec3b03cbe))
* Improve alloc/realloc/dealloc tests ([f02e19c99de9e7b2621c56f6a88cb2b9eb91e954](https://github.com/cisco/cjose/commit/f02e19c99de9e7b2621c56f6a88cb2b9eb91e954))

<a name="0.4.1"></a>
## [0.4.1](https://github.com/cisco/cjose/0.4.0..0.4.1) (2016-08-04)

### Build

* Compiler warning/error fixes for multiple platforms ([011612e72698dd02249f578fb4ec0145c624c0e0](https://github.com/cisco/cjose/commit/011612e72698dd02249f578fb4ec0145c624c0e0))


<a name="0.4.0"></a>
## [0.4.0](https://github.com/cisco/cjose/compare/0.3.0...0.4.0) (2016-08-02)

### Update

* Support OpenSSL 1.1.x ([9bc8a801a5160952787d4ed2fdc225eb57d471a5](https://github.com/cisco/cjose/commit/9bc8a801a5160952787d4ed2fdc225eb57d471a5))
* Support AES KeyWrap and AES-CBC-HMAC-SHA2 ([b7518799842e1b411d7b900ef8879f51c65584ee](https://github.com/cisco/cjose/commit/b7518799842e1b411d7b900ef8879f51c65584ee))
* Support Elliptic Curve JWS Algorithms (ES256 / ES384 / ES512) ([8206eebb1c69521a90601a3f37f8f1693fb4ec4f](https://github.com/cisco/cjose/commit/8206eebb1c69521a90601a3f37f8f1693fb4ec4f))
* Support RSAES-PKCS1-v1_5 key encryption ([76ae28a299cf207d4373cfd95cd299b6af0cc248](https://github.com/cisco/cjose/commit/76ae28a299cf207d4373cfd95cd299b6af0cc248))
* Support symmetric HMAC "signatures" ([f43f17dd0ff6b513d02db075c728f08031051e43](https://github.com/cisco/cjose/commit/f43f17dd0ff6b513d02db075c728f08031051e43))
* Support unsecured JWS (**IMPORT ONLY**) ([8512cf3a45bea90bbbba2d55c083d3f08ccd25f6](https://github.com/cisco/cjose/commit/8512cf3a45bea90bbbba2d55c083d3f08ccd25f6))
* Support older versions of Jansson ([d9d3d43df91264a59e94eaefd0f7068e2249cbde](https://github.com/cisco/cjose/commit/d9d3d43df91264a59e94eaefd0f7068e2249cbde))

### Fix

* RS256 verify always returned true ([c177b707a4877406bf93f35171bdc8d7f0b74d33](https://github.com/cisco/cjose/commit/c177b707a4877406bf93f35171bdc8d7f0b74d33))
* Replace free() with dealloc() ([8361f3827622232b1d8fa944b4bc3a3938bb9fd6](https://github.com/cisco/cjose/commit/8361f3827622232b1d8fa944b4bc3a3938bb9fd6))
* Remove the use of strdup ([e968f21e6d1ae4bf499e0dd4e8fd628efcada607](https://github.com/cisco/cjose/commit/e968f21e6d1ae4bf499e0dd4e8fd628efcada607))


### Build

* Use CJOSE_VERSION everywhere ([2c58aa1de96f883c23626b05527754c0c7590079](https://github.com/cisco/cjose/commit/2c58aa1de96f883c23626b05527754c0c7590079))
* Use cjose_err.code instead of errno ([5f40fef38725d375f204a16a79beae754d58fc76](https://github.com/cisco/cjose/commit/5f40fef38725d375f204a16a79beae754d58fc76))


<a name="0.3.0"></a>
## [0.3.0](https://github.com/linuxwolf/cjose/compare/0.2.0...0.3.0) (2016-05-26)


### Update

* expose more key information ([16cf34901bbff6791c20aa831c34660e510cc9ee](https://github.com/cisco/cjose/commit/16cf34901bbff6791c20aa831c34660e510cc9ee))

### Fix

* missing 'util.h' in superheader ([02593fb83991651570ec50dd35d89fb4e747ec71](https://github.com/cisco/cjose/commit/02593fb83991651570ec50dd35d89fb4e747ec71))



<a name="0.2.0"></a>
## [0.2.0](https://github.com/cisco/cjose/compare/0.1.2...0.2.0) (2016-05-06)


### Update

* Expose protected header from imported/created JWE and JWS ([6d1d1be838b546cb73f8d24c42a681a0a0e1ec03](https://github.com/cisco/cjose/commit/6d1d1be838b546cb73f8d24c42a681a0a0e1ec03))

### Fix

* incorrect repo in doc ([642e5896798ac84e7035cd489dd12273b914f829](https://github.com/cisco/cjose/commit/642e5896798ac84e7035cd489dd12273b914f829))

### Build

* friendlier dist ([fdff0a6b1f2d94f896b6416471b7f159d143ce06](https://github.com/cisco/cjose/commit/fdff0a6b1f2d94f896b6416471b7f159d143ce06))
* Use RFC6090 Fundamental EC if present ([436264fd83adb536e827f633a47fc023760b27d1](https://github.com/cisco/cjose/commit/436264fd83adb536e827f633a47fc023760b27d1))


<a name="0.1.2"></a>
## 0.1.2 (2016-03-15)

Initial public release
