# Release Notes #

<a name=""></a>
## [0.6.0](https://github.com/cisco/cjose/0.5.1..0.6.0)  (2018-02-06)

### Update

* support ECDH-ES  ([1250eff10fa178937aea1924887d114c8ba943c2](https://github.com/linuxwolf/cjose/commit/1250eff10fa178937aea1924887d114c8ba943c2))
* compile with LibreSSL  ([8693c22aabf31313a4002838e124e93879bbb50b](https://github.com/linuxwolf/cjose/commit/8693c22aabf31313a4002838e124e93879bbb50b))
* Support multiple recipients and JSON serialization for JWE  ([e569ee824fd5af8654fb0054952f6c7b9d038ce6](https://github.com/linuxwolf/cjose/commit/e569ee824fd5af8654fb0054952f6c7b9d038ce6))


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
