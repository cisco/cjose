/*!
 *
 */

#include "check_cjose.h"

#include <stdlib.h>
#include <openssl/evp.h>
#include <check.h>
#include <cjose/jwk.h>
#include <cjose/base64.h>
#include <cjose/util.h>
#include "include/jwk_int.h"

/**
 * Convenience function for comparing multiple string attributes of two
 * json objects.
 * 
 * \param left_json a json object to be compared.
 * \param right_json a json object to be compared.
 * \param null terminated array of attribute names.
 * \returns true if string values of all named attributes are identical in both
 *         json objects or are both missing from each, false otherwise.
 */
static bool _match_string_attrs(
        json_t *left_json, json_t *right_json, const char **attrs)
{
    for (int i = 0; NULL != attrs[i]; ++i)
    {
        const char *left_attr_str = NULL;
        json_t *left_attr_json = NULL;
        left_attr_json = json_object_get(left_json, attrs[i]);
        if (NULL != left_attr_json)
        {
            left_attr_str = json_string_value(left_attr_json);
        }

        const char *right_attr_str = NULL;
        json_t *right_attr_json = json_object_get(right_json, attrs[i]);
        if (NULL != right_attr_json)
        {
            right_attr_str = json_string_value(right_attr_json);
        }

        // return false if strings don't match (consider NULL==NULL a match)
        if ((left_attr_str != right_attr_str) &&
                (left_attr_str == NULL || right_attr_str == NULL || 
                strcmp(left_attr_str, right_attr_str) != 0))
        {
            return false;
        }
    }
    return true;
}

START_TEST(test_cjose_jwk_name_for_kty)
{
    cjose_err err;
    ck_assert_str_eq("RSA", cjose_jwk_name_for_kty(CJOSE_JWK_KTY_RSA, &err));
    ck_assert_str_eq("EC", cjose_jwk_name_for_kty(CJOSE_JWK_KTY_EC, &err));
    ck_assert_str_eq("oct", cjose_jwk_name_for_kty(CJOSE_JWK_KTY_OCT, &err));
    ck_assert(NULL == cjose_jwk_name_for_kty(0, &err));
    ck_assert(NULL == cjose_jwk_name_for_kty(99, &err));
}
END_TEST

const char * RSA_e = "AQAB";
const char * RSA_n = "2Rgbvu_cGMpvVl8DE6aGGX7IE2lKn5c9ZtexriFrCLqBbKt2TBOZkoCn_AbcDjUVk23CxsIj9Z1VfsL_0UeVA_AeOLUWw0F5-JhoK6NBeLpYZOz7HYieTOSJjSxYhoCYtVbLKI27e3NEvckxTs-90CdKl71P7YwrdSrY59hR-u2etyNCRGAPcoDH5xYJxrG2p5FH_Dh_MQ0ugDnJY2_b_-w9NS2Y2atIkzXZDjtcSpjImKpL0eIFF69ptiF8vd4q2j-ougipFBGP9U5bSVzeZ7FyGkJ5Qa2DYc0osYi1QFs3YZKzkKfcblx14u-yZYhUkZHlb_jbfulnUHxDdO_r8Q";
const char * RSA_d = "P9N6tNRIXXGG8lnUyb43xt8ja7GVIv6QKuBXeN6SXWqYCp8OlKdei1gQC2To5bRtt36ZuV3yvI-ZRz-Ffr4Q7at29y0mmBl0BsaoOcwxv5Dp1CJoYfJ8uBao6jyTelfsjcQKzs18xXrKRxIT0Rv6rmwe3iXmjeycCkKiqudKkv8m9RtbvdWH8AFd2ZsCLNblVRrOZ9ZPQQCMVJLf65pF_cBfux-Zz_CJCfq93gFcN3h1tPFLX8UPBMqvqkBZzDx8PGoYgrydz-T8tcqtkDriyEL3mGYe9b2uH_8JnzMMNMFheVPDdNBhyQQVOmQqPj7idv7677eSle4LJZANUYZdwQ";
const char * RSA_p = "8Yhaq4UMiFptSuUMcLUqOJdZ9Jr0z2KG_ZrPaaHIX8gfbtp5DGjhXEE--SwoX9ukEzR6vCewSFcEl20wnT0uTwrVs-Bf2J1L-5tKKeiiwLQxXtk1cG5-PI-ECkqX0AP2K2Xa0wpIjldBE5SBR0S7whANpKxhVFMtNgKog4xNvxU"; 
const char * RSA_q = "5hkENNaWQSJ5qWXVJYh0LAHddr1NXwkKIfKNjK8vCYfOHXDgKxW4UbAIu7wIU9iZcVjTdN2UcaJMe5fBQR9ZEP8bcuY9ZpeUCkv-g9IGw69HUXE7ERBz1es_lZOuJzENwL85Al7jOtVJ2y26g4r30q4jqaL7CcgUZjBKAytjUG0";
const char * RSA_dp = "pAn1epQsRNcVb05Muqdv-2tfnu824TqLb-YahCVqjxK9tm4O1EzO8fcmK9i_uwrTTm_QA8X4xcjDx4xS_he1Qd2b8kSrE9UQ69s17WygTLyU41QmJSwF9F-MT-kFXjOylxrgGYDccj_0ZLXxb1PRKSX5_iNNHxY2mH4JsP4zN1k";
const char * RSA_dq = "gTTxAL6y9vZl_PKa4w2htoiBlMiuJryLvQ5X3_ULY72nxy54Ipl6vBwue0UWJAcP-u8XJpu6XKj3a7uGoIv61ql5_2Y8elyJm9Kao-kPNVk6oggEVAu6EBiext57v7Qy9dYrLCKeVI4qf_JIts8VZG-2xO4pK4_3rH5XQTpe9W0";
const char * RSA_qi = "xTJ_ON_6kc9g3ZbunSSt_oqJBguxH2x8HVl2KQXafW-F0_DOv09P1e0fbSdOLhR-V9lLjq8DxOcvCMxkpQr2G8lTaBRVTF_-szu9adi9bgb_-egvc_NAvRkuGE9fUmB2_nAyU-j4VUh1MMSP5qqQhMYvFdAF5y36MpI-pV1SLFQ";
START_TEST (test_cjose_jwk_create_RSA_spec)
{
    cjose_err err;
    cjose_jwk_rsa_keyspec   specPub;
    cjose_jwk_rsa_keyspec   specPriv;

    memset(&specPriv, 0, sizeof(cjose_jwk_rsa_keyspec));
    cjose_base64url_decode(RSA_e, strlen(RSA_e), &specPriv.e, &specPriv.elen, &err);
    cjose_base64url_decode(RSA_n, strlen(RSA_n), &specPriv.n, &specPriv.nlen, &err);
    cjose_base64url_decode(RSA_d, strlen(RSA_d), &specPriv.d, &specPriv.dlen, &err);
    cjose_base64url_decode(RSA_p, strlen(RSA_p), &specPriv.p, &specPriv.plen, &err);
    cjose_base64url_decode(RSA_q, strlen(RSA_q), &specPriv.q, &specPriv.qlen, &err);
    cjose_base64url_decode(RSA_dp, strlen(RSA_dp), &specPriv.dp, &specPriv.dplen, &err);
    cjose_base64url_decode(RSA_dq, strlen(RSA_dq), &specPriv.dq, &specPriv.dqlen, &err);
    cjose_base64url_decode(RSA_qi, strlen(RSA_qi), &specPriv.qi, &specPriv.qilen, &err);

    // everything
    cjose_jwk_t *jwk = NULL;
    jwk = cjose_jwk_create_RSA_spec(&specPriv, &err);
    ck_assert(NULL != jwk);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_RSA == jwk->kty);
    ck_assert(2048 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    cjose_jwk_release(jwk);

    // only private is not possible after the OpenSSL 1.1.x changes because e & n always need to be set

    // minimal private
    cjose_get_dealloc()(specPriv.p);
    specPriv.p = NULL;
    cjose_get_dealloc()(specPriv.q);
    specPriv.q = NULL;
    cjose_get_dealloc()(specPriv.dp);
    specPriv.dp = NULL;
    cjose_get_dealloc()(specPriv.dq);
    specPriv.dq = NULL;
    cjose_get_dealloc()(specPriv.qi);
    specPriv.qi = NULL;
    jwk = cjose_jwk_create_RSA_spec(&specPriv, &err);
    ck_assert(NULL != jwk);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_RSA == jwk->kty);
    ck_assert(2048 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    cjose_jwk_release(jwk);

    cjose_get_dealloc()(specPriv.n);
    specPriv.n = NULL;
    cjose_get_dealloc()(specPriv.d);
    specPriv.d = NULL;
    cjose_get_dealloc()(specPriv.e);
    specPriv.e = NULL;

    // public only
    memset(&specPub, 0, sizeof(cjose_jwk_rsa_keyspec));
    cjose_base64url_decode(RSA_e, strlen(RSA_e), &specPub.e, &specPub.elen, &err);
    cjose_base64url_decode(RSA_n, strlen(RSA_n), &specPub.n, &specPub.nlen, &err);

    jwk = cjose_jwk_create_RSA_spec(&specPub, &err);
    ck_assert(NULL != jwk);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_RSA == jwk->kty);
    ck_assert(2048 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    cjose_jwk_release(jwk);

    cjose_get_dealloc()(specPub.n);
    specPub.n = NULL;
    cjose_get_dealloc()(specPub.e);
    specPub.e = NULL;
}
END_TEST

START_TEST (test_cjose_jwk_create_RSA_random)
{
    cjose_err err;
    cjose_jwk_t     *jwk = NULL;
    uint8_t         *e = NULL;
    size_t          elen = 0;

    e = (uint8_t *)"\x01\x00\x01";
    elen = 3;
    jwk = cjose_jwk_create_RSA_random(2048, e, elen, &err);
    ck_assert(NULL != jwk);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_RSA == jwk->kty);
    ck_assert(2048 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);

    cjose_jwk_release(jwk);

    e = NULL;
    elen = 0;
    jwk = cjose_jwk_create_RSA_random(2048, e, elen, &err);
    ck_assert(NULL != jwk);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_RSA == jwk->kty);
    ck_assert(2048 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);

    cjose_jwk_release(jwk);
}
END_TEST

const char * EC_P256_d = "RSSjcBQW_EBxm1gzYhejCdWtj3Id_GuwldwEgSuKCEM";
const char * EC_P256_x = "ii8jCnvs4FLc0rteSWxanup22pNDhzizmlGN-bfTcFk";
const char * EC_P256_y = "KbkZ7r_DQ-t67pnxPnFDHObTLBqn44BSjcqn0STUkaM";
START_TEST (test_cjose_jwk_create_EC_P256_spec)
{
    cjose_err err;
    cjose_jwk_t             *jwk = NULL;
    cjose_jwk_ec_keyspec    spec;

    memset(&spec, 0, sizeof(cjose_jwk_ec_keyspec));
    spec.crv = CJOSE_JWK_EC_P_256;
    cjose_base64url_decode(EC_P256_d, strlen(EC_P256_d), &spec.d, &spec.dlen, &err);
    cjose_base64url_decode(EC_P256_x, strlen(EC_P256_x), &spec.x, &spec.xlen, &err);
    cjose_base64url_decode(EC_P256_y, strlen(EC_P256_y), &spec.y, &spec.ylen, &err);

    jwk = cjose_jwk_create_EC_spec(&spec, &err);
    ck_assert(NULL != jwk);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    ck_assert(256 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    cjose_get_dealloc()(spec.d);
    cjose_get_dealloc()(spec.x);
    cjose_get_dealloc()(spec.y);

    // cleanup
    cjose_jwk_release(jwk);
}
END_TEST
START_TEST (test_cjose_jwk_create_EC_P256_random)
{
    cjose_err err;
    cjose_jwk_t *   jwk = NULL;

    jwk = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_256, &err);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    ck_assert(256 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);

    // cleanup
    cjose_jwk_release(jwk);
}
END_TEST

const char * EC_384_d = "vpwFfxYfV7Ftm3fuidQsK-l_tGxqqnUUG6R5QZStJAeZy7qQiHAo7rZumFslws38";
const char * EC_384_x = "ulIwcMpG6gbi9Bo_CeVFDIu7RT-AFxu5NRiH9Wm39lYQOAcZTlHJM8Tz4Fwbtu-0";
const char * EC_384_y = "WOZtl6a6x_ukWquJbd_sF18zivwVq26HhJbnmwEKuab7zvZ3sGzOX7LJCHl4zmXa";
START_TEST (test_cjose_jwk_create_EC_P384_spec)
{
    cjose_err err;
    cjose_jwk_t             *jwk = NULL;
    cjose_jwk_ec_keyspec    spec;

    memset(&spec, 0, sizeof(cjose_jwk_ec_keyspec));
    spec.crv = CJOSE_JWK_EC_P_384;
    cjose_base64url_decode(EC_384_d, strlen(EC_384_d), &spec.d, &spec.dlen, &err);
    cjose_base64url_decode(EC_384_x, strlen(EC_384_x), &spec.x, &spec.xlen, &err);
    cjose_base64url_decode(EC_384_y, strlen(EC_384_y), &spec.y, &spec.ylen, &err);

    jwk = cjose_jwk_create_EC_spec(&spec, &err);
    ck_assert(NULL != jwk);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    ck_assert(384 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    cjose_get_dealloc()(spec.d);
    cjose_get_dealloc()(spec.x);
    cjose_get_dealloc()(spec.y);

    // cleanup
    cjose_jwk_release(jwk);
}
END_TEST
START_TEST (test_cjose_jwk_create_EC_P384_random)
{
    cjose_err err;
    cjose_jwk_t *   jwk = NULL;

    jwk = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_384, &err);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    ck_assert(384 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);

    // cleanup
    cjose_jwk_release(jwk);
}
END_TEST

const char * EC_521_d = "E-0dXEk-bh2Fb08ge8_kNCiSSLiWu7zAR-4SVxH_SfqX2vPimGlF8cU-RFxb64zjW599vsULwvE62MzFWtK63Y4";
const char * EC_521_x = "C3LEPuVWTeIQ7KGNibjAdUyHYyapCE6GAQ_oEs7P49yA8AWyJhxIVGWuc1punIsi5WjzHRoNhj0TqEBN4LsW0-g";
const char * EC_521_y = "AeMjLFBhdk-lBiaFc8QKYZYziRIS_8q-3ziwXm5zfREdzVv9GUm-l-APSv4gIq-0-G0oSyFf6j6oh7KTf4aYGTV6";
START_TEST (test_cjose_jwk_create_EC_P521_spec)
{
    cjose_err err;
    cjose_jwk_t             *jwk = NULL;
    cjose_jwk_ec_keyspec    spec;

    memset(&spec, 0, sizeof(cjose_jwk_ec_keyspec));
    spec.crv = CJOSE_JWK_EC_P_521;
    cjose_base64url_decode(EC_521_d, strlen(EC_521_d), &spec.d, &spec.dlen, &err);
    cjose_base64url_decode(EC_521_x, strlen(EC_521_x), &spec.x, &spec.xlen, &err);
    cjose_base64url_decode(EC_521_y, strlen(EC_521_y), &spec.y, &spec.ylen, &err);

    jwk = cjose_jwk_create_EC_spec(&spec, &err);
    ck_assert(NULL != jwk);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    ck_assert(521 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    free(spec.d);
    free(spec.x);
    free(spec.y);

    // cleanup
    cjose_jwk_release(jwk);
}
END_TEST
START_TEST (test_cjose_jwk_create_EC_P521_random)
{
    cjose_err err;
    cjose_jwk_t *   jwk = NULL;

    jwk = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_521, &err);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    ck_assert(521 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);

    // cleanup
    cjose_jwk_release(jwk);
}
END_TEST

const uint8_t *OCT_KEY = "pKE-eSbyFqPdtA5WzazKFg";
START_TEST (test_cjose_jwk_create_oct_spec)
{
    cjose_err err;
    cjose_jwk_t *   jwk = NULL;
    uint8_t *       k = NULL;
    size_t          klen = 0;

    cjose_base64url_decode(OCT_KEY, strlen(OCT_KEY), &k, &klen, &err);

    jwk = cjose_jwk_create_oct_spec(k, klen, &err);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_OCT == jwk->kty);
    ck_assert(klen * 8 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    ck_assert_bin_eq(k, jwk->keydata, klen);
    cjose_get_dealloc()(k);

    // cleanup
    cjose_jwk_release(jwk);
}
END_TEST
START_TEST (test_cjose_jwk_create_oct_random)
{
    cjose_err err;
    cjose_jwk_t *   jwk = NULL;

    jwk = cjose_jwk_create_oct_random(128, &err);
    ck_assert(1 == jwk->retained);
    ck_assert(CJOSE_JWK_KTY_OCT == jwk->kty);
    ck_assert(128 == jwk->keysize);
    ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    ck_assert(NULL != jwk->keydata);
    ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);

    // cleanup
    cjose_jwk_release(jwk);
}
END_TEST
START_TEST (test_cjose_jwk_create_oct_random_inval)
{
    cjose_err err;
    cjose_jwk_t *   jwk = NULL;

    jwk = cjose_jwk_create_oct_random(0, &err);
    ck_assert(NULL == jwk);
    ck_assert(CJOSE_ERR_INVALID_ARG == err.code);
}
END_TEST

START_TEST (test_cjose_jwk_retain_release)
{
    cjose_err err;
    // create some type of key
    cjose_jwk_t *   jwk = cjose_jwk_create_oct_random(128, &err);
    ck_assert(1 == jwk->retained);

    cjose_jwk_t *   retained = NULL;
    retained = cjose_jwk_retain(jwk, &err);
    ck_assert(jwk == retained);
    ck_assert(2 == jwk->retained);

    bool result = false;
    result = cjose_jwk_release(jwk);
    ck_assert(result);
    ck_assert(1 == jwk->retained);

    retained = cjose_jwk_retain(jwk, &err);
    ck_assert(jwk == retained);
    ck_assert(2 == jwk->retained);

    result = cjose_jwk_release(jwk);
    ck_assert(result);
    ck_assert(1 == jwk->retained);

    result = cjose_jwk_release(jwk);
    ck_assert(!result);

    result = cjose_jwk_release(NULL);
    ck_assert(!result);

    retained = cjose_jwk_retain(NULL, &err);
    ck_assert(retained == NULL);
}
END_TEST

START_TEST(test_cjose_jwk_get_kty)
{
    cjose_err err;
    cjose_jwk_t *   jwk = NULL;
    jwk = cjose_jwk_create_oct_random(128, &err);
    ck_assert(CJOSE_JWK_KTY_OCT == cjose_jwk_get_kty(jwk, &err));
    cjose_jwk_release(jwk);

    jwk = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_256, &err);
    ck_assert(CJOSE_JWK_KTY_EC == cjose_jwk_get_kty(jwk, &err));
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jwk_to_json_oct)
{
    cjose_err err;
    cjose_jwk_t *   jwk = NULL;
    uint8_t *       k = NULL;
    size_t          klen = 0;

    cjose_base64url_decode(OCT_KEY, strlen(OCT_KEY), &k, &klen, &err);
    jwk = cjose_jwk_create_oct_spec(k, klen, &err);
    cjose_get_dealloc()(k);

    const char *json;
    json = cjose_jwk_to_json(jwk, false, &err);
    ck_assert(NULL != json);
    ck_assert_str_eq("{\"kty\":\"oct\"}", json);
    free(json);

    json = cjose_jwk_to_json(jwk, true, &err);
    ck_assert(NULL != json);
    ck_assert_str_eq("{\"kty\":\"oct\",\"k\":\"pKE-eSbyFqPdtA5WzazKFg\"}", json);
    free(json);

    cjose_jwk_release(jwk);
}
END_TEST
START_TEST(test_cjose_jwk_to_json_ec)
{
    cjose_err err;
    cjose_jwk_t             *jwk = NULL;
    cjose_jwk_ec_keyspec    spec;

    memset(&spec, 0, sizeof(cjose_jwk_ec_keyspec));
    spec.crv = CJOSE_JWK_EC_P_256;
    cjose_base64url_decode(EC_P256_d, strlen(EC_P256_d), &spec.d, &spec.dlen, &err);
    cjose_base64url_decode(EC_P256_x, strlen(EC_P256_x), &spec.x, &spec.xlen, &err);
    cjose_base64url_decode(EC_P256_y, strlen(EC_P256_y), &spec.y, &spec.ylen, &err);

    jwk = cjose_jwk_create_EC_spec(&spec, &err);
    cjose_get_dealloc()(spec.d);
    cjose_get_dealloc()(spec.x);
    cjose_get_dealloc()(spec.y);

    const char *json;
    json = cjose_jwk_to_json(jwk, false, &err);
    ck_assert(NULL != json);
    ck_assert_str_eq(
            "{\"kty\":\"EC\",\"crv\":\"P-256\"" \
            ",\"x\":\"ii8jCnvs4FLc0rteSWxanup22pNDhzizmlGN-bfTcFk\""
            ",\"y\":\"KbkZ7r_DQ-t67pnxPnFDHObTLBqn44BSjcqn0STUkaM\"}",
            json
    );
    free(json);

    json = cjose_jwk_to_json(jwk, true, &err);
    ck_assert(NULL != json);
    ck_assert_str_eq(
            "{\"kty\":\"EC\",\"crv\":\"P-256\""
            ",\"x\":\"ii8jCnvs4FLc0rteSWxanup22pNDhzizmlGN-bfTcFk\""
            ",\"y\":\"KbkZ7r_DQ-t67pnxPnFDHObTLBqn44BSjcqn0STUkaM\""
            ",\"d\":\"RSSjcBQW_EBxm1gzYhejCdWtj3Id_GuwldwEgSuKCEM\"}",
            json);
    free(json);

    cjose_jwk_release(jwk);
}
END_TEST

const char *RSA_PUBLIC_JSON = "{\"kty\":\"RSA\"," \
    "\"e\":\"AQAB\"" \
    ",\"n\":\"2Rgbvu_cGMpvVl8DE6aGGX7IE2lKn5c9ZtexriFrCLqBbKt2TBOZkoCn_AbcDjUVk23CxsIj9Z1VfsL_0UeVA_AeOLUWw0F5-JhoK6NBeLpYZOz7HYieTOSJjSxYhoCYtVbLKI27e3NEvckxTs-90CdKl71P7YwrdSrY59hR-u2etyNCRGAPcoDH5xYJxrG2p5FH_Dh_MQ0ugDnJY2_b_-w9NS2Y2atIkzXZDjtcSpjImKpL0eIFF69ptiF8vd4q2j-ougipFBGP9U5bSVzeZ7FyGkJ5Qa2DYc0osYi1QFs3YZKzkKfcblx14u-yZYhUkZHlb_jbfulnUHxDdO_r8Q\"" \
    "}";
START_TEST(test_cjose_jwk_to_json_rsa)
{
    cjose_err err;
    cjose_jwk_t             *jwk = NULL;
    cjose_jwk_rsa_keyspec   spec;

    memset(&spec, 0, sizeof(cjose_jwk_rsa_keyspec));
    cjose_base64url_decode(RSA_e, strlen(RSA_e), &spec.e, &spec.elen, &err);
    cjose_base64url_decode(RSA_n, strlen(RSA_n), &spec.n, &spec.nlen, &err);
    cjose_base64url_decode(RSA_d, strlen(RSA_d), &spec.d, &spec.dlen, &err);
    cjose_base64url_decode(RSA_p, strlen(RSA_p), &spec.p, &spec.plen, &err);
    cjose_base64url_decode(RSA_q, strlen(RSA_q), &spec.q, &spec.qlen, &err);
    cjose_base64url_decode(RSA_dp, strlen(RSA_dp), &spec.dp, &spec.dplen, &err);
    cjose_base64url_decode(RSA_dq, strlen(RSA_dq), &spec.dq, &spec.dqlen, &err);
    cjose_base64url_decode(RSA_qi, strlen(RSA_qi), &spec.qi, &spec.qilen, &err);

    jwk = cjose_jwk_create_RSA_spec(&spec, &err);
    cjose_get_dealloc()(spec.e);
    cjose_get_dealloc()(spec.n);
    cjose_get_dealloc()(spec.d);
    cjose_get_dealloc()(spec.p);
    cjose_get_dealloc()(spec.q);
    cjose_get_dealloc()(spec.dp);
    cjose_get_dealloc()(spec.dq);
    cjose_get_dealloc()(spec.qi);

    const char *json;
    json = cjose_jwk_to_json(jwk, false, &err);
    ck_assert(NULL != json);
    ck_assert_str_eq(RSA_PUBLIC_JSON, json);
    free(json);

    json = cjose_jwk_to_json(jwk, true, &err);
    ck_assert(NULL != json);
    ck_assert_str_eq(
            "{\"kty\":\"RSA\",\"e\":\"AQAB\"" \
            ",\"n\":\"2Rgbvu_cGMpvVl8DE6aGGX7IE2lKn5c9ZtexriFrCLqBbKt2TBOZkoCn_AbcDjUVk23CxsIj9Z1VfsL_0UeVA_AeOLUWw0F5-JhoK6NBeLpYZOz7HYieTOSJjSxYhoCYtVbLKI27e3NEvckxTs-90CdKl71P7YwrdSrY59hR-u2etyNCRGAPcoDH5xYJxrG2p5FH_Dh_MQ0ugDnJY2_b_-w9NS2Y2atIkzXZDjtcSpjImKpL0eIFF69ptiF8vd4q2j-ougipFBGP9U5bSVzeZ7FyGkJ5Qa2DYc0osYi1QFs3YZKzkKfcblx14u-yZYhUkZHlb_jbfulnUHxDdO_r8Q\"" \
            ",\"d\":\"P9N6tNRIXXGG8lnUyb43xt8ja7GVIv6QKuBXeN6SXWqYCp8OlKdei1gQC2To5bRtt36ZuV3yvI-ZRz-Ffr4Q7at29y0mmBl0BsaoOcwxv5Dp1CJoYfJ8uBao6jyTelfsjcQKzs18xXrKRxIT0Rv6rmwe3iXmjeycCkKiqudKkv8m9RtbvdWH8AFd2ZsCLNblVRrOZ9ZPQQCMVJLf65pF_cBfux-Zz_CJCfq93gFcN3h1tPFLX8UPBMqvqkBZzDx8PGoYgrydz-T8tcqtkDriyEL3mGYe9b2uH_8JnzMMNMFheVPDdNBhyQQVOmQqPj7idv7677eSle4LJZANUYZdwQ\"" \
            ",\"p\":\"8Yhaq4UMiFptSuUMcLUqOJdZ9Jr0z2KG_ZrPaaHIX8gfbtp5DGjhXEE--SwoX9ukEzR6vCewSFcEl20wnT0uTwrVs-Bf2J1L-5tKKeiiwLQxXtk1cG5-PI-ECkqX0AP2K2Xa0wpIjldBE5SBR0S7whANpKxhVFMtNgKog4xNvxU\"" \
            ",\"q\":\"5hkENNaWQSJ5qWXVJYh0LAHddr1NXwkKIfKNjK8vCYfOHXDgKxW4UbAIu7wIU9iZcVjTdN2UcaJMe5fBQR9ZEP8bcuY9ZpeUCkv-g9IGw69HUXE7ERBz1es_lZOuJzENwL85Al7jOtVJ2y26g4r30q4jqaL7CcgUZjBKAytjUG0\"" \
            ",\"dp\":\"pAn1epQsRNcVb05Muqdv-2tfnu824TqLb-YahCVqjxK9tm4O1EzO8fcmK9i_uwrTTm_QA8X4xcjDx4xS_he1Qd2b8kSrE9UQ69s17WygTLyU41QmJSwF9F-MT-kFXjOylxrgGYDccj_0ZLXxb1PRKSX5_iNNHxY2mH4JsP4zN1k\"" \
            ",\"dq\":\"gTTxAL6y9vZl_PKa4w2htoiBlMiuJryLvQ5X3_ULY72nxy54Ipl6vBwue0UWJAcP-u8XJpu6XKj3a7uGoIv61ql5_2Y8elyJm9Kao-kPNVk6oggEVAu6EBiext57v7Qy9dYrLCKeVI4qf_JIts8VZG-2xO4pK4_3rH5XQTpe9W0\"" \
            ",\"qi\":\"xTJ_ON_6kc9g3ZbunSSt_oqJBguxH2x8HVl2KQXafW-F0_DOv09P1e0fbSdOLhR-V9lLjq8DxOcvCMxkpQr2G8lTaBRVTF_-szu9adi9bgb_-egvc_NAvRkuGE9fUmB2_nAyU-j4VUh1MMSP5qqQhMYvFdAF5y36MpI-pV1SLFQ\"" \
            "}",
            json
    );
    free(json);

    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jwk_import_valid)
{
    cjose_err err;
    static const char *JWK[] = 
    {
        // EC P-256
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"4E34BAFD-E5D9-479C-964D-009C419C38DB\" }",

        // EC P-256, attributes rearranged
        "{ \"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"05A9BE36-CBBD-43F4-ACC2-8C7823B2DE23\", "
        "\"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\"}",

        // EC P-256, no 'kid'
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\"}",

        // EC P-256, empty 'kid'
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"\" }",

        // EC P-256, empty 'kid'
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": null }",

        // EC P-256 with private key 'd'
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"ccXrxIe0aS32y9kBkZFfAh6f7UvdcowtGH5uxCIo7eY\", "
        "\"y\": \"GGQACnDgoiQvdQTsv1KxNUzOjZgnNoO4wQe_F75-bb0\", "
        "\"kid\": \"F2BF329A-151B-4066-AB92-1CCA0C0F9DB5\", "
        "\"d\": \"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\" }",

        // EC P-384
        "{ \"kty\": \"EC\", \"crv\": \"P-384\", "
        "\"x\": \"pO1SWmH7uOJfrtU1ibqVVK7VHffbpZtGfPYMPP_5KLQO9Dtsy41UEkMlL3BWHJDH\", "
        "\"y\": \"RdBNoaV42bRE55V8PJR3Toeo8omQAIHPboOa7LlbQSGPYp6H6zW0tKroPquJYr3w\", "
        "\"kid\": \"55680752-989A-4C5C-BC6E-48602489865C\" }",

        // EC P-521
        "{ \"kty\": \"EC\", \"crv\": \"P-521\", "
        "\"x\": \"AC8xogZa6uKAPU8086yAlG_inL3BaRyTB0pQUIJMENsPV_4S32DxIEEellMzQ_ts1Egp6OyS3ewjCUKHv5CTF7IV\", "
        "\"y\": \"AIR1I2rUew5WyetOHYC-arEDDk2R30Yto6TTot92l4aY0DL8pSYxPVwv9beFUJEl95o_1Vv5y1453nFZW1Ca0uUj\", "
        "\"kid\": \"A3EAB438-EBF8-4FEC-B605-A67C3A0D2313\" }",

        // RSA 2048 public params only
        "{ \"kty\": \"RSA\", "
        "\"e\": \"AQAB\", "
        "\"n\": \"zSNO12-ydrm-bheszVm2ZvycKrSV2CN0xqQHPxB4yT8MFlWfopMA2Imt4EkILfPfZPeUYV6lElCjoY_4GBtQOy_e4RvDSMC0pqt5X4e6mjQvLsaAClkBmhhCYd-Vn9XIC3rSeAmBpSJDuwq_RTweXSG0hb_bn5FHf1Bl_ekEBUsm0Xq4p6N5DjC0ImNP74G0qxBVJzu07qsCJzYpifYYoEYkwIY7S4jqyHv55wiuMt89VTl37y8VFR3ll6RPiPFa4Raiminw5wKNJEmrGEukabibspiC0XvWEMXj_zk0YnVTGAGdZeDPwnjYY6JUOJ9KgcYkiQYb9SXetsjSbyheZw\", "
        "\"kid\": \"05F24DC3-59F4-4AC5-9849-F2F5EA8A6F3E\" }",

        // RSA 2048 public and private params with CRT params
        "{ \"kty\": \"RSA\", "
        "\"e\": \"AQAB\", "
        "\"n\": \"zSNO12-ydrm-bheszVm2ZvycKrSV2CN0xqQHPxB4yT8MFlWfopMA2Imt4EkILfPfZPeUYV6lElCjoY_4GBtQOy_e4RvDSMC0pqt5X4e6mjQvLsaAClkBmhhCYd-Vn9XIC3rSeAmBpSJDuwq_RTweXSG0hb_bn5FHf1Bl_ekEBUsm0Xq4p6N5DjC0ImNP74G0qxBVJzu07qsCJzYpifYYoEYkwIY7S4jqyHv55wiuMt89VTl37y8VFR3ll6RPiPFa4Raiminw5wKNJEmrGEukabibspiC0XvWEMXj_zk0YnVTGAGdZeDPwnjYY6JUOJ9KgcYkiQYb9SXetsjSbyheZw\", "
        "\"kid\": \"F7D90C71-6671-4064-A0AA-379AD1862D19\", "
        "\"d\": \"bixuZapp0PYFXp98gXWTT1CQlycR61lvmFf0RFyWYo9n8H7gE7KcG7AmIHVY3UVDT7jgikMIqQOCPn1SI7BXsNIPBBujEGnfHDywHSyKfdNVG-wkTGptP9OTo3kvpP5uSCwY6btBU-1JLyWggJC_RgmaKNNYIyUlny0Q-gOx0x0I-6ipWyLQVdKZBkw6erSODM244sPU9qEmyzVW7Nbmo5PKC1U4w-Dt4nBe19TIUHG-ggN_UDRauljbegIIcnEWWeXdJZDdPUHgmIRa2ODN0mfSKl1CB4LJ2eyKlmddGLFiHys44OVwA8LVzrodUixIQP6wQ02AUwlaYU_BWLEVoQ\", "
        "\"p\": \"9GRrzfmxrL_WgSKXexO6uc2hWh-lV9bPfBU735uHUFBS2_OOUjtQSYSqm-HK2ND1EIlPZBEEu9ccdshaEVYx79eP5fRnpF8EKEo1W-eeinmn7pQsfR-6kFzkKmdBVhUyfpZvWtNuIwNZLu-HEvF2eIVVauQtJCPnjeYFbDyveqk\", "
        "\"q\": \"1uGXUwk052ayLvpYx3-L272X5srOyme3PCS2W1AZBXnXK06jqFp_KqUDpPnL3MNYZlfoYW5HIQBNpGCcZaTwfdLnSZroSbkQk-9w3zfsOiJplDbZb77mG6xbw7m7AqcNQA6szoGlCrxluE74apKg4dUOg5rEx8-LOeK90rz-So8\", "
        "\"dp\": \"D36KYy2weQ5UkC1cQz5V-U-zKh6VggMpdml2OVAH_SyKhE1luYrvJSoXEvj2vlZJIzpBYUu-7BXQRSugoja_xb_57I9ZPs-TWOaTiXce0xKxdevJAknPrzVkddfECawgXmw1NSHweqHMtrAS9T1_0FZLuxIqVn88P__UWi9ixLk\", "
        "\"dq\": \"J733d-MXBslGoUuqCdO8MTsCkivmTScbi6Mamw7YYdvkAN19hVCffmqgnu2YV89FVUBi-UolG6Rrt8AqjN4RoKPWJRXiamgw-btqO86jASmGL2RpmLJM6sdY_X0nalktKTDNoy_1L2QiyBDK_yL5YGtAUPTZ-j6XeHBIPWa4_V8\", "
        "\"qi\": \"DJcZFEvdjynkwHEOrTSXLezReXT8bj73eo7Yoadtbln27nD_8q5yAobHVOO9ZzrwSoDCeepW_fVotgMuqxdGIBXZB_DboRvjWW0QuBZ7Lg2SwwQqi9Ve8w31Z36gvOr1fR-Bd12B5STepC4SYBn1u5uMG5AIgfgzoa-FXEEBgB8\" }",

        // RSA 4096 public and private params, without CRT params
        "{ \"kty\": \"RSA\", "
        "\"e\": \"AQAB\", "
        "\"n\": \"vlbWUA9HUDHB5MDotmXObtE_Y4zKtGNtmPHUy_xkp_fSr0BxNdSOUzvzoAhK3sxTqpzVujKC245RHJ84Hhbl-KDj-n7Ee8EV3nKpnsqiBgHyc3rBpxpIi0J8kYmpiPGXu7k4xnCWCeiu_gfFGzvPdLHzlV7WOfYIHvymtbS7WOyTQLBgDjUKfHdJzH75vogy35h_mEcS-pde-EIi7u4OqD3bNW7iLbf2JVLtSNUYNCMMu23GsOEcBAsdf4QMq5gU-AEFK4Aib8mSPi_tXoohembr-JkzByRAkHbdzoGXssj0EHESt4reDfY8enVo5ACKmzbqlIJ1jmPVV6EKPBPzcQiN9dUA43xei2gmRAswdUKnexVPAPFPfKMpLqr24h1e7jHFBQL23-QqZX-gASbEDiYa9GusSY4kRn80hZRqCq4sgIRVEiu3ofjVdo4YzzESAkmfgFayUThhakqP82_wr9_Uc2vw3ZtlaTC_0LY70ne9yTy3SD3yEOa649nOTBfSh156YGtxvaHHidFojVHpPHBmjGAlak--mONHXHn00l_CVivUcuBqIGcZXRfiO6YwVDH_4ZTVzAkDov1C-4SNJK0XKeIwvGSspaSQrTmH_pT66L7tIhdZLTMVMh2ahnInVZP2G_-motugLq-x962JLQuLLeuh_r_Rk4VHZYhOgoc\", "
        "\"kid\": \"2940921e-3646-451c-8510-971552754e74\", "
        "\"d\": \"oMyvxXcC4icHDQBEGUOswEYabTmWTgrpnho_kg0p5BUjclbYzYdCreKqEPqwdcTcsfhJP0JI9r8mmy2PtSvXINKbhxXtXDdlCEaKMdIySyz97L06OLelrbB_mFxaU4z2iOsToeGff8OJgqaByF4hBw8HH5u9E75cYgFDvaJv29IRHMdkftwkfb4xJIfo6SQbBnbI5Ja22-lhnA4TgRKwY0XOmTeR8NnHIwUJ3UvZZMJvkTBOeUPT7T6OrxmZsqWKoXILMhLQBOyfldXbjNDZM5UbqSuTxmbD_MfO3xTwWWQXfIRqMZEpw1XRBguGj4g9kJ82Ujxcn-yLYbp08QhR0ijBY13HzFVMZ2jxqckrvp3uYgfJjcCN9QXZ6qlv40s_vJRRgv4wxdDc035eoymqGQby0UnDTmhijRV_-eAJQvdl3bv-R5dH9IzhxoJA8xAqZfVtlehPuGaXDAsa4pIWSg9hZkMdDEjW15g3zTQi3ba8_MfmnKuDe4GXYBjrH69z7epxbhnTmKQ-fZIxboA9sYuJHj6pEGT8D485QmrnmLjvqmQUzcxnpU6E3awksTp_HeBYLLbmrv4DPGNyVri2yPPTTRrNBtbWkuvEGVnMhvL2ed9uqLSnH8zOfgWqstqjxadxKADidYEZzmiYfEjYTDZGd9VDIUdKNGHWGFRB7UE\", "
        "\"p\": \"6VtjaNMD_VKTbs7sUQk-qjPTn6mCI8_3loqrOOy32b1G0HfIzCijuV-L7g7RxmMszEEfEILxRpJnOZRehN8etsIEuCdhU6VAdhBsBH5hIA9ZtX8GIs0sPrhc4kzPiwJ6JcLytUc6HCTICf2FIU7SI8I17-p53d35VItYiC1sGLZ2yN61VoKYNTncUSwboP2zXmGv4FPB5wQogryA_bEn-1U12FFSRd75Ku9GAEVxbTk3OaQqYgqfo9LnAWvunTDu31D4uyC6rze77NCo8UguqCpFjvF0ihOryQI6C3d0e8kxcM1vJbMvZNfrDN65btzqWi4m-CnqGYkl6BXQtS5UVw\", "
        "\"q\": \"0M7h_gtxoVoNPLRjYA5zBUD8qmyWiAzjloFOrDRLJwiD4OPHgImUx2WPTiSCjouvGqwfJh1jEEryJV_d0e4iVGyKYbFeXfzadwYXXR2jK4QwO1V_JDHI7HUYwNl6qzZqATi2zNKunPgIwY55gWBKjP2aUvPUBAcTeCsUPvrN_SajPVfc2wSlA2TvEnjmweNvgSTNqtBlMpmpwvEb9WXfv4pl3BfRvoTk3VR4icyvl-PLFedp2y0Fs0aQ4LRQ2ZMKWyGQEam_uAoa1tXrRJ_yQRvtWm1K8GpRZGKwN3TvtAg649PxQ7tJ8cvh3BwQROJyQBZDrlR04wqvDK4SNezlUQ\" }",

        // oct 256
        "{ \"kty\": \"oct\", "
        "\"kid\": \"b779034d-2e9b-44a8-8334-55d6b7a0ef59\", "
        "\"k\": \"wsL6R8uXG4RnsckLggj9Lg-kE5MMSJ8luzIBA8j7WXE\" }",

        // oct 512
        "{ \"kty\": \"oct\", "
        "\"kid\": \"0c17c6d8-307d-4e4a-a860-a14788ee1110\", "
        "\"k\": \"qKcFDl6VSS7CgMpdF9we9JFEenMQniO-8lQ0DvFI1jzfTb93H2Gc0YzO4iNEZ7VPN6p0l-PyA4vlOrn0hPS5qA\" }",

        // oct 1024
        "{ \"kty\": \"oct\", "
        "\"kid\": \"3dfc3c58-74fd-4b8a-88d6-5321b30b554c\", "
        "\"k\": \"dCDW6NH5DkKtH6dTsRm_yJchQtrVxD_ZjDob3UquMBoAwdtVIjKvMztbP4XQE7Gf_QjzEa58_UrI80QzBxG_UpFxzpjTOBfWz8Do1BHZak_W1KBWDyfnEqc8RtxZmc4yE1dko5B8GUyfplMrEFa2tO899hnGe7pqRVdiwFF5QkY\" }",

        NULL,
    };

    cjose_jwk_t *jwk = NULL;
    for (int i = 0; JWK[i] != NULL; ++i)
    {
        // do import
        jwk = cjose_jwk_import( JWK[i], strlen(JWK[i]), &err);
        ck_assert_msg(
                NULL != jwk,
                "expected a cjose_jwk_t, but got NULL (%s) : "
                "%s, file: %s, function: %s, line: %ld",
                JWK[i], err.message, err.file, err.function, err.line);

        // get json representation of "before" 
        json_t *left_json = json_loads(JWK[i], 0, NULL);
        ck_assert(NULL != left_json);

        // get json representation of "after" 
        const char *jwk_str = cjose_jwk_to_json(jwk, true, &err);
        json_t *right_json = json_loads(jwk_str, 0, NULL);
        ck_assert(NULL != right_json);

        // check that cooresponding attributes match up
        const char *attrs[] = { "kty", "crv", "x", "y", "d", "kid", 
            "e", "n", "p", "q", "dp", "dq", "qi", NULL };
        if (!_match_string_attrs(left_json, right_json, attrs))
        {
            ck_assert_str_eq(JWK[i], jwk_str);
        }

        free(jwk_str);
        json_decref(left_json);
        json_decref(right_json);
        cjose_jwk_release(jwk);
    }
}
END_TEST

START_TEST(test_cjose_jwk_import_invalid)
{
    cjose_err err;
    static const char *JWK[] = 
    {
        // EC P-256 invalid 'kty'
        "{ \"kty\": \"EMC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"0406E98B-CE84-4C78-965A-84C53BA73A1E\" }",

        // EC P-256 missing 'kty'
        "{ \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"EE05B07C-22ED-4059-A50B-4AD0A48E28D4\" }",

        // EC P-256 invalid 'crv'
        "{ \"kty\": \"EC\", \"crv\": \"P-257\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"BB70E4BD-9547-4566-9195-1C45777D368B\" }",

        // EC P-256 missing 'crv'
        "{ \"kty\": \"EC\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"928D103F-8DF2-41D5-A42B-7A72508FC70E\" }",

        // EC P-256 invalid 'x' (truncated)
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"685A7314-EBE1-4E1A-A81D-8AB4A1B56452\" }",

        // EC P-256 invalid 'x' (a number)
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": 42, "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"5B3F3AB3-E716-4D85-8E4A-4BAC0D7D64E8\" }",

        // EC P-256 missing 'x' 
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"9354D170-5FA4-46B5-901D-38098716E28A\" }",

        // EC P-256 invalid 'y' (truncated)
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRg\", "
        "\"kid\": \"262DDF7E-1AB5-43D1-91EA-13B99779DF16\" }",

        // EC P-256 invalid 'y' (an object)
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": {}, "
        "\"kid\": \"1BEFD34C-A86E-4512-B206-7A2B94D82D27\" }",

        // EC P-256 missing 'y'
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"kid\": \"CBA61EED-3C61-45B3-9A35-9DE03F247720\" }",

        // EC P-384 invalid 'x' (truncated) 
        "{ \"kty\": \"EC\", \"crv\": \"P-384\", "
        "\"x\": \"pO1SWmH7uOJfrtU1ibqVVK7VHffbpZtGfPYMPP_5KLQO9Dtsy41UEkMlL3BWHJD\", "
        "\"y\": \"RdBNoaV42bRE55V8PJR3Toeo8omQAIHPboOa7LlbQSGPYp6H6zW0tKroPquJYr3w\", "
        "\"kid\": \"FFC23684-88C8-4783-BBA3-ABF29971943B\" }",

        // EC P-521 invalid 'x' (truncated) 
        "{ \"kty\": \"EC\", \"crv\": \"P-521\", "
        "\"x\": \"AVq9Y0jEvSINQJzcExSIUWYjo73cJcVTz_QHXCU7p9rbmC8chFdACiGLKDKlzdgW6lhZzA5qnp8mkpS2qJO_EVxU\", "
        "\"y\": \"AQHcQF8s_dhS_84CKLll0vkr0xCqWLp5XXdb79coYWI7Ev9SwZ4UZZVPxgu7ZGyp_2WdtaWw68uYeUVU4WiyKfP\", "
        "\"kid\": \"3930AC1C-C02F-46DA-9730-87785F405FE8\" }",

        // RSA 2048 missing 'n' (needed for both public and private)
        "{ \"kty\": \"RSA\", "
        "\"e\": \"AQAB\", "
        "\"kid\": \"05F24DC3-59F4-4AC5-9849-F2F5EA8A6F3E\" }",

        // empty object
        "{}",

        // empty string
        "\"\"",

        // null JWK 
        "null",

        // a number 
        "5",

        // nothing
        "",

        // junk
        "!@#$%^&*()",

        NULL,
    };

    cjose_jwk_t *jwk = NULL;
    for (int i = 0; JWK[i] != NULL; ++i)
    {
        jwk = cjose_jwk_import(JWK[i], strlen(JWK[i]), &err);
        ck_assert_msg(NULL == jwk, "expected NULL, received a cjose_jwk_t");
        ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);
        cjose_jwk_release(jwk);
    }
}
END_TEST

START_TEST(test_cjose_jwk_import_underflow_length)
{
    cjose_err err;
    static const char *JWK =
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"CF21823B-D7C3-4C7F-BBE9-F11745E6BD21\" }";

    cjose_jwk_t *jwk = NULL;

    // test zero json doc length
    jwk = cjose_jwk_import(JWK, 0, &err);
    ck_assert_msg(NULL == jwk, "expected NULL, received a cjose_jwk_t");
    cjose_jwk_release(jwk);

    // test truncated length
    jwk = cjose_jwk_import(JWK, 10, &err);
    ck_assert_msg(NULL == jwk, "expected NULL, received a cjose_jwk_t");
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jwk_import_no_zero_termination)
{
    cjose_err err;
    static const char *JWK = 
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"7CD876ED-6404-443A-8BBD-D4C1C99B6F71\" }, "
        "{ \"kty\": \"EC\", \"crv\": \"P-384\", "
        "\"x\": \"pO1SWmH7uOJfrtU1ibqVVK7VHffbpZtGfPYMPP_5KLQO9Dtsy41UEkMlL3BWHJD\", "
        "\"y\": \"RdBNoaV42bRE55V8PJR3Toeo8omQAIHPboOa7LlbQSGPYp6H6zW0tKroPquJYr3w\", "
        "\"kid\": \"7CD876ED-6404-443A-8BBD-D4C1C99B6F71\" }";

    cjose_jwk_t *jwk = NULL;

    // do import providing length of just the first key (which is length 182)  
    jwk = cjose_jwk_import(JWK, 182, &err);
    ck_assert_msg(NULL != jwk, "expected a cjose_jwk_t, but got NULL");

    // get json representation of "before" 
    json_t *left_json = json_loads(JWK, JSON_DISABLE_EOF_CHECK, NULL);
    ck_assert(NULL != left_json);

    // get json representation of "after" 
    const char *jwk_str = cjose_jwk_to_json(jwk, true, &err);
    json_t *right_json = json_loads(jwk_str, 0, NULL);
    ck_assert(NULL != right_json);

    // check that cooresponding attributes match up
    const char *attrs[] = { "kty", "crv", "x", "y", "d", "kid", NULL };
    if (!_match_string_attrs(left_json, right_json, attrs))
    {
        ck_assert_str_eq(JWK, jwk_str);
    }

    free(jwk_str);
    json_decref(left_json);
    json_decref(right_json);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jwk_import_with_base64url_padding)
{
    cjose_err err;
    static const char *JWK_IN =
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M=\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ=\", "
        "\"kid\": \"BEB14BFF-1D35-4AC0-9D0A-3FD44D1C834D\" }";

    static const char *JWK_OUT =
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"BEB14BFF-1D35-4AC0-9D0A-3FD44D1C834D\" }";

    cjose_jwk_t *jwk = NULL;

    // do import
    jwk = cjose_jwk_import(JWK_IN, strlen(JWK_IN), &err);
    ck_assert_msg(NULL != jwk, "expected a cjose_jwk_t, but got NULL");

    // get json representation of "expected" (i.e. no padding) 
    json_t *left_json = json_loads(JWK_OUT, 0, NULL);
    ck_assert(NULL != left_json);

    // get json representation of "actual" (i.e. reserialized original)
    const char *jwk_str = cjose_jwk_to_json(jwk, true, &err);
    json_t *right_json = json_loads(jwk_str, 0, NULL);
    ck_assert(NULL != right_json);        

    // check that cooresponding attributes match up
    const char *attrs[] = { "kty", "crv", "x", "y", "d", "kid", NULL };
    if (!_match_string_attrs(left_json, right_json, attrs))
    {
        ck_assert_str_eq(JWK_OUT, jwk_str);
    }

    free(jwk_str);
    json_decref(left_json);
    json_decref(right_json);
    cjose_jwk_release(jwk);
}
END_TEST


START_TEST(test_cjose_jwk_EC_import_with_priv_export_with_pub)
{
    cjose_err err;
    static const char *JWK_IN = 
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"kid\": \"7302734F-A854-40BC-A44F-93F6F72B0D34\", "
        "\"d\": \"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\" }";

    static const char *JWK_OUT = 
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"ccXrxIe0aS32y9kBkZFfAh6f7UvdcowtGH5uxCIo7eY\", "
        "\"y\": \"GGQACnDgoiQvdQTsv1KxNUzOjZgnNoO4wQe_F75-bb0\", "
        "\"kid\": \"7302734F-A854-40BC-A44F-93F6F72B0D34\", "
        "\"d\": \"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\" }";

    cjose_jwk_t *jwk = NULL;

    // do import which includes just the private key 'd'  
    jwk = cjose_jwk_import(JWK_IN, strlen(JWK_IN), &err);
    ck_assert_msg(NULL != jwk, "expected a cjose_jwk_t, but got NULL");

    // get json representation of "expected" (i.e. includes 'x' and 'y') 
    json_t *left_json = json_loads(JWK_OUT, 0, NULL);
    ck_assert(NULL != left_json);

    // get json representation of "actual" (i.e. reserialized original)
    const char *jwk_str = cjose_jwk_to_json(jwk, true, &err);
    json_t *right_json = json_loads(jwk_str, 0, NULL);
    ck_assert(NULL != right_json);        

    // check that cooresponding attributes match up
    const char *attrs[] = { "kty", "crv", "x", "y", "d", "kid", NULL };
    if (!_match_string_attrs(left_json, right_json, attrs))
    {
        ck_assert_str_eq(JWK_OUT, jwk_str);
    }

    free(jwk_str);
    json_decref(left_json);
    json_decref(right_json);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jwk_hkdf)
{
    cjose_err err;

    const char *ikm = "source key material";
    size_t ikm_len = strlen(ikm);

    size_t ephemeral_key_len = 32;
    uint8_t *ephemeral_key = (uint8_t *)malloc(ephemeral_key_len);
    bool ok = cjose_jwk_hkdf(EVP_sha256(), (uint8_t *)"", 0, (uint8_t *)"", 0, 
            ikm, ikm_len, ephemeral_key, ephemeral_key_len, &err);
    ck_assert_msg(ok, "Failed to compute HKDF");     

    // the following is the expected output of HKDF with the ikm given above, 
    // SHA256, no salt, no info, and an extend length of 256 bits, as provided 
    // by the Ruby impl. of HKDF found here: https://github.com/jtdowney/hkdf
    const uint8_t expected[] = { 
            0x0C, 0x23, 0xF4, 0x62, 0x98, 0x9B, 0x7F, 0x77, 0x3E, 0x7C, 0x2F, 
            0x7C, 0x6B, 0xF4, 0x6B, 0xB7, 0xB9, 0x11, 0x65, 0xC5, 0x92, 0xD1, 
            0x0C, 0x48, 0xFD, 0x47, 0x94, 0x76, 0x74, 0xB4, 0x14, 0xCE };
    for (int i = 0; i < ephemeral_key_len; i++) 
    {
        ck_assert_msg(
                ephemeral_key[i] == expected[i], "HKDF failed on byte: %d", i);     
    }
    free(ephemeral_key);
}
END_TEST

START_TEST(test_cjose_jwk_get_and_set_kid)
{
    cjose_err err;

    const char *oldKid = "725cad72-23c6-4bf7-84c3-4583a6cf5fe9";
    const char *newKid = "aec1cebf-ddec-4d5f-8a61-f29e2f68dc41";

    static const char *JWK_BEFORE[] = 
    {
        // OCT key
        "{\"kty\":\"oct\","
        "\"kid\":\"725cad72-23c6-4bf7-84c3-4583a6cf5fe9\","
        "\"k\":\"wsL6R8uXG4RnsckLggj9Lg-kE5MMSJ8luzIBA8j7WXE\"}",

        // EC key
        "{\"kty\":\"EC\","
        "\"kid\":\"725cad72-23c6-4bf7-84c3-4583a6cf5fe9\","
        "\"crv\":\"P-256\","
        "\"x\":\"ccXrxIe0aS32y9kBkZFfAh6f7UvdcowtGH5uxCIo7eY\","
        "\"y\":\"GGQACnDgoiQvdQTsv1KxNUzOjZgnNoO4wQe_F75-bb0\","
        "\"d\":\"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\"}",

        // RSA key
        "{\"kty\":\"RSA\","
        "\"kid\":\"725cad72-23c6-4bf7-84c3-4583a6cf5fe9\","
        "\"e\":\"AQAB\","
        "\"n\":\"zSNO12-ydrm-bheszVm2ZvycKrSV2CN0xqQHPxB4yT8MFlWfopMA2Im"
        "t4EkILfPfZPeUYV6lElCjoY_4GBtQOy_e4RvDSMC0pqt5X4e6mjQvLsaAClkBmh"
        "hCYd-Vn9XIC3rSeAmBpSJDuwq_RTweXSG0hb_bn5FHf1Bl_ekEBUsm0Xq4p6N5D"
        "jC0ImNP74G0qxBVJzu07qsCJzYpifYYoEYkwIY7S4jqyHv55wiuMt89VTl37y8V"
        "FR3ll6RPiPFa4Raiminw5wKNJEmrGEukabibspiC0XvWEMXj_zk0YnVTGAGdZeD"
        "PwnjYY6JUOJ9KgcYkiQYb9SXetsjSbyheZw\"}",

        NULL

    };

    static const char *JWK_AFTER[] = 
    {
        // OCT key
        "{\"kty\":\"oct\","
        "\"kid\":\"aec1cebf-ddec-4d5f-8a61-f29e2f68dc41\","
        "\"k\":\"wsL6R8uXG4RnsckLggj9Lg-kE5MMSJ8luzIBA8j7WXE\"}",

        // EC key
        "{\"kty\":\"EC\","
        "\"kid\":\"aec1cebf-ddec-4d5f-8a61-f29e2f68dc41\","
        "\"crv\":\"P-256\","
        "\"x\":\"ccXrxIe0aS32y9kBkZFfAh6f7UvdcowtGH5uxCIo7eY\","
        "\"y\":\"GGQACnDgoiQvdQTsv1KxNUzOjZgnNoO4wQe_F75-bb0\","
        "\"d\":\"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\"}",

        // RSA key
        "{\"kty\":\"RSA\","
        "\"kid\":\"aec1cebf-ddec-4d5f-8a61-f29e2f68dc41\","
        "\"e\":\"AQAB\","
        "\"n\":\"zSNO12-ydrm-bheszVm2ZvycKrSV2CN0xqQHPxB4yT8MFlWfopMA2Im"
        "t4EkILfPfZPeUYV6lElCjoY_4GBtQOy_e4RvDSMC0pqt5X4e6mjQvLsaAClkBmh"
        "hCYd-Vn9XIC3rSeAmBpSJDuwq_RTweXSG0hb_bn5FHf1Bl_ekEBUsm0Xq4p6N5D"
        "jC0ImNP74G0qxBVJzu07qsCJzYpifYYoEYkwIY7S4jqyHv55wiuMt89VTl37y8V"
        "FR3ll6RPiPFa4Raiminw5wKNJEmrGEukabibspiC0XvWEMXj_zk0YnVTGAGdZeD"
        "PwnjYY6JUOJ9KgcYkiQYb9SXetsjSbyheZw\"}",

        NULL
    };

    // because stuff happens
    ck_assert(sizeof(JWK_BEFORE) == sizeof(JWK_AFTER));

    const char *kid = NULL;
    const char *json = NULL;
    for (int i = 0; JWK_BEFORE[i] != NULL; ++i)
    {
        // import the before state
        cjose_jwk_t *jwk = cjose_jwk_import(JWK_BEFORE[i], strlen(JWK_BEFORE[i]), &err);
        ck_assert_msg(NULL != jwk, "expected a cjose_jwk_t, but got NULL");

        // check that kid was imported correctly
        kid = cjose_jwk_get_kid(jwk, &err);
        ck_assert_msg(!strcmp(kid, oldKid), "match on imported JWK kid failed: %d", i);

        // change the kid
        ck_assert(cjose_jwk_set_kid(jwk, newKid, strlen(newKid), &err));

        // check that the kid was changed
        kid = cjose_jwk_get_kid(jwk, &err);
        ck_assert_msg(!strcmp(kid, newKid), "match on modified JWK kid failed: %d", i);

        // check that the kid is exported correctly
        json = cjose_jwk_to_json(jwk, true, &err);
        ck_assert_msg(!strcmp(json, JWK_AFTER[i]), "match on modified JWK JSON failed: %d", i);

        // freedom!
        cjose_jwk_release(jwk);
        free(json);
    }
}
END_TEST

Suite *cjose_jwk_suite()
{
    Suite *suite = suite_create("jwk");

    TCase *tc_jwk = tcase_create("core");
    tcase_add_test(tc_jwk, test_cjose_jwk_name_for_kty);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_RSA_spec);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_RSA_random);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P256_spec);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P256_random);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P384_spec);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P384_random);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P521_spec);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P521_random);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_oct_spec);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_oct_random);
    tcase_add_test(tc_jwk, test_cjose_jwk_create_oct_random_inval);
    tcase_add_test(tc_jwk, test_cjose_jwk_retain_release);
    tcase_add_test(tc_jwk, test_cjose_jwk_get_kty);
    tcase_add_test(tc_jwk, test_cjose_jwk_to_json_oct);
    tcase_add_test(tc_jwk, test_cjose_jwk_to_json_ec);
    tcase_add_test(tc_jwk, test_cjose_jwk_to_json_rsa);
    tcase_add_test(tc_jwk, test_cjose_jwk_import_valid);
    tcase_add_test(tc_jwk, test_cjose_jwk_import_invalid);
    tcase_add_test(tc_jwk, test_cjose_jwk_import_underflow_length);
    tcase_add_test(tc_jwk, test_cjose_jwk_import_no_zero_termination);
    tcase_add_test(tc_jwk, test_cjose_jwk_import_with_base64url_padding);
    tcase_add_test(tc_jwk, test_cjose_jwk_EC_import_with_priv_export_with_pub);
    tcase_add_test(tc_jwk, test_cjose_jwk_hkdf);
    tcase_add_test(tc_jwk, test_cjose_jwk_get_and_set_kid);
    suite_add_tcase(suite, tc_jwk);

    return suite;
}
