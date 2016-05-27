/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <cjose/base64.h>
#include <cjose/header.h>
#include <cjose/jwe.h>
#include <cjose/util.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#include "include/header_int.h"
#include "include/jwk_int.h"
#include "include/jwe_int.h"
#include "include/util_int.h"


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_set_cek_a256gcm(
        cjose_jwe_t *jwe, 
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jwe_set_cek_aes_cbc(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jwe_encrypt_ek_dir(
        cjose_jwe_t *jwe, 
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jwe_decrypt_ek_dir(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jwe_encrypt_ek_aes_kw(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jwe_decrypt_ek_aes_kw(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jwe_encrypt_ek_rsa_oaep(
        cjose_jwe_t *jwe, 
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jwe_decrypt_ek_rsa_oaep(
        cjose_jwe_t *jwe, 
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jwe_encrypt_ek_rsa1_5(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jwe_decrypt_ek_rsa1_5(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jwe_set_iv_a256gcm(
        cjose_jwe_t *jwe,
        cjose_err *err);

static bool _cjose_jwe_set_iv_aes_cbc(
        cjose_jwe_t *jwe,
        cjose_err *err);

static bool _cjose_jwe_encrypt_dat_a256gcm(
        cjose_jwe_t *jwe, 
        const uint8_t *plaintext,
        size_t plaintext_len,
        cjose_err *err);

static bool _cjose_jwe_encrypt_dat_aes_cbc(
        cjose_jwe_t *jwe,
        const uint8_t *plaintext,
        size_t plaintext_len,
        cjose_err *err);

static bool _cjose_jwe_decrypt_dat_a256gcm(
        cjose_jwe_t *jwe, 
        cjose_err *err);

static bool _cjose_jwe_decrypt_dat_aes_cbc(
        cjose_jwe_t *jwe,
        cjose_err *err);

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_malloc(
        size_t bytes, bool random, 
        uint8_t **buffer,
        cjose_err *err)
{
    *buffer = (uint8_t *)cjose_get_alloc()(bytes);
    if (NULL == *buffer)
    {   
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }   
    if (random)
    {   
        if (RAND_bytes((unsigned char *)*buffer, bytes) != 1)
        {   
            cjose_get_dealloc()(*buffer);
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            return false;
        }   
    }   
    else
    {   
        memset(*buffer, 0, bytes);
    }   
    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_build_hdr(
        cjose_jwe_t *jwe, 
        cjose_header_t *header,
        cjose_err *err)
{
    // save header object as part of the JWE (and incr. refcount)
    jwe->hdr = header;
    json_incref(jwe->hdr);

    // serialize the header
    char *hdr_str = json_dumps(header, JSON_ENCODE_ANY | JSON_PRESERVE_ORDER);
    if (NULL == hdr_str)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    // copy the serialized header to JWE (hdr_str is owned by header object)
    size_t  len = strlen(hdr_str);
    uint8_t *data = (uint8_t *)_cjose_strndup(hdr_str, len, err);
    if (!data)
    {
        cjose_get_dealloc()(hdr_str);
        return false;
    }

    jwe->part[0].raw = data;
    jwe->part[0].raw_len = len;
    cjose_get_dealloc()(hdr_str);
    
    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_validate_hdr(
        cjose_jwe_t *jwe, 
        cjose_header_t *header,
        cjose_err *err)
{
    // make sure we have an alg header
    json_t *alg_obj = json_object_get(header, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(alg_obj);

    // make sure we have an enc header
    json_t *enc_obj = json_object_get(header, CJOSE_HDR_ENC);
    if (NULL == enc_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *enc = json_string_value(enc_obj);

    // set JWE build functions based on header contents
    if (strcmp(alg, CJOSE_HDR_ALG_RSA_OAEP) == 0)
    {
        jwe->fns.encrypt_ek = _cjose_jwe_encrypt_ek_rsa_oaep;
        jwe->fns.decrypt_ek = _cjose_jwe_decrypt_ek_rsa_oaep;
    }
    if (strcmp(alg, CJOSE_HDR_ALG_RSA1_5) == 0)
    {
        jwe->fns.encrypt_ek = _cjose_jwe_encrypt_ek_rsa1_5;
        jwe->fns.decrypt_ek = _cjose_jwe_decrypt_ek_rsa1_5;
    }
    if (strcmp(alg, CJOSE_HDR_ALG_DIR) == 0)
    {
        jwe->fns.encrypt_ek = _cjose_jwe_encrypt_ek_dir;
        jwe->fns.decrypt_ek = _cjose_jwe_decrypt_ek_dir;
    }
    if ((strcmp(alg, CJOSE_HDR_ALG_A128KW) == 0) || (strcmp(alg, CJOSE_HDR_ALG_A192KW) == 0) || (strcmp(alg, CJOSE_HDR_ALG_A256KW) == 0))
    {
        jwe->fns.encrypt_ek = _cjose_jwe_encrypt_ek_aes_kw;
        jwe->fns.decrypt_ek = _cjose_jwe_decrypt_ek_aes_kw;
    }
    if (strcmp(enc, CJOSE_HDR_ENC_A256GCM) == 0)
    {
        jwe->fns.set_cek = _cjose_jwe_set_cek_a256gcm;
        jwe->fns.set_iv = _cjose_jwe_set_iv_a256gcm;
        jwe->fns.encrypt_dat = _cjose_jwe_encrypt_dat_a256gcm;
        jwe->fns.decrypt_dat = _cjose_jwe_decrypt_dat_a256gcm;
    }
    if ((strcmp(enc, CJOSE_HDR_ENC_A128CBC_HS256) == 0) || (strcmp(enc, CJOSE_HDR_ENC_A192CBC_HS384) == 0) || (strcmp(enc, CJOSE_HDR_ENC_A256CBC_HS512) == 0))
    {
        jwe->fns.set_cek = _cjose_jwe_set_cek_aes_cbc;
        jwe->fns.set_iv = _cjose_jwe_set_iv_aes_cbc;
        jwe->fns.encrypt_dat = _cjose_jwe_encrypt_dat_aes_cbc;
        jwe->fns.decrypt_dat = _cjose_jwe_decrypt_dat_aes_cbc;
    }

    // ensure required builders have been assigned
    if (NULL == jwe->fns.set_cek ||
        NULL == jwe->fns.encrypt_ek ||
        NULL == jwe->fns.decrypt_ek ||
        NULL == jwe->fns.set_iv ||
        NULL == jwe->fns.encrypt_dat ||
        NULL == jwe->fns.decrypt_dat)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_set_cek_a256gcm(
        cjose_jwe_t *jwe, 
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    // 256 bits = 32 bytes
    static const size_t keysize = 32;

    // if no JWK is provided, generate a random key
    if (NULL == jwk)
    {
        cjose_get_dealloc()(jwe->cek);
        if (!_cjose_jwe_malloc(keysize, true, &jwe->cek, err))
        {
            return false;
        }   
        jwe->cek_len = keysize;
    }
    else
    {
        // if a JWK is provided, it must be a symmetric key of correct size
        if (CJOSE_JWK_KTY_OCT != cjose_jwk_get_kty(jwk, err) ||
                jwk->keysize != keysize*8 ||
                NULL == jwk->keydata)
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            return false;
        }

        // copy the key material directly from jwk to the jwe->cek
        cjose_get_dealloc()(jwe->cek);
        if (!_cjose_jwe_malloc(keysize, false, &jwe->cek, err))
        {
            return false;
        }   
        memcpy(jwe->cek, jwk->keydata, keysize);
        jwe->cek_len = keysize;
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_set_cek_aes_cbc(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *dummy_set_to_null_for_random,
        cjose_err *err)
{
    // make sure we have an enc header
    json_t *enc_obj = json_object_get(jwe->hdr, CJOSE_HDR_ENC);
    if (NULL == enc_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *enc = json_string_value(enc_obj);

    // determine the CEK key size based on the encryption algorithm
    if (strcmp(enc, CJOSE_HDR_ENC_A128CBC_HS256) == 0)
        jwe->cek_len = 32;
    if (strcmp(enc, CJOSE_HDR_ENC_A192CBC_HS384) == 0)
        jwe->cek_len = 48;
    if (strcmp(enc, CJOSE_HDR_ENC_A256CBC_HS512) == 0)
        jwe->cek_len = 64;

    // allocate memory for the CEK and fill with random bytes or 0's
    cjose_get_dealloc()(jwe->cek);
    if (!_cjose_jwe_malloc(jwe->cek_len, dummy_set_to_null_for_random == NULL, &jwe->cek, err))
    {
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_encrypt_ek_dir(
        cjose_jwe_t *jwe, 
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    // for direct encryption, JWE sec 5.1, step 6: let CEK be the symmetric key.
    if (!jwe->fns.set_cek(jwe, jwk, err))
    {
        return false;
    }   

    // for direct encryption, JWE sec 5.1, step 5: let EK be empty octet seq.
    jwe->part[1].raw = NULL;
    jwe->part[1].raw_len = 0;

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_decrypt_ek_dir(
        cjose_jwe_t *jwe, 
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    // do not try and decrypt the ek. that's impossible. 
    // instead... only try to realize the truth.  there is no ek.
    return _cjose_jwe_set_cek_a256gcm(jwe, jwk, err);
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_encrypt_ek_aes_kw(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    if (NULL == jwe || NULL == jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // jwk must be OCT
    if (jwk->kty != CJOSE_JWK_KTY_OCT)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // generate random CEK
    if (!jwe->fns.set_cek(jwe, NULL, err))
    {
        return false;
    }

    // create the AES encryption key from the shared key
    AES_KEY akey;
    if (AES_set_encrypt_key(jwk->keydata, jwk->keysize, &akey) < 0)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    // allocate buffer for encrypted CEK (=cek_len + 8)
    if (!_cjose_jwe_malloc(jwe->cek_len + 8, false, &jwe->part[1].raw, err))
    {
        return false;
    }

    // AES wrap the CEK
    int len = AES_wrap_key(&akey, NULL, jwe->part[1].raw, jwe->cek, jwe->cek_len);
    if (len <= 0)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }
    jwe->part[1].raw_len = len;

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_decrypt_ek_aes_kw(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    if (NULL == jwe || NULL == jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // jwk must be OCT
    if (jwk->kty != CJOSE_JWK_KTY_OCT)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // create the AES decryption key from the shared key
    AES_KEY akey;
    if (AES_set_decrypt_key(jwk->keydata, jwk->keysize, &akey) < 0)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    // generate empty CEK so the the right amount of memory is allocated (abuse JWK parameter to empty)
    if (!jwe->fns.set_cek(jwe, (const cjose_jwk_t *) 1, err))
    {
        return false;
    }

    // AES unwrap the CEK in to jwe->cek
    int len = AES_unwrap_key(&akey, (const unsigned char*) NULL, jwe->cek, (const unsigned char *) jwe->part[1].raw,
            jwe->part[1].raw_len);
    if (len <= 0)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }
    jwe->cek_len = len;

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_encrypt_ek_rsa_padding(
        cjose_jwe_t *jwe, 
        const cjose_jwk_t *jwk,
        int padding,
        cjose_err *err)
{
    // jwk must be RSA and have the necessary public parts set
    if (jwk->kty != CJOSE_JWK_KTY_RSA ||
        NULL == jwk->keydata ||
        NULL == ((RSA *)jwk->keydata)->e || 
        NULL == ((RSA *)jwk->keydata)->n)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // generate random cek
    if (!jwe->fns.set_cek(jwe, NULL, err))
    {
        return false;
    }   

    // the size of the ek will match the size of the RSA key
    jwe->part[1].raw_len = RSA_size((RSA *)jwk->keydata);

    // for OAEP padding - the RSA size - 41 must be greater than input
    if (jwe->cek_len >= jwe->part[1].raw_len - 41)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;        
    }

    // allocate memory for RSA encryption
    cjose_get_dealloc()(jwe->part[1].raw);
    if (!_cjose_jwe_malloc(jwe->part[1].raw_len, false, &jwe->part[1].raw, err))
    {
        return false;        
    }

    // encrypt the CEK using RSA v1.5 or OAEP padding
    if (RSA_public_encrypt(jwe->cek_len, jwe->cek, jwe->part[1].raw,
            (RSA *)jwk->keydata, padding) !=
            jwe->part[1].raw_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;        
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_decrypt_ek_rsa_padding(
        cjose_jwe_t *jwe, 
        const cjose_jwk_t *jwk,
        int padding,
        cjose_err *err)
{
    if (NULL == jwe || NULL == jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // jwk must be RSA
    if (jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;        
    }

    // we don't know the size of the key to expect, but must be < RSA_size
    cjose_get_dealloc()(jwe->cek);
    size_t buflen = RSA_size((RSA *)jwk->keydata);
    if (!_cjose_jwe_malloc(buflen, false, &jwe->cek, err))
    {
        return false;
    }

    // decrypt the CEK using RSA v1.5 or OAEP padding
    jwe->cek_len = RSA_private_decrypt(
            jwe->part[1].raw_len, jwe->part[1].raw, jwe->cek, 
            (RSA *)jwk->keydata, padding);
    if (-1 == jwe->cek_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_encrypt_ek_rsa_oaep(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    return _cjose_jwe_encrypt_ek_rsa_padding(jwe, jwk, RSA_PKCS1_OAEP_PADDING ,err);
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_decrypt_ek_rsa_oaep(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    return _cjose_jwe_decrypt_ek_rsa_padding(jwe, jwk, RSA_PKCS1_OAEP_PADDING ,err);
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_encrypt_ek_rsa1_5(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    return _cjose_jwe_encrypt_ek_rsa_padding(jwe, jwk, RSA_PKCS1_PADDING ,err);
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_decrypt_ek_rsa1_5(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    return _cjose_jwe_decrypt_ek_rsa_padding(jwe, jwk, RSA_PKCS1_PADDING ,err);
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_set_iv_a256gcm(
        cjose_jwe_t *jwe,
        cjose_err *err)
{
    // generate IV as random 96 bit value
    cjose_get_dealloc()(jwe->part[2].raw);
    jwe->part[2].raw_len = 12;
    if (!_cjose_jwe_malloc(jwe->part[2].raw_len, true, &jwe->part[2].raw, err))
    {
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_set_iv_aes_cbc(
        cjose_jwe_t *jwe,
        cjose_err *err)
{
    // make sure we have an enc header
    json_t *enc_obj = json_object_get(jwe->hdr, CJOSE_HDR_ENC);
    if (NULL == enc_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *enc = json_string_value(enc_obj);

    cjose_get_dealloc()(jwe->part[2].raw);
    jwe->part[2].raw_len = 0;

    if (strcmp(enc, CJOSE_HDR_ENC_A128CBC_HS256) == 0)
        jwe->part[2].raw_len = 16;
    if (strcmp(enc, CJOSE_HDR_ENC_A192CBC_HS384) == 0)
        jwe->part[2].raw_len = 24;
    if (strcmp(enc, CJOSE_HDR_ENC_A256CBC_HS512) == 0)
        jwe->part[2].raw_len = 32;

    if (jwe->part[2].raw_len == 0)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // generate IV as random iv_size * 8 bit value
    if (!_cjose_jwe_malloc(jwe->part[2].raw_len, true, &jwe->part[2].raw, err))
    {
        return false;
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_encrypt_dat_a256gcm(
        cjose_jwe_t *jwe, 
        const uint8_t *plaintext,
        size_t plaintext_len,
        cjose_err *err)
{
    EVP_CIPHER_CTX *ctx = NULL;

    if (NULL == plaintext)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jwe_encrypt_dat_fail;        
    }

    // get A256GCM cipher
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    if (NULL == cipher)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_fail;
    }

    // instantiate and initialize a new openssl cipher context
    ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_fail;
    }
    EVP_CIPHER_CTX_init(ctx);

    // initialize context for encryption using A256GCM cipher and CEK and IV
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, jwe->cek, jwe->part[2].raw) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_fail;
    }

    // we need the header in base64url encoding as input for encryption
    if ((NULL == jwe->part[0].b64u) && (!cjose_base64url_encode(
        (const uint8_t *)jwe->part[0].raw, jwe->part[0].raw_len, 
        &jwe->part[0].b64u, &jwe->part[0].b64u_len, err)))
    {
        goto _cjose_jwe_encrypt_dat_fail;
    }    

    // set GCM mode AAD data (hdr_b64u) by setting "out" to NULL
    int bytes_encrypted = 0;
    if (EVP_EncryptUpdate(ctx, 
                NULL, &bytes_encrypted, 
                (unsigned char *)jwe->part[0].b64u, 
                jwe->part[0].b64u_len) != 1 ||
                bytes_encrypted != jwe->part[0].b64u_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_fail;
    }

    // allocate buffer for the ciphertext
    cjose_get_dealloc()(jwe->part[3].raw);
    jwe->part[3].raw_len = plaintext_len;
    if (!_cjose_jwe_malloc(jwe->part[3].raw_len, false, &jwe->part[3].raw, err))
    {
        goto _cjose_jwe_encrypt_dat_fail;        
    }

    // encrypt entire plaintext to ciphertext buffer
    if (EVP_EncryptUpdate(ctx, 
            jwe->part[3].raw, &bytes_encrypted, 
            plaintext, plaintext_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_fail;
    }
    jwe->part[3].raw_len = bytes_encrypted;

    // finalize the encryption and set the ciphertext length to correct value
    if (EVP_EncryptFinal_ex(ctx, NULL, &bytes_encrypted) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_fail;
    }

    // allocate buffer for the authentication tag
    cjose_get_dealloc()(jwe->part[4].raw);
    jwe->part[4].raw_len = 16;
    if (!_cjose_jwe_malloc(jwe->part[4].raw_len, false, &jwe->part[4].raw, err))
    {
        goto _cjose_jwe_encrypt_dat_fail;        
    }

    // get the GCM-mode authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 
            jwe->part[4].raw_len, jwe->part[4].raw) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_fail;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;

    _cjose_jwe_encrypt_dat_fail:
    if (NULL != ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
    return false;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_calc_auth_tag(const char *enc, cjose_jwe_t *jwe, uint8_t *md, unsigned int *md_len, cjose_err *err)
{
	bool retval = false;
	const EVP_MD *hash = NULL;

    if (strcmp(enc, CJOSE_HDR_ENC_A128CBC_HS256) == 0)
		hash = EVP_sha256();
    if (strcmp(enc, CJOSE_HDR_ENC_A192CBC_HS384) == 0)
    	hash = EVP_sha384();
    if (strcmp(enc, CJOSE_HDR_ENC_A256CBC_HS512) == 0)
    	hash = EVP_sha512();

    if (NULL == hash)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    uint8_t *msg = NULL;

	// calculate the Authentication Tag value over AAD + IV + ciphertext + AAD length

    //0 = header
    //1 = cek
    //2 = iv
    //3 = ciphertext
    //4 = authentication tag

    // Additional Authentication Data length (base64encoded header) in # of bits in 64 bit length field
    uint64_t al = jwe->part[0].b64u_len * 8;

    // concatenate AAD + IV + ciphertext + AAD length field
    int msg_len = jwe->part[0].b64u_len + jwe->part[2].raw_len + jwe->part[3].raw_len + sizeof(uint64_t);
    if (!_cjose_jwe_malloc(msg_len, false, &msg, err))
    {
        goto _cjose_jwe_calc_auth_tag_end;
    }

    // construct AAD + IV + ciphertext + AAD input
    uint8_t *p = msg;
    memcpy(p, jwe->part[0].b64u, jwe->part[0].b64u_len);
    p += jwe->part[0].b64u_len;
    memcpy(p, jwe->part[2].raw, jwe->part[2].raw_len);
    p += jwe->part[2].raw_len;
    memcpy(p, jwe->part[3].raw, jwe->part[3].raw_len);
    p += jwe->part[3].raw_len;

    // check if we are on a big endian or little endian machine
    int c = 1;
    if (*(char *) &c == 1)
    {
	    // little endian machine: reverse AAD length for big endian representation
	    al = (al & 0x00000000FFFFFFFF) << 32 | (al & 0xFFFFFFFF00000000) >> 32;
	    al = (al & 0x0000FFFF0000FFFF) << 16 | (al & 0xFFFF0000FFFF0000) >> 16;
	    al = (al & 0x00FF00FF00FF00FF) << 8 | (al & 0xFF00FF00FF00FF00) >> 8;
    }
    memcpy(p, &al, sizeof(uint64_t));

    // HMAC the input
	if (!HMAC(hash, jwe->cek, jwe->cek_len / 2, msg, msg_len, md, md_len))
	{
		CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_calc_auth_tag_end;
	}

	// use only the first half of the bits
	*md_len = *md_len / 2;
	retval = true;

	_cjose_jwe_calc_auth_tag_end:
	if (msg)
	{
	    cjose_get_dealloc()(msg);
	}
    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_encrypt_dat_aes_cbc(
        cjose_jwe_t *jwe,
        const uint8_t *plaintext,
        size_t plaintext_len,
        cjose_err *err)
{
    // make sure we have an enc header
    json_t *enc_obj = json_object_get(jwe->hdr, CJOSE_HDR_ENC);
    if (NULL == enc_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *enc = json_string_value(enc_obj);

    // get the AES cipher
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;

    if (strcmp(enc, CJOSE_HDR_ENC_A128CBC_HS256) == 0)
        cipher = EVP_aes_128_cbc();
    if (strcmp(enc, CJOSE_HDR_ENC_A192CBC_HS384) == 0)
        cipher = EVP_aes_192_cbc();
    if (strcmp(enc, CJOSE_HDR_ENC_A256CBC_HS512) == 0)
        cipher = EVP_aes_256_cbc();

    if (NULL == cipher)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_aes_cbc_fail;
    }

    // instantiate and initialize a new openssl cipher context
    ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_aes_cbc_fail;
    }
    EVP_CIPHER_CTX_init(ctx);

    // initialize context for decryption using the cipher, the 2nd half of the CEK and the IV
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, jwe->cek + jwe->cek_len / 2, jwe->part[2].raw) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_aes_cbc_fail;
    }

    // we need the header in base64url encoding as input for encryption
    if ((NULL == jwe->part[0].b64u)
            && (!cjose_base64url_encode((const uint8_t *) jwe->part[0].raw, jwe->part[0].raw_len, &jwe->part[0].b64u,
                    &jwe->part[0].b64u_len, err)))
    {
        goto _cjose_jwe_encrypt_dat_aes_cbc_fail;
    }

    // allocate buffer for the ciphertext (plaintext + block size)
    cjose_get_dealloc()(jwe->part[3].raw);
    jwe->part[3].raw_len = plaintext_len + cipher->block_size;
    if (!_cjose_jwe_malloc(jwe->part[3].raw_len, false, &jwe->part[3].raw, err))
    {
        goto _cjose_jwe_encrypt_dat_aes_cbc_fail;
    }

    // encrypt entire plaintext to ciphertext buffer
    int bytes_encrypted = 0;
    if (EVP_EncryptUpdate(ctx, jwe->part[3].raw, &bytes_encrypted, plaintext, plaintext_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_aes_cbc_fail;
    }
    jwe->part[3].raw_len = bytes_encrypted;

    // finalize the encryption and set the ciphertext length to correct value
    if (EVP_EncryptFinal_ex(ctx, jwe->part[3].raw + bytes_encrypted, &bytes_encrypted) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_encrypt_dat_aes_cbc_fail;
    }
    jwe->part[3].raw_len += bytes_encrypted;

    // calculate Authentication Tag
    unsigned int tag_len = 0;
    uint8_t tag[EVP_MAX_MD_SIZE];
    if (_cjose_jwe_calc_auth_tag(enc, jwe, (unsigned char *) &tag, &tag_len, err) == false)
    {
        return false;
    }

    // allocate buffer for the authentication tag
    cjose_get_dealloc()(jwe->part[4].raw);
    jwe->part[4].raw_len = tag_len;
    if (!_cjose_jwe_malloc(jwe->part[4].raw_len, false, &jwe->part[4].raw, err))
    {
        goto _cjose_jwe_encrypt_dat_aes_cbc_fail;
    }

    memcpy(jwe->part[4].raw, tag, tag_len);

    EVP_CIPHER_CTX_free(ctx);

    return true;

    _cjose_jwe_encrypt_dat_aes_cbc_fail:
    if (NULL != ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
    return false;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_decrypt_dat_a256gcm(
        cjose_jwe_t *jwe, 
        cjose_err *err)
{
    EVP_CIPHER_CTX *ctx = NULL;

    // get A256GCM cipher
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    if (NULL == cipher)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_a256gcm_fail;
    }

    // instantiate and initialize a new openssl cipher context
    ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_a256gcm_fail;
    }
    EVP_CIPHER_CTX_init(ctx);

    // initialize context for decryption using A256GCM cipher and CEK and IV
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, jwe->cek, jwe->part[2].raw) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_a256gcm_fail;
    }

    // set the expected GCM-mode authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 
            jwe->part[4].raw_len, jwe->part[4].raw) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_a256gcm_fail;
    }

    // set GCM mode AAD data (hdr_b64u) by setting "out" to NULL
    int bytes_decrypted = 0;
    if (EVP_DecryptUpdate(ctx, 
                NULL, &bytes_decrypted, 
                (unsigned char *)jwe->part[0].b64u, 
                jwe->part[0].b64u_len) != 1 ||
                bytes_decrypted != jwe->part[0].b64u_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_a256gcm_fail;
    }

    // allocate buffer for the plaintext
    cjose_get_dealloc()(jwe->dat);
    jwe->dat_len = jwe->part[3].raw_len;
    if (!_cjose_jwe_malloc(jwe->dat_len, false, &jwe->dat, err))
    {
        goto _cjose_jwe_decrypt_dat_a256gcm_fail;
    }

    // decrypt ciphertext to plaintext buffer
    if (EVP_DecryptUpdate(ctx, 
            jwe->dat, &bytes_decrypted, 
            jwe->part[3].raw, jwe->part[3].raw_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_a256gcm_fail;
    }
    jwe->dat_len = bytes_decrypted;

    // finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, NULL, &bytes_decrypted) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_a256gcm_fail;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;

    _cjose_jwe_decrypt_dat_a256gcm_fail:
    if (NULL != ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
    return false;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jwe_decrypt_dat_aes_cbc(
        cjose_jwe_t *jwe,
        cjose_err *err)
{
    // make sure we have an enc header
    json_t *enc_obj = json_object_get(jwe->hdr, CJOSE_HDR_ENC);
    if (NULL == enc_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *enc = json_string_value(enc_obj);

    // calculate Authentication Tag
    unsigned int tag_len = 0;
    uint8_t tag[EVP_MAX_MD_SIZE];
    if (_cjose_jwe_calc_auth_tag(enc, jwe, (unsigned char *) &tag, &tag_len, err) == false)
    {
        return false;
    }

    // compare the provided Authentication Tag against our calculation
    if ((tag_len != jwe->part[4].raw_len) || (cjose_const_memcmp(tag, jwe->part[4].raw, tag_len) != 0))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    // get the AES cipher
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;

    if (strcmp(enc, CJOSE_HDR_ENC_A128CBC_HS256) == 0)
        cipher = EVP_aes_128_cbc();
    if (strcmp(enc, CJOSE_HDR_ENC_A192CBC_HS384) == 0)
        cipher = EVP_aes_192_cbc();
    if (strcmp(enc, CJOSE_HDR_ENC_A256CBC_HS512) == 0)
        cipher = EVP_aes_256_cbc();

    if (NULL == cipher)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_aes_cbc_fail;
    }

    // instantiate and initialize a new openssl cipher context
    ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_aes_cbc_fail;
    }
    EVP_CIPHER_CTX_init(ctx);

    // initialize context for decryption using the cipher, the 2nd half of the CEK and the IV
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, jwe->cek + jwe->cek_len / 2, jwe->part[2].raw) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_aes_cbc_fail;
    }

    // allocate buffer for the plaintext + one block padding
    int p_len = jwe->part[3].raw_len, f_len = 0;
    cjose_get_dealloc()(jwe->dat);
    jwe->dat_len = p_len + AES_BLOCK_SIZE;
    if (!_cjose_jwe_malloc(jwe->dat_len, false, &jwe->dat, err))
    {
        goto _cjose_jwe_decrypt_dat_aes_cbc_fail;
    }

    // decrypt ciphertext to plaintext buffer
    if (EVP_DecryptUpdate(ctx, jwe->dat, &p_len, jwe->part[3].raw, jwe->part[3].raw_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_aes_cbc_fail;
    }

    // finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, jwe->dat + p_len, &f_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwe_decrypt_dat_aes_cbc_fail;
    }
    jwe->dat_len = p_len + f_len;

    EVP_CIPHER_CTX_free(ctx);

    return true;

    _cjose_jwe_decrypt_dat_aes_cbc_fail:
    if (NULL != ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
    return false;
}

////////////////////////////////////////////////////////////////////////////////
cjose_jwe_t *cjose_jwe_encrypt(
        const cjose_jwk_t *jwk,
        cjose_header_t *protected_header,
        const uint8_t *plaintext,
        size_t plaintext_len,
        cjose_err *err)
{
    cjose_jwe_t *jwe = NULL;

    if (NULL == jwk || NULL == protected_header)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // if not already set, add kid header to JWE to match that of JWK
    const char *kid = cjose_jwk_get_kid(jwk, err);
    if (NULL != kid) {
        if (!cjose_header_set(protected_header, CJOSE_HDR_KID, kid, err)) 
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_STATE);
            return false;
        }
    }

    // allocate and initialize a new JWE object
    if (!_cjose_jwe_malloc(sizeof(cjose_jwe_t), false, (uint8_t **)&jwe, err))
    {
        return NULL;
    }

    // validate JWE header
    if (!_cjose_jwe_validate_hdr(jwe, protected_header, err))
    {
        cjose_jwe_release(jwe);
        return NULL;
    }

    // build JWE header
    if (!_cjose_jwe_build_hdr(jwe, protected_header, err))
    {
        cjose_jwe_release(jwe);
        return NULL;
    }

    // build JWE content-encryption key and encrypted key
    if (!jwe->fns.encrypt_ek(jwe, jwk, err))
    {
        cjose_jwe_release(jwe);
        return NULL;
    }

    // build JWE initialization vector
    if (!jwe->fns.set_iv(jwe, err))
    {
        cjose_jwe_release(jwe);
        return NULL;
    }

    // build JWE encrypted data and authentication tag
    if (!jwe->fns.encrypt_dat(jwe, plaintext, plaintext_len, err))
    {
        cjose_jwe_release(jwe);
        return NULL;
    }

    return jwe;
}


////////////////////////////////////////////////////////////////////////////////
void cjose_jwe_release(
        cjose_jwe_t *jwe)
{
    if (NULL == jwe)
    {
        return;
    }
    if (NULL != jwe->hdr)
    {
        json_decref(jwe->hdr);
    }

    for (int i = 0; i < 5; ++i)
    {
        cjose_get_dealloc()(jwe->part[i].raw);
        cjose_get_dealloc()(jwe->part[i].b64u);
    }
    cjose_get_dealloc()(jwe->cek);
    cjose_get_dealloc()(jwe->dat);
    cjose_get_dealloc()(jwe);
}

////////////////////////////////////////////////////////////////////////////////
char *cjose_jwe_export(
        cjose_jwe_t *jwe,
        cjose_err *err)
{
    char *cser = NULL;
    size_t cser_len = 0;

    if (NULL == jwe)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // make sure all parts are b64u encoded
    for (int i = 0; i < 5; ++i)
    {
        if ((NULL == jwe->part[i].b64u) && 
            (!cjose_base64url_encode(
            (const uint8_t *)jwe->part[i].raw, jwe->part[i].raw_len, 
            &jwe->part[i].b64u, &jwe->part[i].b64u_len, err)))
        {
            return NULL;
        }    
    }

    // compute length of compact serialization
    cser_len = 0;
    for (int i = 0; i < 5; ++i)
    {
        cser_len += jwe->part[i].b64u_len + 1;
    }

    // allocate buffer for compact serialization
    if (!_cjose_jwe_malloc(cser_len, false, (uint8_t **)&cser, err))
    {
        return NULL;
    }

    // build the compact serialization
    snprintf(cser, cser_len, "%s.%s.%s.%s.%s", jwe->part[0].b64u, 
            jwe->part[1].b64u, jwe->part[2].b64u, 
            jwe->part[3].b64u, jwe->part[4].b64u);

    return cser;
}


////////////////////////////////////////////////////////////////////////////////
bool _cjose_jwe_import_part(
        cjose_jwe_t *jwe,
        size_t p,
        const char *b64u,
        size_t b64u_len,
        cjose_err *err)
{
    // only the ek and the data parts may be of zero length
    if (b64u_len == 0 && p != 1 && p != 3)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // copy the b64u part to the jwe
    jwe->part[p].b64u = _cjose_strndup(b64u, b64u_len, err);
    jwe->part[p].b64u_len = b64u_len;

    // b64u decode the part
    if (!cjose_base64url_decode(
            jwe->part[p].b64u, jwe->part[p].b64u_len, 
            (uint8_t **)&jwe->part[p].raw, &jwe->part[p].raw_len, err) ||
            NULL == jwe->part[p].raw)
    {
        return false;        
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////
cjose_jwe_t *cjose_jwe_import(
        const char *cser,
        size_t cser_len,
        cjose_err *err)
{
    cjose_jwe_t *jwe = NULL;

    if (NULL == cser)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // allocate and initialize a new JWE object
    if (!_cjose_jwe_malloc(sizeof(cjose_jwe_t), false, (uint8_t **)&jwe, err))
    {
        return NULL;
    }

    // import each part of the compact serialization
    int part = 0;
    int idx = 0;
    int start_idx = 0;
    while (idx <= cser_len && part < 5)
    {
        if ((idx == cser_len) || (cser[idx] == '.'))
        {
            if (!_cjose_jwe_import_part(
                    jwe, part++, cser + start_idx, idx - start_idx, err))
            {
                cjose_jwe_release(jwe);
                return NULL;                
            }
            start_idx = idx + 1;
        }
        if (part < 5) ++idx;
    }

    // fail if we didn't find enough parts
    if (part != 5)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jwe_release(jwe);
        return NULL;
    }

    // fail if we finished early (e.g. more than 5 parts)
    if (idx != cser_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jwe_release(jwe);
        return NULL;        
    }

    // deserialize JSON header
    jwe->hdr = json_loadb(
               (const char *)jwe->part[0].raw, jwe->part[0].raw_len, 0, NULL);
    if (NULL == jwe->hdr)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jwe_release(jwe);
        return NULL;
    }

    // validate the JSON header
    if (!_cjose_jwe_validate_hdr(jwe, jwe->hdr, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jwe_release(jwe);
        return NULL;        
    }

    return jwe;
}


////////////////////////////////////////////////////////////////////////////////
uint8_t *cjose_jwe_decrypt(
        cjose_jwe_t *jwe,
        const cjose_jwk_t *jwk,
        size_t *content_len,
        cjose_err *err)
{
    if (NULL == jwe || NULL == jwk || NULL == content_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

     // decrypt JWE content-encryption key from encrypted key
    if (!jwe->fns.decrypt_ek(jwe, jwk, err))
    {
        return NULL;
    }

    // decrypt JWE encrypted data
    if (!jwe->fns.decrypt_dat(jwe, err))
    {
        return NULL;
    }

    // take the plaintext data from the jwe object
    uint8_t *content = jwe->dat;
    *content_len = jwe->dat_len;
    jwe->dat = NULL;
    jwe->dat_len = 0;

    return content;
}

////////////////////////////////////////////////////////////////////////////////
cjose_header_t *cjose_jwe_get_protected(cjose_jwe_t *jwe)
{
    if (NULL == jwe)
    {
        return NULL;
    }
    return jwe->hdr;
}
