/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */


#include <stdlib.h>
#include <jansson.h>
#include "cjose/header.h"
#include "include/header_int.h"


const char *CJOSE_HDR_ALG = "alg";
const char *CJOSE_HDR_ALG_RSA_OAEP = "RSA-OAEP";
const char *CJOSE_HDR_ALG_DIR = "dir";
const char *CJOSE_HDR_ALG_PS256 = "PS256";
const char *CJOSE_HDR_ALG_PS384 = "PS384";
const char *CJOSE_HDR_ALG_PS512 = "PS512";
const char *CJOSE_HDR_ALG_RS256 = "RS256";
const char *CJOSE_HDR_ALG_RS384 = "RS384";
const char *CJOSE_HDR_ALG_RS512 = "RS512";
const char *CJOSE_HDR_ALG_HS256 = "HS256";
const char *CJOSE_HDR_ALG_HS384 = "HS384";
const char *CJOSE_HDR_ALG_HS512 = "HS512";

const char *CJOSE_HDR_ENC = "enc";
const char *CJOSE_HDR_ENC_A256GCM = "A256GCM";

const char *CJOSE_HDR_CTY = "cty";

const char *CJOSE_HDR_KID = "kid";

////////////////////////////////////////////////////////////////////////////////
cjose_header_t *cjose_header_new(
        cjose_err *err)
{
    cjose_header_t *retval = json_object();
    if (NULL == retval)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
    }
    return retval;
}

////////////////////////////////////////////////////////////////////////////////
cjose_header_t *cjose_header_retain(
        cjose_header_t *header)
{
    if (NULL != header)
    {
        header = json_incref(header);
    }
    return header;
}

////////////////////////////////////////////////////////////////////////////////
void cjose_header_release(
        cjose_header_t *header)
{
    if (NULL != header)
    {
        json_decref(header);
    }
}


////////////////////////////////////////////////////////////////////////////////
bool cjose_header_set(
        cjose_header_t *header,
        const char *attr,
        const char *value,
        cjose_err *err)
{
    if (NULL == header || NULL == attr || NULL == value)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    json_t *value_obj = json_string(value);
    if (NULL == value_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    json_object_set(
            header, attr, value_obj);

    json_decref(value_obj);

    return true;
}


////////////////////////////////////////////////////////////////////////////////
const char *cjose_header_get(
        cjose_header_t *header,
        const char *attr,
        cjose_err *err)
{
    if (NULL == header || NULL == attr)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    json_t *value_obj = json_object_get(header, attr);
    if (NULL == value_obj)
    {
        return NULL;
    }

    return json_string_value(value_obj);
}
