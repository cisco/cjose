/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "cjose/header.h"
#include "include/header_int.h"

static const char *CJOSE_HDR_CRIT = "crit";

////////////////////////////////////////////////////////////////////////////////
bool _cjose_header_validate_crit(
    cjose_header_t *const *headers, size_t headers_len, const char *const *supported, size_t supported_len, cjose_err *err)
{
    if (NULL == headers || 0 == headers_len)
    {
        return true;
    }

    // the list has to be integrity protected, so it may only appear in the
    // protected header (RFC 7515 section 4.1.11)
    for (size_t i = 1; i < headers_len; i++)
    {
        if (NULL != headers[i] && NULL != json_object_get((json_t *)headers[i], CJOSE_HDR_CRIT))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            return false;
        }
    }

    if (NULL == headers[0])
    {
        return true;
    }

    json_t *crit = json_object_get((json_t *)headers[0], CJOSE_HDR_CRIT);
    if (NULL == crit)
    {
        return true;
    }

    if (!json_is_array(crit))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // RFC 7515 section 4.1.11: if present, the "crit" list MUST NOT be empty
    if (0 == json_array_size(crit))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    size_t index = 0;
    json_t *entry = NULL;
    json_array_foreach(crit, index, entry)
    {
        if (!json_is_string(entry))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            return false;
        }

        const char *name = json_string_value(entry);
        bool found = false;
        for (size_t i = 0; i < supported_len; i++)
        {
            if (0 == strcmp(name, supported[i]))
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            return false;
        }

        // RFC 7515 section 4.1.11: the list must not carry duplicate names
        for (size_t i = 0; i < index; i++)
        {
            if (0 == strcmp(name, json_string_value(json_array_get(crit, i))))
            {
                CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
                return false;
            }
        }
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
bool _cjose_header_validate_crit_present(cjose_header_t *const *headers, size_t headers_len, cjose_err *err)
{
    if (NULL == headers || 0 == headers_len || NULL == headers[0])
    {
        return true;
    }

    json_t *crit = json_object_get((json_t *)headers[0], CJOSE_HDR_CRIT);
    if (!json_is_array(crit))
    {
        return true;
    }

    size_t index = 0;
    json_t *entry = NULL;
    json_array_foreach(crit, index, entry)
    {
        if (!json_is_string(entry))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            return false;
        }

        const char *name = json_string_value(entry);
        bool found = false;
        for (size_t i = 0; i < headers_len && !found; i++)
        {
            found = (NULL != headers[i]) && (NULL != json_object_get((json_t *)headers[i], name));
        }

        if (!found)
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            return false;
        }
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
bool _cjose_header_validate_disjoint(cjose_header_t *const *headers, size_t headers_len, cjose_err *err)
{
    if (NULL == headers)
    {
        return true;
    }

    for (size_t i = 0; i < headers_len; i++)
    {
        if (NULL == headers[i])
        {
            continue;
        }

        const char *name = NULL;
        json_t *value = NULL;
        json_object_foreach((json_t *)headers[i], name, value)
        {
            for (size_t j = i + 1; j < headers_len; j++)
            {
                if (NULL != headers[j] && NULL != json_object_get((json_t *)headers[j], name))
                {
                    CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
                    return false;
                }
            }
        }
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
cjose_header_t *cjose_header_new(cjose_err *err)
{
    cjose_header_t *retval = (cjose_header_t *)json_object();
    if (NULL == retval)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
    }
    return retval;
}

////////////////////////////////////////////////////////////////////////////////
cjose_header_t *cjose_header_retain(cjose_header_t *header)
{
    if (NULL != header)
    {
        header = (cjose_header_t *)json_incref((json_t *)header);
    }
    return header;
}

////////////////////////////////////////////////////////////////////////////////
void cjose_header_release(cjose_header_t *header)
{
    if (NULL != header)
    {
        json_decref((json_t *)header);
    }
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_header_set(cjose_header_t *header, const char *attr, const char *value, cjose_err *err)
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

    // json_object_set_new fails on OOM or an invalid attr key, and releases
    // value_obj either way; don't report success with the attribute unset
    if (0 != json_object_set_new((json_t *)header, attr, value_obj))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
const char *cjose_header_get(cjose_header_t *header, const char *attr, cjose_err *err)
{
    if (NULL == header || NULL == attr)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    json_t *value_obj = json_object_get((json_t *)header, attr);
    if (NULL == value_obj)
    {
        return NULL;
    }

    return json_string_value(value_obj);
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_header_set_raw(cjose_header_t *header, const char *attr, const char *value, cjose_err *err)
{
    if (NULL == header || NULL == attr || NULL == value)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    json_error_t j_err;
    // JSON_DECODE_ANY: the documented contract accepts any valid JSON value,
    // including a top-level scalar (e.g. RFC 7797 "b64":false), which jansson's
    // default (RFC 4627) mode rejects
    json_t *value_obj = json_loads(value, JSON_DECODE_ANY, &j_err);
    if (NULL == value_obj)
    {
        // unfortunately, it's not possible to tell whether the error is due
        // to syntax, or memory shortage. See https://github.com/akheron/jansson/issues/352
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // json_object_set_new fails on OOM or an invalid attr key, and releases
    // value_obj either way; don't report success with the attribute unset
    if (0 != json_object_set_new((json_t *)header, attr, value_obj))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
char *cjose_header_get_raw(cjose_header_t *header, const char *attr, cjose_err *err)
{
    if (NULL == header || NULL == attr)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    json_t *value_obj = json_object_get((json_t *)header, attr);
    if (NULL == value_obj)
    {
        return NULL;
    }

    // JSON_ENCODE_ANY so a top-level scalar value (see cjose_header_set_raw)
    // round-trips instead of returning NULL
    return json_dumps(value_obj, JSON_COMPACT | JSON_PRESERVE_ORDER | JSON_ENCODE_ANY);
}
