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
bool _cjose_header_validate_crit(cjose_header_t *header, const char *const *supported, size_t supported_len, cjose_err *err)
{
    if (NULL == header)
    {
        return true;
    }

    json_t *crit = json_object_get((json_t *)header, CJOSE_HDR_CRIT);
    if (NULL == crit)
    {
        return true;
    }

    if (!json_is_array(crit))
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

    json_object_set_new((json_t *)header, attr, value_obj);

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
    json_t *value_obj = json_loads(value, 0, &j_err);
    if (NULL == value_obj)
    {
        // unfortunately, it's not possible to tell whether the error is due
        // to syntax, or memory shortage. See https://github.com/akheron/jansson/issues/352
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    json_object_set_new((json_t *)header, attr, value_obj);

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

    return json_dumps(value_obj, JSON_COMPACT);
}
