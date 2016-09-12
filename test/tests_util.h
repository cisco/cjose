#ifndef TEST_UTIL_C
#define TEST_UTIL_C

#include "cjose/cjose_config.h"

#ifndef HAVE_RANDOM
/**
 * Generate random
 *
 * \returns Random number from 0 to RAND_MAX  
 */
int random(void);

#endif
#endif
