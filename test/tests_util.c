#include "tests_util.h"
#include <stdlib.h>

#ifndef HAVE_RANDOM
int random(void)
{
	return rand();
}
#endif
