#ifndef GUARD_H
#define GUARD_H
#include <stddef.h>
#if defined(X)
#  include "x.h"
#else
#  include "y.h"
#endif
// #include "commented.h"
/* #include "block.h" */
#endif
