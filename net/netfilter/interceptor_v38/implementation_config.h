/**
   @copyright
   Copyright (c) 2011 - 2018, Rambus Inc. All rights reserved.
*/


#ifndef IMPLEMENTATION_CONFIG_H
#define IMPLEMENTATION_CONFIG_H

#define DEBUG_IMPLEMENTATION_HEADER "debug_implementation.h"
#define STRING_HEADER "implementation_linux.h"

#define ASSERT_IMPLEMENTATION(condition, description)  \
    ((void) ((condition) ? 0 : panic(description)))

#endif /* IMPLEMENTATION_CONFIG_H */
