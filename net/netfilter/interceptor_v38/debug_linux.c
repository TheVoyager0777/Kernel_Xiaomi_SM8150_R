/**
   @copyright
   Copyright (c) 2011 - 2018, Rambus Inc. All rights reserved.
*/

#include "implementation_defs.h"
#include "debug_filter.h"

#include <linux/module.h>

static const char *
last_slash(const char *str)
{
    const char *last = str;

    while (*str != 0)
    {
        if (*str == '/')
          last = str;

        str++;
    }

    return last + 1;
}


void
debug_outputf(
        const char *level,
        const char *flow,
        const char *module,
        const char *file,
        int line,
        const char *func,
        const char *format, ...)
{
    if (debug_filter(level, flow, module, file, func))
    {
        va_list args;

        printk("%s %s %s:%d ", level, module, last_slash(file), line);
        va_start(args, format);
        vprintk(format, args);
        va_end(args);
        printk("\n");
    }
}

#ifdef DEBUG_LIGHT

#include "debug_filter.h"

#define MAX_DEBUG_STRING_LEN 1024
static char debug_filter_string[MAX_DEBUG_STRING_LEN];

static int
debug_filter_string_set(
        const char *arg,
        const struct kernel_param *kp)
{
    if (strlen(arg) >= MAX_DEBUG_STRING_LEN)
    {
        printk(KERN_ERR "debug_filter_string too long\n");
        return -ENOSPC;
    }

    printk(KERN_INFO "Using debug string: %s\n", arg);

    strcpy(debug_filter_string, arg);
    debug_filter_set_string(debug_filter_string);

    return 0;
}

static int
debug_filter_string_get(
        char *arg,
        const struct kernel_param *kp)
{
    strcpy(arg, debug_filter_string);

    return strlen(arg);
}

static struct kernel_param_ops debug_filter_ops =
{
    .set = debug_filter_string_set,
    .get = debug_filter_string_get,
};

module_param_cb(
        debug_filter_string,
        &debug_filter_ops,
        NULL,
        0644);

MODULE_PARM_DESC(
        debug_filter_string,
        "Filter for debug logs. [+-] level,flow,module,file,func ; ...");

#endif
