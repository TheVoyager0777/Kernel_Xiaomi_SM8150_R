/* 2018-01-25 ickjun.kim@lge.com LGP_DATA_ENV_PATCHCODEID [START] */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <net/patchcodeid.h>

void patch_code_id(const char* log){
// Do nothing. This API is only for checking patch code ID.
if (log == NULL) {} // dummy code.
}
/* 2018-01-25 ickjun.kim@lge.com LGP_DATA_ENV_PATCHCODEID [END] */
