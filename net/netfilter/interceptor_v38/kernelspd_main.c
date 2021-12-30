/**
   @copyright
   Copyright (c) 2013 - 2019, Rambus Inc. All rights reserved.
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>

#include "kernelspd_internal.h"
#include "package_version.h"

MODULE_DESCRIPTION("Kernel IPsec SPD " PACKAGE_VERSION);

struct KernelSpdNet *kernel_spd_net_head;

DEFINE_RWLOCK(spd_net_lock);

static int init_called = 0;

static int __init linux_spd_init(void)
{
    int status = 0;

    init_called = 1;

    spd_hooks_init();

    status = spd_proc_init();

    if (status != 0)
    {
        spd_proc_uninit();
    }

    DEBUG_HIGH("Kernel spd initialised.");

    printk(KERN_INFO "%s\n", PACKAGE_VERSION);
    printk(KERN_INFO "vpnclient kernel spd loaded.\n");

    return status;
}

static void __exit linux_spd_cleanup(void)
{
    DEBUG_HIGH("Kernel spd cleaning up.");

    spd_proc_uninit();

    printk(KERN_INFO "vpnclient kernel spd removed.\n");
}

MODULE_LICENSE("Proprietary");
module_init(linux_spd_init);
module_exit(linux_spd_cleanup);
