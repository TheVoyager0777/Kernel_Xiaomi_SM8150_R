/*
 * Generic GPIO card-detect helper
 *
 * Copyright (C) 2011, Guennadi Liakhovetski <g.liakhovetski@gmx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/mmc/host.h>
#include <linux/mmc/slot-gpio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/extcon.h>

#include "slot-gpio.h"

struct mmc_gpio {
	struct gpio_desc *ro_gpio;
	struct gpio_desc *cd_gpio;
	bool override_ro_active_level;
	bool override_cd_active_level;
	irqreturn_t (*cd_gpio_isr)(int irq, void *dev_id);
	char *ro_label;
	char cd_label[0];
};

#ifdef CONFIG_MACH_LGE
extern unsigned int is_damaged_sd;
static int old_gpio = -1;
#endif

#ifdef CONFIG_LGE_TRAY_EVENT //support the TRAY uevent
static int send_sd_slot_tray_state (struct mmc_host *host, int state) {
	char event_string[20]; /* check the event string length */
	char *envp[2] = { event_string, NULL };

	if (state)
		sprintf(event_string, "TRAY_STATE=INSERTED");
	else
		sprintf(event_string, "TRAY_STATE=EJECTED");

	pr_info("%s: %s", __func__, envp[0]);
	return kobject_uevent_env(&host->class_dev.kobj, KOBJ_CHANGE, envp);
}
#endif

static irqreturn_t mmc_gpio_cd_irqt(int irq, void *dev_id)
{
	/* Schedule a card detection after a debounce timeout */
	struct mmc_host *host = dev_id;
	int present = host->ops->get_cd(host);

	pr_debug("%s: cd gpio irq, gpio state %d (CARD_%s)\n",
		mmc_hostname(host), present, present?"INSERT":"REMOVAL");

	host->trigger_card_event = true;

#ifdef CONFIG_MACH_LGE
	/* LGE_CHANGE, BSP-FS@lge.com
	 * Insertion log of slot detection
	*/
	if(mmc_card_is_removable(host))
		is_damaged_sd = 0;

	pr_info("[LGE][MMC] %s: slot status change detected(%s), GPIO_ACTIVE_%s\n",
		mmc_hostname(host), mmc_gpio_get_cd(host) ?
		"INSERTED" : "EJECTED",
		(host->caps2 & MMC_CAP2_CD_ACTIVE_HIGH) ?
		"HIGH" : "LOW");
#endif

#ifdef CONFIG_MACH_LGE
	pr_info("[LGE][MMC] %s: mmc_gpio_get_cd = %d old_gpio = %d \n", mmc_hostname(host), mmc_gpio_get_cd(host), old_gpio);
	if(old_gpio == mmc_gpio_get_cd(host))
		return IRQ_HANDLED;
	old_gpio = mmc_gpio_get_cd(host);
#endif
	mmc_detect_change(host, msecs_to_jiffies(200));

#ifdef CONFIG_LGE_TRAY_EVENT //support the TRAY uevent
	if (send_sd_slot_tray_state(host, old_gpio) < 0)
		pr_err("%s: send_sd_slot_tray_state was failed.\n", __func__);
#endif

	return IRQ_HANDLED;
}

int mmc_gpio_alloc(struct mmc_host *host)
{
	size_t len = strlen(dev_name(host->parent)) + 4;
	struct mmc_gpio *ctx = devm_kzalloc(host->parent,
				sizeof(*ctx) + 2 * len,	GFP_KERNEL);

	if (ctx) {
		ctx->ro_label = ctx->cd_label + len;
		snprintf(ctx->cd_label, len, "%s cd", dev_name(host->parent));
		snprintf(ctx->ro_label, len, "%s ro", dev_name(host->parent));
		host->slot.handler_priv = ctx;
		host->slot.cd_irq = -EINVAL;
	}

	return ctx ? 0 : -ENOMEM;
}

int mmc_gpio_get_ro(struct mmc_host *host)
{
	struct mmc_gpio *ctx = host->slot.handler_priv;

	if (!ctx || !ctx->ro_gpio)
		return -ENOSYS;

	if (ctx->override_ro_active_level)
		return !gpiod_get_raw_value_cansleep(ctx->ro_gpio) ^
			!!(host->caps2 & MMC_CAP2_RO_ACTIVE_HIGH);

	return gpiod_get_value_cansleep(ctx->ro_gpio);
}
EXPORT_SYMBOL(mmc_gpio_get_ro);

int mmc_gpio_get_cd(struct mmc_host *host)
{
	struct mmc_gpio *ctx = host->slot.handler_priv;
	int ret;

	if (host->extcon) {
		ret =  extcon_get_state(host->extcon, EXTCON_MECHANICAL);
		if (ret < 0)
			dev_err(mmc_dev(host), "%s: Extcon failed to check card state, ret=%d\n",
					__func__, ret);
		return ret;
	}

	if (!ctx || !ctx->cd_gpio)
		return -ENOSYS;

	if (ctx->override_cd_active_level)
		return !gpiod_get_raw_value_cansleep(ctx->cd_gpio) ^
			!!(host->caps2 & MMC_CAP2_CD_ACTIVE_HIGH);

	return gpiod_get_value_cansleep(ctx->cd_gpio);
}
EXPORT_SYMBOL(mmc_gpio_get_cd);

/**
 * mmc_gpio_request_ro - request a gpio for write-protection
 * @host: mmc host
 * @gpio: gpio number requested
 *
 * As devm_* managed functions are used in mmc_gpio_request_ro(), client
 * drivers do not need to worry about freeing up memory.
 *
 * Returns zero on success, else an error.
 */
int mmc_gpio_request_ro(struct mmc_host *host, unsigned int gpio)
{
	struct mmc_gpio *ctx = host->slot.handler_priv;
	int ret;

	if (!gpio_is_valid(gpio))
		return -EINVAL;

	ret = devm_gpio_request_one(host->parent, gpio, GPIOF_DIR_IN,
				    ctx->ro_label);
	if (ret < 0)
		return ret;

	ctx->override_ro_active_level = true;
	ctx->ro_gpio = gpio_to_desc(gpio);

	return 0;
}
EXPORT_SYMBOL(mmc_gpio_request_ro);

void mmc_gpiod_free_cd_irq(struct mmc_host *host)
{
	devm_free_irq(host->parent, host->slot.cd_irq, host);
}
EXPORT_SYMBOL(mmc_gpiod_free_cd_irq);

void mmc_gpiod_restore_cd_irq(struct mmc_host *host)
{
	struct mmc_gpio *ctx = host->slot.handler_priv;
	int irq = host->slot.cd_irq;

	if (irq >= 0) {
		devm_request_threaded_irq(host->parent, irq,
			NULL, ctx->cd_gpio_isr,
			IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING |
			IRQF_ONESHOT,
			ctx->cd_label, host);
	}
}
EXPORT_SYMBOL(mmc_gpiod_restore_cd_irq);

void mmc_gpiod_request_cd_irq(struct mmc_host *host)
{
	struct mmc_gpio *ctx = host->slot.handler_priv;
	int ret, irq;

	if (host->slot.cd_irq >= 0 || !ctx || !ctx->cd_gpio)
		return;

	irq = gpiod_to_irq(ctx->cd_gpio);

	/*
	 * Even if gpiod_to_irq() returns a valid IRQ number, the platform might
	 * still prefer to poll, e.g., because that IRQ number is already used
	 * by another unit and cannot be shared.
	 */
	if (irq >= 0 && host->caps & MMC_CAP_NEEDS_POLL)
		irq = -EINVAL;

	if (irq >= 0) {
		if (!ctx->cd_gpio_isr)
			ctx->cd_gpio_isr = mmc_gpio_cd_irqt;
		ret = devm_request_threaded_irq(host->parent, irq,
			NULL, ctx->cd_gpio_isr,
			IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
			ctx->cd_label, host);
		if (ret < 0)
			irq = ret;
#ifdef CONFIG_LGE_TRAY_EVENT //support the TRAY uevent
		pr_debug("update initial TRAY status\n");
		if (send_sd_slot_tray_state(host, mmc_gpio_get_cd(host)) < 0)
			pr_err("%s: send_sd_slot_tray_state was failed.\n", __func__);
#endif
	}

	host->slot.cd_irq = irq;

	if (irq < 0)
		host->caps |= MMC_CAP_NEEDS_POLL;
	else if ((host->caps & MMC_CAP_CD_WAKE) && !enable_irq_wake(irq))
		host->slot.cd_wake_enabled = true;
}
EXPORT_SYMBOL(mmc_gpiod_request_cd_irq);

#ifdef CONFIG_LGE_TRAY_EVENT
static void work_tray_uevent_fn(struct work_struct *work)
{
	struct mmc_host *host = container_of(work, struct mmc_host, tray_work);

	if (send_sd_slot_tray_state(host, mmc_gpio_get_cd(host)) < 0)
		pr_err("%s: send_sd_slot_tray_state was failed.\n", __func__);
}

static void send_tray_uevent(struct mmc_host *host)
{
	bool ret;
	if (!host)
		return;

	ret = schedule_work(&host->tray_work);
	if (!ret)
		pr_err("[tray_uevent] work_tray_uevent is already in queue.\n");
}
#endif

static int mmc_card_detect_notifier(struct notifier_block *nb,
				       unsigned long event, void *ptr)
{
	struct mmc_host *host = container_of(nb, struct mmc_host,
					     card_detect_nb);

	host->trigger_card_event = true;

#ifdef CONFIG_MACH_LGE
	/* LGE_CHANGE, BSP-FS@lge.com
	 * Insertion log of slot detection
	*/
	if(mmc_card_is_removable(host))
		is_damaged_sd = 0;
#endif

	mmc_detect_change(host, 0);

#ifdef CONFIG_LGE_TRAY_EVENT //support the TRAY uevent
	send_tray_uevent(host);
#endif

	return NOTIFY_DONE;
}

void mmc_register_extcon(struct mmc_host *host)
{
	struct extcon_dev *extcon = host->extcon;
	int err;

	if (!extcon)
		return;

	host->card_detect_nb.notifier_call = mmc_card_detect_notifier;
	err = extcon_register_notifier(extcon, EXTCON_MECHANICAL,
				       &host->card_detect_nb);
	if (err) {
		dev_err(mmc_dev(host), "%s: extcon_register_notifier() failed ret=%d\n",
			__func__, err);
		host->caps |= MMC_CAP_NEEDS_POLL;
	}

#ifdef CONFIG_LGE_TRAY_EVENT //support the TRAY uevent
	INIT_WORK(&host->tray_work, work_tray_uevent_fn);

	pr_info("update initial TRAY status\n");
	send_tray_uevent(host);
#endif

}
EXPORT_SYMBOL(mmc_register_extcon);

void mmc_unregister_extcon(struct mmc_host *host)
{
	struct extcon_dev *extcon = host->extcon;
	int err;

	if (!extcon)
		return;

	err = extcon_unregister_notifier(extcon, EXTCON_MECHANICAL,
					 &host->card_detect_nb);
	if (err)
		dev_err(mmc_dev(host), "%s: extcon_unregister_notifier() failed ret=%d\n",
			__func__, err);
}
EXPORT_SYMBOL(mmc_unregister_extcon);

/* Register an alternate interrupt service routine for
 * the card-detect GPIO.
 */
void mmc_gpio_set_cd_isr(struct mmc_host *host,
			 irqreturn_t (*isr)(int irq, void *dev_id))
{
	struct mmc_gpio *ctx = host->slot.handler_priv;

	WARN_ON(ctx->cd_gpio_isr);
	ctx->cd_gpio_isr = isr;
}
EXPORT_SYMBOL(mmc_gpio_set_cd_isr);

/**
 * mmc_gpio_request_cd - request a gpio for card-detection
 * @host: mmc host
 * @gpio: gpio number requested
 * @debounce: debounce time in microseconds
 *
 * As devm_* managed functions are used in mmc_gpio_request_cd(), client
 * drivers do not need to worry about freeing up memory.
 *
 * If GPIO debouncing is desired, set the debounce parameter to a non-zero
 * value. The caller is responsible for ensuring that the GPIO driver associated
 * with the GPIO supports debouncing, otherwise an error will be returned.
 *
 * Returns zero on success, else an error.
 */
int mmc_gpio_request_cd(struct mmc_host *host, unsigned int gpio,
			unsigned int debounce)
{
	struct mmc_gpio *ctx = host->slot.handler_priv;
	int ret;

	ret = devm_gpio_request_one(host->parent, gpio, GPIOF_DIR_IN,
				    ctx->cd_label);
	if (ret < 0)
		/*
		 * don't bother freeing memory. It might still get used by other
		 * slot functions, in any case it will be freed, when the device
		 * is destroyed.
		 */
		return ret;

	if (debounce) {
		ret = gpio_set_debounce(gpio, debounce);
		if (ret < 0)
			return ret;
	}

	ctx->override_cd_active_level = true;
	ctx->cd_gpio = gpio_to_desc(gpio);

	return 0;
}
EXPORT_SYMBOL(mmc_gpio_request_cd);

/**
 * mmc_gpiod_request_cd - request a gpio descriptor for card-detection
 * @host: mmc host
 * @con_id: function within the GPIO consumer
 * @idx: index of the GPIO to obtain in the consumer
 * @override_active_level: ignore %GPIO_ACTIVE_LOW flag
 * @debounce: debounce time in microseconds
 * @gpio_invert: will return whether the GPIO line is inverted or not, set
 * to NULL to ignore
 *
 * Use this function in place of mmc_gpio_request_cd() to use the GPIO
 * descriptor API.  Note that it must be called prior to mmc_add_host()
 * otherwise the caller must also call mmc_gpiod_request_cd_irq().
 *
 * Returns zero on success, else an error.
 */
int mmc_gpiod_request_cd(struct mmc_host *host, const char *con_id,
			 unsigned int idx, bool override_active_level,
			 unsigned int debounce, bool *gpio_invert)
{
	struct mmc_gpio *ctx = host->slot.handler_priv;
	struct gpio_desc *desc;
	int ret;

	desc = devm_gpiod_get_index(host->parent, con_id, idx, GPIOD_IN);
	if (IS_ERR(desc))
		return PTR_ERR(desc);

	if (debounce) {
		ret = gpiod_set_debounce(desc, debounce);
		if (ret < 0)
			return ret;
	}

	if (gpio_invert)
		*gpio_invert = !gpiod_is_active_low(desc);

	ctx->override_cd_active_level = override_active_level;
	ctx->cd_gpio = desc;

	return 0;
}
EXPORT_SYMBOL(mmc_gpiod_request_cd);

bool mmc_can_gpio_cd(struct mmc_host *host)
{
	struct mmc_gpio *ctx = host->slot.handler_priv;

	return ctx->cd_gpio ? true : false;
}
EXPORT_SYMBOL(mmc_can_gpio_cd);

/**
 * mmc_gpiod_request_ro - request a gpio descriptor for write protection
 * @host: mmc host
 * @con_id: function within the GPIO consumer
 * @idx: index of the GPIO to obtain in the consumer
 * @override_active_level: ignore %GPIO_ACTIVE_LOW flag
 * @debounce: debounce time in microseconds
 * @gpio_invert: will return whether the GPIO line is inverted or not,
 * set to NULL to ignore
 *
 * Use this function in place of mmc_gpio_request_ro() to use the GPIO
 * descriptor API.
 *
 * Returns zero on success, else an error.
 */
int mmc_gpiod_request_ro(struct mmc_host *host, const char *con_id,
			 unsigned int idx, bool override_active_level,
			 unsigned int debounce, bool *gpio_invert)
{
	struct mmc_gpio *ctx = host->slot.handler_priv;
	struct gpio_desc *desc;
	int ret;

	desc = devm_gpiod_get_index(host->parent, con_id, idx, GPIOD_IN);
	if (IS_ERR(desc))
		return PTR_ERR(desc);

	if (debounce) {
		ret = gpiod_set_debounce(desc, debounce);
		if (ret < 0)
			return ret;
	}

	if (gpio_invert)
		*gpio_invert = !gpiod_is_active_low(desc);

	ctx->override_ro_active_level = override_active_level;
	ctx->ro_gpio = desc;

	return 0;
}
EXPORT_SYMBOL(mmc_gpiod_request_ro);
