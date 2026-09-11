/*
 * RISC-V RERI HART Component Emulation
 *
 * Copyright (c) 2023 Ventana Micro Systems, Inc.
 *
 * Author: Himanshu Chauhan <hchauhan@ventanamicro.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 or
 * (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/coroutine.h"
#include "qemu/cutils.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "target/riscv/cpu.h"
#include "hw/core/cpu.h"
#include "cpu-qom.h"
#include "hw/irq.h"
#include "hw/riscv/riscv_reri_hart_dev.h"
#include "hw/riscv/riscv_reri_helper.h"


static void coroutine_fn riscv_error_inject(void *opaque);

static int riscv_reri_status_severity(RiscvReriStatus status)
{
    if (status.uec) {
        return 2;
    }
    if (status.ued) {
        return 1;
    }
    if (status.ce) {
        return 0;
    }
    return -1;
}

/*
 * QEMU models the records of a hart bank as a common pool.  Prefer an
 * invalid record.  If the pool is full, target the valid record holding
 * the lowest severity and, within that severity, the lowest priority.
 * The per-record RERI overwrite rules still make the final decision.
 */
static int riscv_reri_select_record(RiscvReriState *s)
{
    int victim = 0;
    int victim_severity;
    uint8_t victim_priority;

    for (uint32_t i = 0; i < s->nr_records; i++) {
        if (!s->err_banks->records[i].status_i.v) {
            return i;
        }
    }

    victim_severity = riscv_reri_status_severity(
        s->err_banks->records[0].status_i);
    victim_priority = s->err_banks->records[0].status_i.pri;

    for (uint32_t i = 1; i < s->nr_records; i++) {
        RiscvReriStatus status = s->err_banks->records[i].status_i;
        int severity = riscv_reri_status_severity(status);

        if (severity < victim_severity ||
            (severity == victim_severity && status.pri < victim_priority)) {
            victim = i;
            victim_severity = severity;
            victim_priority = status.pri;
        }
    }

    return victim;
}

int riscv_reri_inject(void *opaque, int record, RiscvReriStatus sts,
                      vaddr addr, uint64_t info)
{
    RiscvReriState *s = opaque;
    RiscvReriErrorBank *bank = s->err_banks;
    int signal = 0;
    int rc;

    if (!bank || record < -1 ||
        (record >= 0 && (uint32_t)record >= s->nr_records) ||
        sts.ce + sts.ued + sts.uec != 1) {
        return EINVAL;
    }

    qemu_mutex_lock(&s->lock);
    if (record == -1) {
        record = riscv_reri_select_record(s);
    }
    rc = riscv_reri_do_inject(&bank->records[record], sts, addr, info);
    if (sts.uec) {
        signal = bank->records[record].control_i.uecs;
    } else if (sts.ued) {
        signal = bank->records[record].control_i.ueds;
    } else {
        signal = bank->records[record].control_i.ces;
    }
    qemu_mutex_unlock(&s->lock);

    if (signal == 1) {
        qemu_irq_raise(s->irqs[IRQ_LOW_PRIORITY]);
    } else if (signal == 2) {
        qemu_irq_raise(s->irqs[IRQ_HIGH_PRIORITY]);
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "RERI hart %u hardware injection: record=%d "
                  "status=0x%016" PRIx64 " addr=0x%016" PRIx64 "\n",
                  s->hartid, record, sts.value, (uint64_t)addr);
    return rc;
}

static char *riscv_reri_hart_get_inject(Object *obj, Error **errp)
{
    return g_strdup("record|auto,severity,priority,error-code,address,info");
}

static void riscv_reri_hart_set_inject(Object *obj, const char *value,
                                       Error **errp)
{
    RiscvReriState *s = RISCV_RERI_HART_STATE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ",", -1);
    RiscvReriStatus status = { .value = 0 };
    uint64_t priority;
    uint64_t error_code;
    uint64_t address;
    uint64_t info;
    int record;
    int rc;

    if (g_strv_length(fields) != 6) {
        error_setg(errp, "Expected record|auto,severity,priority,"
                   "error-code,address,info");
        return;
    }

    for (int i = 0; i < 6; i++) {
        g_strstrip(fields[i]);
    }

    if (!strcmp(fields[0], "auto")) {
        record = -1;
    } else if (qemu_strtoi(fields[0], NULL, 0, &record)) {
        error_setg(errp, "Invalid RERI record '%s'", fields[0]);
        return;
    }

    if (!strcmp(fields[1], "ce")) {
        status.ce = 1;
    } else if (!strcmp(fields[1], "ued")) {
        status.ued = 1;
    } else if (!strcmp(fields[1], "uec")) {
        status.uec = 1;
    } else {
        error_setg(errp, "Invalid RERI severity '%s'; use ce, ued, or uec",
                   fields[1]);
        return;
    }

    if (qemu_strtou64(fields[2], NULL, 0, &priority) || priority > 3) {
        error_setg(errp, "RERI priority must be between 0 and 3");
        return;
    }
    if (qemu_strtou64(fields[3], NULL, 0, &error_code) ||
        error_code > UINT8_MAX) {
        error_setg(errp, "RERI error code must be between 0 and 255");
        return;
    }
    if (qemu_strtou64(fields[4], NULL, 0, &address)) {
        error_setg(errp, "Invalid RERI address '%s'", fields[4]);
        return;
    }
    if (qemu_strtou64(fields[5], NULL, 0, &info)) {
        error_setg(errp, "Invalid RERI information value '%s'", fields[5]);
        return;
    }

    status.pri = priority;
    status.ec = error_code;
    status.ait = 1;
    status.iv = 1;

    rc = riscv_reri_inject(s, record, status, address, info);
    if (rc) {
        error_setg(errp, "RERI hardware injection failed (%d)", rc);
    }
}

static MemTxResult riscv_reri_hart_read_impl(void *opaque, hwaddr addr,
                                             uint64_t *data, unsigned size,
                                             MemTxAttrs attrs)
{
    RiscvReriState *s = opaque;
    int error;


    qemu_mutex_lock(&s->lock);
    error = riscv_reri_read(s->err_banks, addr, data, size);
    qemu_mutex_unlock(&s->lock);
    if (error != 0) {
        return MEMTX_ERROR;
    }

    return MEMTX_OK;
}

static MemTxResult riscv_reri_hart_write_impl(void *opaque, hwaddr addr,
                                              uint64_t val64, unsigned int size,
                                              MemTxAttrs attrs)
{
    RiscvReriState *s = opaque;
    bool inject = false;
    bool clrsts = false;
    int error;


    qemu_mutex_lock(&s->lock);
    error = riscv_reri_write(s->err_banks, addr, val64, size, &inject, &clrsts);
    qemu_mutex_unlock(&s->lock);
    if (error != 0) {
        return MEMTX_ERROR;
    }

    if (inject) {
        if (s->w.to_wake != NULL) {
            qemu_co_sleep_wake(&s->w);
        } else {
            qemu_coroutine_enter_if_inactive(s->co);
        }
    }

    if (clrsts) {
	    qemu_irq_lower(s->irqs[IRQ_HIGH_PRIORITY]);
    }

    return MEMTX_OK;
}

static void coroutine_fn riscv_error_inject(void *opaque)
{
    RiscvReriState *s = opaque;
    bool waiting;

    do {
        waiting = false;

        qemu_mutex_lock(&s->lock);
        for (uint32_t index = 0; index < s->nr_records; index++) {
            int rc = riscv_error_injection_tick(&s->err_banks->records[index]);

            if (rc == RISCV_RERI_INJECT_WAIT) {
                waiting = true;
            } else if (rc == RISCV_RERI_INJECT_LOW) {
                qemu_irq_raise(s->irqs[IRQ_LOW_PRIORITY]);
            } else if (rc == RISCV_RERI_INJECT_HIGH) {
                qemu_irq_raise(s->irqs[IRQ_HIGH_PRIORITY]);
            }
        }
        qemu_mutex_unlock(&s->lock);

        if (waiting) {
            qemu_co_sleep_ns_wakeable(&s->w, QEMU_CLOCK_VIRTUAL, 1000000);
        }
    } while (waiting);
}

static const MemoryRegionOps riscv_reri_hart_ops = {
    .read_with_attrs = riscv_reri_hart_read_impl,
    .write_with_attrs = riscv_reri_hart_write_impl,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8
    }
};

static const Property riscv_reri_hart_properties[] = {
    DEFINE_PROP_UINT32("hartid", RiscvReriState, hartid, 0),
    DEFINE_PROP_UINT32("records", RiscvReriState, nr_records, 1),
};

static void riscv_reri_hart_realize(DeviceState *dev, Error **errp)
{
    RiscvReriState *s = RISCV_RERI_HART_STATE(dev);
    RISCVCPU *cpu;
    CPUState *cpu_state;


    qdev_init_gpio_out(dev, s->irqs, RISCV_RERI_IRQS);

    cpu_state = cpu_by_arch_id(s->hartid);
    if (!cpu_state)
        return;

    cpu = RISCV_CPU(cpu_state);

    s->err_banks = (RiscvReriErrorBank *)malloc(sizeof(RiscvReriErrorBank));
    memset(s->err_banks, 0, sizeof(RiscvReriErrorBank));
    s->nr_err_banks = 1;

    riscv_reri_register_init(s->err_banks, 0x1af4, 0xabcd, s->nr_records);

    memory_region_init_io(&s->iomem, OBJECT(dev), &riscv_reri_hart_ops,
                          s, TYPE_RISCV_RERI_HART_DEV, RISCV_RERI_DEV_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->iomem);

    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irqs[IRQ_HIGH_PRIORITY]);
    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irqs[IRQ_LOW_PRIORITY]);

    if (riscv_cpu_claim_interrupts(cpu, MIP_RASHIP) < 0) {
            fprintf(stderr, "%s: Already claimed MIP_RASHIP\n", __func__);
            exit(1);
    }

    if (riscv_cpu_claim_interrupts(cpu, MIP_RASLOP) < 0) {
            fprintf(stderr, "%s: Already claimed MIP_RASLOP\n", __func__);
            exit(1);
    }

    s->co = qemu_coroutine_create(riscv_error_inject, s);
    qemu_mutex_init(&s->lock);
}

static void riscv_reri_hart_reset(Object *obj, ResetType type)
{
}

static void riscv_reri_hart_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = riscv_reri_hart_realize;
    device_class_set_props(dc, riscv_reri_hart_properties);
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    rc->phases.enter = riscv_reri_hart_reset;

    object_class_property_add_str(klass, "x-reri-inject",
                                  riscv_reri_hart_get_inject,
                                  riscv_reri_hart_set_inject);
    object_class_property_set_description(
        klass, "x-reri-inject", "Test-only hardware RERI injection");
}

static const TypeInfo riscv_reri_hart_info = {
    .name = TYPE_RISCV_RERI_HART_DEV,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(RiscvReriState),
    .class_init = riscv_reri_hart_class_init,
};

DeviceState *riscv_reri_hart_create(hwaddr addr, uint32_t hartid,
                                 uint32_t records)
{
    DeviceState *dev = qdev_new(TYPE_RISCV_RERI_HART_DEV);
    CPUState *cpu = cpu_by_arch_id(hartid);
    RISCVCPU *rvcpu = RISCV_CPU(cpu);
    g_autofree char *name = g_strdup_printf("reri-hart%u", hartid);

    assert(!(addr & 0x3));

    object_property_add_child(qdev_get_machine(), name, OBJECT(dev));

    qdev_prop_set_uint32(dev, "hartid", hartid);
    qdev_prop_set_uint32(dev, "records", records);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);

    qdev_connect_gpio_out(dev, 0, qdev_get_gpio_in(DEVICE(rvcpu), IRQ_RAS_LOW));
    qdev_connect_gpio_out(dev, 1, qdev_get_gpio_in(DEVICE(rvcpu), IRQ_RAS_HIGH));

    return dev;
}

static void riscv_reri_hart_dev_register_types(void)
{
    type_register_static(&riscv_reri_hart_info);
}

type_init(riscv_reri_hart_dev_register_types);
