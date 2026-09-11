/*
 * RISC-V RERI Emulation Helper
 *
 * Copyright (c) 2023 Rivos Inc
 * Copyright (c) 2023 Ventana Micro Systems, Inc.
 *
 * Author(s):
 * Dhaval Sharma <dhaval@rivosinc.com>
 * Himanshu Chauhan <hchauhan@ventanamicro.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 or
 * (at your option) any later version.
 */
#include "qemu/osdep.h"
#include "hw/riscv/riscv_reri_helper.h"
#include "qemu/log.h"

#define RERI_RECORD_SIZE   sizeof(RiscvReriErrorRecord) /* 64, non più hardcoded */

int riscv_reri_read(RiscvReriErrorBank *err_bank, uintptr_t addr, uint64_t *out,
                    unsigned size)
{
    uint64_t valid_summary = 1;
    uint64_t val64 = 0;
    uint32_t i;
    uint8_t *reg;
    if (addr + size > sizeof(RiscvReriErrorBank) ||
       ((addr & 0x7) + size) > 8) {
        return EINVAL;
    }

    for (i = 0; i < err_bank->bank_info.n_err_recs; i++) {
        valid_summary |=
            (uint64_t)err_bank->records[i].status_i.v << (i + 1);
    }

    err_bank->valid_summary = valid_summary;
    reg = ((uint8_t *)err_bank) + addr;
    while (size--) {
        val64 <<= 8;
        val64 |= *(reg + size);
    }
    *out = val64;
    return 0;
}

int riscv_reri_read_error_record(RiscvReriErrorBank *err_bank, uint32_t index,
                                 RiscvReriErrorRecord *record)
{
        RiscvReriErrorRecord *rec;
        if (!err_bank)
                return EINVAL;
        if (index >= err_bank->bank_info.n_err_recs)   /* fix: off-by-one */
                return ENOENT;
        rec = &err_bank->records[index];
        memcpy(record, rec, sizeof(RiscvReriErrorRecord));
        return 0;
}

int riscv_reri_write_error_record(RiscvReriErrorBank *err_bank, uint32_t index,
                                  RiscvReriErrorRecord *record)
{
        RiscvReriErrorRecord *rec;
        if (!err_bank)
                return EINVAL;
        if (index >= err_bank->bank_info.n_err_recs)   /* fix: off-by-one */
                return ENOENT;
        rec = &err_bank->records[index];
        memcpy(rec, record, sizeof(RiscvReriErrorRecord));
        return 0;
}

/*
 * Implements the "Error record writing rules" pseudocode from the
 * ratified RERI v1.0 spec, Section "Error Record Overwrite Rules".
 * Assumes the caller passes exactly one severity bit set in `new`
 * (ce XOR ued XOR uec), consistent with how this helper is invoked
 * both from register writes and from riscv_reri_do_inject().
 */
static uint64_t riscv_reri_write_status(RiscvReriStatus old,
                                        RiscvReriStatus new,
                                        bool *overwrite)
{
    *overwrite = false;
    new.value &= RERI_STS_MASK;
    qemu_log_mask(LOG_GUEST_ERROR, "%s: new status 0x%lx\n",
                  __func__, new.value);

    /* Only one error type can be injected per call. */
    if (new.ce + new.ued + new.uec != 1) {
        return old.value;
    }

    if (old.v == 0) {
        /* No valid error currently logged: clean new record. */
        old.rdip = 1;
        old.uec = new.uec;
        old.ued = new.ued & ~new.uec;
        old.ce  = new.ce & ~new.uec & ~new.ued;
        old.mo  = 0;
        *overwrite = true;
    } else {
        /* A valid error is already logged: apply severity/priority rules. */
        int old_sev = old.uec ? 2 : (old.ued ? 1 : (old.ce ? 0 : -1));
        int new_sev = new.uec ? 2 : (new.ued ? 1 : 0);

        if (new_sev > old_sev) {
            old.mo = 0;
            *overwrite = true;
        } else if (new_sev == old_sev) {
            old.mo = 1;
            if (new.pri > old.pri) {
                *overwrite = true;
            }
        }
        old.rdip = 0;
        old.uec |= new.uec;
        old.ued |= new.ued;
        old.ce  |= new.ce;

        if (!*overwrite) {
            return old.value;
        }
    }

    /* Overwrite path: copy the rest of the new error's fields in. */
    old.pri   = new.pri;
    old.c     = new.c;
    old.tt    = new.tt;
    old.ait   = new.ait;
    old.iv    = new.iv;
    old.siv   = new.siv;
    old.tsv   = new.tsv;
    old.scrub = new.scrub;
    old.ec    = new.ec;
    old.v     = 1;
    return old.value;
}

/*
 * Software writes to status_i prepare an EID injection.
 * V and RDIP are set by the device only when EID reaches zero.
 */
static uint64_t riscv_reri_stage_status(RiscvReriStatus old,
                                         RiscvReriStatus new)
{
    new.value &= RERI_STS_MASK;

    /* Do not modify a record that is already valid. */
    if (old.v) {
        return old.value;
    }

    new.v = 0;
    new.rdip = 0;
    new.mo = 0;

    return new.value;
}

int riscv_reri_write(RiscvReriErrorBank *err_bank, uintptr_t addr, uint64_t val,
                     unsigned size, bool *inject, bool *clrsts)
{
    RiscvReriErrorRecord *record;
    RiscvReriControl ctrl;
    uint64_t reg;
    qemu_log_mask(LOG_GUEST_ERROR, "%s: addr: 0x%lx val: 0x%lx size: %u\n", __func__, addr, val, size);
    if (addr + size > sizeof(RiscvReriErrorBank) ||
       ((addr & 0x7) + size) > 8) {
        return EINVAL;
    }
    /* fix: l'header del bank è 64 byte (offset 0-63), non 32 */
    if (addr < 64) {
        return 0;
    }
    reg = *(((uint64_t *)err_bank) + (addr / 8));
    /*
     * In order to handle a partial register write merge the new bytes
     * with the current value of the register.
     */
    for (int i = addr & 0x7; i < size + (addr & 0x7); i++) {
        reg &= ~((uint64_t)UINT8_MAX << 8 * i);
        reg |= (val & UINT8_MAX) << 8 * i;
        val >>= 8;
    }
    addr &= ~0x7;
    addr -= 64;
    /* fix: dimensione record è 64 byte, non 32 */
    record = &err_bank->records[addr / RERI_RECORD_SIZE];
    addr = addr % RERI_RECORD_SIZE;
    switch (addr) {
    case 0: /* control_i */
        ctrl.value = reg;
        if (ctrl.srdp) {
            record->status_i.rdip = 1;
            ctrl.srdp = 0;
        }
        if (ctrl.sinv) {
            if (record->status_i.rdip) {
                record->status_i.v = 0;
            }
            ctrl.sinv = 0;
            *clrsts = true;
        }
        if (ctrl.eid != 0 && record->control_i.eid == 0) {
            *inject = true;
        }
        record->control_i = ctrl;
        break;
    case 8: /* status_i */
        qemu_log_mask(LOG_GUEST_ERROR, "%s (%d): reg: 0x%lx\n", __func__, __LINE__, reg);
        record->status_i.value =
	    riscv_reri_stage_status(record->status_i, (RiscvReriStatus)reg);
        break;
    /* XXX: Allow modification of addr_i and info_i only if status_i.v==0? */
    case 16: /* addr_i */
        record->addr_i = reg;
        break;
    case 24: /* info_i */
        record->info_i = reg;
        break;
    case 32: /* suppl_info_i */
        record->suppl_info_i = reg;
        break;
    case 40: /* timestamp_i */
        record->timestamp_i = reg;
        break;
    }
    return 0;
}

int riscv_reri_do_inject(RiscvReriErrorRecord *record, RiscvReriStatus sts,
                         uint64_t addr, uint64_t info)
{
    bool overwrite;
    RiscvReriStatus old;

    old = record->status_i;
    record->status_i.value = riscv_reri_write_status(old, sts, &overwrite);
    if (overwrite) {
        record->addr_i = addr;
        record->info_i = info;
    }
    return 0;
}

int riscv_error_injection_tick(RiscvReriErrorRecord *record)
{
    int irq = 0;
    /* Check if the injection was cancelled. */
    if (record->control_i.eid == 0) {
        return RISCV_RERI_INJECT_ABORT;
    }
    if (--record->control_i.eid > 0) {
        return RISCV_RERI_INJECT_WAIT;
    }
    if (record->status_i.v == 1) {
        return RISCV_RERI_INJECT_ABORT;
    }
    record->status_i.v = 1;
    record->status_i.rdip = 1;
    if (record->status_i.uec) {
        irq = record->control_i.uecs;
    } else if (record->status_i.ce) {
        irq = record->control_i.ces;
    } else if (record->status_i.ued) {
        irq = record->control_i.ueds;
    }
    switch (irq) {
    case 1:
        return RISCV_RERI_INJECT_LOW;
    case 2:
        return RISCV_RERI_INJECT_HIGH;
    case 0:
    default:
        return RISCV_RERI_INJECT_ABORT;
    }
}

void riscv_reri_register_init(RiscvReriErrorBank *err_bank, uint32_t vendor_id,
                              uint32_t imp_id, uint16_t nr_records)
{
    err_bank->vendor_n_imp_id.vendor_id = vendor_id;
    err_bank->vendor_n_imp_id.imp_id = imp_id;
    err_bank->bank_info.inst_id = 0;
    err_bank->bank_info.layout = 0;
    err_bank->bank_info.n_err_recs = nr_records;
    err_bank->bank_info.version = 1;
}
