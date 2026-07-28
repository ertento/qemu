/*
 * RISC-V RERI Registers Definitions
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
#ifndef __RISCV_RERI_REGS_H
#define __RISCV_RERI_REGS_H
#include <stdint.h>
#include <stddef.h>

#define MAX_ERROR_RECORDS       63

/* RERI Error Codes - ratified spec v1.0, Table 5 (Error code encodings) */
enum {
    RERI_EC_NONE,
    RERI_EC_OUE, /* Other unspecified error */
    RERI_EC_CDA, /* Corrupted data access */
    RERI_EC_CBA, /* Cache block data error */
    RERI_EC_CSD, /* Cache scrubbing detected */
    RERI_EC_CAS, /* Cache address/state error */
    RERI_EC_CUE, /* Cache unspecified error */
    RERI_EC_SDC, /* Snoop-filter/directory address/ control state */
    RERI_EC_SUE, /* Snoop-filter/directory unspecified error */
    RERI_EC_TPD, /* TLB/Page-walk cache data */
    RERI_EC_TPA, /* TLB/Page-walk address control state */
    RERI_EC_TPU, /* TLB/Page-walk unknown error */
    RERI_EC_HSE, /* Hart state error */
    RERI_EC_ICS, /* Interrupt controller state */
    RERI_EC_ITD, /* Interconnect data error */
    RERI_EC_ITO, /* Interconnection other error */
    RERI_EC_IWE, /* Internal watchdog error */
    RERI_EC_IDE, /* Internal datapath/memory or execution unit error */
    RERI_EC_SBE, /* System memory command or address bus error */
    RERI_EC_SMU, /* System memory unspecified error */
    RERI_EC_SMD, /* System memory data error */
    RERI_EC_SMS, /* System memory scrubbing detected error */
    RERI_EC_PIO, /* Protocol error illegal IO */
    RERI_EC_PUS, /* Protocol error unexpected state */
    RERI_EC_PTO, /* Protocol error timeout error */
    RERI_EC_SIC, /* System internal controller error */
    RERI_EC_DPU, /* Deferred error passthrough not supported */
    RERI_EC_PCX, /* PCI/CXL detected error */
    RERI_EC_RES, /* Reserved errors start */
    RERI_EC_REE = 63, /* Reserved errors end */
    RERI_EC_CES = 64, /* Custom error start */
    RERI_EC_CEE = 255, /* Custom error end */
    RERI_EC_INVALID,
};

enum {
    RERI_TT_UNSPECIFIED,
    RERI_TT_CUSTOM,
    RERI_TT_RES1,
    RERI_TT_RES2,
    RERI_TT_EXPLICIT_READ,
    RERI_TT_EXPLICIT_WRITE,
    RERI_TT_IMPLICIT_READ,
    RERI_TT_IMPLICIT_WRITE,
    RERI_TT_INVALID,
};

/*
 * control_i register - ratified spec v1.0 layout:
 * bit 0      else  (renamed 'ele': 'else' is a C keyword)
 * bit 1      cece
 * bit 2-3    ces
 * bit 4-5    ueds
 * bit 6-7    uecs
 * bit 8-31   WPRI (24 bit)
 * bit 32-47  eid  (16 bit)
 * bit 48     sinv
 * bit 49     srdp
 * bit 50-59  WPRI (10 bit)
 * bit 60-63  custom (4 bit)
 */
typedef union RiscvReriControl {
    struct __attribute__((__packed__)) {
        uint64_t ele:1;
        uint64_t cece:1;
        uint64_t ces:2;
        uint64_t ueds:2;
        uint64_t uecs:2;
        uint64_t rsvd0:24;
        uint64_t eid:16;
        uint64_t sinv:1;
        uint64_t srdp:1;
        uint64_t rsvd1:10;
        uint64_t custom:4;
    };
    uint64_t value;
} RiscvReriControl;
_Static_assert(sizeof(RiscvReriControl) == sizeof(uint64_t), "Wrong size: RiscvReriControl");
#define RERI_CTRL_MASK 0xf003ffff000000ffull

/*
 * status_i register - ratified spec v1.0 layout:
 * bit 0      v
 * bit 1      ce
 * bit 2      ued
 * bit 3      uec
 * bit 4-5    pri
 * bit 6      mo
 * bit 7      c
 * bit 8-10   tt
 * bit 11     iv
 * bit 12-15  ait
 * bit 16     siv
 * bit 17     tsv
 * bit 18-19  WPRI (2 bit)
 * bit 20     scrub
 * bit 21     ceco
 * bit 22     WPRI (1 bit)
 * bit 23     rdip
 * bit 24-31  ec
 * bit 32-47  WPRI (16 bit)
 * bit 48-63  cec
 */
typedef union RiscvReriStatus {
    struct __attribute__((__packed__)) {
        uint64_t v:1;
        uint64_t ce:1;
        uint64_t ued:1;
        uint64_t uec:1;
        uint64_t pri:2;
        uint64_t mo:1;
        uint64_t c:1;
        uint64_t tt:3;
        uint64_t iv:1;
        uint64_t ait:4;
        uint64_t siv:1;
        uint64_t tsv:1;
        uint64_t rsvd0:2;
        uint64_t scrub:1;
        uint64_t ceco:1;
        uint64_t rsvd1:1;
        uint64_t rdip:1;
        uint64_t ec:8;
        uint64_t rsvd2:16;
        uint64_t cec:16;
   };
   uint64_t value;
} RiscvReriStatus;
_Static_assert(sizeof(RiscvReriStatus) == sizeof(uint64_t), "Wrong size: RiscvReriStatus");
#define RERI_STS_MASK 0xffff0000ffb3ffffull

typedef struct __attribute__((__packed__)) RiscvReriErrorRecord {
    RiscvReriControl control_i;
    RiscvReriStatus status_i;
    uint64_t addr_i;
    uint64_t info_i;
    uint64_t suppl_info_i;
    uint64_t timestamp_i;
    uint64_t reserved;
    uint64_t custom;
} RiscvReriErrorRecord;
_Static_assert(sizeof(RiscvReriErrorRecord) == 64, "Wrong size: RiscvReriErrorRecord");

/*
 * bank_info register - ratified spec v1.0 layout:
 * bit 0-15   inst_id
 * bit 16-21  n_err_recs (6 bit)
 * bit 22-23  layout (2 bit)
 * bit 24-55  WPRI (32 bit)
 * bit 56-63  version
 */
typedef union RiscvReriBankInfo {
    struct __attribute__((__packed__)) {
        uint64_t inst_id:16;
        uint64_t n_err_recs:6;
        uint64_t layout:2;
        uint64_t rsvd0:32;
        uint64_t version:8;
    };
    uint64_t value;
} RiscvReriBankInfo;
_Static_assert(sizeof(RiscvReriBankInfo) == sizeof(uint64_t), "Wrong size: RiscvReriBankInfo");

typedef union RiscvReriVendorImpId {
    struct __attribute__((__packed__)) {
        uint32_t vendor_id;
        uint32_t imp_id;
    };
    uint64_t value;
} RiscvReriVendorImpId;
_Static_assert(sizeof(RiscvReriVendorImpId) == sizeof(uint64_t), "Wrong size: RiscvReriVendorImpId");

typedef struct __attribute__((__packed__)) RiscvReriErrorBank {
    RiscvReriVendorImpId vendor_n_imp_id;
    RiscvReriBankInfo bank_info;
    uint64_t valid_summary;
    uint64_t reserved[4];   /* offset 24, 32 byte riservati (spec Table 1) */
    uint64_t custom;        /* offset 56, 8 byte custom (spec Table 1) */
    RiscvReriErrorRecord records[MAX_ERROR_RECORDS];
} RiscvReriErrorBank;
_Static_assert(offsetof(RiscvReriErrorBank, records) == 64, "Wrong bank header size");

#endif
