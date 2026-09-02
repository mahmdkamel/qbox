/*
 * Copyright (c) 2026 Qualcomm Innovation Center, Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef smmu500_H
#define smmu500_H

#include <systemc>
#include <cci_configuration>
#include <cciutils.h>
#include <scp/report.h>
#include <tlm>
#include <module_factory_registery.h>
#include <ports/initiator-signal-socket.h>
#include <ports/target-signal-socket.h>
#include <tlm_utils/simple_initiator_socket.h>
#include <tlm_utils/simple_target_socket.h>
#include <tlm-extensions/underlying-dmi.h>

#include <cassert>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <vector>
#include <memory>
#include <sstream>

#include "smmu500_gen.h"

#define SMMU_PAGESIZE 4096
#define SMMU_PAGEMASK (SMMU_PAGESIZE - 1)
#define SMMU_MAX_CB   128
#define SMMU_MAX_SMR  224
#define SMMU_MAX_TBU  16
#define SMMU_VA_WIDTH 32
#define SMMU_ADDRMASK ((1ULL << 12) - 1)

/* Theoretically a DMI request can be failed with no ill effects, and to protect against re-entrant code
 * between a DMI invalidate and a DMI request on separate threads, effectively requiring work to be done
 * on the same thread, we make use of this by 'try_lock'ing and failing the DMI. However this has the
 * negative side effect that up-stream models my not get DMI's when they expect them, which at the very
 * least would be a performance hit.
 * Define this as true if you require protection against re-entrant models.
 */
#define THREAD_SAFE_REENTRANT false

namespace gs {

// Optional transaction attributes used to populate the context-fault syndrome.
// Ordinary TLM payloads do not carry these bus-level fields, so the defaults
// describe a synchronous, privileged, non-secure data access.
class smmu500_transaction_attrs_extension : public tlm::tlm_extension<smmu500_transaction_attrs_extension>
{
public:
    uint8_t mid = 0;
    uint8_t pid = 0;
    uint8_t bid = 0;
    bool privileged = true;
    bool instruction = false;
    bool non_secure = true;
    bool address_translation = false;
    bool asynchronous = false;

    tlm::tlm_extension_base* clone() const override { return new smmu500_transaction_attrs_extension(*this); }

    void copy_from(const tlm::tlm_extension_base& ext) override
    {
        const auto& other = static_cast<const smmu500_transaction_attrs_extension&>(ext);
        *this = other;
    }
};

template <unsigned int BUSWIDTH = 32>
class smmu500_tbu;

template <unsigned int BUSWIDTH = 32>
class smmu500 : public sc_core::sc_module, public smmu500_gen
{
    SCP_LOGGER();
    cci::cci_broker_handle m_broker;
    gs::json_zip_archive m_jza;
    bool loaded_ok;
    gs::json_module M;

public:
    typedef enum {
        IOMMU_NONE = 0,
        IOMMU_RO = 1,
        IOMMU_WO = 2,
        IOMMU_RW = 3,
    } IOMMUAccessFlags;

    struct IOMMUTLBEntry {
        uint64_t iova;
        uint64_t translated_addr;
        uint64_t addr_mask;
        IOMMUAccessFlags perm;
    };

    cci::cci_param<uint32_t> p_pamax;
    cci::cci_param<uint16_t> p_num_smr;
    cci::cci_param<uint16_t> p_num_cb;
    cci::cci_param<uint16_t> p_num_pages;
    cci::cci_param<bool> p_ato;
    cci::cci_param<uint8_t> p_version;
    cci::cci_param<uint32_t> p_idr2;
    cci::cci_param<uint8_t> p_num_tbu;

    tlm_utils::multi_passthrough_target_socket<smmu500, BUSWIDTH> socket;
    tlm_utils::simple_initiator_socket<smmu500> dma_socket;
    InitiatorSignalSocket<bool> irq_global;
    sc_core::sc_vector<InitiatorSignalSocket<bool>> irq_context;
    TargetSignalSocket<bool> reset;

    std::vector<smmu500_tbu<BUSWIDTH>*> tbus;

    /* TTBR_HIGH[15:0] is the upper address; [31:16] is ASID. */
    static uint64_t smmu500_ttbr(uint32_t high, uint32_t low)
    {
        return (static_cast<uint64_t>(high & 0xffffu) << 32) |
               (static_cast<uint64_t>(low) & 0xffffffffu);
    }

    smmu500(sc_core::sc_module_name name);

private:
    enum class FaultKind {
        Translation,
        AccessFlag,
        Permission,
        External,
        AddressSize,
    };

    static constexpr uint32_t CB_FSR_TF_MASK = 1u << 1;
    static constexpr uint32_t CB_FSR_AFF_MASK = 1u << 2;
    static constexpr uint32_t CB_FSR_PF_MASK = 1u << 3;
    static constexpr uint32_t CB_FSR_EF_MASK = 1u << 4;
    static constexpr uint32_t CB_FSR_ASF_MASK = 1u << 7;
    static constexpr uint32_t CB_FSR_MULTI_MASK = 1u << 31;
    static constexpr uint32_t CB_FSR_FAULT_MASK = CB_FSR_TF_MASK | CB_FSR_AFF_MASK | CB_FSR_PF_MASK |
                                                   CB_FSR_EF_MASK | CB_FSR_ASF_MASK;

    std::array<uint32_t, SMMU_MAX_CB> m_cb_fsr_before_write = {};
    uint32_t m_sgfsr_before_write = 0;

    std::atomic<uint64_t> m_translation_seq{ 0 };
    /* Page-table/DMI callbacks can re-enter translation on the same
     * SystemC thread.  A plain mutex deadlocks that legal callback path. */
    std::recursive_mutex m_translation_lock;

    typedef struct PageAttr {
        uint64_t pa;
        unsigned int block : 1;
        unsigned int rd : 1;
        unsigned int wr : 1;
        unsigned int ns : 1;
    } PageAttr;

    struct FaultAttrs {
        bool privileged = true;
        bool instruction = false;
        bool non_secure = true;
        bool address_translation = false;
        bool asynchronous = false;
        bool suppress_fault = false;
        uint8_t mid = 0;
        uint8_t pid = 0;
        uint8_t bid = 0;
    };

    typedef struct TransReq {
        uint64_t va;
        uint64_t tcr[3];
        uint64_t ttbr[3][2];
        uint32_t access;
        unsigned int stage;
        bool s2_enabled;
        unsigned int s2_cb;
        uint64_t pa;
        uint32_t prot;
        uint64_t page_size;
        bool err;
        FaultKind fault = FaultKind::Translation;
        bool walk_fault = false;
        bool privileged = true;
        bool instruction = false;
        bool non_secure = true;
        bool address_translation = false;
        bool asynchronous = false;
        bool nested = false;
        bool internal_walk = false;
        bool suppress_fault = false;
        bool ipafar_valid = false;
        uint64_t ipafar = 0;
        unsigned int s1_cb = 0;
        uint8_t mid = 0;
        uint8_t pid = 0;
        uint8_t bid = 0;
        uint64_t trace_id = 0;
        uint64_t sid = 0;
    } TransReq;

    static uint32_t extract32(uint32_t val, int start, int length) { return (val >> start) & ((1u << length) - 1); }

    static uint64_t extract64(uint64_t val, int start, int length) { return (val >> start) & ((1ULL << length) - 1); }

    static int clz32(uint32_t val) { return val ? __builtin_clz(val) : 32; }

    void smmu500_update_ctx_irq(unsigned int cb)
    {
        bool fault = (static_cast<uint32_t>(SMMU_CB_FSR[cb]) & CB_FSR_FAULT_MASK) != 0;
        bool ie = SMMU_CB_SCTLR[cb][CB_SCTLR_CFIE];
        if (irq_context[cb].size() > 0) irq_context[cb]->write(fault && ie);
    }

    void smmu500_update_global_irq()
    {
        bool fault = static_cast<uint32_t>(SMMU_SGFSR) != 0;
        bool ie = SCR0_GFIE;
        if (irq_global.size() > 0) irq_global->write(fault && ie);
    }

    void smmu500_record_global_fault(uint32_t fault_mask)
    {
        SMMU_SGFSR = static_cast<uint32_t>(SMMU_SGFSR) | fault_mask;
        smmu500_update_global_irq();
    }

    void smmu500_report_global_fault(IOMMUTLBEntry& ret, uint32_t fault_mask, bool record_fault = true)
    {
        if (record_fault) smmu500_record_global_fault(fault_mask);
        if (SCR0_GFRE) {
            ret.perm = IOMMU_NONE;
        } else {
            ret.addr_mask = -1;
        }
    }

    void smmu500_program_id_registers()
    {
        const unsigned int num_pages_log2 = 31 - clz32(p_num_pages);
        SIDR0_ATOSNS = static_cast<uint32_t>(p_ato);
        SIDR0_NUMSMRG = std::min<uint32_t>(p_num_smr, SMMU_MAX_SMR);
        SIDR1_NUMCB = std::min<uint32_t>(p_num_cb, SMMU_MAX_CB);
        SIDR1_NUMPAGENDXB = num_pages_log2 - 1;
        SMMU_SIDR2 = static_cast<uint32_t>(p_idr2);
        SMMU_SIDR7 = static_cast<uint32_t>(p_version);
    }

    void smmu500_invalidate_cb(unsigned int cb)
    {
        if (cb >= std::min<unsigned int>(p_num_cb, SMMU_MAX_CB)) return;
        for (auto tbu : tbus) tbu->invalidate(cb);
    }

    void smmu500_invalidate_all()
    {
        for (auto tbu : tbus) tbu->reset_dmi();
    }

    void smmu500_invalidate_vmid(uint32_t vmid)
    {
        const unsigned int nr_cb = std::min<unsigned int>(p_num_cb, SMMU_MAX_CB);
        for (unsigned int cb = 0; cb < nr_cb; ++cb) {
            if (static_cast<uint32_t>(SMMU_CBAR[cb][CBAR_VMID]) == (vmid & 0xffu)) {
                smmu500_invalidate_cb(cb);
            }
        }
    }

    void smmu500_clear_global_tlbi_regs()
    {
        SMMU_STLBIALL = 0;
        SMMU_TLBIVMID = 0;
        SMMU_TLBIALLNSNH = 0;
        SMMU_TLBIALLH = 0;
        SMMU_TLBIVAH_LOW = 0;
        SMMU_STLBIVALM_LOW = 0;
        SMMU_STLBIVALM_HIGH = 0;
        SMMU_STLBIVAM_LOW = 0;
        SMMU_STLBIVAM_HIGH = 0;
        SMMU_TLBIVALH64_LOW = 0;
        SMMU_TLBIVALH64_HIGH = 0;
        SMMU_TLBIVMIDS1 = 0;
        SMMU_STLBIALLM = 0;
        SMMU_TLBIVAH64_LOW = 0;
        SMMU_TLBIVAH64_HIGH = 0;
    }

    void smmu500_clear_cb_tlbi_regs(unsigned int cb)
    {
        if (cb >= SMMU_MAX_CB) return;
        SMMU_CB_TLBIVA_LOW[cb] = 0;
        SMMU_CB_TLBIVA_HIGH[cb] = 0;
        SMMU_CB_TLBIVAA_LOW[cb] = 0;
        SMMU_CB_TLBIVAA_HIGH[cb] = 0;
        SMMU_CB_TLBIASID[cb] = 0;
        SMMU_CB_TLBIALL[cb] = 0;
        SMMU_CB_TLBIVAL_LOW[cb] = 0;
        SMMU_CB_TLBIVAL_HIGH[cb] = 0;
        SMMU_CB_TLBIVAAL_LOW[cb] = 0;
        SMMU_CB_TLBIVAAL_HIGH[cb] = 0;
        SMMU_CB_TLBIIPAS2_LOW[cb] = 0;
        SMMU_CB_TLBIIPAS2_HIGH[cb] = 0;
        SMMU_CB_TLBIIPAS2L_LOW[cb] = 0;
        SMMU_CB_TLBIIPAS2L_HIGH[cb] = 0;
    }

    static uint32_t smmu500_fault_status(FaultKind kind)
    {
        switch (kind) {
        case FaultKind::Translation:
            return CB_FSR_TF_MASK;
        case FaultKind::AccessFlag:
            return CB_FSR_AFF_MASK;
        case FaultKind::Permission:
            return CB_FSR_PF_MASK;
        case FaultKind::External:
            return CB_FSR_EF_MASK;
        case FaultKind::AddressSize:
            return CB_FSR_ASF_MASK;
        }
        return CB_FSR_TF_MASK;
    }

    void smmu500_fault(unsigned int cb, TransReq* req, int level)
    {
        const uint32_t old_fsr = static_cast<uint32_t>(SMMU_CB_FSR[cb]);
        const bool multiple = (old_fsr & CB_FSR_FAULT_MASK) != 0;
        uint32_t new_fsr = old_fsr | smmu500_fault_status(req->fault);
        if (multiple) new_fsr |= CB_FSR_MULTI_MASK;
        SMMU_CB_FSR[cb] = new_fsr;
        req->err = true;
        if (!multiple) {
            const uint64_t ipafar = req->ipafar_valid ? req->ipafar : req->va;
            SMMU_CB_IPAFAR_LOW[cb] = (uint32_t)ipafar;
            SMMU_CB_IPAFAR_HIGH[cb] = (uint32_t)(ipafar >> 32);
            if (req->stage == 2) {
                SMMU_CB_FAR_LOW[cb] = (uint32_t)req->va;
                SMMU_CB_FAR_HIGH[cb] = (uint32_t)(req->va >> 32);
            }

            uint32_t syn = static_cast<uint32_t>(level) & 0x3;
            syn |= (req->access == IOMMU_WO) ? (1u << 4) : 0;
            syn |= req->privileged ? (1u << 5) : 0;
            syn |= req->instruction ? (1u << 6) : 0;
            syn |= req->non_secure ? (1u << 8) : 0;
            syn |= req->address_translation ? (1u << 9) : 0;
            syn |= req->walk_fault ? (1u << 10) : 0;
            syn |= req->asynchronous ? (1u << 11) : 0;
            if (req->stage == 1 || req->nested) {
                const unsigned int s1_cb = req->nested ? req->s1_cb : cb;
                syn |= (s1_cb & 0x7Fu) << 16;
            }
            SMMU_CB_FSYNR0[cb] = syn;
            SMMU_CB_FSYNR1[cb] = req->mid | (static_cast<uint32_t>(req->pid) << 8) |
                                 (static_cast<uint32_t>(req->bid & 0x7u) << 13);
        }
        smmu500_update_ctx_irq(cb);
    }

    bool check_s2_startlevel(bool is_aa64, unsigned int pamax_val, int level, int inputsize, int stride)
    {
        if (level < 0) return false;
        if (is_aa64) {
            switch (stride) {
            case 13:
                if (level == 0 || (level == 1 && pamax_val <= 42)) return false;
                break;
            case 11:
                if (level == 0 || (level == 1 && pamax_val <= 40)) return false;
                break;
            case 9:
                if (level == 0 && pamax_val <= 42) return false;
                break;
            default:
                assert(false);
            }
        } else {
            const int grainsize = stride + 3;
            assert(stride == 9);
            if (level == 0) return false;
            int startsizecheck = inputsize - ((3 - level) * stride + grainsize);
            if (startsizecheck < 1 || startsizecheck > stride + 4) return false;
        }
        return true;
    }

    bool check_out_addr(uint64_t addr, unsigned int outputsize)
    {
        if (outputsize != 48 && extract64(addr, outputsize, 48 - outputsize)) return false;
        return true;
    }

    void dump_trans_req(TransReq const& tr)
    {
        SCP_DEBUG(()) << "Translation Req\n"
                      << std::hex << "VA: 0x" << tr.va << "\n"
                      << "TCR[0]: 0x" << tr.tcr[0] << "\n"
                      << "TCR[1]: 0x" << tr.tcr[1] << "\n"
                      << "TCR[2]: 0x" << tr.tcr[2] << "\n"
                      << "ACCESS: 0x" << tr.access << "\n"
                      << "Stage: " << std::dec << tr.stage << "\n"
                      << "S2_enabled: " << (tr.s2_enabled ? "true" : "false") << "\n"
                      << "S2_CB: " << tr.s2_cb << "\n"
                      << std::hex << "PA: 0x" << tr.pa << "\n"
                      << "Prot: 0x" << tr.prot << "\n"
                      << "Page size: 0x" << tr.page_size << "\n"
                      << "Error: " << (tr.err ? "true" : "false") << "\n";
    }

    void dump_cb_state(unsigned int cb)
    {
        SCP_DEBUG(()) << "CB" << cb << ":\n"
                      << std::hex << "CB_SCTLR = 0x" << (uint32_t)SMMU_CB_SCTLR[cb] << "\n"
                      << "CB_TCR2 = 0x" << (uint32_t)SMMU_CB_TCR2[cb] << "\n"
                      << "CB_TTBR0_LOW = 0x" << (uint32_t)SMMU_CB_TTBR0_LOW[cb] << "\n"
                      << "CB_TTBR0_HIGH = 0x" << (uint32_t)SMMU_CB_TTBR0_HIGH[cb] << "\n"
                      << "CB_TTBR1_LOW = 0x" << (uint32_t)SMMU_CB_TTBR1_LOW[cb] << "\n"
                      << "CB_TTBR1_HIGH = 0x" << (uint32_t)SMMU_CB_TTBR1_HIGH[cb] << "\n"
                      << "CB_TCR_LPAE = 0x" << (uint32_t)SMMU_CB_TCR_LPAE[cb] << "\n"
                      << "CB_FSR = 0x" << (uint32_t)SMMU_CB_FSR[cb] << "\n"
                      << "CB_FAR_LOW = 0x" << (uint32_t)SMMU_CB_FAR_LOW[cb] << "\n"
                      << "CB_FAR_HIGH = 0x" << (uint32_t)SMMU_CB_FAR_HIGH[cb] << "\n"
                      << "CB_IPAFAR_LOW = 0x" << (uint32_t)SMMU_CB_IPAFAR_LOW[cb] << "\n"
                      << "CB_IPAFAR_HIGH = 0x" << (uint32_t)SMMU_CB_IPAFAR_HIGH[cb] << "\n";
    }

    void dump_state()
    {
        SCP_DEBUG(()) << "smmu regs:" << std::hex << "SMMU_SCR0 = 0x" << (uint32_t)SMMU_SCR0 << "\n"
                      << "SMMU_SCR1 = 0x" << (uint32_t)SMMU_SCR1 << "\n"
                      << "SMMU_SACR = 0x" << (uint32_t)SMMU_SACR << "\n"
                      << "SMMU_SIDR0 = 0x" << (uint32_t)SMMU_SIDR0 << "\n"
                      << "SMMU_SIDR1 = 0x" << (uint32_t)SMMU_SIDR1 << "\n"
                      << "SMMU_SIDR2 = 0x" << (uint32_t)SMMU_SIDR2 << "\n"
                      << "SMMU_SIDR7 = 0x" << (uint32_t)SMMU_SIDR7 << "\n"
                      << "SMMU_NSCR0 = 0x" << (uint32_t)SMMU_NSCR0 << "\n";
    }

    void smmu500_ptw64(unsigned int cb, TransReq* req)
    {
        const unsigned int outsize_map[] = { 32, 36, 40, 42, 44, 48, 48, 48 };
        unsigned int tsz;
        unsigned int t0sz;
        unsigned int t1sz;
        unsigned int inputsize;
        unsigned int outputsize;
        unsigned int grainsize = -1;
        unsigned int stride;
        int level = 0;
        unsigned int firstblocklevel = 0;
        unsigned int tg;
        unsigned int ps;
        unsigned int baselowerbound;
        unsigned int stage = req->stage;
        bool blocktranslate = false;
        bool epd = false;
        uint32_t tableattrs = 0;
        uint32_t attrs;
        uint32_t s2attrs;
        uint64_t descmask;
        uint64_t ttbr;
        uint64_t desc;
        uint64_t walk_va;
        bool ttbr1 = false;

        req->err = false;

        if (SMMU_CB_SCTLR[cb][CB_SCTLR_M] == 0) {
            req->pa = req->va;
            req->prot = IOMMU_RW;
            return;
        }

        ttbr = req->ttbr[stage][0];
        tg = extract32(req->tcr[stage], 14, 2);
        if (stage == 1) {
            ps = extract64(req->tcr[stage], 32, 3);
        } else {
            ps = extract64(req->tcr[stage], 16, 3);
        }
        t0sz = extract32(req->tcr[stage], 0, 6);
        tsz = t0sz;
        req->pa = req->va;

        if (req->stage == 1) {
            assert(SMMU_CBA2R[cb][CBA2R_VA64] || extract32(req->tcr[1], 31, 1));

            if ((req->va & (1ULL << 63)) == 0) {
                /* Use TTBR0. */
            } else {
                ttbr1 = true;
                const unsigned int tg1map[] = { 3, 2, 0, 1 };
                tg = tg1map[extract32(req->tcr[stage], 30, 2)];
                t1sz = extract32(req->tcr[stage], 16, 6);
                ttbr = req->ttbr[stage][1];
                tsz = t1sz;
            }
            epd = extract32(req->tcr[1], ttbr1 ? 23 : 7, 1);
        }

        if (epd) goto do_fault;

        inputsize = 64 - tsz;
        if (req->stage == 1) {
            if (inputsize < 25 || inputsize > 48) {
                req->fault = FaultKind::AddressSize;
                goto do_fault;
            }
            const uint64_t upper = extract64(req->va, inputsize, 64 - inputsize);
            const uint64_t expected = ttbr1 ? ((1ULL << (64 - inputsize)) - 1) : 0;
            if (upper != expected) {
                req->fault = FaultKind::AddressSize;
                goto do_fault;
            }
        }
        walk_va = (inputsize >= 64) ? req->va : (req->va & ((1ULL << inputsize) - 1));
        switch (tg) {
        case 1:
            grainsize = 16;
            level = 3;
            firstblocklevel = 2;
            break;
        case 2:
            grainsize = 14;
            level = 3;
            firstblocklevel = 2;
            break;
        case 0:
            grainsize = 12;
            level = 2;
            firstblocklevel = 1;
            break;
        default:
            SCP_ERR(()) << "Wrong pagesize";
            goto do_fault;
        }

        outputsize = outsize_map[ps];
        if (outputsize > p_pamax) outputsize = p_pamax;

        stride = grainsize - 3;
        if (req->stage == 1) {
            if (grainsize < 16 && (inputsize > (grainsize + 3 * stride)))
                level = 0;
            else if (inputsize > (grainsize + 2 * stride))
                level = 1;
            else if (inputsize > (grainsize + stride))
                level = 2;

            if (inputsize < 25 || inputsize > 48) {
                req->fault = FaultKind::AddressSize;
                goto do_fault;
            }
        } else {
            unsigned int startlevel = extract32(req->tcr[stage], 6, 2);
            level = 3 - startlevel;
            if (grainsize == 12) level = 2 - startlevel;
            if (!check_s2_startlevel(true, outputsize, level, inputsize, stride)) goto do_fault;
        }

        baselowerbound = 3 + inputsize - ((3 - level) * stride + grainsize);
        ttbr &= ~((1ULL << baselowerbound) - 1);

        if (!check_out_addr(ttbr, outputsize)) {
            req->fault = FaultKind::AddressSize;
            goto do_fault;
        }

        descmask = (1ULL << grainsize) - 1;
        do {
            unsigned int addrselectbottom = (3 - level) * stride + grainsize;
            uint64_t index = (walk_va >> (addrselectbottom - 3)) & descmask;
            index &= ~7ULL;
            uint64_t descaddr = ttbr | index;

            if (req->stage == 1 && req->s2_enabled) {
                TransReq s2req = *req;
                s2req.stage = 2;
                s2req.internal_walk = true;
                s2req.va = descaddr;
                s2req.access = IOMMU_RO;
                smmu500_ptw64(s2req.s2_cb, &s2req);
                if (s2req.err) {
                    req->ipafar = descaddr;
                    req->ipafar_valid = true;
                    req->fault = s2req.fault;
                    req->walk_fault = true;
                    goto do_fault;
                }
                descaddr = s2req.pa;
            }

            tlm::tlm_generic_payload txn;
            txn.set_command(tlm::TLM_READ_COMMAND);
            txn.set_address(descaddr);
            txn.set_data_ptr(reinterpret_cast<unsigned char*>(&desc));
            txn.set_data_length(sizeof(desc));
            txn.set_streaming_width(sizeof(desc));
            txn.set_byte_enable_length(0);
            txn.set_dmi_allowed(false);
            txn.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);

            // A TLM delay is relative to the caller, not an absolute timestamp.
            sc_core::sc_time now = sc_core::SC_ZERO_TIME;
            dma_socket->b_transport(txn, now);

            if (txn.get_response_status() != tlm::TLM_OK_RESPONSE) {
                SCP_INFO(()) << std::hex << "Bad DMA response CB " << cb << " SID 0x" << req->sid
                             << " VA 0x" << req->va << " descaddr 0x" << descaddr
                             << " TTBR 0x" << ttbr << " status " << txn.get_response_status();
                req->fault = FaultKind::External;
                req->walk_fault = true;
                goto do_fault;
            }

            if (req->trace_id != 0) {
                SCP_INFO(()) << std::hex << "SMMU PTW id " << req->trace_id << " SID 0x" << req->sid
                             << " CB" << cb << " VA 0x" << req->va << " L" << level
                             << " table 0x" << ttbr << " index 0x" << index << " descaddr 0x" << descaddr
                             << " desc 0x" << desc;
            }

            unsigned int type = desc & 3;
            ttbr = extract64(desc, 0, 48);
            ttbr &= ~descmask;

            if (!(type & 2) && level == 3) {
                SCP_INFO(()) << "bad level 3 desc";
                req->walk_fault = true;
                goto do_fault;
            }

            if (level == 3) break;

            switch (type) {
            case 2:
            case 0:
                SCP_INFO(()) << "bad desc id " << req->trace_id << " SID 0x" << std::hex << req->sid
                             << " CB " << cb;
                req->walk_fault = true;
                goto do_fault;
                break;
            case 1:
                blocktranslate = true;
                if (level < (int)firstblocklevel) {
                    req->walk_fault = true;
                    goto do_fault;
                }
                break;
            case 3:
                tableattrs |= extract64(desc, 59, 5);
                if (!check_out_addr(ttbr, outputsize)) {
                    req->fault = FaultKind::AddressSize;
                    goto do_fault;
                }
                level++;
                break;
            }
        } while (!blocktranslate);

        if (!check_out_addr(ttbr, outputsize)) {
            req->fault = FaultKind::AddressSize;
            goto do_fault;
        }

        {
            unsigned long page_size;
            page_size = (1ULL << ((stride * (4 - level)) + 3));
            ttbr |= (walk_va & (page_size - 1));
            req->page_size = ((stride * (4 - level)) + 3);
        }

        s2attrs = attrs = extract64(desc, 2, 10) | (extract64(desc, 52, 12) << 10);
        if (req->stage == 1) {
            attrs |= extract32(tableattrs, 0, 2) << 11;
            attrs |= extract32(tableattrs, 3, 1) << 5;
            if (0 && extract32(tableattrs, 2, 1)) {
                attrs &= ~(1 << 4);
            }
        }

        req->prot = IOMMU_RW;
        if ((attrs & (1 << 8)) == 0) {
            SCP_INFO(()) << "access forbidden " << std::hex << attrs;
            req->fault = FaultKind::AccessFlag;
            goto do_fault;
        }

        if (req->stage == 1) {
            const bool unprivileged_access = !req->privileged;
            const bool user_access = (attrs & (1 << 4)) != 0;
            if (unprivileged_access && !user_access) {
                SCP_INFO(()) << "Unprivileged access forbidden by AP[1]";
                req->fault = FaultKind::Permission;
                goto do_fault;
            }
            if (attrs & (1 << 5)) {
                if (req->access == IOMMU_WO) {
                    SCP_INFO(()) << "Write access forbidden " << std::hex << attrs;
                    req->fault = FaultKind::Permission;
                    goto do_fault;
                }
                req->prot &= ~IOMMU_WO;
            }
        } else {
            switch ((s2attrs >> 4) & 3) {
            case 0:
                req->fault = FaultKind::Permission;
                goto do_fault;
                break;
            case 1:
                if (req->access == IOMMU_WO) {
                    req->fault = FaultKind::Permission;
                    goto do_fault;
                }
                req->prot &= ~IOMMU_WO;
                break;
            case 2:
                if (req->access == IOMMU_RO) {
                    req->fault = FaultKind::Permission;
                    goto do_fault;
                }
                req->prot &= ~IOMMU_RO;
                break;
            case 3:
                break;
            }
        }

        req->pa = ttbr;
        return;

    do_fault:
        SCP_INFO(()) << "smmu fault id " << req->trace_id << " SID 0x" << std::hex << req->sid << " CB" << cb;
        dump_trans_req(*req);
        dump_cb_state(cb);
        dump_state();
        req->err = true;
        if (!req->internal_walk && !req->suppress_fault) {
            const unsigned int fault_cb = (req->nested && req->stage == 2) ? req->s1_cb : cb;
            smmu500_fault(fault_cb, req, level);
        }
    }

    bool smmu500_at64(unsigned int cb, uint64_t va, bool wr, bool s2, uint64_t* pa, int* prot, uint64_t* page_size,
                      uint64_t* fault_addr, const FaultAttrs& fault_attrs, uint64_t trace_id = 0, uint64_t sid = 0)
    {
        unsigned int s2_cb = 0;
        TransReq req{};
        unsigned int t;

        t = SMMU_CBAR[cb][CBAR_TYPE];

        switch (t) {
        case 0:
            req.stage = 2;
            req.s2_enabled = true;
            req.s2_cb = cb;
            s2_cb = cb;
            break;
        case 1:
            req.stage = 1;
            req.s2_enabled = false;
            break;
        case 2:
            req.stage = 1;
            req.s2_enabled = false;
            break;
        case 3:
            req.stage = 1;
            req.s2_enabled = true;
            req.s2_cb = SMMU_CBAR[cb][CBAR_VMID];
            req.nested = true;
            req.s1_cb = cb;
            s2_cb = req.s2_cb;
            break;
        }

        req.va = va;
        req.trace_id = trace_id;
        req.sid = sid;
        req.tcr[1] = (uint32_t)SMMU_CB_TCR2[cb];
        req.tcr[1] <<= 32;
        req.tcr[1] |= (uint32_t)SMMU_CB_TCR_LPAE[cb];

        req.ttbr[1][0] = smmu500_ttbr(static_cast<uint32_t>(SMMU_CB_TTBR0_HIGH[cb]),
                                      static_cast<uint32_t>(SMMU_CB_TTBR0_LOW[cb]));

        req.ttbr[1][1] = smmu500_ttbr(static_cast<uint32_t>(SMMU_CB_TTBR1_HIGH[cb]),
                                      static_cast<uint32_t>(SMMU_CB_TTBR1_LOW[cb]));

        if (req.s2_enabled) {
            req.tcr[2] = (uint32_t)SMMU_CB_TCR_LPAE[s2_cb];
            req.ttbr[2][0] = smmu500_ttbr(static_cast<uint32_t>(SMMU_CB_TTBR0_HIGH[s2_cb]),
                                          static_cast<uint32_t>(SMMU_CB_TTBR0_LOW[s2_cb]));

            if (req.nested) {
                /* Stage-1 table bases are IPAs.  Limit them to the input
                 * address space accepted by the selected stage-2 context. */
                const unsigned int ipa_bits = 64 - extract32(req.tcr[2], 0, 6);
                if (ipa_bits < 64) req.ttbr[1][0] &= (1ULL << ipa_bits) - 1;
            }
        }

        req.access = wr ? IOMMU_WO : IOMMU_RO;
        req.page_size = *page_size;
        req.privileged = fault_attrs.privileged;
        req.instruction = fault_attrs.instruction;
        req.non_secure = fault_attrs.non_secure;
        req.address_translation = fault_attrs.address_translation;
        req.asynchronous = fault_attrs.asynchronous;
        req.suppress_fault = fault_attrs.suppress_fault;
        req.mid = fault_attrs.mid;
        req.pid = fault_attrs.pid;
        req.bid = fault_attrs.bid;

        if (req.stage == 1) {
            smmu500_ptw64(cb, &req);
            if (!req.err) req.stage++;
        } else {
            req.pa = req.va;
        }

        if (!req.err && s2 && req.s2_enabled) {
            req.va = req.pa;
            /* A nested context uses the CBAR-selected stage-2 context for
             * the final walk as well as for translating stage-1 descriptors. */
            smmu500_ptw64(req.s2_cb, &req);
        }

        *pa = req.pa;
        *prot = req.prot;
        *page_size = req.page_size;
        if (fault_addr) *fault_addr = req.ipafar_valid ? req.ipafar : (req.err ? req.va : va);
        return req.err;
    }

    bool smmu500_at(unsigned int cb, uint64_t va, bool wr, bool s2, uint64_t* pa, int* prot, uint64_t* page_size,
                    uint64_t* fault_addr, const FaultAttrs& fault_attrs, uint64_t trace_id = 0, uint64_t sid = 0)
    {
        return smmu500_at64(cb, va, wr, s2, pa, prot, page_size, fault_addr, fault_attrs, trace_id, sid);
    }

    void smmu500_gat(uint64_t v, bool wr, bool s2, bool unprivileged)
    {
        std::lock_guard<std::recursive_mutex> translation_lock(m_translation_lock);
        uint64_t va = v & ~SMMU_ADDRMASK;
        unsigned int cb = v & SMMU_ADDRMASK;
        uint64_t pa;
        int prot;
        uint64_t page_size = 12; // log2 default page size: 4 KiB
        FaultAttrs fault_attrs;
        fault_attrs.privileged = !unprivileged;
        fault_attrs.address_translation = true;

        if (cb >= p_num_cb) {
            smmu500_record_global_fault(1u << 0);
            SMMU_GPAR = 1;
            SMMU_GPAR_H = 0;
            return;
        }

        SCP_INFO(()) << "ATS: va=0x" << std::hex << va << " cb=0x" << cb << " wr=" << wr << " s2=" << s2;
        bool err = smmu500_at(cb, va, wr, s2, &pa, &prot, &page_size, nullptr, fault_attrs);

        SMMU_GPAR = (uint32_t)(pa | err);
        SMMU_GPAR_H = (uint32_t)(pa >> 32);
    }

public:
    static constexpr uint32_t SMMU_STREAM_ID_MASK = 0x7FFFu;

    static uint16_t smmu500_compose_stream_id(uint32_t topology_id, uint64_t addr)
    {
        /* The transport address carries CSID[3:0] in bits [35:32].  Keep
         * the TBU and topology fields from the configured base SID and
         * assemble the architectural SID[14:0] explicitly. */
        const uint32_t tbu_id = (topology_id >> 10) & 0x1fu;
        const uint32_t topo_id = (topology_id >> 5) & 0x1fu;
        const uint32_t configured_csid = topology_id & 0xfu;
        const uint32_t transport_csid = static_cast<uint32_t>((addr >> 32) & 0xfu);
        const uint32_t csid = transport_csid != 0 ? transport_csid : configured_csid;
        return static_cast<uint16_t>((tbu_id << 10) | (topo_id << 5) | csid);
    }

    uint16_t smmu500_resolve_stream_id(uint32_t topology_id, uint64_t addr, int* cb,
                                       bool* stream_match_conflict = nullptr, uint32_t* s2cr_type = nullptr)
    {
        const uint16_t stream_id = smmu500_compose_stream_id(topology_id, addr);
        bool conflict = false;
        uint32_t type = 0;
        const int resolved_cb = smmu500_stream_id_match(stream_id, &conflict, &type);
        if (cb) *cb = resolved_cb;
        if (stream_match_conflict) *stream_match_conflict = conflict;
        if (s2cr_type) *s2cr_type = type;
        return stream_id;
    }

    IOMMUTLBEntry smmu500_translate(tlm::tlm_generic_payload& txn, uint64_t sid,
                                    bool transport_stream_address = false,
                                    bool record_fault = true)
    {
        std::lock_guard<std::recursive_mutex> translation_lock(m_translation_lock);
        const uint64_t trace_id = ++m_translation_seq;
        uint64_t addr = txn.get_address();
        uint64_t page_size = 12;
        IOMMUTLBEntry ret = {
            /* Keep the request address in the TLB entry.  Consumers use this
             * to associate the translated page with the upstream IOVA. */
            .iova = addr,
            .translated_addr = addr,
            .addr_mask = (1ULL << page_size) - 1,
            .perm = IOMMU_RW,
        };
        int cb;
        /* Keep the complete address for stage-1 VA64 contexts.  The upper
         * transport bits are used for stream selection, not discarded from
         * the virtual address before the SMMU walk. */
        uint64_t va = addr & ~SMMU_ADDRMASK;
        if (transport_stream_address) {
            va &= ((1ULL << SMMU_VA_WIDTH) - 1);
        }
        uint64_t pa = va;
        int prot;
        uint64_t fault_addr = va;
        bool err = false;
        const uint16_t master_id = smmu500_compose_stream_id(static_cast<uint32_t>(sid), addr);
        const uint32_t transport_stream_bits = static_cast<uint32_t>(master_id & 0xfu);
        bool clientpd = SCR0_CLIENTPD;
        if (clientpd) {
            ret.addr_mask = -1;
            return ret;
        }

        bool stream_match_conflict = false;
        uint32_t s2cr_type = 0;
        cb = smmu500_stream_id_match(master_id, &stream_match_conflict, &s2cr_type);
        if (cb >= 0 && !SMMU_CBA2R[cb][CBA2R_VA64]) {
            va &= ((1ULL << SMMU_VA_WIDTH) - 1);
        }
        const bool trace_dsp_window = va >= 0x90000000ULL && va < 0xa0000000ULL;
        if (trace_dsp_window) {
            SCP_INFO(()) << std::hex << "SMMU translate id " << trace_id << " VA 0x" << va << " base SID 0x" << sid
                         << " stream bits 0x" << transport_stream_bits << " SID 0x" << master_id << " CB " << cb
                         << " S2CR type " << s2cr_type;
        }
        if (cb < 0) {
            if (trace_dsp_window) {
                unsigned int valid_count = 0;
                SCP_DEBUG(()) << std::hex << "DSP stream miss for SID 0x" << master_id << " effective 0x"
                              << (static_cast<uint32_t>(master_id) & 0x7fffu) << " (SMR/S2CR dump at TRACE level)";
                for (unsigned int i = 0; i < std::min<unsigned int>(static_cast<unsigned int>(p_num_smr), SMMU_MAX_SMR);
                     i++) {
                    const bool valid = SMMU_SMR[i][SMR_VALID];
                    if (!valid) continue;
                    ++valid_count;
                    SCP_TRACE(()) << std::hex << "  valid SMR[" << i << "] raw_smr 0x"
                                  << static_cast<uint32_t>(SMMU_SMR[i]) << " id 0x"
                                  << static_cast<uint32_t>(SMMU_SMR[i][SMR_ID]) << " mask 0x"
                                  << static_cast<uint32_t>(SMMU_SMR[i][SMR_MASK]) << " raw_s2cr 0x"
                                  << static_cast<uint32_t>(SMMU_S2CR[i]) << " cb 0x"
                                  << static_cast<uint32_t>(SMMU_S2CR[i][S2CR_CBNDX_VMID]) << " type 0x"
                                  << static_cast<uint32_t>(SMMU_S2CR[i][S2CR_TYPE]);
                }
                SCP_DEBUG(()) << std::dec << "DSP stream miss valid SMR entries " << valid_count;
            }
            /* USFCFG selects whether unidentified streams generate a global
             * fault. GFRE selects whether that recorded fault rejects the
             * transaction or permits a bypass response.  A TBU request with
             * no transport carrier has no CSID to match; preserve the
             * identity boot traffic instead of turning it into a fault. */
            const bool has_transport_csid = transport_stream_address && ((addr >> 32) & 0xfu) != 0;
            if (SCR0_USFCFG && (!transport_stream_address || has_transport_csid)) {
                smmu500_report_global_fault(ret, 1u << 1, record_fault);
            } else {
                ret.addr_mask = -1;
            }
            return ret;
        }
        if (stream_match_conflict) {
            if (SCR0_SMCFCFG) {
                smmu500_report_global_fault(ret, 1u << 2, record_fault);
                return ret;
            }
        }

        /* S2CR.TYPE selects the action for a matched stream. */
        if (s2cr_type == 1) { // Bypass
            ret.addr_mask = -1;
            return ret;
        }
        if (s2cr_type != 0 || cb >= static_cast<int>(p_num_cb)) { // Fault/reserved/invalid context
            smmu500_report_global_fault(ret, 1u << 0, record_fault);
            return ret;
        }

        bool wr = (txn.get_command() == tlm::TLM_WRITE_COMMAND);
        const bool fault_latched = (static_cast<uint32_t>(SMMU_CB_FSR[cb]) & CB_FSR_FAULT_MASK) != 0;
        FaultAttrs fault_attrs;
        /* A later fault must still reach smmu500_fault so the TRM-defined
         * MULTI status bit is set. Only non-recording probes, such as DMI
         * lookups, suppress fault status updates. */
        fault_attrs.suppress_fault = !record_fault;
        if (const auto* ext = txn.get_extension<smmu500_transaction_attrs_extension>()) {
            fault_attrs.privileged = ext->privileged;
            fault_attrs.instruction = ext->instruction;
            fault_attrs.non_secure = ext->non_secure;
            fault_attrs.address_translation = ext->address_translation;
            fault_attrs.asynchronous = ext->asynchronous;
            fault_attrs.mid = ext->mid;
            fault_attrs.pid = ext->pid;
            fault_attrs.bid = ext->bid;
        }
        err = smmu500_at(cb, va, wr, true, &pa, &prot, &page_size, &fault_addr, fault_attrs, trace_id, master_id);
        if (trace_dsp_window) {
            SCP_INFO(()) << std::hex << "SMMU walk CBAR type " << static_cast<uint32_t>(SMMU_CBAR[cb][CBAR_TYPE])
                         << " err " << err << " PA 0x" << pa << " prot " << prot << " page 0x" << page_size;
        }
        ret.translated_addr = pa;
        ret.perm = (IOMMUAccessFlags)prot;
        if (err) {
            if (record_fault && !fault_latched) {
                const uint64_t recorded_addr = (fault_addr == va) ? (va | (addr & SMMU_PAGEMASK)) : fault_addr;
                SMMU_CB_IPAFAR_LOW[cb] = static_cast<uint32_t>(recorded_addr);
                SMMU_CB_IPAFAR_HIGH[cb] = static_cast<uint32_t>(recorded_addr >> 32);
                if (SMMU_CBAR[cb][CBAR_TYPE] == 0 || SMMU_CBAR[cb][CBAR_TYPE] == 3) {
                    SMMU_CB_FAR_LOW[cb] = static_cast<uint32_t>(recorded_addr);
                    SMMU_CB_FAR_HIGH[cb] = static_cast<uint32_t>(recorded_addr >> 32);
                }
            }
            memset(&ret, 0, sizeof ret);
            ret.iova = addr;
            ret.perm = IOMMU_NONE;
        } else {
            ret.addr_mask = (page_size >= 64) ? UINT64_MAX : ((1ULL << page_size) - 1);
            ret.translated_addr &= ~ret.addr_mask;
        }
        return ret;
    }

    int smmu500_stream_id_match(uint32_t stream_id, bool* stream_match_conflict = nullptr,
                                uint32_t* s2cr_type = nullptr)
    {
        constexpr uint32_t stream_id_mask = 0x7FFFu;
        const uint32_t effective_stream_id = stream_id & stream_id_mask;
        /* SIDR0.NUMSMRG is an 8-bit architectural identification field.
         * Use the configured model capacity for the software-programmable
         * SMR/S2CR arrays instead of making matching depend on that field. */
        const unsigned int nr_smr = std::min<unsigned int>(
            static_cast<unsigned int>(p_num_smr), SMMU_MAX_SMR);
        int cbndx = -1;
        bool conflict = false;
        uint32_t type = 0;

        for (unsigned int i = 0; i < nr_smr; i++) {
            bool valid = SMMU_SMR[i][SMR_VALID];
            const uint32_t mask = static_cast<uint32_t>(SMMU_SMR[i][SMR_MASK]) & stream_id_mask;
            const uint32_t id = static_cast<uint32_t>(SMMU_SMR[i][SMR_ID]) & stream_id_mask;

            if (valid && ((id ^ effective_stream_id) & ~mask & stream_id_mask) == 0) {
                if (cbndx < 0) {
                    cbndx = static_cast<int>(SMMU_S2CR[i][S2CR_CBNDX_VMID]);
                    type = static_cast<uint32_t>(SMMU_S2CR[i][S2CR_TYPE]);
                } else {
                    conflict = true;
                }
            }
        }

        if (stream_match_conflict) *stream_match_conflict = conflict;
        if (s2cr_type) *s2cr_type = type;

        return cbndx;
    }

    void start_of_simulation();
    void before_end_of_elaboration();
};

template <unsigned int BUSWIDTH>
class smmu500_tbu : public sc_core::sc_module
{
    static constexpr unsigned int TRANSPORT_IOVA_WIDTH = 32;

    SCP_LOGGER();
    smmu500<BUSWIDTH>* m_smmu;
    std::mutex m_dmi_invalidate_lock;

    std::pair<uint64_t, uint64_t> dmi_range[SMMU_MAX_CB] = {};
    bool dmi_range_valid[SMMU_MAX_CB] = { false };

    struct MemoryView {
        uint64_t address;
        uint64_t page_start;
        uint64_t page_end;
        uint64_t page_size;
    };

protected:
    void b_transport(tlm::tlm_generic_payload& txn, sc_core::sc_time& delay)
    {
        sc_dt::uint64 addr = txn.get_address();
        tlm::tlm_command cmd = txn.get_command();
        typename smmu500<BUSWIDTH>::IOMMUTLBEntry te =
            m_smmu->smmu500_translate(txn, p_topology_id, true);
        const bool trace_dsp_window = addr >= 0x90000000ULL && addr < 0xa00000000ULL;
        if (trace_dsp_window) {
            SCP_INFO(()) << std::hex << "TBU b_transport VA 0x" << addr << " -> PA 0x" << te.translated_addr
                         << " mask 0x" << te.addr_mask << " perm " << te.perm;
        }

        if (te.perm == smmu500<BUSWIDTH>::IOMMU_NONE ||
            (cmd == tlm::TLM_WRITE_COMMAND && te.perm == smmu500<BUSWIDTH>::IOMMU_RO) ||
            (cmd == tlm::TLM_READ_COMMAND && te.perm == smmu500<BUSWIDTH>::IOMMU_WO)) {
            txn.set_response_status(tlm::TLM_ADDRESS_ERROR_RESPONSE);
            wait(sc_core::SC_ZERO_TIME);
        } else {
            txn.set_address((te.translated_addr & ~te.addr_mask) | (addr & te.addr_mask));
            downstream_socket->b_transport(txn, delay);
            txn.set_address(addr);
        }
    }

    virtual unsigned int transport_dbg(tlm::tlm_generic_payload& txn)
    {
        sc_dt::uint64 addr = txn.get_address();
        typename smmu500<BUSWIDTH>::IOMMUTLBEntry te =
            m_smmu->smmu500_translate(txn, p_topology_id, true, false);
        if (te.perm == smmu500<BUSWIDTH>::IOMMU_NONE) {
            return 0;
        }
        txn.set_address((te.translated_addr & ~te.addr_mask) | (addr & te.addr_mask));
        int ret = downstream_socket->transport_dbg(txn);
        txn.set_address(addr);
        return ret;
    }

    virtual bool get_direct_mem_ptr(tlm::tlm_generic_payload& txn, tlm::tlm_dmi& dmi_data)
    {
#if THREAD_SAFE_REENTRANT == true
        if (!m_dmi_invalidate_lock.try_lock()) {
            SCP_DEBUG(())("Failed to get lock, DMI will be refused");
            return false;
        }
#else
        m_dmi_invalidate_lock.lock();
#endif

        MemoryView VIRT;
        MemoryView PHYS;

        VIRT.address = txn.get_address();
        const bool trace_dsp_window = VIRT.address >= 0x90000000ULL && VIRT.address < 0xa00000000ULL;
        if (trace_dsp_window) {
            SCP_INFO(()) << std::hex << "TBU DMI request VA 0x" << VIRT.address;
        }
        typename smmu500<BUSWIDTH>::IOMMUTLBEntry te =
            m_smmu->smmu500_translate(txn, p_topology_id, true);

        if (te.perm == smmu500<BUSWIDTH>::IOMMU_NONE) {
            if (trace_dsp_window) SCP_INFO(()) << "TBU DMI denied by SMMU";
            const uint32_t master_id = m_smmu->smmu500_compose_stream_id(p_topology_id, VIRT.address);
            const int CB = m_smmu->smmu500_stream_id_match(master_id);
            if (CB >= 0 && static_cast<unsigned int>(CB) < SMMU_MAX_CB) {
                const uint64_t page = VIRT.address & ~SMMU_PAGEMASK;
                if (!dmi_range_valid[CB] || dmi_range[CB].first > page) {
                    dmi_range[CB].first = page;
                }
                if (!dmi_range_valid[CB] || dmi_range[CB].second < page + SMMU_PAGEMASK) {
                    dmi_range[CB].second = page + SMMU_PAGEMASK;
                }
                dmi_range_valid[CB] = true;
            }
            m_dmi_invalidate_lock.unlock();
            return false;
        }

        SCP_DEBUG(())("te iova {:x} translated_addr {:x} addr_mask {:x}", te.iova, te.translated_addr, te.addr_mask);

        if (te.addr_mask == (uint64_t)-1) {
            assert(te.translated_addr == VIRT.address);
            bool ret = downstream_socket->get_direct_mem_ptr(txn, dmi_data);
            if (!ret) {
                m_dmi_invalidate_lock.unlock();
                return false;
            }
            if (reinterpret_cast<uintptr_t>(dmi_data.get_dmi_ptr()) < 4096) {
                m_dmi_invalidate_lock.unlock();
                return false;
            }
            VIRT.page_end = dmi_data.get_end_address();
            if (VIRT.page_end >> TRANSPORT_IOVA_WIDTH != VIRT.address >> TRANSPORT_IOVA_WIDTH) {
                dmi_data.set_end_address(
                    (((VIRT.address >> TRANSPORT_IOVA_WIDTH) + 1) << TRANSPORT_IOVA_WIDTH) - 1);
            }
            VIRT.page_start = dmi_data.get_start_address();
            if (VIRT.page_start >> TRANSPORT_IOVA_WIDTH != VIRT.address >> TRANSPORT_IOVA_WIDTH) {
                uint64_t newstart = (VIRT.address >> TRANSPORT_IOVA_WIDTH) << TRANSPORT_IOVA_WIDTH;
                dmi_data.set_start_address(newstart);
                dmi_data.set_dmi_ptr(dmi_data.get_dmi_ptr() + (newstart - VIRT.page_start));
            }
            m_dmi_invalidate_lock.unlock();
            return ret;
        }

        PHYS.address = te.translated_addr;
        PHYS.page_start = te.translated_addr & ~te.addr_mask;
        PHYS.page_size = (te.addr_mask + 1);
        PHYS.page_end = PHYS.page_start + PHYS.page_size - 1;
        assert(PHYS.page_start <= PHYS.page_end);

        txn.set_address(PHYS.page_start);

        int ret = downstream_socket->get_direct_mem_ptr(txn, dmi_data);
        if (!ret) {
            if (trace_dsp_window) {
                SCP_INFO(()) << std::hex << "TBU downstream DMI unavailable for PA 0x" << PHYS.page_start;
            }
            txn.set_address(VIRT.address);
            m_dmi_invalidate_lock.unlock();
            return ret;
        }
        if (reinterpret_cast<uintptr_t>(dmi_data.get_dmi_ptr()) < 4096) {
            txn.set_address(VIRT.address);
            m_dmi_invalidate_lock.unlock();
            return false;
        }

        gs::UnderlyingDMITlmExtension* u_dmi;
        txn.get_extension(u_dmi);
        if (u_dmi) {
            tlm::tlm_dmi udmi = dmi_data;
            u_dmi->add_dmi(this, udmi, gs::tlm_dmi_ex::dmi_iommu);
        }

        uint64_t dmi_offset = PHYS.page_start - dmi_data.get_start_address();
        assert(dmi_data.get_start_address() <= PHYS.page_start);
        assert(PHYS.page_end <= dmi_data.get_end_address());

        VIRT.page_start = VIRT.address & ~te.addr_mask;
        VIRT.page_end = VIRT.page_start + te.addr_mask;

        dmi_data.set_dmi_ptr(dmi_data.get_dmi_ptr() + dmi_offset);
        dmi_data.set_start_address(VIRT.page_start);
        dmi_data.set_end_address(VIRT.page_end);
        switch (te.perm) {
        case smmu500<BUSWIDTH>::IOMMU_RO:
            dmi_data.allow_read();
            break;
        case smmu500<BUSWIDTH>::IOMMU_WO:
            dmi_data.allow_write();
            break;
        case smmu500<BUSWIDTH>::IOMMU_RW:
            dmi_data.allow_read_write();
            break;
        default:
            txn.set_address(VIRT.address);
            m_dmi_invalidate_lock.unlock();
            return false;
        }

        uint32_t master_id = m_smmu->smmu500_compose_stream_id(p_topology_id, VIRT.address);
        int CB = m_smmu->smmu500_stream_id_match(master_id);
        if (CB < 0) {
            // An unidentified stream reached DMI only through the bypass path, so
            // there is no context-bank DMI range to track.
            txn.set_address(VIRT.address);
            m_dmi_invalidate_lock.unlock();
            return ret;
        }
        if (!dmi_range_valid[CB] || dmi_range[CB].first > VIRT.page_start) {
            dmi_range[CB].first = VIRT.page_start;
        }
        if (!dmi_range_valid[CB] || dmi_range[CB].second < VIRT.page_end) {
            dmi_range[CB].second = VIRT.page_end;
        }
        dmi_range_valid[CB] = true;

        if (PHYS.page_start != VIRT.page_start) {
            uint64_t bits_masked = VIRT.address - (VIRT.address & ~SMMU_PAGEMASK);
            SCP_DEBUG(()) << std::hex << "\nVIRT   Page Start 0x" << VIRT.page_start << "\nPHYS   Page Start 0x"
                         << PHYS.page_start << "\nbits_masked         0x" << bits_masked;
        }
        SCP_DEBUG(()) << std::hex << "smmu TBU DMI: translate 0x" << VIRT.address << " to 0x" << te.translated_addr
                     << " pg size 0x" << PHYS.page_size << " pg base 0x" << PHYS.page_start << " offset 0x"
                     << dmi_offset << " start 0x" << dmi_data.get_start_address() << " end 0x"
                     << dmi_data.get_end_address();

        txn.set_address(VIRT.address);
        m_dmi_invalidate_lock.unlock();
        return ret;
    }

public:
    cci::cci_param<uint32_t> p_topology_id;

    tlm_utils::simple_target_socket<smmu500_tbu> upstream_socket;
    tlm_utils::simple_initiator_socket<smmu500_tbu> downstream_socket;

    smmu500_tbu(const sc_core::sc_module_name& name, sc_core::sc_object* o)
        : smmu500_tbu(name, dynamic_cast<smmu500<BUSWIDTH>*>(o))
    {
    }

    smmu500_tbu(sc_core::sc_module_name name, smmu500<BUSWIDTH>* _smmu)
        : p_topology_id("topology_id", 0x0, "Topology ID for this TBU")
        , upstream_socket("upstream_socket")
        , downstream_socket("downstream_socket")
    {
        m_smmu = _smmu;
        m_smmu->tbus.push_back(this);
        upstream_socket.register_b_transport(this, &smmu500_tbu::b_transport);
        upstream_socket.register_transport_dbg(this, &smmu500_tbu::transport_dbg);
        upstream_socket.register_get_direct_mem_ptr(this, &smmu500_tbu::get_direct_mem_ptr);
    }

    void invalidate(uint32_t CB)
    {
        if (CB >= SMMU_MAX_CB) return;
        std::pair<uint64_t, uint64_t> range;
        {
            std::lock_guard<std::mutex> lock(m_dmi_invalidate_lock);
            if (!dmi_range_valid[CB]) return;
            range = dmi_range[CB];
            dmi_range_valid[CB] = false;
        }

        // Do not hold the TBU lock while synchronously notifying the upstream path.
        SCP_DEBUG(())("TLBIALL invalidate {:x} - {:x}", range.first, range.second);
        upstream_socket->invalidate_direct_mem_ptr(range.first, range.second);
    }

    void reset_dmi()
    {
        std::vector<std::pair<uint64_t, uint64_t>> ranges;
        {
            std::lock_guard<std::mutex> lock(m_dmi_invalidate_lock);
            for (unsigned int cb = 0; cb < SMMU_MAX_CB; ++cb) {
                if (!dmi_range_valid[cb]) continue;
                ranges.push_back(dmi_range[cb]);
                dmi_range_valid[cb] = false;
            }
        }

        for (const auto& range : ranges) {
            upstream_socket->invalidate_direct_mem_ptr(range.first, range.second);
        }
    }

};

} // namespace gs

extern "C" void module_register();

#endif // smmu500_H
