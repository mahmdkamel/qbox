/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <systemc>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <fstream>
#include <functional>
#include <thread>
#include <vector>

#include <cci/utils/broker.h>
#include <libgsutils.h>
#include <gs_memory.h>
#include <router.h>
#include <smmu500.h>
#include <tlm_utils/simple_target_socket.h>
#include <tlm-extensions/qemu-memtx-attrs.h>

#include "cortex-a53.h"
#include "qemu-instance.h"
#include "test/cpu.h"

namespace {

constexpr uint64_t FIRMWARE_ADDR = 0;
constexpr size_t FIRMWARE_SIZE = 256 * 1024;
constexpr size_t PAGE_SIZE = 0x1000;
constexpr uint64_t SECURE_IOVA = 0x100000000ULL;
constexpr uint64_t NON_SECURE_IOVA = 0x200000000ULL;
constexpr uint64_t IOVA_WINDOW_SIZE = NON_SECURE_IOVA - SECURE_IOVA + PAGE_SIZE;
constexpr uint64_t COMPLETE_ADDR = 0x81000000ULL;
constexpr size_t COMPLETE_SIZE = 0x1000;
constexpr uint64_t SECURE_PHYS_ADDR = 0x10000;
constexpr uint64_t NON_SECURE_PHYS_ADDR = SECURE_PHYS_ADDR + PAGE_SIZE;
constexpr uint64_t SECURE_L0_ADDR = 0x1000;
constexpr uint64_t NON_SECURE_L0_ADDR = SECURE_L0_ADDR + (4 * PAGE_SIZE);
constexpr uint64_t SECURE_PRIME_VALUE = 0x5345435f5052494dULL;
constexpr uint64_t SECURE_WRITE_VALUE = 0x534543555245ULL;
constexpr uint64_t NON_SECURE_PRIME_VALUE = 0x4e535f5052494d45ULL;
constexpr uint64_t NON_SECURE_WRITE_VALUE = 0x4e4f4e534543ULL;
constexpr uint64_t COMPLETE_VALUE = 0x434f4d504c455445ULL;
constexpr uint64_t WRONG_EXCEPTION_LEVEL_VALUE = 0x454c4641494cULL;
constexpr uint64_t SMMU_REG_ADDR = 0x90000000ULL;
constexpr size_t SMMU_REG_SIZE = 0x20000;

class security_observing_memory : public gs::gs_memory<>
{
public:
    bool deny_data_dmi = false;
    std::function<void()> on_data_dmi;
    unsigned int data_reads = 0;
    std::vector<bool> data_write_security;
    std::vector<bool> data_dmi_security;
    std::vector<bool> page_table_security;

    security_observing_memory(const sc_core::sc_module_name& name, uint64_t size): gs::gs_memory<>(name, size) {}

    void invalidate_data_dmi()
    {
        for (unsigned int i = 0; i < socket.size(); ++i) {
            socket[i]->invalidate_direct_mem_ptr(SECURE_PHYS_ADDR, NON_SECURE_PHYS_ADDR + PAGE_SIZE - 1);
        }
    }

    uint64_t read_u64(uint64_t address)
    {
        uint64_t value = 0;
        TEST_ASSERT(read(reinterpret_cast<uint8_t*>(&value), address, sizeof(value)));
        return value;
    }

protected:
    static bool is_data_address(uint64_t address)
    {
        return address == SECURE_PHYS_ADDR || address == NON_SECURE_PHYS_ADDR;
    }

    static bool is_page_table_address(uint64_t address)
    {
        return (address >= SECURE_L0_ADDR && address < SECURE_L0_ADDR + (4 * PAGE_SIZE)) ||
               (address >= NON_SECURE_L0_ADDR && address < NON_SECURE_L0_ADDR + (4 * PAGE_SIZE));
    }

    static bool transaction_is_secure(const tlm::tlm_generic_payload& txn)
    {
        const auto* secure = txn.get_extension<gs::QemuMemTxSecureTlmExtension>();
        TEST_ASSERT(secure != nullptr);
        return secure->value;
    }

    void b_transport(int id, tlm::tlm_generic_payload& txn, sc_core::sc_time& delay) override
    {
        if (txn.get_command() == tlm::TLM_READ_COMMAND && is_data_address(txn.get_address())) {
            ++data_reads;
        }
        if (txn.get_command() == tlm::TLM_WRITE_COMMAND && is_data_address(txn.get_address())) {
            data_write_security.push_back(transaction_is_secure(txn));
        }
        if (txn.get_command() == tlm::TLM_READ_COMMAND && is_page_table_address(txn.get_address())) {
            page_table_security.push_back(transaction_is_secure(txn));
        }
        gs::gs_memory<>::b_transport(id, txn, delay);
    }

    bool get_direct_mem_ptr(int id, tlm::tlm_generic_payload& txn, tlm::tlm_dmi& dmi) override
    {
        if (is_data_address(txn.get_address())) {
            data_dmi_security.push_back(transaction_is_secure(txn));
            if (deny_data_dmi) return false;
        }
        const bool valid = gs::gs_memory<>::get_direct_mem_ptr(id, txn, dmi);
        if (is_data_address(txn.get_address()) && on_data_dmi) {
            auto callback = std::move(on_data_dmi);
            on_data_dmi = {};
            callback();
        }
        return valid;
    }
};

class test_tbu : public gs::smmu500_tbu<>
{
public:
    using gs::smmu500_tbu<>::smmu500_tbu;
    using gs::smmu500_tbu<>::b_transport;
    using gs::smmu500_tbu<>::get_direct_mem_ptr;
};

class completion_target : public sc_core::sc_module
{
public:
    tlm_utils::simple_target_socket<completion_target> socket;
    unsigned int writes = 0;
    uint64_t value = 0;

    completion_target(const sc_core::sc_module_name& name, sc_core::sc_event& completion_event)
        : sc_core::sc_module(name), socket("socket"), m_completion_event(completion_event)
    {
        socket.register_b_transport(this, &completion_target::b_transport);
    }

private:
    sc_core::sc_event& m_completion_event;

    void b_transport(tlm::tlm_generic_payload& txn, sc_core::sc_time&)
    {
        TEST_ASSERT(txn.get_command() == tlm::TLM_WRITE_COMMAND);
        TEST_ASSERT(txn.get_data_length() == sizeof(value));
        TEST_ASSERT(writes == 0);
        std::memcpy(&value, txn.get_data_ptr(), sizeof(value));
        ++writes;
        txn.set_response_status(tlm::TLM_OK_RESPONSE);
        m_completion_event.notify(sc_core::SC_ZERO_TIME);
    }
};

class CpuArmCortexA53SMMU500SecureAttrsTest : public TestBench
{
    cci::cci_param<int> p_num_cpu;
    QemuInstanceManager m_instance_manager;
    QemuInstance m_instance;
    cpu_arm_cortexA53 m_cpu;
    gs::router<> m_router;
    security_observing_memory m_memory;
    gs::smmu500<> m_smmu;
    test_tbu m_tbu;
    gs::async_event m_completion_guard;
    gs::async_event m_bridge_done;
    sc_core::sc_event m_completion_event;
    completion_target m_completion_target;

public:
    CpuArmCortexA53SMMU500SecureAttrsTest(const sc_core::sc_module_name& name)
        : TestBench(name)
        , p_num_cpu("num_cpu", 1, "This test requires one CPU")
        , m_instance("inst_a", &m_instance_manager, cpu_arm_cortexA53::ARCH)
        , m_cpu("cpu", m_instance)
        , m_router("router")
        , m_memory("memory", FIRMWARE_SIZE)
        , m_smmu("smmu")
        , m_tbu("tbu", &m_smmu)
        , m_completion_guard("completion_guard")
        , m_bridge_done(false)
        , m_completion_target("completion_target", m_completion_event)
    {
        TEST_ASSERT(p_num_cpu == 1);

        m_completion_guard.async_attach_suspending();
        SC_THREAD(finish_test);
        sensitive << m_completion_event;
        dont_initialize();

        // AArch64 resets at secure EL3, then switches to Non-secure EL1. Both
        // QEMU address spaces converge on this one router and one TBU.
        m_cpu.p_has_el3 = true;
        m_cpu.p_has_el2 = false;
        m_cpu.p_has_secure_memory = true;
        m_memory.p_max_block_size = PAGE_SIZE;
        m_tbu.p_topology_id = 0;
        m_smmu.p_num_cb = 2;
        m_smmu.p_num_smr = 2;
        m_smmu.p_num_pages = 18;

        m_router.add_initiator(m_cpu.secure_mem);
        m_router.add_initiator(m_cpu.socket);
        m_router.add_target(m_memory.socket, FIRMWARE_ADDR, FIRMWARE_SIZE);
        // Keep the IOVA intact so bits [35:32] select a distinct stream ID
        // while the SMMU walks VA zero for each context bank.
        m_router.add_target(m_tbu.upstream_socket, SECURE_IOVA, IOVA_WINDOW_SIZE, false);
        m_router.add_target(m_completion_target.socket, COMPLETE_ADDR, COMPLETE_SIZE);
        m_router.add_target(m_smmu.socket, SMMU_REG_ADDR, SMMU_REG_SIZE);

        // Keep translated DMI responses out of the upstream router: routing a
        // TBU DMI lookup back through the router that initiated it would
        // re-enter its DMI lock. The CPU-side paths still share that router
        // and TBU before both translations reach distinct memory offsets.
        m_tbu.downstream_socket.bind(m_memory.socket);
        m_smmu.dma_socket.bind(m_memory.socket);

        load_firmware_binary(FIRMWARE_BIN_PATH, FIRMWARE_ADDR,
                             { SECURE_IOVA, NON_SECURE_IOVA, SECURE_PRIME_VALUE, SECURE_WRITE_VALUE,
                               NON_SECURE_PRIME_VALUE, NON_SECURE_WRITE_VALUE, COMPLETE_ADDR, COMPLETE_VALUE,
                               WRONG_EXCEPTION_LEVEL_VALUE });
    }

    void end_of_elaboration() override
    {
        // The shared TBU decodes each IOVA's CSID into a stream ID. Both
        // contexts walk VA zero and map to separate pages in one gs_memory.
        m_smmu.SMMU_SCR0 = 0;
        m_smmu.SMMU_NSCR0 = 0;
        configure_context_bank(0, 1, SECURE_L0_ADDR, SECURE_PHYS_ADDR);
        configure_context_bank(1, 2, NON_SECURE_L0_ADDR, NON_SECURE_PHYS_ADDR);
    }

    void end_of_simulation() override
    {
        TEST_ASSERT(m_completion_target.writes == 1);
        TEST_ASSERT(m_completion_target.value == COMPLETE_VALUE);
        TEST_ASSERT(std::find(m_memory.data_write_security.begin(), m_memory.data_write_security.end(), true) !=
                    m_memory.data_write_security.end());
        TEST_ASSERT(std::find(m_memory.data_write_security.begin(), m_memory.data_write_security.end(), false) !=
                    m_memory.data_write_security.end());
        TEST_ASSERT(std::find(m_memory.data_dmi_security.begin(), m_memory.data_dmi_security.end(), true) !=
                    m_memory.data_dmi_security.end());
        TEST_ASSERT(std::find(m_memory.data_dmi_security.begin(), m_memory.data_dmi_security.end(), false) !=
                    m_memory.data_dmi_security.end());
        TEST_ASSERT(std::find(m_memory.page_table_security.begin(), m_memory.page_table_security.end(), true) !=
                    m_memory.page_table_security.end());
        TEST_ASSERT(std::find(m_memory.page_table_security.begin(), m_memory.page_table_security.end(), false) !=
                    m_memory.page_table_security.end());
        TEST_ASSERT(m_memory.read_u64(SECURE_PHYS_ADDR) == SECURE_WRITE_VALUE);
        TEST_ASSERT(m_memory.read_u64(NON_SECURE_PHYS_ADDR) == NON_SECURE_WRITE_VALUE);
    }

private:
    void configure_context_bank(unsigned int cb, uint32_t stream_id, uint64_t l0_addr, uint64_t phys_addr)
    {
        constexpr uint64_t table_desc_flags = (1ULL << 10) | 0x3ULL;
        constexpr uint64_t page_desc_flags = (1ULL << 10) | (3ULL << 8) | (3ULL << 2) | (1ULL << 6) | 0x3ULL;
        const uint64_t l1_addr = l0_addr + PAGE_SIZE;
        const uint64_t l2_addr = l1_addr + PAGE_SIZE;
        const uint64_t l3_addr = l2_addr + PAGE_SIZE;
        // The TBU strips the CSID carrier bits before walking the page tables.
        constexpr uint64_t l1_index = 0;

        write_firmware_u64(l0_addr, l1_addr | table_desc_flags);
        write_firmware_u64(l1_addr + (l1_index * sizeof(uint64_t)), l2_addr | table_desc_flags);
        write_firmware_u64(l2_addr, l3_addr | table_desc_flags);
        write_firmware_u64(l3_addr, phys_addr | page_desc_flags);

        m_smmu.SMMU_SMR[cb][m_smmu.SMR_ID] = stream_id;
        m_smmu.SMMU_SMR[cb][m_smmu.SMR_MASK] = 0;
        m_smmu.SMMU_SMR[cb][m_smmu.SMR_VALID] = 1;
        m_smmu.SMMU_S2CR[cb][m_smmu.S2CR_CBNDX_VMID] = cb;
        m_smmu.SMMU_S2CR[cb][m_smmu.S2CR_TYPE] = 0;
        m_smmu.SMMU_CBAR[cb][m_smmu.CBAR_TYPE] = 1;
        m_smmu.SMMU_CBA2R[cb][m_smmu.CBA2R_VA64] = 1;
        m_smmu.SMMU_CB_TTBR0_LOW[cb] = static_cast<uint32_t>(l0_addr);
        m_smmu.SMMU_CB_TTBR0_HIGH[cb] = static_cast<uint32_t>(l0_addr >> 32);
        m_smmu.SMMU_CB_TCR_LPAE[cb] = (1U << 31) | 16U;
        m_smmu.SMMU_CB_SCTLR[cb][m_smmu.CB_SCTLR_M] = 1;
    }

    void write_firmware_u64(uint64_t address, uint64_t value)
    {
        m_memory.load.ptr_load(reinterpret_cast<uint8_t*>(&value), address, sizeof(value));
    }

    void finish_test()
    {
        m_completion_guard.async_detach_suspending();
    }

    void test_invalidated_dmi_fallback()
    {
        auto& inst = m_instance.get();
        inst.lock_iothread();
        auto container = inst.object_new_unparented<QemuInstanceDmiManager::QemuContainer>();
        auto owner = inst.object_new_unparented<qemu::MemoryRegion>();
        owner.init(container, "fallback-test-owner", UINT64_MAX);
        inst.unlock_iothread();

        // This synthetic payload crosses lower-level DMI/MR internals directly
        // and can receive owner-managed extensions from targets. Production
        // QEMU payloads are tidied by the initiator; keep this scratch payload
        // alive for the process lifetime instead of letting ~tlm_generic_payload
        // free extensions it does not own.
        auto* scratch_txn = new tlm::tlm_generic_payload();
        tlm::tlm_generic_payload& txn = *scratch_txn;
        gs::QemuMemTxSecureTlmExtension secure;
        secure.value = true;
        txn.set_address(SECURE_IOVA);
        txn.set_command(tlm::TLM_READ_COMMAND);
        txn.set_extension(&secure);

        uint64_t transport_value = 0;
        QemuMrHintTlmExtension transport_hint(owner, SECURE_IOVA);
        txn.set_extension(&transport_hint);
        txn.set_data_ptr(reinterpret_cast<unsigned char*>(&transport_value));
        txn.set_data_length(sizeof(transport_value));
        txn.set_streaming_width(sizeof(transport_value));
        txn.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        sc_core::sc_time delay = sc_core::SC_ZERO_TIME;
        m_tbu.b_transport(txn, delay);
        TEST_ASSERT(txn.get_response_status() == tlm::TLM_OK_RESPONSE);
        TEST_ASSERT(transport_value == SECURE_WRITE_VALUE);
        TEST_ASSERT(txn.get_extension<QemuMrHintTlmExtension>() == &transport_hint);
        tlm::tlm_dmi dmi;
        TEST_ASSERT(m_tbu.get_direct_mem_ptr(txn, dmi));
        auto* mapped_hint = txn.get_extension<QemuMrHintTlmExtension>();
        TEST_ASSERT(mapped_hint != nullptr);
        TEST_ASSERT(mapped_hint != &transport_hint);
        TEST_ASSERT(mapped_hint->get_mr().get_size() == PAGE_SIZE);
        auto mr = mapped_hint->get_mr();

        const auto clear_txn_extensions = [&] {
            txn.clear_extension<QemuMrHintTlmExtension>();
            txn.clear_extension<gs::QemuMemTxSecureTlmExtension>();
            txn.clear_extension<gs::QemuMemTxSpaceTlmExtension>();
            txn.clear_extension<gs::QemuMemTxUserTlmExtension>();
            txn.clear_extension<gs::QemuMemTxMemoryTlmExtension>();
            txn.clear_extension<gs::QemuMemTxRequesterIdTlmExtension>();
            txn.clear_extension<gs::QemuMemTxPidTlmExtension>();
            txn.clear_extension<gs::QemuMemTxAddressTypeTlmExtension>();
            txn.clear_extension<gs::QemuMemTxUnspecifiedTlmExtension>();
            txn.clear_extension<gs::ShmemIDExtension>();
        };
        txn.clear_extension<QemuMrHintTlmExtension>();
        QemuMrHintTlmExtension dmi_hint(owner, SECURE_IOVA);
        txn.set_extension(&dmi_hint);
        TEST_ASSERT(m_tbu.get_direct_mem_ptr(txn, dmi));
        mapped_hint = txn.get_extension<QemuMrHintTlmExtension>();
        TEST_ASSERT(mapped_hint != nullptr);
        TEST_ASSERT(mapped_hint->get_mr().get_qemu_obj() == mr.get_qemu_obj());
        txn.clear_extension<QemuMrHintTlmExtension>();

        const auto dmi_probes = m_memory.data_dmi_security.size();
        clear_txn_extensions();
        // Force a fresh backing grant even if firmware populated this window.
        m_memory.invalidate_data_dmi();

        inst.lock_iothread();
        auto as = inst.address_space_new();
        as->init(mr, "fallback-test-as");
        inst.unlock_iothread();
        uint64_t value = 0;
        qemu::MemoryRegionOps::MemTxAttrs attrs;
        attrs.secure = true;
        qemu::MemoryRegionOps::MemTxResult result;
        // Issue DMA from a host thread, not the CPU's SystemC coroutine.
        const auto read_from_host = [&] {
            std::atomic<bool> finished{ false };
            std::thread reader([&] {
                inst.lock_iothread();
                result = as->read(0, &value, sizeof(value), attrs);
                inst.unlock_iothread();
                finished.store(true, std::memory_order_release);
                m_bridge_done.async_notify();
            });
            while (!finished.load(std::memory_order_acquire)) wait(m_bridge_done);
            reader.join();
        };
        const auto reads_before_dmi = m_memory.data_reads;
        read_from_host();
        TEST_ASSERT(result == qemu::MemoryRegionOps::MemTxOK);
        TEST_ASSERT(value == SECURE_WRITE_VALUE);
        TEST_ASSERT(m_memory.data_dmi_security.size() > dmi_probes);
        TEST_ASSERT(m_memory.data_reads == reads_before_dmi);
        value = 0;
        const auto probes_before_tlbi = m_memory.data_dmi_security.size();
        m_tbu.invalidate(0);
        read_from_host();
        TEST_ASSERT(value == SECURE_WRITE_VALUE);
        TEST_ASSERT(m_memory.data_reads == reads_before_dmi);
        TEST_ASSERT(m_memory.data_dmi_security.size() == probes_before_tlbi);

        // A second CPU root in the same instance must reuse the TBU window
        // and its populated translation, without another lazy DMI refill.
        inst.lock_iothread();
        auto second_owner = inst.object_new_unparented<qemu::MemoryRegion>();
        second_owner.init(container, "fallback-test-second-owner", UINT64_MAX);
        inst.unlock_iothread();
        QemuMrHintTlmExtension second_hint(second_owner, SECURE_IOVA);
        txn.clear_extension<QemuMrHintTlmExtension>();
        txn.set_extension(&second_hint);
        txn.set_extension(&secure);
        txn.set_address(SECURE_IOVA);
        txn.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        const auto probes_before_second_transport = m_memory.data_dmi_security.size();
        m_tbu.b_transport(txn, delay);
        TEST_ASSERT(txn.get_response_status() == tlm::TLM_OK_RESPONSE);
        TEST_ASSERT(m_memory.data_dmi_security.size() == probes_before_second_transport);
        TEST_ASSERT(m_tbu.get_direct_mem_ptr(txn, dmi));
        mapped_hint = txn.get_extension<QemuMrHintTlmExtension>();
        TEST_ASSERT(mapped_hint != nullptr);
        TEST_ASSERT(mapped_hint->get_mr().get_qemu_obj() == mr.get_qemu_obj());
        const auto probes_after_second_transport = m_memory.data_dmi_security.size();
        const auto reads_after_second_transport = m_memory.data_reads;
        clear_txn_extensions();
        value = 0;
        read_from_host();
        TEST_ASSERT(result == qemu::MemoryRegionOps::MemTxOK);
        TEST_ASSERT(value == SECURE_WRITE_VALUE);
        TEST_ASSERT(m_memory.data_dmi_security.size() == probes_after_second_transport);
        TEST_ASSERT(m_memory.data_reads == reads_after_second_transport);

        // Race readers of the shared window against revocation of an in-flight
        // DMI result. A canceled refill must never publish the old physical page.
        const uint64_t leaf_address = SECURE_L0_ADDR + 3 * PAGE_SIZE;
        const uint64_t original_leaf = m_memory.read_u64(leaf_address);
        const uint64_t alternate_leaf = original_leaf ^ SECURE_PHYS_ADDR ^ NON_SECURE_PHYS_ADDR;
        for (unsigned int round = 0; round < 32; ++round) {
            const bool alternate = (round & 1) == 0;
            write_firmware_u64(leaf_address, alternate ? original_leaf : alternate_leaf);
            m_memory.invalidate_data_dmi();
            m_memory.on_data_dmi = [&] {
                write_firmware_u64(leaf_address, alternate ? alternate_leaf : original_leaf);
                m_tbu.invalidate(0);
            };
            std::array<uint64_t, 4> values{};
            std::array<qemu::MemoryRegionOps::MemTxResult, 4> results{};
            std::array<std::thread, 4> readers;
            std::atomic<unsigned int> finished{ 0 };
            for (unsigned int i = 0; i < readers.size(); ++i) {
                readers[i] = std::thread([&, i] {
                    inst.lock_iothread();
                    results[i] = as->read(0, &values[i], sizeof(values[i]), attrs);
                    inst.unlock_iothread();
                    finished.fetch_add(1, std::memory_order_release);
                    m_bridge_done.async_notify();
                });
            }
            while (finished.load(std::memory_order_acquire) != readers.size()) wait(m_bridge_done);
            for (auto& reader : readers) reader.join();
            TEST_ASSERT(!m_memory.on_data_dmi);
            const uint64_t expected = alternate ? NON_SECURE_WRITE_VALUE : SECURE_WRITE_VALUE;
            for (unsigned int i = 0; i < readers.size(); ++i) {
                TEST_ASSERT(results[i] == qemu::MemoryRegionOps::MemTxOK);
                TEST_ASSERT(values[i] == expected);
            }
            value = 0;
            read_from_host();
            TEST_ASSERT(result == qemu::MemoryRegionOps::MemTxOK);
            TEST_ASSERT(value == expected);
        }
        write_firmware_u64(leaf_address, original_leaf);
        m_tbu.invalidate(0);

        // Stream resolution must be refreshed for each invalidation, including
        // a window moving into or out of the bank being invalidated.
        m_smmu.SMMU_S2CR[0][m_smmu.S2CR_CBNDX_VMID] = 1;
        m_tbu.invalidate(1);
        value = 0;
        read_from_host();
        TEST_ASSERT(result == qemu::MemoryRegionOps::MemTxOK);
        TEST_ASSERT(value == NON_SECURE_WRITE_VALUE);
        m_smmu.SMMU_S2CR[0][m_smmu.S2CR_CBNDX_VMID] = 0;
        m_tbu.invalidate(1);
        value = 0;
        read_from_host();
        TEST_ASSERT(result == qemu::MemoryRegionOps::MemTxOK);
        TEST_ASSERT(value == SECURE_WRITE_VALUE);

        m_memory.deny_data_dmi = true;
        m_memory.invalidate_data_dmi();
        value = 0;
        read_from_host();
        TEST_ASSERT(result == qemu::MemoryRegionOps::MemTxOK);
        TEST_ASSERT(value == SECURE_WRITE_VALUE);
        TEST_ASSERT(m_memory.data_reads > reads_after_second_transport);
        m_memory.deny_data_dmi = false;
        // Invalidate after obtaining DMI but before the refill can publish it.
        m_tbu.invalidate(0);
        const auto reads_before_invalidation = m_memory.data_reads;
        m_memory.on_data_dmi = [&] {
            m_tbu.invalidate(0);
            m_memory.deny_data_dmi = true;
        };
        value = 0;
        read_from_host();
        TEST_ASSERT(!m_memory.on_data_dmi);
        TEST_ASSERT(result == qemu::MemoryRegionOps::MemTxOK);
        TEST_ASSERT(value == SECURE_WRITE_VALUE);
        TEST_ASSERT(m_memory.data_reads > reads_before_invalidation);
        m_tbu.invalidate(0);
        m_memory.deny_data_dmi = true;
        value = 0;
        read_from_host();
        inst.lock_iothread();
        as.reset();
        inst.unlock_iothread();
        m_memory.deny_data_dmi = false;
        TEST_ASSERT(result == qemu::MemoryRegionOps::MemTxOK);
        TEST_ASSERT(value == SECURE_WRITE_VALUE);

        // A lazy window installed during bypass must still provide access, but
        // it should stay behind the TBU instead of publishing physical RAM.
        const uint32_t saved_scr0 = static_cast<uint32_t>(m_smmu.SMMU_SCR0);
        m_smmu.SMMU_SCR0 = saved_scr0 | 1u;
        m_tbu.reset_dmi();
        txn.set_address(SECURE_PHYS_ADDR);
        txn.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        txn.set_data_ptr(reinterpret_cast<unsigned char*>(&transport_value));
        txn.set_data_length(sizeof(transport_value));
        txn.set_streaming_width(sizeof(transport_value));
        txn.set_extension(&secure);
        QemuMrHintTlmExtension bypass_hint(owner, SECURE_PHYS_ADDR);
        txn.set_extension(&bypass_hint);
        m_tbu.b_transport(txn, delay);
        TEST_ASSERT(txn.get_response_status() == tlm::TLM_OK_RESPONSE);
        TEST_ASSERT(m_tbu.get_direct_mem_ptr(txn, dmi));
        mapped_hint = txn.get_extension<QemuMrHintTlmExtension>();
        TEST_ASSERT(mapped_hint != nullptr);
        mr = mapped_hint->get_mr();
        clear_txn_extensions();

        inst.lock_iothread();
        as = inst.address_space_new();
        as->init(mr, "bypass-test-as");
        inst.unlock_iothread();
        const auto reads_before = m_memory.data_reads;
        value = 0;
        read_from_host();
        TEST_ASSERT(result == qemu::MemoryRegionOps::MemTxOK);
        TEST_ASSERT(value == SECURE_WRITE_VALUE);
        TEST_ASSERT(m_memory.data_reads > reads_before);
        inst.lock_iothread();
        as.reset();
        inst.unlock_iothread();
        m_smmu.SMMU_SCR0 = saved_scr0;
        m_tbu.reset_dmi();
        clear_txn_extensions();
        txn.clear_extension<QemuMrHintTlmExtension>();
        TEST_ASSERT(txn.get_extension<QemuMrHintTlmExtension>() == nullptr);
    }

    void load_firmware_binary(const char* path, uint64_t address, std::initializer_list<uint64_t> patches)
    {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        TEST_ASSERT(file.is_open());

        const std::streamsize size = file.tellg();
        std::vector<uint8_t> firmware(size);
        file.seekg(0, std::ios::beg);
        TEST_ASSERT(file.read(reinterpret_cast<char*>(firmware.data()), size));
        TEST_ASSERT(firmware.size() >= patches.size() * sizeof(uint64_t));

        size_t index = 0;
        for (const uint64_t patch : patches) {
            const size_t offset = firmware.size() - (patches.size() - index) * sizeof(patch);
            std::memcpy(firmware.data() + offset, &patch, sizeof(patch));
            ++index;
        }
        m_memory.load.ptr_load(firmware.data(), address, firmware.size());
    }
};

} // namespace

int sc_main(int argc, char* argv[]) { return run_testbench<CpuArmCortexA53SMMU500SecureAttrsTest>(argc, argv); }
