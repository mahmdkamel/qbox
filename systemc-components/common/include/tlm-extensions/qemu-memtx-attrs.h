/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef _LIBQBOX_TLM_EXTENSIONS_QEMU_MEMTX_ATTRS_H
#define _LIBQBOX_TLM_EXTENSIONS_QEMU_MEMTX_ATTRS_H

#include <cstdint>

#include <tlm>

namespace gs {

enum class QemuSecuritySpace : uint8_t {
    Secure = 0,
    NonSecure = 1,
    Root = 2,
    Realm = 3,
};

// QEMU transaction attributes carried by an upstream transaction.
class QemuMemTxAttrsTlmExtension : public tlm::tlm_extension<QemuMemTxAttrsTlmExtension>
{
public:
    bool secure = false;
    QemuSecuritySpace space = QemuSecuritySpace::Secure;
    bool user = false;
    bool memory = false;
    bool debug = false;
    uint16_t requester_id = 0;
    uint8_t pid = 0;
    bool address_type = false;
    bool unspecified = false;

    QemuMemTxAttrsTlmExtension() = default;
    QemuMemTxAttrsTlmExtension(const QemuMemTxAttrsTlmExtension&) = default;

    tlm::tlm_extension_base* clone() const override { return new QemuMemTxAttrsTlmExtension(*this); }

    void copy_from(const tlm::tlm_extension_base& ext) override
    {
        *this = static_cast<const QemuMemTxAttrsTlmExtension&>(ext);
    }
};

} // namespace gs

#endif
