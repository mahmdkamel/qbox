/*
 * Copyright (c) 2026 Qualcomm Innovation Center, Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <qemu-instance-order.h>

#include <algorithm>
#include <mutex>
#include <vector>

/*
 * QemuInstance is a header-only class, compiled into every module DLL that
 * uses it. This registry lives in libqbox so that all the instances of the
 * process, whatever module created them, share a single copy of it.
 */
namespace {

struct Registry {
    std::mutex lock;
    std::vector<qemu_instance_order::Entry*> entries;
    bool ordering_done = false;
};

Registry& registry()
{
    static Registry r;
    return r;
}

} // namespace

namespace qemu_instance_order {

void register_instance(Entry* e)
{
    Registry& r = registry();
    std::lock_guard<std::mutex> l(r.lock);
    r.entries.push_back(e);
}

void unregister_instance(Entry* e)
{
    Registry& r = registry();
    std::lock_guard<std::mutex> l(r.lock);
    r.entries.erase(std::remove(r.entries.begin(), r.entries.end(), e), r.entries.end());
}

std::vector<Entry*> claim_first_init()
{
    Registry& r = registry();
    std::lock_guard<std::mutex> l(r.lock);

    if (r.ordering_done) {
        return {};
    }
    r.ordering_done = true;
    return r.entries;
}

} // namespace qemu_instance_order
