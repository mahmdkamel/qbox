/*
 * Copyright (c) 2026 Qualcomm Innovation Center, Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _LIBQBOX_QEMU_INSTANCE_ORDER_H
#define _LIBQBOX_QEMU_INSTANCE_ORDER_H

#include <vector>

/*
 * Process-wide registry of the QEMU instances, used to decide the order in
 * which they are initialized (see QemuInstance::init()).
 */
namespace qemu_instance_order {

class Entry
{
public:
    virtual ~Entry() = default;

    /* Name used in diagnostics */
    virtual const char* instance_name() const = 0;

    /* The instance hosts a VNC display */
    virtual bool instance_has_vnc() const = 0;

    /* Initialize the instance if it is not already */
    virtual void instance_init_early() = 0;
};

void register_instance(Entry* e);
void unregister_instance(Entry* e);

/*
 * Returns the registered instances to the first caller only, and an empty
 * list to every later caller. The first QEMU instance being initialized uses
 * it to initialize the VNC instance before anything else.
 */
std::vector<Entry*> claim_first_init();

} // namespace qemu_instance_order

#endif
