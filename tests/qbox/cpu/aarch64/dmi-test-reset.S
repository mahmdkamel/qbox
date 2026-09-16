.text
.global _start

_start:
    // Load addresses from constants defined at end of file
    adr x2, mmio_addr
    ldr x2, [x2]        // MMIO control address
    adr x1, dmi_addr
    ldr x1, [x1]        // DMI data address

    // Derive the linear CPU ID used by the test bench from MPIDR, then
    // select this CPU's eight-byte DMI and MMIO slots.
    mrs x5, mpidr_el1
    and x3, x5, #0xff
    and x5, x5, #0xff00
    lsr x5, x5, #5
    orr x5, x5, x3
    lsl x0, x5, #3
    add x1, x1, x0
    add x2, x2, x0

    mov x3, #10         // max iterations per reset (DMI_WRITES_PER_RESET)
    mov x4, #0          // current counter

loop:
    // Perform DMI read/write
    ldr x0, [x1]        // Read from DMI
    add x4, x4, #1      // Increment counter
    str w4, [x1]        // Write back to DMI (32-bit)

    // Check if this is CPU #0 and time for reset
    cmp x5, #0
    b.ne not_cpu0

    // CPU #0: Check if we should trigger reset
    cmp x4, x3          // Compare current with max iterations per reset
    b.lt loop           // If not time for reset, continue

    // Trigger reset by writing special value to MMIO
    mov x6, #7          // RESET_TRIGGER_VAL
    str w6, [x2]        // Write to MMIO to trigger reset (32-bit)

    // Reset counter for next cycle and continue
    mov x4, #0          // Reset counter
    b loop

not_cpu0:
    // Non-reset CPUs: just write status to MMIO and continue
    str w4, [x2]        // Report current iteration to MMIO (32-bit)

    // Check for completion (higher limit for non-reset CPUs)
    mov x6, #100        // Total iterations limit
    cmp x4, x6
    b.lt loop

end:
    wfi
    b end

fail:
    mov w0, #-1         // Failure indicator outside the normal counter range
    str w0, [x2]        // Write failure indicator (32-bit)
    b end

// Constants section - will be filled in by CMake
.align 3
mmio_addr:
    .quad 0x80000000    // MMIO_ADDR placeholder
dmi_addr:
    .quad 0x90000000    // DMI_ADDR placeholder
