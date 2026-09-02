# SMMU-500 Model Specification Compliance Report

Reference: ARM DDI 0517 (CoreLink MMU-500 TRM), ARM IHI 0062 (SMMUv2 Architecture Specification)

## 1. Summary

This model implements a functional subset of the ARM MMU-500 sufficient for
AArch64 LPAE page table walks (stage 1, stage 2, and nested stage 1+2), stream
matching, TLB invalidation via DMI, and global address translation services.
Only registers with associated behavioral logic are explicitly declared in the
model; all other registers in the SMMU address space (identification, debug,
performance monitors, etc.) are accessible as memory via the reg_model_maker
ZIP configuration.

---

## 2. Features Covered

### 2.1 Register Map

| Area | Status | Notes |
|------|--------|-------|
| Global config (SCR0, SCR1, SACR) | Functional | SCR0.CLIENTPD, USFCFG, SMCFCFG, GFRE, and GFIE are used; GCFGFRE/GCFGFIE fields are exposed; NSCR0 syncs to SCR0 |
| Identification (IDR0-2, IDR7) | Functional | IDR0.NUMSMRG, IDR0.ATOSNS, IDR1.NUMCB, IDR1.NUMPAGENDXB, IDR7 set from CCI params at start_of_simulation |
| Stream Match (SMR[n]) | Functional | VALID/MASK/ID fields used by smmu500_stream_id_match() |
| Stream-to-Context (S2CR[n]) | Functional | CBNDX and TYPE are used; translation, bypass, and fault actions are supported |
| Context Bank Attribute (CBAR[n]) | Functional | TYPE (bits [17:16]) drives stage selection; CBNDX for S2 CB (bits [15:8]) |
| Context Bank Attribute 2 (CBA2R[n]) | Functional | VA64 (bit 0) checked during page table walk |
| Global fault status (SGFSR) | Functional | ICF/USF/SMCF set on global stream/config faults, clear on write-1-to-clear, and drive irq_global when GFIE is set |
| GATS (privileged and unprivileged stage 1/stage 1+2 variants, GPAR) | Functional | Post-write on the _H register triggers translation; result in GPAR; invalid context-bank indices report an error and set SGFSR.ICF |
| Per-CB TLB invalidation (TLBIALL, TLBIASID, VA/IPA variants, TLBSYNC, TLBSTATUS) | Functional | TLBI writes trigger conservative DMI invalidation across all TBUs for the addressed CB; TLBSYNC completes synchronously and TLBSTATUS reads idle |
| Global TLB invalidation | Functional | Global invalidate commands trigger conservative DMI invalidation across all TBUs; VMID-targeted commands invalidate CBs whose CBAR.VMID matches |
| TBU_PWR_STATUS | Stored | Populated from p_num_tbu |

All other registers in the SMMU address space (IDR3-6, PID/CID, global fault
syndrome, non-secure register copies beyond NSCR0, performance monitors,
integration/test, and vendor-specific registers) are accessible as memory via
the reg_model_maker ZIP configuration but have no behavioral logic.

### 2.2 Context Bank Registers (per CB page)

| Register | Status | Notes |
|----------|--------|-------|
| CB_SCTLR | Functional | Bit 0 (M) enables translation; bit 6 (CFIE) used for IRQ |
| CB_ACTLR | Stored | |
| CB_RESUME | Stored | No stall/resume logic |
| CB_TCR2 | Functional | Upper 32 bits of 64-bit TCR for stage 1 |
| CB_TTBR0 (LOW/HIGH) | Functional | Base address for page table walk |
| CB_TTBR1 (LOW/HIGH) | Functional | Used for VA[63]=1 (upper address range) |
| CB_TCR_LPAE | Functional | T0SZ, T1SZ, TG0, TG1, EPD0, EPD1, SL0, PS fields all used |
| CB_CONTEXTIDR | Stored | |
| CB_PRRR_MAIR0 | Stored | Memory attribute registers present but not used in translation |
| CB_NMRR_MAIR1 | Stored | |
| CB_FSR | Functional | TF/AFF/PF/EF/ASF classification, MULTI latching, W1C, and context IRQ |
| CB_FSRRESTORE | Stored | Exists at correct offset |
| CB_FAR (LOW/HIGH) | Functional | Written on stage 2 faults |
| CB_FSYNR0 | Functional | PLVL, WNR, PNU, IND, NSATTR, ATOF, PTWF, AFR, and S1CBNDX are recorded for the first fault |
| CB_FSYNR1 | Functional | MID/PID/BID are recorded from the optional TLM transaction-attributes extension |
| CB_IPAFAR (LOW/HIGH) | Functional | Written with faulting VA/IPA on faults |
| CB_TLBIVA/TLBIVAA/TLBIVAL/TLBIVAAL | Functional | Post-write conservatively invalidates all DMI views for the addressed CB |
| CB_TLBIIPAS2/TLBIIPAS2L | Functional | Post-write conservatively invalidates all DMI views for the addressed CB |
| CB_TLBIASID | Functional | Post-write invalidates DMI views for the addressed CB; the model has no ASID-tagged TLB cache |
| CB_TLBIALL | Functional | Post-write triggers DMI invalidation for the CB |
| CB_TLBSYNC | Functional | Completion is synchronous |
| CB_TLBSTATUS | Functional | Always reads 0 (no pending operations) |

### 2.3 Translation Logic

| Feature | Status | Notes |
|---------|--------|-------|
| AArch64 Stage 1 LPAE walk | Implemented | 4KB, 16KB, 64KB granule sizes supported |
| AArch64 Stage 2 walk | Implemented | SL0 starting level, separate PS field extraction |
| Nested S1+S2 translation | Implemented | S1 descriptor addresses translated through S2 as read accesses; nested stage-1 faults stop before final stage-2 translation; S2 faults during S1 walks are reported as PTWF |
| TTBR0/TTBR1 split (VA[63]) | Implemented | Upper/lower VA range with separate TG, TSZ |
| EPD (Translation Disable) | Implemented | EPD0 checked; faults if set |
| Block translations | Implemented | Block entries at correct levels per granule |
| Table attribute accumulation | Implemented | Bits [63:59] of table descriptors accumulated |
| Output address size check | Implemented | Addresses checked against PAMAX/output size |
| Access permission (AP) | Implemented | S1: AP[1] privileged-only check and AP[2] read-only check; S2: HAP S2AP checking |
| Access flag (AF) check | Implemented | Bit 10 of descriptor checked; fault if not set |
| DMA-based descriptor reads | Implemented | Page table descriptors read via dma_socket b_transport |
| CBAR.TYPE stage selection | Implemented | All four types (S2-only, S1+fault, S1-only, S1+S2) |

### 2.4 TBU Architecture

| Feature | Status | Notes |
|---------|--------|-------|
| Multiple TBUs per TCU | Implemented | Vector of TBU pointers; configurable via p_num_tbu |
| TBU b_transport forwarding | Implemented | Translates address, forwards to downstream_socket |
| TBU transport_dbg | Implemented | Debug transport with address translation |
| TBU DMI (get_direct_mem_ptr) | Implemented | Full DMI support with page-aligned virtual-to-physical mapping; SMMU translation faults are tagged as denied DMI so QEMU cannot synthesize a 1:1 fallback |
| DMI invalidation on TLBI | Implemented | TLBIALL/TLBIASID trigger upstream DMI invalidation |
| Per-CB DMI range tracking | Implemented | dmi_range[] tracks valid ranges per context bank |
| Thread-safe DMI locking | Implemented | Mutex-based locking; THREAD_SAFE_REENTRANT compile-time option |
| Topology ID (stream ID) | Implemented | CCI param per TBU; used for stream matching |

### 2.5 Interrupts

| Feature | Status | Notes |
|---------|--------|-------|
| Per-CB context fault IRQ | Implemented | irq_context[cb] is asserted while any CB_FSR fault bit is set and SCTLR.CFIE is enabled; it is recomputed on fault-status, CFIE, and reset changes |
| Global fault IRQ | Implemented | Asserted while SGFSR.ICF, SGFSR.USF, or SGFSR.SMCF is set and SCR0.GFIE is enabled |

### 2.6 Reset

| Feature | Status | Notes |
|---------|--------|-------|
| Register reset via signal | Implemented | reset signal triggers M.reset(), restores all register defaults, and deasserts IRQ outputs |

### 2.7 Validation Coverage

The repository includes a dedicated SMMU500 unit test bench under
`tests/components/smmu500`. The tests cover stream matching, S2CR bypass/fault
handling, global and context fault status, W1C behavior, GATS operations,
stage-1 and stage-2 translations, nested translation, fault syndrome recording,
TBU read/write/debug forwarding, DMI range handling, and TLBI-triggered DMI
invalidation.

---

## 3. Features Not Covered

### 3.1 Global Fault Behavior

The model implements ICF, USF, and SMCF for stream-mapping transactions. ICF is
reported and rejects the transaction when a matched S2CR selects TYPE=0b10
(Fault), TYPE is reserved, or the selected CBNDX is outside the implemented
context-bank range. SGFSR status is recorded, and `SCR0.GFIE` drives
`irq_global`. SGFSR status bits are write-1-to-clear.
GATS requests with a context-bank index outside `p_num_cb` also report ICF and
return `GPAR.F = 1`.

Configuration-access faults (`SGFSR.CAF`) and their `SCR0.GCFGFRE/GCFGFIE`
reporting paths remain unsupported because the generic register target does not
currently expose security/access metadata needed to identify disallowed
configuration accesses.

### 3.2 S2CR TYPE Field

The S2CR.TYPE field (bits [17:16]) is checked:

- TYPE=0b00 (Translation): Use the selected context bank
- TYPE=0b01 (Bypass): Pass transactions without translation
- TYPE=0b10 (Fault): Generate an Invalid Context Fault
- TYPE=0b11 (Reserved): Treated as an Invalid Context Fault

### 3.3 Write-1-to-Clear (W1C) Semantics

SGFSR.ICF, SGFSR.USF, and SGFSR.SMCF implement write-1-to-clear behavior. CB_FSR
fault status bits also implement write-1-to-clear semantics; clearing the last
fault deasserts the context IRQ. The FSRRESTORE companion registers have no
special relationship to FSR.

### 3.4 Read-Only / Write-Only Register Enforcement

Read-only and write-only register access semantics are partially enforced.
IDR0/1/2/7 are restored from model configuration after writes, and implemented
TLBI command registers are cleared after writes. The remaining register set does
not generally enforce architectural RO/WO access policy.

### 3.5 Context Fault Syndrome Details

The model classifies synchronous translation failures into the context-bank FSR
status bits:

- `TF`: malformed descriptors, disabled walks, and ordinary translation faults
- `AFF`: access-flag failures
- `PF`: stage-1 or stage-2 permission failures
- `EF`: external errors while fetching translation-table descriptors
- `ASF`: output-address-size or canonical-address failures
- `MULTI`: set when a new fault is recorded while another FSR fault bit is latched

For the first fault, `CB_FSYNR0` records the walk level, write/read direction,
privileged/unprivileged state, instruction/data state, security state,
address-translation-operation state, page-table-walk-fault state, asynchronous
recording state, and stage-1 context-bank index. Nested stage-2 faults that
occur while fetching stage-1 descriptors are reported to the stage-1 context as
page-table-walk faults, with IPAFAR set to the descriptor IPA. `CB_FSYNR1`
records MID/PID/BID when the `smmu500_transaction_attrs_extension` is attached;
otherwise those fields default to zero.
The first fault's FAR/IPAFAR and syndrome are preserved when `MULTI` is set.

### 3.6 Security State Differentiation

The model supports optional request attributes through the
`gs::smmu500_transaction_attrs_extension` TLM extension. The extension carries
the request privilege level, security state, instruction/data access, address
translation operation, asynchronous state, and MID/PID/BID syndrome fields.
GATS operations populate the privilege state directly from the operation
variant (`GATS1P*` versus `GATS1U*`).

When an ordinary TLM transaction has no such extension, the model defaults to
a privileged, non-secure data access. This is a compatibility policy: it does
not prove that the originating requester was privileged, and therefore cannot
report an unprivileged-access permission fault for an unannotated transaction.
Translation, access-flag, read/write permission, external-walk, and
address-size faults remain independently checked.

The CPU or interconnect bridge is responsible for attaching the extension at
the TBU ingress. For AXI-like request attributes, the intended mapping is:

- `AxPROT[0]` (unprivileged) -> `privileged = false`
- `AxPROT[1]` (secure) -> `non_secure = false`
- instruction/data indication -> `instruction`

The model does not currently enforce:
- Secure vs non-secure bus transaction access rules
- SCR1 partitioning of CBs/SMRs between secure and non-secure worlds
- Register banking based on security state (secure accesses always go to
  secure copies, non-secure to NS copies)

`SCR1.NSNUMCBO` and `NSNUMSMRGO` are populated but not used for access
control. The existing `smmuv3_secure_extension` and
`smmuv3_memory_attrs_extension` are not substitutes for the SMMU500 request
extension: the former carries only security state, while the latter carries
attributes derived from page-table descriptors rather than requester
privilege.

### 3.7 VMID Support

- VMID matching in S2CR is not implemented
- VMID-based global TLB invalidation is implemented conservatively for DMI
  ranges by invalidating context banks whose CBAR.VMID matches the command VMID
- 16-bit VMID (SCR0.VMID16EN, CBA2R.VMID) is not used

### 3.8 Per-CB TLB Invalidation by VA

CB_TLBIVA, CB_TLBIVAA, CB_TLBIVAL, CB_TLBIVAAL, CB_TLBIIPAS2, and
CB_TLBIIPAS2L are implemented as conservative per-CB DMI invalidations. The
model does not maintain a VA/IPA-tagged TLB, so these commands invalidate all
tracked DMI for the addressed context bank rather than a precise VA/IPA entry.

### 3.9 Global TLB Invalidation

Global TLB invalidation operations (STLBIALL, TLBIVMID, TLBIALLNSNH, TLBIALLH,
TLBIVMIDS1, and 64-bit VA variants) are implemented as conservative DMI
invalidations. The model does not maintain architectural TLB entries, so
address-specific commands invalidate broader DMI state than hardware would.

### 3.10 Transaction Stalling

- CB_SCTLR.CFCFG (stall vs terminate on fault) is not checked
- CB_RESUME has no logic — stalled transactions cannot be resumed
- CB_FSR.SS (stalled status) is never set
- SCR0.STALLD / GSE are not used

### 3.11 GATS Limitations

All eight GATS operations are implemented as translation requests:
- GATS1PR, GATS1PW, GATS12PR, GATS12PW
- GATS1UR, GATS1UW, GATS12UR, GATS12UW

The model uses the operation variant to select privileged versus unprivileged
permission checks and read versus write permission checks. The result is written
to GPAR/GPAR_H. Invalid context-bank indices return `GPAR.F = 1` and set
`SGFSR.ICF`.

### 3.12 AArch32 Short-Descriptor Format

Only the AArch64 LPAE (Long Descriptor) page table format is implemented.
The AArch32 Short-Descriptor format (used when CBA2R.VA64=0 and the CB is
configured for 32-bit virtual addresses) is **not supported**.

### 3.13 Memory Attributes

- MAIR0/MAIR1 (PRRR/NMRR) are stored but not used during translation
- Descriptor memory attributes are not propagated to the translated transaction
- SCR0 shareability/cacheability overrides (SHCFG, RACFG, WACFG, MEMATTR,
  MTCFG) are not applied
- CB_SCTLR cacheability/shareability fields are not used

---

## 4. Implementation Differences from Spec

### 4.1 TBU Transport Encoding

The TBU accepts an integration-specific transport encoding:
```
base_sid  = topology_id & 0x7fff
master_id = base_sid | ((addr >> 32) & 0xf)
iova = addr & 0xffffffff
```
The integration provides `base_sid` as a 15-bit value. The historical
`topology_id` parameter carries this base SID; the transport carrier supplies
the low four stream bits using the same OR-based behavior as the legacy model.
The resulting SID is matched exactly against the programmed SMR entries. An
unresolved SID follows the configured unidentified-stream behavior; it is not
rewritten to another programmed CSID.
For a matched AArch64 stage-1 context, the TBU decodes the transport carrier
into the configured IOVA width before calling the SMMU core. This encoding is
not an architectural SMMU interface; the ARM interface provides the StreamID
and IOVA independently. The core validates the decoded IOVA against TTBR0 or
TTBR1 according to the architecture. Direct translations and GATS operations
preserve their full 64-bit input address.

### 4.2 SMMU Bypass Behavior

When SCR0.CLIENTPD=1, the model returns `addr_mask = -1` (full bypass,
identity mapping). For an unmatched stream, SCR0.USFCFG controls whether the
stream faults: when set, USF is recorded and the transaction is rejected; when
clear, the transaction bypasses without recording USF. For multiple matches,
SCR0.SMCFCFG controls whether SMCF is recorded and rejected; when clear, the
first matching S2CR action is used. There is no software parameter override for
these architectural controls.

Stage-1 input addresses are checked against the selected TTBR0 or TTBR1 range.
Out-of-range or non-canonical addresses raise CB_FSR.ASF.

### 4.3 Fault Handling

The model classifies the main synchronous translation fault types into
CB_FSR.TF, AFF, PF, EF, and ASF, records first-fault syndrome state, and latches
CB_FSR.MULTI on later faults. It does not model stalled-fault delivery or
resume behavior, and FSRRESTORE remains storage-only.

### 4.4 NSCR0-to-SCR0 Sync

Writing NSCR0 copies the full value to SCR0. Per spec, NSCR0 and SCR0 share
some fields but others are secure-only and should not be modifiable via NSCR0.
The model does a wholesale copy without masking.

### 4.5 No TLB Caching in TCU

The model performs a full page table walk on every translation. There is no TLB
cache in the TCU (Translation Control Unit). Only the TBU-side DMI mechanism
provides translation caching. This is functionally correct but differs from
hardware which caches translations in both TBU micro-TLBs and TCU main TLB.

### 4.6 GATS Input Format

The model encodes the GATS input as:
```
va = value & ~0xFFF
cb = value & 0xFFF
```
This uses the lower 12 bits for the context bank index and the upper bits for
the VA. If the decoded context bank is outside `p_num_cb`, the model reports an
invalid-context fault via SGFSR.ICF and returns an error in GPAR. The spec uses a
different encoding where the CB index and VA are packed differently depending on
the register width.

### 4.7 Synchronous TLB Invalidation

TLBSYNC/TLBSTATUS always indicate completion (TLBSTATUS reads 0) because
invalidation is performed synchronously in the post_write callback. Hardware
would have asynchronous invalidation where TLBSTATUS.SACTIVE indicates pending
operations.

---

## 5. Configurable Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| p_pamax | 48 | Physical address width (bits) |
| p_num_smr | 224 | Number of Stream Match Register groups |
| p_num_cb | 16 | Number of context banks |
| p_num_pages | 16 | Number of global register pages |
| p_ato | true | Address Translation Operations supported |
| p_version | 0x24 | IDR7 version (major.minor = 2.4) |
| p_idr2 | 0x7111 | IDR2 advertised translation-table formats and address sizes |
| p_num_tbu | 1 | Number of Translation Buffer Units |
