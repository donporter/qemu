/*
 * CPU operations specific to system emulation
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef SYSEMU_CPU_OPS_H
#define SYSEMU_CPU_OPS_H

#include "hw/core/cpu.h"

/*
 * struct mem_print_state: Used by qmp in walking page tables.
 */
struct mem_print_state {
    GString *buf;
    CPUArchState *env;
    int vaw, paw; /* VA and PA width in characters */
    int max_height;
    bool (*flusher)(CPUState *cs, struct mem_print_state *state);
    bool flush_interior; /* If false, only call flusher() on leaves */
    bool require_physical_contiguity;
    /*
     * The height at which we started accumulating ranges, i.e., the
     * next height we need to print once we hit the end of a
     * contiguous range.
     */
    int start_height;
    int leaf_height; /* The height at which we found a leaf, or -1 */
    /*
     * For compressing contiguous ranges, track the
     * start and end of the range
     */
    hwaddr vstart[MAX_HEIGHT + 1]; /* Starting virt. addr. of open pte range */
    hwaddr vend[MAX_HEIGHT + 1]; /* Ending virtual address of open pte range */
    hwaddr pstart; /* Starting physical address of open pte range */
    hwaddr pend; /* Ending physical address of open pte range */
    uint64_t prot[MAX_HEIGHT + 1]; /** PTE protection flags current root->leaf
                                      path */
    uint64_t pg_size[MAX_HEIGHT + 1]; /** Page size,
                                       *  or address range covered. */
    int offset[MAX_HEIGHT + 1]; /* PTE range starting offsets */
    int last_offset[MAX_HEIGHT + 1]; /* PTE range ending offsets */
};


/*
 * struct SysemuCPUOps: System operations specific to a CPU class
 */
typedef struct SysemuCPUOps {
    /**
     * @get_memory_mapping: Callback for obtaining the memory mappings.
     */
    bool (*get_memory_mapping)(CPUState *cpu, MemoryMappingList *list,
                               Error **errp);
    /**
     * @get_paging_enabled: Callback for inquiring whether paging is enabled.
     */
    bool (*get_paging_enabled)(const CPUState *cpu);
    /**
     * @get_phys_page_debug: Callback for obtaining a physical address.
     */
    hwaddr (*get_phys_page_debug)(CPUState *cpu, vaddr addr);
    /**
     * @get_phys_page_attrs_debug: Callback for obtaining a physical address
     *       and the associated memory transaction attributes to use for the
     *       access.
     * CPUs which use memory transaction attributes should implement this
     * instead of get_phys_page_debug.
     */
    hwaddr (*get_phys_page_attrs_debug)(CPUState *cpu, vaddr addr,
                                        MemTxAttrs *attrs);
    /**
     * @asidx_from_attrs: Callback to return the CPU AddressSpace to use for
     *       a memory access with the specified memory transaction attributes.
     */
    int (*asidx_from_attrs)(CPUState *cpu, MemTxAttrs attrs);
    /**
     * @get_crash_info: Callback for reporting guest crash information in
     * GUEST_PANICKED events.
     */
    GuestPanicInformation* (*get_crash_info)(CPUState *cpu);
    /**
     * @write_elf32_note: Callback for writing a CPU-specific ELF note to a
     * 32-bit VM coredump.
     */
    int (*write_elf32_note)(WriteCoreDumpFunction f, CPUState *cpu,
                            int cpuid, DumpState *s);
    /**
     * @write_elf64_note: Callback for writing a CPU-specific ELF note to a
     * 64-bit VM coredump.
     */
    int (*write_elf64_note)(WriteCoreDumpFunction f, CPUState *cpu,
                            int cpuid, DumpState *s);
    /**
     * @write_elf32_qemunote: Callback for writing a CPU- and QEMU-specific ELF
     * note to a 32-bit VM coredump.
     */
    int (*write_elf32_qemunote)(WriteCoreDumpFunction f, CPUState *cpu,
                                DumpState *s);
    /**
     * @write_elf64_qemunote: Callback for writing a CPU- and QEMU-specific ELF
     * note to a 64-bit VM coredump.
     */
    int (*write_elf64_qemunote)(WriteCoreDumpFunction f, CPUState *cpu,
                                DumpState *s);
    /**
     * @virtio_is_big_endian: Callback to return %true if a CPU which supports
     * runtime configurable endianness is currently big-endian.
     * Non-configurable CPUs can use the default implementation of this method.
     * This method should not be used by any callers other than the pre-1.0
     * virtio devices.
     */
    bool (*virtio_is_big_endian)(CPUState *cpu);

    /**
     * @legacy_vmsd: Legacy state for migration.
     *               Do not use in new targets, use #DeviceClass::vmsd instead.
     */
    const VMStateDescription *legacy_vmsd;

    /**
     * page_table_root - Given a CPUState, return the physical address
     *                    of the current page table root, as well as
     *                    setting a pointer to a PageTableLayout.
     *
     * @cs - CPU state
     * @layout - a pointer to a PageTableLayout structure, which stores
     *           the page table tree geometry.
     *
     * Returns a hardware address on success.  Should not fail (i.e.,
     * caller is responsible to ensure that a page table is actually
     * present).
     *
     * Do not free layout.
     */
    hwaddr (*page_table_root)(CPUState *cs, const PageTableLayout **layout);

    /**
     * get_pte - Copy and decode the contents of the page table entry at
     *           node[i] into pt_entry.
     *
     * @cs - CPU state
     * @node - physical address of the current page table node
     * @i - index (in page table entries, not bytes) of the page table
     *      entry, within node
     * @height - height of node within the tree (leaves are 1, not 0)
     * @pt_entry - Pointer to a DecodedPTE, stores the contents of the page
     *             table entry
     * @vaddr_parent - The virtual address bits already translated in
     *                 walking the page table to node.  Optional: only
     *                 used if vaddr_pte is set.
     */

    void (*get_pte)(CPUState *cs, hwaddr node, int i, int height,
                    DecodedPTE *pt_entry, vaddr vaddr_parent);

    /**
     * @mon_init_page_table_iterator: Callback to configure a page table
     * iterator for use by a monitor function.
     * Returns true on success, false if not supported (e.g., no paging disabled
     * or not implemented on this CPU).
     */
    bool (*mon_init_page_table_iterator)(CPUState *cpu, GString *buf,
                                         struct mem_print_state *state);

    /**
     * @mon_info_pg_print_header: Prints the header line for 'info pg'.
     */
    void (*mon_info_pg_print_header)(struct mem_print_state *state);

    /**
     * @flush_page_table_iterator_state: For 'info pg', it prints the last
     * entry that was visited by the compressing_iterator, if one is present.
     */
    bool (*mon_flush_page_print_state)(CPUState *cs,
                                       struct mem_print_state *state);

    /**
     * @mon_print_pte: Hook called by the monitor to print a page
     * table entry at address addr, with contents pte.
     */
    void (*mon_print_pte) (GString *buf, CPUArchState *env, hwaddr addr,
                           hwaddr pte, uint64_t prot);

    /**
     * @mon_print_mem: Hook called by the monitor to print a range
     * of memory mappings in 'info mem'
     */
    bool (*mon_print_mem)(CPUState *cs, struct mem_print_state *state);

} SysemuCPUOps;

int compressing_iterator(CPUState *cs, void *data, DecodedPTE *pte,
                         int height, int offset,
                         const PageTableLayout *layout);

#endif /* SYSEMU_CPU_OPS_H */
