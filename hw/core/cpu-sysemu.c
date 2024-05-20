/*
 * QEMU CPU model (system emulation specific)
 *
 * Copyright (c) 2012-2014 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "exec/tswap.h"
#include "hw/core/sysemu-cpu-ops.h"

bool cpu_paging_enabled(const CPUState *cpu, int mmu_idx)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->sysemu_ops->get_paging_enabled) {
        return cc->sysemu_ops->get_paging_enabled(cpu, mmu_idx);
    }

    return false;
}

bool cpu_get_memory_mapping(CPUState *cpu, MemoryMappingList *list,
                            Error **errp)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->sysemu_ops->get_memory_mapping) {
        return cc->sysemu_ops->get_memory_mapping(cpu, list, errp);
    }

    error_setg(errp, "Obtaining memory mappings is unsupported on this CPU.");
    return false;
}

hwaddr cpu_get_phys_page_attrs_debug(CPUState *cpu, vaddr addr,
                                     MemTxAttrs *attrs)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->sysemu_ops->get_phys_page_attrs_debug) {
        return cc->sysemu_ops->get_phys_page_attrs_debug(cpu, addr, attrs);
    }
    /* Fallback for CPUs which don't implement the _attrs_ hook */
    *attrs = MEMTXATTRS_UNSPECIFIED;
    return cc->sysemu_ops->get_phys_page_debug(cpu, addr);
}

hwaddr cpu_get_phys_page_debug(CPUState *cpu, vaddr addr)
{
    MemTxAttrs attrs = {};

    return cpu_get_phys_page_attrs_debug(cpu, addr, &attrs);
}

int cpu_asidx_from_attrs(CPUState *cpu, MemTxAttrs attrs)
{
    int ret = 0;

    if (cpu->cc->sysemu_ops->asidx_from_attrs) {
        ret = cpu->cc->sysemu_ops->asidx_from_attrs(cpu, attrs);
        assert(ret < cpu->num_ases && ret >= 0);
    }
    return ret;
}

int cpu_write_elf32_qemunote(WriteCoreDumpFunction f, CPUState *cpu,
                             void *opaque)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (!cc->sysemu_ops->write_elf32_qemunote) {
        return 0;
    }
    return (*cc->sysemu_ops->write_elf32_qemunote)(f, cpu, opaque);
}

int cpu_write_elf32_note(WriteCoreDumpFunction f, CPUState *cpu,
                         int cpuid, void *opaque)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (!cc->sysemu_ops->write_elf32_note) {
        return -1;
    }
    return (*cc->sysemu_ops->write_elf32_note)(f, cpu, cpuid, opaque);
}

int cpu_write_elf64_qemunote(WriteCoreDumpFunction f, CPUState *cpu,
                             void *opaque)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (!cc->sysemu_ops->write_elf64_qemunote) {
        return 0;
    }
    return (*cc->sysemu_ops->write_elf64_qemunote)(f, cpu, opaque);
}

int cpu_write_elf64_note(WriteCoreDumpFunction f, CPUState *cpu,
                         int cpuid, void *opaque)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (!cc->sysemu_ops->write_elf64_note) {
        return -1;
    }
    return (*cc->sysemu_ops->write_elf64_note)(f, cpu, cpuid, opaque);
}

bool cpu_virtio_is_big_endian(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->sysemu_ops->virtio_is_big_endian) {
        return cc->sysemu_ops->virtio_is_big_endian(cpu);
    }
    return target_words_bigendian();
}

GuestPanicInformation *cpu_get_crash_info(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    GuestPanicInformation *res = NULL;

    if (cc->sysemu_ops->get_crash_info) {
        res = cc->sysemu_ops->get_crash_info(cpu);
    }
    return res;
}

/**
 * for_each_pte_recursive - recursive helper function
 *
 * @cs - CPU state
 * @fn(cs, data, pte, vaddr, height) - User-provided function to call on each
 *                                     pte.
 *   * @cs - pass through cs
 *   * @data - user-provided, opaque pointer
 *   * @pte - current pte
 *   * @height - height in the tree of pte
 *   * @layout- The layout of the radix tree
 * @data - user-provided, opaque pointer, passed to fn()
 * @visit_interior_nodes - if true, call fn() on page table entries in
 *                         interior nodes.  If false, only call fn() on page
 *                         table entries in leaves.
 * @visit_not_present - if true, call fn() on entries that are not present.
 *                         if false, visit only present entries.
 * @visit_malformed - if true, call fn() on entries that are malformed (e.g.,
 *                         bad reserved bits.  Even if true, will not follow
 *                         a child pointer to another node.
 * @node - The physical address of the current page table radix tree node
 * @vaddr_in - The virtual address bits translated in walking the page
 *          table to node
 * @height - The height of the node in the radix tree
 * @layout- The layout of the radix tree
 * @read_only - If true, do not update softmmu state (if applicable)
 *              to reflect the page table walk.
 * @mmu_idx - Which level of the mmu we are interested in:
 *            0 == user mode, 1 == nested page table
 *            Note that MMU_*_IDX macros are not consistent across
 *            architectures.
 *
 * height starts at the max and counts down.
 * In a 4 level x86 page table, pml4e is level 4, pdpe is level 3,
 *  pde is level 2, and pte is level 1
 *
 * Returns true on success, false on error.
 */
static bool
for_each_pte_recursive(CPUState *cs, qemu_page_walker_for_each fn, void *data,
                       bool visit_interior_nodes, bool visit_not_present,
                       bool visit_malformed, hwaddr node, vaddr vaddr_in,
                       int height, const PageTableLayout *layout,
                       bool read_only, int mmu_idx)
{
    int i;
    CPUClass *cc = cs->cc;
    const struct SysemuCPUOps *ops = cc->sysemu_ops;

    assert(height > 0);
    int ptes_per_node = layout->entries_per_node[height];

    for (i = 0; i < ptes_per_node; i++) {
        DecodedPTE pt_entry;

        if(!ops->get_pte(cs, node, i, height, &pt_entry, vaddr_in, read_only,
                         mmu_idx)) {
            /* Fail if we can't read the PTE */
            return false;
        }

        if (!pt_entry.reserved_bits_ok && !visit_malformed) {
            continue;
        }

        if (pt_entry.present || visit_not_present) {

            if (!pt_entry.present || pt_entry.leaf) {
                if (fn(cs, data, &pt_entry, height, i, mmu_idx, layout)) {
                    /* Error */
                    return false;
                }
            } else { /* Non-leaf */
                if (visit_interior_nodes) {
                    if (fn(cs, data, &pt_entry, height, i, mmu_idx, layout)) {
                        /* Error */
                        return false;
                    }
                }
                assert(height > 1);

                if (pt_entry.reserved_bits_ok) {

                    if (!for_each_pte_recursive(cs, fn, data,
                                                visit_interior_nodes,
                                                visit_not_present,
                                                visit_malformed,
                                                pt_entry.child,
                                                pt_entry.bits_translated,
                                                height - 1, layout, read_only,
                                                mmu_idx)) {
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

/**
 * for_each_pte - iterate over a page table, and
 *                call fn on each entry
 *
 * @cs - CPU state
 * @fn(cs, data, pte, height, offset, layout) - User-provided function to call
 *                                              on each pte.
 *   * @cs - pass through cs
 *   * @data - user-provided, opaque pointer
 *   * @pte - current pte, decoded
 *   * @height - height in the tree of pte
 *   * @offset - offset within the page tabe node
 *   * @layout- The layout of the radix tree
 * @data - opaque pointer; passed through to fn
 * @visit_interior_nodes - if true, call fn() on interior entries in
 *                         page table; if false, visit only leaf entries.
 * @visit_not_present - if true, call fn() on entries that are not present.
 *                         if false, visit only present entries.
 * @visit_malformed - if true, call fn() on entries that are malformed (e.g.,
 *                         bad reserved bits.  Even if true, will not follow
 *                         a child pointer to another node.
 * @read_only - If true, do not update softmmu state (if applicable) to reflect
 *              the page table walk.
 * @mmu_idx - Which level of the mmu we are interested in:
 *            0 == user mode, 1 == nested page table
 *            Note that MMU_*_IDX macros are not consistent across
 *            architectures.
 *
 * Returns true on success, false on error.
 *
 */
bool for_each_pte(CPUState *cs, qemu_page_walker_for_each fn, void *data,
                  bool visit_interior_nodes, bool visit_not_present,
                  bool visit_malformed, bool read_only, int mmu_idx)
{
    vaddr vaddr = 0;
    hwaddr root;
    CPUClass *cc = cs->cc;
    const PageTableLayout *layout;

    if (!cpu_paging_enabled(cs, mmu_idx)) {
        /* paging is disabled */
        return true;
    }

    if (!cc->sysemu_ops->page_table_root) {
        return false;
    }
    assert(cc->sysemu_ops->get_pte);

    root = cc->sysemu_ops->page_table_root(cs, &layout, mmu_idx);

    assert(layout->height > 1);

    /* Recursively call a helper to walk the page table */
    return for_each_pte_recursive(cs, fn, data, visit_interior_nodes,
                                  visit_not_present, visit_malformed, root,
                                  vaddr, layout->height, layout, read_only,
                                  mmu_idx);

}
