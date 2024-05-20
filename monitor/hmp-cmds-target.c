/*
 * Miscellaneous target-dependent HMP commands
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "disas/disas.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "monitor/hmp-target.h"
#include "monitor/monitor-internal.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "sysemu/hw_accel.h"
#include "hw/core/sysemu-cpu-ops.h"

/* Set the current CPU defined by the user. Callers must hold BQL. */
int monitor_set_cpu(Monitor *mon, int cpu_index)
{
    CPUState *cpu;

    cpu = qemu_get_cpu(cpu_index);
    if (cpu == NULL) {
        return -1;
    }
    g_free(mon->mon_cpu_path);
    mon->mon_cpu_path = object_get_canonical_path(OBJECT(cpu));
    return 0;
}

/* Callers must hold BQL. */
static CPUState *mon_get_cpu_sync(Monitor *mon, bool synchronize)
{
    CPUState *cpu = NULL;

    if (mon->mon_cpu_path) {
        cpu = (CPUState *) object_resolve_path_type(mon->mon_cpu_path,
                                                    TYPE_CPU, NULL);
        if (!cpu) {
            g_free(mon->mon_cpu_path);
            mon->mon_cpu_path = NULL;
        }
    }
    if (!mon->mon_cpu_path) {
        if (!first_cpu) {
            return NULL;
        }
        monitor_set_cpu(mon, first_cpu->cpu_index);
        cpu = first_cpu;
    }
    assert(cpu != NULL);
    if (synchronize) {
        cpu_synchronize_state(cpu);
    }
    return cpu;
}

CPUState *mon_get_cpu(Monitor *mon)
{
    return mon_get_cpu_sync(mon, true);
}

CPUArchState *mon_get_cpu_env(Monitor *mon)
{
    CPUState *cs = mon_get_cpu(mon);

    return cs ? cpu_env(cs) : NULL;
}

int monitor_get_cpu_index(Monitor *mon)
{
    CPUState *cs = mon_get_cpu_sync(mon, false);

    return cs ? cs->cpu_index : UNASSIGNED_CPU_INDEX;
}

void hmp_info_registers(Monitor *mon, const QDict *qdict)
{
    bool all_cpus = qdict_get_try_bool(qdict, "cpustate_all", false);
    int vcpu = qdict_get_try_int(qdict, "vcpu", -1);
    CPUState *cs;

    if (all_cpus) {
        CPU_FOREACH(cs) {
            monitor_printf(mon, "\nCPU#%d\n", cs->cpu_index);
            cpu_dump_state(cs, NULL, CPU_DUMP_FPU);
        }
    } else {
        cs = vcpu >= 0 ? qemu_get_cpu(vcpu) : mon_get_cpu(mon);

        if (!cs) {
            if (vcpu >= 0) {
                monitor_printf(mon, "CPU#%d not available\n", vcpu);
            } else {
                monitor_printf(mon, "No CPU available\n");
            }
            return;
        }

        monitor_printf(mon, "\nCPU#%d\n", cs->cpu_index);
        cpu_dump_state(cs, NULL, CPU_DUMP_FPU);
    }
}

/* Assume only called on present entries */
static
int compressing_iterator(CPUState *cs, void *data, PTE_t *pte,
                         vaddr vaddr_in, int height, int offset)
{
    CPUClass *cc = CPU_GET_CLASS(cs);
    struct mem_print_state *state = (struct mem_print_state *) data;
    hwaddr paddr = cc->sysemu_ops->pte_child(cs, pte, height);
    target_ulong size = cc->sysemu_ops->pte_leaf_page_size(cs, height);
    bool start_new_run = false, flush = false;
    bool is_leaf = cc->sysemu_ops->pte_leaf(cs, height, pte);

    int entries_per_node = cc->sysemu_ops->page_table_entries_per_node(cs,
                                                                       height);

    /* Prot of current pte */
    int prot = cc->sysemu_ops->pte_flags(pte->pte64_t);

    /* If there is a prior run, first try to extend it. */
    if (state->start_height != 0) {

        /*
         * If we aren't flushing interior nodes, raise the start height.
         * We don't need to detect non-compressible interior nodes.
         */
        if ((!state->flush_interior) && state->start_height < height) {
            state->start_height = height;
            state->vstart[height] = vaddr_in;
            state->vend[height] = vaddr_in;
            state->ent[height] = pte->pte64_t;
            if (offset == 0) {
                state->last_offset[height] = entries_per_node - 1;
            } else {
                state->last_offset[height] = offset - 1;
            }
        }

        /* Detect when we are walking down the "left edge" of a range */
        if (state->vstart[height] == -1
            && (height + 1) <= state->start_height
            && state->vstart[height + 1] == vaddr_in) {

            state->vstart[height] = vaddr_in;
            state->vend[height] = vaddr_in;
            state->ent[height] = pte->pte64_t;
            state->offset[height] = offset;
            state->last_offset[height] = offset;

            if (is_leaf) {
                state->pstart = paddr;
                state->pend = paddr;
            }

            /* Detect contiguous entries at same level */
        } else if ((state->vstart[height] != -1)
                   && (state->start_height >= height)
                   && cc->sysemu_ops->pte_flags(state->ent[height]) == prot
                   && (((state->last_offset[height] + 1) % entries_per_node)
                       == offset)
                   && ((!is_leaf)
                       || (!state->require_physical_contiguity)
                       || (state->pend + size == paddr))) {


            /*
             * If there are entries at the levels below, make sure we
             * completed them.  We only compress interior nodes
             * without holes in the mappings.
             */
            if (height != 1) {
                for (int i = height - 1; i >= 1; i--) {
                    int entries = cc->sysemu_ops->page_table_entries_per_node(
                        cs, i);

                    /* Stop if we hit large pages before level 1 */
                    if (state->vstart[i] == -1) {
                        break;
                    }

                    if ((state->last_offset[i] + 1) != entries) {
                        flush = true;
                        start_new_run = true;
                        break;
                    }
                }
            }


            if (!flush) {

                /* We can compress these entries */
                state->ent[height] = pte->pte64_t;
                state->vend[height] = vaddr_in;
                state->last_offset[height] = offset;

                /* Only update the physical range on leaves */
                if (is_leaf) {
                    state->pend = paddr;
                }
            }
            /* Let PTEs accumulate... */
        } else {
            flush = true;
        }

        if (flush) {
            /*
             * We hit dicontiguous permissions or pages.
             * Print the old entries, then start accumulating again
             *
             * Some clients only want the flusher called on a leaf.
             * Check that too.
             *
             * We can infer whether the accumulated range includes a
             * leaf based on whether pstart is -1.
             */
            if (state->flush_interior || (state->pstart != -1)) {
                if (state->flusher(cs, state)) {
                    start_new_run = true;
                }
            } else {
                start_new_run = true;
            }
        }
    } else {
        start_new_run = true;
    }

    if (start_new_run) {
        /* start a new run with this PTE */
        for (int i = state->start_height; i > 0; i--) {
            if (state->vstart[i] != -1) {
                state->ent[i] = 0;
                state->last_offset[i] = 0;
                state->vstart[i] = -1;
            }
        }
        state->pstart = -1;
        state->vstart[height] = vaddr_in;
        state->vend[height] = vaddr_in;
        state->ent[height] = pte->pte64_t;
        state->offset[height] = offset;
        state->last_offset[height] = offset;
        if (is_leaf) {
            state->pstart = paddr;
            state->pend = paddr;
        }
        state->start_height = height;
    }

    return 0;
}

void hmp_info_pg(Monitor *mon, const QDict *qdict)
{
    struct mem_print_state state;

    CPUState *cs = mon_get_cpu(mon);
    if (!cs) {
        monitor_printf(mon, "Unable to get CPUState.  Internal error\n");
        return;
    }

    CPUClass *cc = CPU_GET_CLASS(cs);

    if ((!cc->sysemu_ops->pte_child)
        || (!cc->sysemu_ops->pte_leaf)
        || (!cc->sysemu_ops->pte_leaf_page_size)
        || (!cc->sysemu_ops->page_table_entries_per_node)
        || (!cc->sysemu_ops->pte_flags)
        || (!cc->sysemu_ops->mon_init_page_table_iterator)
        || (!cc->sysemu_ops->mon_info_pg_print_header)
        || (!cc->sysemu_ops->mon_flush_page_print_state)) {
        monitor_printf(mon, "Info pg unsupported on this ISA\n");
        return;
    }

    if (!cc->sysemu_ops->mon_init_page_table_iterator(mon, &state)) {
        monitor_printf(mon, "Unable to initialize page table iterator\n");
        return;
    }

    state.flush_interior = true;
    state.require_physical_contiguity = true;
    state.flusher = cc->sysemu_ops->mon_flush_page_print_state;

    cc->sysemu_ops->mon_info_pg_print_header(mon, &state);

    /*
     * We must visit interior entries to get the hierarchy, but
     * can skip not present mappings
     */
    for_each_pte(cs, &compressing_iterator, &state, true, false);

    /* Print last entry, if one present */
    cc->sysemu_ops->mon_flush_page_print_state(cs, &state);
}

static void memory_dump(Monitor *mon, int count, int format, int wsize,
                        hwaddr addr, int is_physical)
{
    int l, line_size, i, max_digits, len;
    uint8_t buf[16];
    uint64_t v;
    CPUState *cs = mon_get_cpu(mon);

    if (!cs && (format == 'i' || !is_physical)) {
        monitor_printf(mon, "Can not dump without CPU\n");
        return;
    }

    if (format == 'i') {
        monitor_disas(mon, cs, addr, count, is_physical);
        return;
    }

    len = wsize * count;
    if (wsize == 1) {
        line_size = 8;
    } else {
        line_size = 16;
    }
    max_digits = 0;

    switch(format) {
    case 'o':
        max_digits = DIV_ROUND_UP(wsize * 8, 3);
        break;
    default:
    case 'x':
        max_digits = (wsize * 8) / 4;
        break;
    case 'u':
    case 'd':
        max_digits = DIV_ROUND_UP(wsize * 8 * 10, 33);
        break;
    case 'c':
        wsize = 1;
        break;
    }

    while (len > 0) {
        if (is_physical) {
            monitor_printf(mon, HWADDR_FMT_plx ":", addr);
        } else {
            monitor_printf(mon, TARGET_FMT_lx ":", (target_ulong)addr);
        }
        l = len;
        if (l > line_size)
            l = line_size;
        if (is_physical) {
            AddressSpace *as = cs ? cs->as : &address_space_memory;
            MemTxResult r = address_space_read(as, addr,
                                               MEMTXATTRS_UNSPECIFIED, buf, l);
            if (r != MEMTX_OK) {
                monitor_printf(mon, " Cannot access memory\n");
                break;
            }
        } else {
            if (cpu_memory_rw_debug(cs, addr, buf, l, 0) < 0) {
                monitor_printf(mon, " Cannot access memory\n");
                break;
            }
        }
        i = 0;
        while (i < l) {
            switch(wsize) {
            default:
            case 1:
                v = ldub_p(buf + i);
                break;
            case 2:
                v = lduw_p(buf + i);
                break;
            case 4:
                v = (uint32_t)ldl_p(buf + i);
                break;
            case 8:
                v = ldq_p(buf + i);
                break;
            }
            monitor_printf(mon, " ");
            switch(format) {
            case 'o':
                monitor_printf(mon, "%#*" PRIo64, max_digits, v);
                break;
            case 'x':
                monitor_printf(mon, "0x%0*" PRIx64, max_digits, v);
                break;
            case 'u':
                monitor_printf(mon, "%*" PRIu64, max_digits, v);
                break;
            case 'd':
                monitor_printf(mon, "%*" PRId64, max_digits, v);
                break;
            case 'c':
                monitor_printc(mon, v);
                break;
            }
            i += wsize;
        }
        monitor_printf(mon, "\n");
        addr += l;
        len -= l;
    }
}

void hmp_memory_dump(Monitor *mon, const QDict *qdict)
{
    int count = qdict_get_int(qdict, "count");
    int format = qdict_get_int(qdict, "format");
    int size = qdict_get_int(qdict, "size");
    target_long addr = qdict_get_int(qdict, "addr");

    memory_dump(mon, count, format, size, addr, 0);
}

void hmp_physical_memory_dump(Monitor *mon, const QDict *qdict)
{
    int count = qdict_get_int(qdict, "count");
    int format = qdict_get_int(qdict, "format");
    int size = qdict_get_int(qdict, "size");
    hwaddr addr = qdict_get_int(qdict, "addr");

    memory_dump(mon, count, format, size, addr, 1);
}

void *gpa2hva(MemoryRegion **p_mr, hwaddr addr, uint64_t size, Error **errp)
{
    Int128 gpa_region_size;
    MemoryRegionSection mrs = memory_region_find(get_system_memory(),
                                                 addr, size);

    if (!mrs.mr) {
        error_setg(errp, "No memory is mapped at address 0x%" HWADDR_PRIx, addr);
        return NULL;
    }

    if (!memory_region_is_ram(mrs.mr) && !memory_region_is_romd(mrs.mr)) {
        error_setg(errp, "Memory at address 0x%" HWADDR_PRIx " is not RAM", addr);
        memory_region_unref(mrs.mr);
        return NULL;
    }

    gpa_region_size = int128_make64(size);
    if (int128_lt(mrs.size, gpa_region_size)) {
        error_setg(errp, "Size of memory region at 0x%" HWADDR_PRIx
                   " exceeded.", addr);
        memory_region_unref(mrs.mr);
        return NULL;
    }

    *p_mr = mrs.mr;
    return qemu_map_ram_ptr(mrs.mr->ram_block, mrs.offset_within_region);
}

void hmp_gpa2hva(Monitor *mon, const QDict *qdict)
{
    hwaddr addr = qdict_get_int(qdict, "addr");
    Error *local_err = NULL;
    MemoryRegion *mr = NULL;
    void *ptr;

    ptr = gpa2hva(&mr, addr, 1, &local_err);
    if (local_err) {
        error_report_err(local_err);
        return;
    }

    monitor_printf(mon, "Host virtual address for 0x%" HWADDR_PRIx
                   " (%s) is %p\n",
                   addr, mr->name, ptr);

    memory_region_unref(mr);
}

void hmp_gva2gpa(Monitor *mon, const QDict *qdict)
{
    target_ulong addr = qdict_get_int(qdict, "addr");
    MemTxAttrs attrs;
    CPUState *cs = mon_get_cpu(mon);
    hwaddr gpa;

    if (!cs) {
        monitor_printf(mon, "No cpu\n");
        return;
    }

    gpa  = cpu_get_phys_page_attrs_debug(cs, addr & TARGET_PAGE_MASK, &attrs);
    if (gpa == -1) {
        monitor_printf(mon, "Unmapped\n");
    } else {
        monitor_printf(mon, "gpa: %#" HWADDR_PRIx "\n",
                       gpa + (addr & ~TARGET_PAGE_MASK));
    }
}

#ifdef CONFIG_LINUX
static uint64_t vtop(void *ptr, Error **errp)
{
    uint64_t pinfo;
    uint64_t ret = -1;
    uintptr_t addr = (uintptr_t) ptr;
    uintptr_t pagesize = qemu_real_host_page_size();
    off_t offset = addr / pagesize * sizeof(pinfo);
    int fd;

    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1) {
        error_setg_errno(errp, errno, "Cannot open /proc/self/pagemap");
        return -1;
    }

    /* Force copy-on-write if necessary.  */
    qatomic_add((uint8_t *)ptr, 0);

    if (pread(fd, &pinfo, sizeof(pinfo), offset) != sizeof(pinfo)) {
        error_setg_errno(errp, errno, "Cannot read pagemap");
        goto out;
    }
    if ((pinfo & (1ull << 63)) == 0) {
        error_setg(errp, "Page not present");
        goto out;
    }
    ret = ((pinfo & 0x007fffffffffffffull) * pagesize) | (addr & (pagesize - 1));

out:
    close(fd);
    return ret;
}

void hmp_gpa2hpa(Monitor *mon, const QDict *qdict)
{
    hwaddr addr = qdict_get_int(qdict, "addr");
    Error *local_err = NULL;
    MemoryRegion *mr = NULL;
    void *ptr;
    uint64_t physaddr;

    ptr = gpa2hva(&mr, addr, 1, &local_err);
    if (local_err) {
        error_report_err(local_err);
        return;
    }

    physaddr = vtop(ptr, &local_err);
    if (local_err) {
        error_report_err(local_err);
    } else {
        monitor_printf(mon, "Host physical address for 0x%" HWADDR_PRIx
                       " (%s) is 0x%" PRIx64 "\n",
                       addr, mr->name, (uint64_t) physaddr);
    }

    memory_region_unref(mr);
}
#endif
