/*
 * QEMU monitor
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
#include "cpu.h"
#include "monitor/monitor.h"
#include "monitor/hmp-target.h"
#include "monitor/hmp.h"
#include "qapi/qmp/qdict.h"
#include "sysemu/hw_accel.h"
#include "sysemu/kvm.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc-target.h"
#include "qapi/qapi-commands-misc.h"

/* Perform linear address sign extension */
static hwaddr addr_canonical(CPUArchState *env, hwaddr addr)
{
#ifdef TARGET_X86_64
    if (env->cr[4] & CR4_LA57_MASK) {
        if (addr & (1ULL << 56)) {
            addr |= (hwaddr)-(1LL << 57);
        }
    } else {
        if (addr & (1ULL << 47)) {
            addr |= (hwaddr)-(1LL << 48);
        }
    }
#endif
    return addr;
}

static void print_pte(Monitor *mon, CPUArchState *env, hwaddr addr,
                      hwaddr pte, hwaddr mask)
{
    addr = addr_canonical(env, addr);

    monitor_printf(mon, HWADDR_FMT_plx ": " HWADDR_FMT_plx
                   " %c%c%c%c%c%c%c%c%c\n",
                   addr,
                   pte & mask,
                   pte & PG_NX_MASK ? 'X' : '-',
                   pte & PG_GLOBAL_MASK ? 'G' : '-',
                   pte & PG_PSE_MASK ? 'P' : '-',
                   pte & PG_DIRTY_MASK ? 'D' : '-',
                   pte & PG_ACCESSED_MASK ? 'A' : '-',
                   pte & PG_PCD_MASK ? 'C' : '-',
                   pte & PG_PWT_MASK ? 'T' : '-',
                   pte & PG_USER_MASK ? 'U' : '-',
                   pte & PG_RW_MASK ? 'W' : '-');
}

struct tlb_print_state {
    Monitor *mon;
    CPUArchState *env;
};

static
int mem_print_tlb(CPUState *cs, void *data, PTE_t *pte,
                  target_ulong vaddr, int height)
{
    struct tlb_print_state *state = (struct tlb_print_state *) data;
    bool pae_enabled = state->env->cr[4] & CR4_PAE_MASK;
#ifdef TARGET_X86_64
    bool long_mode_enabled = state->env->hflags & HF_LMA_MASK;
#endif
    hwaddr mask = 0;
    switch (height) {
#ifdef TARGET_X86_64
    case 5:
        assert(state->env->cr[4] & CR4_LA57_MASK);
        g_assert_not_reached();
    case 4:
        assert(long_mode_enabled);
        g_assert_not_reached();
#endif
    case 3:
        assert(pae_enabled);
#ifdef TARGET_X86_64
        if (long_mode_enabled) {
            mask = 0x3ffffc0000000ULL;
        } else
#endif
        {
            mask = ~((hwaddr)(1 << 20) - 1);
        }
        break;
    case 2:
        mask = 0x3ffffffe00000ULL;
        break;
    case 1:
        mask = 0x3fffffffff000ULL;
        break;
    default:
            g_assert_not_reached();
    }

    print_pte(state->mon, state->env, vaddr, pte->pte64_t, mask);
    return 0;
}

void hmp_info_tlb(Monitor *mon, const QDict *qdict)
{
    CPUState *cs;
    CPUArchState *env;
    struct tlb_print_state state;
    state.mon = mon;

    env = mon_get_cpu_env(mon);
    if (!env) {
        monitor_printf(mon, "No CPU available\n");
        return;
    }
    state.env = env;

    cs = mon_get_cpu(mon);
    if (!cs) {
        monitor_printf(mon, "Unable to get CPUState.  Internal error\n");
        return;
    }

    if (!(env->cr[0] & CR0_PG_MASK)) {
        monitor_printf(mon, "PG disabled\n");
        return;
    }

    /**
     * 'info tlb' visits only leaf PTEs marked present.
     * It does not check other protection bits.
     */
    for_each_pte(cs, &mem_print_tlb, &state, false, false);
}

static
void mem_print(Monitor *mon, CPUArchState *env,
                      hwaddr *pstart, int *plast_prot,
                      hwaddr end, int prot)
{
    int prot1;
    prot1 = *plast_prot;
    if (prot != prot1) {
        if (*pstart != -1) {
            monitor_printf(mon, HWADDR_FMT_plx "-" HWADDR_FMT_plx " "
                           HWADDR_FMT_plx " %c%c%c\n",
                           addr_canonical(env, *pstart),
                           addr_canonical(env, end),
                           addr_canonical(env, end - *pstart),
                           prot1 & PG_USER_MASK ? 'u' : '-',
                           'r',
                           prot1 & PG_RW_MASK ? 'w' : '-');
        }
        if (prot != 0)
            *pstart = end;
        else
            *pstart = -1;
        *plast_prot = prot;
    }
}

struct mem_print_state {
    Monitor *mon;
    CPUArchState *env;
    hwaddr pstart; /* Starting virtual address of last pte */
    int last_prot;
    int height;
    int prot[5]; /* Maximum x86 height */
};

static
int mem_print_pte(CPUState *cs, void *data, PTE_t *pte,
                  target_ulong vaddr, int height)
{
    struct mem_print_state *state = (struct mem_print_state *) data;

    /* If this is the very first call, save the height of the tree */
    if (state->height == -1) {
        state->height = height;
    }

    int prot = 0;
    bool present = mmu_pte_present(cs, pte);
    if (present) {
        /* Prot of current pte */
        prot = pte->pte64_t & (PG_USER_MASK | PG_RW_MASK |
                               PG_PRESENT_MASK);
        /* Save the protection bits for later use */
        state->prot[height] = prot;

        for (int i = height + 1; i <= state->height; i++) {
            prot &= state->prot[i];
        }
    }

    if ((!present) || mmu_pte_leaf(cs, height, pte)) {
        mem_print(state->mon, state->env, &state->pstart,
                  &state->last_prot, vaddr, prot);
    }
    return 0;
}

void hmp_info_mem(Monitor *mon, const QDict *qdict)
{
    CPUArchState *env;
    CPUState *cs;
    struct mem_print_state state;
    int va_bits;
    state.mon = mon;
    state.pstart = -1;
    state.last_prot = 0;
    state.height = -1;

    env = mon_get_cpu_env(mon);
    if (!env) {
        monitor_printf(mon, "No CPU available\n");
        return;
    }
    state.env = env;

    cs = mon_get_cpu(mon);
    if (!cs) {
        monitor_printf(mon, "Unable to get CPUState.  Internal error\n");
        return;
    }

    if (!(env->cr[0] & CR0_PG_MASK)) {
        monitor_printf(mon, "PG disabled\n");
        return;
    }

    /**
     * We must visit not-present entries and interior entries
     * to update prot
     */
    for_each_pte(cs, &mem_print_pte, &state, true, true);
    if (env->cr[4] & CR4_PAE_MASK) {
#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            if (env->cr[4] & CR4_LA57_MASK) {
                va_bits = 57;
            } else {
                va_bits = 48;
            }
        } else
#endif
        {
            va_bits = 32;
        }
    } else {
        va_bits = 32;
    }

    /* Flush last range */
    mem_print(mon, env, &state.pstart, &state.last_prot,
              (hwaddr)1 << va_bits, 0);
}

void hmp_mce(Monitor *mon, const QDict *qdict)
{
    X86CPU *cpu;
    CPUState *cs;
    int cpu_index = qdict_get_int(qdict, "cpu_index");
    int bank = qdict_get_int(qdict, "bank");
    uint64_t status = qdict_get_int(qdict, "status");
    uint64_t mcg_status = qdict_get_int(qdict, "mcg_status");
    uint64_t addr = qdict_get_int(qdict, "addr");
    uint64_t misc = qdict_get_int(qdict, "misc");
    int flags = MCE_INJECT_UNCOND_AO;

    if (qdict_get_try_bool(qdict, "broadcast", false)) {
        flags |= MCE_INJECT_BROADCAST;
    }
    cs = qemu_get_cpu(cpu_index);
    if (cs != NULL) {
        cpu = X86_CPU(cs);
        cpu_x86_inject_mce(mon, cpu, bank, status, mcg_status, addr, misc,
                           flags);
    }
}

static target_long monitor_get_pc(Monitor *mon, const struct MonitorDef *md,
                                  int val)
{
    CPUArchState *env = mon_get_cpu_env(mon);
    return env->eip + env->segs[R_CS].base;
}

const MonitorDef monitor_defs[] = {
#define SEG(name, seg) \
    { name, offsetof(CPUX86State, segs[seg].selector), NULL, MD_I32 },\
    { name ".base", offsetof(CPUX86State, segs[seg].base) },\
    { name ".limit", offsetof(CPUX86State, segs[seg].limit), NULL, MD_I32 },

    { "eax", offsetof(CPUX86State, regs[0]) },
    { "ecx", offsetof(CPUX86State, regs[1]) },
    { "edx", offsetof(CPUX86State, regs[2]) },
    { "ebx", offsetof(CPUX86State, regs[3]) },
    { "esp|sp", offsetof(CPUX86State, regs[4]) },
    { "ebp|fp", offsetof(CPUX86State, regs[5]) },
    { "esi", offsetof(CPUX86State, regs[6]) },
    { "edi", offsetof(CPUX86State, regs[7]) },
#ifdef TARGET_X86_64
    { "r8", offsetof(CPUX86State, regs[8]) },
    { "r9", offsetof(CPUX86State, regs[9]) },
    { "r10", offsetof(CPUX86State, regs[10]) },
    { "r11", offsetof(CPUX86State, regs[11]) },
    { "r12", offsetof(CPUX86State, regs[12]) },
    { "r13", offsetof(CPUX86State, regs[13]) },
    { "r14", offsetof(CPUX86State, regs[14]) },
    { "r15", offsetof(CPUX86State, regs[15]) },
#endif
    { "eflags", offsetof(CPUX86State, eflags) },
    { "eip", offsetof(CPUX86State, eip) },
    SEG("cs", R_CS)
    SEG("ds", R_DS)
    SEG("es", R_ES)
    SEG("ss", R_SS)
    SEG("fs", R_FS)
    SEG("gs", R_GS)
    { "pc", 0, monitor_get_pc, },
    { NULL },
};

const MonitorDef *target_monitor_defs(void)
{
    return monitor_defs;
}

void hmp_info_local_apic(Monitor *mon, const QDict *qdict)
{
    CPUState *cs;

    if (qdict_haskey(qdict, "apic-id")) {
        int id = qdict_get_try_int(qdict, "apic-id", 0);

        cs = cpu_by_arch_id(id);
        if (cs) {
            cpu_synchronize_state(cs);
        }
    } else {
        cs = mon_get_cpu(mon);
    }


    if (!cs) {
        monitor_printf(mon, "No CPU available\n");
        return;
    }
    x86_cpu_dump_local_apic_state(cs, CPU_DUMP_FPU);
}
