/*
 *  x86 exception helpers - sysemu code
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "exec/page-protection.h"
#include "tcg/helper-tcg.h"

typedef struct TranslateParams {
    target_ulong addr;
    target_ulong cr3;
    int pg_mode;
    int mmu_idx;
    int ptw_idx;
    MMUAccessType access_type;
} TranslateParams;

typedef struct TranslateResult {
    hwaddr paddr;
    int prot;
    uint64_t page_size;
} TranslateResult;

static inline uint32_t ptw_ldl(const PTETranslate *in, uint64_t ra)
{
    if (likely(in->haddr)) {
        return ldl_p(in->haddr);
    }
    return cpu_ldl_mmuidx_ra(in->env, in->gaddr, in->ptw_idx, ra);
}

static inline uint64_t ptw_ldq(const PTETranslate *in, uint64_t ra)
{
    if (likely(in->haddr)) {
        return ldq_p(in->haddr);
    }
    return cpu_ldq_mmuidx_ra(in->env, in->gaddr, in->ptw_idx, ra);
}

/*
 * Note that we can use a 32-bit cmpxchg for all page table entries,
 * even 64-bit ones, because PG_PRESENT_MASK, PG_ACCESSED_MASK and
 * PG_DIRTY_MASK are all in the low 32 bits.
 */
bool ptw_setl_slow(const PTETranslate *in, uint32_t old, uint32_t new)
{
    uint32_t cmp;

    /* Does x86 really perform a rmw cycle on mmio for ptw? */
    start_exclusive();
    cmp = cpu_ldl_mmuidx_ra(in->env, in->gaddr, in->ptw_idx, 0);
    if (cmp == old) {
        cpu_stl_mmuidx_ra(in->env, in->gaddr, new, in->ptw_idx, 0);
    }
    end_exclusive();
    return cmp == old;
}

static bool mmu_translate(CPUX86State *env, const TranslateParams *in,
                          TranslateResult *out, TranslateFault *err,
                          uint64_t ra)
{
    const target_ulong addr = in->addr;
    hwaddr paddr;
    CPUState *cs = env_cpu(env);
    bool dirty = false;

    bool ok = x86_ptw_translate(cs, addr, &paddr, false,
                                in->ptw_idx == MMU_NESTED_IDX ? 1 : 0,
                                is_mmu_index_user(in->mmu_idx), in->access_type,
                                &out->page_size,
                                &err->error_code, (hwaddr *) &err->cr2, &err->stage2, &out->prot, &dirty);
    if (!ok) {

        err->exception_index = EXCP0E_PAGE;
        return false;
    }

    /*
     * Only set write access if already dirty...
     * otherwise wait for dirty access.
     */
    if (in->access_type != MMU_DATA_STORE && !dirty) {
        out->prot &= ~PAGE_WRITE;
    }

    out->paddr = paddr & x86_get_a20_mask(env);

    return true;
}

static G_NORETURN void raise_stage2(CPUX86State *env, TranslateFault *err,
                                    uintptr_t retaddr)
{
    uint64_t exit_info_1 = err->error_code;

    switch (err->stage2) {
    case S2_GPT:
        exit_info_1 |= SVM_NPTEXIT_GPT;
        break;
    case S2_GPA:
        exit_info_1 |= SVM_NPTEXIT_GPA;
        break;
    default:
        g_assert_not_reached();
    }

    x86_stq_phys(env_cpu(env),
                 env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                 err->cr2);
    cpu_vmexit(env, SVM_EXIT_NPF, exit_info_1, retaddr);
}

static
bool x86_cpu_get_physical_address(CPUX86State *env, vaddr addr,
                                  MMUAccessType access_type, int mmu_idx,
                                  TranslateResult *out,
                                  TranslateFault *err, uint64_t ra)
{
    TranslateParams in;
    bool use_stage2 = env->hflags2 & HF2_NPT_MASK;

    in.addr = addr;
    in.access_type = access_type;

    switch (mmu_idx) {
    case MMU_PHYS_IDX:
        break;

    case MMU_NESTED_IDX:
        if (likely(use_stage2)) {
            in.cr3 = env->nested_cr3;
            in.pg_mode = env->nested_pg_mode;
            in.mmu_idx =
                env->nested_pg_mode & PG_MODE_LMA ?
                MMU_USER64_IDX : MMU_USER32_IDX;
            in.ptw_idx = MMU_PHYS_IDX;

            if (!mmu_translate(env, &in, out, err, ra)) {
                err->stage2 = S2_GPA;
                return false;
            }
            return true;
        }
        break;

    default:
        if (is_mmu_index_32(mmu_idx)) {
            addr = (uint32_t)addr;
        }

        if (likely(env->cr[0] & CR0_PG_MASK)) {
            in.cr3 = env->cr[3];
            in.mmu_idx = mmu_idx;
            in.ptw_idx = use_stage2 ? MMU_NESTED_IDX : MMU_PHYS_IDX;
            in.pg_mode = get_pg_mode(env);

            if (in.pg_mode & PG_MODE_LMA) {
                /* test virtual address sign extension */
                int shift = in.pg_mode & PG_MODE_LA57 ? 56 : 47;
                int64_t sext = (int64_t)addr >> shift;
                if (sext != 0 && sext != -1) {
                    *err = (TranslateFault){
                        .exception_index = EXCP0D_GPF,
                        .cr2 = addr,
                    };
                    return false;
                }
            }
            return mmu_translate(env, &in, out, err, ra);
        }
        break;
    }

    /* No translation needed. */
    out->paddr = addr & x86_get_a20_mask(env);
    out->prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
    out->page_size = TARGET_PAGE_SIZE;
    return true;
}

bool x86_cpu_tlb_fill(CPUState *cs, vaddr addr, int size,
                      MMUAccessType access_type, int mmu_idx,
                      bool probe, uintptr_t retaddr)
{
    CPUX86State *env = cpu_env(cs);
    TranslateResult out;
    TranslateFault err;

    if (x86_cpu_get_physical_address(env, addr, access_type, mmu_idx, &out,
                                     &err, retaddr)) {
        /*
         * Even if 4MB pages, we map only one 4KB page in the cache to
         * avoid filling it too fast.
         */
        assert(out.prot & (1 << access_type));
        tlb_set_page_with_attrs(cs, addr & TARGET_PAGE_MASK,
                                out.paddr & TARGET_PAGE_MASK,
                                cpu_get_mem_attrs(env),
                                out.prot, mmu_idx, out.page_size);
        return true;
    }

    if (probe) {
        /* This will be used if recursing for stage2 translation. */
        env->error_code = err.error_code;
        return false;
    }

    if (err.stage2 != S2_NONE) {
        raise_stage2(env, &err, retaddr);
    }

    if (env->intercept_exceptions & (1 << err.exception_index)) {
        /* cr2 is not modified in case of exceptions */
        x86_stq_phys(cs, env->vm_vmcb +
                     offsetof(struct vmcb, control.exit_info_2),
                     err.cr2);
    } else {
        env->cr[2] = err.cr2;
    }
    raise_exception_err_ra(env, err.exception_index, err.error_code, retaddr);
}

G_NORETURN void x86_cpu_do_unaligned_access(CPUState *cs, vaddr vaddr,
                                            MMUAccessType access_type,
                                            int mmu_idx, uintptr_t retaddr)
{
    X86CPU *cpu = X86_CPU(cs);
    handle_unaligned_access(&cpu->env, vaddr, access_type, retaddr);
}
