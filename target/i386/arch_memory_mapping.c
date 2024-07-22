/*
 * i386 memory mapping
 *
 * Copyright Fujitsu, Corp. 2011, 2012
 *
 * Authors:
 *     Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "sysemu/memory_mapping.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "tcg/helper-tcg.h"

/**
 ************** code hook implementations for x86 ***********
 */

/* PAE Paging or IA-32e Paging */
#define PML4_ADDR_MASK 0xffffffffff000ULL /* selects bits 51:12 */

const PageTableLayout x86_lma57_layout = { .height = 5,
    .entries_per_node = {0, 512, 512, 512, 512, 512}};

const PageTableLayout x86_lma48_layout = { .height = 4,
    .entries_per_node = {0, 512, 512, 512, 512, 0}};

const PageTableLayout x86_pae32_layout = { .height = 3,
    .entries_per_node = {0, 512, 512, 4, 0, 0}};

const PageTableLayout x86_ia32_layout = { .height = 2,
    .entries_per_node = {0, 1024, 1024, 0, 0, 0}};

/**
 * x86_page_table_root - Given a CPUState, return the physical address
 *                       of the current page table root, as well as
 *                       setting a pointer to a PageTableLayout.
 *
 * @cs - CPU state
 * @layout - a pointer to a pointer to a PageTableLayout structure,
 *           into which is written a pointer to the page table tree
 *           geometry.
 * @mmu_idx - Which level of the mmu we are interested in:
 *            0 == user mode, 1 == nested page table
 *            Note that MMU_*_IDX macros are not consistent across
 *            architectures.
 *
 * Returns a hardware address on success.  Should not fail (i.e.,
 * caller is responsible to ensure that a page table is actually
 * present, or that, with nested paging, there is a nested
 * table present).
 *
 * Do not free *layout.
 */
hwaddr
x86_page_table_root(CPUState *cs, const PageTableLayout ** layout,
                    int mmu_idx)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    /*
     * DEP 5/15/24: Some original page table walking code sets the a20
     * mask as a 32 bit integer and checks it on each level of hte
     * page table walk; some only checks it against the final result.
     * For 64 bits, I think we need to sign extend in the common case
     * it is not set (and returns -1), or we will lose bits.
     */
    hwaddr root = 0;
    int pg_mode;
    int64_t a20_mask;

    assert(cpu_paging_enabled(cs, mmu_idx));
    a20_mask = x86_get_a20_mask(env);

    switch(mmu_idx) {
    case 0:
        root = env->cr[3];
        pg_mode = get_pg_mode(env);

        if (pg_mode & PG_MODE_PAE) {
#ifdef TARGET_X86_64
            if (pg_mode & PG_MODE_LMA) {
                if (pg_mode & PG_MODE_LA57) {
                    *layout = &x86_lma57_layout;
                } else {
                    *layout = &x86_lma48_layout;
                }
                return (root & PML4_ADDR_MASK) & a20_mask;
            } else
#endif
            {
                *layout = &x86_pae32_layout;
                return (root & ~0x1f) & a20_mask;
            }
        } else {
            assert(mmu_idx != 1);
            *layout = &x86_ia32_layout;
            return (root & ~0xfff) & a20_mask;
        }
        break;
    case 1:
        assert (env->vm_state_valid);
        root = env->nested_pg_root;
        switch(env->nested_pg_height) {
        case 4:
            *layout = &x86_lma48_layout;
            break;
        case 5:
            *layout = &x86_lma57_layout;
            break;
        default:
            g_assert_not_reached();
        }
        return (root & PML4_ADDR_MASK) & a20_mask;
    default:
        g_assert_not_reached();
    }

    g_assert_not_reached();
    return 0;
}

/*
 * Given a CPU state and height, return the number of bits
 * to shift right/left in going from virtual to PTE index
 * and vice versa, the number of useful bits.
 */
static void _mmu_decode_va_parameters(CPUState *cs, int height,
                                      int *shift, int *width)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int _shift = 0;
    int _width = 0;
    bool pae_enabled = env->cr[4] & CR4_PAE_MASK;

    switch (height) {
    case 5:
        _shift = 48;
        _width = 9;
        break;
    case 4:
        _shift = 39;
        _width = 9;
        break;
    case 3:
        _shift = 30;
        _width = 9;
        break;
    case 2:
        /* 64 bit page tables shift from 30->21 bits here */
        if (pae_enabled) {
            _shift = 21;
            _width = 9;
        } else {
            /* 32 bit page tables shift from 32->22 bits */
            _shift = 22;
            _width = 10;
        }
        break;
    case 1:
        _shift = 12;
        if (pae_enabled) {
            _width = 9;
        } else {
            _width = 10;
        }

        break;
    default:
        g_assert_not_reached();
    }

    if (shift) {
        *shift = _shift;
    }

    if (width) {
        *width = _width;
    }
}

/**
 * x86_virtual_to_pte_index - Given a virtual address and height in
 *       the page table radix tree, return the index that should be
 *       used to look up the next page table entry (pte) in
 *       translating an address.
 *
 * @cs - CPU state
 * @vaddr - The virtual address to translate
 * @height - height of node within the tree (leaves are 1, not 0).
 *
 * Example: In 32-bit x86 page tables, the virtual address is split
 * into 10 bits at height 2, 10 bits at height 1, and 12 offset bits.
 * So a call with VA and height 2 would return the first 10 bits of va,
 * right shifted by 22.
 */
int x86_virtual_to_pte_index(CPUState *cs, vaddr vaddr_in, int height)
{
    int shift = 0;
    int width = 0;
    int mask = 0;

    _mmu_decode_va_parameters(cs, height, &shift, &width);

    mask = (1 << width) - 1;

    return (vaddr_in >> shift) & mask;
}

/**
 * x86_get_pte - Copy and decode the contents of the page table entry at
 *               node[i] into pt_entry.
 *
 * @cs - CPU state
 * @node - physical address of the current page table node
 * @i - index (in page table entries, not bytes) of the page table
 *      entry, within node
 * @height - height of node within the tree (leaves are 1, not 0)
 * @pt_entry - Poiter to a DecodedPTE, stores the contents of the page table entry
 * @vaddr_parent - The virtual address bits already translated in walking the
 *                 page table to node.  Optional: only used if vaddr_pte is set.
 * @debug - If true, do not update softmmu state (if applicable) to reflect
 *          the page table walk.
 * @mmu_idx - Which level of the mmu we are interested in: 0 == user
 *            mode, 1 == nested page table Note that MMU_*_IDX macros
 *            are not consistent across architectures.
 * @user_access - For non-debug accesses, is this a user or supervisor-mode
 *                access.  Used to determine faults.
 * @access_type - For non-debug accesses, what type of access is driving the
 *                lookup.  Used to determine faults.
 * @error_code - Optional integer pointer, to store error reason on failure
 * @fault_addr - Optional vaddr pointer, to store the faulting address on a
 *               recursive page walk for the pe.  Otherwise, caller is expected
 *               to determine if this pte access would fault.
 * @nested_fault - Optional pointer, to differentiate causes of nested faults.
 *                 Set to true if there is a fault recurring on a nested page
 *                 table.
 *
 * Returns true on success, false on failure.  This should only fail if a page table
 * entry cannot be read because the address of node is not a valid (guest) physical
 * address.  Otherwise, we capture errors like bad reserved flags in the DecodedPTE
 * entry and let the caller decide how to handle it.
 */
bool
x86_get_pte(CPUState *cs, hwaddr node, int i, int height, DecodedPTE *pt_entry,
            vaddr vaddr_parent, bool debug, int mmu_idx, bool user_access,
            const MMUAccessType access_type, int *error_code,
            vaddr *fault_addr, TranslateFaultStage2 *nested_fault)
{
    CPUX86State *env = cpu_env(cs);
    int32_t a20_mask = x86_get_a20_mask(env);
    hwaddr pte = 0;
    uint64_t pte_contents = 0;
    hwaddr pte_host_addr = 0;
    uint64_t unused = 0; /* We always call probe_access in non-fault mode */
    bool use_stage2 = env->hflags & HF_GUEST_MASK;
    int pte_width = 4;
    uint64_t leaf_mask = 0;
    int pg_mode = get_pg_mode(env);
    bool pae_enabled = !!(pg_mode & PG_MODE_PAE);
    bool long_mode = !!(pg_mode & PG_MODE_LMA);
#ifdef CONFIG_TCG
    void *pte_internal_pointer = NULL;
#endif

    pt_entry->reserved_bits_ok = false;

    if (env->hflags & HF_LMA_MASK) {
        /* 64 bit */
        pte_width = 8;
    }

    pte = (node + (i * pte_width)) & a20_mask;

    if (debug) {

        /* Recur on nested paging */
        if (mmu_idx == 0 && use_stage2) {

            bool ok = x86_ptw_translate(cs, pte, &pte_host_addr, debug, 1,
                                        user_access, access_type, NULL,
                                        error_code, fault_addr, NULL, NULL, NULL);
            if (!ok) {
                if (nested_fault) {
                    *nested_fault = S2_GPT;
                }
                return false;
            }
        } else {
            pte_host_addr = pte;
        }
    } else {
#ifdef CONFIG_TCG
        CPUTLBEntryFull *full;
        int flags = probe_access_full(env, pte, 0, MMU_DATA_STORE,
                                      MMU_NESTED_IDX, true,
                                      &pte_internal_pointer, &full,
                                      unused);

        if (unlikely(flags & TLB_INVALID_MASK)) {
            if (nested_fault) {
                *nested_fault = S2_GPT;
            }
            if (error_code) {
                *error_code = env->error_code;
            }
            if (fault_addr) {
                *fault_addr = pte;
            }
            return false;
        }

        pte_host_addr = full->phys_addr;
        /* probe_access_full() drops the offset bits; we need to re-add them */
        pte_host_addr += i * pte_width;
        /* But don't re-add to pte_internal_pointer, which overlaps with
         * pte_host_addr... */
#else
        /* Any non-TCG use case should be read-only */
        g_assert_not_reached();
#endif
    }
#ifdef CONFIG_TCG
    /*
     * TCG needs to set the accessed bit on the PTE; it does this in a
     * compare-and-swap loop.
     */
 reread_pte:
#endif

    /* Read the PTE contents */
    if (likely(pte_host_addr)) {
        if (long_mode) {
            pte_contents = address_space_ldq(cs->as, pte_host_addr, MEMTXATTRS_UNSPECIFIED, NULL);
        } else {
            pte_contents = address_space_ldl(cs->as, pte_host_addr, MEMTXATTRS_UNSPECIFIED, NULL);
        }
    } else {
        pte_contents = long_mode ?
            cpu_ldq_mmuidx_ra(env, pte, MMU_PHYS_IDX, unused):
            cpu_ldl_mmuidx_ra(env, pte, MMU_PHYS_IDX, unused);
    }

    /* Deserialize flag bits, different by mmu index */
    if (mmu_idx == 0 ||
        (mmu_idx == 1 && env->vm_state_valid && env->nested_pg_format == 1))
    {
        pt_entry->present = pte_contents & PG_PRESENT_MASK;

        if (pt_entry->present) {
            bool nx_enabled = !!(pg_mode & PG_MODE_NXE);
            bool smep_enabled = !!(pg_mode & PG_MODE_SMEP);

            pt_entry->super_read_ok = true;
            if (pg_mode & PG_MODE_WP) {
                pt_entry->super_write_ok = !!(pte_contents & PG_RW_MASK);
            } else {
                pt_entry->super_write_ok = true;
            }

            if (nx_enabled) {
                if (smep_enabled) {
                    pt_entry->super_exec_ok = !(pte_contents & PG_USER_MASK);
                } else {
                    pt_entry->super_exec_ok = !(pte_contents & PG_NX_MASK);
                }
                pt_entry->user_exec_ok = !(pte_contents & PG_NX_MASK);
            } else {
                pt_entry->super_exec_ok = true;
                pt_entry->user_exec_ok = !(pte_contents & PG_USER_MASK);
            }

            if (pte_contents & PG_USER_MASK) {
                pt_entry->user_read_ok = true;
                pt_entry->user_write_ok = !!(pte_contents & PG_RW_MASK);
            }

            pt_entry->dirty = !!(pte_contents & PG_DIRTY_MASK);
        }

        pt_entry->prot = pte_contents & (PG_USER_MASK | PG_RW_MASK |
                                         PG_PRESENT_MASK);



        /* In 32-bit mode without PAE, we need to check the PSE flag in cr4 */
        if (long_mode || pae_enabled || pg_mode & PG_MODE_PSE) {
            leaf_mask = PG_PSE_MASK;
        }

    } else if (mmu_idx == 1) {
        uint64_t mask = PG_EPT_PRESENT_MASK;
        /*
         * One could arguably check whether the CPU is in supervisor mode
         * here. At least for debugging functions, one probably only wants
         * an entry treated as not-present if it is not present in all modes,
         * not just the current guest ring.  OTOH, TCG may want this semantic.
         */
        if ( env->enable_mode_based_access_control ) {
            mask |= PG_EPT_X_USER_MASK;
        }
        pt_entry->present = !!(pte_contents & mask);
        if (pt_entry->present) {
            pt_entry->super_read_ok = pt_entry->user_read_ok
                = !!(pte_contents & PG_EPT_R_MASK);

            pt_entry->super_exec_ok = !!(pte_contents & PG_EPT_X_SUPER_MASK);
            if ( env->enable_mode_based_access_control ) {
                pt_entry->user_exec_ok = !!(pte_contents & PG_EPT_X_USER_MASK);
            } else {
                pt_entry->user_exec_ok = pt_entry->super_exec_ok;
            }

            pt_entry->dirty = !!(pte_contents & PG_DIRTY_MASK);
        }
        pt_entry->prot = pte_contents & (PG_EPT_PRESENT_MASK | PG_EPT_X_USER_MASK);
        leaf_mask = PG_EPT_PSE_MASK;
    } else {
        g_assert_not_reached();
    }

    if (pt_entry->present) {
        pt_entry->leaf = (height == 1 ||
                          pte_contents & leaf_mask);

        /* Sanity checks */
        if (pt_entry->leaf) {
            switch (height) {
#ifdef TARGET_X86_64
            case 5:
                /* No leaves at level 5 in EPT */
                assert(mmu_idx == 0);
                assert(pae_enabled);
                assert(env->cr[4] & CR4_LA57_MASK);
                assert(env->hflags & HF_LMA_MASK);
                break;
            case 4:
                /* No leaves at level 4 in EPT */
                assert(mmu_idx == 0);
                assert(pae_enabled);
                assert(env->hflags & HF_LMA_MASK);
                break;
#endif
            case 3:
                if (mmu_idx == 0) {
                    assert(pae_enabled);
                }
                break;
            }
        }

        switch (height) {
#ifdef TARGET_X86_64
        case 5:
            /* assert(pae_enabled); */
            /* Fall through */
        case 4:
            /* assert(pae_enabled); */
            /* Fall through */
#endif
        case 3:
            assert(pae_enabled);
#ifdef TARGET_X86_64
            if (env->hflags & HF_LMA_MASK) {
                if (pt_entry->leaf) {
                    /* Select bits 30--51 */
                    pt_entry->child = (pte_contents & 0xfffffc0000000);
                } else {
                    pt_entry->child = (pte_contents & PG_ADDRESS_MASK)
                        & a20_mask;
                }
            } else
#endif
            {
                pt_entry->child = (pte_contents & ~0xfff) & a20_mask;
            }
            break;
        case 2:
            if (pt_entry->leaf) {
                if (pae_enabled) {
                    /* Select bits 21--51 */
                    pt_entry->child = (pte_contents & 0xfffffffe00000);
                } else {
                    /*
                     * 4 MB page:
                     * bits 39:32 are bits 20:13 of the PDE
                     * bit3 31:22 are bits 31:22 of the PDE
                     */
                    hwaddr high_paddr = ((hwaddr)(pte_contents & 0x1fe000) << 19);
                    pt_entry->child = (pte_contents & ~0x3fffff) | high_paddr;
                }
                break;
            }
            /* else fall through */
        case 1:
            if (pae_enabled || mmu_idx == 1) {
                pt_entry->child = (pte_contents & PG_ADDRESS_MASK)
                    & a20_mask;
            } else {
                pt_entry->child = (pte_contents & ~0xfff) & a20_mask;
            }
            break;
        default:
            g_assert_not_reached();
        }

        /* Check reserved bits */
        uint64_t rsvd_mask = ~MAKE_64BIT_MASK(0, env_archcpu(env)->phys_bits);
        rsvd_mask &= PG_ADDRESS_MASK;

        if (mmu_idx == 0
            || (mmu_idx == 1 && env->vm_state_valid &&
                env->nested_pg_format == 1)) {

            if (!(env->efer & MSR_EFER_NXE)
                || !long_mode) {
                rsvd_mask |= PG_NX_MASK;
            }
            if (height > 3) {
                rsvd_mask |= PG_PSE_MASK;
            }
            if (!long_mode) {
                if (pae_enabled) {
                    rsvd_mask |= PG_HI_USER_MASK;
                } else if (!pae_enabled && height == 2 && pt_entry->leaf) {
                    rsvd_mask = 0x200000;
                } else {
                    rsvd_mask = 0;
                }
            }

            /* If PAT is not supported, the PAT bit is reserved */
            if(!(env->features[FEAT_1_EDX] & CPUID_PAT)) {
                rsvd_mask |= PG_PSE_PAT_MASK;
            }

        } else if (mmu_idx == 1) {
            assert (env->nested_pg_format == 0);
            /* All EPT formats reserve bits 51..max phys address. */
            rsvd_mask &= 0xffffffffff000;

            if (pt_entry->leaf) {
                /* Leaves reserve irrelevant low-bits of the phys addr */
                if (height == 3) {
                    rsvd_mask |= 0x3ffff000;
                } else if (height == 2) {
                    rsvd_mask |= 0x1ff000;
                }
            } else {
                /* non-leaves should have bits 7:3 clear */
                rsvd_mask |= 0xf8;
            }
        } else {
            g_assert_not_reached();
        }

        if (pte_contents & rsvd_mask) {
            pt_entry->reserved_bits_ok = false;
        } else {
            pt_entry->reserved_bits_ok = true;
        }

        /* In non-read-only case, set accessed bits */
        if (!debug) {
#ifdef CONFIG_TCG
            TranslateFault err;
            PTETranslate pte_trans = {
                .gaddr = pte_host_addr,
                .haddr = pte_internal_pointer,
                .env = env,
                .err = &err,
                .ptw_idx = MMU_PHYS_IDX, /* We already recurred */
            };

            /* If this is a leaf and a store, set the dirty bit too */
            if (mmu_idx == 0 || (mmu_idx == 1 && env->nested_pg_format == 1)) {
                uint32_t set = PG_ACCESSED_MASK;
                if (pt_entry->leaf && access_type == MMU_DATA_STORE) {
                    set |= PG_DIRTY_MASK;
                }
                if(!ptw_setl(&pte_trans, pte_contents, set)) {
                    goto reread_pte;
                }
            } else if (mmu_idx == 1) {
                assert(env->nested_pg_format == 0);
                if (env->enable_ept_accessed_dirty) {
                    uint32_t set = PG_EPT_ACCESSED_MASK;
                    if (pt_entry->leaf && access_type == MMU_DATA_STORE) {
                        set |= PG_EPT_DIRTY_MASK;
                    }
                    if(!ptw_setl(&pte_trans, pte_contents, set)) {
                        goto reread_pte;
                    }
                }
            } else {
                g_assert_not_reached();
            }
#else
            g_assert_not_reached();
#endif
        }
    }

    /*
     * We always report the relevant leaf page size so that
     * consumers know the virtual addresses range translated by this entry.
     */

    /* Decode the child node's hw address */
    switch (height) {
#ifdef TARGET_X86_64
    case 5:
        assert(env->cr[4] & CR4_LA57_MASK);
        pt_entry->leaf_page_size = 1ULL << 48;
        break;
    case 4:
        assert(env->hflags & HF_LMA_MASK);
        pt_entry->leaf_page_size = 1ULL << 39;
        break;
#endif
    case 3:
        pt_entry->leaf_page_size = 1 << 30;
        break;
    case 2:
        if (pae_enabled || mmu_idx == 1) {
            pt_entry->leaf_page_size = 1 << 21;
        } else {
            pt_entry->leaf_page_size = 1 << 22;
        }
        break;
    case 1:
        pt_entry->leaf_page_size = 4096;
        break;
    default:
        g_assert_not_reached();
    }

    int shift = 0;
    _mmu_decode_va_parameters(cs, height, &shift, NULL);
    pt_entry->bits_translated = vaddr_parent | ((i & 0x1ffULL) << shift);
    pt_entry->pte_addr = pte;
    pt_entry->pte_host_addr = (hwaddr) pte_host_addr;
    pt_entry->pte_contents = pte_contents;

    return true;
}

bool x86_ptw_translate(CPUState *cs, vaddr vaddress, hwaddr *hpa,
                       bool debug, int mmu_idx, bool user_access,
                       const MMUAccessType access_type, uint64_t *page_size,
                       int *error_code, hwaddr *fault_addr, TranslateFaultStage2 *nested_fault,
                       int *prot, bool *dirty)
{
    CPUX86State *env = cpu_env(cs);
    const PageTableLayout *layout;
    hwaddr pt_node = x86_page_table_root(cs, &layout, mmu_idx);
    DecodedPTE pt_entry;
    hwaddr offset = 0;
    hwaddr real_hpa = 0;
    uint64_t real_page_size;

    vaddr bits_translated = 0;
    int pg_mode = get_pg_mode(env);
    bool use_stage2 = env->hflags & HF_GUEST_MASK;

    /*
     * As we iterate on the page table, accumulate allowed operations, for
     * a possible TLB refill (e.g., TCG).  Note that we follow the TCG softmmu
     * code in applying protection keys here; my reading is that one needs to flush
     * the TLB on any operation that changes a relevant key, which is beyond this
     * code's purview...
     */
    bool user_read_ok = true, user_write_ok = true, user_exec_ok = true;
    bool super_read_ok = true, super_write_ok = true, super_exec_ok = true;

    /* Initialize the error code to 0 */
    if (error_code) {
        *error_code = 0;
    }

    /* Ensure nested_fault is initialized properly */
    if (nested_fault) {
        *nested_fault = S2_NONE;
    }

    int i = layout->height;
    do {
        int index = x86_virtual_to_pte_index(cs, vaddress, i);

        memset(&pt_entry, 0, sizeof(pt_entry));

        if (!x86_get_pte(cs, pt_node, index, i, &pt_entry, bits_translated,
                         debug, mmu_idx, user_access, access_type, error_code,
                         fault_addr, nested_fault)) {
            return false;
        }

        if (!pt_entry.present) {
            if (error_code) {
                /* Set the P bit to zero */
                if (error_code) {
                    *error_code &= ~PG_ERROR_P_MASK;
                    if (user_access) {
                        *error_code |= PG_ERROR_U_MASK;
                    }
                    if (access_type == MMU_DATA_STORE) {
                        *error_code |= PG_ERROR_W_MASK;
                    } else if (access_type == MMU_INST_FETCH) {
                        *error_code |= PG_ERROR_I_D_MASK;
                    }
                }
            }
            goto fault_out;
        }

        /* Always check reserved bits */
        if (!pt_entry.reserved_bits_ok) {
            if (error_code) {
                *error_code |= PG_ERROR_RSVD_MASK;
            }
            goto fault_out;
        }

        /* Check if we have hit a leaf.  Won't happen (yet) at heights > 3. */
        if (pt_entry.leaf) {
            assert(i < 4);
            break;
        }

        /* Always accumulate the permissions on the page table walk. */
        user_read_ok &= pt_entry.user_read_ok;
        user_write_ok &= pt_entry.user_write_ok;
        user_exec_ok &= pt_entry.user_exec_ok;
        super_read_ok &= pt_entry.super_read_ok;
        super_write_ok &= pt_entry.super_write_ok;
        super_exec_ok &= pt_entry.super_exec_ok;

        /* If we are not in debug mode, check permissions before recurring */
        if (!debug) {
            if (user_access) {
                switch (access_type) {
                case MMU_DATA_LOAD:
                    if(!pt_entry.user_read_ok) {
                        if (error_code) {
                            *error_code |= PG_ERROR_U_MASK | PG_ERROR_P_MASK;
                        }
                        goto fault_out;
                    }
                    break;
                case MMU_DATA_STORE:
                    if(!pt_entry.user_write_ok) {
                        if (error_code) {
                            *error_code |= PG_ERROR_P_MASK | PG_ERROR_W_MASK | PG_ERROR_U_MASK;
                        }
                        goto fault_out;
                    }
                    break;
                case MMU_INST_FETCH:
                    if(!pt_entry.user_exec_ok) {
                        if (error_code) {
                            *error_code = PG_ERROR_P_MASK | PG_ERROR_I_D_MASK | PG_ERROR_U_MASK;
                        }
                        goto fault_out;
                    }
                    break;
                default:
                    g_assert_not_reached();
                }
            } else {
                switch (access_type) {
                case MMU_DATA_LOAD:
                    if(!pt_entry.super_read_ok) {
                        if (error_code) {
                            /* Not a distinct super+r mask */
                            *error_code |= PG_ERROR_P_MASK;
                        }
                        goto fault_out;
                    }
                    break;
                case MMU_DATA_STORE:
                    if(!pt_entry.super_write_ok) {
                        if (error_code) {
                            *error_code = PG_ERROR_P_MASK | PG_ERROR_W_MASK;
                        }
                        goto fault_out;
                    }
                    break;
                case MMU_INST_FETCH:
                    if(!pt_entry.super_exec_ok) {
                        if (error_code) {
                            *error_code = PG_ERROR_P_MASK | PG_ERROR_I_D_MASK;
                        }
                        goto fault_out;
                    }
                    break;
                default:
                    g_assert_not_reached();
                }
            }
        }

        /* Move to the child node */
        assert(i > 1);
        pt_node = pt_entry.child;
        bits_translated |= pt_entry.bits_translated;
        i--;
    } while (i > 0);

    assert(pt_entry.leaf);

    /* Some x86 protection checks are leaf-specific */

    /* Apply MPK at end, only on non-nested page tables */
    if (mmu_idx == 0) {
        /* MPK */
        uint32_t pkr;

        /* Is this a user-mode mapping? */
        if (user_read_ok) {
            pkr = pg_mode & PG_MODE_PKE ? env->pkru : 0;
        } else {
            pkr = pg_mode & PG_MODE_PKS ? env->pkrs : 0;
        }

        if (pkr) {
            uint32_t pk = (pt_entry.pte_contents & PG_PKRU_MASK)
                >> PG_PKRU_BIT;
            /*
             * Follow the TCG pattern here of applying these bits
             * to the protection, which may be fed to the TLB.
             * My reading is that it is not safe to cache this across
             * changes to these registers...
             */
            uint32_t pkr_ad = (pkr >> pk * 2) & 1;
            uint32_t pkr_wd = (pkr >> pk * 2) & 2;

            if (pkr_ad) {
                super_read_ok = false;
                user_read_ok = false;
                super_write_ok = false;
                user_write_ok = false;

                if (!debug) {
                    if (access_type == MMU_DATA_LOAD
                        || access_type == MMU_DATA_STORE) {
                        if (error_code) {
                            *error_code |= PG_ERROR_PK_MASK | PG_ERROR_P_MASK;
                            if (user_access) {
                                *error_code |= PG_ERROR_U_MASK;
                            }
                        }
                        goto fault_out;

                    }
                }
            }

            if (pkr_wd) {
                user_write_ok = false;
                if (pg_mode & PG_MODE_WP) {
                    super_write_ok = false;
                }
                if (!debug) {
                    if (access_type == MMU_DATA_STORE
                        && (user_access || pg_mode & PG_MODE_WP)) {
                        if (error_code) {
                            *error_code |= PG_ERROR_PK_MASK | PG_ERROR_P_MASK;
                            if (user_access) {
                                *error_code |= PG_ERROR_U_MASK;
                            }
                        }
                        goto fault_out;
                    }
                }
            }
        }
    }

    real_page_size = pt_entry.leaf_page_size;
    /* Add offset bits back to hpa */
    offset = vaddress & (pt_entry.leaf_page_size - 1);
    real_hpa = pt_entry.child | offset;

    /* In the event of nested paging, we need to recur one last time on the child
     * address to resolve the host address.  Also, if the nested page size is larger
     * use that for a TLB consumer.  Recursion with the offset bits added in
     * should do the right thing if the nested page sizes differ.
     */

    if (mmu_idx == 0 && use_stage2) {
        vaddr gpa = pt_entry.child | offset;
        uint64_t nested_page_size = 0;

        if (error_code) {
            assert(error_code == 0);
        }

        if (!x86_ptw_translate(cs, gpa, &real_hpa,
                               debug, 1, user_access, access_type,
                               &nested_page_size, error_code, fault_addr,
                               nested_fault, prot, NULL)) {
            if (nested_fault) {
                *nested_fault = S2_GPA;
            }
            return false;
        }

        if (real_page_size < nested_page_size) {
            real_page_size = nested_page_size;
        }
    }

    if (hpa) {
        *hpa = real_hpa;
    }

    if (page_size) {
        *page_size = real_page_size;
    }

    if (prot) {
        *prot = 0;
        if (user_access) {
            if (user_read_ok) {
                *prot |= PAGE_READ;
            }
            if (user_write_ok) {
                *prot |= PAGE_WRITE;
            }
            if (user_exec_ok) {
                *prot |= PAGE_EXEC;
            }
        } else {
            if (super_read_ok) {
                *prot |= PAGE_READ;
            }
            if (super_write_ok) {
                *prot |= PAGE_WRITE;
            }
            if (super_exec_ok) {
                *prot |= PAGE_EXEC;
            }
        }
    }

    if (dirty) {
        *dirty = pt_entry.dirty;
    }

    return true;

 fault_out:
    if (fault_addr) {
        *fault_addr = vaddress;
    }
    return false;

}

struct memory_mapping_data {
    MemoryMappingList *list;
};

static int add_memory_mapping_to_list(CPUState *cs, void *data, DecodedPTE *pte,
                                      int height, int offset, int mmu_idx,
                                      const PageTableLayout *layout)
{
    struct memory_mapping_data *mm_data = (struct memory_mapping_data *) data;

    /* In the case of nested paging, give the real, host-physical mapping. */
    hwaddr start_paddr = pte->pte_host_addr;
    size_t pg_size = pte->leaf_page_size;

    /* This hook skips mappings for the I/O region */
    if (cpu_physical_memory_is_io(start_paddr)) {
        /* I/O region */
        return 0;
    }

    memory_mapping_list_add_merge_sorted(mm_data->list, start_paddr,
                                         pte->bits_translated, pg_size);
    return 0;
}

bool x86_cpu_get_memory_mapping(CPUState *cs, MemoryMappingList *list,
                                Error **errp)
{
    return for_each_pte(cs, &add_memory_mapping_to_list, list, false, false, false, 0);
}
