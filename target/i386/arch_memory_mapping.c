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

#define PML4_ADDR_MASK 0xffffffffff000ULL /* selects bits 51:12 */

const PageTableLayout x86_lma57_layout = { .height = 5,
    .entries_per_node = {0, 512, 512, 512, 512, 512}};

const PageTableLayout x86_lma48_layout = { .height = 4,
    .entries_per_node = {0, 512, 512, 512, 512, 0}};

const PageTableLayout x86_pae32_layout = { .height = 3,
    .entries_per_node = {0, 512, 512, 4, 0, 0}};

const PageTableLayout x86_ia32_layout = { .height = 2,
    .entries_per_node = {0, 1024, 1024, 0, 0, 0}};

static
bool x86_ptw_translate(CPUState *cs, hwaddr gpa, hwaddr *hpa, bool read_only,
                       int mmu_idx);

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
 * @read_only - If true, do not update softmmu state (if applicable) to reflect
 *              the page table walk.
 * @mmu_idx - Which level of the mmu we are interested in: 0 == user
 *            mode, 1 == nested page table Note that MMU_*_IDX macros
 *            are not consistent across architectures.
 *
 * Returns true on success, false on failure
 */
bool
x86_get_pte(CPUState *cs, hwaddr node, int i, int height, DecodedPTE *pt_entry,
            vaddr vaddr_parent, bool read_only, int mmu_idx)
{
    CPUX86State *env = cpu_env(cs);
    int32_t a20_mask = x86_get_a20_mask(env);
    bool pae_enabled = env->cr[4] & CR4_PAE_MASK;
    hwaddr pte = 0;
    uint64_t pte_contents = 0;
    hwaddr pte_host_addr = 0;
    uint64_t unused = 0; /* We always call probe_access in non-fault mode */
    bool use_stage2 = env->hflags & HF_GUEST_MASK;
    int pte_width = 4;
    bool long_mode = env->hflags & HF_LMA_MASK;
    uint64_t leaf_mask = 0;

    pt_entry->reserved_bits_ok = false;

    if (env->hflags & HF_LMA_MASK) {
        /* 64 bit */
        pte_width = 8;
    }

    pte = (node + (i * pte_width)) & a20_mask;


    /* Recur on nested paging */
    if (mmu_idx == 0 && use_stage2) {

        if (read_only) {
            bool ok = x86_ptw_translate(cs, pte, &pte_host_addr, read_only, 1);
            if (!ok) {
                return false;
            }
        } else {
#ifdef CONFIG_TCG
            void *tmp;
            int flags = probe_access_flags(env, pte, 0, MMU_DATA_STORE,
                                           MMU_NESTED_IDX, true,
                                           &tmp, unused);

            if (unlikely(flags & TLB_INVALID_MASK)) {
                return false;
            }

            pte_host_addr = (hwaddr) tmp;
#else
            /* Any non-TCG use case should be read-only */
            g_assert_not_reached();
#endif
        }
    } else {
        pte_host_addr = pte;
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

#ifdef CONFIG_TCG
    /* In non-read-only case, set accessed bits */
    if (!read_only) {
        TranslateFault err;
        PTETranslate pte_trans = {
            .gaddr = pte,
            .haddr = (void *)pte_host_addr,
            .env = env,
            .err = &err,
        };

        switch(mmu_idx) {
        case 0:
            pte_trans.ptw_idx = use_stage2 ? MMU_NESTED_IDX : MMU_PHYS_IDX;
            if(!ptw_setl(&pte_trans, pte, PG_ACCESSED_MASK)) {
                goto reread_pte;
            }
            break;
        case 1:
            if (env->enable_ept_accessed_dirty) {
                pte_trans.ptw_idx = MMU_PHYS_IDX;
                if(!ptw_setl(&pte_trans, pte, PG_EPT_ACCESSED_MASK)) {
                    goto reread_pte;
                }
            }
            break;
        default:
            g_assert_not_reached();
        }
    }
#else
    assert(read_only);
#endif


    /* Deserialize flag bits, different by mmu index */
    if (mmu_idx == 0 ||
        (mmu_idx == 1 && env->vm_state_valid && env->nested_pg_format == 1))
    {
        pt_entry->present = pte_contents & PG_PRESENT_MASK;
        pt_entry->prot = pte_contents & (PG_USER_MASK | PG_RW_MASK |
                                         PG_PRESENT_MASK);
        leaf_mask = PG_PSE_MASK;
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
        pt_entry->prot = pte_contents & (PG_EPT_PRESENT_MASK | PG_EPT_X_USER_MASK);
        leaf_mask = PG_EPT_PSE_MASK;
    } else {
        g_assert_not_reached();
    }

    if (pt_entry->present) {
        pt_entry->leaf = (height == 1 || pte_contents & leaf_mask);
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
                pt_entry->child = (pte_contents & PG_ADDRESS_MASK)
                    & a20_mask;
            } else
#endif
            {
                pt_entry->child = (pte_contents & ~0xfff)
                    & a20_mask;
            }
            break;
        case 2:
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
                } else {
                    rsvd_mask = 0x200000;
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

static
bool x86_ptw_translate(CPUState *cs, hwaddr gpa, hwaddr *hpa, bool read_only,
                       int mmu_idx)
{
    const PageTableLayout *layout;
    hwaddr pt_node = x86_page_table_root(cs, &layout, mmu_idx);
    DecodedPTE pt_entry;
    hwaddr offset = 0;
    vaddr bits_translated = 0;

    int i = layout->height;
    do {
        int index = x86_virtual_to_pte_index(cs, gpa, i);

        x86_get_pte(cs, pt_node, index, i, &pt_entry, bits_translated, read_only, mmu_idx);

        if (!pt_entry.present || !pt_entry.reserved_bits_ok) {
            return false;
        }

        /* Check if we have hit a leaf.  Won't happen (yet) at heights > 3. */
        if (pt_entry.leaf) {
            assert(i < 4);
            break;
        }

        /* Move to the child node */
        assert(i > 1);
        pt_node = pt_entry.child;
        bits_translated |= pt_entry.bits_translated;
        i--;
    } while (i > 0);

    /* Add offset bits back to hpa */
    offset = gpa & (pt_entry.leaf_page_size - 1);

    if (hpa) {
        *hpa = pt_entry.child | offset;
    }
    return true;
}



/* PAE Paging or IA-32e Paging */
static void walk_pte(MemoryMappingList *list, AddressSpace *as,
                     hwaddr pte_start_addr,
                     int32_t a20_mask, target_ulong start_line_addr)
{
    hwaddr pte_addr, start_paddr;
    uint64_t pte;
    target_ulong start_vaddr;
    int i;

    for (i = 0; i < 512; i++) {
        pte_addr = (pte_start_addr + i * 8) & a20_mask;
        pte = address_space_ldq(as, pte_addr, MEMTXATTRS_UNSPECIFIED, NULL);
        if (!(pte & PG_PRESENT_MASK)) {
            /* not present */
            continue;
        }

        start_paddr = (pte & ~0xfff) & ~(0x1ULL << 63);
        if (cpu_physical_memory_is_io(start_paddr)) {
            /* I/O region */
            continue;
        }

        start_vaddr = start_line_addr | ((i & 0x1ff) << 12);
        memory_mapping_list_add_merge_sorted(list, start_paddr,
                                             start_vaddr, 1 << 12);
    }
}

/* 32-bit Paging */
static void walk_pte2(MemoryMappingList *list, AddressSpace *as,
                      hwaddr pte_start_addr, int32_t a20_mask,
                      target_ulong start_line_addr)
{
    hwaddr pte_addr, start_paddr;
    uint32_t pte;
    target_ulong start_vaddr;
    int i;

    for (i = 0; i < 1024; i++) {
        pte_addr = (pte_start_addr + i * 4) & a20_mask;
        pte = address_space_ldl(as, pte_addr, MEMTXATTRS_UNSPECIFIED, NULL);
        if (!(pte & PG_PRESENT_MASK)) {
            /* not present */
            continue;
        }

        start_paddr = pte & ~0xfff;
        if (cpu_physical_memory_is_io(start_paddr)) {
            /* I/O region */
            continue;
        }

        start_vaddr = start_line_addr | ((i & 0x3ff) << 12);
        memory_mapping_list_add_merge_sorted(list, start_paddr,
                                             start_vaddr, 1 << 12);
    }
}

/* PAE Paging or IA-32e Paging */
#define PLM4_ADDR_MASK 0xffffffffff000ULL /* selects bits 51:12 */

static void walk_pde(MemoryMappingList *list, AddressSpace *as,
                     hwaddr pde_start_addr,
                     int32_t a20_mask, target_ulong start_line_addr)
{
    hwaddr pde_addr, pte_start_addr, start_paddr;
    uint64_t pde;
    target_ulong line_addr, start_vaddr;
    int i;

    for (i = 0; i < 512; i++) {
        pde_addr = (pde_start_addr + i * 8) & a20_mask;
        pde = address_space_ldq(as, pde_addr, MEMTXATTRS_UNSPECIFIED, NULL);
        if (!(pde & PG_PRESENT_MASK)) {
            /* not present */
            continue;
        }

        line_addr = start_line_addr | ((i & 0x1ff) << 21);
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            start_paddr = (pde & ~0x1fffff) & ~(0x1ULL << 63);
            if (cpu_physical_memory_is_io(start_paddr)) {
                /* I/O region */
                continue;
            }
            start_vaddr = line_addr;
            memory_mapping_list_add_merge_sorted(list, start_paddr,
                                                 start_vaddr, 1 << 21);
            continue;
        }

        pte_start_addr = (pde & PLM4_ADDR_MASK) & a20_mask;
        walk_pte(list, as, pte_start_addr, a20_mask, line_addr);
    }
}

/* 32-bit Paging */
static void walk_pde2(MemoryMappingList *list, AddressSpace *as,
                      hwaddr pde_start_addr, int32_t a20_mask,
                      bool pse)
{
    hwaddr pde_addr, pte_start_addr, start_paddr, high_paddr;
    uint32_t pde;
    target_ulong line_addr, start_vaddr;
    int i;

    for (i = 0; i < 1024; i++) {
        pde_addr = (pde_start_addr + i * 4) & a20_mask;
        pde = address_space_ldl(as, pde_addr, MEMTXATTRS_UNSPECIFIED, NULL);
        if (!(pde & PG_PRESENT_MASK)) {
            /* not present */
            continue;
        }

        line_addr = (((unsigned int)i & 0x3ff) << 22);
        if ((pde & PG_PSE_MASK) && pse) {
            /*
             * 4 MB page:
             * bits 39:32 are bits 20:13 of the PDE
             * bit3 31:22 are bits 31:22 of the PDE
             */
            high_paddr = ((hwaddr)(pde & 0x1fe000) << 19);
            start_paddr = (pde & ~0x3fffff) | high_paddr;
            if (cpu_physical_memory_is_io(start_paddr)) {
                /* I/O region */
                continue;
            }
            start_vaddr = line_addr;
            memory_mapping_list_add_merge_sorted(list, start_paddr,
                                                 start_vaddr, 1 << 22);
            continue;
        }

        pte_start_addr = (pde & ~0xfff) & a20_mask;
        walk_pte2(list, as, pte_start_addr, a20_mask, line_addr);
    }
}

/* PAE Paging */
static void walk_pdpe2(MemoryMappingList *list, AddressSpace *as,
                       hwaddr pdpe_start_addr, int32_t a20_mask)
{
    hwaddr pdpe_addr, pde_start_addr;
    uint64_t pdpe;
    target_ulong line_addr;
    int i;

    for (i = 0; i < 4; i++) {
        pdpe_addr = (pdpe_start_addr + i * 8) & a20_mask;
        pdpe = address_space_ldq(as, pdpe_addr, MEMTXATTRS_UNSPECIFIED, NULL);
        if (!(pdpe & PG_PRESENT_MASK)) {
            /* not present */
            continue;
        }

        line_addr = (((unsigned int)i & 0x3) << 30);
        pde_start_addr = (pdpe & ~0xfff) & a20_mask;
        walk_pde(list, as, pde_start_addr, a20_mask, line_addr);
    }
}

#ifdef TARGET_X86_64
/* IA-32e Paging */
static void walk_pdpe(MemoryMappingList *list, AddressSpace *as,
                      hwaddr pdpe_start_addr, int32_t a20_mask,
                      target_ulong start_line_addr)
{
    hwaddr pdpe_addr, pde_start_addr, start_paddr;
    uint64_t pdpe;
    target_ulong line_addr, start_vaddr;
    int i;

    for (i = 0; i < 512; i++) {
        pdpe_addr = (pdpe_start_addr + i * 8) & a20_mask;
        pdpe = address_space_ldq(as, pdpe_addr, MEMTXATTRS_UNSPECIFIED, NULL);
        if (!(pdpe & PG_PRESENT_MASK)) {
            /* not present */
            continue;
        }

        line_addr = start_line_addr | ((i & 0x1ffULL) << 30);
        if (pdpe & PG_PSE_MASK) {
            /* 1 GB page */
            start_paddr = (pdpe & ~0x3fffffff) & ~(0x1ULL << 63);
            if (cpu_physical_memory_is_io(start_paddr)) {
                /* I/O region */
                continue;
            }
            start_vaddr = line_addr;
            memory_mapping_list_add_merge_sorted(list, start_paddr,
                                                 start_vaddr, 1 << 30);
            continue;
        }

        pde_start_addr = (pdpe & PLM4_ADDR_MASK) & a20_mask;
        walk_pde(list, as, pde_start_addr, a20_mask, line_addr);
    }
}

/* IA-32e Paging */
static void walk_pml4e(MemoryMappingList *list, AddressSpace *as,
                       hwaddr pml4e_start_addr, int32_t a20_mask,
                       target_ulong start_line_addr)
{
    hwaddr pml4e_addr, pdpe_start_addr;
    uint64_t pml4e;
    target_ulong line_addr;
    int i;

    for (i = 0; i < 512; i++) {
        pml4e_addr = (pml4e_start_addr + i * 8) & a20_mask;
        pml4e = address_space_ldq(as, pml4e_addr, MEMTXATTRS_UNSPECIFIED,
                                  NULL);
        if (!(pml4e & PG_PRESENT_MASK)) {
            /* not present */
            continue;
        }

        line_addr = start_line_addr | ((i & 0x1ffULL) << 39);
        pdpe_start_addr = (pml4e & PLM4_ADDR_MASK) & a20_mask;
        walk_pdpe(list, as, pdpe_start_addr, a20_mask, line_addr);
    }
}

static void walk_pml5e(MemoryMappingList *list, AddressSpace *as,
                       hwaddr pml5e_start_addr, int32_t a20_mask)
{
    hwaddr pml5e_addr, pml4e_start_addr;
    uint64_t pml5e;
    target_ulong line_addr;
    int i;

    for (i = 0; i < 512; i++) {
        pml5e_addr = (pml5e_start_addr + i * 8) & a20_mask;
        pml5e = address_space_ldq(as, pml5e_addr, MEMTXATTRS_UNSPECIFIED,
                                  NULL);
        if (!(pml5e & PG_PRESENT_MASK)) {
            /* not present */
            continue;
        }

        line_addr = (0x7fULL << 57) | ((i & 0x1ffULL) << 48);
        pml4e_start_addr = (pml5e & PLM4_ADDR_MASK) & a20_mask;
        walk_pml4e(list, as, pml4e_start_addr, a20_mask, line_addr);
    }
}
#endif

bool x86_cpu_get_memory_mapping(CPUState *cs, MemoryMappingList *list,
                                Error **errp)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int32_t a20_mask;

    if (!cpu_paging_enabled(cs, 0)) {
        /* paging is disabled */
        return true;
    }

    a20_mask = x86_get_a20_mask(env);
    if (env->cr[4] & CR4_PAE_MASK) {
#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            if (env->cr[4] & CR4_LA57_MASK) {
                hwaddr pml5e_addr;

                pml5e_addr = (env->cr[3] & PLM4_ADDR_MASK) & a20_mask;
                walk_pml5e(list, cs->as, pml5e_addr, a20_mask);
            } else {
                hwaddr pml4e_addr;

                pml4e_addr = (env->cr[3] & PLM4_ADDR_MASK) & a20_mask;
                walk_pml4e(list, cs->as, pml4e_addr, a20_mask,
                        0xffffULL << 48);
            }
        } else
#endif
        {
            hwaddr pdpe_addr;

            pdpe_addr = (env->cr[3] & ~0x1f) & a20_mask;
            walk_pdpe2(list, cs->as, pdpe_addr, a20_mask);
        }
    } else {
        hwaddr pde_addr;
        bool pse;

        pde_addr = (env->cr[3] & ~0xfff) & a20_mask;
        pse = !!(env->cr[4] & CR4_PSE_MASK);
        walk_pde2(list, cs->as, pde_addr, a20_mask, pse);
    }

    return true;
}
