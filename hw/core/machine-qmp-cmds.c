/*
 * QMP commands related to machines and CPUs
 *
 * Copyright (C) 2014 Red Hat Inc
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "hw/acpi/vmgenid.h"
#include "hw/boards.h"
#include "hw/core/sysemu-cpu-ops.h"
#include "hw/intc/intc.h"
#include "hw/mem/memory-device.h"
#include "qapi/error.h"
#include "qapi/qapi-builtin-visit.h"
#include "qapi/qapi-commands-machine.h"
#include "qapi/qmp/qobject.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/type-helpers.h"
#include "qemu/uuid.h"
#include "qom/qom-qobject.h"
#include "sysemu/hostmem.h"
#include "sysemu/hw_accel.h"
#include "sysemu/numa.h"
#include "sysemu/runstate.h"
#include "sysemu/sysemu.h"

/*
 * fast means: we NEVER interrupt vCPU threads to retrieve
 * information from KVM.
 */
CpuInfoFastList *qmp_query_cpus_fast(Error **errp)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    MachineClass *mc = MACHINE_GET_CLASS(ms);
    CpuInfoFastList *head = NULL, **tail = &head;
    SysEmuTarget target = qapi_enum_parse(&SysEmuTarget_lookup, target_name(),
                                          -1, &error_abort);
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        CpuInfoFast *value = g_malloc0(sizeof(*value));

        value->cpu_index = cpu->cpu_index;
        value->qom_path = object_get_canonical_path(OBJECT(cpu));
        value->thread_id = cpu->thread_id;

        if (mc->cpu_index_to_instance_props) {
            CpuInstanceProperties *props;
            props = g_malloc0(sizeof(*props));
            *props = mc->cpu_index_to_instance_props(ms, cpu->cpu_index);
            value->props = props;
        }

        value->target = target;
        if (cpu->cc->query_cpu_fast) {
            cpu->cc->query_cpu_fast(cpu, value);
        }

        QAPI_LIST_APPEND(tail, value);
    }

    return head;
}

MachineInfoList *qmp_query_machines(bool has_compat_props, bool compat_props,
                                    Error **errp)
{
    GSList *el, *machines = object_class_get_list(TYPE_MACHINE, false);
    MachineInfoList *mach_list = NULL;

    for (el = machines; el; el = el->next) {
        MachineClass *mc = el->data;
        MachineInfo *info;

        info = g_malloc0(sizeof(*info));
        if (mc->is_default) {
            info->has_is_default = true;
            info->is_default = true;
        }

        if (mc->alias) {
            info->alias = g_strdup(mc->alias);
        }

        info->name = g_strdup(mc->name);
        info->cpu_max = !mc->max_cpus ? 1 : mc->max_cpus;
        info->hotpluggable_cpus = mc->has_hotpluggable_cpus;
        info->numa_mem_supported = mc->numa_mem_supported;
        info->deprecated = !!mc->deprecation_reason;
        info->acpi = !!object_class_property_find(OBJECT_CLASS(mc), "acpi");
        if (mc->default_cpu_type) {
            info->default_cpu_type = g_strdup(mc->default_cpu_type);
        }
        if (mc->default_ram_id) {
            info->default_ram_id = g_strdup(mc->default_ram_id);
        }

        if (compat_props && mc->compat_props) {
            int i;
            info->compat_props = NULL;
            CompatPropertyList **tail = &(info->compat_props);
            info->has_compat_props = true;

            for (i = 0; i < mc->compat_props->len; i++) {
                GlobalProperty *mt_prop = g_ptr_array_index(mc->compat_props,
                                                            i);
                CompatProperty *prop;

                prop = g_malloc0(sizeof(*prop));
                prop->qom_type = g_strdup(mt_prop->driver);
                prop->property = g_strdup(mt_prop->property);
                prop->value = g_strdup(mt_prop->value);

                QAPI_LIST_APPEND(tail, prop);
            }
        }

        QAPI_LIST_PREPEND(mach_list, info);
    }

    g_slist_free(machines);
    return mach_list;
}

CurrentMachineParams *qmp_query_current_machine(Error **errp)
{
    CurrentMachineParams *params = g_malloc0(sizeof(*params));
    params->wakeup_suspend_support = qemu_wakeup_suspend_enabled();

    return params;
}

TargetInfo *qmp_query_target(Error **errp)
{
    TargetInfo *info = g_malloc0(sizeof(*info));

    info->arch = qapi_enum_parse(&SysEmuTarget_lookup, target_name(), -1,
                                 &error_abort);

    return info;
}

HotpluggableCPUList *qmp_query_hotpluggable_cpus(Error **errp)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    MachineClass *mc = MACHINE_GET_CLASS(ms);

    if (!mc->has_hotpluggable_cpus) {
        error_setg(errp, "machine does not support hot-plugging CPUs");
        return NULL;
    }

    return machine_query_hotpluggable_cpus(ms);
}

void qmp_set_numa_node(NumaOptions *cmd, Error **errp)
{
    if (phase_check(PHASE_MACHINE_INITIALIZED)) {
        error_setg(errp, "The command is permitted only before the machine has been created");
        return;
    }

    set_numa_options(MACHINE(qdev_get_machine()), cmd, errp);
}

static int query_memdev(Object *obj, void *opaque)
{
    Error *err = NULL;
    MemdevList **list = opaque;
    Memdev *m;
    QObject *host_nodes;
    Visitor *v;

    if (object_dynamic_cast(obj, TYPE_MEMORY_BACKEND)) {
        m = g_malloc0(sizeof(*m));

        m->id = g_strdup(object_get_canonical_path_component(obj));

        m->size = object_property_get_uint(obj, "size", &error_abort);
        m->merge = object_property_get_bool(obj, "merge", &error_abort);
        m->dump = object_property_get_bool(obj, "dump", &error_abort);
        m->prealloc = object_property_get_bool(obj, "prealloc", &error_abort);
        m->share = object_property_get_bool(obj, "share", &error_abort);
        m->reserve = object_property_get_bool(obj, "reserve", &err);
        if (err) {
            error_free_or_abort(&err);
        } else {
            m->has_reserve = true;
        }
        m->policy = object_property_get_enum(obj, "policy", "HostMemPolicy",
                                             &error_abort);
        host_nodes = object_property_get_qobject(obj,
                                                 "host-nodes",
                                                 &error_abort);
        v = qobject_input_visitor_new(host_nodes);
        visit_type_uint16List(v, NULL, &m->host_nodes, &error_abort);
        visit_free(v);
        qobject_unref(host_nodes);

        QAPI_LIST_PREPEND(*list, m);
    }

    return 0;
}

MemdevList *qmp_query_memdev(Error **errp)
{
    Object *obj = object_get_objects_root();
    MemdevList *list = NULL;

    object_child_foreach(obj, query_memdev, &list);
    return list;
}

HumanReadableText *qmp_x_query_numa(Error **errp)
{
    g_autoptr(GString) buf = g_string_new("");
    int i, nb_numa_nodes;
    NumaNodeMem *node_mem;
    CpuInfoFastList *cpu_list, *cpu;
    MachineState *ms = MACHINE(qdev_get_machine());

    nb_numa_nodes = ms->numa_state ? ms->numa_state->num_nodes : 0;
    g_string_append_printf(buf, "%d nodes\n", nb_numa_nodes);
    if (!nb_numa_nodes) {
        goto done;
    }

    cpu_list = qmp_query_cpus_fast(&error_abort);
    node_mem = g_new0(NumaNodeMem, nb_numa_nodes);

    query_numa_node_mem(node_mem, ms);
    for (i = 0; i < nb_numa_nodes; i++) {
        g_string_append_printf(buf, "node %d cpus:", i);
        for (cpu = cpu_list; cpu; cpu = cpu->next) {
            if (cpu->value->props && cpu->value->props->has_node_id &&
                cpu->value->props->node_id == i) {
                g_string_append_printf(buf, " %" PRIi64, cpu->value->cpu_index);
            }
        }
        g_string_append_printf(buf, "\n");
        g_string_append_printf(buf, "node %d size: %" PRId64 " MB\n", i,
                               node_mem[i].node_mem >> 20);
        g_string_append_printf(buf, "node %d plugged: %" PRId64 " MB\n", i,
                               node_mem[i].node_plugged_mem >> 20);
    }
    qapi_free_CpuInfoFastList(cpu_list);
    g_free(node_mem);

 done:
    return human_readable_text_from_str(buf);
}

KvmInfo *qmp_query_kvm(Error **errp)
{
    KvmInfo *info = g_malloc0(sizeof(*info));

    info->enabled = kvm_enabled();
    info->present = accel_find("kvm");

    return info;
}

UuidInfo *qmp_query_uuid(Error **errp)
{
    UuidInfo *info = g_malloc0(sizeof(*info));

    info->UUID = qemu_uuid_unparse_strdup(&qemu_uuid);
    return info;
}

void qmp_system_reset(Error **errp)
{
    qemu_system_reset_request(SHUTDOWN_CAUSE_HOST_QMP_SYSTEM_RESET);
}

void qmp_system_powerdown(Error **errp)
{
    qemu_system_powerdown_request();
}

void qmp_system_wakeup(Error **errp)
{
    if (!qemu_wakeup_suspend_enabled()) {
        error_setg(errp,
                   "wake-up from suspend is not supported by this guest");
        return;
    }

    qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER, errp);
}

MemoryDeviceInfoList *qmp_query_memory_devices(Error **errp)
{
    return qmp_memory_device_list();
}

MemoryInfo *qmp_query_memory_size_summary(Error **errp)
{
    MemoryInfo *mem_info = g_new0(MemoryInfo, 1);
    MachineState *ms = MACHINE(qdev_get_machine());

    mem_info->base_memory = ms->ram_size;

    mem_info->plugged_memory = get_plugged_memory_size();
    mem_info->has_plugged_memory =
        mem_info->plugged_memory != (uint64_t)-1;

    return mem_info;
}

HumanReadableText *qmp_x_query_ramblock(Error **errp)
{
    g_autoptr(GString) buf = ram_block_format();

    return human_readable_text_from_str(buf);
}

static int qmp_x_query_irq_foreach(Object *obj, void *opaque)
{
    InterruptStatsProvider *intc;
    InterruptStatsProviderClass *k;
    GString *buf = opaque;

    if (object_dynamic_cast(obj, TYPE_INTERRUPT_STATS_PROVIDER)) {
        intc = INTERRUPT_STATS_PROVIDER(obj);
        k = INTERRUPT_STATS_PROVIDER_GET_CLASS(obj);
        uint64_t *irq_counts;
        unsigned int nb_irqs, i;
        if (k->get_statistics &&
            k->get_statistics(intc, &irq_counts, &nb_irqs)) {
            if (nb_irqs > 0) {
                g_string_append_printf(buf, "IRQ statistics for %s:\n",
                                       object_get_typename(obj));
                for (i = 0; i < nb_irqs; i++) {
                    if (irq_counts[i] > 0) {
                        g_string_append_printf(buf, "%2d: %" PRId64 "\n", i,
                                               irq_counts[i]);
                    }
                }
            }
        } else {
            g_string_append_printf(buf,
                                   "IRQ statistics not available for %s.\n",
                                   object_get_typename(obj));
        }
    }

    return 0;
}

HumanReadableText *qmp_x_query_irq(Error **errp)
{
    g_autoptr(GString) buf = g_string_new("");

    object_child_foreach_recursive(object_get_root(),
                                   qmp_x_query_irq_foreach, buf);

    return human_readable_text_from_str(buf);
}

GuidInfo *qmp_query_vm_generation_id(Error **errp)
{
    GuidInfo *info;
    VmGenIdState *vms;
    Object *obj = find_vmgenid_dev();

    if (!obj) {
        error_setg(errp, "VM Generation ID device not found");
        return NULL;
    }
    vms = VMGENID(obj);

    info = g_malloc0(sizeof(*info));
    info->guid = qemu_uuid_unparse_strdup(&vms->guid);
    return info;
}

/* Assume only called on present entries */
static
int compressing_iterator(CPUState *cs, void *data, DecodedPTE *pte,
                         int height, int offset, int mmu_idx,
                         const PageTableLayout *layout)
{
    struct mem_print_state *state = (struct mem_print_state *) data;
    hwaddr paddr = pte->child;
    uint64_t size = pte->leaf_page_size;
    bool start_new_run = false, flush = false;
    bool is_leaf = pte->leaf;

    int entries_per_node = layout->entries_per_node[height];


    /* Prot of current pte */
    int prot = pte->prot;

    /* If there is a prior run, first try to extend it. */
    if (state->start_height != 0) {

        /*
         * If we aren't flushing interior nodes, raise the start height.
         * We don't need to detect non-compressible interior nodes.
         */
        if (!state->flush_interior && state->start_height < height) {
            state->start_height = height;
            state->vstart[height] = pte->bits_translated;
            state->vend[height] = pte->bits_translated;
            assert(pte->leaf_page_size != -1);
            state->pg_size[height] = pte->leaf_page_size;
            state->prot[height] = prot;
            if (offset == 0) {
                state->last_offset[height] = entries_per_node - 1;
            } else {
                state->last_offset[height] = offset - 1;
            }
        }

        /* Detect when we are walking down the "left edge" of a range */
        if (state->vstart[height] == -1
            && (height + 1) <= state->start_height
            && state->vstart[height + 1] == pte->bits_translated) {

            state->vstart[height] = pte->bits_translated;
            assert(pte->leaf_page_size != -1);
            state->pg_size[height] = pte->leaf_page_size;
            state->vend[height] = pte->bits_translated;
            state->prot[height] = prot;
            state->offset[height] = offset;
            state->last_offset[height] = offset;

            if (is_leaf) {
                state->pstart = paddr;
                state->pend = paddr;
                state->leaf_height = height;
            }

            /* Detect contiguous entries at same level */
        } else if (state->vstart[height] != -1
                   && state->start_height >= height
                   && state->prot[height] == prot
                   && (state->last_offset[height] + 1) % entries_per_node
                       == offset
                   && (!is_leaf
                       || !state->require_physical_contiguity
                       || state->pend + size == paddr)) {


            /*
             * If there are entries at the levels below, make sure we
             * completed them.  We only compress interior nodes
             * without holes in the mappings.
             */
            if (height != 1) {
                for (int i = height - 1; i >= 1; i--) {
                    int entries = layout->entries_per_node[i];

                    /* Stop if we hit large pages before level 1 */
                    if (state->vstart[i] == -1) {
                        break;
                    }

                    if (state->last_offset[i] + 1 != entries) {
                        flush = true;
                        start_new_run = true;
                        break;
                    }
                }
            }


            if (!flush) {

                /* We can compress these entries */
                state->prot[height] = prot;
                state->vend[height] = pte->bits_translated;
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
                state->prot[i] = 0;
                state->last_offset[i] = 0;
                state->vstart[i] = -1;
                state->pg_size[height] = -1;
            }
        }
        state->pstart = -1;
        state->leaf_height = -1;
        state->vstart[height] = pte->bits_translated;
        state->vend[height] = pte->bits_translated;
        state->pg_size[height] = pte->leaf_page_size;
        state->prot[height] = prot;
        state->offset[height] = offset;
        state->last_offset[height] = offset;
        if (is_leaf) {
            state->pstart = paddr;
            state->pend = paddr;
            state->leaf_height = height;
        }
        state->start_height = height;
    }

    return 0;
}

static
void query_page_helper(GString *buf, CPUState *cpu, int mmu_idx, bool nested) {

    CPUClass *cc = cpu->cc;
    struct mem_print_state state;

    if (!cc->sysemu_ops->mon_init_page_table_iterator(cpu, buf, mmu_idx, &state)) {
        g_string_append_printf(buf, "Unable to initialize page table iterator\n");
        return;
    }

    if (nested) {
        if (mmu_idx == 0) {
            g_string_append_printf(buf, "Info pg for CPU %d, guest mode\n", cpu->cpu_index);
        } else if (mmu_idx == 1) {
            g_string_append_printf(buf, "Info pg for CPU %d, host mode\n", cpu->cpu_index);
        } else {
            g_assert_not_reached();
        }
    } else {
        g_string_append_printf(buf, "Info pg for CPU %d\n", cpu->cpu_index);
    }

    state.flush_interior = true;
    state.require_physical_contiguity = true;
    state.flusher = cc->sysemu_ops->mon_flush_page_print_state;

    cc->sysemu_ops->mon_info_pg_print_header(&state);

    /*
     * We must visit interior entries to get the hierarchy, but
     * can skip not present mappings
     */
    for_each_pte(cpu, &compressing_iterator, &state, true, false, true, true,
                 mmu_idx);

    /* Print last entry, if one present */
    cc->sysemu_ops->mon_flush_page_print_state(cpu, &state);
}

HumanReadableText *qmp_x_query_pg(Error **errp)
{

    g_autoptr(GString) buf = g_string_new("");

    CPUState *cpu;
    CPU_FOREACH(cpu) {
        bool nested;

        cpu_synchronize_state(cpu);

        if (!cpu_paging_enabled(cpu, 0)) {
            continue;
        }

        nested = cpu_paging_enabled(cpu, 1);

        CPUClass *cc = cpu->cc;

        if (!cc->sysemu_ops->page_table_root) {
            g_string_append_printf(buf, "Info pg unsupported on this ISA\n");
            break;
        }

        assert(cc->sysemu_ops->mon_init_page_table_iterator);
        assert(cc->sysemu_ops->mon_info_pg_print_header);
        assert(cc->sysemu_ops->mon_flush_page_print_state);

        query_page_helper(buf, cpu, 0, nested);

        if (nested) {
            query_page_helper(buf, cpu, 1, nested);
        }
    }

    return human_readable_text_from_str(buf);
}
