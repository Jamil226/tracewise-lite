/*
 * TRACEWISE-Lite DynamoRIO Client
 * 
 * Extracts provenance-centric telemetry from real binaries:
 *  - Function calls (via call instructions & module parsing)
 *  - Memory reads/writes
 *  - Syscalls
 *  - Crashes (fault handling)
 * 
 * Outputs JSON directly mapping to ExecutionEvent python structures.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "drx.h"
#include <string.h>
#include <stdint.h>

static file_t outf;
static uint64_t timestamp = 0;

static void
event_exit(void);

static void
event_thread_init(void *drcontext);

static void
event_thread_exit(void *drcontext);

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb,
                      instr_t *inst, bool for_trace,
                      bool translating, void *user_data);

static bool
event_filter_syscall(void *drcontext, int sysnum);

static bool
event_pre_syscall(void *drcontext, int sysnum);

static dr_signal_action_t
event_signal(void *drcontext, dr_siginfo_t *siginfo);

/* Memory reference tracing */
static void
trace_mem(app_pc instr_addr, app_pc mem_addr, uint size, bool is_write)
{
    uint64_t ts = dr_atomic_add32_return_sum((volatile int *)&timestamp, 1);
    
    // Write JSON line for memory access
    char buf[512];
    int len = dr_snprintf(buf, sizeof(buf), 
        "{\"event_type\": \"%s\", \"address\": %llu, \"timestamp\": %llu, \"thread_id\": 0, \"memory_address\": %llu, \"memory_size\": %u}\n",
        is_write ? "mem_write" : "mem_read",
        (uint64_t)instr_addr, ts, (uint64_t)mem_addr, size);
    
    dr_write_file(outf, buf, len);
}

/* Call tracing */
static void
trace_call(app_pc instr_addr, app_pc target_addr)
{
    uint64_t ts = dr_atomic_add32_return_sum((volatile int *)&timestamp, 1);
    
    // In a full implementation, we'd look up the symbol for target_addr.
    // For now, we emit the call target address as the function name.
    char buf[512];
    int len = dr_snprintf(buf, sizeof(buf), 
        "{\"event_type\": \"func_call\", \"address\": %llu, \"timestamp\": %llu, \"thread_id\": 0, \"func_name\": \"func_%llx\"}\n",
        (uint64_t)instr_addr, ts, (uint64_t)target_addr);
    
    dr_write_file(outf, buf, len);
}

static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where,
               app_pc pc, opnd_t ref, bool is_write)
{
    /* We use clean calls to log memory accesses. For production, inline 
       instrumentation is much faster, but clean calls are safer for prototyping. */
    dr_insert_clean_call(drcontext, ilist, where, (void *)trace_mem,
                         false, /* save fpstate */
                         4,
                         OPND_CREATE_INTPTR(pc),
                         OPND_CREATE_INTPTR(opnd_get_addr(ref)),
                         OPND_CREATE_INT32(opnd_size_in_bytes(opnd_get_size(ref))),
                         OPND_CREATE_INT32(is_write));
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb,
                      instr_t *inst, bool for_trace,
                      bool translating, void *user_data)
{
    // Skip if not translating
    if (translating) return DR_EMIT_DEFAULT;

    app_pc pc = instr_get_app_pc(inst);

    // Instrument Calls
    if (instr_is_call(inst)) {
        app_pc target = instr_get_branch_target_pc(inst);
        if (target != NULL) {
            dr_insert_clean_call(drcontext, bb, inst, (void *)trace_call,
                                 false, 2,
                                 OPND_CREATE_INTPTR(pc),
                                 OPND_CREATE_INTPTR(target));
        }
    }

    // Instrument Memory Reads & Writes
    // Too many memory events will explode the trace. We should selectively instrument
    // them, but for TRACEWISE-Lite Phase 1, we capture all data memory accesses.
    int num_srcs = instr_num_srcs(inst);
    for (int i = 0; i < num_srcs; i++) {
        if (opnd_is_memory_reference(instr_get_src(inst, i))) {
            instrument_mem(drcontext, bb, inst, pc, instr_get_src(inst, i), false);
        }
    }

    int num_dsts = instr_num_dsts(inst);
    for (int i = 0; i < num_dsts; i++) {
        if (opnd_is_memory_reference(instr_get_dst(inst, i))) {
            instrument_mem(drcontext, bb, inst, pc, instr_get_dst(inst, i), true);
        }
    }

    return DR_EMIT_DEFAULT;
}

/* Syscall instrumentation */
static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return true; /* intercept all syscalls */
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    uint64_t ts = dr_atomic_add32_return_sum((volatile int *)&timestamp, 1);
    char buf[512];
    int len = dr_snprintf(buf, sizeof(buf), 
        "{\"event_type\": \"syscall\", \"address\": 0, \"timestamp\": %llu, \"thread_id\": 0, \"syscall_number\": %d}\n",
        ts, sysnum);
    
    dr_write_file(outf, buf, len);
    return true;
}

/* Crash handling */
static dr_signal_action_t
event_signal(void *drcontext, dr_siginfo_t *siginfo)
{
    // If it's a segmentation fault or similar terminating signal
    if (siginfo->sig == 11 /* SIGSEGV */ || siginfo->sig == 6 /* SIGABRT */ || siginfo->sig == 4 /* SIGILL */) {
        uint64_t ts = dr_atomic_add32_return_sum((volatile int *)&timestamp, 1);
        char buf[512];
        int len = dr_snprintf(buf, sizeof(buf), 
            "{\"event_type\": \"crash\", \"address\": %llu, \"timestamp\": %llu, \"thread_id\": 0}\n",
            (uint64_t)siginfo->access_address, ts);
        
        dr_write_file(outf, buf, len);
    }
    return DR_SIGNAL_DELIVER;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("TRACEWISE-Lite DynamoRIO Client", "http://dynamorio.org/issues");

    // Output file
    const char *out_name = "trace_output.json";
    if (argc > 1) {
        out_name = argv[1];
    }
    outf = dr_open_file(out_name, DR_FILE_WRITE_OVERWRITE);
    DR_ASSERT(outf != INVALID_FILE);

    // Initialize drmgr
    drmgr_init();
    drx_init();

    // Register events
    dr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_signal_event(event_signal);
    
    dr_log(NULL, DR_LOG_ALL, 1, "TRACEWISE-Lite Client Initialized\n");
}

static void
event_exit(void)
{
    dr_close_file(outf);
    drx_exit();
    drmgr_exit();
}
