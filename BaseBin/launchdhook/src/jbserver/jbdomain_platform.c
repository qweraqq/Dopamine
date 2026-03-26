#include "jbserver_global.h"
#include "jbsettings.h"

#include <libjailbreak/codesign.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/kernel.h>
#include <libjailbreak/primitives.h>
#include <libjailbreak/info.h>

extern void systemwide_domain_set_enabled(bool enabled);

static bool platform_domain_allowed(audit_token_t clientToken)
{
	pid_t pid = audit_token_to_pid(clientToken);
	uint32_t csflags = 0;
	if (csops_audittoken(pid, CS_OPS_STATUS, &csflags, sizeof(csflags), &clientToken) != 0) return false;
	return (csflags & CS_PLATFORM_BINARY);
}

int platform_clear_process_noattach(uint64_t pid, bool preflight, bool hideTraced)
{
    // 1. Safely resolve the target process
    uint64_t proc = proc_find(pid);
    if (!proc) return -1;
    
    // UAF Mitigation: Verify the PID matches
    off_t off_pid = koffsetof(proc, pid);
    if (kread32(proc + off_pid) != (uint32_t)pid) return -1;

    // Calculate the exact kernel virtual address of proc->p_lflag
    uint64_t flag_ptr = proc + koffsetof(proc, flag) + sizeof(uint32_t);
    
    // Resolve our atomic kernel functions from the jailbreak info
    uint64_t kaddr_OSBitAndAtomic = jbinfo_get_symbol("OSBitAndAtomic");
    uint64_t kaddr_OSBitOrAtomic  = jbinfo_get_symbol("OSBitOrAtomic");
    
    if (!kaddr_OSBitAndAtomic || !kaddr_OSBitOrAtomic) {
        // Fallback to the unsafe method if patchfinder failed, or abort
        return platform_clear_process_noattach_fallback(pid, preflight, hideTraced); 
    }

    if (preflight) {
        // PRE-FLIGHT: We want to clear P_LNOATTACH and set P_LCLEARED_NOATTACH
        
        // 1st kcall: Atomic AND to clear P_LNOATTACH
        // Equivalent to: OSBitAndAtomic(~P_LNOATTACH, flag_ptr);
        kcall(kaddr_OSBitAndAtomic, 2, (uint64_t)(~P_LNOATTACH), flag_ptr);
        
        // 2nd kcall: Atomic OR to set our secret marker
        // Equivalent to: OSBitOrAtomic(P_LCLEARED_NOATTACH, flag_ptr);
        kcall(kaddr_OSBitOrAtomic, 2, (uint64_t)P_LCLEARED_NOATTACH, flag_ptr);
        
    } else {
        // POST-FLIGHT: Restore original state and hide P_LTRACED
        
        // Check if our secret marker is present (safe to use standard kread32 for a check)
        uint32_t current_flag = kread32(flag_ptr);
        
        if ((current_flag & P_LCLEARED_NOATTACH) != 0) {
            // Atomic AND to clear our secret marker
            kcall(kaddr_OSBitAndAtomic, 2, (uint64_t)(~P_LCLEARED_NOATTACH), flag_ptr);
            
            // Atomic OR to restore the app's original PT_DENY_ATTACH state
            kcall(kaddr_OSBitOrAtomic, 2, (uint64_t)P_LNOATTACH, flag_ptr);
        }
        
        if (hideTraced) {
            // Atomic AND to clear the P_LTRACED flag set by the kernel during attach
            kcall(kaddr_OSBitAndAtomic, 2, (uint64_t)(~P_LTRACED), flag_ptr);
        }
    }
    
    // Final UAF check to ensure we didn't operate on a reassigned struct
    if (kread32(proc + off_pid) != (uint32_t)pid) return -1;

    return 0;
}

int platform_clear_process_noattach_fallback(uint64_t pid, bool preflight, bool hideTraced)
{
    uint64_t proc = proc_find(pid);
    if (!proc) return -1;

	off_t off_pid = koffsetof(proc, pid);
	if (kread32(proc + off_pid) != (uint32_t)pid) return -1;

    // p_lflag stands next to p_flag
    off_t off_lflag = koffsetof(proc, flag) + sizeof(uint32_t);
    uint32_t flag = kread32(proc + off_lflag);
    if (preflight) {
        if ((flag & P_LNOATTACH) == 0) return 0;
        // clear P_LNOATTACH for ptrace
        // borrow an unused flag bit to indicate we cleared deny-attach
        flag &= ~P_LNOATTACH;
        flag |= P_LCLEARED_NOATTACH;
    } else {
        if ((flag & P_LCLEARED_NOATTACH) != 0) {
            // restore P_LNOATTACH
            flag &= ~P_LCLEARED_NOATTACH;
            flag |= P_LNOATTACH;
        }
        if (hideTraced) {
            // hide the fact that the process is being traced
            // FIXME: this might cause undefined behavior with debugger?
            flag &= ~P_LTRACED;
        }
    }
    kwrite32(proc + off_lflag, flag);

	if (kread32(proc + off_pid) != (uint32_t)pid) return -1;
	
    return 0;
}

int platform_set_process_debugged(uint64_t pid, bool fullyDebugged)
{
	uint64_t proc = proc_find(pid);
	if (!proc) return -1;
	cs_allow_invalid(proc, fullyDebugged);
	return 0;
}

static int platform_stage_jailbreak_update(const char *updateTar)
{
	if (!access(updateTar, F_OK)) {
		setenv("STAGED_JAILBREAK_UPDATE", updateTar, 1);
		return 0;
	}
	return 1;
}

struct jbserver_domain gPlatformDomain = {
	.permissionHandler = platform_domain_allowed,
	.actions = {
		// JBS_PLATFORM_SET_PROCESS_DEBUGGED
		{
			.handler = platform_set_process_debugged,
			.args = (jbserver_arg[]){
				{ .name = "pid", .type = JBS_TYPE_UINT64, .out = false },
				{ .name = "fully-debugged", .type = JBS_TYPE_BOOL, .out = false },
				{ 0 },
			},
		},
		// JBS_PLATFORM_STAGE_JAILBREAK_UPDATE
		{
			.handler = platform_stage_jailbreak_update,
			.args = (jbserver_arg[]){
				{ .name = "update-tar", .type = JBS_TYPE_STRING, .out = false },
				{ 0 },
			},
		},
		// JBS_PLATFORM_JBSETTINGS_SET
		{
			.handler = jbsettings_set,
			.args = (jbserver_arg[]){
				{ .name = "key", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "value", .type = JBS_TYPE_XPC_GENERIC, .out = false },
				{ 0 },
			},
		},
		// JBS_PLATFORM_SET_SYSTEMWIDE_DOMAIN_ENABLED
		{
			.handler = systemwide_domain_set_enabled,
			.args = (jbserver_arg[]){
				{ .name = "enabled", .type = JBS_TYPE_BOOL, .out = false },
				{ 0 },
			},
		},
        // JBS_PLATFORM_CLEAR_PROCESS_NOATTACH
        {
            .handler = platform_clear_process_noattach,
            .args = (jbserver_arg[]){
                { .name = "pid", .type = JBS_TYPE_UINT64, .out = false },
                { .name = "preflight", .type = JBS_TYPE_BOOL, .out = false },
                { .name = "hide-traced", .type = JBS_TYPE_BOOL, .out = false },
                { 0 },
            },
        },
		{ 0 },
	},
};