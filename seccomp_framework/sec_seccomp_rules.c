#include <stdlib.h>

#include <stdio.h>
#include <seccomp.h>
#include <fcntl.h>
#include <errno.h>
#include "sec_seccomp_bpf_generator.h"
#include "sec_seccomp_rules.h"
#include "sec_ptrace_lib.h"
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/time.h>
#include <linux/seccomp.h>

void loadClientSeccompRules(){
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("Could not start seccomp:");
		exit(1);
	}
	
	seccomp_ctx ctx;
	ctx = sec_seccomp_init(SCMP_ACT_TRAP);
	// Add general allow rules
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(exit), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(read), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(getrlimit), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(write), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(fstat), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(close), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(exit_group), 0);
	// Add specific allow rules
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(fcntl), 1, SCMP_A1(SCMP_CMP_EQ, F_GETFL));
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(setrlimit), 1, SCMP_A0(SCMP_CMP_EQ, RLIMIT_CPU));
	// Add specific skip rules
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_SKIP | PTRACE_GENERAL_RULE), SCMP_SYS(fcntl), 1, SCMP_A1(SCMP_CMP_EQ, F_GETFD));
	// Add general modify rules
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_MODIFY | PTRACE_GENERAL_RULE), SCMP_SYS(setrlimit), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_MODIFY | PTRACE_GENERAL_RULE), SCMP_SYS(dup), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_MODIFY | PTRACE_GENERAL_RULE), SCMP_SYS(getcwd), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_MODIFY | PTRACE_GENERAL_RULE), SCMP_SYS(gettimeofday), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_MODIFY | PTRACE_GENERAL_RULE), SCMP_SYS(chdir), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_MODIFY | PTRACE_GENERAL_RULE), SCMP_SYS(open), 0);
	// Add default actions for custom system calls
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(chdir), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_TERMINATE | PTRACE_GENERAL_RULE), SCMP_SYS(setrlimit), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_SKIP | PTRACE_GENERAL_RULE), SCMP_SYS(open), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_TERMINATE | PTRACE_GENERAL_RULE), SCMP_SYS(fcntl), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_DBG_ALLOW | PTRACE_GENERAL_RULE), SCMP_SYS(dup), 0);
	
	FILE *f = fopen("debug_seccomp_bpf_Client.txt", "w");
	sec_seccomp_export_bpf(ctx, fileno(f));
	fclose(f);
	
	if (sec_seccomp_load(ctx)== -1) {
		perror("Seccomp could not be initialized. Abort Process.");
		exit(1);
	}
}

void loadTracerSeccompRules(){
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("Could not start seccomp:");
		exit(1);
	}
	
	seccomp_ctx ctx;
	ctx = sec_seccomp_init(SCMP_ACT_TRAP);
	// Add general tracer allow rules
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ptrace), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
	// Add general allow rules
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	// Add specific allow rules
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1, SCMP_A1(SCMP_CMP_EQ, F_GETFL));
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setrlimit), 1, SCMP_A0(SCMP_CMP_EQ, RLIMIT_CPU));
	// Add specific skip rules
	sec_seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fcntl), 1, SCMP_A1(SCMP_CMP_EQ, F_GETFD));
	// Add general modify rules
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setrlimit), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	// Add default actions for custom system calls
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(setrlimit), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fcntl), 0);
	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
	
	FILE *f = fopen("debug_seccomp_bpf_Tracer.txt", "w");
	sec_seccomp_export_bpf(ctx, fileno(f));
	fclose(f);
	
	if (sec_seccomp_load(ctx)== -1) {
		perror("Seccomp could not be initialized. Abort Process.");
		exit(1);
	}
}

