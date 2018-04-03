/******************************************************************
* Seccomp Toolkit by Remo Schweizer as a part of the master thesis
*                  ____ _ _  ___  _ _ _ 
*                 |_  /| | || . || | | |
*                  / / |   ||   || | | |
*                 /___||_|_||_|_||__/_/ 
*                      
* Seccomp bpf-source generator.
* This module has the same reduced interface like libseccomp
* to generate Berkeley packet filters for seccomp out of 
* simplified constructs.
*
* Contrary to libseccomp, no modifications are made to the rules.
* Tests have shown, that libseccomp modifies the rule structure
* which may lead to unwanted behavior, like removing rules
* wich parameter checks, when there are others without.
* unfortunately, there is no option to disable this behaviour
*
* As a result, this module does not perform any modifications
* to the rule layout,...
*
* The generated seccomp bpf source can be exported using the
* function sec_seccomp_export_bpf.
* Otherwise the use is exactly the same like libseccomp.
*
* //////////////////////////////////////////////////
*
*   // example source for the usage
*
*	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
*		perror("Could not start seccomp:");
*		exit(1);
*	}
*	
*	seccomp_ctx ctx;
*	ctx = sec_seccomp_init(SCMP_ACT_TRAP);
*	// Add general allow rules
*	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
*	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
*	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
*	sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
*	
*	if (sec_seccomp_load(ctx)== -1) {
*		perror("Seccomp could not be initialized. Abort Process.");
*		exit(1);
*	}
*
* //////////////////////////////////////////////////
*
* -----------------------------------------------------------------
* Version: 1.0
* -----------------------------------------------------------------
* 01.04.2018:       schwerem        Version 1.0 implemented
* -----------------------------------------------------------------
*
* TODO:
*  - Add support for bitwise flag comparisons (SCMP_CMP_MASKED_EQ)
*  - Add support for checks of 64 bit values (HIGH and LOW)
*  - Support rule modifications after the export function has been called
*  - Add support for SCMP_ACT_ALLOW
*  - Add support for additional ARCH structures besides (X86_64)
*  - Add support for BPF programs larger than 255 instructions
*
******************************************************************/

#ifndef SEC_SECCOMP_BPF_GENERATOR_H
#define SEC_SECCOMP_BPF_GENERATOR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef enum seccomp_instruction{ 
	LOAD,
	CHECK_AND_JUMP,
	EXECUTE,
	RULE_END
} seccomp_instruction;

typedef enum accumulator_value{ 
	NONE,
	ARCH,
	SYSTEMCALL,
	PARAMETER0,
	PARAMETER1,
	PARAMETER2,
	PARAMETER3,
	PARAMETER4,
	PARAMETER5
} accumulator_value;

typedef struct _seccomp_ctx {
	seccomp_instruction action;
	accumulator_value load_value;
	size_t jt;
	size_t jf;
	int comparator;
	uint32_t value;
	uint32_t seccomp_action;
	size_t code_line;

	accumulator_value accumulator_value;

	int is_final;
	struct _seccomp_ctx *next;
	struct _seccomp_ctx *previous;
} _seccomp_ctx, *seccomp_ctx;

seccomp_ctx sec_seccomp_init(uint32_t default_seccomp_action);
void sec_seccomp_rule_add(seccomp_ctx ctx, uint32_t action, int syscall_nr, uint32_t argc, ...);
void sec_seccomp_export_bpf(seccomp_ctx ctx, int fd);
int sec_seccomp_load(seccomp_ctx ctx);

#endif //SEC_SECCOMP_BPF_GENERATOR_H