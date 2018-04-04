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

#include <seccomp.h>
#include "sec_seccomp_bpf_generator.h"
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <sys/prctl.h>

typedef int bool;
#define true 1
#define false 0

// macros from the official bpf.h header
#define LD_SYSCALL_NR (offsetof(struct seccomp_data, nr))
#define LD_ARCH_NR (offsetof(struct seccomp_data, arch))

#if defined(__LITTLE_ENDIAN)
#define LD_LO_ARG(idx) offsetof(struct seccomp_data, args[(idx)])
#define LD_HI_ARG(idx) offsetof(struct seccomp_data, args[(idx)]) + sizeof(__u32)
#elif defined(__BIG_ENDIAN)
#define LD_LO_ARG(idx) offsetof(struct seccomp_data, args[(idx)]) + sizeof(__u32)
#define LD_HI_ARG(idx) offsetof(struct seccomp_data, args[(idx)])
#else
#error "Unknown endianness"
#endif

// define prototypes
int addAction(seccomp_ctx ctx, seccomp_instruction action, accumulator_value load_value, int comparator, uint32_t value, uint32_t seccomp_action);
int addRuleEnd(seccomp_ctx ctx);
int addParameterLoad(seccomp_ctx ctx, accumulator_value load_value);
int addParameterCheck(seccomp_ctx ctx, int comparator, uint32_t value, uint32_t seccomp_action);
int addExecution(seccomp_ctx ctx, uint32_t seccomp_action);
void addDefaultRule(seccomp_ctx ctx);
void addArchCheck(seccomp_ctx ctx);

bool isLastCheckOfRule(seccomp_ctx start);
int findNextRuleStart(seccomp_ctx start);
int findExecutionIndex(seccomp_ctx start, uint32_t seccomp_action);

int countStatements(seccomp_ctx ctx);
void finalizeSeccompRules(seccomp_ctx ctx);
void cleanupRuleSet(seccomp_ctx ctx);
void calculateJumps(seccomp_ctx ctx);

void freeSeccompContext(seccomp_ctx ctx);
struct sock_fprog buildFilterProg(seccomp_ctx ctx);
struct sock_filter buildFilter(seccomp_ctx pt);



/*
* Description:
* Adds an action to the list of instructions
* base function to add any kind of instruction type
* to the bpf program filter
*
* Parameters:
* ctx: filter context
* action: action of the statement / jump
* load_value: value which have to be active in the accumulator
* comparator: comparator (SCMP_CMP_EQ,...)
* value: value which should be checked
* seccomp_action: action of the rule (SCMP_ACT_ALLOW,...)
*
* Return:
* Code line of the instruction
*/
int addAction(seccomp_ctx ctx, seccomp_instruction action, accumulator_value load_value, int comparator, uint32_t value, uint32_t seccomp_action){
	seccomp_ctx entry = malloc(sizeof(_seccomp_ctx));

	entry->action = action;
	entry->load_value = load_value;
	entry->jt = 0;
	entry->jf = 0;
	entry->comparator = comparator;
	entry->value = value; 
	entry->accumulator_value = NONE;
	entry->seccomp_action = seccomp_action;
	entry->next = NULL;
	entry->previous = NULL;

	seccomp_ctx last = ctx;
	while (last->next != NULL){
		last = last->next;
	}
	last->next = entry;
	entry->previous = last;

	if (action != RULE_END){
		entry->code_line = last->code_line + 1;
	} else {
		entry->code_line = last->code_line;
	}

	return entry->code_line;
}


/*
* Description:
* Adds a parameter load instruction to the program
*
* Parameters:
* ctx: filter context
* load_value: value which have to be active in the accumulator
*
* Return:
* Code line of the instruction
*/
int addParameterLoad(seccomp_ctx ctx, accumulator_value load_value){
	int index = -1;

	if (ctx->accumulator_value != load_value){
		index = addAction(ctx, LOAD, load_value, 0, 0, 0);
		ctx->accumulator_value = load_value;
	}

	return index;
}


/*
* Description:
* Adds a parameter check instruction to the program
*
* Parameters:
* ctx: filter context
* comparator: comparator (SCMP_CMP_EQ,...)
* value: value which should be checked
* seccomp_action: action of the rule (SCMP_ACT_ALLOW,...)
*
* Return:
* Code line of the instruction
*/
int addParameterCheck(seccomp_ctx ctx, int comparator, uint32_t value, uint32_t seccomp_action){
	return addAction(ctx, CHECK_AND_JUMP, ctx->accumulator_value, comparator, value, seccomp_action);
}

/*
* Description:
* Adds a non existing instruction called
* RULE_END to the program
* This rule is used to detect boundaries
* between the single rules and the jump calculation
*
* Parameters:
* ctx: filter context
*
* Return:
* Code line of the instruction
*/
int addRuleEnd(seccomp_ctx ctx){
	return addAction(ctx, RULE_END, NONE, 0, 0, 0);
}

/*
* Description:
* Adds the arch check instruction to the program
*
* Parameters:
* ctx: filter context
*/
void addArchCheck(seccomp_ctx ctx){
	addParameterLoad(ctx, ARCH);
	addParameterCheck(ctx, SCMP_CMP_NE, AUDIT_ARCH_X86_64, SCMP_ACT_KILL);
	addRuleEnd(ctx);
}


/*
* Description:
* Adds the execution (return) of a seccomp action
* to the bpf-program
*
* Parameters:
* ctx: filter context
* seccomp_action: action of the rule (SCMP_ACT_ALLOW,...)
*
* Return:
* Code line of the instruction
*/
int addExecution(seccomp_ctx ctx, uint32_t seccomp_action){
	return addAction(ctx, EXECUTE, NONE, 0, 0, seccomp_action);
}


/*
* Description:
* Searches the code line for the given seccomp_action
* execution (reduces the number of instructions)
* If it does not exist, it is appended to the end of the
* program
*
* Parameters:
* ctx: filter context
* seccomp_action: action of the rule (SCMP_ACT_ALLOW,...)
*
* Return:
* Code line of the instruction
*/
int findExecutionIndex(seccomp_ctx start, uint32_t seccomp_action){
	seccomp_ctx pt = start;
	bool found = false;
	int index = -1;

	while(pt != NULL && found == false){
		if (pt->action == EXECUTE && pt->seccomp_action == seccomp_action){
			index = pt->code_line;
			found = true;
		}

		pt = pt->next;
	}

	if (found == false){
		index = addExecution(start, seccomp_action);
	}

	return index;
}


/*
* Description:
* Finds the code line on which the next rule check 
* begins. Required for the jump calculation
*
* Parameters:
* ctx: filter context after which the search takes place
*
* Return:
* Code line of the instruction
*/
int findNextRuleStart(seccomp_ctx start){
	seccomp_ctx pt = start->next;
	int index = -1;

	while(pt != NULL){
		if (pt->action == RULE_END && pt->next != NULL){
			index = pt->next->code_line;
			break;	
		}

		pt = pt->next;
	}

	return index;
}


/*
* Description:
* Returns if the instruction is the last
* instruction of the rule.
*
* Parameters:
* ctx: filter context
*
* Return:
* true if the next rule defines the rule end
*/
bool isLastCheckOfRule(seccomp_ctx start){
	if (start->next == NULL){
		return true;
	} else {
		return start->next->action == RULE_END;
	}
}


/*
* Description:
* Calculates the jumps for the BPF instructions
*
* Parameters:
* ctx: filter context
*/
void calculateJumps(seccomp_ctx ctx){
	// evaluate the number of instructions
	seccomp_ctx pt = ctx->next;
	while (pt != NULL){
		if (pt->action == CHECK_AND_JUMP){
			if (isLastCheckOfRule(pt)){
				int execution_index = findExecutionIndex(pt, pt->seccomp_action);
				pt->jt = execution_index - pt->code_line - 1;
				pt->jf = 0;
			} else {
				int next_rule = findNextRuleStart(pt);
				pt->jt = 0;
				pt->jf = next_rule - pt->code_line - 1;
			}
		} 

		pt = pt->next;
	}
}


/*
* Description:
* Cleans up the seccomp bpf rules, which means
* that the operations SCMP_CMP_LT, LE and NE
* are transformed into GE, GT and EQ, because
* the primitive format does not support those
*
* Parameters:
* ctx: filter context
*/
void cleanupRuleSet(seccomp_ctx ctx){
	seccomp_ctx pt = ctx->next;
	while (pt != NULL){
		bool performSwap = false;

		// BPF does not know !=, < and <= so we have to swap the jumps
		// and modify the comparator
		switch(pt->comparator){
			case SCMP_CMP_LT:
				pt->comparator = SCMP_CMP_GE;
				performSwap = true;
				break;
			case SCMP_CMP_LE:
				pt->comparator = SCMP_CMP_GT;
				performSwap = true;
				break;
			case SCMP_CMP_NE:
				pt->comparator = SCMP_CMP_EQ;
				performSwap = true;
				break;
			default:
			performSwap = false; 
		}

		// swap the jumps
		if (performSwap == true){
			pt->jt = pt->jt ^ pt-> jf;
			pt->jf = pt->jf ^ pt-> jt;
			pt->jt = pt->jt ^ pt-> jf;
		}

		pt = pt->next;
	}
}


/*
* Description:
* Adds the default action to the program
*
* Parameters:
* ctx: filter context
*/
void addDefaultRule(seccomp_ctx ctx){
	addExecution(ctx, ctx->seccomp_action);
}


/*
* Description:
* Finalizes the bpf filter program
* If it is not done, the following action take place
* - add the default execution rule
* - calculate the jumps between the instructions
* - transform checks so bpf supports them
*
* Parameters:
* ctx: filter context
*/
void finalizeSeccompRules(seccomp_ctx ctx){
	if (ctx->is_final == false){
		addDefaultRule(ctx);
		calculateJumps(ctx);
		cleanupRuleSet(ctx);
		ctx->is_final = true;
	}
}


/*
* Description:
* Counts the number of bpf instructions
*
* Parameters:
* ctx: filter context
*
* Return:
* Code number of bpf instructions
*/
int countStatements(seccomp_ctx ctx){
	int count = 0;

	seccomp_ctx pt = ctx->next;
	while (pt != NULL){
		if (pt->action != RULE_END){
			++count;
		}

		pt = pt->next;
	}

	return count;
}


/*
* Description:
* Builds a single bpf filter instruction
*
* Parameters:
* ctx: filter context
*
* Return:
* sock_filter for the instruction
*/
struct sock_filter buildFilter(seccomp_ctx pt){
	struct sock_filter filter = {0, 0, 0, 0};

	if (pt->action == LOAD){
		filter.code = BPF_LD | BPF_W | BPF_ABS;
		switch(pt->load_value){
			case ARCH:
				filter.k = LD_ARCH_NR;
				break;
			case SYSTEMCALL:
				filter.k = LD_SYSCALL_NR;
				break;
			case PARAMETER0:
				filter.k = LD_LO_ARG(0);
				break;
			case PARAMETER1:
				filter.k = LD_LO_ARG(1);
				break;
			case PARAMETER2:
				filter.k = LD_LO_ARG(2);
				break;	
			case PARAMETER3:
				filter.k = LD_LO_ARG(3);
				break;	
			case PARAMETER4:
				filter.k = LD_LO_ARG(4);
				break;	
			case PARAMETER5:
				filter.k = LD_LO_ARG(5);
				break;	
			default:
				filter.k = 0;
				filter.code = 0;
		}
	} else if (pt->action == EXECUTE) {
		filter.code = BPF_RET | BPF_K;
		switch(pt->seccomp_action & 0xFFFF0000U){
			case SCMP_ACT_KILL:
				filter.k = SECCOMP_RET_KILL;
				break;
			case SCMP_ACT_TRAP:
				filter.k = SECCOMP_RET_TRAP;
				break;
			case SCMP_ACT_ERRNO(0):
				filter.k = SECCOMP_RET_ERRNO | (pt->seccomp_action & 0x0000FFFFFU & SECCOMP_RET_DATA);
				break;
			case SCMP_ACT_TRACE(0):
				filter.k = SECCOMP_RET_TRACE | (pt->seccomp_action & 0x0000FFFFFU & SECCOMP_RET_DATA);
				break;
			case SCMP_ACT_ALLOW:
				filter.k = SECCOMP_RET_ALLOW;
				break;
			default:
				filter.k = 0;
				filter.code = 0;
		}
	} else if (pt->action == CHECK_AND_JUMP) {
		filter.code = BPF_JMP | BPF_K;
		filter.jt = pt->jt;
		filter.jf = pt->jf;
		filter.k = pt->value;
		switch (pt->comparator){
			case SCMP_CMP_EQ:
				filter.code |= BPF_JEQ;
				break;
			case SCMP_CMP_GE:
				filter.code |= BPF_JGE;
				break;
			case SCMP_CMP_GT:
				filter.code |= BPF_JGT;
				break;
			default:
				filter.k = 0;
				filter.code = 0;
				filter.jt = 0;
				filter.jf = 0;
		}
	}

	return filter;
}


/*
* Description:
* Builds the seccomp filter program which can
* be loaded into seccomp
*
* Parameters:
* ctx: filter context
*
* Return:
* sock_fprog filter program
*/
struct sock_fprog buildFilterProg(seccomp_ctx ctx){
	int loc = countStatements(ctx);
	int index = 0;
	struct sock_filter *filter = malloc(loc * sizeof(struct sock_filter));

	seccomp_ctx pt = ctx->next;
	while (pt != NULL){
		if (pt->action != RULE_END){
			filter[index] = buildFilter(pt);
			++index;
		}

		pt = pt->next;
	}

	return (struct sock_fprog){.len = loc, .filter = filter};
}

void freeSeccompContext(seccomp_ctx ctx){
	seccomp_ctx node = ctx;
	while (node != NULL){
		seccomp_ctx temp = node;
		node = node->next;
		free(temp);
	}
}

/*
* Description:
* Generates and loads the seccomp bpf program
* at the same time, the context object is freed (destroyed)
*
* Parameters:
* ctx: filter context
*
* Return:
* return value of the prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,...) instruction
* -1 if it fails to initialize the filter
*/
int sec_seccomp_load(seccomp_ctx ctx){
	finalizeSeccompRules(ctx);

	struct sock_fprog prog = buildFilterProg(ctx);

	freeSeccompContext(ctx);

	int result = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	free(prog.filter);
	return result;
}


/*
* Description:
* Exports the bpf program as a string representation 
* to the specified file descriptor
*
* Parameters:
* ctx: filter context
* fd: file descriptor
*/
void sec_seccomp_export_bpf(seccomp_ctx ctx, int fd){
	finalizeSeccompRules(ctx);

	FILE *f = fdopen(fd, "w");

	seccomp_ctx pt = ctx->next;
	fprintf(f, "Seccomp BPF Output for %d statements\n------------------------------\n\n", countStatements(ctx));
	while (pt != NULL){
		if (pt->action == LOAD){
			char data[50];
			switch(pt->load_value){
				case ARCH:
					strcpy(data, "(offsetof(struct seccomp_data, arch)");
					break;
				case SYSTEMCALL:
					strcpy(data, "(offsetof(struct seccomp_data, nr)");
					break;
				case PARAMETER0:
					strcpy(data, "(offsetof(struct seccomp_data, args[0])");
					break;
				case PARAMETER1:
					strcpy(data, "(offsetof(struct seccomp_data, args[1])");
					break;
				case PARAMETER2:
					strcpy(data, "(offsetof(struct seccomp_data, args[2])");
					break;	
				case PARAMETER3:
					strcpy(data, "(offsetof(struct seccomp_data, args[3])");
					break;	
				case PARAMETER4:
					strcpy(data, "(offsetof(struct seccomp_data, args[4])");
					break;	
				case PARAMETER5:
					strcpy(data, "(offsetof(struct seccomp_data, args[5])");
					break;	
				default:
					strcpy(data, "INVALID_CHECK");
			}
			fprintf(f, "BPF_STMT(BPF_LD | BPF_W | BPF_ABS, %s),\n", data);
		} else if (pt->action == EXECUTE) {
			char act[50];
			switch(pt->seccomp_action & 0xFFFF0000U){
				case SCMP_ACT_KILL:
					strcpy(act, "SECCOMP_RET_KILL");
					break;
				case SCMP_ACT_TRAP:
					strcpy(act, "SECCOMP_RET_TRAP");
					break;
				case SCMP_ACT_ERRNO(0):
					sprintf(act, "SECCOMP_RET_ERRNO | (%u & SECCOMP_RET_DATA)", pt->seccomp_action & 0x0000FFFFFU);
					break;
				case SCMP_ACT_TRACE(0):
					sprintf(act, "SECCOMP_RET_TRACE | (%u & SECCOMP_RET_DATA)", pt->seccomp_action & 0x0000FFFFFU);
					break;
				case SCMP_ACT_ALLOW:
					strcpy(act, "SECCOMP_RET_ALLOW");
					printf("allow\n");
					break;
				default:
					strcpy(act, "INVALID_CHECK");
			}
			fprintf(f, "BPF_STMT(BPF_RET | BPF_K, %s),\n", act);
		} else if (pt->action == CHECK_AND_JUMP) {
			char jmp[10];
			switch (pt->comparator){
				case SCMP_CMP_EQ:
					strcpy(jmp, "BPF_JEQ");
					break;
				case SCMP_CMP_GE:
					strcpy(jmp, "BPF_JGE");
					break;
				case SCMP_CMP_GT:
					strcpy(jmp, "BPF_JGT");
					break;
				default:
					strcpy(jmp, "INVALID_CHECK");
			}
			fprintf(f, "BPF_JMP(BPF_JMP | %s | BPF_K, %u, %ld, %ld),\n", jmp, pt->value, pt->jt, pt->jf);
		} else if (pt->action == RULE_END){
			fprintf(f, "\n");
		}

		pt = pt->next;
	}

	fclose(f);
}

/*
* Description:
* Initializes the seccomp context structure
* storing all the information about the bpf program
*
* Parameters:
* default_seccomp_action: default action of the seccomp filter program
*
* Return:
* seccomp_ctx context object
*/
seccomp_ctx sec_seccomp_init(uint32_t default_seccomp_action){
	seccomp_ctx ctx = malloc(sizeof(_seccomp_ctx));

	ctx->action = NONE;
	ctx->next = NULL;
	ctx->previous = NULL;
	ctx->accumulator_value = NONE;
	ctx->seccomp_action = default_seccomp_action;
	ctx->code_line = -1;
	ctx->is_final = false;

	addArchCheck(ctx);

	return ctx;
}

/*
* Description:
* Adds a rule to the bpf filter program
*
* Parameters:
* ctx: filter context
* action: action of the statement / jump
* syscall_nr: syscall nr to which the check is applied
* argc: number of arguments (parameter checks)
* ...: variadic amount of seccomp parameter checks
*/
void sec_seccomp_rule_add(seccomp_ctx ctx, uint32_t action, int syscall_nr, uint32_t argc, ...){
	// check the system call
	addParameterLoad(ctx, SYSTEMCALL);
	addParameterCheck(ctx, SCMP_CMP_EQ, syscall_nr, action);

	va_list params;
	va_start(params, argc);

	for (size_t i = 0; i < argc; i++){
		struct scmp_arg_cmp comparison = va_arg(params, struct scmp_arg_cmp);

		accumulator_value param = NONE;
		switch(comparison.arg){
			case 0:
				param = PARAMETER0;
				break;
			case 1:
				param = PARAMETER1;
				break;
			case 2:
				param = PARAMETER2;
				break;
			case 3:
				param = PARAMETER3;
				break;
			case 4:
				param = PARAMETER4;
				break;
			case 5:
				param = PARAMETER5;
				break;
			default:
				param = NONE;
		}

		addParameterLoad(ctx, param);
		addParameterCheck(ctx, comparison.op, comparison.datum_a, action);
	}

	addRuleEnd(ctx);

	va_end(params);
}