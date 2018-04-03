/******************************************************************
* Seccomp Toolkit by Remo Schweizer as a part of the master thesis
*                  ____ _ _  ___  _ _ _ 
*                 |_  /| | || . || | | |
*                  / / |   ||   || | | |
*                 /___||_|_||_|_||__/_/ 
*                      
* Defines the core functions to interact with the tracee.
* offers function to manipulate data in the user space
* of the debugged application and retrieve data from it
*
* The module also offers fundamental functions for logging
* and helper functions for the emulation part
*
* -----------------------------------------------------------------
* Version: 1.0
* -----------------------------------------------------------------
* 01.04.2018:       schwerem        Version 1.0 implemented
* -----------------------------------------------------------------
*
******************************************************************/

#ifndef SEC_PTRACE_LIB_H
#define SEC_PTRACE_LIB_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>

// Defines the bool datatype
typedef int bool;
#define true 1
#define false 0

// Defines which parameter corresponds to which register
#if defined(__x86_64__) || defined(__x86_64) || defined(__amd64__) || defined(__amd64)
#define SC_NUMBER  (8 * ORIG_RAX)
#define SC_RETCODE (8 * RAX)
#define RET 		RAX
#define PAR1		RDI 
#define PAR2		RSI 
#define PAR3		RDX
#define PAR4		RCX
#define PAR5		R8
#define PAR6 		R9
#else
#define SC_NUMBER  (4 * ORIG_EAX)
#define SC_RETCODE (4 * EAX)
#define RET 		PLATTFORM_NOT_SUPPORTED_YET
#define PAR1		PLATTFORM_NOT_SUPPORTED_YET 
#define PAR2		PLATTFORM_NOT_SUPPORTED_YET 
#define PAR3		PLATTFORM_NOT_SUPPORTED_YET
#define PAR4		PLATTFORM_NOT_SUPPORTED_YET
#define PAR5		PLATTFORM_NOT_SUPPORTED_YET
#define PAR6 		PLATTFORM_NOT_SUPPORTED_YET
#endif

// Defines tracer constants sent thorugh the PTRACE_GETEVENTMSG event
#define PTRACE_SYSCALL_SHIFT		12
#define PTRACE_DBG_ALLOW			0x01
#define PTRACE_DBG_TERMINATE		0x02
#define PTRACE_DBG_MODIFY			0x04
#define PTRACE_DBG_SKIP				0x08
#define PTRACE_EXECUTE				0x10
#define PTRACE_GENERAL_RULE			0x20

// Structure containing data about the match of a string comparison
struct match_info{
	bool match;
	int start;
	int length;
	int reference_length;
	char *realpath;
};

// Enumeration of possible rule actions
enum sec_rule_action{
	SEC_ACTION_NONE,
	SEC_ACTION_ALLOW,
	SEC_ACTION_SKIP,
	SEC_ACTION_MODIFY,
	SEC_ACTION_TERMINATE,
	SEC_ACTION_TRAP
};

// Structure defining the action of a rule
struct sec_rule_result {
	enum sec_rule_action action;
	void *new_value;
	int size;
};

// Defines the red zone for stack manipulations according to ABI
#define RED_ZONE	128

// General helper functions
char *getRealPath(const char *string);
bool stringMatchesStart(const char *check, const char *string, size_t string_length, bool is_path);
bool stringMatchesEnd(const char *check, const char *string, size_t string_length, bool is_path);
bool fdPathMatchesStart(pid_t pid, const char *check, int fd);
bool fdPathMatchesEnd(pid_t pid, const char *check, int fd);
struct sec_rule_result changeStringOnStartMatch(const char *check, const char *string, size_t string_length, const char *new_string, bool is_path);
struct sec_rule_result changeStringOnEndMatch(const char *check, const char *string, size_t string_length, const char *new_string, bool is_path);
void writeLog(int level, char *string);

// Functions to interact with a target process (Tracee)
int readInt(pid_t pid, int param_register);
void* readData(pid_t pid, int param_register, size_t size);
char* readTerminatedString(pid_t pid, int param_register);

void modifyPrimitiveParameter(pid_t pid, int param_register, int new_value);
void modifyParameter(pid_t pid, int param_register, void *new_data, int new_size);
void modifyReturnParameter(pid_t pid, int param_register, void *new_data, int target_buffer_size);
void modifyReturnValue(pid_t pid, int value);
void invalidateSystemcall(pid_t pid);

void executeRuleResult(pid_t pid, struct sec_rule_result, int param_register, bool isOutParam);

#endif  //SEC_PTRACE_LIB_H