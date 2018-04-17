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
#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <sys/types.h>
#include <dirent.h>

#include "sec_ptrace_lib.h"

extern int errno;


//-------------------------------------------------------
//
// General helper functions
//
//-------------------------------------------------------

/*
* Description:
* Returns the working directory for a given process
* Note that the function uses realpath to
* resolve /proc/pid/cwd
* Tests have shown, that readlink can return wrong
* path information, when for example the client has
* changed the directory.
* In this case, read link has returned the old path
* after a call of getcwd, the path was resolved
* correctly. Realpath did not had that problem
*
* Parameter:
* pid: process id of the calling process
*
* Return
* Working directory or NULL if it failed
*/
char *getPidCwd(pid_t pid){
	char cwd_path[30] = {"/0"};

	sprintf(cwd_path, "/proc/%d/cwd", pid);
	char *pid_cwd = realpath(cwd_path, NULL);

	errno = 0;
	return pid_cwd;
}

/*
* Description:
* Resolves a path and returns the resolved one
* contrary to the realpath functoin of glibc
* this version allows to apply the realpath
* function for an different process
*
* this is achieved by temporary changing the working
* directory
*
* Parameters:
* pid: process id of the calling process
* string: path to resolve
*
* Return;
* Resolved path or NULL if not successfull
*/
char *getPidRealPath(pid_t pid, const char *string){
	bool cwd_changed = false;
	char *pid_cwd = getPidCwd(pid);
	char *own_cwd = getcwd(NULL, 0);

	// check dirs we got
	if (pid_cwd == NULL || own_cwd == NULL){
		return NULL;
	} 

	// change to dir of pid
	if (chdir(pid_cwd) == -1){
		cwd_changed = true;
	}

	// perform realpath action
	char *res = realpath(string, NULL);

	if (cwd_changed == true){
		// change back to old cwd
		chdir(own_cwd);
	}

	// free data
	if (pid_cwd != NULL){
		free(pid_cwd);
	} 
	if (own_cwd != NULL){
		free(own_cwd);
	}

	errno = 0;
	return res;
}

/*
* Description:
* Checks if a string matches a specific substring at the beginning
*
* INFO:
* Returns a match_info struct containing the following information:
* .match: true if the beginning matches
* .start: start of the match (index)
* .length: length of the match (length)
* .reference_length: real length of the string to check
*                    necessary, because the string can be shorter than the passed size of the buffer
* .realpath_string: pointer to the resolved path to check if it was one (needs to be freed)
* .realpath_check: pointer to the resolved check path (needs to be freed)
*
* Parameters:
* pid: process id of the calling process
* check: string to match on the parameter string
* string: string which should be checked
* string_length: length of the string buffer (must not equal to the string length inside)
* is_path: defines if the string represents a path (will be resolved)
*/
struct match_info compareStringStart(pid_t pid, const char *check, const char *string, size_t string_length, bool is_path){
	bool result = false;
	size_t check_length = 0;
	size_t real_length = 0;
	char *real_string = NULL;
	char *real_check = NULL;

	if (is_path == true){
		real_string = getPidRealPath(pid, string);
		real_check = getPidRealPath(pid, check);
	}

	if (real_string != NULL && real_check != NULL){
		string_length = PATH_MAX;
		check_length = strlen(real_check);
		
		// find the real string end, because the string can be shorter than the buffer size
		for(real_length = 0; real_length < string_length && real_string[real_length] != '\0'; ++real_length){}

		if (real_length >= check_length){
			result = (strncmp(real_check, real_string, check_length) == 0) ? true : false;			
		}
	} else {
		check_length = strlen(check);

		// find the real string end, because the string can be shorter than the buffer size
		for(real_length = 0; real_length < string_length && string[real_length] != '\0'; ++real_length){}

		if (real_length >= check_length){
			result = (strncmp(check, string, check_length) == 0) ? true : false;			
		}
	}

	return (struct match_info) {.match = result, .start = 0, .length = check_length, .reference_length = real_length, .realpath_string = real_string, .realpath_check = real_check};
}


/*
* Description:
* Checks if a string matches a specific substring at the end
*
* INFO:
* Returns a match_info struct containing the following information:
* .match: true if the end matches
* .start: start of the match (index)
* .length: length of the match (length)
* .reference_length: real length of the string to check
*                    necessary, because the string can be shorter than the passed size of the buffer
* .realpath_string: pointer to the resolved realpath if it was one (needs to be freed)
* .realpath_check: pointer to the resolved check path (needs to be freed)
*
* Parameters:
* pid: process id of the calling process
* check: string to match on the parameter string
* string: string which should be checked
* string_length: length of the string buffer (must not equal to the string length inside)
* is_path: defines if the string represents a path (will be resolved)
*/
struct match_info compareStringEnd(pid_t pid, const char *check, const char *string, size_t string_length, bool is_path){
	bool result = false;
	size_t check_length = strlen(check);
	size_t real_length = 0;
	char *real_string = NULL;

	if (is_path == true){
		real_string = getPidRealPath(pid, string);
	}

	if (real_string != NULL){
		string_length = PATH_MAX;

		// find the real string end, because the string can be shorter than the buffer size
		for(real_length = 0; real_length < string_length && real_string[real_length] != '\0'; ++real_length){}

		if (real_length >= check_length){
			result = strncmp(check, &real_string[real_length - check_length], check_length) == 0;			
		}
	} else {
		// find the real string end, because the string can be shorter than the buffer size
		for(real_length = 0; real_length < string_length && string[real_length] != '\0'; ++real_length){}

		if (real_length >= check_length){
			result = strncmp(check, &string[real_length - check_length], check_length) == 0;			
		}
	}

	return (struct match_info) {.match = result, .start = real_length - check_length, .length = check_length, .reference_length = real_length, .realpath_string = real_string, .realpath_check = NULL};
}

/*
* Description:
* Checks if a string matches a specific substring at the beginning
*
* Parameters:
* pid: process id of the calling process
* check: string to match on the parameter string
* string: string which should be checked
* string_length: length of the string buffer (must not equal to the string length inside)
* is_path: defines if the string represents a path (will be resolved)
*/
bool stringMatchesStart(pid_t pid, const char *check, const char *string, size_t string_length, bool is_path){
	struct match_info matchdata = compareStringStart(pid, check, string, string_length, is_path);

	if (matchdata.realpath_string != NULL){
		free(matchdata.realpath_string);
	}
	if (matchdata.realpath_check != NULL){
		free(matchdata.realpath_check);
	}

	return matchdata.match;
}

/*
* Description:
* Checks if a string matches a specific substring at the end
*
* Parameters:
* pid: process id of the calling process
* check: string to match on the parameter string
* string: string which should be checked
* string_length: length of the string buffer (must not equal to the string length inside)
* is_path: defines if the string represents a path (will be resolved)
*/
bool stringMatchesEnd(pid_t pid, const char *check, const char *string, size_t string_length, bool is_path){
	struct match_info matchdata = compareStringEnd(pid, check, string, string_length, is_path);

	if (matchdata.realpath_string != NULL){
		free(matchdata.realpath_string);
	}
	if (matchdata.realpath_check != NULL){
		free(matchdata.realpath_check);
	}

	return matchdata.match;
}

/*
* Description:
* Checks if a string matches the path of a file descriptor
* Note, that this is not a 100% secure check, because a file
* descriptor can change over time and those changes
* may not be notified under /proc/pid/fd
* Especially, if we deal wich hardlinks
*
* INFO:
* Returns true if the paths matches otherwise false
*
* Parameters:
* pid: process id of the calling process
* check: string to match on the parameter string
* fd: file descriptor to check
*/
bool fdPathMatchesStart(pid_t pid, const char *check, int fd){
	char file[80] = {"/0"};
	bool result = false;

	sprintf(file, "/proc/%d/fd/%d", pid, fd);
	char *fd_path = realpath(file, NULL);
	if (fd_path != NULL){
		char *real_check_path = getPidRealPath(pid, check);

		if (real_check_path != NULL){
			result = stringMatchesStart(pid, real_check_path, fd_path, PATH_MAX, false);
			free(real_check_path);
		} else {
			result = stringMatchesStart(pid, check, fd_path, PATH_MAX, false);
		}

		free(fd_path);
	}

	return result;
}

/*
* Description:
* Checks if a string matches the path of a file descriptor
* Note, that this is not a 100% secure check, because a file
* descriptor can change over time and those changes
* may not be notified under /proc/pid/fd
* Especially, if we deal wich hardlinks
*
* INFO:
* Returns true if the paths matches otherwise false
*
* Parameters:
* pid: process id of the calling process
* check: string to match on the parameter string
* fd: file descriptor to check
*/
bool fdPathMatchesEnd(pid_t pid, const char *check, int fd){
	char file[80] = {"/0"};
	bool result = false;

	sprintf(file, "/proc/%d/fd/%d", pid, fd);
	char *fd_path = realpath(file, NULL);
	if (fd_path != NULL){
		result = stringMatchesEnd(pid, check, fd_path, PATH_MAX, false);
	}

	return result;
}

/*
* Description:
* Checks if a string matches a specific substring at the beginning
* and replace the matched area with a new string
*
* INFO:
* Returns the sec_rule_result struct with the instructions about the new data
*
* Parameters:
* pid: process id of the calling process
* check: string to match on the parameter string
* string: string which should be checked
* string_length: length of the string buffer (must not equal to the string length inside)
* new_string: replacement string for the match region
* is_path: defines if the string represents a path (will be resolved)
*/
struct sec_rule_result changeStringOnStartMatch(pid_t pid, const char *check, const char *string, size_t string_length, const char *new_string, bool is_path){
	struct sec_rule_result result = {.action = SEC_ACTION_NONE, .new_value = NULL, .size = -1};
	struct match_info matchdata = compareStringStart(pid, check, string, string_length, is_path);

	if (matchdata.match){
		string_length = matchdata.reference_length;
		size_t new_string_length = strlen(new_string);
		size_t buffer_size = (string_length + (new_string_length - matchdata.length)) + 1;
		char *buffer = malloc(buffer_size);
		memset(buffer, 0, buffer_size);

		strncpy(buffer, new_string, new_string_length);
		if (matchdata.realpath_string != NULL){
			strncpy(&buffer[new_string_length], &matchdata.realpath_string[matchdata.length], string_length - matchdata.length);
		} else {
			strncpy(&buffer[new_string_length], &string[matchdata.length], string_length - matchdata.length);
		}
		result.new_value = buffer;
		result.size = buffer_size;
		result.action = SEC_ACTION_MODIFY;
	}

	// free realpath data
	if (matchdata.realpath_string != NULL){
		free(matchdata.realpath_string);
	}
	if (matchdata.realpath_check != NULL){
		free(matchdata.realpath_check);
	}

	return result;
}

/*
* Description:
* Checks if a string matches a specific substring at the end
* and replace the matched area with a new string
*
* INFO:
* Returns the sec_rule_result struct with the instructions about the new data
*
* Parameters:
* pid: process id of the calling process
* check: string to match on the parameter string
* string: string which should be checked
* string_length: length of the string buffer (must not equal to the string length inside)
* is_path: defines if the string represents a path (will be resolved)
*/
struct sec_rule_result changeStringOnEndMatch(pid_t pid, const char *check, const char *string, size_t string_length, const char *new_string, bool is_path){
	struct sec_rule_result result = {.action = SEC_ACTION_NONE, .new_value = NULL, .size = -1};
	struct match_info matchdata = compareStringEnd(pid, check, string, string_length, is_path);

	if (matchdata.match){
		string_length = matchdata.reference_length;
		size_t new_string_length = strlen(new_string);
		size_t buffer_size = (string_length + (new_string_length - matchdata.length)) + 1;
		char *buffer = malloc(buffer_size);
		memset(buffer, 0, buffer_size);

		if (matchdata.realpath_string != NULL){
			strncpy(buffer, matchdata.realpath_string, string_length - matchdata.length);
		} else {
			strncpy(buffer, string, string_length - matchdata.length);
		}
		strncpy(&buffer[matchdata.start], new_string, new_string_length);
		result.new_value = buffer;
		result.size = buffer_size;
		result.action = SEC_ACTION_MODIFY;
	}

	// free realpath data
	if (matchdata.realpath_string != NULL){
		free(matchdata.realpath_string);
	}
	if (matchdata.realpath_check != NULL){
		free(matchdata.realpath_check);
	}

	return result;
}


/*
* Description:
* Prepares the data structure to prepare a string value (parameter)
*
* Parameters:
* new_string the new string which should be set for a variable
*/
struct sec_rule_result changeStringValue(const char *new_string){
	struct sec_rule_result result = {.action = SEC_ACTION_MODIFY, .new_value = NULL, .size = -1};

	size_t buffer_size = strlen(new_string) + 1;
	char *buffer = malloc(buffer_size);

	for (size_t i = 0; i < buffer_size; i++){
		buffer[i] = '\0';
	}

	strcpy(buffer, new_string);
	result.new_value = buffer;
	result.action = SEC_ACTION_MODIFY;
	result.size = buffer_size;

	return result;
}

/*
* Description:
* Writes a log entry into the syslog
*
* Parameters:
* level: log level
* string: new string
*/
void writeLog(int level, char *string){		
	openlog("sec_seccomp_log", LOG_PID|LOG_CONS, LOG_USER);
	syslog(level, "%s", string);
	closelog();
}

//-------------------------------------------------------
//
// Functions to get and manipulate parameters
//
//-------------------------------------------------------

/*
* Description:
* Reads an integer from the traced application
*
* Parameters:
* pid: pid of the traced application
* param_register: register which holds the value
*
* Return:
* Read integer value
*/
int readInt(pid_t pid, int param_register){
	return (int)ptrace(PTRACE_PEEKUSER, pid, sizeof(uintptr_t)*param_register, 0);
}

/*
* Description:
* Modifies a primitive parameter (int)
* This is achieved by simply overwriting the specified
* register content
*
* Parameters:
* pid: pid of the traced application
* param_register: register which holds the value
* new_value: new value
*/
void modifyPrimitiveParameter(pid_t pid, int param_register, int new_value){
	ptrace(PTRACE_POKEUSER, pid, sizeof(uintptr_t)*param_register, new_value);
}

/*
* Description:
* Reads a data block from the client
* This is achieved by retrieving the pointer address
* of the client application from the register
* afterwards the data is read character wise
* from the memory region
*
* Parameters:
* pid: pid of the traced application
* param_register: register which holds the value
* size: size of the data to read
*
* Return:
* void* pointer to the data
*/
void* readData(pid_t pid, int param_register, size_t size){
	size_t count = 0;
	char *text = calloc(size, 1);
	char *retval = text;
	size_t i;

	char *param_addr = (char *)ptrace(PTRACE_PEEKUSER, pid, sizeof(uintptr_t)*param_register, 0);
	if (param_addr != NULL){
	    do {
	        long val;
	        char *p;

	  		errno = 0;
	        val = ptrace(PTRACE_PEEKTEXT, pid, param_addr, NULL);
	        if (val == -1 && errno != 0) {
	            fprintf(stderr, "PTRACE_PEEKTEXT error: %s\n", strerror(errno));
	            exit(1);
	        }
	        param_addr += sizeof (long);
	  
	        p = (char *) &val;
	        for (i = 0; i < sizeof (long) && count < size; ++i, ++text, ++count) {
	            *text = *p++;
	        }
	    } while (count < size);
	} else {
		retval = NULL;
	}

	return (void*)retval;
}

/*
* Description:
* Reads a \0 terminated string from the traced application
* The buffer size is statically set to 1024. 
* The data is read by getting the pointer address from 
* the register and loading the data afterwards from
* the memory region
*
* Parameters:
* pid: pid of the traced application
* param_register: register which holds the value
*
* Return:
* Read string as char*
*/
char* readTerminatedString(pid_t pid, int param_register){
	size_t max_length = 1024;
	char *text = calloc(max_length, 1);
	char *retval = text;
	size_t i;

	char *param_addr = (char *)ptrace(PTRACE_PEEKUSER, pid, sizeof(uintptr_t)*param_register, 0);
	if (param_addr != NULL){
	    do {
	        long val;
	        char *p;
	  
	  		errno = 0;
	        val = ptrace(PTRACE_PEEKTEXT, pid, param_addr, NULL);
	        if (val == -1 && errno != 0) {
	            fprintf(stderr, "PTRACE_PEEKTEXT error: %s\n", strerror(errno));
	            exit(1);
	        }
	        param_addr += sizeof (long);
	  
	        p = (char *) &val;
	        for (i = 0; i < sizeof (long); ++i, ++text) {
	            *text = *p++;
	            if (*text == '\0') break;
	        }
	    } while (i == sizeof (long));
	} else {
		retval = NULL;
	}

	return retval;
}

/*
* Description:
* Copies data to a target address of another application (tracee)
*
* INFO:
* Used, if we modify any non-output syscall parameters
*
* Parameters:
* pid: tracee process id
* base_address: base address where to store the data
* data: new data as a pointer to a char array
* size: size of the new data block
*/
void copyDataToTracee(pid_t pid, char *base_address, char *data, size_t size){
	size_t data_idx = 0;
	do {
		char val[sizeof(uintptr_t)];

		for (size_t i = 0; i < sizeof(uintptr_t) && data_idx < size; ++i, ++data_idx, ++data){
			val[i] = *data;
		}

		ptrace(PTRACE_POKETEXT, pid, base_address, *(uintptr_t *)val);
		base_address += sizeof(uintptr_t);
	} while(data_idx < size);
}

/*
* Description:
* Copies data to a target address of another application (tracee)
* The data at the target is preserved. Means, that if we just modify 4 of 8 bytes,
* the other 4 bytes will preserve the value of the target address space
*
* INFO:
* Used, if we modify buffer syscall parameters, which will store the return value
*
* Parameters:
* pid: tracee process id
* base_address: base address where to store the data
* data: new data as a pointer to a char array
* size: size of the new data block
*/
void copyDataToTraceeInplace(pid_t pid, char *base_address, char *data, size_t size){
	size_t data_idx = 0;

	do {
		char target_value[sizeof(uintptr_t)];
		long original_value = ptrace(PTRACE_PEEKTEXT, pid, base_address, NULL);

		memcpy(target_value, (char *)&original_value, sizeof(uintptr_t));

		for (size_t i = 0; i < sizeof(uintptr_t) && data_idx < size; ++i, ++data_idx, ++data){
			target_value[i] = *(char *)data;
		}

		ptrace(PTRACE_POKETEXT, pid, base_address, *(uintptr_t *)target_value);
		base_address += sizeof(uintptr_t);
	} while(data_idx < size);
}

/*
* Description:
* Modifies a specific Parameter. 
* Extends the stack and modifies the target address of the register
*
* INFO:
* Inplace modification is not alway possible, especially when the following points apply
*   - Parameter is in a read only space
*   - Other Threads,.. use the data
*   - We would have to restore it after the syscall is executed
*
* ATTENTION:
* May lead to memory leaks in the target applications if the return value of the syscall overwrites
* a pointer (return value) which is the same as one of the parameters.
* Depending on the rules, a function which usually returns the same address like one of the parameters,
* this rule can be harmed.
*
* Parameters:
* pid: Target process id
* param_register_entry: address of the parameter (Register entry)
* new_data: pointer to the new data structure
* new_size: size of the new data structure (if -1, it is asumed that new_data contains a null terminated string)
*/
void modifyParameter(pid_t pid, int param_register, void *new_data, int new_size){
	char *stack_addr, *new_target_addr;
	char *new_data_ptr = (char*) new_data;

	// modify new_size parameter if we have a null terminated string
	if (new_size == -1){
		new_size = strlen(new_data_ptr) + 1;
	}

	// evaluate stack and new target address
	stack_addr = (char *)ptrace(PTRACE_PEEKUSER, pid, sizeof(uintptr_t)*RSP, 0);
	stack_addr -= RED_ZONE + new_size;
	new_target_addr = stack_addr;

	// write data to the lower part of the stack
	copyDataToTracee(pid, new_target_addr, new_data_ptr, new_size);

	// change param address (in register)
	ptrace(PTRACE_POKEUSER, pid, sizeof(uintptr_t)*param_register, new_target_addr);
}

/*
* Description:
* Modifies the specified parameter which counts as a return parameter
* to the system call. One example is getcwd, where the first parameter
* is the buffer to which a return value is written
*
* Parameters:
* pid: Target process id
* param_register_entry: address of the parameter (Register entry)
* new_data: pointer to the new data structure
* target_buffer_size: size of the new data structure
*/
void modifyReturnParameter(pid_t pid, int param_register, void *new_data, int target_buffer_size)
{
	char *target_addr = (char *)ptrace(PTRACE_PEEKUSER, pid, sizeof(uintptr_t)*param_register, 0);

	// only write the value back, if we have a target address
	// this is not the case, if we have a null/0 parameter
	if (target_addr != NULL && new_data != NULL){
		copyDataToTraceeInplace(pid, target_addr, (char *)new_data, target_buffer_size);
	}
}

/*
* Description:
* Modifies the return value of a system call
*
* Parameters:
* pid: Target process id
* value: return value of the system call
*/
void modifyReturnValue(pid_t pid, int value){
	ptrace(PTRACE_POKEUSER, pid, sizeof(uintptr_t)*RET, value);
}

/*
* Description:
* Invalidates a system call, which means, that it
* will never be executed, the system call will return -1
*
* Parameters:
* pid: Target process id
*/
void invalidateSystemcall(pid_t pid){
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	regs.orig_rax = -1;
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

/*
* Description:
* Executes the actions of a sec_rule_result containing information
* about the action of a system call*
*
* The structure must have an information about the action to execute
* ALLOW, NONE, SKIP, MODIFY or TERMINATE
*
* If result contains dat in the new_value field, it is freed within this function
*
* Parameters:
* pid: Target process id
* result: structure containing information about the action 
* param_register: register to modify (if SEC_ACTION_MODIFY)
* isOutParam: defines if the modified register contains an output buffer (out parameter)
*/
void executeRuleResult(pid_t pid, struct sec_rule_result result, int param_register, bool isOutParam)
{
	switch(result.action){
		case SEC_ACTION_ALLOW: case SEC_ACTION_NONE:
			// do nothing
			break;
		case SEC_ACTION_SKIP: case SEC_ACTION_TRAP:
			invalidateSystemcall(pid);
			break;
		case SEC_ACTION_MODIFY:
			if (result.new_value != NULL){
				if (isOutParam == true){	
					modifyReturnParameter(pid, param_register, result.new_value, result.size);
				} else {
					modifyParameter(pid, param_register, result.new_value, result.size);
				}
			}
			break;
		case SEC_ACTION_TERMINATE: default:
			writeLog(LOG_CRIT, "Application was terminated. Reason seccomp rule violation.");
			kill(pid, SIGSTOP);
			exit(0);
			break;
	}

	if (result.new_value != NULL){
		free(result.new_value);
	}
}