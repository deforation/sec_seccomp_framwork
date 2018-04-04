/******************************************************************
* Seccomp Toolkit by Remo Schweizer as a part of the master thesis
*                  ____ _ _  ___  _ _ _ 
*                 |_  /| | || . || | | |
*                  / / |   ||   || | | |
*                 /___||_|_||_|_||__/_/ 
*                      
* The systemcall configuration file specifies how the system calls
* look in terms of their parameters and data types.
* These prototypes are essential if checks are performed on
* parameter values or if we would like to emulate system calls.
*
* To maniuplate the system calls and check them against rules,
* different macros are introduced reducing the implementation
* difficulty. These macros are modified by the python interpreter
* script
*
* To emulate a system call, its parameters or even the
* return value can be changed. If we change the return
* value, we don't want the original system call to be 
* executed. It is therefore necessary to call SKIP_SYSTEMCALL()
* To prevent the system call from execution
*
* All log action are performed using the syslog library
* of linux. The entries are stored under the name
* sec_seccomp_log in /var/log/syslog (UBUNTU)
*
* NOTE:
* This file consists only of some system calls for demo
* purpose and to show the possibilities as well
* as the functions the framework provides
*
* /////////////////////////////////////////
* 
* A function definition has the following format consisting
* of a comment block defining important data and the function itself
*
* - {syscall_name}:		Describes the name of the system call which
*						will be modified. Starts usually with SYS_{name}
*						example: SYS_open, SYS_gettimeofday
*
* - {header_list}:		Defines a list of headers which have to be
*						included in order to be able to compile the file
*						The list is separated through commas
*						example: sys/time.h, sys/resource.h
*
* - {field}:			Represents the name of a system call argument
* 						example: filename
*
* - {group_name_list}:	Defines a name of alternative names for which
*						the argument can be called in the rule definition
*						file. This is useful, if we would like to perform
*						actions on all paths for different system calls
*						example: open_path, my_path_group		
*
* - {length}:			Defines the length of the specified field
*						This is important, if we deal with pointers where
*						the size is given through another parameter or
*						if it is a zero terminated string.
*						In getcwd, the buf size is for example
*						defined thorugh the parameter size of the syscall
*						The length can therefore be an integer, argument name
*						or an expression like strlen+1
*						If no length is defined, sizeof is used as default
*						example: strlen+1
*						example: size_arg
*
* - {arguments}:		Describes the arguments of the system call as they are 
*						listed in the man page or source.
*						If an argument is a buffer which is filled by a 
*						system call as for example in getcwd,
*						The buffer parameter has to be marked by the
*						__OUT macro
*						example: __OUT struct timeval *tv, __OUT struct timezone *tz
*						example: const char *filename, int flags, mode_t mode
*
* - {ov_target}:		Argument which should be overwritten
*						Has to be one of the syscalls argument names
*
* - {ov_value}:			Variable containing the new value for the field
*						Has to be from the same datatype
* 
* / * 
* * systemcall:				{syscall_name}
* * headers:				{header_list}
* * set_group[{field}]:		{group_name_list}
* * set_length[{field}]:	{length}
* * /
* void sec_functionname({arguments}){
* 	// any kind of source
*
*   // Sections which should only be executed in the debug
*	// mode (suitable for debug prints / logs) can be marked with
*   // DEBUG_BEGIN() and DEBUG_END()
*  	DEBUG_BEGIN()
*		LOG_INFO("gettimeofday called by the process %d", __PID)
*	DEBUG_END()
*
*   // To define the section where the rules are checked
*   // the macro CHECK_RULES() has to be used
*   CHECK_RULES()
*
*   // If we would like to emulate the system call, we can 
*   // implement it by our own
*   // To overwrite parameter values or the return parameter
*   // the macro OVERWRITE({ov_target}, {ov_value}) is provided
*   // example based on SYS_gettimeofday
*
*   // init variables
* 	time_t t;
*	int retval = gettimeofday(tv, tz);	
*
*	// we wont expose the real time to the calling application, so we add a random value on top of it
*	srand((unsigned) time(&t));
*	float offset = (float)rand() - RAND_MAX/2;
*	tv->tv_sec += (int)(offset / RAND_MAX * 20.0);
*
*	// overwrite the return value of the system call and its parameters
*   // Only the overwrite macro modifies the register values of the clien
*   // application so the changes are visible
*	OVERWRITE(tv, tv)
*	OVERWRITE(tz, tz)
*	OVERWRITE(return, retval)
*
*	// to use the overwritten data (emulation)
*	// we have to skip the system call execution on the client application
*	SKIP_SYSTEMCALL()
* }
*
* /////////////////////////////////////////
*
* -----------------------------------------------------------------
* Version: 1.0
* -----------------------------------------------------------------
* 01.04.2018:       schwerem        Version 1.0 implemented
* -----------------------------------------------------------------
*
******************************************************************/



/*
* Defines all Includes
*/
// Section-Start: Includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
// Section-End


/*
* Defines all Macros
*/
// Section-Start: Macros
#define __OUT 						ERROR_USE_PARSER_SCRIPT_FIRST
#define __PID						ERROR_USE_PARSER_SCRIPT_FIRST
#define OVERWRITE(TARGET, SOURCE) 	ERROR_USE_PARSER_SCRIPT_FIRST
#define SKIP_SYSTEMCALL()			ERROR_USE_PARSER_SCRIPT_FIRST
#define CHECK_RULES()				ERROR_USE_PARSER_SCRIPT_FIRST
#define DEBUG_BEGIN()				ERROR_USE_PARSER_SCRIPT_FIRST
#define DEBUG_END()					ERROR_USE_PARSER_SCRIPT_FIRST
#define LOG_INFO()					ERROR_USE_PARSER_SCRIPT_FIRST
#define LOG_DEBUG()					ERROR_USE_PARSER_SCRIPT_FIRST
#define LOG_ALERT()					ERROR_USE_PARSER_SCRIPT_FIRST
#define LOG_CRIT()					ERROR_USE_PARSER_SCRIPT_FIRST
// Section-End


/*
* Defines where the SecFunction definition start
*/
// Section-Start: SecFunctions
/*
* systemcall: 			SYS_open
* headers: 				stdlib.h, stdio.h
*
* set_group[filename]: 	path
* set_group[flags]: 	permission_flag
*
* set_length[filename]: strlen+1
*
*/
void sec_open(const char *filename, int flags, mode_t mode){
	DEBUG_BEGIN()
		// print function call end parameters if debug is active
		char log[1024];
		sprintf(log, "Process %d called open(%s, %d, %d) ", __PID, filename, flags, mode);
		LOG_INFO(log)
	DEBUG_END()

	CHECK_RULES()
}

/*
* systemcall: 			SYS_getcwd
*
* set_group[buf]: 		path
*
* set_length[buf]: 		size
*/
void sec_getcwd(__OUT char *buf, unsigned long size){
	DEBUG_BEGIN()
		// print function call end parameters if debug is active
		char log[1024];
		sprintf(log, "Process %d called getcwd(buffer, %ld) ", __PID, size);
		LOG_INFO(log)
	DEBUG_END()

	// simulate getcwd
	char *name = malloc(size);

	sprintf(name, "/proc/%d/cwd", __PID);
	realpath(name, buf);

	free(name);

	// set return value and modify the return parameter
	OVERWRITE(buf, buf)
	OVERWRITE(return, strlen(buf))
	SKIP_SYSTEMCALL()

	CHECK_RULES()
}

/*
* systemcall: 			SYS_chdir
*
* set_group[path]: 		path
*
* set_length[path]: 	strlen+1
*/
void sec_chdir(const char *path){
	DEBUG_BEGIN()
		// print function call end parameters if debug is active
		char log[1024];
		sprintf(log, "Process %d called chdir(%s) ", __PID, path);
		LOG_INFO(log)
	DEBUG_END()

	CHECK_RULES()
}


/*
* systemcall: 			SYS_setrlimit
* headers:				sys/time.h, sys/resource.h
*
* set_group[rlim]:		limit
*/
void sec_setrlimit(int resource, struct rlimit *rlim){
	DEBUG_BEGIN()
		// print function call end parameters if debug is active
		char log[1024];
		sprintf(log, "Process %d called setrlimit(%d, [%ld, %ld]) ", __PID, resource, rlim->rlim_cur, rlim->rlim_max);
		LOG_INFO(log)
	DEBUG_END()

	CHECK_RULES()
}

/*
* systemcall: 			SYS_gettimeofday
* headers:				time.h
*
* set_group[tv]:		timeval
* set_group[tz]:		timezone
*/
void sec_gettimeofday(__OUT struct timeval *tv, __OUT struct timezone *tz){
	static int randval = 0;
	int retval = gettimeofday(tv, tz);
	
	// we wont expose the real time to the calling application, so we add a random value on top of it
	if (randval == 0){
		srand(time(0));
		randval = (int)rand();
	}
	srand(++randval);
	float offset = (float)rand() - RAND_MAX/2;
	tv->tv_sec += (int)(offset / RAND_MAX * 20.0);

	// overwrite the return value of the system call and its parameters
	OVERWRITE(tv, tv)
	OVERWRITE(tz, tz)
	OVERWRITE(return, retval)

	// to use the overwritten data (emulation)
	// we have to skip the system call execution on the client application
	SKIP_SYSTEMCALL()

	CHECK_RULES()
}

/*
* systemcall: 			SYS_socket
* headers:				sys/socket.h, sys/un.h
*
* set_group[domain]: 	domain
* set_group[type]: 		socket_type
* set_group[protocol]: 	protocol
*/
void sec_socket(int domain, int type, int protocol){
	CHECK_RULES()
}

/*
* systemcall:			SYS_dup
* headers:				unistd.h
*
* set_group[oldfd]:		fd
*/
void sec_dup(int oldfd){
	CHECK_RULES();
}

/*
* systemcall: 			SYS_fcntl
* headers:				unistd.h, fcntl.h
*
* set_group[fd]:		fd
*/
void sec_fcntl(int fd, int cmd){
	CHECK_RULES();
}

// Section-End