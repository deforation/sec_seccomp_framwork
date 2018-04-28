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
* sec_seccomp_log in /var/log/syslog (Debian)
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
*						The modifier ":after" can be added to the system call
*						name. This means, that the function will be called
*						after the system call was executed.
*						It is possible to define the normal and the after version
*						but the functions must have a different name						
*						example: SYS_open, SYS_gettimeofday
*						example: SYS_read:after, SYS_recvmsg:after
*
*	{after}:			Allows to specify the flag ":after".
*						This means, that the function will be called
*						after the system call was executed.
*						If the flag is not set, the check is done before execution
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
* * systemcall:				{syscall_name}{after}
* * headers:				{header_list}
* * set_group[{field}]:		{group_name_list}
* * set_length[{field}]:	{length}
* * read_length[{field}]:	{length}
* * link_update[{field}]:	{field}={length}
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
*
* Note: The normal behaviour of seccomp is to check a system call
* before it is executed. Unfortunately, many system calls become
* interesting after they have been executed.
* To be able to inspect the data after the execution,
* the :after flag can be added to the system calls section name.
* With the flag, the rules will be applied once the call is finished.
* - It is possible to define the normal section and the after version
* - Within the c-configuration file, an equivalent function block has to
*   be defined by adding :after to the system call name: SYS_read:after,...
* - The action skip has no effect when the system call was already executed
*
*
* Note: There are 3 different length flags called (set_length, read_length and set_return)
* - set_length:  defines the length of a system all argument.
*  				 This can either be strlen or mor likely strlen+1,
*				 the name of another argumen or it can be skiped.
*				 If the value is skiped, sizeof(datatype) is used by default
*
* - read_length: The read length defines how many bytes have to be
*                read from the target application. This has the following
*				 reason: If we modify the read systemcall after it was executed
*				 we are able to manipulate the retrieved data.
*				 Now, if we would read the whole length according to the buffer size
*				 we may end up reading parts of old data. To prevent this,
*				 we need the return value of the system call, which gives us the information
*				 how many bytes have been read (are valid in the buffer).
*				 In the case of SYS_read, we would therefore have to define
*				 the length to "return". As a result, only the given amount
*				 of data is read. If the option is not defined, the set_length rule is used.
*
* - link_update: Enables the possibility to link updates. So that after a
*				 specific parameter was manipulated, a second one will be modified at the same time.
*				 This allows us to define a rule to modify for example
*				 the output of the read system call and return the new
*				 length of the modified string with the system call.
*				 If we for example change the read output of "leet"
*				 to "magnus", the return value has to be set to the
*				 new length of magnus. Otherwise the application would
*				 just read "magn", which is not what we want.
*				 The same behaviour can be observed with the write system call.
*				 If the write buffer is modified, the count parameter has to be 
*				 updated to the length of the new buffer.
*				 - This option is currently only supported in combination
*				   with buffer manipulations.
*				 example for SYS_read:after:  link_update[buf]:	return=strlen+1
*				 example for Sys_write:		  link_update[buf]:	count=strlen+1
*					
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
// Section-End


/*
* Defines custom functions and data structures
* which are taken over to the generated file
*/
// Section-Start: CustomFunctions
int get_random_value(){
	static int randval = 0;
	
	// we wont expose the real time to the calling application, so we add a random value on top of it
	if (randval == 0){
		srand(time(0));
		randval = (int)rand();
	}

	return ++randval;
}
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
void sec_open(char *filename, int flags, mode_t mode){
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
	char *cwd = getPidCwd(pid);
	strncpy(buf, cwd, size);
	free(cwd);
	
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
void sec_chdir(char *path){
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
	int retval = gettimeofday(tv, tz);

	srand(get_random_value());
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

/*
* systemcall:			SYS_read:after
* headers:				unistd.h
*
* set_length[buf]:		count
* read_length[buf]:		return
*
* link_update[buf]:		return=strlen+1
*
* Note: Two different lengths are defined set and read
* the set length is used as an information for the maximum buffer size
* the read length is used to retrieve the data for buf argument
* In this case, the system call returns it with the return value.
* if it is not set, we may read data from a previous system call, because there is not
* necessary a '\0' describing the end
*
* link update defines, that the return value of the system call
* should automatically be updated to the new length
*/
void sec_read_after(int fd, __OUT void *buf, size_t count){
	CHECK_RULES()
}

/*
* systemcall:			SYS_write
* headers:				unistd.h
*
* set_length[buf]:		count
* read_lenth[buf]:		count
*
* link_update[buf]:		count=strlen+1
*/
void sec_write(int fd, void *buf, size_t count){
	CHECK_RULES()
}

// Section-End