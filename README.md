# sec_seccomp_framwork
The sec_seccomp_framework provides an easy way to implement privilege dropping and system call manipulations for linux operating systems. The framework does not represent a sandbox, it aims for software developers who want to improve the security of their application against privilege escalation attacks.

## Capabilities
The framework offers the ability to:
* Generate seccomp bpf filter programs with an easy to use and extensive rule design
* Manipulate parameters and the return value of system calls using the integrated ptrace module
* Integrate the framework into an existing applications with little effort

## Requirements
The framework has for the rule generation process the following requirements:
* Python >3.5
* Python libraries: argparse, ConfigParser

The c-part of the framework requires:
* seccomp development libraries
* os: Linux or linux based derivate (tested on Debian GNU/Linux 9)
* currently: x86 or x64 structure
* recommended: kernel version > 4.8

## Usage
To use the framework, the following steps must be performed:
1. Download the respository
2. Rename the main function (int main ...) of the application to (int sec_main_after ...)
3. Optional: Add a function (int sec_main_before ...) if needed, to perform privileged actions
4. Include the header file "seccomp_framework/sec_client.h"
5. Create the defines for the used main functions (#define SEC_MAIN_BEFORE, #define SEC_MAIN_AFTER)
6. Open seclib.c and add an include for the main .c file of your application (#include "your c file.c")
7. Write rules and modify/extend the system call configuration file if required.
8. Generate the seccomp and tracer rule checks with the python script "SecConfigBuilder.py"
9. Copy the generated files into the directory "seccomp_framework" or let the script generate it directly into it.
10. Compile the application (main file is now seclib.c) [all framework files have to be linked]

These 10 easy steps are everything it needs to configure and use the framework.
Depending on the used compiler, a flag has to be set during compilation to add seccomp support.

* For gcc, add the compiler flag -lseccomp

### Run the test application
To run the attached test application, perform the following steps:
1. Download the repository
2. Change to the Generator directory
3. Execute the command: python3 SecConfigBuilder.py -o ../seccomp_framework
4. A message should appear, that all files were generated successfully
5. Change to the directory with the app.c file and call make to compile the application
6. Run the application

A successfull run should show different test cases and their expected outcome as well as the results.

### Minimum example
The following is a minimum example for the main applications source file:
```c
#include <stdio.h>
#include "seccomp_framework/sec_client.h"

#define SEC_MAIN_BEFORE
#define SEC_MAIN_AFTER

int sec_main_before(int argc, char **argv){
	(void)argc;
	(void)argv;
	
	printf("Run privileged operations.\n");

	return EXIT_SUCCESS;
}

int sec_main_after(int argc, char **argv){
	(void)argc;
	(void)argv;

	printf("Run unprivileged operations.\n");

	return EXIT_SUCCESS;
}
```

In the file "seclib.c" the specified line has to be modified so the applications c-file is included (see extract below).
```c
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "seccomp_framework/sec_client.h"
#include "seccomp_framework/sec_tracer.h"

#include "app.c"	 // CHANGE TO YOUR MAIN .C FILE
```

## Rule configuration scheme

The rules config file defines what actions are allowed on system calls. It is possible to define global rules or for specific system calls. The rule design allows to define system calls which should be
allowed, skipped, modified or system calls which should lead to a termination of the application

To be able to define actions based on parameter values, the rule design also allows to check parameters against
specific values or change the value of those.

Note, that the tracer needs most likely at least access to the following system calls to be fully operational
- ptrace, wait4, getpid, socket, 
  sendto, read, chdir, getcwd, 
  lseek, lstat, readlink, kill, 
  exit, exit_group, write, close, connect


A normal client application needs at least the following permissions so it is able to startup and terminate without any further logic:
 - exit, exit_group, write, read

The rule file itself has the following structure (or see the example rule file in the repository):
```
[General]
debug:     		True or False
default_action:		{action} (trap, terminate, skip, allow or modify)
default_action_tracer:	{action} (allow, terminate)

# defines which systemcalls shoud strictly be allowed, forbidden,...
syscall {action}:		list of systemcalls like (open, write, ...)
# the same for the tracer
tracer {action}:		list of systemcalls like (open, write, ...)

[Global]
# Allows to define rules targeting all system calls which
# contain all the given field groups

[{syscall_name}]
# Allows to specify rules for specific system calls
```

```
There exist different ways to define rules.
The following constructs are supported:
Keep in mind, that each rule can only apper once, but it is possible
to specify multiple checks / actions by separating them with a comma

- {action} 		represents an action like (terminate, allow or skip)

- {c-expression} 	defines nearly any kind of c expression.
                  	example: domain == AF_UNIX
                 	example: domain == AF_UNIX && type == SOCK_STREAM
			example: (rlim->rlim_max < 50 || rlim->rlim_max > 100) && resource == 5
			example: stat->st_uid == getuid()

- {permissions}  	defines a permission string consisting of "rwcx"
			r = read, w = write, c = create, x = execute
			if for example the paremeter flags in the open syscall
 			is added to the group permission_flag, it is checked against
			these flags
			example: allow(r)    path dir_starts_with("/home/remo/read_only_dir")
			example: allow(r)    path not dir_starts_with("/home/remo/read_only_dir")

- {field}		defines the field against a value should be checked.
			it can either be the name of the argument or the group name of an argument
			it is also possible to access elements of a struct as it would be in c
			example: filename
			example: buf
			example: rlim->rlim_max

- {value_check}  	defines a check against a specific value. These can easier be transformed
			into kernel checked system calls.
			example: != AF_IPX
			example: == AF_UNIX or just AF_UNIX
			example: dir_starts_with("/home/remo/Desktop")
			example: starts_with("start of a string")

- {new_value}		Defines the new value an argument should get before syscall execution
			It can either be a value like 10, AF_UNIX, ... or a String "new_string"
			example: redirect		resource == 1 && rlim->rlim_max > 2048: rlim->rlim_max => 1024
			example: path redirect:		dir_starts_with("/home/remo/denied") => "/home/remo/allowed"
 			example: redirect:		filename dir_ends_with(".txt") => ".dat"


default:				{action} 	//specifies the default action of a syscall section

{action}:				{c-expression}, {c-expression}, ...
{action}({permissions}):		{c-expression}, {c-expression}, ...

{field} {action}:			{value_check}, {value_check}, ...
{field} {action}({permissions}):	{value_check}, {value_check}, ...

redirect:				{c-expression}: {field} => {new_value}, {c-expression}: {field} => {new_value}, ...
redirect({permissions}):		{c-expression}: {field} => {new_value}, {c-expression}: {field} => {new_value}, ...
{field} redirect:			{value_check}, {value_check}, ...
{field} redirect({permissions}):	{value_check}, {value_check}, ...
```

The rule configuration logic allows also to modify and check strings and paths using. The prefix dir_ is necessary if the auto resolve of the path within the system call argument should automatically be resolved. Note that the value it should be checked against is also automatically resolved, which allows to define relative path checks
 - dir_starts_with("path") 
 - dir_ends_with("path")


If on the other way, we want to check strings itself, the following functions hould be used:
 - starts_with("string") 
 - ends_with("string")

There is also a way to perform checks (no modifications) on the path of a file descriptor. Note, that file descriptors generally have no strictly defined path representation, especially if we deal with hardlinks,... 
The runctions resolve the path based on the directory "/proc/pid/fd/fdnum
 - fd_path_starts_with("path") and
 - fd_path_ends_with("path")

### Example rules
The following examples show what is possible with the rule definition scheme
```
[setrlimit]
default:			allow
redirect:			resource == RLIMIT_NPROC && limit->rlim_max > 8: limit->rlim_max => 8,
				limit->rlim_cur > limit->rlim_max: limit->rlim_cur => limit->rlim_max-1
terminate:			(rlim->rlim_max > 33317 || rlim->rlim_max == 33320) && resource == 5	
rlim->rlim_min allow:		> 20, != 30, >= 50, 80
rlim->rlim_low redirect:	20 => 50, 80 => 30

[open]
default:			allow
path redirect(r):		dir_starts_with("./demo_files/modify") => "./demo_files/redirected_read"
skip(c):			filename dir_starts_with("./demo_files/write_yes_create_no")
allow(w):			filename dir_starts_with("./demo_files/write_yes_create_no")

[fcntl]:
default:			terminate
cmd allow:			F_GETFL
skip:				cmd == F_GETFD
```

## System call configuration scheme
The systemcall configuration file specifies how the system calls look in terms of their parameters and data types.
These prototypes are essential if checks are performed on parameter values or if we would like to emulate system calls.

To maniuplate the system calls and check them against rules, different macros are introduced reducing the implementation
difficulty. These macros are modified by the python interpreter script.

To emulate a system call, its parameters and the return value can be changed. If we change the return
value, we don't want the original system call to be executed. It is therefore necessary to call SKIP_SYSTEMCALL()
To prevent the system call from execution.

All log action are performed using the syslog library of linux. The entries are stored under the name sec_seccomp_log in /var/log/syslog (Debian)

NOTE:
This file consists only of some system calls for demo purpose and to show the possibilities as well as the functions the framework provides

```
A function definition has the following format consisting
of a comment block defining important data and the function itself

- {syscall_name}:		Describes the name of the system call which
				will be modified. Starts usually with SYS_{name}
				example: SYS_open, SYS_gettimeofday

- {header_list}:		Defines a list of headers which have to be
				included in order to be able to compile the file
				The list is separated through commas
				example: sys/time.h, sys/resource.h

- {field}:			Represents the name of a system call argument
 				example: filename

- {group_name_list}:		Defines a name of alternative names for which
				the argument can be called in the rule definition
				file. This is useful, if we would like to perform
				actions on all paths for different system calls
				example: open_path, my_path_group		

- {length}:			Defines the length of the specified field
				This is important, if we deal with pointers where
				the size is given through another parameter or
				if it is a zero terminated string.
				In getcwd, the buf size is for example
				defined thorugh the parameter size of the syscall
				The length can therefore be an integer, argument name
				or an expression like strlen+1
				If no length is defined, sizeof is used as default
				example: strlen+1
				example: size_arg

- {arguments}:			Describes the arguments of the system call as they are 
				listed in the man page or source.
				If an argument is a buffer which is filled by a 
				system call as for example in getcwd,
				The buffer parameter has to be marked by the
				__OUT macro
				example: __OUT struct timeval *tv, __OUT struct timezone *tz
				example: const char *filename, int flags, mode_t mode

- {ov_target}:			Argument which should be overwritten
				Has to be one of the syscalls argument names

- {ov_value}:			Variable containing the new value for the field
				Has to be from the same datatype
```
```c
/ * 
* systemcall:			{syscall_name}
* headers:			{header_list}
* set_group[{field}]:		{group_name_list}
* set_length[{field}]:		{length}
* /
void sec_functionname({arguments}){
	// any kind of source

   	// Sections which should only be executed in the debug
	// mode (suitable for debug prints / logs) can be marked with
 	// DEBUG_BEGIN() and DEBUG_END()
  	DEBUG_BEGIN()
		LOG_INFO("gettimeofday called by the process %d", __PID)
	DEBUG_END()

   	// To define the section where the rules are checked
   	// the macro CHECK_RULES() has to be used
   	CHECK_RULES()

   	// If we would like to emulate the system call, we can 
   	// implement it by our own
   	// To overwrite parameter values or the return parameter
   	// the macro OVERWRITE({ov_target}, {ov_value}) is provided
   	// example based on SYS_gettimeofday

   	// init variables
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
  	// Only the overwrite macro modifies the register values of the clien
   	// application so the changes are visible
	OVERWRITE(tv, tv)
	OVERWRITE(tz, tz)
	OVERWRITE(return, retval)

	// to use the overwritten data (emulation)
	// we have to skip the system call execution on the client application
	SKIP_SYSTEMCALL()
}

```

### Example configuration
The following examples show how the system calls can be defined.
```c
/*
* systemcall: 		SYS_open
* headers: 		stdlib.h, stdio.h
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
* systemcall: 		SYS_socket
* headers:		sys/socket.h, sys/un.h
*
* set_group[domain]: 	domain
* set_group[type]: 	socket_type
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
```

## Debug support
The framework offers the flag "debug" within the "General" section of the rule configuration file.
Once the flag is set, seccomp rules like (terminate, allow and skip) wont be executed by seccomp itself.
Instead, all requests are redirected to the tracer which offers the possibility to print debug information.
To find why an application may terminate, which is likely if not all system calls have been allowed which should be able to use by the application. Second, all defined debug sections within the system call configuration file

For all logging purposes, the framework uses the syslog module. On Debian, all messages are written to /var/log/syslog
The output may look like this:
```
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (MODIFY, 96)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (MODIFY, 2)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: Process 92504 called open(/etc/localtime, 524288, 438)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 1)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (MODIFY, 2)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: Process 92504 called open(/home/remo/Schreibtisch/test/fd_copy_deny/test.txt, 0, 438)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 72)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 1)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (SKIP, 72)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 1)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 3)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 1)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (MODIFY, 2)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: Process 92504 called open(/home/remo/Schreibtisch/test/fd_copy_deny/test.txt, 0, 438)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 5)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 0)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 1)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (MODIFY, 32)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 1)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 3)
Apr  4 15:44:25 debian sec_seccomp_log[92503]: SECCOMP SYSTEMCALL: (ALLOW, 231)
...
```
The number behind the action represents the number of the system call.
For an appropriate translation to the system call see
[https://filippo.io/linux-syscall-table/](https://filippo.io/linux-syscall-table/)

## Architecture
The framework takes basically two input files from the user. 

First, there is the system call configuration file.
It defines how the system calls look like. This way the framework knows what parameter it has and to what group arguments belong as well as the headers for the import. Second the framework is notified how the final function looks like. If we for example want to perform modifications on them beside the functionalities the framework comes with.

Second, the rule definition. Its content defines what actions are allowed for what system call. Expressions can be defined to simply allow, skip, terminate or modify/redirect system calls. Allowed system calls are processed normally by the application. Skipped system calls will fail in their execution. Termination rules will lead to the termination of the application. Redirection rules allow to modify system call parameters or perform any kind of modification on the system calls from their emulation to altering the return value.

![framework overview](https://raw.githubusercontent.com/deforation/sec_seccomp_framwork/master/readme_images/framework_overview.jpg "Overview")

These files are fed into the python based configuration builder. The application parses the files and generates the seccomp rules for the application and tracer as well as c-code for the rule checks and modifications within the tracer part of the framework.

Finally, the generated files have to be linked to the application together with the other c-source files from sec_seccomp_framework.

### System call execution scheme
The application execution starts with the main framework file "seclib.c". After a check if already a tracer is attached to the executable, a fork operation is performed. The parent path becomes the tracer and the child becomes the main application.

Before seccomp gets initialized, the sec_main_before function of the application is called which allows to perform privileged operations. Afterwards, both the tracer and the main application load their seccomp rules. After this step, sec_main_after is called which should contain the main start routine of the application. At this point, the privilege dropping process has taken place and all further systemcalls are strictly checked using seccomp and the tracer part of the application.

![framework overview](https://raw.githubusercontent.com/deforation/sec_seccomp_framwork/master/readme_images/framework_sequence.jpg "System call execution scheme")

If the application tries to execute a system call, it is checked within the kernel against the defined seccomp rules.
Redirection and modification rules as well as rules with checks on data behind pointers (which is not possible in seccomp itself) are redirected to the tracer. The tracer than performes the action according to the rules and either let the application execute the system call or emulate the system call for it.

## Pending tasks
The following tasks which are pending are mostly improvements and beautify measurements:
* Enhance the error handling in the rule generation script and the file parsers
* Extend the framework to check file descriptor permissions using the existing rule format for permissions
* Add more log automation to the code for better error handling while setting up the rules
* Add support for more architectures (currently limited by the bpf code generation [arch support])
* Performance improvements so paths are only resolved once for each system call and not for each check
* Add bpf filter support for more than 255 instructions (current limit is caused by the max jump distance)
* Add support for || parameter checks in seccomp bpf instead of only && statements
* Other pending changes are noted in the source files

## Example rule transformations
The following examples demonstrate, how the rules are transformed into seccomp and c rules.
We assume the input configuration:
```
[setrlimit]
default:		terminate
redirect:		resource == RLIMIT_NPROC && limit->rlim_max > 8: limit->rlim_max => 8,
			limit->rlim_cur > limit->rlim_max: limit->rlim_cur => limit->rlim_max-1
skip:			resource == RLIMIT_CPU

[socket]
default:		terminate
allow:			domain == AF_UNIX && type == SOCK_STREAM,
			domain == AF_LOCAL && type == SOCK_STREAM
			
[open]
default:		skip
redirect:		path dir_ends_with(".dat") => ".txt"
```
The Configuration Builder creates the following seccomp instructions for the client.
```c
// Add specific allow rules
sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 2, SCMP_A0(SCMP_CMP_EQ, AF_LOCAL),SCMP_A1(SCMP_CMP_EQ, SOCK_STREAM));
sec_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 2, SCMP_A0(SCMP_CMP_EQ, AF_UNIX),SCMP_A1(SCMP_CMP_EQ, SOCK_STREAM));
// Add specific skip rules
sec_seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setrlimit), 1, SCMP_A0(SCMP_CMP_EQ, RLIMIT_CPU));
// Add general modify rules
sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_EXECUTE), SCMP_SYS(open), 0);
sec_seccomp_rule_add(ctx, SCMP_ACT_TRACE(PTRACE_EXECUTE), SCMP_SYS(setrlimit), 0);
// Add default actions for custom system calls
sec_seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 0);
```
On the tracer part of the application, the following output is generated:
```c
void sec_open(pid_t pid, const char *filename, int flags, mode_t mode){
	(void)pid;
	(void)filename;
	(void)flags;
	(void)mode;

	struct sec_rule_result __rule_action;
	__rule_action.new_value = NULL;
	__rule_action.size = -1;
	__rule_action.action = SEC_ACTION_SKIP;
	
	{
		struct sec_rule_result redirect_result = changeStringOnEndMatch(pid, ".dat", filename, strlen(filename)+1, ".txt", true);
		executeRuleResult(pid, redirect_result, PAR1, false);
		if (redirect_result.action == SEC_ACTION_MODIFY){
			__rule_action.action = SEC_ACTION_ALLOW;
		}
	}
	
	executeRuleResult(pid, __rule_action, -1, false);
}

void sec_setrlimit(pid_t pid, int resource, struct rlimit *rlim){
	(void)pid;
	(void)rlim;
	(void)resource;
	
	struct sec_rule_result __rule_action;
	__rule_action.new_value = NULL;
	__rule_action.size = -1;
	__rule_action.action = SEC_ACTION_TERMINATE;
	
	if(resource == RLIMIT_NPROC && rlim->rlim_max > 8){
		rlim->rlim_max = 8;
		modifyParameter(pid, PAR2, rlim, sizeof(struct rlimit));
		__rule_action.action = SEC_ACTION_ALLOW;
	}
	if(rlim->rlim_cur > rlim->rlim_max){
		rlim->rlim_cur = rlim->rlim_max-1;
		modifyParameter(pid, PAR2, rlim, sizeof(struct rlimit));
		__rule_action.action = SEC_ACTION_ALLOW;
	}
	
	executeRuleResult(pid, __rule_action, -1, false);
}

void performSystemcall(pid_t pid, int status, int syscall_n){
	switch (syscall_n){
		case SYS_open:
			{
				mode_t mode = (mode_t)readInt(pid, PAR3);
				int flags = (int)readInt(pid, PAR2);
				char *filename = readTerminatedString(pid, PAR1);
				sec_open(pid, filename, flags, mode);
				free(filename);
			}
			break;
		case SYS_setrlimit:
			{
				struct rlimit *rlim = readData(pid, PAR2, sizeof(struct rlimit));
				int resource = (int)readInt(pid, PAR1);
				sec_setrlimit(pid, resource, rlim);
				free(rlim);
			}
			break;
		default:
			{
				invalidateSystemcall(pid);
				if (status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))){
					printf("Called invalide system call [%d]. Application will be terminated.\n", syscall_n);
					kill(pid, SIGSTOP);
					exit(0);
				}
			}
	}
}
```
