# sec_seccomp_framwork
The sec_seccomp_framework provides an easy way to implement privilege dropping and system call manipulations for linux operating systems. The framework does not represent a sandbox, it aims for software developers who want to improve the security of their application against privilege escalation attacks.

## Capabilities
The framework offers the ability to:
* Generate seccomp bpf filter programs with an easy to use and extensive rule design
* Manipulate parameters and the return value of system calls before and afther their execution using the integrated ptrace module
* Integrate the framework into an existing applications with little effort

## Requirements
The framework has for the rule generation process the following requirements:
* Python >= 3.5
* Python libraries: argparse, ConfigParser
* Linux-packages: libseccomp-dev

The c-part of the framework requires:
* seccomp development libraries
* os: Linux or linux based derivate (tested on Debian GNU/Linux 9)
* currently: x86 or x64 structure
* recommended: kernel version >= 4.8

In the debug mode, seccomp will be initialized with the flag SECCOMP_FILTER_FLAG_LOG,
which automatically logs all seccomp actions under "/proc/sys/kernel/seccomp/actions_logged".
Note, that this feature is only available with a kernel version >= 4.14.

## Usage
To use the framework, the following steps must be performed:
1. Download the respository
2. Rename the main function (int main ...) of the application to (int sec_main_after) or something else
3. Optional: Add a main function (int sec_main_before ...) if needed, to perform privileged actions
4. Include the header file "seclib.h"
5. Create a new main function and call: return run_seccomp_framework(argc, argv, sec_main_before, sec_main_after);
6. Write rules and modify/extend the system call configuration file if required.
7. Generate the seccomp and tracer rule checks with the python script "SecConfigBuilder.py"
8. Copy the generated files into the directory "seccomp_framework" or let the script generate it directly into it.
9. Compile the application [all framework files have to be linked]

These 9 easy steps are everything it needs to configure and use the framework.

Note: Step 5 is the main call which starts the whole seccomp framework.
The function call consists of 4 parameters:
* argc: Number of arguments
* argv: Arguments
* sec_main_after: Main function which should be executed before seccomp is initialized
* sec_main_after: Main function which should be executed after seccomp is initialized
sec_main_after and sec_main_before can have any name. It is only necessary that they have the the following type: typedef int (*sec_main_function)(int, char **);

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
#include <stdlib.h>
#include "seclib.h"

// function prototypes
int sec_main_before(int argc, char **argv);
int sec_main_after(int argc, char **argv);

int main(int argc, char **argv){
	return run_seccomp_framework(argc, argv, sec_main_before, sec_main_after);
}

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

## Rule configuration scheme

The rules config file defines what actions are allowed on system calls. It is possible to define global rules or for specific system calls. The rule design allows to define system calls which should be
allowed, skipped, modified or system calls which should lead to a termination of the application

To be able to define actions based on parameter values, the rule design also allows to check parameters against
specific values or change the value of those.

Note, that the tracer needs most likely at least access to the following system calls to be fully operational
- ptrace, wait4, getpid, socket, 
  sendto, read, chdir, getcwd, fstat,
  lseek, lstat, readlink, kill, open,
  exit, exit_group, write, close, connect


A normal client application needs at least the following permissions so it is able to startup and terminate without any further logic:
 - exit, exit_group, write, read

Note that the actions have the following behaviour:
 - terminate: Terminates the application
 - skip: Does not run the system call. Errno is set to ENOSYS instead. (Only in productive mode)
         In debug mode, -1 is returned by the system call instead because errno can not easily be set by the tracer.
 - allow: Executes the system call.
 - trap: Calls the trap function which terminates the application and prints the causing system call number.
 - modify: Reroutes the system call to the tracer which can emulate it (modify the return value), perform deep inspection on pointer arguments, modify arguments or let the application execute it.

The rule file itself has the following structure (or see the example rule file in the repository):
```
[General]
debug:     		True or False
default_action:		{action} (allow, terminate, trap, skip or modify)
default_action_tracer:	{action} (allow, terminate, trap, skip)

# defines which systemcalls shoud strictly be allowed, forbidden,...
syscall {action}:		list of systemcalls like (open, write, ...)
# the same for the tracer
tracer {action}:		list of systemcalls like (open, write, ...)

[Global]
# Allows to define rules targeting all system calls which
# contain all the given field groups

[{syscall_name}{after}]
# Allows to specify rules for specific system calls
```

```
There exist different ways to define rules.
The following constructs are supported:
Keep in mind, that each rule can only apper once, but it is possible
to specify multiple checks / actions by separating them with a comma

 - {after}		Allows to specify special rules when the system call
			was already executed, allowing to check and manipulate
			return parameters of functions like: read, recvmsg, ...
			The normal behaviour of seccomp is to check the system call
			before it is executed
			example: [read:after]
			exanoke: [recvmsg:after]

- {action} 		represents an action like (terminate, allow, skip, trap)

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
			example: return

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
 			example: redirect:		buf contains("invalid"): return => -1


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

Note: The normal behaviour of seccomp is to check a system call
before it is executed. Unfortunately, many system calls become
interesting after they have been executed.
To be able to inspect the data after the execution,
the :after flag can be added to the system calls section name.
With the flag, the rules will be applied once the call is finished.
 - It is possible to define the normal section and the after version
 - Within the c-configuration file, an equivalent function block has to be defined by adding :after to the system call name: SYS_read:after,...
 - The action skip has no effect when the system call was already executed


The rule configuration logic allows also to modify and check strings and paths using. The prefix dir_ is necessary if the auto resolve of the path within the system call argument should automatically be resolved. Note that the value it should be checked against is also automatically resolved, which allows to define relative path checks
 - dir_starts_with("path") 
 - dir_contains("path") 
 - dir_ends_with("path")


If on the other way, we want to check strings itself, the following functions hould be used:
 - starts_with("string") 
 - contains("string") 
 - ends_with("string")

There is also a way to perform checks (no modifications) on the path of a file descriptor. Note, that file descriptors generally have no strictly defined path representation, especially if we deal with hardlinks,... 
The functions resolve the path based on the directory "/proc/pid/fd/fdnum"
 - fd_path_starts_with("path")
 - fd_path_contains("path")
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

[recvfrom:after]
default:			modify
buf redirect:			starts_with("GET /data/private/") => "GET /data/public/"	
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

Note: 
There are 3 different length flags called (set_length, read_length and link_update)
 - set_length:  defines the length of a system all argument. This can either be strlen or mor likely strlen+1, the name of another argumen or it can be skiped. If the value is skiped, sizeof(datatype) is used by default
 - read_length: The read length defines how many bytes have to be read from the target application. This has the following reason: If we modify the read systemcall after it was executed we are able to manipulate the retrieved data. Now, if we would read the whole length according to the buffer size we may end up reading parts of old data. To prevent this, we need the return value of the system call, which gives us the information how many bytes have been read (are valid in the buffer). In the case of SYS_read, we would therefore have to define the length to "return". As a result, only the given amount of data is read. If the option is not defined, the set_length rule is used.
 - link_update: Enables the possibility to link updates. So that after a specific parameter was manipulated, a second one will be modified at the same time. This allows us to define a rule to modify for example the output of the read system call and return the new length of the modified string with the system call. If we for example change the read output of "leet" to "magnus", the return value has to be set to the new length of magnus. Otherwise the application would just read "magn", which is not what we want. The same behaviour can be observed with the write system call. If the write buffer is modified, the count parameter has to be updated to the length of the new buffer.
Note: This option is currently only supported in combination with buffer manipulations.
example for SYS_read:after:  link_update[buf]:	return=strlen+1
example for Sys_write:		 link_update[buf]:	count=strlen+1

```
A function definition has the following format consisting
of a comment block defining important data and the function itself

 - {syscall_name}:		Describes the name of the system call which
				will be modified. Starts usually with SYS_{name}
				Te modifier ":after" can be added to the system call
				name. This means, that the function will be called
				after the system call was executed.
				It is possible to define the normal and the after version
				but the functions must have a different name						
				example: SYS_open, SYS_gettimeofday
				example: SYS_read:after, SYS_recvmsg:after

- {after}:			Allows to specify the flag ":after".
				This means, that the function will be called
				after the system call was executed.
				If the flag is not set, the check is done before execution

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
* read_length[{field}]:		{length}
* link_update[{field}]:		{field}={length}
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

/*
* systemcall:			SYS_recvfrom:after
* headers:				sys/types.h, sys/socket.h
*
* set_length[buf]:		len
* read_length[buf]:		return
* link_update[buf]:		return=strlen+1
*/
void sec_recvfrom_after(int sockfd, __OUT void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
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
```

## Debug support
The framework offers the flag "debug" within the "General" section of the rule configuration file.
Once the flag is set, seccomp rules like (terminate, allow and skip) wont be executed by seccomp itself.
Instead, all requests are redirected to the tracer which offers the possibility to print debug information.
To find why an application may terminate, which is likely if not all system calls have been allowed which should be able to use by the application. Second, all defined debug sections within the system call configuration file. In some cases, when the default rule is set to terminate for the tracer or in the productive environment for the client, it is hard to detect which system call lead to termination. Therefore it may be useful to set the default action to trap. As a result, the applicaiton will on termination display, which system call lead to termination.

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
* Add support for more architectures (currently limited by the bpf code generation [arch support] AUDIT_ARCH_X86_64)
* Performance improvements so paths are only resolved once for each system call and not for each check
* Add bpf filter support for more than 255 instructions (current limit is caused by the max jump distance)
* Add support for || parameter checks in seccomp bpf instead of only && statements
* Other pending changes are noted in the source files
* Add binary search within large seccomp bpf programs to improve the performance

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
sec_seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(setrlimit), 1, SCMP_A0(SCMP_CMP_EQ, RLIMIT_CPU));
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
		struct sec_rule_result new_string = changeStringOnEndMatch(pid, ".dat", filename, strlen(filename)+1, ".txt", true);
		if (new_string.action == SEC_ACTION_MODIFY){
			filename = realloc(filename, new_string.size);
			memcpy(filename, new_string.new_value, new_string.size);
			
			__rule_action.action = SEC_ACTION_ALLOW;
		}
		executeRuleResult(pid, new_string, PAR1, false, -1);
	}
	
	executeRuleResult(pid, __rule_action, -1, false);

	free(filename);
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

	free(rlim);
}

void performSystemcall(pid_t pid, int status, int syscall_n){
	switch (syscall_n){
		case SYS_open:
			{
				mode_t mode = (mode_t)readInt(pid, PAR3);
				int flags = (int)readInt(pid, PAR2);
				char *filename = readTerminatedString(pid, PAR1);
				sec_open(pid, filename, flags, mode);
			}
			break;
		case SYS_setrlimit:
			{
				struct rlimit *rlim = readData(pid, PAR2, sizeof(struct rlimit));
				int resource = (int)readInt(pid, PAR1);
				sec_setrlimit(pid, resource, rlim);
			}
			break;
		default:
			{
				invalidateSystemcall(pid);
				if (status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))){
					printf("Called invalide system call [%d]. Application will be terminated.\n", syscall_n);
					kill(pid, SIGKIL);
				}
			}
	}
}
```
