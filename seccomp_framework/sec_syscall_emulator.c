#include <unistd.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <syslog.h>
#include "sec_syscall_emulator.h"
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <signal.h>
#include "sec_ptrace_lib.h"

void sec_open(pid_t pid, const char *filename, int flags, mode_t mode){
	(void)pid;
	(void)mode;
	(void)filename;
	(void)flags;
	
	{
		// print function call end parameters if debug is active
		char log[1024];
		sprintf(log, "Process %d called open(%s, %d, %d) ", pid, filename, flags, mode);
		writeLog(LOG_INFO, log);
	}
	
	struct sec_rule_result __rule_action;
	__rule_action.new_value = NULL;
	__rule_action.size = -1;
	__rule_action.action = SEC_ACTION_SKIP;
	
	if((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR){
		{
			struct sec_rule_result redirect_result = changeStringOnStartMatch("/home/remo/Schreibtisch/test/modify", filename, strlen(filename)+1, "/home/remo/Schreibtisch/test/redirected_readwrite", true);
			executeRuleResult(pid, redirect_result, PAR1, false);
			if (redirect_result.action == SEC_ACTION_MODIFY){
				__rule_action.action = SEC_ACTION_ALLOW;
			}
		}
	}
	if((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR){
		{
			struct sec_rule_result redirect_result = changeStringOnStartMatch("/home/remo/Schreibtisch/test/modify", filename, strlen(filename)+1, "/home/remo/Schreibtisch/test/redirected_read", true);
			executeRuleResult(pid, redirect_result, PAR1, false);
			if (redirect_result.action == SEC_ACTION_MODIFY){
				__rule_action.action = SEC_ACTION_ALLOW;
			}
		}
	}
	{
		struct sec_rule_result redirect_result = changeStringOnEndMatch(".dat", filename, strlen(filename)+1, ".txt", true);
		executeRuleResult(pid, redirect_result, PAR1, false);
		if (redirect_result.action == SEC_ACTION_MODIFY){
			__rule_action.action = SEC_ACTION_ALLOW;
		}
	}
	
	if(stringMatchesStart("/home/remo/Schreibtisch/test/skip", filename, strlen(filename)+1, true)){
		__rule_action.action = SEC_ACTION_SKIP;
	}
	else if((stringMatchesStart("/home/remo/Schreibtisch/test/valid", filename, strlen(filename)+1, true)) && ((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR)){
		__rule_action.action = SEC_ACTION_ALLOW;
	}
	else if((stringMatchesStart("/home/remo/Schreibtisch/test/fd_copy_deny", filename, strlen(filename)+1, true)) && ((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR)){
		__rule_action.action = SEC_ACTION_ALLOW;
	}
	else if((stringMatchesStart("/home/remo/Schreibtisch/test/write_yes_create_no", filename, strlen(filename)+1, true)) && (flags & O_CREAT)){
		__rule_action.action = SEC_ACTION_TERMINATE;
	}
	else if((stringMatchesStart("/home/remo/Schreibtisch/test/write_yes_create_no", filename, strlen(filename)+1, true)) && ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR)){
		__rule_action.action = SEC_ACTION_ALLOW;
	}
	else if((stringMatchesStart("/home/remo/Schreibtisch/test/fd_copy_deny/test.txt", filename, strlen(filename)+1, true)) && ((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR)){
		__rule_action.action = SEC_ACTION_ALLOW;
	}
	
	executeRuleResult(pid, __rule_action, -1, false);
}

void sec_getcwd(pid_t pid, char *buf, unsigned long size){
	(void)pid;
	(void)size;
	(void)buf;
	
	{
		// print function call end parameters if debug is active
		char log[1024];
		sprintf(log, "Process %d called getcwd(buffer, %ld) ", pid, size);
		writeLog(LOG_INFO, log);
	}
	
	// simulate getcwd
	char *name = malloc(size);
	
	sprintf(name, "/proc/%d/cwd", pid);
	realpath(name, buf);
	
	free(name);
	
	// set return value and modify the return parameter
	modifyReturnParameter(pid, PAR1, buf, size);
	modifyReturnValue(pid, strlen(buf));
	invalidateSystemcall(pid);
	
}

void sec_chdir(pid_t pid, const char *path){
	(void)pid;
	(void)path;
	
	{
		// print function call end parameters if debug is active
		char log[1024];
		sprintf(log, "Process %d called chdir(%s) ", pid, path);
		writeLog(LOG_INFO, log);
	}
	
	struct sec_rule_result __rule_action;
	__rule_action.new_value = NULL;
	__rule_action.size = -1;
	__rule_action.action = SEC_ACTION_ALLOW;
	
	{
		struct sec_rule_result redirect_result = changeStringOnStartMatch("/home/remo/Schreibtisch/test/invalid", path, strlen(path)+1, "/home/remo/Schreibtisch/test/valid", true);
		executeRuleResult(pid, redirect_result, PAR1, false);
		if (redirect_result.action == SEC_ACTION_MODIFY){
			__rule_action.action = SEC_ACTION_ALLOW;
		}
	}
	{
		struct sec_rule_result redirect_result = changeStringOnStartMatch("/home/remo/Schreibtisch/test/modify", path, strlen(path)+1, "/home/remo/Schreibtisch/test/redirected_readwrite", true);
		executeRuleResult(pid, redirect_result, PAR1, false);
		if (redirect_result.action == SEC_ACTION_MODIFY){
			__rule_action.action = SEC_ACTION_ALLOW;
		}
	}
	{
		struct sec_rule_result redirect_result = changeStringOnStartMatch("/home/remo/Schreibtisch/test/modify", path, strlen(path)+1, "/home/remo/Schreibtisch/test/redirected_read", true);
		executeRuleResult(pid, redirect_result, PAR1, false);
		if (redirect_result.action == SEC_ACTION_MODIFY){
			__rule_action.action = SEC_ACTION_ALLOW;
		}
	}
	
	if(stringMatchesStart("/home/remo/Schreibtisch/test/skip", path, strlen(path)+1, true)){
		__rule_action.action = SEC_ACTION_SKIP;
	}
	
	executeRuleResult(pid, __rule_action, -1, false);
}

void sec_setrlimit(pid_t pid, int resource, struct rlimit *rlim){
	(void)pid;
	(void)resource;
	(void)rlim;
	
	{
		// print function call end parameters if debug is active
		char log[1024];
		sprintf(log, "Process %d called setrlimit(%d, [%ld, %ld]) ", pid, resource, rlim->rlim_cur, rlim->rlim_max);
		writeLog(LOG_INFO, log);
	}
	
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

void sec_gettimeofday(pid_t pid, struct timeval *tv, struct timezone *tz){
	(void)pid;
	(void)tz;
	(void)tv;
	
	time_t t;
	int retval = gettimeofday(tv, tz);
	
	// we wont expose the real time to the calling application, so we add a random value on top of it
	srand((unsigned) time(&t));
	float offset = (float)rand() - RAND_MAX/2;
	tv->tv_sec += (int)(offset / RAND_MAX * 20.0);
	
	// overwrite the return value of the system call and its parameters
	modifyReturnParameter(pid, PAR1, tv, sizeof(struct timeval));
	modifyReturnParameter(pid, PAR2, tz, sizeof(struct timezone));
	modifyReturnValue(pid, retval);
	
	// to use the overwritten data (emulation)
	// we have to skip the system call execution on the client application
	invalidateSystemcall(pid);
	
}

void sec_socket(pid_t pid, int domain, int type, int protocol){
	(void)pid;
	(void)domain;
	(void)type;
	(void)protocol;
	
}

void sec_dup(pid_t pid, int oldfd){
	(void)pid;
	(void)oldfd;
	
	struct sec_rule_result __rule_action;
	__rule_action.new_value = NULL;
	__rule_action.size = -1;
	__rule_action.action = SEC_ACTION_ALLOW;
	
	
	if(fdPathMatchesStart(pid, "/home/remo/Schreibtisch/test/fd_copy_deny/test.txt", oldfd)){
		__rule_action.action = SEC_ACTION_SKIP;
	}
	
	executeRuleResult(pid, __rule_action, -1, false);
}

void sec_fcntl(pid_t pid, int fd, int cmd){
	(void)pid;
	(void)cmd;
	(void)fd;
	
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

		case SYS_getcwd:
			{
				unsigned long size = (unsigned long)readInt(pid, PAR2);
				char *buf = readData(pid, PAR1, size);
				sec_getcwd(pid, buf, size);
				free(buf);
			}
			break;

		case SYS_chdir:
			{
				char *path = readTerminatedString(pid, PAR1);
				sec_chdir(pid, path);
				free(path);
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

		case SYS_gettimeofday:
			{
				struct timezone *tz = readData(pid, PAR2, sizeof(struct timezone));
				struct timeval *tv = readData(pid, PAR1, sizeof(struct timeval));
				sec_gettimeofday(pid, tv, tz);
				free(tz);
				free(tv);
			}
			break;

		case SYS_socket:
			{
				int protocol = (int)readInt(pid, PAR3);
				int type = (int)readInt(pid, PAR2);
				int domain = (int)readInt(pid, PAR1);
				sec_socket(pid, domain, type, protocol);
			}
			break;

		case SYS_dup:
			{
				int oldfd = (int)readInt(pid, PAR1);
				sec_dup(pid, oldfd);
			}
			break;

		case SYS_fcntl:
			{
				int cmd = (int)readInt(pid, PAR2);
				int fd = (int)readInt(pid, PAR1);
				sec_fcntl(pid, fd, cmd);
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

