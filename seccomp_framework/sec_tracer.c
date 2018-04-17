/******************************************************************
* Seccomp Toolkit by Remo Schweizer as a part of the master thesis
*                  ____ _ _  ___  _ _ _ 
*                 |_  /| | || . || | | |
*                  / / |   ||   || | | |
*                 /___||_|_||_|_||__/_/ 
*                      
* Tracer module of the seccomp framework
* Runs the tracer which intercepts the child application
* on systemcalls triggered by seccomp rules.
*
* The tracer supports the handling of multithreaded and
* forked applications. This may lead to severe performance
* issues, because when one thread is interecepted, the others
* have to be halted
*
* If any kind of problem exists within the tracer,
* the main application is halted too
*
* If the debug part is enabled, some actions are reported
* using the syslog module. All messages belong to the
* application name: sec_seccomp_log in /var/log/syslog
*
* The application has also a signal handler attached to it,
* so error messages can be triggered when the tracer has 
* itself insufficient rights for some system calls
* This can be the case, because the tracer itself has 
* also a limited range of functionalities to improve security
*
* In the ideal case, the tracer has the exact same priviliges
* with just a little bit more to perform the trace and manipulation
* actions
*
* -----------------------------------------------------------------
* Version: 1.0
* -----------------------------------------------------------------
* 01.04.2018:       schwerem        Version 1.0 implemented
* -----------------------------------------------------------------
*
******************************************************************/

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "sec_ptrace_lib.h"
#include "sec_syscall_emulator.h"
#include "sec_seccomp_rules.h"

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

extern int errno;


/*
* Description:
* Catch violations so we see, which system call caused the problems
*
* Parameter:
* sig: integer for the signal number
* si: siginfo_t containing information about the signal
* threadContext: informations about the thread
*/
static void catch_violation(int sig, siginfo_t* si, void* threadContext)
{
  (void)threadContext;

  if (si->si_code == SYS_SECCOMP){
	  char errormsg[255];
	  sprintf(errormsg, "Tracer: Attempted banned syscall with number [%d].\n", si->si_syscall);
	  write(STDOUT_FILENO, errormsg, strlen(errormsg));
	  exit(sig);
	}
}

/*
* Description:
* Setup error handling
*/
void init_error_handling(){
	struct sigaction sa = { .sa_sigaction = catch_violation, .sa_flags = SA_SIGINFO };
	if (sigaction(SIGSYS, &sa, NULL)){
		printf("sigaction(SIGSYS) -> [%s]\n", strerror(errno));
	}
}

/*
* Description:
* Terminates the application, if the child has a severe issue
* which may be errors within the source, external
* interceptions,...
*
* Parameter:
* status:	status info of waitpid
*/
void terminateOnChildError(int status){
	//long sc_number, sc_retcode;

	if (WIFEXITED(status)) {
        printf("\nChild exit with status %d\n", WEXITSTATUS(status));
        exit(0);
    }
    if (WIFSIGNALED(status)) {
        printf("\nChild exit due to signal %d\n", WTERMSIG(status));
        exit(0);
    }
    if (!WIFSTOPPED(status)) {
        printf("\nwait() returned unhandled status 0x%x\n", status);
        exit(0);
    }
    if (WSTOPSIG(status) == SIGTRAP || WSTOPSIG(status) == SIGCONT || WSTOPSIG(status) == SIGCONT+1) {
        /* Note that there are *three* reasons why the child might stop
         * with SIGTRAP:
         *  1) syscall entry
         *  2) syscall exit
         *  3) child calls exec
         */
    	/*
        sc_number = ptrace(PTRACE_PEEKUSER, pid, SC_NUMBER, NULL);
        sc_retcode = ptrace(PTRACE_PEEKUSER, pid, SC_RETCODE, NULL);

        (void)sc_number;
        (void)sc_retcode;*/
        //printf("SIGTRAP: syscall %ld, rc = %ld\n", sc_number, sc_retcode);
    } else {
        printf("\nChild stopped due to signal %d\n", WSTOPSIG(status));
        exit(0);
    }
}

//-------------------------------------------------------
//
// Tracer
//
//-------------------------------------------------------

/*
* Description:
* Creates a log entry with the syslog module
* the log entry contains information about the
* intercepted systemcall and the executed action
*
* for a good overview about the systemcall numbers 
* look on https://filippo.io/linux-syscall-table/
*
* Parameter:
* action:		The performed action as a string
* syscall:		System call number
*/
void log_debug_action(const char *action, int syscall){
	char str[1024];
	sprintf(str, "SECCOMP SYSTEMCALL: (%s, %d)\n", action, syscall);
	writeLog(LOG_INFO, str);
}

/*
* Description:
* Runs the tracer.
* At the beginning, the error handling is initialized
* after we have successfully connected to the tracee,
* the seccomp rules are applied to the tracer part
* of the application
*
* The tracer then intercepts all system calls performed
* by any child, thread,...
*
* Parameter:
* action:		The performed action as a string
* syscall:		System call number
*/
void start_tracer(){
	// initialize error handling
	init_error_handling();

	struct user_regs_struct regs;
	pid_t pid;
	long trace_message = -1;
	int status = 0;
	int syscall_n = 0;

	// wait for client to appear
	pid = waitpid(-1, &status, __WALL);
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK );

	// load seccomp rules
	loadTracerSeccompRules();

	// reset errno
	errno = 0;
	while(1){
		// Init wait for event
		ptrace(PTRACE_EVENT_SECCOMP, pid, 0, 0 );

		// wait for event to happen
		pid = waitpid(-1, &status, __WALL);

		// Terminate the application, when a child has an error (unexpected termination)
		terminateOnChildError(status);

		if (status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))){
			// read the child's registers and get the system call number
			ptrace(PTRACE_GETREGS, pid, 0, &regs );
			syscall_n = regs.orig_rax;

			// retrieve the ptrace message
			ptrace(PTRACE_GETEVENTMSG, pid, 0, &trace_message);

			// interprete and handle the ptrace event messages
			bool interfere = false;
			if (trace_message & PTRACE_DBG_ALLOW){
				log_debug_action("ALLOW", syscall_n);
			} else if (trace_message & PTRACE_DBG_TERMINATE){
				log_debug_action("TERMINATE", syscall_n);
				kill(pid, SIGSTOP);
				exit(0);
			} else if (trace_message & PTRACE_DBG_MODIFY){
				log_debug_action("MODIFY", syscall_n);
				interfere = true;
			} else if (trace_message & PTRACE_DBG_SKIP){
				log_debug_action("SKIP", syscall_n);
				invalidateSystemcall(pid);
				modifyReturnValue(pid, -1);
			} else if (trace_message & PTRACE_EXECUTE){
				interfere = true;
			}

			// if we are on the productive system (no debug)
			// or modify is called, we run the emulator
			if (interfere == true){
				performSystemcall(pid, status, syscall_n);
			}
		}
	}
}