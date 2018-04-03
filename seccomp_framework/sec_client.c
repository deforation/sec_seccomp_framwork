/******************************************************************
* Seccomp Toolkit by Remo Schweizer as a part of the master thesis
*                  ____ _ _  ___  _ _ _ 
*                 |_  /| | || . || | | |
*                  / / |   ||   || | | |
*                 /___||_|_||_|_||__/_/ 
*                      
* Client part of the seccomp framework
* This module is required to initialize the debugging handler
* and the seccomp rules
*
* -----------------------------------------------------------------
* Version: 1.0
* -----------------------------------------------------------------
* 01.04.2018:       schwerem        Version 1.0 implemented
* -----------------------------------------------------------------
*
* TODO:
*  - Link the activation / deactivation of the debugging handler
*    to the python script
*
******************************************************************/

#define _GNU_SOURCE
#include "sec_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "sec_seccomp_rules.h"

extern int errno;

/*
* Description:
* Callback handler for the signal just printing the
* received signal
*
* Parameter:
* signum: integer for the signal number
*/
void signal_callback_handler_client(int signum)
{
   printf("Caught signal %d\n",signum);

   // Cleanup and close up stuff here
   // Terminate program
   exit(signum);
}

/*
* Description:
* Catch violations so we see, which system call caused the problems
*
* Parameter:
* sig: integer for the signal number
* si: siginfo_t containing information about the signal
* threadContext: informations about the thread
*/
static void catchViolation(int sig, siginfo_t* si, void* threadContext)
{
  (void)threadContext;
  printf("Client: Attempted banned syscall number [%d] see doc/Seccomp.md for more information [%d]\n", si->si_syscall, sig);
  exit(sig);
}

/*
* Description:
* Setup error handling
*/
static void init_error_handling(){
	signal(SIGSYS, signal_callback_handler_client);	

	struct sigaction sa = { .sa_sigaction = catchViolation, .sa_flags = SA_SIGINFO };
	if (sigaction(SIGSYS, &sa, NULL)){
		printf("sigaction(SIGSYS) -> [%s]\n", strerror(errno));
	}
}


/*
* Description:
* Initializes the debugging helper
* and the seccomp rules for the client
*/
void init_client()
{
	init_error_handling();
	loadClientSeccompRules();
}

