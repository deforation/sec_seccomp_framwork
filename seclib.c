/******************************************************************
* Seccomp Toolkit by Remo Schweizer as a part of the master thesis
*                  ____ _ _  ___  _ _ _ 
*                 |_  /| | || . || | | |
*                  / / |   ||   || | | |
*                 /___||_|_||_|_||__/_/ 
*                      
* This module contains the main function to initialize and start
* the seccomp framework.
* At the beginning, the application performs a fork
* the parent process becomes the tracer and the child
* process becomes the tracee.
* 
* To be able to trace the child process, execvp is used to 
* run the application again. To not perform an endless loop,
* the application checks at the beginning, if a tracer (debugger)
* is attached to the process. This tracee must logically have
* the same path as the application itself.
*
* The child process then runs the main_before function if it 
* is defined. This allows an application to perform tasks
* without any limitations in permissions.
* Afterwards, the seccomp rules are initialized and the 
* main_after function is called. This is where the main
* application starts. All actions are now restricted by 
* seccomp and the defined rules within the tracer.
*
* -----------------------------------------------------------------
* Version: 1.1
* -----------------------------------------------------------------
* 16.04.2018:		schwerem		Changed logic so the framework
*									can be run as a command so it 
*									does not overwrite the main function
* 01.04.2018:       schwerem        Version 1.0 implemented
* -----------------------------------------------------------------
*
******************************************************************/

#include "seclib.h"
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

// Some macros for easy readibility
#define IS_CHILD_PROC(pid) 	pid==0
#define true 1
#define false 0

// prototypes
int is_tracer_present(void);
char *get_application_path(pid_t pid);

/*
* Description: 
* Defines the main before routine which is called at the beginning
* of the client application life time cycle.
* As long as its use is defined within the main application
*
* Parameters:
* argc: number of arguments
* argv: arguments
*
* Returns:
* Exit message
*/
int main_before(int argc, char **argv){
	(void)argc;
	(void)argv;

	#ifdef SEC_MAIN_BEFORE
		return sec_main_before(argc, argv);
	#else 
		return EXIT_SUCCESS;
	#endif
}


/*
* Description: 
* Defines the main after routine which is called after the 
* initialization of seccomp. This routine starts
* the main application
*
* Parameters:
* argc: number of arguments
* argv: arguments
*
* Returns:
* Exit message
*/
int main_after(int argc, char **argv){
	(void)argc;
	(void)argv;

	#ifdef SEC_MAIN_AFTER
		return sec_main_after(argc, argv);
	#else
		return EXIT_FAILURE;
	#endif
}

/*
* Description: 
* Starts the tracer part of the application
*/
void run_tracer(){
	start_tracer();
}


/*
* Description: 
* Initializes the client and runs the main application
*
* Parameters:
* argc: number of arguments
* argv: arguments
*
* Returns:
* Exit message
*/
int run_client(int argc, char **argv){
	init_client();
	return main_after(argc, argv);
}

/*
* Description: 
* Returns the path of an application
* represented through its process id
*
* Parameters:
* pid: process id
*
* Returns:
* Path to the application (needs to be freed)
*/
char *get_application_path(pid_t pid){
	char *path = malloc(PATH_MAX);

	sprintf(path, "/proc/%d/exe", pid);
	readlink(path, path, PATH_MAX);

	return path;
}

/*
* Description: 
* Checks if a tracer / debugger is precent, which is necessary 
* to check if it is the first start of the application or the second
*
* Source mostly based on:
* https://stackoverflow.com/questions/3596781/how-to-detect-if-the-current-process-is-being-run-by-gdb
*
* Returns:
* true if the tracer is present, otherwise false
*/
int is_tracer_present()
{
    char buf[1024];
    int tracer_present = false;

    int status_fd = open("/proc/self/status", O_RDONLY);
    if (status_fd == -1)
        return 0;

    ssize_t num_read = read(status_fd, buf, sizeof(buf)-1);

    if (num_read > 0)
    {
        static const char TracerPid[] = "TracerPid:";
        char *tracer_pid;

        buf[num_read] = 0;
        tracer_pid    = strstr(buf, TracerPid);

        if (tracer_pid){
        	pid_t pid = atoi(tracer_pid + sizeof(TracerPid) - 1);
            tracer_present = !!atoi(tracer_pid + sizeof(TracerPid) - 1);

            // check if the debugger is the same executable
            if (tracer_present){
            	char *tracer = get_application_path(pid);
            	char *app = get_application_path(getpid());

            	if (strcmp(tracer, app) == 0){
            		tracer_present = true;
            	} else {
            		tracer_present = false;
            	}

            	free(tracer);
            	free(app);
            }
        }
    }

    return tracer_present;
}

/*
* Description: 
* Launches the application
* 
* On the first run, the process is forked to the application and the tracer
* the child process let it self be attached to a debugger / tracer
* in the second launch, the client application is launched
*
* the before function will be executed before seccomp is initialized
* the after function will be executed after seccomp is initalized
* It is not necessary to pass a function when it is not used.
* So NULL is a valid value, which means, that the function call will 
*
* Parameters:
* argc: Number of arguments
* argv: Arguments
* before: defines the function to be called before seccomp is initialized
* after: defines the functio to be called after seccomp is initialized
*
* Returns:
* Exit message
*/
int run_seccomp_framework(int argc, char **argv, sec_main_function before, sec_main_function after){
	int exit_state = 0;
	(void)argv;

	// if no debugger is present, we are on the first run
	if (!is_tracer_present()){
		pid_t pid = fork();

		if (IS_CHILD_PROC(pid)){
			ptrace(PTRACE_TRACEME, 0, 0, 0);
			exit_state = execvp(argv[0], argv);
		} else {
			run_tracer();
		}
	} else {
		// Run user main before
		if (before != NULL){
			if ((exit_state = before(argc, argv)) != EXIT_SUCCESS){
				return exit_state;
			}
		}

		init_client();

		// run the user main after (seccomp is now initialized)
		if (after != NULL){
			exit_state = after(argc, argv);
		}
	}
	return exit_state;
}