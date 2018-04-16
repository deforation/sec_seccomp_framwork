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

#ifndef SECLIB_H
#define SECLIB_H

typedef int (*sec_main_function)(int, char **);
int run_seccomp_framework(int argc, char **argv, sec_main_function before, sec_main_function after);

#endif  //SECLIB_H