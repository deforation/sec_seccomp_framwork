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

#ifndef SEC_TRACER_H
#define SEC_TRACER_H

void init_error_handling();
void start_tracer();

#endif  //SEC_TRACER_H