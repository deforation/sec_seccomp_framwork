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

#ifndef SEC_CLIENT_H
#define SEC_CLIENT_H

void init_client();
void write_test();

#endif  //SEC_BROKER_H