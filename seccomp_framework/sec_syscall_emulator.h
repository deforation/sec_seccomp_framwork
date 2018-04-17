#ifndef SEC_SYSCALL_EMULATOR_H

#define SEC_SYSCALL_EMULATOR_H

#include <unistd.h>

void performSystemcall(pid_t pid, int status, int syscall_n, int use_after_check);

#endif //SEC_SYSCALL_EMULATOR_H
