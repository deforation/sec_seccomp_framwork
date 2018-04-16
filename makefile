CC = gcc
CFLAGS =  -pthread -Wall -Wextra -Werror -fwrapv -s -lseccomp  -g
#CFLAGS =   -Ofast  -std=c99 -g3 -Wall -Wextra -Wpointer-arith -Wcast-align -Wwrite-strings -Wswitch-default -Wunreachable-code -Winit-self -Wmissing-field-initializers -Wno-unknown-pragmas -Wstrict-prototypes -Wundef -Wold-style-definition -fwrapv

# ------ NO USER SERVICEABLE PARTS BELOW
STUBS = app seclib seccomp_framework/sec_client seccomp_framework/sec_tracer seccomp_framework/sec_ptrace_lib seccomp_framework/sec_syscall_emulator seccomp_framework/sec_seccomp_rules seccomp_framework/sec_seccomp_bpf_generator

CFILES = $(addsuffix .c, $(STUBS))
OFILES = $(addsuffix .o, $(STUBS))
DFILES = $(addsuffix .d, $(STUBS))
SOFILES = $(addsuffix .so, $(STUBS))

.PHONY: all 
all: clean prog

prog: $(OFILES)
	$(CC) $(CFLAGS) $(OFILES) -o $@

%.d : %.c
	$(CC) $(CFLAGS) -MM $< -o $@	

.PHONY: clean
clean:
	rm -rf $(OFILES) $(DFILES) $(SOFILES) app.o prog
