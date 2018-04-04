// include the sec_client module
#include "seccomp_framework/sec_client.h"

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <errno.h>

extern int errno;

// define which main functions are used
// MAIN_BEFORE is called before seccomp is activated
// MAIN_AFTER is called after seccomp is activated
#define SEC_MAIN_BEFORE
#define SEC_MAIN_AFTER


void readFile(char *path, char *access){
	char line[1024];

	printf("---------ACCESS FILE WITH %s ---------\n", access);
	printf("path: %s\n", path);

	FILE *f2;
	f2 = fopen(path, access);
	if (f2){
		while (fgets(line, sizeof(line), f2) != NULL){
			printf("%s", line);
		}
		fclose(f2);
	} else {
		printf("Error\n");
	}

	printf("---------END---------\n\n");
}

void writeFile(char *path, char *access){
	printf("---------WRITE FILE WITH %s ---------\n", access);
	printf("path: %s\n", path);

	FILE *f2;
	f2 = fopen(path, access);
	if (f2){
		fprintf(f2, "wrote to file");
		fclose(f2);
	} else {
		printf("Error\n");
	}

	printf("---------END---------\n\n");
}

void createFile(char *path){
	printf("---------CREATE FILE WITH %s ---------\n", "w");
	printf("path: %s\n", path);

	FILE *f2;
	f2 = fopen(path, "w");
	if (f2){
		fprintf(f2, "created forbidden file, rule was unsuccessful");
		fclose(f2);
	} else {
		printf("Error\n");
	}

	printf("---------END---------\n\n");
}

int sec_main_before(int argc, char **argv){
	(void)argc;
	(void)argv;

	for (int i = 0; i < argc; i++){
		printf("arg%d = %s\n", i, argv[i]);
	}
	
	printf("before main\n");

	return 0;
}

int sec_main_after(int argc, char **argv){
	(void)argc;
	(void)argv;

	// read and write file test
	printf(" ** Try to read a valid file. Should be possible\n");
	readFile("/home/remo/Schreibtisch/test/valid/test.txt", "r");

	printf(" ** Try to read the modify file with r. Should be redirected to the redirected file.\n");
	readFile("/home/remo/Schreibtisch/test/modify/test.txt", "r");

	printf(" ** Try to read the skip file with r. Should return an error and print nothing.\n");
	readFile("/home/remo/Schreibtisch/test/skip/test.txt", "r");

	printf(" ** Try to create a file and write data into it in a directory where create is disallowed and read allowed. Should not be allowed.\n");
	createFile("/home/remo/Schreibtisch/test/write_yes_create_no/existing.txt");

	printf(" ** Try to read a file in a directory where create is disallowed and read allowed. Should be possible.\n");
	readFile("/home/remo/Schreibtisch/test/write_yes_create_no/existing.txt", "r+");

	printf(" ** Try to read a file with the ending .txt. Should redirected to the .dat file.\n");
	readFile("/home/remo/Schreibtisch/test/filechange/test.dat", "r");

	// getcwd and chdir test
	printf("--------------------------\n");
	char dir[100] = "should be cleared";
	printf("PTR: %p\n", dir);
	printf("INIT TEXT: %s\n", dir);
	char *ret = getcwd(dir, 100);
	printf("Client CWD is: %s\n", dir);
	printf("RETVAL is: %p\n", ret);
	printf("SHOULD BE: %p\n", dir);
	printf("--------------------------\n");
	char *test = calloc(100, 1);
	printf("PTR: %p\n", test);
	printf("INIT TEXT: %s\n", test);
	getcwd(test, 100);
	printf("Client CWD is: %s\n", test);
	printf("--------------------------\n");
	printf("Try Change CWD to invalid FOLDER: %s\n", "/home/remo/Schreibtisch/test/invalid");
	printf("Due to the defined rule, the path should be /home/remo/Schreibtisch/test/valid instead\n");
	chdir("/home/remo/Schreibtisch/test/invalid");
	getcwd(dir, 100);
	printf("Client CWD is: %s\n", dir);
	printf("--------------------------\n");

	// setrlimit test
	printf("--------------------------\n\n");
	printf("Try to modify different resource limits\n");
	printf("Set RLIMIT_NPROC max to 50, we should be modified to 8 and cur to 1 less\n");
	struct rlimit lim = {rlim_cur: 40, rlim_max: 50};
	struct rlimit rlim; 
	setrlimit(RLIMIT_NPROC, &lim);
	getrlimit(RLIMIT_NPROC, &rlim);
	printf("cur: %ld\n", rlim.rlim_cur);
	printf("max: %ld\n", rlim.rlim_max);


	printf("\nTry to set RLIMIT_CPU to cur = 200 and max to 250. Should not be possible (skip call)\n");
	lim = (struct rlimit){rlim_cur: 200, rlim_max: 250};
	setrlimit(RLIMIT_CPU, &lim);
	getrlimit(RLIMIT_CPU, &rlim);
	printf("cur: %ld\n", rlim.rlim_cur);
	printf("max: %ld\n", rlim.rlim_max);
	
	// get timeofday test
	printf("--------------------------\n\n");
	printf("Get the time which is slightly modified on each call\n");
	char buffer[30];
	struct timeval tv;

	time_t curtime;

	for (int i = 0; i < 5; i++){
		syscall(SYS_gettimeofday, &tv, NULL);
		curtime=tv.tv_sec;
		strftime(buffer,30,"%m-%d-%Y  %T.",localtime(&curtime));
		printf("%s%ld\n",buffer,tv.tv_usec);
	}


	printf("--------------------------\n\n");
	printf("Try to read the access mode with fcntl -> should be possible\n");
	FILE *ffc = fopen("/home/remo/Schreibtisch/test/fd_copy_deny/test.txt", "r");
	int flags = fcntl(fileno(ffc), F_GETFL, 0);
	if (flags >= 0){
		printf("RULE SUCCESSFUL\n");
	}
	printf("Try to read the descriptor flags with fcntl -> should be invalid\n");
	errno = 0;
	int desc = fcntl(fileno(ffc), F_GETFD, 0);
	if (desc < 0){
		printf("RULE SUCCESSFUL (errno = %d)\n", errno);
	}
	fclose(ffc);

	// file descriptor test
	printf("--------------------------\n\n");
	printf("Try to copy a file descriptor which is blocked\n");

	FILE *f = fopen("/home/remo/Schreibtisch/test/fd_copy_deny/test.txt", "r");
	char line[1024];
	if (f){
		while (fgets(line, sizeof(line), f) != NULL){
			printf("%s", line);
		}
	} else {
		printf("Could not open file");
	}

	printf("original fd: %d\n", fileno(f));
	errno = 0;
	int fd_copy = dup(fileno(f));
	printf("copied fd: %d\n", fd_copy);
	if (fd_copy == -1){
		printf("COPY failed as expected (errno = %d)\n", errno);
	}
	fclose(f);

	return 0;
}
