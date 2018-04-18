// include the sec_client module
#include "seclib.h"

#include <stdio.h>
#include <stdlib.h>
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
#include <limits.h>
#include <sys/syscall.h>
#include <errno.h>

extern int errno;

// prototypes
int sec_main_before(int argc, char **argv);
int sec_main_after(int argc, char **argv);


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

/*
* The main function has no other logic than starting
* the sec_seccomp_framework.
*
* The first argument is the number of arguments
* The second argument are the arguments
* The third argument is the function which should be executed before seccomp is initialized
* The fourth argument is the function which should be executed after seccomp is initialized
*/
int main(int argc, char **argv){
	return run_seccomp_framework(argc, argv, sec_main_before, sec_main_after);
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
	readFile("./demo_files/valid/test.txt", "r");

	printf(" ** Try to read the modify file with r. Should be redirected to the redirected file.\n");
	readFile("./demo_files/modify/test.txt", "r");

	printf(" ** Try to read the skip file with r. Should return an error and print nothing.\n");
	readFile("./demo_files/skip/test.txt", "r");

	printf(" ** Try to create a file and write data into it in a directory where create is disallowed and read allowed. Should not be allowed.\n");
	createFile("./demo_files/write_yes_create_no/existing.txt");

	printf(" ** Try to read a file in a directory where create is disallowed and read allowed. Should be possible.\n");
	readFile("./demo_files/write_yes_create_no/existing.txt", "r+");

	printf(" ** Try to read a file with the ending .dat. Should redirected to the .txt file.\n");
	readFile("./demo_files/filechange/test.dat", "r");

	// getcwd and chdir test
	char cwdsafe[PATH_MAX];
	getcwd(cwdsafe, PATH_MAX);
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
	printf("Try Change CWD to invalid FOLDER: %s\n", "./demo_files/invalid");
	printf("Due to the defined rule, the path should be ./demo_files/valid instead\n");
	chdir("./demo_files/invalid");
	getcwd(dir, 100);
	printf("Client CWD is: %s\n", dir);
	chdir(cwdsafe);
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
	FILE *ffc = fopen("./demo_files/fd_copy_deny/test.txt", "r");
	int flags = fcntl(fileno(ffc), F_GETFL, 0);
	if (flags >= 0){
		printf("RULE SUCCESSFUL\n");
	}
	printf("Try to read the descriptor flags with fcntl -> should be invalid\n");
	errno = 0;
	int desc = fcntl(fileno(ffc), F_GETFD, 0);
	if (desc < 0){
		printf("RULE SUCCESSFUL\n");
	}
	fclose(ffc);

	// file descriptor test
	printf("--------------------------\n\n");
	printf("Try to copy a file descriptor which is not permitted\n");

	FILE *f = fopen("./demo_files/fd_copy_deny/test.txt", "r");
	char line[1024];
	if (f){
		printf(" - file descriptor is open with content:\n");
		while (fgets(line, sizeof(line), f) != NULL){
			printf(" - %s", line);
		}
	} else {
		printf("Could not open file");
	}

	printf("original fd: %d\n", fileno(f));
	errno = 0;
	int fd_copy = dup(fileno(f));
	printf("copied fd: %d\n", fd_copy);
	if (fd_copy == -1){
		printf("COPY failed as expected\n");
	} else {
		printf("ERROR, Wrong result\n");
	}
	fclose(f);

	// after execution system call manipulation test 
	printf("--------------------------\n\n");
	printf("The indent of the file starts with <not>, whith should be replaced by <its>\n");

	readFile("./demo_files/after_test/not_file.txt", "r");


	// after execution system call manipulation for search replace 
	printf("--------------------------\n\n");
	printf("All double spaces should be replaced by underscores..\n");

	readFile("./demo_files/replace/test.txt", "r");

	return 0;
}
