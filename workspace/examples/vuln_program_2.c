#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void gadget() {
    asm volatile (
        "ldp x0, x1, [sp]\n" // Load two values from the stack into x0 and x1
        "ret\n"              // Return
    );
}

void gadget2() {
    asm volatile (
        "str x1, [x0]\n" // Store the value in x1 to the address in x0
    );
}

void gadget3() {
    asm volatile (
        "mov x8, #0xdd\n" // syscall number for execve (hexadecimal)
        "ret\n"
    );
}

void gadget_svc() {
    asm volatile (
        "svc #0\n"
        "ret\n"
    );
}


int copyData(char *string)
{
	char buf[32];
	strcpy(buf, string);
	return (0);
}

int main(int argc, char *argv[])
{
	char buffer[700];
	FILE *file;
    if (argc !=2)
    {
        printf("[*] invalid arguments!\n [*] > %s file_name\n",argv[0]);
        exit(0);
    }
	printf("opening file\n");
	file = fopen(argv[1],"rb");
	if (!file)
	{ 
		//printf("file not opened %s", strerror(errno));
		fprintf(stderr,"file not opened %s", strerror(errno));
		//printf("error");
		return (0);
	}
	printf("file opened\n");
	fread(buffer, 699,1,file);
	fclose(file);
	copyData(buffer);
	return (0);
}
		