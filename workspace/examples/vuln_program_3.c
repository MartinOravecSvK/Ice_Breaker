#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

__attribute__((naked)) void ldp_x0_x1_ret() {
    __asm__(
        "ldp x0, x1, [sp], #16\n"
        "ret\n"
    );
}

__attribute__((naked)) void ldp_x1_x2_ret() {
    __asm__(
        "ldp x1, x2, [sp], #16\n"
        "ret\n"
    );
}

__attribute__((naked)) void ldr_x0_ret() {
    __asm__(
        "ldr x0, [sp], #8\n"
        "ret\n"
    );
}

__attribute__((naked)) void str_x1_x0_ret() {
    __asm__(
        "str x1, [x0]\n"
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
		