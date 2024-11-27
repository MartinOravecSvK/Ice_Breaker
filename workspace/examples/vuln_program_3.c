#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

char* process_input(char *buf) {
    char newbuf[64];
    int i , j =0;

    if(strlen(buf) <=58)
        for(i=0;i<strlen(buf);i++){
            if(buf[i]>=32 && buf[i]<55){
            newbuf[j++]=buf[i];
                if(buf[i]=='\'')
                    newbuf[j++]=buf[i];
            }
        }
    else return 0;

    if(j > i) {
        strcpy(newbuf, buf);
        printf("found me!\n");
    }

    newbuf[j]='\0';

    return *newbuf;
}

int main(int argc, char *argv[]) {
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
    process_input(buffer);
    return 0;
}