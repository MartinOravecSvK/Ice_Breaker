#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void secret_function() {
    system("/bin/sh");
}

void vulnerable_function() {
    char buffer[64];
    printf("Enter some text: ");
    gets(buffer);
}

int main() {
    vulnerable_function();
    printf("Returned safely to main.\n");
    return 0;
}
