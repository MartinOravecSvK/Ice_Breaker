#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function() {
    char buffer[128];
    printf("Enter some text: ");
    gets(buffer);
}

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

int main() {
    vulnerable_function();
    printf("Returned safely to main.\n");
    return 0;
}
