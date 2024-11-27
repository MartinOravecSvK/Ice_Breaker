#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function() {
    char buffer[64];
    printf("Enter some text: ");
    gets(buffer);
}

// ARM 64
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

// ARM 32
// __attribute__((naked)) void gadget1() {
//     __asm__(
//         "pop {r0, r1}\n"
//         "bx lr\n"
//     );
// }

// __attribute__((naked)) void gadget2() {
//     __asm__(
//         "pop {r1, r2}\n"
//         "bx lr\n"
//     );
// }

// __attribute__((naked)) void gadget3() {
//     __asm__(
//         "ldr r0, [sp], #4\n"
//         "bx lr\n"
//     );
// }

// __attribute__((naked)) void gadget4() {
//     __asm__(
//         "str r1, [r0]\n"
//         "bx lr\n"
//     );
// }

int main() {
    vulnerable_function();
    printf("Returned safely to main.\n");
    return 0;
}

// #include <stdio.h>
// #include <string.h>
// #include <stdlib.h>

// void vuln_function() {
//     char buffer[64];
//     printf("Enter your input: ");
//     gets(buffer);
//     printf("You entered: %s\n", buffer);
// }

// __attribute__((naked)) void gadget_pop_r0_pc() {
//     __asm__(
//         "pop {r0, pc}\n"
//     );
// }

// __attribute__((naked)) void gadget_pop_r1_pc() {
//     __asm__(
//         "pop {r1, pc}\n"
//     );
// }

// __attribute__((naked)) void gadget_pop_r2_pc() {
//     __asm__(
//         "pop {r2, pc}\n"
//     );
// }

// __attribute__((naked)) void gadget_pop_r7_pc() {
//     __asm__(
//         "pop {r7, pc}\n"
//     );
// }

// __attribute__((naked)) void gadget_svc() {
//     __asm__(
//         "svc #0\n"
//     );
// }


// int main() {
//     vuln_function();
//     return 0;
// }
