#include <stdio.h>
#include <stdint.h>

#include "check_sum.h"


int main(int argc, char* argv[])
{
    char output[64] = {0};
    int a = 1000029;
    int b = 9999999;
    int64_t c = 234567893939;

    check_sum_init();

    check_reset();
    check_update((unsigned char*)&a, sizeof(a));
    check_finish(output, sizeof(output));
    printf("aaa  :%s\n", output);

    check_reset();
    check_update((unsigned char*)&a, sizeof(a));
    check_finish(output, sizeof(output));
    printf("aaa  :%s\n", output);


    check_reset();
    check_update((unsigned char*)&b, sizeof(b));
    check_update((unsigned char*)&a, sizeof(a));
    check_finish(output, sizeof(output));
    printf("  b,a:%s\n", output);

    check_reset();
    check_update((unsigned char*)&c, sizeof(c));
    check_update((unsigned char*)&b, sizeof(b));
    check_update((unsigned char*)&a, sizeof(a));
    check_finish(output, sizeof(output));
    printf("c,b,a:%s\n", output);

    check_sum_destroy();

    return 0;
}


