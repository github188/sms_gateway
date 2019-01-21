#include <stdio.h>

#include "tsbase.h"

int main()
{
    init_log("ts_sid");
    set_term_level(0);
    set_file_level(0);

    int64_t sid1 = 0;
    int64_t sid2 = 0;

    get_sid_two(100, &sid1, &sid2);

    printf("1 ===========sid1:%lx sid2:%lx\n", sid1, sid2);

    get_sid_two(0, &sid1, &sid2);
    printf("2 ===========sid1:%lx sid2:%lx\n", sid1, sid2);

    ts_sid_t s;
    get_sid_one(99999999, &s);
    printf("3 =========sid_first:%lx sid_second:%lx\n", s.sid_first, s.sid_second);

    get_sid_one(0, &s);
    printf("4 =========sid_first:%lx sid_second:%lx\n", s.sid_first, s.sid_second);

    return 0;
}

