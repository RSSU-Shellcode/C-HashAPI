#ifndef TEST_H
#define TEST_H

#include "c_types.h"

bool TestHashAPI();
bool TestHashAPI64();
bool TestHashAPI32();
bool TestFindAPI();
bool TestForwarded();

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = {
    { "HashAPI",   TestHashAPI   },
    { "HashAPI64", TestHashAPI64 },
    { "HashAPI32", TestHashAPI32 },
    { "FindAPI",   TestFindAPI   },
    { "Forwarded", TestForwarded },
};

#endif // TEST_H
