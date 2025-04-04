#ifndef TEST_H
#define TEST_H

#include "c_types.h"

// define unit tests
#pragma warning(push)
#pragma warning(disable: 4276)
bool TestLibMemory();
bool TestLibString();

bool TestHashAPI();
bool TestHashAPI64();
bool TestHashAPI32();
bool TestFindAPI();
bool TestForwarded();
#pragma warning(pop)

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = {
    { "Lib_Memory", TestLibMemory },
    { "Lib_String", TestLibString },

    { "HashAPI",   TestHashAPI   },
    { "HashAPI64", TestHashAPI64 },
    { "HashAPI32", TestHashAPI32 },
    { "FindAPI",   TestFindAPI   },
    { "Forwarded", TestForwarded },
};

#endif // TEST_H
