#ifndef TEST_H
#define TEST_H

#include "c_types.h"

// define unit tests
#pragma warning(push)
#pragma warning(disable: 4276)
bool TestLibMemory();
bool TestLibString();

bool TestFindAPI();
bool TestFindAPI_ML();
bool TestFindAPI_A();
bool TestFindAPI_W();
bool TestForwarded();
bool TestCalcModHash32();
bool TestCalcModHash64();
bool TestCalcProcHash32();
bool TestCalcProcHash64();

#pragma warning(pop)

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = {
    { "Lib_Memory", TestLibMemory },
    { "Lib_String", TestLibString },

    { "FindAPI",        TestFindAPI        },
    { "FindAPI_ML",     TestFindAPI_ML     },
    { "FindAPI_A",      TestFindAPI_A      },
    { "FindAPI_W",      TestFindAPI_W      },
    { "Forwarded",      TestForwarded      },
    { "CalcModHash32",  TestCalcModHash32  },
    { "CalcModHash64",  TestCalcModHash64  },
    { "CalcProcHash32", TestCalcProcHash32 },
    { "CalcProcHash64", TestCalcProcHash64 },
};

#endif // TEST_H
