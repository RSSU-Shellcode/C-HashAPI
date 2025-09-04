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
bool TestCalcModHash_A();
bool TestCalcModHash_W();
bool TestCalcProcHash();

#pragma warning(pop)

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = {
    { "Lib_Memory", TestLibMemory },
    { "Lib_String", TestLibString },

    { "FindAPI",       TestFindAPI },
    { "FindAPI_ML",    TestFindAPI_ML },
    { "FindAPI_A",     TestFindAPI_A },
    { "FindAPI_W",     TestFindAPI_W },
    { "Forwarded",     TestForwarded },
    { "CalcModHash_A", TestCalcModHash_A },
    { "CalcModHash_W", TestCalcModHash_W },
    { "CalcProcHash",  TestCalcProcHash },
};

#endif // TEST_H
