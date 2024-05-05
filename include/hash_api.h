#ifndef HASH_API_H
#define HASH_API_H

#include "go_types.h"

typedef uintptr (*FindAPI_t)(uint hash, uint key);

// FindAPI is used to FindAPI address by hash and key.
uintptr FindAPI(uint hash, uint key);

// HashAPI is used to calculate Windows API hash by module
// and function with key, module and function are ASCII.
uint HashAPI_A(byte* module, byte* function, uint key);

// HashAPI is used to calculate Windows API hash by module
// and function with key, module is Unicode, function is ASCII.
uint HashAPI_W(byte* module, byte* function, uint key);

#endif // HASH_API_H
