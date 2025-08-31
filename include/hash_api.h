#ifndef HASH_API_H
#define HASH_API_H

#include "c_types.h"

// FindAPI will not call GetProcAddress, if this module is
// not loaded, it cannot find the target procedure address.
//
// FindAPI is support forwarded function.
// FindAPI is NOT support DLL about API Sets.

typedef void* (*FindAPI_t)(uint hash, uint key);
typedef void* (*FindAPI_A_t)(byte* module, byte* procedure);
typedef void* (*FindAPI_W_t)(uint16* module, byte* procedure);

// FindAPI is used to find Windows API address by hash and key.
void* FindAPI(uint module, uint procedure, uint key);

// FindAPI_A is used to find Windows API address by module name
// and procedure name with ANSI, it is a wrapper about FindAPI.
void* FindAPI_A(byte* module, byte* procedure);

// FindAPI_W is used to find Windows API address by module name
// and procedure name with UTF-16, it is a wrapper about FindAPI.
void* FindAPI_W(uint16* module, byte* procedure);

// CalcHash_A is used to calculate ANSI string hash with key.
// It can calculate module name and procedure name.
uint   CalcHash_A  (byte* data, uint key);
uint32 CalcHash32_A(byte* data, uint32 key);
uint64 CalcHash64_A(byte* data, uint64 key);

// CalcHash_W is used to calculate UTF-16 string hash with key.
// It can calculate module name.
uint   CalcHash_W  (uint16* data, uint key);
uint32 CalcHash32_W(uint16* data, uint32 key);
uint64 CalcHash64_W(uint16* data, uint64 key);

#endif // HASH_API_H
