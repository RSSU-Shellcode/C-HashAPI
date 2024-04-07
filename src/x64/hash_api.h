#include "include/types.h"

uintptr FindAPI(uint hash, uint key);

static uint64 calcSeedHash(uint key);
static uint64 calcKeyHash(uint seed, uint key);
static uint64 ror64(uint64 value, uint64 bits);
