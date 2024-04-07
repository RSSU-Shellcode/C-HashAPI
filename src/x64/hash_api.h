#include "include/types.h"

uintptr FindAPI(uint64 hash, uint64 key);

static uint64 calcSeedHash(uint64 key);
static uint64 calcKeyHash(uint64 seed, uint64 key);
static uint64 ror64(uint64 value, uint64 bits);
