typedef char      int8;
typedef short     int16;
typedef int       int32;
typedef long long int64;

typedef unsigned char      uint8;
typedef unsigned short     uint16;
typedef unsigned int       uint32;
typedef unsigned long long uint64;

#ifdef _WIN64
    typedef int64  int;
    typedef uint64 uint;
    typedef uint64 uintptr;
#elif _WIN32
    typedef int32  int;
    typedef uint32 uint;
    typedef uint32 uintptr;
#endif

typedef float  float32;
typedef double float64;

typedef unsigned char byte;
typedef int32 rune;

#define TRUE  1;
#define FALSE 0;

#define NULL 0;
