#ifndef WINDOWS_T_H
#define WINDOWS_T_H

#include "c_types.h"

typedef const char* LPCSTR;

typedef uint (*WinExec_t)
(
    LPCSTR lpCmdLine, uint uCmdShow
);

#endif // WINDOWS_T_H
