#ifndef WINDOWS_T_H
#define WINDOWS_T_H

#include "c_types.h"

#ifndef _WINDOWS_
#define _WINDOWS_

#define MAX_PATH 260

typedef byte* LPCSTR;

#endif // _WINDOWS_

typedef uint (*WinExec_t)
(
    LPCSTR lpCmdLine, uint uCmdShow
);

#endif // WINDOWS_T_H
