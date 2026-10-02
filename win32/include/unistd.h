/* Minimal unistd shim for the kvmrun native backend on Windows.
 * host.c only needs getcwd(); map to the CRT underscore name. */
#ifndef KVMRUN_WIN32_UNISTD_H
#define KVMRUN_WIN32_UNISTD_H

#include <direct.h>
#include <io.h>
#include <process.h>
#include <stdlib.h>

#ifndef getcwd
#define getcwd _getcwd
#endif

#endif /* KVMRUN_WIN32_UNISTD_H */
