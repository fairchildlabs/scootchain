#ifndef __SCOOT_H
#define __SCOOT_H

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>




#define SINT8  int8_t
#define SINT16 int16_t
#define SINT32 int32_t
#define SINT64 int64_t
#define UINT8  uint8_t
#define UINT16 uint16_t
#define UINT32 uint32_t
#define UINT64 uint64_t
#define BOOL   UINT8 
#define TRUE   ((BOOL)(1))
#define FALSE  ((BOOL)(0))

#include "scoot_platform.h"
#include "scootchain.h"

#define SCOOT_DBGLVL_NONE    0
#define SCOOT_DBGLVL_IOPATH  1
#define SCOOT_DBGLVL_ERROR   2
#define SCOOT_DBGLVL_INFO    3
#define SCOOT_DBGLVL_DETAIL  4
#define SCOOT_DBGLVL_VERBOSE 5

#define SCOOT_DBGLVL_COMPILE SCOOT_DBGLVL_ERROR

#define BLOCK4K (4 * 1024)



static inline void scoot_dbg_printf(int verbose, const char* fmt, ...)
{

    va_list args;

    if (verbose >= SCOOT_DBGLVL_COMPILE)
    {

        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }

}

static inline int scoot_get_verbosity(int level)
{
    //allows you to turn on verbosity globally by returning something different
    return level;
}


#define SCOOT_DBG(__verbose, __format, ...) do { if( __verbose >= SCOOT_DBGLVL_COMPILE) scoot_dbg_printf(__verbose, __format, __VA_ARGS__); } while (0)\


typedef struct _Scoot
{
    UINT64 scoot_idx;


} Scoot;


























//noncore headers 
#include "scoot_bootstrap.h"

#endif


