#ifndef _SCOOT_PLATFORM_H
#define _SCOOT_PLATFORM_H

#if 1 //WINDOWS FOR NOW 

#define SCOOT_ASSERT(x) assert(x)

static inline void* scmalloc(int xbytes)
{
	void* pPtr = _aligned_malloc(xbytes, 64);
	SCOOT_ASSERT(pPtr);
	memset(pPtr, 0, xbytes);
	return pPtr;
}
#define SCOOT_ALLOC(xbytes) scmalloc(xbytes)

#else

#define SCOOT_ASSERT
#endif

//convert date at 12am to unix timestamp
#define SCOOT_DATETIME(_mm, __dd, __yy) 0



#endif