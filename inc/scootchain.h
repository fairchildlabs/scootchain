#ifndef __SCOOTCHAIN_H
#define __SCOOTCHAIN_H
// 8-bit types
typedef unsigned char  UINT8;
typedef signed char    INT8;

// 16-bit types
typedef unsigned short UINT16;
typedef signed short   INT16;

// 32-bit types
typedef unsigned int   UINT32;
typedef signed int     INT32;

// 64-bit types
typedef unsigned long long UINT64;
typedef signed long long   INT64;


typedef UINT64 scoot_ts;

typedef struct 
{
	INT64    scoot_index;
	UINT64   block_number;
	UINT16   version;
	UINT8    block_type;
	UINT8    block_flags;
	UINT32   block_length;
	UINT64   ts;	
	UINT8    prev_block_hash[32];
	UINT8    this_block_hash[32];
	scoot_ts validation_ts;
	UINT64   validation_id;
	UINT8    validation_signature[32];
	

} scootchain_block_header;

typedef struct
{
	INT64   scoot_index;
 scoot_ts   scoot_timestamp;
	
} scootchain_genesis_block_header;


typedef union
{
	



} scootchain_genesis_block_u;





#endif
