#ifndef __SCOOTCHAIN_H
#define __SCOOTCHAIN_H

//*************************************************************************************************
//** Headers
//*************************************************************************************************

#include "scoot_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <oqs/sha3.h>
#include "db_wrapper.h"


//*************************************************************************************************
// This mess setup up enumerations with matching string decode
// Unfortunately, this hack prevents explict assigning of a partciular value
// TODO: Somebody come up with a better one that allows assignment of the enum value 
// WARNING:  Until then, only add enums at the END of the series, doing otherwise will invalidate blocks
//*************************************************************************************************

#define SC_BLOCK_TYPE \
	__Cx(ScBtGenesis) \
	__Cx(ScBtMint) \
	__Cx(ScBtProclaim) \

#define __Cx(x) x, 
enum ScBlockTypeEnum { SC_BLOCK_TYPE ScBtMaxEnum };
#undef __Cx
#define __Cx(x) #x,
static const char* const ScBtStr[] = { SC_BLOCK_TYPE };
#define ScootBlockTypeStr(x) &ScBtStr[x][4] 


//*************************************************************************************************
// Scoot-chain blocks are of fixed sizes (512/4096/16K/64K...) 
// Physical blocks are padded, unless compressed, where Padding is stripped
// Transactional blocks are single block units (containing as many transactions as will fit)
// You'd use larger blocks on scootchains that have high amount of media content on chain
// Genesis block specfies BUL as min - chains can always use larger blocks when practical
//*************************************************************************************************

#define SC_BLOCK_UNIT_LEN \
	__Dx(ScBul512b) \
	__Dx(ScBul4k) \
	__Dx(ScBul16k) \
	__Dx(ScBul64k) \
	__Dx(ScBul256k) \
	__Dx(ScBul1M) \

#define __Dx(x) x, 
enum ScBlockUnitLenEnum { SC_BLOCK_UNIT_LEN ScBulMaxEnum };
#undef __Dx
#define __Dx(x) #x,
static const char* const ScBulStr[] = { SC_BLOCK_UNIT_LEN };
#define ScootBulStr(x) &ScBulStr[x][5] 



typedef struct _scootchain_header
{
	SINT64                      scoot_idx;
	UINT32                      block_number;                //Always sequential and block 1 is genesis block
	UINT32                      block_count;                 //Releated Content logical blocks may span multple block units
	UINT32                      block_entry;                 //Sequencing for spanned content blocks
	UINT32						block_byte_len;              //number of valid bypes in block, including header 
	UINT32                      rsvd_blkscoot_extension;     //future proof 128 byte header for scoot/blocknum exceeting 32-bit (can also eat into block_entry/block count) 
	enum ScBlockTypeEnum        bt;
	enum ScBlockUnitLenEnum     bul;                         //Block Unit Length - short blocks always padded 

	UINT32                      rsvd[23];                   

} scootchain_header;

#define SCOOT_BLOCK_HEADER_SIZE sizeof(scootchain_header)
#define SCOOT_SPEC_BLOCK_HEADER_SIZE 128
#define MAX_GENESIS_SEATS 12
//*************************************************************************************************
//Scoot Unit Type 
//*************************************************************************************************
#define SC_UNIT_TYPE \
	__Ex(ScUtFractional) \
	__Ex(ScUtSerialized) \
	__Ex(ScUtPrimeShard) \

#define __Ex(x) x, 
enum ScUtEnum { SC_UNIT_TYPE ScUtMaxEnum };
#undef __Ex
#define __Ex(x) #x,
static const char* const ScUtStr[] = { SC_UNIT_TYPE };

#define ScootUtStr(x) &ScUtStr[x][4] 
//*************************************************************************************************
//Scoot Electorate Types 
//*************************************************************************************************
#define SC_ELECTORAL_TYPE \
	__Gx(ScEtAsimass) \
	__Gx(ScEtScootoro) \
	__Gx(ScEtScootara) \

#define __Gx(x) x, 
enum ScEtEnum { SC_ELECTORAL_TYPE ScEtMaxEnum };
#undef __Gx
#define __Gx(x) #x,
static const char* const ScEtStr[] = { SC_ELECTORAL_TYPE };

#define ScootEtStr(x) &ScEtStr[x][4] 

//*************************************************************************************************
//Scoot Elective Period Types 
//*************************************************************************************************
#define SC_ELECTIVE_PERIOD_TYPE \
	__Gex(ScEptYears) \
	__Gex(ScEptDays) \

#define __Gex(x) x, 
enum ScEptEnum { SC_ELECTIVE_PERIOD_TYPE ScEptMaxEnum };
#undef __Gex
#define __Gex(x) #x,
static const char* const ScEptStr[] = { SC_ELECTIVE_PERIOD_TYPE };
#define ScootEptStr(x) &ScEptStr[x][5] 


typedef union _scootchain_u_powers
{
	UINT32 powers32;
	struct _bitmask_powers
	{
		UINT32 trustee            : 1;
		UINT32 genesis_assignment : 1;
		
	} bmpow;

} scootchain_electoral_powers;

#define DATETIME UINT32

typedef struct _scootchain_elector_types_common
{
	DATETIME           first_election;
	UINT8              type;
	UINT8              inanuargartion_days_offset; //inaugragation must be less than 255 days after election
	UINT8              elective_period_type;
	UINT8              elective_period;
	UINT32             subtype;
	UINT32             p1;
	UINT32             p2;
	UINT32             ballotlink;  //seats linked by a common ballot

} scootchain_electoral_types;

#define ASIMASS_SUBTYPE_MOST        0  //straighup, who has the most percentage 
#define ASIMASS_SUBTYPE_MAJORITY    1  //must clear "P1" % of the vote
#define ASIMASS_SUBTYPE_MVP         2  //P1 represent number of rankings, P2 represent number of names on ballot


#define SCOOTARA_SUBTYPE_MOST        0
#define SCOOTARA_SUBTYPE_CONTINENTAL 1


typedef struct _scootchain_seat_desc
{
	scootchain_electoral_types  type;
	scootchain_electoral_powers powers;

} scoot_chain_seat_descriptor;

typedef struct _scootchain_genesis_block
{
	//-- Scoot Unit -----------------------------------------------------
	scootchain_header                              header;
	SINT64                                         scoot_index;
	enum ScUtEnum                                  scoot_unit_type;
	UINT64                                         scoot_subunit;
	//----Electoral ------------------------------------------------------
	UINT32                                         scoot_seats;

	scoot_chain_seat_descriptor                    scsd[MAX_GENESIS_SEATS];


} scootchain_genesis_block;

#define SGB scootchain_genesis_block
#define SCSD scoot_chain_seat_descriptor




// Address typedef - 34 bytes total (1 flag + 1 checksum + 32 hash)
typedef struct _uscootaddress
{
    union
    {
        struct
        {
            UINT8  f0         : 1;
            UINT8  f1         : 1;
            UINT8  pledge     : 1;
            UINT8  f3         : 1;
            UINT8  foundation : 1;
            UINT8  engineer   : 1;
            UINT8  f6         : 1;
            UINT8  anon       : 1;
        } bflags;
        UINT8 flags;
    } u;
    //checksum includes flag and hash
    UINT8  checksum;
    UINT8  hash[32];

} scoot_address;

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





// Function declarations
void pubkey_to_address(const UINT8 *pubkey, size_t pubkey_len, scoot_address *pAddress);
int validate_address(const scoot_address address);

#endif
