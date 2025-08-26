#include <stddef.h>
#include "scootchain.h"
#include "genesis.h"

int init_genesis_block(scootchain_genesis_block_header *header)
{
    if (header == NULL)
    {
        return -1;
    }

    header->scoot_index = 0;
    header->scoot_timestamp = 0;

    return 0;
}

