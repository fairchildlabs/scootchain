#include <scoot.h>

//boostrap foundation


void bootstrap_validation()
{
	int i;
	int verbose = scoot_get_verbosity(SCOOT_DBGLVL_INFO);

	SCOOT_DBG(verbose, "boostrap_validation(%d)\n", verbose);

	SCOOT_DBG(verbose, "sizeof(UINT64)               = %d\n", sizeof(UINT64));
	SCOOT_DBG(verbose, "sizeof(UINT32)               = %d\n", sizeof(UINT32));
	SCOOT_DBG(verbose, "sizeof(UINT16)               = %d\n", sizeof(UINT16));
	SCOOT_DBG(verbose, "sizeof(UINT8)                = %d\n", sizeof(UINT8));
	SCOOT_DBG(verbose, "sizeof(BOOL)                 = %d\n", sizeof(BOOL));
	SCOOT_DBG(verbose, "SCOOT_BLOCK_HEADER_SIZE      = %d\n", SCOOT_BLOCK_HEADER_SIZE);
	SCOOT_DBG(verbose, "scootchain_genesis_block size= %d\n", sizeof(scootchain_genesis_block));

	


	for (i = 0; i < ScBtMaxEnum; i++)
	{
		SCOOT_DBG(verbose, "ScootBlockTypeStr(%d) = %s\n", i, ScootBlockTypeStr(i));
	}
	for (i = 0; i < ScBulMaxEnum; i++)
	{
		SCOOT_DBG(verbose, "ScootBulStr(%d)       = %s\n", i, ScootBulStr(i));
	}
	for (i = 0; i < ScUtMaxEnum; i++)
	{
		SCOOT_DBG(verbose, "ScootUtStr(%d)       = %s\n", i, ScootUtStr(i));
	}
	for (i = 0; i < ScEtMaxEnum; i++)
	{
		SCOOT_DBG(verbose, "ScootEtStr(%d)       = %s\n", i, ScootEtStr(i));
	}
	for (i = 0; i < ScEptMaxEnum; i++)
	{
		SCOOT_DBG(verbose, "ScootEptStr(%d)       = %s\n", i, ScootEptStr(i));
	}

	

	

	SCOOT_ASSERT(SCOOT_SPEC_BLOCK_HEADER_SIZE == SCOOT_BLOCK_HEADER_SIZE);



}

BOOL genesis_foundation(SGB *pGenesisBlock)
{	
	int i;
	int verbose = scoot_get_verbosity(SCOOT_DBGLVL_INFO);
	BOOL bErr = TRUE;
	pGenesisBlock = SCOOT_ALLOC(BLOCK4K);

	SCOOT_ASSERT(pGenesisBlock);
	SCOOT_DBG(verbose, "genesis_foundation(%d) pGenesisBLock = %px\n", sizeof(SGB), pGenesisBlock);

	//** Scoot Index ******************************************************************************
	//Foundation root is Scoot(0) == Asimov
	//Scoot > 0 = Resposibility Domain - user addresses registered with foundation
	//Scoot == 0  Value Domain (Asimov) - can be used by anonymous or registered addresses
	//Scoot < 0 = Foundation Flow Control Tokens -1(Liu), -2(Stephenson) (others may follow) 
	//Scoot < 0 = Logs, other utility chains
	//***********************************************************************************************
	pGenesisBlock->scoot_index = 0;  //Asimov
	//** Scoot Unit Type*****************************************************************************
	// ScUtFractional (1) - Each Scoot is made up of fractional units
	// ScUtSerialized (2) - Each Scoot has an individual identifier and a Mask
	// ScUtPrimeShard (3) - Each Scoot is a prime shard (see Asimov Appendix C, p195)
	//***********************************************************************************************
	pGenesisBlock->scoot_unit_type = ScUtFractional;
	//** Scoot Subunit  *****************************************************************************
	//Behavior of this field is dependendent on scoot_unit_type
	// ScUtFractional (1) - Number of Fractional Units per Scoot 
	// ScUtSerialized (2) - High Order bits as test mask
	//                      Least Signficant Bit sets the maximum number of units
	//                      Can be minted decrementally or incrementally or randomly within range
	// ScUtPrimeShard (3) - Prime Number INDEX (not the prime number itself) to  
	//***********************************************************************************************
	//1000 Isaacs per Asimov 
	pGenesisBlock->scoot_subunit = 1000;
	//** Scoot Seats  *****************************************************************************
	// Number of elective posistions governing the Scoot
	// This is limited to max of 16 in the genesis block
	// But more maybe added by proclamation or referendum
	//***********************************************************************************************
	pGenesisBlock->scoot_seats = 11;

	//** Scoot Seats  *****************************************************************************
	// Seat 0 - Trustee - Engineer
	//***********************************************************************************************

	pGenesisBlock->scsd[0].type.type = ScEtScootara;  //any member that holds unencumbered scoot
	pGenesisBlock->scsd[0].type.elective_period_type = ScEptYears;
	pGenesisBlock->scsd[0].type.elective_period = 10; //10 years
	pGenesisBlock->scsd[0].type.first_election = SCOOT_DATETIME(11, 17, 2029);
	pGenesisBlock->scsd[0].type.inanuargartion_days_offset = 13 + 31; //should be inaugration 1/1/2030
	pGenesisBlock->scsd[0].type.subtype = SCOOTARA_SUBTYPE_MOST;


	pGenesisBlock->scsd[0].powers.bmpow.genesis_assignment = 1;
	pGenesisBlock->scsd[0].powers.bmpow.trustee = 1;

	//** Scoot Seats  *****************************************************************************
	// Seat 1 - Popular1
	//***********************************************************************************************

	pGenesisBlock->scsd[1].type.type = ScEtAsimass;  //any scoot(0) holder, any address, can be anonymous
	pGenesisBlock->scsd[1].type.elective_period_type = ScEptYears;
	pGenesisBlock->scsd[1].type.elective_period = 3; //3 years
	pGenesisBlock->scsd[1].type.first_election = SCOOT_DATETIME(11, 17, 2024);
	pGenesisBlock->scsd[1].type.inanuargartion_days_offset = 13 + 31; //should be inaugration 1/1/2030
	pGenesisBlock->scsd[1].type.subtype = ASIMASS_SUBTYPE_MVP;
	pGenesisBlock->scsd[1].type.p1      = 11; //11 names on ballot
	pGenesisBlock->scsd[1].type.p2      = 5; //5 scores (ranking 1 to 5) on ballot

	pGenesisBlock->scsd[1].powers.bmpow.genesis_assignment = 1;
	pGenesisBlock->scsd[1].powers.bmpow.trustee = 0;

	//** Scoot Seats  *****************************************************************************
	// Seat 2 - Popular2
	//***********************************************************************************************

	pGenesisBlock->scsd[2].type.type = ScEtAsimass;  //any scoot(0) holder, any address, can be anonymous
	pGenesisBlock->scsd[2].type.elective_period_type = ScEptYears;
	pGenesisBlock->scsd[2].type.elective_period = 3; //3 years
	pGenesisBlock->scsd[2].type.first_election = SCOOT_DATETIME(11, 17, 2025);
	pGenesisBlock->scsd[2].type.inanuargartion_days_offset = 13 + 31; //should be inaugration 1/1/2030
	pGenesisBlock->scsd[2].type.subtype = ASIMASS_SUBTYPE_MVP;
	pGenesisBlock->scsd[2].type.p1 = 11; //11 names on ballot
	pGenesisBlock->scsd[2].type.p2 = 5; //5 scores (ranking 1 to 5) on ballot


	pGenesisBlock->scsd[2].powers.bmpow.genesis_assignment = 1;
	pGenesisBlock->scsd[2].powers.bmpow.trustee = 0;

	//** Scoot Seats  *****************************************************************************
	// Seat 3 - Popular3
	//***********************************************************************************************

	pGenesisBlock->scsd[3].type.type = ScEtAsimass;  //any scoot(0) holder, any address, can be anonymous
	pGenesisBlock->scsd[3].type.elective_period_type = ScEptYears;
	pGenesisBlock->scsd[3].type.elective_period = 3; //3 years
	pGenesisBlock->scsd[3].type.first_election = SCOOT_DATETIME(11, 17, 2026);
	pGenesisBlock->scsd[3].type.inanuargartion_days_offset = 13 + 31; //should be inaugration 1/1/2030
	pGenesisBlock->scsd[3].type.subtype = ASIMASS_SUBTYPE_MVP;
	pGenesisBlock->scsd[3].type.p1 = 11; //11 names on ballot
	pGenesisBlock->scsd[3].type.p2 = 5; //5 scores (ranking 1 to 5) on ballot


	pGenesisBlock->scsd[3].powers.bmpow.genesis_assignment = 1;
	pGenesisBlock->scsd[3].powers.bmpow.trustee = 0;

	//** Scoot Seats  *****************************************************************************
	// Seat 4,5,6,7,8,9,10 - Continetals - 
	// Africa, Antarctica, Asia, Austrailia, Europe, North America, South America
	// 7 Continentals are elected at once, on a single ballot
	// pledges must choose a representive continent, and only one
	//***********************************************************************************************
	for (i = 4; i < 11; i++)
	{
		pGenesisBlock->scsd[i].type.type = ScEtScootara;  //any scoot(0) holder, any address, can be anonymous
		pGenesisBlock->scsd[i].type.elective_period_type = ScEptYears;
		pGenesisBlock->scsd[i].type.elective_period = 7; //7 years
		pGenesisBlock->scsd[i].type.first_election = SCOOT_DATETIME(11, 17, 2026);
		pGenesisBlock->scsd[i].type.inanuargartion_days_offset = 13 + 31; //should be inaugration 1/1/2030
		pGenesisBlock->scsd[i].type.subtype = SCOOTARA_SUBTYPE_CONTINENTAL;
		pGenesisBlock->scsd[i].type.p1 = 5; //5 names on ballot
		pGenesisBlock->scsd[i].type.p2 = 0; //5 scores (ranking 1 to 5) on ballot
		pGenesisBlock->scsd[i].type.ballotlink = 1;
		pGenesisBlock->scsd[i].powers.bmpow.genesis_assignment = 1;
		pGenesisBlock->scsd[i].powers.bmpow.trustee = 0;
	}


	bErr = FALSE;
	return bErr;
}

Scoot * bootstrap_foundation(void)
{
	int verbose = scoot_get_verbosity(SCOOT_DBGLVL_INFO);
	Scoot * pScoot = NULL;
	SGB *pGenesisBlock = NULL;
	bootstrap_validation();

	if (genesis_foundation(pGenesisBlock))
	{
		SCOOT_DBG(verbose, "Error Genesis Foundation");

	}
	

	return pScoot;

}
