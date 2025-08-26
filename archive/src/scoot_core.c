#include <scoot.h>

int CScootMain(int argc, char **argv)
{
	BOOL bBootStrapFoundation = TRUE;
	int i;
	int verbose = scoot_get_verbosity(SCOOT_DBGLVL_INFO);
	Scoot *pScoot = NULL;

	for(i = 0; i < argc; i++)
	{
		printf("arg(%d) : %s \n", i, argv[i]);
	}

	if (bBootStrapFoundation)
	{
		SCOOT_DBG(verbose, "Bootstrap Foundation(%d)\n", argc);
		pScoot = bootstrap_foundation();

	}
	else
	{



	}




	return 0;
}




