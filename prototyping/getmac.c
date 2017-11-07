#include <stdio.h>  
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "getmac.h"


const char *get_my_mac()
{
	printf("_____MAC function start here_____\n");
	FILE *in;
	static char buff[512];
		in = fopen("/tmp/gw_mac", "r");
		fscanf(in, "%s", buff);
		fclose(in);
		printf("In function: %s\n", buff);

	return buff;
	free(buff);
}