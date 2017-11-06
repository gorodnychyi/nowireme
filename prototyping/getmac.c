#include <stdio.h>  
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "getmac.h"


const char *get_my_mac()
{

	printf("MAC function start here_____\n");
	FILE *in;
	char buff[512];
	//char *result;
	//result = NULL;

	in = popen("ifconfig wlp2s0 | grep HWaddr | awk '{print $5}'", "r");

	fgets(buff, sizeof(buff), in);

	pclose(in);
	
	//sprintf(result, "%s", buff);

	//printf("0_this: %s\n", result);
	printf("In function: %s\n", buff);
	
	return 0;
	//free(result);

}