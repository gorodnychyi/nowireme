/* building instructions
g++ -Wall -Wextra url_enc.c getmac.c -o url_enc
*/


#include <iostream>
#include <stdio.h>
#include <string>
#include <cstring>
#include <stdlib.h>

#include "getmac.h"

using namespace std;

FILE * fo;
const int size = 256;
int main(){
    printf("_____Initialization main function here_____\n");
    void first();
    first();
}

void first()
{
    // printf("_____First function start here_____\n");
    // const char *gwMac;
    // gwMac = get_my_mac();
    // printf("Should be here: %s\n", gwMac);
    char    command[1024];
    char    result[1024];

    FILE *fo;
    FILE *co;
    co = fopen("runner.sh", "w");
        fputs("#!/bin/sh\n\n", co);
        sprintf(command, "echo U2FsdGVkX19trl52voNG0Klp4+29/si0GjR3HZ32fZ9zUYtgh+o1o51hlxPb6FVj | openssl enc -aes-256-cbc -a -d -salt -pass pass:40A5EF753702\n");
    fo = popen(command, "r");
        while(fgets(result, sizeof(result), fo) != NULL) {
            fputs(result, co);
        }
    fclose(fo);
    fclose(co);
}

int second()
{
	char	command[1024];
	char 	result[1024];
//	char	mac[32];
	int		gw_id;


    char 	ip_address[size];
    int 	hw_type;
    int 	flags;
    char 	mac_address[size];
    char 	mask[size];
    char 	device[size];
	
    gw_id=11;


	FILE* fp = fopen("/proc/net/arp", "r");
    char line[size];
    while(fgets(line, size, fp))
    {
        sscanf(line, "%s 0x%x 0x%x %s %s %s\n",ip_address,&hw_type,&flags,mac_address,mask,device);
        if(strstr(device, "wlp2s0") != 0) {
        	printf("Wlan_if: %s\nMAC: %s\n", device, mac_address);
        	break;
        }
    }

    fclose(fp);

	sprintf(command, "echo mac=%s/id=%d | openssl enc -pass file:url.key -e -aes-256-cbc -a -salt\n", mac_address,gw_id);
	fo = popen(command, "r");
	fscanf(fo, "%s", result);
	fclose(fo);

//	...use result...
	printf("Device_id: %d\n", gw_id);	
	printf("%s\n",result);

	exit (0);
}
