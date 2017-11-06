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
    printf("Initialization main function here_____\n");
    void first();
    first();
}

void first()
{
    printf("First function start here_____\n");
    //int second();
    //second();
    char buff;
    //char result[12];
    //get_my_mac();
    const char *gwMac;

    gwMac = get_my_mac();

    //gwMac = sscanf("%s", &gwMac);

    printf("Should be here: %s\n", buff);

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
