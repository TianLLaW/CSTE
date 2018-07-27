#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <sys/sysinfo.h>
#include "system/system.h"

int main(int argc, char *argv[])
{ 
	int iSche;

	iSche=atoi(argv[1]);
	if(iSche>0){
		printf("The system will auto restasrt in %ld seconds!\n",iSche);
		sleep(iSche);	
		system("reboot");
	}
	return 0;
}

