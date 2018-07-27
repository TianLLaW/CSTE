/*
# Read Me: This file is used to making a cmd pub_client.
# There is already a pub_client in Mosquitto/client, but it doesn't work on RTL boards
*/

#include <stdio.h>
#include "cstelib.h"

int main(int argc, char *argv[])
{
	if(argc != 4){
		printf("USAGE: cs_pub dst_host your_topic your_message");
		exit(-1);
	}
	safe_cs_pub(argv[1], argv[2], argv[3]);
	exit(0);
}