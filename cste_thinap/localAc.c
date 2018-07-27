#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "manageAgent.h"
#include "../cstelib.h"


void send_mqtt_heart_beat(void)
{
	safe_cs_pub("127.0.0.1", "sendAPHeartBeat","{}");
}

