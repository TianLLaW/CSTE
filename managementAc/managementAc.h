#include <stdio.h>
#include <mosquitto.h>
#include <cJSON.h>
#include <signal.h>
#include <setjmp.h>
#include <netdb.h>
#include <time.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/stat.h>   
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <linux/if.h>


#include <cste_sql.h>
#include "../cstelib.h"

#define SIG_ACRESET	61 

#define SIG_BROADCAST 62

#define SIG_SETAPIP 63

