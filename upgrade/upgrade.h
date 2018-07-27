#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"
#include "sigHd.h"

#define GOOD_BANK_MARK_MASK 0x80000000  //goo abnk mark must set bit31 to 1
#define NO_IMAGE_BANK_MARK 0x80000000  
#define FORCEBOOT_BANK_MARK 0xFFFFFFF0  //means always boot/upgrade in this bank
#define BASIC_BANK_MARK 0x80000002
#define OLD_BURNADDR_BANK_MARK 0x80000001 

#if  defined(CONFIG_KL_C7185R_04336)||defined(CONFIG_KL_C7187R_1200)
static char *Kernel_dev_name[2]=
 {
   "/dev/mtd0", "/dev/mtd2"
 };
static char *Rootfs_dev_name[2]=
 {
   "/dev/mtd1", "/dev/mtd3"
 };
#define MTD_USERDATA "/dev/mtd4"   
#else
#define MTD_ROOTFS "/dev/mtd1"
#define MTD_KERNEL "/dev/mtd0"
#endif 

#if defined(CONFIG_KL_USER_DATA_PARTITION)
#define MTD_USERDATA "/dev/mtd2"
#endif

#define INIFILE       "/mnt/custom/product.ini"


#define CONFIGSIZE 		128*1024

int setUpgradeFW(struct mosquitto *mosq, cJSON* data, char *tp);
int setUploadSetting(struct mosquitto *mosq, cJSON* data, char *tp);
int CloudACMunualUpdate(struct mosquitto *mosq, cJSON* data, char *tp);
