#include <mosquitto.h>
#include <cJSON.h>

#define PROC_IF_STATISTIC	"/proc/net/dev"
#define PROC_MEM_STATISTIC	"/proc/meminfo"
#define PROC_APCLI_STATISTIC_RX5g	"/proc/apclient_statistics5g/rx"
#define PROC_APCLI_STATISTIC_TX5g	"/proc/apclient_statistics5g/tx"
#define PROC_APCLI_STATISTIC_RX	"/proc/apclient_statistics/rx"
#define PROC_APCLI_STATISTIC_TX	"/proc/apclient_statistics/tx"


#define TXBYTE		0
#define TXPACKET	1
#define RXBYTE		2
#define RXPACKET	3

typedef union _LARGE_INTEGER {
	struct {
		unsigned long LowPart;
		long HighPart;
	};
	struct {
		unsigned long LowPart;
		long HighPart;
	} u;
	signed long long QuadPart;
} LARGE_INTEGER;


typedef struct _NDIS_802_11_STATISTICS
{
	unsigned long   Length;             // Length of structure
	LARGE_INTEGER   TransmittedFragmentCount;
	LARGE_INTEGER   MulticastTransmittedFrameCount;
	LARGE_INTEGER   FailedCount;
	LARGE_INTEGER   RetryCount;
	LARGE_INTEGER   MultipleRetryCount;
	LARGE_INTEGER   RTSSuccessCount;
	LARGE_INTEGER   RTSFailureCount;
	LARGE_INTEGER   ACKFailureCount;
	LARGE_INTEGER   FrameDuplicateCount;
	LARGE_INTEGER   ReceivedFragmentCount;
	LARGE_INTEGER   MulticastReceivedFrameCount;
	LARGE_INTEGER   FCSErrorCount;
#if 1
	LARGE_INTEGER	TransmittedFrameCount;
	LARGE_INTEGER	WEPUndecryptableCount;
#endif
	LARGE_INTEGER   TKIPLocalMICFailures;
	LARGE_INTEGER   TKIPRemoteMICErrors;
	LARGE_INTEGER   TKIPICVErrors;
	LARGE_INTEGER   TKIPCounterMeasuresInvoked;
	LARGE_INTEGER   TKIPReplays;
	LARGE_INTEGER   CCMPFormatErrors;
	LARGE_INTEGER   CCMPReplays;
	LARGE_INTEGER   CCMPDecryptErrors;
	LARGE_INTEGER   FourWayHandshakeFailures;
} NDIS_802_11_STATISTICS, *PNDIS_802_11_STATISTICS;

typedef union _MACHTTRANSMIT_SETTING {
	struct  {
		unsigned short  MCS:7;  // MCS
		unsigned short  BW:1;   //channel bandwidth 20MHz or 40 MHz
		unsigned short  ShortGI:1;
		unsigned short  STBC:2; //SPACE
		unsigned short	eTxBF:1;
		unsigned short	rsv:1;
		unsigned short	iTxBF:1;
		unsigned short  MODE:2; // Use definition MODE_xxx.
	} field;
	unsigned short      word;
} MACHTTRANSMIT_SETTING;

typedef struct _RT_802_11_MAC_ENTRY {
	unsigned char			ApIdx;
	unsigned char           Addr[6];
	unsigned char           Aid;
	unsigned char           Psm;     // 0:PWR_ACTIVE, 1:PWR_SAVE
	unsigned char           MimoPs;  // 0:MMPS_STATIC, 1:MMPS_DYNAMIC, 3:MMPS_Enabled
	char                    AvgRssi0;
	char                    AvgRssi1;
	char                    AvgRssi2;
	unsigned int            ConnectedTime;
	MACHTTRANSMIT_SETTING	TxRate;
	unsigned int			LastRxRate;
	int					    StreamSnr[3];
	int					    SoundingRespSnr[3];
} RT_802_11_MAC_ENTRY;

#define MAX_NUMBER_OF_MAC   32 // if MAX_MBSSID_NUM is 8, this value can't be larger than 211

typedef struct _RT_802_11_MAC_TABLE {
	unsigned long            Num;
	RT_802_11_MAC_ENTRY      Entry[MAX_NUMBER_OF_MAC]; //MAX_LEN_OF_MAC_TABLE = 32
} RT_802_11_MAC_TABLE;

int setEasyWizardCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getEasyWizardCfg(struct mosquitto *mosq, cJSON* data, char *tp);
int getGlobalFeatureBuilt(struct mosquitto *mosq, cJSON* data, char *tp);
int getSysStatusCfg(struct mosquitto *mosq, cJSON* data, char *tp);

