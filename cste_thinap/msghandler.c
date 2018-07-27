#include "manageAgent.h"
#include "../cstelib.h"

int WlanConunt;
struct WirelessConfigContent WirelessConfig;
struct SystemConfigContent SytstemConfig;

/****************************************************************
*                                                               *
*           Specific functions take effect                      *
*                                                               *
*****************************************************************/
int TakeEffectConfig(char *action, char *http_data, cJSON *data)
{
    pthread_mutex_unlock(&thd_mutex);
    return 0;
}

int TakeEffectWireless(void)
{
	if(WlanConunt<=1){
		#if defined (FOR_DUAL_BAND) 	//2.4G and 5G
			takeEffectWlan(W24G_DE, 1);
			takeEffectWlan(W58G_DE, 1);
		#else							//only 2.4G or only 5G
			takeEffectWlan(W24G_DE, 1); 
		#endif
	}else if(WlanConunt==2){
		#if defined (FOR_DUAL_BAND)
			takeEffectWlan(W24G_DE, 1);
			takeEffectWlan(W24G_DE_VAP1, 1);
			takeEffectWlan(W58G_DE, 1);
			takeEffectWlan(W58G_DE_VAP1, 1);
		#else
			takeEffectWlan(W24G_DE, 1); 
			takeEffectWlan(W24G_DE_VAP1, 1);
		#endif
	}else{
		#if defined (FOR_DUAL_BAND)
			takeEffectWlan(W24G_DE, 0);
			takeEffectWlan(W24G_DE_VAP1, 0);
			takeEffectWlan(W24G_DE_VAP2, 0);
			takeEffectWlan(W58G_DE, 0);
			takeEffectWlan(W58G_DE_VAP1, 0);
			takeEffectWlan(W58G_DE_VAP2, 1);
		#else
			takeEffectWlan(W24G_DE, 0);
			takeEffectWlan(W24G_DE_VAP1, 0);
			takeEffectWlan(W24G_DE_VAP2, 1);
		#endif
	}
	return 0;
}

int TakeEffectSystem(void)
{
  unsigned int iSche;
    unsigned long cfgSec,sec;
    char buff[TEMP_BUF_SIZE];
	int iMode=0;
    struct sysinfo info;
	iMode = atoi(SytstemConfig.rebooScheduleCfg.mode);
	
	CsteSystem("killall sche_reboot", CSTE_PRINT_CMD);
	CsteSystem("csteSys rebootSch", CSTE_PRINT_CMD);
	CsteSystem("csteSys updateCrond", CSTE_PRINT_CMD);
	switch(iMode){
		case 1:
			CsteSystem("csteSys rebootSch", CSTE_PRINT_CMD);
			CsteSystem("csteSys updateCrond", CSTE_PRINT_CMD);
			break;
		case 2://倒计时
 			iSche=atoi(SytstemConfig.rebooScheduleCfg.recHour);
			if(iSche>0){
				sysinfo(&info);
				sec = (unsigned long) info.uptime ;
				cfgSec = iSche * 3600-sec;
				if(cfgSec>0){
					CsteSystem("killall sche_reboot", CSTE_PRINT_CMD);
					sprintf(buff,"sche_reboot %ld &",cfgSec);
					CsteSystem(buff, CSTE_PRINT_CMD);
				}else{
					CsteSystem("reboot",CSTE_PRINT_CMD);
				}
			}else{
				 CsteSystem("killall sche_reboot", CSTE_PRINT_CMD);
			}
			break;
		case 0: 
			break;
		default:
			break;
	}
    return 0;
}

int TakeEffectUpgradeFW(void)
{
	safe_cs_pub("127.0.0.1", "CloudACMunualUpdate","{}");
    return 0;
}

int TakeEffectReset(void)
{
#if defined(CONFIG_KL_C8B180A_AP0167)||defined(CONFIG_KL_CSB180A_AP0167)||defined(CONFIG_KL_C8B181A_AP0169)
	system("csteSys reg 1 0xb800350c 15 1");//关闭红色灯H1
#elif defined(CONFIG_KL_C8B182A_AP0170)
	system("csteSys reg 1 0xb800350c 15 1");//关闭红色灯
#endif	
	system("csteSys reg 1 0xb800350c 31 2");//绿灯快闪
	
	CsteSystem("csteSys csnl 1 -2", CSTE_PRINT_CMD);
	int pid;		
	pid=fork();
	if(0 == pid)
	{
		apmib_updateDef();//生成DEF配置
		apmib_reinit();//初始化配置

		if(0 != f_exist("/mnt/custom/product.ini")){
			RunSystemCmd(NULL_FILE, "convertIniToCfg",NULL_STR);
		}

		apmib_update_web(CURRENT_SETTING);//更新配置至flash
		sleep(1);

		CsteSystem("reboot", CSTE_PRINT_CMD);
		exit(1);
	}

    return 0;
}

int TakeEffectReboot(void)
{
    CsteSystem("reboot", CSTE_PRINT_CMD);
    return 0;
}

/****************************************************************
*                                                               *
*                   Update configuration file                   *
*                                                               *
*****************************************************************/
void UpdateRadioConfig(void)
{
    int RadioIndex;
	int iband=0;
	int bandwidth,tmpInt,len_channel;
	char tmpBuf[32]={0};
	char t_Buf[32]={0};
	
    for(RadioIndex=0; RadioIndex<MAX_RADIO_NUM; RadioIndex++)
    {
        if(RadioIndex == 0)
        {
			SetWlan_idx(W24G_DE);
			iband=11;
        }
        else if(RadioIndex == 1)
        {
			SetWlan_idx(W58G_DE);
			iband=76;
        }
		
		//BAND
        
        switch(atoi(WirelessConfig.RadioConfigTable[RadioIndex].wirelessmode)){
            case 0 :
                iband = BAND_11BG; // 3
                break;
            case 1 :
                iband = BAND_11B; // 1
                break;
            case 2 :
                iband = BAND_11A; // 4
                break;
            case 4 :
                iband = BAND_11G; // 2
                break;
            case 6 :
                iband = BAND_11N; // 8
                break;
            case 8 :
                iband = BAND_5G_11AN; // 12
                break;
            case 9 :
                iband = 11;
                break;
            case 14 :
                iband = 76;
                break;
            default :
                break;
        }
	
        apmib_set(MIB_WLAN_BAND, (char *)&iband);

		//bandwidth
        if (atoi(WirelessConfig.RadioConfigTable[RadioIndex].htmode)==0)
			bandwidth = 0;//20M
        else if (atoi(WirelessConfig.RadioConfigTable[RadioIndex].htmode)==1)
            bandwidth = 3;//40M
        else
            bandwidth = 2;//80M
        apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&bandwidth);
		
        // Channel
		apmib_get(MIB_WLAN_CHANNEL,(void *)&len_channel);
		sprintf(t_Buf,"%d",len_channel);
		if(strlen(WirelessConfig.RadioConfigTable[RadioIndex].channel)>0 && strcmp(t_Buf,WirelessConfig.RadioConfigTable[RadioIndex].channel)!=0){
			int ichannel=atoi(WirelessConfig.RadioConfigTable[RadioIndex].channel);
			if(ichannel==165){
				tmpInt = 0;//BW:20M
				apmib_set(MIB_WLAN_CHANNEL_BONDING,(void *)&tmpInt);
			}
			apmib_set(MIB_WLAN_CHANNEL,(void *)&ichannel);
		}
		
		//country
		int iReg;
		memset(tmpBuf,'\0',sizeof(tmpBuf));
		apmib_get(MIB_WLAN_COUNTRY_STRING, (void *)tmpBuf);
		if(!strcmp(tmpBuf,WirelessConfig.RadioConfigTable[RadioIndex].country)){
			printf("country string no change!\n");
		}else{
			apmib_set(MIB_WLAN_COUNTRY_STRING, (void *)WirelessConfig.RadioConfigTable[RadioIndex].country);
			if(!strcmp("US",WirelessConfig.RadioConfigTable[RadioIndex].country)){
				iReg=FCC;
			}else if(!strcmp("EU",WirelessConfig.RadioConfigTable[RadioIndex].country)){
				iReg=ETSI;
			}else if(!strcmp("OT",WirelessConfig.RadioConfigTable[RadioIndex].country)){
				iReg=16;
			}else if(!strcmp("IN",WirelessConfig.RadioConfigTable[RadioIndex].country)){
				iReg=CN;
			}else{
				iReg=CN;
			}
			if ( apmib_set(MIB_HW_REG_DOMAIN, (void *)&iReg) == 0) {
				printf("Set wlan regdomain error!\n");
			}
			apmib_update(HW_SETTING);
		}

		//tx_power
		if(strlen(WirelessConfig.RadioConfigTable[RadioIndex].txpower)>0){
			tmpInt = atoi(WirelessConfig.RadioConfigTable[RadioIndex].txpower);
			if( 0<=tmpInt && tmpInt<=15 ) tmpInt = 4;
			else if(15<tmpInt && tmpInt<=35) tmpInt = 3;
			else if(35<tmpInt && tmpInt<=50) tmpInt = 2;
			else if(50<tmpInt && tmpInt<=75) tmpInt = 1;
			else if(75<tmpInt && tmpInt<=100) tmpInt = 0;
			else tmpInt = 0;
			apmib_set(MIB_WLAN_RFPOWER_SCALE,(void *)&tmpInt);
		}
    }
	
	apmib_update_web(CURRENT_SETTING);
	
    return;
}

void UpdateWlanConfig(void)
{
    int wlanIndex=0,vap0Count=0,vap1Count=0,dualband=0;
	int rtl_hidden_ssid;
	int wlan_disabled=0;
    char *vap0_attr[]= {W24G_DE,W24G_DE_VAP1,W24G_DE_VAP2,W24G_DE_VAP3,W24G_DE_VAP4};
    char *vap1_attr[]= {W58G_DE,W58G_DE_VAP1,W58G_DE_VAP2,W58G_DE_VAP3,W58G_DE_VAP4};

    /*config vap by server info*/
    for(wlanIndex=0; wlanIndex<WlanConunt; wlanIndex++)
    {
        if (atoi(WirelessConfig.WlanConfigTable[wlanIndex].usefor) == 3) //5G and 2.4G
        {
            dualband=1;
			SetWlan_idx(vap0_attr[vap0Count++]);
        }
        if (atoi(WirelessConfig.WlanConfigTable[wlanIndex].usefor) == 2) //5G
        {
			SetWlan_idx(vap1_attr[vap1Count++]);
        }
        else if(atoi(WirelessConfig.WlanConfigTable[wlanIndex].usefor) == 1) //2.4G
        {
       	 	
			SetWlan_idx(vap0_attr[vap0Count++]);
				
        }
        else if(atoi(WirelessConfig.WlanConfigTable[wlanIndex].usefor) == 0)
        {
            continue;
        }
		
dual:
		apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
		if(strlen(WirelessConfig.WlanConfigTable[wlanIndex].ssid)>0)
			apmib_set( MIB_WLAN_SSID, (char *)WirelessConfig.WlanConfigTable[wlanIndex].ssid);

        if(atoi(WirelessConfig.WlanConfigTable[wlanIndex].encryption) == 1){
			int wep,encryp,auth_wpa,pskformat,ciphersuite1,ciphersuite2;
			encryp=ENCRYPT_WPA2_MIXED;
			ciphersuite1 = WPA_CIPHER_AES;
			ciphersuite2 = WPA_CIPHER_MIXED;
			pskformat = 0;//RTL 0:ASCII 1:HEX MTK 0:Hex 1:ASCII
			wep=WEP_DISABLED;
			auth_wpa=WPA_AUTH_PSK;
			apmib_set( MIB_WLAN_WPA_PSK, (void *)WirelessConfig.WlanConfigTable[wlanIndex].passphrass);
			apmib_set( MIB_WLAN_WEP, (void *)&wep);
			apmib_set( MIB_WLAN_ENCRYPT, (void *)&encryp);
			apmib_set( MIB_WLAN_PSK_FORMAT, (void *)&pskformat);
			apmib_set( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&ciphersuite1);
			apmib_set( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&ciphersuite2);
			apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
		}else{
			int wep,encryp,auth_wpa;
			encryp=ENCRYPT_DISABLED;
			wep=WEP_DISABLED;
			auth_wpa=WPA_AUTH_PSK;
			apmib_set( MIB_WLAN_WEP, (void *)&wep);
			apmib_set( MIB_WLAN_ENCRYPT, (void *)&encryp);			
			apmib_set( MIB_WLAN_WPA_AUTH, (void *)&auth_wpa);
			apmib_set( MIB_WLAN_WPA_PSK,"");	
        }
		
		rtl_hidden_ssid = atoi(WirelessConfig.WlanConfigTable[wlanIndex].hide);
		apmib_set( MIB_WLAN_HIDDEN_SSID, (void *)&rtl_hidden_ssid);
		
		if(dualband){
			dualband=0;
			SetWlan_idx(W58G_DE);
			goto dual;
		}
		
		apmib_update_web(CURRENT_SETTING);
	}
    return;
}

void UpdateSystemConfig(void)
{
	int ledstate=0,iMode=0,ischeWeek=0,ischeHour=0,ischeMn,count_down=0,week;
    apmib_set(MIB_APNAME, (char *)SytstemConfig.apName);
	
	iMode=atoi(SytstemConfig.rebooScheduleCfg.mode);
	apmib_set(MIB_REBOOTSCH_ENABLED,(void *)&iMode);//0:禁用；1:定时 2:倒计时；
	//定时
	ischeWeek=atoi(SytstemConfig.rebooScheduleCfg.week);
	switch(ischeWeek){
		case 255:
			week=0;
			break;
		case 128:
			week=7;
			break;
		case 64:
			week=6;
			break;
		case 32:
			week=5;
			break;
		case 16:
			week=4;
			break;
		case 8:
			week=3;
			break;
		case 4:
			week=2;
			break;
		case 2:
			week=1;
			break;
		default:
			break;
			
	}
	apmib_set(MIB_REBOOTSCH_WEEK, (void *)&week);
	ischeHour=atoi(SytstemConfig.rebooScheduleCfg.hour);
	apmib_set(MIB_REBOOTSCH_HOUR, (void *)&ischeHour);
	ischeMn=atoi(SytstemConfig.rebooScheduleCfg.minute);
	apmib_set(MIB_REBOOTSCH_MINUTE, (void *)&ischeMn);
	//倒计时
	count_down=atoi(SytstemConfig.rebooScheduleCfg.recHour);
	apmib_set(MIB_SCHE_DAY,(void *)&count_down);

	apmib_update_web(CURRENT_SETTING);

	ledstate = atoi(SytstemConfig.ledState);
	switch (ledstate)
	{
		case 3://off
			system("csteSys reg 1 0xb800350c 17 3");
			system("csteSys reg 1 0xb800350c 17 1");
			break;
		case 2://blink
			system("csteSys reg 1 0xb800350c 17 2");
			break;
		case 1://light
			system("csteSys reg 1 0xb800350c 17 3");
			system("csteSys reg 1 0xb800350c 17 0");
			break;
		defaule:
			break;
	}
  
    return;
}

/****************************************************************
*                                                               *
*                   Thread processing events                    *
*                                                               *
*****************************************************************/
void *HanderThread(void *arg)
{
    while(1)
    {
        pthread_mutex_lock(&thd_mutex);
        if(HB_TRUE == gwAc.SetWireless)
        {
            GWAC_SET_WIRELESS(HB_FALSE);
            UpdateRadioConfig();
            UpdateWlanConfig();
			TakeEffectWireless();
        }

        if(HB_TRUE == gwAc.SetSystem)
        {
            GWAC_SET_SYSTEM(HB_FALSE);
            UpdateSystemConfig();
            TakeEffectSystem();
        }

        if(HB_TRUE == gwAc.SetUpgrade)
        {
            GWAC_SET_UPG(HB_FALSE);
            TakeEffectUpgradeFW();
        }

        if(HB_TRUE == gwAc.SetReset)
        {
            GWAC_SET_RESET(HB_FALSE);
            TakeEffectReset();
        }

        if(HB_TRUE == gwAc.SetReboot)
        {
            GWAC_SET_REBOOT(HB_FALSE);
            TakeEffectReboot();
        }
    }
}

/****************************************************************
*                                                               *
*                       events registration                     *
*                                                               *
*****************************************************************/
int SetRadioConfig(char *action, char *http_data, cJSON *data)
{
    cJSON *PRadio=NULL;
    int RadioIndex=0;
    char RadioName[SMALL_BUF_SIZE]= {0};

    for(RadioIndex=0; RadioIndex<MAX_RADIO_NUM; RadioIndex++)
    {
    	#if defined(ONLY_5G_SUPPORT)
			sprintf(RadioName, "RADIO%d", 1);
		#else
       	 	sprintf(RadioName, "RADIO%d", RadioIndex);
		#endif
        PRadio = cJSON_GetObjectItem(data, RadioName);
        if(PRadio != NULL)
        {
            strcpy(WirelessConfig.RadioConfigTable[RadioIndex].country,           websGetVar(PRadio, T("country"), T(""))         );
            strcpy(WirelessConfig.RadioConfigTable[RadioIndex].wirelessmode,      websGetVar(PRadio, T("wirelessmode"), T(""))   );
            strcpy(WirelessConfig.RadioConfigTable[RadioIndex].htmode,            websGetVar(PRadio, T("htmode"), T(""))          );
            strcpy(WirelessConfig.RadioConfigTable[RadioIndex].channel,           websGetVar(PRadio, T("channel"), T(""))         );
            strcpy(WirelessConfig.RadioConfigTable[RadioIndex].txpower,           websGetVar(PRadio, T("txpower"), T(""))         );
            strcpy(WirelessConfig.RadioConfigTable[RadioIndex].beacon,            websGetVar(PRadio, T("beacon"), T(""))          );
        }
    }

    GWAC_SET_WIRELESS(HB_TRUE);
    JobQueueDeleteFirstJobByType(JOB_CONFIG_EFFECT);
    JobQueueAddJob(HANDER_DELAY_TIME,JOB_CONFIG_EFFECT, TakeEffectConfig, NULL, NULL);
    return 0;
}

int SetWlanConfig(char *action, char *http_data, cJSON *data)
{
    int WlanIndex=0;
    cJSON *PWlan=NULL, *SubObj=NULL;

    PWlan = cJSON_GetObjectItem(data, "SSIDS");;
    WlanConunt = cJSON_GetArraySize(PWlan);
    for(WlanIndex=0; WlanIndex<WlanConunt; WlanIndex++)
    {
        SubObj = cJSON_GetArrayItem(PWlan, WlanIndex);
        strcpy(WirelessConfig.WlanConfigTable[WlanIndex].ssid,          websGetVar(SubObj, T("ssid"), T(""))        );
        strcpy(WirelessConfig.WlanConfigTable[WlanIndex].hide,          websGetVar(SubObj, T("hide"), T(""))        );
        strcpy(WirelessConfig.WlanConfigTable[WlanIndex].stanum,        websGetVar(SubObj, T("stanum"), T(""))     );
        strcpy(WirelessConfig.WlanConfigTable[WlanIndex].vlanid,        websGetVar(SubObj, T("vlanid"), T(""))      );
        strcpy(WirelessConfig.WlanConfigTable[WlanIndex].isolate,       websGetVar(SubObj, T("isolate"), T(""))     );
        strcpy(WirelessConfig.WlanConfigTable[WlanIndex].usefor,        websGetVar(SubObj, T("usefor"), T(""))      );
        strcpy(WirelessConfig.WlanConfigTable[WlanIndex].encryption,    websGetVar(SubObj, T("encryption"), T(""))  );
        strcpy(WirelessConfig.WlanConfigTable[WlanIndex].passphrass,    websGetVar(SubObj, T("passphrase"), T(""))  );
    }

	GWAC_SET_WIRELESS(HB_TRUE);
    JobQueueDeleteFirstJobByType(JOB_CONFIG_EFFECT);
    JobQueueAddJob(HANDER_DELAY_TIME,JOB_CONFIG_EFFECT, TakeEffectConfig, NULL, NULL);
    return 0;
}

int SetSysConfig(char *action, char *http_data, cJSON *data)
{
    strcpy(SytstemConfig.apName,          websGetVar(data, T("apName"), T(""))         );
	strcpy(SytstemConfig.ledState,        websGetVar(data, T("ledState"), T("0"))      );
    //strcpy(SytstemConfig.HbInterval,      websGetVar(data, T("HbInterval"), T(""))     );
    cJSON *schdReboot =  cJSON_GetObjectItem(data,"rebooSchedule");
	if(schdReboot){
		strcpy(SytstemConfig.rebooScheduleCfg.mode,   websGetVar(schdReboot, T("mode"), T("0")) );
		strcpy(SytstemConfig.rebooScheduleCfg.week,   websGetVar(schdReboot, T("week"), T(""))  );
		strcpy(SytstemConfig.rebooScheduleCfg.hour,   websGetVar(schdReboot, T("hour"), T(""))  );
		strcpy(SytstemConfig.rebooScheduleCfg.minute, websGetVar(schdReboot, T("minute"), T("")));
		strcpy(SytstemConfig.rebooScheduleCfg.recHour, websGetVar(schdReboot, T("recHour"), T("")));
	}
    GWAC_SET_SYSTEM(HB_TRUE);
    JobQueueDeleteFirstJobByType(JOB_CONFIG_EFFECT);
    JobQueueAddJob(HANDER_DELAY_TIME,JOB_CONFIG_EFFECT, TakeEffectConfig, NULL, NULL);
    return 0;
}

int SetCheckTime(char *action, char *http_data, cJSON *data)
{
    JobQueueAddJob(HANDER_DELAY_TIME,JOB_CONFIG_EFFECT, TakeEffectConfig, NULL, NULL);
    return 0;
}


int SetUpgrade(char *action, char *http_data, cJSON *data)
{
    char cmd[CMD_BUF_SIZE]= {0};
    char *fileUrl = websGetVar(data, T("url"), T(""));
    if(strlen(fileUrl) > 0)
    {
        sprintf(cmd, "echo %s > /tmp/DlFileUrl", fileUrl);
        CsteSystem(cmd, CSTE_PRINT_CMD);
    }
	
    GWAC_SET_UPG(HB_TRUE);
    JobQueueAddJob(HANDER_DELAY_TIME,JOB_CONFIG_EFFECT, TakeEffectConfig, NULL, NULL);
    return 0;
}

int SetReset(char *action, char *http_data, cJSON *data)
{
    GWAC_SET_RESET(HB_TRUE);
    JobQueueAddJob(HANDER_DELAY_TIME,JOB_CONFIG_EFFECT, TakeEffectConfig, NULL, NULL);
    return 0;
}

int SetReboot(char *action, char *http_data, cJSON *data)
{
    GWAC_SET_REBOOT(HB_TRUE);
    JobQueueAddJob(HANDER_DELAY_TIME,JOB_CONFIG_EFFECT, TakeEffectConfig, NULL, NULL);
    return 0;
}

