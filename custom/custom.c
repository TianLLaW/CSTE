
#include "custom.h"

static const char Base64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';

int base64_decode (char *src, char *target, size_t targsize)
{
  int tarindex, state, ch;
  char *pos;

  state = 0;
  tarindex = 0;

  while ((ch = *src++) != '\0')
    {
      if (isspace (ch))		/* Skip whitespace anywhere. */
	continue;

      if (ch == Pad64)
	break;

      pos = strchr (Base64, ch);
      if (pos == 0)		/* A non-base64 character. */
	return (-1);

      switch (state)
	{
	case 0:
	  if (target)
	    {
	      if ((size_t) tarindex >= targsize)
		return (-1);
	      target[tarindex] = (pos - Base64) << 2;
	    }
	  state = 1;
	  break;
	case 1:
	  if (target)
	    {
	      if ((size_t) tarindex + 1 >= targsize)
		return (-1);
	      target[tarindex] |= (pos - Base64) >> 4;
	      target[tarindex + 1] = ((pos - Base64) & 0x0f) << 4;
	    }
	  tarindex++;
	  state = 2;
	  break;
	case 2:
	  if (target)
	    {
	      if ((size_t) tarindex + 1 >= targsize)
		return (-1);
	      target[tarindex] |= (pos - Base64) >> 2;
	      target[tarindex + 1] = ((pos - Base64) & 0x03) << 6;
	    }
	  tarindex++;
	  state = 3;
	  break;
	case 3:
	  if (target)
	    {
	      if ((size_t) tarindex >= targsize)
		return (-1);
	      target[tarindex] |= (pos - Base64);
	    }
	  tarindex++;
	  state = 0;
	  break;
	default:
	  abort ();
	}
    }

  /*
   * We are done decoding Base-64 chars.  Let's see if we ended
   * on a byte boundary, and/or with erroneous trailing characters.
   */

  if (ch == Pad64)
	  { 			  /* We got a pad char. */
		ch = *src++;	  /* Skip it, get next. */
		switch (state)
	  {
	  case 0:	  /* Invalid = in first position */
	  case 1:	  /* Invalid = in second position */
		return (-1);
  
	  case 2:	  /* Valid, means one byte of info */
		/* Skip any number of spaces. */
		for ((void) NULL; ch != '\0'; ch = *src++)
		  if (!isspace (ch))
			break;
		/* Make sure there is another trailing = sign. */
		if (ch != Pad64)
		  return (-1);
		ch = *src++;	  /* Skip the = */
		/* Fall through to "single trailing =" case. */
		/* FALLTHROUGH */
  
	  case 3:	  /* Valid, means two bytes of info */
		/*
		 * We know this char is an =.  Is there anything but
		 * whitespace after it?
		 */
		for ((void) NULL; ch != '\0'; ch = *src++)
		  if (!isspace (ch))
			return (-1);
  
		/*
		 * Now make sure for cases 2 and 3 that the "extra"
		 * bits that slopped past the last full byte were
		 * zeros.  If we don't check them, they become a
		 * subliminal channel.
		 */
		if (target && target[tarindex] != 0)
		  return (-1);
	  }
	  }
	else
	  {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != 0)
	  return (-1);
	  }

  return (tarindex);
}

void lockUserData()
{
	system("echo 1 > /proc/udwrite 2>/dev/null");
	return;
}

void unlockUserData()
{
	system("echo 0 > /proc/udwrite 2>/dev/null");
	return;
}

void QuickSettingRsp(struct mosquitto *mosq, char *tp, cJSON *root)
{	
    char* output;
    
    char topic[256]={0};
    int mid_sent = 0;

    output =cJSON_Print(root);
    sprintf(topic,"%s/R", tp);
    mosquitto_publish(mosq, &mid_sent, topic, strlen(output), output, 0, 0);
    cJSON_Delete(root);
	free(output);
}

int QuickCustom(struct mosquitto *mosq, cJSON* data, char *tp)
{
	if(0 == f_exist(cste_lock))
	{
		lock_file(cste_lock);
	}
	else
	{
		return 0;
	}
	int i = 0;
	char tmpbuf[64],base64_src[204800]={0},file_centent[204800]={0};
	char cmd[128],lang[8] ={0},tmpHelpUrl[32] = {0};
	
	FILE *creatFile =NULL;
	size_t bytes;
	cJSON *DATA=NULL,*root;
	root=cJSON_CreateObject();

	char *Action=websGetVar(data,T("Action"),T(""));
	DATA = cJSON_GetObjectItem(data,"data");

	if(strcmp(Action,"GetFile")==0){
		char *MD5=websGetVar(DATA,T("FileMd5"),T(""));
		char *fileUrl=websGetVar(DATA,T("FileUrl"),T(""));
		char *file=websGetVar(DATA,T("File"),T(""));

		sprintf(base64_src,"%s",file);
		bytes=base64_decode(base64_src,file_centent,sizeof(file_centent));
		
		FILE *fp=fopen("/tmp/custom_file","wb");
		fwrite(file_centent,bytes,1,fp);
		memset(file_centent,0,sizeof(file_centent));
		memset(base64_src,0,sizeof(base64_src));
		fclose(fp);
		
		char CalfileMd5[33]={0};
		int ret=Cal_file_md5("/tmp/custom_file",CalfileMd5);
		if(strcmp(MD5,CalfileMd5)==0 ){
			unlockUserData();
			if(strstr(fileUrl,".ini")!=NULL){
				unlockUserData();
				CsteSystem("cp -f /tmp/custom_file /mnt/custom/product.ini", CSTE_PRINT_CMD);
				CsteSystem("rm /tmp/custom_file", CSTE_PRINT_CMD);
				lockUserData();
				CsteSystem("convertIniToCfg", CSTE_PRINT_CMD);
				int pid=fork();
				if(0 == pid)
				{
					sleep(1);
					apmib_update_web(CURRENT_SETTING);
					sleep(1);
					run_init_script("all");
					exit(1);
				}
			}else{
				if(0 != d_exist(WEBDIR)){
					sprintf(cmd,"cp -f /tmp/custom_file %s/%s",WEBDIR,fileUrl);
					CsteSystem(cmd, CSTE_PRINT_CMD);
					sprintf(cmd,"cp -f /tmp/custom_file %s/%s",CUR_WEB_DIR,fileUrl);
					CsteSystem(cmd, CSTE_PRINT_CMD);
					CsteSystem("rm /tmp/custom_file", CSTE_PRINT_CMD);
				}else{
					sprintf(cmd,"mkdir -p %s %s %s",WEBDIR,STYLEDIR,JSDIR,IMAGE);
					CsteSystem(cmd, CSTE_PRINT_CMD);
					sprintf(cmd,"cp -f /tmp/custom_file %s/%s",WEBDIR,fileUrl);
					CsteSystem(cmd, CSTE_PRINT_CMD);
					sprintf(cmd,"cp -f /tmp/custom_file %s/%s",CUR_WEB_DIR,fileUrl);
					CsteSystem(cmd, CSTE_PRINT_CMD);
					CsteSystem("rm /tmp/custom_file", CSTE_PRINT_CMD);
				}
			}
			lockUserData();
			cJSON_AddStringToObject(root,"Result","Success");
		}
		else
		{
			cJSON_AddStringToObject(root,"Result","Fail");
		}
	}else if(strcmp(Action,"SetINI")==0){
		char *softmodel=websGetVar(DATA,T("Model"),T(""));
		char *csid=websGetVar(DATA,T("Csid"),T(""));
		char *hostname=websGetVar(DATA,T("HostName"),T(""));
		char *webTitle=websGetVar(DATA,T("webTitle"),T(""));
		char *Vendor=websGetVar(DATA,T("Vendor"),T(""));
		char *copyRight=websGetVar(DATA,T("copyRight"),T(""));
		char *domainAccess = websGetVar(DATA,T("DomainAccess"),T(""));
		char *language=websGetVar(DATA,T("Language"),T(""));
		char *multiLang=websGetVar(DATA,T("MultiLang"),T(""));
		char *TZ=websGetVar(DATA,T("TimeZone"),T(""));
		char *telnetkey=websGetVar(DATA,T("TelnetKey"),T(""));
		char *statistics_softmodel=websGetVar(DATA,T("StatisticsModel"),T(""));
		char *statistics_domain=websGetVar(DATA,T("StatisticsDomain"),T(""));
		char *LoginPassword=websGetVar(DATA,T("LoginPassword"),T(""));
		char *CloudUpdateDomain=websGetVar(DATA,T("CloudUpdateDomain"),T(""));

		char *def_ip=websGetVar(DATA,T("IpAddress"),T(""));
		char *dhcpStart=websGetVar(DATA,T("DhcpStart"),T(""));
		char *dhcpEnd=websGetVar(DATA,T("DhcpEnd"),T(""));
		
		char *Ssid_2G=websGetVar(DATA,T("Ssid_2G"),T(""));
		char *Ssid_Tail_2G=websGetVar(DATA,T("Ssid_Tail_2G"),T(""));
		char *wlanKey_2G=websGetVar(DATA,T("WlanKey_2G"),T("-1"));
		char *Channel_2G=websGetVar(DATA,T("Channel_2G"),T(""));
		char *CountryCode_2G=websGetVar(DATA,T("CountryCode_2G"),T(""));
		char *Txpower_2G=websGetVar(DATA,T("Txpower_2G"),T(""));

		char *Ssid_5G=websGetVar(DATA,T("Ssid_5G"),T(""));
		char *Ssid_Tail_5G=websGetVar(DATA,T("Ssid_Tail_5G"),T(""));
		char *wlanKey_5G=websGetVar(DATA,T("WlanKey_5G"),T("-1"));
		char *Channel_5G=websGetVar(DATA,T("Channel_5G"),T(""));
		char *CountryCode_5G=websGetVar(DATA,T("CountryCode_5G"),T(""));
		char *Txpower_5G=websGetVar(DATA,T("Txpower_5G"),T(""));
		
		char *FixedMac=websGetVar(DATA,T("FixedMac"),T(""));
		char *maxsta=websGetVar(DATA,T("MaxSta"),T(""));
		char *CountryCodeSupport=websGetVar(DATA,T("CountryCodeSupport"),T(""));
		char *CountryCodeList=websGetVar(DATA,T("CountryCodeList"),T(""));

		char *PppoeSpecSupport=websGetVar(DATA,T("PppoeSpecSupport"),T(""));
		char *PppoeSpecRussia=websGetVar(DATA,T("PppoeSpecRussia"),T(""));
		char *IptvSupport=websGetVar(DATA,T("IptvSupport"),T(""));
		char *IptvEnable=websGetVar(DATA,T("IptvEnable"),T(""));
		char *IptvModeDefault=websGetVar(DATA,T("IptvModeDefault"),T(""));
		char *IptvModeList=websGetVar(DATA,T("IptvModeList"),T(""));
		char *Ipv6Support=websGetVar(DATA,T("Ipv6Support"),T(""));
		char *WanTypeList=websGetVar(DATA,T("WanTypeList"),T(""));
		char *WanTypeDefault=websGetVar(DATA,T("WanTypeDefault"),T(""));
		char *L2tpClientSupport=websGetVar(DATA,T("L2tpClientSupport"),T(""));
		char *PptpClientSupport=websGetVar(DATA,T("PptpClientSupport"),T(""));
		char *L2tpServerSupport=websGetVar(DATA,T("L2tpServerSupport"),T(""));
		char *PptpServerSupport=websGetVar(DATA,T("PptpServerSupport"),T(""));
		char *DdnsSupport=websGetVar(DATA,T("DdnsSupport"),T(""));
		char *SsrServerSupport=websGetVar(DATA,T("SsrServerSupport"),T(""));
		char *WechatQrSupport=websGetVar(DATA,T("WechatQrSupport"),T(""));
		

		unlockUserData();
		
	    //[PRODUCT]
		memset(tmpbuf,0,sizeof(tmpbuf));	
		inifile_get_string(INI_FILE,"PRODUCT","HostName",tmpbuf);
		if(strlen(hostname)>0 && strcmp(hostname,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","HostName",hostname);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));	
		inifile_get_string(INI_FILE,"PRODUCT","Csid",tmpbuf);
		if(strlen(csid)>0 && strcmp(csid,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","Csid",csid);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","Model",tmpbuf);
		if(strlen(softmodel)>0 && strcmp(softmodel,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","Model",softmodel);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","DomainAccess",tmpbuf);
		if(strlen(domainAccess)>0 && strcmp(domainAccess,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","DomainAccess",domainAccess);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","webTitle",tmpbuf);
		if(strlen(webTitle)>0 && strcmp(webTitle,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","webTitle",webTitle);
		}

		while((getNthValueSafe(i++, multiLang, ',', lang, sizeof(lang)) != -1))
		{
			sprintf(tmpHelpUrl,"helpUrl_%s",lang);
			char *helpUrl=websGetVar(DATA,tmpHelpUrl,T("-1"));

			memset(tmpbuf,0,sizeof(tmpbuf));
			inifile_get_string(INI_FILE,"PRODUCT",tmpHelpUrl,tmpbuf);
			if(strcmp(helpUrl,"-1") && strcmp(helpUrl,tmpbuf)!=0){
				inifile_set(INI_FILE,"PRODUCT",tmpHelpUrl,helpUrl);
			}
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","Vendor",tmpbuf);
		if(strlen(Vendor)>0 && strcmp(Vendor,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","Vendor",Vendor);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","copyRight",tmpbuf);
		if(strlen(copyRight)>0 && strcmp(copyRight,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","copyRight",copyRight);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","statisticsModel",tmpbuf);
		if(strlen(statistics_softmodel)>0 && strcmp(statistics_softmodel,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","statisticsModel",statistics_softmodel);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","language",tmpbuf);
		if(strlen(language)>0 && strcmp(language,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","language",language);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","multilang",tmpbuf);
		if(strlen(multiLang)>0 && strcmp(multiLang,tmpbuf)!=0){
			sprintf(tmpbuf,"\"%s\"",multiLang);
			inifile_set(INI_FILE,"PRODUCT","multilang",tmpbuf);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","TimeZone",tmpbuf);
		if(strlen(TZ)>0 && strcmp(TZ,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","TimeZone",TZ);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","TelnetKey",tmpbuf);
		if(strlen(telnetkey)>0 && strcmp(telnetkey,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","TelnetKey",telnetkey);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","LoginPassword",tmpbuf);
		if(strlen(LoginPassword)>0 && strcmp(LoginPassword,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","LoginPassword",LoginPassword);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","IpAddress",tmpbuf);
		if(strlen(def_ip)>5 && strcmp(def_ip,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","IpAddress",def_ip);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","DhcpStart",tmpbuf);
		if(strlen(dhcpStart)>5 && strcmp(dhcpStart,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","DhcpStart",dhcpStart);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","DhcpEnd",tmpbuf);
		if(strlen(dhcpEnd)>5 && strcmp(dhcpEnd,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","DhcpEnd",dhcpEnd);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PRODUCT","CloudUpdateDomain",tmpbuf);
		if(strlen(CloudUpdateDomain)>1 && strcmp(CloudUpdateDomain,tmpbuf)!=0){
			inifile_set(INI_FILE,"PRODUCT","CloudUpdateDomain",dhcpEnd);
		}
		
		//[PLUGIN]
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","WanTypeList",tmpbuf);
		if(strlen(WanTypeList)>0 && strcmp(WanTypeList,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","WanTypeList",WanTypeList);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","WanTypeDefault",tmpbuf);
		if(strlen(WanTypeDefault)>0 && strcmp(WanTypeDefault,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","WanTypeDefault",WanTypeDefault);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","PppoeSpecSupport",tmpbuf);
		if(strlen(PppoeSpecSupport)>5 && strcmp(PppoeSpecSupport,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","PppoeSpecSupport",PppoeSpecSupport);
		}
		
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","PppoeSpecRussia",tmpbuf);
		if(strlen(PppoeSpecRussia)>0 && strcmp(PppoeSpecRussia,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","PppoeSpecRussia",PppoeSpecRussia);
		}
		
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","IptvSupport",tmpbuf);
		if(strlen(IptvSupport)>0 && strcmp(IptvSupport,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","IptvSupport",IptvSupport);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","IptvEnable",tmpbuf);
		if(strlen(IptvEnable)>0 && strcmp(IptvEnable,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","IptvEnable",IptvEnable);
		}
		
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","IptvModeDefault",tmpbuf);
		if(strlen(IptvModeDefault)>0 && strcmp(IptvModeDefault,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","IptvModeDefault",IptvModeDefault);
		}
		
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","IptvModeList",tmpbuf);
		if(strlen(IptvModeList)>0 && strcmp(IptvModeList,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","IptvModeList",IptvModeList);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","Ipv6Support",tmpbuf);
		if(strlen(Ipv6Support)>0 && strcmp(Ipv6Support,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","Ipv6Support",Ipv6Support);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","L2tpClientSupport",tmpbuf);
		if(strlen(L2tpClientSupport)>0 && strcmp(L2tpClientSupport,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","L2tpClientSupport",L2tpClientSupport);
		}
		
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","PptpClientSupport",tmpbuf);
		if(strlen(PptpClientSupport)>0 && strcmp(PptpClientSupport,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","PptpClientSupport",PptpClientSupport);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","L2tpServerSupport",tmpbuf);
		if(strlen(L2tpServerSupport)>0 && strcmp(L2tpServerSupport,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","L2tpServerSupport",L2tpServerSupport);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","PptpServerSupport",tmpbuf);
		if(strlen(PptpServerSupport)>0 && strcmp(PptpServerSupport,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","PptpServerSupport",PptpServerSupport);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","DdnsSupport",tmpbuf);
		if(strlen(DdnsSupport)>0 && strcmp(DdnsSupport,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","DdnsSupport",DdnsSupport);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","SsrServerSupport",tmpbuf);
		if(strlen(SsrServerSupport)>0 && strcmp(SsrServerSupport,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","SsrServerSupport",SsrServerSupport);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"PLUGIN","WechatQrSupport",tmpbuf);
		if(strlen(WechatQrSupport)>0 && strcmp(WechatQrSupport,tmpbuf)!=0){
			inifile_set(INI_FILE,"PLUGIN","WechatQrSupport",WechatQrSupport);
		}
		//[WLAN]
		//------------------2G----------------------------
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","Ssid_2G",tmpbuf);
		if(strlen(Ssid_2G)>0 && strcmp(Ssid_2G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","Ssid_2G",Ssid_2G	);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","Ssid_Tail_2G",tmpbuf);
		if(strlen(Ssid_Tail_2G)>0 && strcmp(Ssid_Tail_2G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","Ssid_Tail_2G",Ssid_Tail_2G);
		}
		
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","WlanKey_2G",tmpbuf);
		if(strlen(wlanKey_2G)>7 && strcmp(wlanKey_2G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","WlanKey_2G",wlanKey_2G);
		}else if(strcmp(wlanKey_2G,"")==0){
			inifile_set(INI_FILE,"WLAN","WlanKey_2G","");
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","Channel_2G",tmpbuf);
		if(strlen(Channel_2G)>0 && strcmp(Channel_2G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","Channel_2G",Channel_2G);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","CountryCode_2G",tmpbuf);
		if(strlen(CountryCode_2G)>0 && strcmp(CountryCode_2G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","CountryCode_2G",CountryCode_2G	);
		}
		
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","Txpower_2G",tmpbuf);
		if(strlen(Txpower_2G)>0 && strcmp(Txpower_2G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","Txpower_2G",Txpower_2G	);
		}

		//-------------------------5G---------------------------
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","Ssid_5G",tmpbuf);
		if(strlen(Ssid_5G)>0 && strcmp(Ssid_5G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","Ssid_5G",Ssid_5G);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","Ssid_Tail_5G",tmpbuf);
		if(strlen(Ssid_Tail_5G)>0 && strcmp(Ssid_Tail_5G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","Ssid_Tail_5G",Ssid_Tail_5G);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","WlanKey_5G",tmpbuf);
		if(strlen(wlanKey_5G)>7 && strcmp(wlanKey_5G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","WlanKey_5G",wlanKey_5G);
		}else if(strcmp(wlanKey_5G,"")==0){
			inifile_set(INI_FILE,"WLAN","WlanKey_5G","");
		}
			
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","Channel_5G",tmpbuf);
		if(strlen(Channel_5G)>0 && strcmp(Channel_5G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","Channel_5G",Channel_5G);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","CountryCode_5G",tmpbuf);
		if(strlen(CountryCode_5G)>0 && strcmp(CountryCode_5G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","CountryCode_5G",CountryCode_5G	);
		}
		
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","Txpower_5G",tmpbuf);
		if(strlen(Txpower_5G)>0 && strcmp(Txpower_5G,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","Txpower_5G",Txpower_5G	);
		}
		
		//--------------------wlan common----------------------
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","FixedMac",tmpbuf);
		if(strlen(FixedMac)>0 && strcmp(FixedMac,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","FixedMac",FixedMac);
		}
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","MaxSta",tmpbuf);
		if(strlen(maxsta)>0 && strcmp(maxsta,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","MaxSta",maxsta);
		}

		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","CountryCodeSupport",tmpbuf);
		if(strlen(CountryCodeSupport)>0 && strcmp(CountryCodeSupport,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","CountryCodeSupport",CountryCodeSupport);
		}
		
		memset(tmpbuf,0,sizeof(tmpbuf));
		inifile_get_string(INI_FILE,"WLAN","CountryCodeList",tmpbuf);
		if(strlen(CountryCodeList)>0 && strcmp(CountryCodeList,tmpbuf)!=0){
			inifile_set(INI_FILE,"WLAN","CountryCodeList",CountryCodeList);
		}

		lockUserData();
		
		cJSON_AddStringToObject(root,"Result","Success");
		CsteSystem("convertIniToCfg", CSTE_PRINT_CMD);
		int pid=fork();
		if(0 == pid)
		{
			sleep(1);
			apmib_update_web(CURRENT_SETTING);
			sleep(1);
			run_init_script("all");
			exit(1);
		}
	}
	else if(strcmp(Action,"CreateFlash")==0)
	{
		int telnet_enable=1,mtdNum=4;
		apmib_set(MIB_TELNET_ENABLED,(void *)&telnet_enable);
		apmib_update_web(CURRENT_SETTING);
		
		char FwCalMd5[33]={0};
		mtdNum=getCmdVal("cat /proc/mtd | grep mtd |  wc -l");
		
		CsteSystem("rm -f /tmp/device.flash", CSTE_PRINT_CMD);
		for(i=0;i<mtdNum;i++){
			sprintf(cmd,"cat /dev/mtdblock%d >>  /tmp/device.flash", i);
			CsteSystem(cmd, CSTE_PRINT_CMD);
		}
		CsteSystem("ln -s /tmp/device.flash /web_cste/device.flash 1>/dev/null 2>&1", CSTE_PRINT_CMD);
		Cal_file_md5("/web_cste/device.flash", FwCalMd5);
		if(strlen(FwCalMd5)==32)
		{
			cJSON_AddStringToObject(root,"FileMd5",FwCalMd5);
			cJSON_AddStringToObject(root,"FileUrl","device.flash");
			cJSON_AddStringToObject(root,"Result","Success");
		}
		else
		{
			cJSON_AddStringToObject(root,"Result","Fail");
		}
	}
	else if(strcmp(Action,"CreateCustom")==0)
	{
		char FwCalMd5[33]={0},buff[32],mtdname[32],cmdBuf[128];
		
		rtl_name_to_mtdblock("userdata", mtdname);
		
		sprintf(cmdBuf,"cat %s > /tmp/tmp.bin", mtdname);
		CsteSystem(cmdBuf, CSTE_PRINT_CMD);
		
		Cal_file_md5("/tmp/tmp.bin", FwCalMd5);
		int len = f_size("/tmp/tmp.bin");

		custom_header_t pHeader;
		memset(&pHeader,0,sizeof(pHeader));
		memset(tmpbuf,0,sizeof(tmpbuf));
		memset(buff,0,sizeof(buff));
		inifile_get_string(INI_FILE,"PRODUCT","Csid",tmpbuf);
		sprintf(buff,"USERDATABIN-%s",tmpbuf);
		memcpy(pHeader.ih_name,buff,strlen(buff));
		memcpy(pHeader.ih_md5,FwCalMd5,sizeof(FwCalMd5));
		pHeader.ih_size=len;

		f_write("/web_cste/custom.bin", &pHeader, sizeof(pHeader), FW_CREATE, 0);
		CsteSystem("cat /tmp/tmp.bin >> /web_cste/custom.bin", CSTE_PRINT_CMD);
		CsteSystem("rm -f /tmp/tmp.bin", CSTE_PRINT_CMD);
		Cal_file_md5("/web_cste/custom.bin", FwCalMd5);
		
		if(strlen(FwCalMd5)==32)
		{
			cJSON_AddStringToObject(root,"FileMd5",FwCalMd5);
			cJSON_AddStringToObject(root,"FileUrl","custom.bin");
			cJSON_AddStringToObject(root,"Result","Success");
		}
		else
		{
			cJSON_AddStringToObject(root,"Result","Fail");
		}
	}
	else if(strcmp(Action,"ClearCustomInfo")==0)
	{
		unlockUserData();
		CsteSystem("rm -rf /mnt/custom", CSTE_PRINT_CMD);
		int pid=fork();
		if(0 == pid)
		{
			sleep(1);
			CsteSystem("cs reset;reboot", CSTE_PRINT_CMD);
		}
		cJSON_AddStringToObject(root,"Result","Success");
	}

	QuickSettingRsp(mosq, tp, root);
	unlock_file(cste_lock);
	return 0;
}

int module_init()
{
	if(0 == f_exist("/mnt/custom/product.ini"))
	{
		unlockUserData();
		CsteSystem("mkdir -p /mnt/custom/", CSTE_PRINT_CMD);
		CsteSystem("cp -f /web_cste/cgi-bin/product.ini /mnt/custom/product.ini", CSTE_PRINT_CMD);
		lockUserData();
	}
	cste_hook_register("QuickCustom",QuickCustom);
	
	return 0;
}
