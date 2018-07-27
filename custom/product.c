
#include "product.h"

#define INIFILE       "/mnt/custom/product.ini"
#define WEBDIR       "/mnt/custom/web"
#define STYLEDIR     "/mnt/custom/web/style"
#define JSDIR        "/mnt/custom/web/js"
#define ADMDIR       "/mnt/custom/web/adm"
#define INTERNETDIR  "/mnt/custom/web/internet"
#define WLANDIR      "/mnt/custom/web/wirless"
#define CUR_WEB_DIR  "/web_cste"

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

void UploadCustomModuleRsp(struct mosquitto *mosq, char *tp, cJSON *root)
{
	char* output;
	
	char topic[256]={0},tmpBuf[32];
	int mid_sent = 0;

	output =cJSON_Print(root);
	sprintf(topic,"%s/R", tp);
	mosquitto_publish(mosq, &mid_sent, topic, strlen(output), output, 0, 0);
	cJSON_Delete(root);
	free(output);
}

int UploadCustomModule(struct mosquitto *mosq, cJSON* data, char *tp)
{
	char base64_src[204800]={0},file_centent[204800]={0};

	size_t bytes;
	cJSON *DATA=NULL,*root;
	
	root=cJSON_CreateObject();
	char *Action=websGetVar(data,T("Action"),T(""));
	DATA = cJSON_GetObjectItem(data,"data");
	
	if(strcmp(Action,"GetCustomModule")==0){
		char *MD5=websGetVar(DATA,T("FileMd5"),T(""));
		char *fileUrl=websGetVar(DATA,T("FileUrl"),T(""));
		char *file=websGetVar(DATA,T("File"),T(""));
		
		sprintf(base64_src,"%s",file);
		bytes=base64_decode(base64_src,file_centent,sizeof(file_centent));

		CsteSystem("mkdir -p /tmp/custom_module", CSTE_PRINT_CMD);
		
		FILE *fp=fopen("/tmp/custom_module/custom.so","wb");
		fwrite(file_centent,bytes,1,fp);
		memset(file_centent,0,sizeof(file_centent));
		memset(base64_src,0,sizeof(base64_src));
		fclose(fp);
		
		char CalfileMd5[33]={0};
		int ret=Cal_file_md5("/tmp/custom_module/custom.so",CalfileMd5);
		
		if(strcmp(MD5,CalfileMd5)==0 ){
			if(strstr(fileUrl,"custom.so")!=NULL){
				cJSON_AddStringToObject(root,"Result","Success");
				system("csteSys csteRestart &");
			}else{
				CsteSystem("rm -f /tmp/custom_module/*.so", CSTE_PRINT_CMD);
				cJSON_AddStringToObject(root,"Result","Fail");
			}
		}
		else
		{
			CsteSystem("rm -f /tmp/custom_module/*.so", CSTE_PRINT_CMD);
			cJSON_AddStringToObject(root,"Result","Fail");
		}
	}else{
		cJSON_AddStringToObject(root,"Result","Fail");
	}
	UploadCustomModuleRsp(mosq, tp, root);

	return 0;
}

int module_init()
{
	cste_hook_register("UploadCustomModule",UploadCustomModule);

	char buff[128]={0};
	if( 0 != d_exist(WEBDIR))
	{
		sprintf(buff, "cp -f %s/*.html  /web_cste/ 2> /dev/null",WEBDIR);
		CsteSystem(buff, CSTE_PRINT_CMD);
		sprintf(buff, "cp -f %s/style/*  /web_cste/style/ 2> /dev/null",WEBDIR);
		CsteSystem(buff, CSTE_PRINT_CMD);
		sprintf(buff, "cp -f %s/js/* /web_cste/js/ 2> /dev/null",WEBDIR);
		CsteSystem(buff, CSTE_PRINT_CMD);
		sprintf(buff, "cp -f %s/adm/* /web_cste/adm 1>/dev/null 2>&1",WEBDIR);
		CsteSystem(buff, CSTE_PRINT_CMD);
		sprintf(buff, "cp -f %s/internet/* /web_cste/internet 1>/dev/null 2>&1",WEBDIR);
		CsteSystem(buff, CSTE_PRINT_CMD);
	}

	return 0;  
}


