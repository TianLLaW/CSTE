
ifeq ($(wildcard ../boa/wfaudio.include.mk),)
echo ""
else
include ../boa/wfaudio.include.mk
endif

ifeq ($(wildcard $(DIR_LINUX)/.config),)
include ../../linux-3.10/.config
else
include $(DIR_LINUX)/.config
endif

ifeq ($(wildcard $(DIR_USERS)/.config),)
include ../.config
else
include $(DIR_USERS)/.config
endif


ifdef CONFIG_RTL_8198_AP_ROOT
CONFIG_RTL_AP = CONFIG_RTL_8198_AP_ROOT
endif

ifdef CONFIG_RTL_8197D_AP
CONFIG_RTL_AP = CONFIG_RTL_8197D_AP
endif

ifdef CONFIG_RTL_AP_PACKAGE 
CONFIG_RTL_AP = CONFIG_RTL_AP_PACKAGE
endif

ifdef CONFIG_RTL_AP
AP=1
SKUTAG=ap
else
GW=1
SKUTAG=gw
endif

APMIB_SHARED = 1
APMIB_DIR=../boa/apmib

#------------------------------------------------------------------------------
.SUFFIXES:
.SUFFIXES: .o .c
.PHONY: clean all

ifeq ($(CONFIG_KL_C818ER_04325), y)
CFLAGS += -DCONFIG_KL_C818ER_04325
endif
LDFLAGS =  -g
CFLAGS = -Os -pipe
#------------------------------------------------------------------------------



#------------------------------------------------------------------------------
# CFLAGS
#------------------------------------------------------------------------------
CFLAGS += $(SYS_COMMON_CFLAGS)

ifeq ($(CONFIG_RTL_MESH_CROSSBAND),y)
CFLAGS += -DCONFIG_RTL_MESH_CROSSBAND
endif

ifeq ($(CONFIG_RTL_MESH_SUPPORT),y)
CFLAGS += -DCONFIG_RTK_MESH
CFLAGS += -DSUPPORT_MESH
endif

ifeq ($(CONFIG_APP_NOTICE),y)
CFLAGS += -DCONFIG_SUPPORT_NOTICE
endif

ifeq ($(CONFIG_APP_YDDNS), y)
CFLAGS += -DCONFIG_APP_YDDNS
endif

ifeq ($(CONFIG_SUPPORT_SCHEDULE_REBOOT), y)
CFLAGS += -DCONFIG_SUPPORT_SCHEDULE_REBOOT
endif

ifeq ($(CONFIG_APP_DNS_URLFILTER), y)
CFLAGS += -DCONFIG_APP_DNS_URLFILTER
endif
ifeq ($(CONFIG_APP_CLOUDSRVUP), y)
CFLAGS += -DCONFIG_APP_CLOUDSRVUP
endif

ifeq ($(CONFIG_APP_AVAHI),y)
CFLAGS += -DCONFIG_AVAHI
endif

ifeq ($(CONFIG_APP_APPLE_MFI_WAC),y)
CFLAGS += -DCONFIG_APP_APPLE_MFI_WAC
endif

ifeq ($(CONFIG_APP_APPLE_HOMEKIT),y)
CFLAGS += -DCONFIG_APPLE_HOMEKIT
endif

ifeq ($(CONFIG_APP_RTK_BLUETOOTH_FM),y)
CFLAGS += -DCONFIG_APP_RTK_BLUETOOTH_FM
endif

ifdef CONFIG_APP_MULTIPPPOE
	CFLAGS += -D MULTI_PPPOE
endif

ifeq ($(CONFIG_WLAN),y)
	CFLAGS += -D SUPPORT_WLAN
endif

ifeq ($(CONFIG_RTL_WDS_SUPPORT),y)
	CFLAGS += -D SUPPORT_WDS
endif

ifeq ($(CONFIG_RTL_WPS2_SUPPORT),y)
	CFLAGS += -D SUPPORT_WPS
endif

ifeq ($(CONFIG_RTL_VAP_SUPPORT),y)
	CFLAGS += -D SUPPORT_MBSS
endif

ifeq ($(CONFIG_SLOT_0_8822BE),y)
	CFLAGS += -D SUPPORT_WLAN5G -D FOR_DUAL_BAND
ifeq ($(CONFIG_RTL_WDS_SUPPORT),y)
	CFLAGS += -D SUPPORT_WDS5G
endif

ifeq ($(CONFIG_RTL_WPS2_SUPPORT),y)
	CFLAGS += -D SUPPORT_WPS5G
endif

ifeq ($(CONFIG_RTL_VAP_SUPPORT),y)
	CFLAGS += -D SUPPORT_MBSS5G
endif
endif



CFLAGS += -DHAVE_STDBOOL_H

CFLAGS += -I. -I../lib/lib -I$(APMIB_DIR) -I../libcjson  -I../mosquitto-1.4.8/lib
CFLAGS += -I../libmystdlib

ifeq ($(CONFIG_APP_MANAGEMENTAC), y)
CFLAGS += -I../libsqlite3 -I../libcste-sql
endif

ifeq ($(CONFIG_APP_LIBINIPARSE), y)
CFLAGS += -I../libiniparse
endif

ifeq ($(CONFIG_RTL_ISP_MULTI_WAN_SUPPORT), y)
CFLAGS += -DCONFIG_RTL_ISP_MULTI_WAN_SUPPORT
endif

ifeq ($(CONFIG_APP_MANAGEMENTAC), y)
CFLAGS += -DSUPPORT_MANAGEMENTAC
endif

ifeq ($(CONFIG_APP_STATISTICS), y)
CFLAGS += -DSUPPORT_STATISTICS
endif

ifeq ($(CONFIG_APP_BWCONTRL),y)
CFLAGS += -DSUPPORT_BWCONTRL
endif

ifeq ($(CONFIG_APP_BMCONTRL),y)
CFLAGS += -DSUPPORT_BMCONTRL
endif

ifeq ($(CONFIG_PA_ONLINE_IP),y)
CFLAGS += -DCONFIG_PA_ONLINE_IP
endif

ifeq ($(CONFIG_CS_MESH_SYNC), y)
CFLAGS += -DCS_MESH_SYNC
endif

ifeq ($(CONFIG_SUPPORT_UPATE_WITHCONFIG),y)
CFLAGS += -DSUPPORT_UPATE_WITHCONFIG
endif

ifeq ($(CONFIG_APP_CSTE_DEBUG),y)
CFLAGS += -DCONFIG_APP_CSTE_DEBUG
endif

ifeq ($(CONFIG_APP_DIAGNOSTIC),y)
CFLAGS += -D SUPPORT_DIAGNOSTIC
endif

ifeq ($(CONFIG_APP_CUSTOMIZATION),y)
CFLAGS += -D SUPPORT_CUSTOMIZATION
endif

ifeq ($(CONFIG_APP_UPGRADE_PROTECTED),y)
CFLAGS += -D SUPPORT_UPGRADE_PROTECTED
endif

ifeq ($(CONFIG_APP_NETX),y)
CFLAGS += -D SUPPORT_NETX
endif

ifeq ($(CONFIG_APP_PPTP_CLIENT),y)
CFLAGS += -D SUPPORT_PPTP_CLIENT
endif

ifeq ($(CONFIG_APP_L2TP_CLIENT),y)
CFLAGS += -D SUPPORT_L2TP_CLIENT
endif

ifeq ($(CONFIG_APP_WECHATQR),y)
CFLAGS += -D SUPPORT_WECHATQR
endif


#------------------------------------------------------------------------------
# LDFLAGS
#------------------------------------------------------------------------------
LIBLDFLAGS= -lpthread -ldl -L$(APMIB_DIR) -lapmib -L../libcjson -lcjson -L../mosquitto-1.4.8/lib -lmosquitto
LDFLAGS += $(LIBLDFLAGS)
LDFLAGS += -L./ -lcstelib
LDFLAGS += -L../libmystdlib -lmystdlib -L../lib/lib -lmtdapi


ifeq ($(CONFIG_APP_MANAGEMENTAC), y)
LDFLAGS += -L../libsqlite3/.libs -lsqlite3 -L../libcste-sql -lcste_sql
endif

ifeq ($(CONFIG_APP_LIBINIPARSE), y)
LDFLAGS += -L../libiniparse -liniparse
endif


#------------------------------------------------------------------------------
# targets
#------------------------------------------------------------------------------
TARGET = libcstelib.so


TARGET += cste updateUI cs cs_pub tcpcheck initcste
TARGET += sche_reboot
TARGET += forceupg

ifeq ($(CONFIG_APP_STATISTICS), y)
TARGET += cs_statistics
endif

ifeq ($(CONFIG_APP_CLOUDSRVUP), y)
TARGET += cloudupdate.so cs_cloudfwcheck
endif

TARGET += global.so upgrade.so lan.so wan.so system.so ipv6.so

ifeq ($(CONFIG_APP_MANAGEMENTAC), y)
TARGET += managementAc.so
endif

ifeq ($(CONFIG_APP_WLAN), y)
TARGET += wireless.so
endif

ifeq ($(CONFIG_APP_WPS), y)
TARGET += wps.so
endif

ifeq ($(CONFIG_APP_FIREWALL), y)
TARGET += firewall.so
endif

ifeq ($(CONFIG_APP_CUSTOMIZATION),y)
TARGET += custom.so product.so convertIniToCfg
endif

ifeq ($(CONFIG_APP_NETX),y)
TARGET += vpn.so
endif

#------------------------------------------------------------------------------
# compile
#------------------------------------------------------------------------------

all: $(TARGET)


libcstelib.so: cstelib.c
	$(CC)  $(CFLAGS) -c -fpic cstelib.c -o cstelib.o
	$(CC) -shared -lc -o  libcstelib.so cstelib.o $(LIBLDFLAGS)

cste : cste.o
	$(CC) $^ -o $@ $(LDFLAGS) -Wl,--export-dynamic -lrt
	$(STRIP) $@

initcste:initcste.o
	$(CC) $^ -o $@ $(LDFLAGS) -Wl,--export-dynamic -lrt
	$(STRIP) $@

sche_reboot:sche_reboot.o
	$(CC) $^ -o $@ $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@
sche_reboot.o: sche_reboot.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)
	
updateUI: updateUI.o
	$(CC)  updateUI.o -o updateUI $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@

cs : cs.o
	$(CC) $^ -o $@ $(LDFLAGS) -Wl,--export-dynamic -lrt
	$(STRIP) $@

cs_pub : cs_pub.o
	$(CC) $^ -o $@ $(LDFLAGS) -Wl,--export-dynamic -lrt
	$(STRIP) $@

tcpcheck : tcpcheck.o
	$(CC) $^ -o $@ $(LDFLAGS) -Wl,--export-dynamic -lrt
	$(STRIP) $@

global.so : global/global.c global/global.h
	$(CC) $(CFLAGS) -c -fpic global/global.c -o global.o
	$(CC) -shared -lc -o  global.so global.o $(LDFLAGS)

upgrade.so : upgrade/upgrade.c upgrade/upgrade.h
	$(CC) $(CFLAGS) -c -fpic upgrade/upgrade.c -o upgrade.o
	$(CC) -shared -lc -o  upgrade.so upgrade.o $(LDFLAGS)

lan.so : network/lan.c network/lan.h
	$(CC) $(CFLAGS) -c -fpic network/lan.c -o lan.o
	$(CC) -shared -lc -o  lan.so lan.o $(LDFLAGS)

wan.so : network/wan.c network/wan.h
	$(CC) $(CFLAGS) -c -fpic network/wan.c -o wan.o
	$(CC) -shared -lc -o  wan.so wan.o $(LDFLAGS)

vlan.so : network/vlan.c network/vlan.h
	$(CC) $(CFLAGS) -c -fpic network/vlan.c -o vlan.o
	$(CC) -shared -lc -o  vlan.so vlan.o $(LDFLAGS)

vpn.so : network/vpn.c
	$(CC) $(CFLAGS) -c -fpic network/vpn.c -o vpn.o
	$(CC) -shared -lc -o  vpn.so vpn.o $(LDFLAGS)

wireless.so : wireless/wireless.c wireless/wireless.h
	$(CC) $(CFLAGS) -c -fpic wireless/wireless.c -o wireless.o
	$(CC) -shared -lc -o  wireless.so wireless.o $(LDFLAGS)
	
wps.so : wireless/wps.c wireless/wps.h
	$(CC) $(CFLAGS) -c -fpic wireless/wps.c -o wps.o
	$(CC) -shared -lc -o  wps.so wps.o $(LDFLAGS)
	
system.so : system/system.c system/system.h
	$(CC) $(CFLAGS) -c -fpic system/system.c -o system.o
	$(CC) -shared -lc -o  system.so system.o $(LDFLAGS)

ipv6.so : system/ipv6.c system/ipv6.h
	$(CC) $(CFLAGS) -c -fpic system/ipv6.c -o ipv6.o
	$(CC) -shared -lc -o  ipv6.so ipv6.o $(LDFLAGS)

firewall.so : firewall/firewall.c firewall/firewall.h
	$(CC) $(CFLAGS) -c -fpic firewall/firewall.c -o firewall.o
	$(CC) -shared -lc -o  firewall.so firewall.o $(LDFLAGS)

ifeq ($(CONFIG_APP_CLOUDSRVUP), y)
cloudupdate.so: cloud/cloudupdate.c cloud/cloudupdate.h
	$(CC) $(CFLAGS) -c -fpic cloud/cloudupdate.c -o cloudupdate.o
	$(CC) -shared -lc -o  cloudupdate.so cloudupdate.o $(LDFLAGS)

cs_cloudfwcheck: cs_cloudfwcheck.o
	$(CC) cs_cloudfwcheck.o  -o cs_cloudfwcheck $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@

cs_cloudfwcheck.o: cloud/cloudfwcheck.c
	$(CC) $(CFLAGS) -c cloud/cloudfwcheck.c -o cs_cloudfwcheck.o
endif

cstecwmp.so: startcwmp/cstecwmp.c startcwmp/cstecwmp.h
	$(CC)  $(CFLAGS) -c -fpic startcwmp/cstecwmp.c -o cstecwmp.o	
	$(CC) -shared -lc -o  cstecwmp.so cstecwmp.o $(LDFLAGS)

usb.so: usb/usb.c usb/usb.h
	$(CC)  $(CFLAGS) -c -fpic usb/usb.c -o usb.o
	$(CC) -shared -lc -o  usb.so usb.o $(LDFLAGS)

onekey_conn:onekey_conn.o cstelib.o
	$(CC) $^ -o $@ $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@
onekey_conn.o: onekey_conn.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)
#--------------------------------------------------------------------

rarp_server:rarp_server.o 
	$(CC) $^ -o $@ $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@
rarp_server.o: rarp_server.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

rarp_request:rarp_request.o 
	$(CC) $^ -o $@ $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@
rarp_request.o: rarp_request.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)
#--------------------------------------------------------------------

cs_statistics : cs_statistics.o
	$(CC) cs_statistics.o  -o cs_statistics $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@

cs_statistics.o: statistics/statistics.c statistics/statistics.h
	$(CC) $(CFLAGS) -c statistics/statistics.c -o cs_statistics.o
#--------------------------------------------------------------------
cs_thinap : manageAgent.o gatewayAc.o jobqueen.o msghandler.o remoteAc.o localAc.o  
	$(CC) manageAgent.o jobqueen.o  gatewayAc.o msghandler.o remoteAc.o localAc.o -o cs_thinap $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@

gatewayAc.o : cste_thinap/gatewayAc.c cste_thinap/manageAgent.h
	$(CC) $(CFLAGS) -c cste_thinap/gatewayAc.c  -o gatewayAc.o
	
jobqueen.o : cste_thinap/jobqueen.c cste_thinap/jobqueen.h
	$(CC) $(CFLAGS) -c cste_thinap/jobqueen.c -o jobqueen.o

msghandler.o : cste_thinap/msghandler.c cste_thinap/manageAgent.h
	$(CC) $(CFLAGS) -c cste_thinap/msghandler.c  -o msghandler.o
	
manageAgent.o : cste_thinap/manageAgent.c cste_thinap/manageAgent.h
	$(CC) $(CFLAGS) -c cste_thinap/manageAgent.c -o manageAgent.o

remoteAc.o : cste_thinap/remoteAc.c cste_thinap/manageAgent.h
	$(CC) $(CFLAGS) -c cste_thinap/remoteAc.c -o remoteAc.o

localAc.o : cste_thinap/localAc.c cste_thinap/manageAgent.h
	$(CC) $(CFLAGS) -c cste_thinap/localAc.c -o localAc.o
#--------------------------------------------------------------------

ap.so: ac/ap.c ac/ap.h
	$(CC)  $(CFLAGS) -c -fpic ac/ap.c -o ap.o
	$(CC) -shared -lc -o  ap.so ap.o $(LDFLAGS)

hapc : hapc.o hapc.o
	$(CC) hapc.o  -o hapc $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@

hapc.o: hapc.c
	$(CC) $(CFLAGS) -c hapc.c -o hapc.o

#--------------------------------------------------------------------		

forceupg:forceupg.o
	$(CC) $^ -o $@ $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@
forceupg.o: forceupg.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS) 

#--------------------------------------------------------------------
cs_cloudap : cloudac.o cloudac.o
	$(CC) cloudac.o  -o cs_cloudap $(LDFLAGS) -Wl,--export-dynamic

cloudac.o: cloudac/cloudac.c cloudac/cloudac.h
	$(CC) $(CFLAGS) -c cloudac/cloudac.c -o cloudac.o

#--------------------------------------------------------------------

product.so : custom/product.c custom/product.h
	$(CC) $(CFLAGS) -c -fpic custom/product.c -o product.o
	$(CC) -shared -lc -o  product.so product.o $(LDFLAGS)

custom.so : custom/custom.c custom/custom.h
	$(CC) $(CFLAGS) -c -fpic custom/custom.c -o custom.o
	$(CC) -shared -lc -o  custom.so custom.o $(LDFLAGS)

convertIniToCfg : convertIniToCfg.o
	$(CC) convertIniToCfg.o  -o convertIniToCfg $(LDFLAGS) -Wl,--export-dynamic
	$(STRIP) $@

convertIniToCfg.o: custom/convertIniToCfg.c
	$(CC) $(CFLAGS) -c custom/convertIniToCfg.c -o convertIniToCfg.o

#--------------------------------------------------------------------

managementAc.so: managementAc/managementAc.c managementAc/managementAc.h
	$(CC)  $(CFLAGS) -c -fpic managementAc/managementAc.c -o managementAc.o
	$(CC) -shared -lc -o  managementAc.so managementAc.o  $(LDFLAGS)

#--------------------------------------------------------------------

romfs:
	mkdir -p $(DIR_ROMFS)/lib/cste_modules
	
	$(ROMFSINST) libcstelib.so /lib/libcstelib.so
	$(ROMFSINST) global.so  /lib/cste_modules/global.so
	$(ROMFSINST) upgrade.so /lib/cste_modules/upgrade.so
	$(ROMFSINST) system.so  /lib/cste_modules/system.so
	$(ROMFSINST) ipv6.so /lib/cste_modules/ipv6.so
	$(ROMFSINST) lan.so /lib/cste_modules/lan.so
	$(ROMFSINST) wan.so /lib/cste_modules/wan.so
	$(ROMFSINST) -e CONFIG_APP_NETX vpn.so /lib/cste_modules/vpn.so

	$(ROMFSINST) -e CONFIG_APP_WLAN wireless.so /lib/cste_modules/wireless.so
	$(ROMFSINST) -e CONFIG_APP_WPS  wps.so /lib/cste_modules/wps.so
	$(ROMFSINST) -e CONFIG_APP_FIREWALL firewall.so /lib/cste_modules/firewall.so
	$(ROMFSINST) -e CONFIG_APP_MANAGEMENTAC managementAc.so /lib/cste_modules/managementAc.so
	$(ROMFSINST) -e CONFIG_APP_CLOUDSRVUP cloudupdate.so /lib/cste_modules
	$(ROMFSINST) -e CONFIG_APP_CLOUDSRVUP cs_cloudfwcheck /bin/cs_cloudfwcheck
	$(ROMFSINST) -e CONFIG_APP_CUSTOMIZATION product.so /lib/cste_modules
	$(ROMFSINST) -e CONFIG_APP_CUSTOMIZATION convertIniToCfg /bin/convertIniToCfg
	$(ROMFSINST) cste /bin/cste_sub
	$(ROMFSINST) initcste /bin/initcste
	$(ROMFSINST) updateUI /bin/updateUI
	$(ROMFSINST) cs /bin/cs
	$(ROMFSINST) cs_pub /bin/cs_pub
	$(ROMFSINST) tcpcheck /bin/tcpcheck
	$(ROMFSINST) -e CONFIG_APP_STATISTICS cs_statistics /bin/cs_statistics
	$(ROMFSINST) sche_reboot /bin/sche_reboot
	$(ROMFSINST) forceupg /bin/forceupg

	
	
#--------------------------------------------------------------------

clean:
	rm -f *.o $(TARGET)
