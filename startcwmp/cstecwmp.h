#include "../cstelib.h"
#include "mosquitto.h"
#include "cJSON.h"
#include "apmib.h"

#define SERIAL_NUMBER "CZ1604000000"  
//?MIB ?( HW_PRODUCT_SN ),?????

#define LOCAL_interface 	"eth1"
#define LOCAL_logging_level "3"//DEFAULT_LOGGING_LEVEL
#define DM_FILE "/var/datamodel.xml"
#define UNVAULED_JSONS_FILE "/var/unvalued_jsons"
#define EASYCWMP_TRACE "/tmp/easycwmp_trace"

//单频
#define RADIO_NUM			1		
#define SSID_NUM			3	
#define ACCESS_POINT_NUM	3
#define INTERFACE_NB		2
#define IP_INTER_EN			"TRUE"
#define IP_INTERFACE_NUMBER 2	//LAN WAN
#define WAN_INDEX   		11
#define LAN_INDEX			1
#define IPADDR_V4_NUMBER	1
#define IPV4_ADDR_EN		"TRUE"

//制定动态数据的数目
#define NUM_WiFiDiagnostic			"10"
#define NUM_NAT						"10"
#define NUM_DHCPv4_StaticAddress		"10"
#define NUM_DHCPv4_Client			"10" 
#define NUM_Hosts					10
#define NUM_WiFi_Radio				"4"
#define NUM_WiFi_AccessPoint1		"10"
#define NUM_WiFi_AccessPoint2		"10"
#define NUM_WiFi_AccessPoint3		"10"
#define NUM_IP						"30"
#define NUM_FIREWARLL1				"10"
#define NUM_FIREWARLL2				"10"
#define NUM_FIREWARLL3				"10"
#define NUM_WiFi_Schedule			"10"

//Public	
#define NAME						"Name"

#define DINFO_HD					"Device.DeviceInfo."
#define MANAG_HD					"Device.ManagementServer."
#define TIME_HD						"Device.Time."
#define USER_HD						"Device.UserInterface."

//Ethernet
#define ETHERNET_HD1				"Device.Ethernet.X_HUMAX_IndexRules."
#define ETHERNET_HD2				"Device.Ethernet.Interface.11."
#define ETHERNET_HD3				"Device.Ethernet.Interface.11.Stats."
#define ETHERNET_HD4				"Device.Ethernet.Interface.1."
#define ETHERNET_HD5				"Device.Ethernet.Interface.1.Stats."

//Usb
#define USB_HD1 					"Device.USB.USBHosts.Host.1."
#define USB_HD2						"Device.USB.USBHosts.Host.1.Device.1."

//DynamicDNS
#define DYDNS_HD1					"Device.DynamicDNS."
#define DYDNS_HD2					"Device.DynamicDNS.Client.1."
#define DYDNS_HD3					"Device.DynamicDNS.Server."

//DHCPv4
#define DHCP_HD1					"Device.DHCPv4.Client.1."
#define DHCP_HD2					"Device.DHCPv4.Server.Pool.1."

//DECPv6
#define DHCPV6_HD1					"Device.DHCPv6.Server."

//Users
#define USERS_HD					"Device.Users.User.1."

//UPnP
#define UPNP_HD						"Device.UPnP.Device."

//Firewall
#define FW_HD 						"Device.Firewall.X_HUMAX_"
#define FW_HD2						"Device.Firewall.Chain."

//NAT
#define NAT_HD1						"Device.NAT."

//DNS
#define DNS_HD1						"Device.DNS.Client."
#define DNS_HD2						"Device.DNS.Client.Server.1."
#define DNS_HD3						"Device.DNS.Client.Server.2."

//Hosts

//PPP
#define PPP_HD 						"Device.PPP.Interface.1."

//WiFi
#define WIFI_HD1					"Device.WiFi."
#define WIFI_HD2					"Device.WiFi.Radio.1."
#define WIFI_HD3					"Device.WiFi.Radio.1.X_HUMAX_WDS."

//WIFI SCAN
#define SCAN_HD1					"Device.WiFi.NeighboringWiFiDiagnostic."
#define SSID_HD1					"Device.WiFi.SSID."
#define	ACESS_HD1					"Device.WiFi.AccessPoint."

//IP
#define IP_HD1						"Device.IP."
#define IP_HD2						"Device.IP.Interface.1."
#define IP_HD3						"Device.IP.Interface.11."
#define IP_HD4						"Device.IP.Interface."
#define IPPING_HD 					"Device.IP.Diagnostics.IPPing."
#define IPTRACE_HD 					"Device.IP.Diagnostics.TraceRoute."


//CurrentNetwork
#define CURR_HD1					"Device.X_HUMAX_CurrentNetwork."

//X_HUMAX_RebootSchedule
#define REBOOT_HD1					"Device.X_HUMAX_RebootSchedule."

//X_HUMAX_WiFiSchedule
#define WIFISCH_HD1					"Device.X_HUMAX_WirelessSchedule."


/*
注: 请严格按照已有格式添加相应空值项
各参数的值必须是一个空格!
*/
#define UN_WiFiDiagnostic \
"	\"Device.WiFi.NeighboringWiFiDiagnostic.Result\":	  { " \
"				  \"Radio\":\" \", " \
"				  \"SSID\":\" \", " \
"				  \"BSSID\":\" \", " \
"				  \"Mode\":\" \", " \
"				  \"Channel\":\" \", " \
"				  \"SignalStrength\":\" \", " \
"				  \"SecurityModeEnabled\":\" \", " \
"				  \"EncryptionMode\":\" \", " \
"                 \"OperatingFrequencyBand\":\" \", " \
"				  \"OperatingStandards\":\" \", " \
"				  \"OperatingChannelBandwidth\":\" \" " \
"			  } " 

#define UN_NAT \
"	\"Device.NAT.PortMapping\":   { " \
"				  \"Enable\":\" \", " \
"				  \"Status\":\" \", " \
"				  \"ExternalPort\":\" \", " \
"				  \"ExternalPortEndRange\":\" \", " \
"				  \"InternalPort\":\" \", " \
"				  \"Protocol\":\" \", " \
"				  \"InternalClient\":\" \", " \
"				  \"Description\":\" \", " \
"			 } "

#define UN_DHCPv4_StaticAddress \
"	\"Device.DHCPv4.Server.Pool.1.StaticAddress\":	  { " \
"				  \"Enable\":\" \", " \
"				  \"Chaddr\":\" \", " \
"				  \"Yiaddr\":\" \", " \
"			  } "

#define UN_DHCPv4_Client \
"	\"Device.DHCPv4.Server.Pool.1.Client\":	  { " \
"				  \"Chaddr\":\" \", " \
"				  \"IPv4AddressNumberOfEntries\":\" \", " \
"				  \"IPv4Address.1.IPAddress\":\" \", " \
"				  \"IPv4Address.1.LeaseTimeRemaining\":\" \", " \
"			  } "

#define UN_Hosts \
"	\"Device.Hosts.Host\":	 { " \
"				  \"PhysAddress\":\" \", " \
"				  \"IPAddress\":\" \", " \
"				  \"AddressSource\":\" \", " \
"				  \"Layer1Interface\":\" \", " \
"				  \"HostName\":\" \", " \
"				  \"Active\":\" \", " \
"				  \"ActiveLastChange\":\" \", " \
"				  \"IPv4AddressNumberOfEntries\":\" \", " \
"				  \"IPv6AddressNumberOfEntries\":\" \", " \
"				  \"IPv4Address.1.IPAddress\":\" \", " \
"			  } "

#if 0
#define UN_WiFi_Radio \
"	\"Device.WiFi.Radio.1.X_HUMAX_WDS.SlaveAP\":	  { " \
"				  \"Description\":\" \", " \
"				  \"MACAddress\":\" \", " \
"			  } "
#endif

#define UN_WiFi_AccessPoint1 \
"	\"Device.WiFi.AccessPoint.1.AssociatedDevice\":   { " \
"				  \"MACAddress\":\" \", " \
"				  \"OperatingStandard\":\" \", " \
"				  \"SignalStrength\":\" \", " \
"			  } "

#define UN_WiFi_AccessPoint2 \
"	\"Device.WiFi.AccessPoint.2.AssociatedDevice\":   { " \
"				  \"MACAddress\":\" \", " \
"				  \"OperatingStandard\":\" \", " \
"				  \"SignalStrength\":\" \", " \
"			  } "

#define UN_WiFi_AccessPoint3 \
"	\"Device.WiFi.AccessPoint.3.AssociatedDevice\":   { " \
"				  \"MACAddress\":\" \", " \
"				  \"OperatingStandard\":\" \", " \
"				  \"SignalStrength\":\" \", " \
"			  } "

#define UN_IP \
"	\"Device.IP.Diagnostics.TraceRoute.RouteHops\":   { " \
"				  \"Host\":\" \", " \
"				  \"HostAddress\":\" \", " \
"				  \"ErrorCode\":\" \", " \
"				  \"RTTimes\":\" \", " \
"			} "

#define UN_FIREWARLL1 \
"	\"Device.Firewall.Chain.1.Rule\":	{ " \
"				  \"Enable\":\" \", " \
"				  \"Description\":\" \", " \
"				  \"CreationDate\":\" \", " \
"				  \"ExpiryDate\":\" \", " \
"				  \"DestIP\":\" \", " \
"				  \"SourceIP\":\" \", " \
"				  \"Protocol\":\" \", " \
"				  \"DestPort\":\" \", " \
"				  \"DestPortRangeMax\":\" \", " \
"				  \"X_HUMAX_SourceMACAddress\":\" \", " \
"				  \"X_HUMAX_URL\":\" \" " \
"			} " \

#define UN_FIREWARLL2 \
"	\"Device.Firewall.Chain.2.Rule\":	{ " \
"				  \"Enable\":\" \", " \
"				  \"Description\":\" \", " \
"				  \"CreationDate\":\" \", " \
"				  \"ExpiryDate\":\" \", " \
"				  \"DestIP\":\" \", " \
"				  \"SourceIP\":\" \", " \
"				  \"Protocol\":\" \", " \
"				  \"DestPort\":\" \", " \
"				  \"DestPortRangeMax\":\" \", " \
"				  \"X_HUMAX_SourceMACAddress\":\" \", " \
"				  \"X_HUMAX_URL\":\" \" " \
"			} " \

#define UN_FIREWARLL3 \
"	\"Device.Firewall.Chain.3.Rule\":	{ " \
"				  \"Enable\":\" \", " \
"				  \"Description\":\" \", " \
"				  \"CreationDate\":\" \", " \
"				  \"ExpiryDate\":\" \", " \
"				  \"DestIP\":\" \", " \
"				  \"SourceIP\":\" \", " \
"				  \"Protocol\":\" \", " \
"				  \"DestPort\":\" \", " \
"				  \"DestPortRangeMax\":\" \", " \
"				  \"X_HUMAX_SourceMACAddress\":\" \", " \
"				  \"X_HUMAX_URL\":\" \" " \
"			} " \

#define UN_WirelessSchedule \
"	\"Device.X_HUMAX_WirelessSchedule.Rule\":	{ " \
"				  \"Enable\":\" \", " \
"				  \"DayOfWeek\":\" \", " \
"				  \"StartTime\":\" \", " \
"				  \"Duration\":\" \" " \
"			} " \

#define UNVALUED_JSONS \
"{ " \
	UN_WiFiDiagnostic "," \
	UN_NAT "," \
	UN_DHCPv4_StaticAddress "," \
	UN_DHCPv4_Client "," \
	UN_Hosts "," \
	UN_WiFi_AccessPoint1 "," \
	UN_WiFi_AccessPoint2 "," \
	UN_WiFi_AccessPoint3 "," \
	UN_IP "," \
	UN_FIREWARLL1 "," \
	UN_FIREWARLL2 "," \
	UN_FIREWARLL3 "," \
	UN_WirelessSchedule \
"} " 



#define DM_SERVICES \
" 	<Services type=\"object\" Writable=\"0\">" \
" 	</Services>"

#define DM_DEVICEINFO \
" 	<DeviceInfo type=\"object\" Writable=\"0\" tid=\"setting/cwmp_DeviceInfo\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<Manufacturer type=\"string-(64)\" Writable=\"0\">TOTOLINK</Manufacturer>" \
" 		<ManufacturerOUI type=\"string-(6:6)\" Writable=\"0\">04EC90</ManufacturerOUI>" \
" 		<ModelName type=\"string-(64)\" Writable=\"0\">RTL8196E</ModelName>" \
" 		<ProductClass type=\"string-(64)\" Writable=\"0\">HUMAX_cpedev1</ProductClass>" \
" 		<SerialNumber type=\"string-(64)\" Writable=\"0\">FB0C12980121</SerialNumber>" \
" 		<HardwareVersion type=\"string-(64)\" Writable=\"0\">IP042XX</HardwareVersion>" \
" 		<SoftwareVersion type=\"string-(64)\" Writable=\"0\">V10.0c.999</SoftwareVersion>" \
" 		<AdditionalSoftwareVersion type=\"string-(64)\" Writable=\"0\">jk</AdditionalSoftwareVersion>" \
" 		<UpTime type=\"unsignedInt\" Writable=\"0\">0</UpTime>" \
" 		<VendorConfigFileNumberOfEntries type=\"unsignedInt\" Writable=\"0\">1</VendorConfigFileNumberOfEntries>" \
" 		<VendorLogFileNumberOfEntries type=\"unsignedInt\" Writable=\"0\">1</VendorLogFileNumberOfEntries>" \
" 		<X_HUMAX_SystemLogEnable type=\"boolean\" Writable=\"1\">FALSE</X_HUMAX_SystemLogEnable>" \
" 		<VendorConfigFile type=\"object\" Writable=\"0\">" \
" 			<1 type=\"object\" Writable=\"0\">" \
" 				<Name type=\"string-(64)\" Writable=\"0\">config.dat</Name>" \
" 			</1>" \
" 		</VendorConfigFile>" \
" 		<MemoryStatus type=\"object\" Writable=\"0\">" \
" 			<Total type=\"unsignedInt\" Writable=\"0\">32</Total>" \
" 			<Free type=\"unsignedInt\" Writable=\"0\">10</Free>" \
" 		</MemoryStatus>" \
" 		<ProcessStatus type=\"object\" Writable=\"0\" time=\"0000-00-00T00:00:00+08:00\">" \
" 			<CPUUsage type=\"unsignedInt-[:100]\" Writable=\"0\">10%</CPUUsage>" \
" 		</ProcessStatus>" \
" 		<VendorLogFile type=\"object\" Writable=\"0\">" \
" 			<1 type=\"object\" Writable=\"0\">" \
" 				<Name type=\"string-(64)\" Writable=\"0\">jk</Name>" \
" 			</1>" \
" 		</VendorLogFile>" \
" 	</DeviceInfo>"

#define DM_MANAGEMENTERVER \
"	<ManagementServer type=\"object\" Writable=\"0\" tid=\"setting/cwmp_ManagementServer\" time=\"0000-00-00T00:00:00+08:00\">" \
"		<EnableCWMP type=\"boolean\" Writable=\"1\">1</EnableCWMP>" \
"		<URL type=\"string-(256)\" Writable=\"1\">http://cpedemo.cloudapp.net:8500/tr069</URL>" \
"		<Username type=\"string-(256)\" Writable=\"1\">04EC90-FB0C12980121</Username>" \
"		<Password type=\"string-(256)\" Writable=\"1\">cpedev</Password>" \
"		<PeriodicInformEnable type=\"boolean\" Writable=\"1\">1</PeriodicInformEnable>" \
"		<PeriodicInformInterval type=\"unsignedInt-[1:]\" Writable=\"1\">86400</PeriodicInformInterval>" \
"		<PeriodicInformTime type=\"dateTime\" Writable=\"1\">0000-00-00T00:00:00Z</PeriodicInformTime>" \
"		<ParameterKey type=\"string-(32)\" Writable=\"0\">jk10</ParameterKey>" \
"		<ConnectionRequestURL type=\"string-(256)\" Writable=\"0\">http://192.168.10.17:7547/</ConnectionRequestURL>" \
"		<ConnectionRequestUsername type=\"string-(256)\" Writable=\"1\">admin</ConnectionRequestUsername>" \
"		<ConnectionRequestPassword type=\"string-(256)\" Writable=\"1\">admin</ConnectionRequestPassword>" \
"		<UpgradesManaged type=\"boolean\" Writable=\"1\">0</UpgradesManaged>" \
"		<CWMPRetryMinimumWaitInterval type=\"unsignedInt-[1:65535]\" Writable=\"1\">1</CWMPRetryMinimumWaitInterval>" \
"		<CWMPRetryIntervalMultiplier type=\"unsignedInt-[1000:65535]\" Writable=\"1\">1000</CWMPRetryIntervalMultiplier>" \
"	</ManagementServer>"

#define DM_TIME \
" 	<Time type=\"object\" Writable=\"0\" tid=\"setting/cwmp_Timing\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<Enable type=\"boolean\" Writable=\"1\">1</Enable>" \
" 		<Status type=\"string\" Writable=\"0\">ok</Status>" \
" 		<NTPServer1 type=\"string-(64)\" Writable=\"1\">time.nist.gov</NTPServer1>" \
" 		<NTPServer2 type=\"string-(64)\" Writable=\"1\">203.117.180.36</NTPServer2>" \
" 		<NTPServer3 type=\"string-(64)\" Writable=\"1\">0.0.0.0</NTPServer3>" \
" 		<CurrentLocalTime type=\"dateTime\" Writable=\"0\">0000-00-00T00:00:00</CurrentLocalTime>" \
" 		<LocalTimeZone type=\"string-(256)\" Writable=\"1\">CST_008</LocalTimeZone>" \
" 	</Time>"

#define DM_USERINTERFACE \
" 	<UserInterface type=\"object\" Writable=\"0\" tid=\"setting/cwmp_UserInterface\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<CurrentLanguage type=\"string-(16)\" Writable=\"0\">cn</CurrentLanguage>" \
" 		<RemoteAccess type=\"object\" Writable=\"0\" >" \
" 			<Enable type=\"boolean\" Writable=\"1\">1</Enable>" \
" 			<Port type=\"unsignedInt-[:65535]\" Writable=\"1\">8080</Port>" \
" 		</RemoteAccess>" \
" 	</UserInterface>"

#define DM_ETHERNET \
" 	<Ethernet type=\"object\" Writable=\"0\" tid=\"setting/cwmp_Ethernet\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<InterfaceNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</InterfaceNumberOfEntries>" \
" 		<X_HUMAX_IndexRules type=\"object\" Writable=\"0\">" \
" 			<WAN type=\"unsignedInt-[1:]\" Writable=\"0\">11</WAN>" \
" 			<LAN type=\"unsignedInt-[1:]\" Writable=\"0\">1</LAN>" \
" 		</X_HUMAX_IndexRules>" \
" 		<Interface type=\"object\" Writable=\"0\">" \
" 			<1 type=\"object\" Writable=\"0\">" \
" 				<Enable type=\"boolean\" Writable=\"0\">TRUE</Enable>" \
" 				<Status type=\"string\" Writable=\"0\">Up</Status>" \
" 				<Upstream type=\"boolean\" Writable=\"0\">1</Upstream>" \
" 				<MACAddress type=\"string-(17)\" Writable=\"0\">00</MACAddress>" \
" 				<Stats type=\"object\" Writable=\"0\">" \
" 					<BytesSent type=\"unsignedLong\" Writable=\"0\">0</BytesSent>" \
" 					<BytesReceived type=\"unsignedLong\" Writable=\"0\">0</BytesReceived>" \
" 					<PacketsSent type=\"unsignedLong\" Writable=\"0\">0</PacketsSent>" \
" 					<PacketsReceived type=\"unsignedLong\" Writable=\"0\">0</PacketsReceived>" \
" 					<ErrorsSent type=\"unsignedInt\" Writable=\"0\">0</ErrorsSent>" \
" 					<ErrorsReceived type=\"unsignedInt\" Writable=\"0\">0</ErrorsReceived>" \
" 					<UnicastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</UnicastPacketsSent>" \
" 					<UnicastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</UnicastPacketsReceived>" \
" 					<MulticastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</MulticastPacketsSent>" \
" 					<MulticastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</MulticastPacketsReceived>" \
" 					<BroadcastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</BroadcastPacketsSent>" \
" 					<BroadcastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</BroadcastPacketsReceived>" \
" 				</Stats>" \
" 			</1>" \
" 			<11 type=\"object\" Writable=\"0\">" \
" 				<Enable type=\"boolean\" Writable=\"0\">TRUE</Enable>" \
" 				<Status type=\"string\" Writable=\"0\">0</Status>" \
" 				<Upstream type=\"boolean\" Writable=\"0\">0</Upstream>" \
" 				<MACAddress type=\"string-(17)\" Writable=\"0\">00</MACAddress>" \
" 				<Stats type=\"object\" Writable=\"0\">" \
" 					<BytesSent type=\"unsignedLong\" Writable=\"0\">0</BytesSent>" \
" 					<BytesReceived type=\"unsignedLong\" Writable=\"0\">0</BytesReceived>" \
" 					<PacketsSent type=\"unsignedLong\" Writable=\"0\">0</PacketsSent>" \
" 					<PacketsReceived type=\"unsignedLong\" Writable=\"0\">0</PacketsReceived>" \
" 					<ErrorsSent type=\"unsignedInt\" Writable=\"0\">0</ErrorsSent>" \
" 					<ErrorsReceived type=\"unsignedInt\" Writable=\"0\">0</ErrorsReceived>" \
" 					<UnicastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</UnicastPacketsSent>" \
" 					<UnicastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</UnicastPacketsReceived>" \
" 					<MulticastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</MulticastPacketsSent>" \
" 					<MulticastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</MulticastPacketsReceived>" \
" 					<BroadcastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</BroadcastPacketsSent>" \
" 					<BroadcastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</BroadcastPacketsReceived>" \
" 				</Stats>" \
" 			</11>" \
" 		</Interface>" \
" 	</Ethernet>"

#ifdef CONFIG_APP_STORAGE
#define DM_USB \
"	<USB type=\"object\" Writable=\"0\" tid=\"setting/cwmp_USB\" time=\"0000-00-00T00:00:00+08:00\">" \
"		<USBHosts type=\"object\" Writable=\"0\">" \
"			<HostNumberOfEntries type=\"unsignedInt\" Writable=\"0\">1</HostNumberOfEntries>" \
"			<Host type=\"object\" Writable=\"0\">" \
"				<1 type=\"object\" Writable=\"0\">" \
"					<Enable type=\"boolean\" Writable=\"1\">1</Enable>" \
"					<USBVersion type=\"string-(4)\" Writable=\"0\">usb2</USBVersion>" \
"					<DeviceNumberOfEntries type=\"unsignedInt\" Writable=\"0\">1</DeviceNumberOfEntries>" \
"					<Device type=\"object\" Writable=\"0\">" \
"						<1 type=\"object\" Writable=\"0\">" \
"							<DeviceNumber type=\"unsignedInt\" Writable=\"0\">111</DeviceNumber>" \
"							<USBVersion type=\"string-(4)\" Writable=\"0\">111</USBVersion>" \
"							<DeviceClass type=\"hexBinary-(1)\" Writable=\"0\">111</DeviceClass>" \
"							<DeviceSubClass type=\"hexBinary-(1)\" Writable=\"0\">111</DeviceSubClass>" \
"							<DeviceVersion type=\"unsignedInt-[:65535]\" Writable=\"0\">111</DeviceVersion>" \
"							<DeviceProtocol type=\"hexBinary-(1)\" Writable=\"0\">111</DeviceProtocol>" \
"							<ProductID type=\"unsignedInt-[:65535]\" Writable=\"0\">111</ProductID>" \
"							<VendorID type=\"unsignedInt-[:65535]\" Writable=\"0\">111</VendorID>" \
"							<Manufacturer type=\"string-(64)\" Writable=\"0\">111</Manufacturer>" \
"							<ProductClass type=\"string-(64)\" Writable=\"0\">111</ProductClass>" \
"							<Rate type=\"string\" Writable=\"0\">111</Rate>" \
"						</1>" \
"					</Device>" \
"				</1>" \
"			</Host>" \
"		</USBHosts>" \
"	</USB>"
#else
#define DM_USB ""
#endif

#define DM_WIFI_RADIO \
"		<Radio type=\"object\" MaxIdx=\"1\" Writable=\"0\" tid=\"setting/cwmp_wifi_basic\" time=\"0000-00-00T00:00:00\">" \
"			<1 type=\"object\" Writable=\"0\">" \
"				<Enable type=\"boolean\" Writable=\"1\">1</Enable>" \
"				<Status type=\"string\" Writable=\"0\">jk</Status>" \
"				<Name type=\"string-(64)\" Writable=\"0\">jk</Name>" \
"				<Upstream type=\"boolean\" Writable=\"0\">false</Upstream>" \
"				<OperatingFrequencyBand type=\"string\" Writable=\"0\">jk</OperatingFrequencyBand>" \
"				<OperatingStandards type=\"string\" Writable=\"1\">jk</OperatingStandards>" \
"				<ChannelsInUse type=\"string-(1024)\" Writable=\"0\">jk</ChannelsInUse>" \
"				<Channel type=\"unsignedInt-[1:255]\" Writable=\"1\">1</Channel>" \
"				<AutoChannelEnable type=\"boolean\" Writable=\"1\">false</AutoChannelEnable>" \
"				<OperatingChannelBandwidth type=\"string\" Writable=\"1\">fg</OperatingChannelBandwidth>" \
"				<ExtensionChannel type=\"string\" Writable=\"1\">jk</ExtensionChannel>" \
"				<GuardInterval type=\"string\" Writable=\"1\">jk</GuardInterval>" \
"				<TransmitPower type=\"int-[-1:100]\" Writable=\"1\">0</TransmitPower>" \
"				<IEEE80211hEnabled type=\"boolean\" Writable=\"1\">false</IEEE80211hEnabled>" \
"				<RegulatoryDomain type=\"string-(3:3)\" Writable=\"1\">sf</RegulatoryDomain>" \
"				<FragmentationThreshold type=\"unsignedInt\" Writable=\"1\">0</FragmentationThreshold>" \
"				<RTSThreshold type=\"unsignedInt\" Writable=\"1\">0</RTSThreshold>" \
"				<BeaconPeriod type=\"unsignedInt\" Writable=\"1\">100</BeaconPeriod>" \
"				<DTIMPeriod type=\"unsignedInt\" Writable=\"1\">0</DTIMPeriod>" \
"				<PreambleType type=\"string\" Writable=\"1\">jk</PreambleType>" \
"				<X_HUMAX_ProtectionMode type=\"boolean\" Writable=\"1\">false</X_HUMAX_ProtectionMode>" \
"			</1>" \
"		</Radio>" \

#define DM_WIFI_SCAN \
"		<NeighboringWiFiDiagnostic type=\"object\" Writable=\"0\" tid=\"setting/cwmp_wifi_scan\" time=\"0000-00-00T00:00:00\">" \
"			<DiagnosticsState type=\"string\" Writable=\"0\">jk</DiagnosticsState>" \
"			<ResultNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"0\">0</ResultNumberOfEntries>" \
"			<Result type=\"object\" Writable=\"0\">" \
"				<i type=\"object\" Writable=\"0\">" \
"					<Radio type=\"string\" Writable=\"0\">jk</Radio>" \
"					<SSID type=\"string-(32)\" Writable=\"0\">jk</SSID>" \
"					<BSSID type=\"string-(17)\" Writable=\"0\">kl</BSSID>" \
"					<Mode type=\"string\" Writable=\"0\">jk</Mode>" \
"					<Channel type=\"unsignedInt-[1:255]\" Writable=\"0\">0</Channel>" \
"					<SignalStrength type=\"int-[-200:0]\" Writable=\"0\">0</SignalStrength>" \
"					<SecurityModeEnabled type=\"string\" Writable=\"0\">jk</SecurityModeEnabled>" \
"					<EncryptionMode type=\"string\" Writable=\"0\">jk</EncryptionMode>" \
"					<OperatingFrequencyBand type=\"string\" Writable=\"0\">kl</OperatingFrequencyBand>" \
"					<OperatingStandards type=\"string\" Writable=\"0\">kl</OperatingStandards>" \
"					<OperatingChannelBandwidth type=\"string\" Writable=\"0\">kl</OperatingChannelBandwidth>" \
"				</i>" \
"			</Result>" \
"		</NeighboringWiFiDiagnostic>" \

#define DM_WIFI_SSID \
"		<SSID type=\"object\" Writable=\"1\" tid=\"setting/cwmp_wifi_multilssid\" time=\"0000-00-00T00:00:00+08:00\">" \
"			<1 type=\"object\" Writable=\"1\">" \
"				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"				<Status type=\"string\" Writable=\"0\">Down</Status>" \
"				<Name type=\"string-(64)\" Writable=\"0\">jk</Name>" \
"				<LowerLayers type=\"string-(1024)\" Writable=\"0\">jk</LowerLayers>" \
"				<BSSID type=\"string-(17)\" Writable=\"0\">00:E0:4C:61:35:D1</BSSID>" \
"				<SSID type=\"string-(32)\" Writable=\"1\">TOTOLINK_SSID1</SSID>" \
"				<Stats type=\"object\" Writable=\"0\">" \
"					<BytesSent type=\"unsignedLong\" Writable=\"0\">0</BytesSent>" \
"					<BytesReceived type=\"unsignedLong\" Writable=\"0\">0</BytesReceived>" \
"					<PacketsSent type=\"unsignedLong\" Writable=\"0\">0</PacketsSent>" \
"					<PacketsReceived type=\"unsignedLong\" Writable=\"0\">0</PacketsReceived>" \
"					<ErrorsSent type=\"unsignedInt\" Writable=\"0\">0</ErrorsSent>" \
"					<ErrorsReceived type=\"unsignedInt\" Writable=\"0\">0</ErrorsReceived>" \
"					<UnicastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</UnicastPacketsSent>" \
"					<UnicastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</UnicastPacketsReceived>" \
"					<MulticastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</MulticastPacketsSent>" \
"					<MulticastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</MulticastPacketsReceived>" \
"					<BroadcastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</BroadcastPacketsSent>" \
"					<BroadcastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</BroadcastPacketsReceived>" \
"				</Stats>" \
"			</1>" \
"			<2 type=\"object\" Writable=\"1\">" \
"				<Enable type=\"boolean\" Writable=\"1\">0</Enable>" \
"				<Status type=\"string\" Writable=\"0\">FALSE</Status>" \
"				<Name type=\"string-(64)\" Writable=\"0\">jk</Name>" \
"				<LowerLayers type=\"string-(1024)\" Writable=\"0\">jk</LowerLayers>" \
"				<BSSID type=\"string-(17)\" Writable=\"0\">00:E0:4C:61:35:D2</BSSID>" \
"				<SSID type=\"string-(32)\" Writable=\"1\">TOTOLINK_SSID2</SSID>" \
"				<Stats type=\"object\" Writable=\"0\">" \
"					<BytesSent type=\"unsignedLong\" Writable=\"0\">0</BytesSent>" \
"					<BytesReceived type=\"unsignedLong\" Writable=\"0\">0</BytesReceived>" \
"					<PacketsSent type=\"unsignedLong\" Writable=\"0\">0</PacketsSent>" \
"					<PacketsReceived type=\"unsignedLong\" Writable=\"0\">0</PacketsReceived>" \
"					<ErrorsSent type=\"unsignedInt\" Writable=\"0\">0</ErrorsSent>" \
"					<ErrorsReceived type=\"unsignedInt\" Writable=\"0\">0</ErrorsReceived>" \
"					<UnicastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</UnicastPacketsSent>" \
"					<UnicastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</UnicastPacketsReceived>" \
"					<MulticastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</MulticastPacketsSent>" \
"					<MulticastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</MulticastPacketsReceived>" \
"					<BroadcastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</BroadcastPacketsSent>" \
"					<BroadcastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</BroadcastPacketsReceived>" \
"				</Stats>" \
"			</2>" \
"			<3 type=\"object\" Writable=\"1\">" \
"				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"				<Status type=\"string\" Writable=\"0\">Down</Status>" \
"				<Name type=\"string-(64)\" Writable=\"0\">jk</Name>" \
"				<LowerLayers type=\"string-(1024)\" Writable=\"0\">jk</LowerLayers>" \
"				<BSSID type=\"string-(17)\" Writable=\"0\">00:E0:4C:61:35:D1</BSSID>" \
"				<SSID type=\"string-(32)\" Writable=\"1\">TOTOLINK_SSID1</SSID>" \
"				<Stats type=\"object\" Writable=\"0\">" \
"					<BytesSent type=\"unsignedLong\" Writable=\"0\">0</BytesSent>" \
"					<BytesReceived type=\"unsignedLong\" Writable=\"0\">0</BytesReceived>" \
"					<PacketsSent type=\"unsignedLong\" Writable=\"0\">0</PacketsSent>" \
"					<PacketsReceived type=\"unsignedLong\" Writable=\"0\">0</PacketsReceived>" \
"					<ErrorsSent type=\"unsignedInt\" Writable=\"0\">0</ErrorsSent>" \
"					<ErrorsReceived type=\"unsignedInt\" Writable=\"0\">0</ErrorsReceived>" \
"					<UnicastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</UnicastPacketsSent>" \
"					<UnicastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</UnicastPacketsReceived>" \
"					<MulticastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</MulticastPacketsSent>" \
"					<MulticastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</MulticastPacketsReceived>" \
"					<BroadcastPacketsSent type=\"unsignedLong\" Writable=\"0\">0</BroadcastPacketsSent>" \
"					<BroadcastPacketsReceived type=\"unsignedLong\" Writable=\"0\">0</BroadcastPacketsReceived>" \
"				</Stats>" \
"			</3>" \
"		</SSID>" \

#define DM_WIFI_ACCESS \
"		<AccessPoint type=\"object\" Writable=\"1\" tid=\"setting/cwmp_wifi_accsspoint\" time=\"0000-00-00T00:00:00\">" \
"			<1 type=\"object\" Writable=\"1\">" \
"				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"				<SSIDReference type=\"string-(256)\" Writable=\"0\">Empty</SSIDReference>" \
"				<SSIDAdvertisementEnabled type=\"boolean\" Writable=\"1\">false</SSIDAdvertisementEnabled>" \
"				<WMMEnable type=\"boolean\" Writable=\"1\">false</WMMEnable>" \
"				<AssociatedDeviceNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"0\">0</AssociatedDeviceNumberOfEntries>" \
"				<MaxAssociatedDevices type=\"unsignedInt\" Writable=\"1\">0</MaxAssociatedDevices>" \
"				<IsolationEnable type=\"boolean\" Writable=\"1\">false</IsolationEnable>" \
"				<MACAddressControlEnabled type=\"boolean\" Writable=\"1\">df</MACAddressControlEnabled>" \
"				<AllowedMACAddress type=\"string\" Writable=\"1\">df</AllowedMACAddress>" \
"				<X_HUMAX_MACAddressControlAllowMode type=\"boolean\" Writable=\"1\">TRUE</X_HUMAX_MACAddressControlAllowMode>" \
"				<Security type=\"object\" Writable=\"0\">" \
"					<ModesSupported type=\"string\" Writable=\"0\">kj</ModesSupported>" \
"					<ModeEnabled type=\"string\" Writable=\"1\">kj</ModeEnabled>" \
"					<WEPKey type=\"hexBinary-(5:5, 13:13)\" Writable=\"1\">00</WEPKey>" \
"					<KeyPassphrase type=\"string-(8:63)\" Writable=\"1\">jkjkjkjkjk</KeyPassphrase>" \
"					<X_HUMAX_EncryptionType type=\"string-(256)\" Writable=\"1\">AES</X_HUMAX_EncryptionType>" \
"					<X_HUMAX_KeyType type=\"string-(256)\" Writable=\"1\">Hexadecimal</X_HUMAX_KeyType>" \
"				</Security>" \
"				<WPS type=\"object\" Writable=\"0\">" \
"					<Enable type=\"boolean\" Writable=\"1\">TRUE</Enable>" \
"					<ConfigMethodsEnabled type=\"string\" Writable=\"1\">sd</ConfigMethodsEnabled>" \
"					<X_HUMAX_Status type=\"string-(256)\" Writable=\"0\">Disconnected</X_HUMAX_Status>" \
"					<X_HUMAX_LocalPinCode type=\"string-(256)\" Writable=\"0\">00000</X_HUMAX_LocalPinCode>" \
"				</WPS>" \
"				<AssociatedDevice type=\"object\" Writable=\"0\">" \
"					<i type=\"object\" Writable=\"0\">" \
"						<MACAddress type=\"string-(17)\" Writable=\"0\">sd</MACAddress>" \
"						<OperatingStandard type=\"string\" Writable=\"0\">sd</OperatingStandard>" \
"						<SignalStrength type=\"int-[-200:0]\" Writable=\"0\">01</SignalStrength>" \
"					</i>" \
"				</AssociatedDevice>" \
"			</1>" \
"			<2 type=\"object\" Writable=\"1\">" \
"				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"				<SSIDReference type=\"string-(256)\" Writable=\"1\">Empty</SSIDReference>" \
"				<SSIDAdvertisementEnabled type=\"boolean\" Writable=\"1\">false</SSIDAdvertisementEnabled>" \
"				<WMMEnable type=\"boolean\" Writable=\"1\">false</WMMEnable>" \
"				<AssociatedDeviceNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"0\">0</AssociatedDeviceNumberOfEntries>" \
"				<MaxAssociatedDevices type=\"unsignedInt\" Writable=\"1\">0</MaxAssociatedDevices>" \
"				<IsolationEnable type=\"boolean\" Writable=\"1\">false</IsolationEnable>" \
"				<MACAddressControlEnabled type=\"boolean\" Writable=\"1\">df</MACAddressControlEnabled>" \
"				<AllowedMACAddress type=\"string\" Writable=\"1\">df</AllowedMACAddress>" \
"				<X_HUMAX_MACAddressControlAllowMode type=\"boolean\" Writable=\"1\">TRUE</X_HUMAX_MACAddressControlAllowMode>" \
"				<Security type=\"object\" Writable=\"0\">" \
"					<ModeEnabled type=\"string\" Writable=\"1\">kj</ModeEnabled>" \
"					<ModeEnabled type=\"string\" Writable=\"1\">kj</ModeEnabled>" \
"					<WEPKey type=\"hexBinary-(5:5, 13:13)\" Writable=\"1\">00</WEPKey>" \
"					<KeyPassphrase type=\"string-(8:63)\" Writable=\"1\">jkjkjkjkjk</KeyPassphrase>" \
"					<X_HUMAX_EncryptionType type=\"string-(256)\" Writable=\"1\">AES</X_HUMAX_EncryptionType>" \
"					<X_HUMAX_KeyType type=\"string-(256)\" Writable=\"1\">Hexadecimal</X_HUMAX_KeyType>" \
"				</Security>" \
"				<WPS type=\"object\" Writable=\"0\">" \
"					<Enable type=\"boolean\" Writable=\"1\">TRUE</Enable>" \
"					<ConfigMethodsEnabled type=\"string\" Writable=\"1\">sd</ConfigMethodsEnabled>" \
"					<X_HUMAX_Status type=\"string-(256)\" Writable=\"0\">Disconnected</X_HUMAX_Status>" \
"					<X_HUMAX_LocalPinCode type=\"string-(256)\" Writable=\"0\">00000</X_HUMAX_LocalPinCode>" \
"				</WPS>" \
"				<AssociatedDevice type=\"object\" Writable=\"0\">" \
"					<i type=\"object\" Writable=\"0\">" \
"						<MACAddress type=\"string-(17)\" Writable=\"0\">sd</MACAddress>" \
"						<OperatingStandard type=\"string\" Writable=\"0\">sd</OperatingStandard>" \
"						<SignalStrength type=\"int-[-200:0]\" Writable=\"0\">01</SignalStrength>" \
"					</i>" \
"				</AssociatedDevice>" \
"			</2>" \
"			<3 type=\"object\" Writable=\"1\">" \
"				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"				<SSIDReference type=\"string-(256)\" Writable=\"1\">Empty</SSIDReference>" \
"				<SSIDAdvertisementEnabled type=\"boolean\" Writable=\"1\">false</SSIDAdvertisementEnabled>" \
"				<WMMEnable type=\"boolean\" Writable=\"1\">false</WMMEnable>" \
"				<AssociatedDeviceNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"0\">0</AssociatedDeviceNumberOfEntries>" \
"				<MaxAssociatedDevices type=\"unsignedInt\" Writable=\"1\">0</MaxAssociatedDevices>" \
"				<IsolationEnable type=\"boolean\" Writable=\"1\">false</IsolationEnable>" \
"				<MACAddressControlEnabled type=\"boolean\" Writable=\"1\">df</MACAddressControlEnabled>" \
"				<AllowedMACAddress type=\"string\" Writable=\"1\">df</AllowedMACAddress>" \
"				<X_HUMAX_MACAddressControlAllowMode type=\"boolean\" Writable=\"1\">TRUE</X_HUMAX_MACAddressControlAllowMode>" \
"				<Security type=\"object\" Writable=\"0\">" \
"					<ModeEnabled type=\"string\" Writable=\"0\">kj</ModeEnabled>" \
"					<ModeEnabled type=\"string\" Writable=\"1\">kj</ModeEnabled>" \
"					<WEPKey type=\"hexBinary-(5:5, 13:13)\" Writable=\"1\">00</WEPKey>" \
"					<KeyPassphrase type=\"string-(8:63)\" Writable=\"1\">jkjkjkjkjk</KeyPassphrase>" \
"					<X_HUMAX_EncryptionType type=\"string-(256)\" Writable=\"1\">AES</X_HUMAX_EncryptionType>" \
"					<X_HUMAX_KeyType type=\"string-(256)\" Writable=\"1\">Hexadecimal</X_HUMAX_KeyType>" \
"				</Security>" \
"				<WPS type=\"object\" Writable=\"0\">" \
"					<Enable type=\"boolean\" Writable=\"1\">TRUE</Enable>" \
"					<ConfigMethodsEnabled type=\"string\" Writable=\"1\">sd</ConfigMethodsEnabled>" \
"					<X_HUMAX_Status type=\"string-(256)\" Writable=\"0\">Disconnected</X_HUMAX_Status>" \
"					<X_HUMAX_LocalPinCode type=\"string-(256)\" Writable=\"0\">00000</X_HUMAX_LocalPinCode>" \
"				</WPS>" \
"				<AssociatedDevice type=\"object\" Writable=\"0\">" \
"					<i type=\"object\" Writable=\"0\">" \
"						<MACAddress type=\"string-(17)\" Writable=\"0\">sd</MACAddress>" \
"						<OperatingStandard type=\"string\" Writable=\"0\">sd</OperatingStandard>" \
"						<SignalStrength type=\"int-[-200:0]\" Writable=\"0\">01</SignalStrength>" \
"					</i>" \
"				</AssociatedDevice>" \
"			</3>" \
"		</AccessPoint>" \


#define DM_WIFI \
"	<WiFi type=\"object\" Writable=\"0\" tid=\"setting/cwmp_wifi\" time=\"0000-00-00T00:00:00\">" \
"		<RadioNumberOfEntries type=\"unsignedInt\" Writable=\"0\">1</RadioNumberOfEntries>" \
"		<SSIDNumberOfEntries type=\"unsignedInt\" Writable=\"0\">3</SSIDNumberOfEntries>" \
"		<AccessPointNumberOfEntries type=\"unsignedInt\" Writable=\"0\">3</AccessPointNumberOfEntries>" \
	DM_WIFI_RADIO \
	DM_WIFI_SCAN \
	DM_WIFI_SSID \
	DM_WIFI_ACCESS \
"	</WiFi>"

#define DM_PPP \
"	<PPP type=\"object\" Writable=\"0\" tid=\"setting/cwmp_PPP\" time=\"0000-00-00T00:00:00+08:00\">" \
"		<InterfaceNumberOfEntries type=\"unsignedInt\" Writable=\"0\">1</InterfaceNumberOfEntries>" \
"		<Interface type=\"object\" Writable=\"1\">" \
"			<1 type=\"object\" Writable=\"1\">" \
"				<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
"				<Status type=\"string\" Writable=\"0\">\"Down\"</Status>" \
"				<Username type=\"string-(64)\" Writable=\"1\">jk</Username>" \
"				<Password type=\"string-(64)\" Writable=\"1\">jk</Password>" \
"				<ConnectionTrigger type=\"string\" Writable=\"1\">jk</ConnectionTrigger>" \
"				<PPPoE type=\"object\" Writable=\"0\">" \
"					<SessionID type=\"unsignedInt-[1:]\" Writable=\"0\">2</SessionID>" \
"					<ACName type=\"string-(256)\" Writable=\"0\">Empty</ACName>" \
"					<ServiceName type=\"string-(256)\" Writable=\"0\">Empty</ServiceName>" \
"				</PPPoE>" \
"			</1>" \
"		</Interface>" \
"	</PPP>" \

#define DM_IP \
"	<IP type=\"object\" Writable=\"0\" tid=\"setting/cwmp_IP\" time=\"0000-00-00T00:00:00+08:00\">" \
"		<IPv6Enable type=\"boolean\" Writable=\"1\">FALSE</IPv6Enable>" \
"		<InterfaceNumberOfEntries type=\"unsignedInt\" Writable=\"0\">2</InterfaceNumberOfEntries>" \
"		<X_HUMAX_IndexRules type=\"object\" Writable=\"0\">" \
"			<WAN type=\"unsignedInt-[1:]\" Writable=\"1\">11</WAN>" \
"			<LAN type=\"unsignedInt-[1:]\" Writable=\"1\">11</LAN>" \
"		</X_HUMAX_IndexRules>" \
"		<Interface type=\"object\" Writable=\"1\">" \
"			<1 type=\"object\" Writable=\"1\">" \
"				<Enable type=\"boolean\" Writable=\"0\">TRUE</Enable>" \
"				<IPv6Enable type=\"boolean\" Writable=\"1\">FALSE</IPv6Enable>" \
"				<Status type=\"string\" Writable=\"0\">jk</Status>" \
"				<Name type=\"string-(64)\" Writable=\"0\">jk</Name>" \
"				<LowerLayers type=\"string-(1024)\" Writable=\"0\">jk</LowerLayers>" \
"				<MaxMTUSize type=\"unsignedInt-[64:65535]\" Writable=\"1\">65</MaxMTUSize>" \
"				<IPv4AddressNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</IPv4AddressNumberOfEntries>" \
"				<IPv6AddressNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</IPv6AddressNumberOfEntries>" \
"				<IPv4Address type=\"object\" Writable=\"1\">" \
"					<1 type=\"object\" Writable=\"1\">" \
"						<Enable type=\"boolean\" Writable=\"0\">TRUE</Enable>" \
"						<IPAddress type=\"string-(15)\" Writable=\"1\">0.0.0.0</IPAddress>" \
"						<SubnetMask type=\"string-(15)\" Writable=\"1\">0.0.0.0</SubnetMask>" \
"						<AddressingType type=\"string\" Writable=\"0\">jk</AddressingType>" \
"					</1>" \
"				</IPv4Address>" \
"				<IPv6Address type=\"object\" Writable=\"1\">" \
"					<i type=\"object\" Writable=\"1\">" \
"						<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"						<IPAddress type=\"string-(45)\" Writable=\"1\">Empty</IPAddress>" \
"						<Origin type=\"string\" Writable=\"0\">Static</Origin>" \
"						<Prefix type=\"string\" Writable=\"1\">Empty</Prefix>" \
"					</i>" \
"				</IPv6Address>" \
"				<IPv6Prefix type=\"object\" Writable=\"1\">" \
"					<i type=\"object\" Writable=\"1\">" \
"						<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"						<Prefix type=\"string-(49)\" Writable=\"1\">Empty</Prefix>" \
"						<Origin type=\"string\" Writable=\"0\">Static</Origin>" \
"						<ChildPrefixBits type=\"string-(49)\" Writable=\"1\">Empty</ChildPrefixBits>" \
"						<PreferredLifetime type=\"dateTime\" Writable=\"1\">9999-12-31T23:59:59Z</PreferredLifetime>" \
"					</i>" \
"				</IPv6Prefix>" \
"			</1>" \
"			<11 type=\"object\" Writable=\"1\">" \
"				<Enable type=\"boolean\" Writable=\"1\">TRUE</Enable>" \
"				<IPv6Enable type=\"boolean\" Writable=\"0\">FALSE</IPv6Enable>" \
"				<Status type=\"string\" Writable=\"0\">jk</Status>" \
"				<Name type=\"string-(64)\" Writable=\"0\">jk</Name>" \
"				<LowerLayers type=\"string-(1024)\" Writable=\"0\">jk</LowerLayers>" \
"				<MaxMTUSize type=\"unsignedInt-[64:65535]\" Writable=\"1\">65</MaxMTUSize>" \
"				<IPv4AddressNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</IPv4AddressNumberOfEntries>" \
"				<IPv6AddressNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</IPv6AddressNumberOfEntries>" \
"				<IPv4Address type=\"object\" Writable=\"1\">" \
"					<1 type=\"object\" Writable=\"1\">" \
"						<Enable type=\"boolean\" Writable=\"1\">TRUE</Enable>" \
"						<IPAddress type=\"string-(15)\" Writable=\"1\">0.0.0.0</IPAddress>" \
"						<SubnetMask type=\"string-(15)\" Writable=\"1\">0.0.0.0</SubnetMask>" \
"						<AddressingType type=\"string\" Writable=\"0\">jk</AddressingType>" \
"					</1>" \
"				</IPv4Address>" \
"				<IPv6Address type=\"object\" Writable=\"1\">" \
"					<1 type=\"object\" Writable=\"1\">" \
"						<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"						<IPAddress type=\"string-(45)\" Writable=\"1\">Empty</IPAddress>" \
"						<Origin type=\"string\" Writable=\"0\">Static</Origin>" \
"						<Prefix type=\"string\" Writable=\"1\">Empty</Prefix>" \
"					</1>" \
"				</IPv6Address>" \
"				<IPv6Prefix type=\"object\" Writable=\"1\">" \
"					<1 type=\"object\" Writable=\"1\">" \
"						<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"						<Prefix type=\"string-(49)\" Writable=\"1\">Empty</Prefix>" \
"						<Origin type=\"string\" Writable=\"0\">Static</Origin>" \
"						<ChildPrefixBits type=\"string-(49)\" Writable=\"1\">Empty</ChildPrefixBits>" \
"						<PreferredLifetime type=\"dateTime\" Writable=\"1\">9999-12-31T23:59:59Z</PreferredLifetime>" \
"					</1>" \
"				</IPv6Prefix>" \
"			</11>" \
"		</Interface>" \
"		<Diagnostics type=\"object\" Writable=\"0\">" \
"			<IPv4PingSupported type=\"boolean\" Writable=\"0\">TRUE</IPv4PingSupported>" \
"			<IPPing type=\"object\" Writable=\"0\" tid=\"setting/cwmp_IPPingDiagnostics\" time=\"0000-00-00T00:00:00+08:00\">" \
"				<DiagnosticsState type=\"string\" Writable=\"1\">Requested</DiagnosticsState>" \
"				<ProtocolVersion type=\"string\" Writable=\"0\">IPv4</ProtocolVersion>" \
"				<Host type=\"string-(256)\" Writable=\"1\">Empty</Host>" \
"				<NumberOfRepetitions type=\"unsignedInt-[1:]\" Writable=\"1\">1</NumberOfRepetitions>" \
"				<SuccessCount type=\"unsignedInt\" Writable=\"0\">0</SuccessCount>" \
"				<FailureCount type=\"unsignedInt\" Writable=\"0\">0</FailureCount>" \
"				<AverageResponseTime type=\"unsignedInt\" Writable=\"0\">0</AverageResponseTime>" \
"			</IPPing>" \
"			<TraceRoute type=\"object\" Writable=\"0\" tid=\"setting/cwmp_IPTraceDiagnostics\" time=\"0000-00-00T00:00:00+08:00\">" \
"				<DiagnosticsState type=\"string\" Writable=\"1\">Requested</DiagnosticsState>" \
"				<Host type=\"string-(256)\" Writable=\"1\">Empty</Host>" \
"				<NumberOfTries type=\"unsignedInt-[1:3]\" Writable=\"1\">3</NumberOfTries>" \
"				<Timeout type=\"unsignedInt-[1:]\" Writable=\"1\">5</Timeout>" \
"				<MaxHopCount type=\"unsignedInt-[1:64]\" Writable=\"1\">30</MaxHopCount>" \
"				<ResponseTime type=\"unsignedInt\" Writable=\"0\">0</ResponseTime>" \
"				<RouteHopsNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"0\">0</RouteHopsNumberOfEntries>" \
"				<RouteHops type=\"object\" Writable=\"1\">" \
"					<i type=\"object\" Writable=\"1\">" \
"						<Host type=\"string-(256)\" Writable=\"0\">Empty</Host>" \
"						<HostAddress type=\"string\" Writable=\"0\">Empty</HostAddress>" \
"						<RTTimes type=\"string-(16)\" Writable=\"0\">Empty</RTTimes>" \
"					</i>" \
"				</RouteHops>" \
"			</TraceRoute>" \
"		</Diagnostics>" \
"	</IP>"

#define DM_ROUTING \
" 	<Routing type=\"object\" Writable=\"0\" tid=\"setting/cwmp_Routing\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<RouterNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</RouterNumberOfEntries>" \
" 		<Router type=\"object\" Writable=\"1\">" \
" 			<i type=\"object\" Writable=\"1\">" \
" 				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
" 				<IPv4ForwardingNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</IPv4ForwardingNumberOfEntries>" \
" 				<IPv6ForwardingNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</IPv6ForwardingNumberOfEntries>" \
" 				<IPv4Forwarding type=\"object\" Writable=\"1\">" \
" 					<i type=\"object\" Writable=\"1\">" \
" 						<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
" 						<Status type=\"string\" Writable=\"0\">Disabled</Status>" \
" 						<DestIPAddress type=\"string-(15)\" Writable=\"1\">Empty</DestIPAddress>" \
" 						<DestSubnetMask type=\"string-(15)\" Writable=\"1\">Empty</DestSubnetMask>" \
" 						<GatewayIPAddress type=\"string-(15)\" Writable=\"1\">Empty</GatewayIPAddress>" \
" 					</i>" \
" 				</IPv4Forwarding>" \
" 				<IPv6Forwarding type=\"object\" Writable=\"1\">" \
" 					<i type=\"object\" Writable=\"1\">" \
" 						<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
" 						<NextHop type=\"string-(45)\" Writable=\"1\">Empty</NextHop>" \
" 					</i>" \
" 				</IPv6Forwarding>" \
" 			</i>" \
" 		</Router>" \
" 	</Routing>" \

//??????,?????dm ??,?DHCPv4 ???
#define DM_HOSTS \
" 	<Hosts type=\"object\" Writable=\"0\" tid=\"setting/cwmp_Hosts\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<HostNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"0\">0</HostNumberOfEntries>" \
" 		<Host type=\"object\" Writable=\"0\">" \
" 			<i type=\"object\" Writable=\"0\">" \
" 				<PhysAddress type=\"string-(64)\" Writable=\"0\">jk</PhysAddress>" \
" 				<IPAddress type=\"string-(45)\" Writable=\"0\">0.0.0.0</IPAddress>" \
" 				<AddressSource type=\"string\" Writable=\"0\">jk</AddressSource>" \
" 				<Layer1Interface type=\"string-(256)\" Writable=\"0\">jk</Layer1Interface>" \
" 				<HostName type=\"string-(64)\" Writable=\"0\">jk</HostName>" \
" 				<Active type=\"boolean\" Writable=\"0\">FALSE</Active>" \
"				<ActiveLastChange	type=\"string-(32)\" Writable=\"0\">UnKown</ActiveLastChange>" \
" 				<IPv4AddressNumberOfEntries type=\"unsignedInt\" Writable=\"0\">1</IPv4AddressNumberOfEntries>" \
" 				<IPv6AddressNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</IPv6AddressNumberOfEntries>" \
" 				<IPv4Address.1.IPAddress type=\"string-(32)\" Writable=\"0\">0.0.0.0</IPv4Address.1.IPAddress>" \
" 				<IPv6Address type=\"object\" Writable=\"0\">" \
" 					<i type=\"object\" Writable=\"0\">" \
" 						<IPAddress type=\"string-(45)\" Writable=\"0\">0.0.0.0</IPAddress>" \
" 					</i>" \
" 				</IPv6Address>" \
" 			</i>" \
" 		</Host>" \
" 	</Hosts>" \

#define DM_DNS \
" 	<DNS type=\"object\" Writable=\"0\" tid=\"setting/cwmp_DNS\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<Client type=\"object\" Writable=\"0\">" \
" 			<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 			<Status type=\"string\" Writable=\"0\">Disabled</Status>" \
" 			<ServerNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</ServerNumberOfEntries>" \
" 			<Server type=\"object\" Writable=\"1\">" \
" 				<1 type=\"object\" Writable=\"1\">" \
" 					<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 					<Status type=\"string\" Writable=\"0\">Disabled</Status>" \
" 					<DNSServer type=\"string-(45)\" Writable=\"1\">0.0.0.0</DNSServer>" \
" 				</1>" \
"				<2 type=\"object\" Writable=\"1\">" \
"					<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"					<Status type=\"string\" Writable=\"0\">Disabled</Status>" \
"					<DNSServer type=\"string-(45)\" Writable=\"1\">0.0.0.0</DNSServer>" \
"				</2>" \
" 			</Server>" \
" 		</Client>" \
" 	</DNS>" \

#define DM_NAT \
" 	<NAT type=\"object\" Writable=\"0\" tid=\"setting/cwmp_NAT\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<X_HUMAX_PortForwardingEnable type=\"boolean\" Writable=\"1\">FALSE</X_HUMAX_PortForwardingEnable>" \
" 		<X_HUMAX_DMZEnable type=\"boolean\" Writable=\"1\">FALSE</X_HUMAX_DMZEnable>" \
" 		<X_HUMAX_DMZDestIPAddress type=\"string-(256)\" Writable=\"1\">0.0.0.0</X_HUMAX_DMZDestIPAddress>" \
"		<PortMappingNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"0\">0</PortMappingNumberOfEntries>" \
" 		<PortMapping type=\"object\" Writable=\"1\">" \
" 			<i type=\"object\" Writable=\"1\">" \
" 				<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 				<Status type=\"string\" Writable=\"0\">Disabled</Status>" \
" 				<ExternalPort type=\"unsignedInt-[0:65535]\" Writable=\"1\">0</ExternalPort>" \
" 				<ExternalPortEndRange type=\"unsignedInt-[0:65535]\" Writable=\"0\">0</ExternalPortEndRange>" \
" 				<InternalPort type=\"unsignedInt-[0:65535]\" Writable=\"1\">0</InternalPort>" \
" 				<Protocol type=\"string\" Writable=\"1\">TCP</Protocol>" \
" 				<InternalClient type=\"string-(256)\" Writable=\"1\">Empty</InternalClient>" \
" 				<Description type=\"string-(256)\" Writable=\"1\">Empty</Description>" \
" 			</i>" \
" 		</PortMapping>" \
" 	</NAT>" \

/*
 ?:   Datamodel ?,Device.DHCPv4.Server.Pool.1.Client ?????
" 					<Client type=\"object\" Writable=\"0\">" \
" 						<i type=\"object\" Writable=\"0\">" \
" 							<Chaddr type=\"string-(17)\" Writable=\"0\">0.0.0.0</Chaddr>" \
" 							<Active type=\"boolean\" Writable=\"0\">1</Active>" \
" 							<IPv4AddressNumberOfEntries type=\"unsignedInt\" Writable=\"0\">1</IPv4AddressNumberOfEntries>" \
" 							<IPv4Address type=\"object\" Writable=\"0\">" \
" 								<1 type=\"object\" Writable=\"0\">" \
" 									<IPAddress type=\"string-(15)\" Writable=\"0\">0.0.0.0</IPAddress>" \
" 									<LeaseTimeRemaining type=\"dateTime\" Writable=\"0\">0</LeaseTimeRemaining>" \
" 								</1>" \
" 							</IPv4Address>" \
" 						</i>" \
" 					</Client>" \

??ACS  ?????????,  ???easycwmp ????????,
????????????????,??????????????
*/

#define DM_DHCPV4 \
" 	<DHCPv4 type=\"object\" Writable=\"0\" tid=\"setting/cwmp_DHCPv4\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<ClientNumberOfEntries type=\"unsignedInt\" Writable=\"0\">1</ClientNumberOfEntries>" \
" 		<Client type=\"object\" Writable=\"1\">" \
" 			<1 type=\"object\" Writable=\"1\">" \
" 				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
" 				<Status type=\"string\" Writable=\"0\">Disabled</Status>" \
" 				<IPAddress type=\"string-(15)\" Writable=\"0\">Empty</IPAddress>" \
" 				<SubnetMask type=\"string-(15)\" Writable=\"0\">Empty</SubnetMask>" \
" 				<IPRouters type=\"string-(256)\" Writable=\"0\">Empty</IPRouters>" \
" 				<DNSServers type=\"string-(256)\" Writable=\"0\">Empty</DNSServers>" \
" 				<DHCPServer type=\"string-(15)\" Writable=\"0\">Empty</DHCPServer>" \
" 			</1>" \
" 		</Client>" \
" 		<Server type=\"object\" Writable=\"0\">" \
" 			<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
" 			<PoolNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</PoolNumberOfEntries>" \
" 			<Pool type=\"object\" Writable=\"1\">" \
" 				<1 type=\"object\" Writable=\"1\">" \
" 					<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 					<Status type=\"string\" Writable=\"0\">Disabled</Status>" \
" 					<MinAddress type=\"string-(15)\" Writable=\"1\">0.0.0.0</MinAddress>" \
" 					<MaxAddress type=\"string-(15)\" Writable=\"1\">0.0.0.0</MaxAddress>" \
" 					<ReservedAddresses type=\"string\" Writable=\"1\">Empty</ReservedAddresses>" \
" 					<SubnetMask type=\"string-(15)\" Writable=\"1\">0.0.0.0</SubnetMask>" \
" 					<DNSServers type=\"string\" Writable=\"0\">0.0.0.0</DNSServers>" \
" 					<LeaseTime type=\"int-[-1:]\" Writable=\"1\">86400</LeaseTime>" \
" 					<X_HUMAX_StaticAddressEnable type=\"boolean\" Writable=\"1\">FALSE</X_HUMAX_StaticAddressEnable>" \
" 					<StaticAddressNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"0\">0</StaticAddressNumberOfEntries>" \
" 					<StaticAddress type=\"object\" Writable=\"1\">" \
" 						<i type=\"object\" Writable=\"1\">" \
" 							<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 							<Chaddr type=\"string-(17)\" Writable=\"1\">Empty</Chaddr>" \
" 							<Yiaddr type=\"string-(15)\" Writable=\"1\">Empty</Yiaddr>" \
" 						</i>" \
" 					</StaticAddress>" \
"					<ClientNumberOfEntries  mode=\"auto\" type=\"unsignedInt\" Writable=\"0\">0</ClientNumberOfEntries>" \
" 					<Client type=\"object\" Writable=\"0\">" \
" 						<i type=\"object\" Writable=\"0\">" \
" 							<Chaddr type=\"string-(17)\" Writable=\"0\">0.0.0.0</Chaddr>" \
" 							<Active type=\"boolean\" Writable=\"0\">1</Active>" \
" 							<IPv4AddressNumberOfEntries type=\"unsignedInt\" Writable=\"0\">1</IPv4AddressNumberOfEntries>" \
"							<IPv4Address.1.IPAddress type=\"string-(15)\" Writable=\"0\" >aaa</IPv4Address.1.IPAddress>" \
"							<IPv4Address.1.LeaseTimeRemaining type=\"int-[-1:]\" Writable=\"0\">bbb</IPv4Address.1.LeaseTimeRemaining>" \
" 						</i>" \
" 					</Client>" \
" 				</1>" \
" 			</Pool>" \
" 		</Server>" \
" 	</DHCPv4>"

#define DM_DHCPV6 \
" 	<DHCPv6 type=\"object\" Writable=\"0\" tid=\"setting/cwmp_DHCPv6\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<Server type=\"object\" Writable=\"0\">" \
" 			<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
" 			<PoolNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</PoolNumberOfEntries>" \
" 			<Pool type=\"object\" Writable=\"1\">" \
" 				<1 type=\"object\" Writable=\"1\">" \
" 					<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 					<IAPDManualPrefixes type=\"string\" Writable=\"0\">Empty</IAPDManualPrefixes>" \
" 				</1>" \
" 			</Pool>" \
" 		</Server>" \
" 	</DHCPv6>" \

#define DM_USERS \
" 	<Users type=\"object\" Writable=\"0\" tid=\"setting/cwmp_Users\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<UserNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</UserNumberOfEntries>" \
" 		<User type=\"object\" Writable=\"1\">" \
" 			<1 type=\"object\" Writable=\"1\">" \
" 				<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 				<Username type=\"string-(64)\" Writable=\"1\">Empty</Username>" \
" 				<Password type=\"string-(64)\" Writable=\"1\">Empty</Password>" \
" 			</1>" \
" 		</User>" \
" 	</Users>" \

#define DM_UPNP \
" 	<UPnP type=\"object\" Writable=\"0\" tid=\"setting/cwmp_UPnP\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<Device type=\"object\" Writable=\"0\">" \
" 			<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
" 			<UPnPIGD type=\"boolean\" Writable=\"1\">FALSE</UPnPIGD>" \
" 			<Capabilities type=\"object\" Writable=\"0\">" \
" 				<UPnPArchitecture type=\"unsignedInt\" Writable=\"0\">0</UPnPArchitecture>" \
" 				<UPnPArchitectureMinorVer type=\"unsignedInt\" Writable=\"0\">0</UPnPArchitectureMinorVer>" \
" 				<UPnPIGD type=\"unsignedInt\" Writable=\"0\">0</UPnPIGD>" \
" 			</Capabilities>" \
" 		</Device>" \
" 	</UPnP>" \

#define DM_FIREWALL \
" 	<Firewall type=\"object\" Writable=\"0\" tid=\"setting/cwmp_Firewall\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 		<ChainNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</ChainNumberOfEntries>" \
" 		<X_HUMAX_ICMPBlocking type=\"boolean\" Writable=\"1\">FALSE</X_HUMAX_ICMPBlocking>" \
" 		<X_HUMAX_IPsecPassthrough type=\"boolean\" Writable=\"1\">FALSE</X_HUMAX_IPsecPassthrough>" \
" 		<X_HUMAX_PPTPPassthrough type=\"boolean\" Writable=\"1\">FALSE</X_HUMAX_PPTPPassthrough>" \
" 		<X_HUMAX_L2TPPassthrough type=\"boolean\" Writable=\"1\">FALSE</X_HUMAX_L2TPPassthrough>" \
" 		<X_HUMAX_IPFilter type=\"object\" Writable=\"0\">" \
" 			<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 			<Description type=\"string-(64)\" Writable=\"1\">jk</Description>" \
" 			<Chain type=\"string\" Writable=\"0\">jk</Chain>" \
" 			<DefaultPolicy type=\"string\" Writable=\"0\">Drop</DefaultPolicy>" \
" 		</X_HUMAX_IPFilter>" \
" 		<X_HUMAX_MACFilter type=\"object\" Writable=\"0\">" \
" 			<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 			<Description type=\"string-(64)\" Writable=\"1\">jk</Description>" \
" 			<Chain type=\"string\" Writable=\"0\">jk</Chain>" \
" 			<DefaultPolicy type=\"string\" Writable=\"0\">Drop</DefaultPolicy>" \
" 		</X_HUMAX_MACFilter>" \
" 		<X_HUMAX_URLFilter type=\"object\" Writable=\"0\">" \
" 			<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 			<Description type=\"string-(64)\" Writable=\"1\">jk</Description>" \
" 			<Chain type=\"string\" Writable=\"0\">jk</Chain>" \
" 			<DefaultPolicy type=\"string\" Writable=\"0\">Drop</DefaultPolicy>" \
" 		</X_HUMAX_URLFilter>" \
" 		<Chain type=\"object\" Writable=\"1\">" \
" 			<1 type=\"object\" Writable=\"1\" tid=\"setting/cwmp_Firewall_IP\" time=\"0000-00-00T00:00:00+08:00\">" \
" 				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
" 				<Name type=\"string-(64)\" Writable=\"1\">jk</Name>" \
" 				<RuleNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"0\">0</RuleNumberOfEntries>" \
" 				<Rule type=\"object\" Writable=\"1\">" \
" 					<i type=\"object\" Writable=\"1\">" \
" 						<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 						<Description type=\"string-(256)\" Writable=\"1\">jk</Description>" \
" 						<CreationDate type=\"dateTime\" Writable=\"0\">9999-12-31T23:59:59Z</CreationDate>" \
" 						<ExpiryDate type=\"dateTime\" Writable=\"1\">9999-12-31T23:59:59Z</ExpiryDate>" \
" 						<DestIP type=\"string-(45)\" Writable=\"1\">Empty</DestIP>" \
" 						<SourceIP type=\"string-(45)\" Writable=\"1\">Empty</SourceIP>" \
" 						<Protocol type=\"int-[-1:255]\" Writable=\"1\">-1</Protocol>" \
" 						<DestPort type=\"int-[-1:65535]\" Writable=\"1\">-1</DestPort>" \
" 						<DestPortRangeMax type=\"int-[-1:65535]\" Writable=\"0\">-1</DestPortRangeMax>" \
"						<X_HUMAX_URL type=\"string-(256)\" Writable=\"1\">Empty</X_HUMAX_URL>" \
" 						<X_HUMAX_SourceMACAddress type=\"string-(256)\" Writable=\"1\">Empty</X_HUMAX_SourceMACAddress>" \
" 					</i>" \
" 				</Rule>" \
" 			</1>" \
"			<2 type=\"object\" Writable=\"1\" tid=\"setting/cwmp_Firewall_Mac\" time=\"0000-00-00T00:00:00+08:00\">" \
"				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"				<Name type=\"string-(64)\" Writable=\"1\">jk</Name>" \
"				<RuleNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"\">0</RuleNumberOfEntries>" \
"				<Rule type=\"object\" Writable=\"1\">" \
"					<i type=\"object\" Writable=\"1\">" \
"						<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
"						<Description type=\"string-(256)\" Writable=\"1\">jk</Description>" \
"						<CreationDate type=\"dateTime\" Writable=\"0\">9999-12-31T23:59:59Z</CreationDate>" \
"						<ExpiryDate type=\"dateTime\" Writable=\"1\">9999-12-31T23:59:59Z</ExpiryDate>" \
"						<DestIP type=\"string-(45)\" Writable=\"1\">Empty</DestIP>" \
"						<SourceIP type=\"string-(45)\" Writable=\"1\">Empty</SourceIP>" \
"						<Protocol type=\"int-[-1:255]\" Writable=\"1\">-1</Protocol>" \
"						<DestPort type=\"int-[-1:65535]\" Writable=\"1\">-1</DestPort>" \
"						<DestPortRangeMax type=\"int-[-1:65535]\" Writable=\"1\">-1</DestPortRangeMax>" \
"						<X_HUMAX_URL type=\"string-(256)\" Writable=\"1\">Empty</X_HUMAX_URL>" \
"						<X_HUMAX_SourceMACAddress type=\"string-(256)\" Writable=\"1\">Empty</X_HUMAX_SourceMACAddress>" \
"					</i>" \
"				</Rule>" \
"			</2>" \
"			<3 type=\"object\" Writable=\"1\" tid=\"setting/cwmp_Firewall_Url\" time=\"0000-00-00T00:00:00+08:00\">" \
"				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"				<Name type=\"string-(64)\" Writable=\"1\">jk</Name>" \
"				<RuleNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"\">0</RuleNumberOfEntries>" \
"				<Rule type=\"object\" Writable=\"1\">" \
"					<i type=\"object\" Writable=\"1\">" \
"						<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
"						<Description type=\"string-(256)\" Writable=\"1\">jk</Description>" \
"						<CreationDate type=\"dateTime\" Writable=\"0\">9999-12-31T23:59:59Z</CreationDate>" \
"						<ExpiryDate type=\"dateTime\" Writable=\"1\">9999-12-31T23:59:59Z</ExpiryDate>" \
"						<DestIP type=\"string-(45)\" Writable=\"1\">Empty</DestIP>" \
"						<SourceIP type=\"string-(45)\" Writable=\"1\">Empty</SourceIP>" \
"						<Protocol type=\"int-[-1:255]\" Writable=\"1\">-1</Protocol>" \
"						<DestPort type=\"int-[-1:65535]\" Writable=\"1\">-1</DestPort>" \
"						<DestPortRangeMax type=\"int-[-1:65535]\" Writable=\"1\">-1</DestPortRangeMax>" \
"						<X_HUMAX_URL type=\"string-(256)\" Writable=\"1\">Empty</X_HUMAX_URL>" \
"						<X_HUMAX_SourceMACAddress type=\"string-(256)\" Writable=\"1\">Empty</X_HUMAX_SourceMACAddress>" \
"					</i>" \
"				</Rule>" \
"			</3>" \
" 		</Chain>" \
" 	</Firewall>" \

#define DM_DYNAMICDNS \
" 	<DynamicDNS type=\"object\" Writable=\"0\" tid=\"setting/cwmp_DynamicDNS\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<ClientNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</ClientNumberOfEntries>" \
" 		<ServerNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</ServerNumberOfEntries>" \
" 		<Client type=\"object\" Writable=\"1\">" \
" 			<1 type=\"object\" Writable=\"1\">" \
" 				<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
" 				<Status type=\"string\" Writable=\"0\">Disabled</Status>" \
" 				<Server type=\"string-(256)\" Writable=\"1\">ls</Server>" \
" 				<Interface type=\"string-(256)\" Writable=\"0\">eth0</Interface>" \
" 				<Username type=\"string-(256)\" Writable=\"1\">jk</Username>" \
" 				<Password type=\"string-(256)\" Writable=\"1\">jk</Password>" \
" 				<HostnameNumberOfEntries type=\"unsignedInt\" Writable=\"0\">0</HostnameNumberOfEntries>" \
" 				<Hostname type=\"object\" Writable=\"1\">" \
" 					<1 type=\"object\" Writable=\"1\">" \
" 						<Enable type=\"boolean\" Writable=\"0\">FALSE</Enable>" \
" 						<Name type=\"string-(256)\" Writable=\"1\">jk</Name>" \
" 					</1>" \
" 				</Hostname>" \
" 			</1>" \
" 		</Client>" \
" 		<Server type=\"object\" Writable=\"1\">" \
" 			<1 type=\"object\" Writable=\"1\">" \
" 				<Name type=\"string-(64)\" Writable=\"1\">jk</Name>" \
" 				<ServerAddress type=\"string-(256)\" Writable=\"1\">jk</ServerAddress>" \
" 			</1>" \
" 			<2 type=\"object\" Writable=\"1\">" \
" 				<Name type=\"string-(64)\" Writable=\"1\">jk</Name>" \
" 				<ServerAddress type=\"string-(256)\" Writable=\"1\">jk</ServerAddress>" \
" 			</2>" \
" 			<3 type=\"object\" Writable=\"1\">" \
" 				<Name type=\"string-(64)\" Writable=\"1\">jk</Name>" \
" 				<ServerAddress type=\"string-(256)\" Writable=\"1\">jk</ServerAddress>" \
" 			</3>" \
" 		</Server>" \
" 	</DynamicDNS>" \

#define DM_X_HUMAX_CURRENTNETWORK \
" 	<X_HUMAX_CurrentNetwork type=\"object\" Writable=\"0\" tid=\"setting/cwmp_X_HUMAX_CurrentNetwork\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<RouterMode type=\"string-(64)\" Writable=\"1\">Router</RouterMode>" \
" 		<WanIPType type=\"string-(64)\" Writable=\"0\">DynamicIP</WanIPType>" \
" 		<WanIPInterface type=\"string-(256)\" Writable=\"0\">0.0.0.0</WanIPInterface>" \
" 	</X_HUMAX_CurrentNetwork>" \

#define DM_X_HUMAX_WIRELESSSCHEDULE \
" 	<X_HUMAX_WirelessSchedule type=\"object\" Writable=\"0\" tid=\"setting/cwmp_X_HUMAX_WirelessSchedule\" time=\"0000-00-00T00:00:00+08:00\">" \
" 		<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"		<RuleNumberOfEntries mode=\"auto\" type=\"unsignedInt\" Writable=\"\">0</RuleNumberOfEntries>" \
"		<Rule type=\"object\" Writable=\"1\">" \
"			<i type=\"object\" Writable=\"1\">" \
"			<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"			<DayOfWeek type=\"string-(256)\" Writable=\"1\">SUN</DayOfWeek>" \
"			<StartTime type=\"string-(256)\" Writable=\"1\">21:00</StartTime>" \
"			<Duration type=\"string-(256)\" Writable=\"1\">21</Duration>" \
"			</i>" \
"		</Rule>" \
" 	</X_HUMAX_WirelessSchedule>" \

#define X_HUMAX_REBOOTSCHEDULE \
" 	<X_HUMAX_RebootSchedule type=\"object\" Writable=\"0\" tid=\"setting/cwmp_X_HUMAX_RebootSchedule\" time=\"0000-00-00T00:00:00+08:00\">" \
"		<Enable type=\"boolean\" Writable=\"1\">FALSE</Enable>" \
"		<DayOfWeek type=\"string-(256)\" Writable=\"1\">Weekday</DayOfWeek>" \
"		<Time type=\"string-(256)\" Writable=\"1\">21:00</Time>" \
"	</X_HUMAX_RebootSchedule>" \

#if 0 //all
#define XMLDATAMODEL \
	" <Device type=\"object\" Writable=\"0\">" \
	DM_SERVICES \
	DM_DEVICEINFO \
	DM_MANAGEMENTERVER \
	DM_TIME \
	DM_USERINTERFACE \
	DM_ETHERNET \
	DM_USB \
	DM_WIFI \
	DM_PPP \
	DM_IP \
	DM_ROUTING \
	DM_HOSTS \
	DM_DNS \
	DM_NAT \
	DM_DHCPV4 \
	DM_DHCPV6 \
	DM_USERS \
	DM_UPNP \
	DM_FIREWALL \
	DM_DYNAMICDNS \
	DM_X_HUMAX_CURRENTNETWORK \
	DM_X_HUMAX_WIRELESSSCHEDULE \
	X_HUMAX_REBOOTSCHEDULE \
	" </Device>"

#else //support part

#define XMLDATAMODEL \
	" <Device type=\"object\" Writable=\"0\">" \
	DM_DEVICEINFO \
	DM_MANAGEMENTERVER \
	DM_TIME \
	DM_USERINTERFACE \
	DM_ETHERNET \
	DM_USB \
	DM_WIFI \
	DM_PPP \
	DM_IP \
	DM_HOSTS \
	DM_DNS \
	DM_NAT \
	DM_DHCPV4 \
	DM_DHCPV6 \
	DM_USERS \
	DM_UPNP \
	DM_FIREWALL \
	DM_DYNAMICDNS \
	DM_X_HUMAX_CURRENTNETWORK \
	DM_X_HUMAX_WIRELESSSCHEDULE \
	X_HUMAX_REBOOTSCHEDULE \
	" </Device>"
#endif

int easycwmp(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_config_local(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_config_acs(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_DeviceInfo(struct mosquitto *mosq, cJSON* data, char *tp);
int	cwmp_ManagementServer(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_Timing(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_UserInterface(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_Ethernet(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_USB(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_DynamicDNS(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_DHCPv4(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_DHCPv6(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_Users(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_UPnP(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_Firewall(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_NAT(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_DNS(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_Hosts(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_PPP(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_wifi_basic(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_wifi_scan(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_wifi_multilssid(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_wifi_accsspoint(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_IP(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_Routing(struct mosquitto *mosq, cJSON* data, char *tp);
int cwmp_X_HUMAX_CurrentNetwork(struct mosquitto *mosq, cJSON* data, char *tp);
