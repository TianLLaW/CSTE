#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <signal.h>
	//netlink
#include <sys/socket.h>
	/* Local include files */
#include <time.h>	
#include <string.h>  
#include <errno.h>  
#include <netdb.h>  
	  
#include <sys/types.h>  
	  
#include <netinet/if_ether.h>  
#include <netinet/in.h>  
#include <netpacket/packet.h>	  
#include <arpa/inet.h>  

	/* args: yiaddr - what IP to ping
	*  ip - our ip
	*  mac - our arp address
	*  interface - interface to use
	* retn:  1 addr free
	*  0 addr used
	*  -1 error 
	*/ 
	/* FIXME: match response against chaddr */
struct arpMsg {
	struct ethhdr ethhdr;    /* Ethernet header */
	u_short htype;    /* hardware type (must be ARPHRD_ETHER) */
	u_short ptype;    /* protocol type (must be ETH_P_IP) */
	u_char  hlen;    /* hardware address length (must be 6) */
	u_char  plen;    /* protocol address length (must be 4) */
	u_short operation;   /* ARP opcode */
	u_char  sHaddr[6];   /* sender's hardware address */
	u_char  sInaddr[4];   /* sender's IP address */
	u_char  tHaddr[6];   /* target's hardware address */
	u_char  tInaddr[4];   /* target's IP address */
	u_char  pad[18];   /* pad for min. Ethernet payload (60 bytes) */
};
	/* miscellaneous defines */
#define MAC_BCAST_ADDR  (uint8_t *) "\xff\xff\xff\xff\xff\xff"
#define OPT_CODE 0
#define OPT_LEN 1
#define OPT_DATA 2
struct interface_info
{
	char  ifname[64];
	unsigned char ip[4];
	unsigned char mac[6]; 
}; 
struct interface_info if_info[10];
int eth_num = 0;
void print_mac(unsigned char * mac_addr)
{
	int i=0;
	for ( i =0; i < 6; ++i)
	{
		printf("%02X", mac_addr[i]);
		if (i != 5) printf(":");
	} 
	printf("\n");
} 
void print_ip(unsigned char * ip_addr)
{
	int i=0;
	for ( i =0; i < 4; ++i)
	{
		printf("%d", ip_addr[i]);
		if (i != 3) printf(".");
	} 
	printf("\n");
} 
int get_iface_index(int fd, const char* interface_name)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strcpy (ifr.ifr_name, interface_name);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
	{
		return (-1);
	}
	return ifr.ifr_ifindex;
}
int get_interfaces()
{
	int  sock;
	int  len = 64,i=0;
	int  last_len = 0;
	char  *pBuff = NULL;
	int  interface_num = 0;

	struct ifconf  interface_conf;
	struct ifreq  ifreq1;
	struct sockaddr_in *psockaddr_in = NULL;


	if ( (sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("Could not create socket for geting interface info");
		exit(1);
	}

	while(1)
	{
		pBuff = (char*)malloc(len);
		interface_conf.ifc_len = len;
		interface_conf.ifc_buf = pBuff;
		if (ioctl(sock, SIOCGIFCONF, &interface_conf) < 0)
		{
			perror("ioctl error");
		}
		else
		{
			if (interface_conf.ifc_len == last_len)
			{
				break;
			}
			else
			{
				last_len = interface_conf.ifc_len;    
			}   
		}
		len += 2*sizeof(struct ifreq);
		free(pBuff);       
	}

	interface_num = last_len / sizeof(struct ifreq);

	for (i =0; i < interface_num; ++i)
	{
		strcpy(ifreq1.ifr_name, interface_conf.ifc_ifcu.ifcu_req[i].ifr_name);
		if (strcmp(ifreq1.ifr_name, "lo") == 0)
		{
			continue;
		}    
		if (ioctl(sock, SIOCGIFHWADDR, &ifreq1) < 0)
		{
		continue;   
		}  
		if (strcmp(ifreq1.ifr_name, "br0") == 0)
		{
			memcpy(if_info[eth_num].mac, ifreq1.ifr_hwaddr.sa_data, 6); 
			strcpy(if_info[eth_num].ifname, ifreq1.ifr_name);
			psockaddr_in = (struct sockaddr_in*)&interface_conf.ifc_req[i].ifr_addr;
			memcpy(if_info[eth_num].ip, &(psockaddr_in->sin_addr.s_addr), 4);
			printf("Interface name: %s", if_info[eth_num].ifname);
			printf(" ip address: ");
			print_ip(if_info[eth_num].ip);
			printf(" mac address:");
			print_mac(if_info[eth_num].mac); 
			eth_num++;
		}
	} 

	free(pBuff); 
	close(sock); 
}
int equal_mac(unsigned char* mac1, unsigned char* mac2)
{
	int i=0;
	for (i =0; i < 6; ++i)
	{
		if (mac1[i] != mac2[i]) return 0;
	}
	return 1; 
} 

int main()
{
	int timeout = 2;
	int  optval = 1;
	int s;   /* socket */
	int rv = 1,i = 0;   /* return value */
	struct sockaddr addr;  /* for interface name */
	struct arpMsg arp;
	struct arpMsg *parp;

	fd_set  fdset;
	struct timeval tm;
	time_t  prevTime;
	u_int32_t  ip;
	u_int32_t  yiaddr;
	struct in_addr my_ip;
	struct in_addr dst_ip;
	char  buff[2000];
	int nLen;
	char szBuffer[4096];

	if ((s = socket (PF_PACKET, SOCK_PACKET, htons(ETH_P_RARP))) == -1) 
	{
		printf("Could not open raw socket\n");
		return -1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) == -1) 
	{
		printf("Could not setsocketopt on raw socket\n");
		close(s);
		return -1;
	} 

	memset(&addr, 0, sizeof(addr));
	strcpy(addr.sa_data, "br0");

	get_interfaces();

	memset(szBuffer, 0, sizeof(szBuffer));        
	while ((nLen = recvfrom(s, szBuffer, sizeof(szBuffer), MSG_TRUNC, NULL, NULL)) > 0)
	{
		parp = (struct arpMsg*)szBuffer;
		printf("The request is from ");
		print_ip(parp->sInaddr);
		for (i = 0; i < eth_num; ++i)
		{
			printf("[%d]\n",eth_num);
			
			printf("parp->sHaddr: [%x][%x][%x][%x][%x][%x]\n",
				if_info[i].mac[0],if_info[i].mac[1],if_info[i].mac[2],if_info[i].mac[3],if_info[i].mac[4],if_info[i].mac[5]);
			
			printf("tHaddr [%x][%x][%x][%x][%x][%x]\n",
				parp->tHaddr[0],parp->tHaddr[1],parp->tHaddr[2],parp->tHaddr[3],parp->tHaddr[4],parp->tHaddr[5]);
			if (equal_mac(if_info[i].mac, parp->tHaddr))
			{


				/* send arp request */
				memset(&arp, 0, sizeof(arp));
				memcpy(arp.ethhdr.h_dest, parp->sHaddr, 6); // MAC DA
				memcpy(arp.ethhdr.h_source, parp->tHaddr, 6); // MAC SA
				arp.ethhdr.h_proto = htons(ETH_P_RARP);  // protocol type (Ethernet)
				arp.htype = htons(ARPHRD_ETHER);  // hardware type
				arp.ptype = htons(ETH_P_IP);   // protocol type (ARP message)
				arp.hlen = 6;     // hardware address length
				arp.plen = 4;     // protocol address length
				arp.operation = htons(4);   // RARP reply code
				memcpy(arp.sInaddr, if_info[i].ip, 4); // source IP address 
				memcpy(arp.sHaddr, parp->tHaddr, 6);  // source hardware address
				memcpy(arp.tInaddr, parp->sInaddr, 4);  // target IP address
				memcpy(arp.tHaddr, parp->sHaddr, 6);

				if (sendto(s, &arp, sizeof(arp), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0)
				{
					perror("Unabele to send arp request");
					return 0;  
				}
				else
					printf("send reply\n"); 
			}
		}   
	}
	close(s);
	return 0;
}


