#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<net/ethernet.h>
#include<net/if_arp.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<linux/if_packet.h>



#define MAX_ROUTE_TABLES 4
#define MAX_ARP_TABLES 10
#define MAX_DEVICE_TABLES 2
#define MAX_IP_TABLES 2

#define IP_ALEN 4
#define NET_MASK 8
#define IP_ADDR 8
#define ETH_INDEX 8
#define MAX_BUFF 64
#define MAX_BUFFER 2048
#define ETH_ARP_LEN (sizeof(struct ether_header)+sizeof(struct arphdr))

#define NOT_DEST -2
#define OWN_SENT -3
#define NOF_MAC -4
#define NOF_IP -5
#define NOF_ARP -6
#define SEND_ERROR -7
#define SOCK_ERROR -8
#define FICT_ERROR -9

#define false 0
#define true 1


typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;


typedef int bool;


typedef struct
{//PC的路由表中只有默认default
	uint8_t dst[IP_ADDR]; //"default"
	uint8_t gtw[IP_ADDR];  //四个字节，网关ip地址
	uint8_t ntm[NET_MASK]; //子网掩码，四个字节
	uint8_t itf[ETH_INDEX]; //设备
}routetable;
routetable route_table[MAX_ROUTE_TABLES];
int num_of_route=0;

typedef struct
{
	uint8_t ipaddr[IP_ADDR];   //四个字节
	uint8_t macaddr[IP_ADDR]; //六个字节的mac地址
}arptable;
arptable arp_table[MAX_ARP_TABLES];
int num_of_arp=0;

typedef struct
{
	uint8_t itf[ETH_INDEX];    //四个字节，eth*
	uint8_t macaddr[IP_ADDR];//6字节mac地址
	int ifindex;
}devicetable;
devicetable device_table[MAX_DEVICE_TABLES];
int num_of_device=0;

typedef struct
{
	uint8_t ipaddr[IP_ADDR];//四个字节
	uint8_t itf[ETH_INDEX]; //四个字节 eth*
}iptable;
iptable ip_table[MAX_IP_TABLES];
int num_of_ip=0;

typedef struct
{
	uint16_t arp_hrd;
	uint16_t arp_pro;
	uint8_t arp_hln;
	uint8_t arp_pln;
	uint16_t arp_op;
	uint8_t arp_sha[ETH_ALEN];
	uint8_t arp_spa[IP_ALEN];
	uint8_t arp_tha[ETH_ALEN];
	uint8_t arp_tpa[IP_ALEN];
}eth_arp;

void init_route_table();
void init_ip_table();
void init_device_table();
int ifdest(uint8_t* eth_header);
int ifmyown(uint8_t* eth_header);
uint16_t checksum(uint16_t* buffer, int n);
void dowithdst(int sockfd, uint8_t* eth_header, int num);
void addarp(eth_arp* arp_header);
void sendarp(int sockfd, char src_ip[8], char dst_ip[8], int flag);
void dowithbroadcast(int sockfd, uint8_t* eth_header);
void dowitherror(int errornum, int loc);
void do_work();
void sendicmp(int sockfd,struct sockaddr* sa);