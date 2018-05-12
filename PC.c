#include"route.h"

extern routetable route_table[MAX_ROUTE_TABLES];
extern arptable arp_table[MAX_ARP_TABLES];
extern devicetable device_table[MAX_DEVICE_TABLES];
extern iptable ip_table[MAX_IP_TABLES];
extern int num_of_route;
extern int num_of_arp;
extern int num_of_device;
extern int num_of_ip;

void init_route_table()
{//初始化路由表
	FILE* readfile = fopen("route.txt","r");
	if(readfile==NULL)
	{
		dowitherror(FICT_ERROR,0);
		exit(0);
	}
	uint8_t tmp[MAX_BUFF];
	int i,j,m=0;
	uint8_t temp;
	printf("Read file \"route.txt\"\n");
	while(fgets(tmp,MAX_BUFF,readfile))//读取一行文件，最后一个字符为换行符或者文件结束符
	{
		for(i=0,j=0;i<MAX_BUFF;i++)
		{
			if(tmp[i]!=' ')
				route_table[m].dst[j]=tmp[i];
			else
			{
				route_table[m].dst[j]='\0';
				break;
			}
		}
		for(i++,j=0,temp=0;i<MAX_BUFF;i++)
		{
			if(tmp[i]!=' '&&tmp[i]!='.')
				temp=temp*10+tmp[i]-'0';
			else if(tmp[i]=='.')
			{
				route_table[m].gtw[j++]=temp;
				temp=0;
			}
			else
			{
				route_table[m].gtw[j++]=temp;
				route_table[m].gtw[j]='\0';
				break;
			}
		}
		for(i++,j=0,temp=0;i<MAX_BUFF;i++)
		{
			if(tmp[i]!=' '&&tmp[i]!='.')
				temp=temp*10+tmp[i]-'0';
			else if(tmp[i]=='.')
			{
				route_table[m].ntm[j++]=temp;
				temp=0;
			}
			else
			{
				route_table[m].ntm[j++]=temp;
				route_table[m].ntm[j]='\0';
				break;
			}
		}
		for(i++,j=0;i<MAX_BUFF;i++,j++)
		{
			if(tmp[i]!='\n'&&tmp[i]!='\0')
				route_table[m].itf[j]=tmp[i];
			else
			{
				route_table[m].itf[j]='\0';
				break;
			}
		}
		m++;
	}
	num_of_route=m;
	fclose(readfile);
	printf("Read file \"route.txt\" successfully!\n");
}

void init_ip_table()
{//初始化ip表
//需要修改
	FILE* readfile=fopen("ip.txt","r");
	if(readfile==NULL)
	{
		dowitherror(FICT_ERROR,1);
		exit(0);
	}
	uint8_t tmp[MAX_BUFF];
	int i,j,m=0;
	uint8_t temp;
	printf("Read file \"ip.txt\"\n");
	while(fgets(tmp,MAX_BUFF,readfile))//读取一行文件，最后一个字符为换行符或字符串结束符
	{
		for(i=0,j=0,temp=0;i<MAX_BUFF;i++)
		{
			if(tmp[i]!=' '&&tmp[i]!='.')
				temp=temp*10+tmp[i]-'0';
			else if(tmp[i]=='.')
			{
				ip_table[m].ipaddr[j++]=temp;
				temp=0;
			}
			else
			{//tmp[i]==' '
				ip_table[m].ipaddr[j++]=temp;
				ip_table[m].ipaddr[j]='\0';
				break;
			}
		}
		for(i++,j=0;i<MAX_BUFF;i++,j++)
		{
			if(tmp[i]!='\n'&&tmp[i]!='\0')
				ip_table[m].itf[j]=tmp[i];
			else
			{
				ip_table[m].itf[j]='\0';
				break;
			}
		}
		m++;
	}
	num_of_ip=m;
	fclose(readfile);
	printf("Read file \"ip.txt\" successfully!\n");
}

void init_device_table()
{//初始化网卡对应的mac地址信息
	//eth0
	uint8_t* if_name="eth0";
	memcpy(device_table[0].itf,if_name,4);
	device_table[0].itf[4]='\0';
	struct ifreq req;
	memset(&req,0,sizeof(struct ifreq));
	memcpy(req.ifr_name,if_name,4);
	int sockfd=socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
	ioctl(sockfd,SIOCGIFINDEX,&req);
	device_table[0].ifindex=req.ifr_ifindex;
	ioctl(sockfd,SIOCGIFHWADDR,&req);
	memcpy(device_table[0].macaddr,req.ifr_hwaddr.sa_data,ETH_ALEN);
	
	//eth1
	/*if_name="eth1";
	memcpy(device_table[1].itf,if_name,4);
	device_table[1].itf[4]='\0';
	memset(&req,0,sizeof(struct ifreq));
	memcpy(req.ifr_name,if_name,4);
	ioctl(sockfd,SIOCGIFINDEX,&req);
	device_table[1].ifindex=req.ifr_ifindex;
	ioctl(sockfd,SIOCGIFHWADDR,&req);
	memcpy(device_table[1].macaddr,req.ifr_hwaddr.sa_data,ETH_ALEN);
	num_of_device=2;*/
	
	//close socket
	close(sockfd);
}

/*int ifdest(uint8_t* eth_header)
{//根据eth_header判断数据包的目的mac地址是不是本机mac地址
//在设备表中查找有没有对应的mac地址项
	uint8_t dst_mac[8];
	memcpy(dst_mac,((struct ether_header*)(eth_header))->ether_dhost,6);
	dst_mac[6]='\0';
	int i;
	for(i=0;i<num_of_device;i++)
	{
		if(strcmp(device_table[i].macaddr,dst_mac)==0)
			return i;//返回数据包的目的mac地址对应的网卡号
	}
	//如果是广播帧则返回-1，如果不是广播帧返回-2
	if(dst_mac[0]==255&&dst_mac[1]==255&&dst_mac[2]==255&&dst_mac[3]==255&&dst_mac[4]==255&&dst_mac[5]==255)
		return -1;
	return NOT_DEST;
}*/

int ifmyown(uint8_t* eth_header)
{//判断是否是自己发出的包被自己收到
//源mac地址是不是自己
	uint8_t src_mac[8];
	memcpy(src_mac,((struct ether_header*)(eth_header))->ether_shost,6);
	src_mac[6]='\0';
	int i;
	for(i=0;i<num_of_device;i++)
	{
		if(strcmp(src_mac,device_table[i].macaddr)==0)
			return OWN_SENT;
	}
	return 0;
}

uint16_t checksum(uint16_t* buffer, int n)
{//计算校验和
	uint32_t sum = 0;
	while(n > 1)
	{
		sum += *buffer;
		buffer++;
		n -= 2;
	}
	if(n == 1)
		sum += *((uint8_t*)buffer);
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	sum = ~sum;
	return sum;
}

/*void dowithdst(int sockfd, uint8_t* eth_header, int num)
{//目的地址是本机第num个网卡
//根据三层包类型进行相应处理
	//有可能是本机发送或接收的数据包
	
	//三层包可能是arp回应，可能是ip包
	uint16_t type=*(uint16_t*)(eth_header+12);
	type=ntohs(type);
	switch(type)
	{
		case 0x0800: break;
		case 0x0806:
		//arp回应，将源ip地址和源mac地址的对应关系添加到arp表中
		addarp((eth_arp*)(eth_header+14));
		return;
		default:
		printf("to complete packet type\n");
		return;
	}
	//三层是ip包
	//如果目的ip地址跟自己在同一网段，则在arp表中查找目的ip地址的mac地址
	//如果在不同网段，则在路由表中查找目的网段所对应的网关，在arp表中查找网关的mac地址
	//如果没有对应的mac地址，则发送arp请求mac地址
	struct iphdr* ip_header=(struct iphdr*)(eth_header+14);
	uint8_t dst_ip[8];
	uint8_t src_ip[8];
	memcpy(dst_ip,(uint8_t*)&(ip_header->daddr),4);
	dst_ip[4]='\0';
	memcpy(src_ip,(uint8_t*)&(ip_header->saddr),4);
	src_ip[4]='\0';
	if(src_ip[0]==dst_ip[0]&&src_ip[1]==dst_ip[1]&&src_ip[2]==dst_ip[2])
	{
		printf("dst and src are in the same net\n");
		return;
	}
	int i,j;
	for(i=0;i<num_of_ip;i++)
	{//在ip表中查找自己的ip地址
		if(strcmp(dst_ip,ip_table[i].ipaddr)==0)//如果目标地址是自己，暂时不做回应
			return;
	}
	bool ifinsamenet=false;
	int route_num;
	uint8_t dsttmp[8];
	for(j=0;j<3;j++)
		dsttmp[j]=dst_ip[j];
	dsttmp[3]='\0';
	for(i=0;i<num_of_ip;i++)
	{
		if(strcmp(dsttmp,route_table[i].dst)==0)
		{
			route_num=i;
			if(route_table[i].gtw[0]=='*')
			{
				ifinsamenet=true;
				break;
			}
			break;
		}
	}
	if(!ifinsamenet)
	{//在不同网段，在路由表第route_num个表项中查找网关ip,将dst_ip更新为网关ip
		//根据dsttmp查找网关
		memcpy(dst_ip,route_table[route_num].gtw,4);
		dst_ip[4]='\0';
	}
	//在arp表中查找dst_ip的mac地址
	uint8_t dst_mac[8];
	dst_mac[0]='\0';
	for(i=0;i<num_of_arp;i++)
	{
		if(strcmp(dst_ip,arp_table[i].ipaddr)==0)
		{
			memcpy(dst_mac,arp_table[i].macaddr,6);
			dst_mac[6]='\0';
			break;
		}
	}
	//如果arp中无缓存，发送arp请求
	uint8_t device[8];  //从哪个网卡发出
	uint8_t sent_ip[8]; //以哪个ip发出，用于arp请求
	uint8_t sent_mac[8];//以哪个mac地址发出
	
	memcpy(device,route_table[route_num].itf,4);
	device[4]='\0';
	for(i=0;i<num_of_ip;i++)
	{
		if(strcmp(device,ip_table[i].itf)==0)
		{
			memcpy(sent_ip,ip_table[i].ipaddr,4);
			sent_ip[4]='\0';
			break;
		}
	}
	int device_num;
	for(i=0;i<num_of_device;i++)
	{
		if(strcmp(device,device_table[i].itf)==0)
		{
			memcpy(sent_mac,device_table[i].macaddr,6);
			sent_mac[6]='\0';
			device_num=i;
			break;
		}
	}
	//arp缓存中无对应的mac地址，发送arp请求
	if(dst_mac[0]=='\0')
	{
		uint8_t recv_eth[MAX_BUFFER];
		sendarp(sockfd,sent_ip,dst_ip,1);
		uint8_t tmpmac[8];
		uint8_t tmpsrcip[8];
		while(true)
		{
			int n=recvfrom(sockfd,recv_eth,MAX_BUFFER,0,NULL,NULL);
			memcpy(tmpmac,recv_eth,6);
			tmpmac[6]='\0';
			uint16_t type=*(uint16_t*)(recv_eth+12);
			type=ntohs(type);
			if(strcmp(tmpmac,sent_mac)==0&&type==0x0806)
			{
				memcpy(tmpsrcip,(uint8_t*)&(((eth_arp*)(recv_eth+14))->arp_spa),4);
				if(strcmp(tmpsrcip,dst_ip)!=0)
					continue;
				addarp((eth_arp*)(recv_eth+14));
				memcpy(dst_mac,(recv_eth+6),6);
				dst_mac[6]='\0';
				break;
			}
		}
	}
	//填充以太网帧头部，发送
	ip_header->ttl--;
	ip_header->check=checksum((uint16_t*)(ip_header),sizeof(struct iphdr));
	memcpy(((struct ether_header*)eth_header)->ether_shost,sent_mac,6);
	memcpy(((struct ether_header*)eth_header)->ether_dhost,dst_mac,6);
	struct sockaddr_ll addr;
	addr.sll_family=AF_PACKET;
	addr.sll_halen=ETH_ALEN;
	addr.sll_ifindex=device_table[device_num].ifindex;
	memcpy(addr.sll_addr,sent_mac,6);
	int n=sendto(sockfd,eth_header,MAX_BUFFER,0,(struct sockaddr*)&addr,sizeof(struct sockaddr_ll));
	if(n<0)
		dowitherror(SEND_ERROR,0);
}*/

void addarp(eth_arp* arp_header)
{//将发送端ip地址和发送端mac地址的对应关系添加到arp缓存中
	//也可能会添加自己的ip地址和mac地址...
	int i;
	char src_ip[8];
	memcpy(src_ip,(uint8_t*)&(arp_header->arp_spa),4);
	src_ip[4]='\0';
	for(i=0;i<num_of_arp;i++)
	{
		if(strcmp(arp_table[i].ipaddr,src_ip)==0)
			break;
	}
	if(i==num_of_arp)
	{
		memcpy(arp_table[num_of_arp].ipaddr,src_ip,4);
		arp_table[num_of_arp].ipaddr[4]='\0';
		memcpy(arp_table[num_of_arp].macaddr,arp_header->arp_sha,6);
		arp_table[num_of_arp].macaddr[6]='\0';
		num_of_arp++;
	}
}

void sendarp(int sockfd, char src_ip[8], char dst_ip[8], int flag)
{//发送arp请求或回应，flag=1表示arp请求，flag=2表示arp回应
	//构造以太网包头
	//同一个网段内的arp报文，回应报文直接发给目的主机
	char buff[ETH_ARP_LEN];
	struct ether_header* eth_header=(struct ether_header*)buff;
	eth_arp* arp_header=(eth_arp*)(buff+sizeof(struct ether_header));
	//通用包内容
	eth_header->ether_type=htons(ETHERTYPE_ARP);
	
	arp_header->arp_hrd=htons(ARPHRD_ETHER);
	arp_header->arp_pro=htons(ETHERTYPE_IP);
	arp_header->arp_hln=ETH_ALEN;
	arp_header->arp_pln=IP_ALEN;
	arp_header->arp_op=htons(flag);
	memcpy((uint8_t*)&(arp_header->arp_spa),src_ip,4);
	memcpy((uint8_t*)&(arp_header->arp_tpa),dst_ip,4);
	//search src mac addr
	int i,j;
	char src_mac[8];
	char dst_mac[8];
	int device;
	uint8_t src_device[8];
	//在ip表中查找
	for(i=0;i<num_of_ip;i++)
	{
		if(strcmp(src_ip,ip_table[i].ipaddr)==0)
		{
			memcpy(src_device,ip_table[i].itf,4);
			src_device[4]='\0';
			//再在设备表中找到mac地址
			for(j=0;j<num_of_device;j++)
			{
				if(strcmp(device_table[j].itf,src_device)==0)
				{
					memcpy(src_mac,device_table[j].macaddr,6);
					src_mac[6]='\0';
					device=j;
					break;
				}
			}
			break;
		}
	}
	if(i==num_of_ip)
	{
		printf("ip: %x:%x:%x:%x\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
		dowitherror(NOF_IP,0);
		return;
	}
	if(j==num_of_device)
	{
		printf("device: %s\n",ip_table[i].itf);
		dowitherror(NOF_MAC,0);
		return;
	}
	memcpy(arp_header->arp_sha,src_mac,6);
	memcpy(eth_header->ether_shost,src_mac,6);
	if(flag==1)
	{//arp请求
		uint8_t mmx[8];
		mmx[0]=mmx[1]=mmx[2]=mmx[3]=mmx[4]=mmx[5]=0xff;
		memcpy(arp_header->arp_tha,mmx,ETH_ALEN);
		memcpy(eth_header->ether_dhost,mmx,ETH_ALEN);
	}
	else
	{//arp回应
		//查找arp表
		for(i=0;i<num_of_arp;i++)
		{
			if(strcmp(dst_ip,arp_table[i].ipaddr)==0)
			{
				memcpy(dst_mac,arp_table[i].macaddr,6);
				dst_mac[6]='\0';
				break;
			}
		}
		if(i==num_of_arp)
		{
			printf("ip: %x:%x:%x:%x\n",dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3]);
			dowitherror(NOF_ARP,0);
			return;
		}
		memcpy(arp_header->arp_tha,dst_mac,ETH_ALEN);
		memcpy(eth_header->ether_dhost,dst_mac,ETH_ALEN);
	}
	struct sockaddr_ll sll;
	bzero(&sll, sizeof(sll));
	sll.sll_ifindex=device_table[j].ifindex;
	sll.sll_family=PF_PACKET;
	sll.sll_halen=ETH_ALEN;
	memcpy(sll.sll_addr,src_mac,ETH_ALEN);
	int n=sendto(sockfd,buff,ETH_ARP_LEN,0,(struct sockaddr*)&sll,sizeof(struct sockaddr_ll));
	if(n<0)
	{
		printf("send arp ");
		dowitherror(SEND_ERROR,0);
	}
}

/*void dowithbroadcast(int sockfd, uint8_t* eth_header)
{//收到广播请求
	//将源ip地址和mac地址的对应关系加入到arp缓存中
	//首先看目的ip地址是不是自己，如果是自己且跟自己在同一个网段内则回复一个arp回复包
	//如果目的ip地址不是自己，或在不同网段则忽略
	
	//将收到的包ip地址和mac地址的对应关系添加到arp缓存中
	eth_arp* arp_header=(eth_arp*)(eth_header+14);
	addarp(arp_header);
	char dst_ip[8];
	char src_ip[8];
	memcpy(dst_ip,(uint8_t*)&(arp_header->arp_tpa),4);
	dst_ip[4]='\0';
	memcpy(src_ip,(uint8_t*)&(arp_header->arp_spa),4);
	src_ip[4]='\0';
	int i;
	//看目的ip地址是不是自己，且跟自己是否是同一网段
	//如果不是，则丢弃包
	for(i=0;i<num_of_ip;i++)
	{
		if(strcmp(dst_ip,ip_table[i].ipaddr)==0)
		{//目的ip地址是自己
			if(src_ip[0]==dst_ip[0]&&src_ip[1]==dst_ip[1]&&dst_ip[2]==src_ip[2])
			{//跟自己在同一网段
				sendarp(sockfd,dst_ip,src_ip,2);
				break;
			}
			break;
		}
	}
}*/

void dowitherror(int errornum, int loc)
{//错误号
	switch(errornum)
	{
		case FICT_ERROR:
		printf("error while opening file ");
		if(loc==0)
			printf("\"route.txt\"\n");
		else
			printf("\"ip.txt\"\n");
		break;
		case SOCK_ERROR:
		printf("creating socket error "); break;
		if(loc==0)
			printf("in do_work()\n");
		else if(loc==1)
			
		case SEND_ERROR:
		printf("send packet error\n"); break;
		case NOF_ARP:
		printf("cannot find ip addr and corresponding mac addr in arp table\n"); break;
		case NOF_IP:
		printf("cannot find ip addr in ip table\n"); break;
		case NOF_MAC:
		printf("cannot find mac addr in device table\n"); break;
		//case OWN_SENT:
		//printf("Frame packet is from myself\n"); break;
		case NOT_DEST:
		printf("Frame packet's destination is not local mac address \n");
		if(loc==0)
			printf("in do_work()\n");
		break;
	}
	//exit(0);
}

void sendicmp(int sockfd,uint8_t dst_ip[8],uint8_t dst_mac[8])
{//ping 5 次
	uint8_t src_ip[8];
	uint8_t src_mac[8];
	uint8_t send_buff[MAX_BUFFER];
	memset(send_buff,0,MAX_BUFFER);
	struct ether_header* eth_header=send_buff;
	memcpy(src_ip,ip_table[0].ipaddr,4);
	src_ip[4]='\0';
	memcpy(src_mac,device_table[0].macaddr,6);
	src_mac[6]='\0';
	memcpy(eth_header->ether_dhost,dst_mac,6);
	memcpy(eth_header->ether_shost,src_mac,6);
	eth_header->ether_type=htons(0x0800);
	struct iphdr* ip_header=(struct iphdr*)(send_buff+14);
	ip_header->version=4;
	ip_header->ihl=5;
	ip_header->tot_len=htons(sizeof(struct iphdr)+sizeof(struct icmphdr));
	ip_header->ttl=10;
	ip_header->protocol=IPPROTO_ICMP;
	memcpy((uint8_t*)&(ip_header->saddr),ip_table[0].ipaddr,4);
	memcpy((uint8_t*)&(ip_header->daddr),dst_ip,4);


	static id=1;
	struct icmphdr* icmp_header=(struct icmphdr*)(((uint8_t*)ip_header)+20);
	int i;
	icmp_header->code=0;
	icmp_header->type=ICMP_ECHO;
	icmp_header->un.echo.id=htons(getpid());
	uint8_t recv_buff[MAX_BUFFER];
	struct sockaddr_ll sa;
	sa.sll_family=AF_PACKET;
	sa.sll_halen=ETH_ALEN;
	sa.sll_ifindex=device_table[0].ifindex;
	memcpy(sa.sll_addr,device_table[0].macaddr,ETH_ALEN);
	for(i=1;i<=5;i++)
	{
		ip_header->id=id;
		id++;
		ip_header->check=0;
		icmp_header->un.echo.sequence=i;
		icmp_header->checksum=0;
		icmp_header->checksum=checksum((uint8_t*)icmp_header,sizeof(struct icmphdr));
		ip_header->check=checksum((uint8_t*)ip_header,sizeof(struct iphdr)+sizeof(struct icmphdr));
		int n=sendto(sockfd,(uint8_t*)eth_header,60,0,(struct sockaddr*)&sa,sizeof(struct sockaddr));
		if(n>0)
			printf("send successfully\n");
		else
		{
			printf("send error\n");
			continue;
		}
		while(true)
		{
			recvfrom(sockfd,recv_buff,MAX_BUFFER,0,NULL,NULL);
			if(ifmyown(recv_buff)==OWN_SENT)
				continue;
			uint16_t type=*(uint16_t*)(recv_buff+12);
			type=ntohs(type);
			uint8_t recv_src_ip[8];
			uint8_t recv_dst_ip[8];
			if(type==0x0800)
			{
				memcpy(recv_src_ip,(uint8_t*)&(((struct iphdr*)(recv_buff+14))->saddr),4);
				memcpy(recv_dst_ip,(uint8_t*)&(((struct iphdr*)(recv_buff+14))->daddr),4);
				recv_src_ip[4]=recv_dst_ip[4]='\0';
				if(strcmp(recv_src_ip,dst_ip)==0&&strcmp(recv_dst_ip,ip_table[0].ipaddr)==0&&((struct icmphdr*)(recv_buff+34))->type==ICMP_ECHOREPLY)
					break;
			}
		}
		printf("receive icmp reply\n");
	}

}

void do_work(uint8_t* argv)
{//首先将dst_ip转换成4个字节的表示
	//查询网关的mac地址
	int sockfd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sockfd<0)
	{
		dowitherror(SOCK_ERROR,0);
		exit(0);
	}
	int n_read;
	uint8_t buffer[MAX_BUFFER];
	struct ether_header* eth_header=(struct ether_header*)buffer;
	uint8_t dst_ip[8];
	uint8_t src_ip[8];
	uint32_t addr=inet_addr(argv);
	memcpy(dst_ip,(uint8_t*)&addr,4);
	dst_ip[4]='\0';
	memcpy(src_ip,ip_table[0].ipaddr,4);
	src_ip[4]='\0';
	uint32_t gtw_ip[8];
	memcpy(gtw_ip,route_table[0].gtw,4);
	gtw_ip[4]='\0';
	//在arp缓存中查找是否有网关的mac地址
	int i;
	for(i=0;i<num_of_arp;i++)
	{
		if(strcmp(gtw_ip,arp_table[i].ipaddr)==0)
			break;
	}
	if(i==num_of_arp)
	{//无网关mac地址，发送arp请求报文
		sendarp(sockfd,src_ip,gtw_ip,1);
		uint8_t srctmp[8];
		uint16_t type;
		while(true)
		{
			n_read=recvfrom(sockfd,buffer,MAX_BUFFER,0,NULL,NULL);
			if(ifmyown(eth_header)==OWN_SENT)
				continue;
			type=*(uint16_t*)(eth_header+12);
			type=ntohs(type);
			memcpy(srctmp,(uint8_t*)&(((eth_arp*)(eth_header+14))->arp_spa),4);
			srctmp[4]='\0';
			if(type==0x0806&&strcmp(srctmp,gtw_ip)==0)
			{
				addarp((eth_arp*)(eth_header+14));
				i=num_of_arp-1;
				break;
			}
		}
	}
	uint8_t dst_mac[8];
	memcpy(dst_mac,arp_table[i].macaddr,6);
	dst_mac[6]='\0';
	sendicmp(sockfd,dst_ip,dst_mac);
}

int main(int argc, char* argv[])
{//for a PC
	if(argc<2)
	{
		printf("please input dst ip\n");
		return -1;
	}
	init_route_table();
	init_ip_table();
	init_device_table();
	do_work(argv[1]);
	return 0;
}