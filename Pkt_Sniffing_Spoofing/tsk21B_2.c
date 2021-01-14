#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct eth_header
{
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short eth_type;
}eth_header;
eth_header *ethernet;


typedef struct ip_header{	
	char version:4; //version&header_len
	char tos;	
	unsigned short totalen;	
	unsigned short ident;	
	unsigned short flags;//flags&displacement	
	unsigned char ttl;	
	unsigned char protocol;	
	unsigned short checksum;	
	unsigned int sourceIP;
	unsigned int destIP;	
	
}ip_header;
ip_header *ip;


typedef struct tcp_header
{
	unsigned short sport;
	unsigned short dport;
	unsigned int seq;
	unsigned int ack;
	unsigned char head_len;
	unsigned char flags;
	unsigned short wind_size;
	unsigned short check_sum;
	unsigned short urg_ptr;
}tcp_header;
tcp_header *tcp;

typedef struct udp_header
{
	unsigned short sport;
	unsigned short dport;
	unsigned short tot_len;
	unsigned short check_sum;
}udp_header;
udp_header *udp;

int num=0;	//packet number

void handle_pkt(u_char *args,const struct pcap_pktheader *header,const u_char *packet)
{
	num++;
	printf("\n\n[%d] sniff a packet\n",num);
	

	u_int eth_len=sizeof(struct eth_header);
	u_int ip_len=sizeof(struct ip_header);

	ip=(ip_header*)(packet+eth_len);	
	char ipbuffer[100];

	inet_ntop(AF_INET,&ip->sourceIP,ipbuffer,100);	
	printf("Source IP : %s\n",ipbuffer);	

	inet_ntop(AF_INET,&ip->destIP,ipbuffer,100);
	printf("Dest IP : %s\n",ipbuffer);	
	

       
}

int main(int argc, char *argv[])
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	
	char filter_exp[100]="tcp && port==33";
	
	
	bpf_u_int32 net;
	
	handle=pcap_open_live("ens33",BUFSIZ,1,1000,errbuf);   

	if(pcap_compile(handle,&fp,filter_exp,1,net)==-1) 
		printf("Filter error");

	pcap_setfilter(handle,&fp); 

	pcap_loop(handle,-1,handle_pkt,NULL); 
	
	pcap_close(handle); 
	return 0;
}
