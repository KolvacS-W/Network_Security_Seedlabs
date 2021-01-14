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
    char ip_ver; //version&header_len
    char ip_tos;    
    unsigned short ip_totalen;  
    unsigned short ident;   
    unsigned short ip_flags;//flags&displacement    
    unsigned char ip_ttl;   
    unsigned char ip_protocol;  
    unsigned short ip_cksum;    
    //unsigned int sourceIP;
    //unsigned int destIP;  
    struct in_addr ip_srcip;
    struct in_addr ip_dstip;
    
}ip_header;

typedef struct icmp_header{
    char icmp_type;
    char icmp_code;
    unsigned short icmp_chksum;
    unsigned short icmp_id;
    unsigned short icmp_seq;
    unsigned long long icmp_timestamp;

}icmp_header;


int num=0;	//packet number
unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}

void send_pkt(struct ip_header* ip)
{
    struct sockaddr_in dest_info;
    int enable=1;

    int sock=socket(AF_INET,SOCK_RAW,IPPROTO_RAW); //open socket

    setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable)); //set socket
    
    dest_info.sin_family=AF_INET;
    dest_info.sin_addr=ip->ip_dstip; //construct dest_info

    sendto(sock,ip,ntohs(ip->ip_totalen),0,(struct sockaddr *)&dest_info,sizeof(dest_info));


    close(sock);
}

void handle_pkt(u_char *args,const struct pcap_pktheader *header,const u_char *packet)
{

	u_int eth_len=sizeof(struct eth_header);
	u_int ip_len=sizeof(struct ip_header);
	struct icmp_header *icmp;

	struct ip_header *ip=(ip_header*)(packet+eth_len);

	if(ip->ip_protocol==1){ //if get a ICMP
		icmp=(icmp_header*)(packet+eth_len+ip_len); //get icmp
 
		if(icmp->icmp_type!=8) //if it is not a request
			return;

		num++;
	printf("\n\n[%d] sniff a ping,ready to reply\n",num);
	}

	char ipbuffer[100];

	inet_ntop(AF_INET,&ip->ip_srcip,ipbuffer,100);	
	printf("Source IP : %s\n",ipbuffer);	

	inet_ntop(AF_INET,&ip->ip_dstip,ipbuffer,100);
	printf("Dest IP : %s\n",ipbuffer);	

	///////开始spoof///////////////////
	//指定目标地址
    char* dst_ip="172.16.133.129";
    char buffer[1024];
    memset(buffer,0,1024);

    struct icmp_header *nicmp;
    
    //icmp部分起始位置
    nicmp=(struct  icmp_header *)(buffer+sizeof(struct ip_header));

    nicmp->icmp_type=0;
    nicmp->icmp_code=0;
	nicmp->icmp_id=icmp->icmp_id;
	nicmp->icmp_seq=icmp->icmp_seq;
	nicmp->icmp_timestamp=icmp->icmp_timestamp;
    nicmp->icmp_chksum=0;
   
    struct ip_header *nip=(struct ip_header*) buffer;
    nip->ip_ver=69; //0000 0000 -> 0100 0101 -> 64+4+1 ->69
    nip->ip_ttl=20;

    //源地址设置成这个ping数据包的目标地址
    nip->ip_srcip.s_addr=ip->ip_dstip.s_addr;
    nip->ip_dstip.s_addr=ip->ip_srcip.s_addr;
    nip->ip_protocol=IPPROTO_ICMP;

    //计算总长度
    nip->ip_totalen=htons(sizeof(struct ip_header)+sizeof(struct icmp_header));

     //构造校验和
    nicmp->icmp_chksum=in_cksum((unsigned short*)icmp,sizeof(struct icmp_header));

    //printf("%s"," send_raw_packet ");

    send_pkt(nip);

       
}

int main(int argc, char *argv[])
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	char filter_exp[100]="icmp";

	
	bpf_u_int32 net;
	
	handle=pcap_open_live("ens33",BUFSIZ,1,1000,errbuf);  

	if(pcap_compile(handle,&fp,filter_exp,1,net)==-1) 
		printf("Filter error");

	pcap_setfilter(handle,&fp);

	pcap_loop(handle,-1,handle_pkt,NULL); 
	
	pcap_close(handle); 
	return 0;
}
