#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

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
    unsigned short icmp_flag;
    unsigned short icmp_seq;

}icmp_header;


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



int main(){
    //指定目标地址
    char* dst_ip="172.16.133.129";
    char buffer[1024];
    memset(buffer,0,1024);
    //初始化很重要，否则失败
    
    //icmp部分起始位置
    struct icmp_header *icmp=(struct  icmp_header *)(buffer+sizeof(struct ip_header));

    icmp->icmp_type=8;
    icmp->icmp_chksum=0;
    //构造校验和
    icmp->icmp_chksum=in_cksum((unsigned short*)icmp,sizeof(struct icmp_header));

    struct ip_header *ip=(struct ip_header*) buffer;
    ip->ip_ver=69; //0000 0000 -> 0100 0101 -> 64+4+1 ->69
    ip->ip_ttl=20;
    //原地址
    ip->ip_srcip.s_addr=inet_addr("172.16.133.128");
    ip->ip_dstip.s_addr=inet_addr(dst_ip);
    ip->ip_protocol=IPPROTO_ICMP;

    //计算总长度
    ip->ip_totalen=htons(sizeof(struct ip_header)+sizeof(struct icmp_header));

    //printf("%s"," send_raw_packet ");

    send_pkt(ip);

}


