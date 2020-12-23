#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518 //設定一個封包最多捕獲1518 bytes

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14 //header 必定14 bytes

/* Ethernet addresses are 6 bytes */
#define ADDR_LEN	6 //address 必定6 bytes

struct sniff_udp {
	uint16_t uh_sport;					//source port
	uint16_t uh_dport;					//destination port
	uint16_t uh_length;
	uint16_t uh_sum;				//checksum
};

/* Ethernet header */
struct sniff_ethernet {
	u_char  ether_dhost[ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */

#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};

/* MAC Adress */
struct sniff_ether{
	const struct ether_addr dAddr;
	const struct ether_addr sAddr;
	uint8_t protocol; 
};

typedef struct accm{
	char src[30];
	char dst[30];
	int cnt;
}accm;

#define idxofmem 100

int int_cmp(const void *a, const void *b) 
{ 
	struct accm *ia = (struct accm *)a; // casting pointer types 
	struct accm *ib = (struct accm *)b;
	return ib->cnt-ia->cnt; 
} 

int main(int argc, char **argv)
{
	char *filename= argv[1];
	char frmt[] = "%Y-%m-%d %H:%M:%S";
	char errbuf[PCAP_ERRBUF_SIZE];
	int idxme=0;
	pcap_t *handle = pcap_open_offline(filename, errbuf);

	FILE *captured_fp = fopen("captured.txt","w");
	FILE *result_fp = fopen("result.txt","w");
	
	struct pcap_pkthdr *header;
	static int count = 0;
	const char *payload;
	const u_char *packet;

	accm counterfile[100000];
	int run=0;

	/* header of output file */
	// result.txt儲存：SrcAddr DestAddr和相應的數量
	fprintf(result_fp,"No\tSource-address\t\tDest-address\t\tCount\n");
	// captured.txt儲存：IP來源和目的地址 --- Protocol --- PORT來源和目的地址 --- MAC來源和目的位置 --- 時間戳
	fprintf(captured_fp,"No\tSrc-addr\tDest-addr\tPrtcl\tSrc-port\tDst-port\tSrc-mac\t\t\tDst-mac\t\t\tTime\n");

	while ( pcap_next_ex(handle, &header, &packet) >=0)
	{
		/* declare pointers to packet headers */
		const struct sniff_ether *eth;
		const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
		const struct sniff_ip *ip;              /* The IP header */
		const struct sniff_tcp *tcp;            /* The TCP header */
		const struct sniff_udp *udp;            /* The UDP header */
		const char *payload;                    /* Packet payload */

		int size_ip;
		int size_tcp;
		int size_udp;
		int size_payload;

		/* define mac header*/
		eth = (struct sniff_ether*)(packet);

		/* define ethernet header */
		ethernet = (struct sniff_ethernet*)(packet); //定義Ethernet header

		/* define/compute ip header offset */
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);       
		size_ip = IP_HL(ip)*4; //IP header長度
		// if (size_ip < 20) {
		//     printf("   * Invalid IP header length: %u bytes\n", size_ip);
		//     break;
		// }

		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;

		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

		fprintf(captured_fp, "%d\t", ++count);

		/* source and destination ip */
		if(run > 0)
		{
			int i;
			int flag = 0;

			for(i=0; i<run; i++)
			{
				//inet_ntoa() 將IP位置裝換為10進制的IP位置
				if(strcmp( counterfile[i].src, inet_ntoa(ip->ip_src) )==0 )
				{
					if(strcmp( counterfile[i].dst, inet_ntoa(ip->ip_dst) )==0 )
					{
						counterfile[i].cnt++;
						flag = 1;
						break;
					}
				}
			}
			// printf("|i=%d flag=%d run=%d|\n",i,flag,run);

			if(flag==0)
			{   
				strcpy ( counterfile[i].src , inet_ntoa(ip->ip_src) );
				strcpy ( counterfile[i].dst , inet_ntoa(ip->ip_dst) );
				counterfile[i].cnt = 1;
				run++;
			}
			// printf("%d|%s|\t\t|%s|\n",count,counterfile[i].src,counterfile[i].dst);
		}

		else if (run == 0)
		{
			strcpy ( counterfile[0].src , inet_ntoa(ip->ip_src) );
			strcpy ( counterfile[0].dst , inet_ntoa(ip->ip_dst) );
			counterfile[0].cnt = 1;
			// printf("|%s|\t\t|%s|\n", counterfile[0].src, counterfile[0].dst);
			run++;
		}

		if( strcmp(inet_ntoa(ip->ip_src),"0.0.0.0")==0 || strlen(inet_ntoa(ip->ip_src)) < 8){
			fprintf(captured_fp,"%s\t\t",inet_ntoa(ip->ip_src)); 
		} else{
			fprintf(captured_fp,"%s\t",inet_ntoa(ip->ip_src));
		}

		if( strcmp(inet_ntoa(ip->ip_dst),"0.0.0.0")==0 || strlen(inet_ntoa(ip->ip_dst)) < 8){
			fprintf(captured_fp,"%s\t\t", inet_ntoa(ip->ip_dst));
		}  else{
			fprintf(captured_fp,"%s\t", inet_ntoa(ip->ip_dst));
		}

		//----------------------------------------------------------------------------------------//

		// 根據protocol進行分類，fprintf(fp,"|%d|\t",ip->ip_p); 
		switch(ip->ip_p) {
			case 7:
				fprintf(captured_fp," ARP\t");
				break;
				// case 17:
			case IPPROTO_UDP:
				fprintf(captured_fp," UDP\t");
				break;
			case IPPROTO_TCP:
				fprintf(captured_fp," TCP\t");
				break;
			case IPPROTO_ICMP:
				fprintf(captured_fp," ICMP\t");
				break;
			case IPPROTO_IP:
				fprintf(captured_fp," IP\t");
				break;
			default:
				fprintf(captured_fp,"unknow\t");
				break;
		}

		//----------------------------------------------------------------------------------------//

		//ports (if TCP, get src-port and dst-port)
		if(ip->ip_p == IPPROTO_TCP){
			fprintf(captured_fp,"%d\t\t%d\t\t", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
		}
		else if(ip->ip_p == IPPROTO_UDP){
			fprintf(captured_fp,"%d\t\t%d\t\t", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
		}
		else{
			fprintf(captured_fp,"----\t\t----\t\t");
		}

		//----------------------------------------------------------------------------------------//

		/*mac adrress*/
		if(strlen(ether_ntoa(&eth->sAddr))<=15){
			fprintf(captured_fp,"%s\t\t", ether_ntoa(&eth->sAddr));
			printf("srcMac:%d\n", strlen(ether_ntoa(&eth->sAddr)));
		} else{
			fprintf(captured_fp,"%s\t", ether_ntoa(&eth->sAddr));
			printf("srcMac:%d\n", strlen(ether_ntoa(&eth->sAddr)));
		}

		if(strlen(ether_ntoa(&eth->dAddr))<=15){
			fprintf(captured_fp,"%s\t\t", ether_ntoa(&eth->dAddr));
			printf("dstMac:%d\n", strlen(ether_ntoa(&eth->sAddr)));
		} else{
			fprintf(captured_fp,"%s\t", ether_ntoa(&eth->dAddr));
			printf("dstMac:%d\n", strlen(ether_ntoa(&eth->sAddr)));
		}

		//---------------------------------------------------------------------------------------//
		//time
		//運用time_t形態變數存取header的時間
		struct tm *lt = localtime(&header->ts.tv_sec); //用localtime()轉換成struct tm的形式
		char st[100];
		strftime(st, 100, frmt, lt); //用strftime()轉換成string
		fprintf(captured_fp,"%s",st); //寫入time到captured.txt

		/* fill in new line at the ned*/
		fprintf(captured_fp,"\n");
	}

	int i;
	qsort(counterfile, run, sizeof(accm), int_cmp);
	for(i=0; i<run; i++)
	{
		fprintf(result_fp,"%d\t%s\t\t%s\t\t%d\n", i+1, counterfile[i].src, counterfile[i].dst, counterfile[i].cnt);
	}

	fclose(captured_fp);
	fclose(result_fp);
	return 0;
}
