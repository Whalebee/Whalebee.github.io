---
title:  "[Project] 프로젝트에 사용될 메인 코드 선택 및 분석"

categories:
  - Project
tags:
  - [project, C, linux, pcap, DB] 

toc: true
toc_sticky: true

date: 2023-08-13
last_modified_at: 2023-08-13
---

- <span style="font-size:150%"> 내가 만든 코드가 <span style="color:violet"> 베이스 코드</span>가 되었으니, 더욱 더 상세하게 <span style="color:#00FF00"> 분석 </span> 해서 <span style="color:#00FF00"> 파악 </span> 해야한다. </span>


# 코드

<details>
<summary> <span style="color:yellow"> 코드 </span> </summary>
<div markdown="1">

```c
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
//#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <netdb.h>

#define SUPPORT_OUTPUT

// for mariadb .
//#include <mariadb/my_global.h>
#include <mariadb/mysql.h>

#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/*------------------global variables------------------*/
// socket
#define TO_MS 1000
#define IP_SIZE 16
#define IP_HDR_SIZE 20
#define TCP_HDR_SIZE 20

// sendraw
char bind_device_name[] = "lo" ;
int bind_device_name_len = 2 ;
int sendraw_mode = 1;



// DB
MYSQL *connection = NULL;
MYSQL conn;
MYSQL_RES *res;
MYSQL_ROW row;
MYSQL_RES *res_block;
MYSQL_ROW row_block;
int cmp_ret = 1; // base: allow
#define DOMAIN_BUF 260
#define REC_DOM_MAX 20
#define REC_DOM_LEN 260

// TCP Header checksum
struct pseudohdr {
        u_int32_t   saddr;
        u_int32_t   daddr;
        u_int8_t    useless;
        u_int8_t    protocol;
        u_int16_t   tcplength;
};

// Protocol Info
char IPbuffer_str[IP_SIZE]; 		// IP_SIZE 16
char IPbuffer2_str[IP_SIZE]; 		// IP_SIZE 16
unsigned short tcp_src_port = 0;
unsigned short tcp_dst_port = 0;

// int gbl_debug = 1; 	// later .
// int g_ret = 0; 		// later .



/*------------------function------------------*/
// got_packet
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_info(const struct sniff_ethernet *ethernet, 
				const struct sniff_ip *ip, 
				const struct sniff_tcp *tcp,
				u_char* domain_str);

// DB
MYSQL_RES* mysql_perform_query(MYSQL *connection, char *sql_query);
void mysql_insert(u_char* domain_str);
void mysql_select_log();
void mysql_block_list(u_char* domain_str, const u_char *packet);

// sendraw
int sendraw( u_char* pre_packet , int mode ) ;
int print_chars(char print_char, int nums);
void print_payload_right(const u_char *payload, int len);
void print_hex_ascii_line_right(const u_char *payload, int len, int offset);
unsigned short in_cksum ( u_short *addr , int len );



///////////////////////////////////////
//                                   //
// begin MAIN FUNCTION !!!    		 //
//                                   //
///////////////////////////////////////
int main(int argc, char *argv[])
{
	pcap_t *handle;					/* Session handle */
	char *dev;						/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;			/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;				/* Our netmask */
	bpf_u_int32 net;				/* Our IP */
	struct pcap_pkthdr header;		/* The header that pcap gives us */
	const u_char *packet;			/* The actual packet */
	struct pcap_if *devs;
	int result = 0 ;
	
	/* Define the device */
	pcap_findalldevs(&devs, errbuf);
	printf("INFO: dev name = %s .\n" , (*devs).name );
	dev = (*devs).name ;
	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, TO_MS, errbuf); 	// TO_MS 1000
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	mysql_init(&conn);
	connection = mysql_real_connect(
			&conn,				// mariadb/mysql handler
			"localhost",		// host address
			"dbuser",				// db id
			"dbuserpass",				// db pass
			"project_db",		// db_name
			3306,				// port
			(char*)NULL,		// unix_socket -> usually NULL
			0					// client_flag -> usually 0
	);
	
	if ( connection == NULL ) {
		fprintf ( stderr , "ERROR: mariadb connection error: %s\n", mysql_error(&conn) );
		return 1;
	} else { 
		fprintf ( stdout , "INFO: mariadb connection OK\n" );
	}
	
	
	result = pcap_loop(handle, 0, got_packet, NULL) ;
	if ( result != 0 ) {
		fprintf(stderr, "ERROR: pcap_loop end with error !!!!\n");
	} else {
		fprintf(stdout, "INFO: pcap_loop end without error .\n");
	}
	
	/* And close the session */
	pcap_close(handle);
	return(0);
} // end of main function.

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
	/*------------------ethernet------------------*/
	#define SIZE_ETHERNET 14 /* ethernet headers are always exactly 14 bytes */
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	ethernet = (struct sniff_ethernet*)(packet); // ethernet header
	
	/*---------------------IP---------------------*/
	u_int size_ip;
	const struct sniff_ip *ip;
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < IP_HDR_SIZE)	// IP_HDR_SIZE 20
	{											
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
		
	/*--------------------PORT--------------------*/
	u_int size_tcp;
	const struct sniff_tcp *tcp;
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < TCP_HDR_SIZE) // TCP_HDR_SIZE 20
	{
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
		
	/*-------------------payload------------------*/
	const char *payload; /* Packet payload */
	unsigned short payload_len = 0; // payload
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	payload_len = ntohs(ip->ip_len) - size_ip - size_tcp;
	// printf("payload_len (pre_packet) %u \n", payload_len);
	
	/*-------------------domain-------------------*/
	u_char* domain = NULL;
	u_char* domain_end = NULL;
	u_char domain_str[DOMAIN_BUF] = {0x00};		// DOMAIN_BUF 1048576
	int domain_len = 0;
	domain = strstr(payload, "Host: ");
	if(domain != NULL){
		domain_end = strstr(domain, "\x0d\x0a");
		if(domain_end != NULL){
			domain_len = domain_end - domain - 6;
			strncpy(domain_str, domain + 6, domain_len);
		}
	}

	/*-----------------print data-----------------*/
	if(domain_len){
		
		// print ehternet, ip, tcp, domain
		print_info(ethernet, ip, tcp, domain_str);
	
		// block_list : print, compare(domain_str <-> block_list), block or allow
		mysql_block_list(domain_str, packet);
		
		// INSERT to tb_packet_log
		mysql_insert(domain_str);
		
		// SELECT tb_packet_log
		mysql_select_log();
		
		fputc('\n',stdout);	
	}	
	
} // end of got_packet function .

unsigned short in_cksum(u_short *addr, int len)
{
        int         sum = 0;
        int         nleft = len;
        u_short     *w = addr;
        u_short     answer = 1;		// return for checksum .
		u_short 	result = 0;		// check for integrity .
		
        while (nleft > 1){
            sum += *w++;
            nleft -= 2;
        }

        if (nleft == 1){
            *( (u_char *)(&answer) ) = *(u_char *)w ;
            sum += answer;
        }
		
        sum = (sum >> 16) + (sum & 0xffff); // hight bit(8 8=16) + low bit(ff ff) .
        sum += (sum >> 16); 				// wrap around -> carry value is too add in sum .
		
        answer = ~sum;

		result = answer + sum  + 1;
		if( result == 0 ) {
			//	fprintf(stdout, "INFO: tcphdr in_cksum() success ! \n");
			return answer;
		} else {
			fprintf(stderr, "ERROR :  tcphdr in_cksum() result is not integrity status !! \n");
			return -1;
		}
}
// end in_cksum function .


int sendraw( u_char* pre_packet, int mode)
{
		const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

		u_char packet[1600];
        int IP_HDRINCL_ON=1, len ; // len Later .
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;
		struct sockaddr_in address, target_addr; // target_addr later
        int port;
        int pre_payload_size = 0 ;
		u_char *payload = NULL ;
		int size_payload = 0 ;
        int post_payload_size = 0 ;
        int sendto_result = 0 ;
		int setsockopt_result = 0 ;
		int prt_sendto_payload = 0 ;
		int warning_page = 1 ;
		int ret = 1 ;							
		int raw_socket, recv_socket;			// recv_socket later .
		
		
		// --------vlan--------
		// int size_vlan = 0 ; 					// excepted because of i think that i don't need this yet .
		// int size_vlan_apply = 0 ; 			// excepted because of i think that i don't need this yet .
		// int vlan_tag_disabled = 0 ;			// excepted because of i think that i don't need this yet .
		
		// --------later--------
		// char recv_packet[100], compare[100]; // later .
        // struct hostent *target; 				// later .
		// int loop1=0; 						// later .
        // int loop2=0; 						// later .
		// int rc = 0 ; 						// later .
		// struct ifreq ifr ; 					// relative ioctl() -> ioctl function is control hardware and analyze hardware status
		// char * if_bind ; 					// later .
		// int if_bind_len = 0 ; 				// later .
		// char* ipaddr_str_ptr ; 				// later .
		
		

		#ifdef SUPPORT_OUTPUT
		printf("\n");
		print_chars('\t',6);
		printf( "[raw socket sendto]\t[start]\n\n" );

		print_chars('\t',6);
		printf("   PRE_PACKET WHOLE(L2_PACKET_DATA) (%d bytes only):\n", 54);
		print_payload_right(pre_packet, 54);
		printf("\n");
		#endif

        for( port=80; port<81; port++ ) {
			// create raw socket
			raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
			if ( raw_socket < 0 ) {
				print_chars('\t',6);
				fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
				fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
				return -2;
			}
		
			// IP_HDRINCL option: include IP_Header .
			setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&IP_HDRINCL_ON, sizeof(IP_HDRINCL_ON)); 

			if ( bind_device_name != NULL ) {
				// i think that ifreq will be use later ( SO_BINDTODEVICE ) .
				setsockopt_result = setsockopt( raw_socket, SOL_SOCKET, SO_BINDTODEVICE, bind_device_name, bind_device_name_len );

				if( setsockopt_result == -1 ) {
					print_chars('\t',6);
					fprintf(stderr,"ERROR: setsockopt() - %s\n", strerror(errno));
					return -2;
				}
				#ifdef SUPPORT_OUTPUT
				else {
					print_chars('\t',6);
					fprintf(stdout,"OK: setsockopt(%s)(%d) - %s\n", bind_device_name, setsockopt_result, strerror(errno));
				}
				#endif
			}
			
			// ethernet setting in pre_packet without vlan
			ethernet = (struct sniff_ethernet*)(pre_packet);
			if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00" ) {
				#ifdef SUPPORT_OUTPUT
				print_chars('\t',6);
				printf("NORMAL PACKET");
				#endif
			} else {
				fprintf(stderr,"NOTICE: ether_type is not IPv4, so you prepare other ether_types .......... \n");
			}

			// TCP, IP reset header without vlan
			iphdr = (struct iphdr *)(packet) ;
			memset( iphdr, 0, 20 );
			tcphdr = (struct tcphdr *)(packet + 20);
			memset( tcphdr, 0, 20 );

			// twist s and d address
			source_address.s_addr = ((struct iphdr *)(pre_packet + 14))->saddr ;
			dest_address.s_addr = ((struct iphdr *)(pre_packet + 14))->daddr ;		// for return response
          
			iphdr->id = ((struct iphdr *)(pre_packet + 14))->id ;// identification field in ip_header
			
			int pre_tcp_header_size = 0;
			// char pre_tcp_header_size_char = 0x0; 	// Later
			pre_tcp_header_size = ((struct tcphdr *)(pre_packet + 14 + 20))->doff ;
			pre_payload_size = ntohs( ((struct iphdr *)(pre_packet + 14))->tot_len ) - ( 20 + pre_tcp_header_size * 4 ) ;

			// TCP header setting
			tcphdr->source = ((struct tcphdr *)(pre_packet + 14 + 20))->dest ;// src_port field in tcp_header
			tcphdr->dest = ((struct tcphdr *)(pre_packet + 14 + 20))->source ;// dst_port field in tcp_header
			tcphdr->seq = ((struct tcphdr *)(pre_packet + 14 + 20))->ack_seq ;// SEQ num field in tcp_header
			tcphdr->ack_seq = ((struct tcphdr *)(pre_packet + 14 + 20))->seq  + htonl(pre_payload_size - 20)  ;// ACK num field in tcp_header
			tcphdr->window = ((struct tcphdr *)(pre_packet + 14 + 20))->window ;// window field in tcp_header
			tcphdr->doff = 5;// offset field in tcp_header
			tcphdr->ack = 1;// tcp_flag field in tcp_header
			tcphdr->psh = 1;// tcp_flag field in tcp_header
			tcphdr->fin = 1;// tcp_flag field in tcp_header
			
			// created pseudo_header for calculate TCP checksum ( total = 12bytes )
			pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
			pseudo_header->saddr = source_address.s_addr;// TTL,Protocol,Checksum field in ip_header(strange value)
			pseudo_header->daddr = dest_address.s_addr;// src_ip field in ip_header(not change value)
			pseudo_header->useless = (u_int8_t) 0;// reserved field in tcp_header
			pseudo_header->protocol = IPPROTO_TCP;// dst_ip field in ip_header(strange value)
			pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);// dst_ip field in ip_header(strange value)


			char *fake_packet = 
						"HTTP/1.1 200 OK\x0d\x0a"
						"Content-Length: 230\x0d\x0a"
						"Content-Type: text/html"
						"\x0d\x0a\x0d\x0a"
						"<html>\r\n"
						"<head>\r\n"
						"<meta charset=\"UTF-8\">\r\n"
						"<title>\r\n"
						"CroCheck - WARNING - PAGE\r\n"
						"SITE BLOCKED - WARNING - \r\n"
						"</title>\r\n"
						"</head>\r\n"
						"<body>\r\n"
						"<center>\r\n"
						"<img   src=\"http://127.0.0.1:3000/warning.jpg\" alter=\"*WARNING*\">\r\n"
						"<h1>SITE BLOCKED</h1>\r\n"
						"</center>\r\n"
						"</body>\r\n"
						"</html>\r\n"
						;
			
			post_payload_size = strlen(fake_packet);
			
			// choose output content
			warning_page = 5; // for test redirecting
			if ( warning_page == 5 ){
				memcpy ( (char*)packet + 40, fake_packet , post_payload_size ) ;
			}
			
			// renewal after post_payload_size for calculate TCP checksum
			pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

			// calculate TCP header checksum
			tcphdr->check = in_cksum( (u_short *)pseudo_header,
			               sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);// checksum field in tcp_header

			
			// line
			print_chars('\t',6);
			
			// IP header setting
			iphdr->version = 4;// version field in ip_header
			iphdr->ihl = 5;// IHL field in ip_header
			iphdr->protocol = IPPROTO_TCP;// protocol field in ip_header(reset)
			iphdr->tot_len = htons(40 + post_payload_size);// total length field in ip_header
			iphdr->id = ((struct iphdr *)(pre_packet + 14))->id + htons(1);//identification field in ip_header(increase 1)
			
			// 0x40 -> don't use flag
			memset( (char*)iphdr + 6 ,  0x40  , 1 );// IP_flags field in ip_header
			iphdr->ttl = 60;// TTL field in ip_header(reset)
			iphdr->saddr = source_address.s_addr;// src_ip field in ip_header(change value)
			iphdr->daddr = dest_address.s_addr;// dst_ip field in ip_header(change value)
			
			// calculate IP header checksum
			iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));// checksum field in ip_header(reset)
			
			// for sendto
			address.sin_family = AF_INET;
			address.sin_port = tcphdr->dest ;
			address.sin_addr.s_addr = dest_address.s_addr;

			prt_sendto_payload = 0;
			#ifdef SUPPORT_OUTPUT
			prt_sendto_payload = 1 ;
			#endif

			if( prt_sendto_payload == 1 ) {

				printf("\n\n");
				print_chars('\t',6);
				printf("----------------sendto Packet data----------------\n");

				print_chars('\t',6);
				printf("    From: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( source_address ),
								((char*)&source_address.s_addr)[0],
								((char*)&source_address.s_addr)[1],
								((char*)&source_address.s_addr)[2],
								((char*)&source_address.s_addr)[3]
						);
				print_chars('\t',6);
				printf("      To: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( dest_address ),
								((char*)&dest_address.s_addr)[0],
								((char*)&dest_address.s_addr)[1],
								((char*)&dest_address.s_addr)[2],
								((char*)&dest_address.s_addr)[3]
						);

				switch(iphdr->protocol) {
					case IPPROTO_TCP:
						print_chars('\t',6);
						printf("Protocol: TCP\n");
						break;
					case IPPROTO_UDP:
						print_chars('\t',6);
						printf("Protocol: UDP\n");
						return -1;
					case IPPROTO_ICMP:
						print_chars('\t',6);
						printf("Protocol: ICMP\n");
						return -1;
					case IPPROTO_IP:
						print_chars('\t',6);
						printf("Protocol: IP\n");
						return -1;
					case IPPROTO_IGMP:
						print_chars('\t',6);
						printf("Protocol: IGMP\n");
						return -1;
					default:
						print_chars('\t',6);
						printf("Protocol: unknown\n");
						return -2;
				}

				print_chars('\t',6);
				printf("Src port: %d\n", ntohs(tcphdr->source));
				print_chars('\t',6);
				printf("Dst port: %d\n", ntohs(tcphdr->dest));

				payload = (u_char *)(packet + sizeof(struct iphdr) + tcphdr->doff * 4 );

				size_payload = ntohs(iphdr->tot_len) - ( sizeof(struct iphdr) + tcphdr->doff * 4 );
				
				if (size_payload > 0) {
					printf("\n");
					print_chars('\t',6);
					printf("   PACKET-HEADER(try1) (%d bytes):\n", ntohs(iphdr->tot_len) - size_payload); // 40
					print_payload_right((const u_char*)&packet, ntohs(iphdr->tot_len) - size_payload);
				}

				if (size_payload > 0) {
					printf("\n");
					print_chars('\t',6);
					printf("   Payload (%d bytes):\n", size_payload);
					print_payload_right(payload, size_payload);
				}
				
			} // end -- if -- prt_sendto_payload = 1 ;
			
			if ( mode == 1 ) {
				sendto_result = sendto( raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,
										(struct sockaddr *)&address, sizeof(address) ) ;
				if ( sendto_result != ntohs(iphdr->tot_len) ) {
					fprintf ( stderr,"ERROR: sendto() - %s\n", strerror(errno) ) ;
					ret = -2;
				} else {
					// fprintf ( stdout,"INFO: sendto() success ! \n");
					ret = 0;
				}
			} // end if(mode)


			if ( (unsigned int)iphdr->daddr == (unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" ) {
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf( "address1 == %hhu.%hhu.%hhu.%hhu\taddress2 == %X\taddress3 == %X\n",
						*(char*)((char*)&source_address.s_addr + 0),*(char*)((char*)&source_address.s_addr + 1),
						*(char*)((char*)&source_address.s_addr + 2),*(char*)((char*)&source_address.s_addr + 3),
						source_address.s_addr,	(unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" );
			}
			
			close( raw_socket );
        } // end for loop
		
		#ifdef SUPPORT_OUTPUT
		printf("\n");
		print_chars('\t',6);
        printf( "[sendraw] end . \n\n" );
		#endif
	
		
		return ret; // 0 -> normal exit
}
// end sendraw function .


int print_chars(char print_char, int nums)
{
	int i = 0;
	for ( i ; i < nums ; i++) {
		printf("%c",print_char);
	}
	return i;
}


void
print_hex_ascii_line_right(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;
	int tabs_cnt = 6 ;  // default at now , afterward receive from function caller

	/* print 10 tabs for output to right area	*/
	for ( i = 0 ; i < tabs_cnt ; i++ ) {
		printf("\t");
	}

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload_right(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;


	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line_right(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line_right(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line_right(ch, len_rem, offset);
			break;
		}
		//m-debug
		if ( offset > 600 ) {
			print_chars('\t',6);
			printf("INFO: ..........    payload too long (print_payload_right func) \n");
			break;
		}
	}
    return;
}


void mysql_block_list(u_char* domain_str, const u_char *packet) {
	
		// Receive tb_packet_block---------------------------------
		res_block = mysql_perform_query(connection, "SELECT * FROM tb_packet_block");
		char domain_arr[REC_DOM_MAX][REC_DOM_LEN] = { 0x00 }; // domain_arr array for print block_list
		// REC_DOM_MAX 20
		// REC_DOM_LEN 1024
		int num = 0;

		// print block_list
		int cnt = 1;
		printf("\n");
		while( (row_block = mysql_fetch_row(res_block) ) != NULL){
			printf("Mysql block_list in tb_packet_block [ row : %d | ID : %s ] \n", cnt++, row_block[0]);
			printf("src_ip: %20s | ", row_block[1]); 			
			printf("src_port: %5s | \n", row_block[2]);
			printf("dst_ip: %20s | ", row_block[3]);
			printf("dst_port: %5s | \n", row_block[4]);
			printf("Domain: %20s | ", row_block[5]);
			strcpy( &domain_arr[num++][0], row_block[5]);		// string copy for compare
			printf("created at: %s . \n\n\n", row_block[6]); 	// doesn't exist result in block_list
		}
		
		printf("\n");


		// compare---------------------------------
		for(int i = 0; i < 100; i++ ) {

			// if you knew str_len, you choice method like this
			int str1_len = strlen( &domain_arr[i][0] ); // block list
			int str2_len = strlen( domain_str );		// domain_string
			
			// break different value each other and
			if( str1_len != str2_len && str1_len != 0 ) {
				continue; // move to next array .
			}
			
			// first, break if meet NULL data in array .
			if( strlen( &domain_arr[i][0] ) == 0 ) 
				break; 
			
			cmp_ret = strcmp( &domain_arr[i][0], domain_str );
			
			// if each other string is same length but not same string, so break
			if( cmp_ret < 0 ) break; 
			printf("DEBUG: domain name check result : %d \n", cmp_ret);

			if( cmp_ret == 0 )
				break;
			
			
		} 

		// block or allow
		if( cmp_ret == 0 ) {
			printf("DEBUG: domain blocked . \n");
			int sendraw_ret = sendraw(packet , sendraw_mode);
			if ( sendraw_ret != 0 ) {
				fprintf(stderr, "ERROR: emerge in sendraw() !!! (line=%d) \n", __LINE__);
			}
		} else {
			printf("DEBUG: domain allowed . \n");
		} // end if emp_ret .
		
		mysql_free_result(res_block);
} // end of mysql_block_list() .

MYSQL_RES* mysql_perform_query(MYSQL *connection, char *sql_query) {
 
    if(mysql_query(connection, sql_query)) {
        printf("MYSQL query error : %s\n", mysql_error(connection));
        exit(1);
    }
    return mysql_use_result(connection);
} // end of mysql_perform_query() .

void mysql_insert(u_char* domain_str)
{
	// INSERT
	char query[DOMAIN_BUF] = { 0x00}; // DOMAIN_BUF 1048576
	// query setting
	sprintf(query,"INSERT INTO tb_packet_log ( src_ip , src_port , dst_ip , dst_port , domain , result )"
				  "VALUES('%s', '%u', '%s' , '%u' , '%s' , '%d')",
				  IPbuffer_str , 
				  tcp_src_port , 
				  IPbuffer2_str , 
				  tcp_dst_port ,  
				  domain_str , 
				  cmp_ret
				  );

	if( mysql_query(connection, query) != 0 ) {
		fprintf(stderr, "ERROR : mysql_query() is failed !!! \n");
	} else {
		printf("mysql_query() success :D \n");
	}
} // end of mysql_insert() .


void mysql_select_log()
{
	char query[DOMAIN_BUF] = { 0x00 }; // DOMAIN_BUF 1048576
	sprintf(query, "SELECT * FROM tb_packet_log");
	
	res = mysql_perform_query(connection, query);

	printf("\n");
	int cnt = 1;
	
	while( (row = mysql_fetch_row(res) ) != NULL){
		printf("Mysql contents in tb_packet_log [ row : %d | ID : %s ] \n", cnt++, row[0]);
		printf(" src_ip: %20s | ", row[1]); 
		printf(" src_port: %5s | \n", row[2]);
		printf(" dst_ip: %20s | ", row[3]);
		printf(" dst_port: %5s | \n", row[4]);
		printf(" Domain: %20s | ", row[5]);
		printf(" result: %7s | ", row[6]);
		printf(" created at: %s . \n\n\n", row[7]);
	}
	printf("\n");
	mysql_free_result(res);
} // end of mysql_select_log() .


void print_info(const struct sniff_ethernet *ethernet, 
				const struct sniff_ip *ip, 
				const struct sniff_tcp *tcp,
				u_char* domain_str)
{
	// print ethernet
	printf("DATA: dest MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
		ethernet->ether_dhost[0],
		ethernet->ether_dhost[1],
		ethernet->ether_dhost[2],
		ethernet->ether_dhost[3],
		ethernet->ether_dhost[4],
		ethernet->ether_dhost[5]
	);
	printf("DATA: src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
		ethernet->ether_shost[0],
		ethernet->ether_shost[1],
		ethernet->ether_shost[2],
		ethernet->ether_shost[3],
		ethernet->ether_shost[4],
		ethernet->ether_shost[5]
	);
	
	// print ip
	char *IPbuffer, *IPbuffer2;

	IPbuffer = inet_ntoa(ip->ip_src);
	strcpy(IPbuffer_str, IPbuffer);
	IPbuffer2 = inet_ntoa(ip->ip_dst);
	strcpy(IPbuffer2_str, IPbuffer2);
	
	printf("DATA: IP src : %s\n",IPbuffer_str);
	printf("DATA: IP dst : %s\n",IPbuffer2_str);
	
	
	// print port
	tcp_src_port = ntohs(tcp->th_sport);
	tcp_dst_port = ntohs(tcp->th_dport);
	
	printf("DATA: src Port : %u\n", tcp_src_port);
	printf("DATA: dst Port : %u\n", tcp_dst_port);	
	
	
	// print domain
	printf("INFO: Domain = %s\n", domain_str);
}
```

</div>
</details>













# 분석

## 추가한 함수들

### <span style="color:#00FFFF"> MYSQL_RES* </span> <span style="color:yellow"> mysql_perform_query(<span style="color:#00FFFF"> MYSQL *</span> <span style="color:#87CEEB"> connection </span> , <span style="color:#3399FF"> char * </span> <span style="color:#87CEEB"> sql_query </span> ) </span>

```c
MYSQL_RES* mysql_perform_query(MYSQL *connection, char *sql_query) {
 
    if(mysql_query(connection, sql_query)) {
        printf("MYSQL query error : %s\n", mysql_error(connection));
        exit(1);
    }
    return mysql_use_result(connection);
} // end of mysql_perform_query() .
```
- <span style="color:yellow"> mysql_query() </span>를 사용하면 되지만, 이렇게 따로 빼놓은 이유는 <span style="color:violet"> SELECT 명령어 </span> 를 <span style="color:#00FF00"> 편하게 </span> 쓰기 위해서이다 ! 

<br>


### <span style="color:#3399FF"> void </span> <span style="color:yellow"> mysql_insert(<span style="color:#3399FF"> u_char* </span> <span style="color:#87CEEB"> domain_str </span> ) </span>

```c
void mysql_insert(u_char* domain_str)
{
	// INSERT
	char query[DOMAIN_BUF] = { 0x00}; // DOMAIN_BUF 1048576
	// query setting
	sprintf(query,"INSERT INTO tb_packet_log ( src_ip , src_port , dst_ip , dst_port , domain , result )"
				  "VALUES('%s', '%u', '%s' , '%u' , '%s' , '%d')",
				  IPbuffer_str , 
				  tcp_src_port , 
				  IPbuffer2_str , 
				  tcp_dst_port ,  
				  domain_str , 
				  cmp_ret
				  );

	if( mysql_query(connection, query) != 0 ) {
		fprintf(stderr, "ERROR : mysql_query() is failed !!! \n");
	} else {
		printf("mysql_query() success :D \n");
	}
} // end of mysql_insert() .
```
- 여기서 새로운 함수 <span style="color:yellow"> sprintf() </span>를 사용해서  <span style="color:#00FF00"> 문자열과 형식문자를 사용</span>해 변수에 값을 대입시킨 것이다.

<br>


### <span style="color:#3399FF"> void </span> <span style="color:yellow"> mysql_select_log() </span>

```c
void mysql_select_log()
{
	char query[DOMAIN_BUF] = { 0x00 }; // DOMAIN_BUF 1048576
	sprintf(query, "SELECT * FROM tb_packet_log");
	
	res = mysql_perform_query(connection, query);

	printf("\n");
	int cnt = 1;
	
	while( (row = mysql_fetch_row(res) ) != NULL){
		printf("Mysql contents in tb_packet_log [ row : %d | ID : %s ] \n", cnt++, row[0]);
		printf(" src_ip: %20s | ", row[1]); 
		printf(" src_port: %5s | \n", row[2]);
		printf(" dst_ip: %20s | ", row[3]);
		printf(" dst_port: %5s | \n", row[4]);
		printf(" Domain: %20s | ", row[5]);
		printf(" result: %7s | ", row[6]);
		printf(" created at: %s . \n\n\n", row[7]);
	}
	printf("\n");
	mysql_free_result(res);
} // end of mysql_select_log() .
```

- <span style="color:yellow"> mysql_fetch_row() </span>를 사용해서 한 row씩 가져와서 row 변수에 담아 출력하는 방식 !
- 2차원 배열에 대입하는 것은 밑에 <span style="color:yellow"> mysql_block_list() </span>에서 사용하고 최근 Log에서는 필요없다는 판단에 사용하지 않았다.

<br>

### <span style="color:#3399FF"> void </span> <span style="color:yellow"> mysql_block_list(<span style="color:#3399FF"> u_char* </span> <span style="color:#87CEEB"> domain_str </span> , <span style="color:#3399FF"> const u_char * </span> <span style="color:#87CEEB"> packet </span> ) </span>

```c
void mysql_block_list(u_char* domain_str, const u_char *packet) {
	
		// Receive tb_packet_block---------------------------------
		res_block = mysql_perform_query(connection, "SELECT * FROM tb_packet_block");
		char domain_arr[REC_DOM_MAX][REC_DOM_LEN] = { 0x00 }; // domain_arr array for print block_list
		// REC_DOM_MAX 20
		// REC_DOM_LEN 260
		int num = 0;

		// print block_list
		int cnt = 1;
		printf("\n");
		while( (row_block = mysql_fetch_row(res_block) ) != NULL){
			printf("Mysql block_list in tb_packet_block [ row : %d | ID : %s ] \n", cnt++, row_block[0]);
			printf("src_ip: %20s | ", row_block[1]); 			
			printf("src_port: %5s | \n", row_block[2]);
			printf("dst_ip: %20s | ", row_block[3]);
			printf("dst_port: %5s | \n", row_block[4]);
			printf("Domain: %20s | ", row_block[5]);
			strcpy( &domain_arr[num++][0], row_block[5]);		// string copy for compare
			printf("created at: %s . \n\n\n", row_block[6]); 	// doesn't exist result in block_list
		}
		
		printf("\n");


		// compare---------------------------------
		for(int i = 0; i < 100; i++ ) {

			// if you knew str_len, you choice method like this
			int str1_len = strlen( &domain_arr[i][0] ); // block list
			int str2_len = strlen( domain_str );		// domain_string
			
			// break different value each other and
			if( str1_len != str2_len && str1_len != 0 ) {
				continue; // move to next array .
			}
			
			// first, break if meet NULL data in array .
			if( strlen( &domain_arr[i][0] ) == 0 ) 
				break; 
			
			cmp_ret = strcmp( &domain_arr[i][0], domain_str );
			
			// if each other string is same length but not same string, so break
			if( cmp_ret < 0 ) break; 
			printf("DEBUG: domain name check result : %d \n", cmp_ret);

			if( cmp_ret == 0 )
				break;
			
			
		} 

		// block or allow
		if( cmp_ret == 0 ) {
			printf("DEBUG: domain blocked . \n");
			int sendraw_ret = sendraw(packet , sendraw_mode);
			if ( sendraw_ret != 0 ) {
				fprintf(stderr, "ERROR: emerge in sendraw() !!! (line=%d) \n", __LINE__);
			}
		} else {
			printf("DEBUG: domain allowed . \n");
		} // end if emp_ret .
		
		mysql_free_result(res_block);
} // end of mysql_block_list() .
```

- 2차원 배열을 사용해서 block_list의 목록들을 모두 저장해놓고 비교를 하는 방식이다.
- 출력과 비교를 한 번에 하기위해 사용한 방법이지만, 추후에 더 좋은 방법을 발견하게 되면 추가하도록 하자 !
- for문 중에서 길이 비교, 도메인 존재 확인으로 빨리 끝내는 방법이 결과를 빠르게 불러올 수 있을 것 같다.


<br>

### <span style="color:#3399FF"> void </span> <span style="color:yellow"> print_info(<span style="color:#3399FF"> const </span> <span style="color:#00FFFF"> struct sniff_ethernet * </span> <span style="color:#87CEEB"> ethernet </span> , <span style="color:#3399FF"> const </span> <span style="color:#00FFFF"> struct sniff_ip * </span> <span style="color:#87CEEB"> ip </span> , <span style="color:#3399FF"> const </span> <span style="color:#00FFFF"> struct sniff_tcp * </span> <span style="color:#87CEEB"> tcp </span> , <span style="color:#3399FF"> u_char* </span> <span style="color:#87CEEB"> domain_str </span> ) </span>

```c
void print_info(const struct sniff_ethernet *ethernet, 
				const struct sniff_ip *ip, 
				const struct sniff_tcp *tcp,
				u_char* domain_str)
{
	// print ethernet
	printf("DATA: dest MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
		ethernet->ether_dhost[0],
		ethernet->ether_dhost[1],
		ethernet->ether_dhost[2],
		ethernet->ether_dhost[3],
		ethernet->ether_dhost[4],
		ethernet->ether_dhost[5]
	);
	printf("DATA: src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
		ethernet->ether_shost[0],
		ethernet->ether_shost[1],
		ethernet->ether_shost[2],
		ethernet->ether_shost[3],
		ethernet->ether_shost[4],
		ethernet->ether_shost[5]
	);
	
	// print ip
	char *IPbuffer, *IPbuffer2;

	IPbuffer = inet_ntoa(ip->ip_src);
	strcpy(IPbuffer_str, IPbuffer);
	IPbuffer2 = inet_ntoa(ip->ip_dst);
	strcpy(IPbuffer2_str, IPbuffer2);
	
	printf("DATA: IP src : %s\n",IPbuffer_str);
	printf("DATA: IP dst : %s\n",IPbuffer2_str);
	
	
	// print port
	tcp_src_port = ntohs(tcp->th_sport);
	tcp_dst_port = ntohs(tcp->th_dport);
	
	printf("DATA: src Port : %u\n", tcp_src_port);
	printf("DATA: dst Port : %u\n", tcp_dst_port);	
	
	
	// print domain
	printf("INFO: Domain = %s\n", domain_str);
}
```

- 처음엔 <span style="color:#00FF00"> ethernet </span> 과 <span style="color:#00FF00"> ip </span> , <span style="color:#00FF00"> tcp </span> , <span style="color:#00FF00"> domain </span> 을 <span style="color:yellow"> got_packet() </span>에서 모두 출력했으나, 함수로 뺏지만 각자의 프로토콜을 토대로 하나의 함수로 따로따로 만들었더니 <span style="color:violet"> 비효율적 </span> 이라서 하나로 합쳤다 !


<br>


# 피드백 및 트러블 슈팅

## 1. 코어덤프 해결

- <span style="color:#FF0000"> Segmentation fault ( Core Dump )  </span> 는 메모리의 버퍼 오버플로우 일 때 뜨는 경우가 많다. <br>
먼저 <span style="color:#00FF00"> ulimit -a </span> 명령어로 stack size를 확인하면 기본 사이즈는 <span style="color:orange"> 8192(Kb) </span>를 나타낸다. <br>
지금은 <span style="color:#87CEEB"> domain_arr </span> 의 사이즈가 엄청 크지는 않지만, 전에 stack_size의 기본 사이즈를 뛰어 넘었을 때가 있었는데, <br>
gdb로 찾아보는 연습을 할 수 있었다 !

![pj_7_gdb](../../images/pj_7_gdb.png)  

- <span style="color:#87CEEB"> domain_arr </span> 에 <span style="color:#FF0000"> error </span> 가 난 것을 볼 수 있다 !
				
# 나머지는 가독성을 위한 변수와 define 정리
