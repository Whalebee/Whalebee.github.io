---
title:  "[Project] 프로젝트 pcap 라이브러리 사용 (basic) "

categories:
  - Project
tags:
  - [project, C, linux, pcap] 

toc: true
toc_sticky: true

date: 2023-07-28
last_modified_at: 2023-07-28
---



<details>
<summary> <span style="color:yellow"> 코드 </span> </summary>
<div markdown="1">

```c
#include <pcap.h>
#include <stdio.h>
#include <string.h>

/* Ethernet addresses are 6 bytes */
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

void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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

//	for ( int i = 0; i < 10; i++) {
//		/* Grab a packet */
//		packet = pcap_next(handle, &header);
//		/* Print its length */
//		printf("Jacked a packet with length of [%d]\n", header.len);
//	}

	int result = 0;
	result = pcap_loop(handle, 10, got_packet, NULL);
	
	if (result != 0) {
		fprintf(stderr, "ERROR: pcap_loop end with error !!!!\n");
	} else {
		fprintf(stdout, "INFO: pcap_loop end without error. \n");
	}

	
	/* And close the session */
	pcap_close(handle);

	



	return(0);
} // end of main




void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet)
{
	/* ethernet headers are always exactly 14 bytes */
	#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;


	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	unsigned short int payload_len = 0;
	payload_len = ntohs(ip->ip_len) - size_ip - size_tcp ;
		      // big -> little
	printf("INFO: payload_len = %u \n", payload_len);

	printf("Jacked a packet with length of [%d]\n", header->len);
	
	// printf Ethernet address
	printf("DATA: dest MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
					 ethernet->ether_dhost[0],
					ethernet->ether_dhost[1],
					ethernet->ether_dhost[2],
					ethernet->ether_dhost[3],
					ethernet->ether_dhost[4],
					ethernet->ether_dhost[5]
					);

	printf("DATA: dest src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
					 ethernet->ether_shost[0],
					ethernet->ether_shost[1],
					ethernet->ether_shost[2],
					ethernet->ether_shost[3],
					ethernet->ether_shost[4],
					ethernet->ether_shost[5]
					);
	
	char* IPbuffer, *IPbuffer2;
	char IPbuffer_str[16]; // 123.123.123.123 this lentgh 16 ( include . )
	char IPbuffer2_str[16];



	// printf IP addrs	
	IPbuffer = inet_ntoa(ip->ip_src);
	strcpy(IPbuffer_str, IPbuffer);

	IPbuffer2 = inet_ntoa(ip->ip_dst);
	strcpy(IPbuffer2_str, IPbuffer2);

	printf("DATA: IP src : %s\n", IPbuffer_str);
	printf("DATA: IP dst : %s\n", IPbuffer2_str);



	// print tcp port number .
	unsigned short tcp_src_port = 0;
	unsigned short tcp_dst_port = 0;

	tcp_src_port = ntohs(tcp->th_sport);
	tcp_dst_port = ntohs(tcp->th_dport);

	printf("DATA : src Port : %u\n", tcp_src_port);	
	printf("DATA : dst Port : %u\n", tcp_dst_port);	

	u_char* domain = NULL;
	u_char* domain_end = NULL;
	u_char domain_str[256] = { 0x00};

	int domain_len = 0;

	domain = strstr(payload, "Host: ");
	if ( domain != NULL ) {
		domain_end = strstr(domain, "\x0d\x0a");
		if ( domain_end != NULL ) {
			domain_len = domain_end - domain - 6;
			strncpy(domain_str, domain + 6 , domain_len);
			printf("INFO: Domain = %s . \n", domain_str);
		}

	} else {
		printf("INFO: Host string not found \n");
	}


	printf("\n");


} // end of got_packet
```


</div>
</details>




# 코드 분석


## 1. 변수 선언
```c
    pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
```

### 1. pcap_t *handle
pcap_t 구조체는 네트워크 디바이스나 패킷에 들어있는 pcap파일에서 패킷을 읽는데 사용된다. <br>

### 2. char* dev
char* dev 라는 변수를 만들어 device의 정보를 담으려 했고, <br>
```c
dev = pcap_lookupdev(errbuf);
if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return(2);
}
```
<span style="color:yellow"> pcap_lookupdev() </span>함수를 사용하여, 현재 사용중인 디바이스를 반환받아 dev에 저장하려 했다 !
예상 결과 : enp0s3 라는 device의 이름이 dev에 저장된다. <br>


### 3. char errbuf[PCAP_ERRBUF_SIZE]
에러 문자열을 저장하기 위한 배열을 선언하였다. <br>
<span style="color:violet"> PCAP_ERRBUF_SIZE </span> 는 <span style="color:violet"> 256바이트 </span> 이다. 



### 4. struct bpf_program fp
bpf_program 구조체를 사용하기 위한 변수 선언



### 5. char filter_exp[] = "port 80"
<span style="color:yellow"> pcap_compile() </span>함수에서 필터링을 쓰기위한 조건을 위해 선언한 변수이다. <br>



### 6.bpf_u_int32 mask;		bpf_u_int32 net;
IP와 netmask를 저장하기 위한 변수 선언이다.


### 7. struct pcap_pkthdr header

```c
원형
struct pcap_pkthdr {
     struct timeval ts;
     bpf_u_int32 caplen; 
     bpf_u_int32 len;    
 };
```
1. ts -> time stamp
2. <span style="color:green"> caplen -> captured length </span> 로 실제로 읽은 길이를 뜻한다.
3. <span style="color:yellow"> len -> length </span> 이번에 캡쳐한 패킷의 길이이다.

- 예시) 패킷의 길이가 <span style="color:violet"> 100 바이트 </span> 인데 패킷의 캡쳐 길이제한을 <span style="color:violet"> 60바이트 </span> 로 두었다면, <br>
<span style="color:green"> caplen </span> 은 <span style="color:violet"> 60바이트 </span> 가 되고, <span style="color:yellow"> len </span> 은 <span style="color:violet"> 100바이트 </span> 가 된다.


	
### 8. const u_char *packet







<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>

# 사용한 pcap 라이브러리의 함수 총 정리


## 2-1. pcap_lookup

```c
char* pcap_lookup(char* errbuf)
```

1. `Return Value` <br>
<span style="color:#00FF00"> `성공시:` </span>  <span style="color:#00FF00"> 현재 사용중인 디바이스 </span> <br>
<span style="color:#FF0000"> `실패시:` </span> <span style="color:#FF0000"> 0 </span><br>
 
2. `Parameter` <br>
<span style="color:#87CEEB"> `char* errbuf` </span> <span style="color:#87CEEB"> 에러에 관한 내용을 저장  </span> <br>



<br>
<br>
<br>
<br>


## 2-2. pcap_lookupnet

```c
int pcap_lookupnet(char* device, bpf_u_int32 *netp, bpf_u_int32* maskp, char* errbuf)
```

1. `Return Value` <br>
<span style="color:#00FF00"> `성공시:` </span>  <span style="color:#00FF00"> 각 포인터에 해당 정보를 저장 </span> <br>
<span style="color:#FF0000"> `실패시:` </span> <span style="color:#FF0000"> -1 </span><br>
 
2. `Parameter` <br>
<span style="color:#87CEEB"> `errbuf` </span> <span style="color:#87CEEB"> 에러에 관한 내용을 저장 </span> <br>
<br>
<br>
<br>
<br>



## 2-3. pcap_open_live

```c
pcap_t* pcap_open_live(const char* device, int snaplen, int promisc, int to_ms, char* errbuf);
```

1. `Return Value` <br>
<span style="color:#00FF00"> `성공시:` </span>  <span style="color:#00FF00"> Descriptor 반환 </span> <br>
<span style="color:#FF0000"> `실패시:` </span> <span style="color:#FF0000"> NULL </span><br>
 
2. `Parameter` <br>
<span style="color:#87CEEB"> `const char*` </span> <span style="color:#87CEEB"> 어떤 Descriptor를 가져와야할지 판단 </span> <br>
<span style="color:#87CEEB"> `int snaplen` </span> <span style="color:#87CEEB"> 받아들이는 최대 패킷의 길이를 설정 </span> <br>
<span style="color:#87CEEB"> `promisc*` </span> <span style="color:#87CEEB"> promiscuous 모드를 설정할 수 있다 <br>
-> 0 : 자기 자신과 관련된 패킷만 캡쳐 <br>
-> 1 : 모든 패킷을 캡쳐 </span> <br>
<span style="color:#87CEEB"> `int to_ms` </span> <span style="color:#87CEEB"> 시간 초과 기준 설정 (milli second 단위) </span> <br>

<br>
<br>
<br>
<br>



## 2-4. pcap_compile

```c
int pcap_compile(pcap_t *p, struct bpf_program *fp, char* str, int optimize, bpf_u_int32 netmask);
```

- <span style="color:yellow"> `역할:` </span> 들어오는 패킷을 <span style="color:yellow"> 필터링 </span> 해서 받아들이기 위해 사용한다.

<span style="color:#87CEEB"> `char* str` </span> <span style="color:#87CEEB"> 필터링할 조건을 문자열 형태로 가져온다. <br>
<br>
예시) <br>
```php
host advent.perl.kr      # advent.perl.kr 과 통신하는 모든 패킷 
dst host advent.perl.kr  # destination 이 advent.perl.kr 인 패킷 
src host advent.perl.kr  # source 가 advent.perl.kr 인 패킷 
port 80                  # port가 80인 패킷 
dst port 80              # destination port 가 80인 패킷 
src port 80              # source port 가 80인 패킷 
len <= 10                # 10 바이트 이하인 패킷 
len >= 10                # 10 바이트 이상인 패킷 
```






</span> <br>

<br>
<br>
<br>
<br>


## 2-5. pcap_setfilter

```c
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
```
- <span style="color:yellow"> `역할:` </span> <span style="color:yellow"> pcap_compile() </span> 로 컴파일된 필터 프로그램(fp)을 p에 지정할 때 사용한다. <br>


<br>
<br>
<br>
<br>




## 2-6. pcap_loop

```c
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char* user)
```

1. `Return Value` <br>
<span style="color:#00FF00"> `성공시:` </span>  <span style="color:#00FF00"> cnt를 모두 소진이 0을 반환한다. </span> <br>
<span style="color:#FF0000"> `실패시:` </span> <span style="color:#FF0000"> pcap_breakloop()함수가 호출되어 cnt를 모두 소진하기 전에 loop가 깨지면 PCAP_ERROR_BREAK 를 반환한다. </span><br>
 
2. `Parameter` <br>
<span style="color:#87CEEB"> `pcap_t *p` </span> <span style="color:#87CEEB"> p를 통해서 PCD(Packet capture Descriptor)를 반환한다. </span> <br>
<span style="color:#87CEEB"> `int cnt` </span> <span style="color:#87CEEB"> 캡쳐할 패킷의 수를 정한다. </span> <br>
<span style="color:#87CEEB"> `pcap_handler callback` </span> <span style="color:#87CEEB"> 패킷을 받을 때 호출할 callback 함수를 지정한다. </span> <br>
<span style="color:#87CEEB"> `u_char* user` </span> <span style="color:#FF0000"> 아직 잘 모르겠다.. </span> <br>

<br>
<br>
<br>
<br>




<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>


# 피드백 & Tips

1. gcc 할 때 file 사용

```c
file="pcap-003" ; gcc -o $file $file.c -lpcap && ./$file
```

2. echo $?

0이면 정상종료 <br>
오류가 났을 때는 1로 나오게 됨 ( 숫자가 커질수록 보통 더 오류가 심각함 )



3. printf로 줄 찾기 힘들 때 
(사진첨부)

%s:%d (%s), __FILE__, __LINE__, __FUNCTION__


4. 주석처리
#define commentout

#ifdef commentout

define 안되어있으면 아예 안하게 됨

#endif



5. 와샼
패킷이 너무 많으면 필터링해서 나온 패킷만 저장ㄱㄱ
file -> export specific packets 하면 됨