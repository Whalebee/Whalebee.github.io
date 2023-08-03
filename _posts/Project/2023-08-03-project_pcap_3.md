---
title:  "[Project] 프로젝트 pcap 라이브러리 도메인 차단"

categories:
  - Project
tags:
  - [project, C, linux, pcap] 

toc: true
toc_sticky: true

date: 2023-08-03
last_modified_at: 2023-08-03
---



<details>
<summary> <span style="color:yellow"> 코드 </span> </summary>
<div markdown="1">

```c
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#define ETHER_ADDR_LEN 6

struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct sniff_ip {
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;

#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	
	struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip)	(( (ip)->ip_vhl ) & 0x0f)
#define IP_V(ip)	(( (ip)->ip_vhl ) >> 4)


typedef u_int tcp_seq;
struct sniff_tcp {
	u_short th_dport;
	u_short th_sport;
	tcp_seq th_seq;
	tcp_seq th_ack;

	u_char th_offx2;
#define TH_OFF(tcp)	(( (tcp)->th_offx2 & 0xf0) >> 4 )
	u_char th_flags;

	
#define TH_FIN 0x01
#define TH_SYN 0x02 
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CRW 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CRW)

	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char* packet);

int main( int argc, char *argv[])
{

	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle;

	bpf_u_int32 net;
	bpf_u_int32 mask;

	struct bpf_program fp;
	char filter_exp[] = "port 80";

	struct pcap_pkthdr header;
	const u_char *packet;


	dev = pcap_lookupdev(errbuf);
	if( dev == NULL ) {
		fprintf(stderr, "could not find default device %s \n", errbuf);
		return 2;
	}

	if( pcap_lookupnet(dev, &net, &mask, errbuf) == -1 ) {
		fprintf(stderr, "could not get netmask for device %s : %s \n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if( handle == NULL ) {
		fprintf(stderr, "could not open device %s : %s \n", dev, errbuf);
		return 2;
	}

	if( pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ) {
		fprintf(stderr, "could not parse filter %s : %s \n", filter_exp, pcap_geterr(handle));
		return 2;
	}

	if( pcap_setfilter(handle, &fp) == -1 ) {
		fprintf(stderr, "could not install filter %s : %s \n", filter_exp, pcap_geterr(handle));
		return 2;
	}


	int result = 0;
	result = pcap_loop(handle, 0, got_packet, NULL);
	if( result != 0 ) {
		fprintf(stderr,"ERROR : pcap_loop() end with error !!! \n");
	} else {
		fprintf(stdout,"INFO : pcap_loop() end without error \n");
	}

	pcap_close(handle);

	return 0;
} // end of main() .

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char* packet)
{
	#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if( size_ip < 20 ) {
		fprintf(stderr, " * Invalid IP Header Length %u bytes \n", size_ip);
	}

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if( size_tcp < 20 ) {
		fprintf(stderr, " * Invalid TCP Header Length %u bytes \n", size_tcp);
	}

	payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);


	unsigned short int payload_len = 0;
	payload_len = ntohs(ip->ip_len) - size_ip - size_tcp;

//	printf("DATA: payload_len %u \n", payload_len);
//
//	printf("Jacked a packet with Length of [%d] \n", header->len);
//
//
//	printf("DATA: dest MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
//			ethernet->ether_dhost[0],
//			ethernet->ether_dhost[1],
//			ethernet->ether_dhost[2],
//			ethernet->ether_dhost[3],
//			ethernet->ether_dhost[4],
//			ethernet->ether_dhost[5]
//			);
//
//
//
//	printf("DATA: src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
//			ethernet->ether_shost[0],
//			ethernet->ether_shost[1],
//			ethernet->ether_shost[2],
//			ethernet->ether_shost[3],
//			ethernet->ether_shost[4],
//			ethernet->ether_shost[5]
//			);


	// IP
	char *IPbuffer, *IPbuffer2;
	char IPbuffer_str[16];
	char IPbuffer2_str[16];


	IPbuffer = inet_ntoa(ip->ip_src);
	strcpy(IPbuffer_str, IPbuffer);

	IPbuffer2 = inet_ntoa(ip->ip_dst);
	strcpy(IPbuffer2_str, IPbuffer2);

//	printf("DATA: IP src : %s \n", IPbuffer_str);
//	printf("DATA: IP dst : %s \n", IPbuffer2_str);

	// port
	unsigned short tcp_src_port = 0;
	unsigned short tcp_dst_port = 0;

	tcp_src_port = ntohs(tcp->th_sport);
	tcp_dst_port = ntohs(tcp->th_dport);


//	printf("DATA : src Port %u \n", tcp_src_port);
//	printf("DATA : dst Port %u \n", tcp_dst_port);


	// domain
	u_char *domain = NULL;
	u_char *domain_end = NULL;
	u_char domain_str[256] = { 0x00};

	int domain_len = 0;

	domain = strstr(payload, "Host: ");
	if( domain != NULL ) {
		domain_end = strstr(domain, "\x0d\x0a");
		if( domain_end != NULL ) {
			domain_len = domain_end - domain - 6;
			strncpy(domain_str, domain + 6, domain_len );
//			printf("INFO: Domain : %s \n", domain_str);
		} else {
//			printf("INFO: Host string not found \n");
		}
	}



// new -------------------------------------
// i know struct declare at the outside . ( temp )
struct check_domain_struct {
	char domain[256];
};




// reset method 1 ( if i were have not DB )
//struct chk_domain_struct chk_domain_str[100] = { 0x00 };
//
//char *chk_domain_ptr[100] = { NULL };
//char *chk_strcpy[100] = { NULL };
//
//for(int i = 0; i < 100; i++) {
//	chk_domain_ptr[i] = malloc(256);
//	if( chk_domain_ptr[i] == NULL ) {
//		fprintf(stderr, "ERROR: malloc() fail !! \n");
//	}
//} // end for loop 
//
//
//// strcpy & check
//strcpy(chk_domain_ptr[0], "naver.com");
//if( strlen(chk_domain_ptr[0]) == 0 )
//	 fprintf(stderr, "chk_domain_ptr[0] is NULL !! \n");
//strcpy(chk_domain_ptr[1], "kakao.com");
//if( strlen(chk_domain_ptr[1]) == 0 )
//	 fprintf(stderr, "chk_domain_ptr[1] is NULL !! \n");
//strcpy(chk_domain_ptr[2], "mail.naver.com");
//if( strlen(chk_domain_ptr[2]) == 0 )
//	fprintf(stderr, "chk_domain_ptr[2] is NULL !! \n");
//// printf("%s \n", chk_domain_ptr[0]);




// reset method 2 ( declare & reset at the same time )
//struct chk_domain_struct chk_domain_str[100];
//for( int j = 0 ; j < 100 ; j++ ) {
//	strcpy(chk_domain_str[j].domain, "");
//}


//// method 2 strcpy & check .
//strcpy(chk_domain_str[0], "naver.com");
//if( strlen(chk_domain_str[0]) == 0 )
//	 fprintf(stderr, "chk_domain_str[0] is NULL !! \n");
//strcpy(chk_domain_str[1], "kakao.com");
//if( strlen(chk_domain_str[1]) == 0 )
//	 fprintf(stderr, "chk_domain_str[1] is NULL !! \n");
//strcpy(chk_domain_str[2], "mail.naver.com");
//if( strlen(chk_domain_str[2]) == 0 )
//	fprintf(stderr, "chk_domain_str[2] is NULL !! \n");
//// printf("%s \n", chk_domain_str[0]);


// reset method 3 ( use this )
int check_domain_str_count = 10000;
struct check_domain_struct *check_domain_str = NULL;

// malloc
check_domain_str = malloc ( sizeof(struct check_domain_struct) *
			check_domain_str_count
			);
if( check_domain_str == NULL ) {
	fprintf(stderr, "ERROR: malloc fail !!! (line=%d) \n", __LINE__);
} else {
//	fprintf(stdout,"INFO: malloc ok (line=%d) \n", __LINE__);
}


// reset 0
memset( check_domain_str, 0x00, sizeof( struct check_domain_struct ) *
					check_domain_str_count
	);



// method 3 strcpy & check .
strcpy(check_domain_str[0].domain, "naver.com");
if( strlen(check_domain_str[0].domain) == 0 )
	 fprintf(stderr, "check_domain_str[0] is NULL !! \n");
strcpy(check_domain_str[1].domain, "kakao.com");
if( strlen(check_domain_str[1].domain) == 0 )
	 fprintf(stderr, "check_domain_str[1] is NULL !! \n");
strcpy(check_domain_str[2].domain, "mail.naver.com");
if( strlen(check_domain_str[2].domain) == 0 )
	fprintf(stderr, "check_domain_str[2] is NULL !! \n");
// printf("%s \n", check_domain_str[0]);




if( domain_len ) {
	int cmp_ret = 1; // for compare result


	// start for loop 1 .
	for(int i = 0; i < 100; i++ ) {

	// reset method 2
	// cmp_ret = strcmp(check_domain_ptr[i], domain_str);


	
	// if you knew str_len, you choice method like this
	int str1_len = strlen ( check_domain_str[i].domain );
	int str2_len = strlen ( domain_str );

	if( str1_len != str2_len ) {
		continue; // move to next array !
	}

	cmp_ret = strcmp(check_domain_str[i].domain, domain_str);
	printf("DEBUG: domain name check result : %d \n", cmp_ret);

	if( cmp_ret == 0 )
		break; // stop for loop 1 .
	
	// break if meet NULL data in array .
	if( strlen( check_domain_str[i].domain) == 0 ) {
		break; // stop for loop 1.
	}

	} // end for loop 1 .

	printf("DATA: IP src : %s \n", IPbuffer_str);
	printf("DATA: IP dst : %s \n", IPbuffer2_str);

	printf("DATA : src Port %u \n", tcp_src_port);
	printf("DATA : dst Port %u \n", tcp_dst_port);
	
	printf("INFO: Domain : %s . \n", domain_str);

	if( cmp_ret == 0 ) {
		printf("DEBUG: main blocked . \n");
	// sendraw(); // here is block packet function location later
	} else {
		printf("DEBUG: domain allowed . \n");
	} // end if emp_ret .


	if( check_domain_str != NULL ) {
		free(check_domain_str);
		check_domain_str = NULL;
	} else {
		fprintf(stderr, "CRIT: check_domain_str was already free status !! (line=%d) \n", __LINE__);
	} // end check_domain_str

	} // end if domain_len

//	printf("\n");

} // end of got_packet()
```


</div>
</details>

<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>



# 코드 분석


## domain 구조체 선언
```c
struct check_domain_struct {
	char domain[256];
};
```
domain 주소를 담을 구조체를 선언했다. <br>
다른 방법들이 있지만 구조체로 하는 것부터 해보자. <br>


## <span style="color:gray"> 1. reset을 하는 첫번째 방법 </span>
- <span style="color:yellow"> 안 좋은 방법 </span> 이지만 <span style="color:yellow"> DB가 없을 때 </span>를 가정한 <span style="color:#FF0000"> 하드 </span> 코딩 방법이다.


### <span style="color:gray"> 1-1. 선언 부분 </span>
```c
// reset method 1 ( if i were have not DB )
struct check_domain_struct check_domain_str[100] = { 0x00 };

char *chk_domain_ptr[100] = { NULL };

for(int i = 0; i < 100; i++) {
	chk_domain_ptr[i] = malloc(256);
	if( chk_domain_ptr[i] == NULL ) {
		fprintf(stderr, "ERROR: malloc() fail !! \n");
	}
} // end for loop 

```
- 먼저 check_domain_struct 구조체를 사용해서 배열 100개를 만들고 그 자리를 모두 힙 영역에 malloc으로 메모리를 할당 시켜주었다.
- malloc을 사용할 때 항상 fail check를 할 것 !

<br>
<br>
<br>
<br>

```c
// strcpy & check
strcpy(chk_domain_ptr[0], "naver.com");
if( strlen(chk_domain_ptr[0]) == 0 )
	 fprintf(stderr, "chk_domain_ptr[0] is NULL !! \n");
strcpy(chk_domain_ptr[1], "kakao.com");
if( strlen(chk_domain_ptr[1]) == 0 )
	 fprintf(stderr, "chk_domain_ptr[1] is NULL !! \n");
strcpy(chk_domain_ptr[2], "mail.naver.com");
if( strlen(chk_domain_ptr[2]) == 0 )
	fprintf(stderr, "chk_domain_ptr[2] is NULL !! \n");
// printf("%s \n", chk_domain_ptr[0]);
```
- 하드코딩으로 도메인 주소를 담고 간단하게 길이로 check 해서 strcpy가 잘 되었는지 확인했다.


<br>
<br>
<br>
<br>


## <span style="color:gray"> 2. reset을 하는 2번째 방법 </span>

```c
// reset method 2 ( declare & reset at the same time )
struct chk_domain_struct chk_domain_str[100];
for( int j = 0 ; j < 100 ; j++ ) {
	strcpy(chk_domain_str[j].domain, "");
}

// method 2 strcpy & check .
strcpy(chk_domain_str[0], "naver.com");
if( strlen(chk_domain_str[0]) == 0 )
	 fprintf(stderr, "chk_domain_str[0] is NULL !! \n");
strcpy(chk_domain_str[1], "kakao.com");
if( strlen(chk_domain_str[1]) == 0 )
	 fprintf(stderr, "chk_domain_str[1] is NULL !! \n");
strcpy(chk_domain_str[2], "mail.naver.com");
if( strlen(chk_domain_str[2]) == 0 )
	fprintf(stderr, "chk_domain_str[2] is NULL !! \n");
// printf("%s \n", chk_domain_str[0]);
```

- 간단하게 선언과 동시에 초기화를 해주고 사용한 방법이지만, 첫번째 방법과 두번째 방법 다 권유하지 않는다.

<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>



## <span style="color:#87CEEB"> 3. reset을 하는 3번째 방법 ( 이 방법 사용 ) </span>


### 3-1. 선언과 <span style="color:yellow"> malloc() </span>
```c
// reset method 3 ( use this )
int check_domain_str_count = 10000;
struct check_domain_struct *check_domain_str = NULL;

// malloc
check_domain_str = malloc ( sizeof(struct check_domain_struct) *
			check_domain_str_count
			);
if( check_domain_str == NULL ) {
	fprintf(stderr, "ERROR: malloc fail !!! (line=%d) \n", __LINE__);
} else {
//	fprintf(stdout,"INFO: malloc ok (line=%d) \n", __LINE__);
}
```
- <span style="color:yellow"> malloc() </span> check는 필수이지만 성공했을 때를 굳이 check 할 필요 없어서 주석처리했다.

<br>
<br>
<br>
<br>



```c
// reset 0
memset( check_domain_str, 0x00, sizeof( struct check_domain_struct ) *
					check_domain_str_count
	);
```
- 0으로 초기화 시켜줘야할 때 <span style="color:yellow"> memset() </span>을 사용했다.

<br>
<br>
<br>
<br>



```c
// method 3 strcpy & check .
strcpy(check_domain_str[0].domain, "naver.com");
if( strlen(check_domain_str[0].domain) == 0 )
	 fprintf(stderr, "check_domain_str[0] is NULL !! \n");
strcpy(check_domain_str[1].domain, "kakao.com");
if( strlen(check_domain_str[1].domain) == 0 )
	 fprintf(stderr, "check_domain_str[1] is NULL !! \n");
strcpy(check_domain_str[2].domain, "mail.naver.com");
if( strlen(check_domain_str[2].domain) == 0 )
	fprintf(stderr, "check_domain_str[2] is NULL !! \n");
// printf("%s \n", check_domain_str[0]);
```
- <span style="color:yellow"> strcpy() </span> 와 check는 비슷하나, .domain으로써 <span style="color:#87CEEB"> 구조체의 멤버 </span> 를 사용한다는 것 !! 잊지말자.



### 3-2. <span style="color:#87CEEB"> domain_len </span>의 값이 존재할 때 ( domain 값이 잡혔을 때 )

```c
if( domain_len ) {
	int cmp_ret = 1; // for compare result


	// start for loop 1 .
	for(int i = 0; i < 100; i++ ) {

	// reset method 2
	// cmp_ret = strcmp(check_domain_ptr[i], domain_str);


	
	// if you knew str_len, you choice method like this
	int str1_len = strlen ( check_domain_str[i].domain );
	int str2_len = strlen ( domain_str );

	if( str1_len != str2_len ) {
		continue; // move to next array !
	}

	cmp_ret = strcmp(check_domain_str[i].domain, domain_str);
	printf("DEBUG: domain name check result : %d \n", cmp_ret);

	if( cmp_ret == 0 )
		break; // stop for loop 1 .
	
	// break if meet NULL data in array .
	if( strlen( check_domain_str[i].domain) == 0 ) {
		break; // stop for loop 1.
	}

	} // end for loop 1 .

	printf("DATA: IP src : %s \n", IPbuffer_str);
	printf("DATA: IP dst : %s \n", IPbuffer2_str);

	printf("DATA : src Port %u \n", tcp_src_port);
	printf("DATA : dst Port %u \n", tcp_dst_port);
	
	printf("INFO: Domain : %s . \n", domain_str);

	if( cmp_ret == 0 ) {
		printf("DEBUG: main blocked . \n");
	// sendraw(); // here is block packet function location later
	} else {
		printf("DEBUG: domain allowed . \n");
	} // end if emp_ret .


	if( check_domain_str != NULL ) {
		free(check_domain_str);
		check_domain_str = NULL;
	} else {
		fprintf(stderr, "CRIT: check_domain_str was already free status !! (line=%d) \n", __LINE__);
	} // end check_domain_str

	} // end if domain_len
```
- 이번 부분이 어려운 부분이 없고 설명할 것들을 주석으로 넣어놔서 피드백으로 넘어가서 컴파일 중 주의해야했던 부분들을 적어놓자.

# 피드백 & Tips

1. gdb로 디버거 활용하는 방법을 알아내었고 수시로 잘 쓰도록 하자 <br>
간단한 사용법이다. <br>
- <span style="color:yellow"> gcc로 컴파일 </span> 할 때 <span style="color:#00FF00"> -g </span> 옵션을 넣어서 gdb를 사용할 수 있게 한다.
- 예시: gdb pcap-001 으로 실행한다
- <span style="color:#3399FF"> R</span>un 으로 실행하고 다른 terminal에서 curl로 패킷전송을 시작한다.
- <span style="color:orange"> SegmentFault Core Dump </span> 오류가 떴을 때 <span style="color:yellow"> B</span>ack<span style="color:yellow">T</span>racer 명령어로 쌓인<span style="color:#00FF00"> 스택 </span> 을 찾아간다.
- 이때 보이는 라인의 문법에 <span style="color:#FF0000"> 문제 </span> 가 있는 것이니 수정한다.
- 코어덤프가 아닌 다른 오류가 생긴다면 <span style="color:yellow"> N</span>ext 명령어로 다음을 실행해보며 찾아가면 된다.

2. 오류가 생길 것 같이 예측이 되는 부분은 <span style="color:yellow"> printf() </span>를 사용할 때 <span style="color:#00FF00"> (line=%d) </span>을 사용하고, __LINE__ 이라는 인수를 주면 해당 라인의 번호가 같이 출력된다 !



# 현재까지의 진행상황 중 느낀점
몇 가지 궁금증이 생겼다. <br>
먼저,
## 1. 현재 이 <span style="color:blueviolet"> 프로젝트 </span> 를 진행함에 있어서 <span style="color:#00FF00"> 방향성</span>이 맞는가?
- 결과나 과정들을 제대로 흡수하기 위해서 어떤 방향으로 걸어야하는지 생각하고 있지만, <br>
 오류가 났을 때의 대부분의 원인은 오타였고, 함수를 추가하거나 길을 틀어버려서 <br>
오류들을 발견하고, 그 오류들을 해결하여 경험치가 쌓이는 방법들을 생각해봐야겠다.

<br>
<br>

## 2. 이 <span style="color:blueviolet"> 프로젝트 </span>의 전체 흐름을 보아 <span style="color:#00FF00"> 장단점 </span> 은 무엇이라 생각하는가?
- 장점 <br>
도메인들을 추가하거나 삭제하여 유해사이트를 차단할 수 있다고 생각한다. <br>
현재는 DB와 연결되어있지 않아 하드코딩으로 추가하고 삭제하고 있지만, <br>
Web과 DB를 활용한다면 편리하게 사이트를 차단하고 해제할 수 있다고 생각한다. <br>
또한, 유해사이트를 차단하는 전체 흐름을 이해하고 배울 수 있었다는점이 가장 크다고 생각한다.

- 단점 <br>
역시나 http에서만 작동한다는게 가장 큰 문제점이다. <br>
언젠가는 꼭 https 에서도 작동하는 것들을 배우고 싶다. <br>

## 3. https가 아닌 http에서의 보안 기능을 <span style="color:orange"> 왜 </span> 배운다고 생각하는가?
현재 거의 사용하지 않는 http지만 유해사이트의 차단 흐름이 어떤 식으로 흘러가는지 파악할 수 있었고, <br>
 이 <span style="color:violet"> 프로젝트 </span>를 진행하면서 능력이 쌓이고, 오류들을 해결하는 과정들이 경험이 되었다. <br>
 그로인해 관심과 실력이 늘어날 수 있다면 http로 시작하는 지금의 과정도 중요하다고 생각한다. <br>
기본이 없으면 응용은 배울 수 없는 법이니, 기본부터 탄탄하게 쌓아가자. 
