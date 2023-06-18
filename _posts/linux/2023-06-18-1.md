---
title:  "[Linux] 실습 환경을 위한 설치 과정" 

categories:
  - Linux
tags:
  - [Linux, server, client]

toc: true
toc_sticky: true

date: 2023-06-18
last_modified_at: 2023-06-18
---

## ▶ 1. iso 파일을 이용한 설치
>컴퓨터 사양문제로 최신버전이 아닌 구버전으로 실행했음 !!
<br>
- [우분투 20.4 버전(구버전)과 ubuntu-20.04.6-live-server-amd64.iso ( 2개를 다운 받을 것 )](https://releases.ubuntu.com/20.04/)
- [mate-client](https://releases.ubuntu-mate.org/20.04/amd64/)
- [win-client는 구글드라이브 공유](https://drive.google.com/file/d/1Qi8jSgH0qgpIFOa_PfM1HUWcBeFPLAzc/view?usp=sharing)
<br>

- 총 3개를 다운 받은 뒤 hdd에 옮겨놓기
- 꼭 SDD에 드라이버들을 설치하기

### ▶ 1-1. 설치하는 동안 NAT network 미리 설정해주기
![NAT network 설정 2023-06-18 131821](https://github.com/whalebee/Whalebee.github.io/assets/127908829/18712431-0564-41ce-a386-ae19a82624ed)
1. Tools -> Network
2. NAT Networks 클릭
3. Create로 만들어주자
4. Name은 알아볼 수 있으면 되고, IPv4의 prefix는 사용할 네트워크의 주소를 쓰면 된다 !



## ▶ 2. 설치 후 각 서버와 클라이언트들의 세부 설정
### ▶ 2-1. server a 세부 설정
- 먼저 server a의 NAT Network 설정
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/29581a59-f289-4fd0-9d0f-e6896425b2d7)
- 1번부터 3번까지의 과정을 거쳐서 [1-1(NAT network 미리 설정하기)](#-1-1-설치하는-동안-nat-network-미리-설정해주기)에서 설정한 NAT network를 지정해준다.
- try로 시작하여 해상도 설정부터 먼저해주면 편하다.
- 파티션 설정을 위해 드라이브를 지우지말고 else로 선택하여 파티션을 나눈다.
- 파티션은 총 2개 / 1개는 용량: 8192, swap area / 다른 한 개는 용량: 나머지 전부, ex4,  mount point: / (루트)로 지정하고 Next

**중요한 점<br>
Version upgrade 금지 ! ( 사양 낮은 곳에서 일부로 버전 낮게 선택했기 때문 ) <br>
software update는 실행해야한다 !**
{: .notice--primary}

- <u>DHCP 해제</u>와 <u>Static IP 설정</u>을 위해 다음처럼 <u>Wired Settings</u>에 들어간다
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/350709e6-f22d-4d49-bdbc-3fedd9544e6d)
- <u>번호 순서대로 설정</u>해준다
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/5dd58dbf-d5e6-4fb7-924e-f375a83df0f1)
- 그 뒤로 <u>Ctrl + Alt + T</u>로 Terminal을 열어서 다음과 같이 입력한다.
```
$ apt update
$ apt upgrade
$ apt install net-tools  ( ifconfig 를 위함 )
-> ifconfig로 192.168.111.100 확인
$ apt install vim ( vim 설치 )
```

### ▶ 2-2. server b 세부 설정
- server a와 <u>똑같이</u> NAT Network 설정해준다
- server a는 GUI지만 server b는 CLI이기때문에 살짝 다를 수 있다.
- 하지만 파티션은 Swap area만 2G로 설정해주고 나머지는 통으로 ex4 그리고 중간에 나오는 Custom 설정부분만 space_bar로 Check해주고 넘어가면 된다.
- server b의 **ip설정도 GUI와 다르기 때문에** 스크린샷을 첨부하여 설명해줄게
- 먼저 `$ cd /etc/netplan` 명령어로 netplan 폴더로 이동한다.
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/f56b4537-7425-44b5-bec7-de25dd6b6dcb)
- `$ vi 00-installer-config.yaml` 명령어로 편집모드로 들어가서 **아래와 똑같이** 입력해주자
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/751f7664-c8a5-4c5c-906a-4d4b327231e2)

```
$ apt update
$ apt upgrade

vim과 net-tools는 이미 설치되어 있다 !
``` 

### ▶ 2-3. mate-client 세부 설정
- NAT Network 설정
- 설치시 모두 default 설정으로 해준다
- 파티션 할 필요 X / Normal installation / Don't Upgrade  <u>but</u> **do software update**
- 리스타트 후에 아래 명령어들을 입력하여 도구 설치

```
$ apt install net-tools
-> ifconfig 확인 필요 !
```

### ▶ 2-4. win-client 세부 설정
- NAT Network 설정
- 파티션은 새로 만들기 -> 디폴트 설정으로 만들어주면 된다 ( 시스템 쓸 곳이 자동으로 나눠짐 )
- `appwiz.cpl`명령어로 telnet 아래와 같이 <u>Telnet</u> 클라이언트를 활성화 시켜준다 !
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/c5238bed-5bb7-4200-87e8-ceea64faf3c8)
- <u>putty</u> 다운로드 ( Drag and Drop 을 쓰거나 chrome을 설치하여 다운로드 하면 된다. )


## ▶ 3. 프로토콜을 사용한 서버와 클라이언트의 연결 과정

### ▶ 3-1. Server a
#### ▶ 3-1-1. Server a에서의 <u>telnet</u> 설정
- `$ apt install xinetd telnetd` 명령어로 <u>telnet</u>설치
- `vi /etc/xinetd.d/telnet` 파일 설정해준다 ( 아래와 똑같이 입력할 것!! )
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/e08d98f2-4818-4a18-9c5d-e88b25afd5bd)
- systemctl 3형제라 부르는 restart, enable, status 시작
  - `$ systemctl  restart xinetd`
  - `$ systemctl enable xinetd`
  - `$ systemctl status xinetd`
- <u>telnet</u>의 방화벽 설정
  - `$ ufw enable`
  - `$ ufw allow 23/tcp`
  - `$ ufw status`으로 확인
#### ▶ 3-1-2. server a에서의 <u>ssh</u> 설정
- `$ apt install openssh-server`명령어로 ssh 설치
- 설정은 따로 해줄 것이 없다
- 시스템 3형제 ( enable 부분이 조금 다르니 주의해서 보길 ! )
  - `$ systemctl restart ssh`
  - `$ /lib/systemd/systemd_sysv-install enable ssh`
  - `$ systemctl status ssh`
- 방화벽 설정
  - `$ ufw enable`
  - `$ ufw allow 22/tcp`
  - `$ ufw status`으로 확인

#### ▶ 3-1-3. server a에서의 <u>NS(system: bind9)</u> 설정
- `$ apt install bind9 -y` ( -y는 묻는 질문에 모두 yes로 하겠다는 것 ! )
- `$ apt install bind9utils -y`
- 시스템 3형제 ( enable이 <u>불가능</u> 하다 ! )
  -`$ systemctl restart bind9`
  -`$ systemctl status bind9`
- 방화벽 설정
  - `$ ufw enable`
  - `$ ufw allow 53` DNS의 포트번호이며 tcp와 udp 둘 중 아무것도 적지 않을 땐 모두 열어주게 된다.
  - `$ ufw status`으로 확인
- `$ vi /etc/bind/named.conf` 명령어 입력 후 아래와 <u>똑같이</u> 설정 ( http와 ftp를 사용하기 위한 사전 설정 )
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/3672d0f2-9d44-4f23-bb13-987410775962)
- `$ cd /etc/bind` 폴더 이동
- `$ named-checkconf` 문법적 오류 여부 검사를 위한 명령어 입력
- `$ vi /etc/bind/john.com.db` www와 ftp를 동시에 사용하기 위한 설정(2번째)이므로 아래와 <u>똑같이</u> 작성
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/2a920350-8b73-4759-b585-9ceee7a79b91)
- **/etc/bind 폴더에서** `$ named-checkzone john.com john.com.db` 문법적 오류 검사 -> OK 나오면 완료

#### ▶ 3-1-4. server a에서의 <u>apache2</u> 설정
- `$ apt install apache2` 명령어로 apache2 설치
- 시스템 3형제
  - `$ systemctl restart apache2`
  - `$ /lib/systemd/systemd_sysv-install enable apache2`
  - `$ systemctl status apache2`
- 방화벽 설정
  - `$ ufw enable`
  - `$ ufw allow 80` DNS의 포트번호이며 tcp와 udp 둘 중 아무것도 적지 않을 땐 모두 열어주게 된다.
  - `$ ufw status`으로 확인
- `$ cd /var/www/html` 편집을 위하여 폴더 이동
- `$ cp index.html index.html.bak` 명령어로 index.html 백업
- `$ rm index.html` 백업 후에 기존 파일 삭제
- `$ vi index.html` HTML 꾸미듯이 꾸며주고 저장

### ▶ 3-2. server b
#### ▶ 3-2-1. server b에서의 <u>ftp</u> 설정
- `$ apt install vsftpd`명령어로 ftp 설치 ( ftp의 service name은 vsftpd 이다 )
- `$ cd /srv/ftp`로 폴더 이동 후 설정을 하려한다.
- `$ vi welcome.msg` 편집모드로 아래와 같이 배너 파일 설정해주기
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/9c13ab07-80bc-4c53-9bc7-d6c89d0a56e7)
- `$ vi /etc/vsftpd.conf` 명령어로 아래와 같이 ftp 설정해주기 ( 26 ~ 27번 line에 있다 ! )
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/99cb6763-b47a-46df-9e6f-380e477814b1)
```
틀리면 오류가 생기니 틀리지 말고 제대로 적자 !
$ anonymous_enable = YES
$ banner_file=/srv/ftp/welcome.msg 
```
- 시스템 3형제 ( enable 부분이 조금 다르니 주의해서 보길 ! )
  - `$ systemctl restart vsftpd`
  - `$ /lib/systemd/systemd_sysv-install enable vsftpd`
  - `$ systemctl status vsftpd`
- 방화벽 설정
  - `$ ufw enable`
  - `$ ufw allow 21/tcp` 
  - `$ ufw status`으로 확인

### ▶ 3-3 mate-client
#### ▶ 3-3-1 mate-client <u>telnet</u> 설정 & Test
- `$ apt install net-tools` 설치
- `$ telnet 192.168.111.100` Test

#### ▶ 3-3-2 mate-client <u>ssh</u> 설정 & Test
- `$ ssh ubuntu@192.168.111.100` Test
#### ▶ 3-3-3 mate-client <u>ftp</u> 설정 & Test
- `$ ftp 192.168.111.100` Test
#### ▶ 3-3-4 mate-client <u>ns</u> 설정 & Test
```
`$ vi /etc/host.conf`명령어로 order(순서)를 확인할 수 있다 ! ( 참고용 )
```
- `$ vi /etc/resolv.conf`명령어로 nameserverf를 server a의 IP주소로 바꿔준다.
- `$ ifconfig`입력시 개인의 IP가 나와야한다. 192.168.111.?
- `$ nslookup www.google.com`입력시 address에는 <u>server a</u>의 IP주소가 나와야한다
- 인터넷(FireFox)으로 `www.john.com` 입력하여 테스트
#### ▶ 3-3-5 mate-client <u>apache2</u> 설정 & Test
- 인터넷에 server a의 IP주소를 입력하면 server a의 /var/www/html/index.html에서 설정한 내용들이 나오는지 확인

### ▶ 3-4 win-client
#### ▶ 3-4-1 win-client <u>telnet</u> 설정 & Test
- putty로 server a의 IP주소와 port번호를 입력하여 접속
#### ▶ 3-4-2 win-client <u>ssh</u> 설정 & Test
- putty로 server a의 IP주소와 port번호를 입력하여 접속
#### ▶ 3-4-3 win-client <u>ftp</u> 설정 & Test
- putty로 server a의 IP주소와 port번호를 입력하여 접속
#### ▶ 3-3-4 win-client <u>ns</u> 설정 & Test
- DHCP 적용을 위해 실행창에 <u>ncpa.cpl</u> 입력 후 네트워크 설정해준다
- 로컬 영역 연결 -> 오른쪽 클릭 후 속성 -> IPv4 속성에 들어간 다음 아래와 같이 DNS를 수동으로 설정해주고 DNS 주소 입력
- ![image](https://github.com/whalebee/Whalebee.github.io/assets/127908829/68611ebf-591c-4dd9-8adb-83f2773e571e)
- 인터넷에 `www.john.com` 입력으로 테스트
#### ▶ 3-4-5 win-client <u>apache2</u> 설정 & Test
- 인터넷에 server a의 IP주소를 입력하면 server a의 /var/www/html/index.html에서 설정한 내용들이 나오는지 확인






[맨 위로 이동하기](#){: .btn .btn--primary }{: .align-right}