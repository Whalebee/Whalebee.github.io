---
title:  "[Linux] Kali 설치"

categories:
  - Linux
tags:
  - [Linux, server, client, kali] 

toc: true
toc_sticky: true

date: 2023-06-20
last_modified_at: 2023-06-24
---
<!-- post 폴더 이름 -> 연관성을 찾지못함 ( 이상하게 바꿔도 정상적으로 작동했기때문 ) -->
```
백견이 불여일타
벽타가 불여일작 !!
```

## 1. Kali 설치

### 1-1. Kali.iso insert
- (just) install not graphic install
- name: kali / passwd: ubuntu
- default setting, but only different setting is pacific
- just continue again and again until install's finished

### 1-1. Run kali
```
$ passwd
:ubuntu

$ ifconfig
( already installed )

$ vim 
( already installed )

$ ufw
( not installed, but you don't need installed
 because of teacher's don't installed too )
```
- IP 설정을 위해 오른쪽 Network부분 오른쪽 클릭
- IP 추가
- IP 192.168.111.111/24
- Gateway 192.168.111.1
- dns KT default ( 168.126.63.1 )
- 여기까지 한 다음에 $ ping www.google.com 테스트

- 업데이트하려하지만 옛날 kali라서 오류 발생
```
$ wget -q -O - https://archive.kali.org/archive-key.asc  | apt-key add
입력 후
$ apt update
$ apt upgrade -y ( 굉장히 오래 걸림 )
```



## 2. Win-client
### 2-1. IIS 설치 ( internet information server )
- appwiz.cpl로 ftp설치한 것과 같이 아래처럼 설치해준다
- ![K-004](https://github.com/whalebee/Whalebee.github.io/assets/127908829/e3062f92-1ef8-4395-af94-1ba53b61f0f5)
- 3개 부분 체크
- DHCP 해제
- win-client의 핑을 알기 위해 cmd에서 ipconfig
- firewall.cpl로 방화벽 해제 필요
	- 고급설정 -> 인바운드 -> web 서비스를 규칙사용으로 설정을


## 3. server a
- 파이어폭스에서 win-client IP 입력 !
- IIS 확인
