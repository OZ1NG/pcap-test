# pcap-test

- 과제 링크 : https://gitlab.com/gilgil/sns/-/wikis/pcap-programming/report-pcap-test

- skeleton code : https://gitlab.com/gilgil/pcap-test

- 패킷 디버깅 : https://gilgil.gitlab.io/2020/07/23/1.html

## 준비

  - 라이브러리 설치

    ```bash
    sudo apt install libpcap-dev
    ```

  - 사용

    ```c
    // source code
    # include <pcap.h>
    ...
        
    // link : '-lpcap' 옵션 추가
    ```

## pcap  주요 함수

- [pcap_open_live](https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html)
  
  - pcap 핸들을 live로 여는 함수
  ```c
  pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
  ```
    -  device : 네트워크 장비를 뜻 한다. : interface 이름
    -  snaplen : 캡쳐할 패킷의 최대 바이트 수를 말한다.
    -  promisc : promiscuous mode 여부 : 참이면 사용, 하지만 false여도 특정 경우에는 promiscuous mode가 사용 될 수 있다.
    -  to_ms : 패킷을 읽는데 대기할 시간.(시간초과) (0이면 무한히 기다림.)
    -  ebuf : 에러 버퍼 : 에러 메시지를 저장할 버퍼
    -  return 
       -  pcap 핸들
  
- pcap_close
  
  - pcap 핸들 종료하는 함수
  
  ```c
  void pcap_close(pcap_t *p);
  ```

  - p : pcap 핸들

- [pcap_next_ex](https://www.tcpdump.org/manpages/pcap_next_ex.3pcap.html)
  
  - packet을 수신하는 함수, 수신에 대한 성공 여부를 리턴한다.
  
  ```c
  int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);
  ```

  - p : pcap 핸들

  - pkt_header : pcap_pkthdr 구조체
  
    ```c
    struct pcap_pkthdr {
    	struct timeval ts;	/* time stamp */
    	bpf_u_int32 caplen;	/* length of portion present */
    	bpf_u_int32 len;	/* length this packet (off wire) */
    };
    ```
  
    - ts : 패킷이 잡힌 시간 정보
    - caplen : 실제로 캡쳐된 패킷의 크기(바이트 단위) (이걸 사용하면 된다. 요즘엔 len과 따로 구분을 안한다고 한다.)
    - len : 캡쳐된 패킷의 크기(그냥 모든 바이트 크기)
  
  - pkt_data : 패킷의 실제 데이터
  - return
    - 1 : 수신 성공
    - 0 : 타임 아웃
    - -1 : 어떤 특정한 경우가 발생해서 받아들이지 못함 : PCAP_ERROR
    - -2 : 패킷의 데이터를 전부 읽었을 경우 (EOF) : PCAP_ERROR_BREAK
  
- pcap_sendpacket
  
  - 패킷 송신하는 함수. 근데 레퍼를 못찾았다. 실제로 안쓰이는 걸지도...

- 참고 : https://www.tcpdump.org/pcap.html

- man page : https://www.tcpdump.org/manpages/

# 헤더 정보 정리(과제에 사용한 것들 위주로...)

## Ethernet 헤더

- [참고 사이트](http://www.ktword.co.kr/test/view/view.php?m_temp1=2965)
- 크기 : 14 byte 고정
- Destination : 목적지 MAC
  - size : 6 byte
  - 1바이트당 dot으로 구분된 하나의 octet 값
  - 00 50 56 e4 46 f5 => 00:50:56:e4:46:f5
- Source : 출발지 MAC
  - size : 6 byte
  - 1바이트당 dot으로 구분된 하나의 octet 값
- Length/Type : Length(Ethernet 헤더를 제외한 데이터의 크기) 또는 Type(Ethertype 프로토콜)에 대한 정보
  - size : 2 byte
  - 0x0600 미만이면 Length(IEEE 802.3)로 판단
  - 0x0600 이상이면 Type([Ethertype 프로토콜](http://www.ktword.co.kr/test/view/view.php?m_temp1=2039&id=852))으로 판단
    - 0x0800 : IPv4
    - 0x0806 : ARP
    - 등... 자세한건 Ethertype 프로토콜 문서 참조

## IPv4 헤더

- [참고 사이트](http://www.ktword.co.kr/test/view/view.php?m_temp1=1859)

- header len : 헤더의 길이 

  - size : 첫 번째 바이트의 **하위 4bit** 값으로 표현
    - 실제 크기는 4bit 값 * 4를 한 값
    - 범위 : 20byte ~ 60byte

- Protocol : 프로토콜

  - size : 1byte

  - value

    - ICMP : 1
    - TCP : 6
    - UDP : 17

    - 등... [IANA 프로토콜 번호 관리 참고](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)

- Total Length : IPv4 헤더의 크기 + Data의 크기(프로토콜 헤더 + 데이터)

  - size : 2byte
  - byte order : big endian

- Source IP

  - size : 4byte
  - 1바이트당 dot으로 구분된 하나의 octet 값
  - 예시) c0 a8 dc 81 ==> 192.168.220.129

- Destination IP

  - size : 4byte
  - 1바이트당 dot으로 구분된 하나의 octet 값
  - 예시) c0 a8 dc 81 ==> 192.168.220.129

## TCP 헤더

- [참고 사이트](http://www.ktword.co.kr/test/view/view.php?m_temp1=1889)
- header len : 헤더의 길이 
  - size : +12번째 바이트의 **상위 4 bit** 값으로 표현
    - 실제 크기는 4 bit 값 * 4를 한 값
    - 범위 : 20 byte ~ 60 byte
- Source Port : 출발지의 포트
  - size : 2 byte
  - byte order : big endian
- Destination Port : 목적지의 포트
  - size : 2 byte
  - byte order : big endian


