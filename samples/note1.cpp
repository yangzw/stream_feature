 /*
  2    时间戳在pcap数据头中 
  3    以太网头部:偏移14字节
  4    ip头部:首部长度值*4
  5    tcp头部:首部长度*4
  6    后来的就属于payload了
  7 =============
  8 */
  9 
 10 #include<pcap.h>
 11 struct pcap_pkthdr {
 12         struct timeval ts; /* time stamp */
 13         bpf_u_int32 caplen; /* length of portion present */
 14         bpf_u_int32 len; /* length this packet (off wire) */
 15 };
 16 
 17 /*
 18 caplen:捕获的实际长度
 19 len:包的长度
 20 
 =============

typedef void(* pcap_handler)(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
Prototype of the callback function that receives the packets.

When pcap_dispatch() or pcap_loop() are called by the user, the packets are passed to the application by means of this callback.
user is a user-defined parameter that contains the state of the capture session, it corresponds to the user parameter of pcap_dispatch() and pcap_loop().
pkt_header is the header associated by the capture driver to the packet. It is NOT a protocol header.
pkt_data points to the data of the packet, including the protocol headers.
Definition at line 27 of file funcs/pcap.h.
=============
*/

#include<netinet/ip.h>
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
	u_char	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	short	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};
//============
#include<netinet/tcp.h>
struct tcphdr{
	uint16_t 	th_sport;
	// 	Source port. 
	uint16_t 	th_dport;
	//	Destination port. 
	uint32_t 	th_seq;
	//	Sequence number of first octet in this segment. 
	uint32_t 	th_ack;
	//	Expected sequence number of next octet. 
	uint8_t 	th_x2:4;
	//	Unused. 
	uint8_t 	th_off:4;
	//	Data offset. 
	uint8_t 	th_flags;
	//	Control flags. 
	uint16_t 	th_win;
	//	Number of acceptable octects. 
	uint16_t 	th_sum;
	//	96 byte pseudo header checksum. 
	uint16_t 	th_urp;
	//	Urgent data pointer. 
}

//gcc -o tcp0 tcp.c -lnids -lpcap -lnet -lgthread-2.0
