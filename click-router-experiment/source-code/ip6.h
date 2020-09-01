/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef CLICKNET_IP6_H
#define CLICKNET_IP6_H
#include <clicknet/ip.h>
#undef s6_addr
#undef s6_addr16
#undef s6_addr32
#undef s6_addr64

/*
 * <clicknet/ip6.h> -- our own definitions of IP6 headers
 * based on RFC 2460
 */

/* IPv6 address , same as from /usr/include/netinet/in.h  */
struct click_in6_addr {
    union {
	uint8_t		u6_addr8[16];
	uint16_t	u6_addr16[8];
	uint32_t	u6_addr32[4];
#ifdef HAVE_INT64_TYPES
	uint64_t	u6_addr64[2];
#endif
    } in6_u;
};

#define s6_addr in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
#define s6_addr64 in6_u.u6_addr64


struct click_ip6 {
    union {
	struct {
	    uint32_t ip6_un1_flow;	/* 0-3	 bits 0-3: version == 6	     */
					/*	 bits 4-11: traffic class    */
					/*	   bits 4-9: DSCP	     */
					/*	   bits 10-11: ECN	     */
					/*	 bits 12-31: flow label	     */
	    uint16_t ip6_un1_plen;	/* 4-5	 payload length		     */
	    uint8_t ip6_un1_nxt;	/* 6	 next header		     */
	    uint8_t ip6_un1_hlim;	/* 7	 hop limit		     */
	} ip6_un1;
	uint8_t ip6_un2_vfc;		/* 0	 bits 0-3: version == 6	     */
					/*	 bits 4-7: top 4 class bits  */
	struct {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
	    unsigned ip6_un3_v : 4;	/* 0	 version == 6		     */
	    unsigned ip6_un3_fc : 4;	/*	 header length		     */
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	    unsigned ip6_un3_fc : 4;	/* 0	 header length		     */
	    unsigned ip6_un3_v : 4;	/*	 version == 6		     */
#endif
	} ip6_un3;
    } ip6_ctlun;
    struct click_in6_addr ip6_src;	/* 8-23	 source address */
    struct click_in6_addr ip6_dst;	/* 24-39 dest address */
};

/*IP6 Header Extension*/
union click_ip6_header_ext {
	/*For Hop-by-Hop, Destination and Routing Header*/
	struct {
		uint8_t _nxt_header; 		/* Next header*/
		uint8_t _header_length;  	/*Header lenght*/
	} ip6_header_extension;

	/*Routing Header*/
	struct {
		uint8_t _nxt_header; 		/* Next header*/
		uint8_t _header_length;  	/*Header lenght*/
		uint8_t _routing_type;
		uint8_t _segment_left;
		uint8_t _reserved;
		uint8_t _strict_loose[3];
	} ip6_routing_extension;

	/*For Fragment Header */
	struct {
		uint8_t _frag_nxt_header;	/* Next header*/
		uint8_t _frag_reserved;		/* Reserved 8 bits*/
		uint16_t _frag_offset_flag;	/* Fragment Offset 13 bits, Reserved 2 bits, More Fragment Flag 1 bit*/
		uint32_t _frag_id;			/*Identification 32 bits*/
	} ip6_frag;

	/*For Authentication Header*/
	struct {
		uint8_t _ip6_nxt_header;		/* Next header*/
		uint8_t _ip6_payload_length;	/* Payload length*/
		uint16_t _ip6_reserved;			/* Reserved*/
		uint32_t _ip6_spi;				/* Security parameter index*/
		uint32_t _ip6_sn;				/* Sequence number*/
	} ip6_auth_header;

	/*Authentication header is not implemented yet*/

	/*TCP header*/
	struct {
		uint16_t _src_port;
		uint16_t _dst_port;
		uint32_t _seq_no;
		uint32_t _ack_no;
		uint16_t _data_offset;
		uint16_t _window_size;
		uint16_t _checksum;
		uint16_t _urgent_pointer;
	} ip6_tcp_header;

	/*UDP header*/
	struct {
		uint16_t _src_port;
		uint16_t _dst_port;
		uint16_t _length;
		uint16_t _checksum;
	} ip6_udp_header;

	/*ICMP header*/
	struct{
		uint8_t _type;
		uint8_t _code;
		uint16_t _checksum;
	} ip6_icmp_header;
};


#define ip6_nxt_hdr			ip6_header_extension._nxt_header;
#define ip6_hdr_length		ip6_header_extension._header_length;
#define ip6_tcp_src_port	ip6_tcp_header._src_port;
#define ip6_tcp_dst_port	ip6_tcp_header._dst_port;
#define ip6_udp_src_port	ip6_udp_header._src_port;
#define ip6_udp_dst_port	ip6_udp_header._dst_port;
#define ip6_icmp_type		ip6_icmp_header._type;
#define ip6_icmp_code		ip6_icmp_header._code;
#define frag_nxt_header		ip6_frag._frag_nxt_header;
#define frag_reserved		ip6_frag._frag_reserved;
#define frag_offset_flag	ip6_frag._frag_offset_flag;
#define frag_id				ip6_frag._frag_id;
#define routing_type		ip6_routing_extension._routing_type;
#define segment_left		ip6_routing_extension._segment_left;
#define auth_nxt_header		ip6_auth_header._ip6_nxt_header;
#define auth_payload_length	ip6_auth_header._ip6_payload_length;
#define auth_reserved		ip6_auth_header._ip6_reserved;
#define auth_spi			ip6_auth_header._ip6_spi;
#define auth_sn				ip6_auth_header._ip6_sn;


#define ip6_v			ip6_ctlun.ip6_un3.ip6_un3_v
#define ip6_vfc			ip6_ctlun.ip6_un2_vfc
#define ip6_flow		ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen		ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt			ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim		ip6_ctlun.ip6_un1.ip6_un1_hlim

#define IP6_FLOW_MASK		0x000FFFFFU
#define IP6_FLOW_SHIFT		0
#define IP6_CLASS_MASK		0x0FF00000U
#define IP6_CLASS_SHIFT		20
#define IP6_DSCP_MASK		0x0FC00000U
#define IP6_DSCP_SHIFT		22
#define IP6_V_MASK		0xF0000000U
#define IP6_V_SHIFT		28

#define IP6_CHECK_V(hdr)	(((hdr).ip6_vfc & htonl(IP6_V_MASK)) == htonl(6 << IP6_V_SHIFT))

CLICK_DECLS

uint16_t in6_fast_cksum(const struct click_in6_addr *saddr,
			const struct click_in6_addr *daddr,
			uint16_t len,
			uint8_t proto,
			uint16_t ori_csum,
			const unsigned char *addr,
			uint16_t len2);

uint16_t in6_cksum(const struct click_in6_addr *saddr,
		   const struct click_in6_addr *daddr,
		   uint16_t len,
		   uint8_t proto,
		   uint16_t ori_csum,
		   unsigned char *addr,
		   uint16_t len2);

CLICK_ENDDECLS
#endif
