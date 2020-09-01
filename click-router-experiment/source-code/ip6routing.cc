/*
 * ip6fragmenter.{cc,hh} -- element fragments IP6 packets
 * Robert Morris
 *
 * Copyright (c) 1999 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "ip6routing.hh"
#include <clicknet/ip6.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
CLICK_DECLS

IP6Routing::IP6Routing()
  : _drops(0)
{

}

IP6Routing::~IP6Routing()
{
}


int
IP6Routing::configure(Vector<String> &conf, ErrorHandler *errh) {
    return 0;
}

void
IP6Routing::routing(Packet *p_in){

	int _offset = 0;
	int r_type = 0, seg_left, swap_pos, hll;
	click_ip6 *ip;
	const click_ip6 *ip_in = reinterpret_cast <const click_ip6 *>( p_in->data() + _offset);
	const click_ip6_header_ext *header;
	click_ip6_header_ext *out_header;
	int pace = sizeof(click_ip6);
	uint8_t header_length;	//header extension length
	int number_of_addresses = 0;
	WritablePacket *p;
	click_in6_addr cur_dst_addr;
	int cur_hdr_ext = ip_in->ip6_nxt;

	//hop limit
	hll = ip_in->ip6_hlim;
	if(hll == 0){
		//drop the packet
		return;
	}

	bool loop_break = false;
	while(!loop_break) {
		  header = reinterpret_cast <const click_ip6_header_ext *>( p_in->data() + pace);

		  switch(cur_hdr_ext){
		  case 6:	//TCP header
			  click_chatter("TCP Packet - No routing header exists\n");
			  checked_output_push(0, p_in);
			  return;
		  case 17:	//UDP header
			  click_chatter("UDP Packet - No routing header exists\n");
			  checked_output_push(0, p_in);
			  return;
		  case 58:	//ICMP header
			  click_chatter("ICMP Packet - No routing header exists\n");
			  checked_output_push(0, p_in);
			  return;
		  case 0:	//Hop by Hop Header
			  header_length = header->ip6_hdr_length;
			  pace = pace + (header_length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 60: 	//Destination header
			  header_length = header->ip6_hdr_length;
			  pace = pace + (header_length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 43:	//Routing Header
			  r_type = header->routing_type;
			  if(r_type != 0) {
				  click_chatter("Error. Routing Type is %d. IP6Routing element only supports Routing Type 0.\n", r_type);
				  //push out this packet
				  checked_output_push(0, p_in);
				  return;
			  }

			  header_length = header->ip6_hdr_length;
			  if((header_length % 2) != 0) {
				  click_chatter("Error. Routing Header Length (%d) is an odd number. \n", header_length);
				  //drop the packet
				  return;
			  }
			  /*
			   * The length of routing header is in 8-byte unit except the first 8 bytes
			   * The length of IPv6 address is 16 bytes so
			   * ==> number of addresses is equal (header length)/2
			   */
			  number_of_addresses = header_length/2;
			  if(number_of_addresses > 23) {	//maximum number of addresses is 23
				  click_chatter("Error. The number of addresses in Routing Header exceeds 23.\n");
				  //drop this packet
				  return;
			  }

			  seg_left = header->segment_left;
			  if(seg_left == 0){	//this is the final destination
				  checked_output_push(0, p_in);
				  return;
			  }

			  //make input packet writable
			  p = p_in->uniqueify();
			  ip = reinterpret_cast <click_ip6 *>( p->data() + _offset);

			  //decrease the hop limit
			  ip->ip6_hlim = hll - 1;

			  //swap current destination address with (N-segment + 1)-th address in header
			  swap_pos = pace + 8 + (number_of_addresses - seg_left)*sizeof(click_in6_addr);
			  cur_dst_addr = ip_in->ip6_dst;
			  //p->data() + 24 maps to location of destination address
			  memcpy(p->data() + 24, p->data() + swap_pos, sizeof(click_in6_addr));
			  //Note: the length of fixed part in type 0 routing header is 8 bytes
			  memcpy(p->data() + pace + 8 + swap_pos*sizeof(click_in6_addr), &cur_dst_addr, sizeof(click_in6_addr));

			  //decrease segment left field
			  seg_left--;
			  out_header = reinterpret_cast <click_ip6_header_ext *>( p->data() + pace);
			  out_header->ip6_routing_extension._segment_left = seg_left;
			  //in this case, no need to process reserved bits and strict/loose Bit Map
			  checked_output_push(0, p);	//push out packet
			  return;
		  case 44: 	//fragment header
			  pace = pace + 8;		//Fragment header has fixed length of 8bytes
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 50: 	//ESP
			  header_length = header->ip6_hdr_length;
			  pace = pace + (header_length + 2) * 4;	//Length of ESP is calculated in 4bytes block except the first 8bytes
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 51: 	//Authentication header
			  checked_output_push(0, p_in);
			  return;	//do nothing
		  case 59:	//no header
			  checked_output_push(0, p_in);
			  return; 	//do nothing
		  case 41:	//Encapsulating header
			  checked_output_push(0, p_in);
			  return; //do nothing
		  default:	//unknown IP6 header extension
			  click_chatter("Header Type (%d) is unrecognized.\n", cur_hdr_ext);
			  checked_output_push(0, p_in);
			  return;
		  }
	  }
}


void
IP6Routing::add_handlers() {

}


void
IP6Routing::push(int, Packet *p) {
  click_chatter("IP6Routing::push, packet length is %d \n", p->ip_header_length());
  routing(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6Routing)
