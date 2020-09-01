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
#include "ip6fragmenter.hh"
#include <clicknet/ip6.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
CLICK_DECLS

IP6Fragmenter::IP6Fragmenter()
  : _drops(0)
{
  _fragments = 0;
  _mtu = 0;
}

IP6Fragmenter::~IP6Fragmenter()
{
}


int
IP6Fragmenter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    //return Args(conf, this, errh).read_mp("MTU", _mtu).complete();
    _headroom = Packet::default_headroom;
    if (Args(conf, this, errh)
	.read_mp("MTU", _mtu)
	.complete() < 0)
	return -1;
    if (_mtu < 8)
	return errh->error("MTU must be at least 8");
    return 0;
}

void
IP6Fragmenter::fragment(Packet *p_in){

	//find the length of unfragmentable part
	//including ip6 header, Hop by Hop, Destination and Routing Header Extension
	int _offset = 0;
	const click_ip6 *ip_in = reinterpret_cast <const click_ip6 *>( p_in->data());
	if((htons(ip_in->ip6_plen) + sizeof(click_ip6)) <=_mtu){		//packet length is less than MTU no need to fragment
		checked_output_push(0, p_in);
		return;
	}
	const click_ip6_header_ext *header;
	int unfragmentable_len = sizeof(click_ip6);	//initialize unfragment part equal to IP6 header length
	int previous_hdr_pos = 6;		//The 7th byte in IPv6 main header is next header field
	uint8_t header_length;	//header extension length
	int cur_hdr_ext = ip_in->ip6_nxt;
	//traverse through the unfragmentable part of the packet
	bool loop_break = false;
	while(!loop_break) {
		  header = reinterpret_cast <const click_ip6_header_ext *>( p_in->data() + _offset + unfragmentable_len);
		  switch(cur_hdr_ext){
		  case 0:	//Hop by Hop Header
			  header_length = header->ip6_hdr_length;
			  previous_hdr_pos = unfragmentable_len;
			  unfragmentable_len = unfragmentable_len + (header_length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 60: 	//Destination header
			  header_length = header->ip6_hdr_length;
			  previous_hdr_pos = unfragmentable_len;
			  unfragmentable_len = unfragmentable_len + (header_length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 43:	//Routing Header
			  header_length = header->ip6_hdr_length;
			  previous_hdr_pos = unfragmentable_len;
			  unfragmentable_len = unfragmentable_len + (header_length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  default:	//other header extension
			  loop_break = true;
			  break;
		  }
	  }


	  //unfragmentable part includes IPv6 header
	  int in_dlen = ntohs(ip_in->ip6_plen) + (sizeof(click_ip6) - unfragmentable_len);

	  //add fragmentation header to every fragmeted packet
	  //fragment offset is in unit of 8-byte block
	  int out_dlen = (_mtu - 8 - unfragmentable_len) & ~7;	//fragment header size is 8

	  //out put packet length field. Exclude ip6 header
	  int out_plen = out_dlen + FRAG_HDR_LEN + unfragmentable_len - sizeof(click_ip6);	//fragment header size is 8

	  //make packet writable
	  WritablePacket *p = p_in->uniqueify();
	  click_ip6 *ip = reinterpret_cast <click_ip6 *>(p->data());
	  uint32_t unique_frag_id = click_random();
	  bool last_frag = false;

	  while(!last_frag){
		  if(_offset + out_dlen >= in_dlen){		//if this is the last fragment
			  last_frag = true;
			  out_dlen = in_dlen - _offset;
			  out_plen = out_dlen + unfragmentable_len + FRAG_HDR_LEN - sizeof(click_ip6);
		  }

		  WritablePacket *out_packet = Packet::make(_headroom, 0, out_dlen + unfragmentable_len + sizeof(click_ip6_header_ext), 0);

		  /*
		   * Fragment Offset field contains the offset of the data following
		   * this header relative to the start of the fragmentable part of the original
		   * packet (before fragmentation), in 8-octet (64-bit) units.
		   */
		  //copy unfragmentable part of original packet to all fragmented packets
		  memcpy(out_packet->data(), p->data(), unfragmentable_len);

		  //set IPv6 header of fragmented packet
		  out_packet->set_network_header(out_packet->data(), sizeof(click_ip6));
		  click_ip6 *t_ip = out_packet->ip6_header();
		  t_ip->ip6_plen = htons(out_plen);

		  //set the NextHeader field of last extension header in unfragmentable part to 44
		  uint8_t *frag_hdr = new uint8_t(44);
		  memcpy(out_packet->data() + previous_hdr_pos, frag_hdr, sizeof(uint8_t));

		  //set fragmentation header for fragmented packets
		  click_ip6_header_ext *frag_ext = reinterpret_cast <click_ip6_header_ext *>(out_packet->data() + unfragmentable_len);
		  frag_ext->ip6_frag._frag_nxt_header = cur_hdr_ext;	//next header
		  frag_ext->ip6_frag._frag_reserved = 0b00000000;		//reserved byte

		  //set fragment offset
		  frag_ext->ip6_frag._frag_offset_flag = _offset << 3;	//divide _offset by 8 (_offset << 3)
		  frag_ext->ip6_frag._frag_offset_flag = frag_ext->ip6_frag._frag_offset_flag << 3;

		  if(last_frag){	  //if last fragment, set more fragment flag to 0
			  frag_ext->ip6_frag._frag_offset_flag = frag_ext->ip6_frag._frag_offset_flag & 0b1111111111111110;
		  } else {			  //set more fragment flag to 1
			  frag_ext->ip6_frag._frag_offset_flag = frag_ext->ip6_frag._frag_offset_flag | 0b0000000000000001;
		  }

		  //set reserved bits to 0
		  frag_ext->ip6_frag._frag_offset_flag = frag_ext->ip6_frag._frag_offset_flag & 0b1111111111111001;

		  //set fragmentation id - random number
		  frag_ext->ip6_frag._frag_id = unique_frag_id;

		  //move to offset of next fragmented packet
		  _offset = _offset + out_dlen;

		  memcpy(out_packet->data() + unfragmentable_len + sizeof(click_ip6_header_ext),
				  p->data() + unfragmentable_len + _offset, out_dlen);

		  checked_output_push(0, out_packet);
	  }
	  //bad header, discard packet
	  p->kill();
}

static String
IP6Fragmenter_read_drops(Element *xf, void *)
{
  IP6Fragmenter *f = (IP6Fragmenter *)xf;
  return String(f->drops());
}

static String
IP6Fragmenter_read_fragments(Element *xf, void *)
{
  IP6Fragmenter *f = (IP6Fragmenter *)xf;
  return String(f->fragments());
}

void
IP6Fragmenter::add_handlers()
{
  add_read_handler("drops", IP6Fragmenter_read_drops, 0);
  add_read_handler("fragments", IP6Fragmenter_read_fragments, 0);
}


void
IP6Fragmenter::push(int, Packet *p) {
  fragment(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6Fragmenter)
