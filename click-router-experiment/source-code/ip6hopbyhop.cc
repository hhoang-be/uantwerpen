
#include <click/config.h>
#include "ip6hopbyhop.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
CLICK_DECLS

IP6HopByHop::IP6HopByHop() : _drops(0) {

}

IP6HopByHop::~IP6HopByHop() {
}


int
IP6HopByHop::configure(Vector<String> &conf, ErrorHandler *errh) {
    return 0;
}

int
IP6HopByHop::checkingHopByHop(const click_ip6_header_ext *t_header){
	/*
	 * 1st byte is next header, 2nd byte is header length
	 * so the beginning position of Hop by Hop option data is 3rd
	 */
	uint8_t index = 2;
	//convert header extension to an array of uint8_t
	const uint8_t *header = reinterpret_cast<const uint8_t *>(t_header);
	const uint8_t *opt_type, *opt_length;
	const jumbo_option *jumbo_opt;
	uint32_t jumbo_length;

	int hdr_length = t_header->ip6_hdr_length;
	//Hop By Hop header length in bytes
	int hdr_length_in_bytes = (hdr_length + 1)*8;

	while(index < hdr_length_in_bytes - 1) {
		opt_type = reinterpret_cast <const uint8_t *>(header + index);
		opt_length = reinterpret_cast <const uint8_t *>(header + index + 1);

		switch(*opt_type){
		case 0:
			//Pad1 option
			index = index + 1;
			break;
		case 1:			//PadN option
			index = index + *opt_length + 2;
			break;
		case 5:			//Router Alert option
			// if option length != 2 or not in alignment of 2n + 0
			if ((*opt_length != 2) || ((index % 2) != 0)) {
				click_chatter("Error. Router Alert option length must be 2 and in alignment of 2n + 0. \n");
			} else {
				//Router Alert option is ok. Push to port 2
				return 2;
			}
			//if unrecognized, skip this option
			index = index + *opt_length + 2;
			break;
		case 194:			//Jumbo payload option
			jumbo_opt = reinterpret_cast <const jumbo_option *>(header + index);
			if((index % 4) != 2) {
				click_chatter("Error. Jumbo option must be in alignment of 4n + 2. \n");
				//push to jumbo error port 3
				return 3;
			}
			if (jumbo_opt->_j_o_length != 4) {
				click_chatter("Error. Jumbo option length must be 4 bytes. \n");
				//push to jumbo error port 3
				return 3;
			}

			jumbo_length = jumbo_opt->_j_length;
			if(jumbo_length <= 65535){
				click_chatter("Error. Jumbo packet payload is less than 65,535 bytes.\n");
				//push to jumbo error port 3
				return 3;
			}
			//Jumbo option is ok. Push to port 1
			return 1;
		default:
			click_chatter("Unrecognized hop by hop option. %d \n", *opt_type);
			//skip option and push packet to port 0
			return 0;
		}
	}
	return 0;
}


void
IP6HopByHop::add_handlers() {

}

void
IP6HopByHop::push(int, Packet *p) {
	int _offset = 0;
	int hll, out_port = 0;
	uint16_t packet_length;
	const click_ip6 *ip_in = reinterpret_cast <const click_ip6 *>( p->data() + _offset);
	const click_ip6_header_ext *in_header;
	int pace = sizeof(click_ip6);
	uint8_t header_length;	//header extension length

	uint8_t cur_hdr_ext = ip_in->ip6_nxt;

	//hop limit
	hll = ip_in->ip6_hlim;
	if(hll == 0){
		//drop the packet
		click_chatter("Hop limit is zero. Drop packet. \n");
		return;
	}

	packet_length = htons(ip_in->ip6_plen);
	while(true) {
		  in_header = reinterpret_cast <const click_ip6_header_ext *>( p->data() + pace);

		  switch(cur_hdr_ext){
		  case 0:	//Hop by Hop Header
			  header_length = in_header->ip6_hdr_length;
			  pace = pace + (header_length + 1) * 8;
			  cur_hdr_ext = in_header->ip6_nxt_hdr;
			  out_port = checkingHopByHop(in_header);
			  //if jumbo option and packet length is not zero ==> error
			  if((out_port == 1) && (packet_length != 0)) {
				  click_chatter("Error. For jumbo packet, packet length must be zero. \n");
				  //push to error port 3
				  out_port = 3;
			  }

			  checked_output_push(out_port, p);
			  return;

		  default:	//if Hop By Hop option does not exist
			  checked_output_push(0, p);
			  return;
		  }
	  }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6HopByHop)
