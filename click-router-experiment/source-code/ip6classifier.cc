/*
 * IP6Classifier.{cc,hh} -- element classifies IP6 packets depending on its type (TCP, UDP, ICMP)
 * Hoang Trung Hieu
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
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
 *
 * Reference: CheckIP6Header.{cc,hh} by Robert Morris , Peilei Fan
 */

#include <click/config.h>
#include "ip6classifier.hh"
#include <clicknet/ip6.h>
#include <click/ip6address.hh>
#include <click/glue.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/standard/alignmentinfo.hh>
CLICK_DECLS

IP6Classifier::IP6Classifier()
  : _bad_src(0), _drops(0)
{
}

IP6Classifier::~IP6Classifier() {
  delete[] _bad_src;
}

Token*
IP6Classifier::parseConfigurationString(String inputString) {
	Token *rootNode, *nextNode;
	String right_sub_string,left_sub_string;
	right_sub_string = inputString;
	if(right_sub_string.find_left(' ', 0) < 0){
		rootNode = new Token(inputString);
		rootNode->nextToken = NULL;
	} else {
		left_sub_string = right_sub_string.substring(0, right_sub_string.find_left(' ', 0));
		rootNode = new Token(left_sub_string);
		nextNode = rootNode;
		right_sub_string = right_sub_string.substring(right_sub_string.find_left(' ', 0) + 1);
		while(right_sub_string.find_left(' ', 0) >=0){
			left_sub_string = right_sub_string.substring(0, right_sub_string.find_left(' ', 0));
			nextNode->nextToken = new Token(left_sub_string);
			nextNode = nextNode->nextToken;
			right_sub_string = right_sub_string.substring(right_sub_string.find_left(' ', 0) + 1);
		}
		nextNode->nextToken = new Token(right_sub_string);
	}

	return rootNode;
}

bool pattern(Token *, filter_types *);

int
IP6Classifier::match_ip6_hdr_fields(filter_types *_filter, Packet *p){
	const click_ip6 *ip = reinterpret_cast <const click_ip6 *>( p->data() + _offset);
	uint32_t _ip6_un = htonl(ip->ip6_flow), _ip6_flow, _ip6_vers, _ip6_cos;
	uint8_t _hlim = ip->ip6_hlim;
	unsigned int _bit_mask;
	switch(_filter->sub_type){
		case SUB_TYPE_IP_VERS:
			_ip6_vers = _ip6_un>>28;
			if(_ip6_vers == _filter->list->current_argument.numeric_data){
				return 1;
			}else{
				return -1;
			}
		case SUB_TYPE_IP_HLL:
			if(_filter->list->current_argument.numeric_data == _hlim){
				return 1;
			}else{
				return -1;
			}
		case SUB_TYPE_IP_COS:
			_bit_mask = 0b00001111111100000000000000000000;
			_ip6_cos = (_ip6_un&_bit_mask)>>20;
			if(_ip6_cos == _filter->list->current_argument.numeric_data){
				return 1;
			}else{
				return -1;
			}
			return 1;
		case SUB_TYPE_IP_FLOW:
			_bit_mask = 0b00000000000011111111111111111111;
			_ip6_flow = (_ip6_un&_bit_mask);
			if(_ip6_flow == _filter->list->current_argument.numeric_data){
				return 1;
			}else{
				return -1;
			}
			return 1;
		case SUB_TYPE_IP_FRAG:
			return isFragmented(p);
		case SUB_TYPE_IP_UNFRAG:
			return -1*isFragmented(p);
		default:
			return -1;
	}
}

int
IP6Classifier::isFragmented(Packet *p){
	  const click_ip6 *ip = reinterpret_cast <const click_ip6 *>( p->data() + _offset);
	  const click_ip6_header_ext *header;
	  unsigned plen = p->length() - _offset;
	  int pace = 40;
	  uint8_t length;
	  int cur_hdr_ext = ip->ip6_nxt;

	  while(true) {
		  header = reinterpret_cast <const click_ip6_header_ext *>( p->data() + _offset + pace);
		  switch(cur_hdr_ext){
		  case 6:	//TCP header
			  click_chatter("Next header is TCP\n");
			  return -1;
		  case 17:	//UDP header
			  click_chatter("Next header is UDP \n");
			  return -1;
		  case 58:	//ICMP header
			  click_chatter("Next header is ICMP \n");
			  return -1;
		  case 0:	//Hop by Hop Header
			  length = header->ip6_hdr_length;
			  pace = pace + (length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 41:	//Encapsulating header
			  break; //do nothing
		  case 43:	//Routing Header
			  length = header->ip6_hdr_length;
			  pace = pace + (length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 44: 	//fragment header
			  pace = pace + 8;		//Fragment header has fixed length of 8bytes
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  //yes, this is fragmented packet. Return true
			  return 1;
		  case 50: 	//ESP
			  length = header->ip6_hdr_length;
			  pace = pace + (length + 2) * 4;	//Length of ESP is calculated in 4bytes block except the first 8bytes
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 51: 	//Authentication header
			  break;	//do nothing
		  case 59:	//no header
			  break; 	//do nothing
		  case 60: 	//Destination header
			  length = header->ip6_hdr_length;
			  pace = pace + (length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  default:	//unknown IP6 header extension
			  goto bad;
		  }
	  }

	  bad:
	 	 //click_chatter("Do not match in match_transport_protocols() \n");
	 	 return -1;
}

int
IP6Classifier::match_transport_protocols(filter_types *_filter, Packet *p){
	  const click_ip6 *ip = reinterpret_cast <const click_ip6 *>( p->data() + _offset);
	  const click_ip6_header_ext *header;
	  unsigned plen = p->length() - _offset;
	  uint16_t _src_port, _dst_port, t_port;
	  uint8_t _icmp_type, _icmp_code;
	  int pace = 40;
	  uint8_t length;
	  int cur_hdr_ext = ip->ip6_nxt;
	  arguments *arg;
	  while (true) {
		  header = reinterpret_cast <const click_ip6_header_ext *>( p->data() + _offset + pace);
		  switch (cur_hdr_ext) {
		  case 6:	//TCP header
			  click_chatter("Next header is TCP\n");
			  if (_filter->sub_sub_type != SUB_SUB_TYPE_TCP) {
				  return -1;
			  } else {
				  if (_filter->sub_type == SUB_TYPE_IP_PROTO) {
					  return 1;
				  }
			  }
			 _src_port = header->ip6_tcp_src_port;
			 _dst_port = header->ip6_tcp_dst_port;
			 _src_port = htons(_src_port);
			 _dst_port = htons(_dst_port);
			 goto good;
		  case 17:	//UDP header
			  click_chatter("Next header is UDP \n");
			  if (_filter->sub_sub_type != SUB_SUB_TYPE_UDP) {
				  return -1;
			  } else {
				  if (_filter->sub_type == SUB_TYPE_IP_PROTO) {
				  		return 1;
				  }
			  }
				 _src_port = header->ip6_udp_src_port;
				 _dst_port = header->ip6_udp_dst_port;
				 _src_port = htons(_src_port);
				 _dst_port = htons(_dst_port);
			  goto good;
		  case 58:	//ICMP header
			  click_chatter("Next header is ICMP \n");
			  if (_filter->sub_sub_type != SUB_SUB_TYPE_ICMP) {
				  return -1;
			  } else {
				  if (_filter->sub_type == SUB_TYPE_IP_PROTO) {
				  		return 1;
				  }
			  }
			  _icmp_type = header->ip6_icmp_type;
			  goto good;

		  case 0:	//Hop by Hop Header
			  length = header->ip6_hdr_length;
			  pace = pace + (length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 41:	//Encapsulating header
			  break; //do nothing
		  case 43:	//Routing Header
			  length = header->ip6_hdr_length;
			  pace = pace + (length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 44: 	//fragment header
			  pace = pace + 8;		//Fragment header has fixed length of 8bytes
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 50: 	//ESP
			  length = header->ip6_hdr_length;
			  pace = pace + (length + 2) * 4;	//Length of ESP is calculated in 4bytes block except the first 8bytes
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  case 51: 	//Authentication header
			  break;	//do nothing
		  case 59:	//no header
			  break; 	//do nothing
		  case 60: 	//Destination header
			  length = header->ip6_hdr_length;
			  pace = pace + (length + 1) * 8;
			  cur_hdr_ext = header->ip6_nxt_hdr;
			  break;
		  default:	//unknown IP6 header extension
			  goto bad;
		  }
	  }
	  p->set_ip6_header(ip);
	  return -1;

	 good:
	 	 arg = _filter->list;
	 	 while(arg != NULL){
	 		 t_port = arg->current_argument.numeric_data;
	 		 if (_filter->type == TYPE_ICMP) {
	 			 if (t_port == _icmp_type) {
	 				 return 1;
	 			 }
	 		 } else {
				 switch (_filter->sub_type) {
				 case SUB_TYPE_SRC:
					 if (t_port == _src_port) {
						 return 1;
					 }
					 break;
				 case SUB_TYPE_DST:
					 if (t_port == _dst_port) {
						 return 1;
					 }
					 break;
				 case SUB_TYPE_SRC_AND_DST:
					 if ((t_port == _src_port)&&(t_port == _dst_port)) {
						 return 1;
					 }
					 break;
				 case SUB_TYPE_SRC_OR_DST:
					 if ((t_port == _src_port)||(t_port == _dst_port)) {
						 return 1;
					 }
					 break;
				 case SUB_TYPE_IP_PROTO:
					 break;
				 default:
					 click_chatter("Error in match_transport_protocols()");
					 return -1;
				 }
	 		 }
			 arg = arg->next_argument;
	 	 }

	bad:
	 	 click_chatter("Do not match in match_transport_protocols() \n");
	 	 return -1;
}

inline bool
IP6Classifier::compare_host_net(int option, IP6Address left, IP6Address *right){
    uint32_t *ai = left.data32(), *bi = right->data32();
    if (option == SUB_SUB_TYPE_HOST) {
    	return ai[0] == bi[0] && ai[1] == bi[1] && ai[2] == bi[2] && ai[3] == bi[3];
    } else if (option == SUB_SUB_TYPE_NET) {
    	//check whether it is network address or not
    	//one or more bits in the node part of ip6address are not 0
    	if ((bi[2] != 0)||(bi[3] != 0)) {
    		return false;
    	}
    	return ai[0] == bi[0] && ai[1] == bi[1];
    } else {
    	return false;
    }

}

int
IP6Classifier::match_ip(filter_types *_filter, Packet *p){
	const click_ip6 *ip = reinterpret_cast <const click_ip6 *>( p->data() + _offset);
	IP6Address _src_addr;
	IP6Address _dst_addr;
	_src_addr = IP6Address(ip->ip6_src);
	_dst_addr = IP6Address(ip->ip6_dst);
	//mask address uses 64bits network mask
	IP6Address _mask_addr = IP6Address("FF:FF:FF:FF:00:00:00:00");
	arguments *arg = _filter->list;

	if ((_filter->sub_sub_type == SUB_SUB_TYPE_TCP)||
			(_filter->sub_sub_type == SUB_SUB_TYPE_UDP)) {
		return match_transport_protocols(_filter, p);
	}

	while (arg != NULL) {
		switch (_filter->sub_type) {
			case SUB_TYPE_SRC:
				if (compare_host_net(_filter->sub_sub_type, _src_addr, arg->current_argument.ip6address)) {
					return 1;
				} else {
					return -1;
				}
			case SUB_TYPE_DST:
				if (compare_host_net(_filter->sub_sub_type, _dst_addr, arg->current_argument.ip6address)) {
					return 1;
				} else {
					return -1;
				}
			case SUB_TYPE_SRC_AND_DST:
				if ((compare_host_net(_filter->sub_sub_type, _src_addr, arg->current_argument.ip6address))
						&&(compare_host_net(_filter->sub_sub_type, _dst_addr, arg->current_argument.ip6address))) {
					return 1;
				} else {
					return -1;
				}
			case SUB_TYPE_SRC_OR_DST:
					if ((compare_host_net(_filter->sub_sub_type, _src_addr, arg->current_argument.ip6address))
							||(compare_host_net(_filter->sub_sub_type, _dst_addr, arg->current_argument.ip6address))) {
						return 1;
					} else {
						return -1;
					}
			default:
				return -1;
		}
		arg = arg->next_argument;
	}
}

int
IP6Classifier::match_pattern(filter_types *_filter, Packet *p){
	switch (_filter->type) {
	case TYPE_DST:
		if ((_filter->sub_sub_type == SUB_SUB_TYPE_TCP)||(_filter->sub_sub_type == SUB_SUB_TYPE_UDP)) {
			return match_transport_protocols(_filter, p);
		} else {
			return match_ip(_filter, p);
		}
	case TYPE_ETHER:
		break;
	case TYPE_ICMP:
		return match_transport_protocols(_filter, p);
		break;
	case TYPE_IP:
		if (_filter->sub_type == SUB_TYPE_IP_PROTO) {
			return match_transport_protocols(_filter, p);
		} else {
			return match_ip6_hdr_fields(_filter, p);
		}
	case TYPE_SRC:
		if ((_filter->sub_sub_type == SUB_SUB_TYPE_TCP)||(_filter->sub_sub_type == SUB_SUB_TYPE_UDP)) {
			return match_transport_protocols(_filter, p);
		} else {
			return match_ip(_filter, p);
		}
	case TYPE_TCP:
		return match_transport_protocols(_filter, p);
	case TYPE_UDP:
		return match_transport_protocols(_filter, p);
	case TYPE_TRUE:		//match every packet
		return 1;
	case TYPE_FALSE:	//match no packet at all
		return -1;
	default:
		break;
	}
	return -1;
}

int
IP6Classifier::configure(Vector<String> &conf, ErrorHandler *errh) {
	Token* temp;
	int _out_port = 0;
	ArgContext argcontext;
	filter_types *temp_filter;
	root_filter = new filter_types;
	temp_filter = root_filter;
	for (Vector<String>::iterator i=conf.begin(); i!=conf.end(); i++ ) {
		//check syntax error and get the stream of tokens
		temp = parseConfigurationString(*i);
		if (_out_port != 0) {	//if this is not the first pattern;
			temp_filter->next_pattern = new filter_types;
			temp_filter = temp_filter->next_pattern;
		}
		if (pattern(temp, temp_filter) == true) {
			temp_filter->output_port = _out_port;
		} else {
			click_chatter("Syntax error in configure() \n");
			return -1;
		}
		_out_port++;
	}
	temp_filter->next_pattern = NULL;
/*
 String badaddrs = String::make_empty();
 _offset = 0;
 Vector<String> ips;
 // ips.push_back("0::0"); // this address is only bad if we are a router
 ips.push_back("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); // bad IP6 address

 if (Args(conf, this, errh)
     .read_p("BADADDRS", badaddrs)
     .read_p("OFFSET", _offset)
     .complete() < 0)
    return -1;

  if (badaddrs) {
    Vector<String> words;
    cp_spacevec(badaddrs, words);
    IP6Address a;
    for (int j = 0; j < words.size(); j++) {
      if (!cp_ip6_address(words[j], (unsigned char *)&a)) {
	return errh->error("expects IP6ADDRESS -a ");
      }
      for (int j = 0; j < ips.size(); j++) {
	IP6Address b = IP6Address(ips[j]);
	if (b == a)
	  goto repeat;
      }
      ips.push_back(a.s());
     repeat: ;
    }
  }

  _n_bad_src = ips.size();
  _bad_src = new IP6Address [_n_bad_src];

  for (int i = 0; i<_n_bad_src; i++) {
    _bad_src[i]= IP6Address(ips[i]);
  }*/
  return 0;
}

void
IP6Classifier::push(int, Packet *p){
  filter_types *temp_filter = root_filter;
  Packet *temp_packet;
  /*in case some packets sastify more than one patterns,
   * packet p should be cloned and passed to more than one output ports
   * If packet p is not cloned, segmentation error will occurs*/
  while (temp_filter != NULL) {
	  if (match_pattern(temp_filter, p)>0) {
		  temp_packet = p->clone();
		  checked_output_push(temp_filter->output_port, temp_packet);
		  //p->kill;
	  }
	  temp_filter = temp_filter->next_pattern;
  }
}

static String
IP6Classifier_read_drops(Element *xf, void *)
{
  IP6Classifier *f = (IP6Classifier *)xf;
  return String(f->drops());
}

void
IP6Classifier::add_handlers()
{
  add_read_handler("drops", IP6Classifier_read_drops);
}

bool retrieveNumericData(Token *currentToken, filter_types *_filter){
	if (currentToken == NULL) {
		click_chatter("Syntax error at retrieveNumericData() \n");
		return false;
	}
	arguments *temp_arg = _filter->list;
	arguments *arg;
	Token *temp_token = currentToken;
	String *inputString;
	uint32_t temp_numeric;
	char * p;
	while(temp_token != NULL){

		inputString = temp_token->getTokenText();
		temp_numeric = (uint32_t)strtol(inputString->c_str(), &p, 10);
		if(*p != 0){
			click_chatter("Syntax error in retrieveNumericData() \n");
			return false;
		}
		temp_arg->current_argument.numeric_data = temp_numeric;
		if(temp_token->nextToken != NULL){
			temp_arg->next_argument = new arguments;
			temp_arg = temp_arg->next_argument;
		}
		temp_token = temp_token->nextToken;
	}
	return true;
}

bool retrieveIP6AddressData(Token *currentToken, filter_types *_filter){
	if (currentToken == NULL) {
		click_chatter("Syntax error at retrieveIP6AddressData() \n");
		return false;
	}
	arguments *temp_arg = _filter->list;
	arguments *arg;
	Token *temp_token = currentToken;
	String *inputString;
	IP6Address temp_ip6address;
	ArgContext arg_context;
	while (temp_token != NULL) {
		inputString = temp_token->getTokenText();
		if (IP6AddressArg::parse(*inputString, temp_ip6address, arg_context) == false) {
			printf("Syntax error in retrieveIP6AddressData() \n");
			return false;
		} else {
			temp_arg->current_argument.ip6address = new IP6Address(*inputString);
			if (temp_token->nextToken != NULL) {
				temp_arg->next_argument = new arguments;
				temp_arg = temp_arg->next_argument;
			}
			temp_token = temp_token->nextToken;
		}
	}
	return true;
}

bool parse_port(Token *currentToken, filter_types *_filter){
	String *currentTokenString = currentToken->getTokenText();
	if (*currentTokenString == "port") {
		return retrieveNumericData(currentToken->nextToken, _filter);
	} else {
		click_chatter("Syntax error in parse_port()");
		return false;
	}
}

bool parse_ether(Token *currentToken, filter_types *_filter){
	return true;
}

bool parse_src_dst(Token *currentToken, filter_types *_filter) {
	String *currentTokenString = currentToken->getTokenText();
	if (*currentTokenString == "host") {
		_filter->sub_sub_type = SUB_SUB_TYPE_HOST;
		return retrieveIP6AddressData(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "net") {
		_filter->sub_sub_type = SUB_SUB_TYPE_NET;
		return retrieveIP6AddressData(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "tcp"){
		_filter->sub_sub_type = SUB_SUB_TYPE_TCP;
		return parse_port(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "udp"){
		_filter->sub_sub_type = SUB_SUB_TYPE_UDP;
		return parse_port(currentToken->nextToken, _filter);

	} else {
		click_chatter("Syntax error in parse_src_and_dst()");
		return false;
	}
}


bool parse_src_or(Token *currentToken, filter_types *_filter){
	String *currentTokenString = currentToken->getTokenText();
	if (*currentTokenString == "dst") {
		_filter->sub_type = SUB_TYPE_SRC_OR_DST;
		return parse_src_dst(currentToken->nextToken, _filter);
	} else {
		click_chatter("Syntax error in parse_src_or()");
		return false;
	}
}

bool parse_src_and(Token *currentToken, filter_types *_filter){
	String *currentTokenString = currentToken->getTokenText();
	if (*currentTokenString == "dst") {
		_filter->sub_type = SUB_TYPE_SRC_AND_DST;
		return parse_src_dst(currentToken->nextToken, _filter);
	} else {
		click_chatter("Syntax error in parse_src_and()");
		return false;
	}
}


bool parse_ip_proto(Token *currentToken, filter_types *_filter){
	String *currentTokenString = currentToken->getTokenText();
	if (*currentTokenString == "tcp") {
		_filter->sub_sub_type = SUB_SUB_TYPE_TCP;
		return true;

	} else if (*currentTokenString == "udp") {
		_filter->sub_sub_type = SUB_SUB_TYPE_UDP;
		return true;

	} else if (*currentTokenString == "icmp") {
		_filter->sub_type = SUB_SUB_TYPE_ICMP;
		return true;

	} else {
		click_chatter("Syntax error in parse_ip_proto()");
		return false;
	}
}

bool parse_dst(Token *currentToken, filter_types *_filter) {
	String *currentTokenString = currentToken->getTokenText();
	if (*currentTokenString == "host") {
		_filter->sub_type = SUB_TYPE_DST;
		_filter->sub_sub_type = SUB_SUB_TYPE_HOST;
		return retrieveIP6AddressData(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "net") {
		_filter->sub_type = SUB_TYPE_DST;
		_filter->sub_sub_type = SUB_SUB_TYPE_NET;
		return retrieveIP6AddressData(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "tcp"){
		_filter->sub_type = SUB_TYPE_DST;
		_filter->sub_sub_type = SUB_SUB_TYPE_TCP;
		return parse_port(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "udp"){
		_filter->sub_type = SUB_TYPE_DST;
		_filter->sub_sub_type = SUB_SUB_TYPE_UDP;
		return parse_port(currentToken->nextToken, _filter);

	} else {
		click_chatter("Syntax error in parse_dst()");
		return false;
	}
}

bool parse_src(Token *currentToken, filter_types *_filter) {
	String *currentTokenString = currentToken->getTokenText();

	if (*currentTokenString == "and") {
		_filter->sub_type = SUB_TYPE_SRC_AND_DST;
		return parse_src_and(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "or") {
		_filter->sub_type = SUB_TYPE_SRC_OR_DST;
		return parse_src_or(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "host") {
		_filter->sub_type = SUB_TYPE_SRC;
		_filter->sub_sub_type = SUB_SUB_TYPE_HOST;
		return retrieveIP6AddressData(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "net") {
		_filter->sub_type = SUB_TYPE_SRC;
		_filter->sub_sub_type = SUB_SUB_TYPE_NET;
		return retrieveIP6AddressData(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "tcp") {
		_filter->sub_type = SUB_TYPE_SRC;
		_filter->sub_sub_type = SUB_SUB_TYPE_TCP;
		return parse_port(currentToken->nextToken, _filter);

	} else if (*currentTokenString == "udp") {
		_filter->sub_type = SUB_TYPE_SRC;
		_filter->sub_sub_type = SUB_SUB_TYPE_UDP;
		return parse_port(currentToken->nextToken, _filter);

	} else {
		//check if it is IP address or net address
		click_chatter("Syntax error in parse_src()");
		return false;
	}
}


bool parse_icmp(Token *currentToken, filter_types *_filter) {
	String *currentTokenString = currentToken->getTokenText();
	if(*currentTokenString == "type") {
		if(currentToken->nextToken != NULL){
			return retrieveNumericData(currentToken->nextToken, _filter);
		} else {
			click_chatter("Syntax error in parse_icmp()");
			return false;
		}
	} else {
		click_chatter("Syntax error in parse_icmp()");
		return false;
	}
}

bool parse_ip(Token *currentToken, filter_types *_filter){
	String *currentTokenString = currentToken->getTokenText();
	if(*currentTokenString == "proto") {
		_filter->sub_type = SUB_TYPE_IP_PROTO;
		return parse_ip_proto(currentToken->nextToken, _filter);

	} else if(*currentTokenString == "vers") {
		_filter->sub_type = SUB_TYPE_IP_VERS;
		return retrieveNumericData(currentToken->nextToken, _filter);

	} else if(*currentTokenString == "frag") {
		_filter->sub_type = SUB_TYPE_IP_FRAG;
		return true;

	} else if(*currentTokenString == "unfrag") {
		_filter->sub_type = SUB_TYPE_IP_UNFRAG;
		return true;

	} else if(*currentTokenString == "hll") {
		_filter->sub_type = SUB_TYPE_IP_HLL;
		return retrieveNumericData(currentToken->nextToken, _filter);

	} else if(*currentTokenString == "CoS") {
		_filter->sub_type = SUB_TYPE_IP_COS;
		return retrieveNumericData(currentToken->nextToken, _filter);

	} else if(*currentTokenString == "flow") {
		_filter->sub_type = SUB_TYPE_IP_FLOW;
		return retrieveNumericData(currentToken->nextToken, _filter);

	} else {
		click_chatter("Syntax error in parse_ip()");
		return false;
	}
}

bool pattern(Token *currentToken, filter_types *_filter){
	String *currentTokenString = currentToken->getTokenText();
	if(*currentTokenString == "ip") {
		_filter->type = TYPE_IP;
		return parse_ip(currentToken->nextToken, _filter);
	} else if(*currentTokenString == "icmp") {
		_filter->type = TYPE_ICMP;
		_filter->sub_sub_type = SUB_SUB_TYPE_ICMP;
		return parse_icmp(currentToken->nextToken, _filter);
	} else if(*currentTokenString == "src") {
		_filter->type = TYPE_SRC;
		return parse_src(currentToken->nextToken, _filter);
	} else if(*currentTokenString == "dst") {
		_filter->type = TYPE_DST;
		return parse_dst(currentToken->nextToken, _filter);
	} else if(*currentTokenString == "ether"){
		_filter->type = TYPE_ETHER;
		return parse_ether(currentToken->nextToken, _filter);
	} else if(*currentTokenString == "tcp") {
		_filter->type = TYPE_SRC;
		_filter->sub_type = SUB_TYPE_SRC_OR_DST;
		_filter->sub_sub_type = SUB_SUB_TYPE_TCP;
		return parse_port(currentToken->nextToken, _filter);
	} else if(*currentTokenString == "udp") {
		_filter->type = TYPE_SRC;
		_filter->sub_type = SUB_TYPE_SRC_OR_DST;
		_filter->sub_sub_type = SUB_SUB_TYPE_UDP;
		return parse_port(currentToken->nextToken, _filter);
	} else if(*currentTokenString == "true") {
		_filter->type = TYPE_TRUE;
		if(currentToken->nextToken == NULL){
			return true;
		}else{
			click_chatter("Syntax error in parse_pattern() \n");
			return false;
		}
	} else if(*currentTokenString == "false") {
		_filter->type = TYPE_FALSE;
		if(currentToken->nextToken == NULL){
			return true;
		}else{
			click_chatter("Syntax error in parse_pattern() \n");
			return false;
		}
	} else {
		click_chatter("Syntax error in pattern()");
		return false;
	}
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6Classifier)
