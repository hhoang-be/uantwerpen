#ifndef CLICK_IP6CLASSIFIER_HH
#define CLICK_IP6CLASSIFIER_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/ip6address.hh>
CLICK_DECLS

/*
 * =c
 * IP6Classifier([BADADDRS, OFFSET])
 * =s ip6
 *
 * =d
 *
 * Expects IP6 packets as input starting at OFFSET bytes. Default OFFSET
 * is zero. Checks that the packet's length is
 * reasonable, and that the IP6 version,  length, are valid. Checks that the
 * IP6 source address is a legal unicast address. Shortens packets to the IP6
 * length, if the IP length is shorter than the nominal packet length (due to
 * Ethernet padding, for example). Pushes invalid packets out on output 1,
 * unless output 1 was unused; if so, drops invalid packets.
 *
 * Keyword arguments are:
 *
 * =over 8
 *
 * =item BADADDRS
 *
 * The BADADDRS argument is a space-separated list of IP6 addresses that are
 * not to be tolerated as source addresses. 0::0 is a bad address for routers,
 * for example, but okay for link local packets.
 *
 * =item OFFSET
 *
 * Unsigned integer. Byte position at which the IP6 header begins. Default is 0.
 *
 * =back
 *
 * =a MarkIP6Header */

enum{
	  TYPE_IP = 1001,
	  TYPE_ICMP = 1002,
	  TYPE_SRC = 1003,
	  TYPE_DST = 1004,
	  TYPE_ETHER = 1005,
	  TYPE_TCP = 1006,
	  TYPE_UDP = 1007,
	  TYPE_TRUE = 1008,
	  TYPE_FALSE = 1009,

	  SUB_TYPE_IP_PROTO_TCP = 101,
	  SUB_TYPE_IP_VERS = 102,
	  SUB_TYPE_IP_FRAG = 103,
	  SUB_TYPE_IP_UNFRAG = 104,
	  SUB_TYPE_IP_HLL = 105,
	  SUB_TYPE_IP_COS = 106,
	  SUB_TYPE_IP_FLOW = 107,
	  SUB_TYPE_IP_PROTO = 110,

	  SUB_TYPE_SRC = 301,
	  SUB_TYPE_DST = 302,
	  SUB_TYPE_SRC_AND_DST = 303,
	  SUB_TYPE_SRC_OR_DST = 304,

	  SUB_SUB_TYPE_HOST = 401,
	  SUB_SUB_TYPE_NET = 402,
	  SUB_SUB_TYPE_TCP = 403,
	  SUB_SUB_TYPE_UDP = 404,
	  SUB_SUB_TYPE_ICMP = 405
};

/*List of parameters given to classification criteria*/
struct arguments {
	union {
		uint32_t numeric_data;	//numeric parameters
		IP6Address *ip6address;	//ip address parameters
	} current_argument;
	arguments *next_argument;

	//Constructor
	arguments(){
		current_argument.ip6address = NULL;
		next_argument = NULL;
	};
};

/*List of patterns*/
struct filter_types{
	uint16_t output_port;	//output port of packets matching this pattern
	uint16_t type;			//main category of classification
	uint16_t sub_type;		//sub-catergory of classification
	uint16_t sub_sub_type;	//sub-sub catergory of classification
	arguments *list;
	filter_types *next_pattern;
	//Constructor
	filter_types(){
		list = new arguments;
		next_pattern = NULL;
	}
};

class Token {
private:
	int tokenID;
	String tokenText;
public:
	Token* nextToken;
	Token(int _tokenID, String _tokenText):tokenID(_tokenID), tokenText(_tokenText), nextToken(NULL){};
	Token(String _tokenText): tokenID(1), tokenText(_tokenText), nextToken(NULL){};
	int getTokenID() {return tokenID;};
	String* getTokenText() {return &tokenText;};
};

class IP6Classifier : public Element {

  int _offset;

  int _n_bad_src;
  IP6Address *_bad_src; // array of illegal IP6 src addresses.
#ifdef CLICK_LINUXMODULE
  bool _aligned;
#endif
  int _drops;

 public:
  filter_types *root_filter;

  IP6Classifier();
  ~IP6Classifier();

  const char *class_name() const		{ return "IP6Classifier"; }
  const char *port_count() const		{ return "1/-6"; }
  const char *processing() const		{ return PUSH; }

  Token* parseConfigurationString(String);
  int match_filter(filter_types *_filter, Packet *p);
  int match_transport_protocols(filter_types *_filter, Packet *p);
  int match_ip(filter_types *_filter, Packet *p);
  int match_ip6header(int option, uint32_t parameter, Packet *p);
  int match_pattern(filter_types *_filter, Packet *p);
  int isFragmented(Packet *p);
  int match_ip6_hdr_fields(filter_types *_filter, Packet *p);
  int configure(Vector<String> &, ErrorHandler *);
  inline bool compare_host_net(int option, IP6Address left, IP6Address *right);

  int drops() const				{ return _drops; }


  void add_handlers();
  void push(int, Packet *p);
};

CLICK_ENDDECLS
#endif
