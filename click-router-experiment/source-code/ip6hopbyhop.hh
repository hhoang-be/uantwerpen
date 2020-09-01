#ifndef CLICK_IP6HOPBYHOP_HH
#define CLICK_IP6HOPBYHOP_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <clicknet/ip.h>
#include <clicknet/ip6.h>
CLICK_DECLS

struct jumbo_option{
	uint8_t _j_type;
	uint8_t _j_o_length;
	uint32_t _j_length;
};


class IP6HopByHop : public Element {

	uint32_t _drops;

 public:

  IP6HopByHop();
  ~IP6HopByHop();

  const char *class_name() const		{ return "IP6HopByHop"; }
  const char *port_count() const		{ return "1/-6";}
  const char *processing() const		{ return PUSH; }
  int configure(Vector<String> &, ErrorHandler *);

  int checkingHopByHop(const click_ip6_header_ext *t_header);
  int drops() const				{ return _drops; }

  void add_handlers();
  void push(int, Packet *p);


};

CLICK_ENDDECLS
#endif
