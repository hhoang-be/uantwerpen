#ifndef CLICK_IP6ROUTING_HH
#define CLICK_IP6ROUTING_HH
#include <click/element.hh>
#include <click/glue.hh>
CLICK_DECLS

/*
 * =c
 * IP6Fragmenter(MTU)
 * =s ip6
 *
 * =d
 * Expects IP6 packets as input.
 * If the IP6 packet size is <= mtu, just emits the packet on output 0.
 * If the size is greater than mtu and DF isn't set, splits into
 * fragments emitted on output 0.
 * If DF is set and size is greater than mtu, sends to output 1.
 *
 * Ordinarily output 1 is connected to an ICMP6Error packet generator
 * with type 3 (UNREACH) and code 4 (NEEDFRAG).
 *
 * Only the mac_broadcast annotation is copied into the fragments.
 *
 * Sends the first fragment last.
 *
 * =e
 * Example:
 *
 *   ... -> fr::IP6Fragmenter -> Queue(20) -> ...
 *   fr[1] -> ICMP6Error(18.26.4.24, 3, 4) -> ...
 *
 * =a ICMP6Error, CheckLength
 */

class IP6Routing : public Element {

  unsigned _mtu;
  unsigned _headroom;
  uint32_t _drops;
  uint32_t _fragments;

 public:

  IP6Routing();
  ~IP6Routing();

  const char *class_name() const		{ return "IP6Routing"; }
  const char *port_count() const		{ return PORTS_1_1X2; }
  const char *processing() const		{ return PUSH; }
  int configure(Vector<String> &, ErrorHandler *);

  int drops() const				{ return _drops; }

  void add_handlers();
  void routing(Packet *p_in);
  void push(int, Packet *p);


};

CLICK_ENDDECLS
#endif
