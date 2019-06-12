#!/usr/bin/env ython3
# -*- coding: utf-8 -*-

from scapy.all import sniff,DNS,DNSRR,IP,DNSQR

def dns_capture(pkt):
    """
    Decode the DNS packets and log Query, Answer data.
    """
    if DNSRR in pkt:
        ip_src = pkt[IP].src
        # ip_dst=pkt[IP].dst
        query_domain = pkt.getlayer(DNS).qd.qname
        query_type = pkt.getlayer(DNS).qd.get_field(
            'qtype').i2repr(DNSQR, pkt.getlayer(DNS).qd.qtype)
        if pkt.getlayer(DNS).an:
            aid = 0
            response = pkt.getlayer(DNS)
            while aid < response.ancount:
                resp = response.an[aid]
                dns_answer = resp.rdata
                dns_answer_for = resp.rrname
                resp_type = resp.get_field('type').i2repr(DNSRR, resp.type)
                print("Answer from %s: %s <- %s, %s" %
                      (ip_src, dns_answer, dns_answer_for, resp_type))
                aid = aid+1
            print("Query: %s, %s" % (query_domain, query_type))
        else:
            print("Query: %s, %s (no results)" % (query_domain, query_type))


sniff(iface=["wlp58s0"], filter="port 53", prn=dns_capture, store=0)
