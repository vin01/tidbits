#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import sniff,DNS,DNSRR,IP,DNSQR,DNSRRDNSKEY
import logging

logging.basicConfig(
    format='%(asctime)s %(levelname)-5s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')

def dns_capture(pkt):
    """
    Decode the DNS packets and log Query, Answer data.
    """
    if DNSRR in pkt or DNSRRDNSKEY in pkt:
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
                if DNSRRDNSKEY in pkt:
                    dns_answer = resp.publickey
                else:
                    dns_answer = resp.rdata
                dns_answer_for = resp.rrname
                resp_type = resp.get_field('type').i2repr(DNSRR, resp.type)
                logging.info("Answer from %s: %s <- %s, %s" %
                      (ip_src, dns_answer, dns_answer_for, resp_type))
                aid = aid+1
            logging.info("Query: %s, %s" % (query_domain, query_type))
        else:
            logging.info("Query: %s, %s (no results)" % (query_domain, query_type))


sniff(filter="port 53", prn=dns_capture, store=0)
