#include "main.h"
#include "utils.h"

void dump_mbuf(const struct rte_mbuf *m) {
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	uint16_t proto = eth_hdr->ether_type;
	size_t vlan_offset = get_vlan_offset(eth_hdr, &proto);

	printf("type:%d vlan_offset:%u vlan_hdr->eth_proto:%d\n", 
			eth_hdr->ether_type, (uint32_t)vlan_offset, proto);

#if 0
	struct iphdr *iph;
	struct tcphdr *th;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	int i, llen, dlen;
	const unsigned char *pos;
	const int line_len = 16;
	char buff[1024-32];
	char *p;

	iph = ip_hdr(skb);

	p = buff;
	if (iph->protocol != IPPROTO_TCP){
		p += snprintf(p, sizeof(buff) - (p - buff), "%s: protocal not tcp [%d]\n", __FUNCTION__, iph->protocol);
		printk(KERN_DEBUG "%s", buff);
		return;
	}
	th = (struct tcphdr *) ((char*)iph + iph->ihl*4);
	dlen = ntohs(iph->tot_len) - iph->ihl * 4 - th->doff * 4;

	{
		p += snprintf(p, sizeof(buff) - (p - buff),
			"%s:%lu skb len/datalen:%d/%d, dlen:%d %pI4:%u(%s)-->%pI4:%u(%s), seq:%x, ack:%x, next seq:%x\n\t[",
			__FUNCTION__, jiffies, skb->len, skb->data_len, dlen,
			&iph->saddr, ntohs(th->source), in  ? in->name  : "NULL",
			&iph->daddr, ntohs(th->dest),   out ? out->name : "NULL",
			ntohl(th->seq), ntohl(th->ack_seq), ntohl(th->seq)+(dlen > 0 ? dlen : 1) );
		if(th->fin) p += snprintf(p, sizeof(buff) - (p - buff), "F");
		if(th->syn) p += snprintf(p, sizeof(buff) - (p - buff), "S");
		if(th->rst) p += snprintf(p, sizeof(buff) - (p - buff), "R");
		if(th->ack) p += snprintf(p, sizeof(buff) - (p - buff), ".");
		if(th->psh) p += snprintf(p, sizeof(buff) - (p - buff), "P");
		if(th->urg) p += snprintf(p, sizeof(buff) - (p - buff), "U");
		if(th->ece) p += snprintf(p, sizeof(buff) - (p - buff), "E");
		if(th->cwr) p += snprintf(p, sizeof(buff) - (p - buff), "C");

		p += snprintf(p, sizeof(buff) - (p - buff), "] window[%04x] ", th->window);
		ct = nf_ct_get(skb, &ctinfo);
		if (ct){
			if((ct->status & IPS_NAT_MASK) == IPS_SRC_NAT)
				p += snprintf(p, sizeof(buff) - (p - buff), " [SNAT] ");
			if((ct->status & IPS_NAT_MASK) == IPS_DST_NAT)
				p += snprintf(p, sizeof(buff) - (p - buff), " [DNAT] ");
		}
		printf("%s\n", buff);
		p = buff;
		if(dlen >= HTTP_MIN_LEN && skb->data_len == 0) {
			dlen = dlen > line_len * 4 ? line_len * 4 : dlen;
			pos = (char *)th + th->doff * 4;
			while (dlen) {
				llen = dlen > line_len ? line_len : dlen;
				p += snprintf(p, sizeof(buff) - (p - buff), "    ");
				for (i = 0; i < llen; i++)
					p += snprintf(p, sizeof(buff) - (p - buff), " %02x", pos[i]);
				for (i = llen; i < line_len; i++)
					p += snprintf(p, sizeof(buff) - (p - buff), "   ");
				p += snprintf(p, sizeof(buff) - (p - buff), "   ");
				for (i = 0; i < llen; i++) {
					if (isprint(pos[i]))
						p += snprintf(p, sizeof(buff) - (p - buff), "%c", pos[i]);
					else
						p += snprintf(p, sizeof(buff) - (p - buff), "*");
				}
				for (i = llen; i < line_len; i++)
					p += snprintf(p, sizeof(buff) - (p - buff), " ");
				printf("%s\n", buff);
				p = buff;
				pos += llen;
				dlen -= llen;
			}
		}
	}
#endif
}



size_t get_vlan_offset(struct ether_hdr *eth_hdr, uint16_t *proto) {
	size_t vlan_offset = 0;

	if (rte_cpu_to_be_16(ETHER_TYPE_VLAN) == *proto) {
		struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);

		vlan_offset = sizeof(struct vlan_hdr);
		*proto = vlan_hdr->eth_proto;

		if (rte_cpu_to_be_16(ETHER_TYPE_VLAN) == *proto) {
			vlan_hdr = vlan_hdr + 1;
			*proto = vlan_hdr->eth_proto;
			vlan_offset += sizeof(struct vlan_hdr);
		}
	}
	return vlan_offset;
}

uint32_t xmit_l34_hash32(struct rte_mbuf *buf) {
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
	uint16_t proto = eth_hdr->ether_type;
	size_t vlan_offset = get_vlan_offset(eth_hdr, &proto);

	struct udp_hdr *udp_hdr = NULL;
	struct tcp_hdr *tcp_hdr = NULL;
	uint32_t hash, l3hash = 0, l4hash = 0;

	if (rte_cpu_to_be_16(ETHER_TYPE_IPv4) == proto) {
		struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)
				((char *)(eth_hdr + 1) + vlan_offset);
		size_t ip_hdr_offset;

		l3hash = ipv4_hash(ipv4_hdr);

		ip_hdr_offset = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
				IPV4_IHL_MULTIPLIER;

		if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
			tcp_hdr = (struct tcp_hdr *)((char *)ipv4_hdr +
					ip_hdr_offset);
			l4hash = HASH_L4_PORTS(tcp_hdr);
		} else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
			udp_hdr = (struct udp_hdr *)((char *)ipv4_hdr +
					ip_hdr_offset);
			l4hash = HASH_L4_PORTS(udp_hdr);
		}
	} else if  (rte_cpu_to_be_16(ETHER_TYPE_IPv6) == proto) {
		struct ipv6_hdr *ipv6_hdr = (struct ipv6_hdr *)
				((char *)(eth_hdr + 1) + vlan_offset);
		l3hash = ipv6_hash(ipv6_hdr);

		if (ipv6_hdr->proto == IPPROTO_TCP) {
			tcp_hdr = (struct tcp_hdr *)(ipv6_hdr + 1);
			l4hash = HASH_L4_PORTS(tcp_hdr);
		} else if (ipv6_hdr->proto == IPPROTO_UDP) {
			udp_hdr = (struct udp_hdr *)(ipv6_hdr + 1);
			l4hash = HASH_L4_PORTS(udp_hdr);
		}
	}

	hash = l3hash ^ l4hash;
	hash ^= hash >> 16;
	hash ^= hash >> 8;

	buf->hash.usr = hash;
	return hash;
}
