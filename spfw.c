/*
* spfw.c - Tested on Ubuntu 20, with Linux version 5.4.0
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>

static struct nf_hook_ops *spfw_nfho = NULL;
static struct list_head *spfw_rules_list = NULL;
static DEFINE_RWLOCK(spfw_rules_list_lock);

static unsigned int localhost_ip = 0x7F000001; // Network byte order for 127.0.0.1

typedef enum {
	TCP,
	UDP
} spfw_protocol;

struct spfw_rule {
	struct list_head list;
	bool allow;					// Whether this is an allow rule: true -> allow, false -> block
	spfw_protocol protocol;		// Transport layer protocol
	unsigned int port;			// Destination port
	unsigned int src_ip_addr;	// Source IP address
};

// Allocate a new rule for the list
static struct spfw_rule *spfw_new_rule(bool allow, spfw_protocol protocol, unsigned int port, unsigned int src_ip_addr) {
	struct spfw_rule *rule = (struct spfw_rule *) kcalloc(1, sizeof(struct spfw_rule), GFP_KERNEL);
	rule->allow = allow;
	rule->protocol = protocol;
	rule->port = port;
	rule->src_ip_addr = src_ip_addr;
	return rule;
}

#define RULE_MATCHES_PACKET(ip_header, hdr, rule) \
	(ntohs(hdr->dest) == rule->port || rule->port == 0) \
	&& ((ntohl(ip_header->saddr) == rule->src_ip_addr) || rule->src_ip_addr == 0)

/*
static inline bool rule_matches_tcp_packet(struct iphdr *ip_header, struct tcphdr *tcp_header, struct spfw_rule *rule) {
	return (ntohs(tcp_header->dest) == rule->port || rule->port == 0) \
	&& ((ntohl(ip_header->saddr) == rule->src_ip_addr) || rule->src_ip_addr == 0);
}

static inline bool rule_matches_udp_packet(struct iphdr *ip_header, struct udphdr *udp_header, struct spfw_rule *rule) {
	return ntohs(udp_header->dest) == rule->port 
		&& ((ntohl(ip_header->saddr) == rule->src_ip_addr) || rule->src_ip_addr == 0);
}
*/


// TODO need to persist rules to filesystem, they are currently stored in memory only


// Netfilter Hook Function
static unsigned int spfw_hook_fn(void *p, struct sk_buff *skb, const struct nf_hook_state *state) {
	unsigned long lflags;
	struct spfw_rule *rule;
	struct list_head *ptr;
	unsigned int outcome;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	
	if (!skb || !(ip_header = ip_hdr(skb))) {
		return NF_ACCEPT;
	}

	// Always allow traffic from localhost
	if (ntohl(ip_header->saddr) == localhost_ip) {
		return NF_ACCEPT;
	}

	outcome = NF_ACCEPT; //  TODO this should be NF_DROP, equivalent to a DENY all rule at the end ? 

	// Loop through rules list and check for matches
	read_lock_irqsave(&spfw_rules_list_lock, lflags);

	ptr = spfw_rules_list->next;
	while (ptr != spfw_rules_list) {
		rule = list_entry(ptr, struct spfw_rule, list);

		// TCP traffic
		if (ip_header->protocol == IPPROTO_TCP) {
			// pr_info("Got TCP packet.\n");
			tcp_header = tcp_hdr(skb);
			if (!tcp_header) {
				break;
			}

			if (RULE_MATCHES_PACKET(ip_header, tcp_header, rule)) {
				outcome = rule->allow ? NF_ACCEPT : NF_DROP;
				pr_info("!! GOT MATCH for TCP on port %d\n", rule->port);
				break;
			}

		// UDP traffic
		} else if (ip_header->protocol == IPPROTO_UDP) {
			udp_header = udp_hdr(skb);
			if (!udp_header) {
				break;
			}

			if (RULE_MATCHES_PACKET(ip_header, udp_header, rule)) {
				outcome = rule->allow ? NF_ACCEPT : NF_DROP;
				pr_info("!! GOT MATCH for UDP on port %d\n", rule->port);
				break;
			}

		// OTHER protocols (just accept them for now)
		} else {
			outcome = NF_ACCEPT;
			break;
		}

		ptr = ptr->next;
	}

	read_unlock_irqrestore(&spfw_rules_list_lock, lflags);

	if (outcome == NF_DROP) {
		pr_info("   DROPPING PACKET for port %d!\n", rule->port);
	}

	return outcome;
}

static int __init spfw_init(void) {
	struct spfw_rule *tmp;

	// Initialise the list of rules
	spfw_rules_list = (struct list_head *) kcalloc(1, sizeof(struct list_head), GFP_KERNEL);
	INIT_LIST_HEAD(spfw_rules_list);

	tmp = spfw_new_rule(true, TCP, 7800, 0); 
	list_add(&tmp->list, spfw_rules_list);

	tmp = spfw_new_rule(false, TCP, 7801, 0); 
	list_add(&tmp->list, spfw_rules_list);

	tmp = spfw_new_rule(false, TCP, 7802, 0); 
	list_add(&tmp->list, spfw_rules_list);

	// Intialise the hook for netfilter
	spfw_nfho = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	spfw_nfho->hook 	= (nf_hookfn *) spfw_hook_fn;
	spfw_nfho->hooknum 	= NF_INET_PRE_ROUTING;
	spfw_nfho->pf 		= PF_INET;
	spfw_nfho->priority = NF_IP_PRI_FIRST;

	// Register our hook with netfilter
	nf_register_net_hook(&init_net, spfw_nfho);

	pr_info("Initialised SPFW module\n");
    return 0;
}


static void __exit spfw_exit(void) {
	unsigned long lflags;
	struct spfw_rule *rule;
	struct list_head *ptr = spfw_rules_list->next;

	// Deallocate memory used for the rules list
	write_lock_irqsave(&spfw_rules_list_lock, lflags);

	while (ptr != spfw_rules_list) {
		rule = list_entry(ptr, struct spfw_rule, list);
		ptr = ptr->next;
		kfree(rule);
	}
	kfree(spfw_rules_list);

	write_unlock_irqrestore(&spfw_rules_list_lock, lflags);


	// Unregister hook and deallocate its memory
	nf_unregister_net_hook(&init_net, spfw_nfho);
	kfree(spfw_nfho);

    pr_info("Exitted SPFW module\n");
}


module_init(spfw_init);
module_exit(spfw_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex Constantin-Gomez");
MODULE_DESCRIPTION("Simple Programmable Firewall");
