//
// Headers required for all modules
#include <linux/module.h>
// Required for kernel log level definitions such as KERN_INFO
#include <linux/kernel.h>
// Required for module initialization/cleanup macros (__init, __exit)
#include <linux/init.h>
// Required for the definition of the sk_buff structure
#include <linux/skbuff.h>
// Required for Netfilter hook function related definitions
#include <linux/netfilter.h>
// Required for Netfilter definitions for IPv4
#include <linux/netfilter_ipv4.h>
// Required for the definition of the IP header (iphdr)
#include <linux/ip.h>
// Required for the definition of the UDP header (udphdr)
#include <linux/udp.h>
// Required for endian conversion definitions (ntohs, etc.)
#include <linux/in.h>

// Module license declaration
MODULE_LICENSE("GPL v2");
// Module author information
MODULE_AUTHOR("Kohei Agata<dev.kohei@gata.email>");
// Module description
MODULE_DESCRIPTION("UDP DNS Query Analyzer");

#define DNS_PORT 53
#define DNS_QR_QUERY 0 // QR flag in DNS header (Query)

/**
 * @brief DNS header structure
 *
 * Defines the header part of the DNS protocol.
 * Each field is in network byte order (big-endian).
 */
struct dnshdr {
    __be16 id;      // Transaction ID
    __be16 flags;   // Flags
    __be16 qdcount; // Number of entries in the question section
    __be16 ancount; // Number of entries in the answer section
    __be16 nscount; // Number of entries in the authority section
    __be16 arcount; // Number of entries in the additional records section
};

// Structure variable to define Netfilter hook operations
static struct nf_hook_ops nf_dns_hook_ops;

/**
 * @brief Parses the DNS query name (QNAME) and converts it to a readable domain name.
 *
 * @param qname_ptr Pointer to the beginning of the QNAME in the DNS payload
 * @param payload_end Pointer to the end of the DNS payload
 * @param out_domain_name Buffer to store the converted domain name
 * @param out_len Size of the buffer
 * @return int 0 on success, a negative value on failure
 */
static int parse_dns_qname(const unsigned char *qname_ptr, const unsigned char *payload_end, char *out_domain_name, int out_len)
{
    int domain_len = 0;
    const unsigned char *p = qname_ptr;

    while (*p != 0) {
        // Check for pointer compression (common in DNS, but not supported here for simplicity)
        if ((*p & 0xc0) == 0xc0) {
            printk(KERN_LOCAL0 | KERN_WARNING "DNS QNAME parsing failed: pointer compression is not supported.\n");
            return -1;
        }

        // Get the length of the label
        unsigned int label_len = *p;
        p++;

        // Prevent out-of-bounds access to the payload
        if (p + label_len > payload_end) {
            printk(KERN_LOCAL0 | KERN_WARNING "DNS QNAME parsing failed: label length exceeds payload.\n");
            return -1;
        }

        // Prevent overflow of the output buffer
        if (domain_len + label_len + 1 > out_len) {
            printk(KERN_LOCAL0 | KERN_WARNING "DNS QNAME parsing failed: output buffer is too small.\n");
            return -1;
        }

        // Copy the label and add a dot
        memcpy(out_domain_name + domain_len, p, label_len);
        domain_len += label_len;
        out_domain_name[domain_len] = '.';
        domain_len++;

        p += label_len;
    }

    // Replace the trailing dot with a null terminator
    if (domain_len > 0) {
        out_domain_name[domain_len - 1] = '\0';
    } else {
        out_domain_name[0] = '\0';
    }

    return 0;
}


/**
 * @brief Netfilter hook function. Parses DNS queries and outputs them to the log.
 *
 * @param priv Private data passed during Netfilter hook registration
 * @param skb Socket buffer holding the packet data
 * @param state Structure holding the state of the hook point
 * @return unsigned int A value that determines the fate of the packet (always NF_ACCEPT)
 */
static unsigned int dns_analyzer_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    struct dnshdr *dns_header;
    char domain_name[256];

    // Do not process if skb is NULL or if linearization fails
    if (!skb || skb_linearize(skb) != 0) {
        return NF_ACCEPT;
    }

    // Get the IP header
    ip_header = ip_hdr(skb);

    // Ignore non-IPv4 UDP packets
    if (ip_header->protocol != IPPROTO_UDP) {
        return NF_ACCEPT;
    }

    // Get the UDP header
    udp_header = udp_hdr(skb);

    // Ignore non-DNS packets (destination port not 53)
    if (ntohs(udp_header->dest) != DNS_PORT) {
        return NF_ACCEPT;
    }

    // Get the DNS header (immediately after the UDP header)
    dns_header = (struct dnshdr *)((unsigned char *)udp_header + sizeof(struct udphdr));

    // Process only if it is a DNS query (QR flag=0) and there is at least one question
    if (((ntohs(dns_header->flags) >> 15) & 0x1) == DNS_QR_QUERY && ntohs(dns_header->qdcount) > 0) {
        // Get the starting position of the QNAME (domain name) (immediately after the DNS header)
        const unsigned char *qname_ptr = (unsigned char *)dns_header + sizeof(struct dnshdr);
        // End position of the UDP payload
        const unsigned char *payload_end = (unsigned char *)udp_header + ntohs(udp_header->len);

        // Parse the QNAME
        if (parse_dns_qname(qname_ptr, payload_end, domain_name, sizeof(domain_name)) == 0) {
            // Output the parsing result to the kernel log
            printk(KERN_LOCAL0 | KERN_INFO "[DNS Query] src: %pI4 dst: %pI4 QNAME: %s\n",
                   &ip_header->saddr, &ip_header->daddr, domain_name);
        }
    }

    // Allow all packets to pass through
    return NF_ACCEPT;
}

/**
 * @brief Initialization function called when the module is loaded.
 *
 * @return int 0 on success, an error code on failure
 */
static int __init dns_analyzer_init(void)
{
    printk(KERN_LOCAL0 | KERN_INFO "DNS Query Analyzer: module loaded.\n");

    // Netfilter hook settings
    nf_dns_hook_ops.hook = dns_analyzer_hook;
    nf_dns_hook_ops.pf = PF_INET; // IPv4
    // PRE_ROUTING: Hook all incoming packets before the routing decision
    nf_dns_hook_ops.hooknum = NF_INET_PRE_ROUTING;
    nf_dns_hook_ops.priority = NF_IP_PRI_FIRST; // Execute with the highest priority

    // Register the Netfilter hook
    if (nf_register_net_hook(&init_net, &nf_dns_hook_ops)) {
        printk(KERN_LOCAL0 | KERN_ERR "DNS Query Analyzer: failed to register netfilter hook.\n");
        return -1;
    }

    return 0;
}

/**
 * @brief Cleanup function called when the module is unloaded.
 */
static void __exit dns_analyzer_exit(void)
{
    // Unregister the registered Netfilter hook
    nf_unregister_net_hook(&init_net, &nf_dns_hook_ops);
    printk(KERN_LOCAL0 | KERN_INFO "DNS Query Analyzer: module unloaded.\n");
}

// Register the module's initialization and exit functions
module_init(dns_analyzer_init);
module_exit(dns_analyzer_exit);
