#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "cms.h"

#ifndef IPPROTO_TCP
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define IPPROTO_ICMP 1
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef TC_ACT_OK'
#define TC_ACT_OK 0
#endif

// ---------------------------------------------------------
// Mapas BPF
// ---------------------------------------------------------

// Matriz do Count-Min Sketch: d linhas × w colunas
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CMS_TOTAL);
    __type(key, __u32);
    __type(value, __u64);
} cms_map SEC(".maps");

// Mapa auxiliar: fluxos "exatos" para validação (top-K debug)
// Opcional — útil para comparar com o sketch
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, __u64);
} exact_map SEC(".maps");

// ---------------------------------------------------------
// Funções hash (Murmur-inspired, sem divisão)
// ---------------------------------------------------------

static __always_inline __u32
hash_flow(const struct flow_key *k, __u32 seed)
{
    __u32 h = seed;
    // mistura os campos com rotações e XOR
    h ^= k->src_ip;
    h = (h << 13) | (h >> 19);
    h *= 0x5bd1e995;
    h ^= k->dst_ip;
    h = (h << 13) | (h >> 19);
    h *= 0x5bd1e995;
    h ^= (__u32)(k->src_port) | ((__u32)(k->dst_port) << 16);
    h = (h << 13) | (h >> 19);
    h *= 0x5bd1e995;
    h ^= k->protocol;
    h ^= h >> 15;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    return h;
}

// Seeds distintas para cada linha do sketch
static const __u32 seeds[CMS_ROWS] = {
    0xdeadbeef, 0xcafebabe, 0x12345678, 0xabcdef01
};

// ---------------------------------------------------------
// Atualização do CMS
// ---------------------------------------------------------

static __always_inline void
cms_update(const struct flow_key *key)
{
    // Loop com iterações fixas — o verificador eBPF exige isso
    __u32 col, idx;
    __u64 *val;

    // Linha 0
    col = hash_flow(key, seeds[0]) & (CMS_COLS - 1);
    idx = CMS_INDEX(0, col);
    val = bpf_map_lookup_elem(&cms_map, &idx);
    if (val) __sync_fetch_and_add(val, 1);

    // Linha 1
    col = hash_flow(key, seeds[1]) & (CMS_COLS - 1);
    idx = CMS_INDEX(1, col);
    val = bpf_map_lookup_elem(&cms_map, &idx);
    if (val) __sync_fetch_and_add(val, 1);

    // Linha 2
    col = hash_flow(key, seeds[2]) & (CMS_COLS - 1);
    idx = CMS_INDEX(2, col);
    val = bpf_map_lookup_elem(&cms_map, &idx);
    if (val) __sync_fetch_and_add(val, 1);

    // Linha 3
    col = hash_flow(key, seeds[3]) & (CMS_COLS - 1);
    idx = CMS_INDEX(3, col);
    val = bpf_map_lookup_elem(&cms_map, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}

// ---------------------------------------------------------
// Parser de pacotes
// ---------------------------------------------------------

static __always_inline int
parse_packet(struct __sk_buff *skb, struct flow_key *key)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;

    // IPv4
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    key->src_ip   = ip->saddr;
    key->dst_ip   = ip->daddr;
    key->protocol = ip->protocol;
    key->src_port = 0;
    key->dst_port = 0;

    // L4: TCP ou UDP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return -1;
        key->src_port = tcp->source;
        key->dst_port = tcp->dest;

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return -1;
        key->src_port = udp->source;
        key->dst_port = udp->dest;
    }
    // ICMP e outros: portas ficam zero (válido para o sketch)

    return 0;
}

// ---------------------------------------------------------
// Programa principal — TC egress
// ---------------------------------------------------------

SEC("classifier")
int cms_egress(struct __sk_buff *skb)
{
    struct flow_key key = {};

    if (parse_packet(skb, &key) < 0)
        return TC_ACT_OK;   // passa o pacote sem contar

    // Debug: loga src e dst
    //bpf_printk("src=%x dst=%x proto=%d\n",
    //           key.src_ip, key.dst_ip, key.protocol);

    // Atualiza CMS
    cms_update(&key);

    // Atualiza mapa exato (para validação)
    __u64 one = 1;
    __u64 *cnt = bpf_map_lookup_elem(&exact_map, &key);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        bpf_map_update_elem(&exact_map, &key, &one, BPF_NOEXIST);
    }

    return TC_ACT_OK;   // nunca dropa — só observa
}

char LICENSE[] SEC("license") = "GPL";