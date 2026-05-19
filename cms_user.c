#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/tc_act/tc_bpf.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <sys/socket.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cms.h"

static volatile int running = 1;
static void sig_handler(int sig) { running = 0; }

// Executa comando tc e verifica retorno
static void tc_cmd(const char *fmt, ...) {
    char cmd[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    int r = system(cmd);
    if (r != 0)
        fprintf(stderr, "[warn] tc cmd retornou %d: %s\n", r, cmd);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <iface>\n", argv[0]);
        return 1;
    }
    const char *iface = argv[1];
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Interface '%s' não encontrada\n", iface);
        return 1;
    }

    // Carrega o objeto BPF
    struct bpf_object *obj = bpf_object__open("cms_kern.o");
    if (!obj) { perror("bpf_object__open"); return 1; }
    if (bpf_object__load(obj)) { perror("bpf_object__load"); return 1; }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "cms_egress");
    if (!prog) { fprintf(stderr, "Programa 'cms_egress' não encontrado\n"); return 1; }

    int prog_fd = bpf_program__fd(prog);
    printf("[*] prog_fd = %d\n", prog_fd);

    // Instala clsact qdisc + filtro via tc (com BPF object pinado)
    // Primeiro pina o programa num path conhecido
    const char *pin_path = "/sys/fs/bpf/cms_egress";
    unlink(pin_path);  // remove se existir
    if (bpf_program__pin(prog, pin_path)) {
        perror("bpf_program__pin");
        return 1;
    }
    printf("[*] Programa pinado em %s\n", pin_path);

    // Instala qdisc clsact e filtro usando o path pinado
    tc_cmd("tc qdisc del dev %s clsact 2>/dev/null; true", iface);
    tc_cmd("tc qdisc add dev %s clsact", iface);
    // tc_cmd("tc filter add dev %s egress bpf da obj pinned %s sec classifier",
    //       iface, pin_path);
    tc_cmd("tc filter add dev %s egress bpf object-pinned %s direct-action",
       iface, pin_path);

    // Verifica se o filtro foi instalado
    printf("[*] Verificando filtro:\n");
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "tc filter show dev %s egress", iface);
        system(cmd);
    }

    // Obtém FDs dos mapas
    int cms_fd   = bpf_object__find_map_fd_by_name(obj, "cms_map");
    int exact_fd = bpf_object__find_map_fd_by_name(obj, "exact_map");
    if (cms_fd < 0 || exact_fd < 0) {
        fprintf(stderr, "Mapas não encontrados\n");
        return 1;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[*] CMS ativo na saída de %s. Ctrl+C para relatório.\n\n", iface);
    while (running) sleep(1);

    // Relatório
    printf("\n%-20s %-20s %-8s %-8s %-6s | %10s %10s %8s\n",
           "SRC_IP", "DST_IP", "SPORT", "DPORT", "PROTO",
           "EXACT", "SKETCH", "ERRO%");
    printf("%s\n", "-------------------------------------------------------------------------------------------");

    struct flow_key {
        __u32 src_ip, dst_ip;
        __u16 src_port, dst_port;
        __u8  protocol, pad[3];
    } fkey = {}, next_fkey;

    int ncpus = libbpf_num_possible_cpus();

    while (bpf_map_get_next_key(exact_fd, &fkey, &next_fkey) == 0) {
        fkey = next_fkey;
        __u64 exact = 0;
        bpf_map_lookup_elem(exact_fd, &fkey, &exact);

        // Consulta CMS
        __u32 seeds[] = { 0xdeadbeef, 0xcafebabe, 0x12345678, 0xabcdef01 };
        __u64 min_count = UINT64_MAX;
        for (int row = 0; row < CMS_ROWS; row++) {
            __u32 h = seeds[row];
            h ^= fkey.src_ip;  h = (h<<13)|(h>>19); h *= 0x5bd1e995;
            h ^= fkey.dst_ip;  h = (h<<13)|(h>>19); h *= 0x5bd1e995;
            h ^= (__u32)fkey.src_port | ((__u32)fkey.dst_port << 16);
            h = (h<<13)|(h>>19); h *= 0x5bd1e995;
            h ^= fkey.protocol;
            h ^= h>>15; h *= 0x85ebca6b; h ^= h>>13;

            __u32 col = h & (CMS_COLS - 1);
            __u32 idx = row * CMS_COLS + col;

            __u64 percpu_vals[256] = {};
            if (bpf_map_lookup_elem(cms_fd, &idx, percpu_vals) == 0) {
                __u64 total = 0;
                for (int c = 0; c < ncpus; c++) total += percpu_vals[c];
                if (total < min_count) min_count = total;
            }
        }
        __u64 sketch = (min_count == UINT64_MAX) ? 0 : min_count;

        double err = exact > 0
            ? 100.0 * (double)(sketch - exact) / exact : 0.0;

        char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
        struct in_addr src = { .s_addr = fkey.src_ip };
        struct in_addr dst = { .s_addr = fkey.dst_ip };
        // inet_ntoa usa buffer estático — chamar duas vezes na mesma
        // expressão retorna o mesmo ponteiro sobrescrito
        inet_ntop(AF_INET, &src, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &dst, dst_str, sizeof(dst_str));
        printf("%-20s %-20s %-8u %-8u %-6u | %10llu %10llu %+8lld %7.2f%%\n",
            src_str, dst_str,
            ntohs(fkey.src_port), ntohs(fkey.dst_port),
            fkey.protocol, exact, sketch,
            (long long)(sketch - exact),   // erro absoluto
            err);

    }

    // Limpeza
    tc_cmd("tc filter del dev %s egress 2>/dev/null; true", iface);
    tc_cmd("tc qdisc del dev %s clsact 2>/dev/null; true", iface);
    unlink(pin_path);
    bpf_object__close(obj);
    return 0;
}