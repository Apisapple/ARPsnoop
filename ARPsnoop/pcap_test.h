#pragma once

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>


#define ARP 0x0806
#define REQ 0x0001
#define REP 0x0002


class pcap_test
{
private:
    struct pcap_pkthdr *header;
    pcap_t *handle;
    u_int send_naddr;
    u_int send_haddr;
    u_int target_naddr;
    u_int target_haddr;
    u_int8_t src_mac[6];
    u_char sender_mac[6];
    u_char sender_ip[4];
    u_char target_mac[6];
    u_char target_ip[6];

    char *dev;
    bool isARP = false;
    bool isOK = true;
    bool cmpIP = true;
    unsigned int opcode;
    const u_char *packet;
    int res;

    struct Ethernet {
        u_char Dmac[6];
        u_char Smac[6];
        uint16_t etype;
    };

    struct rep_packet{
        struct Ethernet eth;        //arp 구조체와 한번에 이어서 쓰기 위하여 ethernet 구조체를 가져옴
        u_int16_t hard_type;        //hardware type -- ethernet(1)
        u_int16_t proc_type;        //protocol type -- ARP(0x0806)
        u_int8_t hard_len;          //Hardware size -- 6
        u_int8_t proc_len;          //Protocol size -- 4
        u_int16_t oper;             //Opcode -- request(1) , reply(2)
        u_int8_t sender_mac[6];     //Sender MAC address
        u_int8_t sender_ip[4];      //Sender IP address
        u_int8_t target_mac[6];     //Target MAC address
        u_int8_t target_ip[4];      //Target IP address
    };

public:
    pcap_test();
    ~pcap_test();
    int catch_Handle(char errbuf[]);
    int catch_res();


    //  setter
    void setDev(char* argv[]);
    void setSenderip();
    void setTargetip();
    void setTargetmac();
    void setSendermac();
    void setOpcode();
    void allSetting();
    int setMy_dev(char *dev, u_int8_t* mac);

    //  getter
    u_char* getSenderip();
    u_char* getTargetip();
    u_char* getTargetmac();
    u_char* getSendermac();
    //    u_char* getMacAddress(char *interface);
    unsigned int getOpcode();

    //  show
    void showDev();
    void showSenderip();
    void showTargetip();
    void showSendermac();
    void showTest();

    // function
    bool findARP();
    bool ipCmp();
    void findSenderpacket();
    void sendReppacket();


};

