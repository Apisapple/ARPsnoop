#include "pcap_test.h"


void usage()
{
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char *argv[])
{
    //    u_int32_t sender_ip;
    //    u_int32_t target_ip;

    char errbuf[PCAP_ERRBUF_SIZE];
    // Wron argc
    if (argc != 4)
    {
        usage();
        return -1;
    }
    /*-----------------------------------*/
    pcap_test* tester = new pcap_test();
    //setting
    tester->setDev(argv);
    /*=============== argv[2] == sender ip, argv[3] == target ip =======================*/
    tester->catch_Handle(errbuf);

    /*=============================Start cpature packet ==========================================*/
    while(true){
        if (tester->catch_res() == 0)
            continue;
        else if (tester->catch_res() == -1 || tester->catch_res() == -2)
            break;
        tester->allSetting();
        /*================================= Capture ARP ==============================================*/
        if(tester->findARP()){
            tester->findSenderpacket();
            tester->sendReppacket();
        }
    }
}
