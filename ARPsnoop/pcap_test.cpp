#include "pcap_test.h"

pcap_test::pcap_test()
{

}
pcap_test::~pcap_test(){
    pcap_close(handle);
}

// Try catch handler
int pcap_test::catch_Handle(char errbuf[]){
    handle = pcap_open_live(this->dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    return 0;
}

int pcap_test::catch_res(){
    res = pcap_next_ex(handle, &header, &packet);
    return res;
}

/*==================================setter========================================*/
void pcap_test::setDev(char* argv[]){
    this->dev = argv[1];
    this->send_naddr = inet_addr(argv[2]);
    this->send_haddr = ntohl(send_naddr);
    this->target_naddr = inet_addr(argv[3]);
    this->target_haddr = ntohl(target_naddr);
    printf("%u", send_haddr>>24);
    //    printf("%d.%d.%d.%d\n",send_haddr>>24, (u_char)(send_haddr>>16),(u_char)(send_haddr>>8),(u_char)(send_haddr));

}
void pcap_test::setSendermac(){
    for(int i = 0; i < 6; i++){
        this->sender_mac[i] = packet[i+22];
    }
}
void pcap_test::setSenderip(){
    for(int i = 0 ; i < 4; i++){
        this->sender_ip[i] = packet[i+28];
    }
}
void pcap_test::setTargetmac(){
    for(int i = 0 ; i < 6; i++){
        this->target_mac[i] = packet[i+32];
    }
}
void pcap_test::setTargetip(){
    for (int i = 0; i < 4; i++) {
        this->target_ip[i] = packet[i+38];
    }
}
void pcap_test::setOpcode(){
    opcode = (unsigned int)((packet[20] << 8) | packet[21]);
    //    printf("%d\n", opcode);
}
int pcap_test::setMy_dev(char *dev, u_int8_t *mac)
{
    struct ifreq ifr;            //Ethernet 관련 정보 필요할때 사용
    int fd;
    int rv; // return value - error value from df or ioctl call

    /* determine the local MAC address */
    strcpy(ifr.ifr_name, dev);                //2번째 인자의 값을 1번째 인자로 복사 (ifr.ifr_name 은 interface name)
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);     //AF_INET = 네트워크 도메인 소켓(IPv4 프로토콜), Sock_Dgram = 데이터그램 소켓, IPProto_ip = IP 프로토콜 사용
    if (fd < 0)
        rv = fd;
    else
    {
        rv = ioctl(fd, SIOCGIFHWADDR, &ifr);            //SIOCGIFHWADDR 요청
        if (rv >= 0) /* worked okay */
            memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);    //SIOCGIFHWADDR 를 요청하면 ifreq 구조체의 sa_data를 6바이트 읽어낸다.
    }

    return rv;
}
void pcap_test::allSetting(){
    this->setSendermac();
    this->setSenderip();
    this->setTargetmac();
    this->setTargetip();
    this->setOpcode();
}

/*==================================getter========================================*/
u_char* pcap_test::getSenderip(){
    return this->sender_ip;
}
u_char* pcap_test::getTargetip(){
    return this->target_ip;
}
u_char* pcap_test::getSendermac(){
    return this->sender_mac;
}
u_char* pcap_test::getTargetmac(){
    return this->target_mac;
}
unsigned int pcap_test::getOpcode(){
    return this->opcode;
}
/*================================== show ========================================*/
void pcap_test::showDev(){
    printf("%s\n", this->dev);
}
void pcap_test::showSenderip(){
    printf("%u. %u. %u. %u\n", this->sender_ip[2], this->sender_ip[3], this->sender_ip[0], this->sender_ip[1]);
}
void pcap_test::showTargetip(){
    printf("%s\n", this->target_ip);
}
void pcap_test::showSendermac(){
    for(int i = 0; i < 6; i++){
        printf("%02X :",sender_mac[i]);
    }
    printf("\n");
}

/*================================= function ===================================*/
bool pcap_test::findARP(){
    if((unsigned int)((packet[12] << 8) | packet[13]) == ARP){
        isARP = true;
    }
    return isARP;
}
bool pcap_test::ipCmp(){
    if((this->send_haddr>>24) != sender_ip[2]) this->cmpIP = false;
    if((this->send_haddr>>16) != sender_ip[3]) this->cmpIP = false;
    if((this->send_haddr>>8) != sender_ip[0]) this->cmpIP = false;
    if(this->send_haddr != sender_ip[1]) this->cmpIP = false;

    return cmpIP;
}
/*==============================find Sender Packet ============================*/
void pcap_test::findSenderpacket(){

    //    find request
    if(this->opcode == REQ){
        if(this->ipCmp()){
            this->setSendermac();
            this->setSenderip();
            this->setMy_dev(dev,src_mac);
        }
    }
}

void pcap_test::sendReppacket(){

    rep_packet rep;
    for(int i=0; i<6; i++){
        rep.eth.Dmac[i] = sender_mac[i];
//        printf("%02X\n", src_mac[i]);
    }
    for(int i=0; i<6; i++){

        rep.eth.Smac[i] = src_mac[i];
    }
    rep.eth.etype = (u_int16_t)ntohs(ARP);
    rep.hard_type = (u_int16_t)ntohs(0x0001);   //ethernet
    rep.proc_type = (u_int16_t)ntohs(0x0800);   //http
    rep.hard_len = (u_int8_t)0x06;
    rep.proc_len = (u_int8_t)0x04;
    rep.oper = (u_int16_t)ntohs(REP);
    for(int i=0; i<6; i++){
        rep.sender_mac[i] = sender_mac[i];
    }
    for(int i=0; i<4; i++){
        rep.sender_ip[i] = target_ip[i];
    }
    memcpy((char*)rep.target_mac, target_mac,6);
    for(int i=0; i<4; i++){
        rep.target_ip[i] = sender_ip[i];
    }while(1){
        pcap_sendpacket(handle,(u_char*)&rep, sizeof(rep));
    }
}
