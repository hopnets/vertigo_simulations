#ifndef __INET_V2PIFOPACKETINFO_H
#define __INET_V2PIFOPACKETINFO_H

#include "inet/common/INETDefs.h"

using namespace inet;

class INET_API V2PIFOPacketInfo
{
  public:
    Packet* packet;
    simtime_t arrival_time;
    unsigned long seq;

  public:
    V2PIFOPacketInfo(Packet* packet, simtime_t arrival_time, unsigned long seq) {
        this->packet = packet;
        this->arrival_time = arrival_time;
        this->seq = seq;
    };
};

#endif
