#ifndef __INET_ORDERINGCOMPONENTLRUNODE_H
#define __INET_ORDERINGCOMPONENTLRUNODE_H

#include "inet/common/INETDefs.h"
#include <unordered_set>
#include <unordered_map>

namespace inet {

/*
 * The information of packets and their flows that  kept in ordering component
 */

class INET_API OrderingComponentPacketInfo
{

  public:
    Packet *packet;
    simtime_t arrival_time = -1;
    // this time stays constant
    simtime_t actual_arrival_time = -1;

  public:
    OrderingComponentPacketInfo(simtime_t arrival_time, Packet *packet) {
        this->arrival_time = arrival_time;
        this->actual_arrival_time = arrival_time;
        this->packet = packet;
    };

    OrderingComponentPacketInfo(){};
};

class INET_API OrderingComponentFlowInfo
{
  public:
    unsigned long expected_seq;
    simtime_t last_updated = -1;
    // Note that packets should be ordered so that when we iterate, we iterate based on seqs of packets.
    // so we use map instead of unordered_map
    std::map<unsigned long, OrderingComponentPacketInfo*> stored_packet_hash_table; //used for LAS
    std::map<unsigned long, OrderingComponentPacketInfo*, std::greater<unsigned long>> descending_stored_packet_hash_table; // used for SRPT
    std::unordered_set<unsigned long> sent_packet_seqs; // used for las where size of payload doesn't matter: stores seq
    std::unordered_map<unsigned long, unsigned int> sent_packet_seqs_payload_length; // used for srpt where size of payload matters: seq --> payload_length
    cMessage *timeoutMsg;
    int expected_flow_let_id;
  public:
    OrderingComponentFlowInfo(unsigned long expected_seq, cMessage *timeoutMsg, int expected_flow_let_id = -1) {
        this->expected_seq = expected_seq;
        this->timeoutMsg = timeoutMsg;
        this->expected_flow_let_id = expected_flow_let_id;
    };

    OrderingComponentFlowInfo(){};
};

} // namespace inet

#endif // ifndef __INET_BITVECTOR_H
