#ifndef __INET_LRUSINGLEVALUENODE_H
#define __INET_LRUSINGLEVALUENODE_H

#include "inet/common/INETDefs.h"

namespace inet {

// valinor marking component
/*
 * The information of the packets and their flows that are kept in the marking component
 */
struct MarkingInfoHolder
{
    unsigned long seq;
    unsigned long ret_count;
    bool is_first_packet = false;
    int flow_let_id;
    bool is_control_message = false;
};

struct PayloadInfoHolder
{
    bool is_bursty;
    b payload_length;
    b total_payload_length;
    b offset;
};

class INET_API LRUPacketInfo
{
  public:
    unsigned long seq;
    unsigned long ret_count;
    bool is_first_packet;
    int flow_let_id = -1;

  public:
    LRUPacketInfo(unsigned long seq, unsigned long ret_count, int flow_let_id, bool is_first_packet = false) {
        this->seq = seq;
        this->ret_count = ret_count;
        this->flow_let_id = flow_let_id;
        this->is_first_packet = is_first_packet;
    };

    LRUPacketInfo(){};
};

class INET_API LRUFlowInfo
{
  public:
    unsigned long seq;
    unsigned long ret_count;
    simtime_t last_updated = -1;
    int flow_let_id = -1;
    std::unordered_map<unsigned long, LRUPacketInfo*> packet_hash_table;
    bool should_close_after_sending = false;

  public:
    LRUFlowInfo(unsigned long seq, unsigned long ret_count, simtime_t last_updated, int flow_let_id) {
        this->seq = seq;
        this->ret_count = ret_count;
        this->last_updated = last_updated;
        this->flow_let_id = flow_let_id;
    };

    LRUFlowInfo(){};
};

} // namespace inet

#endif // ifndef __INET_BITVECTOR_H
