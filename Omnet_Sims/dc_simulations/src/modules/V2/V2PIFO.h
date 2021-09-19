//
// Copyright (C) OpenSim Ltd.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see http://www.gnu.org/licenses/.
//

#ifndef __INET_V2PIFO_H
#define __INET_V2PIFO_H

#include "inet/queueing/queue/PacketQueue.h"
#include "inet/queueing/compat/cpacketqueue.h"
#include "inet/queueing/contract/IPacketBuffer.h"
#include "inet/queueing/contract/IActivePacketSink.h"
#include "inet/queueing/contract/IPacketComparatorFunction.h"
#include "inet/queueing/contract/IPacketDropperFunction.h"
#include "inet/queueing/contract/IActivePacketSource.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/linklayer/ethernet/EtherFrame_m.h"
#include "inet/queueing/marker/EcnMarker.h"

using namespace inet;
using namespace queueing;

class INET_API V2PIFO : public PacketQueue
{

  protected:
    static simsignal_t packetDropSeqSignal;
    static simsignal_t packetDropRetCountSignal;
    static simsignal_t packetDropTotalPayloadLenSignal;

    virtual void initialize(int stage) override;

    // calculates the priority based on sequence number and ret_cnt
    unsigned long calculate_priority(unsigned long seq, unsigned long ret_count);

    // extracts priority of a packet
    unsigned long extract_priority(Packet *packet, bool is_packet_being_dropped=false);

    // hash table sorted based on packets' priority
    std::map<unsigned long, std::list<Packet*>> sorted_queued_packet_hash_table; // sorted based on priority

    int dropper_type;
    int scheduler_type;

    // dctcp support
    int dctcp_thresh;
    bool mark_packets_in_enqueue;

    // true if the deflection is on
    bool bounce_randomly_v2;

    // boosting factor for retransmission
    double denominator_for_retrasnmissions;

    // measurement counters
    unsigned long long light_in_queue_packet_drop_count = 0;
    double all_packets_queueing_time_sum = 0;
    double mice_packets_queueing_time_sum = 0;
    unsigned int num_all_packets = 0;
    unsigned int num_mice_packets = 0;


  public:
    virtual ~V2PIFO();

    /*
     * pushes the packet into the appropriate position in the priority queue
     */
    virtual void pushPacket(Packet *packet, cGate *gate) override;

    /*
     * pops the appropriate packet according to the scheduling technique
     */
    virtual Packet *popPacket(cGate *gate) override;

    /*
     * removes a packet from queue
     */
    virtual void removePacket(Packet *packet) override;

    /*
     * calculates how many packets with lower priority
     * should be ejected from the queue to make room
     * for a new packet of length packet_length. Returns
     * -1 if there are not enought packets with lower priority
     * to make room for the new packet.
     */
    virtual int getNumPacketsToEject(b packet_length, long seq, long ret_count,
            long on_the_way_packet_num, b on_the_way_packet_length) override;

    /*
     * ejects the packets to make room for new packet
     */
    virtual std::list<Packet*> eject_and_push(int num_packets_to_eject) override;

    /*
     * returns True if the queue is full
     */
    virtual bool is_queue_full(b packet_length, long on_the_way_packet_num = 0, b on_the_way_packet_length = b(0)) override;

    /*
     * returns the queue occupancy at any instance of time
     */
    virtual long get_queue_occupancy(long on_the_way_packet_num = 0, b on_the_way_packet_length = b(0)) override;


};

#endif // ifndef __INET_V2PIFO_H

