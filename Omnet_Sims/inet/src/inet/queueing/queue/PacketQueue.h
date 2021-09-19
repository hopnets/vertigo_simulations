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

#ifndef __INET_PACKETQUEUE_H
#define __INET_PACKETQUEUE_H

#include "inet/queueing/base/PacketQueueBase.h"
#include "inet/queueing/compat/cpacketqueue.h"
#include "inet/queueing/contract/IPacketBuffer.h"
#include "inet/queueing/contract/IActivePacketSink.h"
#include "inet/queueing/contract/IPacketComparatorFunction.h"
#include "inet/queueing/contract/IPacketDropperFunction.h"
#include "inet/queueing/contract/IActivePacketSource.h"

namespace inet {
namespace queueing {

class INET_API PacketQueue : public PacketQueueBase, public IPacketBuffer::ICallback
{
  protected:
    cGate *inputGate = nullptr;
    IActivePacketSource *producer = nullptr;

    cGate *outputGate = nullptr;
    IActivePacketSink *collector = nullptr;

    int packetCapacity = -1;
    b dataCapacity = b(-1);

    cPacketQueue queue;
    IPacketBuffer *buffer = nullptr;

    IPacketDropperFunction *packetDropperFunction = nullptr;
    IPacketComparatorFunction *packetComparatorFunction = nullptr;

  protected:
    simsignal_t customQueueLengthSignal;
    simsignal_t customQueueLengthSignalPacketBytes;
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *message) override;
    virtual bool isOverloaded();

  public:
    virtual ~PacketQueue() { delete packetDropperFunction; }

    virtual int getMaxNumPackets() override { return packetCapacity; }
    virtual int getNumPackets() override;

    virtual b getMaxTotalLength() override { return dataCapacity; }
    virtual b getTotalLength() override { return b(queue.getBitLength()); }

    virtual bool isEmpty() override { return getNumPackets() == 0; }
    virtual Packet *getPacket(int index) override;
    virtual void removePacket(Packet *packet) override;

    virtual bool supportsPushPacket(cGate *gate) override { return inputGate == gate; }
    virtual bool canPushSomePacket(cGate *gate) override;
    virtual bool canPushPacket(Packet *packet, cGate *gate) override;
    virtual void pushPacket(Packet *packet, cGate *gate) override;
    virtual void pushPacketAfter(Packet *where, Packet *packet) override;

    virtual bool supportsPopPacket(cGate *gate) override { return outputGate == gate; }
    virtual bool canPopSomePacket(cGate *gate) override { return !isEmpty(); }
    virtual Packet *canPopPacket(cGate *gate) override { return !isEmpty() ? getPacket(0) : nullptr; }
    virtual Packet *popPacket(cGate *gate) override;

    virtual void handlePacketRemoved(Packet *packet) override;
    virtual std::string get_full_path() override {return getFullPath();}

    virtual int getNumPacketsToEject(b packet_length, long seq, long ret_count,
                long on_the_way_packet_num, b on_the_way_packet_length) {
        throw cRuntimeError("getNumPacketsToEject called in PacketQueue");
    }
    virtual std::list<Packet*> eject_and_push(int num_packets_to_eject) {
        throw cRuntimeError("eject_and_push called in PacketQueue");
    }
    virtual bool is_queue_full(b packet_length, long on_the_way_packet_num = 0, b on_the_way_packet_length = b(0)) {
        throw cRuntimeError("is_queue_full called in PacketQueue");
    }
    virtual long get_queue_occupancy(long on_the_way_packet_num = 0, b on_the_way_packet_length = b(0)) {
        throw cRuntimeError("get_queue_occupancy called in PacketQueue");
    }
};

} // namespace queueing
} // namespace inet

#endif // ifndef __INET_PACKETQUEUE_H

