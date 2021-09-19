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

#include "inet/common/Simsignals.h"
#include "inet/queueing/queue/CompoundPacketQueue.h"

namespace inet {
namespace queueing {

Define_Module(CompoundPacketQueue);

void CompoundPacketQueue::initialize(int stage)
{
    PacketQueueBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        packetCapacity = par("packetCapacity");
        dataCapacity = b(par("dataCapacity"));
        inputGate = gate("in");
        outputGate = gate("out");
        consumer = check_and_cast<IPassivePacketSink *>(inputGate->getPathEndGate()->getOwnerModule());
        provider = check_and_cast<IPassivePacketSource *>(outputGate->getPathStartGate()->getOwnerModule());
        collection = check_and_cast<IPacketCollection *>(provider);
        customQueueLengthSignal = registerSignal("customQueueLength");
        customQueueLengthSignalPacketBytes = registerSignal("customQueueLengthPacketBytes");
    }
    else if (stage == INITSTAGE_QUEUEING) {
        checkPushPacketSupport(inputGate);
        checkPopPacketSupport(outputGate);
    }
    else if (stage == INITSTAGE_LAST)
        updateDisplayString();
}

int CompoundPacketQueue::getMaxNumPackets() {
    if (packetCapacity == -1 && dataCapacity == b(-1)) {
        return collection->getMaxNumPackets();
    }
    return packetCapacity;
}

int CompoundPacketQueue::getNumPackets()
{
    return collection->getNumPackets();
}

b CompoundPacketQueue::getMaxTotalLength() {
    if (packetCapacity == -1 && dataCapacity == b(-1)) {
        return collection->getMaxTotalLength();
    }
    return dataCapacity;
}

b CompoundPacketQueue::getTotalLength()
{
    return collection->getTotalLength();
}

Packet *CompoundPacketQueue::getPacket(int index)
{
    return collection->getPacket(index);
}

void CompoundPacketQueue::pushPacket(Packet *packet, cGate *gate)
{
    Enter_Method("pushPacket");
    emit(packetPushedSignal, packet);
    if ((packetCapacity != -1 && getNumPackets() >= packetCapacity) ||
        (dataCapacity != b(-1) && getTotalLength() + packet->getTotalLength() > dataCapacity))
    {
        EV_INFO << "Dropping packet " << packet->getName() << " because the queue is full." << endl;
        dropPacket(packet, QUEUE_OVERFLOW, packetCapacity);
    }
    else {
        if (packetCapacity != -1)
            cSimpleModule::emit(customQueueLengthSignal, getNumPackets());
        else
            cSimpleModule::emit(customQueueLengthSignalPacketBytes, getTotalLength().get());
        pushOrSendPacket(packet, inputGate, consumer);
        updateDisplayString();
    }
}

Packet *CompoundPacketQueue::popPacket(cGate *gate)
{
    Enter_Method("popPacket");
    auto packet = provider->popPacket(outputGate->getPathStartGate());
    animateSend(packet, outputGate->getPathStartGate());
    emit(packetPoppedSignal, packet);
    updateDisplayString();
    if (packetCapacity != -1)
        cSimpleModule::emit(customQueueLengthSignal, getNumPackets());
    else
        cSimpleModule::emit(customQueueLengthSignalPacketBytes, getTotalLength().get());
    return packet;
}

void CompoundPacketQueue::removePacket(Packet *packet)
{
    Enter_Method("removePacket");
    collection->removePacket(packet);
    emit(packetRemovedSignal, packet);
    if (packetCapacity != -1)
        cSimpleModule::emit(customQueueLengthSignal, getNumPackets());
    else
        cSimpleModule::emit(customQueueLengthSignalPacketBytes, getTotalLength().get());
    updateDisplayString();
}

} // namespace queueing
} // namespace inet

