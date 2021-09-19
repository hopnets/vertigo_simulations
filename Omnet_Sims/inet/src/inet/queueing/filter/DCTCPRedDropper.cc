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

#include "inet/common/ModuleAccess.h"
#include "inet/queueing/filter/DCTCPRedDropper.h"
#include "inet/queueing/marker/EcnMarker.h"

namespace inet {
namespace queueing {

Define_Module(DCTCPRedDropper);
simsignal_t DCTCPRedDropper::queueCapSignal = cComponent::registerSignal("queueCap");
void DCTCPRedDropper::initialize(int stage)
{
    PacketFilterBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        useEcn = par("useEcn");
        packetCapacity = par("packetCapacity");
        dataCapacity = b(par("dataCapacity"));
        threshold = par("threshold");
        auto outputGate = gate("out");
        collection = findConnectedModule<IPacketCollection>(outputGate);
        if (collection == nullptr)
            collection = getModuleFromPar<IPacketCollection>(par("collectionModule"), this);
    }
}

DCTCPRedDropper::RedResult DCTCPRedDropper::doRandomEarlyDetection(Packet *packet)
{
    EV << "SOUGOL: The threshold is " << threshold <<endl;
    EV_INFO << "SEPEHR: Queue length: "
                << collection->getNumPackets() << " & packetCapacity: " << packetCapacity <<
                ", Queue data occupancy is " << collection->getTotalLength() <<
                " and dataCapacity is " << dataCapacity << endl;

    int queueLength = collection->getNumPackets();
    //    emit(queueCapSignal, queue_length);

    bool is_queue_full = (packetCapacity != -1 && queueLength >= packetCapacity) ||
                (dataCapacity != b(-1) && (collection->getTotalLength() + b(packet->getBitLength())) > dataCapacity);

    if (is_queue_full) {   // maxth is also the "hard" limit
        EV << "SEPEHR: Queue is full. No space for packet " << packet->str() << endl;
        count = 0;
        PacketDropDetails details;
        details.setReason(QUEUE_OVERFLOW);
        details.setLimit(packetCapacity);
        emit(packetDroppedSignal, packet, &details);
        return QUEUE_FULL;
    }
    else if (queueLength >= threshold) {
        EV << "The threshold in the switch is hit, so ECN is marked for the this packet." << endl;
        return ABOVE_THRESHOLD;
    }
    return BELOW_THRESHOLD;
}

bool DCTCPRedDropper::matchesPacket(Packet *packet)
{
//    throw cRuntimeError("Gotchaa1!!!!");
    auto redResult = doRandomEarlyDetection(packet);
        switch (redResult) {
            case ABOVE_THRESHOLD: {
                std::string protocol = packet->getName();
                if (!useEcn){
                    EV << "SOUGOL: This packet is not going to be marked since useEcn is false! " << endl;
                    return false;
                }
                else {
//                    IpEcnCode ecn = EcnMarker::getEcn(packet);
//                    EV << "SOUGOL: This is ecn in here: " << ecn << endl;
//                    if (ecn == IP_ECN_NOT_ECT){
//                        EV << "SOUGOL: This is packet type: " << protocol << endl;
//                        if (protocol.find("arp") != std::string::npos)
//                            return true;
//                        return false;
//                    }
//                    else {
                    if (protocol.find("tcp") != std::string::npos){
                        EcnMarker::setEcn(packet, IP_ECN_CE);
//                        markNext = true;
                        EV << "SOUGOL: The ECN is marked for this packet!" << endl;
                        return true;
                    }
                    return true;
//                    }
                }
            }
            case BELOW_THRESHOLD:
                return true;
            case QUEUE_FULL:
                return false;
            default:
                throw cRuntimeError("Unknown XXX");
        }
}

void DCTCPRedDropper::pushOrSendPacket(Packet *packet, cGate *gate, IPassivePacketSink *consumer)
{
    PacketFilterBase::pushOrSendPacket(packet, gate, consumer);
    // TD: Set the time stamp q_time when the queue gets empty.
    const int queueLength = collection->getNumPackets();
    if (queueLength == 0)
        q_time = simTime();
}

} // namespace queueing
} // namespace inet
