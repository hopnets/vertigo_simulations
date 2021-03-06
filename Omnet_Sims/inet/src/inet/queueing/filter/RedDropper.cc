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
#include "inet/queueing/filter/RedDropper.h"
#include "inet/queueing/marker/EcnMarker.h"

namespace inet {
namespace queueing {

Define_Module(RedDropper);

void RedDropper::initialize(int stage)
{
    PacketFilterBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        wq = par("wq");
        if (wq < 0.0 || wq > 1.0)
            throw cRuntimeError("Invalid value for wq parameter: %g", wq);
        minth = par("minth");
        maxth = par("maxth");
        maxp = par("maxp");
        pkrate = par("pkrate");
        count = -1;
        if (minth < 0.0)
            throw cRuntimeError("minth parameter must not be negative");
        if (maxth < 0.0)
            throw cRuntimeError("maxth parameter must not be negative");
        if (minth >= maxth)
            throw cRuntimeError("minth must be smaller than maxth");
        if (maxp < 0.0 || maxp > 1.0)
            throw cRuntimeError("Invalid value for maxp parameter: %g", maxp);
        if (pkrate < 0.0)
            throw cRuntimeError("Invalid value for pkrate parameter: %g", pkrate);
        useEcn = par("useEcn");
        packetCapacity = par("packetCapacity");
        dataCapacity = b(par("dataCapacity"));
        auto outputGate = gate("out");
        collection = findConnectedModule<IPacketCollection>(outputGate);
        if (collection == nullptr)
            collection = getModuleFromPar<IPacketCollection>(par("collectionModule"), this);
    }
}

void RedDropper::emit_packet_drop_signal(Packet *packet) {
    PacketDropDetails details;
    details.setReason(QUEUE_OVERFLOW);
    details.setLimit(packetCapacity);
    emit(packetDroppedSignal, packet, &details);
}

RedDropper::RedResult RedDropper::doRandomEarlyDetection(Packet *packet)
{
//    std::string protocol = packet->getName();
//    if (protocol.find("tcp") != std::string::npos) {
//        return RANDOMLY_ABOVE_LIMIT;
//    }
    EV << "RedDropper::doRandomEarlyDetection talking!" << endl;
    int queueLength = collection->getNumPackets();
    bool is_queue_full = (packetCapacity != -1 && queueLength >= packetCapacity) ||
                    (dataCapacity != b(-1) && (collection->getTotalLength() + b(packet->getBitLength())) > dataCapacity);

    if (queueLength > 0) {
        // TD: This following calculation is only useful when the queue is not empty!
        avg = (1 - wq) * avg + wq * queueLength;
    }
    else {
        // TD: Added behaviour for empty queue.
        const double m = SIMTIME_DBL(simTime() - q_time) * pkrate;
        avg = pow(1 - wq, m) * avg;
    }

    EV << "avg is: " << avg << endl;

//    std::string protocol = getFullPath();
//    if (protocol.find("agg[0].eth[34]") != std::string::npos) {
//        std::cout << queueLength << ", " << (collection->getTotalLength() + b(packet->getBitLength())) << endl;
//        std::cout << packetCapacity << endl;
//        std::cout << dataCapacity << endl;
//    }

    if (is_queue_full) {   // maxth is also the "hard" limit
        EV << "SEPEHR: Queue is full. No space for packet " << packet->str() << endl;
        count = 0;
        return QUEUE_FULL;
    }
    else if (minth <= avg && avg < maxth) {
        count++;
        const double pb = maxp * (avg - minth) / (maxth - minth);
        const double pa = pb / (1 - count * pb); // TD: Adapted to work as in [Floyd93].
        double dice = dblrand();
        EV << "Deciding randomly to mark the packet with pa = " << pa << " and dice = " << dice << endl;
        if (dice < pa) {
            EV << "Random early packet (avg queue len=" << avg << ", pa=" << pa << ")\n";
            count = 0;
            EV << "returning RANDOMLY_ABOVE_LIMIT" << endl;
            return RANDOMLY_ABOVE_LIMIT;
        }
        else {
            EV << "returning RANDOMLY_BELOW_LIMIT" << endl;
            return RANDOMLY_BELOW_LIMIT;
        }
    }
    else if (avg >= maxth) {
        EV << "Avg queue len " << avg << " >= maxth.\n";
        EV << "returning ABOVE_MAX_LIMIT" << endl;
        count = 0;
        return ABOVE_MAX_LIMIT;
    }
    else {
        count = -1;
    }

    EV << "returning BELOW_MIN_LIMIT" << endl;
    return BELOW_MIN_LIMIT;
}

bool RedDropper::matchesPacket(Packet *packet)
{
    auto redResult = doRandomEarlyDetection(packet);
    switch (redResult) {
        case RANDOMLY_ABOVE_LIMIT:
        case ABOVE_MAX_LIMIT: {
            if (!useEcn) {
                EV << "useECN not set." << endl;
                emit_packet_drop_signal(packet);
                return false;
            }
            else {
                EV << "useECN set." << endl;
                IpEcnCode ecn = EcnMarker::getEcn(packet);
                if (ecn == IP_ECN_NOT_ECT) {
                    EV << "ecn == IP_ECN_NOT_ECT." << endl;
                    emit_packet_drop_signal(packet);
                    return false;
                }
                else {
                    // if next packet should be marked and it is not
                    if (markNext && ecn != IP_ECN_CE) {
                        EV << "markNext && ecn != IP_ECN_CE." << endl;
                        EcnMarker::setEcn(packet, IP_ECN_CE);
                        markNext = false;
                    }
                    else {
                        if (ecn == IP_ECN_CE) {
                            EV << "ecn == IP_ECN_CE" << endl;
                            markNext = true;
                        }
                        else {
                            EV << "ecn != IP_ECN_CE" << endl;
                            EcnMarker::setEcn(packet, IP_ECN_CE);
                        }
                    }
                    return true;
                }
            }
        }
        case RANDOMLY_BELOW_LIMIT:
        case BELOW_MIN_LIMIT:
            return true;
        case QUEUE_FULL:
            EV << "queue full!" << endl;
            emit_packet_drop_signal(packet);
            return false;
        default:
            throw cRuntimeError("Unknown XXX");
    }
}

void RedDropper::pushOrSendPacket(Packet *packet, cGate *gate, IPassivePacketSink *consumer)
{
    PacketFilterBase::pushOrSendPacket(packet, gate, consumer);
    // TD: Set the time stamp q_time when the queue gets empty.
    const int queueLength = collection->getNumPackets();
    if (queueLength == 0)
        q_time = simTime();
}

} // namespace queueing
} // namespace inet

