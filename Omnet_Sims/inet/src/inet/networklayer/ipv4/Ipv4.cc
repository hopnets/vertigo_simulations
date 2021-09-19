//
// Copyright (C) 2004 Andras Varga
// Copyright (C) 2014 OpenSim Ltd.
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
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include <stdlib.h>
#include <string.h>

#include "inet/applications/common/SocketTag_m.h"
#include "inet/common/INETUtils.h"
#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/LayeredProtocolBase.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/checksum/TcpIpChecksum.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/lifecycle/NodeStatus.h"
#include "inet/common/packet/Message.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/networklayer/arp/ipv4/ArpPacket_m.h"
#include "inet/networklayer/common/DscpTag_m.h"
#include "inet/networklayer/common/EcnTag_m.h"
#include "inet/networklayer/common/FragmentationTag_m.h"
#include "inet/networklayer/common/HopLimitTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/L3Tools.h"
#include "inet/networklayer/common/MulticastTag_m.h"
#include "inet/networklayer/common/NextHopAddressTag_m.h"
#include "inet/networklayer/contract/IArp.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/contract/ipv4/Ipv4SocketCommand_m.h"
#include "inet/networklayer/ipv4/IIpv4RoutingTable.h"
#include "inet/networklayer/ipv4/IcmpHeader_m.h"
#include "inet/networklayer/ipv4/Ipv4.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/networklayer/ipv4/Ipv4OptionsTag_m.h"
#include "inet/transportlayer/tcp_common/TcpHeader_m.h"
#include "inet/linklayer/ethernet/EtherPhyFrame_m.h"

namespace inet {

Define_Module(Ipv4);

#define MSGKIND_PUSH_UP    0

// v2 marking component
#define MARKING_LAS 0
#define MARKING_SRPT 1
#define MAX_FLOW_LET_ID 16

//v2 ordering component
simsignal_t Ipv4::v2PacketQueueingTimeSignal = registerSignal("v2PacketQueueingTime");

//TODO TRANSLATE
// a multicast cimek eseten hianyoznak bizonyos NetFilter hook-ok
// a local interface-k hasznalata eseten szinten hianyozhatnak bizonyos NetFilter hook-ok

int test_seq = 1;
int test_counter = 0;

Ipv4::Ipv4()
{
}

Ipv4::~Ipv4()
{
    for (auto it : socketIdToSocketDescriptor)
        delete it.second;
    flush();

    recordScalar("IPPacketSentCounter", ip_packet_sent_counter);
    recordScalar("IPDataPacketSentCounter", ip_data_packet_sent_counter);

    if (should_use_v2_marking) {
        // flush v2 marking tables
        // remove from flow and packet tables also clear the packet lru tarcker
        EV << "The remained length of flow_hash_table: " << flow_hash_table.size() << endl;
        recordScalar("numTimeoutsMarking", num_timeouts_marking);
        for (std::unordered_map<unsigned long, LRUFlowInfo*>::iterator flow_it = flow_hash_table.begin();
                flow_it != flow_hash_table.end(); flow_it++) {
            for (std::unordered_map<unsigned long, LRUPacketInfo*>::iterator it =
                    flow_it->second->packet_hash_table.begin();
                    it != flow_it->second->packet_hash_table.end(); it++) {
                delete it->second;
            }
            flow_it->second->packet_hash_table.clear();
            delete flow_it->second;
        }
        flow_hash_table.clear();
        flow_lru_tracker.clear();
    }

    if (has_ordering_layer) {
        // emit the counter signals
        recordScalar("numTimeoutsOrdering", num_timeouts_ordering);
        recordScalar("v2RcvdSoonerStored", received_sooner_stored_counter);
        recordScalar("v2RcvdCorrectlyPushed", received_correctly_pushed_counter);
        recordScalar("v2RcvdLaterPushed", received_later_pushed_counter);

        // flush v2 ordering tables
        EV << "The remained length of ordering_component_flow_hash_table: "
                << ordering_component_flow_hash_table.size() << endl;
        for (std::unordered_map<unsigned long, OrderingComponentFlowInfo*>::iterator flow_it =
                ordering_component_flow_hash_table.begin();
                flow_it != ordering_component_flow_hash_table.end(); flow_it++) {
            if (flow_it->second->timeoutMsg != nullptr) {
                cancelEvent(flow_it->second->timeoutMsg);
            }
            delete flow_it->second->timeoutMsg;
            flow_it->second->timeoutMsg = nullptr;
            // delete the packet objects stored in hash table
            for (std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it =
                    flow_it->second->stored_packet_hash_table.begin();
                    it != flow_it->second->stored_packet_hash_table.end(); it++) {
                delete it->second->packet;
                delete it->second;
            }
            for (std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it =
                    flow_it->second->descending_stored_packet_hash_table.begin();
                    it != flow_it->second->descending_stored_packet_hash_table.end(); it++) {
                delete it->second->packet;
                delete it->second;
            }
            flow_it->second->sent_packet_seqs.clear();
            flow_it->second->sent_packet_seqs_payload_length.clear();
            flow_it->second->stored_packet_hash_table.clear();
            flow_it->second->descending_stored_packet_hash_table.clear();
            delete flow_it->second;
        }
        ordering_component_flow_hash_table.clear();
        ordering_component_flow_lru_tracker.clear();
    }
}

void Ipv4::initialize(int stage)
{
    OperationalBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        rt = getModuleFromPar<IIpv4RoutingTable>(par("routingTableModule"), this);
        arp = getModuleFromPar<IArp>(par("arpModule"), this);
        icmp = getModuleFromPar<Icmp>(par("icmpModule"), this);

        transportInGateBaseId = gateBaseId("transportIn");

        const char *crcModeString = par("crcMode");
        crcMode = parseCrcMode(crcModeString, false);

        defaultTimeToLive = par("timeToLive");
        defaultMCTimeToLive = par("multicastTimeToLive");
        fragmentTimeoutTime = par("fragmentTimeout");
        limitedBroadcast = par("limitedBroadcast");
        directBroadcastInterfaces = par("directBroadcastInterfaces").stdstringValue();

        directBroadcastInterfaceMatcher.setPattern(directBroadcastInterfaces.c_str(), false, true, false);

        curFragmentId = 0;
        lastCheckTime = 0;

        numMulticast = numLocalDeliver = numDropped = numUnroutable = numForwarded = 0;

        // NetFilter:
        hooks.clear();
        queuedDatagramsForHooks.clear();

        pendingPackets.clear();
        cModule *arpModule = check_and_cast<cModule *>(arp);
        arpModule->subscribe(IArp::arpResolutionCompletedSignal, this);
        arpModule->subscribe(IArp::arpResolutionFailedSignal, this);

        registerService(Protocol::ipv4, gate("transportIn"), gate("queueIn"));
        registerProtocol(Protocol::ipv4, gate("queueOut"), gate("transportOut"));

        WATCH(numMulticast);
        WATCH(numLocalDeliver);
        WATCH(numDropped);
        WATCH(numUnroutable);
        WATCH(numForwarded);
        WATCH_MAP(pendingPackets);
        WATCH_MAP(socketIdToSocketDescriptor);

        // Valinor marking component
        should_use_v2_marking = par("should_use_v2_marking");
        delta = par("delta");
        flow_hash_table_size = par("flow_hash_table_size");
        if (should_use_v2_marking) {
            std::string marking_type_str = par("marking_type");
            if (marking_type_str.compare("LAS") == 0)
                marking_type = MARKING_LAS;
            else if (marking_type_str.compare("SRPT") == 0)
                marking_type = MARKING_SRPT;
            else
                throw cRuntimeError("No marking type identified!");
        }

        // Valinor ordering component
        has_ordering_layer = par("has_ordering_layer");
        omega = par("omega");

        if (has_ordering_layer && !should_use_v2_marking)
            throw cRuntimeError("how can we have the ordering layer without marking component.");

    }
}

void Ipv4::handleRegisterService(const Protocol& protocol, cGate *out, ServicePrimitive servicePrimitive)
{
    Enter_Method("handleRegisterService");
}

void Ipv4::handleRegisterProtocol(const Protocol& protocol, cGate *in, ServicePrimitive servicePrimitive)
{
    Enter_Method("handleRegisterProtocol");
    if (in->isName("transportIn"))
            upperProtocols.insert(&protocol);
}

void Ipv4::refreshDisplay() const
{
    OperationalBase::refreshDisplay();

    char buf[80] = "";
    if (numForwarded > 0)
        sprintf(buf + strlen(buf), "fwd:%d ", numForwarded);
    if (numLocalDeliver > 0)
        sprintf(buf + strlen(buf), "up:%d ", numLocalDeliver);
    if (numMulticast > 0)
        sprintf(buf + strlen(buf), "mcast:%d ", numMulticast);
    if (numDropped > 0)
        sprintf(buf + strlen(buf), "DROP:%d ", numDropped);
    if (numUnroutable > 0)
        sprintf(buf + strlen(buf), "UNROUTABLE:%d ", numUnroutable);
    getDisplayString().setTagArg("t", 0, buf);
}

void Ipv4::handleRequest(Request *request)
{
    auto ctrl = request->getControlInfo();
    if (ctrl == nullptr)
        throw cRuntimeError("Request '%s' arrived without controlinfo", request->getName());
    else if (Ipv4SocketBindCommand *command = dynamic_cast<Ipv4SocketBindCommand *>(ctrl)) {
        int socketId = request->getTag<SocketReq>()->getSocketId();
        SocketDescriptor *descriptor = new SocketDescriptor(socketId, command->getProtocol()->getId(), command->getLocalAddress());
        socketIdToSocketDescriptor[socketId] = descriptor;
        delete request;
    }
    else if (Ipv4SocketConnectCommand *command = dynamic_cast<Ipv4SocketConnectCommand *>(ctrl)) {
        int socketId = request->getTag<SocketReq>()->getSocketId();
        if (socketIdToSocketDescriptor.find(socketId) == socketIdToSocketDescriptor.end())
            throw cRuntimeError("Ipv4Socket: should use bind() before connect()");
        socketIdToSocketDescriptor[socketId]->remoteAddress = command->getRemoteAddress();
        delete request;
    }
    else if (dynamic_cast<Ipv4SocketCloseCommand *>(ctrl) != nullptr) {
        int socketId = request->getTag<SocketReq>()->getSocketId();
        auto it = socketIdToSocketDescriptor.find(socketId);
        if (it != socketIdToSocketDescriptor.end()) {
            delete it->second;
            socketIdToSocketDescriptor.erase(it);
            auto indication = new Indication("closed", IPv4_I_SOCKET_CLOSED);
            auto ctrl = new Ipv4SocketClosedIndication();
            indication->setControlInfo(ctrl);
            indication->addTag<SocketInd>()->setSocketId(socketId);
            send(indication, "transportOut");
        }
        delete request;
    }
    else if (dynamic_cast<Ipv4SocketDestroyCommand *>(ctrl) != nullptr) {
        int socketId = request->getTag<SocketReq>()->getSocketId();
        auto it = socketIdToSocketDescriptor.find(socketId);
        if (it != socketIdToSocketDescriptor.end()) {
            delete it->second;
            socketIdToSocketDescriptor.erase(it);
        }
        delete request;
    }
    else
        throw cRuntimeError("Unknown command: '%s' with %s", request->getName(), ctrl->getClassName());
}

void Ipv4::handleMessageWhenUp(cMessage *msg)
{
    if (msg->arrivedOn("transportIn")) {    //TODO packet->getArrivalGate()->getBaseId() == transportInGateBaseId
        if (auto request = dynamic_cast<Request *>(msg))
            handleRequest(request);
        else
            handlePacketFromHL(check_and_cast<Packet*>(msg));
    }
    else if (msg->arrivedOn("queueIn")) {    // from network
        EV_INFO << "Received " << msg->str() << " from network.\n";
        auto packet = check_and_cast<Packet*>(msg);

        //swift
//        std::cout << "test: " << packet->str() << endl;
        b position = packet->getFrontOffset();
        packet->setFrontOffset(b(0));
        auto phy_header = packet->removeAtFront<EthernetPhyHeader>();
        auto eth_header = packet->removeAtFront<EthernetMacHeader>();
        simtime_t local_nic_rx_delay = simTime() - eth_header->getTime_packet_received_at_nic();
        EV << "SWIFT: Time packet received at nic is " << eth_header->getTime_packet_received_at_nic() <<
                " so setting the local_nic_rx_delay to " << local_nic_rx_delay << endl;
        eth_header->setLocal_nic_rx_delay(local_nic_rx_delay);
        packet->insertAtFront(eth_header);
        packet->insertAtFront(phy_header);
        packet->setFrontIteratorPosition(position);

        handleIncomingDatagram(packet);
    } else if (msg->isSelfMessage()) {
        if (msg->getKind() == MSGKIND_PUSH_UP) {
            unsigned long flow_hash = (unsigned long) msg->par("flow_hash").longValue();
            unsigned long packet_seq = (unsigned long) msg->par("packet_seq").longValue();
            EV << "V2 timeout happened with flow hash: " << flow_hash <<
                    " and packet_seq: " << packet_seq << endl;
            handle_timeout_v2(flow_hash, packet_seq);
            // no need to delete the message, we delete it in our class
        }
    }
    else
        throw cRuntimeError("message arrived on unknown gate '%s'", msg->getArrivalGate()->getName());
}

bool Ipv4::verifyCrc(const Ptr<const Ipv4Header>& ipv4Header)
{
    switch (ipv4Header->getCrcMode()) {
        case CRC_DECLARED_CORRECT: {
            // if the CRC mode is declared to be correct, then the check passes if and only if the chunk is correct
            return ipv4Header->isCorrect();
        }
        case CRC_DECLARED_INCORRECT:
            // if the CRC mode is declared to be incorrect, then the check fails
            return false;
        case CRC_COMPUTED: {
            if (ipv4Header->isCorrect()) {
                // compute the CRC, the check passes if the result is 0xFFFF (includes the received CRC) and the chunks are correct
                MemoryOutputStream ipv4HeaderStream;
                Chunk::serialize(ipv4HeaderStream, ipv4Header);
                uint16_t computedCrc = TcpIpChecksum::checksum(ipv4HeaderStream.getData());
                return computedCrc == 0;
            }
            else {
                return false;
            }
        }
        default:
            throw cRuntimeError("Unknown CRC mode");
    }
}

const InterfaceEntry *Ipv4::getSourceInterface(Packet *packet)
{
    auto tag = packet->findTag<InterfaceInd>();
    return tag != nullptr ? ift->getInterfaceById(tag->getInterfaceId()) : nullptr;
}

const InterfaceEntry *Ipv4::getDestInterface(Packet *packet)
{
    auto tag = packet->findTag<InterfaceReq>();
    return tag != nullptr ? ift->getInterfaceById(tag->getInterfaceId()) : nullptr;
}

Ipv4Address Ipv4::getNextHop(Packet *packet)
{
    auto tag = packet->findTag<NextHopAddressReq>();
    return tag != nullptr ? tag->getNextHopAddress().toIpv4() : Ipv4Address::UNSPECIFIED_ADDRESS;
}

void Ipv4::handleIncomingDatagram(Packet *packet)
{
    ASSERT(packet);
    int interfaceId = packet->getTag<InterfaceInd>()->getInterfaceId();
    emit(packetReceivedFromLowerSignal, packet);

    //
    // "Prerouting"
    //

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    packet->addTagIfAbsent<NetworkProtocolInd>()->setProtocol(&Protocol::ipv4);
    packet->addTagIfAbsent<NetworkProtocolInd>()->setNetworkProtocolHeader(ipv4Header);

    if (!verifyCrc(ipv4Header)) {
        EV_WARN << "CRC error found, drop packet\n";
        PacketDropDetails details;
        details.setReason(INCORRECTLY_RECEIVED);
        emit(packetDroppedSignal, packet, &details);
        delete packet;
        return;
    }

    if (ipv4Header->getTotalLengthField() > packet->getDataLength()) {
        EV_WARN << "length error found, sending ICMP_PARAMETER_PROBLEM\n";
        sendIcmpError(packet, interfaceId, ICMP_PARAMETER_PROBLEM, 0);
        return;
    }

    // remove lower layer paddings:
    if (ipv4Header->getTotalLengthField() < packet->getDataLength()) {
        packet->setBackOffset(packet->getFrontOffset() + ipv4Header->getTotalLengthField());
    }

    // check for header biterror
    if (packet->hasBitError()) {
        // probability of bit error in header = size of header / size of total message
        // (ignore bit error if in payload)
        double relativeHeaderLength = B(ipv4Header->getHeaderLength()).get() / (double)B(ipv4Header->getChunkLength()).get();
        if (dblrand() <= relativeHeaderLength) {
            EV_WARN << "bit error found, sending ICMP_PARAMETER_PROBLEM\n";
            sendIcmpError(packet, interfaceId, ICMP_PARAMETER_PROBLEM, 0);
            return;
        }
    }

    EV_DETAIL << "Received datagram `" << ipv4Header->getName() << "' with dest=" << ipv4Header->getDestAddress() << "\n";

    if (datagramPreRoutingHook(packet) == INetfilter::IHook::ACCEPT)
        preroutingFinish(packet);
}

Packet *Ipv4::prepareForForwarding(Packet *packet) const
{
    const auto& ipv4Header = removeNetworkProtocolHeader<Ipv4Header>(packet);
    ipv4Header->setTimeToLive(ipv4Header->getTimeToLive() - 1);
    insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header);
    return packet;
}

void Ipv4::preroutingFinish(Packet *packet)
{
    const InterfaceEntry *fromIE = ift->getInterfaceById(packet->getTag<InterfaceInd>()->getInterfaceId());
    Ipv4Address nextHopAddr = getNextHop(packet);

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    ASSERT(ipv4Header);
    Ipv4Address destAddr = ipv4Header->getDestAddress();

    // route packet

    if (fromIE->isLoopback()) {
        reassembleAndDeliver(packet);
    }
    else if (destAddr.isMulticast()) {
        // check for local delivery
        // Note: multicast routers will receive IGMP datagrams even if their interface is not joined to the group
        if (fromIE->getProtocolData<Ipv4InterfaceData>()->isMemberOfMulticastGroup(destAddr) ||
            (rt->isMulticastForwardingEnabled() && ipv4Header->getProtocolId() == IP_PROT_IGMP))
            reassembleAndDeliver(packet->dup());
        else
            EV_WARN << "Skip local delivery of multicast datagram (input interface not in multicast group)\n";

        // don't forward if IP forwarding is off, or if dest address is link-scope
        if (!rt->isMulticastForwardingEnabled()) {
            EV_WARN << "Skip forwarding of multicast datagram (forwarding disabled)\n";
            delete packet;
        }
        else if (destAddr.isLinkLocalMulticast()) {
            EV_WARN << "Skip forwarding of multicast datagram (packet is link-local)\n";
            delete packet;
        }
        else if (ipv4Header->getTimeToLive() <= 1) {      // TTL before decrement
            EV_WARN << "Skip forwarding of multicast datagram (TTL reached 0)\n";
            delete packet;
        }
        else
            forwardMulticastPacket(prepareForForwarding(packet));
    }
    else {
        const InterfaceEntry *broadcastIE = nullptr;

        // check for local delivery; we must accept also packets coming from the interfaces that
        // do not yet have an IP address assigned. This happens during DHCP requests.
        if (rt->isLocalAddress(destAddr) || fromIE->getProtocolData<Ipv4InterfaceData>()->getIPAddress().isUnspecified()) {
            reassembleAndDeliver(packet);
        }
        else if (destAddr.isLimitedBroadcastAddress() || (broadcastIE = rt->findInterfaceByLocalBroadcastAddress(destAddr))) {
            // broadcast datagram on the target subnet if we are a router
            if (broadcastIE && fromIE != broadcastIE && rt->isForwardingEnabled()) {
                if (directBroadcastInterfaceMatcher.matches(broadcastIE->getInterfaceName()) ||
                    directBroadcastInterfaceMatcher.matches(broadcastIE->getInterfaceFullPath().c_str()))
                {
                    auto packetCopy = prepareForForwarding(packet->dup());
                    packetCopy->addTagIfAbsent<InterfaceReq>()->setInterfaceId(broadcastIE->getInterfaceId());
                    packetCopy->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(Ipv4Address::ALLONES_ADDRESS);
                    fragmentPostRouting(packetCopy);
                }
                else
                    EV_INFO << "Forwarding of direct broadcast packets is disabled on interface " << broadcastIE->getInterfaceName() << std::endl;
            }

            EV_INFO << "Broadcast received\n";
            reassembleAndDeliver(packet);
        }
        else if (!rt->isForwardingEnabled()) {
            EV_WARN << "forwarding off, dropping packet\n";
            numDropped++;
            PacketDropDetails details;
            details.setReason(FORWARDING_DISABLED);
            emit(packetDroppedSignal, packet, &details);
            delete packet;
        }
        else {
            EV << "SEPEHR: forwarding on, packet is: " << packet->str() << endl;
            b packetPosition = packet->getFrontOffset();
            packet->setFrontIteratorPosition(b(0));
            auto phyHeader = packet->removeAtFront<EthernetPhyHeader>();
            auto ethHeader = packet->removeAtFront<EthernetMacHeader>();
            auto ipHeader = packet->removeAtFront<Ipv4Header>();
            auto tcp_header = packet->removeAtFront<tcp::TcpHeader>();
            EV << "SEPEHR: packet's current ttl is: " << ipHeader->getTimeToLive() << endl;
            packet->insertAtFront(tcp_header);
            packet->insertAtFront(ipHeader);
            packet->insertAtFront(ethHeader);
            packet->insertAtFront(phyHeader);
            packet->setFrontIteratorPosition(packetPosition);
            packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(nextHopAddr);
            routeUnicastPacket(prepareForForwarding(packet));
        }
    }
}

void Ipv4::assign_payload_info_to_packet(Packet *main_packet) {
    auto packet = main_packet->dup();
    auto tcpHeader = packet->removeAtFront<tcp::TcpHeader>();
    b payload_length = b(0), total_pyload_length = b(0),
            offset = b(0);
    if (packet->getBitLength() != 0) {
        // packet has payload
        auto chunk = packet->removeAtFront<SliceChunk>();
        auto main_chunk = chunk->getChunk();
        payload_length = chunk->getLength();
        offset = chunk->getOffset();
        total_pyload_length = main_chunk->getChunkLength();
    }
    delete packet;
    auto payload_info_tag = main_packet->addTagIfAbsent<PayloadInfoTag>();;
    payload_info_tag->setPayload_length(payload_length);
    payload_info_tag->setOffset(offset);
    payload_info_tag->setTotal_length(total_pyload_length);
}

void Ipv4::handlePacketFromHL(Packet *packet)
{
    EV_INFO << "Received " << packet << " from upper layer.\n";
    emit(packetReceivedFromUpperSignal, packet);
    auto is_bursty_tag = packet->removeTagIfPresent<IsBurstyTag>();
    bool is_bursty = false;
    if (is_bursty_tag != nullptr) {
        is_bursty = is_bursty_tag->getIs_bursty();
    }
    delete is_bursty_tag;

    // v2 marking component
    assign_payload_info_to_packet(packet);

    // if no interface exists, do not send datagram
    if (ift->getNumInterfaces() == 0) {
        EV_ERROR << "No interfaces exist, dropping packet\n";
        numDropped++;
        PacketDropDetails details;
        details.setReason(NO_INTERFACE_FOUND);
        emit(packetDroppedSignal, packet, &details);
        delete packet;
        return;
    }

    // encapsulate
    encapsulate(packet);
    packet->addTagIfAbsent<IsBurstyTag>()->setIs_bursty(is_bursty);

    // TODO:
    L3Address nextHopAddr(Ipv4Address::UNSPECIFIED_ADDRESS);
    if (datagramLocalOutHook(packet) == INetfilter::IHook::ACCEPT)
        datagramLocalOut(packet);
}

void Ipv4::datagramLocalOut(Packet *packet)
{
    const InterfaceEntry *destIE = getDestInterface(packet);
    Ipv4Address requestedNextHopAddress = getNextHop(packet);

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    bool multicastLoop = false;
    MulticastReq *mcr = packet->findTag<MulticastReq>();
    if (mcr != nullptr) {
        multicastLoop = mcr->getMulticastLoop();
    }

    // send
    Ipv4Address destAddr = ipv4Header->getDestAddress();

    EV_DETAIL << "Sending datagram '" << packet->getName() << "' with destination = " << destAddr << "\n";

    if (ipv4Header->getDestAddress().isMulticast()) {
        destIE = determineOutgoingInterfaceForMulticastDatagram(ipv4Header, destIE);
        packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE ? destIE->getInterfaceId() : -1);

        // loop back a copy
        if (multicastLoop && (!destIE || !destIE->isLoopback())) {
            const InterfaceEntry *loopbackIF = ift->findFirstLoopbackInterface();
            if (loopbackIF) {
                auto packetCopy = packet->dup();
                packetCopy->addTagIfAbsent<InterfaceReq>()->setInterfaceId(loopbackIF->getInterfaceId());
                packetCopy->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(destAddr);
                fragmentPostRouting(packetCopy);
            }
        }

        if (destIE) {
            numMulticast++;
            packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE->getInterfaceId());        //FIXME KLUDGE is it needed?
            packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(destAddr);
            fragmentPostRouting(packet);
        }
        else {
            EV_ERROR << "No multicast interface, packet dropped\n";
            numUnroutable++;
            PacketDropDetails details;
            details.setReason(NO_INTERFACE_FOUND);
            emit(packetDroppedSignal, packet, &details);
            delete packet;
        }
    }
    else {    // unicast and broadcast
              // check for local delivery
        if (rt->isLocalAddress(destAddr)) {
            EV_INFO << "Delivering " << packet << " locally.\n";
            if (destIE && !destIE->isLoopback()) {
                EV_DETAIL << "datagram destination address is local, ignoring destination interface specified in the control info\n";
                destIE = nullptr;
                packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(-1);
            }
            if (!destIE) {
                destIE = ift->findFirstLoopbackInterface();
                packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE ? destIE->getInterfaceId() : -1);
            }
            ASSERT(destIE);
            packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(destAddr);
            routeUnicastPacket(packet);
        }
        else if (destAddr.isLimitedBroadcastAddress() || rt->isLocalBroadcastAddress(destAddr))
            routeLocalBroadcastPacket(packet);
        else {
            packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(requestedNextHopAddress);
            routeUnicastPacket(packet);
        }
    }
}

/* Choose the outgoing interface for the muticast datagram:
 *   1. use the interface specified by MULTICAST_IF socket option (received in the control info)
 *   2. lookup the destination address in the routing table
 *   3. if no route, choose the interface according to the source address
 *   4. or if the source address is unspecified, choose the first MULTICAST interface
 */
const InterfaceEntry *Ipv4::determineOutgoingInterfaceForMulticastDatagram(const Ptr<const Ipv4Header>& ipv4Header, const InterfaceEntry *multicastIFOption)
{
    const InterfaceEntry *ie = nullptr;
    if (multicastIFOption) {
        ie = multicastIFOption;
        EV_DETAIL << "multicast packet routed by socket option via output interface " << ie->getInterfaceName() << "\n";
    }
    if (!ie) {
        Ipv4Route *route = rt->findBestMatchingRoute(ipv4Header->getDestAddress());
        if (route)
            ie = route->getInterface();
        if (ie)
            EV_DETAIL << "multicast packet routed by routing table via output interface " << ie->getInterfaceName() << "\n";
    }
    if (!ie) {
        ie = rt->getInterfaceByAddress(ipv4Header->getSrcAddress());
        if (ie)
            EV_DETAIL << "multicast packet routed by source address via output interface " << ie->getInterfaceName() << "\n";
    }
    if (!ie) {
        ie = ift->findFirstMulticastInterface();
        if (ie)
            EV_DETAIL << "multicast packet routed via the first multicast interface " << ie->getInterfaceName() << "\n";
    }
    return ie;
}

void Ipv4::routeUnicastPacket(Packet *packet)
{
    const InterfaceEntry *fromIE = getSourceInterface(packet);
    const InterfaceEntry *destIE = getDestInterface(packet);
    Ipv4Address nextHopAddress = getNextHop(packet);

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    Ipv4Address destAddr = ipv4Header->getDestAddress();
    EV_INFO << "Routing " << packet << " with destination = " << destAddr << ", ";

    // if output port was explicitly requested, use that, otherwise use Ipv4 routing
    if (destIE) {
        EV_DETAIL << "using manually specified output interface " << destIE->getInterfaceName() << "\n";
        // and nextHopAddr remains unspecified
        if (!nextHopAddress.isUnspecified()) {
            // do nothing, next hop address already specified
        }
        // special case ICMP reply
        else if (destIE->isBroadcast()) {
            // if the interface is broadcast we must search the next hop
            const Ipv4Route *re = rt->findBestMatchingRoute(destAddr);
            if (re && re->getInterface() == destIE) {
                packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(re->getGateway());
            }
        }
    }
    else {
        // use Ipv4 routing (lookup in routing table)
        const Ipv4Route *re = rt->findBestMatchingRoute(destAddr);
        if (re) {
            destIE = re->getInterface();
            packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE->getInterfaceId());
            packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(re->getGateway());
        }
    }

    if (!destIE) {    // no route found
        EV_WARN << "unroutable, sending ICMP_DESTINATION_UNREACHABLE, dropping packet\n";
        numUnroutable++;
        PacketDropDetails details;
        details.setReason(NO_ROUTE_FOUND);
        emit(packetDroppedSignal, packet, &details);
        sendIcmpError(packet, fromIE ? fromIE->getInterfaceId() : -1, ICMP_DESTINATION_UNREACHABLE, 0);
    }
    else {    // fragment and send
        if (fromIE != nullptr) {
            if (datagramForwardHook(packet) != INetfilter::IHook::ACCEPT)
                return;
        }

        routeUnicastPacketFinish(packet);
    }
}

void Ipv4::routeUnicastPacketFinish(Packet *packet)
{
    EV_INFO << "output interface = " << getDestInterface(packet)->getInterfaceName() << ", next hop address = " << getNextHop(packet) << "\n";
    numForwarded++;
    fragmentPostRouting(packet);
}

void Ipv4::routeLocalBroadcastPacket(Packet *packet)
{
    auto interfaceReq = packet->findTag<InterfaceReq>();
    const InterfaceEntry *destIE = interfaceReq != nullptr ? ift->getInterfaceById(interfaceReq->getInterfaceId()) : nullptr;
    // The destination address is 255.255.255.255 or local subnet broadcast address.
    // We always use 255.255.255.255 as nextHopAddress, because it is recognized by ARP,
    // and mapped to the broadcast MAC address.
    if (destIE != nullptr) {
        packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE->getInterfaceId());    //FIXME KLUDGE is it needed?
        packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(Ipv4Address::ALLONES_ADDRESS);
        fragmentPostRouting(packet);
    }
    else if (limitedBroadcast) {
        // forward to each interface including loopback
        for (int i = 0; i < ift->getNumInterfaces(); i++) {
            const InterfaceEntry *ie = ift->getInterface(i);
            auto packetCopy = packet->dup();
            packetCopy->addTagIfAbsent<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
            packetCopy->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(Ipv4Address::ALLONES_ADDRESS);
            fragmentPostRouting(packetCopy);
        }
        delete packet;
    }
    else {
        numDropped++;
        PacketDropDetails details;
        details.setReason(NO_INTERFACE_FOUND);
        emit(packetDroppedSignal, packet, &details);
        delete packet;
    }
}

const InterfaceEntry *Ipv4::getShortestPathInterfaceToSource(const Ptr<const Ipv4Header>& ipv4Header) const
{
    return rt->getInterfaceForDestAddr(ipv4Header->getSrcAddress());
}

void Ipv4::forwardMulticastPacket(Packet *packet)
{
    const InterfaceEntry *fromIE = ift->getInterfaceById(packet->getTag<InterfaceInd>()->getInterfaceId());
    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    const Ipv4Address& srcAddr = ipv4Header->getSrcAddress();
    const Ipv4Address& destAddr = ipv4Header->getDestAddress();
    ASSERT(destAddr.isMulticast());
    ASSERT(!destAddr.isLinkLocalMulticast());

    EV_INFO << "Forwarding multicast datagram `" << packet->getName() << "' with dest=" << destAddr << "\n";

    numMulticast++;

    const Ipv4MulticastRoute *route = rt->findBestMatchingMulticastRoute(srcAddr, destAddr);
    if (!route) {
        EV_WARN << "Multicast route does not exist, try to add.\n";
        // TODO: no need to emit fromIE when tags will be used in place of control infos
        emit(ipv4NewMulticastSignal, ipv4Header.get(), const_cast<InterfaceEntry *>(fromIE));

        // read new record
        route = rt->findBestMatchingMulticastRoute(srcAddr, destAddr);

        if (!route) {
            EV_ERROR << "No route, packet dropped.\n";
            numUnroutable++;
            PacketDropDetails details;
            details.setReason(NO_ROUTE_FOUND);
            emit(packetDroppedSignal, packet, &details);
            delete packet;
            return;
        }
    }

    if (route->getInInterface() && fromIE != route->getInInterface()->getInterface()) {
        EV_ERROR << "Did not arrive on input interface, packet dropped.\n";
        // TODO: no need to emit fromIE when tags will be used in place of control infos
        emit(ipv4DataOnNonrpfSignal, ipv4Header.get(), const_cast<InterfaceEntry *>(fromIE));
        numDropped++;
        PacketDropDetails details;
        emit(packetDroppedSignal, packet, &details);
        delete packet;
    }
    // backward compatible: no parent means shortest path interface to source (RPB routing)
    else if (!route->getInInterface() && fromIE != getShortestPathInterfaceToSource(ipv4Header)) {
        EV_ERROR << "Did not arrive on shortest path, packet dropped.\n";
        numDropped++;
        PacketDropDetails details;
        emit(packetDroppedSignal, packet, &details);
        delete packet;
    }
    else {
        // TODO: no need to emit fromIE when tags will be used in place of control infos
        emit(ipv4DataOnRpfSignal, ipv4Header.get(), const_cast<InterfaceEntry *>(fromIE));    // forwarding hook

        numForwarded++;
        // copy original datagram for multiple destinations
        for (unsigned int i = 0; i < route->getNumOutInterfaces(); i++) {
            Ipv4MulticastRoute::OutInterface *outInterface = route->getOutInterface(i);
            const InterfaceEntry *destIE = outInterface->getInterface();
            if (destIE != fromIE && outInterface->isEnabled()) {
                int ttlThreshold = destIE->getProtocolData<Ipv4InterfaceData>()->getMulticastTtlThreshold();
                if (ipv4Header->getTimeToLive() <= ttlThreshold)
                    EV_WARN << "Not forwarding to " << destIE->getInterfaceName() << " (ttl threshold reached)\n";
                else if (outInterface->isLeaf() && !destIE->getProtocolData<Ipv4InterfaceData>()->hasMulticastListener(destAddr))
                    EV_WARN << "Not forwarding to " << destIE->getInterfaceName() << " (no listeners)\n";
                else {
                    EV_DETAIL << "Forwarding to " << destIE->getInterfaceName() << "\n";
                    auto packetCopy = packet->dup();
                    packetCopy->addTagIfAbsent<InterfaceReq>()->setInterfaceId(destIE->getInterfaceId());
                    packetCopy->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(destAddr);
                    fragmentPostRouting(packetCopy);
                }
            }
        }

        // TODO: no need to emit fromIE when tags will be use, d in place of control infos
        emit(ipv4MdataRegisterSignal, packet, const_cast<InterfaceEntry *>(fromIE));    // postRouting hook

        // only copies sent, delete original packet
        delete packet;
    }
}

void Ipv4::reassembleAndDeliver(Packet *packet)
{
    EV_INFO << "Delivering " << packet << " locally.\n";

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    if (ipv4Header->getSrcAddress().isUnspecified())
        EV_WARN << "Received datagram '" << packet->getName() << "' without source address filled in\n";

    // reassemble the packet (if fragmented)
    if (ipv4Header->getFragmentOffset() != 0 || ipv4Header->getMoreFragments()) {
        EV_DETAIL << "Datagram fragment: offset=" << ipv4Header->getFragmentOffset()
                  << ", MORE=" << (ipv4Header->getMoreFragments() ? "true" : "false") << ".\n";

        // erase timed out fragments in fragmentation buffer; check every 10 seconds max
        if (simTime() >= lastCheckTime + 10) {
            lastCheckTime = simTime();
            fragbuf.purgeStaleFragments(icmp, simTime() - fragmentTimeoutTime);
        }

        packet = fragbuf.addFragment(packet, simTime());
        if (!packet) {
            EV_DETAIL << "No complete datagram yet.\n";
            return;
        }
        if (packet->peekAtFront<Ipv4Header>()->getCrcMode() == CRC_COMPUTED) {
            auto ipv4Header = removeNetworkProtocolHeader<Ipv4Header>(packet);
            setComputedCrc(ipv4Header);
            insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header);
        }
        EV_DETAIL << "This fragment completes the datagram.\n";
    }

    if (datagramLocalInHook(packet) == INetfilter::IHook::ACCEPT)
        reassembleAndDeliverFinish(packet);
}

void Ipv4::connection_closed_notif(bool close_immediately,
        std::string source_ip, std::string source_port,
            std::string dest_ip, std::string dest_port) {
    unsigned long hash_of_flow = flow_hash(source_ip + dest_ip + source_port + dest_port);
    unsigned long hash_of_flow_reverse = flow_hash(dest_ip + source_ip +
            dest_port + source_port);
    EV << "Ip notified from connection close." << endl;
    EV << "hash_of_flow: " << hash_of_flow << endl;
    EV << "hash_of_flow_reverse: " << hash_of_flow_reverse << endl;
    if (flow_hash_table_size < 0 && should_use_v2_marking) {
        // to prevent ram overflow, remove the connection information
        auto flow_found = flow_hash_table.find(hash_of_flow);
        if (flow_found != flow_hash_table.end()){
            if (close_immediately) {
                for (std::unordered_map<unsigned long, LRUPacketInfo*>::iterator it =
                        flow_found->second->packet_hash_table.begin();
                        it != flow_found->second->packet_hash_table.end(); it++) {
                    delete it->second;
                }
                flow_found->second->packet_hash_table.clear();
                // check if something is there to be removed
                if (flow_lru_tracker.size() > 0)
                    flow_lru_tracker.erase(flow_found->second->last_updated);
                delete flow_found->second;
                flow_hash_table.erase(flow_found);
            } else {
                flow_found->second->should_close_after_sending = true;
            }
        }
    }

    // in either cases of close, ordering should be removed right away
    if (ordering_component_flow_hash_table_size < 0 && has_ordering_layer) {
        // to prevent ram overflow, remove the connection information
        auto flow_found = ordering_component_flow_hash_table.find(hash_of_flow_reverse);
        if (flow_found != ordering_component_flow_hash_table.end()) {
            if (flow_found->second->timeoutMsg != nullptr) {
                cancelEvent(flow_found->second->timeoutMsg);
            }
            delete flow_found->second->timeoutMsg;
            flow_found->second->timeoutMsg = nullptr;
            // send and packets stored in hash table and delete their object
            for (std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it =
                    flow_found->second->stored_packet_hash_table.begin();
                    it != flow_found->second->stored_packet_hash_table.end(); it++) {
                send(it->second->packet, "transportOut");
                delete it->second;
            }
            for (std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it =
                    flow_found->second->descending_stored_packet_hash_table.begin();
                    it != flow_found->second->descending_stored_packet_hash_table.end(); it++) {
                send(it->second->packet, "transportOut");
                delete it->second;
            }
            flow_found->second->sent_packet_seqs.clear();
            flow_found->second->sent_packet_seqs_payload_length.clear();
            flow_found->second->stored_packet_hash_table.clear();
            flow_found->second->descending_stored_packet_hash_table.clear();
            if (ordering_component_flow_lru_tracker.size() > 0)
                ordering_component_flow_lru_tracker.erase(flow_found->second->last_updated);
            delete flow_found->second;
            ordering_component_flow_hash_table.erase(hash_of_flow_reverse);
        }
    }
}

bool Ipv4::should_check_ordering(std::string packet_name) {
    bool is_arp_related = packet_name.find("arp") != std::string::npos;
    return should_use_v2_marking && has_ordering_layer && (!is_arp_related);
}

bool Ipv4::compare_packets(Packet* first, Packet* second) {
    bool are_similiar = false;
    auto first_dup = first->dup();
    auto second_dup = second->dup();

    first_dup->setFrontIteratorPosition(b(0));
    first_dup->removeAtFront<EthernetPhyHeader>();
    first_dup->removeAtFront<EthernetMacHeader>();
    auto first_ipv4header = first_dup->removeAtFront<Ipv4Header>();
    auto first_tcpheader = first_dup->peekAtFront<tcp::TcpHeader>();
    std::string first_src_ip = first_ipv4header->getSourceAddress().str();
    std::string first_dst_ip = first_ipv4header->getDestinationAddress().str();
    std::string first_src_port = std::to_string(first_tcpheader->getSourcePort());
    std::string first_dst_port = std::to_string(first_tcpheader->getDestinationPort());
    std::string first_tcp_seq_num = std::to_string(first_tcpheader->getSequenceNo());
    std::string first_packet_name = first_dup->getName();
    std::string first_tcp_ack_num = std::to_string(first_tcpheader->getAckNo());
    unsigned long first_hash_of_packet = packet_hash(first_src_ip + first_dst_ip + first_src_port +
            first_dst_port + first_tcp_seq_num + first_tcp_ack_num + first_packet_name);


    second_dup->setFrontIteratorPosition(b(0));
    second_dup->removeAtFront<EthernetPhyHeader>();
    second_dup->removeAtFront<EthernetMacHeader>();
    auto second_ipv4header = second_dup->removeAtFront<Ipv4Header>();
    auto second_tcpheader = second_dup->peekAtFront<tcp::TcpHeader>();
    std::string second_src_ip = second_ipv4header->getSourceAddress().str();
    std::string second_dst_ip = second_ipv4header->getDestinationAddress().str();
    std::string second_src_port = std::to_string(second_tcpheader->getSourcePort());
    std::string second_dst_port = std::to_string(second_tcpheader->getDestinationPort());
    std::string second_tcp_seq_num = std::to_string(second_tcpheader->getSequenceNo());
    std::string second_packet_name = second_dup->getName();
    std::string second_tcp_ack_num = std::to_string(second_tcpheader->getAckNo());
    unsigned long second_hash_of_packet = packet_hash(second_src_ip + second_dst_ip + second_src_port +
            second_dst_port + second_tcp_seq_num + second_tcp_ack_num + second_packet_name);

    delete first_dup;
    delete second_dup;

    are_similiar = first_hash_of_packet == second_hash_of_packet;
    return are_similiar;
}

MarkingInfoHolder Ipv4::extract_marking_info_holder(Packet* packet) {
    MarkingInfoHolder marking_info_holder;
    auto packet_dup = packet->dup();
    packet_dup->setFrontIteratorPosition(b(0));
    packet_dup->removeAtFront<EthernetPhyHeader>();
    packet_dup->removeAtFront<EthernetMacHeader>();
    auto ipHeader = packet_dup->removeAtFront<Ipv4Header>();
    delete packet_dup;
    for (unsigned int i = 0; i < ipHeader->getOptionArraySize(); i++) {
        const TlvOptionBase *option = &ipHeader->getOption(i);
        if (option->getType() == IPOPTION_V2_MARKING) {
            auto opt = check_and_cast<const Ipv4OptionV2Marking*>(option);
            marking_info_holder.seq = opt->getSeq();
            marking_info_holder.ret_count = opt->getRet_num();
            marking_info_holder.flow_let_id = opt->getFlow_let_id();
            marking_info_holder.is_first_packet = opt->getIs_first_packet();
            marking_info_holder.is_control_message = opt->getIs_control_message();
            break;
        }
        // Check if something is returned
        if (i == ipHeader->getOptionArraySize() - 1)
            throw cRuntimeError("Marking cannot be off at this position!");
    }
    if (marking_info_holder.seq < 0)
        throw cRuntimeError("How can seq be less than 0?");
    return marking_info_holder;
}

PayloadInfoHolder Ipv4::extract_payload_info_holder(Packet* packet) {
    PayloadInfoHolder payload_info_holder;
    auto packet_dup = packet->dup();
    packet_dup->setFrontIteratorPosition(b(0));
    packet_dup->removeAtFront<EthernetPhyHeader>();
    auto ethHeader = packet_dup->removeAtFront<EthernetMacHeader>();
    delete packet_dup;
    payload_info_holder.is_bursty = ethHeader->getIs_bursty();
    payload_info_holder.offset = ethHeader->getOffset();
    payload_info_holder.payload_length = ethHeader->getPayload_length();
    payload_info_holder.total_payload_length = ethHeader->getTotal_length();
    return payload_info_holder;
}

bool Ipv4::apply_LAS_ordering(Packet *packet, unsigned long hash_of_flow,
        MarkingInfoHolder marking_info_holder) {
    bool result;
    EV << "LAS: Applying ordering to packet " << packet->str() << endl;
    EV << "Packet received in ordering component." << endl;
    simtime_t now = simTime();

    auto flow_found = ordering_component_flow_hash_table.find(hash_of_flow);
    if (flow_found != ordering_component_flow_hash_table.end()) {
        // Flow found
        EV << "Flow with hash " << hash_of_flow << " found. Expected seq is " << flow_found->second->expected_seq <<
                ", and expected_flow_let_id is " << flow_found->second->expected_flow_let_id << endl;
        // bring the flow to the head of flow_lru_tracker
        // update the flow's last_updated and re-insert it in lru tracker
        if (ordering_component_flow_hash_table_size > 0) {
            ordering_component_flow_lru_tracker.erase(flow_found->second->last_updated);
            ordering_component_flow_lru_tracker.emplace_hint(ordering_component_flow_lru_tracker.end(), now, hash_of_flow);
        }
        flow_found->second->last_updated = now;

        if (marking_info_holder.flow_let_id > flow_found->second->expected_flow_let_id) {
            // packet of the next flowlet is received, push everything up
            // flow_let_id = expected_flow_let_id + 1

            //If anything is left in the queue, push them up.
            if (flow_found->second->stored_packet_hash_table.size() != 0) {
                for (std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it =
                                    flow_found->second->stored_packet_hash_table.begin();
                                    it != flow_found->second->stored_packet_hash_table.end(); it++)
                {
                    //push everything up
                    EV << "Pushing packet with seq=" << it->first << " up." << endl;
                    emit(v2PacketQueueingTimeSignal, now - it->second->actual_arrival_time);
                    send(it->second->packet, "transportOut");
                    delete it->second;
                    numLocalDeliver++;
                }
            }

            flow_found->second->stored_packet_hash_table.clear();
            flow_found->second->sent_packet_seqs.clear();
            if (flow_found->second->timeoutMsg != nullptr) {
                cancelEvent(flow_found->second->timeoutMsg);
                delete flow_found->second->timeoutMsg;
                flow_found->second->timeoutMsg = nullptr;
            }

            flow_found->second->expected_flow_let_id = marking_info_holder.flow_let_id;

            if (marking_info_holder.seq == 0) {
                // new co-flow
                received_correctly_pushed_counter++;
                EV << "Packet with seq=" << marking_info_holder.seq <<
                        " received. So we push everything up and get ready for a new co-flow" << endl;
                // push the current packet up
                emit(v2PacketQueueingTimeSignal, 0);
                result = false;
                flow_found->second->expected_seq = 1;

            } else {
                // just store the packet, packet out of order
                received_sooner_stored_counter++;
                result = true;
                flow_found->second->expected_seq = 0;
                auto packet_info_node = new OrderingComponentPacketInfo(now, packet);
                flow_found->second->stored_packet_hash_table.insert(std::pair<unsigned long,
                        OrderingComponentPacketInfo*>(marking_info_holder.seq, packet_info_node));
                EV << "No running timer, setting the timeout=" << now + omega << endl;
                flow_found->second->timeoutMsg = new cMessage("timer");
                flow_found->second->timeoutMsg->setKind(MSGKIND_PUSH_UP);
                flow_found->second->timeoutMsg->addPar("flow_hash") = hash_of_flow;
                flow_found->second->timeoutMsg->addPar("packet_seq") = marking_info_holder.seq;
                scheduleAt(now + omega, flow_found->second->timeoutMsg);
            }
        } else if(marking_info_holder.flow_let_id < flow_found->second->expected_flow_let_id) {
            // packet of the previous flowlet is received, push it up, flow_let_id = expected_flow_let_id -1 1
            received_later_pushed_counter++;
            emit(v2PacketQueueingTimeSignal, 0);
            result = false;
        } else if (marking_info_holder.flow_let_id == flow_found->second->expected_flow_let_id) {
            // packet of the current flowlet is received
            if (marking_info_holder.seq < flow_found->second->expected_seq) {
                // packet is old, send it up
                received_later_pushed_counter++;
                emit(v2PacketQueueingTimeSignal, 0);
                result = false;
            } else if (marking_info_holder.seq == flow_found->second->expected_seq) {
                // packet is in-place and thus might fill a gap
                received_correctly_pushed_counter++;
                flow_found->second->expected_seq++;
                if (flow_found->second->timeoutMsg == nullptr) {
                    // No timeout initiated, no gap exists
                    EV << "seq == flow_found->second->expected_seq and no timeout. pushing packet up." << endl;
                    emit(v2PacketQueueingTimeSignal, 0);
                    result = false;

                    // keep increasing the expected seq as long as you have already received the required packets before
                    while (flow_found->second->sent_packet_seqs.find(flow_found->second->expected_seq) !=
                            flow_found->second->sent_packet_seqs.end()) {
                        EV << "Packet with seq=" << flow_found->second->expected_seq << " received before. increasing the "
                                "expected seq to " << flow_found->second->expected_seq + 1 << endl;
                        flow_found->second->sent_packet_seqs.erase(flow_found->second->expected_seq);
                        flow_found->second->expected_seq++;
                    }
                } else {
                    // A timeout was running so the packet fills a gap
                    // stop timer
                    EV << "seq == flow_found->second->expected_seq and timeout. packet fills a gap." << endl;
                    cancelEvent(flow_found->second->timeoutMsg);
                    delete flow_found->second->timeoutMsg;
                    flow_found->second->timeoutMsg = nullptr;

                    // send the packet yourself right now and then send the others
                    EV << "pushing packet with seq=" << marking_info_holder.seq << " up." << endl;
                    result = true;
                    emit(v2PacketQueueingTimeSignal, 0); // no queueing time
                    send(packet, "transportOut");
                    numLocalDeliver++;

                    // our map is sorted, so we can start iterating till a point where there is a gap again
                    // As timer is running, we know that no packet has been timed out yet
                    bool expected_is_stored = flow_found->second->stored_packet_hash_table.find(
                            flow_found->second->expected_seq) != flow_found->second->stored_packet_hash_table.end();
                    bool expected_was_received = flow_found->second->sent_packet_seqs.find(
                            flow_found->second->expected_seq) != flow_found->second->sent_packet_seqs.end();
                    while (expected_is_stored || expected_was_received) {
                        if (expected_is_stored) {
                            //todo: remove, this is a test
                            auto packet_found = flow_found->second->stored_packet_hash_table.find(flow_found->second->expected_seq);
                            if (flow_found->second->stored_packet_hash_table.begin()->first !=
                                    flow_found->second->expected_seq &&
                                    packet_found != flow_found->second->stored_packet_hash_table.end())
                                throw cRuntimeError("We passed over a packet and it will always be in the queue.");

                            // check if the packet with the expected seq is stored
                            EV << "Continue pushing. Pushing packet with seq=" << packet_found->first << " up." << endl;
                            emit(v2PacketQueueingTimeSignal, now - packet_found->second->actual_arrival_time);
                            send(packet_found->second->packet, "transportOut");
                            numLocalDeliver++;
                            delete packet_found->second;
                            flow_found->second->stored_packet_hash_table.erase(flow_found->second->expected_seq);
                            if (expected_was_received) {
                                // packet was also received before
                                flow_found->second->sent_packet_seqs.erase(flow_found->second->expected_seq);
                            }
                        } else if (expected_was_received) {
                            // check if the expected seq was sent before
                            EV << "Continue pushing. Packet with seq=" << flow_found->second->expected_seq << " was received before." << endl;
                            flow_found->second->sent_packet_seqs.erase(flow_found->second->expected_seq);
                        }

                        flow_found->second->expected_seq++;
                        expected_is_stored = flow_found->second->stored_packet_hash_table.find(
                                flow_found->second->expected_seq) != flow_found->second->stored_packet_hash_table.end();
                        expected_was_received = flow_found->second->sent_packet_seqs.find(
                                flow_found->second->expected_seq) != flow_found->second->sent_packet_seqs.end();
                    }

                    // see if you should re-initiate the timer
                    if (flow_found->second->stored_packet_hash_table.size() != 0) {
                        auto packet_found = flow_found->second->stored_packet_hash_table.begin();
                        if (now < packet_found->second->arrival_time)
                            throw cRuntimeError("How is a packet received in the future? :)");
                        simtime_t remained_time = now + (omega - (now - packet_found->second->arrival_time));
                        if (remained_time <= 0) {
                            throw cRuntimeError("I didn't expect the remaining time to be <= 0 for any of the packets.");
                        }

                        EV << "Another gap recognized. Setting timeout=" << remained_time << " for packet with seq=" << packet_found->first << " was received before." << endl;
                        flow_found->second->timeoutMsg = new cMessage("timer");
                        flow_found->second->timeoutMsg->setKind(MSGKIND_PUSH_UP);
                        flow_found->second->timeoutMsg->addPar("flow_hash") = flow_found->first;
                        flow_found->second->timeoutMsg->addPar("packet_seq") = packet_found->first;
                        scheduleAt(remained_time, flow_found->second->timeoutMsg);
                    }
                }
            } else {
                // The packet is out of order
                received_sooner_stored_counter++;
                EV << "The received packet is out of order." << endl;
                result = true;
                auto packet_found = flow_found->second->stored_packet_hash_table.find(marking_info_holder.seq);

                if (packet_found != flow_found->second->stored_packet_hash_table.end()) {
                    // The packet is already stored in hash table
                    bool are_packets_similar = compare_packets(packet, packet_found->second->packet);

                    if (!are_packets_similar) {
                        auto first_dup = packet;
                        std::cout << "newly arrived packet: " << first_dup->str() << endl;
                        first_dup->setFrontIteratorPosition(b(0));
                        first_dup->removeAtFront<EthernetPhyHeader>();
                        first_dup->removeAtFront<EthernetMacHeader>();
                        auto first_ipv4header = first_dup->removeAtFront<Ipv4Header>();
                        auto first_tcpheader = first_dup->peekAtFront<tcp::TcpHeader>();
                        std::string first_src_ip = first_ipv4header->getSourceAddress().str();
                        std::string first_dst_ip = first_ipv4header->getDestinationAddress().str();
                        std::string first_src_port = std::to_string(first_tcpheader->getSourcePort());
                        std::string first_dst_port = std::to_string(first_tcpheader->getDestinationPort());
                        std::string first_tcp_seq_num = std::to_string(first_tcpheader->getSequenceNo());
                        std::string first_packet_name = first_dup->getName();
                        std::string first_tcp_ack_num = std::to_string(first_tcpheader->getAckNo());
                        unsigned long first_hash_of_flow = flow_hash(first_src_ip + first_dst_ip + first_src_port +
                                                    first_dst_port);
                        unsigned long first_reverse_hash_of_flow = flow_hash(first_dst_ip + first_src_ip + first_dst_port
                                + first_src_port);
                        unsigned long first_hash_of_packet = packet_hash(first_src_ip + first_dst_ip + first_src_port +
                                first_dst_port + first_tcp_seq_num + first_tcp_ack_num + first_packet_name);
                        unsigned long first_seq = -1;
                        unsigned long first_ret_count = -1;
                        for (unsigned int i = 0; i < first_ipv4header->getOptionArraySize(); i++) {
                            const TlvOptionBase *option = &first_ipv4header->getOption(i);
                            if (option->getType() == IPOPTION_V2_MARKING) {
                                auto opt = check_and_cast<const Ipv4OptionV2Marking*>(option);
                                first_seq = opt->getSeq();
                                first_ret_count = opt->getRet_num();
                                break;
                            }
                        }
                        if (first_seq < 0)
                            throw cRuntimeError("How can seq be less than 0?");

                        std::cout << "time is " << simTime() << endl;

                        std::cout << "first_src_ip: " << first_src_ip << endl <<
                                "first_dst_ip: " << first_dst_ip << endl <<
                                "first_src_port: " << first_src_port << endl <<
                                "first_dst_port: " << first_dst_port << endl <<
                                "first_tcp_seq_num: " << first_tcp_seq_num << endl <<
                                "first_tcp_ack_num: " << first_tcp_ack_num << endl <<
                                "first_seq: " << first_seq << endl <<
                                "first_ret_count: " << first_ret_count << endl <<
                                "first_arrival_time: " << now << endl <<
                                "first_hash_of_flow: " << first_hash_of_flow << endl <<
                                "first_reverse_hash_of_flow: " << first_reverse_hash_of_flow << endl <<
                                "first_hash_of_packet: " << first_hash_of_packet << endl;

                        std::cout << "--------------------------------------------" << endl;

                        auto second_dup = packet_found->second->packet;
                        std::cout << "old packet: " << second_dup->str() << endl;
                        second_dup->setFrontIteratorPosition(b(0));
                        second_dup->removeAtFront<EthernetPhyHeader>();
                        second_dup->removeAtFront<EthernetMacHeader>();
                        auto second_ipv4header = second_dup->removeAtFront<Ipv4Header>();
                        auto second_tcpheader = second_dup->peekAtFront<tcp::TcpHeader>();
                        std::string second_src_ip = second_ipv4header->getSourceAddress().str();
                        std::string second_dst_ip = second_ipv4header->getDestinationAddress().str();
                        std::string second_src_port = std::to_string(second_tcpheader->getSourcePort());
                        std::string second_dst_port = std::to_string(second_tcpheader->getDestinationPort());
                        std::string second_tcp_seq_num = std::to_string(second_tcpheader->getSequenceNo());
                        std::string second_packet_name = second_dup->getName();
                        std::string second_tcp_ack_num = std::to_string(second_tcpheader->getAckNo());
                        unsigned long second_hash_of_flow = flow_hash(second_src_ip + second_dst_ip + second_src_port +
                                second_dst_port);
                        unsigned long second_reverse_hash_of_flow = flow_hash(second_dst_ip + second_src_ip + second_dst_port
                                + second_src_port);
                        unsigned long second_hash_of_packet = packet_hash(second_src_ip + second_dst_ip + second_src_port +
                                second_dst_port + second_tcp_seq_num + second_tcp_ack_num + second_packet_name);
                        unsigned long second_seq = -1;
                        unsigned long second_ret_count = -1;
                        for (unsigned int i = 0; i < second_ipv4header->getOptionArraySize(); i++) {
                            const TlvOptionBase *option = &second_ipv4header->getOption(i);
                            if (option->getType() == IPOPTION_V2_MARKING) {
                                auto opt = check_and_cast<const Ipv4OptionV2Marking*>(option);
                                second_seq = opt->getSeq();
                                second_ret_count = opt->getRet_num();
                                break;
                            }
                        }
                        if (second_seq < 0)
                            throw cRuntimeError("How can seq be less than 0?");

                        std::cout << "second_src_ip: " << second_src_ip << endl <<
                                    "second_dst_ip: " << second_dst_ip << endl <<
                                    "second_src_port: " << second_src_port << endl <<
                                    "second_dst_port: " << second_dst_port << endl <<
                                    "second_tcp_seq_num: " << second_tcp_seq_num << endl <<
                                    "second_tcp_ack_num: " << second_tcp_ack_num << endl <<
                                    "second_seq: " << second_seq << endl <<
                                    "second_ret_count: " << second_ret_count << endl <<
                                    "second_arrival_time: " << packet_found->second->arrival_time << endl <<
                                    "second_hash_of_flow: " << second_hash_of_flow << endl <<
                                    "second_reverse_hash_of_flow: " << second_reverse_hash_of_flow << endl <<
                                    "second_hash_of_packet: " << second_hash_of_packet << endl;

                        delete packet;
                        throw cRuntimeError("A different packet with same seq was received before the previous packet was deleted or pushed up");
                    } else {
                        // Keep everything the same and just remove the new packet
                        delete packet;
                    }
                } else {
                    // packet isn't inside the hash table
                    auto packet_info_node = new OrderingComponentPacketInfo(now, packet);
                    flow_found->second->stored_packet_hash_table.insert(std::pair<unsigned long,
                            OrderingComponentPacketInfo*>(marking_info_holder.seq, packet_info_node));
                    if (flow_found->second->timeoutMsg == nullptr) {
                        EV << "No running timer, setting the timeout=" << now + omega << endl;
                        flow_found->second->timeoutMsg = new cMessage("timer");
                        flow_found->second->timeoutMsg->setKind(MSGKIND_PUSH_UP);
                        flow_found->second->timeoutMsg->addPar("flow_hash") = hash_of_flow;
                        flow_found->second->timeoutMsg->addPar("packet_seq") = marking_info_holder.seq;
                        scheduleAt(now + omega, flow_found->second->timeoutMsg);
                    } else {
                        EV << "A timer is already running so there is no need to instantiate a timer again." << endl;
                    }
               }
            }
        } else {
            EV << "packet flowlet id: " << marking_info_holder.flow_let_id << endl;
            EV << flow_found->second->expected_flow_let_id << endl;
            throw cRuntimeError("The gap in the flow_let_id is more than 1");
        }
    } else {
        // Flow does not exist initiate it
        EV << "No flow with hash " << hash_of_flow << " found." << endl;
        // marking_info_holder.seq == 0 -> packet in order
        unsigned long expected_seq = (marking_info_holder.seq == 0) ? 1 : 0;
        result = (marking_info_holder.seq == 0) ? false : true;
        auto flow_info_node = new OrderingComponentFlowInfo(expected_seq, nullptr, marking_info_holder.flow_let_id);
        if (marking_info_holder.seq != 0) {
            // packet is out of order
            received_sooner_stored_counter++;
            EV << "Setting the timeout=" << now + omega << endl;
            auto packet_info_node = new OrderingComponentPacketInfo(now, packet);
            flow_info_node->stored_packet_hash_table.insert(std::pair<unsigned long,
                    OrderingComponentPacketInfo*>(marking_info_holder.seq, packet_info_node));
            flow_info_node->timeoutMsg = new cMessage("timer");
            flow_info_node->timeoutMsg->setKind(MSGKIND_PUSH_UP);
            flow_info_node->timeoutMsg->addPar("flow_hash") = hash_of_flow;
            flow_info_node->timeoutMsg->addPar("packet_seq") = marking_info_holder.seq;
            scheduleAt(now + omega, flow_info_node->timeoutMsg);
        } else {
            emit(v2PacketQueueingTimeSignal, 0);
            received_correctly_pushed_counter++;
        }
        ordering_component_flow_hash_table.insert(std::pair<unsigned long,
                OrderingComponentFlowInfo*>(hash_of_flow,
                        flow_info_node));

        if (ordering_component_flow_hash_table_size > 0)
            ordering_component_flow_lru_tracker.emplace_hint(ordering_component_flow_lru_tracker.end(), now, hash_of_flow);
    }

    // if required update the arrival time of the inserted packet
    {
        auto flow_found = ordering_component_flow_hash_table.find(hash_of_flow);
        if (flow_found != ordering_component_flow_hash_table.end()) {
            std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it =
                    flow_found->second->stored_packet_hash_table.find(marking_info_holder.seq);
            if (it != flow_found->second->stored_packet_hash_table.end()) {
                std::map<unsigned long, OrderingComponentPacketInfo*>::iterator next_it =
                        flow_found->second->stored_packet_hash_table.find(marking_info_holder.seq);
                next_it++;
                if (next_it != flow_found->second->stored_packet_hash_table.end()) {
                    if (it->second->arrival_time > next_it->second->arrival_time)
                        it->second->arrival_time = next_it->second->arrival_time;
                }
            }
        } else {
            throw cRuntimeError("Naturally, the flow should exist in the hash table at this point.");
        }
    }

    return result;
}

void Ipv4::push_old_stored_packets(std::unordered_map<unsigned long, OrderingComponentFlowInfo*>::iterator flow_it,
        bool restart_timer) {
    if (marking_type == MARKING_SRPT) {
        unsigned long timeout_packet_seq = 0;
        unsigned long hash_of_flow = 0;
        simtime_t now = simTime();
        bool timeout_running = flow_it->second->timeoutMsg != nullptr;
        if (timeout_running) {
            timeout_packet_seq = (unsigned long) flow_it->second->timeoutMsg->par("packet_seq").longValue();
            hash_of_flow = (unsigned long) flow_it->second->timeoutMsg->par("flow_hash").longValue();
        }
        while (flow_it->second->descending_stored_packet_hash_table.begin()->first >
                                flow_it->second->expected_seq) {
            std::map<unsigned long, OrderingComponentPacketInfo*,
                    std::greater<unsigned long>>::iterator packet_it =
                    flow_it->second->descending_stored_packet_hash_table.begin();

            unsigned long first_element_seq = packet_it->first;
            PayloadInfoHolder first_element_payload_info_holder = extract_payload_info_holder(
                    packet_it->second->packet);
            // update expected if needed!
            if (first_element_seq - first_element_payload_info_holder.payload_length.get() <
                    flow_it->second->expected_seq)
                flow_it->second->expected_seq =
                        first_element_seq - first_element_payload_info_holder.payload_length.get();

            if (timeout_running && timeout_packet_seq == first_element_seq) {
                cancelEvent(flow_it->second->timeoutMsg);
                delete flow_it->second->timeoutMsg;
                flow_it->second->timeoutMsg = nullptr;
                timeout_running = false;
            }

            EV << "Pushing packet with seq=" << first_element_seq << " up because it's old and stored!" << endl;
            emit(v2PacketQueueingTimeSignal, now - packet_it->second->actual_arrival_time);
            send(packet_it->second->packet, "transportOut");
            flow_it->second->sent_packet_seqs_payload_length.insert(
                    std::pair<unsigned long, unsigned int>(packet_it->first,
                    first_element_payload_info_holder.payload_length.get()));
            delete packet_it->second;
            flow_it->second->descending_stored_packet_hash_table.erase(packet_it->first);
            numLocalDeliver++;
        }

        // re-initiate the time if required, if the time is initiated in the code there is no need to re-initiate it here, causes problems
        if (restart_timer && !timeout_running) {
            // if the timeout wasn't running or was canceled
            if (flow_it->second->descending_stored_packet_hash_table.size() != 0) {
                auto packet_found = flow_it->second->descending_stored_packet_hash_table.begin();
                if (now < packet_found->second->arrival_time)
                    throw cRuntimeError("How is a packet received in the future? :)");
                simtime_t remained_time = now + (omega - (now - packet_found->second->arrival_time));
                if (remained_time <= 0) {
                    throw cRuntimeError("I didn't expect the remaining time to be <= 0 for any of the packets.");
                }
                EV << "Another gap recognized after pushing old packets. Setting timeout=" << remained_time << " for packet with seq=" << packet_found->first << " was received before." << endl;
                flow_it->second->timeoutMsg = new cMessage("timer");
                flow_it->second->timeoutMsg->setKind(MSGKIND_PUSH_UP);
                flow_it->second->timeoutMsg->addPar("flow_hash") = hash_of_flow;
                flow_it->second->timeoutMsg->addPar("packet_seq") = packet_found->first;
                scheduleAt(remained_time, flow_it->second->timeoutMsg);
            }
        }
    } else {
        throw cRuntimeError("You shouldn't need this function for other marking types!");
    }
}

bool Ipv4::apply_SRPT_ordering(Packet *packet, unsigned long hash_of_flow,
        MarkingInfoHolder marking_info_holder) {


    auto packet_dup = packet->dup();
    packet_dup->setFrontIteratorPosition(b(0));
    packet_dup->removeAtFront<EthernetPhyHeader>();
    auto eth_header = packet_dup->removeAtFront<EthernetMacHeader>();
    delete packet_dup;

    bool result;
    // check if the message is a control message
    if (marking_info_holder.is_control_message) {
        // push the packet up
        EV << "Message is a control message. Avoiding extra ordering measurements." << endl;
        result = false;
        return result;
    }

    EV << "SRPT: Applying ordering to packet " << packet->str() << endl;
    EV << "Packet received in ordering component." << endl;

    simtime_t now = simTime();
    auto flow_found = ordering_component_flow_hash_table.find(hash_of_flow);
    if (flow_found != ordering_component_flow_hash_table.end()) {
        // Flow found
        EV << "Flow with hash " << hash_of_flow << " found. Expected seq is " << flow_found->second->expected_seq << endl;
        // bring the flow to the head of flow_lru_tracker
        if (ordering_component_flow_hash_table_size > 0) {
            ordering_component_flow_lru_tracker.erase(flow_found->second->last_updated);
            ordering_component_flow_lru_tracker.emplace_hint(ordering_component_flow_lru_tracker.end(), now, hash_of_flow);
        }
        flow_found->second->last_updated = now;

        if (marking_info_holder.flow_let_id > flow_found->second->expected_flow_let_id) {
            // packet of the next flowlet is received, store it, flow_let_id = expected_flow_let_id + 1
            // If anything is left in the queue, push them up.

            EV << "marking_info_holder.flow_let_id > flow_found->second->expected_flow_let_id, packet of the next flowlet is received" << endl;
            if (flow_found->second->descending_stored_packet_hash_table.size() != 0) {
                for (std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it =
                                    flow_found->second->descending_stored_packet_hash_table.begin();
                                    it != flow_found->second->descending_stored_packet_hash_table.end(); it++)
                {
                    //push everything up
                    EV << "Pushing packet with seq=" << it->first << " up." << endl;
                    emit(v2PacketQueueingTimeSignal, now - it->second->actual_arrival_time);
                    send(it->second->packet, "transportOut");
                    delete it->second;
                    numLocalDeliver++;
                }
            }

            flow_found->second->descending_stored_packet_hash_table.clear();
            flow_found->second->sent_packet_seqs_payload_length.clear();

            if (flow_found->second->timeoutMsg != nullptr) {
                cancelEvent(flow_found->second->timeoutMsg);
                delete flow_found->second->timeoutMsg;
                flow_found->second->timeoutMsg = nullptr;
            }

            flow_found->second->expected_flow_let_id = marking_info_holder.flow_let_id;

            if (marking_info_holder.is_first_packet) {
                // new co-flow
                EV << "First packet with seq=" <<
                        marking_info_holder.seq << " received. So we push everything up and get ready for a new co-flow" << endl;
                // push the current packet up
                result = false;
                flow_found->second->expected_seq =
                        marking_info_holder.seq - eth_header->getPayload_length().get();
            } else {
                // just store the packet
                EV << "Packet is out of order" << endl;
                received_sooner_stored_counter++;
                result = true;
                auto packet_info_node = new OrderingComponentPacketInfo(now, packet);
                flow_found->second->descending_stored_packet_hash_table.insert(std::pair<unsigned long,
                        OrderingComponentPacketInfo*>(marking_info_holder.seq, packet_info_node));
                EV << "No running timer, setting the timeout=" << now + omega << endl;
                flow_found->second->timeoutMsg = new cMessage("timer");
                flow_found->second->timeoutMsg->setKind(MSGKIND_PUSH_UP);
                flow_found->second->timeoutMsg->addPar("flow_hash") = hash_of_flow;
                flow_found->second->timeoutMsg->addPar("packet_seq") = marking_info_holder.seq;
                scheduleAt(now + omega, flow_found->second->timeoutMsg);

                flow_found->second->expected_seq = eth_header->getTotal_length().get();
            }
        } else if(marking_info_holder.flow_let_id < flow_found->second->expected_flow_let_id) {
            // packet of the previous flowlet is received, push it up, flow_let_id = expected_flow_let_id -1 1
            EV << "marking_info_holder.flow_let_id < flow_found->second->expected_flow_let_id, packet of old flowlet" << endl;
            result = false;
        } else if (marking_info_holder.flow_let_id == flow_found->second->expected_flow_let_id) {
            // packet of the current flowlet is received
            EV << "marking_info_holder.flow_let_id == flow_found->second->expected_flow_let_id" << endl;

            if (marking_info_holder.seq > flow_found->second->expected_seq) {
                // packet is old, send it up
                // in srpt, the seq is descending, so higher seqs means older packets
                EV << "marking_info_holder.seq > flow_found->second->expected_seq, the packet is old" << endl;
                // before pushing the packet check if it passes the expecte_seq
                if (marking_info_holder.seq - eth_header->getPayload_length().get() <
                        flow_found->second->expected_seq) {
                    // There is a chance that TCP passes our expected seq
                    EV << "Pushing this old packet moves everything out of sync, update expected seq" << endl;
                    flow_found->second->expected_seq = marking_info_holder.seq - eth_header->getPayload_length().get();
                }
                result = false;
            } else if (marking_info_holder.seq == flow_found->second->expected_seq) {
                // packet is in-place and thus might fill a gap
                EV << "marking_info_holder.seq == flow_found->second->expected_seq" << endl;

                flow_found->second->expected_seq -= eth_header->getPayload_length().get();
                if (flow_found->second->timeoutMsg == nullptr) {
                    // No timeout initiated, no gap exists
                    EV << "seq == flow_found->second->expected_seq and no timeout. pushing packet up." << endl;
                    result = false;

                    // keep increasing the expected seq as long as you have already received the required packets before
                    auto packet_received_before = flow_found->second->sent_packet_seqs_payload_length.find(flow_found->second->expected_seq);
                    while (packet_received_before != flow_found->second->sent_packet_seqs_payload_length.end()) {
                        EV << "Packet with seq=" << flow_found->second->expected_seq << " received before. increasing the "
                                "expected seq to " << flow_found->second->expected_seq - packet_received_before->second << endl;
                        flow_found->second->expected_seq -= packet_received_before->second;
                        flow_found->second->sent_packet_seqs_payload_length.erase(packet_received_before->first);
                        packet_received_before = flow_found->second->sent_packet_seqs_payload_length.find(flow_found->second->expected_seq);
                    }

                } else {
                    // A timeout was running so the packet fills a gap
                    // stop timer
                    EV << "seq == flow_found->second->expected_seq and timeout. packet fills a gap." << endl;
                    cancelEvent(flow_found->second->timeoutMsg);
                    delete flow_found->second->timeoutMsg;
                    flow_found->second->timeoutMsg = nullptr;

                    // send the packet yourself right now and then send the others
                    EV << "pushing packet with seq=" << marking_info_holder.seq << " up." << endl;
                    result = true;
                    send(packet, "transportOut");
                    numLocalDeliver++;
                    push_old_stored_packets(flow_found, false);

                    // our map is sorted, so we can start iterating till a point where there is a gap again
                    // As timer is running, we know that no packet has been timed out yet
                    bool expected_is_stored = flow_found->second->descending_stored_packet_hash_table.find(
                            flow_found->second->expected_seq) != flow_found->second->descending_stored_packet_hash_table.end();
                    bool expected_was_received = flow_found->second->sent_packet_seqs_payload_length.find(
                            flow_found->second->expected_seq) != flow_found->second->sent_packet_seqs_payload_length.end();
                    int max_iteration_count = flow_found->second->descending_stored_packet_hash_table.size() +
                            flow_found->second->sent_packet_seqs_payload_length.size();
                    while (max_iteration_count > 0 && (expected_is_stored || expected_was_received)) {
                        max_iteration_count--;
                        if (expected_is_stored) {
                            //todo: remove, this is a test
                            auto packet_found = flow_found->second->descending_stored_packet_hash_table.find(flow_found->second->expected_seq);
                            if (flow_found->second->descending_stored_packet_hash_table.begin()->first !=
                                    flow_found->second->expected_seq &&
                                    packet_found != flow_found->second->descending_stored_packet_hash_table.end()) {
                                std::cout << flow_found->second->expected_seq << endl;
                                std::cout << flow_found->second->descending_stored_packet_hash_table.begin()->first << endl;
                                auto first_dup = flow_found->second->descending_stored_packet_hash_table.begin()->second->packet;
                                first_dup->setFrontIteratorPosition(b(0));
                                first_dup->removeAtFront<EthernetPhyHeader>();
                                first_dup->removeAtFront<EthernetMacHeader>();
                                auto first_ipv4header = first_dup->removeAtFront<Ipv4Header>();
                                auto first_tcpheader = first_dup->peekAtFront<tcp::TcpHeader>();
                                std::string first_src_ip = first_ipv4header->getSourceAddress().str();
                                std::string first_dst_ip = first_ipv4header->getDestinationAddress().str();
                                std::string first_src_port = std::to_string(first_tcpheader->getSourcePort());
                                std::string first_dst_port = std::to_string(first_tcpheader->getDestinationPort());
                                std::string first_tcp_seq_num = std::to_string(first_tcpheader->getSequenceNo());
                                std::string first_packet_name = first_dup->getName();
                                std::string first_tcp_ack_num = std::to_string(first_tcpheader->getAckNo());
                                unsigned long first_hash_of_flow = flow_hash(first_src_ip + first_dst_ip + first_src_port +
                                                            first_dst_port);
                                unsigned long first_reverse_hash_of_flow = flow_hash(first_dst_ip + first_src_ip + first_dst_port
                                        + first_src_port);
                                unsigned long first_hash_of_packet = packet_hash(first_src_ip + first_dst_ip + first_src_port +
                                        first_dst_port + first_tcp_seq_num + first_tcp_ack_num + first_packet_name);
                                unsigned long first_seq = -1;
                                unsigned long first_ret_count = -1;
                                for (unsigned int i = 0; i < first_ipv4header->getOptionArraySize(); i++) {
                                    const TlvOptionBase *option = &first_ipv4header->getOption(i);
                                    if (option->getType() == IPOPTION_V2_MARKING) {
                                        auto opt = check_and_cast<const Ipv4OptionV2Marking*>(option);
                                        first_seq = opt->getSeq();
                                        first_ret_count = opt->getRet_num();
                                        break;
                                    }
                                }
                                if (first_seq < 0)
                                    throw cRuntimeError("How can seq be less than 0?");

                                std::cout << "first_src_ip: " << first_src_ip << endl <<
                                        "first_dst_ip: " << first_dst_ip << endl <<
                                        "first_src_port: " << first_src_port << endl <<
                                        "first_dst_port: " << first_dst_port << endl <<
                                        "first_tcp_seq_num: " << first_tcp_seq_num << endl <<
                                        "first_tcp_ack_num: " << first_tcp_ack_num << endl <<
                                        "first_seq: " << first_seq << endl <<
                                        "first_ret_count: " << first_ret_count << endl <<
                                        "first_arrival_time: " << now << endl <<
                                        "first_hash_of_flow: " << first_hash_of_flow << endl <<
                                        "first_reverse_hash_of_flow: " << first_reverse_hash_of_flow << endl <<
                                        "first_hash_of_packet: " << first_hash_of_packet << endl;
                                delete first_dup;
                                throw cRuntimeError("We passed over a packet and it will always be in the queue.");
                            }

                            // check if the packet with the expected seq is stored
                            PayloadInfoHolder payload_info_holder = extract_payload_info_holder(packet_found->second->packet);
                            EV << "Continue pushing. Pushing packet with seq=" << packet_found->first << " up." << endl;
                            emit(v2PacketQueueingTimeSignal, now - packet_found->second->actual_arrival_time);
                            send(packet_found->second->packet, "transportOut");
                            numLocalDeliver++;
                            delete packet_found->second;
                            flow_found->second->descending_stored_packet_hash_table.erase(flow_found->second->expected_seq);
                            if (expected_was_received) {
                                // packet was also received before
                                flow_found->second->sent_packet_seqs_payload_length.erase(flow_found->second->expected_seq);
                            }
                            flow_found->second->expected_seq -= payload_info_holder.payload_length.get();
                        } else if (expected_was_received) {
                            // check if the expected seq was sent before
                            EV << "Continue pushing. Packet with seq=" << flow_found->second->expected_seq << " was received before." << endl;
                            unsigned int payload_length = flow_found->second->sent_packet_seqs_payload_length.find(flow_found->second->expected_seq)->second;
                            flow_found->second->sent_packet_seqs_payload_length.erase(flow_found->second->expected_seq);
                            flow_found->second->expected_seq -= payload_length;
                        }

                        push_old_stored_packets(flow_found, false);

                        expected_is_stored = flow_found->second->descending_stored_packet_hash_table.find(
                                flow_found->second->expected_seq) != flow_found->second->descending_stored_packet_hash_table.end();
                        expected_was_received = flow_found->second->sent_packet_seqs_payload_length.find(
                                flow_found->second->expected_seq) != flow_found->second->sent_packet_seqs_payload_length.end();
                    }

                    // see if you should re-initiate the timer
                    if (flow_found->second->descending_stored_packet_hash_table.size() != 0) {
                        if (flow_found->second->timeoutMsg == nullptr) {
                            // extra checkes not to initiate multiple timers
                            auto packet_found = flow_found->second->descending_stored_packet_hash_table.begin();
                            if (now < packet_found->second->arrival_time)
                                throw cRuntimeError("How is a packet received in the future? :)");
                            simtime_t remained_time = now + (omega - (now - packet_found->second->arrival_time));
                            if (remained_time <= 0) {
                                throw cRuntimeError("I didn't expect the remaining time to be <= 0 for any of the packets.");
                            }
                            EV << "Another gap recognized. Setting timeout=" << remained_time << " for packet with seq=" << packet_found->first << " was received before." << endl;
                            flow_found->second->timeoutMsg = new cMessage("timer");
                            flow_found->second->timeoutMsg->setKind(MSGKIND_PUSH_UP);
                            flow_found->second->timeoutMsg->addPar("flow_hash") = flow_found->first;
                            flow_found->second->timeoutMsg->addPar("packet_seq") = packet_found->first;
                            scheduleAt(remained_time, flow_found->second->timeoutMsg);
                        }
                    }
                }
            } else {
                // The packet is out of order
                EV << "The received packet is out of order." << endl;
                received_sooner_stored_counter++;
                result = true;
                auto packet_found = flow_found->second->descending_stored_packet_hash_table.find(marking_info_holder.seq);

                if (packet_found != flow_found->second->descending_stored_packet_hash_table.end()) {
                    // The packet is already stored in hash table
                    bool are_packets_similar = compare_packets(packet, packet_found->second->packet);

                    if (!are_packets_similar) {
                        auto first_dup = packet->dup();
                        EV << "newly arrived packet: " << first_dup->str() << endl;
                        first_dup->setFrontIteratorPosition(b(0));
                        first_dup->removeAtFront<EthernetPhyHeader>();
                        first_dup->removeAtFront<EthernetMacHeader>();
                        auto first_ipv4header = first_dup->removeAtFront<Ipv4Header>();
                        auto first_tcpheader = first_dup->peekAtFront<tcp::TcpHeader>();
                        std::string first_src_ip = first_ipv4header->getSourceAddress().str();
                        std::string first_dst_ip = first_ipv4header->getDestinationAddress().str();
                        std::string first_src_port = std::to_string(first_tcpheader->getSourcePort());
                        std::string first_dst_port = std::to_string(first_tcpheader->getDestinationPort());
                        std::string first_tcp_seq_num = std::to_string(first_tcpheader->getSequenceNo());
                        std::string first_packet_name = first_dup->getName();
                        std::string first_tcp_ack_num = std::to_string(first_tcpheader->getAckNo());
                        unsigned long first_hash_of_flow = flow_hash(first_src_ip + first_dst_ip + first_src_port +
                                                    first_dst_port);
                        unsigned long first_reverse_hash_of_flow = flow_hash(first_dst_ip + first_src_ip + first_dst_port
                                + first_src_port);
                        unsigned long first_hash_of_packet = packet_hash(first_src_ip + first_dst_ip + first_src_port +
                                first_dst_port + first_tcp_seq_num + first_tcp_ack_num + first_packet_name);
                        unsigned long first_seq = -1;
                        unsigned long first_ret_count = -1;
                        for (unsigned int i = 0; i < first_ipv4header->getOptionArraySize(); i++) {
                            const TlvOptionBase *option = &first_ipv4header->getOption(i);
                            if (option->getType() == IPOPTION_V2_MARKING) {
                                auto opt = check_and_cast<const Ipv4OptionV2Marking*>(option);
                                first_seq = opt->getSeq();
                                first_ret_count = opt->getRet_num();
                                break;
                            }
                        }
                        if (first_seq < 0)
                            throw cRuntimeError("How can seq be less than 0?");

                        EV << "first_src_ip: " << first_src_ip << endl <<
                                "first_dst_ip: " << first_dst_ip << endl <<
                                "first_src_port: " << first_src_port << endl <<
                                "first_dst_port: " << first_dst_port << endl <<
                                "first_tcp_seq_num: " << first_tcp_seq_num << endl <<
                                "first_tcp_ack_num: " << first_tcp_ack_num << endl <<
                                "first_seq: " << first_seq << endl <<
                                "first_ret_count: " << first_ret_count << endl <<
                                "first_arrival_time: " << now << endl <<
                                "first_hash_of_flow: " << first_hash_of_flow << endl <<
                                "first_reverse_hash_of_flow: " << first_reverse_hash_of_flow << endl <<
                                "first_hash_of_packet: " << first_hash_of_packet << endl;
                        delete first_dup;

                        EV << "--------------------------------------------" << endl;

                        auto second_dup = packet_found->second->packet->dup();
                        EV << "old packet: " << second_dup->str() << endl;
                        second_dup->setFrontIteratorPosition(b(0));
                        second_dup->removeAtFront<EthernetPhyHeader>();
                        second_dup->removeAtFront<EthernetMacHeader>();
                        auto second_ipv4header = second_dup->removeAtFront<Ipv4Header>();
                        auto second_tcpheader = second_dup->peekAtFront<tcp::TcpHeader>();
                        std::string second_src_ip = second_ipv4header->getSourceAddress().str();
                        std::string second_dst_ip = second_ipv4header->getDestinationAddress().str();
                        std::string second_src_port = std::to_string(second_tcpheader->getSourcePort());
                        std::string second_dst_port = std::to_string(second_tcpheader->getDestinationPort());
                        std::string second_tcp_seq_num = std::to_string(second_tcpheader->getSequenceNo());
                        std::string second_packet_name = second_dup->getName();
                        std::string second_tcp_ack_num = std::to_string(second_tcpheader->getAckNo());
                        unsigned long second_hash_of_flow = flow_hash(second_src_ip + second_dst_ip + second_src_port +
                                second_dst_port);
                        unsigned long second_reverse_hash_of_flow = flow_hash(second_dst_ip + second_src_ip + second_dst_port
                                + second_src_port);
                        unsigned long second_hash_of_packet = packet_hash(second_src_ip + second_dst_ip + second_src_port +
                                second_dst_port + second_tcp_seq_num + second_tcp_ack_num + second_packet_name);
                        unsigned long second_seq = -1;
                        unsigned long second_ret_count = -1;
                        for (unsigned int i = 0; i < second_ipv4header->getOptionArraySize(); i++) {
                            const TlvOptionBase *option = &second_ipv4header->getOption(i);
                            if (option->getType() == IPOPTION_V2_MARKING) {
                                auto opt = check_and_cast<const Ipv4OptionV2Marking*>(option);
                                second_seq = opt->getSeq();
                                second_ret_count = opt->getRet_num();
                                break;
                            }
                        }
                        if (second_seq < 0)
                            throw cRuntimeError("How can seq be less than 0?");

                        EV << "second_src_ip: " << second_src_ip << endl <<
                                    "second_dst_ip: " << second_dst_ip << endl <<
                                    "second_src_port: " << second_src_port << endl <<
                                    "second_dst_port: " << second_dst_port << endl <<
                                    "second_tcp_seq_num: " << second_tcp_seq_num << endl <<
                                    "second_tcp_ack_num: " << second_tcp_ack_num << endl <<
                                    "second_seq: " << second_seq << endl <<
                                    "second_ret_count: " << second_ret_count << endl <<
                                    "second_arrival_time: " << packet_found->second->arrival_time << endl <<
                                    "second_hash_of_flow: " << second_hash_of_flow << endl <<
                                    "second_reverse_hash_of_flow: " << second_reverse_hash_of_flow << endl <<
                                    "second_hash_of_packet: " << second_hash_of_packet << endl;
                        delete second_dup;

                        EV << "--------------------------------------------" << endl;
                        PayloadInfoHolder old_packet_payload_info_holder = extract_payload_info_holder(packet_found->second->packet);
                        PayloadInfoHolder new_packet_payload_info_holder = extract_payload_info_holder(packet);
                        if (old_packet_payload_info_holder.payload_length >= new_packet_payload_info_holder.payload_length)
                            // keep old packet
                            delete packet;
                        else {
                            // keep new packet
                            delete packet_found->second->packet;
                            packet_found->second->packet = packet;
                        }
//                        throw cRuntimeError("A different packet with same seq was received before the previous packet was deleted or pushed up");
                    } else {
                        // Keep everything the same and just remove the new packet
                        delete packet;
                    }
                } else {
                    // packet isn't inside the hash table
                    auto packet_info_node = new OrderingComponentPacketInfo(now, packet);
                    flow_found->second->descending_stored_packet_hash_table.insert(std::pair<unsigned long,
                            OrderingComponentPacketInfo*>(marking_info_holder.seq, packet_info_node));
                    if (flow_found->second->timeoutMsg == nullptr) {
                        EV << "No running timer, setting the timeout=" << now + omega << endl;
                        flow_found->second->timeoutMsg = new cMessage("timer");
                        flow_found->second->timeoutMsg->setKind(MSGKIND_PUSH_UP);
                        flow_found->second->timeoutMsg->addPar("flow_hash") = hash_of_flow;
                        flow_found->second->timeoutMsg->addPar("packet_seq") = marking_info_holder.seq;
                        scheduleAt(now + omega, flow_found->second->timeoutMsg);
                    } else {
                        EV << "A timer is already running so there is no need to instantiate a timer again." << endl;
                    }
                }
            }
        } else {
            EV << "packet flowlet id: " << marking_info_holder.flow_let_id << endl;
            EV << flow_found->second->expected_flow_let_id << endl;
            throw cRuntimeError("The gap in the flow_let_id is more than 1");
        }
    } else {
        // Flow does not exist initiate it
        EV << "No flow with hash " << hash_of_flow << " found." << endl;
        unsigned long expected_seq;
        if (marking_info_holder.is_first_packet) {
            // packet is for a new flow and not reordered
            EV << "The received packet is in-order." << endl;
            expected_seq = marking_info_holder.seq - eth_header->getPayload_length().get();
            if (expected_seq < 0)
                throw cRuntimeError("How did seq get smaller than 0!?");
            result = false;
        }
        else {
            // packet is for new flow but re-ordered
            expected_seq = eth_header->getTotal_length().get();
            result = true;
            received_sooner_stored_counter++;
        }

        auto flow_info_node = new OrderingComponentFlowInfo(expected_seq, nullptr,
                marking_info_holder.flow_let_id);

        if (!marking_info_holder.is_first_packet) {
            PayloadInfoHolder payload_info_holder = extract_payload_info_holder(packet);
            flow_info_node->sent_packet_seqs_payload_length.insert(
                                std::pair<unsigned long, unsigned int>(marking_info_holder.seq,
                                        payload_info_holder.payload_length.get()));
        }

        if (!marking_info_holder.is_first_packet) {
            EV << "Setting the timeout=" << now + omega << endl;
            auto packet_info_node = new OrderingComponentPacketInfo(now, packet);
            flow_info_node->descending_stored_packet_hash_table.insert(std::pair<unsigned long,
                    OrderingComponentPacketInfo*>(marking_info_holder.seq, packet_info_node));
            flow_info_node->timeoutMsg = new cMessage("timer");
            flow_info_node->timeoutMsg->setKind(MSGKIND_PUSH_UP);
            flow_info_node->timeoutMsg->addPar("flow_hash") = hash_of_flow;
            flow_info_node->timeoutMsg->addPar("packet_seq") = marking_info_holder.seq;
            scheduleAt(now + omega, flow_info_node->timeoutMsg);
        }
        ordering_component_flow_hash_table.insert(std::pair<unsigned long,
                OrderingComponentFlowInfo*>(hash_of_flow,
                        flow_info_node));
        if (ordering_component_flow_hash_table_size > 0)
            ordering_component_flow_lru_tracker.emplace_hint(ordering_component_flow_lru_tracker.end(), now, hash_of_flow);
    }

    // if required update the arrival time of the inserted packet
    {
        auto flow_found = ordering_component_flow_hash_table.find(hash_of_flow);
        if (flow_found != ordering_component_flow_hash_table.end()) {
            std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it =
                    flow_found->second->descending_stored_packet_hash_table.find(marking_info_holder.seq);
            if (it != flow_found->second->descending_stored_packet_hash_table.end()) {
                std::map<unsigned long, OrderingComponentPacketInfo*>::iterator next_it =
                        flow_found->second->descending_stored_packet_hash_table.find(marking_info_holder.seq);
                next_it++;
                if (next_it != flow_found->second->descending_stored_packet_hash_table.end()) {
                    if (it->second->arrival_time > next_it->second->arrival_time)
                        it->second->arrival_time = next_it->second->arrival_time;
                }
            }
        } else {
            throw cRuntimeError("Naturally, the flow should exist in the hash table at this point.");
        }
    }

    return result;
}

bool Ipv4::is_packet_reordered(Packet *packet) {
    // 1) find the hash of packet and flow
    // I hash src_ip, dst_ip, src_port, dst_port, tcp_seq_num
    auto packet_dup = packet->dup();
    packet_dup->setFrontIteratorPosition(b(0));
    packet_dup->removeAtFront<EthernetPhyHeader>();
    auto eth_header = packet_dup->removeAtFront<EthernetMacHeader>();
    auto ipHeader = packet_dup->removeAtFront<Ipv4Header>();
    auto tcp_header = packet_dup->peekAtFront<tcp::TcpHeader>();
    std::string packet_name = packet->getName();
    std::string src_ip = ipHeader->getSourceAddress().str();
    std::string dst_ip = ipHeader->getDestinationAddress().str();
    std::string src_port = std::to_string(tcp_header->getSourcePort());
    std::string dst_port = std::to_string(tcp_header->getDestinationPort());
    unsigned long hash_of_flow = flow_hash(src_ip + dst_ip + src_port + dst_port);
    EV << "Info used for flow hash is: " << src_ip + dst_ip + src_port + dst_port << endl;
    EV << "Hash of flow is: " << hash_of_flow << endl;
    delete packet_dup;

    // 2) find the seq added by marking component in the packet
    MarkingInfoHolder marking_info_holder = extract_marking_info_holder(packet);

    bool result;
    switch (marking_type) {
        case MARKING_LAS:
            result = apply_LAS_ordering(packet, hash_of_flow, marking_info_holder);
            break;
        case MARKING_SRPT:
            result = apply_SRPT_ordering(packet, hash_of_flow, marking_info_holder);
            // no checks requred if it's control message
            if (marking_info_holder.is_control_message)
                return result;
            break;
        default:
            throw cRuntimeError("Unknown marking type!");
    }

    // handle lru for flows
    if (ordering_component_flow_hash_table_size > 0 &&
            ordering_component_flow_hash_table.size() >
            ordering_component_flow_hash_table_size) {

        if (ordering_component_flow_hash_table.size() > ordering_component_flow_hash_table_size + 1) {
            throw cRuntimeError("how did you let ordering_component_flow_hash_table size get this large!");
        }

        // cancel any running timer for the flow that is going to be removed
        auto flow_to_be_removed_lru_pointer = ordering_component_flow_lru_tracker.begin();
        auto flow_found = ordering_component_flow_hash_table.find(flow_to_be_removed_lru_pointer->second);
        if (flow_found->second->timeoutMsg != nullptr) {
            cancelEvent(flow_found->second->timeoutMsg);
            delete flow_found->second->timeoutMsg;
            flow_found->second->timeoutMsg = nullptr;
        }
        // delete the packet objects stored in hash tables
        for (std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it = flow_found->second->stored_packet_hash_table.begin();
                it != flow_found->second->stored_packet_hash_table.end(); it++) {
            delete it->second->packet;
            delete it->second;
        }
        for (std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it = flow_found->second->descending_stored_packet_hash_table.begin();
                it != flow_found->second->descending_stored_packet_hash_table.end(); it++) {
            delete it->second->packet;
            delete it->second;
        }
        flow_found->second->sent_packet_seqs.clear();
        flow_found->second->sent_packet_seqs_payload_length.clear();
        flow_found->second->stored_packet_hash_table.clear();
        delete flow_found->second;
        ordering_component_flow_hash_table.erase(flow_found);
        ordering_component_flow_lru_tracker.erase(flow_to_be_removed_lru_pointer);
    }

    EV << "Modules stored in our ordering component: " << endl;
    return result;
}

void Ipv4::handle_timeout_v2_LAS(unsigned long hash_of_flow, unsigned long packet_seq) {
    auto flow_found = ordering_component_flow_hash_table.find(hash_of_flow);
    simtime_t now = simTime();
    if (flow_found != ordering_component_flow_hash_table.end()) {

        cancelEvent(flow_found->second->timeoutMsg);
        delete flow_found->second->timeoutMsg;
        flow_found->second->timeoutMsg = nullptr;

        auto packet_found = flow_found->second->stored_packet_hash_table.find(packet_seq);
        if (packet_found == flow_found->second->stored_packet_hash_table.end())
            throw cRuntimeError("How isn't the packet in our hash table?");

        std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it =
                                flow_found->second->stored_packet_hash_table.begin();

        EV << "Push all the packets before the timed out packet up" << endl;
        while (it != flow_found->second->stored_packet_hash_table.end() && it->first < packet_seq) {
            // push all the packets before the timed out packet up
            // record that you have sent this packet for future use
            flow_found->second->sent_packet_seqs.insert(it->first);

            EV << "Pushing " << it->second->packet->str() << endl;
            send(it->second->packet, "transportOut");
            numLocalDeliver++;
            delete it->second;
            unsigned long value_to_be_removed = it->first;
            it++;
            flow_found->second->stored_packet_hash_table.erase(value_to_be_removed);

        }

        // push all the packets of the same chunk of the timed out packet
        unsigned long temp_seq = packet_seq;
        if (it->first != temp_seq)
            throw cRuntimeError("Why didn't we reach the timed out packet?");

        EV << "Push all the packets of the same chunk of the timed out packet" << endl;

        while (it != flow_found->second->stored_packet_hash_table.end() && (temp_seq == it->first ||
                flow_found->second->sent_packet_seqs.find(temp_seq) != flow_found->second->sent_packet_seqs.end())) {

            //todo: remove. this is a test:
            auto packet_found = flow_found->second->stored_packet_hash_table.find(temp_seq);
            if (temp_seq != it->first && packet_found != flow_found->second->stored_packet_hash_table.end())
                throw cRuntimeError("We moved over a packet. So it would always be there in the queue");


            if (temp_seq == it->first) {
                // the packet is stored, push it up
                flow_found->second->sent_packet_seqs.insert(it->first);
                EV << "Pushing " << it->second->packet->str() << endl;

                send(it->second->packet, "transportOut");
                numLocalDeliver++;
                delete it->second;
                unsigned long value_to_be_removed = it->first;
                it++;
                flow_found->second->stored_packet_hash_table.erase(value_to_be_removed);
            } else {
                // the packet was sent before, do nothing. don't delete it from the sent hashset because we only delete
                // when the actual expected_seq moves further than what we stored
                EV << "Packet with seq " << temp_seq << " has been already pushed up." << endl;
            }
            temp_seq++;
        }

        if (it != flow_found->second->stored_packet_hash_table.end()) {
            // still some packets left that we should set timeout for
            flow_found->second->timeoutMsg = new cMessage("timer");
            flow_found->second->timeoutMsg->setKind(MSGKIND_PUSH_UP);
            flow_found->second->timeoutMsg->addPar("flow_hash") = flow_found->first;
            flow_found->second->timeoutMsg->addPar("packet_seq") = it->first;
            simtime_t remained_time = now + (omega - (now - it->second->arrival_time));
            EV << "Some packets are still left. Re-initiating the timer to " << remained_time << endl;
            scheduleAt(remained_time, flow_found->second->timeoutMsg);
        }
    } else {
        throw cRuntimeError("How is the flow deleted but its timer was still running?");
    }
}

void Ipv4::handle_timeout_v2_SRPT(unsigned long hash_of_flow, unsigned long packet_seq) {
    auto flow_found = ordering_component_flow_hash_table.find(hash_of_flow);
    simtime_t now = simTime();
    if (flow_found != ordering_component_flow_hash_table.end()) {
        cancelEvent(flow_found->second->timeoutMsg);
        delete flow_found->second->timeoutMsg;
        flow_found->second->timeoutMsg = nullptr;

        auto packet_found = flow_found->second->descending_stored_packet_hash_table.find(packet_seq);
        if (packet_found == flow_found->second->descending_stored_packet_hash_table.end())
            throw cRuntimeError("How isn't the packet in our hash table?");

        std::map<unsigned long, OrderingComponentPacketInfo*>::iterator it =
                                flow_found->second->descending_stored_packet_hash_table.begin();

        EV << "Push all the packets before the timed out packet up" << endl;
        while (it != flow_found->second->descending_stored_packet_hash_table.end() && it->first > packet_seq) {
            // push all the packets before the timed out packet up
            // record that you have sent this packet for future use


            PayloadInfoHolder payload_info_holder = extract_payload_info_holder(
                    it->second->packet);
            flow_found->second->sent_packet_seqs_payload_length.insert(
                    std::pair<unsigned long, unsigned int>(it->first,
                            payload_info_holder.payload_length.get()));

            EV << "Pushing " << it->second->packet->str() << endl;
            send(it->second->packet, "transportOut");
            numLocalDeliver++;
            delete it->second;
            unsigned long value_to_be_removed = it->first;
            it++;
            flow_found->second->descending_stored_packet_hash_table.erase(value_to_be_removed);

        }

        // push all the packets of the same chunk of the timed out packet
        unsigned long temp_seq = packet_seq;

        if (it->first != temp_seq)
            throw cRuntimeError("Why didn't we reach the timed out packet?");

        EV << "Push all the packets of the same chunk of the timed out packet" << endl;

        while (it != flow_found->second->descending_stored_packet_hash_table.end() && (temp_seq == it->first ||
                flow_found->second->sent_packet_seqs_payload_length.find(temp_seq) !=
                        flow_found->second->sent_packet_seqs_payload_length.end())) {

            //todo: remove. this is a test:
            auto packet_found = flow_found->second->descending_stored_packet_hash_table.find(temp_seq);
            if (temp_seq != it->first && packet_found != flow_found->second->descending_stored_packet_hash_table.end())
                throw cRuntimeError("We moved over a packet. So it would always be there in the queue");


            if (temp_seq == it->first) {
                // the packet is stored, push it up
                PayloadInfoHolder payload_info_holder = extract_payload_info_holder(
                        it->second->packet);
                flow_found->second->sent_packet_seqs_payload_length.insert(
                        std::pair<unsigned long, unsigned int>(it->first,
                                payload_info_holder.payload_length.get()));
                EV << "Pushing " << it->second->packet->str() << endl;

                send(it->second->packet, "transportOut");
                numLocalDeliver++;
                delete it->second;
                unsigned long value_to_be_removed = it->first;
                it++;
                flow_found->second->descending_stored_packet_hash_table.erase(value_to_be_removed);
            } else {
                // the packet was sent before, do nothing. don't delete it from the sent hashset because we only delete
                // when the actual expected_seq moves further than what we stored
                EV << "Packet with seq " << temp_seq << " has been already pushed up." << endl;
            }
            temp_seq++;
        }

        if (it != flow_found->second->descending_stored_packet_hash_table.end()) {
            // still some packets left that we should set timeout for
            flow_found->second->timeoutMsg = new cMessage("timer");
            flow_found->second->timeoutMsg->setKind(MSGKIND_PUSH_UP);
            flow_found->second->timeoutMsg->addPar("flow_hash") = flow_found->first;
            flow_found->second->timeoutMsg->addPar("packet_seq") = it->first;
            simtime_t remained_time = now + (omega - (now - it->second->arrival_time));
            EV << "Some packets are still left. Re-initiating the timer to " << remained_time << endl;
            scheduleAt(remained_time, flow_found->second->timeoutMsg);
        }
    } else {
        std::cout << "hash of flow: " << hash_of_flow << endl;
        std::cout << "packet_seq: " << packet_seq << endl;
        throw cRuntimeError("How is the flow deleted but its timer was still running?");
    }
}

void Ipv4::handle_timeout_v2(unsigned long hash_of_flow, unsigned long packet_seq) {
    num_timeouts_ordering++;
    switch (marking_type) {
        case MARKING_LAS:
            handle_timeout_v2_LAS(hash_of_flow, packet_seq);
            break;
        case MARKING_SRPT:
            handle_timeout_v2_SRPT(hash_of_flow, packet_seq);
            break;
        default:
            throw cRuntimeError("Unknown marking type!");
    }
}

void Ipv4::reassembleAndDeliverFinish(Packet *packet)
{
    auto ipv4HeaderPosition = packet->getFrontOffset();
    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    const Protocol *protocol = ipv4Header->getProtocol();
    auto remoteAddress(ipv4Header->getSrcAddress());
    auto localAddress(ipv4Header->getDestAddress());
    decapsulate(packet);
    bool hasSocket = false;
    for (const auto &elem: socketIdToSocketDescriptor) {
        if (elem.second->protocolId == protocol->getId()
                && (elem.second->localAddress.isUnspecified() || elem.second->localAddress == localAddress)
                && (elem.second->remoteAddress.isUnspecified() || elem.second->remoteAddress == remoteAddress)) {
            auto *packetCopy = packet->dup();
            packetCopy->setKind(IPv4_I_DATA);
            packetCopy->addTagIfAbsent<SocketInd>()->setSocketId(elem.second->socketId);
            EV_INFO << "Passing up to socket " << elem.second->socketId << "\n";
            emit(packetSentToUpperSignal, packetCopy);
            send(packetCopy, "transportOut");
            hasSocket = true;
        }
    }
    if (upperProtocols.find(protocol) != upperProtocols.end()) {
        EV_INFO << "Passing up to protocol " << *protocol << "\n";
        emit(packetSentToUpperSignal, packet);

        // v2 ordering component
        bool check_ordering = should_check_ordering(packet->getName());

        if (check_ordering) {
            if (is_packet_reordered(packet)) {
                return;
            }
        }

        EV << "packet either wasn't considered for reordering or wasn't out of order." << endl;
        send(packet, "transportOut");
        numLocalDeliver++;
    }
    else if (hasSocket) {
        delete packet;
    }
    else {
        EV_ERROR << "Transport protocol '" << protocol->getName() << "' not connected, discarding packet\n";
        packet->setFrontOffset(ipv4HeaderPosition);
        const InterfaceEntry* fromIE = getSourceInterface(packet);
        sendIcmpError(packet, fromIE ? fromIE->getInterfaceId() : -1, ICMP_DESTINATION_UNREACHABLE, ICMP_DU_PROTOCOL_UNREACHABLE);
    }
}

void Ipv4::decapsulate(Packet *packet)
{
    // decapsulate transport packet
    const auto& ipv4Header = packet->popAtFront<Ipv4Header>();

    // create and fill in control info
    packet->addTagIfAbsent<DscpInd>()->setDifferentiatedServicesCodePoint(ipv4Header->getDscp());
//    packet->addTagIfAbsent<EcnInd>()->setExplicitCongestionNotification(ipv4Header->getExplicitCongestionNotification());
    packet->addTagIfAbsent<EcnInd>()->setExplicitCongestionNotification(ipv4Header->getEcn());

    // original Ipv4 datagram might be needed in upper layers to send back ICMP error message

    auto transportProtocol = ProtocolGroup::ipprotocol.getProtocol(ipv4Header->getProtocolId());
    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(transportProtocol);
    packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(transportProtocol);
    auto l3AddressInd = packet->addTagIfAbsent<L3AddressInd>();
    l3AddressInd->setSrcAddress(ipv4Header->getSrcAddress());
    l3AddressInd->setDestAddress(ipv4Header->getDestAddress());
    packet->addTagIfAbsent<HopLimitInd>()->setHopLimit(ipv4Header->getTimeToLive());
}

void Ipv4::fragmentPostRouting(Packet *packet)
{
    const InterfaceEntry *destIE = ift->getInterfaceById(packet->getTag<InterfaceReq>()->getInterfaceId());
    // fill in source address
    if (packet->peekAtFront<Ipv4Header>()->getSrcAddress().isUnspecified()) {
        auto ipv4Header = removeNetworkProtocolHeader<Ipv4Header>(packet);
        ipv4Header->setSrcAddress(destIE->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
        insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header);
    }

    // v2 marking component
    if (should_use_v2_marking) {
        apply_marking(packet);
    }

    if (datagramPostRoutingHook(packet) == INetfilter::IHook::ACCEPT)
        fragmentAndSend(packet);
}

void Ipv4::setComputedCrc(Ptr<Ipv4Header>& ipv4Header)
{
    ASSERT(crcMode == CRC_COMPUTED);
    ipv4Header->setCrc(0);
    MemoryOutputStream ipv4HeaderStream;
    Chunk::serialize(ipv4HeaderStream, ipv4Header);
    // compute the CRC
    uint16_t crc = TcpIpChecksum::checksum(ipv4HeaderStream.getData());
    ipv4Header->setCrc(crc);
}

void Ipv4::insertCrc(const Ptr<Ipv4Header>& ipv4Header)
{
    CrcMode crcMode = ipv4Header->getCrcMode();
    switch (crcMode) {
        case CRC_DECLARED_CORRECT:
            // if the CRC mode is declared to be correct, then set the CRC to an easily recognizable value
            ipv4Header->setCrc(0xC00D);
            break;
        case CRC_DECLARED_INCORRECT:
            // if the CRC mode is declared to be incorrect, then set the CRC to an easily recognizable value
            ipv4Header->setCrc(0xBAAD);
            break;
        case CRC_COMPUTED: {
            // if the CRC mode is computed, then compute the CRC and set it
            // this computation is delayed after the routing decision, see INetfilter hook
            ipv4Header->setCrc(0x0000); // make sure that the CRC is 0 in the Udp header before computing the CRC
            MemoryOutputStream ipv4HeaderStream;
            Chunk::serialize(ipv4HeaderStream, ipv4Header);
            // compute the CRC
            uint16_t crc = TcpIpChecksum::checksum(ipv4HeaderStream.getData());
            ipv4Header->setCrc(crc);
            break;
        }
        default:
            throw cRuntimeError("Unknown CRC mode: %d", (int)crcMode);
    }
}

void Ipv4::fragmentAndSend(Packet *packet)
{
    const InterfaceEntry *destIE = ift->getInterfaceById(packet->getTag<InterfaceReq>()->getInterfaceId());
    Ipv4Address nextHopAddr = getNextHop(packet);
    if (nextHopAddr.isUnspecified()) {
        nextHopAddr = packet->peekAtFront<Ipv4Header>()->getDestAddress();
        packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(nextHopAddr);
    }

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();

    // hop counter check
    if (ipv4Header->getTimeToLive() <= 0) {
        // drop datagram, destruction responsibility in ICMP
        PacketDropDetails details;
        details.setReason(HOP_LIMIT_REACHED);
        emit(packetDroppedSignal, packet, &details);
        EV_WARN << "datagram TTL reached zero, sending ICMP_TIME_EXCEEDED\n";
        sendIcmpError(packet, -1    /*TODO*/, ICMP_TIME_EXCEEDED, 0);
        numDropped++;
        return;
    }

    int mtu = destIE->getMtu();

    // send datagram straight out if it doesn't require fragmentation (note: mtu==0 means infinite mtu)
    if (mtu == 0 || packet->getByteLength() <= mtu) {
        if (crcMode == CRC_COMPUTED) {
            auto ipv4Header = removeNetworkProtocolHeader<Ipv4Header>(packet);
            setComputedCrc(ipv4Header);
            insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header);
        }
        sendDatagramToOutput(packet);
        return;
    }

    // if "don't fragment" bit is set, throw datagram away and send ICMP error message
    if (ipv4Header->getDontFragment()) {
        PacketDropDetails details;
        emit(packetDroppedSignal, packet, &details);
        EV_WARN << "datagram larger than MTU and don't fragment bit set, sending ICMP_DESTINATION_UNREACHABLE\n";
        sendIcmpError(packet, -1    /*TODO*/, ICMP_DESTINATION_UNREACHABLE,
                ICMP_DU_FRAGMENTATION_NEEDED);
        numDropped++;
        return;
    }

    // FIXME some IP options should not be copied into each fragment, check their COPY bit
    int headerLength = B(ipv4Header->getHeaderLength()).get();
    int payloadLength = B(packet->getDataLength()).get() - headerLength;
    int fragmentLength = ((mtu - headerLength) / 8) * 8;    // payload only (without header)
    int offsetBase = ipv4Header->getFragmentOffset();
    if (fragmentLength <= 0)
        throw cRuntimeError("Cannot fragment datagram: MTU=%d too small for header size (%d bytes)", mtu, headerLength); // exception and not ICMP because this is likely a simulation configuration error, not something one wants to simulate

    int noOfFragments = (payloadLength + fragmentLength - 1) / fragmentLength;
    EV_DETAIL << "Breaking datagram into " << noOfFragments << " fragments\n";

    // create and send fragments
    std::string fragMsgName = packet->getName();
    fragMsgName += "-frag-";

    int offset = 0;
    while (offset < payloadLength) {
        bool lastFragment = (offset + fragmentLength >= payloadLength);
        // length equal to fragmentLength, except for last fragment;
        int thisFragmentLength = lastFragment ? payloadLength - offset : fragmentLength;

        std::string curFragName = fragMsgName + std::to_string(offset);
        if (lastFragment)
            curFragName += "-last";
        Packet *fragment = new Packet(curFragName.c_str());     //TODO add offset or index to fragment name

        //copy Tags from packet to fragment
        fragment->copyTags(*packet);

        ASSERT(fragment->getByteLength() == 0);
        auto fraghdr = staticPtrCast<Ipv4Header>(ipv4Header->dupShared());
        const auto& fragData = packet->peekDataAt(B(headerLength + offset), B(thisFragmentLength));
        ASSERT(fragData->getChunkLength() == B(thisFragmentLength));
        fragment->insertAtBack(fragData);

        // "more fragments" bit is unchanged in the last fragment, otherwise true
        if (!lastFragment)
            fraghdr->setMoreFragments(true);

        fraghdr->setFragmentOffset(offsetBase + offset);
        fraghdr->setTotalLengthField(B(headerLength + thisFragmentLength));
        if (crcMode == CRC_COMPUTED)
            setComputedCrc(fraghdr);

        fragment->insertAtFront(fraghdr);
        ASSERT(fragment->getByteLength() == headerLength + thisFragmentLength);
        sendDatagramToOutput(fragment);
        offset += thisFragmentLength;
    }

    delete packet;
}

MarkingInfoHolder Ipv4::apply_SRPT_marking(Packet *transportPacket,
        unsigned long hash_of_flow, unsigned long hash_of_packet) {
    // applying srpt marking
    EV << "Marking packet " << transportPacket->str() << " with SRPT" << endl;

    // Check if packet has been seen before.
    simtime_t now = simTime();
    MarkingInfoHolder marking_info_holder;

    auto protocol_info_tag = transportPacket->getTag<PayloadInfoTag>();
    b payload_length = protocol_info_tag->getPayload_length();
    b total_length = protocol_info_tag->getTotal_length();
    b offset = protocol_info_tag->getOffset();

    auto flow_found = flow_hash_table.find(hash_of_flow);
    if (flow_found != flow_hash_table.end()) {
        EV << "Flow with hash: " << hash_of_flow << " found." << endl;
        if (now - flow_found->second->last_updated < 0)
            throw cRuntimeError("How is now - flow_found->second->last_updated < 0 even possible?");


        // check if packet is a control packet (payloadlength = 0)
        if (payload_length == b(0)) {
            marking_info_holder.flow_let_id = flow_found->second->flow_let_id;
            marking_info_holder.is_control_message = true;
            marking_info_holder.seq = 0;
            marking_info_holder.ret_count = 0;
            return marking_info_holder;
        }

        auto packet_found = flow_found->second->packet_hash_table.find(hash_of_packet);
        if (packet_found != flow_found->second->packet_hash_table.end()) {
            // packet found -> re-transmission
            EV << "Packet with hash: " << hash_of_packet << " found and is being retransmitted." << endl;
            packet_found->second->ret_count++;
            marking_info_holder.seq = packet_found->second->seq;
            marking_info_holder.ret_count = packet_found->second->ret_count;
            marking_info_holder.is_first_packet = packet_found->second->is_first_packet;
            // flow_let_id shouldn't have changed at this point
            marking_info_holder.flow_let_id = packet_found->second->flow_let_id;

            if (now - flow_found->second->last_updated > delta) {
                // new flowlet -> old coflow
                EV << "new flowlet, old coflow." << endl;
                flow_found->second->ret_count++;
            } else {
                // old flowlet -> old coflow
                // nothing happens :)
                EV << "old flowlet, old coflow." << endl;
            }
        } else {
            // new packet
            EV << "No packet with hash: " << hash_of_packet << " found" << endl;

            // no need to consider flowlet
            auto protocol_info_tag = transportPacket->getTag<PayloadInfoTag>();
            b payload_length = protocol_info_tag->getPayload_length();
            b total_length = protocol_info_tag->getTotal_length();
            b offset = protocol_info_tag->getOffset();

            marking_info_holder.seq = (total_length - offset).get();
            if (offset == b(0)) {
                // new coflow
                // todo: for now we don't use MAX_FLOW_LET_ID for SRPT
                marking_info_holder.ret_count = 0;
                flow_found->second->ret_count = marking_info_holder.ret_count;
                marking_info_holder.is_first_packet = true;
                flow_found->second->flow_let_id++;
//                flow_found->second->flow_let_id %= MAX_FLOW_LET_ID;
                marking_info_holder.flow_let_id = flow_found->second->flow_let_id;
            } else {
                // old coflow
                marking_info_holder.ret_count = flow_found->second->ret_count;
                marking_info_holder.is_first_packet = false;
                marking_info_holder.flow_let_id = flow_found->second->flow_let_id;
            }

            auto packet_info_node = new LRUPacketInfo(marking_info_holder.seq,
                    marking_info_holder.ret_count, marking_info_holder.flow_let_id,
                    marking_info_holder.is_first_packet);
            flow_found->second->packet_hash_table.insert(std::pair<unsigned long, LRUPacketInfo*>(hash_of_packet,
                    packet_info_node));
        }

        // update the flow's last_updated and re-insert it in lru tracker
        if (flow_hash_table_size > 0) {
            flow_lru_tracker.erase(flow_found->second->last_updated);
            flow_lru_tracker.emplace_hint(flow_lru_tracker.end(), now, hash_of_flow);
        }
        flow_found->second->last_updated = now;


    } else {

        // check if packet is a control packet (payloadlength = 0)
        if (payload_length == b(0)) {
            marking_info_holder.flow_let_id = 0;
            marking_info_holder.is_control_message = true;
            marking_info_holder.seq = 0;
            marking_info_holder.ret_count = 0;
            return marking_info_holder;
        }

        // New flowlet + new coflow(response)
        EV << "No flow with hash: " << hash_of_flow << " found, creating a new flow with seq = 0 and ret_count = 0" << endl;

        marking_info_holder.seq = (total_length - offset).get();
        if (offset == b(0)) {
            // new coflow
            marking_info_holder.is_first_packet = true;
        }
        marking_info_holder.ret_count = 0;
        marking_info_holder.flow_let_id = 0;
        // seq of flow here doesn't matter
        auto flow_info_node = new LRUFlowInfo(marking_info_holder.seq,
                marking_info_holder.ret_count, now, marking_info_holder.flow_let_id);
        auto packet_info_node = new LRUPacketInfo(marking_info_holder.seq,
                marking_info_holder.ret_count, marking_info_holder.flow_let_id,
                marking_info_holder.is_first_packet);
        flow_info_node->packet_hash_table.insert(std::pair<unsigned long, LRUPacketInfo*>(hash_of_packet, packet_info_node));
        flow_hash_table.insert(std::pair<unsigned long, LRUFlowInfo*>(hash_of_flow, flow_info_node));
        if (flow_hash_table_size > 0) {
            flow_lru_tracker.emplace_hint(flow_lru_tracker.end(), now, hash_of_flow);
        }
    }
    return marking_info_holder;
}


MarkingInfoHolder Ipv4::apply_LAS_marking(Packet *transportPacket,
        unsigned long hash_of_flow, unsigned long hash_of_packet) {
    // applying LAS marking
    EV << "Marking packet " << transportPacket->str() << " with LAS" << endl;
    simtime_t now = simTime();
    MarkingInfoHolder marking_info_holder;

    auto flow_found = flow_hash_table.find(hash_of_flow);
    if (flow_found != flow_hash_table.end()) {
        EV << "Flow with hash: " << hash_of_flow << " found." << endl;
        if (now - flow_found->second->last_updated < 0)
            throw cRuntimeError("How is now - flow_found->second->last_updated < 0 even possible?");


        auto packet_found = flow_found->second->packet_hash_table.find(hash_of_packet);
        if (packet_found != flow_found->second->packet_hash_table.end()) {
            // packet found -> re-transmission
            EV << "Packet with hash: " << hash_of_packet << " found and is being retransmitted." << endl;
            marking_info_holder.seq = packet_found->second->seq;
            packet_found->second->ret_count++;
            marking_info_holder.ret_count = packet_found->second->ret_count;
            marking_info_holder.flow_let_id = packet_found->second->flow_let_id;

            if (now - flow_found->second->last_updated > delta) {
                // new flowlet -> old coflow
                num_timeouts_marking++;
                EV << "new flowlet, old coflow." << endl;
                flow_found->second->ret_count++;
            } else {
                // old flowlet -> old coflow
                // nothing happens :)
                EV << "old flowlet, old coflow." << endl;
            }

        } else {
            // new packet
            EV << "No packet with hash: " << hash_of_packet << " found" << endl;
            if (now - flow_found->second->last_updated > delta) {
                // new flowlet -> new coflow
                num_timeouts_marking++;
                marking_info_holder.seq = 0;
                marking_info_holder.ret_count = 0;
                flow_found->second->ret_count = marking_info_holder.ret_count;
                flow_found->second->seq = marking_info_holder.seq;
                flow_found->second->flow_let_id++;
                marking_info_holder.flow_let_id = flow_found->second->flow_let_id;
            } else {
                // old flowlet -> old coflow
                flow_found->second->seq++;
                marking_info_holder.seq = flow_found->second->seq;
                marking_info_holder.ret_count = flow_found->second->ret_count;
                marking_info_holder.flow_let_id = flow_found->second->flow_let_id;
            }
            auto packet_info_node = new LRUPacketInfo(marking_info_holder.seq,
                    marking_info_holder.ret_count, marking_info_holder.flow_let_id);
            flow_found->second->packet_hash_table.insert(std::pair<unsigned long, LRUPacketInfo*>(hash_of_packet,
                    packet_info_node));
        }

        // update the flow's last_updated and re-insert it in lru tracker
        if (flow_hash_table_size > 0) {
            flow_lru_tracker.erase(flow_found->second->last_updated);
            flow_lru_tracker.emplace_hint(flow_lru_tracker.end(), now, hash_of_flow);
        }
        flow_found->second->last_updated = now;

    } else {

        // New flowlet + new coflow(response)
        EV << "No flow with hash: " << hash_of_flow << " found, creating a new flow with seq = 0 and ret_count = 0" << endl;
        marking_info_holder.seq = 0;
        marking_info_holder.ret_count = 0;
        marking_info_holder.flow_let_id = 0;
        auto flow_info_node = new LRUFlowInfo(marking_info_holder.seq,
                marking_info_holder.ret_count, now, marking_info_holder.flow_let_id);
        auto packet_info_node = new LRUPacketInfo(marking_info_holder.seq,
                marking_info_holder.ret_count, marking_info_holder.flow_let_id);
        flow_info_node->packet_hash_table.insert(std::pair<unsigned long, LRUPacketInfo*>(hash_of_packet, packet_info_node));
        flow_hash_table.insert(std::pair<unsigned long, LRUFlowInfo*>(hash_of_flow, flow_info_node));
        if (flow_hash_table_size > 0) {
            flow_lru_tracker.emplace_hint(flow_lru_tracker.end(), now, hash_of_flow);
        }
    }
    return marking_info_holder;
}

void Ipv4::apply_marking(Packet *transportPacket) {

    auto ipv4Header = transportPacket->removeAtFront<Ipv4Header>();

    // I hash src_ip, dst_ip, src_port, dst_port, tcp_seq_num
    auto tcp_header = transportPacket->peekAtFront<tcp::TcpHeader>();
    std::string src_ip = ipv4Header->getSourceAddress().str();
    std::string dst_ip = ipv4Header->getDestinationAddress().str();
    std::string src_port = std::to_string(tcp_header->getSourcePort());
    std::string dst_port = std::to_string(tcp_header->getDestinationPort());
    std::string tcp_seq_num = std::to_string(tcp_header->getSequenceNo());
    std::string packet_name = transportPacket->getName();
    std::string tcp_ack_num = std::to_string(tcp_header->getAckNo());
    unsigned long hash_of_packet = packet_hash(src_ip + dst_ip + src_port + dst_port + tcp_seq_num + tcp_ack_num + packet_name);
    unsigned long hash_of_flow = flow_hash(src_ip + dst_ip + src_port + dst_port);
    EV << "Info used for packet hash is: " << src_ip + dst_ip + src_port + dst_port + tcp_seq_num + tcp_ack_num + packet_name << endl;
    EV << "Packet hash is: " << hash_of_packet << endl;
    EV << "Info used for flow hash is: " << src_ip + dst_ip + src_port + dst_port << endl;
    EV << "Flow hash is: " << hash_of_flow << endl;

    transportPacket->insertAtFront(ipv4Header);

    MarkingInfoHolder marking_info_holder;
    switch (marking_type) {
        case MARKING_LAS:
            marking_info_holder = apply_LAS_marking(transportPacket, hash_of_flow, hash_of_packet);
            break;
        case MARKING_SRPT:
            marking_info_holder = apply_SRPT_marking(transportPacket, hash_of_flow, hash_of_packet);
            break;
        default:
            throw cRuntimeError("No known marking type!");
    }
    EV << "Sending packet " << transportPacket->str() << " in the marking component" << endl;

    // add the info to options header
    for (unsigned int i = 0; i < ipv4Header->getOptionArraySize(); i++) {
        TlvOptionBase *option = &ipv4Header->getOptionForUpdate(i);
        if (option->getType() == IPOPTION_V2_MARKING) {
            auto opt = check_and_cast<Ipv4OptionV2Marking*>(option);
            opt->setSeq(marking_info_holder.seq);
            opt->setRet_num(marking_info_holder.ret_count);
            opt->setFlow_let_id(marking_info_holder.flow_let_id);
            opt->setIs_first_packet(marking_info_holder.is_first_packet);
            opt->setIs_control_message(marking_info_holder.is_control_message);
            break;
        }
    }

    // remove the information if the connection is closing
    auto flow_found2 = flow_hash_table.find(hash_of_flow);
    if (flow_found2 != flow_hash_table.end() &&
            flow_hash_table_size < 0 &&
            flow_found2->second->should_close_after_sending) {
        EV << "Closing the flow with hash: " << hash_of_flow << endl;
        // to prevent ram overflow, remove the connection information
        for (std::unordered_map<unsigned long, LRUPacketInfo*>::iterator it =
                flow_found2->second->packet_hash_table.begin();
                it != flow_found2->second->packet_hash_table.end(); it++) {
            delete it->second;
        }
        flow_found2->second->packet_hash_table.clear();
        if (flow_hash_table_size > 0)
            flow_lru_tracker.erase(flow_found2->second->last_updated);
        delete flow_found2->second;
        flow_hash_table.erase(flow_found2);
    }

    // no checks if packet is control message in SRPT
    if (marking_type == MARKING_SRPT && marking_info_holder.is_control_message) {
        EV << "Message is a control message, skiping hash table checks!" << endl;
        return;
    }

    // Apply size constraints to the tables
    if (flow_hash_table_size > 0 && flow_hash_table.size() > flow_hash_table_size) {
        // delete a flow info and all packet info inside it
        if (flow_hash_table.size() > flow_hash_table_size + 1) {
            throw cRuntimeError("how did you let flow_hash_table size get this large!");
        }
        // the highest use time is stored last as it is sorted, so we have to remove begin
        unsigned long hash_of_flow_to_be_deleted = flow_lru_tracker.begin()->second;
        flow_lru_tracker.erase(flow_lru_tracker.begin());
        auto flow_to_be_deleted = flow_hash_table.find(hash_of_flow_to_be_deleted);
        for (std::unordered_map<unsigned long, LRUPacketInfo*>::iterator it =
                flow_to_be_deleted->second->packet_hash_table.begin();
                it != flow_to_be_deleted->second->packet_hash_table.end(); it++) {
            delete it->second;
        }
        delete flow_to_be_deleted->second;
        flow_hash_table.erase(flow_to_be_deleted);
    }
}

void Ipv4::encapsulate(Packet *transportPacket)
{
    const auto& ipv4Header = makeShared<Ipv4Header>();

    auto l3AddressReq = transportPacket->removeTag<L3AddressReq>();
    Ipv4Address src = l3AddressReq->getSrcAddress().toIpv4();
    bool nonLocalSrcAddress = l3AddressReq->getNonLocalSrcAddress();
    Ipv4Address dest = l3AddressReq->getDestAddress().toIpv4();
    delete l3AddressReq;

    ipv4Header->setProtocolId((IpProtocolId)ProtocolGroup::ipprotocol.getProtocolNumber(transportPacket->getTag<PacketProtocolTag>()->getProtocol()));

    auto hopLimitReq = transportPacket->removeTagIfPresent<HopLimitReq>();
    short ttl = (hopLimitReq != nullptr) ? hopLimitReq->getHopLimit() : -1;
    delete hopLimitReq;
    bool dontFragment = false;
    if (auto dontFragmentReq = transportPacket->removeTagIfPresent<FragmentationReq>()) {
        dontFragment = dontFragmentReq->getDontFragment();
        delete dontFragmentReq;
    }

    // set source and destination address
    ipv4Header->setDestAddress(dest);

    // when source address was given, use it; otherwise it'll get the address
    // of the outgoing interface after routing
    if (!src.isUnspecified()) {
        if (!nonLocalSrcAddress && rt->getInterfaceByAddress(src) == nullptr)
        // if interface parameter does not match existing interface, do not send datagram
            throw cRuntimeError("Wrong source address %s in (%s)%s: no interface with such address",
                    src.str().c_str(), transportPacket->getClassName(), transportPacket->getFullName());

        ipv4Header->setSrcAddress(src);
    }

//    // set other fields
//    if (DscpReq *dscpReq = transportPacket->removeTagIfPresent<DscpReq>()) {
//        ipv4Header->setDiffServCodePoint(dscpReq->getDifferentiatedServicesCodePoint());
//        delete dscpReq;
//    }
//    if (EcnReq *ecnReq = transportPacket->removeTagIfPresent<EcnReq>()) {
//        ipv4Header->setExplicitCongestionNotification(ecnReq->getExplicitCongestionNotification());
//        delete ecnReq;
//    }

    // set other fields
//    if (TosReq *tosReq = transportPacket->removeTagIfPresent<TosReq>()) {
//        ipv4Header->setTypeOfService(tosReq->getTos());
//        delete tosReq;
//        if (transportPacket->findTag<DscpReq>())
//            throw cRuntimeError("TosReq and DscpReq found together");
//        if (transportPacket->findTag<EcnReq>())
//            throw cRuntimeError("TosReq and EcnReq found together");
//    }
    if (DscpReq *dscpReq = transportPacket->removeTagIfPresent<DscpReq>()) {
        ipv4Header->setDscp(dscpReq->getDifferentiatedServicesCodePoint());
        delete dscpReq;
    }
    if (EcnReq *ecnReq = transportPacket->removeTagIfPresent<EcnReq>()) {
        ipv4Header->setEcn(ecnReq->getExplicitCongestionNotification());
        delete ecnReq;
    }

    ipv4Header->setIdentification(curFragmentId++);
    ipv4Header->setMoreFragments(false);
    ipv4Header->setDontFragment(dontFragment);
    ipv4Header->setFragmentOffset(0);

    if (ttl != -1) {
        ASSERT(ttl > 0);
    }
    else if (ipv4Header->getDestAddress().isLinkLocalMulticast())
        ttl = 1;
    else if (ipv4Header->getDestAddress().isMulticast())
        ttl = defaultMCTimeToLive;
    else
        ttl = defaultTimeToLive;
    ipv4Header->setTimeToLive(ttl);

    if (Ipv4OptionsReq *optReq = transportPacket->removeTagIfPresent<Ipv4OptionsReq>()) {
        for (size_t i = 0; i < optReq->getOptionArraySize(); i++) {
            auto opt = optReq->dropOption(i);
            ipv4Header->addOption(opt);
            ipv4Header->addChunkLength(B(opt->getLength()));
        }
        delete optReq;
    }

    // v2 marking component
    if (should_use_v2_marking) {
        // adding empty overhead on the packet length. These values are set before the packet is sent
        EV << "Assigning empty v2 marking option for now " << endl;
        auto marking_options = new Ipv4OptionV2Marking();
        marking_options->setRet_num(0);
        marking_options->setSeq(0);
        marking_options->setFlow_let_id(-1);
        marking_options->setIs_first_packet(false);
        ipv4Header->addOption(marking_options);
        ipv4Header->addChunkLength(B(marking_options->getLength()));
    }

    ASSERT(ipv4Header->getChunkLength() <= IPv4_MAX_HEADER_LENGTH);
    ipv4Header->setHeaderLength(ipv4Header->getChunkLength());
    ipv4Header->setTotalLengthField(ipv4Header->getChunkLength() + transportPacket->getDataLength());
    ipv4Header->setCrcMode(crcMode);
    ipv4Header->setCrc(0);
    switch (crcMode) {
        case CRC_DECLARED_CORRECT:
            // if the CRC mode is declared to be correct, then set the CRC to an easily recognizable value
            ipv4Header->setCrc(0xC00D);
            break;
        case CRC_DECLARED_INCORRECT:
            // if the CRC mode is declared to be incorrect, then set the CRC to an easily recognizable value
            ipv4Header->setCrc(0xBAAD);
            break;
        case CRC_COMPUTED: {
            ipv4Header->setCrc(0);
            // crc will be calculated in fragmentAndSend()
            break;
        }
        default:
            throw cRuntimeError("Unknown CRC mode");
    }

    insertNetworkProtocolHeader(transportPacket, Protocol::ipv4, ipv4Header);
    // setting Ipv4 options is currently not supported
}

void Ipv4::sendDatagramToOutput(Packet *packet)
{
    const InterfaceEntry *ie = ift->getInterfaceById(packet->getTag<InterfaceReq>()->getInterfaceId());
    auto nextHopAddressReq = packet->removeTag<NextHopAddressReq>();
    Ipv4Address nextHopAddr = nextHopAddressReq->getNextHopAddress().toIpv4();
    delete nextHopAddressReq;
    if (!ie->isBroadcast() || ie->getMacAddress().isUnspecified()) // we can't do ARP
        sendPacketToNIC(packet);
    else {
        MacAddress nextHopMacAddr = resolveNextHopMacAddress(packet, nextHopAddr, ie);
        if (nextHopMacAddr.isUnspecified()) {
            EV_INFO << "Pending " << packet << " to ARP resolution.\n";
            pendingPackets[nextHopAddr].insert(packet);
        }
        else {
            ASSERT2(pendingPackets.find(nextHopAddr) == pendingPackets.end(), "Ipv4-ARP error: nextHopAddr found in ARP table, but Ipv4 queue for nextHopAddr not empty");
            packet->addTagIfAbsent<MacAddressReq>()->setDestAddress(nextHopMacAddr);
            sendPacketToNIC(packet);
        }
    }
}

void Ipv4::arpResolutionCompleted(IArp::Notification *entry)
{
    if (entry->l3Address.getType() != L3Address::IPv4)
        return;
    auto it = pendingPackets.find(entry->l3Address.toIpv4());
    if (it != pendingPackets.end()) {
        cPacketQueue& packetQueue = it->second;
        EV << "ARP resolution completed for " << entry->l3Address << ". Sending " << packetQueue.getLength()
           << " waiting packets from the queue\n";

        while (!packetQueue.isEmpty()) {
            Packet *packet = check_and_cast<Packet *>(packetQueue.pop());
            EV << "Sending out queued packet " << packet << "\n";
            packet->addTagIfAbsent<InterfaceReq>()->setInterfaceId(entry->ie->getInterfaceId());
            packet->addTagIfAbsent<MacAddressReq>()->setDestAddress(entry->macAddress);
            sendPacketToNIC(packet);
        }
        pendingPackets.erase(it);
    }
}

void Ipv4::arpResolutionTimedOut(IArp::Notification *entry)
{
    if (entry->l3Address.getType() != L3Address::IPv4)
        return;
    auto it = pendingPackets.find(entry->l3Address.toIpv4());
    if (it != pendingPackets.end()) {
        cPacketQueue& packetQueue = it->second;
        EV << "ARP resolution failed for " << entry->l3Address << ",  dropping " << packetQueue.getLength() << " packets\n";
        for (int i = 0; i < packetQueue.getLength(); i++) {
            auto packet = packetQueue.get(i);
            PacketDropDetails details;
            details.setReason(ADDRESS_RESOLUTION_FAILED);
            emit(packetDroppedSignal, packet, &details);
        }
        packetQueue.clear();
        pendingPackets.erase(it);
    }
}

MacAddress Ipv4::resolveNextHopMacAddress(cPacket *packet, Ipv4Address nextHopAddr, const InterfaceEntry *destIE)
{
    if (nextHopAddr.isLimitedBroadcastAddress() || nextHopAddr == destIE->getProtocolData<Ipv4InterfaceData>()->getNetworkBroadcastAddress()) {
        EV_DETAIL << "destination address is broadcast, sending packet to broadcast MAC address\n";
        return MacAddress::BROADCAST_ADDRESS;
    }

    if (nextHopAddr.isMulticast()) {
        MacAddress macAddr = MacAddress::makeMulticastAddress(nextHopAddr);
        EV_DETAIL << "destination address is multicast, sending packet to MAC address " << macAddr << "\n";
        return macAddr;
    }

    return arp->resolveL3Address(nextHopAddr, destIE);
}

void Ipv4::sendPacketToNIC(Packet *packet)
{
    EV_INFO << "Sending " << packet << " to output interface = " << ift->getInterfaceById(packet->getTag<InterfaceReq>()->getInterfaceId())->getInterfaceName() << ".\n";
    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ipv4);
    packet->addTagIfAbsent<DispatchProtocolInd>()->setProtocol(&Protocol::ipv4);
    delete packet->removeTagIfPresent<DispatchProtocolReq>();
    ASSERT(packet->findTag<InterfaceReq>() != nullptr);
    ip_packet_sent_counter++;
    std::string packet_name = packet->getName();
    if (packet_name.find("tcpseg") != std::string::npos)
        ip_data_packet_sent_counter++;
    send(packet, "queueOut");
}

// NetFilter:

void Ipv4::registerHook(int priority, INetfilter::IHook *hook)
{
    Enter_Method("registerHook()");
    NetfilterBase::registerHook(priority, hook);
}

void Ipv4::unregisterHook(INetfilter::IHook *hook)
{
    Enter_Method("unregisterHook()");
    NetfilterBase::unregisterHook(hook);
}

void Ipv4::dropQueuedDatagram(const Packet *packet)
{
    Enter_Method("dropQueuedDatagram()");
    for (auto iter = queuedDatagramsForHooks.begin(); iter != queuedDatagramsForHooks.end(); iter++) {
        if (iter->packet == packet) {
            delete packet;
            queuedDatagramsForHooks.erase(iter);
            return;
        }
    }
}

void Ipv4::reinjectQueuedDatagram(const Packet *packet)
{
    Enter_Method("reinjectDatagram()");
    for (auto iter = queuedDatagramsForHooks.begin(); iter != queuedDatagramsForHooks.end(); iter++) {
        if (iter->packet == packet) {
            auto *qPacket = iter->packet;
            take(qPacket);
            switch (iter->hookType) {
                case INetfilter::IHook::LOCALOUT:
                    datagramLocalOut(qPacket);
                    break;

                case INetfilter::IHook::PREROUTING:
                    preroutingFinish(qPacket);
                    break;

                case INetfilter::IHook::POSTROUTING:
                    fragmentAndSend(qPacket);
                    break;

                case INetfilter::IHook::LOCALIN:
                    reassembleAndDeliverFinish(qPacket);
                    break;

                case INetfilter::IHook::FORWARD:
                    routeUnicastPacketFinish(qPacket);
                    break;

                default:
                    throw cRuntimeError("Unknown hook ID: %d", (int)(iter->hookType));
                    break;
            }
            queuedDatagramsForHooks.erase(iter);
            return;
        }
    }
}

INetfilter::IHook::Result Ipv4::datagramPreRoutingHook(Packet *packet)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramPreRoutingHook(packet);
        switch (r) {
            case INetfilter::IHook::ACCEPT:
                break;    // continue iteration

            case INetfilter::IHook::DROP:
                delete packet;
                return r;

            case INetfilter::IHook::QUEUE:
                queuedDatagramsForHooks.push_back(QueuedDatagramForHook(packet, INetfilter::IHook::PREROUTING));
                return r;

            case INetfilter::IHook::STOLEN:
                return r;

            default:
                throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

INetfilter::IHook::Result Ipv4::datagramForwardHook(Packet *packet)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramForwardHook(packet);
        switch (r) {
            case INetfilter::IHook::ACCEPT:
                break;    // continue iteration

            case INetfilter::IHook::DROP:
                delete packet;
                return r;

            case INetfilter::IHook::QUEUE:
                queuedDatagramsForHooks.push_back(QueuedDatagramForHook(packet, INetfilter::IHook::FORWARD));
                return r;

            case INetfilter::IHook::STOLEN:
                return r;

            default:
                throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

INetfilter::IHook::Result Ipv4::datagramPostRoutingHook(Packet *packet)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramPostRoutingHook(packet);
        switch (r) {
            case INetfilter::IHook::ACCEPT:
                break;    // continue iteration

            case INetfilter::IHook::DROP:
                delete packet;
                return r;

            case INetfilter::IHook::QUEUE:
                queuedDatagramsForHooks.push_back(QueuedDatagramForHook(packet, INetfilter::IHook::POSTROUTING));
                return r;

            case INetfilter::IHook::STOLEN:
                return r;

            default:
                throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

void Ipv4::handleStartOperation(LifecycleOperation *operation)
{
    start();
}

void Ipv4::handleStopOperation(LifecycleOperation *operation)
{
    // TODO: stop should send and wait pending packets
    stop();
}

void Ipv4::handleCrashOperation(LifecycleOperation *operation)
{
    stop();
}

void Ipv4::start()
{
}

void Ipv4::stop()
{
    flush();
    for (auto it : socketIdToSocketDescriptor)
        delete it.second;
    socketIdToSocketDescriptor.clear();
}

void Ipv4::flush()
{
    EV_DEBUG << "Ipv4::flush(): pending packets:\n";
    for (auto & elem : pendingPackets) {
        EV_DEBUG << "Ipv4::flush():    " << elem.first << ": " << elem.second.str() << endl;
        elem.second.clear();
    }
    pendingPackets.clear();

    EV_DEBUG << "Ipv4::flush(): packets in hooks: " << queuedDatagramsForHooks.size() << endl;
    for (auto & elem : queuedDatagramsForHooks) {
        delete elem.packet;
    }
    queuedDatagramsForHooks.clear();

    fragbuf.flush();
}

INetfilter::IHook::Result Ipv4::datagramLocalInHook(Packet *packet)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramLocalInHook(packet);
        switch (r) {
            case INetfilter::IHook::ACCEPT:
                break;    // continue iteration

            case INetfilter::IHook::DROP:
                delete packet;
                return r;

            case INetfilter::IHook::QUEUE: {
                if (packet->getOwner() != this)
                    throw cRuntimeError("Model error: netfilter hook changed the owner of queued datagram '%s'", packet->getFullName());
                queuedDatagramsForHooks.push_back(QueuedDatagramForHook(packet, INetfilter::IHook::LOCALIN));
                return r;
            }

            case INetfilter::IHook::STOLEN:
                return r;

            default:
                throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

INetfilter::IHook::Result Ipv4::datagramLocalOutHook(Packet *packet)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramLocalOutHook(packet);
        switch (r) {
            case INetfilter::IHook::ACCEPT:
                break;    // continue iteration

            case INetfilter::IHook::DROP:
                delete packet;
                return r;

            case INetfilter::IHook::QUEUE:
                queuedDatagramsForHooks.push_back(QueuedDatagramForHook(packet, INetfilter::IHook::LOCALOUT));
                return r;

            case INetfilter::IHook::STOLEN:
                return r;

            default:
                throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

void Ipv4::receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details)
{
    Enter_Method_Silent();

    if (signalID == IArp::arpResolutionCompletedSignal) {
        arpResolutionCompleted(check_and_cast<IArp::Notification *>(obj));
    }
    if (signalID == IArp::arpResolutionFailedSignal) {
        arpResolutionTimedOut(check_and_cast<IArp::Notification *>(obj));
    }
}

void Ipv4::sendIcmpError(Packet *origPacket, int inputInterfaceId, IcmpType type, IcmpCode code)
{
    icmp->sendErrorMessage(origPacket, inputInterfaceId, type, code);
}

} // namespace inet
