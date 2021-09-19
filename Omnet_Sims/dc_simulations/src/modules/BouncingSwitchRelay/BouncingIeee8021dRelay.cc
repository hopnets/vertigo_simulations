// Copyright (C) 2013 OpenSim Ltd.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//
// Author: Benjamin Martin Seregi

#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/linklayer/ieee8022/Ieee8022LlcHeader_m.h"
#include "inet/networklayer/common/InterfaceEntry.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/transportlayer/tcp_common/TcpHeader_m.h"
#include "inet/linklayer/ethernet/EtherPhyFrame_m.h"
#include "inet/queueing/queue/PacketQueue.h"
#include "BouncingIeee8021dRelay.h"
#include "inet/applications/tcpapp/GenericAppMsg_m.h"

using namespace inet;

Define_Module(BouncingIeee8021dRelay);


simsignal_t BouncingIeee8021dRelay::feedBackPacketDroppedSignal = registerSignal("feedBackPacketDropped");
simsignal_t BouncingIeee8021dRelay::feedBackPacketDroppedPortSignal = registerSignal("feedBackPacketDroppedPort");
simsignal_t BouncingIeee8021dRelay::feedBackPacketGeneratedSignal = registerSignal("feedBackPacketGenerated");
simsignal_t BouncingIeee8021dRelay::bounceLimitPassedSignal = registerSignal("bounceLimitPassed");
simsignal_t BouncingIeee8021dRelay::burstyPacketReceivedSignal = registerSignal("burstyPacketReceived");

BouncingIeee8021dRelay::BouncingIeee8021dRelay()
{
}

BouncingIeee8021dRelay::~BouncingIeee8021dRelay()
{
    recordScalar("lightInRelayPacketDropCounter", light_in_relay_packet_drop_counter);
}

void BouncingIeee8021dRelay::initialize(int stage)
{
    LayeredProtocolBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // statistics
        numDispatchedBDPUFrames = numDispatchedNonBPDUFrames = numDeliveredBDPUsToSTP = 0;
        numReceivedBPDUsFromSTP = numReceivedNetworkFrames = numDroppedFrames = 0;
        isStpAware = par("hasStp");

        macTable = getModuleFromPar<LSIMacAddressTable>(par("macTableModule"), this);
        ifTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);

        use_ecmp = getAncestorPar("useECMP");
        use_power_of_n_lb = getAncestorPar("use_power_of_n_lb");
        random_power_factor = getAncestorPar("random_power_factor");

        if ((!use_ecmp && !use_power_of_n_lb)) {
            // TODO if you want to have the option to don't use no LB, comment out this if.
            throw cRuntimeError("No load balancing technique used. Are you sure you want this?");
        }

        if (use_ecmp && use_power_of_n_lb)
            throw cRuntimeError("More than one LB technique is chosen. WTF?");

        learn_mac_addresses = par("learn_mac_addresses");

        //DIBS
        bounce_randomly = getAncestorPar("bounce_randomly");

        // Power of N bouncing
        bounce_randomly_v2 = getAncestorPar("bounce_randomly_v2");
        use_v2_pifo = getAncestorPar("use_v2_pifo");
        random_power_bounce_factor = getAncestorPar("random_power_bounce_factor");

        if (bounce_randomly_v2 && !use_v2_pifo)
            throw cRuntimeError("How are we using v2 bouncing without v2 pifo");

        std::string switch_name = getParentModule()->getFullName();
        std::string module_path_string = switch_name + ".eth[" + std::to_string(0) + "].mac.queue";
        cModule* queue_module = getModuleByPath(module_path_string.c_str());
        std::string queue_module_name = queue_module->getModuleType()->getFullName();

        bool have_v2pifo_queues = queue_module_name.find("V2PIFO") != std::string::npos;
        if (use_v2_pifo && !have_v2pifo_queues)
            throw cRuntimeError("We're planning to use v2pifo, why we don't have v2pifo queues?");
        else if (!use_v2_pifo && have_v2pifo_queues)
            throw cRuntimeError("We are not using v2pifo, why we still have v2pifo queues?");

        if (getParentModule()->getIndex() == 0) {
            std::cout << "You're setting for forwarding and bouncing is: " << endl <<
                    "use_ecmp: " << use_ecmp << endl <<
                    "use_power_of_n_lb: " << use_power_of_n_lb << endl <<
                    "bounce_randomly: " << bounce_randomly << endl <<
                    "bounce_randomly_v2: " << bounce_randomly_v2 << endl <<
                    "use_v2_pifo: " << use_v2_pifo << endl;
            std::cout << "**********************************************************" << endl;
        }
    }
    else if (stage == INITSTAGE_LINK_LAYER) {
        registerService(Protocol::ethernetMac, gate("upperLayerIn"), gate("ifIn"));
        registerProtocol(Protocol::ethernetMac, gate("ifOut"), gate("upperLayerOut"));

        //TODO FIX Move it at least to STP module (like in ANSA's CDP/LLDP)
        if(isStpAware) {
            registerAddress(MacAddress::STP_MULTICAST_ADDRESS);
        }

        WATCH(bridgeAddress);
        WATCH(numReceivedNetworkFrames);
        WATCH(numDroppedFrames);
        WATCH(numReceivedBPDUsFromSTP);
        WATCH(numDeliveredBDPUsToSTP);
        WATCH(numDispatchedNonBPDUFrames);

        // store the information of neighbor switches for every switch
        // used for deflection
        // NOTE: Set the name of hosts to server :(
        // FIXME: Change this part to support every name for hosts
        std::string other_side_input_module_path;
        bool is_other_side_input_module_path_server;
        for (int i = 0; i < ifTable->getNumInterfaces(); i++) {
           other_side_input_module_path = getParentModule()->gate(getParentModule()->gateBaseId("ethg$o")+ i)->getPathEndGate()->getFullPath();
           is_other_side_input_module_path_server = (other_side_input_module_path.find("server") != std::string::npos);
           if (!is_other_side_input_module_path_server) {
               EV << other_side_input_module_path << " is not a host." << endl;
               port_idx_connected_to_switch_neioghbors.push_back(i);
           }
        }
    }
}

void BouncingIeee8021dRelay::registerAddress(MacAddress mac)
{
    registerAddresses(mac, mac);
}

void BouncingIeee8021dRelay::registerAddresses(MacAddress startMac, MacAddress endMac)
{
    registeredMacAddresses.insert(MacAddressPair(startMac, endMac));
}

void BouncingIeee8021dRelay::handleLowerPacket(Packet *packet)
{
    // messages from network
    numReceivedNetworkFrames++;
    std::string switch_name = this->getParentModule()->getFullName();

    EV_INFO << "Received " << packet << " from network." << endl;
    delete packet->removeTagIfPresent<DispatchProtocolReq>();
    handleAndDispatchFrame(packet);
}

void BouncingIeee8021dRelay::handleUpperPacket(Packet *packet)
{
    const auto& frame = packet->peekAtFront<EthernetMacHeader>();

    InterfaceReq* interfaceReq = packet->findTag<InterfaceReq>();
    int interfaceId =
            interfaceReq == nullptr ? -1 : interfaceReq->getInterfaceId();

    if (interfaceId != -1) {
        InterfaceEntry *ie = ifTable->getInterfaceById(interfaceId);
        chooseDispatchType(packet, ie);
    } else if (frame->getDest().isBroadcast()) {    // broadcast address
        broadcast(packet, -1);
    } else {
        std::list<int> outInterfaceId = macTable->getInterfaceIdForAddress(frame->getDest());
        // Not known -> broadcast
        if (outInterfaceId.size() == 0) {
            EV_DETAIL << "Destination address = " << frame->getDest()
                                      << " unknown, broadcasting frame " << frame
                                      << endl;

            throw cRuntimeError("2)Destination address not known. Broadcasting the frame. For DCs based on you're setting this shouldn't happen.");
            broadcast(packet, -1);
        } else {
            InterfaceEntry *ie = ifTable->getInterfaceById(interfaceId);
            chooseDispatchType(packet, ie);
        }
    }
}

bool BouncingIeee8021dRelay::isForwardingInterface(InterfaceEntry *ie)
{
    if (isStpAware) {
        if (!ie->getProtocolData<Ieee8021dInterfaceData>())
            throw cRuntimeError("Ieee8021dInterfaceData not found for interface %s", ie->getFullName());
        return ie->getProtocolData<Ieee8021dInterfaceData>()->isForwarding();
    }
    return true;
}

void BouncingIeee8021dRelay::broadcast(Packet *packet, int arrivalInterfaceId)
{
    if (!learn_mac_addresses) {
        throw cRuntimeError("Even though a learning is off, a packet is "
                "being broadcasted. If global ARP is set. This can actually"
                "mean that the tables are not created correctly and some "
                "packets are being broadcasted!");
    }
    EV_DETAIL << "Broadcast frame " << packet << endl;

    auto oldPacketProtocolTag = packet->removeTag<PacketProtocolTag>();
    packet->clearTags();
    auto newPacketProtocolTag = packet->addTag<PacketProtocolTag>();
    *newPacketProtocolTag = *oldPacketProtocolTag;
    delete oldPacketProtocolTag;
    packet->trim();

    int numPorts = ifTable->getNumInterfaces();
    EV_DETAIL << "SEPEHR: number of ports are: " << numPorts << endl;
    EV_DETAIL << "SEPEHR: arrival ID is: " << arrivalInterfaceId << endl;
    EV_DETAIL << "SEPEHR: arrival ID index is: " << arrivalInterfaceId - 100 << endl;


    std::string other_side_input_module_path = getParentModule()->gate(getParentModule()->gateBaseId("ethg$o")+ arrivalInterfaceId - 100)->getPathEndGate()->getFullPath();
    bool is_other_side_input_module_path_spine = (other_side_input_module_path.find("spine") != std::string::npos);


    for (int i = 0; i < numPorts; i++) {
        InterfaceEntry *ie = ifTable->getInterface(i);

        if (ie->isLoopback() || !ie->isBroadcast())
            continue;
        std::string other_side_output_module_path = getParentModule()->gate(getParentModule()->gateBaseId("ethg$o")+ i)->getPathEndGate()->getFullPath();
        bool is_other_side_output_module_path_spine = (other_side_output_module_path.find("spine") != std::string::npos);
        if (is_other_side_input_module_path_spine && is_other_side_output_module_path_spine) {
            EV_DETAIL << "SEPEHR: Came from upper layer and should not go to the upper layer" << endl;
            continue;
        }
        if (ie->getInterfaceId() != arrivalInterfaceId && isForwardingInterface(ie)) {
            chooseDispatchType(packet->dup(), ie);
        }
    }
    delete packet;
}

namespace {
bool isBpdu(Packet *packet, const Ptr<const EthernetMacHeader>& hdr)
{
    if (isIeee8023Header(*hdr)) {
        const auto& llc = packet->peekDataAt<Ieee8022LlcHeader>(hdr->getChunkLength());
        return (llc->getSsap() == 0x42 && llc->getDsap() == 0x42 && llc->getControl() == 3);
    }
    else
        return false;
}
}

const uint64_t string_to_mac(std::string const& s) {
    unsigned char a[6];
    int last = -1;
    int rc = sscanf(s.c_str(), "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx%n",
                    a + 0, a + 1, a + 2, a + 3, a + 4, a + 5,
                    &last);
    if(rc != 6 || s.size() != last)
        throw std::runtime_error("invalid mac address format " + s);
    return
        uint64_t(a[0]) << 40 |
        uint64_t(a[1]) << 32 | (
            // 32-bit instructions take fewer bytes on x86, so use them as much as possible.
            uint32_t(a[2]) << 24 |
            uint32_t(a[3]) << 16 |
            uint32_t(a[4]) << 8 |
            uint32_t(a[5])
        );
}

void BouncingIeee8021dRelay::handleAndDispatchFrame(Packet *packet)
{
    b packet_position = packet->getFrontOffset();
    packet->setFrontIteratorPosition(b(0));
    auto& phy_header = packet->removeAtFront<EthernetPhyHeader>();
    const auto& frame2 = packet->removeAtFront<EthernetMacHeader>();
    int hop_count = frame2->getHop_count();
    hop_count++;
    EV << "SEPEHR: packet hop count is " << hop_count << endl;
    frame2->setHop_count(hop_count);
    packet->insertAtFront(frame2);
    packet->insertAtFront(phy_header);
    packet->setFrontIteratorPosition(packet_position);
    const auto& frame = packet->peekAtFront<EthernetMacHeader>();

    if (frame->getIs_bursty()) {
        emit(burstyPacketReceivedSignal, string_to_mac(frame->getDest().str()));
    }

    int arrivalInterfaceId = packet->getTag<InterfaceInd>()->getInterfaceId();
    InterfaceEntry *arrivalInterface = ifTable->getInterfaceById(arrivalInterfaceId);
    Ieee8021dInterfaceData *arrivalPortData = arrivalInterface->findProtocolData<Ieee8021dInterfaceData>();
    if (isStpAware && arrivalPortData == nullptr)
        throw cRuntimeError("Ieee8021dInterfaceData not found for interface %s", arrivalInterface->getFullName());
    if (learn_mac_addresses) {
        learn(frame->getSrc(), arrivalInterfaceId);
    }

    //TODO revise next "if"s: 2nd drops all packets for me if not forwarding port; 3rd sends up when dest==STP_MULTICAST_ADDRESS; etc.
    // reordering, merge 1st and 3rd, ...

    // BPDU Handling
    if (isStpAware
            && (frame->getDest() == MacAddress::STP_MULTICAST_ADDRESS || frame->getDest() == bridgeAddress)
            && arrivalPortData->getRole() != Ieee8021dInterfaceData::DISABLED
            && isBpdu(packet, frame)) {
        EV_DETAIL << "Deliver BPDU to the STP/RSTP module" << endl;
        sendUp(packet);    // deliver to the STP/RSTP module
    }
    else if (isStpAware && !arrivalPortData->isForwarding()) {
        EV_INFO << "The arrival port is not forwarding! Discarding it!" << endl;
        numDroppedFrames++;
        delete packet;
    }
    else if (in_range(registeredMacAddresses, frame->getDest())) {
        // destination MAC address is registered, send it up
        sendUp(packet);
    }
    else if (frame->getDest().isBroadcast()) {    // broadcast address
        broadcast(packet, arrivalInterfaceId);
    }
    else {
        std::list<int> outputInterfaceId = macTable->getInterfaceIdForAddress(frame->getDest());
        // Not known -> broadcast
        if (outputInterfaceId.size() == 0) {
            EV_DETAIL << "Destination address = " << frame->getDest() << " unknown, broadcasting frame " << frame << endl;
            throw cRuntimeError("1)Destination address not known. Broadcasting the frame. For DCs based on you're setting this shouldn't happen.");
            broadcast(packet, arrivalInterfaceId);
        }
        else {
            //for (std::list<int>::iterator it=outputInterfaceId.begin(); it != outputInterfaceId.end(); ++it){
            //NOTE: HERE I USED the first path
            InterfaceEntry *outputInterface = ifTable->getInterfaceById(*outputInterfaceId.begin());
            if (isForwardingInterface(outputInterface))
                chooseDispatchType(packet, outputInterface);
            else {
                EV_INFO << "Output interface " << *outputInterface->getFullName() << " is not forwarding. Discarding!" << endl;
                numDroppedFrames++;
                delete packet;
            }
        }
    }
}

void BouncingIeee8021dRelay::chooseDispatchType(Packet *packet, InterfaceEntry *ie){
    const auto& frame = packet->peekAtFront<EthernetMacHeader>();
    std::list<int> destInterfaceIds = macTable->getInterfaceIdForAddress(frame->getDest());

    int portNum = destInterfaceIds.size();
    Chunk::enableImplicitChunkSerialization = true;
    std::string protocol = packet->getName();
    bool is_packet_arp_or_broadcast = (protocol.find("arp") != std::string::npos) || (frame->getDest().isBroadcast());

    // reduce the ttl
    if (!is_packet_arp_or_broadcast){
        EV << "SEPEHR: Should reduce packet's ttl." << endl;
        b packetPosition = packet->getFrontOffset();
        packet->setFrontIteratorPosition(b(0));
        auto phyHeader = packet->removeAtFront<EthernetPhyHeader>();
        auto ethHeader = packet->removeAtFront<EthernetMacHeader>();
        auto ipHeader = packet->removeAtFront<Ipv4Header>();
        short ttl = ipHeader->getTimeToLive() - 1;
        if (ttl <= 0) {
            EV << "ttl is " << ttl << ". dropping the packet!" << endl;
            light_in_relay_packet_drop_counter++;
            delete packet;
            return;
        }
        EV << "SEPEHR: packet's old ttl is: " << ipHeader->getTimeToLive() << " and it's new ttl is: " << ttl << endl;
        ipHeader->setTimeToLive(ttl);
        packet->insertAtFront(ipHeader);
        packet->insertAtFront(ethHeader);
        packet->insertAtFront(phyHeader);
        packet->setFrontIteratorPosition(packetPosition);
    }

    EV << "SOUGOL: This is the Packet Name: " << protocol << endl;
    EV << "SEPEHR: The number of available ports for this packet is " << portNum << endl;
    EV << "SEPEHR: source mac address: " << frame->getSrc().str() << " and dest mac address: " << frame->getDest().str() << endl;
    if (!is_packet_arp_or_broadcast){
        InterfaceEntry *ie2;

        if (use_power_of_n_lb) {
            //forward the packet towards destination using power of n choices
            // Considering ports towards servers as well
            // power of N LB

            EV << "Finding random interface for packet " << packet->str() << endl;
            ie2 = find_interface_to_fw_randomly_power_of_n(packet, true);
            if (ie2 == nullptr)
                ie2 = ie;
        }
        else if (use_ecmp && portNum > 1) {
            // ECMP
            destInterfaceIds.sort();
            b packetPosition = packet->getFrontOffset();
            packet->setFrontIteratorPosition(b(0));
            auto phyHeader = packet->removeAtFront<EthernetPhyHeader>();
            auto ethHeader = packet->removeAtFront<EthernetMacHeader>();
            auto ipHeader = packet->removeAtFront<Ipv4Header>();
            auto tcpHeader = packet->peekAtFront<tcp::TcpHeader>();
            EV << "S&S: The flow info is: ( src_ip: " << ipHeader->getSourceAddress() << ", dest_ip: " << ipHeader->getDestinationAddress() << ", src_port: " << tcpHeader->getSourcePort() << ", dest_port: " << tcpHeader->getDestinationPort() << " )" << endl;
            EV << "SEPEHR: Switch IS using ECMP for this packet!" << endl;
            std::string header_info = ipHeader->getSourceAddress().str() + ipHeader->getDestinationAddress().str() +
                    std::to_string(tcpHeader->getSourcePort()) + std::to_string(tcpHeader->getDestinationPort());
            unsigned long header_info_hash = header_hash(header_info);
            EV << "There are " << portNum << " ports and header hash is " << header_info_hash << endl;
            int outputPortNum;
            outputPortNum = header_info_hash % portNum;
            EV << "SEPEHR: output port number is: " << outputPortNum << endl;
            std::list<int>::iterator it = destInterfaceIds.begin();
            std::advance(it, outputPortNum);
            EV << "SEPEHR: output interface ID is: " << *it << endl;
            packet->insertAtFront(ipHeader);
            packet->insertAtFront(ethHeader);
            packet->insertAtFront(phyHeader);
            packet->setFrontIteratorPosition(packetPosition);
            ie2 = ifTable->getInterfaceById(*it);
        } else {
            ie2 = ie;
        }
        dispatch(packet, ie2);
    }
    else {
        dispatch(packet, ie);
    }
}

InterfaceEntry* BouncingIeee8021dRelay::find_interface_to_bounce_randomly(Packet *packet) {
    // DIBS
    InterfaceEntry *ie = nullptr;
    std::list<int> port_idx_connected_to_switch_neioghbors_copy = port_idx_connected_to_switch_neioghbors;
    int port_idx_connected_to_switch_neioghbors_copy_size;
    int random_index;
    std::string module_path_string;
    std::string switch_name = getParentModule()->getFullName();
    b packet_length = b(packet->getBitLength());
    while (true){
        // if not choose a random port that is connected to a switch with available buffer space
        port_idx_connected_to_switch_neioghbors_copy_size = port_idx_connected_to_switch_neioghbors_copy.size();
        if (port_idx_connected_to_switch_neioghbors_copy_size == 0) {
            EV << "No switch port with available buffer space found for our packet. Dropping the packet!" << endl;
            return nullptr;
        }
        // choose randomly from the list without replacement
        random_index = rand() % port_idx_connected_to_switch_neioghbors_copy_size;
        std::list<int>::iterator it = port_idx_connected_to_switch_neioghbors_copy.begin();
        std::advance(it, random_index);

        module_path_string = switch_name + ".eth[" + std::to_string(*it) + "].mac";
        EV << "SEPEHR: Extracting info for " << module_path_string << endl;
        AugmentedEtherMac *mac = check_and_cast<AugmentedEtherMac *>(getModuleByPath(module_path_string.c_str()));
        std::string queue_full_path = "";

        if (!mac->is_queue_full(packet_length, queue_full_path)) {
            ie = ifTable->getInterface(*it);
            EV << "The packet is randomly bounced to id: " << ie->getInterfaceId() << endl;

            std::string other_side_input_module_path = getParentModule()->gate(getParentModule()->gateBaseId("ethg$o")+ ie->getIndex())->getPathEndGate()->getFullPath();
            bool is_other_side_input_module_path_server = other_side_input_module_path.find("server") != std::string::npos;
            if (is_other_side_input_module_path_server) {
                throw cRuntimeError("The chosen bouncing port is towards a host!");
            }

            return ie;
        }
        port_idx_connected_to_switch_neioghbors_copy.erase(it);
        if (port_idx_connected_to_switch_neioghbors_copy.size() == port_idx_connected_to_switch_neioghbors.size())
            throw cRuntimeError("You're erasing from the base array two. Probably its because of calling by reference!");
    }
}

InterfaceEntry* BouncingIeee8021dRelay::find_interface_to_fw_randomly_power_of_n(Packet *packet, bool consider_servers) {
    // This forwards the packet randomly using power of N choices
    // we don't filter out the ports with available capacity
    InterfaceEntry *ie;
    std::string module_path_string;
    std::string switch_name = getParentModule()->getFullName();
    b packet_length = b(packet->getBitLength());
    const auto& frame = packet->peekAtFront<EthernetMacHeader>();
    long min_queue_occupancy = -1;
    int chosen_source_index = -1;
    std::list<int> chosen_interface_indexes;
    int chosen_interface_counter = 0;
    const MacAddress address = frame->getDest();
    EV << "Finding port for " << address << endl;
    std::list<int> interface_ids = macTable->getInterfaceIdForAddress(address);

    interface_ids.sort();

    //Try finding an available port that goes towards the source of the packet.
    // Consider ports towards sources for forwarding but not for bouncing
    while(chosen_interface_counter < random_power_factor && interface_ids.size() != 0) {
        int random_idx = rand() % interface_ids.size();
        EV << "randomly choosing one of the ports. random_idx is " << random_idx << endl;
        std::list<int>::iterator it = interface_ids.begin();
        std::advance(it, random_idx);
        int interface_idx = ifTable->getInterfaceById(*it)->getIndex();
        module_path_string = switch_name + ".eth[" + std::to_string(interface_idx) + "].mac";
        EV << "finding main ports: " << module_path_string << endl;
        AugmentedEtherMac *mac = check_and_cast<AugmentedEtherMac *>(getModuleByPath(module_path_string.c_str()));
        std::string other_side_input_module_path = getParentModule()->gate(getParentModule()->gateBaseId("ethg$o")+ interface_idx)->getPathEndGate()->getFullPath();
        bool is_other_side_input_module_path_server = other_side_input_module_path.find("server") != std::string::npos;

        if (consider_servers || !is_other_side_input_module_path_server) {
            // I count the chosen ports but only add those with free
            // ports because those that are full do not matter.
            chosen_interface_counter++;
            std::string queue_full_path = "";
            if (use_v2_pifo || !mac->is_queue_full(packet_length, queue_full_path)) {
                chosen_interface_indexes.push_back(interface_idx);
                EV << "Adding port: " << module_path_string << endl;
            }
        }
        interface_ids.erase(it);
        if (interface_ids.size() == (macTable->getInterfaceIdForAddress(address)).size())
            throw cRuntimeError("You have also changed the size of base array of source_interface_ids.");
    }

    if (chosen_interface_indexes.size() == 0) {
        EV << "No available ports was found to forward the packet normally" << endl;
        return nullptr;
    }

    // Apply power of n: Find least congested port and forward the packet to that port
    chosen_interface_indexes.sort();
    for (std::list<int>::iterator it=chosen_interface_indexes.begin(); it != chosen_interface_indexes.end(); it++){
        module_path_string = switch_name + ".eth[" + std::to_string(*it) + "].mac";
        AugmentedEtherMac *mac = check_and_cast<AugmentedEtherMac *>(getModuleByPath(module_path_string.c_str()));
        std::string queue_full_path = "";
        long queue_occupancy = mac->get_queue_occupancy(queue_full_path);
        EV << "considering " << module_path_string << " with occupancy: " << queue_occupancy << endl;
        if (min_queue_occupancy == -1 || queue_occupancy < min_queue_occupancy) {
            min_queue_occupancy = queue_occupancy;
            chosen_source_index = *it;
        } else if (queue_occupancy == min_queue_occupancy) {
            // two equally full buffers, break the tie randomly
            double dice = dblrand();
            EV << "Two ports with occupancy of " << min_queue_occupancy << ". Breaking tie: dice is " << dice << endl;
            if (dice >= 0.5) {
                // 50% update the chosen source idx
                chosen_source_index = *it;
            }
        }
    }
    module_path_string = switch_name + ".eth[" + std::to_string(chosen_source_index) + "].mac";
    EV << "Chosen port: " << module_path_string << endl;
    AugmentedEtherMac *mac = check_and_cast<AugmentedEtherMac *>(getModuleByPath(module_path_string.c_str()));
    ie = ifTable->getInterface(chosen_source_index);

    if (!consider_servers) {
        std::string other_side_input_module_path = getParentModule()->gate(getParentModule()->gateBaseId("ethg$o")+ ie->getIndex())->getPathEndGate()->getFullPath();
        bool is_other_side_input_module_path_server = other_side_input_module_path.find("server") != std::string::npos;
        if (is_other_side_input_module_path_server) {
            throw cRuntimeError("The chosen bouncing port is towards a host!");
        }
    }

    return ie;
}

void BouncingIeee8021dRelay::find_interface_to_bounce_randomly_v2(Packet *packet, bool consider_servers, InterfaceEntry *ie2) {

    // eject the packets to create room for packet
    // we don't filter out the ports with available capacity
    std::string module_path_string;
    std::string switch_name = getParentModule()->getFullName();
    b packetPosition = packet->getFrontOffset();
    packet->setFrontIteratorPosition(b(0));
    auto phyHeader = packet->removeAtFront<EthernetPhyHeader>();
    auto ethHeader = packet->removeAtFront<EthernetMacHeader>();
    auto ipHeader = packet->removeAtFront<Ipv4Header>();

    unsigned long seq, ret_count;
    for (unsigned int i = 0; i < ipHeader->getOptionArraySize(); i++) {
        const TlvOptionBase *option = &ipHeader->getOption(i);
        if (option->getType() == IPOPTION_V2_MARKING) {
            auto opt = check_and_cast<const Ipv4OptionV2Marking*>(option);
            seq = opt->getSeq();
            ret_count = opt->getRet_num();
            break;
        }
        // Check if something is returned
        if (i == ipHeader->getOptionArraySize() - 1)
            throw cRuntimeError("Marking cannot be off at this position!");
    }

    EV << "Packet's seq = " << seq << " and ret_count = " << ret_count << endl;

    packet->insertAtFront(ipHeader);
    packet->insertAtFront(ethHeader);
    packet->insertAtFront(phyHeader);
    packet->setFrontIteratorPosition(packetPosition);
    const auto& frame = packet->peekAtFront<EthernetMacHeader>();
    PacketQueue* queue;

    module_path_string = switch_name + ".eth[" + std::to_string(ie2->getIndex()) + "].mac.queue";
    if (use_v2_pifo)
        queue = check_and_cast<V2PIFO *>(getModuleByPath(module_path_string.c_str()));

    module_path_string = switch_name + ".eth[" + std::to_string(ie2->getIndex()) + "].mac";
    AugmentedEtherMac *mac = check_and_cast<AugmentedEtherMac *>(getModuleByPath(module_path_string.c_str()));
    std::string queue_full_path = "";

    EV << "Trying to inject packet" << packet->str() << " with seq=" << seq << endl;
    EV << module_path_string << ": ";
    int num_packets_to_eject = queue->getNumPacketsToEject(b(packet->getBitLength()), seq, ret_count,
            mac->on_the_way_packet_num, mac->on_the_way_packet_length);
    EV << "Number of packets to eject is " << num_packets_to_eject << endl;
    std::list<Packet*> ejected_packets;
    if (num_packets_to_eject < 0) {
        // deflect packet itself
        EV << "Adding the main packets to the list to be bounced" << endl;
        ejected_packets.push_back(packet);
    } else {
        // eject packets to make room for the main packet
        EV << "Ejecting packets from the queue to be bounced." << endl;
        module_path_string = switch_name + ".eth[" + std::to_string(ie2->getIndex()) + "].mac";
        AugmentedEtherMac *mac = check_and_cast<AugmentedEtherMac *>(getModuleByPath(module_path_string.c_str()));
        auto frame = packet->peekAtFront<EthernetMacHeader>();
        mac->add_on_the_way_packet(b(packet->getBitLength()));

        ejected_packets = queue->eject_and_push(num_packets_to_eject);

        // send the main packet to the output queue
        EV << "Sending the main packet " << packet << " on output interface " << ie2->getFullName() << " with destination = " << frame->getDest() << endl;
        numDispatchedNonBPDUFrames++;
        auto oldPacketProtocolTag = packet->removeTag<PacketProtocolTag>();
        packet->clearTags();
        auto newPacketProtocolTag = packet->addTag<PacketProtocolTag>();
        *newPacketProtocolTag = *oldPacketProtocolTag;
        delete oldPacketProtocolTag;
        packet->addTag<InterfaceReq>()->setInterfaceId(ie2->getInterfaceId());
        packet->trim();
        emit(packetSentToLowerSignal, packet);
        send(packet, "ifOut");
    }

    // deflect the remaining packets
    while (ejected_packets.size() > 0){

        // This forwards or bounces the packet randomly to ports with free space using power of two choices
        InterfaceEntry *ie;
        auto packet = ejected_packets.front();
        EV << "Bouncing the ejected packet " << packet->str() << endl;
        ejected_packets.pop_front();
        b packet_length = b(packet->getBitLength());
        const auto& frame = packet->peekAtFront<EthernetMacHeader>();
        long min_queue_occupancy = -1;
        int chosen_source_index = -1;
        std::list<int> chosen_interface_indexes;
        int chosen_interface_counter = 0;

        // we choose two random ports and drop if both of them are full
        chosen_interface_counter = 0;
        std::list<int> port_idx_connected_to_switch_neioghbors_copy = port_idx_connected_to_switch_neioghbors;

        while(chosen_interface_counter < random_power_bounce_factor && port_idx_connected_to_switch_neioghbors_copy.size() != 0) {
            int random_idx = rand() % port_idx_connected_to_switch_neioghbors_copy.size();
            EV << "randomly choosing a port for bounce towards neighbor switches. random_idx is " << random_idx << endl;
            std::list<int>::iterator it = port_idx_connected_to_switch_neioghbors_copy.begin();
            std::advance(it, random_idx);
            module_path_string = switch_name + ".eth[" + std::to_string(*it) + "].mac";
            EV << "finding additional ports: " << module_path_string << endl;

            if (use_v2_pifo || !mac->is_queue_full(packet_length, queue_full_path)) {
                chosen_interface_indexes.push_back(*it);
                EV << "Adding port: " << module_path_string << endl;
            }

            chosen_interface_counter++;
            port_idx_connected_to_switch_neioghbors_copy.erase(it);
            if (port_idx_connected_to_switch_neioghbors.size() == port_idx_connected_to_switch_neioghbors_copy.size())
                throw cRuntimeError("2)You have also changed the size of base array of port_idx_connected_to_switch_neioghbors.");
        }

        if (chosen_interface_indexes.size() == 0) {
            // Cannot bounce this packet, drop it and get to the next packet
            EV << "No available ports was found to bounce the packet, drop the bounced packet." << endl;
            light_in_relay_packet_drop_counter++;
            delete packet;
            continue;
        }

        // Apply power of n: Find least congested port and forward the packet to that port
        chosen_interface_indexes.sort();
        for (std::list<int>::iterator it=chosen_interface_indexes.begin(); it != chosen_interface_indexes.end(); it++){
            module_path_string = switch_name + ".eth[" + std::to_string(*it) + "].mac";
            AugmentedEtherMac *mac = check_and_cast<AugmentedEtherMac *>(getModuleByPath(module_path_string.c_str()));
            std::string queue_full_path = "";
            long queue_occupancy = mac->get_queue_occupancy(queue_full_path);
            EV << "considering " << module_path_string << " with occupancy: " << queue_occupancy << endl;
            if (min_queue_occupancy == -1 || queue_occupancy < min_queue_occupancy) {
                min_queue_occupancy = queue_occupancy;
                chosen_source_index = *it;
            } else if (queue_occupancy == min_queue_occupancy) {
                // two equally full buffers, break the tie randomly
                double dice = dblrand();
                EV << "Two ports with occupancy of " << min_queue_occupancy << ". Breaking tie: dice is " << dice << endl;
                if (dice >= 0.5) {
                    // 50% update the chosen source idx
                    chosen_source_index = *it;
                }
            }
        }
        module_path_string = switch_name + ".eth[" + std::to_string(ie2->getIndex()) + "].mac.queue";


        module_path_string = switch_name + ".eth[" + std::to_string(chosen_source_index) + "].mac";
        EV << "Chosen port: " << module_path_string << endl;
        AugmentedEtherMac *mac = check_and_cast<AugmentedEtherMac *>(getModuleByPath(module_path_string.c_str()));
        ie = ifTable->getInterface(chosen_source_index);

        queue_full_path = "";

        // Send packet
        auto mac_header = packet->peekAtFront<EthernetMacHeader>();
        mac->add_on_the_way_packet(b(packet->getBitLength()));
        EV << module_path_string << ": ";
        if (!consider_servers) {
            std::string other_side_input_module_path = getParentModule()->gate(getParentModule()->gateBaseId("ethg$o")+ ie->getIndex())->getPathEndGate()->getFullPath();
            bool is_other_side_input_module_path_server = other_side_input_module_path.find("server") != std::string::npos;
            if (is_other_side_input_module_path_server) {
                throw cRuntimeError("The chosen bouncing port is towards a host!");
            }
        }

        emit(feedBackPacketGeneratedSignal, packet->getId());
        EV << "Sending frame " << packet << " on output interface " << ie->getFullName() << " with destination = " << frame->getDest() << endl;
        numDispatchedNonBPDUFrames++;
        auto oldPacketProtocolTag = packet->removeTag<PacketProtocolTag>();
        packet->clearTags();
        auto newPacketProtocolTag = packet->addTag<PacketProtocolTag>();
        *newPacketProtocolTag = *oldPacketProtocolTag;
        delete oldPacketProtocolTag;
        packet->addTag<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
        packet->trim();
        emit(packetSentToLowerSignal, packet);
        send(packet, "ifOut");
    }
}

void BouncingIeee8021dRelay::dispatch(Packet *packet, InterfaceEntry *ie)
{
    if (ie != nullptr) {
        b position = packet->getFrontOffset();
        packet->setFrontIteratorPosition(b(0));
        auto phy_header_temp = packet->removeAtFront<EthernetPhyHeader>();
        auto mac_header_temp = packet->removeAtFront<EthernetMacHeader>();
        mac_header_temp->setOriginal_interface_id(ie->getInterfaceId());
        packet->insertAtFront(mac_header_temp);
        packet->insertAtFront(phy_header_temp);
        packet->setFrontIteratorPosition(position);
    }

    const auto& frame = packet->peekAtFront<EthernetMacHeader>();
    std::string switch_name = getParentModule()->getFullName();
    b packet_length = b(packet->getBitLength());

    std::string module_path_string;
    InterfaceEntry *ie2 = nullptr;

    if (!frame->getDest().isBroadcast()) {
        // If there is enough space on the chosen port simply forward it
        module_path_string = switch_name + ".eth[" + std::to_string(ie->getIndex()) + "].mac";
        EV << "The chosen port path is " << module_path_string << endl;
        AugmentedEtherMac *mac_temp = check_and_cast<AugmentedEtherMac *>(getModuleByPath(module_path_string.c_str()));
        std::string queue_full_path = "";

        if (mac_temp->is_queue_full(packet_length, queue_full_path)) {
            if (bounce_randomly) {
                // Using DIBS --> Randomly bouncing to a not full switch port
                ie2 = find_interface_to_bounce_randomly(packet);
            }
            else if (bounce_randomly_v2) {
                // Bounce the packet to source using power of n choices.
                // Not considering ports towards servers
                EV << "Frames src is " << frame->getSrc() << " and frame's dst is " << frame->getDest() << endl;
                find_interface_to_bounce_randomly_v2(packet, false, ie);
                return;
            } else {
                ie2 = nullptr;
                EV << "No bouncing method chosen! Normally drop the packet!" << endl;
            }
            if (ie2 == nullptr && use_v2_pifo) {
                // if this is true, we handle the drop in the mac layer and not the relay unit
                ie2 = ie;
            }
            if (ie2 == nullptr) {
//                emit(feedBackPacketDroppedSignal, int(frame->getIs_bursty()));
//                emit(feedBackPacketDroppedPortSignal, ie->getIndex());
                light_in_relay_packet_drop_counter++;
                delete packet;
                return;
            }
        } else {
            ie2 = ie;
        }
    } else {
        ie2 = ie;
    }

    if (ie2->getInterfaceId() != ie->getInterfaceId()) {
        EV << "The output interface has changed as a result of bouncing." << endl;
        emit(feedBackPacketGeneratedSignal, packet->getId());
    }

    module_path_string = switch_name + ".eth[" + std::to_string(ie2->getIndex()) + "].mac";
    AugmentedEtherMac *mac = check_and_cast<AugmentedEtherMac *>(getModuleByPath(module_path_string.c_str()));
    auto mac_header = packet->peekAtFront<EthernetMacHeader>();
    mac->add_on_the_way_packet(packet_length);

    EV << "Sending frame " << packet << " on output interface " << ie2->getFullName() << " with destination = " << frame->getDest() << endl;

    numDispatchedNonBPDUFrames++;
    auto oldPacketProtocolTag = packet->removeTag<PacketProtocolTag>();
    packet->clearTags();
    auto newPacketProtocolTag = packet->addTag<PacketProtocolTag>();
    *newPacketProtocolTag = *oldPacketProtocolTag;
    delete oldPacketProtocolTag;
    packet->addTag<InterfaceReq>()->setInterfaceId(ie2->getInterfaceId());
    packet->trim();
    emit(packetSentToLowerSignal, packet);
    send(packet, "ifOut");
}

void BouncingIeee8021dRelay::learn(MacAddress srcAddr, int arrivalInterfaceId)
{
    Ieee8021dInterfaceData *port = getPortInterfaceData(arrivalInterfaceId);

    EV << "SEPEHR: Is learning." << endl;

    if (!isStpAware || port->isLearning())
        macTable->updateTableWithAddress(arrivalInterfaceId, srcAddr);
}

void BouncingIeee8021dRelay::sendUp(Packet *packet)
{
    EV_INFO << "Sending frame " << packet << " to the upper layer" << endl;
    send(packet, "upperLayerOut");
}

Ieee8021dInterfaceData *BouncingIeee8021dRelay::getPortInterfaceData(unsigned int interfaceId)
{
    if (isStpAware) {
        InterfaceEntry *gateIfEntry = ifTable->getInterfaceById(interfaceId);
        Ieee8021dInterfaceData *portData = gateIfEntry ? gateIfEntry->getProtocolData<Ieee8021dInterfaceData>() : nullptr;

        if (!portData)
            throw cRuntimeError("Ieee8021dInterfaceData not found for port = %d", interfaceId);

        return portData;
    }
    return nullptr;
}

void BouncingIeee8021dRelay::start()
{
    ie = chooseInterface();
    if (ie) {
        bridgeAddress = ie->getMacAddress(); // get the bridge's MAC address
        registerAddress(bridgeAddress); // register bridge's MAC address
    }
    else
        throw cRuntimeError("No non-loopback interface found!");
}

void BouncingIeee8021dRelay::stop()
{
    ie = nullptr;
}

InterfaceEntry *BouncingIeee8021dRelay::chooseInterface()
{
    // TODO: Currently, we assume that the first non-loopback interface is an Ethernet interface
    //       since relays work on EtherSwitches.
    //       NOTE that, we don't check if the returning interface is an Ethernet interface!
    for (int i = 0; i < ifTable->getNumInterfaces(); i++) {
        InterfaceEntry *current = ifTable->getInterface(i);
        if (!current->isLoopback())
            return current;
    }

    return nullptr;
}

void BouncingIeee8021dRelay::finish()
{
    recordScalar("number of received BPDUs from STP module", numReceivedBPDUsFromSTP);
    recordScalar("number of received frames from network (including BPDUs)", numReceivedNetworkFrames);
    recordScalar("number of dropped frames (including BPDUs)", numDroppedFrames);
    recordScalar("number of delivered BPDUs to the STP module", numDeliveredBDPUsToSTP);
    recordScalar("number of dispatched BPDU frames to the network", numDispatchedBDPUFrames);
    recordScalar("number of dispatched non-BDPU frames to the network", numDispatchedNonBPDUFrames);
}


