//
// In this version of V2PIFO, the higher the value of priority variable, the lower the packet's priority
//

#include "inet/common/ModuleAccess.h"
#include "inet/common/Simsignals.h"
#include "inet/queueing/function/PacketComparatorFunction.h"
#include "inet/queueing/function/PacketDropperFunction.h"
#include "./V2PIFO.h"

using namespace inet;
using namespace queueing;

#define LAS 0
#define SRPT 1
#define FIFO 2

#define MICE_FLOW_SIZE 800000   // required for measurements: 100KB = 800000b


Define_Module(V2PIFO);

bool popped_marking_off_error = false;

simsignal_t V2PIFO::packetDropSeqSignal = registerSignal("packetDropSeq");
simsignal_t V2PIFO::packetDropRetCountSignal = registerSignal("packetDropRetCount");
simsignal_t V2PIFO::packetDropTotalPayloadLenSignal = registerSignal("packetDropTotalPayloadLength");

V2PIFO::~V2PIFO()
{
    recordScalar("lightInQueuePacketDropCount", light_in_queue_packet_drop_count);
    recordScalar("lightAllQueueingTime", all_packets_queueing_time_sum / num_all_packets);
    recordScalar("lightMiceQueueingTime", mice_packets_queueing_time_sum / num_mice_packets);
}

void V2PIFO::initialize(int stage) {
    PacketQueue::initialize(stage);
    dctcp_thresh = par("dctcp_thresh");
    bounce_randomly_v2 = getAncestorPar("bounce_randomly_v2");
    denominator_for_retrasnmissions = getAncestorPar("denominator_for_retrasnmissions");

    std::string dropper_type_str = par("dropper_type");
    if (dropper_type_str.compare("LAS") == 0)
        dropper_type = LAS;
    else if (dropper_type_str.compare("SRPT") == 0)
        dropper_type = SRPT;
    else if (dropper_type_str.compare("FIFO") == 0)
        dropper_type = FIFO;
    else
        throw cRuntimeError("No dropper type identified!");

    std::string scheduler_type_str = par("scheduler_type");
    if (scheduler_type_str.compare("LAS") == 0)
        scheduler_type = LAS;
    else if (scheduler_type_str.compare("SRPT") == 0)
        scheduler_type = SRPT;
    else if (scheduler_type_str.compare("FIFO") == 0)
        scheduler_type = FIFO;
    else
        throw cRuntimeError("No dropper type identified!");

    std::string where_to_mark_packets = par("where_to_mark_packets");
    if (where_to_mark_packets.compare("enqueue") == 0) {
        mark_packets_in_enqueue = true;
    } else if (where_to_mark_packets.compare("dequeue") == 0) {
        mark_packets_in_enqueue = false;
    } else
        throw cRuntimeError("where to mark packet is neither enqueue nor dequeue!");
}

int V2PIFO::getNumPacketsToEject(b packet_length, long seq, long ret_count,
        long on_the_way_packet_num, b on_the_way_packet_length) {
    // pass bitlength to this because the phy header is removed when the packet is inserted in the queue
    // Ejects packets with the lowest priorities, also add fifo ejecting
    EV << "getNumPacketsToEject called for packet with lenght: " << packet_length <<
            ", seq: " << seq << ", and ret_count: " << ret_count << endl;
    if (dropper_type == FIFO) {
        // If you're acting FIFO, there is no sense in ejecting any packets, how are you deciding
        // which packet to eject? You should just bounce/drop the received packet itself
        return -1;
    }
    unsigned long priority = calculate_priority(seq, ret_count);
    int num_packets_to_eject = 0;
    b required_length = packet_length;
    long queue_occupancy = get_queue_occupancy(on_the_way_packet_num, on_the_way_packet_length);
    int max_capacity;
    if (getMaxNumPackets() != -1) {
        max_capacity = getMaxNumPackets();
    } else {
        max_capacity = getMaxTotalLength().get();
    }
    EV << "max capacity is " << max_capacity << endl;

    if (sorted_queued_packet_hash_table.size() == 0)
        throw cRuntimeError("How is this possible? The queue is empty but you're ejecting a packet!");

    // iterate over the sorted queue to count the number of packets
    // with lower priority of the new packet
    std::map<unsigned long, std::list<Packet*>>::iterator map_it =
            sorted_queued_packet_hash_table.end();
    map_it--;
    if (map_it->second.size() == 0) {
        throw cRuntimeError("There shouldn't be any empty lists in our hash map1!");
    }
    std::list<Packet*>::iterator list_it = map_it->second.end();
    list_it--; // we made sure that list isn't empty
    int num_packets = getNumPackets();
    while(num_packets > 0) {
        num_packets--; // makes sure that there is no infinite while loop in the code
        EV << "considering packet " << (*list_it)->str() << " with priority=" << map_it->first << endl;
        if (map_it->first > priority) {
            // packet has higher priority
            EV << "packet has higher priority" << endl;
            num_packets_to_eject++;
            if (getMaxNumPackets() != -1) {
                queue_occupancy--;
            } else {
                queue_occupancy -= (*list_it)->getBitLength();
            }
            if ((getMaxNumPackets() != -1 && max_capacity - queue_occupancy >= 1) ||
                    (getMaxNumPackets() == -1 && max_capacity - queue_occupancy >= packet_length.get()))
                return num_packets_to_eject;
        } else {
            EV << "not enough packets with lower priority to be ejected" << endl;
            // not enough packets with lower priority to be ejected
            return -1;
        }
        if (list_it == map_it->second.begin()) {
            // check if we reached the first packet of first list
            EV << "check if we reached the first packet of first list" << endl;
            if (map_it == sorted_queued_packet_hash_table.begin())
                return -1;
            map_it--;
            if (map_it->second.size() == 0) {
                throw cRuntimeError("There shouldn't be any empty lists in our hash map2!");
            }
            list_it = map_it->second.end();
            list_it--;
        } else {
            list_it--;
        }
    }
    return -1;
}

std::list<Packet*> V2PIFO::eject_and_push(int num_packets_to_eject) {
    if (dropper_type == FIFO) {
        // If you're acting FIFO, there is no sense in ejecting any packets, how are you deciding
        // which packet to eject? You should just bounce/drop the received packet itself
        throw cRuntimeError("Based on getNumPacketsToEject's definition, this function should never be called"
                " if the dropper/bouncer is FIFO.");
    }

    // extracts the "num_packets_to_eject" with the lowest priorities (highest seq/rank)
    std::list<Packet*> packets;
    for (int i = 0; i < num_packets_to_eject; i++) {
        std::map<unsigned long, std::list<Packet*>>::iterator map_it =
                    sorted_queued_packet_hash_table.end();
        map_it--;
        if (map_it->second.size() == 0) {
            throw cRuntimeError("There shouldn't be any empty lists in our hash map3!");
        }
        packets.push_back(check_and_cast<Packet *>(queue.remove(map_it->second.back())));
        map_it->second.pop_back();
        if (map_it->second.size() == 0)
            sorted_queued_packet_hash_table.erase(map_it->first);
    }
    if (packets.size() != num_packets_to_eject)
        throw cRuntimeError("packets.size() != num_packets_to_eject");
    return packets;
}

unsigned long V2PIFO::calculate_priority(unsigned long seq, unsigned long ret_count) {

    // if Valinor is not on or the boosting factor is 0, don't boost the priority
    if (!bounce_randomly_v2 || denominator_for_retrasnmissions <= 0) {
        return seq;
    }

    unsigned long priority = seq;
    for (int i = 0; i < ret_count; i++) {
        // todo: here is where we apply the function
        priority = (unsigned long) (priority / denominator_for_retrasnmissions);
    }
    if (priority < 0)
        priority = 0;
    return priority;
}

unsigned long V2PIFO::extract_priority(Packet *packet, bool is_packet_being_dropped) {
    unsigned long priority;
    unsigned long seq, ret_count;
    auto packet_dup = packet->dup();
    auto etherheader = packet_dup->removeAtFront<EthernetMacHeader>();
    auto ipv4header = packet_dup->peekAtFront<Ipv4Header>();
    delete packet_dup;


    // This should be added, whether marking is on or not!
    if(is_packet_being_dropped) {
        EV << "Packet dropped in extract priority!" << endl;
        light_in_queue_packet_drop_count++;
    }

    for (unsigned int i = 0; i < ipv4header->getOptionArraySize(); i++) {
        const TlvOptionBase *option = &ipv4header->getOption(i);
        if (option->getType() == IPOPTION_V2_MARKING) {
            auto opt = check_and_cast<const Ipv4OptionV2Marking*>(option);
            seq = opt->getSeq();
            ret_count = opt->getRet_num();
            priority = calculate_priority(seq, ret_count);
            if (is_packet_being_dropped) {
//                cSimpleModule::emit(packetDropSeqSignal, seq);
//                cSimpleModule::emit(packetDropRetCountSignal, ret_count);
//                cSimpleModule::emit(packetDropTotalPayloadLenSignal, etherheader->getTotal_length().get());
            }
            return priority;
        }
    }

    // The marking component is probably off!
    if (!popped_marking_off_error) {
        popped_marking_off_error = true;
        std::cout << "Option not found in V2PIFO, marking is probably off. Setting prio to 1 for all packets." << endl;
    }
    return 1;
}

void V2PIFO::pushPacket(Packet *packet, cGate *gate)
{

    Enter_Method("pushPacket");
    EV << "pushPacket is called in V2PIFO" << endl;
    emit(packetPushedSignal, packet);
    EV_INFO << "Pushing packet " << packet->getName() << " into the queue." << endl;

    // see if you should mark packet
    int queue_occupancy = getNumPackets();
    auto eth_header = packet->removeAtFront<EthernetMacHeader>();
    eth_header->setQueue_occupancy(queue_occupancy);
    packet->insertAtFront(eth_header);

    if (mark_packets_in_enqueue) {
        if (dctcp_thresh >= 0) {
            EV << "dctcp_thresh is " << dctcp_thresh << endl;
            if (queue_occupancy >= dctcp_thresh) {
                EV << "marking at enqueue" << endl;
                std::string protocol = packet->getName();
                if (protocol.find("tcpseg") != std::string::npos){
                    EcnMarker::setEcn(packet, IP_ECN_CE);
                    EV << "SOUGOL: The ECN is marked for this packet!" << endl;
                }
            }
        }
    }

    //calculate priority
    unsigned long priority = extract_priority(packet, false);
    EV << "priority is " << priority << ". finding where to push the packet." << endl;

    // push packet
    auto priority_found = sorted_queued_packet_hash_table.find(priority);
    if (priority_found != sorted_queued_packet_hash_table.end()) {
        priority_found->second.push_back(packet);
    } else {
        std::list<Packet*> packets;
        packets.push_back(packet);
        sorted_queued_packet_hash_table.insert(std::pair<unsigned long,
                std::list<Packet*>>(priority, packets));
    }
    EV << "Inserting the packet at the end of the queue" << endl;
    queue.insert(packet);

    EV_INFO << "A packet is inserted into the queue. Queue length: "
            << getNumPackets() << " & packetCapacity: " << packetCapacity <<
            ", Queue data occupancy is " << getTotalLength() <<
            " and dataCapacity is " << dataCapacity << endl;

    if (buffer != nullptr)
        buffer->addPacket(packet);
    else {
        int num_packets = getNumPackets();
        // if queue is overloaded, drop the appropriate packets with regards to dropper function
        while (isOverloaded() && num_packets > 0) {
            num_packets--; // avoiding infinite loops
            unsigned long priority;
            Packet *packet;
            if (dropper_type == FIFO) {
                // drop the last packet received
                EV << "Drop the last packet received" << endl;
                packet = check_and_cast<Packet *>(queue.remove(queue.get(getNumPackets() - 1)));
                priority = extract_priority(packet, true);
                auto priority_found = sorted_queued_packet_hash_table.find(priority);
                if (priority_found == sorted_queued_packet_hash_table.end() ||
                        priority_found->second.size() == 0)
                    throw cRuntimeError("Priority doesn't exist or its list is emptly!");
                if (packet != priority_found->second.back())
                    throw cRuntimeError("packet != priority_found->second.back(). Mismatch between the packets of hash table and queue!");
                priority_found->second.pop_back(); // the packet that is received last, it stored last in the list of each priority
                if (priority_found->second.size() == 0) {
                    sorted_queued_packet_hash_table.erase(priority_found->first);
                }
            } else {
                // drop the lowest priority packet
                EV << "Drop the lowest priority packet" << endl;
                std::map<unsigned long, std::list<Packet*>>::iterator it = sorted_queued_packet_hash_table.end();
                it--;
                priority = it->first;
                if (priority != extract_priority(it->second.back(), true)) {
                    // this checks if the priority of the packet we are dropping is equal
                    // to its key in hash table
                    // it also emit appropriate dropped signals
                    throw cRuntimeError("Priority mismatch between packet and hash key!");
                }
                packet = check_and_cast<Packet *>(queue.remove(it->second.back()));
                if (packet != it->second.back())
                    throw cRuntimeError("packet != it->second.back(). Mismatch between the packets of hash table and queue!");
                it->second.pop_back();
                if (it->second.size() == 0) {
                    sorted_queued_packet_hash_table.erase(it->first);
                }
            }
            EV << "Queue is overloaded. Dropping the packet in queue with priority: " << priority<< endl;
            delete packet;
        }
    }

    updateDisplayString();
    if (packetCapacity != -1)
        cSimpleModule::emit(customQueueLengthSignal, getNumPackets());
    else
        cSimpleModule::emit(customQueueLengthSignalPacketBytes, getTotalLength().get());
    if (collector != nullptr && getNumPackets() != 0){
        EV << "SEPEHR: Handling can pop packet." << endl;
        collector->handleCanPopPacket(outputGate);
    }
}

Packet *V2PIFO::popPacket(cGate *gate)
{
    Enter_Method("popPacket");
    EV << "popPacket is called in V2PIFO" << endl;
    EV << "Initial queue len: " << getNumPackets() << endl;
    Packet* popped_packet;
    unsigned long priority;
    if (scheduler_type == FIFO) {
        // forward the packet at the beginning of the queue
        popped_packet = PacketQueue::popPacket(gate);
        priority = extract_priority(popped_packet, false);
        auto priority_found = sorted_queued_packet_hash_table.find(priority);
        if (priority_found == sorted_queued_packet_hash_table.end() ||
                priority_found->second.size() == 0)
            throw cRuntimeError("PopPacket: Priority doesn't exist or its list is empty!");
        if (popped_packet != priority_found->second.front())
            throw cRuntimeError("popped_packet != priority_found->second.front()");
        priority_found->second.pop_front(); // the packet that is received last, it stored last in the list of each priority
        if (priority_found->second.size() == 0) {
            sorted_queued_packet_hash_table.erase(priority_found->first);
        }
    } else {
        // forward the packet with highest priority
        EV << "Forward the packet with highest priority" << endl;
        std::map<unsigned long, std::list<Packet*>>::iterator it =
                sorted_queued_packet_hash_table.begin();
        priority = it->first;
        popped_packet = check_and_cast<Packet *>(queue.remove(it->second.front()));
        if (popped_packet != it->second.front())
            throw cRuntimeError("popped_packet != it->second.front()");
        it->second.pop_front();
        if (it->second.size() == 0) {
            sorted_queued_packet_hash_table.erase(it->first);
        }
    }

    emit(packetPoppedSignal, popped_packet);
    simtime_t queueing_time = simTime() - popped_packet->getArrivalTime();
    all_packets_queueing_time_sum += queueing_time.dbl();
    num_all_packets++;
    auto eth_header = popped_packet->peekAtFront<EthernetMacHeader>();
    b flow_len = eth_header->getTotal_length();
    b payload_len = eth_header->getPayload_length();
    if (payload_len > b(0) && flow_len.get() <= MICE_FLOW_SIZE) {
        mice_packets_queueing_time_sum += queueing_time.dbl();
        num_mice_packets++;
    }
    if (packetCapacity != -1)
        cSimpleModule::emit(customQueueLengthSignal, getNumPackets());
    else
        cSimpleModule::emit(customQueueLengthSignalPacketBytes, getTotalLength().get());
    EV << "Final queue len: " << getNumPackets() << endl;

    if (!mark_packets_in_enqueue) {
        if (dctcp_thresh >= 0) {
            EV << "dctcp_thresh is " << dctcp_thresh << endl;
            auto eth_header = popped_packet->peekAtFront<EthernetMacHeader>();
            if (eth_header->getQueue_occupancy() >= dctcp_thresh) {
                EV << "marking at dequeue" << endl;
                std::string protocol = popped_packet->getName();
                if (protocol.find("tcpseg") != std::string::npos){
                    EcnMarker::setEcn(popped_packet, IP_ECN_CE);
                    EV << "SOUGOL: The ECN is marked for this popped_packet!" << endl;
                }
            }
        }
    }

    return popped_packet;
}

void V2PIFO::removePacket(Packet *packet)
{
    Enter_Method("removePacket");
    EV << "removePacket is called in V2PIFO" << endl;
    unsigned long priority = extract_priority(packet, false);
    auto priority_found = sorted_queued_packet_hash_table.find(priority);
    if (priority_found == sorted_queued_packet_hash_table.end() ||
            priority_found->second.size() == 0)
        throw cRuntimeError("The packet that is supposed to be removed doesn't exist!");
    priority_found->second.remove(packet);
    if (priority_found->second.size() == 0) {
        sorted_queued_packet_hash_table.erase(priority_found->first);
    }
    PacketQueue::removePacket(packet);
    emit(packetRemovedSignal, packet);
    if (packetCapacity != -1)
        cSimpleModule::emit(customQueueLengthSignal, getNumPackets());
    else
        cSimpleModule::emit(customQueueLengthSignalPacketBytes, getTotalLength().get());

    // TODO temp: check the correctness
//    check_correctness();
}

long V2PIFO::get_queue_occupancy(long on_the_way_packet_num, b on_the_way_packet_length)
{
    EV << "V2PIFO::get_queue_occupancy" << endl;
    if (getMaxNumPackets() != -1) {
        return (getNumPackets() + on_the_way_packet_num);
    }
    else if (getMaxTotalLength() != b(-1)) {
        return (getTotalLength() + on_the_way_packet_length).get();
    } else {
        throw cRuntimeError("No queue capacity specified! WTF?");
    }
}

bool V2PIFO::is_queue_full(b packet_length, long on_the_way_packet_num, b on_the_way_packet_length) {
    EV << "V2PIFO::is_queue_full" << endl;
    bool is_queue_full = (getMaxNumPackets() != -1 && getNumPackets() + on_the_way_packet_num >= getMaxNumPackets()) ||
            (getMaxTotalLength() != b(-1) && (getTotalLength() + on_the_way_packet_length + packet_length) >= getMaxTotalLength());
    EV << "Checking if queue is full" << endl;
    if (getMaxNumPackets() != -1)
        EV << "The queue capacity is " << getMaxNumPackets() << ", There are currently " << getNumPackets() << " packets inside the queue and " << on_the_way_packet_num << " packets on the way. Is the queue full? " << is_queue_full << endl;
    else if (getMaxTotalLength() != b(-1))
        EV << "The queue capacity is " << getMaxTotalLength() << ", Queue length is " << getTotalLength() << " and packet length is " << packet_length << " and " << on_the_way_packet_length << " bytes on the way. Is the queue full? " << is_queue_full << endl;
    return is_queue_full;
}
