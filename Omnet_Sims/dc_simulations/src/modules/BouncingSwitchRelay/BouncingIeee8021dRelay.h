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

#ifndef BOUNCINGIEEE8021DRELAY_H
#define BOUNCINGIEEE8021DRELAY_H

#include "inet/common/INETDefs.h"
#include "inet/common/LayeredProtocolBase.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/InterfaceTable.h"
#include "inet/linklayer/configurator/Ieee8021dInterfaceData.h"
#include "inet/linklayer/ethernet/EtherFrame_m.h"
#include "../LSSwitch/LSMACTable/LSIMacAddressTable.h"
#include "../Augmented_Mac/AugmentedEtherMac.h"
#include "../V2/V2PIFO.h"

using namespace inet;

/*
 * The version of relay unit we defined to support deflection
 */
class BouncingIeee8021dRelay : public LayeredProtocolBase
{
  public:
    BouncingIeee8021dRelay();
    virtual ~BouncingIeee8021dRelay();

    /**
     * Register single MAC address that this switch supports.
     */

    void registerAddress(MacAddress mac);

    /**
     * Register range of MAC addresses that this switch supports.
     */
    void registerAddresses(MacAddress startMac, MacAddress endMac);

  protected:
    MacAddress bridgeAddress;
    IInterfaceTable *ifTable = nullptr;
    LSIMacAddressTable *macTable = nullptr;
    InterfaceEntry *ie = nullptr;
    bool isStpAware = false;

    /*
     * Information required for LB and deflection
     */
    std::list<int> port_idx_connected_to_switch_neioghbors;
    int random_power_factor;
    int random_power_bounce_factor;
    bool use_ecmp, use_power_of_n_lb;
    std::hash<std::string> header_hash;

    /*
     * DIBS
     */
    bool bounce_randomly;

    /*
     * V2
     */
    bool bounce_randomly_v2;
    bool use_v2_pifo;

    typedef std::pair<MacAddress, MacAddress> MacAddressPair;

    static simsignal_t feedBackPacketDroppedSignal;
    static simsignal_t feedBackPacketDroppedPortSignal;
    static simsignal_t feedBackPacketGeneratedSignal;
    static simsignal_t feedBackPacketGeneratedReqIDSignal;
    static simsignal_t bounceLimitPassedSignal;
    static simsignal_t burstyPacketReceivedSignal;
    unsigned long long light_in_relay_packet_drop_counter = 0;


    struct Comp
    {
        bool operator() (const MacAddressPair& first, const MacAddressPair& second) const
        {
            return (first.first < second.first && first.second < second.first);
        }
    };

    bool in_range(const std::set<MacAddressPair, Comp>& ranges, MacAddress value)
    {
        return ranges.find(MacAddressPair(value, value)) != ranges.end();
    }


    std::set<MacAddressPair, Comp> registeredMacAddresses;

    // statistics: see finish() for details.
    int numReceivedNetworkFrames = 0;
    int numDroppedFrames = 0;
    int numReceivedBPDUsFromSTP = 0;
    int numDeliveredBDPUsToSTP = 0;
    int numDispatchedNonBPDUFrames = 0;
    int numDispatchedBDPUFrames = 0;
    bool learn_mac_addresses;

  protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

    /**
     * Updates address table (if the port is in learning state)
     * with source address, determines output port
     * and sends out (or broadcasts) frame on ports
     * (if the ports are in forwarding state).
     * Includes calls to updateTableWithAddress() and getPortForAddress().
     *
     */
    void handleAndDispatchFrame(Packet *packet);

    void handleUpperPacket(Packet *packet) override;
    void handleLowerPacket(Packet *packet) override;

    void dispatch(Packet *packet, InterfaceEntry *ie);
    void learn(MacAddress srcAddr, int arrivalInterfaceId);
    void broadcast(Packet *packet, int arrivalInterfaceId);

    void sendUp(Packet *packet);

    //@{ For ECMP
    void chooseDispatchType(Packet *packet, InterfaceEntry *ie);
    //@}

    //@{ For lifecycle
    virtual void start();
    virtual void stop();
    virtual void handleStartOperation(LifecycleOperation *operation) override { start(); }
    virtual void handleStopOperation(LifecycleOperation *operation) override { stop(); }
    virtual void handleCrashOperation(LifecycleOperation *operation) override { stop(); }
    virtual bool isUpperMessage(cMessage *message) override { return message->arrivedOn("upperLayerIn"); }
    virtual bool isLowerMessage(cMessage *message) override { return message->arrivedOn("ifIn"); }

    virtual bool isInitializeStage(int stage) override { return stage == INITSTAGE_LINK_LAYER; }
    virtual bool isModuleStartStage(int stage) override { return stage == ModuleStartOperation::STAGE_LINK_LAYER; }
    virtual bool isModuleStopStage(int stage) override { return stage == ModuleStopOperation::STAGE_LINK_LAYER; }
    //@}

    /*
     * Gets port data from the InterfaceTable
     */
    Ieee8021dInterfaceData *getPortInterfaceData(unsigned int portNum);

    bool isForwardingInterface(InterfaceEntry *ie);

    /*
     * Returns the first non-loopback interface.
     */
    virtual InterfaceEntry *chooseInterface();
    virtual void finish() override;

    /*
     * Handle's DIBS deflection
     */
    InterfaceEntry* find_interface_to_bounce_randomly(Packet *packet);

    /*
     * Handles Valinor forwarding and deflection
     */
    InterfaceEntry* find_interface_to_fw_randomly_power_of_n(Packet *packet, bool consider_servers);
    void find_interface_to_bounce_randomly_v2(Packet *packet, bool consider_servers, InterfaceEntry *ie2);
};


#endif // ifndef __INET_BouncingIEEE8021DRELAY_H

