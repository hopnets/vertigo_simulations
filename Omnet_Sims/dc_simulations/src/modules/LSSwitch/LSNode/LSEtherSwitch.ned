//
// Copyright (C) 2003 Andras Varga; CTIE, Monash University, Australia
//               2010 Zoltan Bojthe
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

package dc_simulations.modules.LSSwitch.LSNode;

import inet.common.MessageDispatcher;
import inet.common.lifecycle.NodeStatus;
import inet.common.packet.recorder.PcapRecorder;
import inet.linklayer.configurator.L2NodeConfigurator;
import inet.linklayer.contract.IEthernetInterface;
import inet.linklayer.contract.IExternalInterface;
import dc_simulations.modules.LSSwitch.LSMACTable.LSIMacAddressTable;
import inet.linklayer.contract.IMacRelayUnit;
import inet.linklayer.contract.ISpanningTree;
import inet.linklayer.ethernet.IEtherEncap;
import inet.networklayer.common.InterfaceTable;

//
// Model of an Ethernet switch.
//
// The duplexChannel attributes of the MACs must be set according to the
// medium connected to the port; if collisions are possible (it's a bus or hub)
// it must be set to false, otherwise it can be set to true.
// By default used half duples CSMA/CD mac
//
//
module LSEtherSwitch
{
    parameters:
        @networkNode();
        @labels(node,ethernet-node);
        @display("i=device/switch");
        int numPcapRecorders = default(0);
        bool hasStatus = default(false);
        bool hasStp = default(false);
        bool learn_mac_addresses = default(true);
        bool bounce_back_random_port = default(false);
        bool csmacdSupport = default(true);  // by default use CSMA/CD --FIXME remove
        string fcsMode @enum("declared","computed") = default("declared");
        string spanningTreeProtocol = default("Stp");
        int numEthInterfaces = default(0);  // minimum number of ethernet interfaces
        eth[*].encap.typename = "EtherEncapDummy";
        eth[*].csmacdSupport = csmacdSupport;
        eth[*].mac.typename = default(csmacdSupport ? "EtherMac" : "EtherMacFullDuplex");
        *.fcsMode = fcsMode;
        *.interfaceTableModule = default(absPath(".interfaceTable"));
        *.macTableModule = default(absPath(".macTable"));
        
        // DIBS
        bool bounce_randomly = default(false);
        
        // Power of N bouncing: Valinor
        bool bounce_randomly_v2 = default(false);
        bool use_v2_pifo = default(false); 
        int random_power_bounce_factor = default(2);
        double denominator_for_retrasnmissions = default(2);

		// Load Balancing
		bool useECMP = default(false);
		bool use_power_of_n_lb = default(false);
        int random_power_factor = default(2);
		
        relayUnit.hasStp = hasStp;
        relayUnit.learn_mac_addresses = learn_mac_addresses;
        encap.registerProtocol = true;

    gates:
        inout ethg[numEthInterfaces] @labels(EtherFrame-conn);
    submodules:
        status: NodeStatus if hasStatus {
            @display("p=100,400;is=s");
        }
        l2NodeConfigurator: L2NodeConfigurator if hasStp {
            @display("p=100,300;is=s");
        }
        interfaceTable: InterfaceTable {
            @display("p=100,200;is=s");
        }
        pcapRecorder[numPcapRecorders]: PcapRecorder {
            @display("p=100,500;is=s");
        }
        macTable: <default("LSMacAddressTable")> like LSIMacAddressTable {
            @display("p=100,100;is=s");
        }
        relayUnit: <default(firstAvailable("LSIeee8021dRelay"))> like IMacRelayUnit {
            @display("p=800,300;is=m");
        }
        stp: <spanningTreeProtocol> like ISpanningTree if hasStp {
            @display("p=474,92");
        }
        up: MessageDispatcher {
            parameters:
                @display("p=800,160;b=1200,5");
        }
        down: MessageDispatcher {
            parameters:
                @display("p=800,380;b=1200,5");
        }
        eth[sizeof(ethg)]: <default("EthernetInterface")> like IEthernetInterface {
            parameters:
                mac.promiscuous = true;
                @display("p=250,450,row,150;q=txQueue");
        }
        encap: <default("EtherEncap")> like IEtherEncap {
            @display("p=800,220");
        }
    connections:
        relayUnit.ifOut --> down.in++;
        relayUnit.ifIn <-- down.out++;

        encap.lowerLayerIn <-- relayUnit.upperLayerOut;
        encap.lowerLayerOut --> relayUnit.upperLayerIn;

        encap.upperLayerIn <-- up.out++;
        encap.upperLayerOut --> up.in++;

        for i=0..sizeof(ethg)-1 {
            down.out++ --> eth[i].upperLayerIn;
            down.in++ <-- eth[i].upperLayerOut;
            eth[i].phys <--> { @display("m=s"); } <--> ethg[i];
        }

        if hasStp {
            stp.relayIn <-- up.out++; // relayUnit.stpOut;
            stp.relayOut --> up.in++; // relayUnit.stpIn;
        }
}

