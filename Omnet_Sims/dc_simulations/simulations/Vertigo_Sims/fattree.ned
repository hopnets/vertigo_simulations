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

package dc_simulations.simulations.Vertigo_Sims;

import inet.networklayer.common.InterfaceTable;
import inet.networklayer.arp.ipv4.GlobalArp;
import inet.networklayer.configurator.ipv4.Ipv4FlatNetworkConfigurator;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import dc_simulations.modules.LSSwitch.LSNode.LSEtherSwitch;
import ned.DatarateChannel;
import inet.node.ethernet.EtherSwitch;
import dc_simulations.modules.Host.HostWithPortPadding.PortPaddingStandardHost;



//
// TODO auto-generated type
//
network FatTree
{
    parameters:
        @display("bgb=643,481");
        int k;
        int num_bursty_apps = default(0);
        int num_mice_background_flow_apps_in_each_server = default(0);
        int num_elephant_background_flow_apps_in_each_server = default(0);
    types:
        channel C extends DatarateChannel
        {
            datarate = 10Gbps;
            delay = 1us;
        }

    submodules:
        core[int(k/2)*int(k/2)]: LSEtherSwitch {
            parameters:
            	@display("p=100,100,r,50");
            gates:
                ethg[k];
        }
        agg[k * int(k/2)]: LSEtherSwitch {
            parameters:
                @display("p=100,200,r,50");
            gates:
                ethg[k];
        }
        edge[k * int(k/2)]: LSEtherSwitch {
            parameters:
                @display("p=100,300,r,50");
            gates:
                ethg[k];
        }
        server[k * int(k/2) * int(k/2)]: PortPaddingStandardHost {
            // k pods * k/2 edges per pod * k/2 servers per edge
            parameters:
            	@display("p=100,400,r,50");
        }
        configurator: Ipv4NetworkConfigurator;
//    connections allowunconnected:
    connections:
        // iterate over the servers
        for i=0..(k * int(k/2) * int(k/2))-1 {
            server[i].ethg++ <--> C <--> edge[int(i/(k/2))].ethg[i%int(k/2)];
        }
        // iterate over edges
        for i=0..(int(k/2)*k)-1, for j=(int(k/2))..k-1 {
            edge[i].ethg[j] <--> C <--> agg[(int(i/(k/2)) * int(k/2)) + (j - int(k/2))].ethg[i%(int(k/2))];
        }
        // iterate over aggs
        for i=0..(int(k/2)*k)-1, for j=int(k/2)..k-1 {
            agg[i].ethg[j] <--> C <--> core[(i%int(k/2)) * int(k/2) + (j - int(k/2))].ethg[int(i / (k / 2))];
        }
}
