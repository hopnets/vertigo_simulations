//
// Copyright (C) 2004 Andras Varga
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

package dc_simulations.modules.App;

import inet.applications.contract.IApp;

//
// Client for a generic request-response style protocol over TCP.
// May be used as a rough model of HTTP or FTP users.
// Compatible with both IPv4 (~Ipv4) and IPv6 (~Ipv6).
//
// The model communicates with the server in sessions. During a session,
// the client opens a single TCP connection to the server, sends several
// requests (always waiting for the complete reply to arrive before
// sending a new request), and closes the connection.
//
// The server app should be ~TcpGenericServerApp; the model sends ~GenericAppMsg
// messages.
//
// Example settings:
//
// FTP:
// <pre>
//    numRequestsPerSession = exponential(3)
//    requestLength = 1B*int(truncnormal(20,5))
//    replyLength = 1B*int(exponential(1000000))
// </pre>
//
// Note that this module doesn't open separate TCP connections for commands
// and data transfer as the FTP protocol.
//
// HTTP:
// <pre>
//    numRequestsPerSession = 1 <i>(HTTP 1.0)</i>
//    numRequestsPerSession = exponential(5) <i>(HTTP 1.1, with keepalive)</i>
//    requestLength = 1B*int(truncnormal(350,20))
//    replyLength = 1B*int(exponential(2000))
// </pre>
//
// Note that since most web pages contain images and may contain frames,
// applets etc, possibly from various servers, and browsers usually download
// these items in parallel to the main HTML document, this module cannot
// serve as a realistic web client.
//
// Also, with HTTP 1.0 it is the server that closes the connection after
// sending the response, while in this model it is the client.
//
// @see ~TcpGenericServerApp, ~GenericAppMsg, ~TelnetApp
//
simple MultiSocketBasicClient like IApp
{
    parameters:
        string localAddress = default(""); // may be left empty ("")
        int localPort = default(-1); // port number to listen on
        string connectAddress = default("");  // server address (may be symbolic)
        int connectPort = default(1000); // port number to connect to
        double startTime @unit(s) = default(0s); // time first session begins
        double stopTime @unit(s) = default(100000s);
        double sendTime @unit(s) = default(0s);
        volatile int numRequestsToSend = default(1);  // number of requests sent per session
        volatile int requestLength @unit(B) = default(200B); // length of a request
        volatile int replyLength @unit(B) = default(1MiB); // length of a reply
        volatile double idleInterval @unit(s) = default(30s); // time gap between sessions
        volatile double reconnectInterval @unit(s) = default(30s);  // if connection breaks, waits this much before trying to reconnect
        int timeToLive = default(-1); // if not -1, set the TTL (IPv4) or Hop Limit (IPv6) field of sent packets to this value
        int dscp = default(-1); // if not -1, set the DSCP (IPv4/IPv6) field of sent packets to this value
        
        // indicates whether the app is responsible for requesting incast or bg flow
        bool is_bursty = default(false);
        bool is_mice_background = default(false);

		// incast scale
        int num_requests_per_burst = default(0);
        
        // multiplier for background flow size and inter-arrival time to achieve different 
        // degrees of load
        double background_flow_size_multiplier = default(1);
        double background_inter_arrival_time_multiplier = default(1);
        
        // incast inter-arrival time (QPS)
        double bursty_inter_arrival_time_multiplier = default(1);
        // no need to scale incast flow size distribution. The flow size is read statically from
        // replyLength variable
        double bursty_flow_size_multiplier = default(1);

		// indicates what sql file should be read for the information
        string application_category = default("");
        
        // the path to distribution files
        string distibutions_base_root = default("./");
        
        @display("i=block/app");
        @lifecycleSupport;
        double stopOperationExtraTime @unit(s) = default(-1s);    // extra time after lifecycle stop operation finished
        double stopOperationTimeout @unit(s) = default(2s);    // timeout value for lifecycle stop operation
        @signal[packetSent](type=inet::Packet);
        @signal[packetReceived](type=inet::Packet);
        @signal[connect](type=long);  // 1 for open, -1 for close
        @signal[flowEnded](type=long);
        @signal[flowEndedQueryID]();
        @signal[flowStarted](type=long);
        @signal[actualFlowStartedTime]();
        @signal[requestSent](type=long);
        @signal[notJitteredRequestSent](type=long);
        @signal[replyLengths]();
        @signal[chunksReceivedLength]();
        @signal[chunksReceivedTotalLength]();
        @statistic[packetReceived](title="packets received"; source=packetReceived; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[packetSent](title="packets sent"; source=packetSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[endToEndDelay](title="end-to-end delay"; source="dataAge(packetReceived)"; unit=s; record=histogram,weightedHistogram,vector; interpolationmode=none);
        @statistic[numActiveSessions](title="number of active sessions"; source="sum(connect)"; record=max,timeavg,vector; interpolationmode=sample-hold);
        @statistic[numSessions](title="total number of sessions"; source="sum(connect+1)/2"; record=last);
        @statistic[flowEndedRequesterID](title="flow ended requester id"; source="flowEnded"; record=vector; interpolationmode=none);
        @statistic[flowEndQueryID](title="flow ended query id"; source="flowEndedQueryID"; record=vector; interpolationmode=none);
        @statistic[flowStartedRequesterID](title="flow started requester id"; source="flowStarted"; record=vector; interpolationmode=none);
        @statistic[flowStartedActualTime](title="flow started actual time"; source="actualFlowStartedTime"; record=vector; interpolationmode=none);
        @statistic[requestSentRequesterID](title="request sent requester id"; source="requestSent"; record=vector; interpolationmode=none);
        @statistic[notJitteredRequestSentTime](title="not jittered request sent requester id"; source="notJitteredRequestSent"; record=vector; interpolationmode=none);
        @statistic[replyLengthAsked](title="reply length of the packets"; source="replyLengths"; record=vector; interpolationmode=none);
        @statistic[chunksRcvdLength](title="length of chunks received in application layer"; source="chunksReceivedLength"; record=vector; interpolationmode=none);
        @statistic[chunksRcvdTotalLength](title="length of data that the received chunk is part of"; source="chunksReceivedTotalLength"; record=vector; interpolationmode=none);
        
    gates:
        input socketIn @labels(TcpCommand/up);
        output socketOut @labels(TcpCommand/down);
}

