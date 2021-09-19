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

#ifndef __INET_MULTISOCKETBASICCLIENT_H
#define __INET_MULTISOCKETBASICCLIENT_H

#include "inet/common/INETDefs.h"
#include "unordered_map"

#include "inet/common/lifecycle/ILifecycle.h"
#include "inet/common/lifecycle/NodeStatus.h"
#include "base/MultiSocketTcpAppBase.h"

using namespace inet;

/**
 * An example request-reply based client application.
 */
class INET_API MultiSocketBasicClient : public MultiSocketTcpAppBase
{
  protected:
//    cMessage *timeoutMsg = nullptr;
    bool earlySend = false;    // if true, don't wait with sendRequest() until established()
//    int numRequestsToSend;    // requests to send in this session
    simtime_t startTime;
    simtime_t stopTime;
    simtime_t sendTime;
    int num_requests_per_burst;
    bool is_mice_background;
    double background_inter_arrival_time_multiplier, background_flow_size_multiplier;
    double bursty_inter_arrival_time_multiplier, bursty_flow_size_multiplier;
    int repetition_num, app_index, parent_index;
    long replyLength, requestLength;

    // info for goodput
    std::unordered_map<long, b> chunk_length_keeper;
    std::unordered_map<long, b> total_length_keeper;

    virtual void sendRequest(long socket_id);
    virtual void rescheduleOrDeleteTimer(simtime_t d, short int msgKind, long socket_id=-1);

    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleTimer(cMessage *msg) override;

    virtual void socketEstablished(TcpSocket *socket) override;
    virtual void socketDataArrived(TcpSocket *socket, Packet *msg, bool urgent) override;
    virtual void socketClosed(TcpSocket *socket) override;
    virtual void socketFailure(TcpSocket *socket, int code) override;

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    virtual void close(int socket_id) override;
    virtual void finish() override;

    /*
     * reads the sql files. The sql files keep information like size of every flow, when it
     * should start etc. The information are put in lists for further use
     */
    virtual void read_value_from_db(std::string inter_arrival_db_path, std::string flow_size_db_path,
                std::string background_server_db_path, std::string bursty_server_db_path,
                std::string background_flow_ids_db_path, std::string bursty_flow_ids_db_path,
                std::string bursty_query_ids_db_path,
                std::string inter_arrival_table_name, std::string flow_size_table_name,
                std::string background_server_table_name, std::string bursty_server_table_name,
                std::string background_flow_ids_table_name, std::string bursty_flow_ids_table_name,
                std::string bursty_query_ids_table_name);

    /*
     * pops an interarrival time from the list
     */
    virtual double get_inter_arrival_time();

    /*
     * pops a flow size from the list
     */
    virtual int get_flow_size();

    /*
     * pops a destination for the flow
     */
    virtual int get_server_idx();

    /*
     * assigns an ID to the flow
     */
    virtual unsigned long get_flow_id();

    /*
     * assigns an ID to every query
     */
    virtual unsigned long get_query_id();

    /*
     * initiating connection
     */
    virtual void connect_for_bursty_request();
    virtual void connect_for_background_request();

    /*
     * getting a new port for new connections
     */
    virtual int get_local_port();

  public:
    MultiSocketBasicClient() {}
    virtual ~MultiSocketBasicClient();
    static simsignal_t flowEndedSignal;
    static simsignal_t flowEndedQueryIDSignal;
    static simsignal_t flowStartedSignal;
    static simsignal_t actualFlowStartedTimeSignal;
    static simsignal_t requestSentSignal;
    static simsignal_t notJitteredRequestSentSignal;
    static simsignal_t replyLengthsSignal;
    static simsignal_t chunksReceivedLengthSignal;
    static simsignal_t chunksReceivedTotalLengthSignal;

    /*
     * lists of different information about the flows
     */
    std::list <int> flow_sizes, background_server_idx, bursty_server_idx;
    std::list <double> inter_arrival_times;
    std::list <unsigned long> background_flow_ids, bursty_flow_ids;
    std::list <unsigned long> bursty_query_ids;
    bool is_bursty;
};

#endif

