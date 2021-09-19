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

#include "./MultiSocketBasicClient.h"
#include "inet/applications/common/SocketTag_m.h"


#include "inet/applications/tcpapp/GenericAppMsg_m.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/TimeTag_m.h"
#include <iostream>
#include <fstream>
#include <sqlite3.h>
#include <list>

using namespace inet;

#define MSGKIND_CONNECT    0
#define MSGKIND_SEND       1

#define MAX_PORT_NUM 65450      // 65535 - 85

Define_Module(MultiSocketBasicClient);

simsignal_t MultiSocketBasicClient::flowEndedSignal = registerSignal("flowEnded");
simsignal_t MultiSocketBasicClient::flowEndedQueryIDSignal = registerSignal("flowEndedQueryID");
simsignal_t MultiSocketBasicClient::flowStartedSignal = registerSignal("flowStarted");
simsignal_t MultiSocketBasicClient::actualFlowStartedTimeSignal = registerSignal("actualFlowStartedTime");
simsignal_t MultiSocketBasicClient::requestSentSignal = registerSignal("requestSent");
simsignal_t MultiSocketBasicClient::notJitteredRequestSentSignal = registerSignal("notJitteredRequestSent");
simsignal_t MultiSocketBasicClient::replyLengthsSignal = registerSignal("replyLengths");
simsignal_t MultiSocketBasicClient::chunksReceivedLengthSignal = registerSignal("chunksReceivedLength");
simsignal_t MultiSocketBasicClient::chunksReceivedTotalLengthSignal = registerSignal("chunksReceivedTotalLength");



MultiSocketBasicClient::~MultiSocketBasicClient()
{
}

void MultiSocketBasicClient::initialize(int stage)
{
    MultiSocketTcpAppBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        earlySend = false;    // TBD make it parameter
        WATCH(earlySend);

        startTime = par("startTime");
        stopTime = par("stopTime");
        sendTime = par("sendTime");

        is_bursty = par("is_bursty");
        is_mice_background = par("is_mice_background");

        if (int(is_bursty) + int(is_mice_background) > 1)
            throw cRuntimeError("Two roles chosen for one app.");


        background_inter_arrival_time_multiplier = par("background_inter_arrival_time_multiplier");
        background_flow_size_multiplier = par("background_flow_size_multiplier");
        bursty_inter_arrival_time_multiplier = par("bursty_inter_arrival_time_multiplier");
        bursty_flow_size_multiplier = par("bursty_flow_size_multiplier");

        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        repetition_num = atoi(getEnvir()->getConfigEx()->getVariable(CFGVAR_REPETITION));
        app_index = getIndex();
        parent_index = getParentModule()->getIndex();

        replyLength = par("replyLength");
        requestLength = par("requestLength");
        num_requests_per_burst = par("num_requests_per_burst");
    }
}

void MultiSocketBasicClient::handleStartOperation(LifecycleOperation *operation)
{
    EV << "SEPEHR: handleStartOperation called." << endl;

    std::string distributions_base_root = par("distibutions_base_root");

    // common bursty and bg values
    std::string rep_num_string = std::to_string(repetition_num);
    std::string application_category = par("application_category");
    std::string flow_multiplier;
    std::string inter_multiplier;
    std::string inter_arrival_db_name;
    std::string flow_size_db_name;

    // bursty values
    std::string num_requests_per_burst_string;
    std::string reply_length_string;
    std::string bursty_server_db_name;
    std::string bursty_flow_ids_db_name;
    std::string bursty_query_ids_db_name;

    // background values
    std::string background_server_db_name;
    std::string background_flow_ids_db_name;

    if (is_bursty) {

        // common bursty and bg values
        flow_multiplier = std::to_string(bursty_flow_size_multiplier);
        inter_multiplier = std::to_string(bursty_inter_arrival_time_multiplier);

        // bursty values
        num_requests_per_burst_string = std::to_string(num_requests_per_burst);
        reply_length_string = std::to_string(replyLength);

        // background values
        // none

        inter_arrival_db_name = distributions_base_root + "distributions/" + application_category + "_bursty_inter_arrival_time_db_" + flow_multiplier + "_flowmult_" + inter_multiplier + "_intermult_" + num_requests_per_burst_string + "_flows_per_incast_" + reply_length_string + "_incast_flow_size_" + rep_num_string + ".db";
        flow_size_db_name = distributions_base_root + "distributions/" + application_category + "_bursty_flow_size_db_" + flow_multiplier + "_flowmult_" + inter_multiplier + "_intermult_" + num_requests_per_burst_string + "_flows_per_incast_" + reply_length_string + "_incast_flow_size_" + rep_num_string + ".db";
        bursty_server_db_name = distributions_base_root + "distributions/" + application_category + "_bursty_server_idx_db_" + flow_multiplier + "_flowmult_" + inter_multiplier + "_intermult_"+ num_requests_per_burst_string + "_flows_per_incast_" + reply_length_string + "_incast_flow_size_" + rep_num_string + ".db";
        bursty_flow_ids_db_name = distributions_base_root + "distributions/" + application_category + "_bursty_flow_ids_db_" + flow_multiplier + "_flowmult_" + inter_multiplier + "_intermult_"+ num_requests_per_burst_string + "_flows_per_incast_" + reply_length_string + "_incast_flow_size_" + rep_num_string + ".db";
        bursty_query_ids_db_name = distributions_base_root + "distributions/" + application_category + "_bursty_query_ids_db_" + flow_multiplier + "_flowmult_" + inter_multiplier + "_intermult_"+ num_requests_per_burst_string + "_flows_per_incast_" + reply_length_string + "_incast_flow_size_" + rep_num_string + ".db";
        background_server_db_name = "";
        background_flow_ids_db_name = "";

    } else if (is_mice_background) {

        // common bursty and bg values
        flow_multiplier = std::to_string(background_flow_size_multiplier);
        inter_multiplier = std::to_string(background_inter_arrival_time_multiplier);

        // bursty values
        num_requests_per_burst_string = "";
        reply_length_string = "";

        // background values
        // none

        inter_arrival_db_name = distributions_base_root + "distributions/" + application_category + "_background_inter_arrival_time_db_" + flow_multiplier + "_flowmult_" + inter_multiplier + "_intermult_" + rep_num_string + ".db";
        flow_size_db_name = distributions_base_root + "distributions/" + application_category + "_background_flow_size_db_" + flow_multiplier + "_flowmult_" + inter_multiplier + "_intermult_" + rep_num_string + ".db";
        bursty_server_db_name = "";
        bursty_flow_ids_db_name = "";
        bursty_query_ids_db_name = "";
        background_server_db_name = distributions_base_root + "distributions/" + application_category + "_background_server_idx_db_" + flow_multiplier + "_flowmult_" + inter_multiplier + "_intermult_" + rep_num_string + ".db";
        background_flow_ids_db_name = distributions_base_root + "distributions/" + application_category + "_background_flow_ids_db_" + flow_multiplier + "_flowmult_" + inter_multiplier + "_intermult_" + rep_num_string + ".db";

    } else {
        throw cRuntimeError("It's the first time you're using elephant flows. You didn't consider it in things like application category. WATCH OUT!");
    }

    read_value_from_db(inter_arrival_db_name, flow_size_db_name, background_server_db_name, bursty_server_db_name,
            background_flow_ids_db_name, bursty_flow_ids_db_name, bursty_query_ids_db_name,
            "inter_arrival", "flow_size",
            "server_idx", "server_idx", "flow_ids", "flow_ids", "query_ids");

    // do nothing if the app was indicated as bursty but then changed to not bursty by reading from stay_bursty_db
    if (!is_bursty && !is_mice_background)
        return;

    simtime_t start = 0;
    if (is_bursty && inter_arrival_times.empty())
        return;
    if (((stopTime < SIMTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime))) {
        rescheduleOrDeleteTimer(get_inter_arrival_time(), MSGKIND_CONNECT);
    }
}

int MultiSocketBasicClient::get_local_port() {
    int local_port_pad = getParentModule()->par("local_padding");
    getParentModule()->par("local_padding") = (local_port_pad + 1) % MAX_PORT_NUM;
    int local_port_test = getParentModule()->par("local_padding");
    if (local_port_test != (local_port_pad + 1) % MAX_PORT_NUM) {
        throw cRuntimeError("The improbable situation has happened!. Multiple threads reading local_pad and increasing"
                "at the same time.");
    }
    EV << "Using local port " << 80 + local_port_pad << " for server["
            << getParentModule()->getIndex() << "].app[" << getIndex() << "]" << endl;
    return 80 + local_port_pad;
}

void MultiSocketBasicClient::connect_for_bursty_request() {
    bool incast_event_started = false;
    unsigned long query_id = get_query_id();
    for (int i = 0; i < num_requests_per_burst; i++){
        int server_idx = get_server_idx();
        if (server_idx == -1) {
            if (incast_event_started)
                throw cRuntimeError("Incast server idx became empty in the middle of an incast event!");
            return;
        }
        connect(get_local_port(), server_idx, 80, is_bursty, query_id);
        incast_event_started = true;
    }
    // The condition below shows that there are no more requests to be sent for bursty app
    if (is_bursty && inter_arrival_times.empty())
        return;
    rescheduleOrDeleteTimer(get_inter_arrival_time(), MSGKIND_CONNECT);

}

void MultiSocketBasicClient::connect_for_background_request() {
    connect(get_local_port(), get_server_idx(), 80);
    rescheduleOrDeleteTimer(get_inter_arrival_time(), MSGKIND_CONNECT);
}

void MultiSocketBasicClient::handleTimer(cMessage *msg)
{
    switch (msg->getKind()) {
        case MSGKIND_CONNECT:
            if (is_bursty)
                connect_for_bursty_request();
            else
                connect_for_background_request();
            delete msg;
            break;

        case MSGKIND_SEND:
            sendRequest(msg->par("socket_id").longValue());
            delete msg;
            break;

        default:
            throw cRuntimeError("Invalid timer msg: kind=%d", msg->getKind());
    }
}

void MultiSocketBasicClient::socketEstablished(TcpSocket *socket)
{
    MultiSocketTcpAppBase::socketEstablished(socket);
    EV << "SEPEHR: socket established!" << endl;
    simtime_t now = simTime();

    EV << "SEPEHR: SendRequest Called in socketEstablished." << endl;
//    socket_ids_for_requests.push_back(socket->getSocketId())

    rescheduleOrDeleteTimer(now, MSGKIND_SEND, socket->getSocketId());
}

void MultiSocketBasicClient::handleStopOperation(LifecycleOperation *operation)
{
    EV << "MultiSocketBasicClient::handleStopOperation called." << endl;
    for (auto socket_pair: socket_map.getMap()) {
        TcpSocket *socket = check_and_cast_nullable<TcpSocket*>(socket_pair.second);
        if (socket->getState() == TcpSocket::CONNECTED || socket->getState() == TcpSocket::CONNECTING || socket->getState() == TcpSocket::PEER_CLOSED)
                        close(socket->getSocketId());
    }

}

void MultiSocketBasicClient::handleCrashOperation(LifecycleOperation *operation)
{
    EV << "MultiSocketBasicClient::handleCrashOperation." << endl;
    if (operation->getRootModule() != getContainingNode(this)) {
        for (auto socket_pair: socket_map.getMap()) {
            TcpSocket *socket = check_and_cast_nullable<TcpSocket*>(socket_pair.second);
            socket->destroy();
        }
    }
}

void MultiSocketBasicClient::sendRequest(long socket_id)
{
    long reply_length = get_flow_size();
    if (requestLength < 1)
        throw cRuntimeError("request_length < 1, are you sure?");
    if (reply_length < 1)
        throw cRuntimeError("reply_length < 1, are you sure?");

    const auto& payload = makeShared<GenericAppMsg>();
    Packet *packet = new Packet("data");
    packet->addTag<SocketInd>()->setSocketId(socket_id);
    if (is_bursty) {
        unsigned long query_id = get_query_id_for_socket(packet);
        payload->setQuery_id(query_id);
    }
    payload->setChunkLength(B(requestLength));
    payload->setExpectedReplyLength(B(reply_length));
    payload->setServerClose(false);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    payload->setRequesterID(get_flow_id());
    payload->setRequested_time(simTime());
    payload->setIs_micro_burst_flow(is_bursty);
    packet->insertAtBack(payload);

    EV << "sending request with " << requestLength << " bytes, expected reply length " << reply_length << " bytes\n";
    EV << "SEPEHR: sending request with request ID: " << payload->getRequesterID() << endl;
    emit(requestSentSignal, payload->getRequesterID());
    emit(replyLengthsSignal, reply_length);
    if (is_bursty)
        emit(flowEndedQueryIDSignal, payload->getQuery_id());
    sendPacket(packet);
}

/*
 * Callbacks are called when reading from sql files
 * They push the values in the sql in different lists
 */

static int callback_inter_arrival(void *data, int argc, char **argv, char **azColName){
   int i;
   MultiSocketBasicClient *app_object = (MultiSocketBasicClient*) data;

   for(i = 0; i<argc; i++){
      if (std::strcmp(argv[i], "") != 0) {
          app_object->inter_arrival_times.push_back(std::stod(argv[i]));
      }
   }

   return 0;
}

static int callback_flow_size(void *data, int argc, char **argv, char **azColName){
   int i;
   MultiSocketBasicClient *app_object = (MultiSocketBasicClient*) data;

   for(i = 0; i<argc; i++){
      if (std::strcmp(argv[i], "") != 0) {
          app_object->flow_sizes.push_back(std::stoi(argv[i]));
      }
   }
   return 0;
}

static int callback_bursty_server(void *data, int argc, char **argv, char **azColName){
   int i;
   MultiSocketBasicClient *app_object = (MultiSocketBasicClient*) data;

   for(i = 0; i<argc; i++){
      if (std::strcmp(argv[i], "") != 0) {
          app_object->bursty_server_idx.push_back(std::stoi(argv[i]));
      }
   }
   return 0;
}

static int callback_background_server(void *data, int argc, char **argv, char **azColName){
   int i;
   MultiSocketBasicClient *app_object = (MultiSocketBasicClient*) data;

   for(i = 0; i<argc; i++){
      if (std::strcmp(argv[i], "") != 0) {
          app_object->background_server_idx.push_back(std::stoi(argv[i]));
      }
   }
   return 0;
}

static int callback_background_flow_ids(void *data, int argc, char **argv, char **azColName){
   int i;
   MultiSocketBasicClient *app_object = (MultiSocketBasicClient*) data;

   for(i = 0; i<argc; i++){
      if (std::strcmp(argv[i], "") != 0) {
          app_object->background_flow_ids.push_back(std::stoul(argv[i]));
      }
   }
   return 0;
}

static int callback_bursty_flow_ids(void *data, int argc, char **argv, char **azColName){
   int i;
   MultiSocketBasicClient *app_object = (MultiSocketBasicClient*) data;

   for(i = 0; i<argc; i++){
      if (std::strcmp(argv[i], "") != 0) {
          app_object->bursty_flow_ids.push_back(std::stoul(argv[i]));
      }
   }
   return 0;
}

static int callback_bursty_query_ids(void *data, int argc, char **argv, char **azColName){
   int i;
   MultiSocketBasicClient *app_object = (MultiSocketBasicClient*) data;

   for(i = 0; i<argc; i++){
      if (std::strcmp(argv[i], "") != 0) {
          app_object->bursty_query_ids.push_back(std::stoul(argv[i]));
      }
   }
   return 0;
}

void MultiSocketBasicClient::read_value_from_db(std::string inter_arrival_db_path, std::string flow_size_db_path,
        std::string background_server_db_path, std::string bursty_server_db_path,
        std::string background_flow_ids_db_path, std::string bursty_flow_ids_db_path,
        std::string bursty_query_ids_db_path,
        std::string inter_arrival_table_name, std::string flow_size_table_name,
        std::string background_server_table_name, std::string bursty_server_table_name,
        std::string background_flow_ids_table_name, std::string bursty_flow_ids_table_name,
        std::string bursty_query_ids_table_name)
{
    std::string column_name = "server" + std::to_string(parent_index) + "app" + std::to_string(app_index);

    sqlite3* DB;
    char *zErrMsg = 0;
    int rc;
    std::string sql;
    int exit = 0;


    if (is_bursty) {

        exit = sqlite3_open(inter_arrival_db_path.c_str(), &DB);
        if (exit) {
            throw cRuntimeError(sqlite3_errmsg(DB));
            return;
        }
        sql = "SELECT " + column_name + " from " + inter_arrival_table_name;
        rc = sqlite3_exec(DB, sql.c_str(), callback_inter_arrival, (void*)this, &zErrMsg);
        if( rc != SQLITE_OK ) {
          throw cRuntimeError("SQL error: %s\n", zErrMsg);
        }
        sqlite3_close(DB);


        exit = sqlite3_open(bursty_server_db_path.c_str(), &DB);
        if (exit) {
            throw cRuntimeError(sqlite3_errmsg(DB));
            return;
        }
        sql = "SELECT " + column_name + " from " + bursty_server_table_name;
        rc = sqlite3_exec(DB, sql.c_str(), callback_bursty_server, (void*)this, &zErrMsg);
        if( rc != SQLITE_OK ) {
          throw cRuntimeError("SQL error: %s\n", zErrMsg);
        }
        sqlite3_close(DB);


        exit = sqlite3_open(bursty_flow_ids_db_path.c_str(), &DB);
        if (exit) {
            throw cRuntimeError(sqlite3_errmsg(DB));
            return;
        }
        sql = "SELECT " + column_name + " from " + bursty_flow_ids_table_name;
        rc = sqlite3_exec(DB, sql.c_str(), callback_bursty_flow_ids, (void*)this, &zErrMsg);
        if( rc != SQLITE_OK ) {
          throw cRuntimeError("SQL error: %s\n", zErrMsg);
        }
        sqlite3_close(DB);


        exit = sqlite3_open(bursty_query_ids_db_path.c_str(), &DB);
        if (exit) {
            throw cRuntimeError(sqlite3_errmsg(DB));
            return;
        }
        sql = "SELECT " + column_name + " from " + bursty_query_ids_table_name;
        rc = sqlite3_exec(DB, sql.c_str(), callback_bursty_query_ids, (void*)this, &zErrMsg);
        if( rc != SQLITE_OK ) {
          throw cRuntimeError("SQL error: %s\n", zErrMsg);
        }
        sqlite3_close(DB);
    }
    else {

        exit = sqlite3_open(inter_arrival_db_path.c_str(), &DB);
        if (exit) {
            throw cRuntimeError(sqlite3_errmsg(DB));
            return;
        }
        sql = "SELECT " + column_name + " from " + inter_arrival_table_name;
        rc = sqlite3_exec(DB, sql.c_str(), callback_inter_arrival, (void*)this, &zErrMsg);
        if( rc != SQLITE_OK ) {
          throw cRuntimeError("SQL error: %s\n", zErrMsg);
        }
        sqlite3_close(DB);



        exit = sqlite3_open(flow_size_db_path.c_str(), &DB);
        if (exit) {
            throw cRuntimeError(sqlite3_errmsg(DB));
            return;
        }
        sql = "SELECT " + column_name + " from " + flow_size_table_name;
        rc = sqlite3_exec(DB, sql.c_str(), callback_flow_size, (void*)this, &zErrMsg);

        if( rc != SQLITE_OK ) {
          throw cRuntimeError("SQL error: %s\n", zErrMsg);
        }
        sqlite3_close(DB);



        exit = sqlite3_open(background_server_db_path.c_str(), &DB);
        if (exit) {
            throw cRuntimeError(sqlite3_errmsg(DB));
            return;
        }
        sql = "SELECT " + column_name + " from " + background_server_table_name;
        rc = sqlite3_exec(DB, sql.c_str(), callback_background_server, (void*)this, &zErrMsg);

        if( rc != SQLITE_OK ) {
          throw cRuntimeError("SQL error: %s\n", zErrMsg);
        }
        sqlite3_close(DB);



        exit = sqlite3_open(background_flow_ids_db_path.c_str(), &DB);
        if (exit) {
            throw cRuntimeError(sqlite3_errmsg(DB));
            return;
        }
        sql = "SELECT " + column_name + " from " + background_flow_ids_table_name;
        rc = sqlite3_exec(DB, sql.c_str(), callback_background_flow_ids, (void*)this, &zErrMsg);

        if( rc != SQLITE_OK ) {
          throw cRuntimeError("SQL error: %s\n", zErrMsg);
        }
        sqlite3_close(DB);

    }
}

int MultiSocketBasicClient::get_server_idx() {
    int server_idx;
    if (is_bursty) {
        if (bursty_server_idx.empty()) {
            return -1;
        }
        server_idx = bursty_server_idx.front();
        bursty_server_idx.pop_front();
    } else {
        if (background_server_idx.empty()) {
            throw cRuntimeError("You're trying to read from background_server_idx while it's empty");
        }
        server_idx = background_server_idx.front();
        background_server_idx.pop_front();
    }
    return server_idx;
}

double MultiSocketBasicClient::get_inter_arrival_time() {
    // Because every app sends background flows independently, the inter_arrival_times for background
    // flows is relative to the time previous flow was sent --> Small values, so we add now to it
    // For incsat flows, because the inter_arrival times are between different apps, the values are actually
    // the time that the flow should be sent --> large values, so we return it independently
    if (inter_arrival_times.empty()) {
        throw cRuntimeError("You're trying to read from inter_arrival_times while it's empty");
    }
    double inter_arrival_time = inter_arrival_times.front();
    // for bursty flows, 1 inter-arrival is recorded equal to the number of req per incast
    if (is_bursty) {
        for (int i = 0; i < num_requests_per_burst; i++) {
            if (inter_arrival_times.empty())
                throw cRuntimeError("There is a problem with the number of elements in inter_arrival_times.");
            inter_arrival_times.pop_front();
        }
        return inter_arrival_time;
    }
    else {
        inter_arrival_times.pop_front();
        simtime_t now = simTime();
        return now.dbl() + inter_arrival_time;
    }
}

int MultiSocketBasicClient::get_flow_size() {
    if (is_bursty) {
        return replyLength;
    }
    else {
        if (flow_sizes.empty()) {
            throw cRuntimeError("You're trying to read from flow_sizes while it's empty");
        }
        int flow_size = flow_sizes.front();
        flow_sizes.pop_front();
        return flow_size;
    }
}

unsigned long MultiSocketBasicClient::get_flow_id() {
    unsigned long flow_id;
    if (is_bursty) {
        if (bursty_flow_ids.empty()) {
            throw cRuntimeError("You're trying to read from bursty_flow_ids while it's empty. How is that possible "
                    "if you already checked the server idx?");
        }
        flow_id = bursty_flow_ids.front();
        bursty_flow_ids.pop_front();
    } else {
        if (background_flow_ids.empty()) {
            throw cRuntimeError("You're trying to read from background_flow_ids while it's empty");
        }
        flow_id = background_flow_ids.front();
        background_flow_ids.pop_front();
    }
    return flow_id;
}

unsigned long MultiSocketBasicClient::get_query_id() {
    unsigned long query_id;
    if (is_bursty) {
        if (bursty_query_ids.empty()) {
            throw cRuntimeError("You're trying to read from bursty_query_ids while it's empty. How is that possible "
                    "if you already checked the server idx?");
        }
        query_id = bursty_query_ids.front();
        bursty_query_ids.pop_front();
    } else {
        throw cRuntimeError("There is not query ID for BG flows!");
    }
    return query_id;
}


void MultiSocketBasicClient::rescheduleOrDeleteTimer(simtime_t d, short int msgKind, long socket_id)
{
    if (stopTime < SIMTIME_ZERO || d < stopTime) {
        cMessage *timeoutMsg = new cMessage("timer");
        timeoutMsg->setKind(msgKind);
        if (socket_id >= 0)
            timeoutMsg->addPar("socket_id") = socket_id;
        EV << "SEPEHR: rescheduleOrDeleteTimer is called to schedule to send a packet at " << d << "s" << endl;
        scheduleAt(d, timeoutMsg);
    }
}

void MultiSocketBasicClient::socketDataArrived(TcpSocket *socket, Packet *msg, bool urgent)
{
    EV << "SEPEHR: Message rcved: " << msg << endl;
    simtime_t region_creation_time = msg->getTag<RegionCreationTimeTag>()->getRegionCreationTime();
    auto msg_dup = msg->dup();
    auto chunk = msg_dup->removeAtFront<SliceChunk>();
    bool should_close = false;
    int socket_id = socket->getSocketId();
    while (true) {
        auto chunk_length = chunk->getLength();
        auto chunk_offset = chunk->getOffset();
        auto main_chunk = chunk->getChunk();
        auto total_length = main_chunk->getChunkLength();
        auto history_found = chunk_length_keeper.find(socket_id);
        auto total_length_found = total_length_keeper.find(socket_id);
        if (history_found != chunk_length_keeper.end()) {
            // Some data has been received for this chunk before
            if (total_length_found == total_length_keeper.end())
                throw cRuntimeError("How do we have a record for a chunk "
                        "but not a record for its total data length!");
            history_found->second += chunk_length;
        } else {
            // This is the first data received for this chunk
            if (total_length_found != total_length_keeper.end())
                throw cRuntimeError("How do we have a record for the total data length of a chunk "
                        "but not a record of the chunk itself!");
            chunk_length_keeper.insert(std::pair<long, b>(socket_id, chunk_length));
            total_length_keeper.insert(std::pair<long, b>(socket_id, total_length));
        }
        if (chunk_offset == b(0)) {
            Packet* temp = new Packet();
            temp->insertAtBack(main_chunk);
            auto payload = temp->popAtFront<GenericAppMsg>();
            // start time should actually be the time that the first packet (whether re-ordered or not is received)
            if (payload->getRequested_time() > region_creation_time)
                throw cRuntimeError("How can the response be received before request is sent.");
            simtime_t actual_start_time = std::min(region_creation_time, simTime());
            emit(flowStartedSignal, payload->getRequesterID());
            emit(actualFlowStartedTimeSignal, actual_start_time);
            delete temp;
        }
        if (chunk_length + chunk_offset == total_length) {
            Packet* temp = new Packet();
            temp->insertAtBack(main_chunk);
            auto payload = temp->popAtFront<GenericAppMsg>();
            // End time should be exactly the time the packet is received even if there was a reordering
            emit(flowEndedSignal, payload->getRequesterID());

            auto chunk_found = chunk_length_keeper.find(socket_id);
            auto total_length_found = total_length_keeper.find(socket_id);
            if (chunk_found == chunk_length_keeper.end() || total_length_found == total_length_keeper.end())
                throw cRuntimeError("chunk_found == chunk_length_keeper.end() || "
                        "total_length_found == total_length_keeper.end()");
            emit(chunksReceivedLengthSignal, chunk_found->second.get());
            emit(chunksReceivedTotalLengthSignal, total_length_found->second.get());
            chunk_length_keeper.erase(socket_id);
            total_length_keeper.erase(socket_id);

            should_close = true;
            delete temp;
        } else if (chunk_length + chunk_offset > total_length)
            throw cRuntimeError("chunk_length + chunk_offset > total_length");
        if (msg_dup->getByteLength() == 0)
            break;
        chunk = msg_dup->removeAtFront<SliceChunk>();
    }

    delete msg_dup;
    MultiSocketTcpAppBase::socketDataArrived(socket, msg, urgent);
    EV_INFO << "reply arrived\n";
    if (should_close) {
        EV << "SEPEHR: Last packet arrived. Closing the socket." << endl;
        close(socket->getSocketId());
    }
    else if (simTime() >= stopTime && socket->getState() != TcpSocket::LOCALLY_CLOSED) {
        EV_INFO << "reply to last request arrived, closing session\n";
        close(socket->getSocketId());
    }
}

void MultiSocketBasicClient::close(int socket_id)
{
    EV << "SEPEHR: closing the socket in server[" << parent_index << "].app["
                << app_index << "] with socket ID " << socket_id
                << ". Time = " << simTime() << endl;
    MultiSocketTcpAppBase::close(socket_id);
}

void MultiSocketBasicClient::finish()
{
    for(std::unordered_map<long, b>::iterator it = chunk_length_keeper.begin();
            it != chunk_length_keeper.end(); it++) {
        auto total_length_found = total_length_keeper.find(it->first);
        if (total_length_found == total_length_keeper.end()) {
            throw cRuntimeError("Mismatch between chunk_length_keeper and total_length_keeper");
        }
        emit(chunksReceivedLengthSignal, it->second.get());
        emit(chunksReceivedTotalLengthSignal, total_length_found->second.get());
    }
    chunk_length_keeper.clear();
    total_length_keeper.clear();
    MultiSocketTcpAppBase::finish();
}

void MultiSocketBasicClient::socketClosed(TcpSocket *socket)
{
    EV << "SEPEHR: Socket closed in server[" << parent_index << "].app["
            << app_index << "] with socket ID " << socket->getSocketId()
            << ". Time = " << simTime() << endl;
    MultiSocketTcpAppBase::socketClosed(socket);
}

void MultiSocketBasicClient::socketFailure(TcpSocket *socket, int code)
{
    MultiSocketTcpAppBase::socketFailure(socket, code);
}

