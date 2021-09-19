//
// Copyright (C) 2004-2005 Andras Varga
// Copyright (C) 2009 Thomas Reschka
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

#include <algorithm>    // min,max

#include "inet/transportlayer/tcp/Tcp.h"
#include "inet/transportlayer/tcp/flavours/Swift.h"
#include <math.h>

#define MIN_CWND_PACKET_NUMBER 0.001    // 0.001 packets
#define MAX_CWND_PACKET_NUMBER 43      // borrowed from TCP. around 65536 bytes
#define RETX_RESET_THRESHOLD 12    // borrowed from TCP max RTO num
#define MAX_CONST_RTO_COUNT 8   // just a hack to avoid aboring

#define ENDPOINT 0
#define FABRIC 1

//PACING TYPES
#define RETRANSMISSION 0
#define NORMAL 1

namespace inet {
namespace tcp {

Register_Class(Swift);

simsignal_t Swift::pacingTimerExpiredSignal = cComponent::registerSignal("pacingTimerExpired");
simsignal_t Swift::pacingTimerSetSignal = cComponent::registerSignal("pacingTimerSet");
simsignal_t Swift::pacingDelaySignal = cComponent::registerSignal("pacingDelay");
simsignal_t Swift::fcwndSignal = cComponent::registerSignal("fcwnd");
simsignal_t Swift::ecwndSignal = cComponent::registerSignal("ecwnd");

Swift::Swift() : SwiftFamily(),
    state((SwiftStateVariables *&)TcpAlgorithm::state)
{
}

void Swift::initialize()
{
    TcpBaseAlg::initialize();
    pacingTimer->addPar("pacing_type") = -1;

    if (state->use_custom_IW) {
        fcwnd = state->custom_IW_mult;
        ecwnd = state->custom_IW_mult;
    } else {
        fcwnd = 1;
        ecwnd = 1;
    }

    t_last_decrease = 0;

    double cwnd_new_packet_num = std::min(ecwnd, fcwnd);
    // turn cwnd back to bytes
    state->snd_cwnd = cwnd_new_packet_num * state->snd_mss;

    EV << "swift initialize: cwnd in bytes is " << state->snd_cwnd << endl;
}

simtime_t Swift::calculate_target_delay(int type) {
    EV << "Swift::calculate_target_delay called." << endl;
    simtime_t target_delay;
    if (type == ENDPOINT) {
        EV << "target delay type is endpoint" << endl;
        target_delay = state->constant_endpoint_target_delay;
    } else if (type == FABRIC) {
        EV << "target delay type is fabric" << endl;
        double alpha = state->fs_range / ((1.0/std::sqrt(state->fs_min_cwnd)) - (1.0/std::sqrt(state->fs_max_cwnd)));
        double beta = -1.0 * alpha / std::sqrt(state->fs_max_cwnd);
        EV << "alpha is " << alpha << ", beta is " << beta << ", and hop_count_to_be_echod is " << conn->hop_count_to_be_echod << endl;
        if (state->has_delay_scaling) {
            EV << "delay scaling is on" << endl;
            target_delay = state->base_target_delay +
            conn->hop_count_to_be_echod * state->per_hop_scaling_factor +
            std::max(0.0, std::min(alpha / std::sqrt(fcwnd) + beta, state->fs_range));
        }
        else {
            EV << "delay scaling is off" << endl;
            target_delay = state->base_target_delay;
        }
    } else
        throw cRuntimeError("Swift: Unkown delay type.");
    EV << "target delay is " << target_delay << endl;
    return target_delay;
}

void Swift::set_final_cwnd_values(simtime_t now, uint32 prev_ecwnd) {
    EV << "Swift::set_final_cwnd_values called." << endl;

    // clamp (min, val, max) <--> max(min, min(val, max))
    ecwnd = std::max(MIN_CWND_PACKET_NUMBER,
            std::min(ecwnd,
                    (double)MAX_CWND_PACKET_NUMBER));
    fcwnd = std::max(MIN_CWND_PACKET_NUMBER,
            std::min(fcwnd,
                    (double)MAX_CWND_PACKET_NUMBER));

    // apply EWMA on ecwnd
    ecwnd = state->endpoint_EWMA_factor * ecwnd +
            (1 - state->endpoint_EWMA_factor) * prev_ecwnd;

    EV << "Final value of ecwnd: " << ecwnd << ", and fcwnd: " << fcwnd << endl;


    double cwnd_prev_packet_num = (double)state->snd_cwnd / state->snd_mss;

    EV << "cwnd value before changing: bytes: " << state->snd_cwnd << ", packets:" << cwnd_prev_packet_num << endl;

    /*
     * TODO: In our simulations the endhost delay is 0 so we don't use ecwnd in our cwnd
     * calculations
     * If you are considering endpoint delay use this:
     * double cwnd_new_packet_num = std::min(ecwnd, fcwnd);
     */
    double cwnd_new_packet_num = fcwnd;

    EV << "cwnd value after changing: " << cwnd_new_packet_num << endl;

    if (cwnd_new_packet_num <= cwnd_prev_packet_num) {
        t_last_decrease = now;
        EV << "last_decrease changed to " << now << endl;
    }
    if (cwnd_new_packet_num < 1)
        pacing_delay = (most_recent_rtt.dbl()) / cwnd_new_packet_num;
    else
        pacing_delay = 0;

    EV << "Pacing delay: " << pacing_delay << ", and cwnd: " << cwnd_new_packet_num << endl;

    if (cwnd_new_packet_num < 1 && pacing_delay == 0) {
        cwnd_new_packet_num = 1;
        EV << "No rtt is yet recorded! Setting cwnd to " << cwnd_new_packet_num << endl;

    }

    // turn cwnd back to byte
    state->snd_cwnd = cwnd_new_packet_num * state->snd_mss;

    EV << "cwnd in bytes is " << state->snd_cwnd << endl;

    conn->emit(pacingDelaySignal, pacing_delay);
    conn->emit(fcwndSignal, fcwnd);
    conn->emit(ecwndSignal, ecwnd);

    conn->emit(cwndSignal, state->snd_cwnd);
}

void Swift::processPacingTimer(TcpEventCode& event, int timer_type) {
    EV << "Swift::processPacingTimer called." << endl;
    conn->emit(pacingTimerExpiredSignal, timer_type);
    if (timer_type == RETRANSMISSION) {
        EV << "Timer expired is retransmission" << endl;
        state->afterRto = true;
        conn->retransmitOneSegment(true);
    } else if (timer_type == NORMAL) {
        EV << "Timer expired is pacing" << endl;
        sendData(false);
    } else {
        throw cRuntimeError("Pacing timer expired, unknown timer type!");
    }
}

void Swift::processRexmitTimer(TcpEventCode& event)
{
    EV << "Swift::processRexmitTimer called." << endl;
    SwiftFamily::processRexmitTimer(event);

    /*
     * we set swift to never abort, instead it uses RETX_RESET_THRESHOLD
     */
    if (state->rexmit_count > MAX_CONST_RTO_COUNT)
        state->rexmit_count = MAX_CONST_RTO_COUNT;


    simtime_t now = simTime();
    uint32 prev_ecwnd = ecwnd;
    bool can_decrease;
    if (t_last_decrease <= 0)
        can_decrease = true;
    else
        can_decrease = ((now - t_last_decrease) >= most_recent_rtt);
    EV << "last_decrease is " << t_last_decrease << ", most_recent_rtt is " << most_recent_rtt
            << ", can_decrease: " << can_decrease << endl;
    EV << "Before changing: ecwnd: " << ecwnd << ", fcwnd: " << fcwnd << endl;

    retransmit_cnt++;
    if (retransmit_cnt >= RETX_RESET_THRESHOLD) {
        EV << "retransmit_cnt >= RETX_RESET_THRESHOLD, reseting the e-/f-cwnds to MIN_CWND_PACKET_NUMBER" << endl;
        ecwnd = MIN_CWND_PACKET_NUMBER;
        fcwnd = MIN_CWND_PACKET_NUMBER;
    } else {
        if (can_decrease) {
            EV << "retransmit_cnt < RETX_RESET_THRESHOLD" << endl;
            ecwnd *= (1 - state->max_mdf);
            fcwnd *= (1 - state->max_mdf);
        }
    }

    EV << "After changing: ecwnd: " << ecwnd << ", fcwnd: " << fcwnd << endl;

    set_final_cwnd_values(now, prev_ecwnd);

    // if pacing_delay < 1, we should pace retransmission
    if (pacing_delay > 0) {
        restart_pacing_timer(RETRANSMISSION);
        return;
    }

    state->afterRto = true;
    conn->retransmitOneSegment(true);
}

void Swift::restart_pacing_timer(int timer_type) {
    EV << "Swift::restart_pacing_timer called." << endl;
    if (pacingTimer->isScheduled())
        cancelEvent(pacingTimer);
    if (pacing_delay > 0) {
        simtime_t target_time = simTime() + pacing_delay;
        conn->emit(pacingTimerSetSignal, target_time);
        EV << "Setting the pacing timer to " << target_time << endl;
        pacingTimer->par("pacing_type") = timer_type;
        conn->scheduleAt(target_time, pacingTimer);
    }
}

bool Swift::sendData(bool sendCommandInvoked)
{
    EV << "Swift::sendData called." << endl;
    //
    // Nagle's algorithm: when a TCP connection has outstanding data that has not
    // yet been acknowledged, small segments cannot be sent until the outstanding
    // data is acknowledged. (In this case, small amounts of data are collected
    // by TCP and sent in a single segment.)
    //
    // FIXME there's also something like this: can still send if
    // "b) a segment that can be sent is at least half the size of
    // the largest window ever advertised by the receiver"

    bool fullSegmentsOnly = sendCommandInvoked && state->nagle_enabled && state->snd_una != state->snd_max;

    if (fullSegmentsOnly)
        EV_INFO << "Nagle is enabled and there's unacked data: only full segments will be sent\n";

    // RFC 2581, pages 7 and 8: "When TCP has not received a segment for
    // more than one retransmission timeout, cwnd is reduced to the value
    // of the restart window (RW) before transmission begins.
    // For the purposes of this standard, we define RW = IW.
    // (...)
    // Using the last time a segment was received to determine whether or
    // not to decrease cwnd fails to deflate cwnd in the common case of
    // persistent HTTP connections [HTH98].
    // (...)
    // Therefore, a TCP SHOULD set cwnd to no more than RW before beginning
    // transmission if the TCP has not sent data in an interval exceeding
    // the retransmission timeout."
    if (!conn->isSendQueueEmpty()) {    // do we have any data to send?
        if ((simTime() - state->time_last_data_sent) > state->rexmit_timeout) {
            // RFC 5681, page 11: "For the purposes of this standard, we define RW = min(IW,cwnd)."
            if (state->increased_IW_enabled)
                state->snd_cwnd = std::min(std::min(4 * state->snd_mss, std::max(2 * state->snd_mss, (uint32)4380)), state->snd_cwnd);
            else if (state->use_custom_IW) {
                state->snd_cwnd = state->custom_IW_mult * state->snd_mss;
                EV << "SEPEHR: Using custom IW with mult: " << state->custom_IW_mult <<
                        ", so the snd_cwnd is " << state->snd_cwnd << endl;
                fcwnd = state->custom_IW_mult;
                ecwnd = state->custom_IW_mult;
            }
            else
                state->snd_cwnd = state->snd_mss;

            EV << "Restarting idle connection, CWND is set to " << state->snd_cwnd << "\n";
        }
    }

    //
    // Send window is effectively the minimum of the congestion window (cwnd)
    // and the advertised window (snd_wnd).
    //

    // this might have been triggered after pacing
    if (pacing_delay > 0) {
        EV << "sendData is triggered after pacing delay" << endl;
        return conn->sendData(fullSegmentsOnly, state->snd_mss);
    }

    return conn->sendData(fullSegmentsOnly, state->snd_cwnd);
}

void Swift::receivedDataAck(uint32 firstSeqAcked)
{
    EV << "Swift::receivedDataAck called." << endl;
    SwiftFamily::receivedDataAck(firstSeqAcked);
    EV << "receivedDataAck called in swift. end_point_delay is: " << state->end_point_delay << " and fabric_delay is: " <<
            state->fabric_delay << endl;

    simtime_t now = simTime();
    uint32 prev_ecwnd = ecwnd;
    bool can_decrease;
    if (t_last_decrease <= 0)
        can_decrease = true;
    else
        can_decrease = ((now - t_last_decrease) >= most_recent_rtt);
    uint32 BytesAcked = state -> snd_una - firstSeqAcked;
    int packets_akced = ceil(((double)BytesAcked / state->snd_mss));

    EV << "last_decrease is " << t_last_decrease << ", most_recent_rtt is " << most_recent_rtt
                << ", can_decrease: " << can_decrease << endl;

    EV << "BytesAcked is " << BytesAcked << ", and packets_akced is " << packets_akced << endl;
    EV << "Before changing: ecwnd: " << ecwnd << ", fcwnd: " << fcwnd << endl;

    if (state->dupacks >= DUPTHRESH) {    // DUPTHRESH = 3
        //
        // Perform Fast Recovery.
        //
        retransmit_cnt = 0;
        if (!state->FRs_disabled) {
            EV_INFO << "Swfit Fast Recovery:" << endl;
            if (can_decrease) {
                EV << "Multiplying e-/f-cwnds by 1 - state->max_mdf: " << (1 - state->max_mdf) << endl;
                ecwnd *= (1 - state->max_mdf);
                fcwnd *= (1 - state->max_mdf);
            }
            conn->tcpMain->num_fast_fast_recoveries++;
        } else
            EV << "Fast Recovery disabled" << endl;
    }
    else {
        retransmit_cnt = 0;
        simtime_t endpoint_target_delay = calculate_target_delay(ENDPOINT);
        EV << "endpoint delay is " << state->end_point_delay << endl;
        if (state->end_point_delay < endpoint_target_delay) {
            // additive increase (AI)
            EV << "Applying AI to ecwnd" << endl;
            if (ecwnd >= 1) {
                EV << "adding state->ai / ecwnd * packets_akced: " << (state->ai / ecwnd * packets_akced) << " to ecwnd" << endl;
                ecwnd += state->ai / ecwnd * packets_akced;
            } else {
                EV << "adding state->ai * packets_akced: " << (state->ai * packets_akced) << " to ecwnd" << endl;
                ecwnd += state->ai * packets_akced;
            }
        } else {
            // multiplicative decrease (MD)
            EV << "Applying MD to ecwnd" << endl;
//            throw cRuntimeError("Technically, with our currect setting this line should never execute!");
            if (can_decrease) {
                EV << "ecwnd being decreased" << endl;
                ecwnd *= std::max(1 - state->beta * ((state->end_point_delay - endpoint_target_delay) / state->end_point_delay),
                        1 - state->max_mdf);
            }
        }

        simtime_t fabric_target_delay = calculate_target_delay(FABRIC);
        EV << "fabric delay is " << state->fabric_delay << endl;
        if (state->fabric_delay < fabric_target_delay) {
            // AI
            EV << "Applying AI to fcwnd" << endl;
            if (fcwnd >= 1) {
                EV << "adding state->ai / fcwnd * packets_akced: " << (state->ai / fcwnd * packets_akced) << " to fcwnd" << endl;
                fcwnd += state->ai / fcwnd * packets_akced;
            } else {
                EV << "adding state->ai * packets_akced: " << (state->ai * packets_akced) << " to fcwnd" << endl;
                fcwnd += state->ai * packets_akced;
            }
        } else {
            // MD
            EV << "Applying MD to fcwnd" << endl;
            if (can_decrease) {
                EV << "fcwnd being decreased" << endl;
                fcwnd *= std::max(1 - state->beta * ((state->fabric_delay - fabric_target_delay) / state->fabric_delay),
                        1 - state->max_mdf);
            }
        }

    }

    EV << "After changing: ecwnd: " << ecwnd << ", fcwnd: " << fcwnd << endl;

    set_final_cwnd_values(now, prev_ecwnd);

    if (state->sack_enabled && state->lossRecovery) {
        // RFC 3517, page 7: "Once a TCP is in the loss recovery phase the following procedure MUST
        // be used for each arriving ACK:
        //
        // (A) An incoming cumulative ACK for a sequence number greater than
        // RecoveryPoint signals the end of loss recovery and the loss
        // recovery phase MUST be terminated.  Any information contained in
        // the scoreboard for sequence numbers greater than the new value of
        // HighACK SHOULD NOT be cleared when leaving the loss recovery
        // phase."
        if (seqGE(state->snd_una, state->recoveryPoint)) {
            EV_INFO << "Loss Recovery terminated.\n";
            state->lossRecovery = false;
        }
        // RFC 3517, page 7: "(B) Upon receipt of an ACK that does not cover RecoveryPoint the
        //following actions MUST be taken:
        //
        // (B.1) Use Update () to record the new SACK information conveyed
        // by the incoming ACK.
        //
        // (B.2) Use SetPipe () to re-calculate the number of octets still
        // in the network."
        else {
            // update of scoreboard (B.1) has already be done in readHeaderOptions()
            conn->setPipe();

            // RFC 3517, page 7: "(C) If cwnd - pipe >= 1 SMSS the sender SHOULD transmit one or more
            // segments as follows:"
            if (((int)state->snd_cwnd - (int)state->pipe) >= (int)state->snd_mss) // Note: Typecast needed to avoid prohibited transmissions
                conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
        }
    }

    // RFC 3517, pages 7 and 8: "5.1 Retransmission Timeouts
    // (...)
    // If there are segments missing from the receiver's buffer following
    // processing of the retransmitted segment, the corresponding ACK will
    // contain SACK information.  In this case, a TCP sender SHOULD use this
    // SACK information when determining what data should be sent in each
    // segment of the slow start.  The exact algorithm for this selection is
    // not specified in this document (specifically NextSeg () is
    // inappropriate during slow start after an RTO).  A relatively
    // straightforward approach to "filling in" the sequence space reported
    // as missing should be a reasonable approach."

    // the following stops timer if pacing delay <= 0
    restart_pacing_timer(NORMAL);
    if (pacing_delay > 0) {
        return;
    }

    sendData(false);

}


void Swift::receivedDuplicateAck()
{
    EV << "Swift::receivedDuplicateAck called." << endl;
    if (!state->FRs_disabled) {
        SwiftFamily::receivedDuplicateAck();

        if (state->dupacks == DUPTHRESH) {    // DUPTHRESH = 3
            EV_INFO << "Reno on dupAcks == DUPTHRESH(=3): perform Fast Retransmit, and enter Fast Recovery:";

            if (state->sack_enabled) {
                // RFC 3517, page 6: "When a TCP sender receives the duplicate ACK corresponding to
                // DupThresh ACKs, the scoreboard MUST be updated with the new SACK
                // information (via Update ()).  If no previous loss event has occurred
                // on the connection or the cumulative acknowledgment point is beyond
                // the last value of RecoveryPoint, a loss recovery phase SHOULD be
                // initiated, per the fast retransmit algorithm outlined in [RFC2581].
                // The following steps MUST be taken:
                //
                // (1) RecoveryPoint = HighData
                //
                // When the TCP sender receives a cumulative ACK for this data octet
                // the loss recovery phase is terminated."

                // RFC 3517, page 8: "If an RTO occurs during loss recovery as specified in this document,
                // RecoveryPoint MUST be set to HighData.  Further, the new value of
                // RecoveryPoint MUST be preserved and the loss recovery algorithm
                // outlined in this document MUST be terminated.  In addition, a new
                // recovery phase (as described in section 5) MUST NOT be initiated
                // until HighACK is greater than or equal to the new value of
                // RecoveryPoint."
                if (state->recoveryPoint == 0 || seqGE(state->snd_una, state->recoveryPoint)) {    // HighACK = snd_una
                    state->recoveryPoint = state->snd_max;    // HighData = snd_max
                    state->lossRecovery = true;
                    EV_DETAIL << " recoveryPoint=" << state->recoveryPoint;
                }
            }
            // RFC 2581, page 5:
            // "After the fast retransmit algorithm sends what appears to be the
            // missing segment, the "fast recovery" algorithm governs the
            // transmission of new data until a non-duplicate ACK arrives.
            // (...) the TCP sender can continue to transmit new
            // segments (although transmission must continue using a reduced cwnd)."

            // enter Fast Recovery
            simtime_t now = simTime();
            uint32 prev_ecwnd = ecwnd;
            bool can_decrease;
            if (t_last_decrease <= 0)
                can_decrease = true;
            else
                can_decrease = ((now - t_last_decrease) >= most_recent_rtt);
            if (can_decrease) {
                ecwnd *= (1 - state->max_mdf);
                fcwnd *= (1 - state->max_mdf);
            }
            set_final_cwnd_values(now, prev_ecwnd);

            EV_DETAIL << " set cwnd=" << state->snd_cwnd << endl;

            // Fast Retransmission: retransmit missing segment without waiting
            // for the REXMIT timer to expire
            if (pacing_delay > 0)
                restart_pacing_timer(RETRANSMISSION);
            else
                conn->retransmitOneSegment(false);

            // Do not restart REXMIT timer.
            // Note: Restart of REXMIT timer on retransmission is not part of RFC 2581, however optional in RFC 3517 if sent during recovery.
            // Resetting the REXMIT timer is discussed in RFC 2582/3782 (NewReno) and RFC 2988.

            if (state->sack_enabled) {
                // RFC 3517, page 7: "(4) Run SetPipe ()
                //
                // Set a "pipe" variable  to the number of outstanding octets
                // currently "in the pipe"; this is the data which has been sent by
                // the TCP sender but for which no cumulative or selective
                // acknowledgment has been received and the data has not been
                // determined to have been dropped in the network.  It is assumed
                // that the data is still traversing the network path."
                conn->setPipe();
                // RFC 3517, page 7: "(5) In order to take advantage of potential additional available
                // cwnd, proceed to step (C) below."
                if (state->lossRecovery) {
                    // RFC 3517, page 9: "Therefore we give implementers the latitude to use the standard
                    // [RFC2988] style RTO management or, optionally, a more careful variant
                    // that re-arms the RTO timer on each retransmission that is sent during
                    // recovery MAY be used.  This provides a more conservative timer than
                    // specified in [RFC2988], and so may not always be an attractive
                    // alternative.  However, in some cases it may prevent needless
                    // retransmissions, go-back-N transmission and further reduction of the
                    // congestion window."
                    // Note: Restart of REXMIT timer on retransmission is not part of RFC 2581, however optional in RFC 3517 if sent during recovery.
                    EV_INFO << "Retransmission sent during recovery, restarting REXMIT timer.\n";
                    restartRexmitTimer();

                    // RFC 3517, page 7: "(C) If cwnd - pipe >= 1 SMSS the sender SHOULD transmit one or more
                    // segments as follows:"
                    if (((int)state->snd_cwnd - (int)state->pipe) >= (int)state->snd_mss) // Note: Typecast needed to avoid prohibited transmissions
                        conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
                }
            }

            // try to transmit new segments (RFC 2581)
            conn->tcpMain->num_fast_retransmits++;
            if (pacing_delay <= 0)
                sendData(false);
        }
    } else
        EV << "Fast Retransmit disabled!" << endl;
}

void Swift::rttMeasurementCompleteUsingTS(simtime_t echoedTS)
{
    EV << "Swift::rttMeasurementCompleteUsingTS called." << endl;

//    if (!state->sack_enabled)
//        throw cRuntimeError("Sack must be enabled for swift!");

    ASSERT(state->ts_enabled);

    simtime_t tSent = echoedTS;
    simtime_t tAcked = simTime();
    most_recent_rtt = tAcked - tSent;
    /*
     * TODO: if the endpoint delay is not zero
     * change the following line to this:
     * state->fabric_delay = most_recent_rtt - state->end_point_delay;
     */
    state->fabric_delay = most_recent_rtt;

    if (state->fabric_delay <= 0)
        throw cRuntimeError("state->fabric_delay <= 0");
    EV << "Swift: RTT is " << most_recent_rtt << " and end_point_delay is: " << state->end_point_delay << " so fabric_delay is " <<
            state->fabric_delay << endl;
    rttMeasurementComplete(tSent, tAcked);
}


} // namespace tcp
} // namespace inet
