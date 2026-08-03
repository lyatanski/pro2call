#ifndef SMS_FSM_H
#define SMS_FSM_H

#include "fsm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SMS transfer transactions — TS 24.011 §6.2 and §8.3, as tables on the
 * generic FSM engine (task/inc/fsm.h).
 *
 * Two machines, one per direction of a short message transfer:
 *
 *   MO: the sender submits an SMS-SUBMIT inside RP-DATA and waits for
 *       RP-ACK or RP-ERROR under timer TR1M (§8.3.2).
 *   MT: the network delivers an SMS-DELIVER inside RP-DATA and waits
 *       for the receiver's RP-ACK or RP-ERROR under TR2M (§8.3.3).
 *
 * Over the radio interface these sit on top of a CP (connection
 * management) layer with its own establishment and its own timers.
 * Over IMS there is no CP layer at all — TS 24.341 puts the RPDU
 * straight into a SIP MESSAGE body and SIP is the reliable transport —
 * so these machines model the RP transaction only, and the SIP
 * transaction underneath is sip_fsm.h's business.
 *
 * Like the SIP machines: state only. Nothing here builds messages or
 * runs timers; feed it what happened and read the state. Illegal moves
 * return FSM_E_NOMATCH and leave the state alone.
 */

typedef enum {
    SMS_TR_ST_IDLE      = 0, /* nothing sent or received yet          */
    SMS_TR_ST_WAIT_ACK  = 1, /* RP-DATA out, waiting for the report   */
    SMS_TR_ST_DELIVERED = 2, /* RP-ACK seen: the transfer succeeded   */
    SMS_TR_ST_FAILED    = 3, /* RP-ERROR seen, or the timer expired   */
    SMS_TR_ST_ABORTED   = 4  /* terminal                              */
} sms_trans_state_t;

typedef enum {
    SMS_TR_EV_SEND_DATA  = 0, /* RP-DATA passed down                  */
    SMS_TR_EV_RECV_DATA  = 1, /* RP-DATA arrived (the receiving side)  */
    SMS_TR_EV_SEND_ACK   = 2, /* RP-ACK passed down                   */
    SMS_TR_EV_RECV_ACK   = 3, /* RP-ACK arrived                       */
    SMS_TR_EV_SEND_ERROR = 4, /* RP-ERROR passed down                 */
    SMS_TR_EV_RECV_ERROR = 5, /* RP-ERROR arrived                     */
    SMS_TR_EV_TIMER      = 6, /* TR1M / TR2M expired                  */
    SMS_TR_EV_ABORT      = 7  /* transport failure, or the TU gave up  */
} sms_trans_event_t;

/* Build a machine in SMS_TR_ST_IDLE with SMS_TR_ST_ABORTED as the
 * terminal state. Free with fsm_destroy(); NULL on allocation failure.
 *
 * sms_trans_fsm_mo() is the submitting side (a UE, or an IP-SM-GW
 * relaying towards the SC); sms_trans_fsm_mt() is the delivering side. */
API_EXPORT fsm_t* sms_trans_fsm_mo(void); /* §8.3.2, TR1M */
API_EXPORT fsm_t* sms_trans_fsm_mt(void); /* §8.3.3, TR2M */

/* Default timer values in milliseconds. TS 24.011 table 8.4 gives TR1M
 * as 35..45 s and TR2M as 15..25 s; the midpoints are what a handset
 * uses and what the emulators in bindings/examples assume. */
#define SMS_TR1M_MS 40000
#define SMS_TR2M_MS 20000

API_EXPORT const char* sms_trans_state_name(fsm_state_id state);
API_EXPORT const char* sms_trans_event_name(fsm_action_id event);

#ifdef __cplusplus
}
#endif

#endif /* SMS_FSM_H */
