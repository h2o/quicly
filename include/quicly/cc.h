/* Interface definition for quicly's congestion controller.
 */

#ifndef quicly_cc_h
#define quicly_cc_h

#include "quicly/constants.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

struct ccstate {
    uint32_t cwnd;
    uint32_t ssthresh;
    uint32_t inflight;
    uint32_t stash;
    uint8_t recovery_end;
};

void cc_init2(struct ccstate *ccs);

/* Called to query the controller whether data can be sent. Returns 1 if yes, 0 otherwise.
 */
int cc_can_send(struct ccstate *ccs);

/* Called after a packet is sent, to inform the controller about sent data.
 */
void cc_on_sent(struct ccstate *ccs, uint32_t bytes);

/* Called when a packet is newly acknowledged.
 */
void cc_on_acked(struct ccstate *ccs, uint32_t bytes, uint64_t acked_pn);

/* Called when a packet is detected as lost. |next_pn| is the next unsent packet number,
 * used for setting the recovery window.
 */
void cc_on_lost(struct ccstate *ccs, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn);

/* Called when persistent congestion is observed.
 */
void cc_on_persistent_congestion(struct ccstate *ccs);

#endif
