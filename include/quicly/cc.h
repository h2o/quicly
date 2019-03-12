/* Interface definition for quicly's congestion controller.
 */

#ifndef quicly_cc_h
#define quicly_cc_h

#include "quicly/constants.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

typedef struct st_quicly_cc_t {
    uint32_t cwnd;
    uint32_t ssthresh;
    uint32_t stash;
    uint64_t recovery_end;
} quicly_cc_t;

void quicly_cc_init(quicly_cc_t *cc);

/* Called to query the controller whether data can be sent. Returns 1 if yes, 0 otherwise.
 */
int quicly_cc_can_send(quicly_cc_t *cc, uint32_t inflight);

/* Called when a packet is newly acknowledged.
 */
void quicly_cc_on_acked(quicly_cc_t *cc, uint32_t bytes, uint64_t largest_acked, uint32_t inflight);

/* Called when a packet is detected as lost. |next_pn| is the next unsent packet number,
 * used for setting the recovery window.
 */
void quicly_cc_on_lost(quicly_cc_t *cc, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn);

/* Called when persistent congestion is observed.
 */
void quicly_cc_on_persistent_congestion(quicly_cc_t *cc);

#endif
