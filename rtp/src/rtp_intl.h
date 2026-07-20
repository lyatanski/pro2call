#ifndef RTP_INTL_H
#define RTP_INTL_H

#include <stdint.h>

/* Network byte order accessors shared by rtp.c and rtcp.c. */
uint16_t rtp_rd16(const uint8_t* p);
uint32_t rtp_rd32(const uint8_t* p);
void     rtp_wr16(uint8_t* p, uint16_t v);
void     rtp_wr32(uint8_t* p, uint32_t v);

#endif /* RTP_INTL_H */
