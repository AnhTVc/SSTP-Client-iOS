/*!
 * @brief Declaration for HDLC frame encoding
 *
 * @file sstp-fcs.h
 *
 * @author Copyright (C) 2011 Eivind Naess,
 *      All Rights Reserved
 *
 * @par License:
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __SSTP_FCS_H__
#define __SSTP_FCS_H__


/*< Initial FCS value */
#define PPPINITFCS16        0xffff

/*< Good final FCS value */
#define PPPGOODFCS16        0xf0b8

#define HDLC_FLAG           0x7E
#define HDLC_ESCAPE         0x7D
#define HDLC_TRANSPARENCY   0x20


/*! 
 * @brief Calculate checksum of a frame per RFC1662
 */
uint16_t sstp_frame_check(uint16_t fcs, const unsigned char *cp, int len);

/*!
 * @brief Decode a frame from the buffer and decapsulate it
 */
status_t sstp_frame_decode(const unsigned char *buf, int *length, 
    unsigned char *frame, int *size);

/*!
 * @brief Encode input buffer with HDLC framing
 */
status_t sstp_frame_encode(const unsigned char *source, int ilen, 
        unsigned char *frame, int *flen);

#endif /* #ifndef __SSTP_FCS_H__ */
