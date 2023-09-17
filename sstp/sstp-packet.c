/*!
 * @brief The packet decoding / encoding related declarations
 *
 * @file sstp-packet.c
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
#include "config.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#include "sstp-private.h"


status_t sstp_pkt_init(sstp_buff_st *buf, sstp_msg_t type)
{
    sstp_pkt_st *pkt = NULL;
    status_t status  = SSTP_FAIL;
    short length = 0;

    /* Reset the buffer position */
    sstp_buff_reset(buf);

    /* Verify that we have at space left */
    length = sizeof(sstp_pkt_st);
    if (sstp_buff_space(buf, length))
    {
        goto done;
    }

    /* Set the version, and flags */
    pkt = (sstp_pkt_st*) &buf->data;
    pkt->version = SSTP_PROTO_VER;
    pkt->flags   = (type != SSTP_MSG_DATA)
        ? SSTP_MSG_FLAG_CTRL
        : 0;

    /* Handle Control Messages */
    if (SSTP_MSG_DATA != type)
    {
        sstp_ctrl_st *ctrl = NULL;
        
        /* Verify that we have space left */
        length += sizeof(sstp_ctrl_st);
        if (sstp_buff_space(buf, length))
        {
            goto done;
        }
        
        /* Set the default control fields */
        ctrl = (sstp_ctrl_st*) &pkt->data;
        ctrl->type   = htons(type);
        ctrl->nattr  = 0;
    }

    /* Track the position in the buffer */
    buf->len    = length;
    pkt->length = htons(length);

    /* Success! */
    status = SSTP_OKAY;

done:

    return status;
}


status_t sstp_pkt_attr(sstp_buff_st *buf, sstp_attr_t type, 
    unsigned short len, void *data)
{
    sstp_pkt_st  *pkt  = NULL;
    sstp_ctrl_st *ctrl = NULL;
    sstp_attr_st *attr = NULL;
    status_t status    = SSTP_FAIL;
    short length       = 0;

    /* Verify that we have space left */
    length = len + sizeof(sstp_attr_st);
    if (sstp_buff_space(buf, length))
    {
        goto done;
    }

    /* Attributes applies to Control Packets only */
    pkt = (sstp_pkt_st*) &buf->data[0];
    if (!(SSTP_MSG_FLAG_CTRL & pkt->flags))
    {
        goto done;
    }

    /* Update the number of attributes section */
    ctrl = (sstp_ctrl_st*) pkt->data;
    ctrl->nattr = htons(ntohs(ctrl->nattr) + 1);

    /* Append the attribute to the end of the stream */
    attr = (sstp_attr_st*) &buf->data[buf->len];
    attr->reserved = 0;
    attr->type   = type;
    attr->length = htons(length);
    memcpy(attr->data, data, len);

    /* Update the total length */
    buf->len += length;

    /* Update the packet header */
    pkt->length = htons(buf->len);

    /* Success */
    status = SSTP_OKAY;

done:

    return status;
}


uint8_t *sstp_pkt_data(sstp_buff_st *buf)
{
    sstp_pkt_st *pkt = (sstp_pkt_st*) buf->data;
    if (!(SSTP_MSG_FLAG_CTRL & pkt->flags))
    {
        return ((uint8_t*)buf->data + sizeof(sstp_pkt_st));
    }

    /*
     * Return the pointer after the attribute section?
     */
    return NULL;
}


int sstp_pkt_data_len(sstp_buff_st *buf)
{
    sstp_pkt_st *pkt = (sstp_pkt_st*) buf->data;
    if (!(SSTP_MSG_FLAG_CTRL & pkt->flags))
    {
        return (buf->len - sizeof(sstp_pkt_st));
    }

    /*
     * Return the pointer after the attribute section?
     */
    return 0;
}


int sstp_pkt_len(sstp_buff_st *buf)
{
    sstp_pkt_st *pkt = (sstp_pkt_st*) buf->data;
    return ntohs(pkt->length);
}


void sstp_pkt_update(sstp_buff_st *buf)
{
    sstp_pkt_st *pkt = (sstp_pkt_st*) &buf->data[0];
    pkt->length = htons(buf->len);
}


sstp_pkt_t sstp_pkt_type(sstp_buff_st *buf, sstp_msg_t *type)
{
    sstp_pkt_st *pkt = NULL;

    /* Can we determine the packet type? */
    if (buf->len < sizeof(sstp_pkt_st))
    {
        return SSTP_PKT_UNKNOWN;
    }

    /* Check if this is a control packet */
    pkt = (sstp_pkt_st*) &buf->data[0];
    if (SSTP_MSG_FLAG_CTRL & pkt->flags)
    {
        sstp_ctrl_st *ctrl = (sstp_ctrl_st*) &pkt->data[0];
        if (type != NULL)
        {
            *type = ntohs(ctrl->type);
        }

        return SSTP_PKT_CTRL;
    }
    
    /* Not a control packet */
    return SSTP_PKT_DATA;
}


status_t sstp_pkt_parse(sstp_buff_st *buf, size_t count,
    sstp_attr_st *attrs[])
{
    sstp_pkt_st *pkt   = NULL;
    sstp_ctrl_st *ctrl = NULL;

    short alen   = 0;
    short index  = 0;
    short length = 0;

    status_t status = SSTP_FAIL;
    
    /* Get the minimum length of the packet */
    length = sizeof(sstp_pkt_st)  +
             sizeof(sstp_ctrl_st) +
             sizeof(sstp_attr_st) + 2 ;
    if (buf->len < length)
    {
        goto done;
    }

    /* Check if it is a control packet */
    pkt    = (sstp_pkt_st*) sstp_buff_data(buf, index);
    index += sizeof(sstp_pkt_st);
    if (!(SSTP_MSG_FLAG_CTRL & pkt->flags))
    {
        goto done;
    }

    /* Get the number of attributes */
    ctrl   = (sstp_ctrl_st*) sstp_buff_data(buf, index);
    index += sizeof(sstp_ctrl_st);
    alen   = ntohs(ctrl->nattr);
    
    /* Reset the pointers */
    memset(attrs, 0, sizeof(sstp_attr_st*) * SSTP_ATTR_MAX);
    while (alen--)
    {
        sstp_attr_st *entry = (sstp_attr_st*) 
                sstp_buff_data(buf, index);

        if (SSTP_ATTR_MAX < entry->type)
        {
            goto done;
        }

        /* Setup the return value */
        attrs[entry->type] = entry;
        index = ntohs(entry->length);
    }

    /* This is where we left of reading */
    buf->off = index;

    /* Success! */
    status = SSTP_OKAY;

done:
    
    return status;
}


void *sstp_attr_data(sstp_attr_st *attr)
{
    return ((char*)attr + sizeof(sstp_attr_st));
}


int sstp_attr_len(sstp_attr_st *attr)
{
    return (ntohs(attr->length) - sizeof(sstp_attr_st));
}


const char *sstp_attr_status_str(int status)
{
    const char *retval = NULL;

    switch (status)
    {
    case SSTP_STATUS_DUPLICATE:
        retval = "Received Duplicate Attribute";
        break;

    case SSTP_STATUS_UNRECOGNIZED:
        retval = "Unrecognized Attribute";
        break;

    case SSTP_STATUS_INVALID_LENGTH:
        retval = "Invalid Attribute Length";
        break;
    
    case SSTP_STATUS_VALUE_NOTSUP:
        retval = "Value of attribute is incorrect";
        break;

    case SSTP_STATUS_ATTR_NOTSUP:
        retval = "Attribute is invalid or not supported";
        break;

    case SSTP_STATUS_ATTR_MISSING:
        retval = "Attribute is missing";
        break;
    
    case SSTP_STATUS_INFO_NOSUP:
        retval = "Invalid info attribute";
        break;

    default:
        retval = "Unknown Status Attribute";
        break;
    }
    
    return retval;
}
