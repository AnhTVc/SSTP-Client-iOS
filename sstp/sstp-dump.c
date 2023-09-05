/*!
 * @brief The packet dump related declarations
 *
 * @file sstp-dump.c
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

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sstp-ppp.h"
#include "sstp-private.h"


/*!
 * @brief Callback handler(s) per protocol
 */
typedef struct 
{
    /* The protocol ID */
    uint16_t proto;

    /* The name of the protocol */
    const char *name;
    
    /* The callback handler designated at processing the protocol */
    int (*fn_cb)(const ppp_hdr_st *pkt, char *msg, int size);

} ppp_handler_st;


static const ppp_handler_st *sstp_ppp_handler(int id);


#define OPT_ENTRY(x)        \
    { CI_##x, #x }

#define IPCP_OPT_ENTRY      OPT_ENTRY

#define LCP_OPT_ENTRY       OPT_ENTRY

#define CCP_OPT_ENTRY       OPT_ENTRY

#define FSM_CODE(x)         \
    [ FSM_##x ] = { FSM_##x, #x }

#define CHAP_MSG_NAME(x)    \
    [ CHAP_##x ] = { CHAP_##x, #x }

#define EAP_MSG_NAME(x)     \
    [ EAP_##x ] = { EAP_##x, #x }

#define EAP_TYP_NAME(x)     \
    [ EAPT_##x ] = { EAPT_##x, #x }

/*!
 * @brief Get the name of the particular code 
 */
static const char *sstp_ppp_getcode(int code)
{
    static const sstp_nval_st codes[] =
    {
        FSM_CODE(CONFREQ),
        FSM_CODE(CONFACK),
        FSM_CODE(CONFNAK),
        FSM_CODE(CONFREJ),
        FSM_CODE(TERMREQ),
        FSM_CODE(TERMACK),
        FSM_CODE(CODEREJ),
        FSM_CODE(PROTOREJ),
        FSM_CODE(ECHOREQ),
        FSM_CODE(ECHOREP),
        FSM_CODE(DISCARDREQ),
        FSM_CODE(RESETREQ),
        FSM_CODE(RESETACK)
    };

    if (code >= FSM_FIRST && code <= FSM_LAST)
    {
        return codes[code].name;
    }

    return NULL;
}


/*!
 * @brief Get the name of the CCP option
 */
static const char *sstp_ccp_getname(int type)
{
    int cnt = 0;
    static const sstp_nval_st ccp_opts [] =
    {
        CCP_OPT_ENTRY(PREDICT1),
        CCP_OPT_ENTRY(PREDICT2),
        CCP_OPT_ENTRY(PUDDLE),
        CCP_OPT_ENTRY(HPPPC),
        CCP_OPT_ENTRY(SELZS),
        CCP_OPT_ENTRY(MPPC),
        CCP_OPT_ENTRY(GFZA),
        CCP_OPT_ENTRY(V42C),
        CCP_OPT_ENTRY(BSD),
    };

    for (cnt = 0; cnt < SIZEOF_ARRAY(ccp_opts); cnt++)
    {
        if (type == ccp_opts[cnt].type)
        {
            return ccp_opts[cnt].name;
        }
    }

    return NULL;
}


/*!
 * @brief Get the name of the LCP option
 */
static const char *sstp_lcp_getname(int type)
{
    int cnt = 0;
    static const sstp_nval_st lcp_opts [] = 
    {
        LCP_OPT_ENTRY(MRU),
        LCP_OPT_ENTRY(ASYNCMAP),
        LCP_OPT_ENTRY(AUTH),
        LCP_OPT_ENTRY(QUALITY),
        LCP_OPT_ENTRY(MAGIC),
        LCP_OPT_ENTRY(PCOMP),
        LCP_OPT_ENTRY(ACCOMP),
        LCP_OPT_ENTRY(FCSALTERN),
        LCP_OPT_ENTRY(SDP),
        LCP_OPT_ENTRY(NUMBERED),
        LCP_OPT_ENTRY(CALLBACK),
        LCP_OPT_ENTRY(MRRU),
        LCP_OPT_ENTRY(SSNHF),
        LCP_OPT_ENTRY(EPDISC),
        LCP_OPT_ENTRY(MPPLUS),
        LCP_OPT_ENTRY(COBS),
        LCP_OPT_ENTRY(PREFELIS),
        LCP_OPT_ENTRY(MPHDRFMT),
        LCP_OPT_ENTRY(I18N),
        LCP_OPT_ENTRY(SDL)
    };

    for (cnt = 0; cnt < SIZEOF_ARRAY(lcp_opts); cnt++)
    {
        if (type == lcp_opts[cnt].type)
        {
            return lcp_opts[cnt].name;
        }
    }

    return NULL;
}


/*! 
 * @brief Get the name of the IPCP option
 */
static const char *sstp_ipcp_getname(ppp_opt_st *opt)
{
    int cnt = 0;

    static const sstp_nval_st ipcp_opts[] = 
    {
        IPCP_OPT_ENTRY(ADDRS),
        IPCP_OPT_ENTRY(COMPRESSTYPE),
        IPCP_OPT_ENTRY(ADDR),
        IPCP_OPT_ENTRY(MS_DNS1),
        IPCP_OPT_ENTRY(MS_WINS1),
        IPCP_OPT_ENTRY(MS_DNS2),
        IPCP_OPT_ENTRY(MS_WINS2),
    };

    for (cnt = 0; cnt < SIZEOF_ARRAY(ipcp_opts); cnt++)
    {
        if (ipcp_opts[cnt].type == opt->type)
        {
            return ipcp_opts[cnt].name;
        }
    }

    return NULL;
}


/**
 * @brief Get the EAP type name
 */
static const char *sstp_eap_typestr(unsigned char type)
{
    static const sstp_nval_st typ[] = 
    {
        EAP_TYP_NAME(IDENTITY),
        EAP_TYP_NAME(NOTIFICATION),
        EAP_TYP_NAME(NAK),
        EAP_TYP_NAME(MD5CHAP),
        EAP_TYP_NAME(OTP),
        EAP_TYP_NAME(TOKEN),
        EAP_TYP_NAME(RSA),
        EAP_TYP_NAME(DSS),
        EAP_TYP_NAME(KEA),
        EAP_TYP_NAME(KEA_VALIDATE),
        EAP_TYP_NAME(TLS),
        EAP_TYP_NAME(DEFENDER),
        EAP_TYP_NAME(W2K),
        EAP_TYP_NAME(ARCOT),
        EAP_TYP_NAME(CISCOWIRELESS),
        EAP_TYP_NAME(NOKIACARD),
        EAP_TYP_NAME(SRP),
        EAP_TYP_NAME(DEPRECATED),
        EAP_TYP_NAME(TTLS),
        EAP_TYP_NAME(RAS),
        EAP_TYP_NAME(AKA),
        EAP_TYP_NAME(3COM),
        EAP_TYP_NAME(PEAP),
        EAP_TYP_NAME(MSCHAPV2)
    };
    int idx;
    
    for (idx = 0; idx < SIZEOF_ARRAY(typ); idx++)
    {
        if (type == typ[idx].type)
        {
            return typ[idx].name;
        }
    }

    return NULL;
}


/*! 
 * @brief Get the EAP message
 */
static const char *sstp_eap_codestr(const ppp_hdr_st *hdr)
{
    static const sstp_nval_st eap [] =
    {
        EAP_MSG_NAME(REQUEST),
        EAP_MSG_NAME(RESPONSE),
        EAP_MSG_NAME(SUCCESS),
        EAP_MSG_NAME(FAILURE)
    };
    int idx;

    for (idx = 0; idx < SIZEOF_ARRAY(eap); idx++)
    {
        if (hdr->code == eap[idx].type)
        {
            return eap[idx].name;
        }
    }

    return NULL;
}


/*! 
 * @brief Get the CHAP message
 */
static const char *sstp_chap_getname(const ppp_hdr_st *hdr)
{
    static const sstp_nval_st chap [] =
    {
        CHAP_MSG_NAME(CHALLENGE),
        CHAP_MSG_NAME(RESPONSE),
        CHAP_MSG_NAME(SUCCESS),
        CHAP_MSG_NAME(FAILURE)
    };
    int idx = 0;

    for (idx = 0; idx < SIZEOF_ARRAY(chap); idx++)
    {
        if (hdr->code == chap[idx].type)
        {
            return chap[idx].name;
        }
    }

    return NULL;
}


/*!
 * @brief Add a message to the string given the right length @a len, and offset @a off
 */
static int sstp_str_add(char *buf, int *len, int *off, const char *fmt, ...)
{
    va_list list;
    int ret = 0;

    va_start(list, fmt);
    ret = vsnprintf(buf + *off, *len - *off, fmt, list);
    va_end(list);
    if (ret < 0 || ret >= (*len - *off)) 
    {
        return -1;   
    }

    *off += ret;

    return ret;
}



/*!
 * @brief Get the next PPP option
 */
static ppp_opt_st *sstp_ppp_nextopt(ppp_opt_st *opt)
{
    return (ppp_opt_st*) ((unsigned char*) opt + opt->len);
}


/*!
 * @brief Get the length of the PPP option payload
 */
static int sstp_ppp_optlen(ppp_opt_st *opt)
{
    return (opt->len - sizeof(*opt));
}


/*! 
 * @brief Get the option data pointer
 */
static unsigned char *sstp_ppp_optptr(ppp_opt_st *opt)
{
    return ((unsigned char*) opt + sizeof(*opt));
}


/*!
 * @brief Get the pointer to the payload
 */
static unsigned char *sstp_ppp_data(const ppp_hdr_st *pkt)
{
    return ((unsigned char*) pkt + sizeof(*pkt));
}


/*!
 * @brief Get the length of the data
 */
static int sstp_ppp_data_len(const ppp_hdr_st* pkt)
{
    return (ntohs(pkt->len) - sizeof(*pkt));
}


/*!
 * @brief Convert the content of a PPP option to an integer
 */
static int sstp_ppp_opt2int(ppp_opt_st *opt)
{
    int val = 0;

    int len = sstp_ppp_optlen(opt);
    switch (len)
    {
    case 1:
        val = *(uint8_t*) sstp_ppp_optptr(opt);
        break;
    case 2:
        val = ntohs(*(uint16_t*) sstp_ppp_optptr(opt));
        break;
    case 4:
        val = ntohl(*(uint32_t*) sstp_ppp_optptr(opt));
        break;
    }

    return val;
}


/*! 
 * @brief Print the CCP options to a string @a buf of size @a len given the packet @a pkt
 */
static int sstp_ccp_opts(const ppp_hdr_st *pkt, char *buf, int len)
{
    ppp_opt_st *opt = (ppp_opt_st*) sstp_ppp_data(pkt);
    ppp_opt_st *next = NULL;
    int ret = 0;
    int idx = 0;
    int off = 0;
    int val = 0;

    for (idx = 0; idx < sstp_ppp_data_len(pkt) && opt->len > 0; idx += opt->len, opt = next)
    {
        const char *name = sstp_ccp_getname(opt->type);
        if (!name)
        {
            next = sstp_ppp_nextopt(opt);
            continue;
        }

        switch (opt->type)
        {
        case CI_MPPC:

            val = sstp_ppp_opt2int(opt);
            ret = sstp_str_add(buf, &len, &off, " %s [ %cH %cM %cS %cL %cD %cC ]", name,
                    ((val >> 24) & MPPE_H_BIT) ? '+' : '-',
                    (val & MPPE_M_BIT) ? '+' : '-',
                    (val & MPPE_S_BIT) ? '+' : '-',
                    (val & MPPE_L_BIT) ? '+' : '-',
                    (val & MPPE_D_BIT) ? '+' : '-',
                    (val & MPPE_C_BIT) ? '+' : '-');
            break;

        default:

            ret = sstp_str_add(buf, &len, &off, " %s", name);
            if (ret < 0)
            {
                return -1;
            }
        }

        next = sstp_ppp_nextopt(opt);
    }

    return off;
}


/*! 
 * @brief Print the LCP options to a string @a buf of size @a size given the stream in @a ptr
 */
static int sstp_lcp_opts(const ppp_hdr_st *pkt, char *buf, int len)
{
    ppp_opt_st *opt = (ppp_opt_st*) sstp_ppp_data(pkt);
    ppp_opt_st *next = NULL;
    int ret = 0;
    int idx = 0;
    int off = 0;

    for (idx = 0; idx < sstp_ppp_data_len(pkt) && opt->len > 0; idx += opt->len, opt = next)
    {
        const char *name = sstp_lcp_getname(opt->type);
        if (!name)
        {
            next = sstp_ppp_nextopt(opt);
            continue;
        }

        switch (opt->type)
        {
            case CI_MRU:
            case CI_MRRU:

                ret = sstp_str_add(buf, &len, &off, " %s: %d", name, sstp_ppp_opt2int(opt));
                if (ret < 0)
                {
                    return -1;
                }
                break;

            case CI_AUTH:
            {
                int auth = ntohs(*(uint16_t*) ((unsigned char*) opt + sizeof(*opt)));
                const char *astr = "UNKNOWN";
                switch (auth) 
                {
                    case 0xc023:
                        astr = "PAP";
                        break;
                    case 0xc223:
                        astr = "CHAP";
                        break;
                    case 0xc227:
                        astr = "EAP";
                        break;
                    default:
                        break;
                }

                ret = sstp_str_add(buf, &len, &off, " %s: %s", name, astr);
                if (ret < 0)
                {
                    return -1;
                }
                break;
            } 
            case CI_MAGIC:
                
                ret = sstp_str_add(buf, &len, &off, " %s: 0x%08X", name, sstp_ppp_opt2int(opt));
                if (ret < 0)
                {
                    return -1;
                }
                break;

            default:
            {
                char hex[128];
                ret = sstp_bin2hex("%02X ", hex, sizeof(hex), sstp_ppp_optptr(opt), 
                        sstp_ppp_optlen(opt));
                if (ret > 0) 
                {
                    hex[ret-1] = '\0';

                    ret = sstp_str_add(buf, &len, &off, " %s: %s", name, hex);
                    if (ret < 0)
                    {
                        return -1;
                    }
                }

                break;
            }
        }

        next = sstp_ppp_nextopt(opt);
    }

    return off;
}


/*!
 * @brief Print the IPCP options to a string @a buf of size @a size given the IPCP packet @a ptr
 */
static int sstp_ipcp_opts(const ppp_hdr_st *pkt, char *buf, int len)
{
    ppp_opt_st *opt = (ppp_opt_st*) sstp_ppp_data(pkt);
    ppp_opt_st *next = NULL;
    int ret = 0;
    int idx = 0;
    int off = 0;

    for (idx = 0; idx < sstp_ppp_data_len(pkt) && opt->len > 0; idx += opt->len, opt = next )
    {
        unsigned char *optptr = NULL;
        char optstr[128] = {};

        const char *name = sstp_ipcp_getname(opt);
        if (!name)
        {
            next = sstp_ppp_nextopt(opt);
            continue;
        }

        switch (opt->type)
        {
            case CI_ADDR:
            case CI_MS_DNS1:
            case CI_MS_DNS2:
            case CI_MS_WINS1:
            case CI_MS_WINS2:

                ret = snprintf(optstr, sizeof(optstr), "%s", inet_ntoa(*(struct in_addr*) sstp_ppp_optptr(opt)));
                if (ret < 0)
                {
                    return -1;
                }
                break;

            case CI_COMPRESSTYPE:
            
                optptr = sstp_ppp_optptr(opt);
                switch (ntohs(*(uint16_t*) optptr))
                {
                    case IPCP_VJ_COMP:
                        snprintf(optstr, sizeof(optstr), "VJ [0x%02X 0x%02X]",
                                optptr[2], optptr[3]); 
                        break;

                    case IPCP_VJ_COMP_OLD:
                        snprintf(optstr, sizeof(optstr), "VJ-OLD");
                        break;

                    default:
                        snprintf(optstr, sizeof(optstr), "UNKNOWN");
                        break;
                }
                break;

            default:

                ret = sstp_bin2hex("0x%02X ", optstr, sizeof(optstr), sstp_ppp_optptr(opt), 
                        sstp_ppp_optlen(opt));
                if (ret > 0) 
                {
                    optstr[ret-1] = '\0';
                }
                break;

        }
       
        ret = sstp_str_add(buf, &len, &off, " %s: %s", name, optstr);
        if (ret < 0)
        {
            return -1;
        }

        next = sstp_ppp_nextopt(opt);
    }
    
    return off;
}


/*!
 * @brief Dump the LCP packet to a log-message
 */
static int sstp_dump_lcp(const ppp_hdr_st *pkt, char *buf, int len)
{
    int off = 0;
    int ret = 0;

    if (pkt->code < FSM_CONFREQ || 
        pkt->code > FSM_DISCARDREQ)
    {
        return -1;
    }

    ret = sstp_str_add(buf, &len, &off, " %s", sstp_ppp_getcode(pkt->code));
    if (ret < 0)
    {
        return -1;
    }

    switch (pkt->code) 
    {
        case FSM_CONFREQ:
        case FSM_CONFACK:
        case FSM_CONFNAK:
        case FSM_CONFREJ:

            ret = sstp_lcp_opts(pkt, buf + off, len - off);
            if (ret > 0)
            {
                len -= ret;
                off += ret;
            }

            break;
        
        case FSM_PROTOREJ:
        case FSM_CODEREJ:
        {
            int code = ntohs(*(uint16_t*) sstp_ppp_data(pkt));
            const ppp_handler_st *p = sstp_ppp_handler(code);
            ret = (p)
                ? sstp_str_add(buf, &len, &off, " %s", p->name)
                : sstp_str_add(buf, &len, &off, " %0x%04X", code);
            if (ret < 0)
            {
                return -1;
            }

            break;
        }
        case FSM_ECHOREQ:
        case FSM_ECHOREP:
        case FSM_DISCARDREQ:

            ret = sstp_str_add(buf, &len, &off, " MAGIC: 0x%08X", ntohl(*(uint32_t*) sstp_ppp_data(pkt)));
            if (ret < 0)
            {
                return -1;
            }
            break;

        default:

            break;
    }

    return off;
}


/*!
 * @brief Dump the IPCP packet to a log-message
 */
static int sstp_dump_ipcp(const ppp_hdr_st *hdr, char *buf, int len)
{
    int off = 0;
    int ret = 0;
    
    if (hdr->code < FSM_CONFREQ || 
        hdr->code > FSM_CODEREJ) 
    {
        return -1;
    }
    
    ret = sstp_str_add(buf, &len, &off, " %s", sstp_ppp_getcode(hdr->code));
    if (ret < 0)
    {
        return -1;
    }

    switch (hdr->code)
    {
        case FSM_CONFREQ:
        case FSM_CONFACK:
        case FSM_CONFNAK:
        case FSM_CONFREJ:
            ret = sstp_ipcp_opts(hdr, buf + off, len - off);
            if (ret > 0)
            {
                len -= ret;
                off += ret;
            }

            break;

        case FSM_TERMREQ:
        case FSM_TERMACK:
            ret = sstp_str_add(buf, &len, &off, " MAGIC: 0x%04X", ntohl(*(uint32_t*) sstp_ppp_data(hdr)));
            if (ret < 0)
            {
                return -1;
            }
            break;

        case FSM_CODEREJ:
            ret = sstp_str_add(buf, &len, &off, " PROTO: 0x%04X", (*(uint16_t*) sstp_ppp_data(hdr)));
            if (ret < 0) 
            {
                return -1;
            }
            break;

        default:

            break;
    }

    return off;
}


/*!
 * @brief Dump the CHAP information to a log-message
 */
static int sstp_dump_chap(const ppp_hdr_st *pkt, char *buf, int len)
{
    unsigned char *ptr = sstp_ppp_data(pkt);
    const char *state = NULL;
    char hex[255] = {};
    char peer[255]= {};
    int off = 0;
    int clen= 0;
    int ret = -1;

    state = sstp_chap_getname(pkt);
    if (!state) 
    {
        goto done;
    }

    /* Prepend default information */
    ret = sstp_str_add(buf, &len, &off, " ID: %d %s", pkt->id, state);
    if (ret < 0)
    {
        goto done;
    }

    switch (pkt->code)
    {
        case CHAP_CHALLENGE:
        case CHAP_RESPONSE:

            /* Get the length of the data */
            clen = *(uint8_t*) ptr++;

            /* Copy the challenge / response */
            ret = sstp_bin2hex("%02X", hex, sizeof(hex), ptr, clen);
            if (ret <= 0) 
            {
                return -1;
            }
            ptr += clen;

            /* Copy the name associated */
            memcpy(peer, ptr, MIN((sstp_ppp_data_len(pkt)-clen-1), sizeof(peer)));
     
            /* Print the message */
            ret = sstp_str_add(buf, &len, &off, " [%s], NAME: %s", hex, peer);
            if (ret < 0)
            {
                return -1;
            }
            break;

        case CHAP_SUCCESS:
        case CHAP_FAILURE:

            /* Print the response */
            ret = sstp_str_add(buf, &len, &off, " [%s]", ptr);
            if (ret < 0)
            {
                return -1;
            }
            break;

        default:
            /* No such code */
            goto done;
    }

done:

    return off;
}


/*!
 * @brief Dump the CCP packet to a log-message
 */
static int sstp_dump_ccp(const ppp_hdr_st *pkt, char *buf, int len)
{
    int pos = 0;
    int ret = 0;

    if (pkt->code < FSM_CONFREQ || 
        pkt->code > FSM_RESETACK)
    {
        return -1;
    }

    ret = sstp_str_add(buf, &len, &pos, " %s", sstp_ppp_getcode(pkt->code));
    if (ret < 0)
    {
        return -1;
    }

    switch (pkt->code)
    {
        case FSM_CONFREQ:
        case FSM_CONFACK:
        case FSM_CONFNAK:
        case FSM_CONFREJ:
            
            ret = sstp_ccp_opts(pkt, buf + pos, len - pos);
            if (ret > 0)
            {
                len -= ret;
                pos += ret;
            }
            break;

        case FSM_PROTOREJ:
        case FSM_CODEREJ:
            break;
        
        default:
            break;
    }

    return pos;
}


/*!
 * @brief Dump the EAP packet to a log-message
 */
static int sstp_dump_eap(const ppp_hdr_st *pkt, char *buf, int len)
{
    unsigned char *ptr = sstp_ppp_data(pkt);
    unsigned int plen = sstp_ppp_data_len(pkt) - 1;
    int pos =  0;
    int ret = -1;
    char flag = 0;
    char type = *ptr++;

    ret = sstp_str_add(buf, &len, &pos, "%s %s", sstp_eap_codestr(pkt), 
            sstp_eap_typestr(type));
    if (ret < 0)
    {
        goto done;
    }

    if (pkt->code == EAP_REQUEST || 
        pkt->code == EAP_RESPONSE) {
        
        switch (type) {
        case EAPT_TLS:

            flag = *ptr++;
            plen--;

            if (flag == 0 && plen == 0) 
            {
                ret = sstp_str_add(buf, &len, &pos, " ACK");
                if (ret < 0) 
                {
                    goto done;
                }
                break;
            }

            ret = sstp_str_add(buf, &len, &pos, " [%s %s %s]", 
                    EAP_TLS_FLAG_LI & flag ? "L" : "-",
                    EAP_TLS_FLAG_MF & flag ? "M" : "-",
                    EAP_TLS_FLAG_START & flag ? "S" : "-");
            if (ret < 0) 
            {
                goto done;
            }
            break;

        case EAPT_IDENTITY:
        case EAPT_NOTIFICATION:

            if (plen > 0) 
            {
                char identity[255];

                memcpy(identity, ptr, plen);
                identity[plen] = '\0';

                ret = sstp_str_add(buf, &len, &pos, " NAME: \"%s\"", identity);
                if (ret < 0) 
                { 
                    goto done;
                }
            }
            break;

        default:
            break;
        }
    }

done:

    if (ret == 0) 
    {
        ret = pos;
    }

    return ret;
}


/*!
 * @brief Dump the PAP packet to a log-message
 */
static int sstp_dump_pap(const ppp_hdr_st *pkt, char *buf, int len)
{
    unsigned char *ptr = sstp_ppp_data(pkt);
    int pos = 0;
    int ret = 0;
    int plen = 0;

    char name[128] = {};
    char pass[128] = {};

    if (pkt->code < FSM_CONFREQ || 
        pkt->code > FSM_CONFNAK)
    {
        return -1;
    }

    ret = sstp_str_add(buf, &len, &pos, " %s", sstp_ppp_getcode(pkt->code));
    if (ret < 0)
    {
        return -1;
    }

    switch (pkt->code)
    {
        case FSM_CONFREQ:

            plen = *ptr++;       
            memcpy(name, ptr, MIN(plen, sizeof(name)));
            ptr += plen;

            plen = *ptr++;
            memcpy(pass, ptr, MIN(plen, sizeof(pass)));
            ptr += plen;

            ret = sstp_str_add(buf, &len, &pos, " NAME=\"%s\", PASSWORD: \"%s\"", name, pass);
            if (ret < 0)
            {
                return -1;
            }
            break;

        case FSM_CONFACK:
        case FSM_CONFNAK:

            plen = *ptr++;
            memcpy(name, ptr, MIN(plen, sizeof(name)));
            ptr += plen;

            ret = sstp_str_add(buf, &len, &pos, " RESULT=\"%s\"", name);
            if (ret < 0)
            {
                return -1;
            }
            break;

        default:
            break;
    }

    return pos;
}


/*!
 * @brief Get the appropriate code name, and callback handler
 */
static const ppp_handler_st *sstp_ppp_handler(int proto)
{
    static ppp_handler_st handler[] =
    {
        { 0xc223,   "CHAP",     sstp_dump_chap  },
        { 0xc227,   "EAP",      sstp_dump_eap   },
        { 0x8021,   "IPCP",     sstp_dump_ipcp  },
        { 0xc021,   "LCP",      sstp_dump_lcp   },
        { 0xc023,   "PAP",      sstp_dump_pap   },
        { 0x80fd,   "CCP",      sstp_dump_ccp   },
        { 0x8281,   "MPLSCP"                    },  // Multi Protocol Label Switching Control Protocol
        { 0x8235,   "ACSP"                      },  // Appe Client Server Protocol
    };
    int idx = 0;

    for (idx = 0; idx < SIZEOF_ARRAY(handler); idx++)
    {
        if (proto == handler[idx].proto)
        {
            return &handler[idx];
        }
    }

    return NULL;
}


/*!
 * @brief Help dump any of the PPP data negotiation and layered PPP protocols
 */
static int sstp_dump_ppp(unsigned char *buf, size_t len, const char *file, int line)
{
    const ppp_handler_st *hdl = NULL;
    char msg[1024] = {};
    int ret = 0;
    int proto = 0;

    /* Skip PPP frame header */
    if (buf[0] == 0xff && buf[1] == 0x03)
    {
        buf += 2;
        len -= 2;
    }

    /* Get the protocol */
    proto = ntohs(*(uint16_t*) buf);
    buf += 2;
    
    /* Get the protocol handler */
    hdl = sstp_ppp_handler(proto);
    if (hdl) 
    {
        /* Validate the length */
        ppp_hdr_st *pkt = (ppp_hdr_st*) buf;
        if (ntohs(pkt->len) == len)
        {
            return -1;
        }

        /* If we have know how to process this PPP packect */
        if (hdl->fn_cb)
        {
            ret = hdl->fn_cb(pkt, msg, sizeof(msg));
        }

        /* Log the message */
        sstp_log_msg(SSTP_LOG_TRACE, file, line, "  PPP %s ID: %u%s%s", 
                hdl->name, 
                pkt->id, 
                ret > 0 ? " " : "", 
                ret > 0 ? msg : "");
        return 0;
    }

    return -1;
}


void sstp_pkt_dump(sstp_buff_st *buf, sstp_direction_t dir, const char *file, int line)
{
    sstp_pkt_st *pkt   = NULL;
    sstp_ctrl_st *ctrl = NULL;
    int type  = 0;
    int alen  = 0;
    int index = 0;
    int ret   = 0;
    int pktlen= 0;

    static const char *sstp_msg_type[] =
    {
        NULL,
        "CONNECT REQUEST",
        "CONNECT ACK",
        "CONNECT NAK",
        "CONNECTED",
        "ABORT",
        "DISCONNECT",
        "DISCONNECT ACK",
        "ECHO REQUEST",
        "ECHO REPLY",
    };

    static const char *sstp_attr_type[] = 
    {
        "NO ERROR",
        "ENCAP PROTO",
        "STATUS INFO",
        "CRYPTO BIND",
        "CRYPTO BIND REQ"
    };


    pkt    = (sstp_pkt_st*) sstp_buff_data(buf, index);
    index += (sizeof(sstp_pkt_st));

    /* Debugging control messages only? */
    if (SSTP_LOG_DBGCTRL == sstp_log_level() &&
        !(SSTP_MSG_FLAG_CTRL & pkt->flags)) {
        return;
    }

    /* Packet Type / Length */
    sstp_log_msg(SSTP_LOG_TRACE, file, line, "%s SSTP %s PKT(%d) ", 
        (dir == SSTP_DIR_RECV) ? "RECV" : "SEND",
        (SSTP_MSG_FLAG_CTRL & pkt->flags) ? "CRTL" : "DATA", 
        (ntohs(pkt->length)));

    /* Handle control packets */
    if (SSTP_MSG_FLAG_CTRL & pkt->flags)
    {
        ctrl   = (sstp_ctrl_st*) sstp_buff_data(buf, index);
        index += (sizeof(sstp_ctrl_st));
        type   = (ntohs(ctrl->type));
        alen   = (ntohs(ctrl->nattr));

        /* Control Type, num attributes */
        sstp_log_msg(SSTP_LOG_TRACE, file, line, "  TYPE(%d): %s, ATTR(%d):",
            type, sstp_msg_type[type], alen);

        while (alen--)
        {
            sstp_attr_st *attr = (sstp_attr_st*) 
                    sstp_buff_data(buf, index);

            if (SSTP_ATTR_MAX < attr->type)
            {
                return;
            }

            sstp_log_msg(SSTP_LOG_TRACE, file, line, "    %s(%d): %d",
                sstp_attr_type[attr->type], attr->type,
                ntohs(attr->length));
            index = ntohs(attr->length);
        }
    }
    else if (SSTP_LOG_TRACE <= sstp_log_level())
    {
        sstp_dump_ppp(sstp_pkt_data(buf), sstp_pkt_data_len(buf), file, line);
    }

    /* Only if dump was specified */
    if (SSTP_LOG_DUMP > sstp_log_level())
    {
        return;
    }

    /* Dump the message */
    pktlen = ntohs(pkt->length);
    for (index = 0; index < pktlen; index += 16)
    {
        int len = MIN(pktlen-index,16);
        char hex[96] = {};

        ret = sstp_bin2hex("0x%02X ", hex, sizeof(hex), (unsigned char*) buf->data + index, len);
        if (ret > 0) 
        {
            sstp_log_msg(SSTP_LOG_TRACE, file, line, "  %s", hex);
        }
    }
}

