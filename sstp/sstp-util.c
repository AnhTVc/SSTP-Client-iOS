/*!
 * @brief Utility Functions
 *
 * @file sstp-util.c
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
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>

#include "sstp-private.h"


status_t sstp_set_nonbl(int sock, int state)
{
    int ret  = -1;
    int flag = fcntl(sock, F_GETFL);

    flag = (state == 1)
        ? (flag | O_NONBLOCK)
        : (flag & ~O_NONBLOCK);

    ret = fcntl(sock, F_SETFL, flag);
    if (ret != 0)
    {
        return SSTP_FAIL;
    }

    return SSTP_OKAY;
}


char *sstp_get_guid(char *buf, int len)
{
    uint32_t data1, data4;
    uint16_t data2, data3;
    unsigned int seed;
    int ret;

    seed = time(NULL) | getpid();
    srand (seed);

    data1 = (rand() + 1);
    data2 = (rand() + 1);
    data3 = (rand() + 1);
    data4 = (rand() + 1);

    /* Create the GUID string */
    ret = snprintf(buf, len, "{%.4X-%.2X-%.2X-%.4X}", data1, data2,
            data3, data4);
    if (ret <= 0 || ret > len)
    {
        return NULL;
    }

    return buf;
}


status_t sstp_set_sndbuf(int sock, int size)
{
    int ret = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    if (ret != 0)
    {
        return SSTP_FAIL;
    }

    return SSTP_OKAY;
}

static int is_ipv6(const char *str)
{
    struct sockaddr_in6 addr;

    if (inet_pton(AF_INET6, str, &addr) == 1)
    {
        return 1;
    }

    return 0;
}

static int is_ipv4(const char *str)
{
    struct sockaddr_in addr;

    if (inet_pton(AF_INET, str, &addr) == 1)
    {
        return 1;
    }

    return 0;
}

/*
 * For now, any string with length less than 253 characters is a FQDN we can try
 */
static int is_hostname(const char *str)
{
    const char *ptr = str;
    const char *ptr1 = ptr;
    int flags = 0x01;

    if (strlen(str) > 253)
    {
        return 0;
    }

    return 1;
}

static int is_port(const char *str)
{
    errno = 0;
    int val = strtol(str, NULL, 10);
    return (errno != ERANGE && val > 0 && val < 65536) ? 1 : 0;
}


status_t sstp_url_parse(sstp_url_st **url, const char *path)
{
    char *ptr = NULL;
    char *ptr1 = NULL;

    /* Allocate url context */
    sstp_url_st *ctx = calloc(1, sizeof(sstp_url_st));
    if (!ctx)
    {
        goto errout;
    }

    /* Copy to working buffer */
    ctx->ptr = strdup(path);
    ptr = ctx->ptr;

    /* Look for the protocol string (optional) */
    ptr1 = strstr(ptr, "://");
    if (ptr1 != NULL)
    {
        ctx->schema = ptr;
        *ptr1 = '\0';
        ptr1  += 3;
        ptr    = ptr1;
    }

    /* Username & Password? (optional) */
    ptr1 = strchr(ptr, '@');
    if (ptr1 != NULL)
    {
        ctx->user = ptr;
        *ptr1++ = '\0';
        ptr = ptr1;
    }

    /* Extract the password (optional) */
    if (ctx->user)
    {
        ptr1 = strchr(ctx->user, ':');
        if (ptr1)
        {
            *ptr1++ = '\0';
            ctx->password = ptr1;
        }
    }

    /* Set the host pointer */
    ctx->host = ptr;

    /* Look for the path component (optional) */
    ptr1 = strchr(ptr, '/');
    if (ptr1 != NULL)
    {
        *ptr1++ = '\0';
        ctx->path = ptr1;
    }

    /* If host is an ipv6 address with an opening bracket? */
    if (*ctx->host == '[')
    {
        ctx->host++;
        ptr1 = strchr(ptr, ']');
        if (!ptr1)
        {
            goto errout;
        }

        *ptr1++ = '\0';
        ptr = ptr1;

        if (*ptr == ':')
        {
            ctx->port = ++ptr;
        }

        if (!is_ipv6(ctx->host))
        {
            goto errout;
        }
    }
    else
    {
        if (!is_ipv6(ptr))
        {
            ptr1 = strrchr(ptr, ':');
            if (ptr1 != NULL)
            {
                *ptr1++ = '\0';
                ctx->port = ptr1;
            }

            if (!is_ipv4(ptr) &&
                !is_hostname(ptr))
            {
                goto errout;
            }
        }
    }

    if (ctx->port &&
        !is_port(ctx->port))
    {
        goto errout;
    }

    /* Either must be specified */
    if (!ctx->schema && !ctx->port)
    {
        ctx->port = "443";
    }

    /* Success */
    *url = ctx;
    return SSTP_OKAY;

errout:

    if (ctx)
    {
        sstp_url_free(ctx);
        ctx = NULL;
    }

    return SSTP_FAIL;
}


void sstp_url_free(sstp_url_st *url)
{
    if (!url)
    {
        return;
    }

    if (url->ptr)
    {
        free(url->ptr);
        url->ptr = NULL;
    }

    free(url);
}


const char *sstp_norm_data(unsigned long long count, char *buf, int len)
{
    float b = count;
    char v [] = { 'K', 'M', 'G', 'T' };
    int i = 0;

    if (count <= 1024)
    {
        snprintf(buf, len, "%llu bytes", count);
        return buf;
    }

    while (b > 1024)
    {
        b /= 1024;
        i++;
    }

    snprintf(buf, len, "%.02f %cb", b, v[i-1]);
    return buf;
}


/*!
 * @brief Normilize into hour, min or sec.
 */
const char *sstp_norm_time(unsigned long t, char *buf, int len)
{
    if (t > 3600)
    {
        snprintf(buf, len, "%.02f hour(s)", (float)t/3600);
        return buf;
    }

    if (t > 60)
    {
        snprintf(buf, len, "%.02f minute(s)", (float)t/60);
        return buf;
    }

    snprintf(buf, len, "%lu seconds", t);
    return buf;
}


/*!
 * @brief Convert sockaddr structure to an ip-string
 */
const char *sstp_ipaddr(struct sockaddr *addr, char *buf, int len)
{
    const char *retval = NULL;

    switch (addr->sa_family)
    {
    case AF_INET:
    {
        struct sockaddr_in *in = (struct sockaddr_in*) addr;
        if (inet_ntop(AF_INET, &in->sin_addr, buf, len))
        {
            retval = buf;
        }
        break;
    }
    case AF_INET6:
    {
        struct sockaddr_in6 *in = (struct sockaddr_in6*) addr;
        if (inet_ntop(AF_INET6, &in->sin6_addr, buf, len))
        {
            retval = buf;
        }
        break;
    }
    default:
        break;
    }

    return retval;
}


int sstp_get_uid(const char *name)
{
    struct passwd pwd;
    struct passwd *res = NULL;
    char *buff = NULL;
    int blen = 0;

    blen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (blen == -1)
    {
        blen = 1024;
    }

    /* Allocate the memory */
    buff = alloca(blen);
    if (!buff)
    {
        return -1;
    }

    /* Get the password entry */
    if (!getpwnam_r(name, &pwd, buff, blen, &res) && res)
    {
        return pwd.pw_uid;
    }

    return -1;
}


int sstp_get_gid(const char *name)
{
    struct group grp;
    struct group *res = NULL;
    char *buff = NULL;
    int blen = 0;

    blen = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (blen == -1)
    {
        blen = 1024;
    }

    /* Allocate the memory */
    buff = alloca(blen);
    if (!buff)
    {
        return -1;
    }

    /* Get the password entry */
    if (!getgrnam_r(name, &grp, buff, blen, &res) && res)
    {
        return grp.gr_gid;
    }

    return -1;
}


int sstp_sandbox(const char *path, const char *user, const char *group)
{
    int gid = -1;
    int uid = -1;
    int retval = -1;

    if (user)
    {
        uid = sstp_get_uid(user);
    }

    if (group)
    {
        gid = sstp_get_gid(group);
    }

    /* Change the root directory */
    if (path)
    {
        if (chdir(path) != 0)
        {
            log_warn("Could not change working directory, %s (%d)",
                strerror(errno), errno);
            goto done;
        }

        if (chroot(path) != 0)
        {
            log_warn("Could not change root directory, %s (%d)",
                strerror(errno), errno);
            goto done;
        }
    }

    /* Set the group id (before setting user id) */
    if (gid >= 0 && gid != getgid())
    {
        /* Call setgroups prior to dropping privileges (setuid,setgid) */
        setgroups(0, NULL);

        if (setgid(gid) != 0)
        {
            log_warn("Could not set process group id, %s (%d)",
                strerror(errno), errno);
            goto done;
        }
    }

    /* Setting the user id */
    if (uid >= 0 && uid != getuid())
    {
        if (setuid(uid) != 0)
        {
            log_warn("Could not set process user id, %s (%d)",
                strerror(errno), errno);
            goto done;
        }
    }

    retval = 0;

done:

    return (retval);
}


int sstp_bin2hex(const char *fmt, char *outbuf, int outlen, unsigned char *inbuf, int inlen)
{
    int count   = 0;
    int offset  = 0;
    int len     = 0;

    for (count = 0; count < inlen; count++)
    {
        len = sprintf(&outbuf[offset], fmt, (inbuf[count]) & 0xFF);
        if (len < 0 || len >= (outlen - offset))
        {
            return -1;
        }

        offset += len;
    }

    /* Return the number of bytes written */
    return offset;
}


int sstp_create_dir(const char *path, const char *user, const char *group, mode_t mode)
{
    int ret = -1;
    int gid = -1;
    int uid = -1;
    int retval = (-1);

    /* Create the directory if it doesn't exists */
    ret = mkdir(path, mode);
    if (ret != 0 && errno != EEXIST)
    {
        log_err("Could not create directory: %s, %s (%d)",
            path, strerror(errno), errno);
        goto done;
    }

    /* Get the user */
    if (user)
    {
        uid = sstp_get_uid(user);
    }

    /* Get the group */
    if (group)
    {
        gid = sstp_get_gid(group);
    }

    /* Change user/group permissions */
    ret = chown(path, uid, gid);
    if (ret != 0)
    {
        log_warn("Could not change permissions on %s, %s (%d)",
            path, strerror(errno), errno);
    }

    /* Success */
    retval = 0;

done:

    return retval;
}

#ifdef __SSTP_UNIT_TEST_UTILS

status_t test_ipv4_urls()
{
    sstp_url_st *url = NULL;
    status_t status;
    int retval = 0;

    status = sstp_url_parse(&url, "192.168.1.1:84433");
    if (status != SSTP_FAIL)
    {
        printf("Success on an invalid port\n");
        retval++;
    }

    status = sstp_url_parse(&url, "192.168.1.1:8443");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse url with ip address and port\n");
        retval++;
    }
    else if (strcmp(url->host, "192.168.1.1"))
    {
        printf("Unexpected host, %s\n", url->host);
        retval++;
    }
    else if (strcmp(url->port, "8443"))
    {
        printf("Unexpected port, %s\n", url->port);
        retval++;
    }

    sstp_url_free(url);

    status = sstp_url_parse(&url, "192.168.1.1");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse url with ip address\n");
        retval++;
    }
    else if (strcmp(url->host, "192.168.1.1"))
    {
        printf("Unexpected host, %s\n", url->host);
        retval++;
    }

    sstp_url_free(url);

    return (retval == 0)
        ? SSTP_OKAY
        : SSTP_FAIL;
}

status_t test_ipv6_urls()
{
    sstp_url_st *url;
    status_t status;
    int retval = 0;

    status = sstp_url_parse(&url, "2001:db8:0:2::3");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse ipv6 address\n");
        retval++;
    }
    else if (strcmp(url->host, "2001:db8:0:2::3"))
    {
        printf("Unexpected host, %s\n", url->host);
        retval++;
    }
    sstp_url_free(url);

    status = sstp_url_parse(&url, "[2001:db8:0:2::3]:80");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse ipv6 address with port\n");
        retval++;
    }
    else if (strcmp(url->host, "2001:db8:0:2::3"))
    {
        printf("Unexpected host, %s\n", url->host);
        retval++;
    }
    else if (strcmp(url->port, "80"))
    {
        printf("Unexpected port, %s\n", url->port);
        retval++;
    }
    sstp_url_free(url);

    status = sstp_url_parse(&url, "::ffff:192.168.122.121");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse ipv6 address within ipv4 space\n");
        retval++;
    }
    sstp_url_free(url);

    status = sstp_url_parse(&url, "[::ffff:192.168.122.121]:80");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse ipv6 address within ipv4 space and port\n");
        retval++;
    }
    sstp_url_free(url);

    status = sstp_url_parse(&url, "::1");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse ipv6 address with trailing compression\n");
        retval++;
    }
    sstp_url_free(url);

    status = sstp_url_parse(&url, "[::1]:80");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse ipv6 address with trailing compression and port\n");
        retval++;
    }
    sstp_url_free(url);

    status = sstp_url_parse(&url, "::");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse ipv6 address with any address compression\n");
        retval++;
    }
    sstp_url_free(url);

    status = sstp_url_parse(&url, "[::]:8080");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse ipv6 address with any address compression and port\n");
        retval++;
    }
    sstp_url_free(url);

    return (retval == 0)
        ? SSTP_OKAY
        : SSTP_FAIL;
}

status_t test_urls_with_user_and_pass()
{
    sstp_url_st *url = NULL;
    status_t status;
    int retval = 0;

    status = sstp_url_parse(&url, "https://user:password@server.sstp-test.com:443/some/path");
    if (status != SSTP_OKAY)
    {
        printf("Failed to parse url with username, password, port and path\n");
        retval++;
    }
    else if (strcmp(url->schema, "https"))
    {
        printf("Unexpected schema, %s\n", url->schema);
        retval++;
    }
    else if (strcmp(url->host, "server.sstp-test.com"))
    {
        printf("Unexpected site, %s\n", url->host);
        retval++;
    }
    else if (strcmp(url->port, "443"))
    {
        printf("Unexpected port, %s\n", url->port);
        retval++;
    }
    else if (strcmp(url->path, "some/path"))
    {
        printf("Unexpected path, %s\n", url->path);
        retval++;
    }
    else if (strcmp(url->user, "user"))
    {
        printf("Unexpected user, %s", url->user);
        retval++;
    }
    else if (strcmp(url->password, "password"))
    {
        printf("Unexpected password, %s", url->password);
        retval++;
    }

    sstp_url_free(url);

    return (retval == 0)
        ? SSTP_OKAY
        : SSTP_FAIL;
}

int main(int argc, char *argv[])
{
    sstp_url_st *url;
    int status = SSTP_FAIL;
    int retval = 0;

    status = test_urls_with_user_and_pass();
    if (status != SSTP_OKAY)
    {
        retval++;
    }

    status = test_ipv4_urls();
    if (status != SSTP_OKAY)
    {
        retval++;
    }

    status = test_ipv6_urls();
    if (status != SSTP_OKAY)
    {
        retval++;
    }

    return (retval == 0)
        ? EXIT_SUCCESS
        : EXIT_FAILURE;
}

#endif
