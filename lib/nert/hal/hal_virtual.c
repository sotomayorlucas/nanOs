/*
 * NERT Virtual PHY Layer
 * UDP multicast implementation for testing without hardware
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "../nert_phy_if.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

/* ============================================================================
 * Virtual PHY Context
 * ============================================================================ */

struct virtual_phy_ctx {
    int sock_fd;
    struct sockaddr_in multicast_addr;
    struct sockaddr_in local_addr;
    uint16_t port;
    uint32_t tick_offset;  /* For tick simulation */
    uint32_t rng_state;    /* Simple RNG */
};

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static uint32_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* ============================================================================
 * PHY Interface Implementation
 * ============================================================================ */

static int virtual_send(const void *data, uint16_t len, void *ctx) {
    struct virtual_phy_ctx *vctx = (struct virtual_phy_ctx *)ctx;

    if (!vctx || vctx->sock_fd < 0) {
        return -1;
    }

    ssize_t sent = sendto(vctx->sock_fd, data, len, 0,
                          (struct sockaddr *)&vctx->multicast_addr,
                          sizeof(vctx->multicast_addr));

    return (sent == len) ? 0 : -1;
}

static int virtual_receive(void *buffer, uint16_t max_len, void *ctx) {
    struct virtual_phy_ctx *vctx = (struct virtual_phy_ctx *)ctx;

    if (!vctx || vctx->sock_fd < 0) {
        return -1;
    }

    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    ssize_t received = recvfrom(vctx->sock_fd, buffer, max_len, 0,
                                (struct sockaddr *)&sender_addr, &addr_len);

    if (received < 0) {
        /* Non-blocking mode - no data available is not an error */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }

    return (int)received;
}

static uint32_t virtual_get_ticks(void *ctx) {
    struct virtual_phy_ctx *vctx = (struct virtual_phy_ctx *)ctx;
    return get_time_ms() - vctx->tick_offset;
}

static uint32_t virtual_random(void *ctx) {
    struct virtual_phy_ctx *vctx = (struct virtual_phy_ctx *)ctx;

    /* Simple xorshift RNG */
    vctx->rng_state ^= vctx->rng_state << 13;
    vctx->rng_state ^= vctx->rng_state >> 17;
    vctx->rng_state ^= vctx->rng_state << 5;

    return vctx->rng_state;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

struct nert_phy_interface* nert_phy_virtual_create(uint16_t port, const char *multicast_group) {
    struct nert_phy_interface *phy = malloc(sizeof(struct nert_phy_interface));
    if (!phy) {
        return NULL;
    }

    struct virtual_phy_ctx *ctx = malloc(sizeof(struct virtual_phy_ctx));
    if (!ctx) {
        free(phy);
        return NULL;
    }

    memset(ctx, 0, sizeof(struct virtual_phy_ctx));
    ctx->port = port;
    ctx->tick_offset = get_time_ms();
    ctx->rng_state = (uint32_t)time(NULL) ^ port;

    /* Create UDP socket */
    ctx->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->sock_fd < 0) {
        free(ctx);
        free(phy);
        return NULL;
    }

    /* Set non-blocking mode */
#ifndef _WIN32
    int flags = fcntl(ctx->sock_fd, F_GETFL, 0);
    fcntl(ctx->sock_fd, F_SETFL, flags | O_NONBLOCK);
#else
    u_long mode = 1;
    ioctlsocket(ctx->sock_fd, FIONBIO, &mode);
#endif

    /* Enable address reuse */
    int reuse = 1;
    setsockopt(ctx->sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

#ifdef SO_REUSEPORT
    setsockopt(ctx->sock_fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuse, sizeof(reuse));
#endif

    /* Bind to local port */
    ctx->local_addr.sin_family = AF_INET;
    ctx->local_addr.sin_addr.s_addr = INADDR_ANY;
    ctx->local_addr.sin_port = htons(port);

    if (bind(ctx->sock_fd, (struct sockaddr *)&ctx->local_addr, sizeof(ctx->local_addr)) < 0) {
        close(ctx->sock_fd);
        free(ctx);
        free(phy);
        return NULL;
    }

    /* Join multicast group */
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(multicast_group);
    mreq.imr_interface.s_addr = INADDR_ANY;

    if (setsockopt(ctx->sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   (const char *)&mreq, sizeof(mreq)) < 0) {
        close(ctx->sock_fd);
        free(ctx);
        free(phy);
        return NULL;
    }

    /* Setup multicast destination */
    ctx->multicast_addr.sin_family = AF_INET;
    ctx->multicast_addr.sin_addr.s_addr = inet_addr(multicast_group);
    ctx->multicast_addr.sin_port = htons(port);

    /* Set multicast TTL */
    unsigned char ttl = 2;  /* Local network only */
    setsockopt(ctx->sock_fd, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&ttl, sizeof(ttl));

    /* Disable loopback if desired (enable for local testing) */
    unsigned char loop = 1;  /* Enable loopback */
    setsockopt(ctx->sock_fd, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&loop, sizeof(loop));

    /* Setup PHY interface */
    phy->send = virtual_send;
    phy->receive = virtual_receive;
    phy->get_ticks = virtual_get_ticks;
    phy->random = virtual_random;
    phy->context = ctx;

    return phy;
}

void nert_phy_virtual_destroy(struct nert_phy_interface *phy) {
    if (!phy) return;

    struct virtual_phy_ctx *ctx = (struct virtual_phy_ctx *)phy->context;
    if (ctx) {
        if (ctx->sock_fd >= 0) {
            close(ctx->sock_fd);
        }
        free(ctx);
    }

    free(phy);
}
