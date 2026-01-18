/*
 * NERT Framework Configuration - Implementation
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "nert_config.h"
#include <string.h>

void nert_config_init(struct nert_config *config,
                      uint16_t node_id,
                      const uint8_t master_key[NERT_KEY_SIZE],
                      struct nert_phy_interface *phy) {
    memset(config, 0, sizeof(struct nert_config));

    /* Node identity */
    config->node_id = node_id;

    /* Security defaults */
    if (master_key) {
        memcpy(config->security.master_key, master_key, NERT_KEY_SIZE);
    }
    config->security.enable_key_rotation = 1;
    config->security.key_rotation_period_sec = 3600;  /* 1 hour */
    config->security.grace_window_ms = 30000;         /* 30 seconds */
    config->security.enable_replay_protection = 1;

    /* PHY interface */
    config->phy = phy;

    /* No handlers by default */
    config->handler_count = 0;
}

int nert_config_add_handler(struct nert_config *config,
                            uint8_t msg_type,
                            nert_message_callback_t callback,
                            void *user_ctx) {
    if (config->handler_count >= NERT_MAX_HANDLERS) {
        return -1;  /* Handler table full */
    }

    struct nert_message_handler *handler = &config->handlers[config->handler_count];
    handler->msg_type = msg_type;
    handler->callback = callback;
    handler->user_ctx = user_ctx;

    config->handler_count++;
    return 0;
}
