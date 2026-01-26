/*
 * NERT PHY Manager - Implementation
 *
 * Provides runtime PHY selection and management for NERT.
 *
 * Copyright (c) 2026 NanOS Project
 * SPDX-License-Identifier: MIT
 */

#include "phy_manager.h"
#include <string.h>

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Registered PHY backends */
static struct {
    uint8_t phy_type;
    const struct nert_phy_ops *ops;
    uint8_t registered;
} phy_registry[PHY_MANAGER_MAX_PHYS];

/* Currently active PHY */
static const struct nert_phy_ops *active_phy = NULL;
static uint8_t active_phy_type = 0;

/* Initialization flag */
static uint8_t initialized = 0;

/* ============================================================================
 * PHY Manager Core Implementation
 * ============================================================================ */

void phy_manager_init(void) {
    memset(phy_registry, 0, sizeof(phy_registry));
    active_phy = NULL;
    active_phy_type = 0;
    initialized = 1;
}

int phy_manager_register(uint8_t phy_type, const struct nert_phy_ops *ops) {
    if (!initialized || ops == NULL || phy_type == 0) {
        return PHY_MGR_ERR_INVALID;
    }

    /* Check if already registered */
    for (int i = 0; i < PHY_MANAGER_MAX_PHYS; i++) {
        if (phy_registry[i].registered &&
            phy_registry[i].phy_type == phy_type) {
            /* Update existing registration */
            phy_registry[i].ops = ops;
            return PHY_MGR_OK;
        }
    }

    /* Find free slot */
    for (int i = 0; i < PHY_MANAGER_MAX_PHYS; i++) {
        if (!phy_registry[i].registered) {
            phy_registry[i].phy_type = phy_type;
            phy_registry[i].ops = ops;
            phy_registry[i].registered = 1;
            return PHY_MGR_OK;
        }
    }

    return PHY_MGR_ERR_FULL;
}

int phy_manager_unregister(uint8_t phy_type) {
    if (!initialized) {
        return PHY_MGR_ERR_INVALID;
    }

    /* If this is the active PHY, deactivate first */
    if (active_phy_type == phy_type && active_phy != NULL) {
        phy_manager_deactivate();
    }

    for (int i = 0; i < PHY_MANAGER_MAX_PHYS; i++) {
        if (phy_registry[i].registered &&
            phy_registry[i].phy_type == phy_type) {
            phy_registry[i].registered = 0;
            phy_registry[i].ops = NULL;
            phy_registry[i].phy_type = 0;
            return PHY_MGR_OK;
        }
    }

    return PHY_MGR_ERR_NOT_FOUND;
}

int phy_manager_select(uint8_t phy_type, void *config) {
    if (!initialized) {
        return PHY_MGR_ERR_INVALID;
    }

    /* Find the requested PHY */
    const struct nert_phy_ops *new_phy = NULL;
    for (int i = 0; i < PHY_MANAGER_MAX_PHYS; i++) {
        if (phy_registry[i].registered &&
            phy_registry[i].phy_type == phy_type) {
            new_phy = phy_registry[i].ops;
            break;
        }
    }

    if (new_phy == NULL) {
        return PHY_MGR_ERR_NOT_FOUND;
    }

    /* Deactivate current PHY if different */
    if (active_phy != NULL && active_phy != new_phy) {
        if (active_phy->destroy) {
            active_phy->destroy();
        }
    }

    /* Initialize new PHY */
    if (new_phy->init) {
        if (new_phy->init(config) != 0) {
            active_phy = NULL;
            active_phy_type = 0;
            return PHY_MGR_ERR_INIT_FAIL;
        }
    }

    active_phy = new_phy;
    active_phy_type = phy_type;

    return PHY_MGR_OK;
}

const struct nert_phy_ops* phy_manager_get_active(void) {
    return active_phy;
}

uint8_t phy_manager_get_active_type(void) {
    return active_phy_type;
}

const struct nert_phy_caps* phy_manager_get_caps(uint8_t phy_type) {
    if (!initialized) {
        return NULL;
    }

    for (int i = 0; i < PHY_MANAGER_MAX_PHYS; i++) {
        if (phy_registry[i].registered &&
            phy_registry[i].phy_type == phy_type) {
            if (phy_registry[i].ops && phy_registry[i].ops->get_caps) {
                return phy_registry[i].ops->get_caps();
            }
            break;
        }
    }

    return NULL;
}

int phy_manager_is_registered(uint8_t phy_type) {
    if (!initialized) {
        return 0;
    }

    for (int i = 0; i < PHY_MANAGER_MAX_PHYS; i++) {
        if (phy_registry[i].registered &&
            phy_registry[i].phy_type == phy_type) {
            return 1;
        }
    }

    return 0;
}

int phy_manager_deactivate(void) {
    if (!initialized) {
        return PHY_MGR_ERR_INVALID;
    }

    if (active_phy != NULL) {
        if (active_phy->destroy) {
            active_phy->destroy();
        }
        active_phy = NULL;
        active_phy_type = 0;
    }

    return PHY_MGR_OK;
}

int phy_manager_list(uint8_t *types, int max_count) {
    if (!initialized || types == NULL || max_count <= 0) {
        return 0;
    }

    int count = 0;
    for (int i = 0; i < PHY_MANAGER_MAX_PHYS && count < max_count; i++) {
        if (phy_registry[i].registered) {
            types[count++] = phy_registry[i].phy_type;
        }
    }

    return count;
}

/* ============================================================================
 * Convenience Wrappers
 * ============================================================================ */

int phy_manager_send(const uint8_t *data, uint16_t len) {
    if (active_phy == NULL || active_phy->send == NULL) {
        return PHY_MGR_ERR_NO_ACTIVE;
    }
    return active_phy->send(data, len);
}

int phy_manager_receive(uint8_t *buf, uint16_t max_len) {
    if (active_phy == NULL || active_phy->receive == NULL) {
        return PHY_MGR_ERR_NO_ACTIVE;
    }
    return active_phy->receive(buf, max_len);
}

int phy_manager_get_mtu(void) {
    if (active_phy == NULL || active_phy->get_mtu == NULL) {
        return PHY_MGR_ERR_NO_ACTIVE;
    }
    return active_phy->get_mtu();
}

int phy_manager_set_channel(uint8_t channel) {
    if (active_phy == NULL || active_phy->set_channel == NULL) {
        return PHY_MGR_ERR_NO_ACTIVE;
    }
    return active_phy->set_channel(channel);
}

int phy_manager_get_rssi(void) {
    if (active_phy == NULL || active_phy->get_rssi == NULL) {
        return -127;  /* Minimum RSSI as error indicator */
    }
    return active_phy->get_rssi();
}

int phy_manager_sleep(uint32_t duration_ms) {
    if (active_phy == NULL || active_phy->sleep == NULL) {
        return PHY_MGR_ERR_NO_ACTIVE;
    }
    return active_phy->sleep(duration_ms);
}

int phy_manager_wake(void) {
    if (active_phy == NULL || active_phy->wake == NULL) {
        return PHY_MGR_ERR_NO_ACTIVE;
    }
    return active_phy->wake();
}
