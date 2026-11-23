// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
#ifndef DMR_AES_RX_H
#define DMR_AES_RX_H

#include <stdbool.h>
#include <stdint.h>

#ifdef RF_DMR_AES_RX
#define DMR_AES_RX_BURSTS 6
#define DMR_AES_RX_FRAME_BYTES 7
#define DMR_AES_RX_KEY_SIZE 32
#define DMR_AES_RX_KEY_ID 1
#define DMR_AES_RX_ALG 0x05
#define DMR_AES_RX_VENDOR 0x10

typedef struct {
	uint32_t mi;
	uint8_t next;
	uint8_t first;
	uint8_t stream[18 * DMR_AES_RX_FRAME_BYTES];
	uint8_t schedule[240];
} dmr_aes_rx_t;

// The bench build can bind one programmed simplex channel to traffic key ID 1.
bool dmr_aes_rx_bound(uint16_t number, const char *name);
bool dmr_aes_rx_provision(uint16_t number, const uint8_t key[DMR_AES_RX_KEY_SIZE]);
bool dmr_aes_rx_start(dmr_aes_rx_t *rx, uint32_t mi);
void dmr_aes_rx_burst(dmr_aes_rx_t *rx, uint8_t burst[27]);
#endif
#endif
