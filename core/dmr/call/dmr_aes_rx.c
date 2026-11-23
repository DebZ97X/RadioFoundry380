// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// Receive-only DMR AES-256-OFB bench decoder. AES block transform: FIPS 197.
#include "dmr/call/dmr_aes_rx.h"

#ifdef RF_DMR_AES_RX
#include <string.h>
#include "dmr/call/dmr_call.h"
#include "dmr/ambe/ambeFec.h"

#include "codeplug/codeplug_kv.h"
#include "codeplug/codeplug_records.h"
#include "codeplug/codeplug_tag.h"

// Reserved bench record at the end of the existing traffic-key family.
#define AES_RX_TRAFFIC_RECORD (CODEPLUG_KEY_ZONE_TAG - 1u)

static const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static uint8_t xtime(uint8_t value)
{
	return (uint8_t)((value << 1) ^ ((value & 0x80) ? 0x1b : 0));
}

static void expand_key(uint8_t schedule[240], const uint8_t key[DMR_AES_RX_KEY_SIZE])
{
	memcpy(schedule, key, DMR_AES_RX_KEY_SIZE);
	uint8_t rcon = 1;
	for (unsigned i = 32; i < 240; i += 4) {
		uint8_t t[4];
		memcpy(t, &schedule[i - 4], sizeof(t));
		if (i % 32 == 0) {
			uint8_t first = t[0];
			t[0] = sbox[t[1]] ^ rcon;
			t[1] = sbox[t[2]];
			t[2] = sbox[t[3]];
			t[3] = sbox[first];
			rcon = xtime(rcon);
		} else if (i % 32 == 16) {
			for (unsigned j = 0; j < 4; j++)
				t[j] = sbox[t[j]];
		}
		for (unsigned j = 0; j < 4; j++)
			schedule[i + j] = schedule[i + j - 32] ^ t[j];
	}
}

static void aes_encrypt(uint8_t block[16], const uint8_t schedule[240])
{
	for (unsigned i = 0; i < 16; i++)
		block[i] ^= schedule[i];
	for (unsigned round = 1; round <= 14; round++) {
		uint8_t t[16];
		for (unsigned col = 0; col < 4; col++)
			for (unsigned row = 0; row < 4; row++)
				t[col * 4 + row] = sbox[block[((col + row) % 4) * 4 + row]];
		if (round != 14) {
			for (unsigned col = 0; col < 16; col += 4) {
				uint8_t *c = &t[col];
				uint8_t first = c[0];
				uint8_t all = c[0] ^ c[1] ^ c[2] ^ c[3];
				c[0] ^= all ^ xtime(c[0] ^ c[1]);
				c[1] ^= all ^ xtime(c[1] ^ c[2]);
				c[2] ^= all ^ xtime(c[2] ^ c[3]);
				c[3] ^= all ^ xtime(c[3] ^ first);
			}
		}
		for (unsigned i = 0; i < 16; i++)
			block[i] = t[i] ^ schedule[round * 16 + i];
	}
}

// The 32-bit DMR message indicator expands MSB first with the same LFSR
// that advances it between superframes (observed on the AT-D578UV).
static uint32_t advance(uint32_t mi)
{
	for (unsigned i = 0; i < 32; i++)
		mi = (mi << 1) | (((mi >> 31) ^ (mi >> 21) ^ (mi >> 1) ^ mi) & 1u);
	return mi;
}

static void prepare_stream(dmr_aes_rx_t *rx)
{
	uint8_t block[16];
	uint32_t word = rx->mi;
	for (unsigned i = 0; i < sizeof(block); i += 4) {
		for (unsigned j = 0; j < 4; j++)
			block[i + j] = (uint8_t)(word >> (24 - 8 * j));
		word = advance(word);
	}
	aes_encrypt(block, rx->schedule); // discard the first OFB block
	for (unsigned i = 0; i < sizeof(rx->stream); i += sizeof(block)) {
		unsigned remaining = sizeof(rx->stream) - i;
		aes_encrypt(block, rx->schedule);
		memcpy(&rx->stream[i], block, remaining < sizeof(block) ? remaining : sizeof(block));
	}
	rx->mi = advance(rx->mi);
}

bool dmr_aes_rx_bound(uint16_t number, const char *name)
{
	uint8_t expected[4] = { (uint8_t)number, (uint8_t)(number >> 8) };
	uint8_t stored[sizeof(expected)];
	uint16_t check = codeplug_name_check(name);
	expected[2] = (uint8_t)check;
	expected[3] = (uint8_t)(check >> 8);
	return number != 0 && codeplug_kv_get(CODEPLUG_KEY_DMR_AES_RX, stored, sizeof(stored)) == sizeof(stored) &&
	       memcmp(stored, expected, sizeof(stored)) == 0;
}

static void wipe(uint8_t *p, unsigned n)
{
	volatile uint8_t *v = p;
	while (n--)
		*v++ = 0;
}

bool dmr_aes_rx_provision(uint16_t number, const uint8_t key[DMR_AES_RX_KEY_SIZE])
{
	channel_t ch;
	if (number == 0 || !codeplug_channel(number, &ch) || ch.mode != RADIO_MODE_DMR ||
	    (ch.rx_hz != ch.tx_hz && !ch.dmo))
		return false;

	// Standalone simplex namespace, AES-256 OFB, key ID 1, flags 0.
	uint8_t rec[CODEPLUG_TRAFFIC_HDR + DMR_AES_RX_KEY_SIZE] = {
		CODEPLUG_SYSTEM_NONE, DMR_AES_RX_ALG, DMR_AES_RX_KEY_ID, 0, 0,
	};
	uint8_t head[CODEPLUG_TRAFFIC_HDR];
	int existing = codeplug_kv_get(AES_RX_TRAFFIC_RECORD, head, sizeof(head));
	if (existing >= 0 && (existing != sizeof(rec) || memcmp(head, rec, sizeof(head)) != 0))
		return false; // the reserved record is occupied by something else

	uint16_t check = codeplug_name_check(ch.name);
	uint8_t bind[4] = { (uint8_t)number, (uint8_t)(number >> 8), (uint8_t)check, (uint8_t)(check >> 8) };
	memcpy(&rec[CODEPLUG_TRAFFIC_HDR], key, DMR_AES_RX_KEY_SIZE);
	const codeplug_kv_op_t ops[] = {
		{ AES_RX_TRAFFIC_RECORD, sizeof(rec), rec },
		{ CODEPLUG_KEY_DMR_AES_RX, sizeof(bind), bind },
	};
	bool ok = codeplug_kv_write(ops, sizeof(ops) / sizeof(ops[0]));
	wipe(rec, sizeof(rec));
	return ok;
}

bool dmr_aes_rx_start(dmr_aes_rx_t *rx, uint32_t mi)
{
	uint8_t key[DMR_AES_RX_KEY_SIZE];
	int len = codeplug_traffic_key(CODEPLUG_SYSTEM_NONE, DMR_AES_RX_ALG, DMR_AES_RX_KEY_ID, key, sizeof(key));
	if (len == sizeof(key)) {
		expand_key(rx->schedule, key);
		rx->mi = mi;
		rx->next = 0;
		rx->first = 1;
	}
	wipe(key, sizeof(key));
	return len == sizeof(key);
}

void dmr_aes_rx_burst(dmr_aes_rx_t *rx, uint8_t burst[27])
{
	if (rx->next == 0)
		prepare_stream(rx);
	static const uint8_t empty_frame[DMR_AMBE_FRAME_BYTES];
	for (unsigned f = 0; f < DMR_AMBE_FRAMES_PER_BURST; f++) {
		uint8_t *frame = &burst[f * DMR_AMBE_FRAME_BYTES];
		uint8_t bits[AMBE_PARAM_BITS];
		// The initial A in both D578 captures carried identical frames despite different MIs.
		if ((rx->first && rx->next == 0) || memcmp(frame, empty_frame, sizeof(empty_frame)) == 0 ||
		    ambeFecDecode(frame, bits, NULL) >= 7) {
			memcpy(frame, dmr_ambe_silence, DMR_AMBE_FRAME_BYTES);
			continue;
		}
		if (memcmp(frame, dmr_ambe_silence, DMR_AMBE_FRAME_BYTES) == 0)
			continue;
		unsigned offset = (rx->next * DMR_AMBE_FRAMES_PER_BURST + f) * DMR_AES_RX_FRAME_BYTES;
		for (unsigned i = 0; i < AMBE_PARAM_BITS; i++)
			bits[i] ^= (rx->stream[offset + i / 8] >> (7 - i % 8)) & 1u;
		ambeFecEncode(bits, frame);
	}
	rx->next = (rx->next + 1u) % DMR_AES_RX_BURSTS;
	rx->first = 0;
}
#endif
