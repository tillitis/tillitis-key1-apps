#include "app_proto.h"
#include "monocypher-ed25519.h"

#include "../common/mta1_mkdf_mem.h"

// clang-format off
static volatile uint32_t *cdi =   (volatile uint32_t *)MTA1_MKDF_MMIO_MTA1_CDI_FIRST;
static volatile uint32_t *led =   (volatile uint32_t *)MTA1_MKDF_MMIO_MTA1_LED;
static volatile uint32_t *touch = (volatile uint32_t *)MTA1_MKDF_MMIO_TOUCH_STATUS;

#define LED_BLACK 0
#define LED_RED   (1 << MTA1_MKDF_MMIO_MTA1_LED_R_BIT)
#define LED_GREEN (1 << MTA1_MKDF_MMIO_MTA1_LED_G_BIT)
#define LED_BLUE  (1 << MTA1_MKDF_MMIO_MTA1_LED_B_BIT)
// clang-format on

#define MAX_SIGN_SIZE 4096

const uint8_t app_name0[4] = "fdkm"; // mkdf backwards
const uint8_t app_name1[4] = "ngis"; // sign backwards
const uint32_t app_version = 0x00000001;

void wait_touch_ledflash(int ledvalue, int loopcount)
{
	int led_on = 0;
	// first a write, to ensure no stray touch?
	*touch = 0;
	for (;;) {
		*led = led_on ? ledvalue : 0;
		for (int i = 0; i < loopcount; i++) {
			if (*touch &
			    (1 << MTA1_MKDF_MMIO_TOUCH_STATUS_EVENT_BIT)) {
				goto touched;
			}
		}
		led_on = !led_on;
	}
touched:
	// write, confirming we read the touch event
	*touch = 0;
}

int main(void)
{
	uint32_t stack;
	uint8_t pubkey[32];
	struct frame_header hdr; // Used in both directions
	uint8_t cmd[CMDLEN_MAXBYTES];
	uint8_t rsp[CMDLEN_MAXBYTES];
	uint32_t message_size = 0;
	uint8_t message[MAX_SIGN_SIZE];
	int msg_idx; // Where we are currently loading the data to sign
	uint8_t signature[64];
	uint32_t signature_done = 0;
	int left = 0;	// Bytes left to read
	int nbytes = 0; // Bytes to write to memory
	uint8_t in;
	uint32_t local_cdi[8];

	puts("Hello! &stack is on: ");
	putinthex((uint32_t)&stack);
	lf();

	// Generate a public key from CDI (only word aligned access to CDI)
	wordcpy(local_cdi, (void *)cdi, 8);
	crypto_ed25519_public_key(pubkey, (const uint8_t *)local_cdi);

	// color for steady led light, depending on state
	int led_steady = LED_BLACK;
	for (;;) {
		// blocking; flashing a safe blue while waiting for cmd
		in = readbyte_ledflash(LED_BLUE, 700000);
		*led = led_steady;
		puts("Read byte: ");
		puthex(in);
		putchar('\n');

		if (parseframe(in, &hdr) == -1) {
			puts("Couldn't parse header\n");
			continue;
		}

		memset(cmd, 0, CMDLEN_MAXBYTES);
		// Read app command, blocking
		read(cmd, hdr.len);

		// Is it for us?
		if (hdr.endpoint != DST_SW) {
			puts("Message not meant for app. endpoint was 0x");
			puthex(hdr.endpoint);
			lf();
			continue;
		}

		// Reset response buffer
		memset(rsp, 0, CMDLEN_MAXBYTES);

		led_steady = LED_BLACK;

		// Min length is 1 byte so this should always be here
		switch (cmd[0]) {
		case APP_CMD_GET_PUBKEY:
			puts("APP_CMD_GET_PUBKEY\n");
			memcpy(rsp, pubkey, 32);
			appreply(hdr, APP_CMD_GET_PUBKEY, rsp);
			break;

		case APP_CMD_SET_SIZE:
			puts("APP_CMD_SET_SIZE\n");
			if (hdr.len != 32) {
				// Bad length
				puts("APP_CMD_SET_SIZE bad length\n");
				break;
			}
			signature_done = 0;
			// cmd[1..4] contains the size.
			message_size = cmd[1] + (cmd[2] << 8) + (cmd[3] << 16) +
				       (cmd[4] << 24);

			if (message_size > MAX_SIGN_SIZE) {
				puts("Message too big!\n");
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_CMD_SET_SIZE, rsp);
				break;
			}

			// Reset where we load the data
			left = message_size;
			msg_idx = 0;

			rsp[0] = STATUS_OK;
			appreply(hdr, APP_CMD_SET_SIZE, rsp);
			led_steady = LED_GREEN;
			break;

		case APP_CMD_SIGN_DATA:
			puts("APP_CMD_SIGN_DATA\n");
			const uint32_t cmdBytelen = 128;

			// Bad length of this command, or APP_CMD_SET_SIZE has
			// not been called
			if (hdr.len != cmdBytelen || message_size == 0) {
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_CMD_SIGN_DATA, rsp);
				break;
			}

			if (left > (cmdBytelen - 1)) {
				nbytes = cmdBytelen - 1;
			} else {
				nbytes = left;
			}

			memcpy(&message[msg_idx], cmd + 1, nbytes);
			msg_idx += nbytes;
			left -= nbytes;

			if (left == 0) {
				wait_touch_ledflash(LED_GREEN, 200000);
				// All loaded, device touched, let's
				// sign the message
				crypto_ed25519_sign(signature,
						    (void *)local_cdi, pubkey,
						    message, message_size);
				signature_done = 1;
				message_size = 0;
			}

			rsp[0] = STATUS_OK;
			appreply(hdr, APP_CMD_SIGN_DATA, rsp);
			led_steady = LED_GREEN;
			break;

		case APP_CMD_GET_SIG:
			puts("APP_CMD_GET_SIG\n");
			if (signature_done == 0) {
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_CMD_GET_SIG, rsp);
				break;
			}
			memcpy(rsp, signature, 64);
			appreply(hdr, APP_CMD_GET_SIG, rsp);
			led_steady = LED_GREEN;
			break;

		case APP_CMD_GET_NAMEVERSION:
			puts("APP_CMD_GET_NAMEVERSION\n");
			// only zeroes if unexpected cmdlen bytelen
			if (hdr.len == 1) {
				memcpy(rsp, app_name0, 4);
				memcpy(rsp + 4, app_name1, 4);
				memcpy(rsp + 8, &app_version, 4);
			}
			appreply(hdr, APP_CMD_GET_NAMEVERSION, rsp);
			break;

		default:
			puts("Received unknown command: ");
			puthex(cmd[0]);
			lf();
			appreply(hdr, APP_RSP_UNKNOWN_CMD, rsp);
		}
	}
}
