/*******************************************************************************
*
*  (c) 2016 Ledger
*  (c) 2018 Nebulous
*  (c) 2019 Haim Bender
*
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include <stdint.h>
#include <stdbool.h>
#include <os_io_seproxyhal.h>
#include "glyphs.h"
#include "ux.h"


#include "ardor.h"
#include "returnValues.h"

ux_state_t ux;

// This is a forward declaration, since menu_about needs to reference
// menu_main.
static const ux_menu_entry_t menu_main[];

static const ux_menu_entry_t menu_about[] = {
	// I won't bother describing how menus work in detail, since it's fairly
	// self-evident and not very useful; but to save you some trouble, this
	// first element is defined with explicit fields, so you can see what they
	// all are.
	{
		.menu     = NULL,       // another menu entry, displayed when this item is "entered"
		.callback = NULL,       // a function that takes a userid, called when this item is entered
		.userid   = 0,          // a custom identifier, helpful for implementing custom menu behavior
		.icon     = NULL,       // the glyph displayed next to the item text
		.line1    = "Version",  // the first line of text
		.line2    = "1.0", // the second line of text; if NULL, line1 will be vertically centered
		.text_x   = 0,          // the x offset of the lines of text; only used if non-zero
		.icon_x   = 0,          // the x offset of the icon; only used if non-zero
	},
	// This element references a custom glyph, C_icon_back. This glyph is
	// defined in glyphs.c, which was generated by the Makefile from the
	// corresponding .gif file in the glyphs/ folder. If you drop your own
	// .gif files into this folder and run make, they will likewise become
	// available for use in your app. The SDK also defines a few built-in
	// icons, such as BAGL_GLYPH_ICON_CHECK, which you'll see in the screen
	// definitions later on.
	{menu_main, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
	UX_MENU_END,
};

static const ux_menu_entry_t menu_main[] = {
	{NULL, NULL, 0, NULL, "Waiting for", "commands...", 0, 0},
	{menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
	{NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
	UX_MENU_END,
};

// ui_idle displays the main menu. Note that your app isn't required to use a
// menu as its idle screen; you can define your own completely custom screen.
void ui_idle(void) {
	// The first argument is the starting index within menu_main, and the last
	// argument is a preprocessor; I've never seen an app that uses either
	// argument.
	UX_MENU_DISPLAY(0, menu_main, NULL);
}


// The APDU protocol uses a single-byte instruction code (INS) to specify
// which command should be executed. We'll use this code to dispatch on a
// table of function pointers.
#define INS_GET_VERSION    			0x01
#define INS_GET_PUBLIC_KEYS 		0x02
#define INS_AUTH_SIGN_TXN  			0x03
#define INS_ENCRYPT_DECRYPT_MSG		0x04
#define INS_SHOW_ADDRESS 			0x05

// This is the function signature for a command handler. 'flags' and 'tx' are
// out-parameters that will control the behavior of the next io_exchange call
typedef void handler_fn_t(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx);

handler_fn_t getVersionHandler;
handler_fn_t getPublicKeyHandler;
handler_fn_t authAndSignTxnHandler;
handler_fn_t encryptDecryptMessageHandler;
handler_fn_t showAddressHandler;

static handler_fn_t* lookupHandler(uint8_t ins) {
	switch (ins) {
	case INS_GET_VERSION:    		return getVersionHandler;
	case INS_GET_PUBLIC_KEYS: 		return getPublicKeyHandler;
	case INS_AUTH_SIGN_TXN:   		return authAndSignTxnHandler;
	case INS_ENCRYPT_DECRYPT_MSG:	return encryptDecryptMessageHandler;
	case INS_SHOW_ADDRESS:			return showAddressHandler;
	default:                 		return NULL;
	}
}

// These are the offsets of various parts of a request APDU packet. INS
// identifies the requested command (see above), and P1 and P2 are parameters
// to the command.
#define CLA          0xE0
#define OFFSET_CLA   0x00
#define OFFSET_INS   0x01
#define OFFSET_P1    0x02
#define OFFSET_P2    0x03
#define OFFSET_LC    0x04
#define OFFSET_CDATA 0x05

uint8_t lastCmdNumber = 0;
states_t state;

extern unsigned long _stack;
#define STACK_CANARY (*((volatile uint32_t*) &_stack))

void init_canary() { //todo, make a rand cannary here
	STACK_CANARY = 0xDEADBEEF;
}

bool check_canary() {
	return STACK_CANARY == 0xDEADBEEF;
}

void cleanSharedState() {
	os_memset(&state, 0, sizeof(state));
}

//todo: make sure the state is cleaned when getting a command that is irrelevant

// This is the main loop that reads and writes APDUs. It receives request
// APDUs from the computer, looks up the corresponding command handler, and
// calls it on the APDU payload. Then it loops around and calls io_exchange
// again. The handler may set the 'flags' and 'tx' variables, which affect the
// subsequent io_exchange call. The handler may also throw an exception, which
// will be caught, converted to an error code, appended to the response APDU,
// and sent in the next io_exchange call.
static void ardor_main(void) {

	init_canary();

	// Mark the transaction context as uninitialized.
    cleanState();


	volatile unsigned int rx = 0;
	volatile unsigned int tx = 0;
	volatile unsigned int flags = 0;

	// Exchange APDUs until EXCEPTION_IO_RESET is thrown.
	for (;;) {
		volatile unsigned short sw = 0;

		// The Ledger SDK implements a form of exception handling. In addition
		// to explicit THROWs in user code, syscalls (prefixed with os_ or
		// cx_) may also throw exceptions.
		//
		// This TRY block serves to catch any thrown exceptions
		// and convert them to response codes, which are then sent in APDUs.
		// However, EXCEPTION_IO_RESET will be re-thrown and caught by the
		// "true" main function defined at the bottom of this file.
		BEGIN_TRY {
			TRY {
				rx = tx;
				tx = 0; // ensure no race in CATCH_OTHER if io_exchange throws an error
				rx = io_exchange(CHANNEL_APDU | flags, rx);
	
				PRINTF("\n ttt %d", check_canary());


				PRINTF("\nasdasd");
				flags = 0;

				// No APDU received; trigger a reset.
				if (rx == 0) {
					THROW(EXCEPTION_IO_RESET);
				}
				// Malformed APDU.
				if (CLA != G_io_apdu_buffer[OFFSET_CLA]) {
					fillBufferWithAnswerAndEnding(R_BAD_CLA, tx);
					continue;
				}

				//this is a safty thing, so that one command can't fuck up some other command's state
				//and have some RCE vulnerability
				if (lastCmdNumber != G_io_apdu_buffer[OFFSET_INS]) {
					cleanSharedState();
					lastCmdNumber = G_io_apdu_buffer[OFFSET_INS];
				}

				// Lookup and call the requested command handler.
				handler_fn_t *handlerFn = lookupHandler(G_io_apdu_buffer[OFFSET_INS]);
				if (!handlerFn) {
					fillBufferWithAnswerAndEnding(R_UNKOWN_CMD, tx);
					continue;
				}
				handlerFn(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2],
				          G_io_apdu_buffer + OFFSET_CDATA, G_io_apdu_buffer[OFFSET_LC], &flags, &tx);
			}
			CATCH(EXCEPTION_IO_RESET) {
				THROW(EXCEPTION_IO_RESET);
			}
			CATCH_OTHER(e) {

				//just to make sure there is no hacking going on
				//reset all the states
			    cleanSharedState();
				
				tx = 0;
				flags = 0;

				G_io_apdu_buffer[tx++] = R_EXCEPTION;
				G_io_apdu_buffer[tx++] = e >> 8;
				fillBufferWithAnswerAndEnding(e & 0xFF, tx);
			}
			FINALLY {
			}
		}
		END_TRY;
	}
}


// Everything below this point is Ledger magic. And the magic isn't well-
// documented, so if you want to understand it, you'll need to read the
// source, which you can find in the nanos-secure-sdk repo. Fortunately, you
// don't need to understand any of this in order to write an app.
//
// Next, we'll look at how the various commands are implemented. We'll start
// with the sizeofmplest command, signHash.c.

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
	io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

unsigned char io_event(unsigned char channel) {
	// can't have more than one tag in the reply, not supported yet.
	switch (G_io_seproxyhal_spi_buffer[0]) {
	case SEPROXYHAL_TAG_FINGER_EVENT:
		UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
		break;

	case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
		UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
		break;

	case SEPROXYHAL_TAG_STATUS_EVENT:
		if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
			!(U4BE(G_io_seproxyhal_spi_buffer, 3) &
			  SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
			THROW(EXCEPTION_IO_RESET);
		}
		UX_DEFAULT_EVENT();
		break;

	case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
		UX_DISPLAYED_EVENT({});
		break;

	case SEPROXYHAL_TAG_TICKER_EVENT:
		UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {});
		break;

	default:
		UX_DEFAULT_EVENT();
		break;
	}

	// close the event if not done previously (by a display or whatever)
	if (!io_seproxyhal_spi_is_status_sent()) {
		io_seproxyhal_general_status();
	}

	// command has been processed, DO NOT reset the current APDU transport
	return 1;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
	switch (channel & ~(IO_FLAGS)) {
	case CHANNEL_KEYBOARD:
		break;
	// multiplexed io exchange over a SPI channel and TLV encapsulated protocol
	case CHANNEL_SPI:
		if (tx_len) {
			io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);
			if (channel & IO_RESET_AFTER_REPLIED) {
				reset();
			}
			return 0; // nothing received from the master so far (it's a tx transaction)
		} else {
			return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
		}
	default:
		THROW(INVALID_PARAMETER);
	}
	return 0;
}

static void app_exit(void) {
	BEGIN_TRY_L(exit) {
		TRY_L(exit) {
			os_sched_exit(-1);
		}
		FINALLY_L(exit) {
		}
	}
	END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
	// exit critical section
	__asm volatile("cpsie i");

	for (;;) {
		UX_INIT();
		os_boot();
		BEGIN_TRY {
			TRY {
				io_seproxyhal_init();
				USB_power(0);
				USB_power(1);
				ui_idle();
				ardor_main();
			}
			CATCH(EXCEPTION_IO_RESET) {
				// reset IO and UX before continuing
				continue;
			}
			CATCH_ALL {
				break;
			}
			FINALLY {
			}
		}
		END_TRY;
	}
	app_exit();
	return 0;
}
