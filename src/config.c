

//This file holds most of the CONSTANTS used in the APP
//TXN_TYPES is configured in txnTypesList.c, it's there cuz the list is auto-generated from some other java file in order to sync between projects

#include <stdint.h>
#include <stdbool.h>

#include "config.h"


//This configures the supported chain types, chainId, name and amount of decimals to the right of the point
const chainType CHAINS[] = {{0x00000001, "Ardor", 8}, {0x00000002, "Ignis", 8}, {0x00000003, "AEUR", 4}, {0x00000004, "BITS", 8}, {0x00000005, "MPG", 8}};
const uint8_t NUM_CHAINS = sizeof(CHAINS) / sizeof(CHAINS[0]);

const uint8_t SUPPORTED_TXN_VERSION = 1;

const uint8_t ARDOR_SPECIAL_IDENTIFIER[] = {0xba, 0xbe, 0x00};
const uint8_t ARDOR_SPECIAL_IDENTIFIER_LEN = sizeof(ARDOR_SPECIAL_IDENTIFIER);

const uint8_t VERSION_FLAGS = 0x00;
