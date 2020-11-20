/*******************************************************************************
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


#include <string.h>
#include <stdbool.h>

#include <os_io_seproxyhal.h>

#include <cx.h>
#include <os.h>
#include "ux.h"

#include "glyphs.h"
#include "returnValues.h"
#include "config.h"
#include "ardor.h"


#define P1_INIT 1
#define P1_CONTINUE 2
#define P1_SIGN 3


// This is the code that parses the txn for signing, it parses streamed txn bytes into the state object while hashing the bytes to be signed later,
// displays a dialog of screens which contain the parsed txn bytes from the state, 
// It solves 2 no trivial problems
// 1 - Allowing txn bytes to be parsed from a stream of bytes (this is very hard, since we don't have a lot memory, so we need to parse bytes and forget about them)
// 2 - txn's very in length depending on type, so the same bytes are sometimes not parsed into the same place, so it has to be dynamic about parsing
//
//
// The way these problems are solved is by the following flow:
//
// The function stack is initiated with an index reference to parseMainTxnData
// 
//
// authAndSignTxnHandlerHelper is called with some of the txn bytes
// => addToReadBuffer is called adds these bytes to the read buffer
// => parseFromStack is called, which calls the first parse function on the stack which is parseMainTxnData
// => parseMainTxnData trys to pull 142 bytes from the buffer
//      if there is are 142 bytes there:
//          parseMainTxnData parses the main txn bytes and then adds more functions to parse stack depending on the appendages
//      else
//          R_SEND_MORE_BYTES is trickled down by the function to be sent to back to the client
//      
// and so on the process goes until the stack of functions is empty and there are no more bytes in the read buffer
// if the parsing goes well without errors => setScreenTexts(); is called which sets up the labels and first screen of the autherization dialog
// => showScreen(); make the first screen apeare setting and sets ui_auth_button() to be the button callback for the dialog =>
// pressing on the right does state.txnAuth.dialogScreenIndex++; if it reaches the end number then the txn is autherized for signing and state.txnAuth.txnPassedAutherization is set to true
// pressing left does state.txnAuth.dialogScreenIndex--; and if it gets to a negative number it will be interpretate as a txn rejection => initTxnAuthState() 
// will be called and R_REJECT will be returned to client


//  API:
//
//
//      The mode is encoded in the first 2 bits of the p1 parameter and the size of the txn should be ((p1 & 0b11111100) << 6) + p2
//      you only need to pass the size when calling P1_INIT
//
//      P1: P1_INIT:
//      dataBuffer: txn bytes //you can send all of your bytes here if you want
//      returns:    1 byte status
//
//      P1: P1_CONTINUE:    more txn bytes
//      returns:    1 byte status
//
//      P1: P1_SIGN:
//      dataBuffer: derivaiton path (uint32) * some length
//      returns:    1 bytes status | 64 byte signiture


//This function cleans the txnAuth part of the state, its important to call it before starting to load a txn
//also whenever there is an error you should call it so that no one can exploit an error state for some sort of attack,
//the cleaner the state is, the better, allways clean when you can
void initTxnAuthState() {

    state.txnAuth.txnSizeBytes = 0;
    state.txnAuth.numBytesRead = 0;

    os_memset(state.txnAuth.functionStack, 0, sizeof(state.txnAuth.functionStack));
    state.txnAuth.functionStack[0] = 1; //Add the first parse function on the stack
    state.txnAuth.functionStack[1] = 2; //The appendages parse function
    state.txnAuth.numFunctionsOnStack = 2;

    state.txnAuth.txnPassedAutherization = false;
    state.txnAuth.isClean = true;
    
    cx_sha256_init(&state.txnAuth.hashstate);

    os_memset(state.txnAuth.readBuffer, 0, sizeof(state.txnAuth.readBuffer));
    state.txnAuth.readBufferReadOffset = 0;
    state.txnAuth.readBufferEndPos = 0;

    state.txnAuth.chainId = 0;
    state.txnAuth.txnTypeAndSubType = 0;
    state.txnAuth.txnTypeIndex = 0;
    state.txnAuth.recipientId = 0;
    state.txnAuth.amount = 0;

    state.txnAuth.attachmentTempInt32Num1 = 0;
    state.txnAuth.attachmentTempInt32Num2 = 0;
    state.txnAuth.attachmentTempInt64Num1 = 0;
    state.txnAuth.attachmentTempInt64Num2 = 0;
    state.txnAuth.attachmentTempInt64Num3 = 0;

    os_memset(state.txnAuth.feeText, 0, sizeof(state.txnAuth.feeText));    
    os_memset(state.txnAuth.chainAndTxnTypeText, 0, sizeof(state.txnAuth.chainAndTxnTypeText));    
    os_memset(state.txnAuth.optionalWindow1Text, 0, sizeof(state.txnAuth.optionalWindow1Text));    
    os_memset(state.txnAuth.optionalWindow2Title, 0, sizeof(state.txnAuth.optionalWindow2Title));    
    os_memset(state.txnAuth.optionalWindow2Text, 0, sizeof(state.txnAuth.optionalWindow2Text));
    os_memset(state.txnAuth.appendagesText, 0, sizeof(state.txnAuth.appendagesText));

    state.txnAuth.uiFlowBitfeild = 0;
}


//Does what it says
txnType * txnTypeAtIndex(const uint8_t index) {
    //Because static memory is weird and might be reclocated in ledger we have to use the PIC macro in order to access it
    return (txnType*)PIC(&TXN_TYPES[index]);
}

//does what it says
char * txnTypeNameAtIndex(const uint8_t index) {
    //Because static memory is weird and might be reclocated in ledger we have to use the PIC macro in order to access it
    return (char*)PIC(((txnType*)PIC(&TXN_TYPES[index]))->name);
}

//does what is says
char * chainName(const uint8_t chainId) {
    //Because static memory is weird and might be reclocated in ledger we have to use the PIC macro in order to access it
    return (char*)PIC(((chainType*)PIC(&CHAINS[chainId - 1]))->name);
}

//the amount of digits on the right of the decimal dot for each chain
uint8_t chainNumDecimalsBeforePoint(const uint8_t chainId) {
    //Because static memory is weird and might be reclocated in ledger we have to use the PIC macro in order to access it
    return ((chainType*)PIC(&CHAINS[chainId - 1]))->numDecimalsBeforePoint;
}


//this function formats amounts into string and most importantly add the dot where it's supposed to be
//the way this is works is that amounts ints and then the dot is added after chainNumDecimalsBeforePoint() digits from right to left
//for example, if the amount is 4200000000 and we are in the Ardor chain in which chainNumDecimalsBeforePoint() is 8 then the formated amount will be "42"
//for 4210100000 it will be 42.101

//@param outputString - does what it says
//@param maxOutputLength - does what it says
//@param numberToFormat - the input number to format, isn't const cuz we play with it in order to format the number
//@param numDigitsBeforeDecimal - read first paragraph for info
//@returns 0 iff some kind of error happend, else the length of the output string including the null terminator
uint8_t formatAmount(char * const outputString, const uint16_t maxOutputLength, uint64_t numberToFormat, const uint8_t numDigitsBeforeDecimal) {
    
    uint16_t outputIndex = 0;
    bool wasANumberWritten = false;
    bool isDotWritten = false;
    uint8_t numberIndex = 0;


    while (42) {

        uint8_t modulo = numberToFormat % 10;
        numberToFormat -= modulo;
        numberToFormat /= 10;

        if (numDigitsBeforeDecimal == numberIndex) {
            if (wasANumberWritten && (!isDotWritten) && (0 != numDigitsBeforeDecimal)) {
                isDotWritten = true;
                outputString[outputIndex++] = '.';
            }

            wasANumberWritten = true;
        }

        if (0 != modulo)
            wasANumberWritten = true;

        if (wasANumberWritten || (0 == numDigitsBeforeDecimal))
            outputString[outputIndex++] = '0' + modulo;

        if (outputIndex >= maxOutputLength)
            return 0;

        if ((0 == numberToFormat) && (numDigitsBeforeDecimal <= numberIndex))
            break;

        numberIndex++;

    }


    //reverse the string since we are creating it from left to right, and numbers are right to left
    for (uint16_t i = 0; i < outputIndex - 1 - i; i++) {
        uint8_t temp = outputString[i];
        outputString[i] = outputString[outputIndex - i - 1];
        outputString[outputIndex - i - 1] = temp;
    }

    outputString[outputIndex] = 0;
    return outputIndex + 1;
}

//defined in readSolomon.c
void reedSolomonEncode(const uint64_t inp, const char * output);

//Accept click callback
unsigned int txn_autherized(const bagl_element_t *e) {
    UNUSED(e);
    
    state.txnAuth.txnPassedAutherization = true;
    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = R_FINISHED;
    G_io_apdu_buffer[2] = 0x90;
    G_io_apdu_buffer[3] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 4);
    
    ui_idle();  // redraw ui
    return 0; // DO NOT REDRAW THE BUTTON
}

//Canceled click callback
unsigned int txn_canceled(const bagl_element_t *e) {  
    UNUSED(e);

    initTxnAuthState();

    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = R_REJECT;
    G_io_apdu_buffer[2] = 0x90;
    G_io_apdu_buffer[3] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 4);

    ui_idle(); // redraw ui
    return 0; // DO NOT REDRAW THE BUTTON
}

//Defenition of the UI for the handler
UX_STEP_NOCB(aasFlowPage1, 
    pnn, 
    {
      &C_icon_eye,
      "Authorize",
      "transaction",
    });
UX_STEP_NOCB(aasFlowPage2, 
    bnnn_paging, 
    {
      .title = "Chain&TxnType",
      .text = state.txnAuth.chainAndTxnTypeText,
    });

UX_STEP_NOCB(aasFlowOptional1,
    bnnn_paging, 
    {
      .title = "Amount",
      .text = state.txnAuth.optionalWindow1Text,
    });
UX_STEP_NOCB(aasFlowOptional2, 
    bnnn_paging, 
    {
      .title = state.txnAuth.optionalWindow2Title,
      .text = state.txnAuth.optionalWindow2Text,
    });
UX_STEP_NOCB(aasFlowAppendages, 
    bnnn_paging, 
    {
      .title = "Appendages",
      .text = state.txnAuth.appendagesText,
    });
UX_STEP_NOCB(aasFlowPage3, 
    bnnn_paging, 
    {
      .title = "Fees",
      .text = state.txnAuth.feeText,
    });
UX_STEP_VALID(aasFlowPage4, 
    pbb, 
    txn_autherized(NULL),
    {
      &C_icon_validate_14,
      "Accept",
      "and send",
    });
UX_STEP_VALID(aasFlowPage5, 
    pb, 
    txn_canceled(NULL),
    {
      &C_icon_crossmark,
      "Reject",
    });

UX_FLOW(ux_flow_00,
  &aasFlowPage1,
  &aasFlowPage2,
  &aasFlowPage3,
  &aasFlowPage4,
  &aasFlowPage5
);

UX_FLOW(ux_flow_01,
  &aasFlowPage1,
  &aasFlowPage2,
  &aasFlowAppendages,
  &aasFlowPage3,
  &aasFlowPage4,
  &aasFlowPage5
);

UX_FLOW(ux_flow_10,
  &aasFlowPage1,
  &aasFlowPage2,
  &aasFlowOptional1,
  &aasFlowOptional2,
  &aasFlowPage3,
  &aasFlowPage4,
  &aasFlowPage5
);

UX_FLOW(ux_flow_11,
  &aasFlowPage1,
  &aasFlowPage2,
  &aasFlowOptional1,
  &aasFlowOptional2,
  &aasFlowAppendages,
  &aasFlowPage3,
  &aasFlowPage4,
  &aasFlowPage5
);

//Just switches between based of the uiFlowBitfeild
static void showScreen() {
    
    if(0 == G_ux.stack_count)
        ux_stack_push();

    switch (state.txnAuth.uiFlowBitfeild) {

        case 0x00:
            ux_flow_init(0, ux_flow_00, NULL);
            break;
        case 0x01:
            ux_flow_init(0, ux_flow_01, NULL);
            break;
        case 0x02:
            ux_flow_init(0, ux_flow_10, NULL);
            break;
        case 0x03:
            ux_flow_init(0, ux_flow_11, NULL);
            break;
    }
}

//This function formats trxn data into text memebers of the state which the UI flow will read from
//Returns: Success iff everything is good, otherwise probably some kind of formating error
uint8_t setScreenTexts() {

    uint8_t ret = 0;

    if (LEN_TXN_TYPES > state.txnAuth.txnTypeIndex) {

        state.txnAuth.uiFlowBitfeild |= 2; //turn on the second bit

        switch (state.txnAuth.txnTypeAndSubType) {

            //note: you have to write the type and subtype in reverse, because of little endian buffer representation an big endian C code representation

            case 0x0000: //OrdinaryPayment
            case 0x00fe: //FxtPayment

                    if (0 == formatAmount(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text), state.txnAuth.amount, chainNumDecimalsBeforePoint(state.txnAuth.chainId)))
                        return R_FORMAT_AMOUNT_ERR;

                    snprintf(state.txnAuth.optionalWindow2Title, sizeof(state.txnAuth.optionalWindow2Title), "Recipient");
                    snprintf(state.txnAuth.optionalWindow2Text, sizeof(state.txnAuth.optionalWindow2Text), APP_PREFIX);
                    reedSolomonEncode(state.txnAuth.recipientId, state.txnAuth.optionalWindow2Text + strlen(state.txnAuth.optionalWindow2Text));

                    break;

            case 0x00fc: //FxtCoinExchangeOrderIssue
            case 0x000b: //CoinExchangeOrderIssue
                    
                    ret = formatAmount(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text), state.txnAuth.attachmentTempInt64Num1, chainNumDecimalsBeforePoint(state.txnAuth.attachmentTempInt32Num2));

                    if (0 == ret)
                        return R_FORMAT_AMOUNT_ERR;

                    //note: the existence of chainName(state.txnAuth.attachmentTempInt32Num2) was already checked in the parsing function
                    snprintf(state.txnAuth.optionalWindow1Text + ret - 1, sizeof(state.txnAuth.optionalWindow1Text) - ret - 1, " %s", chainName(state.txnAuth.attachmentTempInt32Num2));

                    //note: the existence of chainName(state.txnAuth.attachmentTempInt32Num2) was already checked in the parsing function
                    snprintf(state.txnAuth.optionalWindow2Title, sizeof(state.txnAuth.optionalWindow2Title), "Price per %s", chainName(state.txnAuth.attachmentTempInt32Num2));
                    ret = formatAmount(state.txnAuth.optionalWindow2Text, sizeof(state.txnAuth.optionalWindow2Text), state.txnAuth.attachmentTempInt64Num2, chainNumDecimalsBeforePoint(state.txnAuth.attachmentTempInt32Num1));

                    if (0 == ret)
                        return R_FORMAT_AMOUNT_ERR;

                    //note: the existence of chainName(state.txnAuth.attachmentTempInt32Num1) was already checked in the parsing function
                    snprintf(state.txnAuth.optionalWindow2Text + ret - 1, sizeof(state.txnAuth.optionalWindow2Text) - ret - 1, " %s", chainName(state.txnAuth.attachmentTempInt32Num1));

            break;
            default:
                state.txnAuth.uiFlowBitfeild &= (0xff - 2); //since we don't fall under a txn type that needs 2 extra windows, turn off the second bit
        }
    }

    return R_SUCCESS;
}

//Does what is says
uint8_t addToFunctionStack(const uint8_t functionNum) {
    if (sizeof(state.txnAuth.functionStack) == state.txnAuth.numFunctionsOnStack)
        return R_FUNCTION_STACK_FULL;

    state.txnAuth.functionStack[state.txnAuth.numFunctionsOnStack++] = functionNum;

    return R_SUCCESS;
}

//Takes bytes away from the buffer, returns 0 if there aren't enough bytes
uint8_t * readFromBuffer(const uint8_t size) {

    if (state.txnAuth.readBufferEndPos - state.txnAuth.readBufferReadOffset < size)
        return 0;

    uint8_t * ret = state.txnAuth.readBuffer + state.txnAuth.readBufferReadOffset;
    state.txnAuth.readBufferReadOffset += size;
    state.txnAuth.numBytesRead += size;

    return ret;
}

//This is the main parse function, it parses the main txn body and adds more function to the parse stack if needed
uint8_t parseMainTxnData() {
    
    uint8_t * ptr = readFromBuffer(145);

    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    os_memmove(&(state.txnAuth.chainId), ptr, sizeof(state.txnAuth.chainId));

    ptr += sizeof(state.txnAuth.chainId);

    if ((0 == state.txnAuth.chainId) || (NUM_CHAINS < state.txnAuth.chainId)) //note: we do +1 here because ardor start with index 1
        return R_BAD_CHAIN_ID_ERR;


    os_memmove(&(state.txnAuth.txnTypeAndSubType), ptr, sizeof(state.txnAuth.txnTypeAndSubType));

    ptr += sizeof(state.txnAuth.txnTypeAndSubType);

    txnType * currentTxnType = 0;

    for (state.txnAuth.txnTypeIndex = 0; state.txnAuth.txnTypeIndex < LEN_TXN_TYPES; state.txnAuth.txnTypeIndex++) {

        currentTxnType = txnTypeAtIndex(state.txnAuth.txnTypeIndex);

        if (currentTxnType->id == state.txnAuth.txnTypeAndSubType)
            break;
    }

    if (LEN_TXN_TYPES > state.txnAuth.txnTypeIndex) //goto check if the index in range before accessing the array
        if (0 != currentTxnType->attachmentParsingFunctionNumber)
            addToFunctionStack(currentTxnType->attachmentParsingFunctionNumber);

    if (LEN_TXN_TYPES > state.txnAuth.txnTypeIndex) {
        snprintf(state.txnAuth.chainAndTxnTypeText, sizeof(state.txnAuth.chainAndTxnTypeText), "%s %s", chainName(state.txnAuth.chainId), txnTypeNameAtIndex(state.txnAuth.txnTypeIndex));
    } else {
        snprintf(state.txnAuth.chainAndTxnTypeText, sizeof(state.txnAuth.chainAndTxnTypeText), "%s UnknownTxnType", chainName(state.txnAuth.chainId));
    }

    if (SUPPORTED_TXN_VERSION != *((uint8_t*)ptr))
        return R_WRONG_VERSION_ERR;

    ptr += sizeof(uint8_t);

    ptr += 4;   // Skip the timestamp
    ptr += 2;   // Skip the deadline
    ptr += 32;  // Skip the sender publickey

    os_memmove(&(state.txnAuth.recipientId), ptr, sizeof(state.txnAuth.recipientId));
    ptr += sizeof(state.txnAuth.recipientId);

    os_memmove(&(state.txnAuth.amount), ptr, sizeof(state.txnAuth.amount));
    ptr += sizeof(state.txnAuth.amount);

    uint64_t fee = 0;
    os_memmove(&fee, ptr, sizeof(fee));

    uint8_t ret = formatAmount(state.txnAuth.feeText, sizeof(state.txnAuth.feeText), fee, chainNumDecimalsBeforePoint(state.txnAuth.chainId));

    if (0 == ret)
        return R_FORMAT_FEE_ERR;

    snprintf(state.txnAuth.feeText + ret - 1, sizeof(state.txnAuth.feeText) - ret - 1, " %s", chainName(state.txnAuth.chainId));

    ptr += sizeof(uint64_t);

    ptr += 64;  //Skip the sig
    ptr += 4;   //Skip the block height
    ptr += 8;   //Skip the block Id

    addToFunctionStack(6);

    return R_SUCCESS;
}

//Parses a txn reference, by just skiping over the bytes :)
uint8_t parseReferencedTxn() {

    if (0 == readFromBuffer(sizeof(uint32_t) + 32))
        return R_SEND_MORE_BYTES;

    return R_SUCCESS;
}

//Does what it says, it's added to function stack on init
uint8_t parseAppendagesFlags() {
    
    uint8_t * ptr = readFromBuffer(sizeof(uint32_t));
    
    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    uint32_t appendages = 0;

    os_memmove(&appendages, ptr, sizeof(appendages));

    if (0 != appendages) {
        state.txnAuth.uiFlowBitfeild |= 1; //turn on the first bit
        snprintf(state.txnAuth.appendagesText, sizeof(state.txnAuth.appendagesText), "0x%08X", appendages);
    }

    return R_SUCCESS;
}

//Parses all the bytes until the endof the txn, since we don't parse the specifics of all the types, sometimes this is needed
uint8_t parseIngoreBytesUntilTheEnd() {
    while (state.txnAuth.numBytesRead != state.txnAuth.txnSizeBytes) {
        if (0 == readFromBuffer(1))
            return R_SEND_MORE_BYTES;
    }

    return R_SUCCESS;
}

//Parses a specific type of attachment
uint8_t parseFxtCoinExchangeOrderIssueOrCoinExchangeOrderIssueAttachment() {
    
    state.txnAuth.attachmentTempInt32Num1 = 0; //chaidId
    state.txnAuth.attachmentTempInt32Num2 = 0; //exchangeChain
    state.txnAuth.attachmentTempInt64Num1 = 0; //quantity
    state.txnAuth.attachmentTempInt64Num2 = 0; //price

    uint8_t * ptr = readFromBuffer(sizeof(uint8_t) + sizeof(state.txnAuth.attachmentTempInt32Num1) * 2 + sizeof(state.txnAuth.attachmentTempInt64Num1) * 2);
    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    if (1 != *ptr)
        return R_UNSUPPORTED_ATTACHMENT_VERSION;

    ptr += 1;

    os_memmove(&state.txnAuth.attachmentTempInt32Num1, ptr, sizeof(state.txnAuth.attachmentTempInt32Num1));
    ptr += sizeof(state.txnAuth.attachmentTempInt32Num1);

    if (NUM_CHAINS < state.txnAuth.attachmentTempInt32Num1)
        return R_BAD_CHAIN_ID_ERR;

    os_memmove(&state.txnAuth.attachmentTempInt32Num2, ptr, sizeof(state.txnAuth.attachmentTempInt32Num2));
    ptr += sizeof(state.txnAuth.attachmentTempInt32Num2);

    if (NUM_CHAINS < state.txnAuth.attachmentTempInt32Num2)
        return R_BAD_CHAIN_ID_ERR;

    os_memmove(&state.txnAuth.attachmentTempInt64Num1, ptr, sizeof(state.txnAuth.attachmentTempInt64Num1));
    ptr += sizeof(state.txnAuth.attachmentTempInt64Num1);
    
    os_memmove(&state.txnAuth.attachmentTempInt64Num2, ptr, sizeof(state.txnAuth.attachmentTempInt64Num2));

    return R_SUCCESS;
}

//Parses a specific type of attachment
uint8_t parseAskOrderPlacementAttachment() {
    
    state.txnAuth.attachmentTempInt64Num1 = 0;
    state.txnAuth.attachmentTempInt64Num2 = 0;
    state.txnAuth.attachmentTempInt64Num3 = 0;

    uint8_t * ptr = readFromBuffer(sizeof(state.txnAuth.attachmentTempInt64Num1) * 3);
    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    os_memmove(&state.txnAuth.attachmentTempInt64Num1, ptr, sizeof(state.txnAuth.attachmentTempInt64Num1));
    ptr += sizeof(state.txnAuth.attachmentTempInt64Num1);

    os_memmove(&state.txnAuth.attachmentTempInt64Num2, ptr, sizeof(state.txnAuth.attachmentTempInt64Num2));
    ptr += sizeof(state.txnAuth.attachmentTempInt64Num2);

    os_memmove(&state.txnAuth.attachmentTempInt64Num3, ptr, sizeof(state.txnAuth.attachmentTempInt64Num3));

    return R_SUCCESS;
}

//Addes bytes to the read buffer
//@param newData: ptr to the data
//@param numBytes: number of bytes in the data
//return R_SUCCESS on success, R_NO_SPACE_BUFFER_TOO_SMALL othereize
uint8_t addToReadBuffer(const uint8_t * const newData, const uint8_t numBytes) {

    for (uint8_t i = 0; i < state.txnAuth.readBufferEndPos - state.txnAuth.readBufferReadOffset; i++)
        state.txnAuth.readBuffer[i] = state.txnAuth.readBuffer[i + state.txnAuth.readBufferReadOffset];

    os_memset(state.txnAuth.readBuffer + state.txnAuth.readBufferEndPos - state.txnAuth.readBufferReadOffset, 0, state.txnAuth.readBufferReadOffset); //set to 0, just for saftey

    state.txnAuth.readBufferEndPos -= state.txnAuth.readBufferReadOffset;
    state.txnAuth.readBufferReadOffset = 0;

    if (state.txnAuth.readBufferEndPos + numBytes > sizeof(state.txnAuth.readBuffer))
        return R_NO_SPACE_BUFFER_TOO_SMALL;

    cx_hash(&state.txnAuth.hashstate.header, 0, newData, numBytes, 0, 0);

    os_memcpy(state.txnAuth.readBuffer + state.txnAuth.readBufferEndPos, newData, numBytes);
    state.txnAuth.readBufferEndPos += numBytes;

    return R_SUCCESS;
}

//Since we can't store function pointers in the functionstack, we store number and then call the following function
//to make a call to the corresponding function
uint8_t callFunctionNumber(const uint8_t functionNum) {

    switch (functionNum) {
        case 1:
            return parseMainTxnData();
        case 2:
            return parseAppendagesFlags();
        case 3:
            return parseReferencedTxn();
        case 4:
            return parseFxtCoinExchangeOrderIssueOrCoinExchangeOrderIssueAttachment();
        case 5:
            return parseAskOrderPlacementAttachment();
        case 6:
            return parseIngoreBytesUntilTheEnd();
    }

    return R_PARSE_FUNCTION_NOT_FOUND;
}

//This function manages the parsing of the readBuffer with functionStack functions
//If there aren't enough bytes in the read buffer it returns R_SEND_MORE_BYTES
//which will be sent back to the user
uint8_t parseFromStack() {
    
    while (true) {

        if (0 == state.txnAuth.numFunctionsOnStack) {

            if (state.txnAuth.readBufferEndPos != state.txnAuth.readBufferReadOffset)
                return R_NOT_ALL_BYTES_READ;

            uint8_t ret = setScreenTexts();

            if (R_SUCCESS != ret)
                return ret;

            showScreen();

            return R_SHOW_DISPLAY;
        }

        uint8_t ret = callFunctionNumber(state.txnAuth.functionStack[0]);

        if (R_SEND_MORE_BYTES == ret)
            return ret;

        uint8_t tempBuffer[FUNCTION_STACK_SIZE - 1];
        os_memmove(tempBuffer, state.txnAuth.functionStack + 1, sizeof(tempBuffer));
        os_memmove(state.txnAuth.functionStack, tempBuffer, sizeof(tempBuffer));
        state.txnAuth.functionStack[sizeof(state.txnAuth.functionStack) - 1] = 0;
        state.txnAuth.numFunctionsOnStack--;

        if (R_SUCCESS == ret)
            continue;

        return ret;
    }
}


//This is the function used to sign the hash of the txn
//@param txnSha256 -                     ptr to 32 byte sha256 of the txn
//@param derivationPath -                ptr to the derivation path buffer
//@param derivationPathLengthInUints32 - length of the derivation path buffer
//@param destBuffer -                    ptr to 64 bytes of memory of where to write the buffer
//@param outException out -              ptr to where to write the exception if it happends
//@returns R_SUCCESS iff success else the appropriate error code is returned

uint8_t signTxn(const uint8_t * const derivationPath, const uint8_t derivationPathLengthInUints32, 
                 uint8_t * const destBuffer, uint16_t * const outException) {

    uint8_t keySeed[32]; os_memset(keySeed, 0, sizeof(keySeed));
    uint8_t ret = 0;

    if (R_SUCCESS != (ret = ardorKeys(derivationPath, derivationPathLengthInUints32, keySeed, 0, 0, 0, outException))) {
        os_memset(keySeed, 0, sizeof(keySeed));
        return ret;
    }

    uint8_t finalTxnSha256[32];
    cx_hash(&state.txnAuth.hashstate.header, CX_LAST, 0, 0, finalTxnSha256, sizeof(finalTxnSha256));

    //sign msg should only use the first 32 bytes of keyseed
    signMsg(keySeed, finalTxnSha256, destBuffer); //is a void function, no ret value to check against
    
    os_memset(finalTxnSha256, 0, sizeof(finalTxnSha256)); //for security
    os_memset(keySeed, 0, sizeof(keySeed));

    return R_SUCCESS;
}

//This is the main command handler, it checks that params are in the right size,
//and manages calls to initTxnAuthState(), signTxn(), addToReadBuffer(), parseFromStack()

//Since this is a callback function, and this handler manages state, it's this function's reposibility to call initTxnAuthState
//Every time we get some sort of an error
void authAndSignTxnHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    if (dataLength < 1) {
        initTxnAuthState();
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;    
        return;
    }


    if (P1_SIGN == (p1 & 0x03)) {

        if (isLastCommandDifferent) {
            initTxnAuthState();
            G_io_apdu_buffer[(*tx)++] = R_TXN_UNAUTHORIZED;
            return;
        }

        uint8_t derivationParamLengthInBytes = dataLength;
    
        if ((MIN_DERIVATION_LENGTH * sizeof(uint32_t) > dataLength) || (MAX_DERIVATION_LENGTH * sizeof(uint32_t) < dataLength) || (0 != derivationParamLengthInBytes % sizeof(uint32_t))) {
            initTxnAuthState();
            G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
            return; 
        }

        if (!state.txnAuth.txnPassedAutherization) {
            initTxnAuthState();
            G_io_apdu_buffer[(*tx)++] = R_TXN_UNAUTHORIZED;
            return;
        }

        uint16_t exception = 0;

        G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

        uint8_t ret = signTxn(dataBuffer, derivationParamLengthInBytes / 4, G_io_apdu_buffer + 1, &exception);

        initTxnAuthState();

        if (R_SUCCESS == ret) {
            *tx += 64;
        } else {
            *tx -= 1;
            G_io_apdu_buffer[(*tx)++] = ret;

            if (R_KEY_DERIVATION_EX == ret) {
                G_io_apdu_buffer[(*tx)++] = exception >> 8;
                G_io_apdu_buffer[(*tx)++] = exception & 0xFF;   
            }
        }
    } else if ((P1_INIT == (p1 & 0x03)) || (P1_CONTINUE == (p1 & 0x03))) {

        if (P1_INIT != (p1 & 0x03)) {

            if (isLastCommandDifferent) {
                initTxnAuthState();
                G_io_apdu_buffer[(*tx)++] = R_ERR_NO_INIT_CANT_CONTINUE;
                return;
            }

            if (state.txnAuth.txnPassedAutherization) {
                initTxnAuthState();
                G_io_apdu_buffer[(*tx)++] = R_NOT_ALL_BYTES_USED;
                return;
            }

            if (state.txnAuth.isClean) {
                initTxnAuthState();
                G_io_apdu_buffer[(*tx)++] = R_ERR_NO_INIT_CANT_CONTINUE;
                return;
            }
        } else {
            initTxnAuthState();

            state.txnAuth.txnSizeBytes = ((p1 & 0b11111100) << 6) + p2;

            if (145 > state.txnAuth.txnSizeBytes) {
                G_io_apdu_buffer[(*tx)++] = R_TXN_SIZE_TOO_SMALL;
                return;
            }
        }

        state.txnAuth.isClean = false;

        uint8_t ret = addToReadBuffer(dataBuffer, dataLength);

        if (R_SUCCESS != ret) {
            G_io_apdu_buffer[(*tx)++] = ret;
            return;
        }

        ret = parseFromStack();

        if (!((R_SEND_MORE_BYTES == ret) || (R_FINISHED == ret) || (R_SHOW_DISPLAY == ret)))
            initTxnAuthState();

        if (R_SHOW_DISPLAY == ret) {
            *flags |= IO_ASYNCH_REPLY;
        } else {
            G_io_apdu_buffer[(*tx)++] = R_SUCCESS;
            G_io_apdu_buffer[(*tx)++] = ret;
        }
    } else {
        G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
    }
}

void authAndSignTxnHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    authAndSignTxnHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx, isLastCommandDifferent);

    if (0 == ((*flags) & IO_ASYNCH_REPLY)) {
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}
