


//This is the header for different types of consts and configurations, the actual values are set in config.c

typedef struct {
    uint32_t chainId;
    char * name;
    uint8_t numDecimalsBeforePoint;
} chainType;

extern const chainType CHAINS[];
extern const uint8_t NUM_CHAINS;
extern const uint8_t SUPPORTED_TXN_VERSION;

extern const uint8_t ARDOR_SPECIAL_IDENTIFIER[];
extern const uint8_t ARDOR_SPECIAL_IDENTIFIER_LEN;

extern const uint16_t VERSION;
extern const uint8_t VERSION_FLAGS;


//must make this a define instead of static const, because some array declirations are dependant on this size
#define MIN_DERIVATION_LENGTH 3
#define MAX_DERIVATION_LENGTH 20

#define FUNCTION_STACK_SIZE 30
#define IV_SIZE 16
