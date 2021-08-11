/**
 * @file network.hpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version See Git tags for version information.
 * @date 2021.07.30
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <arpa/inet.h>

#define SERVER_POLL_RATE 5
#define RECV_TIMEOUT 15
#define NETWORK_FRAME_GUID 0x1A1C
#define NETWORK_FRAME_MAX_PAYLOAD_SIZE 0x100
#define SERVER_IP "129.63.134.29" // hostname -I

enum NETWORK_FRAME_TYPE
{
    CS_TYPE_ERROR = -1,       // Something is wrong.
    CS_TYPE_NULL = 0,         // Blank, used for holding open the socket and retrieving status data.
    CS_TYPE_ACK = 1,          // Good acknowledgement.
    CS_TYPE_NACK = 2,         // Bad acknowledgement.
    CS_TYPE_CONFIG_UHF = 3,   // Configure UHF radio.
    CS_TYPE_CONFIG_XBAND = 4, // Configure X-Band radio.
    CS_TYPE_DATA = 5,         // Most communications will be _DATA.
    CS_TYPE_POLL_XBAND_CONFIG = 6,  // Asks radio for its config.
    CS_TYPE_XBAND_COMMAND = 7,
};

enum NETWORK_FRAME_ENDPOINT
{
    CS_ENDPOINT_ERROR = -1,
    CS_ENDPOINT_CLIENT = 0,
    CS_ENDPOINT_ROOFUHF,
    CS_ENDPOINT_ROOFXBAND,
    CS_ENDPOINT_HAYSTACK,
    CS_ENDPOINT_SERVER
};

enum NETWORK_FRAME_MODE
{
    CS_MODE_ERROR = -1,
    CS_MODE_RX = 0,
    CS_MODE_TX = 1
};

typedef struct
{
    // Network
    int server_poll_rate;
    int socket;
    struct sockaddr_in serv_ip[1];
    bool connection_ready;
    char discon_reason[64];

    // Booleans
    bool rx_active; // Only able to receive when this is true.  

    int thread_status;
} network_data_t;

void network_data_init(network_data_t *network_data, int server_port);

class NetworkFrame
{
public:
    enum class NetType
    {
        UNDEF,
        POLL, // Used to be 'null' type.
        ACK,
        NACK,
        DATA
    };

    enum class NetVertex
    {
        UNDEF,
        CLIENT,
        SERVER,
        ROOFUHF,
        ROOFXBAND,
        HAYSTACK,
        SERVOS
    };

    /** CONSTRUCTOR
     * @brief Construct a new Network Frame object
     * 
     * @param payload 
     * @param size 
     * @param type 
     * @param dest 
     */
    NetworkFrame(unsigned char *payload, ssize_t size, NetType type, NetVertex dest);

    /** COPY CONSTRUCTOR
     * @brief Copy a NetworkFrame object.
     * 
     * @param obj 
     */
    NetworkFrame(const NetworkFrame &obj);

    /** DESTRUCTOR
     * @brief Destroy the NetworkFrame object.
     * 
     */
    ~NetworkFrame();

    /**
     * @brief Copies data to the payload.
     * 
     * Returns and error if the passed data size does not equal the internal payload_size variable set during class construction.
     * 
     * Sets the CRC16s.
     * 
     * @param endpoint The final destination for the payload (see: NETWORK_FRAME_ENDPOINT).
     * @param data Data to be copied into the payload.
     * @param size Size of the data to be copied.
     * @return int Positive on success, negative on failure.
     */
    // int storePayload(NETWORK_FRAME_ENDPOINT endpoint, void *data, int size);

    /**
     * @brief Copies payload to the passed space in memory.
     * 
     * @param data_space Pointer to memory into which the payload is copied.
     * @param size The size of the memory space being passed.
     * @return int Positive on success, negative on failure.
     */
    int retrievePayload(unsigned char *storage, ssize_t capacity);

    /**
     * @brief Checks the validity of itself.
     * 
     * @return int Positive if valid, negative if invalid.
     */
    int checkIntegrity();

    /**
     * @brief Prints the class' data.
     * 
     */
    void print();

    /**
     * @brief Sends itself using the network data passed to it.
     * 
     * @return ssize_t Number of bytes sent if successful, negative on failure. 
     */
    ssize_t sendFrame(network_data_t *network_data);

    // These exist because 'setting' is managed.
    NetType getType(){return type;};
    NetVertex getOrigin(){return origin;};
    NetVertex getDestination(){return destination;};
    int getPayloadSize(){return payload_size;};
    uint8_t getNetstat(){return netstat;};

private:
    uint32_t guid;                                         // 0x1A1C1A1C

    NetType type;
    NetVertex origin;
    NetVertex destination;

    int payload_size;
    // int payload_capacity? probably not needed - would like to malloc different sizes of payload, but this still isnt needed
    uint16_t crc1;
    unsigned char payload[NETWORK_FRAME_MAX_PAYLOAD_SIZE];
    uint16_t crc2;

    uint8_t netstat;

    uint16_t termination;
};

/**
 * @brief Periodically polls the Ground Station Network Server for its status.
 * 
 * Doubles as the GS Network connection watch-dog, tries to restablish connection to the server if it sees that we are no longer connected.
 * 
 * @param args 
 * @return void* 
 */
void *gs_polling_thread(void *args);

/**
 * @brief Packs data into a NetworkFrame and sends it.
 * 
 * @param network_data 
 * @param type 
 * @param endpoint 
 * @param data 
 * @param data_size 
 * @return int 
 */
int gs_network_transmit(network_data_t *network_data, NETWORK_FRAME_TYPE type, NETWORK_FRAME_ENDPOINT endpoint, void *data, int data_size);

/**
 * @brief 
 * 
 * @param network_data 
 * @return int 
 */
int gs_connect_to_server(network_data_t *network_data);

/**
 * @brief 
 * 
 * From:
 * https://github.com/sunipkmukherjee/comic-mon/blob/master/guimain.cpp
 * with minor modifications.
 * 
 * @param socket 
 * @param address 
 * @param socket_size 
 * @param tout_s 
 * @return int 
 */
int gs_connect(int socket, const struct sockaddr *address, socklen_t socket_size, int tout_s);

/*
 * this is the CCITT CRC 16 polynomial X^16  + X^12  + X^5  + 1.
 * This works out to be 0x1021, but the way the algorithm works
 * lets us use 0x8408 (the reverse of the bit pattern).  The high
 * bit is always assumed to be set, thus we only use 16 bits to
 * represent the 17 bit value.
 */
static inline uint16_t internal_crc16(unsigned char *data_p, uint16_t length)
{
#define CRC16_POLY 0x8408
    unsigned char i;
    unsigned int data;
    unsigned int crc = 0xffff;

    if (length == 0)
        return (~crc);

    do
    {
        for (i = 0, data = (unsigned int)0xff & *data_p++;
             i < 8;
             i++, data >>= 1)
        {
            if ((crc & 0x0001) ^ (data & 0x0001))
                crc = (crc >> 1) ^ CRC16_POLY;
            else
                crc >>= 1;
        }
    } while (--length);

    crc = ~crc;
    data = crc;
    crc = (crc << 8) | (data >> 8 & 0xff);

    return (crc);
}

#endif // NETWORK_HPP
