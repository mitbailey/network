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

#define NETWORK_FRAME_MAX_PAYLOAD_SIZE 0x64
#define NETWORK_FRAME_GUID 0x1A1C
#define NETWORK_FRAME_MAX_PAYLOAD_SIZE 0x64
#define SERVER_IP "172.20.184.170" // hostname -I
#define SERVER_PORT 54210

enum NETWORK_FRAME_TYPE
{
    CS_TYPE_ERROR = -1,       // Something is wrong.
    CS_TYPE_NULL = 0,         // Blank, used for holding open the socket and retrieving status data.
    CS_TYPE_ACK = 1,          // Good acknowledgement.
    CS_TYPE_NACK = 2,         // Bad acknowledgement.
    CS_TYPE_CONFIG_UHF = 3,   // Configure UHF radio.
    CS_TYPE_CONFIG_XBAND = 4, // Configure X-Band radio.
    CS_TYPE_DATA = 5,         // Most communications will be _DATA.
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
    int socket;
    struct sockaddr_in serv_ip[1];
    bool connection_ready;
    char discon_reason[64];

    // Booleans
    bool rx_active; // Only able to receive when this is true.   
} network_data_t;

void network_data_init(network_data_t *network_data);

class NetworkFrame
{
public:
    /**
     * @brief Sets the payload_size, type, GUID, and termination values.
     * 
     * @param payload_size The desired payload size.
     * @param type The type of data this frame will carry (see: NETWORK_FRAME_TYPE).
     */
    NetworkFrame(NETWORK_FRAME_TYPE type, int payload_size);

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
    int storePayload(NETWORK_FRAME_ENDPOINT endpoint, void *data, int size);

    /**
     * @brief Copies payload to the passed space in memory.
     * 
     * @param data_space Pointer to memory into which the payload is copied.
     * @param size The size of the memory space being passed.
     * @return int Positive on success, negative on failure.
     */
    int retrievePayload(unsigned char *data_space, int size);

    int getPayloadSize() { return payload_size; };

    NETWORK_FRAME_TYPE getType() { return type; };

    NETWORK_FRAME_ENDPOINT getEndpoint() { return endpoint; };

    uint8_t getNetstat() { return netstat; };

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

private:
    uint16_t guid;                                         // 0x1A1C
    NETWORK_FRAME_ENDPOINT endpoint;                       // Where is this going?
    NETWORK_FRAME_MODE mode;                               // RX or TX
    int payload_size;                                      // Variably sized payload, this value tracks the size.
    NETWORK_FRAME_TYPE type;                               // NULL, ACK, NACK, CONFIG, DATA, STATUS
    uint16_t crc1;                                         // CRC16 of payload.
    unsigned char payload[NETWORK_FRAME_MAX_PAYLOAD_SIZE]; // Constant sized payload.
    uint16_t crc2;
    uint8_t netstat;      // Network Status Information - Read by the client, set by the server: Bitmask - 0:Client, 1:RoofUHF, 2: RoofXB, 3: Haystack
    uint16_t termination; // 0xAAAA
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
 * @param global_data 
 * @return int 
 */
int gs_connect_to_server(global_data_t *global_data);

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

#endif // NETWORK_HPP