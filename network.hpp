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
#define NETWORK_FRAME_GUID 0x1A1C1A1C
#define NETWORK_FRAME_MAX_PAYLOAD_SIZE 0x100
#define SERVER_IP "129.63.134.29" // hostname -I

enum class NetType
{
    UNDEF = -1,
    POLL, // Used to be 'null' type.
    ACK,
    NACK,
    UHF_CONFIG,
    XBAND_CONFIG,
    XBAND_COMMAND,
    DATA
};

enum class NetVertex
{
    UNDEF = -1,
    CLIENT,
    ROOFUHF,
    ROOFXBAND,
    HAYSTACK,
    SERVOS,
    SERVER
};

class NetData
{
public:
    int socket;
    int thread_status;
    bool connection_ready;
    bool recv_active;

protected:
    NetData();
};

class NetDataClients : public NetData
{
public:
    NetDataClients(int server_port, int polling_rate);

    int polling_rate; // Polling occurs once every this many seconds.
    char disconnect_reason[64];
    struct sockaddr_in server_ip[1];
};

class NetDataServer : public NetData
{
public:
    NetDataServer(int listening_port);

    int listening_port;
};

class NetFrame
{
public:
    /** CONSTRUCTOR
     * @brief THROWS EXCEPTIONS. Construct a new NetworkFrame object
     * 
     * @param payload 
     * @param size 
     * @param type 
     * @param dest 
     */
    NetFrame(unsigned char *payload, ssize_t size, NetType type, NetVertex destination);

    // The copy constructor and destructor will only be needed if dynamic frame payload size is supported.

    /** COPY CONSTRUCTOR
     * @brief Copy a NetworkFrame object.
     * 
     * @param obj 
     */
    // NetFrame(const NetFrame &obj);

    /** DESTRUCTOR
     * @brief Destroy the NetworkFrame object.
     * 
     */
    // ~NetFrame();

    /**
     * @brief Copies payload to the passed space in memory.
     * 
     * @param storage Pointer to memory into which the payload is copied.
     * @param capacity The size of the memory space being passed.
     * @return int Positive on success, negative on failure.
     */
    int retrievePayload(unsigned char *storage, ssize_t capacity);

    /**
     * @brief Sends itself using the network data passed to it.
     * 
     * @return ssize_t Number of bytes sent if successful, negative on failure. 
     */
    ssize_t sendFrame(NetData *network_data);

    /**
     * @brief Checks the validity of itself.
     * 
     * @return int Positive if valid, negative if invalid.
     */
    int validate();

    /**
     * @brief Prints the class' data.
     * 
     */
    void print();

    // This exists because 'setting' is restrictive.
    int setNetstat(uint8_t netstat);

    // These exist because 'setting' is restrictive.
    NetType getType(){ return type; };
    NetVertex getOrigin(){ return origin; };
    NetVertex getDestination(){ return destination; };
    int getPayloadSize(){ return payload_size; };
    uint8_t getNetstat(){ return netstat; };

private:
    uint32_t guid;                                         // 0x1A1C1A1C
    NetType type;
    NetVertex origin;
    NetVertex destination;
    int payload_size;
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
 * @brief 
 * 
 * @param network_data 
 * @return int 
 */
int gs_connect_to_server(NetData *network_data);

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
