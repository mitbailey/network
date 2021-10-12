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
#define NETFRAME_GUID 0x4d454239
#define NETFRAME_MIN_PAYLOAD_SIZE 0x100
#define NETFRAME_MAX_PAYLOAD_SIZE 0xfffe4 
#define SERVER_IP "129.63.134.29"

enum class NetType
{
    POLL,               // Sent to the server periodically.
    ACK,
    NACK,
    DATA,               // To/from SPACE-HAUC
    UHF_CONFIG,         // Sets UHF's configuration.
    XBAND_CONFIG,       // Sets X-Band's configuration.
    XBAND_COMMAND,
    XBAND_DATA,         // Automatically and periodically sent to the client.
    TRACKING_COMMAND,   
    TRACKING_DATA,       // Automatically and periodically send to the client.
    SW_UPDATE
};

enum class NetVertex
{
    CLIENT,
    ROOFUHF,
    ROOFXBAND,
    HAYSTACK,
    SERVER,
    TRACK
};

enum class NetPort
{
    // CLIENT = 54200,
    // ROOFUHF = 54210,
    // ROOFXBAND = 54220,
    // HAYSTACK = 54230,
    // TRACK = 54240
    CLIENT = 52000,
    ROOFUHF = 52010,
    ROOFXBAND = 52020,
    HAYSTACK = 52030,
    TRACK = 52040
};

class NetData
{
public:
    int socket;
    bool connection_ready;
    bool recv_active;
    int thread_status;

protected:
    NetData();
};

class NetDataClient : public NetData
{
public:
    NetDataClient(NetPort server_port, int polling_rate);

    int polling_rate; // POLL frame sent to the server every this-many seconds.
    char disconnect_reason[64];
    struct sockaddr_in server_ip[1];
};

class NetDataServer : public NetData
{
public:
    NetDataServer(NetPort listening_port);

    int listening_port;
};

class NetFrame
{
public:
    /** CONSTRUCTOR
     * @brief Creates a NetFrame for receiving via .recvFrame(...).
     * 
     * Payload size set to negative one to indicate that in its current state, this NetFrame cannot be sent. 
     * 
     */
    NetFrame() : payload_size(-1), payload(nullptr) {}

    /** CONSTRUCTOR
     * @brief THROWS EXCEPTIONS. Creates a NetFrame for sending via .sendFrame(...).
     * 
     * @param payload 
     * @param size 
     * @param type 
     * @param dest 
     */
    NetFrame(unsigned char *payload, ssize_t size, NetType type, NetVertex destination);
    
    /** DESTRUCTOR
     * @brief Frees payload and zeroes payload size.
     * 
     */
    ~NetFrame();
    
    /**
     * @brief Copies payload to the passed space in memory.
     * 
     * @param storage Pointer to memory into which the payload is copied.
     * @param capacity The size of the memory space being passed.
     * @return int Positive on success, negative on failure.
     */
    int retrievePayload(unsigned char *storage, ssize_t capacity);

    /**
     * @brief Sends itself, frame must have been constructed using NetFrame(unsigned char *, ssize_t, NetType, NetVertex).
     * 
     * @return ssize_t Zero on success, negative on failure. 
     */
    ssize_t sendFrame(NetData *network_data);

    /**
     * @brief Receives data into a NetFrame constructed by NetFrame().
     * 
     * @param network_data Network Data struct 
     * @return ssize_t Number of bytes received on success, negative on failure.
     */
    ssize_t recvFrame(NetData *network_data);

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

    /**
     * @brief Print network status.
     * 
     */
    void printNetstat();

    // This exists because 'setting' is restrictive.
    int setNetstat(uint8_t netstat);

    // These exist because 'setting' is restrictive.
    NetType getType(){ return type; };
    NetVertex getOrigin(){ return origin; };
    NetVertex getDestination(){ return destination; };
    int getPayloadSize(){ return payload_size; };
    /**
     * @brief Get the Frame Size of the NetFrame (applicable only for sendFrame())
     * 
     * @return ssize_t Frame size of sendFrame(), should be checked against the return value of sendFrame()
     */
    ssize_t getFrameSize(){ return frame_size; }
    uint8_t getNetstat(){ return netstat; };

private:
    // Sendable Data
    uint32_t guid;              // 0x4d454239
    NetType type;               // 
    NetVertex origin;           // Location the NetFrame was created.
    NetVertex destination;      // Location the NetFrame is going.
    int payload_size;           // Size, in bytes, of the stored payload. If -1, receive only.
    uint16_t crc1;              // CRC16 of the stored payload, including zeroes.
    unsigned char *payload;     // Dynamically sized payload, of capacity 0x100 to 0xfffe4 bytes.
    uint16_t crc2;              // 
    uint8_t netstat;            // 8-bit Network device connection indicator.
    uint16_t termination;       // 0xAAAA

    // Non-sendable Data (invisible to .sendFrame(...) and .recvFrame(...))
    ssize_t frame_size;         // Set to the number of bytes that should have sent during the last .sendFrame(...).
};

typedef union
{
    struct __attribute__((packed))
    {
        uint32_t guid;
        uint32_t type;
        uint32_t origin;
        uint32_t destination;
        uint32_t payload_size;
        uint16_t crc1;
    };
    uint8_t bytes[22];
} NetFrameHeader;

typedef union
{
    struct __attribute__((packed))
    {
        uint16_t crc2;
        uint8_t netstat;
        uint16_t termination;
    };
    uint8_t bytes[5];
} NetFrameFooter;

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
int gs_connect_to_server(NetDataClient *network_data);

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
