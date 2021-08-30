/**
 * @file network.cpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version See Git tags for version information.
 * @date 2021.07.30
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "network.hpp"
#include "meb_debug.hpp"
#include <openssl/err.h>
#include <assert.h>

static int ssl_lib_init = 0;

void InitializeSSLLibrary()
{
    if (ssl_lib_init++ == 0)
    {
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
    }
}

SSL_CTX *InitializeSSLServer(void)
{
    InitializeSSLLibrary();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        dbprintlf(FATAL "Could create SSL context");
        return NULL;
    }
    int use_cert = SSL_CTX_use_certificate_file(ctx, "./cert.pem", SSL_FILETYPE_PEM);
    int use_prv = SSL_CTX_use_PrivateKey_file(ctx, "./key.pem", SSL_FILETYPE_PEM);
    if ((use_cert != 1) || (use_prv != 1) || (SSL_CTX_check_private_key(ctx) != 1))
    {
        dbprintlf("Cert: %d, Private Key: %d, Validation: %d", use_cert, use_prv, SSL_CTX_check_private_key(ctx));
        return NULL;
    }
    SSL_CTX_set_dh_auto(ctx, 1);
    return ctx;
}

SSL_CTX *InitializeSSLClient(void)
{
    InitializeSSLLibrary();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        dbprintlf(FATAL "Could create SSL context");
    }
    else
    {
        SSL_CTX_set_dh_auto(ctx, 1);
    }
    return ctx;
}

void DestroySSL()
{
    assert(ssl_lib_init >= 0);
    if (--ssl_lib_init == 0)
    {
        ERR_free_strings();
        EVP_cleanup();
    }
}

NetData::NetData()
{
    connection_ready = false;
    _socket = -1;
};

void NetData::close_ssl_conn()
{
    if (cssl != NULL)
    {
        ssl_ready = false;
        SSL_shutdown(cssl);
        SSL_free(cssl);
        cssl = NULL;
    }
    if (ctx != NULL)
    {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
    DestroySSL();
}

void NetData::Close()
{
    if (ssl_ready)
        close_ssl_conn();
    connection_ready = false;
    close(_socket);
    _socket = -1;
}

NetDataClient::NetDataClient(const char *ip_addr, NetPort server_port, NetVertex vertex, int polling_rate, sha1_hash_t auth_token)
    : NetData()
{
    ;
    ctx = InitializeSSLClient();
    if (ip_addr == NULL)
        strcpy(this->ip_addr, "127.0.0.1");
    else
    {
        strncpy(this->ip_addr, ip_addr, sizeof(this->ip_addr));
    }
    this->polling_rate = polling_rate;
    strcpy(disconnect_reason, "N/A");
    server_ip->sin_family = AF_INET;
    server_ip->sin_port = htons((int)server_port);
    self = vertex;
    this->auth_token = new sha1_hash_t;
    this->auth_token->copy(&auth_token);
};

NetDataServer::NetDataServer(NetPort listening_port, int clients, sha1_hash_t auth_token)
{
    this->auth_token = new sha1_hash_t();
    InitializeSSLLibrary();
    _NetDataServer(listening_port, clients);
    this->auth_token->copy(&auth_token);
}

void *gs_accept_thread(void *args);

void NetDataServer::_NetDataServer(NetPort listening_port, int clients)
{
    srand(time(NULL));
    if (clients < 1)
        clients = 1;
    else if (clients > 100)
        clients = 100;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 3)
    {
        dbprintlf("Socket creation failed");
        throw std::bad_alloc();
    }
    int opt = 1;
    // Forcefully attaching socket to the port 8080
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   &opt, sizeof(opt)))
    {
        dbprintlf("setsockopt reuseaddr");
        throw std::invalid_argument("setsockopt reuseaddr");
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                   &opt, sizeof(opt)))
    {
        dbprintlf("setsockopt reuseport");
        throw std::invalid_argument("setsockopt reuseport");
    }

    int flags = fcntl(fd, F_GETFL, 0);
    assert(flags != -1);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    // Forcefully attaching socket to the port 8080
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons((int) listening_port);

    if (bind(fd, (struct sockaddr *)&address,
             sizeof(address)) < 0)
    {
        dbprintlf("bind failed");
        throw std::invalid_argument("bind failed");
    }
    if (listen(fd, clients) < 0)
    {
        dbprintlf("listen");
        throw std::invalid_argument("listen");
    }

    this->num_clients = clients;
    this->clients = new NetClient[clients];

    if (this->clients == nullptr)
    {
        dbprintlf("Could not allocate memory for clients");
        throw std::bad_alloc();
    }

    for (int i = 0; i < clients; i++)
    {
        this->clients[i].client_id = i;
        this->clients[i].serv = this;
    }

    if (pthread_create(&accept_thread, NULL, gs_accept_thread, this) != 0)
    {
        dbprintlf("Could not start accept thread");
    }
};

NetClient *NetDataServer::GetClient(int id)
{
    if (id < 0 || id > num_clients)
        return nullptr;
    return &(clients[id]);
}

NetClient *NetDataServer::GetClient(NetVertex target)
{
    NetClient *ret = nullptr;
    for (int i = 0; i < num_clients; i++)
        if (clients[i].self == target)
            ret = &(clients[i]);
    return ret;
}

NetFrame::NetFrame(unsigned char *payload, ssize_t size, NetType type, NetVertex destination) : payload(nullptr), payload_size(0)
{
    if (payload == nullptr || size == 0 || type == NetType::POLL)
    {
        if (payload != nullptr || size != 0 || type != NetType::POLL)
        {
            dbprintlf(FATAL "Invalid combination of NULL payload, 0 size, and/or POLL NetType.");
            throw std::invalid_argument("Invalid combination of NULL payload, 0 size, and/or POLL NetType.");
        }
    }

    if ((int)type < (int)NetType::POLL || (int)type >= (int)NetType::MAX)
    {
        dbprintlf(FATAL "Invalid or unknown NetType.");
        throw std::invalid_argument("Invalid or unknown NetType.");
    }

    if ((int)destination < (int)NetVertex::CLIENT || (int)destination >= (int)NetVertex::MAX)
    {
        dbprintlf("Invalid or unknown NetVertex.");
        throw std::invalid_argument("Invalid or unknown NetVertex.");
    }

    // Figure out origin for ourselves.
#ifdef GSNID
    if (strcmp(GSNID, "guiclient") == 0)
    {
        origin = NetVertex::CLIENT;
    }
    else if (strcmp(GSNID, "server") == 0)
    {
        origin = NetVertex::SERVER;
    }
    else if (strcmp(GSNID, "roofuhf") == 0)
    {
        origin = NetVertex::ROOFUHF;
    }
    else if (strcmp(GSNID, "roofxband") == 0)
    {
        origin = NetVertex::ROOFXBAND;
    }
    else if (strcmp(GSNID, "haystack") == 0)
    {
        origin = NetVertex::HAYSTACK;
    }
    else if (strcmp(GSNID, "track") == 0)
    {
        origin = NetVertex::TRACK;
    }
    else
    {
        dbprintlf(FATAL "GSNID not recognized. Please ensure one of the following exists:");
        dbprintlf(RED_FG "#define GSNID \"guiclient\"");
        dbprintlf(RED_FG "#define GSNID \"server\"");
        dbprintlf(RED_FG "#define GSNID \"roofuhf\"");
        dbprintlf(RED_FG "#define GSNID \"roofxband\"");
        dbprintlf(RED_FG "#define GSNID \"haystack\"");
        dbprintlf(RED_FG "#define GSNID \"track\"");
        dbprintlf(RED_FG "Or, in a Makefile: -DGSNID=\\\"guiclient\\\"");
        throw std::invalid_argument("GSNID not recognized.");
    }
#endif
#ifndef GSNID
    dbprintlf(FATAL "GSNID not defined. Please ensure one of the following exists:");
    dbprintlf(RED_FG "#define GSNID \"guiclient\"");
    dbprintlf(RED_FG "#define GSNID \"server\"");
    dbprintlf(RED_FG "#define GSNID \"roofuhf\"");
    dbprintlf(RED_FG "#define GSNID \"roofxband\"");
    dbprintlf(RED_FG "#define GSNID \"haystack\"");
    dbprintlf(RED_FG "#define GSNID \"track\"");
    dbprintlf(RED_FG "Or, in a Makefile: -DGSNID=\\\"guiclient\\\"");
    throw std::invalid_argument("GSNID not defined.");
#endif
    guid = NETFRAME_GUID;
    this->type = type;
    this->destination = destination;

    payload_size = size;

    // Enforces a minimum payload capacity, even if the payload size if less.
    // payload_size = size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : size;
    size_t malloc_size = size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : size;

    // Payload too large error.
    if (payload_size > NETFRAME_MAX_PAYLOAD_SIZE)
    {
        throw std::invalid_argument("Payload size larger than 0xfffe4.");
    }

    this->payload = (uint8_t *)malloc(malloc_size);

    if (this->payload == nullptr)
    {
        throw std::bad_alloc();
    }

    if (malloc_size == NETFRAME_MIN_PAYLOAD_SIZE)
    {
        memset(this->payload, 0x0, NETFRAME_MIN_PAYLOAD_SIZE);
    }

    // Check if payload is nullptr, and allocate memory if it is not.
    if (payload != nullptr && size > 0)
    {
        memcpy(this->payload, payload, payload_size);
    }

    crc1 = internal_crc16(this->payload, malloc_size);
    crc2 = crc1;
    netstat = 0x0;
    termination = 0xAAAA;
}

NetFrame::~NetFrame()
{
    if (payload != nullptr)
        free(payload);
    payload = nullptr;
    payload_size = 0;
}

int NetFrame::retrievePayload(unsigned char *storage, ssize_t capacity)
{
    if (capacity < payload_size)
    {
        dbprintlf("Capacity less than payload size (%ld < %ld).\n", capacity, payload_size);
        return -1;
    }

    memcpy(storage, payload, payload_size);

    return 1;
}

ssize_t NetFrame::sendFrame(NetData *network_data)
{
    if (!(network_data->connection_ready))
    {
        dbprintlf(YELLOW_FG "Connection is not ready, send aborted.");
        return -1;
    }

    if (network_data->_socket < 0)
    {
        dbprintlf(RED_FG "Invalid socket (%d).", network_data->_socket);
        return -1;
    }

    if (!validate())
    {
        dbprintlf(RED_FG "Frame validation failed, send aborted.");
        return -1;
    }

    if (payload_size < 0)
    {
        dbprintlf(RED_FG "Frame was constructed using NetFrame() not NetFrame(unsigned char *, ssize_t, NetType, NetVertex), has not had data read into it, and is therefore unsendable.");
        return -1;
    }

    size_t payload_buffer_size = payload_size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : payload_size;

    ssize_t send_size = 0;
    uint8_t *buffer = nullptr;
    ssize_t malloc_size = sizeof(NetFrameHeader) + payload_buffer_size + sizeof(NetFrameFooter);
    buffer = (uint8_t *)malloc(malloc_size);

    if (buffer == nullptr)
    {
        return -1;
    }

    // To send a NetFrame which contains a dynamically allocated payload buffer, we must construct a sendable buffer of three components:
    // 1. Header
    // 2. Payload
    // 3. Footer

    // Set the header area of the buffer.
    NetFrameHeader *header = (NetFrameHeader *)buffer;
    header->guid = this->guid;
    header->type = (uint32_t)this->type;
    header->origin = (uint32_t)this->origin;
    header->destination = (uint32_t)this->destination;
    header->payload_size = this->payload_size;
    header->crc1 = this->crc1;

    // Copy the payload into the buffer.
    memcpy(buffer + sizeof(NetFrameHeader), this->payload, payload_buffer_size);

    // Set the footer area of the buffer.
    NetFrameFooter *footer = (NetFrameFooter *)(buffer + sizeof(NetFrameHeader) + payload_buffer_size);
    footer->crc2 = this->crc2;
    footer->netstat = this->netstat;
    footer->termination = termination;

    // Set frame_size to malloc_size, the bytes allocated for the sendable buffer, to track how many bytes should send.
    this->frame_size = malloc_size;

    if (!network_data->ssl_ready)
        send_size = send(network_data->_socket, buffer, malloc_size, 0);
    else
        send_size = SSL_write(network_data->cssl, buffer, malloc_size);

    free(buffer);

    return send_size;
}

ssize_t NetFrame::recvFrame(NetData *network_data)
{
    if (!(network_data->connection_ready))
    {
        dbprintlf(YELLOW_FG "Connection is not ready, send aborted.");
        return -1;
    }

    if (network_data->_socket < 0)
    {
        dbprintlf(RED_FG "Invalid socket (%d).", network_data->_socket);
        return -1;
    }

    // Verify GUID.
    NetFrameHeader header;
    int offset = 0;
    int recv_attempts = 0;

    do
    {
        int sz;
        if (!network_data->ssl_ready) 
            sz = recv(network_data->_socket, header.bytes + offset, 1, MSG_WAITALL);
        else
            sz = SSL_read(network_data->cssl, header.bytes + offset, 1);
        if (sz < 0)
        {
            // Connection broken.
            break;
        }
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
                return -404;
            }
        }
        if ((sz == 1) && (header.bytes[offset] == (uint8_t)(NETFRAME_GUID >> (offset * 8))))
        {
            offset++;
        }
        else
        {
            offset = 0;
        }
    } while (offset < sizeof(NETFRAME_GUID));

    recv_attempts = 0;

    // Receive the rest of the header.
    do
    {
        int sz;
        if (!network_data->ssl_ready) 
            sz = recv(network_data->_socket, header.bytes + offset, sizeof(NetFrameHeader) - offset, MSG_WAITALL);
        else
            sz = SSL_read(network_data->cssl, header.bytes + offset, sizeof(NetFrameHeader) - offset);
        if (sz < 0)
            break;
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
                return -404;
            }
        }
        offset += sz;
    } while (offset < sizeof(NetFrameHeader));

    size_t payload_buffer_size = 0;

    if (offset == sizeof(NetFrameHeader)) // success
    {
        this->guid = header.guid;
        this->type = (NetType)header.type;
        this->origin = (NetVertex)header.origin;
        this->destination = (NetVertex)header.destination;
        this->payload_size = header.payload_size;
        this->crc1 = header.crc1;

        payload_buffer_size = payload_size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : payload_size;

        if (payload_buffer_size <= NETFRAME_MAX_PAYLOAD_SIZE)
        {
            this->payload = (uint8_t *)malloc(payload_buffer_size);
        }
        else
        {
            return -2; // invalid size
        }
    }
    else // failure
    {
        return -1;
    }

    if (this->payload == nullptr)
    {
        return -3; // malloc failed
    }

    offset = 0;

    recv_attempts = 0;

    // Receive the payload.
    do
    {
        int sz;
        if (!network_data->ssl_ready) 
            sz = recv(network_data->_socket, this->payload + offset, payload_buffer_size - offset, MSG_WAITALL);
        else
            sz = SSL_read(network_data->cssl, this->payload + offset, payload_buffer_size - offset);
        if (sz < 0)
        {
            // Connection broken mid-receive-payload.
            return -4;
        }
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
                return -404;
            }
        }
        offset += sz;
    } while (offset < payload_buffer_size);

    offset = 0;

    NetFrameFooter footer;

    recv_attempts = 0;

    // Receive the footer.
    do
    {
        int sz;
        if (!network_data->ssl_ready) 
            sz = recv(network_data->_socket, footer.bytes + offset, sizeof(NetFrameFooter) - offset, MSG_WAITALL);
        else
            sz = SSL_read(network_data->cssl, footer.bytes + offset, sizeof(NetFrameFooter) - offset);
        if (sz < 0)
        {
            // Connection broken.
            return -4;
        }
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
                return -404;
            }
        }
        offset += sz;
    } while (offset < sizeof(NetFrameFooter));

    // memcpy
    if (offset == sizeof(NetFrameFooter))
    {
        this->crc2 = footer.crc2;
        this->netstat = footer.netstat;
        this->termination = footer.termination;
    }

    // Validate the data we read as a valid NetFrame.
    if (this->validate())
    {
        return this->payload_size;
    }

    return -1;
}

int NetFrame::validate()
{
    if (guid != NETFRAME_GUID)
    {
        return -1;
    }
    else if ((int)type < (int)NetType::POLL || (int)type >= (int)NetType::MAX)
    {
        return -2;
    }
    else if (payload == NULL || payload_size == 0 || type == NetType::POLL)
    {
        // dbprintlf(YELLOW_FG "payload == NULL: %d; payload_size: %d; type == NetType::POLL: %d", payload == NULL, payload_size, type == NetType::POLL);
        if (payload_size != 0 || type != NetType::POLL)
        {
            return -3;
        }
    }
    else if ((int)origin < (int)NetVertex::CLIENT || (int)origin >= (int)NetVertex::MAX)
    {
        return -4;
    }
    else if ((int)destination < (int)NetVertex::CLIENT || (int)destination > (int)NetVertex::TRACK)
    {
        return -5;
    }
    else if (payload_size < 0 || payload_size > NETFRAME_MAX_PAYLOAD_SIZE)
    {
        return -6;
    }
    else if (crc1 != crc2)
    {
        return -7;
    }
    else if (crc1 != internal_crc16(payload, payload_size))
    {
        return -8;
    }
    else if (termination != 0xAAAA)
    {
        return -9;
    }

    return 1;
}

void NetFrame::print()
{
    dbprintlf(BLUE_FG "NETWORK FRAME");
    dbprintlf("GUID ------------ 0x%08x", guid);
    dbprintlf("Type ------------ %d", (int)type);
    dbprintlf("Destination ----- %d", (int)destination);
    dbprintlf("Origin ---------- %d", (int)origin);
    dbprintlf("Payload Size ---- %ld", payload_size);
    dbprintlf("CRC1 ------------ 0x%04x", crc1);
    dbprintf("Payload ---- (HEX)");
    for (int i = 0; i < payload_size; i++)
    {
        if ((i % 2) == 0)
        {
            printf(BLUE_FG "%02x" RESET_ALL, payload[i]);
        }
        else
        {
            printf("%02x", payload[i]);
        }
    }
    printf("\n");
    dbprintlf("CRC2 ------------ 0x%04x", crc2);
    dbprintlf("NetStat --------- 0x%x", netstat);
    dbprintlf("Termination ----- 0x%04x", termination);
}

void NetFrame::printNetstat()
{
    dbprintlf(BLUE_FG "NETWORK STATUS (%d)", netstat);
    dbprintf("GUI Client ----- ");
    ((netstat & 0x80) == 0x80) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
    dbprintf("Roof UHF ------- ");
    ((netstat & 0x40) == 0x40) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
    dbprintf("Roof X-Band ---- ");
    ((netstat & 0x20) == 0x20) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
    dbprintf("Haystack ------- ");
    ((netstat & 0x10) == 0x10) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
    dbprintf("Track ---------- ");
    ((netstat & 0x8) == 0x8) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
}

int NetFrame::setNetstat(uint8_t netstat)
{
#ifdef GSNID
    if (strcmp(GSNID, "server") == 0)
    {
        this->netstat = netstat;
        return 1;
    }
    else
    {
        dbprintlf(RED_FG "Only the Ground Station Network Server may set netstat.");
        return -1;
    }
#endif

    dbprintlf(FATAL "GSNID not defined. Please ensure one of the following exists:");
    dbprintlf(RED_FG "#define GSNID \"guiclient\"");
    dbprintlf(RED_FG "#define GSNID \"server\"");
    dbprintlf(RED_FG "#define GSNID \"roofuhf\"");
    dbprintlf(RED_FG "#define GSNID \"roofxband\"");
    dbprintlf(RED_FG "#define GSNID \"haystack\"");
    dbprintlf(RED_FG "#define GSNID \"track\"");
    dbprintlf(RED_FG "Or, in a Makefile: -DGSNID=\\\"guiclient\\\"");
    return -1;
}

void *gs_polling_thread(void *args)
{
    dbprintlf(BLUE_FG "Beginning polling thread.");

    NetDataClient *network_data = (NetDataClient *)args;

    while (network_data->recv_active)
    {
        if (network_data->connection_ready)
        {
            NetFrame *polling_frame = new NetFrame(NULL, 0, NetType::POLL, NetVertex::SERVER);
            polling_frame->sendFrame(network_data);
            delete polling_frame;
        }
        else
        {
#ifdef GSNID
            // Disables automatic reconnection for the GUI Client and Server.
#ifndef XB_GS_TEST // Re-enables automatic reconnection for the xb_gs_test GUI client.
            if (strcmp(GSNID, "guiclient") != 0 && strcmp(GSNID, "server") != 0)
#endif
            {
                // Get our GS Network connection back up and running.
                gs_connect_to_server(network_data);
            }
#endif
#ifndef GSNID
            dbprintlf(FATAL "GSNID not defined. Please ensure one of the following exists:");
            dbprintlf(RED_FG "#define GSNID \"guiclient\"");
            dbprintlf(RED_FG "#define GSNID \"server\"");
            dbprintlf(RED_FG "#define GSNID \"roofuhf\"");
            dbprintlf(RED_FG "#define GSNID \"roofxband\"");
            dbprintlf(RED_FG "#define GSNID \"haystack\"");
            dbprintlf(RED_FG "#define GSNID \"track\"");
            dbprintlf(RED_FG "Or, in a Makefile: -DGSNID=\\\"guiclient\\\"");
#endif
        }
        usleep(network_data->polling_rate * 1000000);
    }

    dbprintlf(FATAL "GS_POLLING_THREAD IS EXITING!");
    if (network_data->thread_status > 0)
    {
        network_data->thread_status = 0;
    }
    return nullptr;
}

void *gs_accept_thread(void *args)
{
    NetDataServer *serv = (NetDataServer *)args;
    while (!serv->listen_done)
    {
        for (int i = 0; i < serv->num_clients; i++)
        {
            gs_accept(serv, i);
        }
        sleep(1);
    }
    return NULL;
}

int gs_accept_ssl(NetData *client);

int gs_accept(NetDataServer *serv, int client_id)
{
    // check if client ID is valid
    if (client_id >= serv->num_clients)
    {
        dbprintlf("Invalid client ID, max clients %d", serv->num_clients);
        return -1;
    }
    // get local pointer to client referenced by ID
    NetClient *client = serv->GetClient(client_id);
    // check if connection already available
    if (client->connection_ready)
    {
        return client->_socket;
    }
    // if not connected
    if (client->_socket <= 0)
    {
        client->client_addrlen = sizeof(struct sockaddr_in);
        client->_socket = accept(serv->fd, (struct sockaddr *)&(client->client_addr), (socklen_t *)&(client->client_addrlen)); // accept request
    }
    if (client->_socket <= 0) // connection attempt unsuccessful
        return client->_socket;

    client->connection_ready = true;
    int set = 1;
    // set socket option to not generate sigpipe if connection is broken
#ifndef __linux__
    setsockopt(client->_socket, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif

    // accept SSL connection
    if (gs_accept_ssl(client) < 0)
    {
        dbprintlf("Could not accept SSL connection");
        client->Close();
        return -1;
    }

    usleep(10000);

    // Receive auth token
    NetFrame *frame = new NetFrame();
    int retval;
    for (int i = 0; i < 20; i++)
    {
        retval = frame->recvFrame(client);
        if (retval > 0)
            break;
    }

    client->self = frame->getOrigin();

    frame->print();

    if (retval <= 0)
    {
        dbprintlf("Could not receive frame for auth token check");
        client->Close();
        return -1;
    }

    // if authentication token
    NetType ret = NetType::NACK;
    if (frame->getType() == NetType::SRV && frame->getDestination() == NetVertex::SERVER)
    {
        sha1_hash_t auth;
        if (!ssl_lib_init)
        {
            dbprintlf(RED_FG "SSL Library not initialized");
        }
        else if (serv->GetAuthToken() == nullptr)
        {
            dbprintlf(RED_FG "Authentication token null");
        }
        else if (serv->GetAuthToken()->valid() == false)
        {
            dbprintlf(RED_FG "Authentication token not set up");
        }
        else if (frame->getPayloadSize() != sizeof(sha1_hash_t))
        {
            dbprintlf(RED_FG "Authentication token size invalid");
        }
        else if (frame->retrievePayload((uint8_t *) auth.GetBytes(), sizeof(auth)) < 0)
        {
            dbprintlf(RED_FG "Could not obtain authentication token\n");
        }
        else if (*(serv->GetAuthToken()) != auth)
        {
            dbprintlf(RED_FG "Authentication token mismatch");
        }
        else
        {
            ret = NetType::ACK;
        }
        delete frame;
    }
    else
    {
        // hang up
        // TODO: Black list IP address
        delete frame;
        dbprintlf("Could not receive frame for auth token check");
        client->Close();
        return -1;
    }

    frame = new NetFrame((uint8_t *) &ret, sizeof(NetType), ret, client->self);
    int bytes = frame->sendFrame(client);
    delete frame;

    if (ret == NetType::NACK)
    {
        dbprintlf("Could not authenticate client");
        client->Close();
        return -1;
    }

    if (bytes <= 0)
    {
        dbprintlf("Cound not send vertex identifiers, closing connection");
        delete frame;
        client->Close();
        return -1;
    }

    return 1;
}

int gs_accept_ssl(NetData *client)
{
    if (client->server)
    {
        dbprintlf("Function not applicable on a server");
        return -100;
    }
    if (client->cssl != NULL)
    {
        dbprintlf("Connection to client %p already over SSL", client);
        return 1;
    }
    else if (client->ssl_ready)
    {
        dbprintlf("SSL ready");
        return 1;
    }
    client->ctx = InitializeSSLServer();
    if (client->ctx == NULL)
    {
        dbprintlf(FATAL "Could not initialize SSL context for the client");
        return -1;
    }
    client->cssl = SSL_new(client->ctx);
    if (client->cssl == NULL)
    {
        dbprintlf(FATAL "Could not allocate SSL connection");
        return -2;
    }
    if (SSL_set_fd(client->cssl, client->_socket) == 0)
    {
        dbprintlf("Could not attach C socket to SSL socket");
        client->close_ssl_conn();
        return -3;
    }
    SSL_set_accept_state(client->cssl);
    int accept_retval = 0;
    for (int i = 0; i < 100; i++)
    {
        accept_retval = SSL_accept(client->cssl);
        if (accept_retval == 0)
        {
            break;
        }
        else if (accept_retval == -1)
        {
            int err = SSL_get_error(client->cssl, accept_retval);
            if (err == SSL_ERROR_WANT_READ)
            {
                usleep(10000);
            }
            else if (err == SSL_ERROR_WANT_WRITE)
            {
                usleep(10000);
            }
            else if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            {
                dbprintlf("Error syscall / ssl");
                break;
            }
            else if (err == SSL_ERROR_ZERO_RETURN)
            {
                dbprintlf("Error return zero");
                break;
            }
        }
        else
        {
            /* Continue */
            break;
        }
    }
    if (accept_retval < 0)
    {
        dbprintlf("Accept failed on SSL");
        ERR_print_errors_fp(stderr);
        client->close_ssl_conn();
        return -4;
    }
    return 1;
}

int gs_connect_to_server(NetDataClient *network_data)
{
    int connect_status = -1;

    dbprintlf(BLUE_FG "Attempting connection to %s.", network_data->ip_addr);

    // This is already done when initializing network_data.
    // network_data->serv_ip->sin_port = htons(server_port);
    if ((network_data->_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        dbprintlf(RED_FG "Socket creation error.");
        connect_status = -1;
    }
    else if (inet_pton(AF_INET, network_data->ip_addr, &network_data->server_ip->sin_addr) <= 0)
    {
        dbprintlf(RED_FG "Invalid address; address not supported.");
        connect_status = -2;
    }
    else if (gs_connect(network_data->_socket, (struct sockaddr *)network_data->server_ip, sizeof(network_data->server_ip), 1) < 0)
    {
        dbprintlf(RED_FG "Connection failure.");
        connect_status = -3;
    }
    else
    {
        // If the socket is closed, but recv(...) was already called, it will be stuck trying to receive forever from a socket that is no longer active. One way to fix this is to close the RX thread and restart it. Alternatively, we could implement a recv(...) timeout, ensuring a fresh socket value is used.
        // Here, we implement a recv(...) timeout.
        struct timeval timeout;
        timeout.tv_sec = RECV_TIMEOUT;
        timeout.tv_usec = 0;
        setsockopt(network_data->_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);

        network_data->connection_ready = true;
        connect_status = 1;

        NetFrame *frame = new NetFrame((uint8_t *)network_data->GetAuthToken()->GetBytes(), SHA512_DIGEST_LENGTH, NetType::SRV, NetVertex::SERVER);
        if (frame->sendFrame(network_data) <= 0)
        {   delete frame;
            dbprintlf("Could not send auth token");
            network_data->Close();
            return -2;
        }
        delete frame;
        usleep(10000);
        frame = new NetFrame();
        if (frame->recvFrame(network_data) <= 0)
        {
            delete frame;
            dbprintlf("Could not receive token ACK/NACK");
            network_data->Close();
            return -3;
        }
        if (frame->getType() == NetType::NACK || frame->getOrigin() != NetVertex::SERVER)
        {
            dbprintlf("Received frame type: %d | Origin: %d", (int) frame->getType(), (int) frame->getOrigin());
            delete frame;
            network_data->Close();
            return -4;
        }
        delete frame;
    }

    return connect_status;
}

int gs_connect(int socket, const struct sockaddr *address, socklen_t socket_size, int tout_s)
{
    int res;
    long arg;
    fd_set myset;
    struct timeval tv;
    int valopt;
    socklen_t lon;

    // Set non-blocking.
    if ((arg = fcntl(socket, F_GETFL, NULL)) < 0)
    {
        dbprintlf(RED_FG "Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    arg |= O_NONBLOCK;
    if (fcntl(socket, F_SETFL, arg) < 0)
    {
        dbprintlf(RED_FG "Error fcntl(..., F_SETFL)");
        erprintlf(errno);
        return -1;
    }

    // Trying to connect with timeout.
    res = connect(socket, address, socket_size);
    if (res < 0)
    {
        if (errno == EINPROGRESS)
        {
            dbprintlf(YELLOW_FG "EINPROGRESS in connect() - selecting");
            do
            {
                if (tout_s > 0)
                {
                    tv.tv_sec = tout_s;
                }
                else
                {
                    tv.tv_sec = 1; // Minimum 1 second.
                }
                tv.tv_usec = 0;
                FD_ZERO(&myset);
                FD_SET(socket, &myset);
                res = select(socket + 1, NULL, &myset, NULL, &tv);
                if (res < 0 && errno != EINTR)
                {
                    dbprintlf(RED_FG "Error connecting.");
                    erprintlf(errno);
                    return -1;
                }
                else if (res > 0)
                {
                    // Socket selected for write.
                    lon = sizeof(int);
                    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon) < 0)
                    {
                        dbprintlf(RED_FG "Error in getsockopt()");
                        erprintlf(errno);
                        return -1;
                    }

                    // Check the value returned...
                    if (valopt)
                    {
                        dbprintlf(RED_FG "Error in delayed connection()");
                        erprintlf(valopt);
                        return -1;
                    }
                    break;
                }
                else
                {
                    dbprintlf(RED_FG "Timeout in select(), cancelling!");
                    return -1;
                }
            } while (1);
        }
        else
        {
            fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
            dbprintlf(RED_FG "Error connecting.");
            erprintlf(errno);
            return -1;
        }
    }
    // Set to blocking mode again...
    if ((arg = fcntl(socket, F_GETFL, NULL)) < 0)
    {
        dbprintlf("Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    arg &= (~O_NONBLOCK);
    if (fcntl(socket, F_SETFL, arg) < 0)
    {
        dbprintlf("Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    return socket;
}
