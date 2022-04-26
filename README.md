Deprecated, superseded by https://github.com/sunipkm/network.

# Network
SPACE-HAUC Ground Station common network files.

## Sending Data (Client)
```c
// Initialize a client's NetData object, giving the port and polling rate in seconds.
NetDataClient *network_data = new NetDataClient(NetPort::CLIENT, SERVER_POLLING_RATE);

// Set network receive to true.
network_data->recv_active = true;

...

// Call the connect to server function, which sets the NetDataClient::socket and ::connection_ready values.
gs_connect_to_server(network_data);

...

// Create a data buffer, and fill it with some data.
unsigned char buffer[DATA_SIZE];

...

// Initialize a NetFrame object, send the frame, and clean up afterwards.
NetFrame *network_frame = new NetFrame(buffer, DATA_SIZE, NetType::DATA, NetVertex::SERVER);
network_frame->sendFrame(network_data);
delete network_frame;
```
## Receiving Data (Client)
```c
NetDataClient *network_data = new NetDataClient(NetPort::CLIENT, SERVER_POLLING_RATE);
network_data->recv_active = true;

...

gs_connect_to_server(network_data);

...

// Construct a NetFrame object for receiving into, and call the receiving function.
NetFrame *network_frame = new NetFrame();
network_frame->recvFrame(network_data);

// Allocate a buffer of appropriate size to hold the payload, and call retrievePayload to fill it.
ssize_t buffer_size = network_frame->getPayloadSize();
unsigned char *buffer = (unsigned char *)malloc(buffer_size);
network_frame->retrievePayload(buffer, buffer_size);

...

free(buffer);
```
## Sending Data (Server)
```c
// Initialize a server's NetData object, giving the port to listen on.
NetDataServer *network_data = new NetDataClient(NetPort::CLIENT);

// Set network receive to true.
network_data->recv_active = true;

...

// Set the socket integer value and, if the connection is open, set connection_ready to true.
network_data->socket = accept(listening_socket, (struct sockaddr *)&accepted_address, (socklen_t *)&socket_size);
network_data->connection_ready = true;

...

// Create a data buffer, and fill it with the payload.
unsigned char buffer[DATA_SIZE];

...

// Initialize a NetFrame object, send the frame, and clean up afterwards.
NetFrame *network_frame = new NetFrame(buffer, DATA_SIZE, NetType::DATA, NetVertex::CLIENT);
network_frame->sendFrame(network_data);
delete network_frame;
```
## Receiving Data (Server)
```c
NetDataServer *network_data = new NetDataClient(NetPort::CLIENT);
network_data->recv_active = true;

...

network_data->socket = accept(listening_socket, (struct sockaddr *)&accepted_address, (socklen_t *)&socket_size);
network_data->connection_ready = true;

...

// Construct a NetFrame object for receiving into, and call the receiving function.
NetFrame *network_frame = new NetFrame();
network_frame->recvFrame(network_data);

// Allocate a buffer of appropriate size to hold the payload, and call retrievePayload to fill it.
ssize_t buffer_size = network_frame->getPayloadSize();
unsigned char *buffer = (unsigned char *)malloc(buffer_size);
network_frame->retrievePayload(buffer, buffer_size);
```
## NetType
_What type of data is contained within this packet's payload?_
```c
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
    TRACKING_DATA       // Automatically and periodically send to the client.
};
```
## NetVertex
_A point within the Ground Station Network._
```c
enum class NetVertex
{
    CLIENT,
    ROOFUHF,
    ROOFXBAND,
    HAYSTACK,
    SERVER,
    TRACK
};
```
## NetPorts
_Ground Station Network device-specific ports._
```c
enum class NetPort
{
    CLIENT = 54200,
    ROOFUHF = 54210,
    ROOFXBAND = 54220,
    HAYSTACK = 54230,
    TRACK = 54240
};
```
