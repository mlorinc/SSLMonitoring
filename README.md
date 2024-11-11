# SSL Monitoring

The following project was part of my networking course. Its primary goal is
to capture Server Name Indication (SNI), which indicates what server the client is
connecting to. SNI can be extracted during the TLS handshake (Client Hello) procedure, which
until TLS 1.3 used to be unencrypted and therefore vulnerable.
Before that, captured packets must be parsed according to the OSI model.

## Data Link Layer

Starting from the Data Link Layer frame, as the Physical Layer refers to physical transmission implementations such as
Ethernet or WiFi. From the frame, it is possible to extract MAC addresses. In the Data section of the frame lies a packet,
either an IPv4 or IPv6 packet. The primary use of the Data Link Layer is routing within a LAN using MAC addresses.

## Network Layer

In this layer, it is possible to have two types of packets. The IPv4 packet is more straightforward to parse as it
has a consistent structure, whereas IPv6 introduces new features such as extension headers which make packet size
variable. The main bit of information to extract here is the IP addresses, which serve to route network communication among
distant networks referred to as WAN. Also, the IPv4 packet contains an offset to the next layer's data, which leads to the Transport Layer.

## Transport Layer

In this project, only TCP segments are parsed, while UDP datagrams and other packets are filtered out.
The Transport Layer is responsible for routing network communication to specific applications (sockets) that
listen to specific ports. Moreover, TCP ensures packets are properly ordered (using sequence numbers) to the socket, even though they might arrive out of order due to different network paths. To achieve that, each segment
includes TCP flags and an acknowledgment number used to sort packets.

## SSL Layer

The layer above the Transport Layer is SSL, which encrypts the application data it contains. As previously mentioned,
the initial part of the connection procedure used to be unencrypted and was therefore vulnerable to capture. However, application
data is still securely encrypted. Parsing ends at this layer because the SNI is located in the Client Hello message
within the server_name extension.

## Build

To build project execute `make sslsniff`. For CLI arguments, refer to man manual.