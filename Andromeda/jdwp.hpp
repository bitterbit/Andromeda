#include "utils.hpp"
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
/* #include <string.h> */
#include <string> /* This header contains string class */
#include <cstdlib>



typedef signed char           s8;
typedef char                  u8;
typedef short                 s16;
typedef unsigned short        u16;
typedef int                   s32;
typedef unsigned int          u32;
typedef long long             s64;
typedef unsigned long long    u64;

namespace andromeda
{
    // struct.pack(">IIccc", pktlen, self.id, chr(flags), chr(cmdset), chr(cmd))
    // I : unsigned int   (4 bytes)
    // H : unsigned short (2 bytes)
    // c : char           (1 byte)
    // > : big-endian
    struct __attribute__((__packed__)) RequestHeader {
        u32 length;
        u32 id;
        u8 flags;
        u8 cmdSet;
        u8 cmd;
    };

    struct __attribute__((__packed__)) ReplyHeader {
        u32 length;
        u32 id;
        u8  flags;
        u16 errcode;
    };

    class jdwp
    {
    public:
        bool is_connected = false;

        int sock = 0;
        char buffer[1024] = {0};

        explicit jdwp() {}

        bool attach(const std::string &remote) {
            auto p = utils::split(remote, ':');
            std::string host = p.first;
            std::string port = p.second;
            printf("jdwp connecting to remote %s : %s\n", host.c_str(), port.c_str());

            RequestHeader header;
            
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                printf("error creating socket\n");
                return false;
            }

            struct sockaddr_in serv_addr;
            serv_addr.sin_family = AF_INET; 
            serv_addr.sin_port = htons(std::atoi(port.c_str())); 
            if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) < 0) {
                printf("bad host %s\n", host.c_str());
                return false;
            }

            if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
                printf("connection failed \n"); 
                return false;
            }

            printf("net connected.\n");

            if (!handshake()) {
                printf("error in jdwp handshake\n");
                return false;
            }

            is_connected = true;
            getVersion();

            return true;
        }

    private:
        bool handshake() {
            std::string magic = "JDWP-Handshake";

            send(sock, magic.c_str(), magic.length(), 0);

            char recv[magic.length() + 1]; 
            read(sock, &recv, magic.length());

            /* std::string str(recv); */
            std::string response(recv);
            if (response == magic) {
                printf("did handshake, magic %s\n", response.c_str());
                return true;
            }

            return false;
        }

        void getVersion() {
            RequestHeader *header = createPacket(1, 1, 0); // version packet            
            sendPacket(header);
            free(header);
            readReply();
        }

        void readReply() {
            ReplyHeader header;
            read(sock, &header, sizeof(ReplyHeader));
            printf("Got reply id: %u, length: %u, errcode: %u\n", header.id, header.length, header.errcode);

            return; // TODO
            void* data = malloc(header.length);
            read(sock, data, header.length);
            printf("Read data");
            free(data); // TODO: implement
        }

        void sendPacket(RequestHeader* header) {
            // sizeof should be 11;
            send(sock, (void *) header, sizeof(RequestHeader), 0);
        }

        void sendPacket(RequestHeader* header, void* data) {
            sendPacket(header);
            send(sock, data, header->length, 0);
        }

        RequestHeader* createPacket(u8 signal_major, u8 signal_minor, u32 length) {
           RequestHeader *packet = (RequestHeader*) malloc(sizeof(RequestHeader));
           packet->length = length;
           packet->cmdSet = signal_major;
           packet->cmd = signal_minor;
           return packet;
        }
    };

}
