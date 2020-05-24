#include "utils.hpp"
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
/* #include <string.h> */
#include <string> /* This header contains string class */
#include <cstdlib>



typedef signed char           s8;
typedef unsigned char         u8;
typedef short                 s16;
typedef unsigned short        u16;
typedef int                   s32;
typedef unsigned int          u32;
typedef long long             s64;
typedef unsigned long long    u64;

#define JDWP_HANDSHAKE "JDWP-Handshake"

#define PACKET_TYPE_COMMAND 0
#define PACKET_TYPE_REPLY 128

#define CMDSET_VM 1
#define CMDSET_REFERENCETYPE 2
#define CMDSET_CLASSTYPE 3
#define CMDSET_ARRAYTYPE 4
#define CMDSET_INTERFACETYPE 5
#define CMDSET_METHOD 6
#define CMDSET_FIELD 8
#define CMDSET_OBJECTREFERENCE 9
#define CMDSET_STRINGREFERENCE 10
#define CMDSET_THREADREFERENCE 11
#define CMDSET_THREADGROUPREFERENCE 12
#define CMDSET_ARRAYREFERENCE 13
#define CMDSET_CLASSLOADERREFERENCE 14
#define CMDSET_EVENTREQUEST 15
#define CMDSET_STACKFRAME 16
#define CMDSET_CLASSOBJECTREFERENCE 17
#define CMDSET_EVENT 64

#define CMD_VERSION 1
#define CMD_CLASSBYSIG 2
#define CMD_IDSIZES 7
#define CMD_SUSPEND 8 
#define CMD_RESUME 9 
#define CMD_EXIT 10 

#define PACKED __attribute__((__packed__))

namespace andromeda
{
    // struct.pack(">IIccc", pktlen, self.id, chr(flags), chr(cmdset), chr(cmd))
    // I : unsigned int   (4 bytes)
    // H : unsigned short (2 bytes)
    // c : char           (1 byte)
    // > : big-endian
    struct PACKED RequestHeader {
        u32 length;
        u32 id;
        u8 flags;
        u8 cmdSet;
        u8 cmd;
    };

    // >IIcH
    struct PACKED ReplyHeader {
        u32 length;
        u32 id;
        u8  flags;
        u16 errcode;
    };

    struct VersionResponse {
        std::string description;
        u32 jdwpMajor;
        u32 jdwpMinor;
        std::string vmVersion;
        std::string vmName;
    };

    VersionResponse* parseVersionResponse(char* buff, ssize_t size) {
        VersionResponse* version = (VersionResponse*) malloc(sizeof(VersionResponse));

        u32 descSize = htonl(*(u32*)buff);
        buff += sizeof(u32);

        version->description = std::string(buff, descSize);
        buff += descSize;

        version->jdwpMajor = htonl(*(u32*)buff);
        buff += sizeof(u32);

        version->jdwpMinor = htonl(*(u32*)buff);
        buff += sizeof(u32);
        
        u32 vmVersionSize = htonl(*(u32*)buff);
        buff += sizeof(u32);
        version->vmVersion = std::string(buff, vmVersionSize);
        buff += vmVersionSize;

        u32 vmNameSize = htonl(*(u32*)buff);
        buff += sizeof(u32);
        version->vmName = std::string(buff, vmNameSize);
        buff += vmNameSize;

        return version;
    }

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

            getIdSizes();
            getVersion();

            return true;
        }

    private:
        u32 packet_id = 1;

        bool handshake() {
            std::string magic = JDWP_HANDSHAKE;

            send(sock, magic.c_str(), magic.length(), 0);

            char recv[magic.length() + 1]; 
            read(sock, &recv, magic.length());

            std::string response(recv);
            if (response == magic) {
                printf("did handshake, magic %s\n", response.c_str());
                return true;
            }

            return false;
        }

        void getIdSizes() {
            RequestHeader *header = createPacket(CMDSET_VM, CMD_IDSIZES, 0); 
            sendPacket(header);
            free(header);

            ssize_t size = 0;
            void* body = readReply(&size);
            free(body);
        }

        void getVersion() {
            RequestHeader *header = createPacket(CMDSET_VM, CMD_VERSION, 0); // version packet            
            sendPacket(header);
            free(header);

            ssize_t size = 0;
            void* body = readReply(&size);
            if (body != nullptr && size > 0) {
                 VersionResponse* version = parseVersionResponse((char*)body, size);
                 printf("version! %u %u, %s\n", version->jdwpMajor, version->jdwpMinor, version->vmName.c_str());
                 free(body);
            }
        }

        void* readReply(ssize_t *size) {
            ReplyHeader header;
            *size = -1;

            ssize_t count = read(sock, &header, sizeof(ReplyHeader));
            if (count == 0 && errno != 0) {
                printf("error: %d\n", errno);
                return nullptr;
            }

            header.length = ntohl(header.length);
            header.id = ntohl(header.id);
            header.errcode = ntohs(header.errcode);
            printf("got reply (%u) id: %u, length: %u, errcode: %u, flags: %u\n", count, header.id, header.length, header.errcode, header.flags);


            if (header.flags != PACKET_TYPE_REPLY || header.errcode != 0) {
                printf("error code: %u, flag: %u\n", header.errcode, header.flags);
                return nullptr;
            }

            ssize_t payload_size = header.length - sizeof(ReplyHeader);

            if (payload_size > 0) {
                void* data = malloc(payload_size);
                read(sock, data, payload_size);
                /* printf("read %u bytes\n", payload_size); */
                *size = payload_size;
                return data;
            }

            // success without data
            *size = 0;
            return nullptr;
        }

        void sendPacket(RequestHeader* header) {
            send(sock, (void*)header, sizeof(RequestHeader), 0);
            /* printf("sent header! id: %u, %u bytes. request header [%d,%d]. payload_size: %u\n", header->id, count, header->cmdSet, header->cmd, header->length); */
        }

        void sendPacket(RequestHeader* header, void* data) {
            sendPacket(header);
            ssize_t payload_size = header->length - sizeof(RequestHeader);
            ssize_t count = send(sock, data, payload_size, 0);
            /* printf("sent body. sent %u bytes. body size: %u\n", count, payload_size); */
        }

        RequestHeader* createPacket(u8 signal_major, u8 signal_minor, u32 length) {
           RequestHeader *packet = (RequestHeader*) malloc(sizeof(RequestHeader));
           packet->length = htonl(length + sizeof(RequestHeader));
           packet->id = htonl(packet_id);
           packet->flags = 0x00;
           packet->cmdSet = signal_major;
           packet->cmd = signal_minor;
           packet_id += 2;
           return packet;
        }
    };

}
