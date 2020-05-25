#include "utils.hpp"
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
/* #include <assert.h> */
/* #include <string.h> */
#include <string> /* This header contains string class */
#include <cstdlib>
#include <iostream>

// https://gist.github.com/atr000/249599
// a) As Mac OS X does not have byteswap.h
// needed this for a c util I had used over the years on linux. 
// did not find a solution to stopgap via macports, sadly, but this did the trick
#if HAVE_BYTESWAP_H
#include <byteswap.h>
#else
#define bswap_16(value) \
    ((((value) & 0xff) << 8) | ((value) >> 8))

#define bswap_32(value) \
    (((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
     (uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define bswap_64(value) \
    (((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) \
      << 32) | \
      (uint64_t)bswap_32((uint32_t)((value) >> 32)))
#endif

typedef signed char           s8;
typedef unsigned char         u8;
typedef short                 s16;
typedef unsigned short        u16;
typedef int                   s32;
typedef unsigned int          u32;
typedef long long             s64;
typedef unsigned long long    u64;

template<typename T> T bswap(T value);

template<>
u16 bswap<u16>(u16 value) {
    return bswap_16(value);
}

template<>
u32 bswap<u32>(u32 value) {
    return bswap_32(value);
}

template<>
u64 bswap<u64>(u64 value) {
    return bswap_64(value);
}

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

// CMDSET_VM
#define CMD_VERSION 1
#define CMD_CLASSBYSIG 2
#define CMD_ALLCLASSES 3
#define CMD_ALLTHREADS 4 
#define CMD_IDSIZES 7
#define CMD_SUSPEND 8 
#define CMD_RESUME 9 
#define CMD_EXIT 10 

// CMDSET_REFERENCETYPE
#define CMD_METHODS 5

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

    struct PACKED IdSizesResponse {
        u32 fieldIDSize;
        u32 methodIDSize;
        u32 objectIDSize;
        u32 referenceTypeIDSize;
        u32 frameIDSize;
    };

    struct JdwpVersion {
        std::string description;
        u32 jdwpMajor;
        u32 jdwpMinor;
        std::string vmVersion;
        std::string vmName;
    };

    // depends on referenceTypeIDSize;
    template <typename T>
    struct PACKED JdwpClassRef {
        u8 refTypeTag;
        T typeID;
        s32 status;
    };

    // depends on methodIDSize;
    template<typename T>
    struct JdwpMethodRef {
        T methodID;
        std::string name;
        std::string signature;
        u32 modBits; // The modifier bit flags (also known as access flags)
    };

    template <typename RefType, typename MethodType>
    struct PACKED BreakpointRequestEvent {
        /* header */
        u8  eventType;
        u8  suspendPolicy;
        u32 modifiers; // can be only 1, if more we need a different structure
        u8  modKind;

        /* location struct */
        u8 typeTag; 
        RefType classID;
        MethodType methodID;
        u64 location;
    };

    JdwpVersion ParseJdwpVersion(char* buff, ssize_t size) {
        JdwpVersion version = {};
        char* limit = buff + size;

        u32 c = htonl(*(u32*)buff);
        buff += sizeof(u32);
        assert(buff < limit);
        assert(c > 0);

        version.description = std::string(buff, c);
        buff += c;
        assert(buff < limit);

        version.jdwpMajor = htonl(*(u32*)buff);
        buff += sizeof(u32);
        assert(buff < limit);

        version.jdwpMinor = htonl(*(u32*)buff);
        buff += sizeof(u32);
        assert(buff < limit);
        
        c = htonl(*(u32*)buff);
        buff += sizeof(u32);
        version.vmVersion = std::string(buff, c);
        buff += c;
        assert(buff < limit);

        c = htonl(*(u32*)buff);
        buff += sizeof(u32);
        version.vmName = std::string(buff, c);
        buff += c;
        assert(buff <= limit);

        return version;
    }

    class jdwp
    {
    public:

        bool Attach(const std::string &remote) {
            auto p = utils::split(remote, ':');
            std::string host = p.first;
            std::string port = p.second;
            printf("jdwp connecting to remote %s : %s\n", host.c_str(), port.c_str());

            RequestHeader header;
            
            sock_ = socket(AF_INET, SOCK_STREAM, 0);
            if (sock_ < 0) {
                printf("error creating sock_et\n");
                return false;
            }

            struct sockaddr_in serv_addr;
            serv_addr.sin_family = AF_INET; 
            serv_addr.sin_port = htons(std::atoi(port.c_str())); 
            if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) < 0) {
                printf("bad host %s\n", host.c_str());
                return false;
            }

            if (connect(sock_, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
                printf("connection failed \n"); 
                return false;
            }

            printf("net connected.\n");

            if (!Handshake()) {
                printf("error in jdwp Handshake\n");
                return false;
            }

            is_connected_ = true;

            FetchIDSizes();
            FetchVersion();

            SetBreakpoint();

            return true;
        }

        void SetBreakpoint() {
            std::string name = "Lcom/example/myapplication/MyActivity;";
            if (!is_connected_) {
                return;
            }

            if (name.rfind("L") != 0 || name.back() != ';')  {
                printf("bad class name %s\n", name.c_str());
                return;
            }

            // TODO: handle different sizes according to IdSizes
            auto classes = GetClassByName<u64>(name);
            auto methods = GetMethodsForType<u64, u32>(classes[0].typeID);

            for(auto const &value: methods) {
                std::cout << "method: " << value.name << std::endl;
            }

            auto bp_request = BreakpointRequestEvent<u64, u32>();
            bp_request.eventType = 2;                   // BREAKPOINT
            bp_request.suspendPolicy = 2;               // SUSPEND_ALL 
            bp_request.modifiers = bswap_32(1);
            bp_request.modKind = 7;                     // MOD_KIND_LOCATIONONLY
            bp_request.typeTag = 1;                     // CLASS
            bp_request.classID = bswap<u64>(classes[0].typeID);
            bp_request.methodID = bswap<u32>(methods[3].methodID);
            bp_request.location = 0;

            printf("size of bp_request %u\n", sizeof(bp_request));
            auto header = CreatePacket(15, 1, sizeof(bp_request)); // EVENT_REQUEST, CMD_SET
            SendPacket(&header, (void*)&bp_request);

            ssize_t size = 0;
            void* body = ReadReply(&size);
            if (size > 0 && body != nullptr) {
                assert(size == sizeof(u32));
                u32 id = bswap_32(*(u32*)body);
                std::cout << "got request id: " << id << std::endl;
                free(body);

                ResumeVM(); // resume vm and wait for event
            }
        }

    private:
        u32 packet_id = 1;
        JdwpVersion version_;
        IdSizesResponse idSizes_;
        bool is_connected_ = false;
        int sock_ = 0;

        bool Handshake() {
            std::string magic = JDWP_HANDSHAKE;

            send(sock_, magic.c_str(), magic.length(), 0);

            char recv[magic.length() + 1]; 
            ssize_t count = read(sock_, &recv, magic.length());

            std::string response(recv, count);
            if (response == magic) {
                printf("did Handshake, magic %s\n", response.c_str());
                return true;
            }

            return false;
        }

        void FetchIDSizes() {
            RequestHeader header = CreatePacket(CMDSET_VM, CMD_IDSIZES);
            SendPacket(&header);

            ssize_t size = 0;
            void* body = ReadReply(&size);
            if (body != nullptr && size >= sizeof(IdSizesResponse)) {
                memcpy((void*)&idSizes_, body, sizeof(IdSizesResponse));
                idSizes_.fieldIDSize = htonl(idSizes_.fieldIDSize);
                idSizes_.methodIDSize = htonl(idSizes_.methodIDSize);
                idSizes_.objectIDSize = htonl(idSizes_.objectIDSize);
                idSizes_.referenceTypeIDSize = htonl(idSizes_.referenceTypeIDSize);
                idSizes_.frameIDSize = htonl(idSizes_.frameIDSize);
                printf("got ID_SIZES %u %u %u %u %u\n", idSizes_.fieldIDSize, idSizes_.methodIDSize, idSizes_.objectIDSize, idSizes_.referenceTypeIDSize, idSizes_.frameIDSize);
                free(body);
            }
        }

        void FetchVersion() {
            RequestHeader header = CreatePacket(CMDSET_VM, CMD_VERSION); 
            SendPacket(&header);

            ssize_t size = 0;
            void* body = ReadReply(&size);
            if (body != nullptr && size > 0) {
                 version_ = ParseJdwpVersion((char*)body, size);
                 printf("got version %u %u, %s %s %s\n", version_.jdwpMajor, version_.jdwpMinor, version_.vmName.c_str(), version_.description.c_str(), version_.vmVersion.c_str());
                 free(body);
            }
        }

        template <typename T>
        std::vector<JdwpClassRef<T>> GetClassByName(std::string name) {
            std::vector<JdwpClassRef<T>> classes;

            RequestHeader header = CreatePacket(CMDSET_VM, CMD_CLASSBYSIG); 
            SendPacketString(&header, name);
            printf("sent classbysig packet\n");

            ssize_t size = 0;
            void* body = ReadReply(&size);
            void* end = ((char*)body + size);
            printf("got classbysig reply, size: %u\n", size);

            if (size > 0 && body != nullptr) {
                char* buff = (char*)body;
                s32 nb_classes = htonl(*(s32*)buff);
                buff += sizeof(s32); 
                printf("found %d classes\n", nb_classes);

                for (s32 i=0; i< nb_classes; i++) {
                    auto classRef = JdwpClassRef<T>();
                    memcpy(&classRef, buff, sizeof(classRef));
                    classRef.typeID = bswap_64(classRef.typeID);
                    classRef.status = htonl(classRef.status);
                    printf("class %d typeId: %lu status: %d\n", i, classRef.typeID, classRef.status);

                    classes.push_back(classRef);
                    buff += sizeof(JdwpClassRef<T>);
                    assert(buff <= end);
                }

                free(body);
            }

            return classes;
        }

        template <typename RefType, typename MethodType>
        std::vector<JdwpMethodRef<MethodType>> GetMethodsForType(RefType refType) {
            std::vector<JdwpMethodRef<MethodType>> methods;

            RequestHeader header = CreatePacket(CMDSET_REFERENCETYPE, CMD_METHODS, sizeof(RefType));
            RefType ref = bswap<RefType>(refType);

            SendPacket(&header, (void*)&ref);

            printf("sent packet\n");

            ssize_t size = 0;
            void* body = ReadReply(&size);
            void* end = ((char*)body + size);
            printf("got methods for class. reply, size: %u\n", size);

            if (size > 0 && body != nullptr) {
                char* buff = (char*)body;
                s32 nb_classes = htonl(*(s32*)buff);
                buff += sizeof(s32); 
                printf("found %d methods\n", nb_classes);
                for(s32 i=0; i<nb_classes; i++){
                    auto methodRef = JdwpMethodRef<MethodType>();

                    memcpy((void*)&methodRef.methodID, buff, sizeof(MethodType));
                    methodRef.methodID = bswap<MethodType>(methodRef.methodID);
                    buff += sizeof(MethodType);

                    u32 n;
                    memcpy((void*)&n, buff, sizeof(u32));
                    n = bswap_32(n);
                    buff += sizeof(u32);
                    methodRef.name = std::string(buff, n);
                    buff += n;

                    memcpy((void*)&n, buff, sizeof(u32));
                    n = bswap_32(n);
                    buff += sizeof(u32);
                    methodRef.signature = std::string(buff, n);
                    buff += n;

                    memcpy((void*)&methodRef.modBits, buff, sizeof(u32));
                    methodRef.modBits = bswap_32(methodRef.modBits);
                    buff += sizeof(u32);

                    assert(buff <= end);
                    methods.push_back(methodRef);
                }
                free(body);
            }

            return methods;
        }

        void ResumeVM() {
            auto packet = CreatePacket(CMDSET_VM, CMD_RESUME); 
            SendPacket(&packet);
            WaitForReply();
        }

        void WaitForReply() {
            ssize_t size = 0;
            void* buff = ReadReply(&size);
            if (size > 0) {
                free(buff);
            }
            return;
        }

        void* ReadReply(ssize_t *size) {
            ReplyHeader header;
            *size = -1;

            ssize_t count = read(sock_, &header, sizeof(ReplyHeader));
            if (count == 0 && errno != 0) {
                printf("error: %d\n", errno);
                return nullptr;
            }
            printf("got reply header");

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
                read(sock_, data, payload_size);
                /* printf("read %u bytes\n", payload_size); */
                *size = payload_size;
                return data;
            }

            // success without data
            *size = 0;
            return nullptr;
        }

        void SendPacket(RequestHeader* header) {
            send(sock_, (void*)header, sizeof(RequestHeader), 0);
        }

        void SendPacket(RequestHeader* header, void* data) {
            SendPacket(header);
            ssize_t payload_size = bswap_32(header->length) - sizeof(RequestHeader);
            printf("sending body. size: %u\n", payload_size);
            ssize_t count = send(sock_, data, payload_size, 0);
        }

        void SendPacketString(RequestHeader* header, std::string& body) {
            // header
            header->length = bswap_32(sizeof(RequestHeader) + sizeof(u32) + body.length());
            printf("sending total length of %u\n", header->length);
            SendPacket(header);

            // body
            ssize_t bytes = 0;
            u32 body_size = body.length();
            u32 swaped_body_size = bswap_32(body_size);
            bytes += send(sock_, &swaped_body_size, sizeof(u32), 0);
            bytes += send(sock_, body.c_str(), body_size, 0);
            printf("sent body of %u bytes\n", bytes);
        }

        RequestHeader CreatePacket(u8 signal_major, u8 signal_minor) {
            return CreatePacket(signal_major, signal_minor, 0);
        }

        RequestHeader CreatePacket(u8 signal_major, u8 signal_minor, u32 length) {
            printf("CreatePacket major: %u minor: %u length: %u\n", signal_major, signal_minor, length);
            RequestHeader packet = RequestHeader{};
            packet.length = bswap_32(length + sizeof(RequestHeader));
            packet.id = htonl(packet_id);
            packet.flags = 0x00;
            packet.cmdSet = signal_major;
            packet.cmd = signal_minor;
            packet_id += 2;
            return packet;
        }
    };

}
