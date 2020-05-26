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
#define CMD_SIGNATURE 1

// CMDSET_REFERENCETYPE
#define CMD_METHODS 5

// CMDSET_THREADREFERENCE
#define CMD_THREAD_RESUME 3

// CMDSET_EVENTREQUEST
#define CMD_EVENT_SET 1
#define CMD_EVENT_CLEAR 2 
#define CMD_EVENT_CLEAR_ALL_BREAKPOINTS 3 


// EventKind Constants
#define EVENT_KIND_SINGLESTEP 1
#define EVENT_KIND_BREAKPOINT 2

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
    struct PACKED JdwpLocation {
        u8 typeTag; 
        RefType classID;
        MethodType methodID;
        u64 location;
    };

    template <typename RefType, typename MethodType>
    struct PACKED BreakpointRequestEvent {
        /* header */
        u8  eventKind;
        u8  suspendPolicy;
        u32 modifiers; // can be only 1, if more we need a different structure
        u8  modKind;

        JdwpLocation<RefType, MethodType> loc;
    };

    template <typename ObjectType>
    struct PACKED StepRequestEvent {
        u8  eventKind;
        u8  suspendPolicy;
        u32 modifiers; // can be only 1, if more we need a different structure
        u8  modKind;

        ObjectType threadID;
        u32 size;
        u32 depth;
    };

    struct PACKED ClearEventRequest {
        u8 eventKind;
        u32 requestID;
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

    class Breakpoint 
    {
        public:
            std::string class_name;
            std::string method_name;
            u64 lineno;
    };


    template <typename RefType, typename ObjectType, typename MethodType>
    struct JdwpLocationEvent 
    {
        u32 event_kind;
        u32 request_id;
        ObjectType thread_id;
        JdwpLocation<RefType, MethodType> loc;
    };

    class jdwp
    {
    public:

        bool Attach(const std::string &remote) {
            if(is_connected_) {
                return false;
            }

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

            return true;
        }

        void SetBreakpoint(std::string class_name, std::string method) {
            if (!is_connected_) {
                return;
            }

            auto cls = class_name;
            std::replace(cls.begin(), cls.end(), '.', '/');
            cls = "L" + cls + ";";

            if (cls.rfind("L") != 0 || cls.back() != ';')  {
                std::cout << "bad class name " << cls << std::endl;
                return;
            }

            // TODO: handle different sizes according to IdSizes
            auto classes = GetClassByName<u64>(cls);
            for(auto const &clsRef: classes) {
                auto methods = GetMethodsForType<u64, u32>(clsRef.typeID);
                for(auto const &methodRef: methods) {
                    if (methodRef.name == method) {
                        std::cout << "setting breakpoint to method: " << methodRef.name << " id: " << methodRef.methodID << std::endl;
                        u32 rid = SendBreakpointEvent<u64, u32>(clsRef.typeID, methodRef.methodID);
                        if (rid != 0) {
                            Breakpoint bp;
                            bp.class_name = class_name;
                            bp.method_name = methodRef.name;
                            breakpoints_[rid] = bp;
                        }
                    }
                }
            }
        }

        void StepInstruction() {
            if (!is_connected_ || suspended_thread_id_ == 0) {
                return;
            }

            printf("next instruction thread_id: %u\n", suspended_thread_id_);
            auto thread_id = suspended_thread_id_;

            if (step_request_id_ == 0) {
                u32 req_id = SendSingleStepEvent<u64>(thread_id);
                if (req_id == 0) {
                    return; // error
                }
                step_request_id_ = req_id;
            }

            u32 c = GetSuspendCount<u64>(thread_id);
            for(u32 i=0; i<c; i++) {
                SendResumeThread<u64>(thread_id);
            }

            auto events = _WaitForBreakpoint<u64,u64,u32>();
            std::cout << "events " << events.size() << std::endl;
            for(auto const &e: events) {
               if (e.request_id == step_request_id_) {
                    auto class_name = GetClassName<u64>(e.loc.classID);
                    std::cout << "stepped. line: " << e.loc.location << " class " << class_name << std::endl;

               } 
            }
        }

        void SuspendVM() {
            if(!is_connected_) {
                return;
            }
            auto packet = CreatePacket(CMDSET_VM, CMD_SUSPEND); 
            SendPacket(&packet);
            WaitForReply();
        }

        void Resume() {
            if(!is_connected_) {
                return;
            }
            SendResumeVM();
            printf("resumeVM acked\n");
            suspended_thread_id_ = 0;
            if (step_request_id_ != 0) {
                SendClearEvent(EVENT_KIND_SINGLESTEP, step_request_id_);
                step_request_id_ = 0;
            }
        }

        Breakpoint* WaitForBreakpoint() {
            auto events = _WaitForBreakpoint<u64,u64,u32>();
            for(auto const &e: events) {
                if (e.event_kind == EVENT_KIND_BREAKPOINT) {
                    u32 bp_id = e.request_id;
                    if (breakpoints_.count(bp_id) > 0) {
                        return &breakpoints_[bp_id]; // we own breakpoints so this is ok, still not sure about this.
                    }
                }
            }

            return nullptr;
        }

        template <typename RefType, typename ObjectType, typename MethodType>
        std::vector<JdwpLocationEvent<RefType, ObjectType, MethodType>> _WaitForBreakpoint() {
            std::vector<JdwpLocationEvent<RefType, ObjectType, MethodType>> events;

            // now wait for a breakpoint event
            printf("waiting for breakponint\n");
            ssize_t size = 0;
            void* body = ReadReply(&size);
            printf("got event breakponint\n");


            if (size > 0 && body != nullptr) {
                char* buff = (char*)body;
                char* end = buff + size; 

                u8 suspend_policy = *((u8*)buff);           // 02
                buff += sizeof(u8);

                u32 nb_events = bswap_32(*((u32*)buff));    // 00000001
                buff += sizeof(u32);

                printf("suspend_policy: %u nb_events %u\n", suspend_policy, nb_events);


                for(u32 i=0; i<nb_events; i++) {
                    u8 event_kind = *((u8*)buff);           // 02
                    buff += sizeof(u8);

                    printf("eventkind %u\n", event_kind);

                    if (event_kind == EVENT_KIND_SINGLESTEP || event_kind == EVENT_KIND_BREAKPOINT) {
                        u32 request_id = bswap_32(*((u32*)buff));
                        buff += sizeof(u32);
                        printf("request_id %u\n", request_id);

                        // TODO IDSizes ObjectID
                        u64 thread_id = bswap<u64>(*((u64*)buff));  // 00 00 00  00 00 00 00 02
                        buff += sizeof(u64);

                        JdwpLocation<u64, u32> loc;
                        memcpy((void*)&loc, buff, sizeof(loc));
                        buff += sizeof(loc);

                        loc.classID = bswap<u64>(loc.classID);      // 00 00 00 00 00 00 01
                        loc.methodID = bswap<u32>(loc.methodID);
                        loc.location = bswap_64(loc.location);
                        suspended_thread_id_ = thread_id;

                        JdwpLocationEvent<RefType, ObjectType, MethodType> event; 
                        event.event_kind = event_kind;
                        event.request_id = request_id;
                        event.thread_id = thread_id;
                        event.loc = loc;
                        events.push_back(event);
                    } else {
                        printf("errrrrr!!\n");
                        free(body);
                        return events;
                    }

                    assert(buff <= end);
                }

                printf("%p %p, diff %d\n", buff, end, end-buff);
                assert(buff <= end);
                free(body);
            }

            return events;
        }

    private:
        u32 packet_id = 1;
        JdwpVersion version_;
        IdSizesResponse idSizes_;
        bool is_connected_ = false;
        int sock_ = 0;

        u64 suspended_thread_id_;
        u32 step_request_id_;

        std::map<u32,Breakpoint> breakpoints_;

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
                printf("got ID_SIZES fieldID: %u, methodID: %u, objectID: %u, referenceID: %u, frameID: %u\n", idSizes_.fieldIDSize, idSizes_.methodIDSize, idSizes_.objectIDSize, idSizes_.referenceTypeIDSize, idSizes_.frameIDSize);
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
                 /* printf("got version %u %u, %s %s %s\n", version_.jdwpMajor, version_.jdwpMinor, version_.vmName.c_str(), version_.description.c_str(), version_.vmVersion.c_str()); */
                 free(body);
            }
        }

        template <typename T>
        std::vector<JdwpClassRef<T>> GetClassByName(std::string name) {
            std::vector<JdwpClassRef<T>> classes;

            RequestHeader header = CreatePacket(CMDSET_VM, CMD_CLASSBYSIG); 
            SendPacketString(&header, name);
            /* printf("sent classbysig packet\n"); */

            ssize_t size = 0;
            void* body = ReadReply(&size);
            void* end = ((char*)body + size);
            /* printf("got classbysig reply, size: %u\n", size); */

            if (size > 0 && body != nullptr) {
                char* buff = (char*)body;
                s32 nb_classes = htonl(*(s32*)buff);
                buff += sizeof(s32); 
                /* printf("found %d classes\n", nb_classes); */

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

            /* printf("sent packet\n"); */

            ssize_t size = 0;
            void* body = ReadReply(&size);
            void* end = ((char*)body + size);
            /* printf("got methods for class. reply, size: %u\n", size); */

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

        template <typename RefType>
        std::string GetClassName(RefType ref_type_id) {
            printf("GetClassName ref: %lu sizeof(%u)\n", ref_type_id, sizeof(RefType));

            RefType refTypeId = bswap<RefType>(ref_type_id);
            auto header = CreatePacket(CMDSET_REFERENCETYPE, CMD_SIGNATURE, sizeof(RefType));
            SendPacket(&header, (void*)&refTypeId);
            printf("sent packet\n");

            ssize_t size = 0;
            void* body = ReadReply(&size);
            if (size > 0 && body != nullptr) {
                char* buff = (char*)body;
                u32 length = bswap_32(*(u32*)buff);
                buff += sizeof(u32);
                auto name = std::string(buff, length);
                free(body);
                return name;
            }

            return "";
        }

        template <typename RefType, typename MethodType>
        u32 SendBreakpointEvent(RefType classID, MethodType methodID){
            auto bp_request = BreakpointRequestEvent<RefType, MethodType>();
            bp_request.eventKind = EVENT_KIND_BREAKPOINT;
            bp_request.suspendPolicy = 2;               // SUSPEND_ALL 
            bp_request.modifiers = bswap_32(1);         // number of modifiers
            bp_request.modKind = 7;                     // MOD_KIND_LOCATIONONLY
            bp_request.loc.typeTag = 1;                 // CLASS
            bp_request.loc.classID = bswap<RefType>(classID);
            bp_request.loc.methodID = bswap<MethodType>(methodID);
            bp_request.loc.location = 0;

            auto header = CreatePacket(CMDSET_EVENTREQUEST, CMD_EVENT_SET, sizeof(bp_request)); // EVENT_REQUEST, CMD_SET
            SendPacket(&header, (void*)&bp_request);

            ssize_t size = 0;
            void* body = ReadReply(&size);
            if (size > 0 && body != nullptr) {
                assert(size == sizeof(u32));
                u32 id = bswap_32(*(u32*)body);
                std::cout << "got request id: " << id << std::endl;
                free(body);
                return id;
            }

            return 0;
        }

        template <typename ObjectType>
        u32 SendSingleStepEvent(ObjectType threadID){
            auto step_request = StepRequestEvent<ObjectType>();
            step_request.eventKind = EVENT_KIND_SINGLESTEP;
            step_request.suspendPolicy = 1;         // ONLY THREAD
            step_request.modifiers = bswap_32(1);   // counter
            step_request.modKind = 10;              // MOD_KIND_STEP                     
            step_request.threadID = bswap<ObjectType>(threadID);
            step_request.size = bswap_32(0);        // MIN (instruction and not source line)
            step_request.depth = bswap_32(1);       // STEP OVER

            auto header = CreatePacket(CMDSET_EVENTREQUEST, CMD_EVENT_SET, sizeof(step_request));
            SendPacket(&header, (void*)&step_request);

            ssize_t size = 0;
            void* body = ReadReply(&size);
            if (size > 0 && body != nullptr) {
                assert(size == sizeof(u32));
                u32 id = bswap_32(*(u32*)body);
                std::cout << "got request id: " << id << std::endl;
                free(body);
                return id;
            }
            return 0;
        }

        void SendClearEvent(u8 event_kind, u32 request_id) {
            printf("SendClearEvent! %u %u\n", event_kind, request_id);
            ClearEventRequest body = {}; 
            body.eventKind = event_kind;
            body.requestID = bswap_32(request_id);

            auto header = CreatePacket(CMDSET_EVENTREQUEST, CMD_EVENT_CLEAR, sizeof(body));
            SendPacket(&header, (void*)&body);
            WaitForReply();
        }

        template <typename ObjectType>
        void SendResumeThread(ObjectType threadID) {
            printf("send resume thread\n");
            auto header = CreatePacket(CMDSET_THREADREFERENCE, CMD_THREAD_RESUME, sizeof(ObjectType));
            ObjectType t = bswap<ObjectType>(threadID);
            SendPacket(&header, (void*)&t);
            WaitForReply();
            printf("resume thread acked\n");
            suspended_thread_id_ = 0;
        }

        template <typename ObjectType>
        u32 GetSuspendCount(ObjectType threadID) {
            printf("get suspend count %u\n", threadID);
            auto header = CreatePacket(CMDSET_THREADREFERENCE, CMD_THREAD_RESUME, sizeof(ObjectType));
            ObjectType t = bswap<ObjectType>(threadID);
            SendPacket(&header, (void*)&t);

            ssize_t size = 0;
            void* body = ReadReply(&size);
            if (size > 0 && body != nullptr) {
                assert(size == sizeof(u32));
                u32 suspend_count = bswap_32(*(u32*)body);
                std::cout << "got suspend count " << suspend_count << " for threadid " << threadID << std::endl;
                free(body);
                return suspend_count;
            }

            return 0;
        }

        void SendResumeVM() {
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
            /* printf("got reply header\n"); */

            header.length = bswap_32(header.length);
            header.id = bswap_32(header.id);
            header.errcode = bswap_16(header.errcode);
            /* printf("got reply (%u) id: %u, length: %u, errcode: %u, flags: %u\n", count, header.id, header.length, header.errcode, header.flags); */


            if (header.flags == PACKET_TYPE_REPLY && header.errcode != 0) {
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
            /* printf("sending body. size: %u\n", payload_size); */
            ssize_t count = send(sock_, data, payload_size, 0);
        }

        void SendPacketString(RequestHeader* header, std::string& body) {
            // header
            header->length = bswap_32(sizeof(RequestHeader) + sizeof(u32) + body.length());
            /* printf("sending total length of %u\n", header->length); */
            SendPacket(header);

            // body
            ssize_t bytes = 0;
            u32 body_size = body.length();
            u32 swaped_body_size = bswap_32(body_size);
            bytes += send(sock_, &swaped_body_size, sizeof(u32), 0);
            bytes += send(sock_, body.c_str(), body_size, 0);
            /* printf("sent body of %u bytes\n", bytes); */
        }

        RequestHeader CreatePacket(u8 signal_major, u8 signal_minor) {
            return CreatePacket(signal_major, signal_minor, 0);
        }

        RequestHeader CreatePacket(u8 signal_major, u8 signal_minor, u32 length) {
            /* printf("CreatePacket major: %u minor: %u length: %u\n", signal_major, signal_minor, length); */
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
