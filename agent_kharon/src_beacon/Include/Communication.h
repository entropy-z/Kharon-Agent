#include <Win32.h>

#define KH_SOCKET_CLOSE 10
#define KH_SOCKET_NEW   20
#define KH_SOCKET_DATA  30

typedef struct {
    PVOID   Buffer;
    size_t  Length;
    size_t  Size;
    BOOL    Encrypt;
    CHAR*   TaskUUID;
} PACKAGE, *PPACKAGE;

typedef struct {
    PCHAR   Original;
    PCHAR   Buffer;
    UINT32  Size;
    UINT32  Length;
} PARSER, *PPARSER;

struct _SMB_PROFILE_DATA {
    CHAR* SmbUUID;
    CHAR* AgentUUID;
    
    HANDLE Handle;

    PACKAGE* Pkg;
    PARSER*  Psr;

    _SMB_PROFILE_DATA* Next;
};

enum class Base64Action {
    GET_SIZE,
    ENCODE,
    DECODE
};

typedef _SMB_PROFILE_DATA SMB_PROFILE_DATA;
