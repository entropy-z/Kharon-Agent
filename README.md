# Kharon v0.1

Kharon is a fully PIC agent that operates without a reflective loader and includes evasion features such as sleep obfuscation, heap obfuscation during sleep, stack spoofing with indirect syscalls, BOF API proxy for spoofed/indirect BOF API executions, and AMSI/ETW bypass.

## Modules

Kharon is compatible with the [Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit) and supports its own modules, available in the [PostEx-Arsenal](https://github.com/entropy-z/PostEx-Arsenal).  
Modules can be loaded into the client using the `kh_modules.axs` script.

## Setup

1. Copy `agent_kharon` and `listener_kharon_http` into:
   `AdaptixC2/AdaptixServer/extenders`

2. Inside of AdaptixServer folder run:
   ```
   go work use extenders/agent_kharon
   go work use extenders/listener_kharon_http
   go work sync
   ```

3. Change directory to `AdaptixC2` and run:
   ```make extenders```

4. Copy the `src_beacon` and `src_loader` from the `AdaptixServer/extenders/agent_kharon` to the `dist/extenders/agent_kharon`

5. Set  
   `dist/extenders/agent_kharon/config.json`
   `dist/extenders/listener_kharon_http/config.json`
   in `profile.json`

6. Also update the go.work file inside AdaptixServer folder 
   (the example below only shows for kharon agent, if you have other agents, their folders will also be there)
```
go 1.25.4
use (
        .
        ./extenders/agent_kharon
        ./extenders/listener_kharon_http
)
```
> To update Kharon agent, just run the update.sh file with the root directory of AdaptixC2

Example (profile.json):
```
"extenders": [
  "extenders/beacon_listener_http/config.json",
  "extenders/beacon_listener_smb/config.json",
  "extenders/beacon_listener_tcp/config.json",
  "extenders/beacon_agent/config.json",
  "extenders/gopher_listener_tcp/config.json",
  "extenders/gopher_agent/config.json",
  "extenders/agent_kharon/config.json",
  "extenders/listener_kharon_http/config.json"
]
```

## Supported BOF API Proxy
<details>
<summary>Click to expand</summary>

- VirtualAlloc
- VirtualAllocEx
- WriteProcessMemory
- ReadProcessMemory
- LoadLibraryA
- VirtualProtect
- VirtualProtectEx
- NtSetContextThread
- SetThreadContext
- NtGetContextThread
- GetThreadContext
- CLRCreateInstance
- CoInitialize
- CoInitializeEx

</details>

## Supported Beacon API
<details>
<summary>Click to expand</summary>

- BeaconDataParse
- BeaconDataInt
- BeaconDataExtract
- BeaconDataShort
- BeaconDataLength
- BeaconOutput
- BeaconPrintf
- BeaconAddValue
- BeaconGetValue
- BeaconRemoveValue
- BeaconVirtualAlloc
- BeaconVirtualProtect
- BeaconVirtualAllocEx
- BeaconVirtualProtectEx
- BeaconIsAdmin
- BeaconUseToken
- BeaconRevertToken
- BeaconOpenProcess
- BeaconOpenThread
- BeaconFormatAlloc
- BeaconFormatAppend
- BeaconFormatFree
- BeaconFormatInt
- BeaconFormatPrintf
- BeaconFormatReset
- BeaconFormatToString
- BeaconWriteAPC
- BeaconDripAlloc
- BeaconGetSpawnTo

</details>
