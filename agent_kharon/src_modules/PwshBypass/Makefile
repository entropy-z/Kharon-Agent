NAME   := amsi_etw_bypass

BUILD_PATH ?= .

CCX64  := clang++ -target x86_64-w64-mingw32
CCX86  := clang++ -target i686-w64-mingw32
ASMCC  := nasm

CFLAGS := -Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20 -fPIC 
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1 -w -mno-sse -s -Wno-error=nested-anon-types
CFLAGS += -ffunction-sections -falign-jumps=1 -falign-labels=1 -mrdrnd -fno-builtin -ffreestanding
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup -masm=intel -fno-exceptions
CFLAGS += -fms-extensions -IInclude -Wl,-TLinker.ld -Wno-error=anonymous-struct

SRC    := $(wildcard Source/*.cc)
OBJ64  := $(SRC:%.cc=%.x64.obj) 
OBJ86  := $(SRC:%.cc=%.x86.obj)

all: amsi etw both

amsi: nasm64 $(OBJ64)
	@ echo "compiling x64 AMSI bypass"
	@ $(CCX64) $(BUILD_PATH)/Bin/obj/*.x64.obj -o $(BUILD_PATH)/Bin/$(NAME).amsi.exe $(CFLAGS) -DPWSH_BYPASS=0x700
	@ objcopy --dump-section .text=$(BUILD_PATH)/Bin/$(NAME).amsi.bin $(BUILD_PATH)/Bin/$(NAME).amsi.exe
	@ rm $(BUILD_PATH)/Bin/$(NAME).amsi.exe

etw: nasm64 $(OBJ64)
	@ echo "compiling x64 ETW bypass"
	@ $(CCX64) $(BUILD_PATH)/Bin/obj/*.x64.obj -o $(BUILD_PATH)/Bin/$(NAME).etw.exe $(CFLAGS) -DPWSH_BYPASS=0x400
	@ objcopy --dump-section .text=$(BUILD_PATH)/Bin/$(NAME).etw.bin $(BUILD_PATH)/Bin/$(NAME).etw.exe
	@ rm $(BUILD_PATH)/Bin/$(NAME).etw.exe

both: nasm64 $(OBJ64)
	@ echo "compiling x64 AMSI+ETW bypass"
	@ $(CCX64) $(BUILD_PATH)/Bin/obj/*.x64.obj -o $(BUILD_PATH)/Bin/$(NAME).both.exe $(CFLAGS) -DPWSH_BYPASS=0x100
	@ objcopy --dump-section .text=$(BUILD_PATH)/Bin/$(NAME).both.bin $(BUILD_PATH)/Bin/$(NAME).both.exe
	@ rm $(BUILD_PATH)/Bin/$(NAME).both.exe

%.x64.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX64) -o $(BUILD_PATH)/Bin/obj/$(notdir $@) -c $< $(CFLAGS) $(DEFS)

%.x86.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX86) -o $(BUILD_PATH)/Bin/obj/$(notdir $@) -c $< $(CFLAGS) $(DEFS)

nasm64:
	@ $(ASMCC) -f win64 Source/Entry.asm -o $(BUILD_PATH)/Bin/obj/start.x64.obj

clean:
	@ rm -f $(BUILD_PATH)/obj/*.x64.obj
	@ rm -f $(BUILD_PATH)/obj/*.x86.obj
	@ rm -f $(BUILD_PATH)/*.exe
	@ rm -f $(BUILD_PATH)/*.Bin
	@ echo "removed object files"