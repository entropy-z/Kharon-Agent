     1	.PHONY: all plugin agent beacon clean help
     2	
     3	# Variáveis
     4	GO := go
     5	GOFLAGS := -buildmode=plugin -ldflags="-s -w"
     6	GOEXPERIMENT := jsonv2,greenteagc
     7	DIST_DIR := dist
     8	SRC_SERVER := src_server
     9	SRC_BEACON := src_beacon
    10	
    11	# Arquivos Go do plugin
    12	PLUGIN_FILES := \
    13		$(SRC_SERVER)/pl_lokycrypt.go \
    14		$(SRC_SERVER)/pl_main.go \
    15		$(SRC_SERVER)/pl_agent.go \
    16		$(SRC_SERVER)/pl_packer.go \
    17		$(SRC_SERVER)/pl_utils.go
    18	
    19	# Diretório de saída
    20	PLUGIN_OUT := $(DIST_DIR)/agent_kharon.so
    21	
    22	# Cores para output
    23	COLOR_RESET := \033[0m
    24	COLOR_GREEN := \033[32m
    25	COLOR_YELLOW := \033[33m
    26	COLOR_BLUE := \033[34m
    27	
    28	all: plugin agent
    29	
    30	help:
    31		@echo "$(COLOR_GREEN)Available targets:$(COLOR_RESET)"
    32		@echo "  $(COLOR_YELLOW)make all$(COLOR_RESET)        - Build plugin e agent beacon"
    33		@echo "  $(COLOR_YELLOW)make plugin$(COLOR_RESET)     - Build apenas o plugin agent_kharon"
    34		@echo "  $(COLOR_YELLOW)make agent$(COLOR_RESET)      - Build apenas o agent beacon source"
    35		@echo "  $(COLOR_YELLOW)make beacon$(COLOR_RESET)     - Alias para 'make agent'"
    36		@echo "  $(COLOR_YELLOW)make clean$(COLOR_RESET)      - Remove diretório dist e artifacts"
    37		@echo "  $(COLOR_YELLOW)make help$(COLOR_RESET)       - Mostra esta mensagem"
    38	
    39	plugin: $(PLUGIN_OUT)
    40	
    41	$(PLUGIN_OUT): $(PLUGIN_FILES)
    42		@echo "$(COLOR_BLUE)[*]$(COLOR_RESET) Building agent_kharon plugin..."
    43		@mkdir -p $(DIST_DIR)
    44		@GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build $(GOFLAGS) \
    45			-o $@ \
    46			$^
    47		@echo "$(COLOR_GREEN)[✓]$(COLOR_RESET) Plugin built: $(PLUGIN_OUT)"
    48	
    49	agent: plugin
    50		@echo "$(COLOR_BLUE)[*]$(COLOR_RESET) Building agent_kharon src code (beacon)..."
    51		@$(MAKE) -C $(SRC_BEACON) prebuild-x64 --no-print-directory
    52		@echo "$(COLOR_GREEN)[✓]$(COLOR_RESET) Agent beacon source built"

clean:
    @echo "$(COLOR_YELLOW)[*]$(COLOR_RESET) Cleaning build artifacts..."
    @rm -rf $(DIST_DIR)
    @$(MAKE) -C $(SRC_BEACON) clean --no-print-directory || true
	@echo "$(COLOR_GREEN)[✓]$(COLOR_RESET) Clean complete"

.SILENT: help
