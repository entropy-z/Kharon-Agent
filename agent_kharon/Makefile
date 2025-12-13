.PHONY: all plugin agent beacon clean help

GO := go
GOFLAGS := -buildmode=plugin -ldflags="-s -w"
GOEXPERIMENT := jsonv2,greenteagc
DIST_DIR := dist
SRC_SERVER := src_server
SRC_BEACON := src_beacon

PLUGIN_FILES := \
	$(SRC_SERVER)/pl_lokycrypt.go \
	$(SRC_SERVER)/pl_main.go \
	$(SRC_SERVER)/pl_agent.go \
	$(SRC_SERVER)/pl_packer.go \
	$(SRC_SERVER)/pl_utils.go

PLUGIN_OUT := $(DIST_DIR)/agent_kharon.so

all: clean plugin agent

plugin: $(PLUGIN_OUT)

$(PLUGIN_OUT): $(PLUGIN_FILES)
	@echo "[*] Building agent_kharon plugin..."
	@mkdir -p $(DIST_DIR)
	@GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build $(GOFLAGS) \
		-o $@ \
		$^
	@echo "[✓] Plugin built: $(PLUGIN_OUT)"

agent: plugin
	@echo "[*] Building agent_kharon src code (beacon)..."
	@$(MAKE) -C $(SRC_BEACON) prebuild-x64 --no-print-directory
	@echo "[✓] Agent beacon source built"

clean:
	@echo "[*] Cleaning build artifacts..."
	@if [ -f "$(PLUGIN_OUT)" ]; then \
		rm -f "$(PLUGIN_OUT)"; \
	fi
	@$(MAKE) -C $(SRC_BEACON) clean --no-print-directory || true
	@echo "[✓] Clean complete"

.SILENT: help