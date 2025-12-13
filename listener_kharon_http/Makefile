.PHONY: all clean help

GO := go
GOFLAGS := -buildmode=plugin -ldflags="-s -w"
GOEXPERIMENT := jsonv2,greenteagc
DIST_DIR := dist
OUTPUT_FILE := $(DIST_DIR)/listener_kharon_http.so
SRC_SERVER := src_server
SOURCE_FILES := \
	$(SRC_SERVER)/pl_lokycrypt.go \
	$(SRC_SERVER)/pl_main.go \
	$(SRC_SERVER)/pl_http.go \
	$(SRC_SERVER)/pl_listener.go \
	$(SRC_SERVER)/pl_utils.go

all: clean
	@ echo "    * Building listener_kharon_http plugin"
	@ mkdir -p $(DIST_DIR)
	@ GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build $(GOFLAGS) -o $(OUTPUT_FILE) $(SOURCE_FILES)
	@ echo "      done..."

clean:
	@ echo "    * Cleaning build artifacts..."
	@if [ -f "$(PLUGIN_OUT)" ]; then \
		rm -f "$(OUTPUT_FILE)"; \
	fi
	@ echo "      done..."