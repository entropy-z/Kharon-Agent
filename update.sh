#!/usr/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <AdaptixC2-folder-path>"
    exit 1
fi

ADAPTIX_DIR="$(realpath $1)"

if [ ! -d "$ADAPTIX_DIR" ]; then
    echo "Error: Directory does not exist: $ADAPTIX_DIR"
    exit 1
fi

echo "[+] Pulling latest changes..."
git pull

AGENT="agent_kharon"
LISTENER="listener_kharon_http"

if [ -d "$ADAPTIX_DIR/AdaptixServer/extenders/$AGENT" ]; then
    echo "[+] Removing existing $AGENT folder..."
    rm -rf "$ADAPTIX_DIR/AdaptixServer/extenders/$AGENT"
fi

if [ -d "$ADAPTIX_DIR/AdaptixServer/extenders/$LISTENER" ]; then
    echo "[+] Removing existing $LISTENER folder..."
    rm -rf "$ADAPTIX_DIR/AdaptixServer/extenders/$LISTENER"
fi

echo "[+] Copying new folders..."
cp -r "$AGENT" "$ADAPTIX_DIR"/AdaptixServer/extenders
cp -r "$LISTENER" "$ADAPTIX_DIR"/AdaptixServer/extenders

if [ -d "$ADAPTIX_DIR/dist/extenders/$AGENT/dist" ]; then
    echo "[+] Removing existing folder..."
    rm -rf "$ADAPTIX_DIR/dist/extenders/$AGENT/dist"
fi

cd $ADAPTIX_DIR

echo "[+] Running make..."
make extenders

cp -r "$ADAPTIX_DIR"/AdaptixServer/extenders/agent_kharon/src_beacon "$ADAPTIX_DIR"/dist/extenders/agent_kharon
cp -r "$ADAPTIX_DIR"/AdaptixServer/extenders/agent_kharon/src_loader "$ADAPTIX_DIR"/dist/extenders/agent_kharon

echo "[+] Kharon agent updated"


