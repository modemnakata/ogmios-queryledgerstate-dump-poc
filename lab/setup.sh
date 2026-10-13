#!/usr/bin/env bash
# One-time setup for the PoC lab: pulls the preview-testnet cardano-node config
# out of the Ogmios image (which bundles it) and prepares writable dirs.
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] Fetching preview-testnet configuration from the Ogmios image..."
docker run --rm --entrypoint sh \
  -v "$(pwd)/preview:/out" \
  cardanosolutions/ogmios:latest \
  -c 'cd /config/preview && tar cf - cardano-node genesis > /out/preview.tar'

mkdir -p preview
tar xf preview/preview.tar -C preview
rm -f preview/preview.tar

echo "[*] Preparing writable directories..."
mkdir -p data/db data/ipc evidence/dumps
chmod -R 777 evidence data

echo "[*] Done. Now run:  docker compose up -d"
echo "    Wait ~60s for cardano-node to sync and Ogmios to report 'connected':"
echo "      docker logs -f ogmios-poc-ogmios"