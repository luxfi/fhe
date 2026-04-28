# fhed — FHE Daemon

`fhed` is a self-contained FHE daemon. It owns its own keys, runs the HTTP API,
and never reaches across the network for cryptographic state.

## Two operating modes

There are exactly two modes, selected by `--mode`:

| Mode | Flag | Topology | Decryption |
|------|------|----------|------------|
| Standalone | `--mode standard` | One process, one key set | Local key holder decrypts directly |
| Threshold | `--mode threshold` | t-of-n cluster, mDNS-discovered | Quorum of nodes cooperatively decrypt |

Both modes are network-independent: there is no Lux-mainnet handshake, no
external consensus binding. Standalone mode is the default and is what most
deployments want.

## Standalone (single-node) start

```sh
fhed start \
    --mode standard \
    --http :8448 \
    --data /var/lib/fhed \
    --password "$FHED_PASSWORD"
```

Keys are generated on first start and persisted to encrypted ZapDB at
`<data>/zapdb`. Subsequent starts load from disk. The password is required
in production; if unset, fhed warns and uses a dev default derived from
`nodeID`.

## Threshold (t-of-n) start

```sh
fhed start \
    --mode threshold \
    --threshold 2 \
    --discover \
    --http :8448 \
    --data /var/lib/fhed
```

mDNS discovery (`_fhed._tcp`) bootstraps the cluster on the same LAN. For
production deployments without multicast, supply peers explicitly via the
membership API (planned).

## Smoke test

```sh
go test -tags=integration ./cmd/fhed/... -count=1 -timeout 120s
```

The integration test in `standalone_test.go` builds fhed, starts it on a free
port with a fresh data directory, and round-trips an encrypted bit through
the HTTP API. It verifies that standalone mode boots, generates keys, and
performs encrypt+decrypt without external dependencies.
