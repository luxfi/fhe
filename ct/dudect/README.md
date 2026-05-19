# Lux TFHE -- constant-time analysis harness (dudect)

Empirical constant-time verification of the Lux TFHE hot path
(Encrypt / Decrypt / Bootstrap) using dudect
(https://github.com/oreparaz/dudect).

## CT population

Both dudect classes are **valid** invocations of the routine under
test, differing only in the secret input:

- **Encrypt**: class A = `encrypt(false)`, class B = `encrypt(random bit)`.
- **Decrypt**: class A = `decrypt(pool[0])`, class B = `decrypt(pool[rand])`.
- **Bootstrap**: class A = `pbs(pool[0])`, class B = `pbs(pool[rand])`.

Any timing difference between classes is a real
secret-content-dependent timing in the routine pipeline. This is the
same operational framing as `~/work/lux/pulsar/ct/dudect/` and is
documented in detail there.

## Quick start

```bash
./fetch.sh             # one-time: pulls dudect.h
make                   # builds all three harnesses
./dudect_encrypt       # smoke test (~30s)
./dudect_decrypt       # smoke test (~30s)
./dudect_bootstrap     # smoke test (~5min; PBS is slow)
```

## Full submission run

```bash
DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_encrypt
DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_decrypt
DUDECT_SAMPLES=100000  DUDECT_MAX_BATCHES=100  ./dudect_bootstrap
```

Pin a CPU (`taskset -c 0` on Linux), disable turbo boost, close
background services. Each verify run takes ~12 hours; bootstrap ~24
hours.

## Exit codes

- `0`: VERDICT no leakage detected within budget.
- `2`: VERDICT leakage detected (t-test > 4.5).
- Other: harness setup error.

## Status

This is the **initial** scaffolding for the Tier A track. The
expected verdict for all three routines is "no leakage detected"
because:

- The Lux Go implementation routes through `lattice/v7/core/rlwe`,
  which is BoringSSL-grade CT.
- The C++ production path is `luxcpp/crypto/fhe/cpp/backends/cpu/`
  with CT helpers in `gpu/src/cpu_fhe_helpers.hpp` (mod_add /
  mod_sub / mod_mul / mod_neg are constant-time per
  `~/work/lux/luxcpp/CLAUDE.md`).

The harness is the empirical regression guard for those code paths.

## Citations

- Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?",
  DATE 2017.
- Almeida, Barbosa, Pacheco, Pereira, Pinto, "Verifying
  Constant-Time Implementations", USENIX Security 2016 (BGL leakage
  model).
