# loom prover — next 5 optimisations

Status as of this branch (`perf/all-combined` = `main` + PRs #7 + #8 + #9):

| shape (100M cells) | prove wall | CPU% (~/32 cores) | gap vs Plonky3 |
|---|---|---|---|
| tall  (2²² × 24)    | **5.55 s** | 1184 % (~11.8) | P3 1.56 s → P3 1.15× faster |
| wide  (2¹⁶ × 1536)  | **1.25 s** | 675 % (~6.7)   | P3 0.40 s → **loom 1.4× faster** |

The CPU% line is the headline: we're sitting on ~12 / 32 cores on tall and ~7 / 32 on wide. **Utilisation is the ceiling, not algorithmic work** — every step below targets either a serial-leaning hot path or a missing-SIMD path.

The five steps below come from pprof + execution-trace analysis on `perf/all-combined`. Each is intended as its **own PR**, branched off `perf/all-combined`. They are mostly independent — order matters only for measurement (later steps see less wall-clock if earlier ones already landed). Per-step success criteria use the synth bench shipped in `bench/synth/main.go` (with `-profile-dir`) and the matched Plonky3 binary at `~/dev/rust/Plonky3/target/release/examples/synth_air`.

Throughout, **never delete `bench/synth/main.go` or the `BenchmarkProveWide` / `BenchmarkProveTall` in `prover/bench_deep_quotient_test.go`** — both are how each step's win is observed.

---

## How to measure (read this before opening a PR)

### loom side

```bash
# Build once
go build -o /tmp/loom-synth ./bench/synth

# Wall + phase breakdown — median of 3 is what to report
for i in 1 2 3; do /tmp/loom-synth -log2-rows 22 -repetitions 8   2>&1 | grep -E "prove wall|compute-air|deep-quotient|fri-query|execute-steps|evaluations"; done
for i in 1 2 3; do /tmp/loom-synth -log2-rows 16 -repetitions 512 2>&1 | grep -E "prove wall|compute-air|deep-quotient|fri-query|execute-steps|evaluations"; done

# Wall + CPU% + RSS
/usr/bin/time -v /tmp/loom-synth -log2-rows 22 -repetitions 8

# CPU + heap + execution trace
mkdir -p /tmp/loom-profiles/foo && /tmp/loom-synth -log2-rows 22 -repetitions 8 -profile-dir /tmp/loom-profiles/foo

go tool pprof -nodecount=20 -cum  -top /tmp/loom-profiles/foo/cpu_prove.pprof
go tool pprof -nodecount=20 -flat -top /tmp/loom-profiles/foo/cpu_prove.pprof
go tool pprof -alloc_space -nodecount=20 -cum -top /tmp/loom-profiles/foo/heap_after_prove.pprof
go tool trace -pprof=sched   /tmp/loom-profiles/foo/trace_prove.out  > /tmp/sched.pprof   && go tool pprof -top -cum /tmp/sched.pprof
go tool trace -pprof=syscall /tmp/loom-profiles/foo/trace_prove.out  > /tmp/syscall.pprof && go tool pprof -top -cum /tmp/syscall.pprof
```

### Plonky3 side (apples-to-apples)

```bash
# Already built; if not:
cd ~/dev/rust/Plonky3 && cargo build --release --example synth_air

# Same shape parameters
for i in 1 2 3; do (cd ~/dev/rust/Plonky3 && ./target/release/examples/synth_air --log-rows 22 --repetitions 8)   | grep "prove wall"; done
for i in 1 2 3; do (cd ~/dev/rust/Plonky3 && ./target/release/examples/synth_air --log-rows 16 --repetitions 512) | grep "prove wall"; done

# Wall + CPU% + RSS
/usr/bin/time -v ./target/release/examples/synth_air --log-rows 22 --repetitions 8
```

P3 numbers may drift run-to-run by 2–5 %. Always re-take a fresh baseline in the same session before reporting a delta — system load matters.

### Reference numbers (baseline on `perf/all-combined`, 32-core AMD EPYC 9R45)

Use these as the "before" line in each PR description. Re-take them on the agent's host first to verify the box matches.

| shape | loom wall | loom CPU% | P3 wall |
|---|---|---|---|
| tall (2²² × 24, 100M cells)   | 5.55 s | 1184 % | 1.56 s |
| wide (2¹⁶ × 1536, 100M cells) | 1.25 s | 675 %  | 0.40 s |
| tall (2²⁰ × 8 — report shape) | 1.36 s | ~700 % | 1.52 s |
| wide (2¹⁴ × 512 — report shape)| 0.29 s | ~600 % | 0.40 s |

Tall phase mix today:
```
compute-air-quotients    2.29 s   41 %
deep-quotient+fri-commit 1.03 s   19 %
fri-query-open           0.83 s   15 %   <-- serial; step 2
execute-steps            0.80 s   14 %
evaluations-at-zeta      0.45 s    8 %
```

Wide phase mix today:
```
compute-air-quotients    0.85 s   68 %   <-- still mostly bound by ext-DAG eval; step 4
execute-steps            0.18 s   14 %
fri-query-open           0.10 s    8 %
deep-quotient+fri-commit 0.07 s    5 %
evaluations-at-zeta      0.06 s    5 %
```

### What "done" looks like for every PR

1. `go test ./...` clean (also `-race ./prover/ ./internal/poly/ ./internal/merkle/`).
2. Phase wall on the targeted shape moves the expected direction; total prove wall moves at least as much as the expected fraction of the phase.
3. `go tool pprof -flat -top cpu_prove.pprof` no longer lists the previously-dominant symbol at the top of the affected phase (or it's dropped by the expected factor).
4. PR description includes: before/after table for **both** shapes, `pprof -top` excerpt before and after, and the matched-shape Plonky3 number.

---

## Step 1 — Batch Poseidon2 internal-node hashing

**Leverage**: by far the biggest. On tall, `permutation16_avx512` is **53 % of total CPU** (36.7 s out of 69 s sampled across 5.5 s wall). Pprof peek:

```
permutation16_avx512  ←  Poseidon2MDHasher.compress
                      ←  Poseidon2NodeHasher.HashNode   (100 % of calls come from here)
                      ←  merkle.Tree.buildInternalNodes.func1
```

For a 2²³-leaf tree, that's ~16 M internal-node hashes, each taking 2 scalar `permutation16_avx512` calls. SIMD already exists for **leaves** (`permutation16x24_avx512`, 16-lane batched) but **nodes** still go one-at-a-time through the MD hasher.

**Files**:
- `internal/merkle/tree.go` — `buildInternalNodes` (line 99), `NodeHasher` interface (line 31), `parallelLevelThreshold` (line 25).
- `internal/commitment/commitment.go` — `Poseidon2NodeHasher.HashNode` (line 183), `NodeHasher` interface (line 57), and the **existing** `BatchLeafHasher` / `hashLeavesBatchParallel` pattern (line 51, 271) — copy it.
- `internal/hash/poseidon2.go` — `Poseidon2MDHasher` (line 11), `Poseidon2SpongeBatch16` (line 38, ← model the new batched node hasher on this).
- `internal/commitment/hash_backend.go` — also has `SHA256NodeHasher` (line 146). The interface extension must remain optional so SHA-256 still works without a batched path.

### Approach A (recommended): keep the MD protocol, add a batched MD compression

Mirror the leaf-side `BatchLeafHasher` / `hashLeavesBatchParallel` pattern node-side. Concretely:

1. In `internal/merkle/tree.go`, add an optional interface:
   ```go
   // BatchNodeHasher hashes `batchSize` (left,right) pairs at once into dst.
   // Implementations are free to require a power-of-two batch size; the
   // tail (fewer than BatchSize() pairs at the last level) falls back to
   // HashNode.
   type BatchNodeHasher interface {
       NodeHasher
       BatchSize() int
       HashNodes(dst []hash.Digest, left, right []hash.Digest)
   }
   ```
2. In `(t *Tree) buildInternalNodes`, type-assert `t.nodeHasher` to `BatchNodeHasher`. If present, build the level in batched chunks (rounded down to `BatchSize()` and a scalar tail). If absent (SHA-256), keep the current scalar path. The outer `parallel.ExecuteWithThreshold` over the level can wrap the batched-chunk loop.
3. In `internal/commitment/commitment.go`, make `Poseidon2NodeHasher` implement `BatchNodeHasher`. The batched implementation lives in `internal/hash/poseidon2.go` as `Poseidon2MDHasherBatch16` — a 16-lane transposed MD hasher analogous to the existing `Poseidon2SpongeBatch16`. There is **no** batched `permutation16` exposed by gnark-crypto. Two options:
   - Use `permutation16x24_avx512` (already used by `Poseidon2SpongeBatch16`) and re-architect the node hash to use the *width-24 sponge* with one rate-16 absorb of `left ‖ right` (drop the domain-tag for nodes, or include it in capacity). This costs 1 perm per node instead of 2 *and* enables 16-lane SIMD. **This changes the on-the-wire node hash**, so the proof binary is incompatible with anything that exists today; bump `HASH_BACKEND_DOMAIN_TAG` in `internal/constants`.
   - Add a new batched width-16 perm in gnark-crypto (modelled after `permutation16x24_avx512`) and call it from a width-16 batched MD hasher. No protocol change, but requires an upstream patch in `gnark-crypto`. Out of scope for one PR.

   Recommend **option (a)**: width-24 sponge for nodes, batched. The cost of a wider state is more than paid back by avoiding the second perm and getting SIMD. Coordinate the protocol bump with the verifier and any deployed setups.

### Approach B (smaller, if approach A is too invasive): pack the existing scalar perm into the parallel.Execute fan-out at a finer granularity

Today `parallel.ExecuteWithThreshold(start, parallelLevelThreshold, ...)` over a level already runs the goroutines, but each goroutine still calls scalar `permutation16_avx512`. Lowering `parallelLevelThreshold` won't help — the issue is the *per-permutation* cost, not the fan-out granularity.

So approach B alone gives **nothing**. Only useful as a fallback for hash backends that have no batched path (SHA-256).

### Pitfalls

- The verifier's `merkle.Verify` (tree.go line 133) walks the path with `HashNode`. After the protocol change it must use the new compression function. Tests in `internal/commitment/commitment_test.go` lines 120 + 171 (`TestRSCommitBatchLeafHasherMatchesScalarRoot`, `TestPoseidon2BatchLeafHasherMatchesScalarLeaves`) are templates for the corresponding node-side tests.
- `parallelLevelThreshold = 64` (line 25) was tuned for the scalar path. With batching, the per-level fixed cost includes the gather/transpose; revisit the threshold.
- Domain separation: leaves currently absorb `leafDomainTag` (commitment.go line 27, `0x4c454146`), nodes absorb `nodeDomainTag` (0x4e4f4445). If switching to the unified sponge perm, keep the tag (or capacity-encode it) to maintain domain separation.
- The tree-root commitment is bound to the Fiat-Shamir transcript via `ts.Bind`. If we change the node hash function we don't break the transcript per se (the digest type is unchanged), but the resulting root values differ — re-derive any committed test vectors.

### Expected impact

If approach A lands and SIMD-scales the way leaves do, the 53 % flat collapses to ~5 % flat. **Tall wall**: 5.55 s → ~3.3–3.6 s. CPU% should rise from 1184 → ~1700 %. Wide wall barely moves (node hashing is only ~5 % there).

### Test plan

- `go test ./internal/merkle ./internal/commitment ./internal/fri ./prover` (the FRI level trees and the commitment tree both flow through this code).
- Add `TestPoseidon2BatchNodeHasherMatchesScalarHash` next to the existing leaf test: build a tree with a `Poseidon2NodeHasher` (scalar) vs a `BatchNodeHasher` (batched); roots must match.
- Cross-version: take a small fixed input, dump root with the old and new node hash, store as a fixture so any future regression on the protocol value is caught.
- `-race ./internal/merkle`.

### Benchmark plan

```bash
# After landing, in order
go test -bench='^BenchmarkProveTall$' -benchtime=3x ./prover/
/tmp/loom-synth -log2-rows 22 -repetitions 8
go tool pprof -flat -top /tmp/loom-profiles/foo/cpu_prove.pprof | head -10
# Plonky3 baseline:
(cd ~/dev/rust/Plonky3 && ./target/release/examples/synth_air --log-rows 22 --repetitions 8)
```

Report: tall wall before/after, `permutation16_avx512` flat % before/after, CPU% before/after, P3 wall same shape.

---

## Step 2 — Parallelise `SampleEvaluations` across queries

**Leverage**: small for wide (~100 ms / 8 %), notable for tall (~830 ms / 15 %). Best leverage-per-LOC of the five — the diff is tiny.

Pprof says `SampleEvaluations` is **1.13 % of CPU on tall but 15 % of wall** — exactly one core busy, ~830 ms. Plenty of headroom.

**Files**:
- `prover/prover.go` — `SampleEvaluations` (line 979). Outer loop is `for q, s := range pr.queryPositions` then `for i, tree := range pr.allTrees`.
- `prover/opening_source.go` — `commitmentOpeningSource.rawLeaf` (line 59) and helpers (`evalBaseOnRoot`, `evalExtOnRoot`, `weightsForRoot`). These are stateless given a `*poly.DomainCache`.
- `prover/prover.go:1050` is the timing site for the `fri-query-open` phase.

### Approach

The two loops are fully independent across `(q, i)` — each call writes to a disjoint slot in `pr.Proof.PointSamplings[q][i]`. Two ways to chunk:

1. **Outer-only**: `parallel.Execute(NQ, ...)` over queries. Simplest. Caps fan-out at `NumQueries=4` — not great on 32 cores but already 4× over today.
2. **Flat 2-D**: build a flat list of `(q, i)` pairs (length `NQ × NumTrees`) and `parallel.Execute` over it. Better fan-out at the cost of one more allocation.

Prefer (2) — `NumQueries × NumTrees` is typically 4 × 4–8 = 16–32, which matches NumCPU well.

`weightsForRoot` (opening_source.go line 105) caches Lagrange weights in a `map[weightKey][]koalabear.Element` — a plain map. **That cache is read-mostly inside `rawLeaf`** and currently single-threaded. The parallel version needs to either (a) make the map safe (e.g. `sync.Map`, or precompute once before the parallel loop), or (b) pass a per-goroutine cache. Recommend **(a) with precompute**: scan the trees once before the parallel loop, populate the map serially with every `(size, rootIndex)` that will be needed, then read-only access in the parallel loop. This avoids both the lock and the cache-miss serialisation that the parallel approach would otherwise exhibit.

`*poly.DomainCache` is already internally locked, so concurrent reads through it are fine.

### Pitfalls

- `pr.Proof.PointSamplings` is allocated up front (`NQ` slots), and we write `pr.Proof.PointSamplings[q] = samplings` after each query's inner loop completes. Don't write the outer slot from inside an inner goroutine without coordination.
- Verify the existing `Proof` accessors don't assume FS-order of writes; pre-allocate the inner slice once, write `[q][i]` from the worker.
- `s mod tree.NumLeaves()` is deterministic per `(q, i)` — no global state changes.

### Expected impact

Tall `fri-query-open` 830 ms → ~150 ms. Total tall wall 5.55 s → ~4.9 s. Wide barely moves.

### Test plan

- `TestVanishingRelationsAndLogupBus` (prover/prover_test.go) and the gnark_plonk integration tests exercise the whole Prove→Verify chain — if the openings are in wrong order or wrong content, Verify will fail.
- `-race ./prover` is the critical check.

### Benchmark plan

Same as step 1, but the headline number is `fri-query-open` from the phase breakdown.

---

## Step 3 — Pool `reedsolomon.Encoder.Encode` buffers

**Leverage**: largest single contributor to wide allocation pressure. Heap alloc_space:
```
reedsolomon.(*Encoder).Encode               1.55 GB (52 % of wide allocs)
```
Visible in CPU as 12 % `runtime.memclr` / `memmove`. On tall, `Encoder.Encode` allocations are smaller as a share but the absolute volume is still significant (it's called once per base-poly column per round).

**Files**:
- `internal/reedsolomon/rs.go` — `Encoder.Encode` (line 62) and `EncodeExt` (line 86). Both `make(poly.Polynomial, N)` once per call.
- `internal/commitment/commitment.go:208–222` — the `parallel.Execute` over base/ext polys is where Encode is invoked per-poly.
- `internal/poly/polynomial.go` — already has a `getBuf` / `putBuf` sync.Pool for base. There's an ext counterpart in `internal/poly/ext.go` (`getExtBuf`/`putExtBuf`).

### Approach

The encoder's returned slice is *owned by the caller* — `commitment.Commit` reads it later when building leaves. So we can't naively `putBuf` inside `Encode`. Two options:

1. **Hand the buffer back to the caller at end of commit phase**. After `commitment.Commit` builds the tree, the encoded slices are still needed for `SampleEvaluations` (raw leaf reconstruction). They are released only when Prove returns. So a `sync.Pool` doesn't fit naturally.
2. **Reuse the input as the output**. The `Encode` path is: copy `p` into `_p` (size N), do FFT-inverse on the first `n` slots, scatter-bit-reverse to N slots, FFT to evaluate. The output is a *fresh* slice every call. We could instead require callers to provide an output buffer:
   ```go
   func (encoder *Encoder) EncodeInto(dst, p poly.Polynomial, d *fft.Domain, fftOpts ...fft.Option)
   ```
   Callers in `commitment.Commit` already build `encodedBase := make([]poly.Polynomial, len(basePolys))` and assign per-index — they could instead reuse a long-lived `[]poly.Polynomial` cache keyed by `(N, polyIdx)` on the prover runtime. The prover-runtime field `domainCache` is a natural sibling; add an `encodeBufCache` that hands out + recycles `[]koalabear.Element` / `[]ext.E4` of size N.

Recommend **option 2** with a `sync.Pool` per `N` rooted on the prover runtime:

```go
type proverRuntime struct {
    ...
    encodeBufBase sync.Pool // []koalabear.Element of size encoderDomain.Cardinality
    encodeBufExt  sync.Pool // []ext.E4              of same size
}
```

The encoder takes a `[]koalabear.Element` of the encoder-domain size as a parameter (allocated once by the caller, reused between rounds). The buffer is returned only once the consumer (`buildLeaves` / `SampleEvaluations`) is done — and `SampleEvaluations` runs after all FRI/sampling work, so the natural release point is just before Prove returns.

A simpler intermediate step is to **clear in place** instead of `make`-ing. The `_p := make(poly.Polynomial, N)` zero-fill is cheap but the GC churn is what costs us — pooled `[]Element` returned to the pool with no clearing avoids both.

### Pitfalls

- The pool grows unbounded if not careful. Cap with a max-keep-size knob, or rely on Go's `sync.Pool` GC-based eviction (default is reasonable here since RSS pressure only shows up in long benchmarks).
- Stale data: `Encode` does `copy(_p, p)` and then `scatterBitReversedCoeffs` does in-place rewrite; the zero-padding `_p[n:N]` is **only** correct if the buffer starts zeroed in those slots or `scatter` clears as it goes. Look at `scatterBitReversedCoeffs` in `internal/reedsolomon/rs.go:39` carefully — the current code writes `p[i] = zero` for stride-internal slots, so the tail past `i*stride` may *not* be cleared. With `make()` we got a fresh zero buffer; with a pool we don't. **Either**: extend `scatterBitReversedCoeffs` to clear all needed slots, or memclr the tail on pool checkout. Add a unit test that calls `Encode` twice on the same pooled buffer with different inputs and checks the second result.

### Expected impact

Wide wall 1.25 s → ~1.05–1.10 s (a 12–15 % drop, mostly from removing `memclr` / `memmove` in `runtime`). Tall is less sensitive.

### Test plan

- `TestRSEncoderEncodeReusesBuffer`: pool a buffer, encode poly A, then encode poly B into the same buffer, compare with a fresh-allocation encode.
- `go test -race ./internal/reedsolomon ./internal/commitment` — the pool is per-prover-runtime, but the `parallel.Execute` over polys still hits it concurrently.
- All existing commitment tests should still pass.

### Benchmark plan

Same shapes. Watch:
- `prove wall`
- `go tool pprof -flat -top /tmp/loom-profiles/wide/cpu_prove.pprof` — `runtime.memclrNoHeapPointers` should drop from ~7 % to <1 %.
- `go tool pprof -alloc_space -cum -top /tmp/loom-profiles/wide/heap_after_prove.pprof` — `Encoder.Encode` alloc_space should drop from 1.55 GB to ~0.

---

## Step 4 — AIR-quotient `EvalOnAllEntriesMixedInto` row-chunked parallelism

**Leverage**: largest remaining single phase on wide (68 % of wall, ~850 ms). Also material on tall (~2.3 s / 41 %).

Pprof on wide (within `compute-air-quotients`):
```
ComputeQuotientMixed                            830 ms  (8.6 % of total CPU)
└── EvalOnAllEntriesMixedInto                   508 ms  (already pure CPU)
    └── evalExtNodeOnAllEntries                 ~280 ms
```

**Files**:
- `internal/poly/compute_quotient.go` — `ComputeQuotient` (line 56) and `ComputeQuotientMixed` (line 218 today on `perf/all-combined`, after the step-1 changes).
- `internal/dag/dag.go` — `EvalOnAllEntriesMixedInto` (line 1133). The outer loop is `for _, n := range d.Nodes` (line 1181), serial across nodes. *Inside* each node, the work is a row-vector evaluation: `evalBaseNodeOnAllEntries(dst, n, baseVec, PiBase, N, ...)` / `evalExtNodeOnAllEntries(...)`. These operate over `N` rows.

### Approach

Per-DAG-node work cannot be reordered (nodes depend on prior nodes), but each node's *N-row inner loop* is embarrassingly parallel — every row's value depends only on the same row of every input column.

Inside `evalBaseNodeOnAllEntries` and `evalExtNodeOnAllEntries`, wrap the per-row loop in `parallel.Execute(N, func(start, end int) { ... })`. The outer per-node loop stays serial; the inner row sweep saturates the CPUs.

Sketch (for `evalExtNodeOnAllEntries`):
```go
parallel.Execute(N, func(start, end int) {
    for i := start; i < end; i++ {
        // existing per-row body for node n
    }
})
```

The `allocBase` / `releaseBase` / `allocExt` / `releaseExt` closures in `EvalOnAllEntriesMixedInto` (lines 1154–1176) are not concurrency-safe — they mutate `ws.basePool` / `ws.extPool`. **But these allocators run in the outer (serial) loop, not the inner row loop**, so they don't need changes. Verify this by reading the body of `evalExtNodeOnAllEntries` (look for any pool calls inside the per-row sweep — if found, the parallel chunk must use a goroutine-local scratch).

The same restructure applies to `EvalOnAllEntries` (base-only) at line 999 — `ComputeQuotient` (base-only `compute_quotient.go`) calls it identically.

### Pitfalls

- Some DAG nodes may have very cheap per-row bodies (e.g. one Mul). `parallel.Execute(N, ...)` will spawn many goroutines for each tiny node which costs more than it saves. **Use `parallel.ExecuteWithThreshold(N, threshold, ...)` instead** — with `threshold = 1 << 12` (matching `quotientParallelThreshold` in `compute_quotient.go`). This is the pattern step 1 already established for the per-element divide.
- The existing per-poly FFT loops in `ComputeQuotientMixed` cap inner FFT parallelism via `parallel.NbTasksPerJob` (step 1 of PR #7). If we now also fan out the DAG eval, we're nesting parallel.Execute calls. Each `parallel.Execute` call defaults to `NumCPU` goroutines. The outer DAG-eval loop is serial, so the *inner* (row chunk) parallel.Execute can use all NumCPU — no nesting conflict.
- `vals := make([]ext.E4, N)` in `ComputeQuotientMixed` (line 345 on `perf/all-combined`) is per-iteration. Today `EvalOnAllEntriesMixedInto(vals, ...)` writes into `dst[0..N]`. The parallel version writes to disjoint indices — safe.

### Expected impact

Wide wall 1.25 s → ~0.7–0.9 s (dropping AIR-quot phase from 850 ms to maybe 300–400 ms). Tall wall ~5.55 s → ~4.8 s. After this step, wide is no longer AIR-bound — `permutation16x24_avx512` (the batched leaf hasher) takes over as the next ceiling.

### Test plan

- Existing tests in `internal/dag` and `internal/poly` exercise both code paths via the prover end-to-end.
- Add `TestEvalOnAllEntriesMixedIntoParallelMatchesSerial`: generate a random Pi map, evaluate twice (once with the parallel path, once with `GOMAXPROCS=1` forcing serial), compare element-wise.
- `-race ./internal/dag ./internal/poly ./prover`.

### Benchmark plan

Same shapes. Watch `compute-air-quotients` phase wall (median of 3). On wide, expect 850 ms → 350 ms. Take a fresh `pprof -flat -top` — `evalExtNodeOnAllEntries` should drop from 6 % of CPU to ~1 %.

---

## Step 5 — Share precomputed `zeta` powers in `EvaluateAtExt`

**Leverage**: smallest of the five. ~10 % of CPU on tall, ~6 % on wide. Cheap to do; do it last when other phases have collapsed and this becomes a larger fraction.

Pprof:
```
poly.EvaluateAtExt   flat 10.3 % (tall), 5.6 % (wide)
└── ext.(*E4).Mul    flat ~3 %
└── Element.Mul      ~2 %
```

The hot loop is the Horner evaluation in `EvaluateAtExt` (and `ExtEvaluateAtExt`) — `internal/poly/ext.go:85` + line 109. Each evaluation does `n` E4 multiplies of running `res` by `zeta`, then adds the coefficient.

**Files**:
- `internal/poly/ext.go` — `EvaluateAtExt`, `ExtEvaluateAtExt`. The signature already accepts `fftOpts ...fft.Option` (step 2 PR #8).
- `prover/prover.go` — `ComputeEvaluationsAtZeta` (line 597 area). It calls `EvaluateAtExt` once per (column, eval-point) pair. For chunk evaluations, every call uses `pr.zeta` directly — `n` is the same for many calls.
- For shifted (rotated) columns, the eval point is `zeta · ω^shift`, so it differs per column. But within a single shift there are often many columns at the same eval point. Group them.

### Approach

Two related optimisations:

1. **Precompute `zeta^j` once per shift**, share across all columns evaluated at that shift. Today each `EvaluateAtExt` re-derives the chain via Horner (`res = res*zeta + coeff`). If `zPow[j] = zeta^j` is precomputed (size N), evaluation becomes `res = Σ_j zPow[j] · coeff_j`, an inner product. That's still `n` ext-muls but the inner product can use the vectorised `ext.Vector.InnerProductByElement` (and friends in gnark-crypto) which is SIMD-accelerated.
2. **Lift the FFT-inverse out of `EvaluateAtExt`** in the bulk case. Today each call does `d.FFTInverse(_p, fft.DIF, fftOpts...)` on a length-`n` copy of the input. The input poly never changes across calls — we copy because the FFT mutates. If the bulk caller (`ComputeEvaluationsAtZeta`) knows it'll call `EvaluateAtExt` once on each column, it can call FFTInverse once per poly (in parallel), then evaluate at every required `zeta_i` from the canonical coefficients. For a single shift this is just a refactor; for K shifts it amortises the FFT cost K-fold.

Recommend (1) first (smaller diff). For (2), the trace + chunk path uses `zeta` directly (no shifts), so the FFT-inverse on each base poly could be done once at trace-commit time and cached. But this is essentially what `prover.evalBaseOnRoot` already does on the verifier-open side — see `prover/opening_source.go`. Worth following up after (1) lands.

### Approach (1) sketch

```go
// In ComputeEvaluationsAtZeta, before launching the parallel.Execute(len(tasks), ...):
// Precompute, per distinct (n, zeta) pair seen across tasks, a zPow slice of length n.
// E4 is the field; one inner-product call per task is the new hot loop.

type zPowKey struct { n int; zeta ext.E4 }
zPows := map[zPowKey][]ext.E4{}
for _, t := range tasks {
    k := zPowKey{n: len(t.basePoly | t.extPoly), zeta: t.evalPoint}
    if _, ok := zPows[k]; !ok {
        zPows[k] = buildZetaPowers(k.zeta, k.n)
    }
}
// Then the parallel.Execute body becomes a Vector.InnerProductByElement (base) or
// InnerProduct (ext) call against the precomputed zPows[k]. Drop the per-task FFT-inverse.
```

Note: today `EvaluateAtExt` does **inverse FFT then Horner**. The Horner is at evaluation in canonical (coefficient) form. With precomputed `zPow` the evaluation is `Σ coeff_j · zPow[j]` over canonical coefficients — same arithmetic, but vectorised. The FFT-inverse is still needed (the input is in Lagrange normal form). If two tasks share `(n, FFT-domain, polynomial)` (they don't — distinct polys), we could share the FFT-inverse output; but the win is from sharing `zPow` across many polys at the same `zeta_i`, not from sharing FFTs.

### Pitfalls

- The cache key is `(n, zeta)` — `ext.E4` is comparable in Go (it's a struct of `Element`s), but verify with a `_ = map[zPowKey]int{}` compile check.
- `buildZetaPowers` itself is `O(n)` serial — for `n = 2²²` that's 4M ext-muls (~50 ms single-threaded). If multiple distinct zetas appear, parallelise the build via chunked seeding (use `poly.PowUint64` from step 1 of PR #7 — already on `perf/all-combined`).
- Memory: one `[]ext.E4` of length N per distinct zeta. For tall N=2²², ~64 MB per buffer × 1–2 zetas = small.

### Expected impact

Modest. `evaluations-at-zeta` phase drops by maybe 20–30 % once the FFT-inverse is no longer the dominant cost (the inner product is much faster than Horner). Tall wall 5.55 s → ~5.4 s. Mostly worth doing after steps 1+2+4 have landed and this phase is a larger fraction.

### Test plan

- `TestEvaluateAtExtMatches` comparing the inner-product path to the existing Horner path on random inputs.
- The integration tests cover the prover end-to-end.

### Benchmark plan

Same shapes; watch `evaluations-at-zeta` phase wall + `EvaluateAtExt` flat % in pprof.

---

## Where this puts us vs Plonky3

Realistic projections, assuming steps 1–4 land. Step 5 is decoration.

| | today (`perf/all-combined`) | +step 1 | +step 2 | +step 3 | +step 4 | P3 |
|---|---|---|---|---|---|---|
| tall wall | 5.55 s | ~3.5 s | ~3.4 s | ~3.3 s | ~3.0 s | 1.56 s |
| wide wall | 1.25 s | 1.20 s | 1.15 s | 1.05 s | ~0.65 s | 0.40 s |
| tall CPU% | 1184 % | ~1700 % | ~1900 % | ~1900 % | ~2100 % | 2526 % |
| wide CPU% | 675 % | 700 % | 720 % | 850 % | ~1500 % | 2646 % |

Tall ceiling after these four steps is `permutation16x24_avx512` (batched leaf + batched node hashing combined) + the FRI commit-phase fold loops. To close the rest of the gap with P3 would need either:
- a real algorithmic change (e.g. matching P3's lower-degree-rate FRI fold tree), or
- per-thread CPU efficiency work (loop nests, allocations inside hot loops).

Wide ceiling after these four steps is `permutation16x24_avx512` for trace-commit leaves. At that point loom is **probably faster than P3 on every shape** but `compute-air-quotients` for very wide traces will still dominate until either:
- the constraint evaluation is rewritten to amortise common subexpressions across rows (compile-time), or
- the DAG evaluator is row-tile-blocked to keep the working set in L1.

Both are deep changes; not in scope here.

---

## House rules for the agent picking this up

- **One step = one PR**. Don't bundle. Each PR's review surface stays under ~300 LOC if possible.
- **Branch off `perf/all-combined`** (this branch, not pushed). Each PR can be opened against `main` and rebased on top of merged predecessors once #7/#8/#9 land.
- **Re-take baselines** on the host before reporting deltas. The numbers in the table above are from a 32-core EPYC 9R45; an agent host may have different SIMD throughput, NUMA, or background load.
- **Don't change protocol values silently**. Step 1 approach A flips the node hash function — that's a deliberate protocol bump, mention it in the PR title and bump `HASH_BACKEND_DOMAIN_TAG` so downstream picks it up.
- **Don't ship perf claims without `-race ./prover ./internal/...`** on the modified packages.
- **Don't add `bench/synth-foo` variants** — extend the existing one with new flags if a shape needs it. The bench surface is intentionally narrow.
- **Don't keep `prover/bench_evals_test.go`** — it was a step-2 artefact; step-3's `bench_deep_quotient_test.go` already exposes `BenchmarkProveWide`/`BenchmarkProveTall`. (Already dropped on `perf/all-combined`.)
