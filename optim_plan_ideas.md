# Loom prover — optimisation plan & ideas

Status: draft, 2026-05-26. All numbers in this document come from `bench/main.go`
(in this repo) running on a 32-core / 32-GOMAXPROCS Linux box with AVX-512,
gnark-crypto v0.20.1, Go 1.26. Workload: 40 aggregated PLONK instances of size
2^17, Poseidon2 leaf hashing.

The goal of this file is to give a coding agent enough context to pick up any
one of these items, work it in isolation, and verify the impact. Each item
includes profile evidence, file:line pointers, the proposed change, and a
verification recipe.

---

## 0. Baseline & reproduction

```
$ go build -o /tmp/loom-bench ./bench
$ /tmp/loom-bench                                # default workload, ~45s wall
$ /tmp/loom-bench -instances N -log2-size L      # tune up/down
$ /tmp/loom-bench -skip-fri                      # to isolate non-FRI work
$ /tmp/loom-bench -hash sha256                   # to swap Merkle hash backend
```

Default run produces:

```
phase           wall    cpu     par     gc%    alloc       peakHeap
traces+modules  2.02s   3.08s   1.52x   7.3%   5.40 GiB    942 MiB
compile         84.2ms  0s      0.00x   0.0%   244 MiB     920 MiB
merge-trace     77 µs   0s      0.00x   0.0%   6.3 KiB     920 MiB
prove           41.98s  45.99s  1.10x   0.1%   12.89 GiB   4.86 GiB
TOTAL           44.08s  49.07s  1.11x   0.6%   18.53 GiB   4.86 GiB
```

Read `par = cpu / wall` as "average cores busy". The headline finding is that
Prove uses **~1 core out of 32** despite parallel primitives existing. Almost
every optimization below either (a) raises that number or (b) reduces work that
would otherwise be parallelised.

The pprof CPU profile referenced throughout lives at
`bench_profiles/cpu_prove.pprof` after a run. Re-render with:

```
go tool pprof -top -cum -nodecount 40 bench_profiles/cpu_prove.pprof
go tool pprof -list <function-name>  bench_profiles/cpu_prove.pprof
go tool pprof -focus <regex> -tree   bench_profiles/cpu_prove.pprof
```

Heap before/after Prove and an allocations profile are written alongside.

### Phase breakdown (cumulative CPU in the profile)

| Phase                       | % of Prove CPU | Notes                                  |
|-----------------------------|----------------|----------------------------------------|
| `ComputeAIRQuotients`       | ~35%           | per-module sequential outer loop       |
| `ExecuteSteps`              | ~12%           | sequential per module, leaf hashing    |
| `commitTraceRound` (in #2)  | ~7%            | Poseidon2 leaf hashing of trace polys  |
| `ComputeDeepQuotient`       | ~6%            | sequential per size, per-elem inverse  |
| `SampleEvaluations`         | ~6%            | sequential per query position          |
| Everything else             | ~34%           | runtime / GC / minor paths             |

### Hottest leaf functions (flat CPU)

| Function (flat %)                                      | Where                              |
|--------------------------------------------------------|------------------------------------|
| `permutation16x24_avx512` 10.0%                        | Poseidon2 batch-16, already SIMD   |
| `extensions.montReduce` 9.95%                          | Every E4.Mul; called from #1, #2   |
| `extensions.E4.Mul` 8.84%                              | Driven by `mulChildVectorIntoExt`  |
| `bitReverseNaive[E4]` 5.28% (+0.58% mem swap)          | See #3                             |
| `vectorButterfly_avx512` 5.04%                         | gnark-crypto FFT, already SIMD     |
| `koalabear.Element.Add` 4.34%                          | Base-field accumulation            |

---

## Top-3 optimisations (high confidence, real numbers)

### #1 — Parallelise the per-module loop in `ComputeAIRQuotients`

**Expected impact:** Up to ~4–5× Prove speedup (this phase is ~35% of CPU and
currently runs at ~1.1× parallelism with 40 independent modules on 32 cores).

**Evidence:**
- `prover/prover.go:420` iterates `for moduleName, module := range pr.program.Modules`
  sequentially. With 40 instances of the bench, there are 40+ modules whose
  AIR quotients are independent.
- pprof tree under `ComputeAIRQuotients` (`go tool pprof -focus=ComputeAIRQuotients -tree`):
  - `poly.ComputeQuotientMixed` — 24.3s cumulative, **26.6% of total Prove CPU**.
  - `dag.EvalOnAllEntriesMixedInto` (`internal/dag/dag.go:1097`) — 24.5s cum.
  - `dag.mulChildVectorIntoExt` (`internal/dag/dag.go:1401`) — 14.0s cum, **15% of total Prove CPU**, scalar Go loop over E4.
- `Total samples = 91.52s` over `Duration: 61.02s` on the 60×2^17 run = ~1.5x
  effective parallelism for the whole Prove; ComputeAIRQuotients dominates.

**Proposed change:**

1. Materialise a deterministic module ordering once:
   ```go
   names := make([]string, 0, len(pr.program.Modules))
   for name := range pr.program.Modules { names = append(names, name) }
   sort.Strings(names)
   ```
2. Wrap the work between `prover.go:420` and `prover.go:472` (i.e. the body
   that produces per-module `airTrace` chunks + populates `chunkDomains`) in
   `internal/parallel.Execute(len(names), func(start, end int) { ... })`.
3. Each goroutine writes into its own pre-allocated `[]ext.E4` / `[]koalabear.Element`
   workspace and into a private `localChunkDomains` and `localAirChunks` map;
   merge under a single mutex (or pre-size the global maps and write disjoint
   keys) after the parallel section.
4. `pr.airTrace.SetBase` / `SetExt` are not safe for concurrent map writes —
   either lock around them, or buffer per goroutine and merge serially in
   <1% time.
5. The downstream "commit by size group" block (`prover.go:474–531`) stays
   serial — it groups across modules and already uses a parallel committer
   internally.

**Watch out for:**
- `pr.domainCache` is shared (`poly.WithDomainCache(&pr.domainCache)`). Check
  `internal/poly/domain_cache.go` for thread-safety; if it isn't safe, either
  give each goroutine its own cache or add an `sync.RWMutex` around it. This
  is the single biggest correctness risk for this change.
- The per-goroutine workspace pool inside `dag.EvalWorkspace`
  (`internal/dag/dag.go:1118-1140`) is currently per-call. If you reuse a
  workspace across modules per goroutine you should also confirm it's reset
  between calls.

**Verification:**
- `go test ./...` must stay green (especially `prover/...` and integration).
- `/tmp/loom-bench` should show `prove`'s `par` jump from ~1.1x toward
  GOMAXPROCS. Even a modest 8x would translate to ~3× Prove speedup.
- `go tool pprof -focus=ComputeAIRQuotients -top` should show `sync.(*WaitGroup).Go.func1`
  cum time rise significantly.

---

### #2 — Batch-invert in `DeepQuotientExt` (and parallelise the per-size loop)

**Expected impact:** 4–8% Prove speedup from the batch invert alone; another
2–4% from parallelising sizes (limited by the small number of distinct sizes,
typically 3–4).

**Evidence:**
- `internal/poly/ext.go:130` — `DeepQuotientExt` does, in a tight loop of N
  iterations:
  ```go
  for j := 0; j < N; j++ {
      var num ext.E4
      num.Sub(&v, &p[j])
      var den ext.E4
      den.Sub(&z, &ω[j])
      var inv ext.E4
      inv.Inverse(&den)           // ← one full E4 inversion per element
      out[j].Mul(&num, &inv)
  }
  ```
- An E4 inversion (Frobenius + base-field inverse + multiplies) is ~10–30×
  the cost of an E4 multiply. The denominators form a vector ideal for
  Montgomery batch inversion: 1 inversion + 3(N-1) multiplies for N elements.
- `ext.BatchInvertE4` already exists and is used at
  `internal/poly/iop_utils.go:375` and `:555` — same pattern.
- `prover.go:612` — `for i, N := range sizes { ... }` is the outer loop over
  distinct module sizes. Each iteration owns its own `deepQuotient` map entry,
  its own RS encoder, its own FRI level tree → trivially independent.
- `prover.go:629` — `C_s := make(poly.ExtPolynomial, N)` is allocated **per
  shift, per size**. For N=2^17, ~20 shifts, ~3 sizes that's ~96 MiB of E4
  churn per Prove (and a contributor to the 12.9 GiB of `prove`-phase
  allocations).

**Proposed change:**

1. In `DeepQuotientExt`:
   - Build `dens[j] = z - ω[j]` into a scratch `[]ext.E4`.
   - Call `ext.BatchInvertE4(dens)` once.
   - Final loop becomes `out[j].Mul(&num, &dens[j])` — single E4 multiply per
     iteration instead of an inversion.
   - Stream-friendly: reuse a scratch buffer across calls via an optional
     argument or a `sync.Pool`.

2. In `ComputeDeepQuotient` (`prover.go:596`):
   - Convert the `for i, N := range sizes` loop body into a closure dispatched
     via `parallel.Execute(len(sizes), ...)`.
   - `deepQuotients` (a `map[int]poly.ExtPolynomial`) is written from disjoint
     keys per iteration → preallocate to `len(sizes)` and write under
     `pr.mu`, **or** swap to `[]poly.ExtPolynomial` indexed by `i` and assemble
     after the parallel section.
   - The inner per-shift work (`prover.go:620–668`) also accumulates into a
     per-size `deepQuotient` — that stays serial within a size, fine.
   - `pr.Proof.DeepQuotientCommitment` and the FRI proving block (`prover.go:709–737`)
     stay serial since `fri.Prove` is invoked once after all level trees are
     built.

3. Bonus, low-effort: reuse `C_s` across shifts. Currently allocated fresh at
   `prover.go:629`; the only operation that writes it is `C_s[x].Add(&C_s[x], &term)`
   inside the `k`-loop, so a zero-on-entry policy + a single allocation per
   size eliminates the per-shift alloc.

**Verification:**
- Existing prover tests cover this end-to-end; if they pass, the batch invert
  is correct.
- Microbench (write a `BenchmarkDeepQuotientExt` in `internal/poly/ext_test.go`
  parameterised on `N`) should show ~5–10× speedup on the function alone.
- `bench_profiles/cpu_prove.pprof` should show `ext.E4.Inverse` cum time drop
  by ~95% and `DeepQuotientExt` flat time shrink to a fraction.

---

### #3 — Stop running `bitReverseNaive` on E4 / E2 polynomials

**Expected impact:** ~5.9% of Prove CPU, ~50 LOC of bit-reverse code, or
**zero work** if you can elide the bit-reverses entirely (see option B).

**Evidence:**
- `utils.bitReverseNaive[E4-shaped]` shows up at **4.83s flat / 5.36s cum =
  5.86% of total Prove CPU**. The function (`gnark-crypto/utils/bitreverse.go:29`)
  is literally a swap-pairs loop — no algorithm.
- `gnark-crypto/utils/bitreverse.go:20` dispatches:
  ```go
  if runtime.GOARCH == "arm64" || len(v) < (1<<21) || unsafe.Sizeof(v[0]) < 8 {
      bitReverseNaive(v)
  } else {
      bitReverseCobra(v)
  }
  ```
  Our quotient FFTs land on `bigSize = eDeg·N`, typically 2^19–2^20 (N=2^17,
  eDeg up to 4–8) — just under the 2^21 cutoff. So even though gnark-crypto
  ships a cache-friendly Cobra variant and specialised `bitReverseCobraInPlace_9_*`
  unrolls, we never reach them.
- Call sites: `internal/poly/compute_quotient.go:128, 131, 301, 304, 392,
  407, 423, 434` and `prover/prover.go:436, 443, 460, 467`.

**Option A — Local fast bit-reverse for E4 (and base):**

Add `internal/poly/bitreverse.go` with a Cobra-style or block-transpose
bit-reverse specialised for `ext.E4` (and likely `koalabear.Element`).
Route all loom call sites through it.

The Cobra threshold is set conservatively in gnark-crypto for arrays with
non-trivial element size — for E4 (16 bytes) and N=2^19 the cache benefit is
real, the threshold could safely come down. Crib the algorithm from
`gnark-crypto/utils/bitreverse.go:128-160` and the `_9_21` family.

**Option B — Eliminate the bit-reverses:**

Several call sites are of the form "FFT (DIF) → BitReverse → … → BitReverse →
FFT (DIT)". When two BitReverses bracket a region with only pointwise
operations, both can be deleted. Inspect:
- `prover.go:435-437` then `:442-443` — `FFTInverseExt(DIF)` → BitReverse →
  chunk → `FFTExt(DIF)` → BitReverse. Either keep everything in bit-reversed
  order or use DIT/DIF pairing carefully.
- `compute_quotient.go:391-407` — same pattern around the coset FFT.

If you can keep polynomials in bit-reversed order between `ComputeQuotient*`
and the per-chunk FFT, you may delete 4 BitReverse calls outright. This is
the loomwide win.

**Verification:**
- Cross-check by running prover_test.go and integration_test — these polys
  feed into Merkle leaves that the verifier re-checks, so any bit-order
  mistake fails the proof.
- Profile: `bitReverseNaive[E4]` should disappear from `pprof -top`.

**Risks:**
- BitReverse interacts with `fft.DIF` vs `fft.DIT` directionality; getting
  the algebra right requires reading `gnark-crypto`'s FFT API. Don't ship
  option B without exhaustive tests.

---

## Secondary opportunities (medium confidence)

These are visible in the profile but harder to size without prototyping.

### #4 — Vectorise `dag.mulChildVectorIntoExt` and friends

**Evidence:** `internal/dag/dag.go:1401` is a scalar Go loop:
```go
for j := range N {
    dst[j].Mul(&dst[j], &src[j])
}
```
This is **15% of Prove CPU** (cumulative including the called E4.Mul). The same
file has analogous `addChildVectorToExt`, `subChildVectorFromExt`,
`copyChildVectorToExt`.

gnark-crypto exposes `extensions.Vector.Mul`, `Vector.MulByElement` (already
shows up at 5.7% via FFT), `Vector.Add`, `Vector.Butterfly` with AVX-512
implementations. Most of those entry points need a third argument shape
(`Vector.Mul(dst, a, b)`); the loom DAG site is `Mul(dst, dst, src)`. Either
adapt the call site to use a scratch buffer, or add an in-place
`Vector.MulSelf(dst, src)` to gnark-crypto.

If a vector entry point cuts this 15% in half, that's ~7% Prove on its own,
**stackable with #1** (parallelising modules just means each module's inner
loop runs on one core; a SIMD inner loop multiplies the per-core throughput).

### #5 — Reuse `EvalWorkspace` across modules (after #1)

`internal/dag/dag.go:1118-1140` has a per-call `basePool` / `extPool`. When #1
lands and modules run in parallel, give each worker goroutine a persistent
`EvalWorkspace` instead of creating one per `EvalOnAllEntriesMixedInto`. This
keeps the slices in the same goroutine's local cache and dodges the allocator
on every coset.

The current `make([]ext.E4, N)` at `dag.go:1138` is allocated `n_nodes × n_cosets`
times per module. With degree ~5 and ~10 cosets per module, that's hundreds
of N-sized E4 slabs in the churn budget per Prove.

### #6 — Parallelise `SampleEvaluations` over query positions

`prover/prover.go:771-786`: NUM_QUERIES (~128) FRI queries, each opening every
committed tree at one position. Currently `for q, s := range pr.queryPositions`
is sequential. Each query owns its own `pr.Proof.PointSamplings[q]` slot — no
data races. `parallel.Execute(NQ, ...)`.

This phase is ~6% of CPU; parallelising should push it to single-digit ms.

### #7 — Parallelise `ExecuteSteps`' `GenCol` loop

`prover.go:365`: `for _, m := range pr.program.Modules { ... gen.Gen(pr.t, &mCopy) }`.
Generators may write to disjoint trace columns, but they share `pr.t` (a
`trace.Trace`); concurrent map writes will race. Requires a per-module
`trace.Trace` produced under the goroutine, then merged. Speculative — confirm
no cross-module data dependencies in `GenCol` before attempting.

### #8 — Poseidon2 `WriteExtBatch` element-by-element absorb

`internal/hash/poseidon2_batch.go`'s `WriteExtBatch` shows up at **7.0s cum =
7.7% of Prove**. It calls `WriteElementBatch` four times per E4 (one per
coefficient). Each `WriteElementBatch` does an `absorbFullBlock` if the sponge
is at capacity. There's probably a vector store / unrolled writer hiding here
— inspect whether you can stage 4 elements at once instead of looping.

Lower confidence: this kernel may already be well-tuned and the time is
fundamental work. But "WriteExt does 4× WriteElement" smells loose.

### #9 — Memory churn: reduce `make([]ext.E4, N)` in inner loops

`prover.go:629`, `prover.go:613`, `prover.go:672` each allocate a per-iteration
N-sized E4 slice. With N=2^17 (= 2 MiB per E4 slice), Prove allocates ~12.9
GiB in total. GC is at 0.1% so the *runtime* cost is negligible — but the
peak heap (4.86 GiB) is driven by these large transient buffers, and Linux
page-fault cost on first-touch is non-zero. Pool / reuse them per Prove run.

This is mostly a memory-footprint win (helpful for running larger workloads
without OOM), not a CPU win.

---

## Things NOT worth optimising (per profile)

- **GC tuning.** 0.1–0.6% of CPU. Already invisible.
- **Poseidon2 permutation kernel.** Already AVX-512 batch-16, near the SIMD
  ceiling.
- **FFT kernels.** `kerDIFNP_512Ext`, `vectorButterfly_avx512` are gnark-crypto
  AVX-512 code — leave alone.
- **`ComputeEvaluationsAtZeta`** (`prover.go:556`). Doesn't even show in top
  40 of pprof. Skip.
- **`merge-trace`**, **`compile`**. 0% and ~0.2% of total wall.

---

## Suggested ordering for a coding-agent campaign

1. **Land #3 Option A** first — small, isolated, low risk, ~6% Prove. Good warmup.
2. **Land #2 batch-invert** — small isolated change in `internal/poly/ext.go`,
   ~5% Prove. Verify with a microbench.
3. **Land #1** (parallelise `ComputeAIRQuotients`) — biggest payoff but most
   careful work (domain-cache thread-safety + per-goroutine workspace). After
   this, re-run the bench and re-profile — the percentage breakdowns will
   shift substantially.
4. **Land #6** while you're in the prover (`SampleEvaluations`).
5. Re-profile. If E4 inner loops are still the leaf cost, do **#4**
   (vector E4 ops in `dag`). Otherwise pick the next-biggest item from the
   refreshed profile.

After 1–4, target should be Prove `par` ≥ 8x on 32 cores and wall time ≤
15s on the default workload.

---

## Open questions for the team

- Is `poly.DomainCache` safe for concurrent reads from multiple goroutines?
  This blocks #1.
- Are `board.Module.GenCol` generators required to be sequential by design,
  or just by current implementation? This blocks #7.
- Why is gnark-crypto's `bitReverseCobra` threshold set at 2^21? Could it be
  lowered upstream for E4-shaped slices (16 bytes/elem) where the cache
  benefit kicks in earlier?
