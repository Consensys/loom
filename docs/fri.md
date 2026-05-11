# FRI in loom

This document explains the FRI-based polynomial commitment layer implemented in `loom`: the mathematics, the public API, and how the code realizes the protocol.

The intended audience is someone who already knows IOPs, Reed-Solomon codes, FFT-based polynomial representations, and ordinary FRI, but wants to understand the exact protocol implemented here, including the role of the DEEP quotient and the multi-degree batching logic.

## Executive Summary

At a high level, `loom` does **not** commit every trace polynomial directly into one monolithic FRI instance. Instead it does the following:

1. It commits trace columns and setup columns with a Merkleized Reed-Solomon encoding, grouped by polynomial size.
2. It computes AIR quotient chunks for each module and commits those too.
3. It samples an out-of-domain point `zeta`.
4. It builds, for each distinct module size `N`, a **DEEP quotient polynomial** that combines:
   - all shifted trace columns of that size that appear in AIR relations, and
   - all AIR quotient chunks of that size.
5. It Reed-Solomon encodes each per-size DEEP quotient and proves low degree with a **multi-degree FRI** protocol.
6. It separately opens all original commitments at the FRI query locations, and the verifier reconstructs the DEEP quotient pointwise to check that the FRI layer really matches the committed trace and AIR data.

The important conceptual split is:

- `internal/fri` implements the FRI protocol itself, including a multi-degree batching mechanism.
- The "DEEP" part lives outside `internal/fri`, in `prover.ComputeDeepQuotient` and `verifier.checkFRIBridge`.

So the end-to-end polynomial commitment scheme is best read as:

$$
\text{AIR / trace commitments} \;+\; \text{DEEP-ALI-style quotienting} \;+\; \text{FRI backend}.
$$

It is **not** that `internal/fri` itself is a DEEP-FRI implementation in isolation.

## FRI as a Polynomial Commitment Scheme

Before talking about `loom` specifically, it is worth isolating what FRI contributes when one uses it as a PCS backend.

### FRI is natively a low-degree proximity test

Strictly speaking, plain FRI is not "first and foremost" an evaluation-opening protocol. Its native statement is:

> given oracle access to a function $f : L \to \mathbb{F}$, prove that $f$ is close to the Reed-Solomon code of degree-`<D` polynomials on the evaluation domain $L$.

Equivalently, FRI is a protocol for proving that a committed codeword is consistent with a low-degree polynomial.

That distinction matters because a polynomial commitment scheme typically exposes an interface closer to:

- `Commit(p)` -> commitment
- `Open(p, z)` -> value $v = p(z)$ plus proof
- `Verify(commitment, z, v, proof)` -> accept / reject

Plain FRI directly addresses the "is this codeword low degree?" part. To turn that into a PCS, one adds:

1. a **binding commitment** to the evaluation vector, usually a Merkle root, and
2. a **reduction from evaluation claims to low-degree claims**, usually by quotienting.

That is exactly the architecture used in STARK-style systems, and it is exactly the architecture used in `loom`.

### The code-family view

Fix:

- a field $\mathbb{F}$,
- an evaluation domain $L = \{x_0, \dots, x_{N-1}\}$,
- and a degree bound $D < N$.

The Reed-Solomon code is

$$
\mathrm{RS}_{L,D} = \{ (p(x_0), \dots, p(x_{N-1})) \mid \deg p < D \}.
$$

So committing to a polynomial via FRI really means committing to a codeword in $\mathrm{RS}_{L,D}$, or at least claiming that the committed oracle is in, or close to, that code.

### The commitment layer: Merkleized codewords

To use FRI non-interactively, the prover first commits to the evaluation vector

$$
c = \big(f(x_0), \dots, f(x_{N-1})\big)
$$

by Merkle-hashing it.

In textbook FRI, the commitment is often described as a Merkle tree over the full vector. In `loom`, the leaves are paired as:

$$
\big(f(x), f(-x)\big),
$$

because the fold relation always consumes opposite points together. So the Merkle root binds the prover to a single oracle on the whole domain while making opposite-point openings efficient.

This gives the usual binding story:

- after publishing the root, the prover is committed to one codeword,
- later Merkle openings authenticate the specific values used in the FRI checks.

### What a FRI proof actually proves about that commitment

If the prover commits to a codeword $c$, then a FRI proof says, informally:

> the committed codeword is consistent with repeated random folds of a low-degree codeword, all the way down to a tiny terminal oracle.

The proof does **not** say, by itself:

> this polynomial evaluates to $v$ at an arbitrary point $z \notin L$.

That second statement needs a separate reduction.

### Turning FRI into an evaluation-opening PCS

Suppose the verifier wants to check an off-domain claim

$$
v \stackrel{?}{=} p(z),
\qquad
z \notin L.
$$

The standard reduction is to define

$$
q(X) = \frac{v - p(X)}{z - X}.
$$

If $v = p(z)$, then the numerator vanishes at $X=z$, so $q$ is a polynomial and

$$
\deg q < \deg p.
$$

If $v \neq p(z)$, then $q$ is not a polynomial at all; it is merely a rational function with a pole at $z$.

That means the verifier can reduce the evaluation claim to a low-degree claim:

1. prove that the committed oracle for $q$ is low degree using FRI,
2. query the original commitment for $p(X)$ and the quotient commitment for $q(X)$ at random domain points $X$,
3. check the identity

$$
q(X) (z - X) = v - p(X).
$$

This is the core reason FRI can act as a PCS backend.

For in-domain points $z \in L$, quotienting is unnecessary: a Merkle opening of $p(z)$ is enough. Quotienting is needed precisely for the out-of-domain openings that dominate STARK/AIR verification.

### Where `loom` fits in that picture

`loom` implements exactly that reduction, but in a richer batched form:

- it does not build a quotient for a single polynomial,
- it batches many shifted trace columns and AIR quotient chunks together,
- it does so separately for each polynomial size,
- and then it uses multi-degree FRI as the low-degree backend.

So, in "FRI as PCS" language, `loom` is best understood as:

$$
\text{Merkleized RS commitments}
\;+\;
\text{batched quotient reduction}
\;+\;
\text{multi-degree FRI proximity proof}.
$$

## Notation and Representation Conventions

### Fields and domains

The code is currently specialized to the Koalabear field:

- field type: `koalabear.Element`
- FFT domains: `github.com/consensys/gnark-crypto/field/koalabear/fft`

For a module of size `N`, let:

$$
H_N = \{ \omega_N^0, \omega_N^1, \dots, \omega_N^{N-1} \}
$$

be the size-`N` multiplicative subgroup used as that module's trace domain.

`loom` uses a fixed Reed-Solomon blowup factor

$$
\rho = \texttt{RATE} = 4
$$

from `internal/constants/const.go`.

So a degree-`<N` polynomial associated with a size-`N` module is committed by evaluating it on a size-`\rho N` domain.

### Polynomial basis

One of the most important implementation conventions is:

- **trace columns are stored in Lagrange form**
- **AIR quotient chunks are converted back into Lagrange form before commitment**
- **FRI layers are handled as evaluation vectors**

This is why functions like `poly.Evaluate`, `poly.DeepQuotient`, `reedsolomon.Encoder.Encode`, and `commitment.RSCommit.Commit` all take Lagrange-form polynomials as their input.

### Opposite-point pairing

Both the Merkle commitment layer and the FRI layer pair evaluations at opposite points:

$$
x \quad \text{and} \quad -x.
$$

For a vector of length `M`, leaf `i` of the paired Merkle tree contains:

$$
(f(x_i), f(-x_i)).
$$

In the code this is implemented by pairing entry `i` with entry `i + M/2`, because on a power-of-two subgroup:

$$
\omega^{i + M/2} = -\omega^i.
$$

This pairing is built in:

- generic commitment trees: `internal/commitment/commitment.go`
- FRI level trees: `internal/fri/fri.go`, `buildTree`

## Where FRI Sits in the Prover and Verifier

The prover path in `prover.Prove` is:

1. `ExecuteSteps`
2. `ComputeAIRQuotients`
3. `ComputeEvaluationsAtZeta`
4. `ComputeDeepQuotient`
5. `SampleEvaluations`

The verifier path in `verifier.Verify` is:

1. `deriveChallenges`
2. `computePublicColumns`
3. `computeLagrange`
4. `checkLogupBus`
5. `checkAIRRelations`
6. `checkFRIProof`
7. `checkMerkleProofsPointSampling`
8. `checkFRIBridge`

The last three steps are the FRI-backed PCS verification:

- `checkFRIProof` checks low degree of the DEEP quotient commitments.
- `checkMerkleProofsPointSampling` authenticates the original column/AIR openings.
- `checkFRIBridge` connects those openings back to the DEEP quotient values used by FRI.

## Step 1: AIR Quotients

Each compiled module has a folded AIR relation `VanishingRelation` in `board.CompiledModule`.

If a module has size `N` and row-wise constraint polynomial $V_M(X)$, the intended algebraic statement is:

$$
V_M(x) = 0 \quad \forall x \in H_N.
$$

Equivalently,

$$
X^N - 1 \;\mid\; V_M(X).
$$

So there exists a quotient polynomial $Q_M(X)$ such that

$$
V_M(X) = (X^N - 1) Q_M(X).
$$

### How the prover computes it

`prover.ComputeAIRQuotients` calls:

- `poly.ComputeQuotient(trace, vanishingRelation, N)`

`poly.ComputeQuotient` evaluates the numerator on a coset-extended domain to avoid division by zero on $X^N-1$, divides pointwise, and returns the quotient in **coset-Lagrange** form. The prover then converts it back:

1. coset-Lagrange -> ordinary Lagrange: `poly.CosetLagrangeToLagrangeNormal`
2. Lagrange -> coefficient form via IFFT
3. split into chunks of size `N`
4. each chunk -> Lagrange form again for commitment

If the quotient has degree larger than `N`, the code writes it as:

$$
Q_M(X) = \sum_{c=0}^{t-1} X^{cN} Q_{M,c}(X),
\qquad \deg Q_{M,c} < N.
$$

Each `Q_{M,c}` becomes one committed AIR chunk, named by:

```go
constants.QuotientChunkName(moduleName, c)
```

### How the verifier checks it

The verifier reconstructs

$$
Q_M(\zeta) = \sum_{c=0}^{t-1} \zeta^{cN} Q_{M,c}(\zeta)
$$

in `verifier.checkAIRRelations`, and checks

$$
V_M(\zeta) = (\zeta^N - 1) Q_M(\zeta).
$$

This is the standard out-of-domain AIR check.

## Step 2: Sampling `zeta`

`zeta` is the final out-of-domain evaluation point used to evaluate:

- AIR quotient chunks
- all trace columns needed by AIR relations
- later, the DEEP quotient construction

In the prover:

- AIR roots are bound to `__zeta` inside `ComputeAIRQuotients`
- then the transcript derives `zeta`

In the verifier:

- the same AIR roots are rebound in `deriveChallenges`
- then the transcript recomputes the same `zeta`

Challenge name:

```go
constants.FINAL_EVALUATION_POINT == "__zeta"
```

## Step 3: Evaluating Columns at `zeta` and `zeta * omega^shift`

If an AIR relation references:

- an unshifted column `A(X)`, the prover evaluates it at `zeta`
- a rotated column `A(omega^s X)`, the prover evaluates it at

$$
\zeta_s = \zeta \cdot \omega_N^s.
$$

This happens in `prover.ComputeEvaluationsAtZeta`.

The results are stored in:

```go
proof.Proof.ValuesAtZeta
```

Keying convention:

- plain column: `leaf.String() == "A"`
- rotated column by `s`: `leaf.String() == "A_shift_s"`

The verifier then extends the same map with the values it can derive on its own from:

- Fiat-Shamir challenges
- public input columns
- Lagrange selector columns

and uses it in `checkAIRRelations` and `checkFRIBridge`.

## Step 4: DEEP Quotients

This is the core DEEP-ALI-like step in `loom`.

### Distinct sizes are handled separately

Modules may have different base sizes. The prover first groups everything by size using:

- `prover.BuildDeepQuotientLayout`

For each distinct size `N`, it constructs one DEEP quotient polynomial

$$
DQ_N(X).
$$

The sizes are ordered in decreasing order.

### The ordering matters

The verifier must reconstruct exactly the same linear combinations as the prover, so the code uses a shared deterministic layout:

- sizes: decreasing `N`
- within a size:
  - shifts: increasing
  - within a shift: columns sorted by `leaf.String()`
- AIR chunks: sorted by `(moduleName, chunkIndex)`

This ordering is encoded by `prover.DEEPquotientLayout`.

### DEEP quotient from shifted trace columns

Fix a size `N`. For each shift `s` that occurs among AIR leaves of that size, the prover gathers all columns with that shift and forms a random-looking linear combination:

$$
C_{N,s}(X) = \sum_i a^{e_{s,i}} C_{s,i}(X),
$$

where:

- the $C_{s,i}$ are the relevant columns of size `N`,
- the exponents $e_{s,i}$ are assigned in the deterministic traversal order,
- `a` is the batching scalar used in `ComputeDeepQuotient`.

Then it evaluates that combination at:

$$
z_s = \zeta \cdot \omega_N^s,
\qquad
v_{N,s} = C_{N,s}(z_s),
$$

and forms the quotient

$$
DQ_{N,s}(X) = \frac{v_{N,s} - C_{N,s}(X)}{z_s - X}.
$$

If the claimed evaluation $v_{N,s}$ is correct, then the numerator vanishes at $X=z_s$, so the quotient is a polynomial and its degree is one less than the degree of $C_{N,s}$.

### DEEP quotient from AIR chunks

For the AIR quotient chunks of size `N`, the prover forms one more linear combination:

$$
A_N(X) = \sum_j a^{e'_j} Q_{N,j}(X),
\qquad
u_N = A_N(\zeta),
$$

and then

$$
DQ^{air}_N(X) = \frac{u_N - A_N(X)}{\zeta - X}.
$$

Here the $Q_{N,j}$ are the AIR quotient chunks of size `N`, pooled across all modules of that size.

### Final per-size DEEP quotient

The prover adds all those quotients:

$$
DQ_N(X) = \sum_s DQ_{N,s}(X) + DQ^{air}_N(X).
$$

This is the object whose low degree will be proven by FRI.

### Important nuance: this is DEEP-ALI-style, not "DEEP inside FRI"

The quotienting above happens in:

- `prover.ComputeDeepQuotient`
- `verifier.checkFRIBridge`
- helper: `poly.DeepQuotient`

The `internal/fri` package itself never computes:

$$
\frac{f(z)-f(X)}{z-X}.
$$

It only receives already-constructed evaluation vectors and proves low degree of those vectors.

## Step 5: Reed-Solomon Encoding and Size Levels

For each per-size DEEP quotient $DQ_N$, the prover Reed-Solomon encodes it from size `N` to size `RATE * N`.

This is done by:

```go
encoder := reedsolomon.NewEncoder(uint64(constants.RATE) * uint64(N))
encoded := encoder.Encode(deepQuotients[N], domainBySize[N])
```

That encoded vector is then committed with a paired Merkle tree:

```go
tree, err := pr.friParams.BuildLevelTree(encoded)
```

The resulting level is stored as:

```go
fri.Level{
    D:     N,
    Evals: [][]koalabear.Element{encoded},
    Trees: []*merkle.Tree{tree},
}
```

In current `loom`, each size contributes exactly **one** polynomial to FRI, but `internal/fri` is more general and supports multiple polynomials introduced at the same degree level.

## Step 6: Multi-Degree FRI

Before discussing `loom`'s multi-degree extension, it helps to spell out the standard single-codeword FRI protocol that `internal/fri` is implementing.

### Standard single-degree FRI, in PCS form

Fix an evaluation domain $L_0$ of size $N_0$, degree bound $D_0$, and a codeword

$$
A_0 : L_0 \to \mathbb{F}
$$

purporting to be the evaluation of some polynomial of degree `< D_0`.

The prover commits to $A_0$ with a Merkle root. Then FRI proceeds by repeated folding.

#### Even/odd decomposition

Any polynomial $P_j(X)$ can be written uniquely as

$$
P_j(X) = G_j(X^2) + X H_j(X^2).
$$

If $A_j$ is the evaluation of $P_j$ on a multiplicative subgroup, then values at opposite points satisfy

$$
P_j(x) = G_j(x^2) + x H_j(x^2),
\qquad
P_j(-x) = G_j(x^2) - x H_j(x^2).
$$

So one can recover:

$$
G_j(x^2) = \frac{P_j(x)+P_j(-x)}{2},
\qquad
H_j(x^2) = \frac{P_j(x)-P_j(-x)}{2x}.
$$

FRI samples a challenge $\beta_j$ and defines the next polynomial

$$
P_{j+1}(Y) = G_j(Y) + \beta_j H_j(Y).
$$

Its degree is roughly half that of $P_j$. Evaluated pointwise, that is exactly the fold relation used in the code:

$$
A_{j+1}(x^2)
=
\frac{A_j(x)+A_j(-x)}{2}
+ \beta_j \frac{A_j(x)-A_j(-x)}{2x}.
$$

This is the heart of `foldLayer` and of the per-round consistency checks in `checkQueryB`.

#### Why the domain halves

At round `j`, the oracle lives on a multiplicative subgroup $L_j$ of size $N_j$. Because the fold maps $(x,-x)$ to $x^2$, the next oracle naturally lives on the squared domain

$$
L_{j+1} = \{ x^2 : x \in L_j \},
$$

whose size is $N_j/2$.

So each FRI round simultaneously:

- halves the evaluation domain size,
- and halves the degree bound.

#### What the proof contains

For a single codeword, a non-interactive FRI proof contains:

1. the Merkle roots of the intermediate folded oracles,
2. the final tiny oracle, sent explicitly,
3. for each sampled query:
   - the authenticated opposite-point pair at every round,
   - enough information to check the fold relation recursively.

That is exactly the structure of `internal/fri.Proof`:

- `FRIRoots`
- `FinalPoly`
- `FRIQueries`

The initial root is supplied externally by the caller because, in a PCS integration, the caller usually already committed to the level-0 oracle before invoking FRI.

#### What a single query checks

If the verifier samples an outer query index $s$, it reduces it modulo the paired-leaf count at each round. At round `j`, the verifier learns the authenticated pair

$$
\big(A_j(x), A_j(-x)\big)
$$

for the corresponding domain point $x$, and checks:

1. the Merkle authentication path is valid,
2. folding those two values with $\beta_j$ yields the next-round value,
3. after the final round, the recursively folded value matches the explicit terminal oracle.

So one FRI query is not "open one point once"; it is "open one opposite-point pair per round, and verify a whole recursive chain of fold identities."

### Why this is a PCS check rather than just a local identity check

The Merkle layer matters because it prevents adaptive cheating across rounds. Without commitments, a dishonest prover could answer each query with freshly invented values satisfying the local fold identities. With commitments:

- the round-`j` values are bound by the round-`j` Merkle root,
- the same root is what the transcript used when sampling $\beta_j$,
- and all rounds are linked by the recursive fold identities.

This is the reason the combination "Merkleized oracle + random folds + random queries" constitutes a polynomial commitment backend rather than merely a consistency gadget.

### The parameterization used by `loom`

The outer FRI instance is created once from the largest module size:

$$
D_0 = \max_M N_M,
\qquad
N_0 = \rho D_0.
$$

That is exactly how `newProverRuntime` and `newVerifierRuntime` call:

```go
fri.NewParams(int(constants.RATE)*maxN, maxN, constants.NUM_QUERIES, ...)
```

So inside `internal/fri`:

- `Params.D = D_0` is the degree bound for the largest level polynomial
- `Params.N = N_0 = rho * D_0` is the largest encoded domain size
- `numRounds = log2(D_0)`

The final FRI polynomial therefore has length:

$$
\frac{N_0}{D_0} = \rho.
$$

With the current constants, that means `FinalPoly` has length `4`.

### Ordinary FRI fold

If a round-`j` committed layer is $A_j$, defined on a domain of size $N_j$, the code folds values at $x$ and $-x$ into a value on $x^2$:

$$
A_{j+1}^{pre}(x^2)
=
\frac{A_j(x) + A_j(-x)}{2}
\;+\;
\beta_j \cdot \frac{A_j(x) - A_j(-x)}{2x}.
$$

This is the standard FRI step obtained by writing

$$
A_j(X) = g_j(X^2) + X h_j(X^2)
$$

and then defining

$$
A_{j+1}^{pre}(Y) = g_j(Y) + \beta_j h_j(Y).
$$

In the code:

- fold challenge: `fri_fold_j`
- implementation: `internal/fri/fri.go`, `foldLayer`

To avoid symbol clash with the DEEP batching scalar, this document writes the fold challenge as $\beta_j$, even though the code stores it in `alphas[j]`.

### Multi-degree batching

Suppose the DEEP quotient levels have degree bounds

$$
D_0 > D_1 > \dots > D_t
$$

with each $D_\ell$ a power of two dividing $D_0$.

Level $\ell$ is introduced at round

$$
j_\ell = \log_2(D_0 / D_\ell).
$$

This is exactly the code in:

```go
jl := log2(p.D / levels[l].D)
```

Why this works: after `j` folds, the largest encoded domain has shrunk from $\rho D_0$ to

$$
\rho D_0 / 2^j.
$$

When $j = j_\ell$, this equals $\rho D_\ell$, which is the encoded length of the smaller level polynomial. So at that round, the smaller level lives on the same domain size as the running FRI polynomial and can be batched in pointwise.

### The running polynomial

Let $L_\ell(X)$ denote the encoded DEEP quotient polynomial for level $\ell$.

The running polynomial evolves as follows:

1. Start with the largest level:

$$
A_0 = L_0.
$$

2. At round $j > 0$, if one or more new levels are introduced there, batch them in:

$$
A_j = A_j^{pre} + \sum_i \gamma_j^{i+1} L_{j,i}.
$$

In current `loom`, there is only one polynomial per size level, so the inner sum is trivial, but `internal/fri` supports several.

3. Commit to $A_j$, derive fold challenge $\beta_j$, and fold to produce the next pre-batched layer.

The per-level batching challenges are transcript names:

- `fri_level_<l>_gamma`

and are derived from the Merkle roots of the level polynomials being introduced.

### What is actually stored in the proof

`internal/fri.Proof` stores:

- `FRIRoots`: the running roots for rounds `1..r-1`
- `FinalPoly`: the final explicit evaluation vector
- `FRIQueries`: query paths for the running polynomial
- `LevelQueries`: query openings for extra level polynomials

It does **not** store the level roots. Those are passed separately to `fri.Verify`.

At the `loom` level, those roots come from:

```go
proof.Proof.DeepQuotientCommitment
```

### Soundness intuition

At a high level, FRI soundness comes from three facts.

#### 1. Bad codewords tend not to stay low degree under random folds

If an oracle is far from every degree-`<D` polynomial, then writing it as

$$
f(X) = g(X^2) + X h(X^2)
$$

does not magically make both pieces low degree. A random challenge $\beta$ mixes the even and odd parts so that an adversarial high-degree component is unlikely to disappear round after round.

#### 2. Commitments freeze every round before the next challenge is sampled

The verifier does not let the prover choose $\beta_j$ first and only then decide what round-`j` oracle to pretend to have committed to. The root is bound into the transcript first, so the prover is stuck with a specific oracle before seeing the next folding challenge.

#### 3. Query repetition drives the residual error down

One query only checks one recursive path. Multiple independent queries force the prover to maintain consistency on multiple random locations. This is why `Params.NumQueries` is the explicit soundness knob in `internal/fri`.

This is only an intuition sketch, not a formal bound, but it is the right mental model for why the protocol works.

### Standard FRI, DEEP-FRI, and DEEP-ALI

These three ideas are related but not identical.

#### Standard FRI

Standard FRI proves that a committed oracle is close to a Reed-Solomon codeword by repeated random folding over the evaluation domain.

That is the core protocol implemented in `internal/fri`.

#### DEEP-FRI

DEEP-FRI strengthens the low-degree test itself by additionally using out-of-domain information to improve proximity soundness. In a DEEP-FRI presentation, the "DEEP" step is part of the low-degree test proper.

`loom`'s `internal/fri` package does **not** implement that stronger variant directly.

#### DEEP-ALI

DEEP-ALI applies the out-of-domain quotient idea one layer above FRI: first compress AIR / trace consistency claims into quotient polynomials using `zeta`, then feed those quotient polynomials to a FRI backend.

That is the role played in `loom` by:

- `ComputeEvaluationsAtZeta`
- `ComputeDeepQuotient`
- `checkFRIBridge`

So the codebase is best described as:

- standard multi-degree FRI in `internal/fri`,
- plus a DEEP-ALI-style quotient reduction around it.

## Step 7: Query Generation

Each query samples an index

$$
s \in \{0, \dots, N_0/2 - 1\}
$$

because each Merkle leaf already contains the pair $(x, -x)$.

For the running FRI polynomial, round `j` opens:

$$
\text{base}_j = s \bmod (N_j / 2).
$$

For a smaller size level `N`, the same outer query is reduced to:

$$
s_N = s \bmod (\rho N / 2).
$$

This is why the prover opens:

- FRI query path: `openQuery`
- original trace/AIR commitments: `SampleEvaluations`

using the same outer `s` but reduced by each tree's paired-leaf count.

## Step 8: The Commitment Layer and the FRI Bridge

The FRI proof only says:

> these encoded DEEP quotient vectors are low degree.

It does **not** by itself say:

> these vectors came from the committed trace columns and AIR chunks.

That second statement is exactly what `checkFRIBridge` proves.

### Commitment format

The main Merkleized polynomial commitment is `commitment.WMerkleTree`.

For a size-`N` commitment with `m` polynomials, leaf `i` contains:

$$
\big(
f_0(x_i), f_0(-x_i),
f_1(x_i), f_1(-x_i),
\dots,
f_{m-1}(x_i), f_{m-1}(-x_i)
\big).
$$

This is built in `commitment.RSCommit.Commit`.

The verifier replays the same leaf serialization in `verifyWMerkleProof`.

### Canonical commitment order

The prover and verifier both need to agree on where each polynomial lives in the flattened commitment list.

That shared order is built by `prover.BuildLayout`:

1. setup commitments, decreasing size
2. trace commitments for Fiat-Shamir round 0, decreasing size
3. trace commitments for round 1, and so on
4. AIR chunk commitments, decreasing size

The associated slot tables are:

- `Layout.ColSlot`
- `Layout.AIRChunkSlot`

This is what lets `checkFRIBridge` look up the right pair in `proof.PointSamplings`.

### What `checkFRIBridge` checks

For each FRI query `q` and each distinct size `N`, the verifier:

1. recovers the query point $X$ and its opposite $-X$ on the size-`\rho N` encoded domain,
2. reconstructs the same DEEP linear combinations the prover used,
3. evaluates the DEEP quotient formulas pointwise:

$$
DQ_N(X), \qquad DQ_N(-X),
$$

4. compares them to the values opened from the DEEP quotient commitment:
   - largest level: `FRIQueries[q].Layers[0].LeafP/Q`
   - smaller levels: `LevelQueries[level-1][q][0].LeafP/Q`

So `checkFRIBridge` is the exact place where the mathematics

$$
DQ_N(X) = \sum_s \frac{C_{N,s}(z_s)-C_{N,s}(X)}{z_s-X}
         + \frac{A_N(\zeta)-A_N(X)}{\zeta-X}
$$

is connected back to authenticated openings of the original trace and AIR commitments.

## FRI Challenge Schedule

There are two nested Fiat-Shamir schedules in play.

### Main IOP schedule

At the `board` / `prover` / `verifier` level:

- `challenge@loom_0`, `challenge@loom_1`, ...
- `__zeta`

The builder canonicalizes these rounds in `board.Compile`.

Notably, `Compile` appends one extra final Fiat-Shamir round so that all columns relevant to folded AIR relations are transcript-bound before the final evaluation point is sampled.

### Internal FRI schedule

Inside `internal/fri`:

- `fri_level_<l>_gamma`
- `fri_fold_<j>`
- `fri_query_<k>`

Both prover and verifier pre-register these challenges in the same order, then replay the same sequence of `Bind` and `ComputeChallenge` calls.

That order is not cosmetic. It is what makes the multi-degree FRI transcript deterministic.

## Public API

## User-facing API

The user-facing proof API is:

```go
setup, err := prover.Setup(trace, program)
prf, err := prover.Prove(trace, setup, publicInputs, program)
err = verifier.Verify(publicInputs, setup, program, prf)
```

Relevant types:

- `trace.Trace`: `map[string][]koalabear.Element`
- `prover.PublicKey`: `[]commitment.WMerkleTree`
- `proof.Proof`

The fields in `proof.Proof` that matter for the FRI layer are:

- `Commitments`: Merkle roots of trace-round and AIR commitments
- `ValuesAtZeta`: claimed evaluations at `zeta` and rotated points
- `DeepQuotientCommitment`: Merkle roots of the per-size DEEP quotient encodings
- `DeepQuotientFriProof`: the actual `internal/fri.Proof`
- `PointSamplings`: all original commitment openings at the FRI query positions

## Internal FRI API

If you want to use `internal/fri` directly, the main entry points are:

```go
params, err := fri.NewParams(N, D, numQueries, leafHash, nodeHash)
evals, err := params.Encode(poly)
tree, err := params.BuildLevelTree(evals)
prf, queries, err := fri.Prove(params, levels, transcript)
err = fri.Verify(params, levelRoots, levelDs, prf, transcript)
```

Key types:

- `fri.Params`
- `fri.Level`
- `fri.Proof`
- `fri.Query`
- `fri.QueryLayer`

Important calling convention:

- `fri.Proof` does **not** contain the roots of the level polynomials passed in `levels`
- the caller is responsible for passing those roots back to `fri.Verify` as `levelRoots`

That design is deliberate because those level roots may already be committed elsewhere by the caller.

## Code Map: Formula to Function

| Mathematical object | Code |
| --- | --- |
| AIR quotient $V(X)/(X^N-1)$ | `poly.ComputeQuotient`, `prover.ComputeAIRQuotients`, `verifier.checkAIRRelations` |
| Point evaluation of Lagrange-form polynomial | `poly.Evaluate` |
| Lagrange basis element $L_i(\zeta)$ | `poly.LagrangeAtZeta` |
| DEEP quotient $(v-f(X))/(z-X)$ | `poly.DeepQuotient` |
| Deterministic DEEP batching order | `prover.BuildDeepQuotientLayout` |
| Per-size DEEP quotient assembly | `prover.ComputeDeepQuotient` |
| Pointwise DEEP reconstruction on verifier side | `verifier.checkFRIBridge` |
| Reed-Solomon encoding from size `D` to size `N` | `reedsolomon.Encoder.Encode` |
| Merkle commitment of packed $(f(x),f(-x))$ pairs | `commitment.RSCommit.Commit` |
| FRI paired-leaf Merkle tree for a single level | `fri.Params.BuildLevelTree`, `buildTree` |
| FRI fold relation | `internal/fri/fri.go`, `foldLayer` and `checkQueryB` |
| Multi-degree round-introduction logic | `fri.Prove`, `fri.Verify`, `levelAtRound` |
| Canonical original-commitment ordering | `prover.BuildLayout` |

## End-to-End Prover and Verifier Logic

### Prover

For a compiled program with module sizes $N_1, \dots, N_m$:

1. commit setup columns by size,
2. commit trace-round columns by size at every main FS round,
3. build AIR quotient chunks and commit them by size,
4. derive `zeta`,
5. evaluate all needed columns at `zeta` and `zeta * omega^shift`,
6. for each distinct size `N`, construct `DQ_N`,
7. encode every `DQ_N` to size `RATE * N`,
8. commit those encoded DEEP quotient vectors,
9. run multi-degree FRI over them,
10. open every original commitment at the FRI query positions.

### Verifier

1. replay the main FS transcript,
2. recompute all public / selector / challenge evaluations at `zeta`,
3. check AIR at `zeta`,
4. replay the internal FRI transcript and verify the multi-degree FRI proof,
5. verify every Merkle opening of the original commitments,
6. reconstruct the DEEP quotient values at the query points and compare them with the values used by the FRI proof.

## Important Caveats and Current Limitations

This section is important if you are reading the code as a protocol implementation rather than just as an engineering artifact.

### 1. The DEEP batching scalar is currently hard-coded

In both:

- `prover.ComputeDeepQuotient`
- `verifier.checkFRIBridge`

the batching scalar for DEEP quotient construction is set to:

```go
alpha.SetUint64(10)
```

with a `TODO` saying it should come from Fiat-Shamir.

That means the DEEP quotient batching is currently **not transcript-randomized**, even though the rest of the FRI challenge schedule is Fiat-Shamir-driven.

This is the single most important protocol caveat in the current implementation.

### 2. `RATE` and `NUM_QUERIES` are fixed constants

Today:

- `RATE = 4`
- `NUM_QUERIES = 4`

from `internal/constants/const.go`.

So the security/performance trade-off is not yet exposed as an API parameter.

### 3. The field is fixed to Koalabear

The entire stack is specialized to Koalabear-specific field and FFT types.

### 4. `internal/fri` is more general than the current `loom` integration

The `internal/fri.Level` type supports multiple polynomials introduced at the same folding round, but `prover.ComputeDeepQuotient` currently passes exactly one polynomial per size level.

### 5. The bridge is the real PCS check

`fri.Verify` only proves low degree of the DEEP quotient encodings. The statement

> these low-degree objects were derived from the trace and AIR commitments

is not checked there; it is checked later in `verifier.checkFRIBridge`.

That separation is deliberate, but it is easy to miss on a first reading.

### 6. `FinalPoly` is explicit, but there is no extra terminal interpolation check

`internal/fri.Verify` binds `FinalPoly` into the transcript and checks that each queried fold chain lands on the corresponding entry of that explicit terminal vector.

What it does **not** currently do is perform a separate terminal algebraic check such as:

- interpolate `FinalPoly` and verify the expected residual degree bound, or
- in the degree-`<1` case, explicitly check that all terminal entries are equal.

Conceptually, textbook FRI presentations often include such a final small-domain low-degree check once the oracle has been reduced enough. In the current implementation, the terminal object acts as an explicit final oracle whose consistency is only enforced along the queried paths.

## Reading Guide

If you want to read the code in the same order the protocol runs, this is the shortest useful path:

1. `prover/prover.go`
2. `verifier/verifier.go`
3. `prover/layout.go`
4. `internal/poly/compute_quotient.go`
5. `internal/poly/deep.go`
6. `internal/commitment/commitment.go`
7. `internal/fri/fri.go`
8. `proof/proof.go`

If instead you want to start from the algebra:

1. AIR quotient: `internal/poly/compute_quotient.go`
2. DEEP quotient: `internal/poly/deep.go`
3. multi-degree FRI fold and verification: `internal/fri/fri.go`
4. bridge back to committed trace data: `verifier.checkFRIBridge`

## Bottom Line

The `loom` FRI layer is best understood as a two-stage argument:

1. build one DEEP quotient polynomial per distinct module size, using `zeta` to compress all AIR-relevant trace and quotient information of that size into a low-degree object;
2. prove low degree of those objects with a multi-degree FRI protocol, and use authenticated point openings to bridge them back to the original commitments.

That architecture explains almost every unusual-looking piece of the code:

- why commitments are grouped by size,
- why the DEEP quotient is built per size rather than per module,
- why the proof contains both a FRI proof and a separate bank of point samplings,
- and why the verifier needs both `checkFRIProof` and `checkFRIBridge`.
