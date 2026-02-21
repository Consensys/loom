# IOP

"Interactive Oracle Proof". This repository allows one to generate a proof that a Trace satisfies a list of constraint and to verify it succintly, by sampling openings of the trace commitment and check

## `./pas` provides efficient polynomial operations primitves, in Go:

* Multivariate polynomials with symbolic expressions
* Univariate polynomials - evaluation, FFTs
* Computation of operations of the form $Q(P_1,..,P_n)$ where $Q$ is a multivariate polynomial and $P_i$ are univariate polynomials of the same degree
* When $Q(P_1,..,P_n) = 0 mod X^m-1$, computes $H = Q(P_1,..,P_n) / X^m-1$

## `./crypto` provides the commitment scheme used to commit to the trace

## 