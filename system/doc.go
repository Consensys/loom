// This package deals with system: a set of columns, with constraints attached to it. We can build columns
// explicitly, for instance we can create a new column which is a linear combination of other columns with a value given explicitly,
// which plays the role of a challenge sent by the verifier.
// Such functions are embedded in the protocol package, where the values are really computed as challenge, with Fiat Shamir.
//
// package univariate = layer 0, just raw operations on polynomials
// package system = layer 1, we use layer 0 in the context of building a system, so we deal with constraints as well
// package protocol = layer 2, we use layer 1, in the context of the protocol, that is we manage prover<->verifier interaction
package system
