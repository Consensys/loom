// proveactions is mainly a wrapper around the Build... functions in pas/univariate/, with an extra layer
// for handling columns in the trace (register new columns).
//
// fiatshamir is the only prover action which requires a bit of work, because we track the exact columns dependeny each
// time we generate a challenge.

package proveractions
