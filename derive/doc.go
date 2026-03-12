// derive is mainly a wrapper around the Build... functions in univariate/, with an extra layer
// for handling columns in the trace (register new columns).
//
// fiatshamir is the only prover action which requires a bit of work, because we track the exact columns dependeny each
// time we generate a challenge.
//
// DerivationStep = creation of one or several new columns, which are not part of the original trace, and which appear in the various IOPs (e.g. grand product column, etc)

package derive
