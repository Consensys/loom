# Generating test data

Test data is produced by the go-corset CLI (`go-corset`) from zkASM test files. The same
principles apply to other languages recognized by go-corset.
Each test case needs a `.bin` (compiled constraints) and an `.lt` (fully expanded trace).

## Step 1: Compile constraints

    go-corset compile --field KOALABEAR_16 -o program.bin myprogram.zkasm

## Step 2: Write a JSON trace

A JSON trace provides the raw input/output initial values for variables. One object per
run, with keys of the form `module.variable` (or `module: { variable: [...] }`):

    { "inc.x": [32366], "inc.r": [32367] }

Valid traces for each test case can be found in the `.accepts` files in
go-corset's `testdata/asm/unit/` directory (one trace per line).

## Step 3: Expand the trace

    go-corset trace --air --field KOALABEAR_16 -o myprogram.lt trace.json myprogram.bin

This runs the full pipeline (propagation, register splitting, trace
expansion, validation) and writes the result as a binary `.lt` file.
The output contains all columns in their final AIR-level form — loom
reads them directly without further expansion.

## Quick reference

    # inc
    go-corset compile --field KOALABEAR_16 -o inc.bin inc.zkasm
    echo '{ "inc.x": [32366], "inc.r": [32367] }' > /tmp/inc.json
    go-corset trace --air --field KOALABEAR_16 -o inc.lt /tmp/inc.json inc.bin

    # counter
    go-corset compile --field KOALABEAR_16 -o counter.bin counter.zkasm
    echo '{ "counter": { "n": [0,1,2], "m": [0,1,2], "r": [0,2,4] } }' > /tmp/counter.json
    go-corset trace --air --field KOALABEAR_16 -o counter.lt /tmp/counter.json counter.bin
