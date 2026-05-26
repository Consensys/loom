package main

import (
	"fmt"
	"os"
	"runtime/pprof"

	"github.com/consensys/loom"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	gnarkplonk "github.com/consensys/loom/integration_test/gnark_plonk"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/trace"
)

func main() {

	nbInstances := 40
	ns := make([]int, nbInstances)
	for i := 0; i < nbInstances; i++ {
		ns[i] = 1 << 15
	}
	builder := board.NewBuilder()
	traces := make([]trace.Trace, len(ns))
	for i, n := range ns {
		tr, sigma, size, err := gnarkplonk.GetIthPlonkTrace(n, i)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		traces[i] = tr
		builder.AddModule(gnarkplonk.PrepareIthPlonk(size, i))

		lro := []expr.Expr{expr.Col(gnarkplonk.Ith(gnarkplonk.ID_L, i)), expr.Col(gnarkplonk.Ith(gnarkplonk.ID_R, i)), expr.Col(gnarkplonk.Ith(gnarkplonk.ID_O, i))}
		sigmaGen := board.NewPermutationGen(sigma, gnarkplonk.Ith("plonk.S", i))
		if err := arguments.CopyConstraint(&builder, gnarkplonk.Ith("plonk", i), lro, sigmaGen); err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
	}

	fullTrace := prover.MergeTrace(traces[0], traces[1:]...)
	program, err := board.Compile(&builder)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	fresh := trace.New(len(fullTrace.Base))
	for k, v := range fullTrace.Base {
		fresh.SetBase(k, v)
	}
	for k, v := range fullTrace.Ext {
		fresh.SetExt(k, v)
	}

	// runtime.GC()
	// fBefore, err := os.Create("heap_before.prof")
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(-1)
	// }
	// fAfter, err := os.Create("heap_after.prof")
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(-1)
	// }
	// defer fBefore.Close()
	// defer fAfter.Close()
	// if err := pprof.WriteHeapProfile(fBefore); err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(-1)
	// }
	f, err := os.Create("cpu_poseidon2.pprof")
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	defer f.Close()
	if err := pprof.StartCPUProfile(f); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	_, err = prover.Prove(fresh, setup.ProvingKey{}, nil, program, prover.WithHashBackend(loom.Poseidon2HashBackend()))
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	pprof.StopCPUProfile()
	// if err := pprof.WriteHeapProfile(fAfter); err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(-1)
	// }

	// f, err := os.Create("cpu.pprof")
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(-1)
	// }
	// defer f.Close()
	// if err := pprof.StartCPUProfile(f); err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(-1)
	// }
	// for i := 0; i < 100; i++ {
	// 	err := verifier.Verify(nil, setup.VerificationKey{}, program, proof)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		os.Exit(-1)
	// 	}
	// }
	// pprof.StopCPUProfile()

}
