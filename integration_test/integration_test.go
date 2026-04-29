package integrationtest

import "testing"

func IntegrationTest(t *testing.T) {

	// 1. make an inventory []struct{TestFile: string, NbTest: Int}{…}
	// for every lisp file in ./testdata (the file follow the naming convention <main_name>_xx, xx is the number, starting from 01)

	// 2. for every file in the inventory, compile the .lisp file, turn it in a loom program, load the corresponding traces
	// and call Prove, Verify (like in ../playground/main.go)

}
