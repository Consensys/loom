package fiatshamir

import (
	"testing"

	"github.com/consensys/gnark-crypto/hash"
	_ "github.com/consensys/gnark-crypto/hash/all"
	"github.com/stretchr/testify/require"
)

func TestTranscript(t *testing.T) {
	fst, err := NewTranscript(hash.POSEIDON2_KOALABEAR.New())
	require.NoError(t, err)

	c1, err := fst.Challenge("one", []byte{1})
	require.NoError(t, err)

	c2, err := fst.Challenge("two", []byte{2})
	require.NoError(t, err)
	require.NotEqual(t, c1, c2)

	require.NoError(t, fst.BeginSubProtocol("sub"))
	c3, err := fst.Challenge("three", []byte{3})
	require.NoError(t, err)

	require.NoError(t, fst.EndSubProtocol())

	c4, err := fst.Challenge("four", []byte{4})
	require.NoError(t, err)

	// "Verifier" side
	fst, err = NewTranscript(hash.POSEIDON2_KOALABEAR.New(), WithProtocolLayout(fst.Layout()))
	require.NoError(t, err)

	v, err := fst.Challenge("one", []byte{1})
	require.NoError(t, err)
	require.Equal(t, c1, v)

	v, err = fst.Challenge("two", []byte{2})
	require.NoError(t, err)
	require.Equal(t, c2, v)

	v, err = fst.Challenge("three", []byte{3})
	require.Error(t, err)

	require.NoError(t, fst.BeginSubProtocol("sub"))
	v, err = fst.Challenge("three", []byte{3})
	require.NoError(t, err)
	require.Equal(t, c3, v)

	require.NoError(t, fst.EndSubProtocol())
	require.Error(t, fst.EndSubProtocol())

	v, err = fst.Challenge("four")
	require.Error(t, err)

	v, err = fst.Challenge("four", []byte{4})
	require.NoError(t, err)
	require.Equal(t, c4, v)
}
