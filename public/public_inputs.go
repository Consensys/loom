package public

import (
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/field"
)

type Input struct {
	Module  string
	Entries []Entry
}

type Entry struct {
	Idx      int
	Field    field.Kind
	Value    koalabear.Element
	ValueExt extensions.E4
}

type Inputs map[string]Input

func (e *Entry) SetBase(v koalabear.Element) {
	e.Field = field.Base
	e.Value.Set(&v)
	e.ValueExt.Lift(&v)
}

func (e *Entry) SetExt(v extensions.E4) {
	e.Field = field.Ext
	e.ValueExt.Set(&v)
}

func (e Entry) ExtValue() extensions.E4 {
	if e.Field == field.Ext {
		return e.ValueExt
	}
	var v extensions.E4
	v.Lift(&e.Value)
	return v
}

// TranscriptBytes returns a deterministic encoding of the public statement
// values suitable for Fiat-Shamir binding.
func (inputs Inputs) TranscriptBytes() []byte {
	var buf bytes.Buffer

	names := make([]string, 0, len(inputs))
	for name := range inputs {
		names = append(names, name)
	}
	sort.Strings(names)

	writeUint64(&buf, uint64(len(names)))
	for _, name := range names {
		input := inputs[name]
		writeString(&buf, name)
		writeString(&buf, input.Module)

		entries := append([]Entry(nil), input.Entries...)
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Idx != entries[j].Idx {
				return entries[i].Idx < entries[j].Idx
			}
			if entries[i].Field != entries[j].Field {
				return entries[i].Field < entries[j].Field
			}
			return bytes.Compare(entryValueBytes(entries[i]), entryValueBytes(entries[j])) < 0
		})

		writeUint64(&buf, uint64(len(entries)))
		for _, entry := range entries {
			writeUint64(&buf, uint64(entry.Idx))
			buf.WriteByte(byte(entry.Field))
			buf.Write(entryValueBytes(entry))
		}
	}

	return buf.Bytes()
}

func writeString(buf *bytes.Buffer, s string) {
	writeUint64(buf, uint64(len(s)))
	buf.WriteString(s)
}

func writeUint64(buf *bytes.Buffer, v uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], v)
	buf.Write(raw[:])
}

func entryValueBytes(entry Entry) []byte {
	if entry.Field == field.Ext {
		return extBytes(entry.ValueExt)
	}
	raw := entry.Value.Bytes()
	return raw[:]
}

func extBytes(v extensions.E4) []byte {
	res := make([]byte, 0, 4*koalabear.Bytes)
	b0a0 := v.B0.A0.Bytes()
	b0a1 := v.B0.A1.Bytes()
	b1a0 := v.B1.A0.Bytes()
	b1a1 := v.B1.A1.Bytes()
	res = append(res, b0a0[:]...)
	res = append(res, b0a1[:]...)
	res = append(res, b1a0[:]...)
	res = append(res, b1a1[:]...)
	return res
}
