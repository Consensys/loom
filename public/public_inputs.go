package public

import (
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
