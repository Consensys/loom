package fiatshamir

import (
	"errors"
	"fmt"
	"hash"
	"slices"
	"strings"
)

type ProtocolChildType uint8

const (
	ProtocolActionTypeChallenge ProtocolChildType = iota
	ProtocolActionTypeSubProtocol
)

const iteratorDelimiter = "/"

type ProtocolLayout struct {
	ChildTypes   []ProtocolChildType
	Names        []string
	SubProtocols []ProtocolLayout
}

// clone returns a shallow copy of the layout.
func (l *ProtocolLayout) clone() *ProtocolLayout {
	return &ProtocolLayout{
		ChildTypes:   slices.Clone(l.ChildTypes),
		Names:        slices.Clone(l.Names),
		SubProtocols: slices.Clone(l.SubProtocols),
	}
}

type ProtocolLayoutIterator struct {
	stack       []*ProtocolLayout
	current     *ProtocolLayout
	currentName string
}

func (i *ProtocolLayoutIterator) BeginSubProtocol(name string) error {
	expectedSubName := i.currentName + iteratorDelimiter + name
	if len(i.current.ChildTypes) == 0 {
		return fmt.Errorf("unexpected subprotocol %s; no protocol actions left", expectedSubName)
	}
	if i.current.ChildTypes[0] != ProtocolActionTypeSubProtocol {
		return fmt.Errorf("unexpected subprotocol %s; expected challenge %s", expectedSubName, i.current.Names[0])
	}
	i.stack = append(i.stack, i.current)
	i.current.Names = i.current.Names[1:]
	i.current.ChildTypes = i.current.ChildTypes[1:]
	next := i.current.SubProtocols[0].clone()
	i.current.SubProtocols = i.current.SubProtocols[1:]
	i.current = next
	i.currentName = expectedSubName
	return nil
}

func (i *ProtocolLayoutIterator) EndSubProtocol() error {
	if len(i.current.ChildTypes) != 0 {
		return fmt.Errorf("unexpected end of subprotocol %s", i.currentName)
	}
	if len(i.stack) == 0 {
		return errors.New("cannot end subprotocol; no subprotocol is open")
	}
	i.currentName = i.currentName[:strings.LastIndex(i.currentName, iteratorDelimiter)]
	i.current = i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	return nil
}

func (i *ProtocolLayoutIterator) Challenge(name string) error {
	if len(i.current.ChildTypes) == 0 {
		return fmt.Errorf("unexpected challenge %s%s%s; no protocol actions left", i.currentName, iteratorDelimiter, name)
	}
	if i.current.ChildTypes[0] != ProtocolActionTypeChallenge {
		return fmt.Errorf("unexpected challenge %s%s%s; expected subprotocol %s", i.currentName, iteratorDelimiter, name, i.current.Names[0])
	}
	if i.current.Names[0] != name {
		return fmt.Errorf("unexpected challenge %s%s%s; expected %s", i.currentName, iteratorDelimiter, name, i.current.Names[0])
	}
	i.current.Names = i.current.Names[1:]
	i.current.ChildTypes = i.current.ChildTypes[1:]
	return nil
}

type Transcript struct {
	// To ensure consistency between prover and verifier runs of the protocol,
	// The prover may record the layout of the protocol as challenges are derived and subprotocols opened
	// and closed. The verifier does the same and catches any mismatch with readable errors.
	// This is a debugging feature, not essential to protocol soundness.
	// If given a layout to begin with, the iterator will be non-nil.
	// Otherwise, we will build out the layout as we go.
	layoutRoot       ProtocolLayout
	subProtocolStack []*ProtocolLayout
	layoutIterator   *ProtocolLayoutIterator

	h       hash.Hash
	unbound bool
}

type NewTranscriptOption func(*Transcript)

// WithProtocolLayout gives the transcript an expected topology of the protocol.
// If the requests are made in the wrong order, the transcript will return errors.
func WithProtocolLayout(layout ProtocolLayout) NewTranscriptOption {
	return func(t *Transcript) {
		t.layoutIterator = &ProtocolLayoutIterator{
			current: layout.clone(),
		}
	}
}

func NewTranscript(h hash.Hash, options ...NewTranscriptOption) *Transcript {
	t := &Transcript{
		h: h,
	}
	t.subProtocolStack = []*ProtocolLayout{&t.layoutRoot}
	for _, option := range options {
		option(t)
	}
	return t
}

func (t *Transcript) Layout() ProtocolLayout {
	return t.layoutRoot
}

func (t *Transcript) BeginSubProtocol(name string) error {
	if t.layoutIterator != nil {
		return t.layoutIterator.BeginSubProtocol(name)
	}
	current := t.subProtocolStack[len(t.subProtocolStack)-1]
	current.ChildTypes = append(current.ChildTypes, ProtocolActionTypeSubProtocol)
	current.Names = append(current.Names, name)
	current.SubProtocols = append(current.SubProtocols, ProtocolLayout{})
	t.subProtocolStack = append(t.subProtocolStack, &current.SubProtocols[len(current.SubProtocols)-1])
	return nil
}

func (t *Transcript) EndSubProtocol() error {
	if t.layoutIterator != nil {
		return t.layoutIterator.EndSubProtocol()
	}
	if len(t.subProtocolStack) <= 1 {
		return errors.New("cannot end subprotocol; no subprotocol is open")
	}
	t.subProtocolStack = t.subProtocolStack[:len(t.subProtocolStack)-1]
	return nil
}

func (t *Transcript) Bind(bindings ...[]byte) {
	if len(bindings) != 0 {
		t.unbound = false
	}
	for i := range bindings {
		t.h.Write(bindings[i])
	}
}

func (t *Transcript) Challenge(name string, bindings ...[]byte) ([]byte, error) {
	if t.layoutIterator != nil {
		if err := t.layoutIterator.Challenge(name); err != nil {
			return nil, err
		}
	} else {
		current := t.subProtocolStack[len(t.subProtocolStack)-1]
		current.ChildTypes = append(current.ChildTypes, ProtocolActionTypeChallenge)
		current.Names = append(current.Names, name)
	}

	t.Bind(bindings...)
	if t.unbound {
		t.h.Write([]byte{0})
	}
	t.unbound = true
	return t.h.Sum(nil), nil
}
