package fiatshamir

import (
	"errors"
	"fmt"
	"hash"
	"strings"
)

type ProtocolChildType uint8

const (
	ProtocolActionTypeChallenge ProtocolChildType = iota
	ProtocolActionTypeSubProtocol
)

const iteratorDelimiter = "/"

type ProtocolLayout struct {
	ChildTypes          []ProtocolChildType
	Names               []string
	ChallengeNbBindings []int
	SubProtocols        []ProtocolLayout
}

func childName(explicitName string, i int) string {
	if explicitName != "" {
		return fmt.Sprintf("#%d:%s", i, explicitName)
	}
	return fmt.Sprintf("#%d", i)
}

// validate that the layout is well-formed.
func (l *ProtocolLayout) validate() error {
	if len(l.ChildTypes) != len(l.Names) {
		return fmt.Errorf("layout has %d names but %d child types", len(l.Names), len(l.ChildTypes))
	}
	nbSubProtocols := 0
	for _, t := range l.ChildTypes {
		switch t {
		case ProtocolActionTypeSubProtocol:
			nbSubProtocols++
		case ProtocolActionTypeChallenge:
		default:
			return fmt.Errorf("layout has unknown child type %d", t)
		}
	}
	if nbSubProtocols != len(l.SubProtocols) {
		return fmt.Errorf("expected %d sub-protocols, got %d", nbSubProtocols, len(l.SubProtocols))
	}
	if len(l.ChallengeNbBindings) != len(l.Names)-nbSubProtocols {
		return fmt.Errorf("expected %d challenges, got %d", len(l.Names)-nbSubProtocols, len(l.ChallengeNbBindings))
	}

	for i := range l.SubProtocols {
		if err := l.SubProtocols[i].validate(); err != nil {
			return err
		}
	}

	return nil
}

type ProtocolLayoutIterator struct {
	stack       []protocolLayoutIteratorFrame
	current     protocolLayoutIteratorFrame
	currentName string
}

type protocolLayoutIteratorFrame struct {
	layout       *ProtocolLayout
	challengeI   int
	subProtocolI int
}

func (f *protocolLayoutIteratorFrame) childI() int {
	return f.challengeI + f.subProtocolI
}

func (i *ProtocolLayoutIterator) BeginSubProtocol(name string) error {
	expectedSubName := i.currentName + iteratorDelimiter + name
	if i.current.childI() >= len(i.current.layout.ChildTypes) {
		return fmt.Errorf("unexpected subprotocol %s; no protocol actions left", expectedSubName)
	}
	if i.current.layout.ChildTypes[i.current.childI()] != ProtocolActionTypeSubProtocol {
		return fmt.Errorf("unexpected subprotocol %s; expected challenge %s", expectedSubName, i.current.layout.Names[i.current.childI()])
	}
	parent := i.current
	next := protocolLayoutIteratorFrame{
		layout: &parent.layout.SubProtocols[parent.subProtocolI],
	}
	parent.subProtocolI++
	i.stack = append(i.stack, parent)
	i.current = next
	i.currentName = expectedSubName
	return nil
}

func (i *ProtocolLayoutIterator) EndSubProtocol() error {
	if i.current.childI() != len(i.current.layout.ChildTypes) {
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

func (i *ProtocolLayoutIterator) Challenge(name string, nbBindings int) error {
	if i.current.childI() >= len(i.current.layout.ChildTypes) {
		return fmt.Errorf("unexpected challenge %s%s%s; no protocol actions left", i.currentName, iteratorDelimiter, name)
	}
	if i.current.layout.ChildTypes[i.current.childI()] != ProtocolActionTypeChallenge {
		return fmt.Errorf("unexpected challenge %s%s%s; expected subprotocol %s", i.currentName, iteratorDelimiter, name, i.current.layout.Names[i.current.childI()])
	}
	if i.current.layout.Names[i.current.childI()] != name {
		return fmt.Errorf("unexpected challenge %s%s%s; expected %s", i.currentName, iteratorDelimiter, name, i.current.layout.Names[i.current.childI()])
	}
	if nbBindings != i.current.layout.ChallengeNbBindings[i.current.challengeI] {
		return fmt.Errorf("challenge %s%s%s: expected %d bindings, got %d", i.currentName, iteratorDelimiter, name, i.current.layout.ChallengeNbBindings[i.current.challengeI], nbBindings)
	}
	i.current.challengeI++
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

	h hash.Hash

	nbBindings int
}

type NewTranscriptOption func(*Transcript) error

// WithProtocolLayout gives the transcript an expected topology of the protocol.
// If the requests are made in the wrong order, the transcript will return errors.
func WithProtocolLayout(layout ProtocolLayout) NewTranscriptOption {
	return func(t *Transcript) error {
		t.layoutIterator = &ProtocolLayoutIterator{
			current: protocolLayoutIteratorFrame{
				layout: &layout,
			},
		}
		if err := t.layoutIterator.current.layout.validate(); err != nil {
			return fmt.Errorf("invalid protocol layout: %w", err)
		}
		return nil
	}
}

func NewTranscript(h hash.Hash, options ...NewTranscriptOption) (*Transcript, error) {
	t := &Transcript{
		h: h,
	}
	t.subProtocolStack = []*ProtocolLayout{&t.layoutRoot}
	for _, option := range options {
		if err := option(t); err != nil {
			return nil, err
		}
	}
	return t, nil
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
	t.nbBindings += len(bindings)
	for i := range bindings {
		t.h.Write(bindings[i])
	}
}

func (t *Transcript) Challenge(name string, bindings ...[]byte) ([]byte, error) {

	nbBindings := len(bindings) + t.nbBindings
	if t.layoutIterator != nil {
		if err := t.layoutIterator.Challenge(name, nbBindings); err != nil {
			return nil, err
		}
	} else {
		current := t.subProtocolStack[len(t.subProtocolStack)-1]
		current.ChildTypes = append(current.ChildTypes, ProtocolActionTypeChallenge)
		current.Names = append(current.Names, name)
		current.ChallengeNbBindings = append(current.ChallengeNbBindings, nbBindings)
	}

	t.Bind(bindings...)

	if t.nbBindings == 0 {
		t.h.Write([]byte{0})
	}
	t.nbBindings = 0
	return t.h.Sum(nil), nil
}
