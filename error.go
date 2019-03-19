package auth

import (
	"fmt"
	"strings"
)

type AggregatingError struct {
	Messages []string
}

func (e *AggregatingError) Errorf(s string, args ...interface{}) {
	if e.Messages == nil {
		e.Messages = []string{}
	}
	e.Messages = append(e.Messages, fmt.Sprintf(s, args...))
}

func (e *AggregatingError) Error() string {
	res := "ERROR: "
	switch len(e.Messages) {
	case 0:
		return res
	case 1:
		return res + ": " + e.Messages[0]
	default:
		allMsgs := strings.Join(e.Messages, "\n  ")
		return res + "\n  " + allMsgs
	}
}

func (e *AggregatingError) AddError(src error) {
	if src == nil {
		return
	}
	if e.Messages == nil {
		e.Messages = []string{}
	}
	switch other := src.(type) {
	case *AggregatingError:
		if other.Messages != nil {
			e.Messages = append(e.Messages, other.Messages...)
		}
	default:
		e.Messages = append(e.Messages, src.Error())
	}
}

func (e *AggregatingError) ContainsError() bool {
	return e != nil && len(e.Messages) != 0
}

func (e *AggregatingError) HasError() error {
	if e.ContainsError() {
		return e
	}
	return nil
}
