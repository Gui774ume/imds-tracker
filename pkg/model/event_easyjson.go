// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package model

import (
	json "encoding/json"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjsonF642ad3eDecodeGithubComGui774umeImdsTrackerPkgModel(in *jlexer.Lexer, out *ProcessListSerializer) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		in.Skip()
		*out = nil
	} else {
		in.Delim('[')
		if *out == nil {
			if !in.IsDelim(']') {
				*out = make(ProcessListSerializer, 0, 0)
			} else {
				*out = ProcessListSerializer{}
			}
		} else {
			*out = (*out)[:0]
		}
		for !in.IsDelim(']') {
			var v1 ProcessContext
			(v1).UnmarshalEasyJSON(in)
			*out = append(*out, v1)
			in.WantComma()
		}
		in.Delim(']')
	}
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonF642ad3eEncodeGithubComGui774umeImdsTrackerPkgModel(out *jwriter.Writer, in ProcessListSerializer) {
	if in == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
		out.RawString("null")
	} else {
		out.RawByte('[')
		for v2, v3 := range in {
			if v2 > 0 {
				out.RawByte(',')
			}
			(v3).MarshalEasyJSON(out)
		}
		out.RawByte(']')
	}
}

// MarshalJSON supports json.Marshaler interface
func (v ProcessListSerializer) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonF642ad3eEncodeGithubComGui774umeImdsTrackerPkgModel(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v ProcessListSerializer) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonF642ad3eEncodeGithubComGui774umeImdsTrackerPkgModel(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *ProcessListSerializer) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonF642ad3eDecodeGithubComGui774umeImdsTrackerPkgModel(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *ProcessListSerializer) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonF642ad3eDecodeGithubComGui774umeImdsTrackerPkgModel(l, v)
}
func easyjsonF642ad3eDecodeGithubComGui774umeImdsTrackerPkgModel1(in *jlexer.Lexer, out *Event) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "process":
			(out.Process).UnmarshalEasyJSON(in)
		case "ancestors":
			if in.IsNull() {
				in.Skip()
			} else {
				in.Delim('[')
				v4 := 0
				for !in.IsDelim(']') {
					if v4 < 9 {
						((out.Ancestors)[v4]).UnmarshalEasyJSON(in)
						v4++
					} else {
						in.SkipRecursive()
					}
					in.WantComma()
				}
				in.Delim(']')
			}
		case "network_direction":
			out.NetworkDirection = NetworkDirection(in.Uint64())
		case "timestamp":
			if data := in.Raw(); in.Ok() {
				in.AddError((out.Timestamp).UnmarshalJSON(data))
			}
		case "packet":
			(out.Packet).UnmarshalEasyJSON(in)
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonF642ad3eEncodeGithubComGui774umeImdsTrackerPkgModel1(out *jwriter.Writer, in Event) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"process\":"
		out.RawString(prefix[1:])
		(in.Process).MarshalEasyJSON(out)
	}
	{
		const prefix string = ",\"ancestors\":"
		out.RawString(prefix)
		(in.Ancestors).MarshalEasyJSON(out)
	}
	{
		const prefix string = ",\"network_direction\":"
		out.RawString(prefix)
		out.Raw((in.NetworkDirection).MarshalJSON())
	}
	{
		const prefix string = ",\"timestamp\":"
		out.RawString(prefix)
		out.Raw((in.Timestamp).MarshalJSON())
	}
	{
		const prefix string = ",\"packet\":"
		out.RawString(prefix)
		(in.Packet).MarshalEasyJSON(out)
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v Event) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonF642ad3eEncodeGithubComGui774umeImdsTrackerPkgModel1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v Event) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonF642ad3eEncodeGithubComGui774umeImdsTrackerPkgModel1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *Event) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonF642ad3eDecodeGithubComGui774umeImdsTrackerPkgModel1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *Event) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonF642ad3eDecodeGithubComGui774umeImdsTrackerPkgModel1(l, v)
}
