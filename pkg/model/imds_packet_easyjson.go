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

func easyjson2bba4802DecodeGithubComGui774umeImdsTrackerPkgModel(in *jlexer.Lexer, out *IMDSPacket) {
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
		case "size":
			out.Size = int(in.Int())
		case "packet_type":
			out.PacketType = string(in.String())
		case "is_imds_v2":
			out.IsIMDSV2 = bool(in.Bool())
		case "url":
			out.URL = string(in.String())
		case "host":
			out.Host = string(in.String())
		case "user_agent":
			out.UserAgent = string(in.String())
		case "server":
			out.Server = string(in.String())
		case "body":
			easyjson2bba4802DecodeGithubComGui774umeImdsTrackerPkgModel1(in, &out.Body)
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
func easyjson2bba4802EncodeGithubComGui774umeImdsTrackerPkgModel(out *jwriter.Writer, in IMDSPacket) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"size\":"
		out.RawString(prefix[1:])
		out.Int(int(in.Size))
	}
	{
		const prefix string = ",\"packet_type\":"
		out.RawString(prefix)
		out.String(string(in.PacketType))
	}
	{
		const prefix string = ",\"is_imds_v2\":"
		out.RawString(prefix)
		out.Bool(bool(in.IsIMDSV2))
	}
	if in.URL != "" {
		const prefix string = ",\"url\":"
		out.RawString(prefix)
		out.String(string(in.URL))
	}
	if in.Host != "" {
		const prefix string = ",\"host\":"
		out.RawString(prefix)
		out.String(string(in.Host))
	}
	if in.UserAgent != "" {
		const prefix string = ",\"user_agent\":"
		out.RawString(prefix)
		out.String(string(in.UserAgent))
	}
	if in.Server != "" {
		const prefix string = ",\"server\":"
		out.RawString(prefix)
		out.String(string(in.Server))
	}
	if true {
		const prefix string = ",\"body\":"
		out.RawString(prefix)
		out.Raw((in.Body).MarshalJSON())
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v IMDSPacket) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson2bba4802EncodeGithubComGui774umeImdsTrackerPkgModel(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v IMDSPacket) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson2bba4802EncodeGithubComGui774umeImdsTrackerPkgModel(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *IMDSPacket) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson2bba4802DecodeGithubComGui774umeImdsTrackerPkgModel(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *IMDSPacket) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson2bba4802DecodeGithubComGui774umeImdsTrackerPkgModel(l, v)
}
func easyjson2bba4802DecodeGithubComGui774umeImdsTrackerPkgModel1(in *jlexer.Lexer, out *IMDSResponseBody) {
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
func easyjson2bba4802EncodeGithubComGui774umeImdsTrackerPkgModel1(out *jwriter.Writer, in IMDSResponseBody) {
	out.RawByte('{')
	first := true
	_ = first
	out.RawByte('}')
}
