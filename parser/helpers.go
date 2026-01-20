package parser

import (
	"bytes"
	"io"
)

// RequestParts holds separated body and length
type RequestParts struct {
	BodyReader    io.Reader
	ContentLength int64
}

// SplitRequestBytes helper to separate header and body for http.Client usage
func SplitRequestBytes(data []byte) RequestParts {
	parts := bytes.SplitN(data, []byte("\r\n\r\n"), 2)
	if len(parts) < 2 {
		parts = bytes.SplitN(data, []byte("\n\n"), 2)
	}

	if len(parts) < 2 {
		return RequestParts{BodyReader: bytes.NewReader([]byte{}), ContentLength: 0}
	}

	body := parts[1]
	return RequestParts{
		BodyReader:    bytes.NewReader(body),
		ContentLength: int64(len(body)),
	}
}
