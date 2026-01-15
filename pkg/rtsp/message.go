package rtsp

import (
	"bufio"
	"fmt"
	"net/textproto"
	"strings"
)

// Request is a simplified RTSP request
type Request struct {
	Method  string
	URL     string
	Headers textproto.MIMEHeader
}

// Response is a simplified RTSP response
type Response struct {
	StatusCode int
	Status     string
	Headers    textproto.MIMEHeader
}

// ReadRequest reads an RTSP request from the reader
func ReadRequest(r *bufio.Reader) (*Request, error) {
	tp := textproto.NewReader(r)
	line, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed request line: %s", line)
	}
	method, url, _ := parts[0], parts[1], parts[2]

	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}

	return &Request{
		Method:  method,
		URL:     url,
		Headers: headers,
	}, nil
}

// ReadResponse reads an RTSP response from the reader
func ReadResponse(r *bufio.Reader) (*Response, error) {
	tp := textproto.NewReader(r)
	line, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed response line: %s", line)
	}
	// e.g. RTSP/1.0 200 OK
	
	statusCode := 0
	fmt.Sscanf(parts[1], "%d", &statusCode)
	
	status := ""
	if len(parts) > 2 {
		status = parts[2]
	}

	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: statusCode,
		Status:     status,
		Headers:    headers,
	}, nil
}
