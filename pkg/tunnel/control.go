package tunnel

import "encoding/json"

// ControlSSRC is the reserved SSRC for control messages
const ControlSSRC = 0

// ControlMessage is the JSON structure for control commands
type ControlMessage struct {
	Cmd  string `json:"cmd"`            // "connect", "close", "data" (if integrated, but data is usually raw)
	ID   uint32 `json:"id"`             // SSRC or connection ID
	Addr string `json:"addr,omitempty"` // For "connect": target address, or local reporting
}

// NewConnectMessage creates a message to initiate a connection
func NewConnectMessage(id uint32, addr string) ([]byte, error) {
	return json.Marshal(ControlMessage{
		Cmd:  "connect",
		ID:   id,
		Addr: addr,
	})
}

// NewCloseMessage creates a message to close a connection
func NewCloseMessage(id uint32) ([]byte, error) {
	return json.Marshal(ControlMessage{
		Cmd: "close",
		ID:  id,
	})
}
