package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	cmdWaste byte = iota
	cmdSYN
	cmdPSH
	cmdFIN
	cmdSettings
	cmdAlert
	cmdUpdatePaddingScheme
	cmdSYNACK
	cmdHeartRequest
	cmdHeartResponse
	cmdServerSettings
)

const (
	frameHeaderLen = 7
	maxFrameData   = 1<<16 - 1
)

type frame struct {
	cmd      byte
	streamID uint32
	data     []byte
}

func readFrame(r io.Reader) (frame, error) {
	var header [frameHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return frame{}, err
	}
	length := binary.BigEndian.Uint16(header[5:7])
	f := frame{
		cmd:      header[0],
		streamID: binary.BigEndian.Uint32(header[1:5]),
	}
	if length > 0 {
		f.data = make([]byte, int(length))
		if _, err := io.ReadFull(r, f.data); err != nil {
			return frame{}, err
		}
	}
	return f, nil
}

func writeFrame(w io.Writer, f frame) error {
	if len(f.data) > maxFrameData {
		return fmt.Errorf("frame data too large: %d", len(f.data))
	}
	var header [frameHeaderLen]byte
	header[0] = f.cmd
	binary.BigEndian.PutUint32(header[1:5], f.streamID)
	binary.BigEndian.PutUint16(header[5:7], uint16(len(f.data)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(f.data) == 0 {
		return nil
	}
	_, err := w.Write(f.data)
	return err
}
