package replay

import (
	"encoding/binary"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/pcap"
	"github.com/kubeshark/tracer/misc"
)

type Replayer struct {
	handle   *pcap.Handle
	buf      [16]byte
	tsScaler int // default: micro
}

const nanosPerMicro = 1000 // default
const nanosPerNano = 1

func (r *Replayer) writePacketHeader(ci gopacket.CaptureInfo) error {
	t := ci.Timestamp
	if t.IsZero() {
		t = time.Now()
	}
	secs := t.Unix()
	usecs := t.Nanosecond() / r.tsScaler
	binary.LittleEndian.PutUint32(r.buf[0:4], uint32(secs))
	binary.LittleEndian.PutUint32(r.buf[4:8], uint32(usecs))
	binary.LittleEndian.PutUint32(r.buf[8:12], uint32(ci.CaptureLength))
	binary.LittleEndian.PutUint32(r.buf[12:16], uint32(ci.Length))
	return r.write(r.buf[:])
}

func (r *Replayer) write(data []byte) error {
	return r.handle.WritePacketData(data)
}

func (r *Replayer) Write(ci gopacket.CaptureInfo, data []byte) (err error) {
	err = r.writePacketHeader(ci)
	if err != nil {
		return
	}
	return r.write(data)
}

func (r *Replayer) SetScalarMicro() {
	r.tsScaler = nanosPerMicro
}

func (r *Replayer) SetScalarNano() {
	r.tsScaler = nanosPerNano
}

func NewReplayer(iface string) (r *Replayer, err error) {
	var handle *pcap.Handle
	handle, err = pcap.OpenLive(iface, int32(misc.Snaplen), true, pcap.BlockForever)
	if err != nil {
		return
	}

	r = &Replayer{
		handle:   handle,
		tsScaler: nanosPerMicro,
	}

	return
}
