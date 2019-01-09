package parse

import (
	"log"
)

/* Map socket state to readable kernel macro */
var sock_type = map[uint32]string {
	1:"SOCK_DGRAM",
	2:"SOCK_STREAM",
	3:"SOCK_RAW",
	4:"SOCK_RDM",
	5:"SOCK_SEQPACKET",
	6:"SOCK_DCCP",
	10:"SOCK_PACKET",
}

var sock_state = map[uint32]string {
	0:"SS_FREE",
	1:"SS_UNCONNECTED",
	2:"SS_CONNECTING",
	3:"SS_CONNECTED",
	4:"SS_DISCONNECYING",
}

var sock_flags = map[uint32]string {
	2:"SOCK_NOSPACE",
	3:"SOCK_PASSCRED",
	4:"SOCK_PASSEC",
}

type flag struct {
	mask     uint32
	shift    uint32
	flagType map[uint32]string
}

/* flag structure, refer to ebpf/ebpf.go ebpf text */
func ParseFlags(rawSignal uint32) {
	var Signal = []flag {
		flag {mask:0x7, flagType:sock_flags, shift:0},
		flag {mask:0xf, flagType:sock_type, shift:4},
		flag {mask:0x7, flagType:sock_state, shift:8},
	}

	for _, s := range Signal {
		parseFlag(rawSignal, s.mask, s.flagType, s.shift)
	}
}

func parseFlag(rawsignal uint32, mask uint32, flagtype map[uint32]string, shift uint32) {
	log.Printf("%s:%x covered", flagtype[(rawsignal&(mask<<shift))>>shift], (rawsignal&(mask<<shift))>>shift)
}
