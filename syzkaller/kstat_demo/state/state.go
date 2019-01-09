package state

import (
	"fmt"
	"strconv"
	"os"
	"regexp"
	"strings"
	"log"
)

/* In a syscall, Several messages from ebpf contain:
 * several kernel probe points and socketstates. 
 * a syscall with a OpsId 
 */
type Ops struct {
	OpsId       int
	KprobePoint string
	SocketState map[uint64]uint64
}

/* record all the state collect by ebpf, a sock with a SockState */
type SockState struct {
	SockState []uint64
	SockOps   []string
}

/* Only record the state coverage */
var StateList []uint64

/* A syscall with a Ops */
var OpsList []Ops

var id int = 0
var tmp uint64 = 0

/* Handle a message from ebpf */
func Handle(msg string) {
	key, value := extract(msg)
	/* Three type of message, refer the ebpf/ebpf.go */
	switch key {
	case "[KPROBE_P]":
		OpsList = append(OpsList, newops(id, value))
		tmp = 0
		id = len(OpsList) - 1
		OpsList[id].SocketState = make(map[uint64]uint64)
	case "[SOCKET_ID]":
		if(strings.Contains(value, "ptrval")) {
			fmt.Println("Socket id miss")
			misshandle()
			return
		}
		sockid := str2int(value)
		if(id > len(OpsList)-1) {
			fmt.Println("id out of range")
			misshandle()
			return
		}
		if _, ok := OpsList[id].SocketState[sockid]; !ok {
			OpsList[id].addsock(sockid)
			tmp = sockid
			}
	case "socket_state":
		/* Only record state, know nothing about which socket is it */
		StateList= append(StateList, str2int(value))
		if(id > len(OpsList)-1) {
			fmt.Println("id out of range")
			misshandle()
			return
		}

		if _, ok := OpsList[id].SocketState[tmp]; ok {
			OpsList[id].SocketState[tmp] =  str2int(value)
			return
			}
	default:
		fmt.Fprint(os.Stderr, "Unknow message:\n", msg)
	}
}

/* From "a syscall with a Ops" to "a socket with several state" */
func Socklist() {
	SockList := make(map[uint64]SockState)
	for _, ops := range OpsList {
		for skid, skst := range ops.SocketState {
			var tmps SockState
			tmps = SockList[skid]
			if (len(tmps.SockState) == 0) {
				tmps.SockState = []uint64{skst}
				tmps.SockOps = []string{ops.KprobePoint}
			} else {
				tmps.SockState = append(tmps.SockState, skst)
				tmps.SockOps = append(tmps.SockOps, ops.KprobePoint)
			}
			SockList[skid] = tmps
		}
	}
	for skid, sock := range SockList {
		fmt.Println("Socket id is", skid)
		fmt.Printf("The state:%v\n", sock.SockState)
		fmt.Printf("The operations:%v\n", sock.SockOps)
	}
}

/* state change hash, as coverage signal in syzkall */
func hash(a uint64, b uint64) uint32{
	a = a ^ b
	a = (a ^ 61) ^ (a >> 16)
	a = a + (a << 3)
	a = a ^ (a >> 4)
	a = a * 0x27d4eb2d
	a = a ^ (a >> 15)
	return uint32(a)
}

/* Only read state change, know nothing about state */
func SockStateHandle() []uint32 {
	var rawSignals []uint32
	if (len(OpsList) < 2) {
		rawSignals = append(rawSignals, 0xffffffff)
		return rawSignals
	}
	SockList := make(map[uint64]SockState)
	for _, ops := range OpsList {
		for skid, skst := range ops.SocketState {
			var tmps SockState
			tmps = SockList[skid]
			if (len(tmps.SockState) == 0) {
				tmps.SockState = []uint64{skst}
				tmps.SockOps = []string{ops.KprobePoint}
			} else {
				tmps.SockState = append(tmps.SockState, skst)
				tmps.SockOps = append(tmps.SockOps, ops.KprobePoint)
			}
			SockList[skid] = tmps
		}
	}
	for _, sock := range SockList {
		for i := 0; i < len(sock.SockState)-1; i++ {
			rawSignals = append(rawSignals, hash(sock.SockState[i], sock.SockState[i+1]))
		}
	}
	rawSignals = append(rawSignals, 0xffffffff)
	return rawSignals
}

/* Read all state coverage */
func Statelist() []uint32{
	var rawSignals []uint32
	log.Printf("%d signals in statelist\n", len(StateList))
	for _, s := range StateList {
		rawSignals = append(rawSignals, uint32(s))
	}
	rawSignals = append(rawSignals, 0xffffffff)
	return rawSignals
}

/* Read Opslist */
func Opslist() {
	fmt.Println("There are", id, "operations of socket")
	for _, ops := range OpsList {
		fmt.Println("Kprobe point is:", ops.KprobePoint)
		for id, ss := range ops.SocketState {
			fmt.Println("Socket id is:", id)
			fmt.Println("Socket state:", ss)
		}
		fmt.Println("")
	}
}

/* Clear historical data */
func Stateclear() {
	if (len(OpsList) == 0) {
		return
	}
	OpsList = OpsList[0:0]
	StateList = StateList[0:0]
	tmp = 1
	id = 1
}	

func (ops Ops)addsock(sockid uint64) {
	ops.SocketState[sockid] = 0
}

func extract(msg string) (key string, value string) {
	rkey := regexp.MustCompile(".*:")
	rvalue := regexp.MustCompile(":.*")
	key = rkey.FindString(msg)
	value = rvalue.FindString(msg)
	key = key[:len(key)-1]
	value = value[1:]
	return key, value
}

func str2int(str string) uint64 {
	ret, err := strconv.ParseUint(str, 16, 64)
	if err != nil {
		fmt.Fprint(os.Stderr, "Invaliable socket ID", err, "\n")
	}
	return ret
}

func newops(id int,  kprobepoint string) Ops {
	ops := new(Ops)
	ops.OpsId = id
	ops.KprobePoint = kprobepoint
	return *ops
}

/* Handle unexpect message */
func misshandle(){
	fmt.Println("Miss handle, historical data may be clean")
}
