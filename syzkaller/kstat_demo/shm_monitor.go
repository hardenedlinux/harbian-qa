/* This is the old monitor, it can track socket state by sock_addr, but it's
 * very slow. Because raw data collection and handling is complex. And  
 * synchronize needs time too. I implement the other monitor pipe_monitor.go
 */

package main

import (
	"log"
	"os"
	"os/signal"
	"encoding/binary"
	"syscall"
	"fmt"
	"sync"
	"strconv"

	"github.com/iovisor/gobpf/pkg/tracepipe"
	"github.com/iovisor/gobpf/bcc"
	"github.com/ghetzel/shmtool/shm"
	
	"./state"
	"./ebpf"
	"./parse"
)

import "C"

var mutex =  &sync.Mutex{}

func main() {
	/* ebpf run at first, it's very slow ... */
	source := ebpf.EbpfInit()
	m := bcc.NewModule(source, []string{})
	defer m.Close()
	ebpf.Attachs(m)

	/* tracepipe for reading out ebpf print */
	tp, err := tracepipe.New()
	if err != nil {
		log.Fatal("%s\n", err)
	}
	defer tp.Close()

	/* Shared memory for signals and pid of process which will be monitored( don't enable NEWPID namespace) */
	shmem, err := shm.Create(4*(400+1))
	if(err != nil) {
		log.Fatal("Share memory create failed")
	}
	shmem.Attach()
	fmt.Printf("%08d", shmem.Id)

	shpid, err := shm.Create(8)
	if(err != nil) {
		log.Fatal("Share memory create failed")
	}
	shpid.Attach()
	fmt.Printf("%08d", shpid.Id)

	rawMessage, errMessage := tp.Channel()
	var pid uint64 = 0
	/* The execute_one will write the prog pid to shared memory */
	for (pid == 0) {
		rawpid := make([]byte, 8)
		shpid.Reset()
		shpid.Read(rawpid)
		pid = binary.LittleEndian.Uint64(rawpid)
	}
	log.Printf("Monitoring the process %d\n", pid)
	/* Catch the SIGUSR1, refer to syzkaller executor patch */
	go wait4sig(tp)
Readloop:
	/* tracepipe will be closed if a SIGUSR1 detected, and errMessage will return */
	for {
		select {
		case te := <- rawMessage:
			tepid, _ := strconv.ParseInt(te.PID, 10, 16)
			if pid != uint64(tepid) {
				break
			}
			mutex.Lock()
			state.Handle(te.Message)
			mutex.Unlock()
		case msg := <- errMessage:
			log.Println("END:", msg)
			break Readloop
		}
	}
	
	log.Println("Socket state handle start ...")
	/* At first, I try to make the state look like coverage signals, but ... */
	mutex.Lock()
	rawSignals := state.Statelist()
	mutex.Unlock()

	log.Printf("%d rawSignals got!\n", len(rawSignals));
	/* a set of rawSignals end with a 0xffffffff */
	if (len(rawSignals) < 2) {
		log.Fatal("No real rawSignal\n");
	}
	if (len(rawSignals) > 401) {
		log.Printf("Too many signals, cut to 400\n")
		rawSignals = rawSignals[len(rawSignals)-400:len(rawSignals)-1]
	}
	/* Refresh the shared memory */
	fresh := make([]byte, 4)
	binary.LittleEndian.PutUint32(fresh, 0xffffffff)
	shmem.Reset()
	_, err = shmem.Write(fresh)
	shmem.Reset()
	if (err != nil) {
		log.Fatal("Write out signal failed\n")
	}
	for _, rawSignal := range rawSignals {
		/* rawSignal to macro */
		if (rawSignal != 0xffffffff) {
			parse.ParseFlags(rawSignal)
		}
		temp := make([]byte, 4)
		binary.LittleEndian.PutUint32(temp, rawSignal)
		log.Printf("Write signal:%x, byte:%s\n", rawSignal, temp)
		/* Write signal to shared memory to executor */
		_, err := shmem.Write(temp)
		if (err != nil) {
			log.Fatal("Write out signal failed\n")
		}
	}
	mutex.Lock()
	state.Stateclear()
	mutex.Unlock()
	/* Waiting for kill-signal, monitor run with prctl */
	for {
	}
}

func wait4sig(tp *tracepipe.TracePipe) {
	log.Printf("Waiting for signal\n");
	c := make(chan os.Signal, 1)	
	signal.Notify(c, syscall.SIGUSR1)
	s := <-c
	if (true) {
		log.Println("Got a signal", s)
	}
	tp.Close()
}
