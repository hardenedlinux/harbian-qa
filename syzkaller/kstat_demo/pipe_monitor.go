/* This monitor only collect single socket state, without any track.
 * It only know if a new state was detected, but know nothing about 
 * which socket does the state belong to.
 */

package main

import (
	"os"
	"log"
	"fmt"
	"regexp"
	"flag"
	"strconv"
	
	"github.com/iovisor/gobpf/pkg/tracepipe"
        "github.com/iovisor/gobpf/bcc"

	"./ebpf"
)

import "C"
func main() {
	/* redirect stderr, there are some ebpf log or warning */
	debug := flag.Bool("debug", false, "More debug information about ebpf")
	flag.Parse()
	_, w, _ := os.Pipe()
	old := os.Stderr
	if(!*debug) {
		old.Close()
		os.Stderr = w
	}

	/* ebpf text is in ebpf/ebpftext.go */
	source := ebpf.EbpfInit()
	m := bcc.NewModule(source, []string{})
	defer m.Close()
	/* Be sure your hook function named as "kprobe__KERN_FUNCNAME" */
	ebpf.Attachs(m)

	tp, err := tracepipe.New()
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	if (!*debug) {
		w.Close()
		os.Stderr = old
	}

	rawMessage, errMessage := tp.Channel()
	re := regexp.MustCompile("syz-executor")
	for (true) {
		select {
		case te := <- rawMessage:
			/* syz-exec has it own pid namespace
                         * pick out those pid under the namespace can be more accurate
                         */
			if(re.FindString(te.Task) == "") {
				continue
			}
			rawSignal, err := strconv.ParseUint(te.Message, 16, 64)
			if (err != nil) {
				log.Println("Wrong rawSignal")
				continue
			}
			fmt.Printf("%016x\n", rawSignal)
		case err := <- errMessage:
			log.Fatal(err)
		}
	}
}
