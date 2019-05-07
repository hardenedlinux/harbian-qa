package ebpf

import (
	"fmt"
	"os"

	"github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/pkg/tracepipe"
)

/*
 * As an example, we monitor the state, type, flags in socket structure.
 * Use ebpf map is a better way to monitor kernel data state.
 * So, we print the state in every hook and handle them after as syzkaller
 * read coverage signal 
 */

func EbpfInit() string {
	ebpf := EbpfSingle
	return ebpf
}

func Attachs(m *bcc.Module) {
	for _, funcname := range ProbePoint {
		attachProbe(funcname, m)
	}
	for _, funcname := range RetProbePoint {
		attachRetProbe(funcname, m)
	}
}

func ReadLine(tp *tracepipe.TracePipe, pid uint64) string {
	return readline(tp, pid)
}

/* Add kprobe__ at the beginning, your hookfunc should be kprobe__KERN_FUNCNAME */
func attachProbe(kprobepoint string, m *bcc.Module) {
	funcName := "kprobe__" + kprobepoint
	tmpKprobe, err := m.LoadKprobe(funcName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load %s: %s\n", kprobepoint, err);
		os.Exit(1)
	}

	err = m.AttachKprobe(kprobepoint, tmpKprobe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach %s: %s\n", kprobepoint, err);
		os.Exit(1)
	}
}

func attachRetProbe(kretprobepoint string, m *bcc.Module) {
	funcName := "kretprobe__" + kretprobepoint
	tmpKretprobe, err := m.LoadKprobe(funcName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load %s: %s\n", kretprobepoint, err);
		os.Exit(1)
	}

	err = m.AttachKretprobe(kretprobepoint, tmpKretprobe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach %s: %s\n", kretprobepoint, err);
		os.Exit(1)
	}
}

/* read a single line from ebpf, strip useless information */
func readline(tp *tracepipe.TracePipe, pid uint64) string {
	ret := ""
	te, err := tp.ReadLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to ReadLine\n", err);
		return ret
	}
	if (te.Message) != "" {
		ret = te.Message
	}
	return ret
}
