package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/espenotterstad/iptables-log-tui/internal/classifier"
	"github.com/espenotterstad/iptables-log-tui/internal/model"
	"github.com/espenotterstad/iptables-log-tui/internal/tailer"
)

// checkAndElevate re-execs the binary under sudo if the log file is
// unreadable due to permissions. It is a no-op if already running as root
// or if the error is not permission-related.
func checkAndElevate(logFile string) {
	if os.Getuid() == 0 {
		return
	}
	f, err := os.Open(logFile)
	if err == nil {
		f.Close()
		return
	}
	if !errors.Is(err, os.ErrPermission) {
		return
	}
	sudoPath, lookErr := exec.LookPath("sudo")
	if lookErr != nil {
		fmt.Fprintf(os.Stderr,
			"iptables-log-tui: permission denied reading %s\n"+
				"  Fix: sudo usermod -aG adm $USER  (then log out/in)\n", logFile)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "iptables-log-tui: permission denied reading %s — re-running with sudo\n", logFile)
	args := append([]string{sudoPath}, os.Args...)
	if execErr := syscall.Exec(sudoPath, args, os.Environ()); execErr != nil {
		fmt.Fprintf(os.Stderr, "iptables-log-tui: exec sudo: %v\n", execErr)
		os.Exit(1)
	}
}

func main() {
	logFile := flag.String("file", "/var/log/iptables.log", "path to the iptables log file")
	history := flag.Bool("history", false, "read file from the beginning (include historical entries)")
	flag.Parse()
	checkAndElevate(*logFile)

	cls := classifier.New()
	t := tailer.New()

	m := model.New(t, cls.Categorize)

	p := tea.NewProgram(m, tea.WithAltScreen())

	// Start the tailer and forward new lines to the Bubble Tea program.
	t.Start(*logFile, *history)
	go func() {
		for {
			select {
			case line, ok := <-t.Lines:
				if !ok {
					return
				}
				p.Send(model.NewLineMsg(line))
			case err, ok := <-t.Errors:
				if !ok {
					return
				}
				p.Send(model.TailerErrMsg{Err: err})
				return
			}
		}
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "iptables-log-tui: %v\n", err)
		os.Exit(1)
	}
}
