package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/espenotterstad/iptables-tui/internal/model"
	"github.com/espenotterstad/iptables-tui/internal/tailer"
)

func main() {
	logFile := flag.String("file", "/var/log/iptables.log", "path to the iptables log file")
	history := flag.Bool("history", false, "read file from the beginning (include historical entries)")
	flag.Parse()

	t := tailer.New()

	m := model.New(t)

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
		fmt.Fprintf(os.Stderr, "iptable-tui: %v\n", err)
		os.Exit(1)
	}
}
