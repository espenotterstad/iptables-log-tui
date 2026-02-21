// Package tailer provides a file-tailing goroutine that emits new lines as
// they are appended to the watched file.  It uses a poll-based approach
// (checking file size on a timer) that works on every OS without requiring
// kernel-specific APIs.
package tailer

import (
	"bufio"
	"io"
	"os"
	"time"
)

const pollInterval = 250 * time.Millisecond

// Tailer watches a file and sends new lines over Lines.
type Tailer struct {
	Lines  chan string
	Errors chan error
	done   chan struct{}
}

// New creates a new Tailer but does not start it.
func New() *Tailer {
	return &Tailer{
		Lines:  make(chan string, 256),
		Errors: make(chan error, 8),
		done:   make(chan struct{}),
	}
}

// Start begins watching path.  When history is true the entire file is read
// from the beginning; otherwise only lines appended after Start is called are
// emitted.  Call Stop to shut down.
func (t *Tailer) Start(path string, history bool) {
	go t.run(path, history)
}

// Stop signals the tailer goroutine to exit.
func (t *Tailer) Stop() {
	close(t.done)
}

func (t *Tailer) run(path string, history bool) {
	f, offset, err := openFile(path, history)
	if err != nil {
		t.sendErr(err)
		return
	}
	defer f.Close()

	reader := bufio.NewReader(f)

	for {
		// Drain all currently available complete lines.
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				// Strip trailing newline characters.
				l := len(line)
				for l > 0 && (line[l-1] == '\n' || line[l-1] == '\r') {
					l--
				}
				if l > 0 {
					select {
					case t.Lines <- line[:l]:
					case <-t.done:
						return
					}
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				t.sendErr(err)
				return
			}
		}

		// Update our known offset.
		pos, _ := f.Seek(0, io.SeekCurrent)
		offset = pos

		// Wait before polling again.
		select {
		case <-t.done:
			return
		case <-time.After(pollInterval):
		}

		// Check for log rotation: if the file is now smaller than our last
		// known position, it has been truncated or replaced.
		fi, err := os.Stat(path)
		if err == nil && fi.Size() < offset {
			// Re-open from the beginning.
			f.Close()
			f, offset, err = openFile(path, true)
			if err != nil {
				t.sendErr(err)
				return
			}
			reader.Reset(f)
			continue
		}

		// Reposition reader in case new data appeared after EOF.
		_, _ = f.Seek(offset, io.SeekStart)
		reader.Reset(f)
	}
}

func (t *Tailer) sendErr(err error) {
	select {
	case t.Errors <- err:
	default:
	}
}

// openFile opens path and seeks to the appropriate start position.
// When history is true it seeks to the beginning; otherwise to EOF.
// Returns the file, the initial byte offset, and any error.
func openFile(path string, history bool) (*os.File, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	var offset int64
	if !history {
		offset, err = f.Seek(0, io.SeekEnd)
		if err != nil {
			f.Close()
			return nil, 0, err
		}
	}
	return f, offset, nil
}
