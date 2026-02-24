// Package model contains the root Bubble Tea model for iptables-log-tui.
package model

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/espenotterstad/iptables-log-tui/internal/classifier"
	"github.com/espenotterstad/iptables-log-tui/internal/parser"
	"github.com/espenotterstad/iptables-log-tui/internal/tailer"
	"github.com/espenotterstad/iptables-log-tui/internal/ui"
	"github.com/espenotterstad/iptables-log-tui/internal/whois"
)

// Tab indices.
const (
	TabLogs    = 0
	TabStats   = 1
	TabFilters = 2
)

// NewLineMsg is sent by the tailer goroutine when a new raw log line arrives.
type NewLineMsg string

// TailerErrMsg is sent when the tailer encounters a fatal error.
type TailerErrMsg struct{ Err error }

// WhoisMsg carries the result of an async whois lookup.
type WhoisMsg struct {
	IP   string
	Info whois.Result
}

// Model is the root Bubble Tea model.
type Model struct {
	// All parsed entries (unfiltered).
	all []parser.LogEntry

	// Filtered view of entries.
	filtered []parser.LogEntry

	// Cursor position within filtered.
	cursor int

	// Active tab.
	tab int

	// Active filters.
	filters ui.Filters

	// True while the IP search input is open.
	searching bool
	searchInput textinput.Model

	// detailOpen is true while the detail page is visible.
	detailOpen bool
	// detailEntry is a plain value-copy of the entry the user selected.
	// It is never updated after being set, so incoming log lines cannot
	// change what is displayed on the detail page.
	detailEntry parser.LogEntry

	// Running stats.
	stats ui.Stats

	// Terminal dimensions.
	width, height int

	// The tailer (kept for Stop on quit).
	tail *tailer.Tailer

	// categorize maps a source IP string to "Internal", "Multicast", or "External".
	categorize func(string) string

	// Whois cache and in-flight tracker.
	whoisCache   map[string]whois.Result
	whoisPending map[string]bool

	// Any fatal error to display.
	err error
}

// New creates and returns the initial model.
func New(t *tailer.Tailer, categorize func(string) string) Model {
	ti := textinput.New()
	ti.Placeholder = "IP substring…"
	ti.CharLimit = 64
	ti.Width = 30

	return Model{
		stats:        ui.NewStats(),
		tail:         t,
		categorize:   categorize,
		searchInput:  ti,
		whoisCache:   make(map[string]whois.Result),
		whoisPending: make(map[string]bool),
	}
}

// Init starts the Bubble Tea program; tailing is managed externally via Send.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles all incoming messages and key events.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case TailerErrMsg:
		m.err = msg.Err
		return m, nil

	case NewLineMsg:
		entry, err := parser.ParseLine(string(msg))
		if err != nil {
			// Skip unparseable lines silently.
			return m, nil
		}
		m.addEntry(*entry)
		return m, nil

	case WhoisMsg:
		m.whoisCache[msg.IP] = msg.Info
		delete(m.whoisPending, msg.IP)
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	// Propagate to search input when active.
	if m.searching {
		var cmd tea.Cmd
		m.searchInput, cmd = m.searchInput.Update(msg)
		m.filters.IPSubstr = m.searchInput.Value()
		m.applyFilters()
		return m, cmd
	}

	return m, nil
}

// handleKey dispatches keyboard events.
func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Global: quit.
	if msg.String() == "q" || msg.String() == "ctrl+c" {
		if m.tail != nil {
			m.tail.Stop()
		}
		return m, tea.Quit
	}

	// Detail overlay: close on Esc or Enter.
	if m.detailOpen {
		if msg.String() == "esc" || msg.String() == "enter" {
			m.detailOpen = false
			// Jump cursor to the latest entry so live-tail resumes naturally.
			if len(m.filtered) > 0 {
				m.cursor = len(m.filtered) - 1
			}
		}
		return m, nil
	}

	// Search input open: handle Esc / Enter to close.
	if m.searching {
		switch msg.String() {
		case "esc", "enter":
			m.searching = false
			m.searchInput.Blur()
			m.filters.IPSubstr = m.searchInput.Value()
			m.applyFilters()
		}
		var cmd tea.Cmd
		m.searchInput, cmd = m.searchInput.Update(msg)
		m.filters.IPSubstr = m.searchInput.Value()
		m.applyFilters()
		return m, cmd
	}

	// Tab switching.
	switch msg.String() {
	case "1":
		m.tab = TabLogs
		return m, nil
	case "2":
		m.tab = TabStats
		return m, nil
	case "3":
		m.tab = TabFilters
		return m, nil
	case "tab":
		m.tab = (m.tab + 1) % 3
		return m, nil
	}

	// Logs-tab specific actions.
	if m.tab == TabLogs {
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.filtered)-1 {
				m.cursor++
			}
		case "pgup":
			m.cursor -= 20
			if m.cursor < 0 {
				m.cursor = 0
			}
		case "pgdown":
			m.cursor += 20
			if m.cursor >= len(m.filtered) {
				m.cursor = len(m.filtered) - 1
			}
		case "enter":
			if len(m.filtered) > 0 && m.cursor < len(m.filtered) {
				m.detailEntry = m.filtered[m.cursor] // plain value copy
				m.detailOpen = true
				src := m.detailEntry.Src
				if m.categorize(src) == classifier.CatExternal && !m.whoisPending[src] {
					if _, cached := m.whoisCache[src]; !cached {
						m.whoisPending[src] = true
						ip := src
						return m, func() tea.Msg {
							return WhoisMsg{IP: ip, Info: whois.Lookup(ip)}
						}
					}
				}
			}
		case "d":
			if m.filters.Action == "DROP" {
				m.filters.Action = ""
			} else {
				m.filters.Action = "DROP"
			}
			m.applyFilters()
		case "a":
			if m.filters.Action == "ACCEPT" {
				m.filters.Action = ""
			} else {
				m.filters.Action = "ACCEPT"
			}
			m.applyFilters()
		case "t":
			if m.filters.Proto == "TCP" {
				m.filters.Proto = ""
			} else {
				m.filters.Proto = "TCP"
			}
			m.applyFilters()
		case "u":
			if m.filters.Proto == "UDP" {
				m.filters.Proto = ""
			} else {
				m.filters.Proto = "UDP"
			}
			m.applyFilters()
		case "/":
			m.searching = true
			m.searchInput.Focus()
			return m, textinput.Blink
		case "esc":
			m.filters = ui.Filters{}
			m.searchInput.SetValue("")
			m.applyFilters()
		}
	}

	// Filter-tab: clear all.
	if m.tab == TabFilters && msg.String() == "c" {
		m.filters = ui.Filters{}
		m.searchInput.SetValue("")
		m.applyFilters()
	}

	return m, nil
}

// addEntry appends a parsed entry to all, updates stats, and refreshes filtered.
func (m *Model) addEntry(e parser.LogEntry) {
	m.all = append(m.all, e)

	// Update stats.
	m.stats.Total++
	m.stats.ByAction[e.Action()]++
	m.stats.ByProto[e.Proto]++
	if e.In != "" {
		m.stats.ByIface[e.In]++
	}
	m.stats.BySrcIP[e.Src]++
	if e.DstPort != 0 {
		key := fmt.Sprintf("%d", e.DstPort)
		m.stats.ByDstPort[key]++
	}

	// Append to filtered if it passes the current filter.
	if m.matchesFilter(e) {
		m.filtered = append(m.filtered, e)
		// Follow the tail only when the cursor was already at the bottom
		// before this entry arrived (len-2 is the old last index).
		// If the user has scrolled up, leave the cursor alone.
		if !m.detailOpen && m.cursor == len(m.filtered)-2 {
			m.cursor = len(m.filtered) - 1
		}
	}
}

// applyFilters rebuilds the filtered slice from all.
func (m *Model) applyFilters() {
	m.filtered = m.filtered[:0]
	for _, e := range m.all {
		if m.matchesFilter(e) {
			m.filtered = append(m.filtered, e)
		}
	}
	// Clamp cursor.
	if m.cursor >= len(m.filtered) {
		m.cursor = len(m.filtered) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

// matchesFilter returns true if e satisfies all active filters.
func (m Model) matchesFilter(e parser.LogEntry) bool {
	if m.filters.Action != "" && e.Action() != m.filters.Action {
		return false
	}
	if m.filters.Proto != "" && e.Proto != m.filters.Proto {
		return false
	}
	if m.filters.IPSubstr != "" {
		sub := strings.ToLower(m.filters.IPSubstr)
		if !strings.Contains(strings.ToLower(e.Src), sub) &&
			!strings.Contains(strings.ToLower(e.Dst), sub) {
			return false
		}
	}
	return true
}

// View renders the entire TUI.
func (m Model) View() string {
	if m.err != nil {
		return fmt.Sprintf("Fatal error: %v\n\nPress q to quit.\n", m.err)
	}

	var sb strings.Builder

	// ── Top bar ─────────────────────────────────────────────────────────────
	tabs := []string{"1: Logs", "2: Stats", "3: Filters"}
	tabBar := ""
	for i, t := range tabs {
		if i == m.tab {
			tabBar += ui.StyleTabActive.Render("["+t+"]")
		} else {
			tabBar += ui.StyleTabInactive.Render("["+t+"]")
		}
		tabBar += "  "
	}
	title := ui.StyleTitle.Render("iptables-log-tui v0.4")
	spacer := m.width - len(tabBar) - len("iptables-log-tui v0.4") - 2
	if spacer < 0 {
		spacer = 0
	}
	sb.WriteString(tabBar + strings.Repeat(" ", spacer) + title + "\n")
	sb.WriteString(ui.StyleDivider.Render(strings.Repeat("─", m.width)) + "\n")

	// ── Body ─────────────────────────────────────────────────────────────────
	contentHeight := m.height - 4 // top bar(2) + divider(1) + help(1)

	switch m.tab {
	case TabLogs:
		if m.detailOpen {
			src := m.detailEntry.Src
			var wi *whois.Result
			if info, ok := m.whoisCache[src]; ok {
				wi = &info
			}
			loading := m.whoisPending[src]
			sb.WriteString(ui.RenderDetailPage(m.detailEntry, m.width, contentHeight, wi, loading))
		} else {
			sb.WriteString(ui.RenderLogsTab(m.filtered, m.cursor, m.width, contentHeight, m.categorize))
		}
	case TabStats:
		sb.WriteString(ui.RenderStatsTab(m.stats, m.width))
	case TabFilters:
		sb.WriteString(ui.RenderFilterTab(m.filters))
	}

	// ── Help footer ──────────────────────────────────────────────────────────
	sb.WriteString(ui.StyleDivider.Render(strings.Repeat("─", m.width)) + "\n")
	switch {
	case m.detailOpen:
		sb.WriteString(ui.StyleHelp.Render("[Esc] or [Enter] — back to log list"))
	case m.searching:
		sb.WriteString("  IP filter: " + m.searchInput.View() + "  " + ui.StyleHelp.Render("[Esc/Enter] done"))
	default:
		sb.WriteString(ui.StyleHelp.Render(
			"[d]DROP  [a]ACCEPT  [t]TCP  [u]UDP  [/]IP search  [Enter]detail  [Tab]switch  [q]quit",
		))
	}

	return sb.String()
}
