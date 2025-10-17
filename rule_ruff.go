package actionlint

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
)

// RuleRuff checks Python scripts at 'run:' using Ruff (https://github.com/astral-sh/ruff).
type RuleRuff struct {
	RuleBase
	cmd                   *externalCommand
	workflowShellIsPython shellIsPythonKind
	jobShellIsPython      shellIsPythonKind
	mu                    sync.Mutex
	args                  []string
}

func newRuleRuff(cmd *externalCommand) *RuleRuff {
	return &RuleRuff{
		RuleBase: RuleBase{
			name: "ruff",
			desc: "Checks for Python script when \"shell: python\" is configured using Ruff",
		},
		cmd:                   cmd,
		workflowShellIsPython: shellIsPythonKindUnspecified,
		jobShellIsPython:      shellIsPythonKindUnspecified,
		args:                  []string{},
	}
}

// NewRuleRuff creates new RuleRuff instance. Parameter executable can be command name or relative/absolute file path.
// When the given executable is not found in system, it returns an error.
func NewRuleRuff(executable string, proc *concurrentProcess) (*RuleRuff, error) {
	// Combine output so we can read findings and syntax errors consistently.
	cmd, err := proc.newCommandRunner(executable, true)
	if err != nil {
		return nil, err
	}
	return newRuleRuff(cmd), nil
}

// VisitJobPre is callback when visiting Job node before visiting its children.
func (rule *RuleRuff) VisitJobPre(n *Job) error {
	if n.Defaults != nil && n.Defaults.Run != nil {
		rule.jobShellIsPython = getShellIsPythonKind(n.Defaults.Run.Shell)
	}
	return nil
}

// VisitJobPost is callback when visiting Job node after visiting its children.
func (rule *RuleRuff) VisitJobPost(n *Job) error {
	rule.jobShellIsPython = shellIsPythonKindUnspecified
	return nil
}

// VisitWorkflowPre is callback when visiting Workflow node before visiting its children.
func (rule *RuleRuff) VisitWorkflowPre(n *Workflow) error {
	if n.Defaults != nil && n.Defaults.Run != nil {
		rule.workflowShellIsPython = getShellIsPythonKind(n.Defaults.Run.Shell)
	}
	return nil
}

// VisitWorkflowPost is callback when visiting Workflow node after visiting its children.
func (rule *RuleRuff) VisitWorkflowPost(n *Workflow) error {
	rule.workflowShellIsPython = shellIsPythonKindUnspecified
	return rule.cmd.wait()
}

// VisitStep is callback when visiting Step node.
func (rule *RuleRuff) VisitStep(n *Step) error {
	run, ok := n.Exec.(*ExecRun)
	if !ok || run.Run == nil {
		return nil
	}

	if !rule.isPythonShell(run) {
		return nil
	}

	rule.runRuff(run.Run.Value, run.RunPos)
	return nil
}

func (rule *RuleRuff) isPythonShell(r *ExecRun) bool {
	if k := getShellIsPythonKind(r.Shell); k != shellIsPythonKindUnspecified {
		return k == shellIsPythonKindPython
	}

	if rule.jobShellIsPython != shellIsPythonKindUnspecified {
		return rule.jobShellIsPython == shellIsPythonKindPython
	}

	return rule.workflowShellIsPython == shellIsPythonKindPython
}

func (rule *RuleRuff) runRuff(src string, pos *Pos) {
	src = sanitizeExpressionsInScript(src)
	rule.Debug("%s: Running %s for Python script:\n%s", pos, rule.cmd.exe, src)

	args := make([]string, 0, len(rule.args)+4)
	args = append(args, "check", "--stdin-filename", "stdin.py")
	args = append(args, rule.args...)
	args = append(args, "-")

	rule.cmd.run(args, src, func(stdout []byte, err error) error {
		if err != nil {
			rule.Debug("Command %s failed: %v", rule.cmd.exe, err)
			return fmt.Errorf("`%s` did not run successfully while checking script at %s: %w", rule.cmd.exe, pos, err)
		}
		if len(stdout) == 0 {
			return nil
		}

		for len(stdout) > 0 {
			var parseErr error
			stdout, parseErr = rule.parseNextError(stdout, pos)
			if parseErr != nil {
				return parseErr
			}
		}
		return nil
	})
}

func (rule *RuleRuff) parseNextError(stdout []byte, pos *Pos) ([]byte, error) {
	b := stdout

	idx := bytes.IndexByte(b, '\n')
	var line []byte
	if idx == -1 {
		line = bytes.TrimSpace(b)
		b = nil
	} else {
		line = bytes.TrimSpace(b[:idx])
		b = b[idx+1:]
	}

	if len(line) == 0 {
		return b, nil
	}

	s := string(line)
	if idx == -1 && len(stdout) > 0 && stdout[len(stdout)-1] != '\n' && stdout[len(stdout)-1] != '\r' && strings.Contains(s, ": ") {
		return nil, fmt.Errorf("error message from ruff does not end with \\n nor \\r\\n while checking script at %s. output: %q", pos, stdout)
	}

	if !strings.Contains(s, ": ") {
		return b, nil
	}
	parts := strings.SplitN(s, ": ", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("error message from ruff does not contain colon separator while checking script at %s. output: %q", pos, stdout)
	}

	loc := parts[0]
	msg := strings.TrimSpace(parts[1])
	locParts := strings.Split(loc, ":")
	if len(locParts) < 3 {
		return nil, fmt.Errorf("error message from ruff does not contain location information while checking script at %s. output: %q", pos, stdout)
	}
	lineStr := strings.TrimSpace(locParts[len(locParts)-2])
	colStr := strings.TrimSpace(locParts[len(locParts)-1])

	code := ""
	prefix := msg
	if sp := strings.Fields(msg); len(sp) > 0 {
		code = sp[0]
		prefix = strings.TrimSpace(strings.TrimPrefix(msg, code))
	}
	if code == "" {
		code = "ruff"
	}

	message := strings.TrimSpace(prefix)
	if message == "" {
		message = msg
	}

	rule.mu.Lock()
	rule.Errorf(pos, "ruff reported issue in this script (%s): %s:%s: %s", code, lineStr, colStr, message)
	rule.mu.Unlock()

	return b, nil
}
