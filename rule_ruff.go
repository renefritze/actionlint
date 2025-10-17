package actionlint

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"encoding/json"
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

	args := make([]string, 0, len(rule.args)+6)
	// Use JSON format for stable, machine-parseable output
	args = append(args, "check", "--stdin-filename", "stdin.py", "--format", "json")
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

		return rule.parseJSONOutput(stdout, pos)
	})
}

// parseJSONOutput parses Ruff JSON output and records errors to the rule.
func (rule *RuleRuff) parseJSONOutput(stdout []byte, pos *Pos) error {
	// Ruff emits a JSON array of objects: [{"path":..., "diagnostics":[{...}, ...]}, ...]
	// If output is empty or not JSON, ignore it (this keeps behaviour robust when non-JSON text is present).
	tb := bytes.TrimSpace(stdout)
	if len(tb) == 0 {
		return nil
	}
	// Quick check: if it does not start with '[' or '{', treat as unrelated plain text and ignore.
	if tb[0] != '[' && tb[0] != '{' {
		// If it looks like ruff plain-text diagnostics (e.g. starts with "stdin:" or "<stdin>:")
		// treat it as a parsing failure so caller can learn something went wrong.
		if bytes.HasPrefix(tb, []byte("stdin:")) || bytes.HasPrefix(tb, []byte("<stdin>:") ) || bytes.Contains(tb, []byte("<stdin>:")) {
			return fmt.Errorf("could not parse ruff JSON output while checking script at %s: legacy/plain output detected; output: %q", pos, stdout)
		}
		// Otherwise ignore unrelated plain text
		return nil
	}
	var entries []struct {
		Path        string `json:"path"`
		Diagnostics []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			// start/end are objects with "line" and "column" in our expected test payload
			Start struct {
				Line   int `json:"line"`
				Column int `json:"column"`
			} `json:"start"`
			End struct {
				Line   int `json:"line"`
				Column int `json:"column"`
			} `json:"end"`
		} `json:"diagnostics"`
	}

	dec := json.NewDecoder(bytes.NewReader(stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		// If JSON decode fails, include raw output in the error for debugging
		return fmt.Errorf("could not parse ruff JSON output while checking script at %s: %w; output: %q", pos, err, stdout)
	}

	for _, e := range entries {
		for _, d := range e.Diagnostics {
			code := d.Code
			if code == "" {
				code = "ruff"
			}
			// Include ruff code and its position inside the message, keep pos as the YAML location
			msg := strings.TrimSpace(d.Message)
			rule.mu.Lock()
			rule.Errorf(pos, "ruff reported issue in this script (%s): %d:%d: %s", code, d.Start.Line, d.Start.Column, msg)
			rule.mu.Unlock()
		}
	}

	return nil
}
