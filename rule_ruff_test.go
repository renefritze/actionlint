package actionlint

import (
	"strings"
	"testing"
)

func TestRuleRuffDetectPythonShell(t *testing.T) {
	tests := []struct {
		what     string
		isPython bool
		workflow string
		job      string
		step     string
	}{
		{what: "no default shell", isPython: false},
		{what: "workflow default", isPython: true, workflow: "python"},
		{what: "job default", isPython: true, job: "python"},
		{what: "step shell", isPython: true, step: "python"},
		{what: "custom shell", isPython: true, workflow: "python {0}"},
		{what: "other shell", isPython: false, workflow: "pwsh"},
		{what: "other custom shell", isPython: false, workflow: "bash -e {0}"},
	}

	for _, tc := range tests {
		t.Run(tc.what, func(t *testing.T) {
			r := newRuleRuff(&externalCommand{})

			w := &Workflow{}
			if tc.workflow != "" {
				w.Defaults = &Defaults{Run: &DefaultsRun{Shell: &String{Value: tc.workflow}}}
			}
			r.VisitWorkflowPre(w)

			j := &Job{}
			if tc.job != "" {
				j.Defaults = &Defaults{Run: &DefaultsRun{Shell: &String{Value: tc.job}}}
			}
			r.VisitJobPre(j)

			e := &ExecRun{}
			if tc.step != "" {
				e.Shell = &String{Value: tc.step}
			}
			if have := r.isPythonShell(e); have != tc.isPython {
				t.Fatalf("Actual isPython=%v but wanted isPython=%v", have, tc.isPython)
			}
		})
	}
}

func TestRuleRuffParseRuffOutputOK(t *testing.T) {
	tests := []struct {
		what  string
		input string
		want  []string
	}{
		{
			what:  "no error",
			input: "",
		},
		{
			what:  "ignore unrelated lines",
			input: "this line\nshould be\nignored\n",
		},
		{
			what:  "single error",
			input: "stdin:1:7: F401 `foo` imported but unused\n",
			want: []string{
				":1:2: ruff reported issue in this script (F401): 1:7: `foo` imported but unused [ruff]",
			},
		},
		{
			what: "multiple errors",
			input: "stdin:1:7: F401 `foo` imported but unused\n" +
				"stdin:2:2: E722 do not use bare 'except'\n",
			want: []string{
				":1:2: ruff reported issue in this script (F401): 1:7: `foo` imported but unused [ruff]",
				":1:2: ruff reported issue in this script (E722): 2:2: do not use bare 'except' [ruff]",
			},
		},
		{
			what:  "fix available marker",
			input: "stdin:3:5: SIM115 [*] Use contextlib.suppress(KeyError)\n",
			want: []string{
				":1:2: ruff reported issue in this script (SIM115): 3:5: [*] Use contextlib.suppress(KeyError) [ruff]",
			},
		},
		{
			what: "CRLF",
			input: "stdin:1:7: F401 `foo` imported but unused\r\n" +
				"stdin:2:1: PLW0602 [*] Universal newline style\r\n",
			want: []string{
				":1:2: ruff reported issue in this script (F401): 1:7: `foo` imported but unused [ruff]",
				":1:2: ruff reported issue in this script (PLW0602): 2:1: [*] Universal newline style [ruff]",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.what, func(t *testing.T) {
			r := newRuleRuff(&externalCommand{})
			stdout := []byte(tc.input)
			pos := &Pos{Line: 1, Col: 2}
			for len(stdout) > 0 {
				o, err := r.parseNextError(stdout, pos)
				if err != nil {
					t.Fatalf("Parse error %q while reading input %q", err, stdout)
				}
				stdout = o
			}
			have := r.Errs()
			if len(have) != len(tc.want) {
				msgs := []string{}
				for _, e := range have {
					msgs = append(msgs, e.Error())
				}
				t.Fatalf("%d errors were expected but got %d errors. got errors are:\n%#v", len(tc.want), len(have), msgs)
			}

			for i, want := range tc.want {
				have := have[i]
				msg := have.Error()
				if !strings.Contains(msg, want) {
					t.Errorf("Error %q does not contain expected message %q", msg, want)
				}
			}
		})
	}
}

func TestRuleRuffParseRuffOutputError(t *testing.T) {
	r := newRuleRuff(&externalCommand{})
	_, err := r.parseNextError([]byte("stdin:1:7: F401"), &Pos{})
	if err == nil {
		t.Fatal("Error did not happen")
	}
	have := err.Error()
	want := "error message from ruff"
	if !strings.Contains(have, want) {
		t.Fatalf("Error %q does not contain expected message %q", have, want)
	}
}
