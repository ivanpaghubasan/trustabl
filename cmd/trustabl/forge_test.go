package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestForgeCommand_RequiresPolicyFlag(t *testing.T) {
	cmd := newForgeCommand(nil)
	buf := &bytes.Buffer{}
	cmd.SetErr(buf)
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when --policy is missing")
	}
	// cobra reports "required flag(s) not set" for MarkFlagRequired
	if !strings.Contains(err.Error(), "policy") && !strings.Contains(buf.String(), "policy") {
		t.Errorf("error should mention 'policy', got err=%v buf=%s", err, buf.String())
	}
}

func TestForgeCommand_UnknownPolicy_Exit1(t *testing.T) {
	root := &cobra.Command{Use: "trustabl", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(newForgeCommand(nil))
	root.SetArgs([]string{"forge", "--policy", "not_a_real_sdk"})

	buf := &bytes.Buffer{}
	root.SetErr(buf)
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for unknown --policy value")
	}
	// exitCodeError.Error() returns "", so check stderr for the bad value
	if !strings.Contains(buf.String(), "not_a_real_sdk") {
		t.Errorf("stderr should mention the bad policy value, got: %s", buf.String())
	}
}

func TestForgeCommand_Flags(t *testing.T) {
	cmd := newForgeCommand(nil)
	if cmd.Flags().Lookup("policy") == nil {
		t.Error("--policy flag not registered")
	}
	if cmd.Flags().Lookup("output") == nil {
		t.Error("--output flag not registered")
	}
	if cmd.Flags().Lookup("rules-ref") == nil {
		t.Error("--rules-ref flag not registered")
	}
}

func TestForgeCommand_HelpText(t *testing.T) {
	cmd := newForgeCommand(nil)
	if !strings.Contains(cmd.Long, "trustabl scan") {
		t.Error("help text should mention trustabl scan for contrast")
	}
	if !strings.Contains(cmd.Long, "trustabl forge") {
		t.Error("help text should mention trustabl forge")
	}
}
