package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/google/subcommands"
	"path/filepath"
)

type setupCmd struct{ wdPath string }

func (s *setupCmd) Name() string     { return "setup" }
func (s *setupCmd) Synopsis() string { return "Setup certificate renewal service" }
func (s *setupCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.wdPath, "wd", ".", "Path to the directory to create config files in (defaults to the working directory)")
}
func (s *setupCmd) Usage() string {
	return `setup [-wd <directory>]
  Setup Orchid automatically by answering questions.
`
}

func (s *setupCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	// get absolute path to specify files
	wdAbs, err := filepath.Abs(s.wdPath)
	if err != nil {
		fmt.Println("[Orchid] Failed to get full directory path: ", err)
		return subcommands.ExitFailure
	}

	// ask about running the setup steps
	createFile := false
	err = survey.AskOne(&survey.Confirm{Message: fmt.Sprintf("Create Orchid config files in this directory: '%s'?", wdAbs)}, &createFile)
	if err != nil {
		fmt.Println("[Orchid] Error: ", err)
		return subcommands.ExitFailure
	}
	if !createFile {
		fmt.Println("[Orchid] Goodbye")
		return subcommands.ExitSuccess
	}

	var answers struct {
		ApiListen    string
		FirstDomains []string
	}
	_ = answers

	// ask main questions
	return subcommands.ExitUsageError
}
