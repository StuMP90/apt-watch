// Package runx runs external commands safely: explicit argv (never a
// shell), a timeout, LC_ALL=C and a minimal environment.
package runx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// Path is the fixed search path used to find commands.
const Path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

// DefaultTimeout applies when Cmd.Timeout is zero.
const DefaultTimeout = 2 * time.Minute

type Cmd struct {
	Name    string
	Args    []string
	Env     []string // extra KEY=VALUE pairs on top of the minimal environment
	Stdin   io.Reader
	Dir     string // working directory; "" for the current one
	Timeout time.Duration
}

type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Run executes c and returns its output. A non-zero exit status is
// returned as an error along with the Result.
func Run(ctx context.Context, c Cmd) (Result, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	path, err := LookPath(c.Name)
	if err != nil {
		return Result{ExitCode: -1}, err
	}
	cmd := exec.CommandContext(ctx, path, c.Args...)
	cmd.Env = append([]string{"PATH=" + Path, "LC_ALL=C", "LANG=C"}, c.Env...)
	cmd.Stdin = c.Stdin
	cmd.Dir = c.Dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second

	err = cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: -1}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("%s: timed out after %s", c.Name, timeout)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			msg := strings.TrimSpace(stderr.String())
			if len(msg) > 300 {
				msg = msg[:300] + "…"
			}
			return res, fmt.Errorf("%s: exit status %d: %s", c.Name, res.ExitCode, msg)
		}
		return res, fmt.Errorf("%s: %w", c.Name, err)
	}
	return res, nil
}

// LookPath finds name on the fixed Path rather than the caller's $PATH.
func LookPath(name string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range strings.Split(Path, ":") {
		p := dir + "/" + name
		if _, err := exec.LookPath(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in %s", name, Path)
}
