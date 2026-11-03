//go:build darwin && arm64 && klorq_p04_cli_live

package command

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const p04CLISyntheticSecret = "klorq-p04-cli-synthetic-credential"

func TestP04CLIServiceSecretLifecycleAgainstOwnedDaemonAndVM(t *testing.T) {
	inputs := getP04CLIInputs(t)
	root, err := os.MkdirTemp("/private/tmp", "lsbx-p04-cli-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cliPath := filepath.Join(binDir, "lsbx")
	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-trimpath", "-o", cliPath, "./cmd/lsbx")
	build.Dir = moduleRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build owned CLI: %v: %s", err, output)
	}
	for _, item := range []struct{ source, name string }{
		{inputs.shim, "containerd-shim-nerdbox-v1"},
		{inputs.kernel, "nerdbox-kernel-arm64"},
		{inputs.rootfs, "nerdbox-rootfs-arm64.erofs"},
	} {
		if err := os.Symlink(item.source, filepath.Join(binDir, item.name)); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var containerd, daemon *exec.Cmd
	var containerdDone, daemonDone <-chan struct{}
	var containerdLog, daemonLog *os.File
	secretStored, sandboxCreated := false, false
	containerdSocket := filepath.Join(root, "containerd.sock")
	cliSocket := filepath.Join(root, "sandboxesd.sock")
	name := "p04-cli-" + randomP04CLIName(t)
	brokerSocket := ""
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	cliEnv := append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+"/opt/homebrew/bin:/usr/bin:/bin")
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		if err := cleanupP04CLIResources(cleanupCtx, cliPath, cliSocket, cliEnv, inputs.ctr, containerdSocket, name, secretStored, sandboxCreated); err != nil {
			t.Errorf("remove owned CLI acceptance resources: %v", err)
		}
		stopP04CLIProcess(t, daemon, daemonDone)
		stopP04CLIProcess(t, containerd, containerdDone)
		if brokerSocket != "" {
			if err := removeP04CLIBrokerSocket(brokerSocket); err != nil {
				t.Errorf("remove only the owned stale broker socket: %v", err)
			}
		}
		if daemonLog != nil {
			if err := daemonLog.Close(); err != nil {
				t.Errorf("close owned daemon log: %v", err)
			}
		}
		if containerdLog != nil {
			if err := containerdLog.Close(); err != nil {
				t.Errorf("close owned containerd log: %v", err)
			}
		}
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove owned CLI acceptance directory: %v", err)
		}
	}
	t.Cleanup(cleanup)

	containerdConfig := filepath.Join(root, "containerd.toml")
	config := fmt.Sprintf("version = 4\nroot = %q\nstate = %q\n[plugins.'io.containerd.server.v1.grpc']\naddress = %q\nuid = %d\ngid = %d\n[plugins.'io.containerd.server.v1.ttrpc']\naddress = %q\nuid = %d\ngid = %d\n",
		filepath.Join(root, "containerd-root"), filepath.Join(root, "containerd-state"), containerdSocket, os.Getuid(), os.Getgid(), containerdSocket+".ttrpc", os.Getuid(), os.Getgid())
	if err := os.WriteFile(containerdConfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	containerdLog, err = os.Create(filepath.Join(root, "containerd.log"))
	if err != nil {
		t.Fatal(err)
	}
	startContainerd := func() error {
		containerd = exec.Command(inputs.containerd, "--config", containerdConfig)
		containerd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		containerd.Env = append(os.Environ(),
			"PATH="+binDir+string(os.PathListSeparator)+"/opt/homebrew/bin:/opt/homebrew/opt/e2fsprogs/sbin:/usr/bin:/bin",
			"LIBKRUN_PATH="+inputs.libkrun,
			"SAILOR_PATH="+filepath.Join(filepath.Dir(inputs.shim), "lib"),
		)
		containerd.Stdout, containerd.Stderr = containerdLog, containerdLog
		var startErr error
		containerdDone, startErr = startP04CLIProcess(containerd)
		if startErr != nil {
			return startErr
		}
		return waitP04CLISocket(ctx, inputs.ctr, containerdSocket, containerdDone)
	}
	if err := startContainerd(); err != nil {
		t.Fatalf("wait for owned containerd: %v", err)
	}

	daemonLog, err = os.Create(filepath.Join(root, "sandboxesd.log"))
	if err != nil {
		t.Fatal(err)
	}
	daemonArgs := []string{
		"-state", filepath.Join(root, "state"), "-socket", cliSocket,
		"-containerd", containerdSocket, "-ctr", inputs.ctr,
		"-runtime", "io.containerd.nerdbox.v1", "-snapshotter", "erofs",
		"-image", inputs.image, "-fifo-dir", filepath.Join(root, "fifo"),
		"-gvproxy", inputs.gvproxy, "-run-dir", filepath.Join(root, "run", "gateway"),
		"-proxy-helper", inputs.helper,
	}
	startDaemon := func() error {
		daemon = exec.Command(inputs.daemon, daemonArgs...)
		daemon.Env = append(os.Environ(),
			"PATH="+binDir+string(os.PathListSeparator)+"/opt/homebrew/bin:/opt/homebrew/opt/e2fsprogs/sbin:/usr/bin:/bin",
			"LIBKRUN_PATH="+inputs.libkrun,
			"SAILOR_PATH="+filepath.Join(filepath.Dir(inputs.shim), "lib"),
		)
		daemon.Stdout, daemon.Stderr = daemonLog, daemonLog
		var startErr error
		daemonDone, startErr = startP04CLIProcess(daemon)
		if startErr != nil {
			return startErr
		}
		return waitP04CLISocket(ctx, cliPath, cliSocket, daemonDone)
	}
	if err := startDaemon(); err != nil {
		t.Fatalf("start owned daemon: %v", err)
	}

	if output, err := runP04CLI(ctx, cliPath, cliSocket, cliEnv, "secret", "set", "openai", "--sandbox", name, "--token", p04CLISyntheticSecret); err != nil {
		t.Fatalf("CLI secret set failed: %v", err)
	} else if strings.Contains(output, p04CLISyntheticSecret) {
		t.Fatal("CLI printed the synthetic service secret")
	} else {
		secretStored = true
	}
	runOutput, err := runP04CLI(ctx, cliPath, cliSocket, cliEnv, "run", "--detach", "--name", name, "--image", inputs.image, "--env", "OPENAI_API_KEY=${proxy:openai}", "shell", workspace)
	if err != nil {
		t.Fatalf("CLI run did not create/start the owned sandbox: %v", err)
	} else {
		sandboxCreated = true
	}
	sandboxID := strings.TrimSpace(runOutput)
	if sandboxID == "" {
		t.Fatal("CLI run did not return the owned sandbox ID")
	}
	brokerSocket = p04CLIBrokerSocket(sandboxID)
	checkEnv := `test "$OPENAI_API_KEY" = klorq-proxy-placeholder && test "$OPENAI_BASE_URL" = http://127.0.0.1:3128/v1`
	execWithProxyEnv := func() (string, error) {
		return runP04CLI(ctx, cliPath, cliSocket, cliEnv, "exec", "--env", "OPENAI_API_KEY=${proxy:openai}", name, "/bin/sh", "-c", checkEnv)
	}
	if _, err := execWithProxyEnv(); err != nil {
		t.Fatalf("CLI exec did not receive proxy placeholder env: %v", err)
	}
	if _, err := runP04CLI(ctx, cliPath, cliSocket, cliEnv, "stop", name); err != nil {
		t.Fatalf("CLI stop failed: %v", err)
	}
	if _, err := runP04CLI(ctx, cliPath, cliSocket, cliEnv, "start", name); err != nil {
		t.Fatalf("CLI start did not restore the broker: %v", err)
	}
	if _, err := execWithProxyEnv(); err != nil {
		t.Fatalf("CLI exec after restart did not receive proxy placeholder env: %v", err)
	}
	if err := requestP04CLIBrokerToken(ctx, brokerSocket); err != nil {
		t.Fatalf("positive control host broker request before daemon kill: %v", err)
	}
	if err := daemon.Process.Kill(); err != nil {
		t.Fatalf("kill only the owned daemon process: %v", err)
	}
	select {
	case <-daemonDone:
	case <-time.After(15 * time.Second):
		t.Fatal("owned daemon did not exit after SIGKILL")
	}
	daemon = nil
	if err := os.Remove(cliSocket); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove stale owned daemon socket: %v", err)
	}
	if _, err := execP04CLIInGuest(ctx, inputs.ctr, containerdSocket, filepath.Join(root, "fifo"), name, "/bin/true"); err != nil {
		t.Fatalf("positive control guest exec after daemon kill: %v", err)
	}
	if err := requestP04CLIBrokerToken(ctx, brokerSocket); err == nil {
		t.Fatal("host broker remained available after abrupt daemon termination")
	}
	if err := startDaemon(); err != nil {
		t.Fatalf("restart owned daemon after process death: %v", err)
	}
	if _, err := runP04CLI(ctx, cliPath, cliSocket, cliEnv, "start", name); err != nil {
		t.Fatalf("CLI start did not recover the daemon-killed sandbox: %v", err)
	}
	if err := requestP04CLIBrokerToken(ctx, brokerSocket); err != nil {
		t.Fatalf("host broker did not recover after daemon restart: %v", err)
	}
	if _, err := execWithProxyEnv(); err != nil {
		t.Fatalf("CLI exec after daemon recovery did not receive proxy placeholder env: %v", err)
	}
	// Simulate loss of the entire owned host runtime process group. The group is
	// isolated with Setpgid above, so this cannot signal the test runner or any
	// user-owned containerd/VM. This is process-crash evidence, not a power-loss
	// simulation.
	if err := daemon.Process.Kill(); err != nil {
		t.Fatalf("kill owned daemon before runtime-stack crash test: %v", err)
	}
	select {
	case <-daemonDone:
	case <-time.After(15 * time.Second):
		t.Fatal("owned daemon did not exit before runtime-stack crash test")
	}
	daemon = nil
	if err := killP04CLIProcessGroup(containerd, containerdDone); err != nil {
		t.Fatalf("kill only the owned containerd runtime process group: %v", err)
	}
	containerd = nil
	containerdDone = nil
	for _, socket := range []string{containerdSocket, containerdSocket + ".ttrpc", cliSocket} {
		if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("remove stale owned runtime socket %s: %v", filepath.Base(socket), err)
		}
	}
	if err := startContainerd(); err != nil {
		t.Fatalf("restart owned containerd after runtime process-group loss: %v", err)
	}
	if err := startDaemon(); err != nil {
		t.Fatalf("restart owned daemon after runtime process-group loss: %v", err)
	}
	if _, err := runP04CLI(ctx, cliPath, cliSocket, cliEnv, "start", name); err != nil {
		t.Fatalf("CLI start did not recover after owned runtime process-group loss: %v", err)
	}
	if err := requestP04CLIBrokerToken(ctx, brokerSocket); err != nil {
		t.Fatalf("host broker did not recover after runtime process-group loss: %v", err)
	}
	if _, err := execWithProxyEnv(); err != nil {
		t.Fatalf("CLI exec after runtime process-group recovery failed: %v", err)
	}
	if _, err := runP04CLI(ctx, cliPath, cliSocket, cliEnv, "secret", "rm", "openai", "--sandbox", name); err != nil {
		t.Fatalf("CLI service secret revoke failed: %v", err)
	} else {
		secretStored = false
	}
	if _, err := execWithProxyEnv(); err == nil {
		t.Fatal("CLI exec succeeded after service secret revoke")
	}
	if err := scanP04CLIState(filepath.Join(root, "state"), []byte(p04CLISyntheticSecret)); err != nil {
		t.Fatalf("synthetic credential persisted in owned daemon state: %v", err)
	}
	if _, err := runP04CLI(ctx, cliPath, cliSocket, cliEnv, "rm", "--force", name); err != nil {
		t.Fatalf("CLI remove failed: %v", err)
	} else {
		sandboxCreated = false
	}
	t.Log("PASS: CLI set/run/exec/stop/start; daemon SIGKILL closed the broker; complete owned containerd process-group loss recovered from persistent state; revoke denied later exec; rm and owned-resource cleanup")
}

func killP04CLIProcessGroup(cmd *exec.Cmd, done <-chan struct{}) error {
	if cmd == nil || cmd.Process == nil || done == nil {
		return errors.New("owned containerd process group is unavailable")
	}
	pgid := cmd.Process.Pid // Setpgid makes the leader PID the unique process-group ID.
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("signal owned containerd process group: %w", err)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		return errors.New("owned containerd did not exit after process-group kill")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(-pgid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("inspect owned containerd process group: %w", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("owned containerd process group still has processes after SIGKILL")
}

func removeP04CLIBrokerSocket(path string) error {
	dir := filepath.Dir(path)
	dirInfo, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm()&0o077 != 0 || !p04CLIOwnedByCurrentUser(dirInfo) {
		return errors.New("refusing to inspect a broker socket in a non-private directory")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || !p04CLIOwnedByCurrentUser(info) {
		return errors.New("refusing to remove a broker path not owned by this user")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func p04CLIOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

type p04CLIInputs struct {
	containerd, ctr, shim, kernel, rootfs, helper, libkrun, gvproxy, daemon, image string
}

func getP04CLIInputs(t *testing.T) p04CLIInputs {
	t.Helper()
	get := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			t.Skipf("set %s to explicitly select owned-VM CLI acceptance input", name)
		}
		if _, err := os.Stat(value); err != nil {
			t.Fatalf("%s is unavailable: %v", name, err)
		}
		return value
	}
	image := os.Getenv("KLORQ_P04_IMAGE")
	if image == "" {
		image = "docker.io/library/alpine:3.22"
	}
	return p04CLIInputs{
		containerd: get("KLORQ_P04_CONTAINERD"), ctr: get("KLORQ_P04_CTR"),
		shim: get("KLORQ_P04_SHIM"), kernel: get("KLORQ_P04_KERNEL"),
		rootfs: get("KLORQ_P04_ROOTFS"), helper: get("KLORQ_P04_HELPER"),
		libkrun: get("KLORQ_P04_LIBKRUN"), gvproxy: get("KLORQ_P04_GVPROXY"),
		daemon: get("KLORQ_P04_DAEMON"), image: image,
	}
}

func randomP04CLIName(t *testing.T) string {
	t.Helper()
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(nonce[:])
}

func startP04CLIProcess(cmd *exec.Cmd) (<-chan struct{}, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	return done, nil
}

func stopP04CLIProcess(t *testing.T, cmd *exec.Cmd, done <-chan struct{}) {
	t.Helper()
	if cmd == nil || cmd.Process == nil || done == nil {
		return
	}
	select {
	case <-done:
		if state := cmd.ProcessState; state != nil && state.ExitCode() != 0 {
			t.Errorf("owned process exited unexpectedly with code %d", state.ExitCode())
		}
		return
	default:
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("signal owned process: %v", err)
	}
	select {
	case <-done:
		if state := cmd.ProcessState; state != nil && state.ExitCode() != 0 {
			t.Errorf("owned process exited with code %d after interrupt", state.ExitCode())
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Error("owned process did not stop after interrupt")
	}
}

func waitP04CLISocket(ctx context.Context, client, socket string, done <-chan struct{}) error {
	for {
		if client == "ctr" || strings.HasSuffix(client, "/ctr") {
			cmd := exec.CommandContext(ctx, client, "--address", socket, "version")
			if err := cmd.Run(); err == nil {
				return nil
			}
		} else {
			conn, err := net.DialTimeout("unix", socket, 250*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return errors.New("owned process exited before socket readiness")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func runP04CLI(ctx context.Context, binary, socket string, env []string, args ...string) (string, error) {
	command := append([]string{"--socket", socket}, args...)
	cmd := exec.CommandContext(ctx, binary, command...)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	redacted := strings.ReplaceAll(string(output), p04CLISyntheticSecret, "[redacted]")
	if err != nil {
		if len(redacted) > 4096 {
			redacted = redacted[:4096] + "[truncated]"
		}
		return redacted, fmt.Errorf("CLI %q exited unsuccessfully: %w: %s", args[0], err, redacted)
	}
	return redacted, nil
}

func execP04CLIInGuest(ctx context.Context, ctrPath, containerdSocket, fifoDir, sandboxName string, argv ...string) (string, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	execID := "klorq-p04-probe-" + hex.EncodeToString(nonce[:])
	args := make([]string, 0, 11+len(argv))
	args = append(args,
		"--address", containerdSocket, "--namespace", "klorq", "tasks", "exec",
		"--exec-id", execID, "--fifo-dir", fifoDir, "klorq-"+sandboxName,
	)
	args = append(args, argv...)
	cmd := exec.CommandContext(ctx, ctrPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("owned guest probe failed: %w: %s", err, output)
	}
	return string(output), nil
}

func p04CLIBrokerSocket(sandboxID string) string {
	hash := sha256.Sum256([]byte(sandboxID))
	return filepath.Join("/tmp", "kp-"+hex.EncodeToString(hash[:8]), "p.sock")
}

func requestP04CLIBrokerToken(ctx context.Context, socket string) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://broker/__klorq/proxy/token", http.NoBody)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
		transport.CloseIdleConnections()
	}()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("broker returned status %d", response.StatusCode)
	}
	return nil
}

func removeP04CLISecret(ctx context.Context, binary, socket string, env []string, sandboxName string) error {
	_, err := runP04CLI(ctx, binary, socket, env, "secret", "rm", "openai", "--sandbox", sandboxName)
	if err == nil {
		return nil
	}
	account := "openai/sandbox/" + sandboxName
	security := exec.CommandContext(ctx, "/usr/bin/security", "delete-generic-password", "-s", "com.klorq.service-secrets.v1", "-a", account)
	if output, fallbackErr := security.CombinedOutput(); fallbackErr != nil {
		return fmt.Errorf("daemon cleanup failed: %w; keychain cleanup failed: %w: %s", err, fallbackErr, output)
	}
	return nil
}

func removeP04CLISandbox(ctx context.Context, binary, socket string, env []string, sandboxName string) error {
	_, err := runP04CLI(ctx, binary, socket, env, "rm", "--force", sandboxName)
	return err
}

func cleanupP04CLIResources(ctx context.Context, binary, socket string, env []string, ctrPath, containerdSocket, sandboxName string, secretStored, sandboxCreated bool) error {
	var cleanupErrors []error
	if secretStored {
		if err := removeP04CLISecret(ctx, binary, socket, env, sandboxName); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove service secret: %w", err))
		}
	}
	if sandboxCreated {
		if err := removeP04CLISandbox(ctx, binary, socket, env, sandboxName); err != nil {
			if runtimeErr := cleanupP04CLIContainer(ctx, ctrPath, containerdSocket, sandboxName); runtimeErr != nil {
				cleanupErrors = append(cleanupErrors, errors.Join(fmt.Errorf("remove sandbox through CLI: %w", err), runtimeErr))
			}
		}
	}
	return errors.Join(cleanupErrors...)
}

func cleanupP04CLIContainer(ctx context.Context, ctrPath, containerdSocket, sandboxName string) error {
	containerID := "klorq-" + sandboxName
	containers, err := exec.CommandContext(ctx, ctrPath, "--address", containerdSocket, "--namespace", "klorq", "containers", "list", "-q").Output()
	if err != nil {
		return fmt.Errorf("list owned containerd containers: %w", err)
	}
	found := false
	for _, id := range strings.Fields(string(containers)) {
		if id == containerID {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	tasks, err := exec.CommandContext(ctx, ctrPath, "--address", containerdSocket, "--namespace", "klorq", "tasks", "list", "-q").Output()
	if err != nil {
		return fmt.Errorf("list owned containerd tasks: %w", err)
	}
	for _, id := range strings.Fields(string(tasks)) {
		if id != containerID {
			continue
		}
		kill := exec.CommandContext(ctx, ctrPath, "--address", containerdSocket, "--namespace", "klorq", "tasks", "kill", "--signal", "SIGKILL", containerID)
		if output, err := kill.CombinedOutput(); err != nil {
			return fmt.Errorf("kill owned task: %w: %s", err, output)
		}
		removeTask := exec.CommandContext(ctx, ctrPath, "--address", containerdSocket, "--namespace", "klorq", "tasks", "delete", containerID)
		if output, err := removeTask.CombinedOutput(); err != nil {
			return fmt.Errorf("delete owned task: %w: %s", err, output)
		}
		break
	}
	removeContainer := exec.CommandContext(ctx, ctrPath, "--address", containerdSocket, "--namespace", "klorq", "containers", "delete", containerID)
	if output, err := removeContainer.CombinedOutput(); err != nil {
		return fmt.Errorf("delete owned container: %w: %s", err, output)
	}
	return nil
}

func scanP04CLIState(root string, secret []byte) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), string(secret)) {
			return fmt.Errorf("synthetic credential found in daemon state file %s", filepath.Base(path))
		}
		return nil
	})
}
