#pragma once
// Launch gate for the agentbelt supervisor (R2 skeleton).
//
// The supervisor forks a child that keeps running supervisor code and blocks on a
// pipe. While it waits, the supervisor reads the child's audit token and registers
// a launch ticket for exactly that identity. Only then is the child released to
// execve() the agent. If the gate closes without a release byte, for example
// because the supervisor died, the child exits without executing anything.
//
// Written in C because the child runs between fork() and execve(), where only
// async-signal-safe calls are allowed; Swift code could allocate or take locks.

#include <mach/message.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    pid_t pid;
    int release_fd;  // write end of the gate; -1 once released or aborted
} agb_gated_child;

// Fork a child that waits on the gate, then execve(path, argv, envp).
// The child leads a new process group, keeps only descriptors 0-2 open, and resets all
// signal dispositions and its signal mask before execve.
// Returns 0 on success, or an errno value. argv and envp must be NULL-terminated.
// Pipe ends are marked close-on-exec just after pipe(); macOS has no pipe2, so another
// thread forking in that window could inherit them. Callers spawn from one thread.
int agb_spawn_gated(const char *path, char *const argv[], char *const envp[], agb_gated_child *out);

// Let the waiting child call execve. Returns 0 or an errno value (EPIPE if the child
// already died; the release end has F_SETNOSIGPIPE, so no signal is raised).
int agb_release(agb_gated_child *child);

// Close the gate without releasing: the child exits with status 126 before exec.
void agb_abort(agb_gated_child *child);

// Terminal foreground handover, done the way a job-control shell does it. The supervisor
// hands its terminal to the agent's group before writing the release byte, so the agent
// never runs as a background job, and takes it back when the agent stops or ends.
// SIGTTOU is blocked on the calling thread around every tcsetpgrp, because the
// supervisor is itself a background job while the agent holds the terminal.

// True if fd is the caller's controlling terminal and the caller's process group is its
// foreground group. Only then does the supervisor hand the terminal over; otherwise the
// launch is non-interactive and the terminal is left alone.
bool agb_terminal_is_foreground(int fd);

// Make pgid the foreground group of the terminal on fd. pgid must be a group in the
// caller's session, such as a gated child's. Returns 0 or an errno value.
int agb_terminal_hand_over(int fd, pid_t pgid);

// Make the caller's own group the foreground group again. Returns 0 or an errno value.
int agb_terminal_reclaim(int fd);

// Handover after a foreground check (at launch, and after `fg`): make pgid the foreground
// group, as a job may that is still in the foreground. Unlike agb_terminal_hand_over, SIGTTOU stays deliverable (and is not
// ignored) for the call, so a caller that became a background job after checking
// agb_terminal_is_foreground (Ctrl-Z and `bg` in between) stops on SIGTTOU like any job
// touching the terminal, and completes the handover only once `fg` continues it. Returns
// 0 or an errno value (EIO for an orphaned background group).
int agb_terminal_start_job(int fd, pid_t pgid);

// Wait for the agent pid while its group holds the terminal on fd, acting as its
// job-control shell:
// - When the agent stops (Ctrl-Z, SIGTTIN, SIGTTOU), take the terminal back and stop the
//   caller's own process group with SIGTSTP, so the user's shell sees the job stopped.
//   Once continued, hand the terminal to the agent again if the job is in the foreground
//   (`fg`, not `bg`) and continue the agent's group with SIGCONT.
// - When the agent exits or is killed, take the terminal back.
// The terminal is taken back only while the agent's group still holds it: if the caller
// was stopped from outside and the shell took the terminal meanwhile, it stays there.
// No signal handlers are installed. Sets *finished_out to true once the agent is reaped,
// with its wait status in *status_out. Returns 0, or the errno value of the first failure;
// if *finished_out is false then, the agent is still alive (possibly stopped) and the
// caller must stop it. The caller must not reap pid concurrently.
int agb_wait_foreground_job(int fd, pid_t pid, int *status_out, bool *finished_out);

// Audit-token PID and pidversion of a same-user process, via task_name_for_pid and
// TASK_AUDIT_TOKEN. Returns 0, or a nonzero Mach/POSIX error code.
int agb_audit_identity(pid_t pid, int32_t *pid_out, int32_t *pidversion_out);

// PID and pidversion carried by an audit token, e.g. one from an ES message.
void agb_token_identity(const audit_token_t *token, int32_t *pid_out, int32_t *pidversion_out);

// Audit token of the calling process, e.g. to mute the ES client's own events.
int agb_self_audit_token(audit_token_t *out);
