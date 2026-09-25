#include "spawn_gate.h"

#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define AGB_EXIT_NOT_RELEASED 126
#define AGB_EXIT_EXEC_FAILED 127

// Highest descriptor to close in the child: the soft limit, or higher if a descriptor
// above it is already open (it can stay open after the limit is lowered). Computed
// before fork because the child may only make async-signal-safe calls.
static int descriptor_ceiling(void) {
    int ceiling = getdtablesize();
    // A few descriptors fit on the stack, so a caller that is itself a forked copy of a
    // multithreaded process (the terminal tests' stand-in supervisor) never allocates.
    // A full buffer may be truncated: then list them all on the heap.
    struct proc_fdinfo local[64];
    struct proc_fdinfo *fds = local;
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, local, (int)sizeof local);
    if (bytes >= (int)sizeof local) {
        bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
        if (bytes <= 0 || !(fds = malloc((size_t)bytes))) return ceiling;
        bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, bytes);
    }
    for (int i = 0; bytes > 0 && i < bytes / (int)PROC_PIDLISTFD_SIZE; i++) {
        if (fds[i].proc_fd >= ceiling) ceiling = fds[i].proc_fd + 1;
    }
    if (fds != local) free(fds);
    return ceiling;
}

static int close_on_exec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    return (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) ? errno : 0;
}

int agb_spawn_gated(const char *path, char *const argv[], char *const envp[], agb_gated_child *out) {
    if (!path || !argv || !envp || !out) return EINVAL;
    int gate[2];
    if (pipe(gate) != 0) return errno;
    // Neither end may leak into the agent image or into other children.
    int status = close_on_exec(gate[0]);
    if (!status) status = close_on_exec(gate[1]);
    // A child that died before release must surface as EPIPE, without a process-wide
    // SIG_IGN that the agent would inherit across execve.
    if (!status && fcntl(gate[1], F_SETNOSIGPIPE, 1) != 0) status = errno;
    if (status) { close(gate[0]); close(gate[1]); return status; }
    int descriptor_limit = descriptor_ceiling();
    pid_t pid = fork();
    if (pid < 0) { status = errno; close(gate[0]); close(gate[1]); return status; }
    if (pid == 0) {
        // Child: async-signal-safe calls only until execve.
        char byte = 0;
        close(gate[1]);  // the supervisor's end: its close must reach us as EOF
        // Own process group, so a failed launch can be killed with its descendants.
        setpgid(0, 0);
        // Only stdin/stdout/stderr reach the agent. A descriptor opened before binding
        // would give access that no later AUTH_OPEN check mediates.
        for (int fd = 3; fd < descriptor_limit; fd++) {
            if (fd != gate[0]) close(fd);
        }
        ssize_t got;
        do { got = read(gate[0], &byte, 1); } while (got < 0 && errno == EINTR);
        if (got != 1) _exit(AGB_EXIT_NOT_RELEASED);
        // Start the agent with default dispositions and an empty mask, whatever the
        // supervisor inherited. Ignored signals would otherwise survive execve.
        struct sigaction default_action;
        default_action.sa_handler = SIG_DFL;
        default_action.sa_flags = 0;
        sigemptyset(&default_action.sa_mask);
        for (int signal_number = 1; signal_number < NSIG; signal_number++) {
            sigaction(signal_number, &default_action, NULL);  // fails harmlessly for KILL/STOP
        }
        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);
        execve(path, argv, envp);
        _exit(AGB_EXIT_EXEC_FAILED);
    }
    // Also set here: the child's setpgid and this one race, and either order is fine.
    setpgid(pid, pid);
    close(gate[0]);
    out->pid = pid;
    out->release_fd = gate[1];
    return 0;
}

int agb_release(agb_gated_child *child) {
    if (!child || child->release_fd < 0) return EINVAL;
    const char byte = 'x';
    ssize_t wrote;
    do { wrote = write(child->release_fd, &byte, 1); } while (wrote < 0 && errno == EINTR);
    int status = wrote == 1 ? 0 : (wrote < 0 ? errno : EIO);
    close(child->release_fd);
    child->release_fd = -1;
    return status;
}

void agb_abort(agb_gated_child *child) {
    if (child && child->release_fd >= 0) {
        close(child->release_fd);
        child->release_fd = -1;
    }
}

bool agb_terminal_is_foreground(int fd) {
    if (!isatty(fd)) return false;
    // Fails with ENOTTY when fd is a terminal but not the caller's controlling terminal.
    pid_t foreground = tcgetpgrp(fd);
    return foreground > 0 && foreground == getpgrp();
}

int agb_terminal_hand_over(int fd, pid_t pgid) {
    if (fd < 0 || pgid <= 0) return EINVAL;
    // A background caller would otherwise get SIGTTOU, and stop, instead of the change.
    sigset_t ttou, previous;
    sigemptyset(&ttou);
    sigaddset(&ttou, SIGTTOU);
    int status = pthread_sigmask(SIG_BLOCK, &ttou, &previous);
    if (status) return status;
    status = tcsetpgrp(fd, pgid) == 0 ? 0 : errno;
    pthread_sigmask(SIG_SETMASK, &previous, NULL);
    return status;
}

int agb_terminal_reclaim(int fd) {
    return agb_terminal_hand_over(fd, getpgrp());
}

int agb_terminal_start_job(int fd, pid_t pgid) {
    if (fd < 0 || pgid <= 0) return EINVAL;
    // The kernel lets a background group's tcsetpgrp through only if the caller blocks or
    // ignores SIGTTOU; otherwise it stops the group with SIGTTOU, and after SIGCONT the call
    // fails with EINTR (measured on macOS 26) and is retried here. So an inherited SIG_IGN
    // is replaced by the default for this call, and the signal is unblocked on this thread
    // (the calling thread's mask is what the kernel checks).
    struct sigaction default_action, previous_action;
    default_action.sa_handler = SIG_DFL;
    default_action.sa_flags = 0;
    sigemptyset(&default_action.sa_mask);
    if (sigaction(SIGTTOU, &default_action, &previous_action) != 0) return errno;
    sigset_t ttou, previous_mask;
    sigemptyset(&ttou);
    sigaddset(&ttou, SIGTTOU);
    int status = pthread_sigmask(SIG_UNBLOCK, &ttou, &previous_mask);
    if (!status) {
        // EINTR: the stop or another signal interrupted the wait; ask again.
        do { status = tcsetpgrp(fd, pgid) == 0 ? 0 : errno; } while (status == EINTR);
        pthread_sigmask(SIG_SETMASK, &previous_mask, NULL);
    }
    sigaction(SIGTTOU, &previous_action, NULL);
    return status;
}

// *held can be stale: if the caller was stopped from outside (kill -STOP) while the agent
// held the terminal, the shell took it back and may have resumed the job with `bg`. Only
// a terminal still in the agent's group is the caller's to take back.
static int reclaim_from_agent(int fd, pid_t pgid) {
    return tcgetpgrp(fd) == pgid ? agb_terminal_reclaim(fd) : 0;
}

// Handle one stop of the agent. *held says whether the agent's group holds the terminal
// on the caller's behalf; it is false after `bg`, when the caller must not take the
// terminal away from whatever job the shell put in the foreground.
static int resume_stopped_job(int fd, pid_t pid, int stop_signal, bool *held) {
    int status;
    if (*held && tcgetpgrp(fd) != pid) *held = false;  // the shell took it meanwhile
    // After `bg` and a later `fg`, the agent stops on its next terminal access while the
    // shell has already made this job the foreground one: just hand the terminal on.
    bool moved_to_foreground = !*held && (stop_signal == SIGTTIN || stop_signal == SIGTTOU) &&
                               agb_terminal_is_foreground(fd);
    if (*held) {
        if ((status = agb_terminal_reclaim(fd))) return status;
        *held = false;
    }
    // Otherwise stop this whole job as the terminal's Ctrl-Z would have. kill() returns
    // once the shell continues it. The kernel discards SIGTSTP for an orphaned group; the
    // job is then still in the foreground and the agent is simply continued.
    if (!moved_to_foreground && kill(0, SIGTSTP) != 0) return errno;
    // Ctrl-Z plus `bg` can land between this check and the handover, as at launch; the
    // supervisor then stops on SIGTTOU and hands over only after `fg`.
    if (agb_terminal_is_foreground(fd)) {
        if ((status = agb_terminal_start_job(fd, pid))) return status;
        *held = true;
    }
    // ESRCH: the group died meanwhile; the next waitpid reports it.
    if (killpg(pid, SIGCONT) != 0 && errno != ESRCH) return errno;
    return 0;
}

int agb_wait_foreground_job(int fd, pid_t pid, int *status_out, bool *finished_out) {
    if (fd < 0 || pid <= 0 || !status_out || !finished_out) return EINVAL;
    *finished_out = false;
    bool held = true;  // the caller handed the terminal over before the release byte
    for (;;) {
        int status = 0;
        if (waitpid(pid, &status, WUNTRACED) < 0) {
            if (errno == EINTR) continue;
            int error = errno;
            if (held) reclaim_from_agent(fd, pid);  // best effort; the wait error is reported
            return error;
        }
        if (!WIFSTOPPED(status)) {
            *status_out = status;
            *finished_out = true;
            // The group may be gone already: tcgetpgrp still names it (measured) until
            // another group takes the terminal, and tcsetpgrp to our own group still works.
            return held ? reclaim_from_agent(fd, pid) : 0;
        }
        int error = resume_stopped_job(fd, pid, WSTOPSIG(status), &held);
        if (error) {
            if (held) reclaim_from_agent(fd, pid);  // best effort; the first error is reported
            return error;
        }
    }
}

int agb_audit_identity(pid_t pid, int32_t *pid_out, int32_t *pidversion_out) {
    if (pid <= 0 || !pid_out || !pidversion_out) return EINVAL;
    mach_port_t name = MACH_PORT_NULL;
    kern_return_t kr = task_name_for_pid(mach_task_self(), pid, &name);
    if (kr != KERN_SUCCESS) return kr;
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kr = task_info(name, TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
    mach_port_deallocate(mach_task_self(), name);
    if (kr != KERN_SUCCESS) return kr;
    // The name port could belong to a reused PID; the caller compares against its own child PID.
    if (audit_token_to_pid(token) != pid) return ESRCH;
    *pid_out = audit_token_to_pid(token);
    *pidversion_out = audit_token_to_pidversion(token);
    return 0;
}

void agb_token_identity(const audit_token_t *token, int32_t *pid_out, int32_t *pidversion_out) {
    *pid_out = audit_token_to_pid(*token);
    *pidversion_out = audit_token_to_pidversion(*token);
}

int agb_self_audit_token(audit_token_t *out) {
    if (!out) return EINVAL;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t kr = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)out, &count);
    return kr == KERN_SUCCESS ? 0 : kr;
}
