// Syscall helpers the probes need but Swift cannot express directly: CMSG macros for
// SCM_RIGHTS, sockaddr_un, MAP_FAILED, ACLs, getattrlist, fork and posix_spawn file actions.
// Every function returns 0 or an errno value; nothing here prints or returns file contents.
#ifndef R3_PROBE_SYS_H
#define R3_PROBE_SYS_H

#include <stddef.h>
#include <sys/types.h>

int r3_clonefile(const char *source, const char *destination);
// copyfile(3) with COPYFILE_DATA | COPYFILE_EXCL: an ordinary open/read/write copy.
int r3_copyfile_data(const char *source, const char *destination);
// renamex_np(RENAME_SWAP): exchanges two existing files.
int r3_rename_swap(const char *first, const char *second);
// getattrlist(ATTR_CMN_OBJTYPE) without following a final symlink.
int r3_getattrlist_type(const char *path);
// Sets an empty extended ACL (acl_set_link_np), which an owner may do unprivileged.
int r3_acl_set_empty(const char *path);

// Opens a directory (O_NOFOLLOW) and reads every entry. `out_failed_at_open` tells which
// step produced the returned errno.
int r3_read_directory(const char *path, size_t *out_entries, int *out_failed_at_open);

// Steps reported by r3_mmap_fd when it fails.
enum { R3_STEP_FSTAT = 1, R3_STEP_CODESIG = 2, R3_STEP_MMAP = 3 };
// Maps a descriptor and touches it. `mode` 0: whole file PROT_READ, MAP_PRIVATE.
// `mode` 1: whole file PROT_READ|PROT_WRITE, MAP_SHARED; the first byte is written back
// unchanged. `mode` 2: one page of the first Mach-O slice, PROT_READ|PROT_EXEC, after
// registering its code signature (F_ADDFILESIGS_RETURN), which the kernel requires for
// executable file mappings. Nothing mapped is executed.
int r3_mmap_fd(int fd, int mode, size_t *out_length, int *out_step);

int r3_unix_listen(const char *path, int *out_fd);
int r3_unix_connect(const char *path, int *out_fd);
int r3_accept_timeout(int listen_fd, int timeout_ms, int *out_fd);
// Reads one request byte, waiting at most `timeout_ms`.
int r3_read_byte_timeout(int fd, int timeout_ms, char *out_byte);
int r3_send_fd(int socket_fd, int fd);
int r3_recv_fd(int socket_fd, int *out_fd);

// fork() without exec: the child opens `path` (O_NOFOLLOW), reads at most 1 MiB, reports
// the outcome over a pipe and exits. Only async-signal-safe calls run in the child.
// `out_failed_at_open` is -1 when the harness itself failed (fork, pipe, wait), 1 or 0 otherwise.
int r3_fork_read(const char *path, size_t *out_bytes, int *out_failed_at_open);

// posix_spawn with an empty environment and POSIX_SPAWN_CLOEXEC_DEFAULT: the child gets
// only stdin, stderr and either stdout or `stdout_fd` (when >= 0) as its stdout.
int r3_spawn(const char *path, char *const argv[], int stdout_fd, pid_t *out_pid);
int r3_wait(pid_t pid, int *out_status);
int r3_self_path(char *buffer, size_t size);

#endif
