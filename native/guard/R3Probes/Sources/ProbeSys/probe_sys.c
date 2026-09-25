#include "probe_sys.h"

#include <copyfile.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <poll.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

int r3_clonefile(const char *source, const char *destination) {
    return clonefile(source, destination, CLONE_NOFOLLOW) == 0 ? 0 : errno;
}

int r3_copyfile_data(const char *source, const char *destination) {
    return copyfile(source, destination, NULL, COPYFILE_DATA | COPYFILE_EXCL) == 0 ? 0 : errno;
}

int r3_rename_swap(const char *first, const char *second) {
    return renamex_np(first, second, RENAME_SWAP) == 0 ? 0 : errno;
}

int r3_getattrlist_type(const char *path) {
    struct attrlist request;
    memset(&request, 0, sizeof(request));
    request.bitmapcount = ATTR_BIT_MAP_COUNT;
    request.commonattr = ATTR_CMN_OBJTYPE;
    char buffer[64];
    return getattrlist(path, &request, buffer, sizeof(buffer), FSOPT_NOFOLLOW) == 0 ? 0 : errno;
}

int r3_acl_set_empty(const char *path) {
    acl_t acl = acl_init(1);
    if (acl == NULL) return errno;
    int status = acl_set_link_np(path, ACL_TYPE_EXTENDED, acl) == 0 ? 0 : errno;
    acl_free(acl);
    return status;
}

int r3_read_directory(const char *path, size_t *out_entries, int *out_failed_at_open) {
    *out_failed_at_open = 1;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno;
    *out_failed_at_open = 0;
    DIR *directory = fdopendir(fd);
    if (directory == NULL) {
        int saved = errno;
        close(fd);
        return saved;
    }
    size_t count = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) break;
        count++;
    }
    int saved = errno;
    closedir(directory);
    *out_entries = count;
    return saved;
}

// Offset of the first Mach-O slice and its code signature, from a fat or thin 64-bit file.
static int first_slice(int fd, off_t *out_slice, uint32_t *out_signature_offset, uint32_t *out_signature_size) {
    uint32_t magic;
    if (pread(fd, &magic, sizeof(magic), 0) != sizeof(magic)) return EINVAL;
    off_t slice = 0;
    if (magic == OSSwapHostToBigInt32(FAT_MAGIC)) {
        struct fat_arch arch;
        if (pread(fd, &arch, sizeof(arch), sizeof(struct fat_header)) != sizeof(arch)) return EINVAL;
        slice = (off_t)OSSwapBigToHostInt32(arch.offset);
    } else if (magic != MH_MAGIC_64) {
        return EINVAL;
    }
    struct mach_header_64 header;
    if (pread(fd, &header, sizeof(header), slice) != sizeof(header) || header.magic != MH_MAGIC_64) return EINVAL;
    off_t cursor = slice + (off_t)sizeof(header);
    for (uint32_t index = 0; index < header.ncmds && index < 512; index++) {
        struct load_command command;
        if (pread(fd, &command, sizeof(command), cursor) != sizeof(command) || command.cmdsize < sizeof(command)) return EINVAL;
        if (command.cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command signature;
            if (pread(fd, &signature, sizeof(signature), cursor) != sizeof(signature)) return EINVAL;
            *out_slice = slice;
            *out_signature_offset = signature.dataoff;
            *out_signature_size = signature.datasize;
            return 0;
        }
        cursor += command.cmdsize;
    }
    return EINVAL;
}

static int map_executable_page(int fd, size_t *out_length, int *out_step) {
    off_t slice;
    uint32_t signature_offset, signature_size;
    *out_step = R3_STEP_CODESIG;
    int status = first_slice(fd, &slice, &signature_offset, &signature_size);
    if (status != 0) return status;
    fsignatures_t signatures = {.fs_file_start = slice, .fs_blob_start = (void *)(uintptr_t)signature_offset,
                                .fs_blob_size = signature_size};
    if (fcntl(fd, F_ADDFILESIGS_RETURN, &signatures) == -1) return errno;
    *out_step = R3_STEP_MMAP;
    size_t length = (size_t)getpagesize();
    void *bytes = mmap(NULL, length, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, slice);
    if (bytes == MAP_FAILED) return errno;
    munmap(bytes, length);
    *out_length = length;
    return 0;
}

int r3_mmap_fd(int fd, int mode, size_t *out_length, int *out_step) {
    if (mode == 2) return map_executable_page(fd, out_length, out_step);
    *out_step = R3_STEP_FSTAT;
    struct stat info;
    if (fstat(fd, &info) != 0) return errno;
    if (!S_ISREG(info.st_mode) || info.st_size <= 0) return EINVAL;
    *out_step = R3_STEP_MMAP;
    size_t length = (size_t)info.st_size;
    int protection = mode == 1 ? PROT_READ | PROT_WRITE : PROT_READ;
    unsigned char *bytes = mmap(NULL, length, protection, mode == 1 ? MAP_SHARED : MAP_PRIVATE, fd, 0);
    if (bytes == MAP_FAILED) return errno;
    // Touch every page so the access really happens; the sum is discarded.
    volatile unsigned char sink = 0;
    long page = sysconf(_SC_PAGESIZE);
    for (size_t offset = 0; offset < length; offset += (size_t)(page > 0 ? page : 4096)) sink ^= bytes[offset];
    (void)sink;
    if (mode == 1) {
        // Writes the first byte back unchanged, so the shared mapping is really written.
        volatile unsigned char *first = bytes;
        *first = *first;
    }
    munmap(bytes, length);
    *out_length = length;
    return 0;
}

static int fill_address(const char *path, struct sockaddr_un *address) {
    memset(address, 0, sizeof(*address));
    if (strlen(path) >= sizeof(address->sun_path)) return ENAMETOOLONG;
    address->sun_family = AF_UNIX;
    strlcpy(address->sun_path, path, sizeof(address->sun_path));
    return 0;
}

static int new_stream_socket(int *out_fd) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return errno;
    int on = 1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 || setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) != 0) {
        int saved = errno;
        close(fd);
        return saved;
    }
    *out_fd = fd;
    return 0;
}

int r3_unix_listen(const char *path, int *out_fd) {
    struct sockaddr_un address;
    int status = fill_address(path, &address);
    if (status != 0) return status;
    int fd;
    if ((status = new_stream_socket(&fd)) != 0) return status;
    // The socket file is created by bind; keep it owner-only.
    mode_t previous = umask(077);
    int bound = bind(fd, (struct sockaddr *)&address, sizeof(address));
    int saved = errno;
    umask(previous);
    if (bound != 0 || listen(fd, 4) != 0) {
        if (bound == 0) saved = errno;
        close(fd);
        return saved;
    }
    *out_fd = fd;
    return 0;
}

int r3_unix_connect(const char *path, int *out_fd) {
    struct sockaddr_un address;
    int status = fill_address(path, &address);
    if (status != 0) return status;
    int fd;
    if ((status = new_stream_socket(&fd)) != 0) return status;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved = errno;
        close(fd);
        return saved;
    }
    *out_fd = fd;
    return 0;
}

int r3_accept_timeout(int listen_fd, int timeout_ms, int *out_fd) {
    struct pollfd waiting = {.fd = listen_fd, .events = POLLIN};
    int ready;
    while ((ready = poll(&waiting, 1, timeout_ms)) < 0 && errno == EINTR) {}
    if (ready < 0) return errno;
    if (ready == 0) return ETIMEDOUT;
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) return errno;
    int on = 1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
    *out_fd = fd;
    return 0;
}

int r3_read_byte_timeout(int fd, int timeout_ms, char *out_byte) {
    struct pollfd waiting = {.fd = fd, .events = POLLIN};
    int ready;
    while ((ready = poll(&waiting, 1, timeout_ms)) < 0 && errno == EINTR) {}
    if (ready < 0) return errno;
    if (ready == 0) return ETIMEDOUT;
    ssize_t count;
    while ((count = read(fd, out_byte, 1)) < 0 && errno == EINTR) {}
    return count == 1 ? 0 : (count < 0 ? errno : ECONNRESET);
}

int r3_send_fd(int socket_fd, int fd) {
    char payload = 'F';
    struct iovec vector = {.iov_base = &payload, .iov_len = 1};
    union {
        struct cmsghdr header;
        char buffer[CMSG_SPACE(sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
                             .msg_control = control.buffer, .msg_controllen = sizeof(control.buffer)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(int));
    ssize_t sent;
    while ((sent = sendmsg(socket_fd, &message, 0)) < 0 && errno == EINTR) {}
    return sent == 1 ? 0 : (sent < 0 ? errno : EIO);
}

int r3_recv_fd(int socket_fd, int *out_fd) {
    char payload;
    struct iovec vector = {.iov_base = &payload, .iov_len = 1};
    union {
        struct cmsghdr header;
        char buffer[CMSG_SPACE(sizeof(int))];
    } control;
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
                             .msg_control = control.buffer, .msg_controllen = sizeof(control.buffer)};
    ssize_t received;
    while ((received = recvmsg(socket_fd, &message, 0)) < 0 && errno == EINTR) {}
    if (received < 0) return errno;
    if (received == 0) return ECONNRESET;
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(sizeof(int))) return EBADMSG;
    memcpy(out_fd, CMSG_DATA(header), sizeof(int));
    // macOS has no MSG_CMSG_CLOEXEC, so close-on-exec is set right after receipt.
    fcntl(*out_fd, F_SETFD, FD_CLOEXEC);
    return 0;
}

// What the forked child reports: errno (0 on success), the failing step and a byte count.
struct fork_report {
    int status;
    int failed_at_open;
    long long bytes;
};

static void fork_child(const char *path, int report_fd) {
    struct fork_report report = {0, 1, 0};
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        report.status = errno;
    } else {
        report.failed_at_open = 0;
        char buffer[4096];
        ssize_t count;
        while (report.bytes < (1 << 20) && (count = read(fd, buffer, sizeof(buffer))) != 0) {
            if (count < 0) {
                if (errno == EINTR) continue;
                report.status = errno;
                break;
            }
            report.bytes += count;
        }
        close(fd);
    }
    ssize_t written = write(report_fd, &report, sizeof(report));
    _exit(written == (ssize_t)sizeof(report) ? 0 : 1);
}

int r3_fork_read(const char *path, size_t *out_bytes, int *out_failed_at_open) {
    // -1 until the child reports: the errno then belongs to the harness, not the probe.
    *out_failed_at_open = -1;
    int ends[2];
    if (pipe(ends) != 0) return errno;
    fcntl(ends[0], F_SETFD, FD_CLOEXEC);
    fcntl(ends[1], F_SETFD, FD_CLOEXEC);
    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        close(ends[0]);
        close(ends[1]);
        return saved;
    }
    if (pid == 0) {
        close(ends[0]);
        fork_child(path, ends[1]);
    }
    close(ends[1]);
    struct fork_report report;
    ssize_t count;
    while ((count = read(ends[0], &report, sizeof(report))) < 0 && errno == EINTR) {}
    close(ends[0]);
    int wait_status;
    int waited = r3_wait(pid, &wait_status);
    if (waited != 0) return waited;
    if (count != (ssize_t)sizeof(report) || !WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0) return EIO;
    *out_failed_at_open = report.failed_at_open;
    *out_bytes = (size_t)report.bytes;
    return report.status;
}

int r3_spawn(const char *path, char *const argv[], int stdout_fd, pid_t *out_pid) {
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int status = posix_spawn_file_actions_init(&actions);
    if (status != 0) return status;
    if ((status = posix_spawnattr_init(&attributes)) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return status;
    }
    status = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT);
    if (status == 0) status = posix_spawn_file_actions_addinherit_np(&actions, STDIN_FILENO);
    if (status == 0) status = posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO);
    if (status == 0) {
        status = stdout_fd >= 0 ? posix_spawn_file_actions_adddup2(&actions, stdout_fd, STDOUT_FILENO)
                                : posix_spawn_file_actions_addinherit_np(&actions, STDOUT_FILENO);
    }
    char *const environment[] = {NULL};
    if (status == 0) status = posix_spawn(out_pid, path, &actions, &attributes, argv, environment);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    return status;
}

int r3_wait(pid_t pid, int *out_status) {
    while (waitpid(pid, out_status, 0) < 0) {
        if (errno != EINTR) return errno;
    }
    return 0;
}

int r3_self_path(char *buffer, size_t size) {
    uint32_t capacity = (uint32_t)size;
    return _NSGetExecutablePath(buffer, &capacity) == 0 ? 0 : ENAMETOOLONG;
}
