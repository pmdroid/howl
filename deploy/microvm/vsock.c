#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <unistd.h>

static int open_port(unsigned int port, int target) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_vm address = {
        .svm_family = AF_VSOCK,
        .svm_cid = VMADDR_CID_HOST,
        .svm_port = port,
    };
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        dup2(fd, target) < 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    if (fd != target)
        close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "0") && strcmp(argv[1], "1")))
        return 2;
    if (open_port(7821, 3) || open_port(7822, 4) ||
        (argv[1][0] == '1' && open_port(7823, 5))) {
        perror("Howl vsock");
        return 1;
    }
    execl("/init", "/init", "--worker", argv[1], (char *)0);
    perror("Howl guest worker");
    return 1;
}
