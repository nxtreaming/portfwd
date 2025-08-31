#include "secure_random.h"
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>
#endif

int secure_random_bytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }

#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }

    BOOL success = CryptGenRandom(hProv, (DWORD)len, buf);
    CryptReleaseContext(hProv, 0);

    return success ? 0 : -1;

#elif defined(__linux__) && defined(SYS_getrandom)
    // Use getrandom() syscall on Linux if available
    ssize_t result = getrandom(buf, len, 0);
    return (result == (ssize_t)len) ? 0 : -1;

#else
    // Fallback to /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            if (n == 0 || errno != EINTR) {
                close(fd);
                return -1;
            }
            continue;
        }
        total += (size_t)n;
    }

    close(fd);
    return 0;
#endif
}
