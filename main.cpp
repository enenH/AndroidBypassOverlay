#include <iostream>
#include <dirent.h>
#include <cstdio>
#include <cstring>
#include <fcntl.h>

#include "elf_util.h"

static int findPid(const char* processName) {
    int id;
    int pid = -1;
    DIR* dir;
    FILE* fp;
    char filename[32];
    char cmdline[256];

    struct dirent* entry;
    if (processName == NULL) {
        return -1;
    }
    dir = opendir("/proc");
    if (dir == NULL) {
        return -1;
    }
    while ((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strcmp(processName, cmdline) == 0) {
                    pid = id;
                    break;
                }
            }
        }
    }
    closedir(dir);
    return pid;
}

static uintptr_t findModuleBase(int pid, const char* moduleName) {
    FILE* fp;
    char filename[32];
    char line[512];
    uintptr_t address = 0;
    char* pch;

    if (pid < 0) {
        return 0;
    }

    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, moduleName)) {
                pch = strtok(line, "-");
                address = strtoul(pch, NULL, 16);
                if (address == 0x8000)
                    address = 0;
                break;
            }
        }
        fclose(fp);
    }
    return address;
}


int main() {
    if (android_get_device_api_level() < 34) {
        system("settings put global block_untrusted_touches 0");
        std::cout << "Done" << std::endl;
        return 0;
    }

    int pid = findPid("system_server");
    if (pid <= 0) {
        std::cout << "Process not found" << std::endl;
        return 0;
    }

    uintptr_t base = findModuleBase(pid, "/lib64/libinputflinger.so");
    if (base == 0) {
        std::cout << "Module not found" << std::endl;
        return 0;
    }

    auto addr = base + (uintptr_t)SandHook::ElfImg("/system/lib64/libinputflinger.so").getSymbAddress(
        "_ZNK7android15inputdispatcher15InputDispatcher20isTouchTrustedLockedERKNS1_18TouchOcclusionInfoE");
    if (addr < 0xffff) {
        std::cout << "Symbol not found" << std::endl;
        return 0;
    }

    std::cout << "Address: " << std::hex << addr << std::endl;

    int memfd = open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDWR);
    if (memfd < 0) {
        std::cout << "Open mem failed" << std::endl;
        return 0;
    }

    uint32_t PACIASP = 0xD503233F;

    uint32_t code = 0;
    pread64(memfd, &code, sizeof(code), addr);
    if (code == PACIASP) {
        uint8_t buffer[] = {0x20, 0x00, 0x80, 0x52, 0xBF, 0x23, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6};
        pwrite64(memfd, buffer, sizeof(buffer), addr + 4);
    } else {
        uint8_t buffer[] = {0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6};
        pwrite64(memfd, buffer, sizeof(buffer), addr);
    }
    close(memfd);

    std::cout << "Done" << std::endl;
    return 0;
}
