#include <windows.h>
#include <cstdio>
#include <cstdint>

/* borrowed from https://github.com/Acrillis/SynapseX/blob/master/Synapse/Src/Utilities/Hashing/fnv.hpp */
template <uint32_t Hash> constexpr uint32_t fnv1a_assured() { return Hash; }
constexpr uint32_t fnv1a(const char* Str, const uint32_t Hash = 0x811c9dc5)
{
    return Str[0] == '\0' ? Hash : fnv1a(&Str[1], (Hash ^ Str[0]) * 0x811c9dc5);
}
#define FNVA1_CONSTEXPR(str) (fnv1a_assured<fnv1a(str)>())

struct ImportEntry {
    uint32_t hash;
    const char* module;
    const char* function;
    void* resolved;
};

ImportEntry g_imports[] = {
    { FNVA1_CONSTEXPR("MessageBoxA"), "user32.dll", "MessageBoxA", nullptr },
};

void* ResolveImportByHash(uint32_t hash) {
    for (auto& import : g_imports) {
        if (import.hash == hash) {
            if (!import.resolved) {
                HMODULE hMod = GetModuleHandleA(import.module);
                if (!hMod) hMod = LoadLibraryA(import.module);
                if (hMod) {
                    import.resolved = GetProcAddress(hMod, import.function);
                }
            }
            return import.resolved;
        }
    }
    return nullptr;
}

LONG WINAPI VEHHandler(EXCEPTION_POINTERS* pExceptionInfo) {
    DWORD exceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;

    if (exceptionCode == EXCEPTION_ACCESS_VIOLATION || exceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        CONTEXT* ctx = pExceptionInfo->ContextRecord;
        uintptr_t rip = ctx->Rip;

        if (rip < 0x100000000ULL) {
            uint32_t hash = (uint32_t)rip;
            void* realFunc = ResolveImportByHash(hash);

            if (realFunc) {
                ctx->Rip = (DWORD64)realFunc;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        if (exceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            void* faultAddr = (void*)pExceptionInfo->ExceptionRecord->ExceptionInformation[1];
            uintptr_t faultValue = (uintptr_t)faultAddr;

            if (faultValue < 0x100000000ULL) {
                uint32_t hash = (uint32_t)faultValue;
                void* realFunc = ResolveImportByHash(hash);

                if (realFunc) {
                    if (ctx->Rax == faultValue) {
                        ctx->Rax = (DWORD64)realFunc;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    if (ctx->Rcx == faultValue) {
                        ctx->Rcx = (DWORD64)realFunc;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    if (ctx->Rdx == faultValue) {
                        ctx->Rdx = (DWORD64)realFunc;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    if (ctx->Rbx == faultValue) {
                        ctx->Rbx = (DWORD64)realFunc;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    if (ctx->Rsi == faultValue) {
                        ctx->Rsi = (DWORD64)realFunc;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    if (ctx->Rdi == faultValue) {
                        ctx->Rdi = (DWORD64)realFunc;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    if (ctx->R8 == faultValue) {
                        ctx->R8 = (DWORD64)realFunc;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    if (ctx->R9 == faultValue) {
                        ctx->R9 = (DWORD64)realFunc;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    if (ctx->R10 == faultValue) {
                        ctx->R10 = (DWORD64)realFunc;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    if (ctx->R11 == faultValue) {
                        ctx->R11 = (DWORD64)realFunc;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                }
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

#define OBFUSCATED_IMPORT(name) \
    __declspec(selectany) void* __import_##name = (void*)(uintptr_t)FNVA1_CONSTEXPR(#name);
OBFUSCATED_IMPORT(MessageBoxA)
#define CALL_IMPORT(name) ((decltype(&name))__import_##name)

int main() {
    AddVectoredExceptionHandler(1, VEHHandler);
    CALL_IMPORT(MessageBoxA)(NULL, "Hello from obfuscated import!", "Test", MB_OK);

    return 0;
}
