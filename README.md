# Nanodimite
A nanomite PoC which uses FNV-1a at compile-time.

## What is this useful for?
Nanodimite´s purpose is to mask/hide native WinAPI calls from reverse engineers. It **can** be modified to support normal functions, should probably rewrite this to use LLVM for more possibilities.

## What to improve?
1. Implement encryption for _**g_imports**_ to make reverse-engineering more painful.
2. Obfuscate and hide the VE handler from static reverse engineering, smack on some LLVM pain :)

Before compilation:
```c++
int main() {
    AddVectoredExceptionHandler(1, VEHHandler);
    CALL_IMPORT(MessageBoxA)(NULL, "Hello from obfuscated import!", "Test", MB_OK);
    return 0;
}
```

After compilation:
```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  AddVectoredExceptionHandler(1u, Handler);
  MEMORY[0x4EA5D77E](0, "Hello from obfuscated import!", "Test", 0);
  return 0;
}
```

Dissasembly:
```asm
; int __fastcall main(int argc, const char **argv, const char **envp)
main proc near
sub     rsp, 28h
lea     rdx, Handler    ; Handler
mov     ecx, 1          ; First
call    cs:AddVectoredExceptionHandler
xor     r9d, r9d
lea     r8, aTest       ; "Test"
lea     rdx, aHelloFromObfus ; "Hello from obfuscated import!"
xor     ecx, ecx
call    cs:qword_140002258
xor     eax, eax
add     rsp, 28h
retn
main endp
```

Address is completely masked. 
