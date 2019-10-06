bits 32
%include "hldr32.inc"

;-----------------------------------------------------------------------------
;recover kernel32 image base
;-----------------------------------------------------------------------------

hldr_begin:
        push    tebProcessEnvironmentBlock
        pop     eax
        fs mov  eax, dword [eax]
        mov     eax, dword [eax + pebLdr]
        mov     esi, dword [eax + ldrInLoadOrderModuleList]
        lodsd
        xchg    eax, esi
        lodsd
        mov     ebp, dword [eax + mlDllBase]
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

        dd      0E9258E7Ah               ;FlushInstructionCache
        dd      009CE0D4Ah               ;VirtualAlloc
        db      0

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports:
        pop     esi
        mov     ebx, ebp
        mov     eax, dword [ebp + lfanew]
        add     ebx, dword [ebp + eax + IMAGE_DIRECTORY_ENTRY_EXPORT]
        cdq

walk_names:
        mov     eax, ebp
        mov     edi, ebp
        inc     edx
        add     eax, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNames]
        add     edi, dword [eax + edx * 4]
        or      eax, -1

crc_outer:
        xor     al, byte [edi]
        push    8
        pop     ecx

crc_inner:
        shr     eax, 1
        jnc     crc_skip
        xor     eax, 0edb88320h

crc_skip:
        loop    crc_inner
        inc     edi
        cmp     byte [edi], cl
        jne     crc_outer
        not     eax
        cmp     dword [esi], eax
        jne     walk_names

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        mov     edi, ebp
        mov     eax, ebp
        add     edi, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNameOrdinals]
        movzx   edi, word [edi + edx * 2]
        add     eax, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfFunctions]
        mov     eax, dword [eax + edi * 4]
        add     eax, ebp
        push    eax
        lodsd
        sub     cl, byte [esi]
        jnz     walk_names

;-----------------------------------------------------------------------------
;allocate executable memory for shellcodeified executable
;-----------------------------------------------------------------------------

        mov     esi, 0xdeadf00d
        mov     ebp, dword [esi + lfanew]
        add     ebp, esi
        mov     ch, (MEM_COMMIT | MEM_RESERVE) >> 8
        push    PAGE_EXECUTE_READWRITE
        push    ecx
        push    0xdeadfeed
        push    0
        call    dword [esp + 10h + krncrcstk.kVirtualAlloc]
        push    eax
        mov     ebx, esp

;-----------------------------------------------------------------------------
;copy shellcode into executable memory and jump to it
;-----------------------------------------------------------------------------

        mov     ecx, 0xdeadfeed
        mov     edi, eax
        push    esi
        rep     movsb
        pop     esi
        jmp     eax
