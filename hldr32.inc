PAGE_EXECUTE_READWRITE          equ     40h

MEM_COMMIT                      equ     1000h
MEM_RESERVE                     equ     2000h

tebProcessEnvironmentBlock      equ     30h
pebLdr                          equ     0ch
ldrInLoadOrderModuleList        equ     0ch
mlDllBase                       equ     18h

lfanew                          equ     3ch

IMAGE_DIRECTORY_ENTRY_EXPORT    equ     78h

struc   krncrcstk
.kVirtualAlloc:          resd 1
.kFlushInstructionCache: resd 1
endstruc

struc _IMAGE_EXPORT_DIRECTORY
.edCharacteristics:       resd 1
.edTimeDateStamp:         resd 1
.edMajorVersion:          resw 1
.edMinorVersion:          resw 1
.edName:                  resd 1
.edBase:                  resd 1
.edNumberOfFunctions:     resd 1
.edNumberOfNames:         resd 1
.edAddressOfFunctions:    resd 1
.edAddressOfNames:        resd 1
.edAddressOfNameOrdinals: resd 1
endstruc                                   