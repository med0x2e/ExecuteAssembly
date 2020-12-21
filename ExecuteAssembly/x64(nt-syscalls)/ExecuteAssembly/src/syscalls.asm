.code

NtReadVirtualMemory PROC
	mov rax, gs:[60h]                             
NtReadVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+118h], 5
	je  NtReadVirtualMemory_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtReadVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtReadVirtualMemory_Check_10_0_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_X_XXXX:               
	cmp dword ptr [rax+11ch], 0
	je  NtReadVirtualMemory_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtReadVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtReadVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtReadVirtualMemory_SystemCall_6_3_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_0_XXXX:               
	cmp word ptr [rax+120h], 6000
	je  NtReadVirtualMemory_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtReadVirtualMemory_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtReadVirtualMemory_SystemCall_6_0_6002
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_1_XXXX:               
	cmp word ptr [rax+120h], 7600
	je  NtReadVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtReadVirtualMemory_SystemCall_6_1_7601
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 10240
	je  NtReadVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtReadVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtReadVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtReadVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtReadVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtReadVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtReadVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtReadVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtReadVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtReadVirtualMemory_SystemCall_10_0_19041
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_SystemCall_5_X_XXXX:          
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_0_6000:          
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_0_6001:          
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_0_6002:          
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 003dh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 003eh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_Unknown:           
	ret
NtReadVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtReadVirtualMemory ENDP

NtProtectVirtualMemory PROC
	mov rax, gs:[60h]                                
NtProtectVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+118h], 5
	je  NtProtectVirtualMemory_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtProtectVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtProtectVirtualMemory_Check_10_0_XXXX
	jmp NtProtectVirtualMemory_SystemCall_Unknown
NtProtectVirtualMemory_Check_6_X_XXXX:               
	cmp dword ptr [rax+11ch], 0
	je  NtProtectVirtualMemory_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtProtectVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtProtectVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtProtectVirtualMemory_SystemCall_6_3_XXXX
	jmp NtProtectVirtualMemory_SystemCall_Unknown
NtProtectVirtualMemory_Check_6_0_XXXX:               
	cmp word ptr [rax+120h], 6000
	je  NtProtectVirtualMemory_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtProtectVirtualMemory_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtProtectVirtualMemory_SystemCall_6_0_6002
	jmp NtProtectVirtualMemory_SystemCall_Unknown
NtProtectVirtualMemory_Check_6_1_XXXX:               
	cmp word ptr [rax+120h], 7600
	je  NtProtectVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtProtectVirtualMemory_SystemCall_6_1_7601
	jmp NtProtectVirtualMemory_SystemCall_Unknown
NtProtectVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 10240
	je  NtProtectVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtProtectVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtProtectVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtProtectVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtProtectVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtProtectVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtProtectVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtProtectVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtProtectVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtProtectVirtualMemory_SystemCall_10_0_19041
	jmp NtProtectVirtualMemory_SystemCall_Unknown
NtProtectVirtualMemory_SystemCall_5_X_XXXX:          
	mov eax, 004dh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_6_0_6000:          
	mov eax, 004dh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_6_0_6001:          
	mov eax, 004dh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_6_0_6002:          
	mov eax, 004dh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 004dh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 004dh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 004eh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 004fh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_Unknown:           
	ret
NtProtectVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtProtectVirtualMemory ENDP

NtOpenProcess PROC
	mov rax, gs:[60h]                       
NtOpenProcess_Check_X_X_XXXX:               
	cmp dword ptr [rax+118h], 5
	je  NtOpenProcess_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtOpenProcess_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtOpenProcess_Check_10_0_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_X_XXXX:               
	cmp dword ptr [rax+11ch], 0
	je  NtOpenProcess_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtOpenProcess_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtOpenProcess_SystemCall_6_3_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_0_XXXX:               
	cmp word ptr [rax+120h], 6000
	je  NtOpenProcess_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtOpenProcess_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtOpenProcess_SystemCall_6_0_6002
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_1_XXXX:               
	cmp word ptr [rax+120h], 7600
	je  NtOpenProcess_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtOpenProcess_SystemCall_6_1_7601
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 10240
	je  NtOpenProcess_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtOpenProcess_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtOpenProcess_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtOpenProcess_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtOpenProcess_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtOpenProcess_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtOpenProcess_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtOpenProcess_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtOpenProcess_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtOpenProcess_SystemCall_10_0_19041
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_SystemCall_5_X_XXXX:          
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_0_6000:          
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_0_6001:          
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_0_6002:          
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_1_7600:          
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_1_7601:          
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_2_XXXX:          
	mov eax, 0024h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_3_XXXX:          
	mov eax, 0025h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10240:        
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10586:        
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_14393:        
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_15063:        
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_16299:        
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17134:        
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17763:        
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18362:        
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18363:        
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19041:        
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_Unknown:           
	ret
NtOpenProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
NtOpenProcess ENDP

NtQueryVirtualMemory PROC
	mov rax, gs:[60h]                              
NtQueryVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+118h], 5
	je  NtQueryVirtualMemory_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtQueryVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtQueryVirtualMemory_Check_10_0_XXXX
	jmp NtQueryVirtualMemory_SystemCall_Unknown
NtQueryVirtualMemory_Check_6_X_XXXX:               
	cmp dword ptr [rax+11ch], 0
	je  NtQueryVirtualMemory_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtQueryVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueryVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtQueryVirtualMemory_SystemCall_6_3_XXXX
	jmp NtQueryVirtualMemory_SystemCall_Unknown
NtQueryVirtualMemory_Check_6_0_XXXX:               
	cmp word ptr [rax+120h], 6000
	je  NtQueryVirtualMemory_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtQueryVirtualMemory_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtQueryVirtualMemory_SystemCall_6_0_6002
	jmp NtQueryVirtualMemory_SystemCall_Unknown
NtQueryVirtualMemory_Check_6_1_XXXX:               
	cmp word ptr [rax+120h], 7600
	je  NtQueryVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtQueryVirtualMemory_SystemCall_6_1_7601
	jmp NtQueryVirtualMemory_SystemCall_Unknown
NtQueryVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 10240
	je  NtQueryVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtQueryVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtQueryVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtQueryVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtQueryVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtQueryVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtQueryVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtQueryVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtQueryVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtQueryVirtualMemory_SystemCall_10_0_19041
	jmp NtQueryVirtualMemory_SystemCall_Unknown
NtQueryVirtualMemory_SystemCall_5_X_XXXX:          
	mov eax, 0020h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_6_0_6000:          
	mov eax, 0020h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_6_0_6001:          
	mov eax, 0020h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_6_0_6002:          
	mov eax, 0020h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 0020h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 0020h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 0021h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 0022h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 0023h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 0023h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 0023h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 0023h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 0023h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 0023h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 0023h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 0023h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 0023h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 0023h
	jmp NtQueryVirtualMemory_Epilogue
NtQueryVirtualMemory_SystemCall_Unknown:           
	ret
NtQueryVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtQueryVirtualMemory ENDP

NtWriteVirtualMemory PROC
	mov rax, gs:[60h]                              
NtWriteVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+118h], 5
	je  NtWriteVirtualMemory_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtWriteVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtWriteVirtualMemory_Check_10_0_XXXX
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_6_X_XXXX:               
	cmp dword ptr [rax+11ch], 0
	je  NtWriteVirtualMemory_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtWriteVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtWriteVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtWriteVirtualMemory_SystemCall_6_3_XXXX
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_6_0_XXXX:               
	cmp word ptr [rax+120h], 6000
	je  NtWriteVirtualMemory_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtWriteVirtualMemory_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtWriteVirtualMemory_SystemCall_6_0_6002
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_6_1_XXXX:               
	cmp word ptr [rax+120h], 7600
	je  NtWriteVirtualMemory_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtWriteVirtualMemory_SystemCall_6_1_7601
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 10240
	je  NtWriteVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtWriteVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtWriteVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtWriteVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtWriteVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtWriteVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtWriteVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtWriteVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtWriteVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtWriteVirtualMemory_SystemCall_10_0_19041
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_SystemCall_5_X_XXXX:          
	mov eax, 0037h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_0_6000:          
	mov eax, 0037h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_0_6001:          
	mov eax, 0037h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_0_6002:          
	mov eax, 0037h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 0037h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 0037h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 0038h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 0039h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_Unknown:           
	ret
NtWriteVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtWriteVirtualMemory ENDP

NtQueryInformationProcess PROC
	mov rax, gs:[60h]                                   
NtQueryInformationProcess_Check_X_X_XXXX:               
	cmp dword ptr [rax+118h], 5
	je  NtQueryInformationProcess_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtQueryInformationProcess_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtQueryInformationProcess_Check_10_0_XXXX
	jmp NtQueryInformationProcess_SystemCall_Unknown
NtQueryInformationProcess_Check_6_X_XXXX:               
	cmp dword ptr [rax+11ch], 0
	je  NtQueryInformationProcess_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtQueryInformationProcess_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueryInformationProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtQueryInformationProcess_SystemCall_6_3_XXXX
	jmp NtQueryInformationProcess_SystemCall_Unknown
NtQueryInformationProcess_Check_6_0_XXXX:               
	cmp word ptr [rax+120h], 6000
	je  NtQueryInformationProcess_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtQueryInformationProcess_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtQueryInformationProcess_SystemCall_6_0_6002
	jmp NtQueryInformationProcess_SystemCall_Unknown
NtQueryInformationProcess_Check_6_1_XXXX:               
	cmp word ptr [rax+120h], 7600
	je  NtQueryInformationProcess_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtQueryInformationProcess_SystemCall_6_1_7601
	jmp NtQueryInformationProcess_SystemCall_Unknown
NtQueryInformationProcess_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 10240
	je  NtQueryInformationProcess_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtQueryInformationProcess_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtQueryInformationProcess_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtQueryInformationProcess_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtQueryInformationProcess_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtQueryInformationProcess_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtQueryInformationProcess_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtQueryInformationProcess_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtQueryInformationProcess_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtQueryInformationProcess_SystemCall_10_0_19041
	jmp NtQueryInformationProcess_SystemCall_Unknown
NtQueryInformationProcess_SystemCall_5_X_XXXX:          
	mov eax, 0016h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_6_0_6000:          
	mov eax, 0016h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_6_0_6001:          
	mov eax, 0016h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_6_0_6002:          
	mov eax, 0016h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_6_1_7600:          
	mov eax, 0016h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_6_1_7601:          
	mov eax, 0016h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_6_2_XXXX:          
	mov eax, 0017h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_6_3_XXXX:          
	mov eax, 0018h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_10240:        
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_10586:        
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_14393:        
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_15063:        
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_16299:        
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_17134:        
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_17763:        
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_18362:        
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_18363:        
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_19041:        
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_Unknown:           
	ret
NtQueryInformationProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
NtQueryInformationProcess ENDP

NtClose PROC
	mov rax, gs:[60h]                 
NtClose_Check_X_X_XXXX:               
	cmp dword ptr [rax+118h], 5
	je  NtClose_SystemCall_5_X_XXXX
	cmp dword ptr [rax+118h], 6
	je  NtClose_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtClose_Check_10_0_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_X_XXXX:               
	cmp dword ptr [rax+11ch], 0
	je  NtClose_Check_6_0_XXXX
	cmp dword ptr [rax+11ch], 1
	je  NtClose_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtClose_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 3
	je  NtClose_SystemCall_6_3_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_0_XXXX:               
	cmp word ptr [rax+120h], 6000
	je  NtClose_SystemCall_6_0_6000
	cmp word ptr [rax+120h], 6001
	je  NtClose_SystemCall_6_0_6001
	cmp word ptr [rax+120h], 6002
	je  NtClose_SystemCall_6_0_6002
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_1_XXXX:               
	cmp word ptr [rax+120h], 7600
	je  NtClose_SystemCall_6_1_7600
	cmp word ptr [rax+120h], 7601
	je  NtClose_SystemCall_6_1_7601
	jmp NtClose_SystemCall_Unknown
NtClose_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 10240
	je  NtClose_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtClose_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtClose_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtClose_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtClose_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtClose_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtClose_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtClose_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtClose_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtClose_SystemCall_10_0_19041
	jmp NtClose_SystemCall_Unknown
NtClose_SystemCall_5_X_XXXX:          
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_0_6000:          
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_0_6001:          
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_0_6002:          
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_1_7600:          
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_1_7601:          
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_2_XXXX:          
	mov eax, 000dh
	jmp NtClose_Epilogue
NtClose_SystemCall_6_3_XXXX:          
	mov eax, 000eh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10240:        
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10586:        
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_14393:        
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_15063:        
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_16299:        
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17134:        
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17763:        
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18362:        
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18363:        
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_19041:        
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_Unknown:           
	ret
NtClose_Epilogue:
	mov r10, rcx
	syscall
	ret
NtClose ENDP

end