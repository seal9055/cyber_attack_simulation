#include "elf.h"

int validate_elf(void* file_buffer) {
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)file_buffer;
    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG)) {
        return 1; // bad header
    }

    if (elf_header->e_ident[EI_CLASS] != 2) {
        return 1; // not x64
    }

    return 0;    
}

int get_decryptor_stub(int file_size, uint64_t image_base, void** decryptor_stub, long* decryptor_stub_size, uint64_t* key) {
    // read assembled decryptor stub from disk
    void* file_buffer;
    long bytes_read;
    if (read_file(STUB_BINARY, &file_buffer, &bytes_read)) {
        printf("Unable to read stub binary from %s\n", STUB_BINARY);
        return 1;
    } 

    uint64_t entry_point = image_base + sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);

    uint8_t* keygen_buffer;
    size_t keygen_size;
    build_keygen(&keygen_buffer, &keygen_size, key);
    printf("RC4 Decryption Key: 0x%lx\n", *key);

    // replace dynamic values, there's probably a better way to do this
    for (long i = 0; i < bytes_read; i++) {
        long* val = (long*)((char*)file_buffer + i);

        switch (*val) {
            case 0xAAAAAAAAAAAAAAAA:
                //name of created file descriptor
                *val = entry_point + bytes_read + keygen_size - 3;
                break;
            case 0xBBBBBBBBBBBBBBBB:
                // offset to encrypted file buffer
                *val = entry_point + bytes_read + keygen_size - 3 + sizeof(MEMFD_NAME) + 1; 
                break;
            case 0xCCCCCCCCCCCCCCCC:
                // size of encrypted file
                *val = file_size; 
                break;
            case 0xDDDDDDDDDDDDDDDD:
                // offset to null string
                *val = entry_point + bytes_read + keygen_size - 3 + sizeof(MEMFD_NAME);
                break;
        }
    }

    // allocate new memory for stub that includes the required strings
    *decryptor_stub = calloc(bytes_read + sizeof(MEMFD_NAME) + 1 + (keygen_size - 3), 1); 
    memcpy(*decryptor_stub, file_buffer, bytes_read);
    memcpy((char*)(*decryptor_stub) + bytes_read - 3, keygen_buffer, keygen_size);
    memcpy((char*)(*decryptor_stub) + bytes_read + keygen_size - 3, MEMFD_NAME, sizeof(MEMFD_NAME));
    free(file_buffer);

    // set the size of the stub
    *decryptor_stub_size = bytes_read - 3 + keygen_size + sizeof(MEMFD_NAME) + 1;
    return 0;
}

void populate_elf_header(Elf64_Ehdr* elf_header, uint64_t image_base) {
    memset(elf_header, 0, sizeof(Elf64_Ehdr));
    memcpy(elf_header->e_ident, ELFMAG, SELFMAG);
    elf_header->e_ident[EI_CLASS] = ELFCLASS64;
    elf_header->e_ident[EI_DATA] = ELFDATA2LSB;
    elf_header->e_ident[EI_VERSION] = EV_CURRENT;
    elf_header->e_ident[EI_OSABI] = ELFOSABI_SYSV;
    elf_header->e_ident[EI_ABIVERSION] = 0;
    elf_header->e_type = ET_EXEC;
    elf_header->e_machine = EM_X86_64;
    elf_header->e_version = EV_CURRENT;
    elf_header->e_entry = image_base + sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    elf_header->e_phoff = sizeof(Elf64_Ehdr);
    elf_header->e_shoff = 0;
    elf_header->e_flags = 0;
    elf_header->e_ehsize = sizeof(Elf64_Ehdr);
    elf_header->e_phentsize = sizeof(Elf64_Phdr);
    elf_header->e_phnum = 1;
    elf_header->e_shentsize = sizeof(Elf64_Shdr);
    elf_header->e_shnum = 0;
    elf_header->e_shstrndx = SHN_UNDEF;
}

void populate_program_header(Elf64_Phdr* prog_header, uint64_t image_base, size_t total_size) {
    prog_header->p_type = PT_LOAD;
    prog_header->p_flags = PF_R | PF_W | PF_X;
    prog_header->p_offset = 0;
    prog_header->p_vaddr = image_base;
    prog_header->p_paddr = image_base;
    prog_header->p_filesz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + total_size;
    prog_header->p_memsz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + total_size;
    prog_header->p_align = 0x200000;
}

int generate_decryptor(void* file_buffer, long file_size, void** decryptor_buffer, long* decryptor_size) {

    // generates a stub to decrypt the input file
    void* decryptor_stub_buffer;
    long decryptor_stub_size;
    uint64_t key;
    if (get_decryptor_stub(file_size, 0x400000, &decryptor_stub_buffer, &decryptor_stub_size, &key)) {
        printf("Failured to generate decryptor stub\n");
        return 1;
    }

    // encrypts the input file
    crypt_rc4(file_buffer, file_size, key);


    // build headers for small elf file that contains the stub
    Elf64_Ehdr elf_header;
    populate_elf_header(&elf_header, 0x400000);

    Elf64_Phdr prog_header;
    populate_program_header(&prog_header, 0x400000, decryptor_stub_size + file_size);

    *decryptor_size = prog_header.p_filesz;
    *decryptor_buffer = calloc(*decryptor_size, 1);
    size_t ptr = 0;

    // write elf header to output buffer
    memcpy((char*)(*decryptor_buffer) + ptr, &elf_header, sizeof(Elf64_Ehdr));
    ptr += sizeof(Elf64_Ehdr);

    // write program header to output buffer
    memcpy((char*)(*decryptor_buffer) + ptr, &prog_header, sizeof(Elf64_Phdr));
    ptr += sizeof(Elf64_Phdr);

    // write decryptor stub to output buffer
    memcpy((char*)(*decryptor_buffer) + ptr, decryptor_stub_buffer, decryptor_stub_size);
    ptr += decryptor_stub_size;

    // write encrypted file to output buffer
    memcpy((char*)(*decryptor_buffer) + ptr, file_buffer, file_size);
    ptr += file_size;

    return 0;
}