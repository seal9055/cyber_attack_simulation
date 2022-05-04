#ifndef ELF_H
#define ELF_H

#include <stdio.h>
#include <string.h>
#include <elf.h>
#include <stdlib.h>

#include "file.h"
#include "rc4.h"
#include "keygen.h"

// path of decryptor stub, assembled in make file
#define STUB_BINARY "stub.bin"

// name of FD that is created by stub to exec binary, will randomize in future
#define MEMFD_NAME "Crypter590J"

/**
 * @brief Makes sure the given elf file is a valid ELF64
 * 
 * @param file_buffer buffer containing the ELF file contents to validate
 * @return int status code (0 for success, 1 for fail)
 */
int validate_elf(void* file_buffer);

/**
 * @brief Generates the decryptor stub for the file to be crypted
 * 
 * @param file_size size of input file that was read
 * @param image_base image base of ELF that we are generating
 * @param decryptor_stub used to output the newly allocated/created decryptor stub
 * @param decryptor_stub_size used to output the size of the decryptor stub
 * @param key pointer to key used to encrypt buffer
 * @return int status code (0 for success, 1 for fail)
 */
int get_decryptor_stub(int file_size, uint64_t image_base, void** decryptor_stub, long* decryptor_stub_size, uint64_t* key);

/**
 * @brief Fills in the required values for the ELF64 header
 * 
 * @param elf_header pointer to Elf64_Ehdr object to populate
 * @param image_base image base of ELF file we are generating
 */
void populate_elf_header(Elf64_Ehdr* elf_header, uint64_t image_base);

/**
 * @brief Fills in the required values for the ELF64 program header
 * 
 * @param prog_header pointer to Elf64_Phdr object to populate
 * @param image_base image base of ELF file we are generating
 * @param total_size total size of the file we are writing to disk, aside from headers
 */
void populate_program_header(Elf64_Phdr* prog_header, uint64_t image_base, size_t total_size);

/**
 * @brief Creates a small ELF file that will decrypt the given file and execute it in memory
 * 
 * @param file_buffer file to crypt
 * @param file_size size of file to crypt
 * @param decryptor_buffer output with the new ELF64 file
 * @param decryptor_size size of newly created ELF file
 * @return int status code (0 for success, 1 for fail)
 */
int generate_decryptor(void* file_buffer, long file_size, void** decryptor_buffer, long* decryptor_size);

#endif // ELF_H