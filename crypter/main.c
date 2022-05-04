#include <sys/stat.h>

#include "file.h"
#include "elf.h"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Incorrect parameters. Correct usage: \'./crypter executable_to_protect output_executable\'\n");
        return 1;
    }

    // read file to encrypt from disk
    void* file_buffer;
    long bytes_read;
    if (read_file(argv[1], &file_buffer, &bytes_read)) {
        printf("Unable to read file \"%s\"\n", argv[1]);
        return 1;
    }

    // make sure it is an ELF64 file
    if (validate_elf(file_buffer)) {
        printf("Invalid ELF64 file provided\n");
        return 1;
    }

    // generate an ELF file that will decrypt and execute the input file
    void* decryptor_buffer;
    long decryptor_size;
    if (generate_decryptor(file_buffer, bytes_read, &decryptor_buffer, &decryptor_size)) {
        printf("Unable to package buffer into a new elf file\n");
        return 1;
    }

    // write the file to disk
    if (write_file(argv[2], decryptor_buffer, decryptor_size)) {
        printf("Unable to write crypted executable to disk (%s)\n", argv[2]);
        return 1;
    }

    if (chmod(argv[2], S_IXUSR)) {
        printf("Unable to chmod generated executable %s with permissions S_IXUSR\n", argv[2]);
        return 1;
    }

    printf("Successfully crypted executable and wrote it to %s\n", argv[2]);
    return 0;   
}