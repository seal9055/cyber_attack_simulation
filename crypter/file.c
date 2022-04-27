#include "file.h"

int get_file_size(FILE* fp, long* file_size) {
    long cur_pointer = ftell(fp);
    if (fseek(fp, 0, SEEK_END))
        return 1;

    *file_size = ftell(fp);
    if (fseek(fp, cur_pointer, SEEK_SET))
        return 1;

    return 0;
}

int read_file(const char* file_path, void** out_buffer, long* bytes_read) {
    FILE* fp = fopen(file_path, "r");

    if (fp && !get_file_size(fp, bytes_read)) {
        char* file_buffer = malloc(*bytes_read);

        size_t total_read = 0, cur_read = 0;
        while ((cur_read = fread(file_buffer + total_read, 1, FILE_CHUNK_SIZE, fp))) {
            total_read += cur_read;
        }

        *out_buffer = file_buffer;
        return 0;
    }
    
    return 1;
}

// TODO: make this much cleaner, I dont really think I need to chunk it like this
int write_file(const char* file_path, void* buffer, size_t num_bytes) {
    FILE* fp = fopen(file_path, "w");
    if (!fp)
        return 1;

    size_t chunk_size = num_bytes > FILE_CHUNK_SIZE ? FILE_CHUNK_SIZE : num_bytes;
    size_t bytes_written = 0;

    while (chunk_size != 0) {
        size_t chunk_written = fwrite(buffer + bytes_written, 1, chunk_size, fp);

        bytes_written += chunk_written;
        num_bytes -= chunk_written;
        chunk_size = num_bytes > FILE_CHUNK_SIZE ? FILE_CHUNK_SIZE : num_bytes;
    }

    return 0;
}