#ifndef FILE_H
#define FILE_H

#include <stdio.h>
#include <stdlib.h>

#define FILE_CHUNK_SIZE 1024

/**
 * @brief Reads the size of a file by fp, doesn't move position in stream
 * 
 * @param fp pointer to FILE object to read
 * @param file_size pointer to read file size
 * @return int status code (0 for success, 1 for fail)
 */
int get_file_size(FILE* fp, long* file_size);

/**
 * @brief Reads a file from disk
 * 
 * @param file_path file to read
 * @param out_buffer pointer to buffer that will contain file contents
 * @param bytes_read pointer to long that will contain file size
 * @return int status code (0 for success, 1 for fail)
 */
int read_file(const char* file_path, void** out_buffer, long* bytes_read);

/**
 * @brief Writes a file from memory onto disk
 * 
 * @param file_path path to write file to
 * @param buffer buffer to write to disk
 * @param num_bytes number of bytes to write to disk
 * @return int status code (0 for success, 1 for fail) 
 */
int write_file(const char* file_path, void* buffer, size_t num_bytes);

#endif // FILE_H