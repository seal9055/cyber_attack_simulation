#include <stdio.h>
#include <stdlib.h>
#include <time.h> 
#include <string.h>
#include <stdint.h>


#define NUM_MIN_BLOCKS 4
#define NUM_MAX_BLOCKS 16
#define NUM_KEY_OPS 5

#define BASIC_OP_SIZE 13
#define STATE_OP_SIZE 6
#define JMP_OP_SIZE 5
#define KEYGEN_BLOCK_SIZE (BASIC_OP_SIZE * NUM_KEY_OPS + STATE_OP_SIZE + JMP_OP_SIZE)

// Defines the supported operations in each decryption block
enum KeyOperation {XOR, MUL, SUB, ADD, NUM_OPERATIONS};

// mov $constant, %rbx
static const uint8_t mov_buffer[2] = {0x48, 0xBB};

// xor %rbx, %rax  |  mul %rbx  |  sub %rbx, %rax  |  add %rbx, %rax
static const uint8_t op_buffer[NUM_OPERATIONS][3] = {{0x48, 0x31, 0xD8}, {0x48, 0xF7, 0xE3}, {0x48, 0x29, 0xD8}, {0x48, 0x01, 0xD8}};

/**
 * @brief Naive 64-bit integer generator
 * 
 * @return uint64_t random value
 */
uint64_t rand64();

/**
 * @brief Naive 32-bit integer generator
 * 
 * @return uint32_t random value
 */
uint32_t rand32();

/**
 * @brief Generates how many blocks to use in decryptions
 * 
 * @return uint8_t number of blocks
 */
uint8_t generate_num_blocks();

/**
 * @brief Generates a "schedule" that determines which blocks should be entered for decryption when
 * 
 * @param n number of blocks in schedule
 * @return uint8_t* list of size `n` with schedule
 */
uint8_t* generate_block_schedule(uint8_t n);

/**
 * @brief Generates a 2d array of shape (block_count, NUM_KEY_OPS) which describes which exact operations
 *        will be done in each block.
 * 
 * @param block_count number of decryption blocks
 * @param block_schedule order of decryption blocks
 * @return uint8_t** 2d array of shape (block_count, NUM_KEY_OPS)
 */
uint8_t** generate_block_descriptors(uint8_t block_count, uint8_t* block_schedule);

/**
 * @brief Adds a key modification operation to a decryption block
 * 
 * @param buffer Buffer to append opcodes to
 * @param op Operation to add
 * @param key RC4 key to update
 * @return uint8_t number of bytes written to buffer
 */
uint8_t add_key_operation(uint8_t* buffer, enum KeyOperation op, uint64_t* key);

/**
 * @brief Adds the state modification operations to a decryption block
 * 
 * @param buffer Buffer to append opcodes to
 * @param state State variable to modify
 * @param target_val State variable of decryption block to go to next
 * @return uint8_t number of bytes written to buffer
 */
uint8_t add_state_operation(uint8_t* buffer, uint32_t* state, uint32_t target_val);

/**
 * @brief Fills in all the key modification operations in a single block
 * 
 * @param buffer buffer to add opcodes to
 * @param home_buffer part of buffer to jump back to after block
 * @param descriptor descriptor of current block
 * @param target_val state variable of next block to jump to
 * @param state current state variable
 * @param key current key to update
 */
void populate_key_block(uint8_t* buffer, uint8_t* home_buffer, uint8_t* descriptor, uint32_t target_val, uint32_t* state, uint64_t* key);

/**
 * @brief Fills in the "home" decryption block, which handles the logic to jump to all the decryption blocks
 * 
 * @param buffer buffer to add opcodes to
 * @param block_count number of blocks
 * @param home_states state variables of all the decryption blocks
 * @param block_schedule order of decryption blocks
 * @param init_state initial state variable
 * @param init_key initial key to build RC4 key with
 */
void populate_home_block(uint8_t* buffer, uint8_t block_count, uint32_t* home_states, uint8_t* block_schedule, uint32_t init_state, uint64_t init_key);

/**
 * @brief Builds buffer of assembly instructions to generate RC4 key
 * 
 * @param block_count number of decryption blocks
 * @param block_schedule order of decryption blocks
 * @param block_descriptors descriptor of each block
 * @param key RC4 key to write to
 * @return uint8_t* buffer of assembly instructions
 */
uint8_t* generate_keygen(uint8_t block_count, uint8_t* block_schedule, uint8_t** block_descriptors, uint64_t* key);

/**
 * @brief Wrapper of `generate_keygen` to generate assembly instructions that generates an RC4 key
 * 
 * @param keygen_buffer pointer to buffer that will hold assembly instructions
 * @param keygen_size pointer to `size_t` that will hold the size of the buffer
 * @param key pointer to 64-bit integer that will hold the RC4 key
 */
void build_keygen(uint8_t** keygen_buffer, size_t* keygen_size, uint64_t* key);
