#include "keygen.h"

uint64_t rand64() {
    uint64_t out = 0;

    for (int i = 0; i < 8; i++) 
        out += (uint64_t)(rand() & 0xFF) << (i * 8);
    
    return out;
}

uint32_t rand32() {
    uint32_t out = 0;

    for (int i = 0; i < 4; i++)
        out += (rand() & 0xFF) << (i * 8);
    
    return out;
}

uint8_t generate_num_blocks() {
    uint8_t block_range = rand() % (NUM_MAX_BLOCKS - NUM_MIN_BLOCKS);
    return block_range + NUM_MIN_BLOCKS;
}

uint8_t* generate_block_schedule(uint8_t n) {
    // can prob do this without calloc using clever bit-manupulation for smaller n
    uint8_t* block_schedule = calloc(n, sizeof(uint8_t));
    for (uint8_t i = 0; i < n; i++)
        block_schedule[i] = i;

    // https://benpfaff.org/writings/clc/shuffle.html
    for (uint8_t i = 0; i < n - 1; i++) {
        uint8_t j = i + rand() / (RAND_MAX / (n - i) + 1);
        uint8_t tmp = block_schedule[i];
        block_schedule[i] = block_schedule[j];
        block_schedule[j] = tmp;
    }
    
    return block_schedule;
}

uint8_t** generate_block_descriptors(uint8_t block_count, uint8_t* block_schedule) {
    uint8_t** descriptors = calloc(block_count, sizeof(uint8_t*));
    for (uint8_t i = 0; i < block_count; i++) {
        uint8_t* block_descriptor = calloc(NUM_KEY_OPS, sizeof(uint8_t));

        for (uint8_t j = 0; j < NUM_KEY_OPS; j++) {
            block_descriptor[j] = (uint8_t)(rand() % NUM_OPERATIONS);
        }

        descriptors[i] = block_descriptor;
    }

    return descriptors;
}

uint8_t add_key_operation(uint8_t* buffer, enum KeyOperation op, uint64_t* key) {
    if (op >= NUM_OPERATIONS) {
        printf("Error: Unknown operation\n");
        return -1;
    }

    uint64_t rand_val = rand64();

    memcpy(buffer, mov_buffer, sizeof(mov_buffer));
    *(uint64_t*)(buffer + 2) = rand_val;
    memcpy(buffer + 10, op_buffer[op], sizeof(op_buffer[op]));

    switch (op) {
        case XOR:
            *key ^= rand_val;
            break;
        case MUL:
            *key *= rand_val;
            break;
        case SUB:
            *key -= rand_val;
            break;
        case ADD:
            *key += rand_val;
            break;
        case NUM_OPERATIONS:
            break;
    }

    return BASIC_OP_SIZE;
}

uint8_t add_state_operation(uint8_t* buffer, uint32_t* state, uint32_t target_val) {
    uint32_t xor_target = *state ^ target_val;

    buffer[0] = 0x81;
    buffer[1] = 0xF1;
    *(uint32_t*)(buffer + 2) = xor_target;

    *state ^= xor_target;
    return STATE_OP_SIZE;
}

void populate_key_block(uint8_t* buffer, uint8_t* home_buffer, uint8_t* descriptor, uint32_t target_val, uint32_t* state, uint64_t* key) {
    for (int i = 0; i < NUM_KEY_OPS; i++) {
        buffer += add_key_operation(buffer, rand() % NUM_OPERATIONS, key);
    }

    buffer += add_state_operation(buffer, state, target_val);

    buffer[0] = 0xE9;
    *(uint32_t*)(buffer + 1) = (uint32_t)(home_buffer - buffer - 5);
}

void populate_home_block(uint8_t* buffer, uint8_t block_count, uint32_t* home_states, uint8_t* block_schedule, uint32_t init_state, uint64_t init_key) {
    buffer[0] = 0xB9;
    *(uint32_t*)(buffer + 1) = init_state;
    buffer += 5;

    buffer[0] = 0x48;
    buffer[1] = 0xB8;
    *(uint64_t*)(buffer + 2) = init_key;
    buffer += 10;

    for (int i = 0; i < block_count; i++) {
        buffer[0] = 0x81;
        buffer[1] = 0xF9;
        *(uint32_t*)(buffer + 2) = home_states[block_schedule[i]];

        buffer[6] = 0x0F;
        buffer[7] = 0x84;

        uint32_t offset = ((block_count - i - 1) * 12 + 1) + block_schedule[i] * KEYGEN_BLOCK_SIZE;  // block_schedule[i]
        *(uint32_t*)(buffer + 8) = offset; // dst - src - 5
        buffer += 12;
    }

    buffer[0] = 0xC3;
}

uint8_t* generate_keygen(uint8_t block_count, uint8_t* block_schedule, uint8_t** block_descriptors, uint64_t* key) {
    uint8_t* keygen_buffer = calloc(16 + 12 * block_count + KEYGEN_BLOCK_SIZE * block_count, sizeof(uint8_t));

    uint32_t* home_states = calloc(block_count + 1, sizeof(uint32_t));
    for (int i = 0; i < block_count + 1; i++)
        home_states[i] = rand32();

    uint32_t state = home_states[block_schedule[0]];
    *key = rand64();

    populate_home_block(keygen_buffer, block_count, home_states, block_schedule, state, *key);

    for (int i = 0; i < block_count; i++) {
        uint8_t block_index = block_schedule[i];
        int block_rva = 16 + 12 * block_count + block_index * KEYGEN_BLOCK_SIZE;

        uint32_t target_val = i == block_count - 1 ? home_states[block_count] : home_states[block_schedule[i + 1]];

        uint8_t* block_buffer = keygen_buffer + block_rva;
        uint8_t* home_buffer = keygen_buffer + 15;
        populate_key_block(block_buffer, home_buffer, block_descriptors[block_index], target_val, &state, key);
    }

    free(home_states);
    return keygen_buffer;
}

void build_keygen(uint8_t** keygen_buffer, size_t* keygen_size, uint64_t* key) {
    time_t t;
    srand(time(&t));

    // generate random number of blocks
    uint8_t block_count = generate_num_blocks();
    printf("Creating %d decryption steps\n", block_count);

    // shuffle identity list to create block schedule
    uint8_t* block_schedule = generate_block_schedule(block_count);

    // create 2d array (block_count, NUM_KEY_OPS) which describes what operations are done in each block
    uint8_t** block_descriptors = generate_block_descriptors(block_count, block_schedule);

    // generate code using block descriptors
    uint64_t generated_key = 0;
    uint8_t* keygen_code = generate_keygen(block_count, block_schedule, block_descriptors, &generated_key);

    free(block_schedule);
    for (int i = 0; i < block_count; i++)
        free(block_descriptors[i]);
    free(block_descriptors);

    *keygen_size = 16 + 12 * block_count + KEYGEN_BLOCK_SIZE * block_count;
    *keygen_buffer = keygen_code;
    *key = generated_key;
}
