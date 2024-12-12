#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <ts/ts.h>

const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


int base64_char_to_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1; // Invalid character
}

int is_base64_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '+') || (c == '/');
}

// Function to encode data to Base64
char *base64(const unsigned char *input, int length) {
    int pl = 4 * ((length + 2) / 3); // Predicted length of the output
    char *output = (char *)malloc(pl + 1); // +1 for the null terminator
    if (!output) {
        TSError("[url_sig] Memory allocation for encode base64 failed failed");
        return NULL;
    }

    int ol = EVP_EncodeBlock((unsigned char *)output, input, length);
    if (pl != ol) {
        TSError("[url_sig] Whoops, encode predicted %d but we got %d", pl, ol);
    }
    return output;
}

// Function to decode Base64 data
unsigned char *decode64(const char *input, int input_length, int* output_length) {
    int pl = 3 * input_length / 4; // Predicted length of the output
    unsigned char *output = (unsigned char *)malloc(pl + 1);
    if (!output) {
        TSError("[url_sig] Memory allocation for decode failed");
        return NULL;
    }

    int ol = EVP_DecodeBlock(output, (const unsigned char *)input, input_length);
    if (pl != ol) {
        TSError("[url_sig] Decode predicted %d but we got %d", pl, ol);
    }
    *output_length = ol;
    *(output + pl) = '\0';
    return output;
}

char* base64_decode(const char* input, int length, int* out_length) {
    // Calculate the length of the input string including padding
    int padded_length = length;
    int mod = length % 4;
    if (mod != 0) {
        padded_length += 4 - mod;
    }

    // Allocate memory for the padded input
    char* padded_input = (char*)malloc(padded_length + 1);
    if (padded_input == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        return NULL;
    }

    // Copy the input to the padded input buffer
    strcpy(padded_input, input);

    // Add padding characters
    for (int i = length; i < padded_length; i++) {
        padded_input[i] = '=';
    }
    padded_input[padded_length] = '\0';

    // Allocate memory for the output
    int output_length = (padded_length / 4) * 3;
    unsigned char* output = (unsigned char*)malloc(output_length + 1);
    if (output == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        free(padded_input);
        return NULL;
    }

    // Decode the Base64 input
    int decoded_length = EVP_DecodeBlock(output, (const unsigned char*)padded_input, padded_length);

    // Adjust the decoded length based on actual padding in the input
    if (mod != 0) {
        decoded_length -= (4 - mod);
    }

    if (out_length != NULL) {
        *out_length = decoded_length;
    }

    // Null-terminate the output
    output[decoded_length] = '\0';

    // Free the padded input buffer
    free(padded_input);

    return (char*)output;
}


