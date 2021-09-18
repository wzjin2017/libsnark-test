#include <iostream>
#include <openssl/rand.h>
#include <fstream>
#include <iomanip>

using namespace std;

int main(int argc, char *argv[]) {    
    
    string fileName = "";
    string fpath = "../data/";
    if (argc != 2) {
        printf("initializer should take one argument\n");
        exit(1);
    } else if (argc == 2) {
        // hop_number = atoi(argv[1]);
        // if (hop_number < 1) {
        //     printf("hop number should larger than zero\n");
        //     exit(1);
        // }
    }
    for (int i = 0; i < atoi(argv[1]); i++) {
        fileName = to_string(i);
        uint8_t* input = new uint8_t[32];
        ofstream file;
        RAND_bytes(input, 32);
        file.open(fpath + fileName + ".secret", ios::out);
        for (int input_byte_idx = 0; input_byte_idx < 32; input_byte_idx++){
            file << setfill('0') << setw(2) << hex << (int)input[input_byte_idx];
        }        
        file.close();
    }

    return 0;
}