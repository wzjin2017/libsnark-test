#include <iostream>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <array>
#include <typeinfo>

using namespace std;

string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int main(int argc, char *argv[]) {    
    
    string fileName = "";
    string fpath = "testdata/";
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

    //generate secrets x
    std::vector<std::array<uint8_t, 32> > X;
    for (int i = 0; i < atoi(argv[1]); i++) {
        fileName = to_string(i+1);
        uint8_t* input = new uint8_t[32];
        std::array<uint8_t, 32> temp;
        ofstream file;
        RAND_bytes(input, 32);
        file.open(fpath + fileName + ".secret", ios::out);
        for (int input_byte_idx = 0; input_byte_idx < 32; input_byte_idx++){
            file << setfill('0') << setw(2) << hex << (int)input[input_byte_idx];
            temp[input_byte_idx] = *(input+input_byte_idx);
        }        
        file.close();
        X.push_back(temp);
        
    }
    for (int i = 0; i < X.size(); i++){
        for (int j = 0; j < X[i].size(); j++){
        std::cout << "X: " << X[i][j] << std::endl;}
    }

      
    char preimage [64];
    for (int i = 0; i < 32; i++){
        preimage[i] = (char)X[0][i];
    }
    for (int i = 0; i < 32; i++){
        preimage[i+32] = (char)X[1][i];

    }

    string preimage1 = "";
    for (int i = 0; i < 64; i++){
        preimage1 = preimage1 + preimage[i];
    }


    string y;
    for (int i = 0; i < atoi(argv[1] - 1); i++) {

        y = sha256(preimage1); 

    }
    ofstream myfile;
    myfile.open (fpath + "y", ios::out);
    myfile << y;
    myfile.close();

    // // generate hashes y
    // int Y[8];
    // for (int i = 0; i < atoi(argv[1]) - 1; i++) {
    //     fileName = to_string(i+1);
        



    //     ofstream file;
    //     file.open(fpath + fileName + ".hash", ios::out);

    //     file.close();
    // }


    return 0;
}