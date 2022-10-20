#include <iostream>
#include <string>
#include <fstream>
#include <string>
#include <iomanip>
#include <stdlib.h>
#include <getopt.h>

#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libff/common/default_types/ec_pp.hpp"
#include "libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp"

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_components.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

using std::vector;

typedef libff::Fr<libff::default_ec_pp> FieldT;

pb_variable_array<FieldT> from_bits(std::vector<bool> bits, pb_variable<FieldT>& ZERO) {
    pb_variable_array<FieldT> acc;

		for (size_t i = 0; i < bits.size(); i++) {
			bool bit = bits[i];
			acc.emplace_back(bit ? ONE : ZERO);
		}

    return acc;
}

class ethereum_sha256 : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

public:
    ethereum_sha256(
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& a,
        pb_variable_array<FieldT>& b,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : gadget<FieldT>(pb, "ethereum_sha256") {

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, "intermediate"));

        // final padding
        pb_variable_array<FieldT> length_padding =
            from_bits({
                // padding
                1,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,

                // length of message (512 bits)
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,1,0,
                0,0,0,0,0,0,0,0
            }, ZERO);

        block1.reset(new block_variable<FieldT>(pb, {
            a,
            b
        }, "block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            length_padding
        }, "block2"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
        "hasher1"));

        pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits);

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *result,
        "hasher2"));
    }

    void generate_r1cs_constraints() {
        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
    }
};

vector<unsigned long> bit_list_to_ints(vector<bool> bit_list, const size_t wordsize) {
  vector<unsigned long> res;
	size_t iterations = bit_list.size()/wordsize+1;
  for (size_t i = 0; i < iterations; ++i) {
      unsigned long current = 0;
      for (size_t j = 0; j < wordsize; ++j) {
					if (bit_list.size() == (i*wordsize+j)) break;
          current += (bit_list[i*wordsize+j] * (1ul<<(wordsize-1-j)));
      }
      res.push_back(current);
  }
  return res;
}

int main(int argc, char *argv[]) {

    const struct option longopts[] =
    {
        {"version", no_argument,          0, 'v'},
        {"help",    no_argument,          0, 'h'},
        {"stuff",   required_argument,    0, 's'},
        {0,0,0,0},
    };

    int index;
    int iarg=0;

    std::string secret_0 = "0.secret";
    std::string secret_1 = "1.secret";
    std::string proof_hash = "proof.hash";
    std::string proof_file = "proof";
    std::string verification_key = "verifyKey";

    while(iarg != -1)
    {
        iarg = getopt_long(argc, argv, "a:b:c:h", longopts, &index);

        switch (iarg)
        {
            case 'h':
                std::cout << "help menu" << std::endl;
                std::cout << argc << std::endl;
                std::cout << argv[0] << std::endl;
                break;

            case 'v':
                std::cout << "version" << std::endl;
                break;

            case 'a':
                secret_0 = optarg;
                break;
            case 'b':
                secret_1 = optarg;
                break;
            case 'c':
                proof_hash = optarg;
                break;
        }
    }


    default_ec_pp::init_public_params();

    protoboard<FieldT> pb;
    std::shared_ptr<digest_variable<FieldT>> result;
    result.reset(new digest_variable<FieldT>(pb, 256, "result"));

    pb.set_input_sizes(1);


    pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "ZERO");
    pb.val(ZERO) = 0;


    string ints_a;
    string ints_b;
    ifstream nameFilein_a;
    nameFilein_a.open(secret_0);
    getline(nameFilein_a, ints_a);
    ifstream nameFilein_b;
    nameFilein_b.open(secret_1);
    getline(nameFilein_b, ints_b);

    pb_variable_array<FieldT> a;
    a.allocate(pb, 256, "a");
    for (size_t i = 0; i < a.size(); i++) {
    pb.val(a[i]) = (int)ints_a[i] - 48;
    //pb.val(a[i]) = 0;
    }
    //pb.val(a[a.size() - 1]) = 1;
    //pb.val(a[a.size() - 3]) = 1;


    pb_variable_array<FieldT> b;
    b.allocate(pb, 256, "b");
    for (size_t i = 0; i < b.size(); i++) {
    pb.val(b[i]) = (int)ints_b[i] - 48;
    //pb.val(b[i]) = 1;
    }

    ethereum_sha256 g(pb, ZERO, a, b, result);
    g.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    // std::cout << "pk: " << keypair.pk << std::endl;
    // std::cout << "vk: " << keypair.vk << std::endl;

    g.generate_r1cs_witness();

    std::cout << "is_satisfied:" << pb.is_satisfied() << std::endl;


    // //Reading in proving key
    // r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair;
    // std::cout << "Reading proverKey" << std::endl;
    // ifstream fileIn("proverKey");
    // stringstream proverKeyFromFile;
    // if (fileIn) {
    //    proverKeyFromFile << fileIn.rdbuf();
    //    fileIn.close();
    // }
    // proverKeyFromFile >> keypair.pk;

    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof1 = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());


    //Serialization
    ofstream fileOut;
    stringstream verifierKey;
    verifierKey << keypair.vk;

    fileOut.open(verification_key);

    fileOut << verifierKey.rdbuf();
    fileOut.close();

    cout << "Saving verifierKey" << endl;
    //cout << keypair.vk << endl;

    stringstream Proof;
    Proof << proof1;


    fileOut.open(proof_file);

    fileOut << Proof.rdbuf();
    fileOut.close();

    cout << "Saving Proof" << endl;


    bool verified1 = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof1);

    std::cout << "hash => Verfied: " << verified1 << std::endl;
    std::cout << "primary_input: " << pb.primary_input() << std::endl;

    ofstream myfile_hash;
    myfile_hash.open (proof_hash);
    cout << "Saving proof hash." << endl;
  
    auto ints = bit_list_to_ints(result->get_digest(), 32);
    for (size_t i = 0; i < ints.size()-1; i++) {
        std::cout << std::setw(8) << std::setfill('0') << std::hex << ints[i] << std::endl;
        myfile_hash << std::setw(8) << std::setfill('0') << std::hex << ints[i];
    }
    myfile_hash.close();


    return 0;
}
