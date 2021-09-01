#include <stdlib.h>
#include <iostream>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"

using namespace libsnark;
using namespace std;

typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

template<typename ppT, typename FieldT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppT> verification_key, r1cs_primary_input<FieldT> primary_input,
        r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof) {
    return r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(verification_key, primary_input, proof);
}

r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> setup_gadget(protoboard<FieldT> &pb, block_variable<FieldT> *&inp, digest_variable<FieldT> *&out, sha256_two_to_one_hash_gadget<FieldT> *&g) {
    out = new digest_variable<FieldT>(pb, SHA256_block_size, "output");
    inp = new block_variable<FieldT>(pb, SHA256_block_size, "input");
    g = new sha256_two_to_one_hash_gadget<FieldT>(pb, SHA256_block_size, *inp, *out, "f");
    pb.set_input_sizes(1);
    g->generate_r1cs_constraints();
    printf("Number of constraints for sha256_two_to_one_hash_gadget: %zu\n", pb.num_constraints());

    // Trusted setup
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(
            constraint_system);
    return keypair;
}

int main() {
    default_r1cs_ppzksnark_pp::init_public_params();

    protoboard<FieldT> pb;
    block_variable<FieldT>* input;
    digest_variable<FieldT>* output;
    sha256_two_to_one_hash_gadget<FieldT>* f;

    r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = setup_gadget(pb, input, output, f);
    
    // Hash of string "hello world"
    const libff::bit_vector hash_bv = libff::int_list_to_bits({0xc082e440, 0x671cd799, 0x8baf04c0, 0x22c07e03, 0x4b125ee7, 0xd28e0a59, 0x49e4b924, 0x5f5cf897}, 32);
    // output->generate_r1cs_witness(hash_bv);

    // Add witness values
    // For string "hello world"
    const libff::bit_vector input_bv = libff::int_list_to_bits({0x6c6c6568, 0x6f77206f, 0x00646c72, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}, 32);
    input->generate_r1cs_witness(input_bv);

    f->generate_r1cs_witness();
    cout << "one_input_hash_gadget => Satisfied status: " << pb.is_satisfied() << endl;

    // Create proof
    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof1 = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(
            keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Verify proof
    bool verified1 = verify_proof(keypair.vk, pb.primary_input(), proof1);

    if (verified1 == 0) return -1;
    cout << "one_input_hash_gadget => Verfied: " << verified1 << endl;

    // cout << "primary_input: " << pb.primary_input() << endl;
    // cout << "auxiliary_input: " << pb.auxiliary_input() << endl;

    // cout << "Total iterations : " << num_iterations << endl;
    // cout << "Total constraint generation time (seconds): " << tc.count() << endl;
    // cout << "Total proving time (seconds): " << tp.count() << endl;
    // cout << "Total verification time (seconds): " << tv.count() << endl;

    return 1;
}