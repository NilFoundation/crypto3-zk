//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE fri_test

#include <string>
#include <random>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

using namespace nil::crypto3;

inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
    using dist_type = std::uniform_int_distribution<int>;
    static std::random_device random_engine;

    std::vector<std::size_t> step_list;
    std::size_t steps_sum = 0;
    while (steps_sum != r) {
        if (r - steps_sum <= max_step) {
            while (r - steps_sum != 1) {
                step_list.emplace_back(r - steps_sum - 1);
                steps_sum += step_list.back();
            }
            step_list.emplace_back(1);
            steps_sum += step_list.back();
        } else {
            step_list.emplace_back(dist_type(1, max_step)(random_engine));
            steps_sum += step_list.back();
        }
    }
    return step_list;
}

BOOST_AUTO_TEST_SUITE(fri_test_suite)

BOOST_AUTO_TEST_CASE(fri_basic_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 1);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};
    //merkle_tree_type commit_merkle = zk::algorithms::precommit<fri_type>(f, D[0]);

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(fri_skipping_layers_wrong_proof_test) {
    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 1024;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    math::polynomial<typename FieldType::value_type> f(d);
    std::generate(std::begin(f), std::end(f), [&rnd]() { return rnd(); });
    f.back() = FieldType::value_type::one();

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    params.max_degree = d/2;
    size_t len = std::pow(2, std::log2(params.max_degree + 1) - r + 1);
    for( size_t i = 0; i < proof.final_polynomials.size(); i++){
        proof.final_polynomials[i] = math::polynomial<typename FieldType::value_type>();
        proof.final_polynomials[i].resize(len);
        for( size_t j = 0; j < len; j++){
            proof.final_polynomials[i][j] = 1;
        }
    }

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(!zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(fri_basic_skipping_layers_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 1024;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    math::polynomial<typename FieldType::value_type> f(d);
    std::generate(std::begin(f), std::end(f), [&rnd]() { return rnd(); });
    f.back() = FieldType::value_type::one();

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(fri_steps_count_test) {

    // fri params
    using curve_type = algebra::curves::mnt4<298>;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> fri_type;
    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;
    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 1);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    math::polynomial<typename FieldType::value_type> final_polynomial = proof.final_polynomials[0];
    BOOST_CHECK_EQUAL(proof.final_polynomials[0].degree(), 1);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(batched_fri_test_suite)

BOOST_AUTO_TEST_CASE(batched_fri_basic_compile_time_size_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t leaf_size = 2;
    constexpr static const bool is_const_size = true;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, is_const_size> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 1);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}, {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}}};

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(batched_fri_basic_compile_time_size_skipping_layers_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 2048;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t leaf_size = 10;
    constexpr static const bool is_const_size = true;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, is_const_size> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f;
    f.fill(math::polynomial<typename FieldType::value_type>(d));
    for (auto &f_i : f) {
        std::generate(std::begin(f_i), std::end(f_i), [&rnd]() { return rnd(); });
        f_i.back() = FieldType::value_type::one();
    }

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(batched_fri_basic_runtime_size_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 1);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    std::vector<math::polynomial<typename FieldType::value_type>> f = {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1},
                                                                       {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 6, 1, 2, 1, 1}};

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root,transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(batched_fri_basic_runtime_size_skipping_layers_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 4096;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    const std::size_t leaf_size = 10;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    std::vector<math::polynomial<typename FieldType::value_type>> f(
        leaf_size, math::polynomial<typename FieldType::value_type>(d));
    for (auto &f_i : f) {
        std::generate(std::begin(f_i), std::end(f_i), [&rnd]() { return rnd(); });
        f_i.back() = FieldType::value_type::one();
    }

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(fri_dfs_test_suite)

BOOST_AUTO_TEST_CASE(fri_dfs_basic_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 1);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    math::polynomial<typename FieldType::value_type> f_data = {1, 3, 4, 1, 5, 6, 7, 2, 8, 5, 6, 1, 2, 1, 1};
    math::polynomial_dfs<typename FieldType::value_type> f;
    f.from_coefficients(f_data);

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(fri_dfs_basic_skipping_layers_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 1024;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    math::polynomial<typename FieldType::value_type> f_data(d);
    std::generate(std::begin(f_data), std::end(f_data), [&rnd]() { return rnd(); });
    f_data.back() = FieldType::value_type::one();
    math::polynomial_dfs<typename FieldType::value_type> f;
    f.from_coefficients(f_data);

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(fri_dfs_test_2) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = {2, 1, 1};

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    math::polynomial<typename FieldType::value_type> f_data = {1, 3, 4, 1, 5, 6, 7, 2, 8, 5, 6, 7, 1, 2, 1, 1};
    math::polynomial_dfs<typename FieldType::value_type> f;
    f.from_coefficients(f_data);

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(batched_fri_dfs_test_suite)

BOOST_AUTO_TEST_CASE(batched_fri_dfs_basic_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t leaf_size = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = {2, 1, 1};

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f_data = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}, {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 7, 7, 7, 1, 1}}};

    std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size> f;
    for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
        f[polynom_index].from_coefficients(f_data[polynom_index]);
    }

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    using ContainerType = std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size>;
    static_assert(
        !std::is_same<typename ContainerType::value_type, math::polynomial<typename FieldType::value_type>>::value);
    static_assert(
        std::is_same<typename ContainerType::value_type, math::polynomial_dfs<typename FieldType::value_type>>::value);
    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(batched_fri_dfs_basic_skipping_layers_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 2048;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t leaf_size = 10;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f_data;
    f_data.fill(math::polynomial<typename FieldType::value_type>(d));
    for (auto &f_i : f_data) {
        std::generate(std::begin(f_i), std::end(f_i), [&rnd]() { return rnd(); });
        f_i.back() = FieldType::value_type::one();
    }

    std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size> f;
    for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
        f[polynom_index].from_coefficients(f_data[polynom_index]);
    }

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    using ContainerType = std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size>;
    static_assert(
        !std::is_same<typename ContainerType::value_type, math::polynomial<typename FieldType::value_type>>::value);
    static_assert(
        std::is_same<typename ContainerType::value_type, math::polynomial_dfs<typename FieldType::value_type>>::value);
    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(batched_fri_dfs_test_2) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t leaf_size = 7;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = {2, 1, 1};

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f_data = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1},
         {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1},
         {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 7, 2, 1, 1},
         {1, 3, 4, 1, 5, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1},
         {1, 3, 4, 1, 5, 8, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1},
         {1, 3, 4, 1, 5, 4, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1},
         {1, 3, 4, 1, 5, 7, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1}}};

    std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size> f;
    for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
        f[polynom_index].from_coefficients(f_data[polynom_index]);
    }

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    using ContainerType = std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size>;
    static_assert(
        !std::is_same<typename ContainerType::value_type, math::polynomial<typename FieldType::value_type>>::value);
    static_assert(
        std::is_same<typename ContainerType::value_type, math::polynomial_dfs<typename FieldType::value_type>>::value);
    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, params, proof.round_proofs[0].T_root, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_SUITE_END()