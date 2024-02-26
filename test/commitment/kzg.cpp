//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#define BOOST_TEST_MODULE kzg_test

#include <string>

#include <boost/test/included/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::math;

void dump_vector(std::vector<uint8_t> const& x, std::string label = "") {
    std::cout << label << "[" << std::dec << x.size() << "] [31;1m";
    for(auto v: x) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << int(v);
    }
    std::cout << "[0m" << std::endl;
}

BOOST_AUTO_TEST_SUITE(kzg_test_suite)

BOOST_AUTO_TEST_CASE(kzg_basic_test) {

    typedef algebra::curves::mnt6_298 curve_type;
    //typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    scalar_value_type alpha = 10;
    std::size_t n = 16;
    scalar_value_type z = 2;
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3};

    auto params = typename kzg_type::params_type(n, alpha);
    BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == params.commitment_key[0]);
    BOOST_CHECK(alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[1]);
    BOOST_CHECK(alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[2]);
    BOOST_CHECK(alpha * alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[3]);
    BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == params.verification_key);

    auto commit = zk::algorithms::commit<kzg_type>(params, f);
    BOOST_CHECK(3209 * curve_type::template g1_type<>::value_type::one() == commit);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));
}

BOOST_AUTO_TEST_CASE(kzg_basic_test_mnt6) {

    typedef algebra::curves::mnt6_298 curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    scalar_value_type alpha = 10;
    std::size_t n = 16;
    scalar_value_type z = 2;
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3};

    auto params = typename kzg_type::params_type(n, alpha);
    BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == params.commitment_key[0]);
    BOOST_CHECK(alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[1]);
    BOOST_CHECK(alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[2]);
    BOOST_CHECK(alpha * alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[3]);
    BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == params.verification_key);

    auto commit = zk::algorithms::commit<kzg_type>(params, f);
    BOOST_CHECK(3209 * curve_type::template g1_type<>::value_type::one() == commit);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));
}

BOOST_AUTO_TEST_CASE(kzg_test_mnt6_accumulated) {

    typedef algebra::curves::mnt6_298 curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    scalar_value_type alpha = 7;
    std::size_t n = 8;
    scalar_value_type z = 2;
    const polynomial<scalar_value_type> f = {
        0x0ed6fb07f52c1f1ef7952250702368474f20fd7af906ba3a5842cdb7946c69b603852bf1069_cppui298,
        0x14db9efba58de09f8ccb1d73fefce45393856e6a7509006561fe67ea354ec69d791b44c1476_cppui298,
        0x0e9fa83a6f8891bc7e6aa1afae85e11dd80cdef32dfcef7cedc12792cf74141c899c8fb1f98_cppui298,
        0x101cc0b43782ca40ae5bf96aabf461e1a623ab9284acac3bb6d55bff4429356dad714ee0bd0_cppui298,
        0x1310586a4d1ed251d1e4c95711fb9346a2b233649f5ce32fe1cf3aea423d131787187a13799_cppui298,
        0x0d9ed064a24e83ac6134de7cca08bdc3e31ffd4db0a004b63039f76821ec2cc53b7e6a74735_cppui298,
        0x2839e48822f55b4e487b817ddf06a6e32e0dcc0c2ced1e738d38fec15bd4717d7680dda90ec_cppui298,
    };

    auto f_eval = f.evaluate(alpha);

    auto params = typename kzg_type::params_type(n, alpha);
    auto commit = zk::algorithms::commit<kzg_type>(params, f);
    nil::marshalling::status_type status;
    using endianness = nil::marshalling::option::big_endian;
    std::vector<uint8_t> single_commitment_bytes =
        nil::marshalling::pack<endianness>(commit, status);
    dump_vector(single_commitment_bytes, "commitment");

    BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == params.commitment_key[0]);
    BOOST_CHECK(alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[1]);
    BOOST_CHECK(alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[2]);
    BOOST_CHECK(alpha * alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[3]);
    BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == params.verification_key);

    BOOST_CHECK(f_eval * curve_type::template g1_type<>::value_type::one() == commit);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

//    std::cout << "proof:" << proof;

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));
}


BOOST_AUTO_TEST_CASE(kzg_basic_test_mnt4) {

    typedef algebra::curves::mnt4_298 curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    scalar_value_type alpha = 10;
    std::size_t n = 16;
    scalar_value_type z = 2;
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3};

    auto params = typename kzg_type::params_type(n, alpha);
    BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == params.commitment_key[0]);
    BOOST_CHECK(alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[1]);
    BOOST_CHECK(alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[2]);
    BOOST_CHECK(alpha * alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[3]);
    BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == params.verification_key);

    auto commit = zk::algorithms::commit<kzg_type>(params, f);
    BOOST_CHECK(3209 * curve_type::template g1_type<>::value_type::one() == commit);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));
}


BOOST_AUTO_TEST_CASE(kzg_random_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    std::size_t n = 298;
    scalar_value_type z = algebra::random_element<scalar_field_type>();
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3, 5, -15};

    auto params = typename kzg_type::params_type(n);
    auto commit = zk::algorithms::commit<kzg_type>(params, f);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));
}

BOOST_AUTO_TEST_CASE(kzg_false_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    scalar_value_type alpha = 10;
    std::size_t n = 16;
    scalar_value_type z = 5;
    const polynomial<scalar_value_type> f = {100, 1, 2, 3};

    auto params = typename kzg_type::params_type(n, alpha);

    auto commit = zk::algorithms::commit<kzg_type>(params, f);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));

    // wrong params
    auto ck2 = params.commitment_key;
    ck2[0] = ck2[0] * 2;
    auto params2 = kzg_type::params_type(ck2, params.verification_key * 2);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params2, proof, pk));

    // wrong commit
    auto pk2 = pk;
    pk2.commit = pk2.commit * 2;
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2));

    // wrong eval
    pk2 = pk;
    pk2.eval *= 2;
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2));

    // wrong proof
    {
        // wrong params
        typename kzg_type::proof_type proof2;
        bool exception = false;
        try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params2, f, pk);}
        catch (std::runtime_error& e) {exception = true;}
        if (!exception) {
            BOOST_CHECK(proof2 != proof);
            BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk), "wrong params");
        }

        // wrong transcript
        exception = false;
        try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, f, pk2);}
        catch (std::runtime_error& e) {exception = true;}
        if (!exception) {
            BOOST_CHECK(proof2 != proof);
            BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk), "wrong transcript");
        }
    }
    auto proof2 = proof * 2;
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk));
}

BOOST_AUTO_TEST_SUITE_END()

// BOOST_AUTO_TEST_SUITE(batched_kzg_test_suite)

// BOOST_AUTO_TEST_CASE(kzg_batched_basic_test) {

//     typedef algebra::curves::bls12<381> curve_type;
//     typedef typename curve_type::base_field_type::value_type base_value_type;
//     typedef typename curve_type::base_field_type base_field_type;
//     typedef typename curve_type::scalar_field_type scalar_field_type;
//     typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

//     typedef hashes::sha2<256> transcript_hash_type;
//     typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, 2> kzg_type;
//     typedef typename kzg_type::transcript_type transcript_type;

//     scalar_value_type alpha = 7;
//     std::size_t n = 8;
//     const std::vector<polynomial<scalar_value_type>> fs{{
//         {{1, 2, 3, 4, 5, 6, 7, 8}},
//         {{11, 12, 13, 14, 15, 16, 17, 18}},
//         {{21, 22, 23, 24, 25, 26, 27, 28}},
//         {{31, 32, 33, 34, 35, 36, 37, 38}},
//     }};
//     const std::vector<polynomial<scalar_value_type>> gs{{
//         {{71, 72, 73, 74, 75, 76, 77, 78}},
//         {{81, 82, 83, 84, 85, 86, 87, 88}},
//         {{91, 92, 93, 94, 95, 96, 97, 98}},
//     }};
//     typename kzg_type::batch_of_batches_of_polynomials_type polys = {fs, gs};
//     std::array<scalar_value_type, 2> zs = {101, 3};

//     auto params = typename kzg_type::params_type(n, alpha);

//     typename kzg_type::batched_public_key_type pk = zk::algorithms::setup_public_key<kzg_type>(params, polys, zs);
//     transcript_type transcript =
//     auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

//     transcript_type transcript_verification =
//     BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
// }

// BOOST_AUTO_TEST_CASE(kzg_batched_random_test) {

//     typedef algebra::curves::bls12<381> curve_type;
//     typedef typename curve_type::base_field_type::value_type base_value_type;
//     typedef typename curve_type::base_field_type base_field_type;
//     typedef typename curve_type::scalar_field_type scalar_field_type;
//     typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

//     typedef hashes::sha2<256> transcript_hash_type;
//     typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, 3> kzg_type;
//     typedef typename kzg_type::transcript_type transcript_type;

//     std::size_t n = 298;
//     const std::vector<polynomial<scalar_value_type>> f0{{
//         {{1, 2, 3, 4, 5, 6, 7, 8}},
//         {{11, 12, 13, 14, 15, 16, 17}},
//         {{21, 22, 23, 24, 25, 26, 27, 28}},
//         {{31, 32, 33, 34, 35, 36, 37, 38, 39}},
//     }};
//     const std::vector<polynomial<scalar_value_type>> f1{{
//         {{71, 72}},
//         {{81, 82, 83, 85, 86, 87, 88}},
//         {{91, 92, 93, 94, 95, 96, 97, 98, 99, 100}},
//     }};
//     const std::vector<polynomial<scalar_value_type>> f2{{
//         {{73, 74, 25}},
//         {{87}},
//         {{91, 92, 93, 94, 95, 96, 97, 100, 1, 2, 3}},
//     }};
//     const kzg_type::batch_of_batches_of_polynomials_type polys = {f0, f1, f2};
//     std::array<scalar_value_type, 3> zs = {101, 3, 5};

//     auto params = typename kzg_type::params_type(n);

//     typename kzg_type::batched_public_key_type pk = zk::algorithms::setup_public_key<kzg_type>(params, polys, zs);
//     transcript_type transcript =
//     auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

//     transcript_type transcript_verification =
//     BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
// }

// BOOST_AUTO_TEST_CASE(kzg_batched_false_test) {

//     typedef algebra::curves::bls12<381> curve_type;
//     typedef typename curve_type::base_field_type::value_type base_value_type;
//     typedef typename curve_type::base_field_type base_field_type;
//     typedef typename curve_type::scalar_field_type scalar_field_type;
//     typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

//     typedef hashes::sha2<256> transcript_hash_type;
//     typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, 3> kzg_type;
//     typedef typename kzg_type::transcript_type transcript_type;

//     scalar_value_type alpha = 7;
//     std::size_t n = 298;
//     const std::vector<polynomial<scalar_value_type>> fs{{
//         {{1, 2, 3, 4, 5, 6, 7, 8}},
//         {{11, 12, 13, 14, 15, 16, 17, 18}},
//         {{21, 22, 23, 24, 25, 26, 27, 28}},
//         {{31, 32, 33, 34, 35, 36, 37, 38}},
//     }};
//     const std::vector<polynomial<scalar_value_type>> gs{{
//         {{71, 72, 73, 74, 75, 76, 77, 78}},
//         {{81, 82, 83, 84, 85, 86, 87, 88}},
//         {{91, 92, 93, 94, 95, 96, 97, 98}},
//     }};
//     const std::vector<polynomial<scalar_value_type>> hs{{
//         {{71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81}},
//     }};
//     typename kzg_type::batch_of_batches_of_polynomials_type polys = {fs, gs, hs};
//     std::array<scalar_value_type, 3> zs = {101, 3, 5};

//     auto params = typename kzg_type::params_type(n, alpha);

//     typename kzg_type::batched_public_key_type pk = zk::algorithms::setup_public_key<kzg_type>(params, polys, zs);;
//     transcript_type transcript =
//     auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

//     transcript_type transcript_verification =
//     BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));

//     // wrong params
//     auto ck2 = params.commitment_key;
//     ck2[0] = ck2[0] * 2;
//     auto params2 = kzg_type::params_type(ck2, params.verification_key * 2);
//     transcript_type transcript_verification_wp =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params2, proof, pk, transcript_verification_wp));

//     // wrong transcript - used
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));

//     // wrong transcript - wrong params
//     transcript_type transcript_verification_wpt =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification_wpt));

//     // wrong evals
//     auto pk_we = pk;
//     pk_we.evals[0].back() = pk_we.evals[0].back() * 2;
//     transcript_type transcript_verification_we =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk_we, transcript_verification_we));

//     // wrong commitments
//     auto pk_wc = pk;
//     pk_wc.commits[0].back() = pk_wc.commits[0].back() * 2;
//     transcript_type transcript_verification_wc =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk_wc, transcript_verification_wc));

//     // wrong pk
//     auto pk2 = pk;
//     pk2.commits[0].back() = pk2.commits[0].back() * 2;
//     pk2.evals[0].back() = pk2.evals[0].back() * 2;
//     transcript_type transcript_verification_wpk =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2, transcript_verification_wpk));

//     // wrong proof
//     {
//         // wrong params
//         typename kzg_type::batched_proof_type proof2;
//         typename kzg_type::batched_public_key_type pk2 = zk::algorithms::setup_public_key<kzg_type>(params2, polys, zs);
//         bool exception = false;
//         transcript_type transcript_wpp =
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params2, polys, pk, transcript_wpp);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpp =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpp), "wrong params");
//         }

//         // wrong transcript - used
//         exception = false;
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript_wpp);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpt =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpt), "wrong transcript");
//         }

//         // wrong evals
//         exception = false;
//         transcript_type transcript_wpe =
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, polys, pk_we, transcript_wpe);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpe =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpe), "wrong evals");
//         }

//         // wrong zs
//         auto pk_zs = pk;
//         pk_zs.zs[0] = pk_zs.zs[0] * 2;
//         exception = false;
//         transcript_type transcript_wzs =
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, polys, pk_zs, transcript_wzs);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpp =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpp), "wrong params");
//         }

//         // wrong commits
//         exception = false;
//         transcript_type transcript_wcs =
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, polys, pk_we, transcript_wcs);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpp =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpp), "wrong params");
//         }

//         // wrong pk
//         exception = false;
//         transcript_type transcript_wpk =
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, polys, pk2, transcript_wpk);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpp =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpp), "wrong params");
//         }
//     }
//     auto proof2 = proof;
//     proof2.back() = proof2.back() * 2;
//     transcript_type transcript_verification_wpr =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpr));

//     // wrong combination of all
//     transcript_type transcript_verification_2 =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params2, proof2, pk2, transcript_verification_2));
// }

// BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(batched_kzg_test_suite)

BOOST_AUTO_TEST_CASE(batched_kzg_basic_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::sha2<256> transcript_hash_type;
    const std::size_t batch_size = 1;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    typename kzg_type::batch_of_polynomials_type polys = {{{1, 2, 3, 4, 5, 6, 7, 8}}};

    scalar_value_type alpha = 7;
    std::size_t d = 8;
    std::size_t t = 8;
    auto params = typename kzg_type::params_type(d, t, alpha);

    std::vector<std::vector<scalar_value_type>> eval_points = {{{101, 2, 3},}};
    std::vector<scalar_value_type> merged_eval_points = zk::algorithms::merge_eval_points<kzg_type>(eval_points);
    auto rs = zk::algorithms::create_evals_polys<kzg_type>(polys, eval_points);

    BOOST_CHECK(rs.size() == batch_size);
    for (std::size_t i = 0; i < batch_size; ++i) {
        for (auto s : eval_points[i]) {
            BOOST_CHECK(polys[i].evaluate(s) == rs[i].evaluate(s));
        }

    }
    auto commits = zk::algorithms::commit<kzg_type>(params, polys);
    auto pk = typename kzg_type::public_key_type(commits, merged_eval_points, eval_points, rs);

    transcript_type transcript;
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

    transcript_type transcript_verification;

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
}

BOOST_AUTO_TEST_CASE(batched_kzg_bigger_basic_test) {
//    typedef algebra::curves::bls12<381> curve_type;
    typedef algebra::curves::mnt6_298 curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::keccak_1600<256> transcript_hash_type;
//    typedef hashes::sha2<256> transcript_hash_type;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    scalar_value_type alpha = 7;
    typename kzg_type::batch_of_polynomials_type polys = {{{{1, 2, 3, 4, 5, 6, 7, 8}},
                                                        {{11, 12, 13, 14, 15, 16, 17, 18}},
                                                        {{21, 22, 23, 24, 25, 26, 27, 28}},
                                                        {{31, 32, 33, 34, 35, 36, 37, 38}}}};

    auto params = typename kzg_type::params_type(8, 8, alpha);

    std::vector<std::vector<scalar_value_type>> S = {{{101, 2, 3}, {102, 2, 3}, {1, 3}, {101, 4}}};
    std::vector<scalar_value_type> T = zk::algorithms::merge_eval_points<kzg_type>(S);
    {
        std::vector<scalar_value_type> T_check = {1, 2, 3, 4, 101, 102};
        std::sort(T.begin(), T.end());
        BOOST_CHECK(T == T_check);
    }
    auto rs = zk::algorithms::create_evals_polys<kzg_type>(polys, S);
    BOOST_CHECK(rs.size() == polys.size());
    for (std::size_t i = 0; i < polys.size(); ++i) {
        BOOST_CHECK(rs[i].degree() < polys[i].degree());
        for (auto s : S[i]) {
            BOOST_CHECK(polys[i].evaluate(s) == rs[i].evaluate(s));
        }
    }
    auto commits = zk::algorithms::commit<kzg_type>(params, polys);
    auto pk = typename kzg_type::public_key_type(commits, T, S, rs);

    transcript_type transcript;
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

    transcript_type transcript_verification;
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
}
/*
BOOST_AUTO_TEST_CASE(batched_kzg_bigger_basic_test_mnt6) {
    typedef algebra::curves::mnt6_298 curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::sha2<256> transcript_hash_type;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    scalar_value_type alpha = 7;
    typename kzg_type::batch_of_polynomials_type polys = {{{{1, 2, 3, 4, 5, 6, 7, 8}},
                                                        {{11, 12, 13, 14, 15, 16, 17, 18}},
                                                        {{21, 22, 23, 24, 25, 26, 27, 28}},
                                                        {{31, 32, 33, 34, 35, 36, 37, 38}}}};

    auto params = typename kzg_type::params_type(8, 8, alpha);

    std::vector<std::vector<scalar_value_type>> S = {{{101, 2, 3}, {102, 2, 3}, {1, 3}, {101, 4}}};
    std::vector<scalar_value_type> T = zk::algorithms::merge_eval_points<kzg_type>(S);
    {
        std::vector<scalar_value_type> T_check = {1, 2, 3, 4, 101, 102};
        std::sort(T.begin(), T.end());
        BOOST_CHECK(T == T_check);
    }
    auto rs = zk::algorithms::create_evals_polys<kzg_type>(polys, S);
    BOOST_CHECK(rs.size() == polys.size());
    for (std::size_t i = 0; i < polys.size(); ++i) {
        BOOST_CHECK(rs[i].degree() < polys[i].degree());
        for (auto s : S[i]) {
            BOOST_CHECK(polys[i].evaluate(s) == rs[i].evaluate(s));
        }
    }
    auto commits = zk::algorithms::commit<kzg_type>(params, polys);
    auto pk = typename kzg_type::public_key_type(commits, T, S, rs);

    transcript_type transcript;
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

    transcript_type transcript_verification;
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
}
*/

template<typename kzg_type>
typename kzg_type::params_type create_kzg_params(std::size_t degree_log) {
    // TODO: what cases t != d?
    typename kzg_type::field_type::value_type alpha (7);
    std::size_t d = 1 << degree_log;

    typename kzg_type::params_type params(d, d, alpha);
    return params;
}


BOOST_AUTO_TEST_CASE(batched_kzg_placeholder_repr) {
    typedef algebra::curves::mnt6_298 curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::keccak_1600<256> transcript_hash_type;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    scalar_value_type alpha = 7;
    typename kzg_type::batch_of_polynomials_type polys = {{
        {{
                 0x39ef702ef59ff1816e4f51f2ae7fe2d78108c006d5f3039cd1a474ba8c48c16a62518f86863_cppui298,
                 0x17dadc1965bae6d9426ef1a2e6d3640ac4cd96089c55c7dc3800924668fcc450cbaa7de9f4c_cppui298,
                 0x1202bd2e4122c826d8ba7cd66346c0df0326468fd6e7989c8eebe3dedfcbd9b0ecdc1fb41c2_cppui298,
                 0x3b718dda0c9262c55640bd1e364df577ec246e46cb05109733008263282cc1a8959b4bf6fa7_cppui298,
                 0x27b08d175547d973e48f341c081c3851eee512d6e73200bfa47b1e049e1d268409ad2ce21c9_cppui298,
                 0x1872fd6e208095436bfcb92388e0d1c8509c3f8e89235d0430c61add0ab203ac30370518ce6_cppui298,
                 0x304c1332568ebbe7347b598eef6cb41f198a574c4ff7cd151337211efea753ec6fc7d61330b_cppui298,
                 0x1b41e76a1c5a4daa01029a0ec27b5f0b06ca7b480b600b8b573ae00feaab4ad9f1146a99459_cppui298,
        }},
        {{
                 0x11cccdf2e5ccc50aa597c4194181c1fe652f508e4aafb2a0137f878c4b3b9d09511285954a1_cppui298,
                 0x1e2f5a14babe0e0d4adcace1969a3c78807ea6da4ae1cca797a6bf88c3101397d8d2452a9dc_cppui298,
                 0x360a362e2078f4e68d4b9e847d6da083454c3ce2e7379483cfa751cf2c0cd7e8a47cc314928_cppui298,
                 0x126a1e24bba3895afe1e9d30005f807b7df2082352cd5c31f79e7e1faee22ae9ef6d091bb5c_cppui298,
                 0x126a1e24bba3895afe1e9d30005f807b7df2082352cd5c31f79e7e1faee22ae9ef6d091bb5c_cppui298,
                 0x011394bbd52cee496c395d41b68e0732c88572384d492e195f8f5b1c7a1c61f6ed67f94c950_cppui298,
                 0x194e4123c5669a48341b2f6b127f0a8b109818666a3d2229f23414de9c5d23d2d63c05309be_cppui298,
                 0x30641ec0f843aeb8202263821cac300d11b237ce42e2876763c8c16513494b993aaf5941f61_cppui298,
        }},
        {{
                 0x1e2f5a14babe0e0d4adcace1969a3c78807ea6da4ae1cca797a6bf88c3101397d8d2452a9dc_cppui298,
                 0x360a362e2078f4e68d4b9e847d6da083454c3ce2e7379483cfa751cf2c0cd7e8a47cc314928_cppui298,
                 0x0c3d778f1a6196ab1c2ba05597c7b275b23cb23faf7b128228ae23ad2aac20cc2bb1cc68ae9_cppui298,
                 0x1d871330c3db0fc34493247dc5f22570c08e3c4d3019e89ccadb340ddf48317d9dda6bf5cd9_cppui298,
                 0x114ac4e3bcbc6bf412878efb87080a493920fdbdb54535e797af6c6f15cacfa5a93c46626f0_cppui298,
                 0x0cfede4389503774cda3e57a7034cc1c54ad074f86f551b54a44118a30afd0fc06ad7393ee6_cppui298,
                 0x3b079297527c765d71f9db51a85f47c081d4047080ad9352f6a325410e1e8490ddc59988939_cppui298,
                 0x299eacd3439bb98b27f8cbaafb3983162a895d3de16cb29360ad4b12f5f114dee4f5a065b97_cppui298,
        }},
        {{
                 0x126a1e24bba3895afe1e9d30005f807b7df2082352cd5c31f79e7e1faee22ae9ef6d091bb5c_cppui298,
                 0x0,
                 0x1,
                 0x0,
                 0x0,
                 0x0,
                 0x0,
                 0x0,
        }}
    }};

//    auto params = typename kzg_type::params_type(8, 8, alpha);
    auto params = create_kzg_params<kzg_type>(3);
    auto commits = zk::algorithms::commit<kzg_type>(params, polys);
    using endianness = nil::marshalling::option::big_endian;
    for(auto &c: commits) {
        nil::marshalling::status_type status;
        std::vector<uint8_t> single_commitment_bytes =
            nil::marshalling::pack<endianness>(c, status);
        dump_vector(single_commitment_bytes, "commitment");
    }

    std::vector<std::vector<scalar_value_type>> S = {{{101, 2, 3}, {102, 2, 3}, {1, 3}, {101, 4}}};
    std::vector<scalar_value_type> T = zk::algorithms::merge_eval_points<kzg_type>(S);
    {
        std::vector<scalar_value_type> T_check = {1, 2, 3, 4, 101, 102};
        std::sort(T.begin(), T.end());
        BOOST_CHECK(T == T_check);
    }
    auto rs = zk::algorithms::create_evals_polys<kzg_type>(polys, S);
    BOOST_CHECK(rs.size() == polys.size());
    for (std::size_t i = 0; i < polys.size(); ++i) {
        BOOST_CHECK(rs[i].degree() < polys[i].degree());
        for (auto s : S[i]) {
            BOOST_CHECK(polys[i].evaluate(s) == rs[i].evaluate(s));
        }
    }
    auto pk = typename kzg_type::public_key_type(commits, T, S, rs);

    transcript_type transcript;
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

    transcript_type transcript_verification;
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
}

BOOST_AUTO_TEST_SUITE_END()
