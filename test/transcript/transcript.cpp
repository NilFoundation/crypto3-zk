//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE zk_transcript_test

#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/test.value()/test_case.hpp>
#include <boost/test.value()/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;

BOOST_AUTO_TEST_SUITE(zk_transcript_test_suite)

BOOST_AUTO_TEST_CASE(zk_transcript_manual_test) {
    using field_type = algebra::curves::alt_bn128_254::scalar_field_type;
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<hashes::keccak_1600<256>> tr(init_blob);
    auto ch1 = tr.challenge<field_type>();
    auto ch2 = tr.challenge<field_type>();
    auto ch_n = tr.challenges<field_type, 3>();

    BOOST_CHECK_EQUAL(ch1.value(), field_type::value_type(0xe858ba005424eabd6d97de7e930779def59a85c1a9ff7e8a5d001cdb07f6e4_cppui256));
    BOOST_CHECK_EQUAL(ch2.value(), field_type::value_type(0xf61f38f58a55b3bbee0480fc5ec3cf8df81603579f4f7134f764bfd3ca5938b_cppui256));

    BOOST_CHECK_EQUAL(ch_n[0].value(), field_type::value_type(0x4f6b97a9bc99d6996fab5e03d1cd0b418a9b3c97ed64cca070e15777e7cc99a_cppui256));
    BOOST_CHECK_EQUAL(ch_n[1].value(), field_type::value_type(0x2414ddf7ecff246500beb2c01b0c5912a400bc3cdca6d7f24bd2bd4987b21e04_cppui256));
    BOOST_CHECK_EQUAL(ch_n[2].value(), field_type::value_type(0x10bfe2f4a414eec551dda5fd9899e9b46e327648b4fa564ed0517b6a99396aec_cppui256));
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(zk_poseidon_transcript_test_suite)

// We need this test to make sure that poseidon keeps working exactly the same after any refactoring/code changes.
BOOST_AUTO_TEST_CASE(zk_poseidon_transcript_manual_test) {
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<poseidon_type> tr(init_blob);
    auto ch1 = tr.challenge<field_type>();
    auto ch2 = tr.challenge<field_type>();
    int ch_int = tr.int_challenge<int>();

    BOOST_CHECK_EQUAL(ch1.value(), field_type::value_type(0x6b671f5c63fa3c99a37a008771e15402914c057ba3246eada3050f6ae27a357_cppui256));
    BOOST_CHECK_EQUAL(ch2.value(), field_type::value_type(0x3d20314554eef41287229e8752b063aec62a482a365b5d592dede44c9fc88464_cppui256));
    BOOST_CHECK_EQUAL(ch_int, 45561);
}

BOOST_AUTO_TEST_SUITE_END()
