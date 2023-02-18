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
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;

BOOST_AUTO_TEST_SUITE(zk_transcript_test_suite)

BOOST_AUTO_TEST_CASE(zk_transcript_manual_test) {
    using curve_type = algebra::curves::bls12<381>;
    using field_type = curve_type::scalar_field_type;
    using g1_type = curve_type::template g1_type<>;
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    typename transcript::fiat_shamir_heuristic_sequential<hashes::sha2<256>> tr(init_blob);
    auto ch1 = tr.challenge<field_type>();
    auto ch2 = tr.challenge<field_type>();
    auto ch_n = tr.challenges<field_type, 3>();

    std::cout << ch1.data << std::endl;
    std::cout << ch2.data << std::endl;
    for (const auto &ch : ch_n) {
        std::cout << ch.data << std::endl;
    }

    std::vector<std::uint8_t> updated_blob {0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    tr(updated_blob);

    // merkle tree root example
    std::vector<std::array<char, 1>> v = {{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}};
    typename containers::merkle_tree<hashes::sha2<256>, 2> mt = containers::make_merkle_tree<hashes::sha2<256>, 2>(v.begin(), v.end());
    tr(mt.root());

    // field element example
    typename field_type::value_type field_elem = algebra::random_element<field_type>();
    std::size_t blob_size = field_type::arity * (field_type::modulus_bits / 8 + (field_type::modulus_bits % 8 ? 1 : 0));
    std::vector<std::uint8_t> byteblob(blob_size);
    using bincode = typename nil::marshalling::bincode::field<field_type>;
    bincode::template field_element_to_bytes<std::vector<std::uint8_t>::iterator>(field_elem, byteblob.begin(), byteblob.end());
    tr(byteblob);

    // curve element example
    typename g1_type::value_type g1_elem = algebra::random_element<g1_type>();
    using serial = typename nil::marshalling::curve_element_serializer<curve_type>;
    tr(serial::point_to_octets(g1_elem));

    ch_n = tr.challenges<field_type, 3>();
    for (const auto &ch : ch_n) {
        std::cout << ch.data << std::endl;
    }
}

BOOST_AUTO_TEST_SUITE_END()
