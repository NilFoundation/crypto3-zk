//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE r1cs_gg_ppzksnark_aggregation_test

#include <vector>
#include <tuple>
#include <string>
#include <utility>
#include <random>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/assert.hpp>
#include <boost/iterator/zip_iterator.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/zk/snark/commitments/kzg.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/srs.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/prover.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/transcript.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk::snark;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << std::hex << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    os << std::hex << "[" << e.data[0].data << "," << e.data[1].data << "]" << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp6_3over2<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << ", ";
    print_field_element(os, e.data[2]);
    os << "]" << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const fields::detail::element_fp12_2over3over2<FieldParams> &e) {
    os << std::hex << "[[[" << e.data[0].data[0].data[0].data << "," << e.data[0].data[0].data[1].data << "],["
       << e.data[0].data[1].data[0].data << "," << e.data[0].data[1].data[1].data << "],["
       << e.data[0].data[2].data[0].data << "," << e.data[0].data[2].data[1].data << "]],"
       << "[[" << e.data[1].data[0].data[0].data << "," << e.data[1].data[0].data[1].data << "],["
       << e.data[1].data[1].data[0].data << "," << e.data[1].data[1].data[1].data << "],["
       << e.data[1].data[2].data[0].data << "," << e.data[1].data[2].data[1].data << "]]]" << std::endl;
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(std::ostream &os, const FpCurveGroupElement &e) {
    os << std::hex << "( " << e.X.data << " : " << e.Y.data << " : " << e.Z.data << " )" << std::endl;
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(std::ostream &os, const Fp2CurveGroupElement &e) {
    os << std::hex << "(" << e.X.data[0].data << " , " << e.X.data[1].data << ") : (" << e.Y.data[0].data << " , "
       << e.Y.data[1].data << ") : (" << e.Z.data[0].data << " , " << e.Z.data[1].data << ")" << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<typename curves::bls12<381>::template g1_type<>::value_type> {
                void operator()(std::ostream &os,
                                typename curves::bls12<381>::template g1_type<>::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::bls12<381>::template g2_type<>::value_type> {
                void operator()(std::ostream &os,
                                typename curves::bls12<381>::template g2_type<>::value_type const &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp2<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp6_3over2<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp6_3over2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp12_2over3over2<FieldParams>> {
                void operator()(std::ostream &os,
                                typename fields::detail::element_fp12_2over3over2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

using curve_type = curves::bls12_381;
using scheme_type =
    r1cs_gg_ppzksnark<curve_type, r1cs_gg_ppzksnark_generator<curve_type, ProvingMode::Aggregate>,
                      r1cs_gg_ppzksnark_prover<curve_type, ProvingMode::Aggregate>,
                      r1cs_gg_ppzksnark_verifier_strong_input_consistency<curve_type, ProvingMode::Aggregate>,
                      ProvingMode::Aggregate>;

using g1_type = typename curve_type::template g1_type<>;
using g2_type = typename curve_type::template g2_type<>;
using gt_type = typename curve_type::gt_type;
using G1_value_type = typename g1_type::value_type;
using G2_value_type = typename g2_type::value_type;

using scalar_field_type = typename curve_type::scalar_field_type;
using scalar_field_value_type = typename scalar_field_type::value_type;

using fq_type = typename curve_type::base_field_type;
using fq_value_type = typename fq_type::value_type;

using fq2_type = typename G2_value_type::field_type;
using fq2_value_type = typename fq2_type::value_type;

using fq12_type = typename curve_type::gt_type;
using fq12_value_type = typename fq12_type::value_type;

using fq6_value_type = typename fq12_value_type::underlying_type;

using scalar_modular_type = typename scalar_field_type::modular_type;
using base_modular_type = typename curve_type::base_field_type::modular_type;

using hash_type = hashes::sha2<256>;

using DistributionType = boost::random::uniform_int_distribution<typename scalar_field_type::integral_type>;
using GeneratorType = boost::random::mt19937;

BOOST_AUTO_TEST_SUITE(aggregation_functions_conformity_test)

// Test data generated by bellperson
BOOST_AUTO_TEST_CASE(bls381_commitment_test) {
    std::size_t n = 10;
    scalar_field_value_type u(0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255);
    scalar_field_value_type v(0x43131d0617d95a6fbd46c1f9055f60e8028acaae2e6e7e500a471ed47553ecfe_cppui255);

    auto w1 = structured_generators_scalar_power<g1_type>(n, u);
    auto w2 = structured_generators_scalar_power<g1_type>(n, v);
    r1cs_gg_ppzksnark_ipp2_wkey<curve_type> wkey {w1, w2};

    auto v1 = structured_generators_scalar_power<g2_type>(n, u);
    auto v2 = structured_generators_scalar_power<g2_type>(n, v);
    r1cs_gg_ppzksnark_ipp2_vkey<curve_type> vkey {v1, v2};

    std::vector<G1_value_type> a = {
        G1_value_type(
            0x0f8a94d761852712cc9408e3b2802aadfac6ae8840e33dc0b02c3df6bf3c139bd9390f10bd7e1942d0a4ee1e2bce3c4c_cppui381,
            0x1243524a748ca8f359697c46e29af5e331be8059628a9dca0d9bf7deb4924360754400222e13f1cfc75606d6695422eb_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x04c1a1c869d164044f09f9a42a10e4488a99adf06a5a689fabfd76890a137a884adf415d516615758b2cb3fb68e8e601_cppui381,
            0x09846e9776d3eeace43f1b26a71cffc0f84d021168ac96bbf32b0037dad49449a3259df6dc4a9542daec9d18d6ad2078_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x014c6d39bcffbe12ae7af62ac383efe538910888b3fdfff45f7789364f09282bb5ae2dba49f5ffb2fe1f0f36318c9d40_cppui381,
            0x19046eac6839db3f1c57c77965eddee9fb4a542acaa83293fc1ed8a9789a11927ed00ea00dd8a99138ebefab2e0a65f3_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x069e0585b1949fe6224f54542589d3f6afcd2064ec9d7cd90ab941c82bd0ee6f9099a327faf71f8b3b1f3fed9655a948_cppui381,
            0x1255d5100e698b3c118cb4f1f6361575c5b227fb1aa16b357e2a8cfabafc003857d288c6d2fbc34b0298510b0c1742e6_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x18ec551102d9902a3e89c67bb4081451ca67933040da61ede139c0d3df4e703dff22c283870a47865fed8e971ea41a0a_cppui381,
            0x14198bf26269a123d6802c3da3e95df666e839ea0be10da952d52942e1114834b83f816bf351ebb89c040e447183fd19_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x1818d8fd8dc994dfba13703ba296b251b58bfd129f8b3265f73a94bc5a424b854cad79cc75321d2161a72f513fe463f5_cppui381,
            0x0165b7d5a5d585709921fde377032bddef937d3a061776ff43b8f6a0d3c2b7fdc61bdc9dc052707da2a6c492a4696f60_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x1101a14b720e8e4b35dc2115304af9a4ebb1a0193b4d82379b8c3943363319d4859e1f0ca76aef7bbbd9d4db6becbc14_cppui381,
            0x0c92c3e46da264c431dac023f654e5c5540fe34471c7946dd32d5f25f6bf3529a041f9965206bf3416216fa7e251c5f4_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0c772ec090d90944627d4ce86f7f9dbc5bb8b3114ace872532d02de88bbef7709314257775dd41b506325a5f567c1289_cppui381,
            0x0e3a498329f47387340451a0984b19be5a8eac672704ebb295f85321cd19aaf5d56952b29bd3d0a6e478c010bbc16ea7_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0f30a9e7a22fad589a2cb9a5f1e7af8b70c98479f9bceda75af8770d5fa04fc60e009433f12712fd8a05b2fbc8d8bd6b_cppui381,
            0x0b4447c7af450fcf8f638ce3c6723e151fd9636cec84ba35f278d25d331cd726eb685c1cbaa48bbbb92523c9204dcae5_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0e26525b8fd932191628e29a2f62939d3f7e387646d48bb33a873331b89dbe007877703c6599291970c320274cfaa1f4_cppui381,
            0x089f59a37dbb4f9fc9a7349ecc0222216b6cb38370c5019e80fdc7c953c33fdd9b2da8966954b594097bf8cf7db6e2c2_cppui381,
            fq_value_type::one()),
    };

    typename kzg_commitment<curve_type>::output_type c1 = kzg_commitment<curve_type>::single(vkey, a.begin(), a.end());

    fq12_value_type etalon_c1_first = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x140bfee03fbe747bbdfbfad4577ea2af7175c5c601772f2d8f3c1751b32bf7177dff399967040a77606991e53df2d8bd_cppui381,
                0x01204263fc7f73813a0ac121e8e98d0b825b30a54eee57e9ea1b1618a7984212206e204fe51341a237c29861b27c68c7_cppui381),
            fq2_value_type(
                0x09ba91ba4f1c1bf8a657a5c946b652f0ca034efe9bdefa7235191c653673d09956c2ca0cf57c1983f525a9112c0f0fd1_cppui381,
                0x059b47fb6a66bd8a99a8a7ec56dddd183b6d1bbc534ff00eaab928a0f10e404fa4fa9ff5cc9eb9a5054eb4dfb3aca030_cppui381),
            fq2_value_type(
                0x16cd370184ae0c5c7fddef3dac1f272c0723d1f2e8f5ed93f8996e83970ee546f500e18a69d81538216156e22ef64f93_cppui381,
                0x199a09c8d60f9246e0d895cc230df9ca3e334b846539b20465e1e420ccadf654c02d90244724d241000b342c2461b878_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x0798b3616ff94070745cabcaa00627006153cc656cf159747eccc17a423df95905edf7db7da023a06f609c0c0c4ed808_cppui381,
                0x0bb15ba186dfdbd6c60c277bee3b29e4b51ebcfdd060cafa265a065d63cf8c72df03be62b31ea8f3b116a6643d8aadda_cppui381),
            fq2_value_type(
                0x179b1fd8d7d72a856dcf12c48c3b91db3930a18afd17660f9047d030a79b494844ff3901fbe1d1fd2933cb76681c68e9_cppui381,
                0x1679d14bcf02ea246f8486419ef20d5384a5d11ef1ade7b7c68f95b27d6bf8e1670a4ea192c8d8e53999ef359b9949da_cppui381),
            fq2_value_type(
                0x03f46c37e53e33257aecb46bd3cabf6f6019a2ea481ac567c8badf8250a27425e425d36614ec8f0bf87ea75df4443bdd_cppui381,
                0x00332853a0ed64dc0e7277fe792432644b9acc0955863ce982dbe3f3b6798fc4a9f56c98293c79e8eceb9e76d579714f_cppui381)));
    fq12_value_type etalon_c1_second = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x044df213be87f69e1ec7d16f831f3651c88d9c933bd005e390d5654043c94135e45b558b7f2ecf6ead89208261de1e97_cppui381,
                0x113daabcd8e117c7799008110783afdbaf320c623c13e1db4cb79e014f9cb825161ddbc05c7777aabd31513c7fc1cace_cppui381),
            fq2_value_type(
                0x19080dd8b95ec5b5e59c29db031a430c940c26559945c7db463737e778aa2fef9d1287196644e0b9fecd671f30ee6019_cppui381,
                0x0487279eec345a6b8230e476eab49bbd28b85082994f3085002c79fcc1c893aa54a46ac2e1b28327b2f21a679428e9d9_cppui381),
            fq2_value_type(
                0x0c9c0377cb585dd7422c3348d3d8ce89befbed472c2570411b15caf6a6bf4c69dc6e7db6092f7d0bd2c8670de5e3ca96_cppui381,
                0x100ae902f195d41ff489e9fd3d58b1684c1c8f81d05f5b99d0c0ab6f0399a893515137edb4c93e59130ad4cfe99f9b37_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x195985fab083b606700086a5abf53c873a03b2e6df0af1ce26430d3412c79958133d26af8e7a5b9a4d353920019a3e7a_cppui381,
                0x0300204c07b1559a6a9ee972e4130960fe286f50bbe4abbf5a3c392d8f1c78673e224a5c0f290c6a273dc4083cbe36c9_cppui381),
            fq2_value_type(
                0x14111077e1ff7677b532ed54e204c82c8c03b0ed963e44d2b9fd615ac4fbdb876f8e0f6f52e11448ea4ab3cd26616200_cppui381,
                0x0d46ee9f57f33c3d6216de22f24f697cbc3ede24da2207c8fc27d76153a0d39ad4198ed01b68f24f9357680183f0a1cf_cppui381),
            fq2_value_type(
                0x0c9ecea9b38974348515e5362a0f1215a6f03d844db50e539d5a1d50999f0cdfdfdd72c9fc6b6f29c42120cc7cc77e63_cppui381,
                0x0e24169cd073d7a84f4bf841f4fc2a223389cc55b3e002d8c8f586183b2aa269909dce414377f17145e1a69918cfd155_cppui381)));

    BOOST_CHECK_EQUAL(c1.first, etalon_c1_first);
    BOOST_CHECK_EQUAL(c1.second, etalon_c1_second);

    std::vector<G2_value_type> b = {
        G2_value_type(
            fq2_value_type(
                0x09e690df81211b6fd71977ace7b7f9907822ae7404c41e08f3a2d7b86daa17b09288c958dbf89527b1afcd50b59ee4c7_cppui381,
                0x00f8c7df5151249b79742ff5ce80660c13ccea63fa2469c48e41671e7a9b693ee2f2c09cd27954bc9532bed9f6d0bb41_cppui381),
            fq2_value_type(
                0x0f959ae56e18cd4185c44ef8b9d0c4930edede16b47963a4871b65fa06cdb5ff69c62f657b348bf189cdb0e3d6493272_cppui381,
                0x03c8015d3a153613d2f2419c911cf6fb6e9428ae23b98d4f19b81e3a57c8c5459f8063a2501aa89fd5ea940add2d6e66_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0c5e0f7fdfbf77ee7d140464ba731db9b99f37df0a06be3123447db3a46bab379b9bf7f16e9e4429de5abb2e9648c8c6_cppui381,
                0x0cb520b8e96560957114ad6d7e67dfdadb1bd88358b2ce482e8879a8ada324f60872ead531b9cb46b1de16041a7e5819_cppui381),
            fq2_value_type(
                0x087b07e6f10e365c78650a766590842a4b3b9072276e16ec58751707724e57261f7102020fb1190f5a730217244157a3_cppui381,
                0x16189daed8628a98dcc5c3982df12242107a2776939a0e23e96ec3a98242ebfedf3aa0ba6faecede760d133e4f8b3b60_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x15e0fd0a87b807e6390a7e72f57d8f47b8c46602939ffdc91407e08d169e036d8e39fd9f114cf4319153d18053fa1201_cppui381,
                0x021ae075bed23c5c04a58196e20d9a9819eaea4b28cdf2c144f3884cce2b3cee1c2ca67edcdb0c81c7629f43b913671f_cppui381),
            fq2_value_type(
                0x0f55034f53bfd3465b0374b7abe44fdb831080ce799f6ae2316df35abe8cae11e8c3c36f347ddc6cc46cb6ba78888b47_cppui381,
                0x022e87bee60c1ac9cdb051cd9d3c7c579cbb77f9ef8572cd42d312a38ec87a432dbe24ee21a165a951f2954efa161fe8_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0c26999b288ac57eaa399e65e1d849e186f304c0474f1c5c70acafe1177cbbba719327d0680e30f5a6ceb11feab39c6f_cppui381,
                0x04cc7745b53e41b642a70002f5f7b4515e81b6d1e7fd7de01d5c827c8a5ee8960f32fa4dc17173625d85a44ec7699f28_cppui381),
            fq2_value_type(
                0x10301cb9b9846330b836cc9d2b21b837f5e954f1d4618525c52c2dd0b734f1f06bcdf9b669285f437723a59df92340cb_cppui381,
                0x0fea154121f26e7bb8d997bba9c1ae7564d08cd51da04e770fec34886004acf78351fa19618b9f815c35acbe8db8bb6c_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x080785a6c856b3beabd7cd4b6bda1e28b06d971d835f7ba537423b267ee5acc809b96f71898b54b34115f9e06d0cb2f9_cppui381,
                0x0433029a8c5dbc20513065c874be1eabfe92b21ce79ecded24ff73687478997f08659cab60eec74a9e896f7d937d94f5_cppui381),
            fq2_value_type(
                0x0d11a2bbd1f8d571f9857353e11822341d24fd51b50155fdf002e41d22eebdfea4b883a2f426332a596edb650cbabcf5_cppui381,
                0x110051f9782ce55f721be563faee85618f262ed52e6c22cea74495647d4a80c07bacbd6db09c5420abc30159b2980819_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x08cb3db1ed554c7f3f8ee249a2bed141e753d37635257b243e9b74add03a91271e9f16da0caafc4193c11d3df5618091_cppui381,
                0x0b817c56f7db7387f7dd9df93a320796a9e1a1365c1f309a82c0e8d711cbbcc394350c8a791ca81ab19eade7f73c72d3_cppui381),
            fq2_value_type(
                0x00a00d84ce31283066883f0bcf1fe487904c2372b6a531978d83dcd901c7a7056055245425d76008c87fd4ea36039b5d_cppui381,
                0x00429080cd40357e275b478e75564af9435ba0480caa56c2bed13c5a5ba5743939645a8334ed0990c3e16fc558e4ff46_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x03df0e71b764fe8ee41af3cf3aa581c5134f7f0fa21d12398b623f3e7862a677b810e6152353cfe9cbffde603ddf258a_cppui381,
                0x00eb2582ffd4e5a26175cb6b8087fded84dd8fe45f386c13225ab17c8b95e211401652cc1edf70d8635c58d76569e8d3_cppui381),
            fq2_value_type(
                0x12dc4daa59ff9794847c54f3953f20228239e02d96cab9f22b8dc050cb4ce01ea2776273a07bd1e0b4813e3d06b9cf3e_cppui381,
                0x16e45e6a31e4f58f71c3f949d477a4035ff5d4611c8f13df495e7c4190f87190d74dc1545df8704d2611f209c221ac92_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x05606487ad598cd53d5ceeebb6572978a0cae7a181a6264429bd8eec68afc0b9e791f8a4190adf807e4390090082aa87_cppui381,
                0x0ce0c26551fe1fbb9cac5cd681b45715352a8e2961da3b616232285c08f42f652b5858a4619368f5bd55900e66ca2910_cppui381),
            fq2_value_type(
                0x174277032ded436b2941e6ffbeea4afd3fc7644754a6eb8838fc605459c13d2f1d8c3479040a0ec9ea345d7412709ae5_cppui381,
                0x0d35ad13fa98efa1d9f665a9212ae2acc8a6a2bcd1d78806c848d0b47a4e084f5491b3c5e2cdc537375bad926ebb47c8_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x103f4048259e2498b3235cf5f8c147c9fe5536f736be621a13c7cd2db960c304bb23c5f9554642acad89420b3802b75f_cppui381,
                0x1214f068b41c5302ed0ff42db19414c9f36821ee1df5d19842e87ccdb2eeb2450c17254195ebc6471c0bb2d4a1a5d76b_cppui381),
            fq2_value_type(
                0x07f58e4bc4bc0d6b1b55f0a1f2676234ad49d7e5f0fd942aaa296e582aff1a614b3183e622f0069fca3fd91b0e74e790_cppui381,
                0x108460a7cc77970d261962fe10933316dfc1b1012b5fb6fa7c3f1d03cb48953564e7c044b93d0f760176740bb2cdf6c3_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x11879877c76cc96ecf44b0fdd92626e2b701907461426955cb363d54f18bb627220988ee2a2568cc1db7a2504be96499_cppui381,
                0x125028b5a85cd28547ece1d1d47ffee83b5540225c8b3538c724608343df38a1b91c99a6e027f6f6c262f1785248e527_cppui381),
            fq2_value_type(
                0x01cbdd7aab1a1be51e6dc92798b94fca2aacda25cf13ecae179e7aedca028adbb5f79ac8bf6a9f5604f9605f0df4663d_cppui381,
                0x0d7b93debfcaca8662889c1f02c6051dea6b6901f17b6bb3c3143d1fccf437e1bef597c7d4d80453f464c874149e51b4_cppui381),
            fq2_value_type::one()),
    };

    typename kzg_commitment<curve_type>::output_type c2 =
        kzg_commitment<curve_type>::pair(vkey, wkey, a.begin(), a.end(), b.begin(), b.end());

    fq12_value_type etalon_c2_first = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x06374258f33742cf76fe64480b8ad2a86974a883987baf7e2f49b787ca7c3bb51054a38ac44adb31c7489e9c8d49e57c_cppui381,
                0x19ea09aac0b3eabd46e1d0941468d6d1d2e2b91adc32f789a099202112bd67091fa1ad6607dde1fdeac668b65f292bb6_cppui381),
            fq2_value_type(
                0x198f67a348fc61989b62bd222ebf556898544ae0a1ecc812c50641ea56f7bb3345631bcaceba13e150e4729278f924a7_cppui381,
                0x129dc8dbe59bf05522cfebaad81d6f7d8e7d3d66f1d90ab054a4598b50ba594e30ed41679b3ad1fbbf2ade87b5430ed9_cppui381),
            fq2_value_type(
                0x12498e9b54216dc229a1005aec0eaaa9b7103ab28feeee6545e316b96b697dc487081a6637ffb77ceb28ada75586d3a8_cppui381,
                0x07fcaf4b1e618d02843eabd0e62a70eaff57d30b6148de786f0a8b582c070ae132555197e92f6f2a3c19873e09c09eea_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x01c30d135188a98243ab65fa03710752698c00ec8dbc0cea0451d8889a6a71a3ad64b22c926e37e4b13fb374642b6ea8_cppui381,
                0x12d513a82eb3c5885a140b572e6871de735417a08273291337ef0c41781eee1856d415a3d4f8e9d7f0a6b52b02935f4d_cppui381),
            fq2_value_type(
                0x03b5a7efdab63732332d570bca0420cda704ca14ae354dd71978e61945520204aff412ce01b96b57751903fdd0f8ff60_cppui381,
                0x14f1eecb185e456af66d744ce71c9a97948f615fe28abc1118525b8fde195fc35ee1391c9d17c456690eaf7412aaa34f_cppui381),
            fq2_value_type(
                0x12247d032fe95b80cca3eb325c377f4d9bff75ced2d2218b46ea3425e0dff032cccb8915f57160ef3156e1f3de32570c_cppui381,
                0x0786d9e022313cc63f2f9019ad0c20fae5ce649ad6f65a15a41c46d1133896be4d584c481116ec988cc621fee980c423_cppui381)));
    fq12_value_type etalon_c2_second = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x05d3e965b1ddf572f81453a80474f013bdcbcbe76091bccad474829803926286c83b30be9b50eb810669e3583b0ace6d_cppui381,
                0x04a9171487ec6caccef97664499065f53a64a2b06dd0a5fea4cbc23bbf793f2cd91cef8c27a49750b2725016f2708a02_cppui381),
            fq2_value_type(
                0x0468d7a42d2338bff7ddffaaeda808496dd2526ff36ee861d9d2fff332997146a5e3309a705b649854f1a5728928a2d2_cppui381,
                0x0c98328b0db9e53e51592c3272ca21acb93f4975ca3f94419b6b2a46c75c5f879a83dedf9d4443cce15339e7ab593534_cppui381),
            fq2_value_type(
                0x04c526ce7891dd2e1efc326860147829bc55586cef46fd4190a574069b2cf59c48cbbe6017dc11a38670d0e1fdc02bc4_cppui381,
                0x0f380eba055ede7d6c14931bee8b094e1e67c4a6b526895cea679cda1fdf0f298bb71f69c867ab00d3573d682154ee34_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x03c63b40ca07dd457d85a76166eab0acdd212bd07969b87e37d62bae6c5a207d42d1d652ddd1ddbca31978f45077c5be_cppui381,
                0x07ea58d0dceb0457cfc50ae675d41b8d67b686a0013d0eff44b7497f420fb61717cf298bde3b9a84ae6741af069db641_cppui381),
            fq2_value_type(
                0x06b7e4d967b9a9debd338c044993a45f18dea0ac2a94ae075a7be650d47d2f28495d0115b5a1b944d3c420664ff8374a_cppui381,
                0x07e9dc11f7bad4aecf09ec07f4d158996f51c9c6d2784f670551d6786f3c0f44b974b6fcd1b508165e43d7fbae297bc8_cppui381),
            fq2_value_type(
                0x0768f0ac2cee937c8ad88372e16e9aeea5186fa1a65ca7f1290e0c361d2f2028e9dd35da7d4d32922610190b9a7cd39c_cppui381,
                0x047a4eaa8daef463a886a6483e9544a810e613fba4eec17b8b9308454c742cc0607671ac4007145152368fa0562a7c2d_cppui381)));

    BOOST_CHECK_EQUAL(c2.first, etalon_c2_first);
    BOOST_CHECK_EQUAL(c2.second, etalon_c2_second);

    scalar_field_value_type c(0x72629fcfc3205536b36d285f185f874593443f8ceab231d81ef8178d2958d4c3_cppui255);
    auto [vkey_left, vkey_right] = vkey.split(n / 2);
    kzg_commitment_key<g2_type> vkey_compressed = vkey_left.compress(vkey_right, c);
    auto [wkey_left, wkey_right] = wkey.split(n / 2);
    kzg_commitment_key<g1_type> wkey_compressed = wkey_left.compress(wkey_right, c);

    std::vector<G2_value_type> et_v1_compressed = {
        G2_value_type(
            fq2_value_type(
                0x0b74b7f8348ef6806367449678620c0943454fb99a4c35db90f2effabf1222b8b0d45175f812eaf687ac8eb8fdcd35e4_cppui381,
                0x101b4827b17e42992ec9cbfd7f942fe15b950bae7e44dbc004c6c6c7242bb7df4b02e54e2b2dd586e05e706236f53148_cppui381),
            fq2_value_type(
                0x1430aa96637e61f55af1ab05b1e3fb0c7d74fc922c0308d964c639103d15816cb3a8b97cf6e43b8bbccb1fb0bcf3c813_cppui381,
                0x195f9a7b105c1ac10b22a5c548fffa142eda073f91c1d867e63c86f1dea2633fc209481d22dd15d6f5de4ce8ff8c52fd_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x00c8044bd8548f5ae0c3a19fc8b3980fc94adbd9e7953c3715b49c25d2ffbb0ccdd1c7dba056a44d0696a0d9f907870f_cppui381,
                0x09bec35b32da6f260bfdabda7f42f6d0b364f9d0527f3ee85019286898776877ed491967f833431a50e9d26943b7e965_cppui381),
            fq2_value_type(
                0x183f644129e79748ea3bdffe2e8f401928ddb814525c229ecef3c181c24fea8e8f814a3da08ad7916af21f5263c86ea0_cppui381,
                0x04703ffe02768a0ffed187e084283db046e8c5d8a871e1cd4f1294c27f0729ade6e60706f5d78943296a0800882a17dc_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0a049b5bb3922ded25acbed4fe6fc260524c4d39af5f6820c0f25f76c87a5de587224fc4ab4ee0fb8e51ca5b354ef034_cppui381,
                0x0089ae4a8fe593660b04d3679e496747347ec7a0091dc4a02cc51cb074c0fa88426acfb5690ed6cfad1e0db3d7a3686d_cppui381),
            fq2_value_type(
                0x0761e2abbb49a3b011dbdb7f904a28dd8316497f0c16bcc06e6f2640443dbad8f1876188102850854c9b82a082e1bb80_cppui381,
                0x02fbb2d1918807d74d16514e1943f393f130fb2d7d6cde1860ce1f5cbe7693bc0eb1e1a84c129cdd063d3b4f121f81e5_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x11556de064ace780a8d6bd92fe9c32f903d65ffa039a596385bb865d61518d3916b319bfb44da815c46352deaff6498b_cppui381,
                0x01eee0a3f808f727bf741a2d036415e3dfcd9abf7a3445c4f0c4b87d5629e5013d3980a1e170c9d170c33d6fdb4d7252_cppui381),
            fq2_value_type(
                0x05b816fcd58e57c58211991f38f1a64ad6be94bc7b1f0a9844f6438f3dd80d3cc51c131e797a0c49bb3a41de4e145615_cppui381,
                0x15e109abc824df3600fabd8f186798187f39c6fa1c751602882bc551c19007012003f061f3e6820a36dd7c3884b0a9ee_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x15293a0e5372631bc3aa71a40cc067bd7eabd9a273bb2e4fbb0e33ec09c6c610bbe473f4c2fc0e276d0fdf3d80ffdae9_cppui381,
                0x1725efdd89c30b2d7665e250e4f0bdde8f97c75ef28c1cc277617756cc4364396ee709aadccbef3dcf2739fbe6e672fe_cppui381),
            fq2_value_type(
                0x05a0d144964762de0be4ce7fe354f3d9156c4316c8affe4ce305d0ab10e684317d9d77a32f306d2e57ed9eb7db8a3c9d_cppui381,
                0x067332db95199c7a9cac48cbbb4d172fbdb368693995cb9e6df88bb3c920a49ea329f6cf52528c8e1289f5189db2b347_cppui381),
            fq2_value_type::one()),
    };
    std::vector<G2_value_type> et_v2_compressed = {
        G2_value_type(
            fq2_value_type(
                0x186a7e15d408fa91dd9e7566d188fe02f7baa045fd16951d35b9d21acfd8005f95301d22fce8441c81c61b955e4589c6_cppui381,
                0x01209911f0abd559c390384a373b2d8e76bf5ac5675d3a5920e80453a8a9c2b648b993c4ba7fb401436e0406f6d8ec31_cppui381),
            fq2_value_type(
                0x0d25f34ceeff50e5502fddf943cfd36a628d119cd5f2d905617928743e71e77201547e433a407eed7f214f26c6e98424_cppui381,
                0x0ac2daac37505f408299340e30438444e5a9952a42d388966ceb504cab2a5498c38c318f1dfc5ad8055cd147ed8734c7_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x06b57042e4849b92a4e81346f8ba0114340c47d468096a46cddc32cfdd719a62137456eeaf56d1d28e0235cc806885c7_cppui381,
                0x063ca8f71db63973e371d8bbd76eee8fa490e59a7529b181c278b67b7a2b415440ccdda92a8834f4da915fe0383d43bd_cppui381),
            fq2_value_type(
                0x055dc89a8b6d8dc2027b1536f7e5ee25d6d1c3652860f2749bc97d17f91ad1655566b224339a8bcc2969783258716529_cppui381,
                0x0ce40dca881a8a4e995ebd12c10ce9f5081bce504e97f4e9f6ade1340c800d399a5fe3d669f44666d340663345e675e4_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x092dcde789e5a67dc5614d0b2462c550e7aa9be6d66d3492706f1454aaa2818609bb8dd1b850aa82d92d0f64c33d0435_cppui381,
                0x170f8e4565aa5ba8187714ffe7baa3a4917fe07475acc3cbd8fa429e034fa4f3ac53b06723eb5696f15d6e27393d888b_cppui381),
            fq2_value_type(
                0x07cbeb5679bad39efe161160a9f858ee129d82c0df28865a96dd23057ca9827c3606f3c2162cb76ac762f336e6bbb871_cppui381,
                0x19034ae5fcd14ab1ef3e1d979fd14ee274e61a1c64992f052c620f0c91a9a103f5a7bcb2bf5ce3056f4bd593d26f4a52_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x109b9b9fbf16c6fff2cf1f276ad1b09aff3ef976611cdc825f78e0f7ca76a271829e694b7f23a9ecb525427cdab92ed2_cppui381,
                0x150d3c3a996cb5713d597b4451e41b34b1b55b722784e951665fb1d07ee3c2ad5630ea3a35466c6dd8d96b105e5195bf_cppui381),
            fq2_value_type(
                0x0f93626288c013dffd087a341de791d5bd0c6cf04f1d0daa47232fd2705042c6a7627d902905bdfdbaa599672708a020_cppui381,
                0x0114d3a70ba03f3991a8c09294f3272e5143a84317494cfc4877f4d22eecb80be7fec0d6d80f6f0efb1b8c678f27f5ac_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x048f8757d41ff0940208039356e5ea7f8014761dea150eb67ef174d406fca8b3ebebac9f8872107ed155d43bbedfaea8_cppui381,
                0x14120aea46096abc03bb60ba301ec921f631dac868d95c2b2a863a74357b4f83ef1f5f5ccb056689abf4a3d6efb37398_cppui381),
            fq2_value_type(
                0x1184c3a34c160c7368114e39f29e949692b45527a4db659f278f3d36761d6906295dc9b7535df62d439c1cac004bb808_cppui381,
                0x197a4921a2fc88f5309e37a21931233b54606f90ecaa91fc0eb44f4431cb76615567acd63b588e8d78e76ee922a653db_cppui381),
            fq2_value_type::one()),
    };
    std::vector<G1_value_type> et_w1_compressed = {
        G1_value_type(
            0x0cc4f23befb077b70594e4727b515a99a71e37a2aba3676f06d92ad8607515b17d396a41c44fb6223d09c38b9609144a_cppui381,
            0x016d54a871a0c361b7b529277fbe4f1c60ccd683a7e2a9858605fec8cf06d485ca88c29b42ed0422a7b227e6f31e0378_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x105a1d84e85d2fbb65419dc25289eea9c6161740ffa7b1480bb9c9c55ec8a5c6e23bbea43ef9e8f1b3f4ad50de0f010a_cppui381,
            0x14c7e1997b89959300bc4d6f26ab37a08426980d2f1776d573ee3d43e44afffe4979ff4690c1e8e189b9e659cfb54302_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x03c866a31a613ccfdab2848521c14a42e232493f3f0799095c21e3f08d04b5fb2a1570df09a9005d1990bff956e2b8ec_cppui381,
            0x0b036658a0a7c475779b17f180a4335e24391f547eb4aa078c9532aeb9613acefc2b97e83356034bd6c9cc6a2f3566fb_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x043d40d8cd4633e48bbfe4aa0032517cd43696465e30269363ab61a3ae9a37be615a36ca3088e3524ad19b3cb1bb2ec8_cppui381,
            0x03595a48c66399f7a07e9753e37cb2419bf288fb247907bccd67f481f184f12d8c3528485d1dca17a7c69ecbae23dae8_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0c47c20a3997052ec6ad1b217c1adfdcf17bb25998222bfd231e69f67cdc8008042cbf1fda89a3bb36715de890c0833c_cppui381,
            0x18438fa4cd0ef23b24bfb959eacc54edae6ccd3870fe55d7fba589c628d5db98cfc0851b231477fa62ac161f0fb882b5_cppui381,
            fq_value_type::one()),
    };
    std::vector<G1_value_type> et_w2_compressed = {
        G1_value_type(
            0x1670abfc0df68a21a2c7cb3bd1c62f8a48fbfd4799d83d484c996ef3d82a3dbdf5fd0175da7abe3d2ba96f059e1881f7_cppui381,
            0x0197a0b5a87ba59fd2c0a9c4de2ce5f773960c4cb59f6d1ef0657cbba79f0f499a7f58d09897716a676edd0a8ca3008f_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x026b17c7a93778cdafc553746420a4d3689de8ec7920233bfd5d0abce2e1cfa29845ad7da2f3e36dc7934e476268284b_cppui381,
            0x0ffe95d7d5b842f8d8227f6e84a728b7a8cf7dbd933d80b2d90a17658dff5e61d2a54b54c575624b74d9b322f7fe2a01_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x13041e72558e8360e2b6adfddeddbd4f86a325245556097bcfa3fd6beb8eeeec6ae8a116545e89438b2f93f9dcf12250_cppui381,
            0x17698d73a7969cbc92b884f01d86c8034f7e764ee8f8f3476b557eb558156bd678706ff636575501a394d91f28314531_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x133030a621342bc3b57541336a5cc1e389fe746d27904be1bbb948abfd281cbe9bb90d746343e8e4481496d3202015e8_cppui381,
            0x0cc3f51d219fa568723c86c71cc6c11160d00a3b3031268a5f6eabe6672e33d147de99d69f4e7dece907f1b954134b5f_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x16f1afdc3b42de247b9278a284ef853e613bb90cf9342b8ae7a6a9cec7f7d26d669d010c69443384d41555943b04de43_cppui381,
            0x0d138e4715989d4c70c92613b10103c17ce187a5f135a7d07ffec540c6101a24c8fd36f9713c25627e8db62a2a35baa4_cppui381,
            fq_value_type::one()),
    };

    BOOST_CHECK_EQUAL(vkey_compressed.a, et_v1_compressed);
    BOOST_CHECK_EQUAL(vkey_compressed.b, et_v2_compressed);
    BOOST_CHECK_EQUAL(wkey_compressed.a, et_w1_compressed);
    BOOST_CHECK_EQUAL(wkey_compressed.b, et_w2_compressed);
}

BOOST_AUTO_TEST_CASE(bls381_polynomial_test) {
    constexpr std::size_t n = 8;
    constexpr scalar_field_value_type r_shift(
        0x70ba0c24f7ef40a196a336804288ebe616f02e36c9ff599a6ab759cd4a0a5712_cppui255);
    constexpr std::array<scalar_field_value_type, n> tr = {
        0x3540c82ee6a14e5d87232db54031a151c313b02c2e5fb8097c98a22b5b1e248a_cppui255,
        0x3cdb7300a2167608f0b4371abde5bbeb0134d0a10c684e15942b9ade19be06b2_cppui255,
        0x1932db8eab26bffd30801c82338662329a83e9cd9e69f8547efee3b971c45333_cppui255,
        0x28a5a5846b8ef1151e23d7dac18b31b6f79ad9762d93a5ab7a09ec367fa15379_cppui255,
        0x32fc439e07ce9f303a50fdcebdede1b4aa3295a7ea84e5dd746466ce09edfadd_cppui255,
        0x17a55ff8ad252c1506c91301bf374301c2ec773f996598c10ec5b8518ab97910_cppui255,
        0x1c8ea45a048d71ca0dfb90deac07c6aba0c661e44b89e40af2ddfc02ddf4a35f_cppui255,
        0x1ba576908f3a792ffba1b1f2f427514cbd2fe9caf194037a178d47b2067547cd_cppui255,
    };
    std::vector<scalar_field_value_type> et_poly_coeffs = {
        0x0000000000000000000000000000000000000000000000000000000000000001_cppui255,
        0x480d5d9990c007e523111f13a4e4061ab69d113818dec59d1273f49f52296162_cppui255,
        0x1c0abb58c4a3de0c94bbde371db6475242fc6123f3e68e3022882416866a0971_cppui255,
        0x3eefdb325408c8ed044d2d8a245821eb03313482868f0776d5db0b6b304de06f_cppui255,
        0x03441b4883df6096879ef162eddeb395ab9a80ca1a2403a61f9bc5d7b66d61a0_cppui255,
        0x6ac136f24de0910a56a8c00eeab93f4e08c4754b0af8d77d45040c23483a3601_cppui255,
        0x595796f3711a982dc195fdc294444fd4127b3bf4fb57ef1fe73ba786e2cd8b3b_cppui255,
        0x68242a724d539dcde318352368080fe13ca7e75638953bee46cebb2aae451d63_cppui255,
        0x1cd6f4493f342dfe8fba32ee030dac4c002ed16c84c9fbbcddf4a510a72d63d9_cppui255,
        0x28ed796d756ceaa877742c2229c7a2249fc6511eaa85f82d51f555c3aa60623c_cppui255,
        0x6013627cbd87199375925d96bb505c1e2c2fac69d0072927a3d62ed8214990ed_cppui255,
        0x1d3c7275c9e6e11e2a4c960edd8c7fd67843a0c59a024bf44fd5314c838e199c_cppui255,
        0x2d9e8b3eb9c9f4ffc6901f6bdc89ec2d6dae92fc0fc19260532723bc3821dd96_cppui255,
        0x584dace948f5c058c571fab6b534749a83f02cbf95c964155c2c221d586dd67f_cppui255,
        0x3c1dc72ea7a79bd9a7fd76ee22484cc48c0bd7ad5d66c2a102862ec7221a88e0_cppui255,
        0x53afeb3f2a7f9cfd5be3ecf160a0316d75be4650158ee59f1960a17ce7e0cb57_cppui255,
        0x3ec8e839758da1f92f47a8777c38cc67a9e243f0a34da25f07df0e976f99cd8c_cppui255,
        0x3943ba6edcade9f65c9f22a154f1b9ca45f1a23b058c9c0e0c6c3c0f4543f491_cppui255,
        0x15aef80fdad1d60ee81fc555b4f8c8f3cb5ad1f0ce2a40e3fba710043dacc1a7_cppui255,
        0x142197f4144a72cb8e25cf5c976b06f9ca9b1aa1c7268be77a870dd3542f6a12_cppui255,
        0x7385a85b56d429a29542d4cb9f41dcd1adf8268c5c560568ccd6b907869722b5_cppui255,
        0x16883f376358bb8b5fcbaa95c203bde08fd98efd6a00de6d286452ba5acaefb9_cppui255,
        0x24f6e1eba0f8bda6c7bba6f678825efda1de9437c37054d68e6dc26d162c616e_cppui255,
        0x18649997a5f6eaafbd0c770811456c1123e1c5fa7aa7d07da777c6548fdfb0a0_cppui255,
        0x5ed4c557c48b3cffc1f462abdf8f4d9c1f2b0019b09d4e83561961bef7be3ecb_cppui255,
        0x0d1916a0935c0f8a5e1d06404fc6a96ed931d082ed1187619ade67cf1892f41f_cppui255,
        0x15437e1083ee249424c4e9a49e7a3724d4d960d13606a76a192bb7012b5f8df6_cppui255,
        0x4f8d6caeb51340c7e7d6341dcc19f4eb7dec5e6f02cc910cd5ff8bf200c9c8e5_cppui255,
        0x70267178abd9a15e624f537d5716e68281fbf95d045cb3a9943cdc26b5bcfe44_cppui255,
        0x2fc5d00aa95d2e97f24d20d29ad4c8307d3b0a6c615429b62f93ecbaaa5fe09d_cppui255,
        0x1a4ba280ba66e01758596ff10ced5f871938cc63228445048f8d18482ef48c6d_cppui255,
        0x1ad39de6f72da86c7730db7491c6dae910b3528d6c5013bbf9adb62c215efdd2_cppui255,
        0x6932ec74d018d36c376c29c5bd0d52c3a526c0fdb34d0136dd9fc87bba6cf45d_cppui255,
        0x44eae134e384252e2ea7bc1b33283bd04edbe1417a22799b1793f2ab0a29a7fb_cppui255,
        0x0db00937710081215915ac1e7dc70b3a4b49352f9a1813aba087629874eeb341_cppui255,
        0x207e89c0c4084f21abd035037ec66165348909e8f2e03808ac3a099372cf927c_cppui255,
        0x105c4d40813de99b80d86ce5e92f8e1f3caaef348644f0f9942a514ade360be0_cppui255,
        0x31e97c20fbc80c8c05758a8530156f2566c1a3d1095df49f4e7f2d3f82e25876_cppui255,
        0x476154855d5fbbb0683806fc9e2f9a6068afd35595a8c51a332bdddae043307a_cppui255,
        0x031874d3c0a6b1324366b64039c4fabf94b0243c39e77a633b6ccd69cb0c8c95_cppui255,
        0x70cc56d291248c13b1341d1964b6837dba9cb47ad37d1c5d95b24406e5a7783c_cppui255,
        0x2ad3e32cceeddbca5a4b04f2aaf2df0726dd4e701e4d2548764a8c0a4647a407_cppui255,
        0x1e3770a820da575dd692bb5bacba9d672093c3247af5b37488fd40e590905048_cppui255,
        0x6ea451815ae5fd07d6b203c600592fbf67f7f71cdac9ad505093cc16a71b5f58_cppui255,
        0x6931fd34b6eb5e501455a274713ecbbaed12c116fbf10585edb00aad5c9225ca_cppui255,
        0x391772c1990b157a9c080afe9e5fa2688565483deb4313d9b3a2398b94a54531_cppui255,
        0x6fd11da108d634967c28d706e1d238952532e938c3a43d2f4c80427ee5e41465_cppui255,
        0x4340a1cdfc5337b60859988391a22c5b74df5fc06064b69c351b0d227f437e78_cppui255,
        0x4a8490fe693187c8cc205c7dedcdbc4708964da51775ac88b298465bf23c1bb4_cppui255,
        0x3e136d819aa9dcb7cb78c693b9feb213e51e79c23df7b3a4aaa64357c459cc09_cppui255,
        0x0096de691391f1e4896e9d17d690f5cb948965349174fc5f488285125362a2db_cppui255,
        0x643df8ad7ba980771b96936fa67a63e485def3d8f9ea4bb82d350949fb092a71_cppui255,
        0x379dc3dcf086eac6f2532596d5f9670b25f5d752d3d3990e5cd64875deb30458_cppui255,
        0x63211c52065d6c71d6d1a8c77a9000896b9588e801f911b13f97f9803ceb9bad_cppui255,
        0x37ac58c5f5826a91c8b182464a083a04aacc5177e4b88d25ca49136efcfef93f_cppui255,
        0x66ba00908a3ba13d2a04457f2094627992685524b6798128e36b633853433526_cppui255,
        0x717311b6e53630e6bebf9443d93a796518c9c8751858deb57f1282c42bc67de3_cppui255,
        0x6b755dff197f12e46d8339ff46bfdf24f805d36f46ba9d42735e8f73bb1bf95d_cppui255,
        0x096cf8eb82f7b46a4e28653634c1750dd2c15bfcbbc082622e980e9826657c8b_cppui255,
        0x486806919560cff5feb7c7824f28a13fac252cdc0e9fef3dfe52486fb73c5d3e_cppui255,
        0x63e53e13aa74972b352467b517dbe8af338d966a5d3aa694b882e2c84e44380c_cppui255,
        0x11063433cc63c9174012cc17458f183539dc4cf386dcf3226213c2179ec5619f_cppui255,
        0x690111ad5e36e656daef3951a67d6610f73bbc301bb42bd3dbd13f8c80abe930_cppui255,
        0x72d25810142fefb4dd10f7f228dde90a73fc0906c77f571471e4af5aa0bfcdb6_cppui255,
        0x0229058f25696cea3fa1f50a6da95c74e5c4386ede7de3b3f505a0e638389bc0_cppui255,
        0x262df7daa19ca683206206a485552a0e431666659494b259ff769bc6fe0fb619_cppui255,
        0x3b25332af4ace3e424f8e355a19e9d428719db4bbbd5edf2b92ac980ef6b908a_cppui255,
        0x3cc2b194b50c7b9826ce8666be7f9cd062e92f77d98d59afabe2283ea14a2698_cppui255,
        0x0696ec6bbb951f3b12895e7f8b05257b1e744c2707e472d2b9db78a79eaf1175_cppui255,
        0x47c69add0279970e4272b8792df7b97098055505bea91ed0935be1b871af8ea2_cppui255,
        0x051638844fe262b56f2c6c3accee9fd55108cbf8ecd667096b3cfc16b7dadaca_cppui255,
        0x12bd689671b16e03368447f220d3e4c5e9e13b457e48ecf410ebecad2f53ed8e_cppui255,
        0x70e67fef8f8d90648ad9cd68d0aaae2b4f6adafdcbee0c16f8566d162b2d9547_cppui255,
        0x4914c12c22604660e3725cecefa32e3b3a84c559aeaada25170faaf10ace6d32_cppui255,
        0x412fc9ba9c6e0b797d1a03f767cca6c80bae5776906d40a67197f4fde5dd2da0_cppui255,
        0x2156733411bce77b968698d04662da57ed3bc79367399b49014a4f2ea03afdfd_cppui255,
        0x425cf78d6d13261cc329ab61755bb4c211b009c483ec62fa216511611aae2464_cppui255,
        0x6a967e87cfa5d5a9c135a78d1e92edc0b4e2528ddfe88efc32c63090b819f196_cppui255,
        0x1ad2bbdfa528b202ffc3c62134ab5a53b60be156f707bae7a10c5489a7ea7e6f_cppui255,
        0x4942e35742a4915a9c891a92aaaa477f4017e7c82d6ac1d3eece75a508fb1572_cppui255,
        0x65f6ca3ebf4c6111057c03ed0cd1127a100710fcca53bf44d7247c0de176260d_cppui255,
        0x0f6d4e5dd7ace3540c4eafb4bd779c86ee12f0ba5c92fa9e3565e52c06c9a881_cppui255,
        0x5b730bfb15839de0ead3db78edcccdcc80f8481ca4203d526aea37a129bc6179_cppui255,
        0x5c412c415597256e2b9159bf612760007a6c109d287634e1690b7dd2a3cb9a40_cppui255,
        0x0534aa0edd228f305dc8ae5a322b9e09d4ff3b82b45d559d935572c106daeea1_cppui255,
        0x43042bdd06fb35f6a553002098576a1d7594ec3297d4935382cde01edbf3b2a4_cppui255,
        0x02df631cc1de108e3b21cb1e19e27e794625bbbcbebb6b1021a8f490a4d26ad3_cppui255,
        0x1404628368af0c392030080227b4f2a3cfe1aa258357428959f5eef2154455a5_cppui255,
        0x2c93e7c0cf251568c29205a7864c9851dd595e5823332c1e13a110a7bb0a57fd_cppui255,
        0x27a90e636f9d9a35b378a1e1af3973d0c39cc941ebefa9f2fa13ef6a1e2fb8a2_cppui255,
        0x1ce47dc601ee5db8e7f2913c33484ad46476a2e1a34428fd14c7a8e822c52fc7_cppui255,
        0x71c6aef4c005a4c1c5f4801f866bc0a6bd5952b7f5e4865feb4940b3177fabe4_cppui255,
        0x040d465c49ca0315130efa3046e049a687e798ce732567d6ee84727b3fa226f8_cppui255,
        0x71706d9bd063ca170cb9f8c41ec32ccaed394a1a876a8302a45484159907ec50_cppui255,
        0x44c08e331896853c9ac99e97242d8808fdfffcd18f1c2701af2270aded40330a_cppui255,
        0x4a48fd884cfa214545860746f43495ede0aa14cb3693899352f42ac3ac523315_cppui255,
        0x3874018552b8014999bde467bd8c36e792fda187de468dc586a1b81ad4800d5f_cppui255,
        0x13221842137b41f2358c2ac97d79157f0cc560f342507259075acd2c783544da_cppui255,
        0x60ba123f92573c8841afed0951bee188f137ca4f04f918222bff7a8fd6526c04_cppui255,
        0x389f821fb8cacfb59d4589c9b13a4ecf379f701df2b9469ceb934256bbb6d776_cppui255,
        0x16754b4e1c0f1233c649c4e21d780128edac4c4c2b2439cf449088dc671fc348_cppui255,
        0x15efb0852b2230ed66cd64c55233ba16f66f5c5b05a6ca71f180cad01c8ed71a_cppui255,
        0x3781f551e85953156a09b638e94f690902f1ca91014f08979d1834c0ead682a5_cppui255,
        0x011d64455f427c0bd0577131f9ef48d47bad44c152029e59bea541a7a7dc98a8_cppui255,
        0x4ecb58e8f31f80905a95f962b9bec0538d53f8664b314684dcc8d04beccde8f2_cppui255,
        0x024d233a1e662788e529a405dcc3f25fa16cf5b574109ae1f2289d5d2193feb7_cppui255,
        0x0d0503ed7e91397bc92a73e4692ca6babfec93c725b55cd69a14879f22fd6ff2_cppui255,
        0x39811338758bd4b1d2bcb9890ba2e2313cec6e9f54db2fe82f0d95e0b359840e_cppui255,
        0x2a4e01fa966e5e1c8f7823d5ec3c708f56c9306af2d0321583613df9a2888209_cppui255,
        0x3665f93bb2da394bdd953a883d4c5fe04e176ae7be88e9ecbbf591703c192e5d_cppui255,
        0x0081b49e88f0b930bfcd84492407c730ea10772b809818c83ab95c36f3aa8de9_cppui255,
        0x22339eb7e2c232be0b60f86b7bfaf1025ccdc145b11d6bfa346f1a066cac2918_cppui255,
        0x0f7e1106cf189bd87a972286b151aca5e929777269b968551f00fa0381ffd891_cppui255,
        0x59841df41488a266e2f227dcaf4da41cde578cbfaba8115859becc20b488fd69_cppui255,
        0x6c8f58a4907e2a0b56434db41d3b1e69f9b360f2039d9856c188ab4deaceabfa_cppui255,
        0x41b6ff2188b920cdd099df98164b3d61696eacaec64aeb839024c7500eb8bcaf_cppui255,
        0x59cb1fcd4cffd255f98f5c64c84ea70651b1bed981e99d72cb4c1044952e098d_cppui255,
        0x4dd9da29ce23a3e5c0349517e283e54808855eb60d8b99e223762d9fd98af51f_cppui255,
        0x652fdc9b3a08078583b7e65b9459f42685acd2e1a61830cdfac7506574f5dd06_cppui255,
        0x6ed64a74f8d017974f6fe87fca5ad3d6433462054cece7622fd4a02f8465287a_cppui255,
        0x7314d4441d6e85dbb7c11797760dfc5f004659aee51e7299c7ecace82cadb00a_cppui255,
        0x03ce7f6f76589dcc32e08c0a0642606ce9af3d4f5d7bed76aa270cd50b3e6cfa_cppui255,
        0x3d497c195db408c4eb1f1c34256a6522c20e27192125c8a07370876deb01241c_cppui255,
        0x107a83d4a1d8c489bb1271df2eb9eb0f8acdabaf583fc97c12f2adc5abbe6c04_cppui255,
        0x6fa391c27c905ea55845cac5bb5cf33d0704173e4c32092326ba7e8bb93fb092_cppui255,
        0x252b7b7d7513e0811d293a194bef93f6e19a06ba180d87015bff1f78bff20116_cppui255,
        0x0bfdd6a008dcdfc40ca9b774424f557d4634cef3a8550914ff98fee3ed22d7e1_cppui255,
        0x5d220bbc372737ee19c02511f9c5aabc872d5a167b95c22bf35005de5aeec55d_cppui255,
        0x3d02fd9bd2224c0c5a062fb2f82a288db5db9f749d9eb0ddbd9dc26b205d344e_cppui255,
        0x684eaecbc3d13fa30cc7ea0c3393724de868b8a34dac4580c9fe3dbfdb4a9eea_cppui255,
        0x43e81faa6b9c5e3ccfb5841e8ff60cda8c5a0a71399bba912d99f63343372d60_cppui255,
        0x13b1ecc701b0566bb8cbf4f186104424a2840d7910d75e10a5c3e30ab4d8abc1_cppui255,
        0x2d1c2e7c193745f6d8f5f7aa63665349b399db387e2c838d9b4306d7a385de62_cppui255,
        0x5ba7d9570ac38ef02c5873c5bd9f655632782b1966b119c6f8b47687a229ae96_cppui255,
        0x1f04a0ef594a5bdc826aee7721c288de4c9fc260b012d0b2b6addbd4814a9668_cppui255,
        0x63e5967f5900365a832334f6b52a51c0390f4925761a2dd074c7fafac149afd6_cppui255,
        0x43ca0adc50da6246f4b1ba6c821bef6873d88541a3a27808a3ebfe6c27a7bd4b_cppui255,
        0x29c75f5d0e2331d4cd60d6654eaf1c22deb629837e53e0b723fdb27f0ab6a99a_cppui255,
        0x643189efbd2fd5099df3539df621a8a60af26e404e098f66c369e207a6e22e5e_cppui255,
        0x5bd13b92659428d50ccefca53a52c697e106fcf7b4ebbbd62bbad9e79638bc13_cppui255,
        0x3b9fffa05fb179e966b7081f0f9622d2f9f077cea9b6f02373d3f424ee146189_cppui255,
        0x3c9a59e0725fc1b24b3e79c7bdd37707ed9784c83fab9f4b8b285f4fad637c24_cppui255,
        0x414377c1398bb503f0174a07e8ee6d95783e74b54bb3066df7e16b75f21dcd3a_cppui255,
        0x2dc29d17bfb8103f6d6d48dcebf383e637ef29fab8f801573a58fb18362d1b8e_cppui255,
        0x67031c1c085c8f8cfffac4e0fbbdbe7214c5dcd0a91685f3fbe6c67160e627bd_cppui255,
        0x724b962b45e2adf79b4dad3a9ed82d6df3a1e385dc031d45f854d8dbfa01943d_cppui255,
        0x271417c390b9c3e27ca918f272fe54cfbe540e300115c96eac8520a5dbaa4d69_cppui255,
        0x011690ae897e8a9face5b0a51cff976734b6cf006a81a4153882bcd51194eec1_cppui255,
        0x33dda0320753586276ccadcb5f4e35f8602718f6d8ddddc5f1db1f376616b442_cppui255,
        0x01ade8747e0ffbc898a5467cac783aa96143266853b44ab6c61cd982ee79ea43_cppui255,
        0x363b2ae933e2c5a5d0e91bb5b24d10f48260c2f053101e6f0198b7a06412ec71_cppui255,
        0x5abe59a863d75729a56a033d105228bf4cf5192eae821ae32189e065844f5a48_cppui255,
        0x570507c4c602d257a873aca3d9c023b6c133e73909aad6687099e104c36ed8e2_cppui255,
        0x4a86a84ee21029642a1595c4f1a645e99ef41c411f7c0dade14b2c4e8bc09933_cppui255,
        0x69a18746efa0393beb7702fe0e7643274f1c7da904beb60b42014d5967ca4b34_cppui255,
        0x570470137359d4b2526f2f489d278e7340b33ae8eb2d9bdb64140067e784abae_cppui255,
        0x653274fd83f5249fbe2e778835c93a23ab783c17b5bd2e85d6dc5648673a6f04_cppui255,
        0x27a2d4099898b0f9f2d1c7f2bb7f70bb1ca1f56f5eab19909400881451434a31_cppui255,
        0x00d8fa1404342a92e90006cba8c13879c90d4c575181b1453c5b790f5465a16e_cppui255,
        0x14435f925aa0f45627bc67436e1b5cf50f003df76037f87b94b4204b21985099_cppui255,
        0x6c066f3f9d9e5d5147456c07203b4283e19298347018292c57a88c1a984268e2_cppui255,
        0x5b515f3be19fb374258075bdd0f16780a3028197c7a278dac6beacaa31ef9ed9_cppui255,
        0x4c09d00fa5ed074637b7c471f9574367ab7e96006bb5dd976e6ce0fb8c510bf8_cppui255,
        0x20d127b6078a21ef7e54391932c085e7f4654df49e8f103e25892c8c20244b5f_cppui255,
        0x580475a5b814e0d82b701ad59f33719fd2653a513dfe376feb6797c9177eba7a_cppui255,
        0x63cf6d747ce233351c5d5df3dfdf5b327baba26df40f08935a22946d55841a0d_cppui255,
        0x351d8afe67168f60d78f4654096232279b729ac581817d19eceb83c5bd92b447_cppui255,
        0x35440021e1f004525bdb52188b514ed08c4f920fa53988b98029b8dcd0eb11fe_cppui255,
        0x08096cabc485ca9da3f9c356d76f274299908e574d76ac054ae85fba5681fce7_cppui255,
        0x53d7a804607db92e9c398510b590021bab8e1480c8e5397c40ca31cc8ef38888_cppui255,
        0x522f728820091af6ca285f126623378f7a2ac3933d31d2065aa855c67c024162_cppui255,
        0x5234437802afc9769d9301cf53c2804f514b6dbac5e2fe4268a62066796acd4e_cppui255,
        0x1dd3ae12d0c460f223e9dabdd4d4049c023f588cf8aef3fe5f9742416b3daea0_cppui255,
        0x33879fb8eb95c5b0e8dd3189324d24a0c09914611e693eedcfccd4cfdbc833aa_cppui255,
        0x658e4fb9c73f946ab5278a26e4a9c0502d980f74e8f0315e4b0643056c862717_cppui255,
        0x1a122193c5f5f0c9e34e5eddb380afa5962e040b546c628d7b54b62bf8faa358_cppui255,
        0x4e51e99c866e7c59ebe92a359141b7ea603c71626c5b04b468515fe943ed5e51_cppui255,
        0x604918f13a0b91ff8980b42934a14fa80c5f95c16d22379943460c62d0050059_cppui255,
        0x64b52e08d3afb19c2d66c375d41d0b50f9d43350e695f972490d4167b4dad706_cppui255,
        0x6448724b222c98f72de1a942bcb7316f6db646eb2a93a1e1ddb73dde6f7630cd_cppui255,
        0x42e9f2d7e03795995872c8e14831757493854f07fd03e28ea5e481fa2e6e5d00_cppui255,
        0x11c5580567cff78b9a3efb5400a17a1b5f22954b775154dd0a98fc5c133fdffe_cppui255,
        0x4739f93374d06c312798481a586955248e0bcb41b01c584e13de06c4f1976cf7_cppui255,
        0x581364822399de7648f346b78c65ed7e6095c5775d122221199486be6aae02a3_cppui255,
        0x3024a680a2d674f96c6841b936d429a5f20762304d2a29532d65f9743369df75_cppui255,
        0x23bd923a227adfdee0cb10ea11d598897c7c0f906b645f887d292817ee66759e_cppui255,
        0x0fe864f291829c40460bf08ef4f593be2739efe8f361fc08047a4be94ae6dd35_cppui255,
        0x630d0f774643cd197aba40e27bf94b45a7310194fc81f904db1b5eec7c35e193_cppui255,
        0x566c33ddae001788c433c1e1566446c991554c37e67c96904d647503856ce4f2_cppui255,
        0x0549ea7a86d6304311e53674d3de0d7c7a8c4e1651e69fe7dd9eb1caf5ad9857_cppui255,
        0x487304c054c8124adb27e5d3079b3dafefd6b69db2d0605fd4506d3aaa5607db_cppui255,
        0x143e742dd25ce947adda8b6d3dc26e683db77101211384cad7eedc12a047b804_cppui255,
        0x41ef40c96879a56b2190dc10f23525865660b629ccb30a4761b779e0628ab857_cppui255,
        0x134d2d53a84ad41e5cfcfe75bf49c8de1e69b615738401bc31287826763faece_cppui255,
        0x1f5120857962996f095ad78e5ddd8258b08be174a7c369744372278cf98a2676_cppui255,
        0x5ea93fbbec339f9554eefc2f87087781a2880127f3dae033264025993654dfca_cppui255,
        0x2e183d894ab20b49f0b937aaf3d65a02ba29d08c89ca69576d53282827e2560f_cppui255,
        0x142e79bfca24b129f8e24be07bdba8f646a98093699013c149b7e90a4867bd97_cppui255,
        0x61a5b1c2f741290bb64a6182d97d6c6734816eb5e909f5e44d2ead92717dc3c9_cppui255,
        0x37ff04291d41edff6b6888cf36de141d18a60a6f57b27364f84c8ef07dd35118_cppui255,
        0x6a6125e36eaf98e32ca267a90895fefc0610a874f497a4187d4bcc2f997bb873_cppui255,
        0x095ffe71832abdc79e750eed95a627095fe785b7b1dcc9bfa5d61195c4ae1cd5_cppui255,
        0x2e11cf7c849427744c1a6d940df52aa6d65614a5fe3f274d115fad8a2bb4580b_cppui255,
        0x43e72e049425ed5b337b69e074664177ac10a35c3ab042115e14343b50362001_cppui255,
        0x653ced05189526caf7f0d24927a2a1eb9605eac04d449063ebf5852b0638dcd3_cppui255,
        0x36d5a09ed0e448e0e8031c485f3eeb83352c7f8d8dbe6c32247163e681388db0_cppui255,
        0x6c192143b75fee703d22dc756a24785563263138ada8a80a9654d45cf222cd68_cppui255,
        0x61ac75bd0db91ce314df5cfc3848d892260321de1d880c129474cf7035bc5ca9_cppui255,
        0x6ab4587e850dfc102c4ffb723c49952893065c31002f2a17d92a09b6201f7043_cppui255,
        0x2280ab51bfc0c3d03a61b1ae0cd199adf8cd7d595755bff1bd56848ac9b2addb_cppui255,
        0x6db3abb4d35f2abddfbf8c5ee58be7b104c4387e723433985589b504880260ef_cppui255,
        0x213e130c3c34db9d738af21150ba76382d55bb3b110a2d67f6cbe9c63795da83_cppui255,
        0x5dadd4dc264d9463821290065a2ff738d9f936ccc17382615cd600736ef8f536_cppui255,
        0x1c96d875fe47cfa371656e119d3a9646f67f5be4bb8784b47de10a587166487f_cppui255,
        0x6257cc59864ec4e2485be286144458bc3f4458eadc536ce8c5f5bb2870651193_cppui255,
        0x3c694078e47276d26913242fbba8a6db76a7fbda52977241af03234072ddafd6_cppui255,
        0x6082df0b0ff44fe79bbffe9366113b31f95741bb4f7fa86fec3fb08d925e11f4_cppui255,
        0x68b8926a41350f57bfbf1dcc61fa61c37b438d611a53a41adbfc4be14bf35f99_cppui255,
        0x13e6befe321c5a318a0fb7ab897bfa1d78de4a8c2451a9c838b483eebcc80b09_cppui255,
        0x5553fb737e38a6e413e00f77b115943e48e69d6e4ec131ccc22ce4ed47bdb6d7_cppui255,
        0x36f00a4a2739ed9ba56ea0d136d25a1a9d449c187f94efeb4e7c2d88ae9dea2e_cppui255,
        0x1d790279938a84ddcddf1f25f89f7fef234bb90e2a209fdabccbe03fda68a3a5_cppui255,
        0x0a864c6180e057fb9b20cea35bad5aae97114adcc43ef0fa4e52df1e1cfd9265_cppui255,
        0x177eda2f8aaae07eeb47e206c8d0caececaa26ef4907d98a67ec2257b4bc6db9_cppui255,
        0x4ab7c5d7846a1d8fff53196ca2f21a5c9569ac3a5688a536a8cb0d2e4c666c28_cppui255,
        0x54be7a81a0c2d015c0442e5756773c08c66150b73fbabb3b0b00e390c7848f07_cppui255,
        0x047ee8158528b7337c5ecdeb31522005ff4130adddbabe6c741159a34760da6c_cppui255,
        0x416bc2ac134682d2160769543dc6e426c3289207864e283e67b5861e409e1207_cppui255,
        0x644386d878eddba7ab5c64208012a25632191d0072caad8f20b4a08fc366d489_cppui255,
        0x0583ade3f8f05abb91350e75bc22edb668c3c92c35991f16ea4af45c46ee02f8_cppui255,
        0x49c9c118dc19529b22bd954defcf599a61447b6c3521eda59a0bd625e55dbee4_cppui255,
        0x5d8451e2595474c20f0b172a3e44da56d0ec7c369e6c0a991ae473bcf67fb579_cppui255,
        0x65a7e8cd2471091cad4ec2877d96e60caeb4eeb7c3c1d546a91253380c0466f9_cppui255,
        0x26f90507486b52fa6931e4392a196203b4784547c4d0eb828086acf8679cdaff_cppui255,
        0x6c5a8636cc7a511afc6a28f2386d6eb68c91d4f7e7fe8d26433e3e8128c80ca8_cppui255,
        0x162695cf98ffdf0e50cef20f0df3f8eb1d061303b3d9d6a35847c57dd6b61250_cppui255,
        0x08c0eaa9d94a3dcfbb2532d5bc18235d299769bba449e0b5a7593f5c72bac89b_cppui255,
        0x639030fa3f7dad88ddcbd3d7dda3ed3645c9290362b75681e3b1f2371b67756d_cppui255,
        0x4d7bc37acaf75c2d7bbf0c267383ae88da9311bf70a0191e5c62ea75bd3dd7f7_cppui255,
        0x38cb86c550bf3221ebb2baba61a3c77e449bd1fba63deba6a9c337db2f56c7da_cppui255,
        0x3150e9d8068b2d6b9490c4375bc60c329cf3318f52c4d32cb2d5ace796a1f9b9_cppui255,
        0x54f6038946d1bbf0553ef6e328682f0f2e47ef581218db4e6bbfe85d449625f8_cppui255,
        0x4b99ad7201e92fbab4ef236df467d7c6d0a10bd01de4c6d360ed09f7605fee2b_cppui255,
        0x05a5d1a97f870fc676987bbc4962d76a58b60d414645a92e8b1ea01ba3a89333_cppui255,
        0x71f99c0a53d6b69ff00ba55d627d925a8dbfe8b565a657f0b4fb5964427cc403_cppui255,
        0x5263f0e9812d3d52f221a16f50c036fe0363416f8e74f7c27f0ea0147d0c9621_cppui255,
        0x1d8d7473a2bcd19b69501843ae4754fb77c46920b74b6256afb9d9647943339c_cppui255,
        0x52a6679a95609c26e47ee4318c5a5b2b9cbe50989142ced50b485544ddd6acce_cppui255,
        0x065d2b0719c0bcc1b02037ae08f9a5398feca58936dfbd62b8fce028b01afb7b_cppui255,
        0x520d73bbb1d0970ea53b4e6337b9e353d09c5a856b923344c6d8cedddc238bce_cppui255,
        0x595276f8984d376dc47db0485377b0f95b3234e28ae1cdae168762e83db9de64_cppui255,
        0x663ab3819c59044a9ecfda430332513579c7a5801d369969cf18cdcb241273ef_cppui255,
        0x6bcd48bd3a63cfa11c3e9d52fddcee3112c22dbc68784894a63c605442b1d34a_cppui255,
        0x383c0f2c20c304caac5fe8b0a3013e48b71e33c608420c8e7bd04a5c138a4a01_cppui255,
        0x2ca94a4785a3e19bf06a91acfcfc0b695d432984da488e863ad056bf040890b4_cppui255,
        0x0ea0f213dc3ee2d046abdaf721c410e2cea5896940461e46a96bce4f52880875_cppui255,
    };
    constexpr scalar_field_value_type kzg_challenge(
        0x73313f808ec41532e12764269b3c8cc1c6d1d01bc4732ebc4c3fba5bbd676376_cppui255);
    constexpr scalar_field_value_type et_eval_val(
        0x256def9d29cdb492f33f938c24ef442857ae93f0bced9e6db5a38de07a948d76_cppui255);

    std::vector<scalar_field_value_type> poly_coeffs =
        polynomial_coefficients_from_transcript<scalar_field_type>(tr.begin(), tr.end(), r_shift);
    scalar_field_value_type eval_val = polynomial_evaluation_product_form_from_transcript<scalar_field_type>(
        tr.begin(), tr.end(), kzg_challenge, r_shift);

    BOOST_CHECK_EQUAL(poly_coeffs, et_poly_coeffs);
    BOOST_CHECK_EQUAL(eval_val, et_eval_val);
}

BOOST_AUTO_TEST_CASE(bls381_prove_commitment_test) {
    constexpr std::size_t n = 8;
    constexpr scalar_field_value_type alpha(
        0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255);
    constexpr scalar_field_value_type beta(0x43131d0617d95a6fbd46c1f9055f60e8028acaae2e6e7e500a471ed47553ecfe_cppui255);
    constexpr scalar_field_value_type kzg_challenge(
        0x1932db8eab26bffd30801c82338662329a83e9cd9e69f8547efee3b971c45333_cppui255);
    std::vector<scalar_field_value_type> tr = {{
        0x70ba0c24f7ef40a196a336804288ebe616f02e36c9ff599a6ab759cd4a0a5712_cppui255,
        0x3540c82ee6a14e5d87232db54031a151c313b02c2e5fb8097c98a22b5b1e248a_cppui255,
        0x3cdb7300a2167608f0b4371abde5bbeb0134d0a10c684e15942b9ade19be06b2_cppui255,
    }};
    kzg_opening<g2_type> et_comm_v(
        G2_value_type(
            fq2_value_type(
                0x130cc68002eab5dd042ad6b44cf05764665429255d243e99ac93df93232efe3ab0690aa049ce7d55975d4468d034cd57_cppui381,
                0x0e9117cdcbca8bdd72d5f002edc2174db28e1db8822faedc36adc87f99a6518871f10c2c05959a112e6bec0108b4d623_cppui381),
            fq2_value_type(
                0x151b4757ffa7a260ca5cd8d3c7dcb380ce0e31cc9a96f7b4e3c0717cd0af0cf62e166d9128fb8a90d3b0afe2e9c77b03_cppui381,
                0x10f62ada6dfa4d1c8fbf7c7f2bafde9f3b9e8896c6432c16707b7ad6da5b5c1797458a154a7268856b5dbdbc9fb4901e_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x12ca1b47637293a935da075572b2fd740a2fbcaa58e2161f61f4fef1982c9f6928d8e3a13a4fe62cf414a34156349502_cppui381,
                0x0384651dd21b50548d96d43ec2ac462c489e3301b20a093ecac9ba24cfd275a2af09c9e699314da975babbf723b4fd7a_cppui381),
            fq2_value_type(
                0x01e201cbc84319db30d383db7411df22609ecf4413dac869ad824024bd46f08a715f2d7eaa79419c869947bcc31b2d38_cppui381,
                0x17dd995635f7e23869a028a2aac730c38edb03b6f30f2db044ac27a4a81963a03c4f2cbc2e9c831403d86a97301f10d3_cppui381),
            fq2_value_type::one()));

    kzg_opening<g1_type> et_comm_w(
        G1_value_type(
            0x085ea66c01bf2544d5cca506b0f230fe3682d7c7f44ba74d70cfc4b0513f7ee658f7e7bad6cb445399e6eb1677a3f6a3_cppui381,
            0x0f7205d63934b7ac8a8416c0e6f1380cf8ef3fe9d74c5b81a4b9c4cdeee3bc10a3a904534ffc542d0c5ba20b3a2f3895_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x003a5a97983e1323251cdb342bd5fe25e9aec95a6beb85e5b608a8859c4b4465e45aca1118bc1c6982732e93ef4a139b_cppui381,
            0x17886e66a7a0b695a242af2a6ee5e872bdc5fcb7f49e2176fb26888464a5cbd6a35d6180a3db4d308fbe2e65c19e2480_cppui381,
            fq_value_type::one()));

    // setup_fake_srs
    r1cs_gg_ppzksnark_aggregate_srs<curve_type> srs(n, alpha, beta);
    auto [pk, vk] = srs.specialize(n);

    kzg_opening<g2_type> comm_v = prove_commitment_v<curve_type>(pk.h_alpha_powers.begin(),
                                                                 pk.h_alpha_powers.end(),
                                                                 pk.h_beta_powers.begin(),
                                                                 pk.h_beta_powers.end(),
                                                                 tr.begin(),
                                                                 tr.end(),
                                                                 kzg_challenge);
    BOOST_CHECK_EQUAL(et_comm_v, comm_v);

    constexpr scalar_field_value_type r_shift(
        0x28a5a5846b8ef1151e23d7dac18b31b6f79ad9762d93a5ab7a09ec367fa15379_cppui255);
    kzg_opening<g1_type> comm_w = prove_commitment_w<curve_type>(pk.g_alpha_powers.begin(),
                                                                 pk.g_alpha_powers.end(),
                                                                 pk.g_beta_powers.begin(),
                                                                 pk.g_beta_powers.end(),
                                                                 tr.begin(),
                                                                 tr.end(),
                                                                 r_shift,
                                                                 kzg_challenge);
    BOOST_CHECK_EQUAL(et_comm_w, comm_w);
}

BOOST_AUTO_TEST_CASE(bls381_transcript_test) {
    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    /// Serialization/deserialization tests

    scalar_field_value_type a(0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255);
    std::vector<std::uint8_t> et_a_ser = {
        93, 227, 44,  5,   215, 179, 179, 161, 188, 47,  202, 226, 198, 224, 235, 229,
        51, 172, 126, 121, 244, 132, 95,  94,  122, 217, 155, 123, 243, 93,  170, 87,
    };
    std::vector<std::uint8_t> a_ser(nil::marshalling::bincode::curve<curve_type>::fr_octets_num);
    nil::marshalling::bincode::curve<curve_type>::field_element_to_bytes<scalar_field_type>(a, a_ser.begin(),
                                                                                            a_ser.end());
    BOOST_CHECK_EQUAL(et_a_ser, a_ser);
    scalar_field_value_type a_deser =
        nil::marshalling::bincode::curve<curve_type>::field_element_from_bytes<scalar_field_type>(a_ser.begin(),
                                                                                                  a_ser.end())
            .second;
    BOOST_CHECK_EQUAL(a_deser, a);

    G1_value_type b(
        0x12b8f3abf50782b18f37410b10cf408e88b7749a40e344f562f7cc171612daa1981b9beae698180202993bcdeb42af53_cppui381,
        0x15800fa0ba4aefb8af1a7ca4af19511799fb01492444a070d485c7a3fe9b22bcfabb6bc2007f76a3adc6560ecf990a47_cppui381,
        fq_value_type::one());
    std::vector<std::uint8_t> et_b_ser = {
        178, 184, 243, 171, 245, 7,   130, 177, 143, 55,  65,  11,  16,  207, 64,  142,
        136, 183, 116, 154, 64,  227, 68,  245, 98,  247, 204, 23,  22,  18,  218, 161,
        152, 27,  155, 234, 230, 152, 24,  2,   2,   153, 59,  205, 235, 66,  175, 83,
    };
    std::vector<std::uint8_t> b_ser(nil::marshalling::bincode::curve<curve_type>::g1_octets_num);
    nil::marshalling::bincode::curve<curve_type>::point_to_bytes<g1_type>(b, b_ser.begin(), b_ser.end());
    BOOST_CHECK_EQUAL(et_b_ser, b_ser);
    G1_value_type b_deser =
        nil::marshalling::bincode::curve<curve_type>::g1_point_from_bytes(b_ser.begin(), b_ser.end());
    BOOST_CHECK_EQUAL(b_deser, b);

    G2_value_type c(
        fq2_value_type(
            0x0c23b14b42d3825f16b9e9b2c3a92fe3a82ac2cf8a5635a9d60188b43ef1408627230c5b6e3958d073ebe7c239ea391e_cppui381,
            0x0c45a0c4d7bda23c7e09ac5d43a9d2ea1898c36e7cb164a5cfcb91cb17c9e8d3d6ba5d177f9ab83a6d1ae554fab749f0_cppui381),
        fq2_value_type(
            0x03a257633aa8a4f3d03541ecda1ed72f30af7660891d39c9c24da7560d22fbc145c6817d3c2833e54454e664cf528c36_cppui381,
            0x01856f2127eaf9be53b902ff71a6a9b4dfb597f085fb3a2a35980683e82f1e2169beee9943a0ecbca676b4bc9370282e_cppui381),
        fq2_value_type::one());
    std::vector<std::uint8_t> et_c_ser = {
        140, 69,  160, 196, 215, 189, 162, 60,  126, 9,   172, 93,  67,  169, 210, 234, 24,  152, 195, 110,
        124, 177, 100, 165, 207, 203, 145, 203, 23,  201, 232, 211, 214, 186, 93,  23,  127, 154, 184, 58,
        109, 26,  229, 84,  250, 183, 73,  240, 12,  35,  177, 75,  66,  211, 130, 95,  22,  185, 233, 178,
        195, 169, 47,  227, 168, 42,  194, 207, 138, 86,  53,  169, 214, 1,   136, 180, 62,  241, 64,  134,
        39,  35,  12,  91,  110, 57,  88,  208, 115, 235, 231, 194, 57,  234, 57,  30,
    };
    std::vector<std::uint8_t> c_ser(nil::marshalling::bincode::curve<curve_type>::g2_octets_num);
    nil::marshalling::bincode::curve<curve_type>::point_to_bytes<g2_type>(c, c_ser.begin(), c_ser.end());
    BOOST_CHECK_EQUAL(et_c_ser, c_ser);
    G2_value_type c_deser =
        nil::marshalling::bincode::curve<curve_type>::g2_point_from_bytes(c_ser.begin(), c_ser.end());
    BOOST_CHECK_EQUAL(c_deser, c);

    fq12_value_type d(
        fq6_value_type(
            fq2_value_type(
                0x005db8a7f4d34ee8386fbdd094280f8cab08317945342ae713c2304055ad78397ca6e8174af0752c3757efe813f06a3b_cppui381,
                0x0c3c7febcc53d75eca6b47c27efbcfa8a2f394bcc5087c1308aa768415ad37fa6d7b2778482ec5d10425b2434974f0fa_cppui381),
            fq2_value_type(
                0x0f681a396bb919c9bd0582afcc6d75fe578df8968266082c18129d8ebc769a5b816efb78fdf962d7719a89bc804ea9b4_cppui381,
                0x041e0cc3da511cde05956a4a90ef1d74732ff001d6694d75a35d4546bd9e4f26b8427da499000e0c2bb282713ff23eea_cppui381),
            fq2_value_type(
                0x027423d44d437b22cebc4b79153c0a6f077507c0fdc5aa30a61249faa72ddce8e956a9e489d69a79bee9e16a79ab2022_cppui381,
                0x0958c21e079b0140de7ca150e1d021f065d2f277d78c138048d47f72b4ea0e943ae07bafbd890270cf152facd09aeb8a_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x0d96831921809f76a8fb439c4e2ca0266fda8500b2cf4eb31d2281fd352dd9d8fe911fb81a1da00bf52d6e81abfd231a_cppui381,
                0x001cc9dca3d826bce7af86210eda9b0f0df5fc7e951c7904f0eccfc3c07ed4efdb793552757212172a2302e4314155a3_cppui381),
            fq2_value_type(
                0x0624b2b4826178f5eba880e953e8343d1afefe52b47f5c98187fd5361d2a3714bf2b62bf148ae91ab6e24ff4e579976f_cppui381,
                0x00ecad906407071532cf7730a6d3f46515d1a70ca123890fcc313d75100fc835bfe1f7c02c026eeda7221cb2a406ffde_cppui381),
            fq2_value_type(
                0x02d254206dd3c9cbc9c5a99a9b21f4776a7c1bc4745b59b71efa508566f2d97e2da95f19cfaaf702e6efe214f6abe45e_cppui381,
                0x1175ac9f5fd87dc2adecabf2ad3fc65bfe2e4054383e07e201d40dbf4bef2df006a4f8588f93bd872f66ad48982a9fb1_cppui381)));
    std::vector<std::uint8_t> et_d_ser = {
        59,  106, 240, 19,  232, 239, 87,  55,  44,  117, 240, 74,  23,  232, 166, 124, 57,  120, 173, 85,  64,  48,
        194, 19,  231, 42,  52,  69,  121, 49,  8,   171, 140, 15,  40,  148, 208, 189, 111, 56,  232, 78,  211, 244,
        167, 184, 93,  0,   250, 240, 116, 73,  67,  178, 37,  4,   209, 197, 46,  72,  120, 39,  123, 109, 250, 55,
        173, 21,  132, 118, 170, 8,   19,  124, 8,   197, 188, 148, 243, 162, 168, 207, 251, 126, 194, 71,  107, 202,
        94,  215, 83,  204, 235, 127, 60,  12,  180, 169, 78,  128, 188, 137, 154, 113, 215, 98,  249, 253, 120, 251,
        110, 129, 91,  154, 118, 188, 142, 157, 18,  24,  44,  8,   102, 130, 150, 248, 141, 87,  254, 117, 109, 204,
        175, 130, 5,   189, 201, 25,  185, 107, 57,  26,  104, 15,  234, 62,  242, 63,  113, 130, 178, 43,  12,  14,
        0,   153, 164, 125, 66,  184, 38,  79,  158, 189, 70,  69,  93,  163, 117, 77,  105, 214, 1,   240, 47,  115,
        116, 29,  239, 144, 74,  106, 149, 5,   222, 28,  81,  218, 195, 12,  30,  4,   34,  32,  171, 121, 106, 225,
        233, 190, 121, 154, 214, 137, 228, 169, 86,  233, 232, 220, 45,  167, 250, 73,  18,  166, 48,  170, 197, 253,
        192, 7,   117, 7,   111, 10,  60,  21,  121, 75,  188, 206, 34,  123, 67,  77,  212, 35,  116, 2,   138, 235,
        154, 208, 172, 47,  21,  207, 112, 2,   137, 189, 175, 123, 224, 58,  148, 14,  234, 180, 114, 127, 212, 72,
        128, 19,  140, 215, 119, 242, 210, 101, 240, 33,  208, 225, 80,  161, 124, 222, 64,  1,   155, 7,   30,  194,
        88,  9,   26,  35,  253, 171, 129, 110, 45,  245, 11,  160, 29,  26,  184, 31,  145, 254, 216, 217, 45,  53,
        253, 129, 34,  29,  179, 78,  207, 178, 0,   133, 218, 111, 38,  160, 44,  78,  156, 67,  251, 168, 118, 159,
        128, 33,  25,  131, 150, 13,  163, 85,  65,  49,  228, 2,   35,  42,  23,  18,  114, 117, 82,  53,  121, 219,
        239, 212, 126, 192, 195, 207, 236, 240, 4,   121, 28,  149, 126, 252, 245, 13,  15,  155, 218, 14,  33,  134,
        175, 231, 188, 38,  216, 163, 220, 201, 28,  0,   111, 151, 121, 229, 244, 79,  226, 182, 26,  233, 138, 20,
        191, 98,  43,  191, 20,  55,  42,  29,  54,  213, 127, 24,  152, 92,  127, 180, 82,  254, 254, 26,  61,  52,
        232, 83,  233, 128, 168, 235, 245, 120, 97,  130, 180, 178, 36,  6,   222, 255, 6,   164, 178, 28,  34,  167,
        237, 110, 2,   44,  192, 247, 225, 191, 53,  200, 15,  16,  117, 61,  49,  204, 15,  137, 35,  161, 12,  167,
        209, 21,  101, 244, 211, 166, 48,  119, 207, 50,  21,  7,   7,   100, 144, 173, 236, 0,   94,  228, 171, 246,
        20,  226, 239, 230, 2,   247, 170, 207, 25,  95,  169, 45,  126, 217, 242, 102, 133, 80,  250, 30,  183, 89,
        91,  116, 196, 27,  124, 106, 119, 244, 33,  155, 154, 169, 197, 201, 203, 201, 211, 109, 32,  84,  210, 2,
        177, 159, 42,  152, 72,  173, 102, 47,  135, 189, 147, 143, 88,  248, 164, 6,   240, 45,  239, 75,  191, 13,
        212, 1,   226, 7,   62,  56,  84,  64,  46,  254, 91,  198, 63,  173, 242, 171, 236, 173, 194, 125, 216, 95,
        159, 172, 117, 17,
    };
    std::vector<std::uint8_t> d_ser(nil::marshalling::bincode::curve<curve_type>::gt_octets_num);
    nil::marshalling::bincode::curve<curve_type>::field_element_to_bytes<fq12_type>(d, d_ser.begin(), d_ser.end());
    BOOST_CHECK_EQUAL(et_d_ser, d_ser);
    fq12_value_type d_deser =
        nil::marshalling::bincode::curve<curve_type>::field_element_from_bytes<fq12_type>(d_ser.begin(), d_ser.end())
            .second;
    BOOST_CHECK_EQUAL(d_deser, d);

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    /// Transcript tests

    scalar_field_value_type et_res = 0x1bff9ec90c94f40fd9360a56a02db6a06be9c09b642d6049eb983bc21fa81fec_cppui255;
    std::string application_tag_str = "snarkpack";
    std::vector<std::uint8_t> application_tag(application_tag_str.begin(), application_tag_str.end());
    std::string domain_separator_str = "random-r";
    std::vector<std::uint8_t> domain_separator(domain_separator_str.begin(), domain_separator_str.end());

    transcript<> tr(application_tag.begin(), application_tag.end());
    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());
    tr.write<scalar_field_type>(a);
    tr.write<g1_type>(b);
    tr.write<g2_type>(c);
    tr.write<gt_type>(d);
    BOOST_CHECK_EQUAL(et_res, tr.read_challenge());
}

BOOST_AUTO_TEST_CASE(bls381_gipa_tipp_mipp_test) {
    constexpr std::size_t n = 8;
    constexpr scalar_field_value_type u(0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255);
    constexpr scalar_field_value_type v(0x43131d0617d95a6fbd46c1f9055f60e8028acaae2e6e7e500a471ed47553ecfe_cppui255);

    auto w1 = structured_generators_scalar_power<g1_type>(n, u);
    auto w2 = structured_generators_scalar_power<g1_type>(n, v);
    r1cs_gg_ppzksnark_ipp2_wkey<curve_type> wkey {w1, w2};

    auto v1 = structured_generators_scalar_power<g2_type>(n, u);
    auto v2 = structured_generators_scalar_power<g2_type>(n, v);
    r1cs_gg_ppzksnark_ipp2_vkey<curve_type> vkey {v1, v2};

    constexpr scalar_field_value_type foo_in_tr(
        0x70ba0c24f7ef40a196a336804288ebe616f02e36c9ff599a6ab759cd4a0a5712_cppui255);

    std::string application_tag_str = "snarkpack";
    std::vector<std::uint8_t> application_tag(application_tag_str.begin(), application_tag_str.end());
    std::string domain_separator_str = "random-r";
    std::vector<std::uint8_t> domain_separator(domain_separator_str.begin(), domain_separator_str.end());

    transcript<> tr(application_tag.begin(), application_tag.end());
    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());
    tr.write<scalar_field_type>(foo_in_tr);

    constexpr std::array<G1_value_type, n> a = {
        G1_value_type(
            0x19382d09ee3fbfb35c5a7784acd3a8b7e26e3c4d2ca1e3b9b954a19961ddf5a04bc3ee1e964b3df3995290247c348ec7_cppui381,
            0x0e1429c57d0b11abeed302fe450ee728b9944a731765408533ea89b81f868ea1086c9d7e62909640641d7c916b19ad33_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0d76e41234948369334b432362d0704bd88599200d80645a69ed47acf10464822776a5ba8efaad891d98bf9b104f9d24_cppui381,
            0x08a8c2ae10d589f38a9d983feba2241cbf0d292d44bc082e8fc9ff872f8eb280f6c6cfd1c34928fa81274781a4f4770e_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x02e080ea7883f56025b965fe7fa27315af7bf0f532fb031075467cc78dbce6319645e23e8febb6660cc864ba9e985afd_cppui381,
            0x0f25c2c8aaceff02da0d5b85030767c64b3ed2ffd3e3f69e9aee42025c737e95fce00d5269eb151c4d22a5f77ef8c815_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0d3541b03376d07cbb7f9f48b3a1cc43cf48160152c20c00c7bad75986839b0f9ef7cc71f1ffb4d254d9ec15ce6bf336_cppui381,
            0x01e48935c827f8ec79129124e8baf1deccf99d8ca0324fae41e037f4854ff4f389a4df3bc9ab2549b6ef949e4acdedb7_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x100462d4d96fcf47dd6f6dd3957f8c2d15cc72fe0f2ab0540813e73a16c74b4bb932722e96a33e2a26ca1ab9bc879e49_cppui381,
            0x0b2d223ea7a3275108aa52b3e4eaba948dc93cb6ae29c3c472a022eab55356e51755a6486e7fa94f3b8b4a06b3ea735c_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x1320c3ca0de8f268ff78f461e5b342960432064eec51743c386fe93f2f1ff8d4592d04605092b7302c217a72e6137632_cppui381,
            0x1613b77929282de9c0a3baf3285394260a50660b2f5168c6924973b44f35dc1a236796b3251c5a748039b78d0b377576_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x16bfa39559ac6ddfd3c63ef03bfd11ae6de4d08e66f82dc4ec4e2ca4318c266a705134204f2aaf99b91f95610d356bdb_cppui381,
            0x0c2dccca4ef18b3cf50f18ff13de4443eb6f5e6160ae985568fc5557232c892599e27285254360f797e4b59da1c19406_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x09f4ebbbaaaf5d2ea52abcb591412f6851539e1919d34de4f00900e60591438a6668d48070b5fb22c3b59a3cdae45799_cppui381,
            0x0aad9a2d04fbced844ab0811af6deefb18e9d67660073ec96954f2f0edf3a884a4ddcef6d8b7889a9bfbf7e2f151b1b5_cppui381,
            fq_value_type::one()),
    };
    constexpr std::array<G2_value_type, n> b = {
        G2_value_type(
            fq2_value_type(
                0x0badfb692a2a7ca4970d2733fc2565afa8e09428453ef5cc916a6d5ab43b8be8b9ef920af378f1823f426bafd1d096c9_cppui381,
                0x0d523776965ea36bab19da0387d38305d628d63fb7da6736f4620b7fce92539fcbaafe7dabd96e98693d9973ecf0544a_cppui381),
            fq2_value_type(
                0x020203c10b37edef960e6921c624ee57a3c2b256385b3c68f8fd611f1deba8ab91cea15d77452639429c74086a322eb7_cppui381,
                0x1498dcc1d84eb92d7e41ee99596e1825901ea430fcb0ff64d346e19375981ba8579d6ebf325c8809f1aee58542bd6c98_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x1634b13dec932a66d5b3ea6406bacd702e020970d533c29a3d6fd80a4ce1e8138744eb41b0f1e66e956fbace9af6a151_cppui381,
                0x0a4edb2465192b1b32c84bd6791aa9795b8533df963b1626c8ee548bb5f7430a563d0e662b3053cc12cd256f9e8471a4_cppui381),
            fq2_value_type(
                0x049004fe74f14513aa607d429e78203f86e08100dc70243fef9fe73cf9f04f9c3793b3fbc1d4833f9db371ee94e60bc2_cppui381,
                0x0f2277dafecdf791e560c89086d7abc21e5f0314fabd492a0926e588acf7a34d30c0713ee2cb03054f44a7dae8288694_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0147be5fd09e02e8d64eec3e6737b40d4099ccfdd88651c692c7d4407a2822c35756ba40ca412f61e201b5cb649391a6_cppui381,
                0x165fd26d77e79da63ffbfaa5771426f4fc6c925a92bd593d1075e84ae1db5e9cb0a7dffaea46dd46a44f6cf904cb873a_cppui381),
            fq2_value_type(
                0x1507d32ecb1783a069322547839ffeadd5bc4e04562dc36914686df787f6f82d5a84f32786996fd56ab2ed75e25264cb_cppui381,
                0x0302e3dd0ef0b642fc55af194e4906d57bcbcfa1a3822f078fd7fa1ea0d665ef6f60531068bd7a6834b92618db91ea23_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x04c0d40f727b43aa40d5a66de08182abf5c15f6d3726a9f43085c7a9c8b535ab17bafbc6d90a6677905271c845768ff2_cppui381,
                0x10e288228d368ee8fbfe240e2a0ac3214bc232334d901feb02f41fbb459c11ae6fb381a4022232b66f8a98ec5ed2425e_cppui381),
            fq2_value_type(
                0x0285029f076803949ea0d635d716ddff562a8ba9a652e43da0e1df737978432082cce2435e857a2b78c886fa7a6dce84_cppui381,
                0x0a52fcec1a0fc4ec51022181a0e1e44aee18f8d2cda18c8ce5acc789838b03205919870c83b4ec54cc523d89a40ef62f_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x113b921ff6a06df8c8ee87288df68472b00f7f8dc243c12731f1177ecb8780fbd3765069e0fd5a8c1c7a67649b00d2a0_cppui381,
                0x12d96c166c7292b72c7bb9e0e9e91ffdf7ca3926f67ce4894f0b7ae0d826d397c7fb8bba8e2e29abcb8aa9e7de01c42b_cppui381),
            fq2_value_type(
                0x0b9231a10b1066269677672e76235e7864d7bc0bc99d9de649c1ecca732e887c6c5975c486b44fae713541d130497bf6_cppui381,
                0x011a97bd656717d31c74a17fec650e2a04894d04631792f14183ccacee8db3ddd731f4ced99488a133f66d12a66d2eaa_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x159a7f20fc1f1fe0f794fa735c6ee28b2837aa5d70d70d1f53f1d7cbae31ca04782e9261818ae6bda542076fb61c8bb1_cppui381,
                0x03d48c028b98f10345bd40a59c2bf27229947241472986bbff174ea87d1a1d4721e2a03ccd0af2fad6d014fbc93f55d9_cppui381),
            fq2_value_type(
                0x0c5b2aa2ac824a6a3df42b895d61832e71202b8fa896eb7bd52e4f1360c696385db9fb84783aaea4e8ad86f80e2703a9_cppui381,
                0x07fc3cf1d974627a821f223dac339045ede041850e3b6b542dc66b0d3bfd3a582c68c65ace31bb3986c70b4f59754e62_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0f228b023d7881ed41446c45cbc1fd05aecb0708291131bb189a6d826921780e1c28864cb0d84f68d4d1933d5bb57c15_cppui381,
                0x14292b6aaa6b19596e452bef413171d6fbf68e1d7642dc0e815c8dda280c32d63279dcb9bd16effa5789722dd403c188_cppui381),
            fq2_value_type(
                0x05e1e5b8555c4d238726565fbca0b37042fd10cf5b7f6e0396d71f5660db2aeaa053b0be570f33c1349503829695eb98_cppui381,
                0x0896a44ec87960d640a89fde02f969a079c781ecf6c29f8c3115f6792cdd20eb5046ae8aaedab29b0b6d12728b9863a9_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x108b91795a87e98f1fee29fa53b60f7bd6f397f6e716654e508303a0f5cf9adf44cda4c8698319da3b7f2f417823e127_cppui381,
                0x1389b59456bc26b56b1ec04cd3deb42033519f78255e3569231d551c121bee2b42151c2ef3513c48851519133c7b24be_cppui381),
            fq2_value_type(
                0x13d4e1d3f953e836bdf9602d2fbb7496b8a922638cbca415d171de4a7df0a9ce630c9d14e3804a662ee558d415308993_cppui381,
                0x0b154e4f42109dd3a7857f02cd95c480d205ba5427fd49389051f7fa927ea6e2b6c4373c145349e8cbd9ca1098fba447_cppui381),
            fq2_value_type::one()),
    };
    constexpr std::array<G1_value_type, n> c = {
        G1_value_type(
            0x0ae765904fababf7bd5d5edab78752b69917962c150f3b0311446579a083a667412ea18f009817a6051cf852e09e9c40_cppui381,
            0x127fb89d20a2b31725091c033f14986b33878ef4853806987412126bd8135731c09d5222fddf44441eb4e04cee8b9469_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x140e91d114a6dbb835d2ae1ab50729b0553e3e988ca0451b29ac1458caf71b1f1c47ef2255814b4a3ccfb924f57cbe33_cppui381,
            0x0ac830f2ed3435b2b9b3900d0bc0d74407467abdde9f72e922859ae1d2cb094299a7ad467680e7eff331e8a6f92df194_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x186aabfcbe235db4a2dcbacbdd571d0b2e857ada26ee83f0a4121c1bed70ee6609bc0f24b3ffc6ea8af50b1b4de25af5_cppui381,
            0x053ea1258a76b5dc15460676bd2380558bd26cbd98266cb04bbe3d18656f68b8ea11c6db24fdffc28470fa8778e08882_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0642350f1aae9598397a7da3190e07b7b896696682c37641cbbede18f05495bcc822cc8bf34b87709372f3b8cb895a38_cppui381,
            0x140f5cb0dc31c1db82e845f53882f8a7a0679380acb7262411d8f9b7877586192f1d306f5eba7b42fe937c3885542c1e_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x04eecaeb1aab1d88696f17a3fb205e7d0bf517c16ccce694f196cf456b45a3983fe40aebbd2c0a5da701c63933d0c388_cppui381,
            0x18dd9108754b69d09b2ad191b8c4f431431030619765f109a0ab1fc9a64e71d483ad96c95a777a0e73aa72703b97f59f_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x16dd473a6acb01617eb7b690657196e837013062c9a20d0afb16f8604882182b65ab55e112265e510b4a0a95ca2fe1e1_cppui381,
            0x1937d9afd12b5a1334475224f967fae496c1b7ad9277845cfe9acb789d9d207d7bd3c2464b337669c9ffb3d5f643a163_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x19bd07f7ce52c9efe33aa9e93c98c9bc2ddaa4c762c52f988064438ed82dff92c49b5799124116af8ea46d9dab5cd5f6_cppui381,
            0x08f805c413e0a8087b32052148a63dda612c34a988e42e8cd12b3fb3d72942201571bf46298c6dc697c1e51be539295a_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x00352edd966153a5fd28fe8ac333ddc95a4dd00a6ef16f7b59095e705c3bd5d6e8805071f3c8ab2a66f70e7a703233bc_cppui381,
            0x0499e107ae36ceb8da7e1da2b83a8217b428976311420b4281bd428bc18b0db518e125d8a21e92efe1d68bc766ac4ffe_cppui381,
            fq_value_type::one()),
    };
    constexpr std::array<scalar_field_value_type, n> r = {
        0x05beb4119e1356ef39f98c7a7115452a3c4c1e2a48975c85d875aae91185fa25_cppui255,
        0x256d4004ff9591bbaeaaf85cac883eed808de37eff2b45c6d05e6670b3cd1fdc_cppui255,
        0x3973e132b07e7b2244f1172a11387054f7c9593b3b258475db005459a0e4bcff_cppui255,
        0x669073a3f8b48ee66412051fc614f73fa8e4e967a81e82562d23bfe430d1e2b4_cppui255,
        0x2d571b235843a47ecc75978a95b3cceb9fb28a6a2919e0304eb79201c4ef0352_cppui255,
        0x622551c093e4773c3e1ffb69e99fcd4a31a1f727369f47b1df49b03b9534a8ad_cppui255,
        0x0b8cb847f81048e85f5843218c1e273b56ce2608d7d9947cd1527a1fca0001f8_cppui255,
        0x3dd77c298708150d79e47bc4afccf78a6e2f32a17bbbcab1ea41e05551c0e96e_cppui255,
    };

    auto [g_proof, challenges, challenges_inv] = gipa_tipp_mipp<curve_type>(
        tr, a.begin(), a.end(), b.begin(), b.end(), c.begin(), c.end(), vkey, wkey, r.begin(), r.end());

    std::vector<scalar_field_value_type> ch = {
        0x2883b568a12a6dc1561fee01f0090f3ff06a0f7c27f7a40185ac41385a200ded_cppui255,
        0x112b150c55bab0273d64d934d71183dbb256751e8b80d2b0ea87088fcac8e851_cppui255,
        0x055e703e64b31bf0b3bebd815951fe581d97779a3b98620ba1794cd9bc58fbd5_cppui255,
    };
    std::vector<scalar_field_value_type> ch_inv = {
        0x43eecdd051ab2519427d7d76b6f873497e3cdfe31c76d5667e08927b96044bfd_cppui255,
        0x0f9da473894f2bc1c166db82fe51c5d092a281205607879752b816113738d899_cppui255,
        0x662891b8617ed1084a8364b6f5079bfa73f61b837d13a795a411dfb2949aea62_cppui255,
    };
    std::size_t gp_n = 8;
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>,
                          r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>>
        gp_comms_ab = {
            std::make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x1701ba7f0509b7e218885999ff8e0d8fd20879249faf6c907327a354db0620de84726c2ae65f7f7346be4c7b9b2c4367_cppui381,
                                0x03fe09ebb7904bfa095554bdfe698518fb1064b0dc9f122531b9a7182e2ccdb8642b42cd4843eb25a79ed4ff5f71075a_cppui381),
                            fq2_value_type(
                                0x09cb83834ac84dd6b6847b473e767ee9894a1245766a744b6c214bb02531cfb94d13343c9aac3860f3eac1a2de7af470_cppui381,
                                0x095dc64073093a6bf7f9e9dded5df10a42b01711dc9f1dba1b1e0ec84f4472e7d2d2d8519e631705b1f9bbb97be68432_cppui381),
                            fq2_value_type(
                                0x0b510e0d90b29d683baa1822f05ecee708864a37d4ea68a4c4816a81b2cd245ec1545d014f62ed13a03023e52edd1dda_cppui381,
                                0x1689673fc750776551be668c09990aaef7e6b6947f1b0e3f73b38a40beda59108dc9e8ea6fbd5585db728f562795ce06_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x0e99ecab8f6548d90cfe9ae76dddcd4e4c10ad72958b452d553c4dc78ffee512c71fff93f8b085293fe3c02c7b96a6cb_cppui381,
                                0x0cbe80765592e2d2a972471d965dbab09c386796cf2a719446e3bd1f3d7d6524c787e1bb7c20b75351220fc2cc121706_cppui381),
                            fq2_value_type(
                                0x194753dfd2e92783ef2aea297b1c264d59dd9a944bb99fe45ac8b5554b0841470f06f3bc007a8a3414bb9e3334e674d0_cppui381,
                                0x0764b08c7bfbd9e71c5422ccbdebcc3f1cc5beb57f67adf295948fd983f73d9930b688af6a489c36cf9d9288f8d22c49_cppui381),
                            fq2_value_type(
                                0x119cc4751db354af4c481685629eb95d805c55ae53a662fdbd00fe2ff7bffa1861c0540ce45ff4a9197f15c853c7d75d_cppui381,
                                0x040a238800a14a56bfef15ce32fbdb59ba5d76d2aa4af45e17828491f6cafad7643b13f74c368b6d574353a47d535d04_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x069b17df187719495bb18c016ae7e7c31e8edacaa7aa30e506e70e134b5f1bbb45442a75a1b8b7b206fdc967bcf14514_cppui381,
                                0x0160243efea1efb70087d7450d69c62edff1432c2fb2b8e3f0d9a01902e6515fc24b35bf0ed0c9812e9587424b41971f_cppui381),
                            fq2_value_type(
                                0x034f424496fb477edeb1b23eb85e7c84a64cdee7d331224d70fdbcb209b06e01bc548cf67d8df92dd79e6e7ed2a4cd6f_cppui381,
                                0x03e1f18f3e7264effff7202321de674e2374696f07f68764878b4344223259ef69619126594e1fc0389eb9b8811432a3_cppui381),
                            fq2_value_type(
                                0x0eb7a0b9e959a2c6d83a2d8f5757f48005bf4774d4e554290377798d8675f416c914c67f4e200befbde44139ceeb09a9_cppui381,
                                0x13c675a9f0527e51c4719f6b3b7bfd92da3f206306c8fb9c85c06c286ee45116749135b06ec1495827f1f8bf739304f5_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x03e302298442ff87e6b52fbef013fe0afc3d002a78b8d2d582bc1ccffc8dce383bb4e21d5f549c64f880a1edad5d2790_cppui381,
                                0x0b16d017c1f4c8bd22188a741d1e93b15748aaaa079ba4694d2194583ae81beb9b2361746c7aaeb11f08f71e937bfe88_cppui381),
                            fq2_value_type(
                                0x162a2dafa59534770a715802d107403a1176924870a320f0462ca850397c41c75efcc11b5b6df2b63fab3ca6566f844d_cppui381,
                                0x022629d916cbb06d74e8ecb06fc8f6a78f56f0a93fcceca7448ef647198638010ce1f518ea05552749bf5dce10720ca9_cppui381),
                            fq2_value_type(
                                0x0df9783d2dcf1c4c1c3b97734551c84a7ddab13c5e9b2537ba3506e02a7440cca899ad1564e27dcc807ca1cebf42b13c_cppui381,
                                0x0a3e3e4769f81a94710995948ba1a9f7792d0e22cbb1abe3f479e328a3ad4ed531eade81eab2629fd2280813f75bcba9_cppui381)))),
                std::
                    make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x0cb6ca8b6d88b711d02573075e1a40f6f25349a80f88e0b07baf511d8a4baad9b586ff7f9c81445622bcc664dd13a6cc_cppui381,
                                    0x0279458add992150b117e6197e5ef3d5c852e1796b449f50cf650cacbb870961629c672ee7b2d9947cdd03bb7b878e3d_cppui381),
                                fq2_value_type(
                                    0x1847cf165d4d0f309788dc34d44535872d7a40bae234462e1b9ed09fd5a0f0d1ee26e38d7cca0eb2f660daa83b930b0f_cppui381,
                                    0x12080acb367923b739d6d1041f9fbad2c2ee94dda3adb9d1258e63482ef3e435661ff3ee1ee3c84b42976a1cfc934e44_cppui381),
                                fq2_value_type(
                                    0x09f8ddf1533933a8d4d6b9b9dbb234924773e13562b9dbeb6875c4001325a67868b782bfc4683c8d49fbd65db65eabfe_cppui381,
                                    0x02979b2429f4d35280394b9b5cdb690d15b4a2aaddeac08e1664705ffe909e59bccf4be90c64bf0f34a08e5efd80dcb9_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x11cdeb302303e06fc11452727a8cf6900c6b8f6bc5f503303e41b9f87add0b195d76772d875af36b1877c8da4044b357_cppui381,
                                    0x038dc01b2c89d1895bea6c068713259fa1f5d02dfafa4fee9a19a05150ad832a875cb5447379756e45b35e73cfca3749_cppui381),
                                fq2_value_type(
                                    0x194c20fe5121f5c1864c5efd03aadb880cd5f6c951d0a7f0a68f53cdfe6aafa5f8d83455ac6883971fca5d743888a579_cppui381,
                                    0x14b7cac6044711b4dd19dbf1895ba9c393ae921d8500ce74246e5356b8d894c71caef2b913bed06b62455c3c446ed7af_cppui381),
                                fq2_value_type(
                                    0x002e2b2d7ea70d38899115877b6d6ea175f96e59f7d216046f49b7f0e9e22ed7e0c267638448d2285c4cc1289458ff0a_cppui381,
                                    0x03966cd64fef5c3ca8e12190400b0ca7da423d329da5270feeeee1ca9f2e8bf52bdb258d5f7ed7a7eaa51bd84852a810_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x0b6e2795e7fa55531035a61ea6a24052b565a5ef05ce509266cc9ac7059039ba70958b1e4bc2da7353d80f0b699b6774_cppui381,
                                    0x1618d8b816e6a34de3e7253178c51b6adadbf2be2f6c4c704fbe40a2c868daa1df8af540c7ab477f27004c5bc3e037b6_cppui381),
                                fq2_value_type(
                                    0x052249bc1c46d9914c01e3a69922141f91bd1eafb2ccad0d7186507eda3c97bed89897f4beedc7634985c0e5d0150452_cppui381,
                                    0x02ff2b93e282ac16b09951a7f14a5290cfaacb3f9f25b9092b710f7ba2c8c30b285f0e6c62284913e9d0b37a92997306_cppui381),
                                fq2_value_type(
                                    0x14bb0012a1d140eff26e210c2f8ef1e29dc4e38aa84c7ab0358313212c2fbd26850b996e82e39f9f65395b4e824dd3ad_cppui381,
                                    0x08e1c0a71d4827a4d0708869f4c75d277625daecbe7dfa78aceb94751274c97a4874bd647edea3831f2ebd15c53e3ff5_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x098646703bafe7dd5cb20f895ab856379ebe2795171a2d2d837c3daf319242413836c94235cdd46a14bff333776cb355_cppui381,
                                    0x06b75a76e67126a0276a38d56b75c97ac7eed982bf0e6bc0ce850b047a66e3dbc0722657affa8fecf54c153e915ddf34_cppui381),
                                fq2_value_type(
                                    0x0febe95b97905efbad801cf2f411b3c42738ddd095c080721dbc0fd8b5b19a1846e88a83903273bfcfe312d4456524c7_cppui381,
                                    0x0eee398f5205e62ad1101261d8e611e78eac9f8f8501a6d3948d6d9709600c8e47d213682f3cf059f69c234ff2dccf7f_cppui381),
                                fq2_value_type(
                                    0x0dd8d7d5ed516418c10b19f95a374a6e896e30fc1e3d1ad535f9cdbae03abd371ce69d37acaf718544c9380022dc0031_cppui381,
                                    0x0fb010c220a47c2abe40a2e2b88aeb11506b9cdb36f9f6e587435be0634c64252126796fae4b841684368b9af64ce00d_cppui381))))),
            std::make_pair(std::make_pair(fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x16da8406c72e50852f40308e036b078f3820b71c63131432691fae238e2f8533959a59f3ff7a517230e76da76ea11293_cppui381, 0x16df3a44d2a8ebb86dc1ef23adeda663a2f21c68f274b2865df249d892c3d47baefe48aa7637e80d9120ba61e5dc1bfd_cppui381), fq2_value_type(0x0485b9438b3d0ab777df7dffe6240f2e6e4c5bcd5d948973671cf15e4e470dc59652eae43e3979332ce80479e7008b3f_cppui381, 0x05c91ce79d3c2d73aba5ddee9f83d201938b90272e620c63fd0987c516a1dcd9633ab470177cb3d51da52b6de9e53cfa_cppui381), fq2_value_type(0x0cda1c363a18c00c3271ff99efb4d016b5b13acca2d801bb7a283b992ae8094e80cadf5e7aa26e7887c183c01aebee0e_cppui381, 0x1141bcb428c8989db7a6e7dc2802d589bf49f8140177012fa81bce1ec75479e6c54fccc3486834a1aba2195bfba1ec4c_cppui381)), fq6_value_type(fq2_value_type(0x17210c1bb1cc4e8b1379271293a66da66f0ee9541c07b7f4d0924177c5ff01107c543a57e4a6800446573495b8cb7f9f_cppui381, 0x0c18658c9e3c0a8129165c8cde1eb4b4b28c50d46ffadef2884b5ec1620b48129a8e65e8fd98a5eace06cc5a51e626c4_cppui381), fq2_value_type(0x0a6e4e70752985d694c8e8f20068ca504aca624f63afcee28a41c8df67b5d24241ccdeac2c2551a1a33c2fee968e9072_cppui381, 0x01a9b5dcd330acb681df8be5747d02bfaa016db2c0b1f7b3dfcfcf09f4a25728c00da7aca745afa7a4351e841b089195_cppui381), fq2_value_type(0x164361d654ef2831b88c3fa1aee44c6903a99034cac2d8b7ee03649b29917876da30d16fc03563e32918f0eb41dac3fa_cppui381, 0x0c34b80d2414c06736417a5e0602edd1411ff3ccd30557fecd123232d5821916fe6ea4e1f8bee4c72e552f174e70b694_cppui381))),
                                          fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x01e66d8c34267edee21c19b8bde31acf91564bc8b36a24e9c0b9e5a1956ce63dbdad95fe355ccfbff4ceb2ee8cec79a2_cppui381, 0x02ca51dd6351566ee9e231b88a751b93fd78a233a860b8bf6bd8aa5e28085b2040d3e48c05b126e1240027864f98ff3e_cppui381), fq2_value_type(0x0f932f1c62814ba4317a6efc07823ef64fc76d8afe0e0a14f375e74b36720b48d08ced11db0d7a3a0b8c0ef122cb265e_cppui381, 0x02870732b2d15ecc4f4af98ac0f5dcf007c47fcf75ca17bfbdb1d559fcb956c7712e73487f638d92d80fe5b35b3289ed_cppui381), fq2_value_type(0x12fb1202408d76d2aadc36a392c7ef2e273d9b835b2a34f42d48e9127437590d07377bf4d56c0088775f687eaa6ac79d_cppui381, 0x0f3d1f91c8bfc0aea320f91720ff12d69e3a0e3a80233471a8ddf9fc0dea3c467e84f9c0316fb75f8cc62fd333920544_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x1125252157c328766e2e4b2f158e9b85c425e27f823418173d7a75690ad2d650b8fb9f1d48f1346a67c1efd13d4b6e25_cppui381, 0x0c9ce95c2b886c2f826f3eac42f0038aa1ded2f86d263566095ebd78b1a9e2624a1e7f36ffa742dac62f81b419d1cab7_cppui381),
                                                  fq2_value_type(0x0b3cc7985be98cd4ff44a6ca8fb4fa60049b224d0be10c124611dffc2ed21ab707352b35b746cbc4313b2d7cd0d5b541_cppui381,
                                                                 0x18c534f303bab5e4a5340f2c0e17b0f183b71e28f49f7bfcb93920cf4d5c33a5de2dc83f6d5eed6cb5406254cf4dc82f_cppui381),
                                                  fq2_value_type(0x074df80972d96ae23b43ef629a8cbe5638e1353e22f51d0df5113a5a262cd3955e3541f73f8714ef4994d7a79432566b_cppui381,
                                                                 0x05d374e795830a7d302915243530cd415f0c18c540b3634c633a2a6739681992cb7daece9674a0491469f260923bc674_cppui381)))),
                           std::make_pair(
                               fq12_value_type(fq6_value_type(fq2_value_type(0x132a78e0b00478b3edfc26db906dbf6c2759c7f27c3b98a84011c65b62bf92af8b54ccdbd3c1db8bc9362589e5078f45_cppui381, 0x0168f77a62d1b0e636dbde50e62161a2ed12142c177742aa798dc8dc8b12bd3b9170ebe41020defebca1e5bb20aaad47_cppui381), fq2_value_type(0x11fe2f2b29287ca8a2365bcb07457c284910cc544bb0211101b8ed23c463a1ddaade5a26f1a56ec93cb78659d5d6152e_cppui381, 0x06a641e4fc2750db919dfd1367961cfc265ab7e14f56110c26fa2f6b0366760abe126c5b50a6e9092e6ea61527935f45_cppui381),
                                                              fq2_value_type(
                                                                  0x04c0aa651f98f36be45309ed33f25884fff4aeb557bebf8f9b75f2286359a1216fd4d8f3a295f812c911f8868159cee4_cppui381, 0x17649067cb9e9d5bcfd3c3bc471e0f769154e7d8722efb664c9ea7ae17dab09daced6ec09bd629f88d9092f6cbd40469_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x1911a9857d93950e3b8b1754d10a44012f88842553804c156f3f8f3516c7696734087e98ed3685c7be16b92e90a945de_cppui381, 0x1489e73b6a540c0e36eb757c0bc1a618f7b6e9be7205292cbdf4361a595e8b7b302434574e7dcb25c1a054903c0e41f7_cppui381),
                                                   fq2_value_type(
                                                       0x17bbc83baed4f6d075d8042261a6cfb22952a2b2e8d5b23a4d526892229d7b03123939d7343a4ada1c5a0b2a76c7bd3d_cppui381,
                                                       0x104cb9d23adba2e984d8ab179f4e433eba61be2aec6229836df5b5b806f612eaf188810f08f2a5ced9580fb489d5c939_cppui381),
                                                   fq2_value_type(
                                                       0x13d5476e4278861e0080218c9b08a75f190512ebe51f993286fab8be19ee2dbb69a8df2e326b4b7522bc58a906ecacbd_cppui381,
                                                       0x05a939f2335e754b28864c96132453330b6abe3eeec760b53a4d774d988c22d5a9c56191401a9d1d7c467149cef95ad8_cppui381))),
                               fq12_value_type(
                                   fq6_value_type(
                                       fq2_value_type(0x11b23e1606ffaab1eb8952f0ba9543f09105aab2d7ac36725ff352a87dfa0b588658b7763b555a1b86aaf933337b59d3_cppui381, 0x14152d1e00b1b620c7f4a3cb377a8e60d576b3455583a01608e94f95f62e1d9b041845f2102e6ac198be8c3d94f68a42_cppui381),
                                       fq2_value_type(
                                           0x1603b8ca6becaddd01195cae5608d302ca23e14984c70dc7a61455895044ef148d0d8642ba0605aa7d7eb38ba44d9180_cppui381,
                                           0x14e9faa3c12ba3da9e5f7ce9b521b63a8061d21569a21a8ffccc71eb8243c1070c6cb47f1f2363c31659dcb623bfefe9_cppui381),
                                       fq2_value_type(
                                           0x0fd584caada92f79eaa839320334d5ec141c278c48701997d37c0c51cba8b08e0451bf66000076a85353e7924b30f8b4_cppui381,
                                           0x075e33a667c52690ddef06bd152fd8b06b7c965740a1bf7d23a765e049cb9abfda9f6bd1677033bb2d4731eb3c1b2196_cppui381)),
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x0c1de6523b8ca977f15bd675452a05d4bdf140a83664def3df217691dbc1c7a3edfdaeb49ae7c8ed0c4ed91389131388_cppui381,
                                           0x1156b0beca8f0bb9bd9716e563b4d776b7a6c9f6f35b6f5003ab392cbb8499a65349bf532573aded001b2e9a76a99cf0_cppui381),
                                       fq2_value_type(
                                           0x102268736c645e758dae75f4145d37b032618734391596206c1b925278a3815f1bd6429b1d1112ad1c091777f7fb50e2_cppui381,
                                           0x0a36bd32a4acc7fa9cea23223cc051bb2a3015d9869acfe90e968127254b240f828430f009c48176242c80a195e8d9be_cppui381),
                                       fq2_value_type(
                                           0x13c34a0f16599f0684d7df9688bc41f0cc5bcb0eb2945b2405e00c2ae4b84c6b0e8b9b4d5240edf63cfb0bbeeefb1f3e_cppui381,
                                           0x04f945294aaee3cad1852fa6dd7b024939483080cf5f561cfe08eea61d8b73cbb0669ad02d9e31f98e5c4ac3401ba2e1_cppui381))))),
            std::
                make_pair(
                    std::
                        make_pair(fq12_value_type(
                                      fq6_value_type(fq2_value_type(0x1796a4837667738bda78651ed8a4c65a87632a3ea97c95f51ac06954ec03d8c8ba490c1ea2a9518649d3f71253d684d8_cppui381, 0x10a7292b41a1e5b516f74e9ac0fe19a5adb4186c3c7557cc479ec3b60c38d09b82c6b24045737f9993b5a2329d8bace6_cppui381), fq2_value_type(0x195fd82c2e6fb90c155b2ad618676d49f694d564cb8409b9acab9242a6d0ee80ab7441b5be1c0ae9de004c706b31883b_cppui381, 0x1651f0e415a83964714442c625425dcfb29c22cce70da59b8ec872f5767f3049c4325a2217ce24deefc3caec95a136f4_cppui381), fq2_value_type(0x040bc81b4ef302791f0405a4a6bb36820aecd26d00161a699ede931fd34dbd727ffbd43854b390adb38f180786b3a635_cppui381, 0x06648e5c5fd111450b478256b589ed24746a56a31934ff6b204accba6b007396f5f56f580255728ccbb0faa46e5b1e21_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x1297fb8567dc9ae1465edcb4d48b476a0640438ebb32c4028457f0fe2e61c695393585e548144898e78d1d01d36f8bce_cppui381, 0x11c84077dd6ad636c43440cedb146cb1adc6751bc993606df76c6aeb0e531367c7b9dc11a52145fb18fc9708ddbee524_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x15a615bbebc925cbaf49322baaeed4e61a5c4ed3b6d69486f0097571ea22ed8772f015ecec1310179726e2aed0c60efa_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x16adf516ab6220a9f9b2d03b48a817221fe288fd431b529b353dd87303f5aaa0634c0feead0cbe424c1eb1c7597b8e67_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x092b831b0608cddc79f2931e2a2b5c83915ec6c57e28dac295046c0c233d165e77b1423dfe27b89e23d12fcadd6f5cee_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x065b4973fe2a9dfebe3961496be7bdd85de4a9c38f6fa2b6012b7cfadbfe50a1e1af8579c12eed88f3f2bf3bbfc9fe17_cppui381))),
                                  fq12_value_type(fq6_value_type(fq2_value_type(0x03e6a19b59584cebd47c6692aad00d5640cbfef27a9439c4c6a2a1ffb927c72e42121e2aa68fde5c64cd372c662ab090_cppui381, 0x08d42616f58f9931a6e197d17f0014d8ac864e1618f2378a1c1bef303e458a3f25fb11ea1de1fbfc12c3f505800b1503_cppui381), fq2_value_type(0x04c8fe00bb3d8b84a035b82e6ff867936536ac6f8de6088b43392e6bdf815ef31e3afab0200d2f7c41ee344137751421_cppui381, 0x00acba90fefd3fb2d9b2340850f406932a031b5f3a8029dd70ee263f735c2b32826f65f67872dda333be336f6b980ec3_cppui381), fq2_value_type(0x0ffde25fd0ec8cc2907dba99b10bcd7cfd14aa026a144af21857dc41fabc35bb2c1787cd31b1b1d5ed2c232c475bab2f_cppui381, 0x164812318daa68df70877bb63c0d8a8001e47c1db8f50d50cb95bc940dffbc7650bc40ea0b24f1595f5226aace718249_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x093481d03fef9cc9f271b5d8230d9cb14f3cf98d654b92160336e41e55f6d42fb605a2af905f17b1a459069fefd57c74_cppui381, 0x11f898ec6152eba558f2cc83c2c7269b9973240c4359a82021f2f4c6553c6f1f21f1b3fe0c5d92a067ef7608509f13eb_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x088cddbf5faf04086b3e25a0981961c144dd9f2c0ab00992f33dc45e9af3910f91fe60ec07efb7c0826dbb7e0862ccd1_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x05f8f806e7fb624bde57aadc678423274f5d1693bd9f1ed59ee83c9f76b690e7eb08998e4f8d811e49ca1335a7cc6aac_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(0x092a53f720e21ac1602e9670cee8b218a7aab84b5e33f05a0038be28f138e9a7abd348dd361fda6a6af61ee9d5f06173_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x14deb63656b666b4767eb71188e1c702a23c45d8cf168a1b35dd52e32cffffde0cf78b2185a7cba029a9b5ae24927258_cppui381)))),
                    std::make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x1710517e71dcc0e44fa6c49b2a6f67c5b3ad99bf27ebb14019d7d76be38a7a9b3d7d7b16b902eab975fef089530c2e76_cppui381,
                                    0x0958e24b6e9472776ecf24d69379d4594d466ba5aeac36ef84a46f8c8d30637674b41982753cd3baf0e44b23a4b45d58_cppui381),
                                fq2_value_type(
                                    0x11c3a389dc556837541b6744234a7fadd3fa80ce9657dc89ece826ea81e1870d89ef29bb22963c3dc0bbf36f2aba73ba_cppui381,
                                    0x090dd7e0a7c9e256eb6a8fb0e20d5c1fce2d46540b2224b496a6c3c1b638051dcb896bbf7952fe186599471533dbbbdb_cppui381),
                                fq2_value_type(
                                    0x13b7b8645c9b4053860778a6d0c900697a8eb71803d905bfcb946f06601bace37094d04a9efb482d941723f34b953f46_cppui381,
                                    0x121617dad31fdaf4c08793363fb9da18053ec94f0c0e6451874ff895df9beca02cc139266282b98b8017f3545fca8823_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x06e9b80e0d58d32189864f7201c765dea9f6396ceed1edebb54f675b64038a4cb8a5d8583dd353bdf7e9070c5fb3662c_cppui381,
                                    0x19fefc64f9dfdc55b956e457e1d7d8df75b72c77514e4d27b53ffe884c9e32a0c0c95f2062006b9f96f25c07dca70886_cppui381),
                                fq2_value_type(
                                    0x17cbbd1bb6ef16b040f4ee89279425e42fc6747f085c089999f306146faa1cbf5acaacbe6fe64a02699e5e544968c860_cppui381,
                                    0x0a457a90d294ff0d56cb9cfcc91785547e122e5b747c4e6b55f6d7502ac96ffb7628d5c35b8e57e7b4fc9da63c801432_cppui381),
                                fq2_value_type(
                                    0x068a208adcf654e32af96029dc1002a2806c73cd16d8342b3f041296bbf956a5e2c2e276019df013ed1ab8418f0a519e_cppui381,
                                    0x06f7930f493139b1c1421bd47ab75edc9674f0eb51b73f0caa95dde8fd6a1f76d0c0ceb804bd93291013bc79ae7f5546_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x107ddadb37b80b74ad3e2c93d85a56da0fa25be724d07a6d57ec84734a2a4efefa52cda682c81535ee716b9c7aff9a30_cppui381,
                                    0x03a8e006494d27a53ad9324616054a4e25463379078156a24beede1925cc8e390e22004f11737c1d9544d2eece19af79_cppui381),
                                fq2_value_type(
                                    0x0664e58fbed899267a597bf36c4c1fd59169881aa246267fcf6ce035f58272d6ca464cc6d7bb40724a76da5dc737c560_cppui381,
                                    0x04a9c751f74a6c4d2a9b6a8fbddcec08aa7093a3ae6fc66e30955a356fabcfe670b030bc04568aa073b404ea6a627a4b_cppui381),
                                fq2_value_type(
                                    0x10ebdbeb44f7419d1dcd072c444b833964615580789127e1865719422604b0effa076bc0557ceac7f399113eeee03e9e_cppui381,
                                    0x104172dad68748a62a06f7abd5442d44b62715336070ccbddec71e5f690cce468c4d316748850d32043b19ad9f1725b8_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x042dfcbafa057d992a14412651340136f38bbda1b27d2ab9e7ee65042ebe52d5feed5d135210dfe35660e0cf811c7ff8_cppui381,
                                    0x00105df46a8c1b1c9e2b3d73c544438ba290cb61336652c136dfbb2fc1a8f2ef94bbb053254c14f6db1564589bf17df9_cppui381),
                                fq2_value_type(
                                    0x1153d7f8cf18508d635a4ab1bcc41bf9ab62648b8114385714616228399f7ef85b38ed94d23f0b8bb0de6711c92f7f25_cppui381,
                                    0x10e25c5d0cd1c5f0d90771f30a87c500c6797dfcb15397793565586c820fabdfc81de036669e6975df8fefbc7abdb4a2_cppui381),
                                fq2_value_type(
                                    0x02c3df2e0fbefa9f39f2fe5809843332c4b052934d4326de1345bb2d33ffcc474ccac2151298e205344a7a0038e360c9_cppui381,
                                    0x120a4f8217c9f0dc474a438ffee41b52e46dd2ffb9646a1d3c3f59ae2ba02883c28b9d4d09c003fd65560b0c130f83a6_cppui381))))),
        };
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>,
                          r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>>
        gp_comms_c = {
            std::make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x0509c0d0ab554d5c1425bea60c60c7ef90a1959d26a3294c7677fe7f9c1b4ddd8ffba5c06d900bc13a1b317a01a5c7cf_cppui381,
                                0x046d5964c703d200662a0da2054e82bdce73f1a37e8694e9c452dcad42f5d15bdb651c44ff8691022d82cf160800bb53_cppui381),
                            fq2_value_type(
                                0x0ff81c9f18341fa508ae9866e78a755eb1b17bd1233bf1d2854614a6323d9818e2240ddacb4fe659ca0d5588a5df22fe_cppui381,
                                0x0ecc54057b774c2b2da8438a1d26041bb778db87c7a68c70225f3494a268daddee73e8c54fe31f74bbcb5a1ffb312430_cppui381),
                            fq2_value_type(
                                0x138a7fb94a9376c8cdb7d715cd68ce504af6f0cdf2bb09c767585e7083aa572de7c96388252a9d73046b166656ded74c_cppui381,
                                0x1a001a345535ff4333d83392a518c90ee849f00672b652a4c7511bfdcb8cefd7cebffe90e802c05056b94328063b2154_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x0c684748ea5920969bd6cf6023c501f74c238b26ecf79d5bf2d741871bc52ae7ae76f0b06c6b6e348bbc0aed9f35db7c_cppui381,
                                0x1575e1ab44ec2501524ff851a2c973807245fab61bdf976a44cc6eb9f371366c23af378889dec49010baafdea025cbf2_cppui381),
                            fq2_value_type(
                                0x1755614454ce7dc81ffd688002bdbaaeaa62355f676a799d665987a058f283363701d2106c2670a9e3041c3975142b48_cppui381,
                                0x17e77e4d08d89f981f8229862d1a889dd3da1f711dd54a11105072866414f2db55da2d15606391d76e503922a1a252e1_cppui381),
                            fq2_value_type(
                                0x0d938f3bd5bc8b07c20be5fbd4897080700a77d9094a60053defcaae68b7058e63aa4a7d8fa1248764ff0d1bcebae30c_cppui381,
                                0x17aa67c74c3ee3c9a26b3df1971942ad9880ebee53ea153b59628090e88937e74a70527f7e330dfd1c319dff4e4c7661_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x05a51b0a92a3f0009ad1374af88f9e95c4a7bbf69e8053b33c315d0608f3fa3eb4a6c9f7248f7f94f394bb28f2f106ac_cppui381,
                                0x029d796a6717c6bc82bc4c123621638fd80aa4adf4fbc0cc93defd66ea43c78eac60c99bdede9b1ad550f89d5bc61b66_cppui381),
                            fq2_value_type(
                                0x089283988b3e2d9668594255575288868791a54a37da8c4de2bd9e2f2ccf68b854bd57aaa35cbe6e6072414f07a7ff91_cppui381,
                                0x03c194d6daad3d011314b6c74b6ab60011836b774b308ec19e5dce5d9007dd167da90ca452f88b02c64ad07c19aa6f20_cppui381),
                            fq2_value_type(
                                0x0441a1ae10a79eb27350220350eca05daf096a7fcc2e9f5957396830b8a2fbebbe8ab383bd84453b029df0edd54c7be1_cppui381,
                                0x156818d2d266c0288f1f675c8483c04203afd696f019530138c82c6734604b081af0565bf1039813105806b2562c53b8_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x0389a59bc7ce5d6a9b92c75cc5dccf1292f2c11051dd3cd44deb8d3ae99a3173824ecec5b837a94f80da7b5725a666da_cppui381,
                                0x0ef2b3c46669b8ecc7881b9d5a1091443662b5f568d28f88d02e40146ddd61790a3219a4980cdf732326fd4cde56317a_cppui381),
                            fq2_value_type(
                                0x07e95ceb0f4b806fcd78c6599e30f8cc166a5987647ee081298eaaac7f693df9aa5a8b12e474b7edc91a1fc120ab45a8_cppui381,
                                0x079b811cb3c4a22a320214a66ce62fc97e6d57ebefa1061e68b6c0d5e57ae03ad64a6c8a0e828b57c32d08dd2ce2797f_cppui381),
                            fq2_value_type(
                                0x154f204ceb40f66e6d7308e75e4c4c3ee625cb1c3a49c5c909f830f0eae85e098b4161fd6ddb0e68e0063fdf2718b963_cppui381,
                                0x03efe4a8ebd8413bf8931eb383dcae700b5aca3deecff3e4e4096110dd2fce607d7c57c27170299c953332b0da763f4d_cppui381)))),
                std::
                    make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x183ca0a6c9be94ab62147fe8328c5d226edbe6cc8239bc43fb3f385f0c48475d00e24e5d0bdd85f29a2f241af3bbd0ff_cppui381,
                                    0x119ef2ed159fcf31d55cceb6bd5ff224f50d1266407fc83d9bc6aa0863eb8cbf90cc023d08039766f70661ac71fdcc80_cppui381),
                                fq2_value_type(
                                    0x0703a4ee74872ed2e39926384cf70eb96fe64fe5a6d21e8a57c36d00f15062be299a7717f558743b13920cb957f438e8_cppui381,
                                    0x0e683f05d223483f5bc169c7a57256c25e0ee36f44b9e91414a4a4f5b8bce38266f447cc346fcd12a2996237c411db51_cppui381),
                                fq2_value_type(
                                    0x0f90ef20a7b4c5c2c118bedf8429d802c9672724339eae4f9d031f78573bfc78596558bf0a872bd3f27c6a70bbb5f3cb_cppui381,
                                    0x125f6c17a7fc83f38fe568b40aa7e42e1ff629e7a26811eca4856d6dfa77dc3bde171d7deaf483a43fc7e304f8dea355_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x08748f5f965488602113fc50ca8ab06ca949be2b93e0a9f3bf4e649d9cbb65f4a82748f10672fbd89d17cb4dc0aa5743_cppui381,
                                    0x0c01b20eca9eaec6b1f5724d3c0a1d4a9433ca0dc521365a12244439bd7caa391766a9fb87826a1634a8e0c84aab4ca6_cppui381),
                                fq2_value_type(
                                    0x0436212511eb8f0360e431d5c986b459379e1e9f7c1b0d366d41ea2d08735c17e76098683d4e5c6c335b83f985893795_cppui381,
                                    0x0ac7b1c2859061c8da434968af4cf854dca613cc69a09488b3e21ee0307d1e3f189d4f748fb88a390d031315ea18f54b_cppui381),
                                fq2_value_type(
                                    0x08d396a836634af9ceffaa6e80e537d0311fc6a642cbbe1dcc92e2a99a494fb9463183d073c797d87da7ba9376fbd1a1_cppui381,
                                    0x191fe239f5a52c76c5c4efe11e206e3ad3236dc233c5d2287ecb32f98bb25407cdff0bf7dbe93924390ce085a8671bc1_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x05042fa800bb8f3dfceb80079cda096a8536002c312e208a313522687e8261d03971699821d6a25fa44b8d13e3ee03ec_cppui381,
                                    0x00968e82d31d90a794e4676126a9d61a6f20aabec1c144858d618d7eef23d1ac86defb409bd034c78b086bcdd0d9cb4d_cppui381),
                                fq2_value_type(
                                    0x0f513a9e86f0775e99974e6b8756f9edfe88535e3d5b5a4fbd22269b914acfd11089447cb34c36b70fcb31ca218e4f00_cppui381,
                                    0x1875b65a1ff784750afcae2912309e0dcf3574aa84c41992a5460e167ad6e3db26a5f4c846bd084db0ae2fb558077dd9_cppui381),
                                fq2_value_type(
                                    0x185da63fe96c8479b6d8ee4a41f925656c56831a183f1bd089711eccc321b8457b13b787b71f0e3fe97878007bd55d57_cppui381,
                                    0x069dcfaae486b11bdb123c41e46a3d641f5b409e8d6dd8eeed5cd35bf08b8bb7864ec81ef89bb052751b9ca109a42d16_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x18088d899da3cd385300387835a876ae3ed61976586dd4f11bf0d400b57da0bf4eb0e2b92b1c1efb195a5791ccc23ef0_cppui381,
                                    0x05b84b60637ed00e55c2bf28b6d5df6dc95081e41bf7abfcf8341b6642245f78076fdcaedd59bf217a1273f022a76c68_cppui381),
                                fq2_value_type(
                                    0x1736f5bd56b43f2b728bc9f14284f6eaba42ebea1f9783e346cfbdbfd5af309c9ad03faebfafd0333c7081b16583b450_cppui381,
                                    0x0f0894b8caf3ce18c79a42ba2f0bae501512e1e7ea94442f4cc5b264f12f6a6e433eb94b616182d7ec85f8860871fe08_cppui381),
                                fq2_value_type(
                                    0x13f46fcb18d43b4edd9a00282666d4041f03d9bd76dbaf5b4cc1717b9d4420b4abb55bb536ff6325a2e1c22a04c15b88_cppui381,
                                    0x125251837a3e3df544acb81d9cac435d323f9a3d37e3e7f2473ab37203fc4aa5a8244506add4f4746164c0536aaa854c_cppui381))))),
            std::make_pair(std::make_pair(fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x07024c86ba5602ab0e57dcdb4b4501da877d539d4ed4a37dd2745aa9bdb55d0a3cd38347f1df0079dde4e1ef74e9e82d_cppui381, 0x1855fcfb4ad62b22a634e5899594e97501deb42501e6481a3690e4f273b92e57657139c97f789d3912a54a8bde6d9006_cppui381), fq2_value_type(0x0d16ce2260f1fff0d92b6988b2e95cb013a818523b7f1d3b26898ba9ef79e97907d7bfc3b69d8db8ac329393b0ad171a_cppui381, 0x11cf91e2d0999bdeb58a5fececcfb8b514c1373126c185964c5d8cc879036f696522bbcdaae477b8eb88306dcb66c222_cppui381), fq2_value_type(0x15d7b157897b0dd8a5d8947983d5bf42bd417548a1c7810c9c09c4b53990d1c32de45c668dae372ac9f35ecf07993b4b_cppui381, 0x04f0ac9c39b1c302e5882028cc67b5a76ec27dcb2d6d6da17de5715b37da2112c5fbc612a2b6a40a4ae3cd239f2de3ea_cppui381)), fq6_value_type(fq2_value_type(0x09beca4a20bfaf28de0b508082d4be151e3ab5c85cf3efbb2b980695361e3b86c41468d7b405ed0f20e47eecd2720983_cppui381, 0x022a2891c36cf2b0ca222a0dba7928cee4523dbc605baf53ab5d111cf095f4c37088190082d0898c73cf82dfe4103811_cppui381), fq2_value_type(0x0b26068b249efddaf8b70903dbd6f816670a596147b0951c4f351516555acb0b720f65b991991043b2ad735d497a0425_cppui381, 0x0fd40b306fab09c4c0def1da79fd2b5b6c2cc7fb517f4e8a721215c4a2d92bdaabe9ea4265db95d621d9407598f9e351_cppui381), fq2_value_type(0x18b8cb7dcaf7d371e6a77c2722792b6829e817c5ec900cebbe081ec7a07c6fa5fd06031dd064995a93d7622b99f7c259_cppui381, 0x15bca171ed3aced3b1ae32ef8153c5dd11e2378791cc0f5fa51907f99c55dde7fd6f507ff4851ba6cb9aa5275cff1a59_cppui381))),
                                          fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x02333748cd46d0cc7ec0509c9f68fe93403a60a40643dfc4ab4d98d5c7a16c8287b3f6316839c055b09ba55545c94f27_cppui381, 0x119719edd3b8f58b195bac16996bf2c5fa51226a8ed2251fcb7ac328664dbeb0786fe8a2f570151cd40e73e7939fa2ad_cppui381), fq2_value_type(0x0cb2fbd3de260005c4a913a13d4b41c94684f3ee84c85dc405712663020fb3722714053859d371c599545ad5d9a7ddd8_cppui381, 0x114f28852c11052b955444a2826d2a43a0fd82b8813a52f95c62eff10c5671edf9dcf82d8abe8761a7953b3985fbd85c_cppui381), fq2_value_type(0x019863e194fdd97e84bc7c410557a709afcae8fd8b26c8796cdf0b34df6bbf16a65a69a02e2c771d83ac736dfdf5fbcb_cppui381, 0x000bca299cf3a818dc9f5a8ec3b58f612abb3a609ffba5ceafca6cacbd4f78e4a212cf098937a2bc4a78fe396351071e_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x0ec5930f04cf4e8e0fc40725a12952439bd55786ac78fe098814b7e8821efe802c375342a178f9b590085b6c482b2bd6_cppui381, 0x07c47f2380508314a412a9637f8ef1de37a445bbdf9a93b70606be70c752adb9359c488cb0d98699d7e455c9fa514edb_cppui381),
                                                  fq2_value_type(0x0854b125658dd5bf28cc52b1b0c52645c0e180de4f39998136534c71142d24d3c7dac56f534b50fb98b0bae1555bff31_cppui381,
                                                                 0x1519b1727b82f0ccab482a151be1ca2dd744566869c7a7cb4ae0f9a663a60e88441d0c3534f47311330af8afd5bc3e90_cppui381),
                                                  fq2_value_type(0x01ad28d7c45be4f02e5b0f7cc7c520419662339b625b0ec713587c633313e2b412c2d89146a60270365b484d21e27f85_cppui381,
                                                                 0x11806a9c74cc0b5a1f6bc6e143d12468cbb7c853f3fd93f9e55b6121e33f6d191f18394a734c115383b6a941679d2336_cppui381)))),
                           std::make_pair(
                               fq12_value_type(fq6_value_type(fq2_value_type(0x014b181b2158c0f2ca68b1b4e9873b86fd7b92eb0f4f763c159c4cf3b035eec79b96f35336e0fec34f687b7b6e060113_cppui381, 0x1851e001f259bb85914a2dac6dd45ef416303118875ebb3a9591e7fbb4aa149382e8fe35a0f2ce00e5de6dba1c2655b1_cppui381), fq2_value_type(0x11a167d2b6c687bb3f803077a48803ce99ed74d072c442ede06c8cd121c01782affcfce1e46abff85e39d34230be2e0c_cppui381, 0x0243d0fcce872bcdd60fe16f14be54b914393819901543b8e439934eaa3e619390ed1d6c53597eeceab8d0dc9e8f9879_cppui381),
                                                              fq2_value_type(
                                                                  0x09ab6d6a7f7a818c7521b34ae94ebc80257f0a55a45d8ed074ed37d4991898f7bd1acb6084bb96ad8c4987a394fbe830_cppui381, 0x0f8d4d57066ddfe290f0607d104a8451b0bbcacba61b8a26cd8529d94c8cf3323278dd843e689ff907edc380f04d7444_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x0f671815379648e914fc13f75f8a28c529b1683ce1ed4d862fb70905b49fd427cb354cd25d941e0b83638a452c5d10ea_cppui381, 0x194496c918d64e046f43ca0c8c405ffefb377fa71d57077c0548353e7059f61767e82933693ba7683a18c04b60b18528_cppui381),
                                                   fq2_value_type(
                                                       0x16e752db00103bb9540d4e3a27f9a198cc676936712aa498f25a4b0c0e8f9d5ca1999c7b73da4de45fcd9b8b6430cc1a_cppui381,
                                                       0x0ea2e0482a11d07624fb1a7900dd113eed25a6cc943d2a0282f73e6ea6b8c0733772859bfb5fed4cddf70940c7f990eb_cppui381),
                                                   fq2_value_type(
                                                       0x160b5fb68460818eafca5b25758d182d030255fce78a72589377fdd36fec81b29107667c5a30dfc2e3456934dee79370_cppui381,
                                                       0x16137e5b5c153ca9e4d79a8b169ae8342ae597661ba6f48e0e1cb65c0aa359c8b82331acde0b664b3b2d3ba3d1aa27be_cppui381))),
                               fq12_value_type(
                                   fq6_value_type(
                                       fq2_value_type(0x142d12f21c5fe9a7a09adf2d49d0acbb7ca5b306248bd371437b0899acdb9c60b17cb608197768c2628253966b9df124_cppui381, 0x01addc2a2195dbfb11ae342651be5f103a8e8304f777766405feef83e5af20d6ec00556bcc0b3c156cb39be11a4002b3_cppui381),
                                       fq2_value_type(
                                           0x072098acd831acdca2e10e8454e743f7ed660976d521867cf953ed1a48d9d0d51e7ab165084ebb458b1fbd72f03997d0_cppui381,
                                           0x19b2c06b471fadc502900bcc7698868104e61b2301c06f55b94bf2b795d775b830354206e29491a368c8b384819731a6_cppui381),
                                       fq2_value_type(
                                           0x041b9548ee21e2042dfcba1ad4f709118b93d3ec63f59d222ba7a88a4e85513b1cdcd82450ca193e74384c1bc8bed15c_cppui381,
                                           0x0803cafba760215f04328f92d089bd982317d0383158b873fc975f3320bf9c7f9dbe34fa38cdb84deb67e38eed0a0e36_cppui381)),
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x0c6e7eb98e093c8606221e04b79c88f6cb740ab97174b1a1f82415fc9ad7cadade4bb41adde6e1aa3d5d74b026d90a69_cppui381,
                                           0x0dd152ce35b3c88c110663260a86a25764f44fb6f824b524df2e60995d7b07a6024b1d40d6578beb147697a060b5717d_cppui381),
                                       fq2_value_type(
                                           0x025366060878ae527ea6f423947e9d1aa706ded60ba657e22e29e0bbe509812b39b1053b3ab9477d533327b659586258_cppui381,
                                           0x0e0fd927e4f26b758b6bc2092b8a0f81d58347a6cb2cf4ac88aea4275ae79c9d4411348b94be35734701122226379fcb_cppui381),
                                       fq2_value_type(
                                           0x0472afc4d6ed38d080d60ce2d0bfa96bf88c101e99aba9e0597d81298a99bfa88e5db8dff60c6dd68807fbd03e235be7_cppui381,
                                           0x15bf76f0a11dfa35d2e010e631c176776a08cbbbcf26b08ab7d40ca6e04d8a1fb9b62d991614ea90da118993db463abc_cppui381))))),
            std::
                make_pair(
                    std::
                        make_pair(fq12_value_type(
                                      fq6_value_type(fq2_value_type(0x1765ab4c391f7e75c994f3ba27cd1f52b8282fbee1bc361bf83b4aba699ce089789d1700bba237fb38e1d741a65c0e4c_cppui381, 0x0da6cd4f3bf4d6bcfabe55c810090e7c1fed3a27136a6820bfe4cb270e05326977998a0c931c82bb1049bd6af3e5c49e_cppui381), fq2_value_type(0x0946e44726ea3f7b561ecb5bc4843606afcc7bf7b2e33a9ae6105298bf722403b7c5634fe1c652dae04f404d5c3e11dd_cppui381, 0x15b8fba0861cc717594314eecfc0620d988197eadd59af19cb515ee400d2ecd5f147fbbca0a770e6c630e13b0285a6f4_cppui381), fq2_value_type(0x18633d791b9748795390333246289615f636dbb3237a1d56ff7fb915773fe9e2d2574c13a126af5cd90a4ff011167c0e_cppui381, 0x04466903327a93aa62775195cce74fe04f94bb324b4f0be9299b872f9ba1ed2f98a973abfe06c208654fef3296f4fce9_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x1540066fbc461be90e646e6f6399d2f7c03371d74dd43d2531c39114e11e0bbe4b86f844c5536ce414460dfbc2eb76d0_cppui381, 0x11e9e422b4dc6ba06a1cd24e976ae03bfa616d053582ca633f0214c0ca6af05a7d383a1d509d6cf43f6eb06a97e201fd_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x154f3391f28fd516037a6da6fe3b33257f023d06fdb501951db53a44ccd7306c650cfeb3658cc951fec2c73571a9271b_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0695d35f6e46c40ca8de1c322a5d21f8ce33eabd85a608a369db39f007292c5d3bf2f340fe67de5b6dc1c980c1c91a63_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x02e7c849c199fb5a675c4eedc7480e431eba542a0c471c3213068aebfa97be71ec61e52a81f1e155eedd6c3acd90eb67_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x00ba921ba55cf5a10b2993145a9c5cb952e919f865f2b07ff07508338c1be221ac51c29d4fdbe1a287256a68d702b2cc_cppui381))),
                                  fq12_value_type(fq6_value_type(fq2_value_type(0x059a65d7f906541fcd4673be639072df8784f2dd35b040aa6bd96feff15d58d321d6258036a4366ced471c86149b5652_cppui381, 0x16872ac23722cdddeb5195fc37246fe97923891918a01b5b03968a57efa7eb21b96347ecafbaf6c8177e366e79a868ba_cppui381), fq2_value_type(0x03c04992b14d73caf283ef079c9444feb7bdb5710020c6ac019d6f5794dfb84a4cef52279d607e868383426b8799920f_cppui381, 0x08add72d8e0fca15b272ac9afa602a94712b19c1119b3e22e5ad8ff34695183c13b76a3072614d077c1ee19f0d6e08ad_cppui381), fq2_value_type(0x008628667be675f64dbc305f520c37de935fa1a4b309c110d9c0b8e52c9b716c9ceb848d224291d0338b1f712a493b2c_cppui381, 0x170adc98a728b395c890d2b5ed099b20ef8cd86007739c8ffa77fc70f2d5761dc83e2ee89b0b61e15af3583f4c92366d_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x185df273536c03e5dbeeb2369eb26c2d393f02a3d3ee6f09fab5717e2dae51db2e6cc977ed913a0207a273cdcd903888_cppui381, 0x1761fcc54d4f5847af22af816df687953bd345c329bbaa77bb54830854cde537811ab6adf2e8f824b34d7b0a4020207b_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x141d58115c750b8075dbc36fa11ee7e18e33b743881d485837c8fc646dacff1a90117c8605c491c770f935a043cbdf76_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x0aba5dacb5c48b91c889fa4c7d44a27190dabcb17fa57999b105076a3394056294cd6d2f4630d89c94571e991467f869_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(0x02adb29e893c00b2a4adac4f0097ed61559a2ed433781fdb1da892c17bf7e3a759f8f55be8c62d09f6ec087e9b0c527e_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x11a08ae7662a9fdbe95c2b4fe958180b8b2e520cd49c4ad4a61c5673c60b657571fc5faafa65b5c57a0f0ca34b742dd0_cppui381)))),
                    std::make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x055df495fbdd2cfb95e4886364cab35c39f2f6ee68051e8a75af04b4b7b6bca05fabb58b72031a7d661278effbada5b9_cppui381,
                                    0x011e9e219bbad776d9cf7b71ba5277cdb96a91c6ca1da660c16a1fadc66a5c2b6ef917cffa3f381bbe84a6ed07613319_cppui381),
                                fq2_value_type(
                                    0x066c474d42bc3cf8c2383525225633ca04e1c834e1dd6c17626cd54a4b25488769c752f7464a8e942acddfa9fbe199c8_cppui381,
                                    0x0d143a2f40ed551fe6f1495dea8d81a0a185a988d3f84f20a26522663f137981d7960ef1431cc4bc92272b54d361da3d_cppui381),
                                fq2_value_type(
                                    0x1158e244ee2d31a82750e2a862dc2897e5e9fc5f3bfa591fdaad46281e52bee48feb202695ceec17793b0fb9dd25164e_cppui381,
                                    0x025c2485998359cbde223524c1619c62035ca1541eebf82b3919e381d79995e35da39f6a8ecda561925a39a4c2ba07bf_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x0eb4913e820d786e0bbb261e79292062cb817b91b10031ccf7915b0ed971799116ff8d40cdd4578807b75404c9ce581f_cppui381,
                                    0x16ae369f9ea045dd88e5b514189577fea5bbf0221535e86383cb16124692c9ee7454ee1ed1f79b2fcbadd0d0ef04dd6d_cppui381),
                                fq2_value_type(
                                    0x0853a2f45d59465598322d9f2e6106abb245dc077db644f20b4f368db07f6a4b55161e63d98f1e3291cc723a87bba803_cppui381,
                                    0x15e42adfe187ebdf6d5a6ce574ffb96503234ddc9bdba8fd047a2b025484d37af85ee239634f217e4f9b449bb524c109_cppui381),
                                fq2_value_type(
                                    0x1889b0271c67209a4a0e4243f21f74ab031f03c9d6d8bcdbe649e3a76c8920b6adffaff5ada3870d4de9402e5cb76084_cppui381,
                                    0x11703389221e7e8f9a4e8bde79f4b182d145dd5a6591ddbca888931a17d1c18913ed0fb6edfabdb2ef4677f7236ad50a_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x1195a6ee7140440abea0622d62939494748606eb7c01579f4fa1958560173bcb73633a09506e47079403fba4b5223edb_cppui381,
                                    0x153e1743c725f821378bc41e04d912db687380ce5f76c43a29ee0aaf8a2f8e715a086dcd03d5cbe7dba8357eda88503d_cppui381),
                                fq2_value_type(
                                    0x0913106effaeffecce955a06dd49398c2e09aa81b843779b32b4137ec697540f6396f39dffcb52a1310d2ff80e43c15b_cppui381,
                                    0x13797048a8aa483b1533be4a60fc9453ef8bd27529171431b622e589b7668280a8cda300c0ec2c4af943713d15b20bb4_cppui381),
                                fq2_value_type(
                                    0x0d3798c33d6a8f49f389d020cda1e3bb4a18685b56f3e5856b62b6836b0ead3d823dbc1f216255031c61c030b5706b92_cppui381,
                                    0x103a8ba97666b53c25c07888532feaaf3c6093bb25d3a55332ef5546f9507166dd7aa60d826153aaa4aa8616194d83c1_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x1816ea6954386c98bda8236ca5dc16ee746010e92bf98d4d63bea468dc519a121e482c8ea039befb4a372d68cb78a979_cppui381,
                                    0x1133a8de50c397628db1dd3fa00b66071331aac01a6a8ed8b6cf7197ffa08557e31a2a1df5fee1f8704d81eaa095df4b_cppui381),
                                fq2_value_type(
                                    0x1970aac58884c46821cdfe774c9a5b34abebc5747dde015f68656fd8eabfbe0084079676acb41ec1bab0a7fe18b97087_cppui381,
                                    0x004f38337491be48f6a51ad92348a7b266e0ed66fbe2efbe40b96b07305e291a89ec04c8549d34b14f5dd29c2a832d94_cppui381),
                                fq2_value_type(
                                    0x04bd3d054f295242f9f32fc3ad21795542dcd2e92af34e8dbf7550cd45120d9dd9700a744651b091fc286919b79798a2_cppui381,
                                    0x0b865cee2e54a6876d88849c5e48b2101e77419f8abac361561a65fb2cf3b25fd43d7344055c17bf11fad4f2518d1b39_cppui381))))),
        };
    std::vector<std::pair<fq12_value_type, fq12_value_type>> gp_z_ab = {
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x1788826b397708b027ad4d28d617f2bdcfaa4bdd9e8ed558eb0e2793bbc7ca92e161fedb8d7d4e899928edd018b9c4e1_cppui381,
                        0x0e5ff5ac95f10e80f0d450459608e81cd8790ded433e89b54b148aba9ee51d3b903c0d6e8151fbda77e080ff0e2ded81_cppui381),
                    fq2_value_type(
                        0x15ab6ecce8f643d8040a160b28a88cc354d0f00a0e36f08d8cf9d0be7498d58049d9efd5a6e1500a847e51b953bb5422_cppui381,
                        0x18ace269e554de2b091e1bf93fe6f49943cd8d933a5ff07c44b74a5919b19003096689adfd70d95bb67e76b898e64ded_cppui381),
                    fq2_value_type(
                        0x055d9b8d6422d95ef658133c5c420428757d798ba2a4f3726a966b8f465f1ced397f342835c604b246c1a35f95652ab7_cppui381,
                        0x08d481eb22d5099d849fab89cd08a204ebea62645ea16b00a5b186a85272585e9ddcbd17a97fcfae5723ed9eed3ecb73_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x13f74e51b80987e58a315930ed5c9bc4ec889b658d7fb1346985335c203ab26e45677cd9f0b270aae0f13579f37dbf0e_cppui381,
                        0x154d0f0200afbc37a60263bfaf2113724b5a418ed775d006347fb689f6e1e5bf9994f29525479a8592fe13507bd013a4_cppui381),
                    fq2_value_type(
                        0x0587bcb5d491260467ed5c4b2f61587b4cdcde1f95bd019a44812493a70d43e8973c9f8fe4d3efe5d1357868bbf6a9d3_cppui381,
                        0x0aac99645c6315981ac98aa22fcd9e5b793a98e9ad4a4303e3509b838f105af4b76c29fcd27876413cc8a32125414d3a_cppui381),
                    fq2_value_type(
                        0x0fbafed0658844cd1b17a8256243fd52b59ae0301bc2ac7448ce9995b35326a16d9607ec7c6d6df93a139e3fc9775f0e_cppui381,
                        0x0d25b354fc9056f541dbbb04557c2bd7c798a104b0532d630ca4a51f479bccfcc7145d1a38358dc4f1c715ed93715969_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x0ee181afb0aaee4aff5e1f376ea7d439777d256497e6b2f98f4503ed7cd57511425fae9c35b5f79db8e6cb9b38793895_cppui381,
                        0x102537a00e697edaa60b7867d87998739ef9cddfe187457648c0a2be3fd05c92b8ef19329bd7c07c61010965e7bef8a3_cppui381),
                    fq2_value_type(
                        0x15bbf319ef5876460c111365bd6478d7e0c569ebf23a68afc9f877e29760042347e4e4aab02dacc71068b41d8b58910b_cppui381,
                        0x187682bad5baab7ae6bfdfd33ef84a0882cbee0980d5369df1538dd0761ed8dcab020fac9a0a4c5a027ad89f4eea5db7_cppui381),
                    fq2_value_type(
                        0x057142517f230eaa05b21cb517f67b5317ae73ae2944a904f64f888239fe63488fe5c657cbb56f3b5d1f2dc678e49200_cppui381,
                        0x101ad09dcdb181b32a1cd4f24d24dcc01978170243650e64d53b838fd828ef5e8bdbd0a9406323cb14cb29a0b787797f_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x1299f190879a96636bde6755bd4d9f45904273b95637c4188ef3aad491d90561ce2d3d79d0598314f462e46fa0631ab4_cppui381,
                        0x1546ca2af0e225be968677ca9fdfccce7f94f2a235ad79f881da67f8e38ee2b01114c52ed579a69ecde37e7517baee53_cppui381),
                    fq2_value_type(
                        0x10f2b3b749f94880c47b7f1d7025f2309da774aed1ae8a9736867fbb681de22e825e275f242691151018103797399948_cppui381,
                        0x04e5051ccfaff5b87864f3917a92f5ab654d35ed7d2b5834ce01d3854dbb64e627126a0d3ffc56f1a504c41bd8f90d3e_cppui381),
                    fq2_value_type(
                        0x194ceb66c0592dfa69c1dcae1947acd98a2b215c89e66ceb16a20857659e66969e81b1b783e6e55d17d516e331ed22b6_cppui381,
                        0x1063386db2d0ecab4c52fa3a83dcc07afde71e86c78acc6a92c389ca5c0c01b2842e79dfa789ae4e35e5ffa2ae8d07cd_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x16a2a61acf5410a8983fee3e65911fc8ef8bf4280e3ce5174c33be1a5a562a426d3fb20f2082e020eafd309c4996cf92_cppui381,
                        0x0909deb1db74f4786ec60019f5b50a60ae735e62aeb57c2097e0436aad72d13f5d84fef69ae187bd4e8417bc5e079b45_cppui381),
                    fq2_value_type(
                        0x1757ac28a92c04bf2c3d9647b2a06d5eb5d9100f50d5823e8912443c66340483edcf5838c8e17765b07d7195ea2dca32_cppui381,
                        0x082a7c7ca07f53ece7ac269c115aae2f8485d746a9c76b207db11bca692387a9970747ce7be1ecc12f44c1f56f88d13b_cppui381),
                    fq2_value_type(
                        0x1779b373b3a78ad69961e102afbf553ac8081d8aedd1cf702574742073b40623e44d0b29436c25f009fbe58541428993_cppui381,
                        0x029f014ca1e66024f211288e38d2f5eefc1535c43c51da87378189fe2effadc5e389b811be547b0ca7ceeda8ef9d4c78_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x1024e769afa0d5ae54bb42fa474d97f198595a8a7ef36d554131dbbaec0ea8cfa3093a7d52eb2ab0282878a90ec78db0_cppui381,
                        0x021b2e0f6b83ed79f4084a8a3c2b62b60d197ef4e7c7da046b53e759d315f0ae5077e881ad5a3ecb82f09e03e67e8bb0_cppui381),
                    fq2_value_type(
                        0x12056bcd46be6351e6052d5b566a26bd8c9c56fb4bfd17c09e250a70940f0444ddfdf69a189c22a886e5d1acd0269f03_cppui381,
                        0x183ee78969b1b718afd496ec57512a92885858aa424329a03ff278bb1502d0de728bae15d88fd535ae4d6e77868c510d_cppui381),
                    fq2_value_type(
                        0x0586752e90ef08d81e98ae6bfe2379cac34d5ceb58c54e93734ba59379e0b085355a00f371f46e8f8c2ffec44cf127db_cppui381,
                        0x00f211527a6db95d4a43f0634fad06355728bc947311c0fd8fe5876106dda01eadf90d9830653e47e9c4bec57db0dd51_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x04960236d2e304dcdf0f985f3d4cf05b2e97a2aaec262023fe0bd44ac6804c20145c28507953f194d4bafd19f66be7f3_cppui381,
                        0x022c81ba8ca9cd70d8b3e1da607fc00ce738f429760a17b8b2e080e1aecdc42fa150beba7a111891ae4224044129c34a_cppui381),
                    fq2_value_type(
                        0x13503659bca2ff69933dfce8950b044a4cfe36deb9abf21dcdc2c948991d73d8d2df5844586ca787a09f22c242cf870c_cppui381,
                        0x0d3979429426d5fef07934b6051d67b4bc5a0c7bf872f5cff9bfad82d82983ed6c9db23556f8cf572e264206707866d7_cppui381),
                    fq2_value_type(
                        0x029a155db0a5002c85c255e640fdc72db1a2644e068aefd9edd68cab9a5e3774e602cce877ff4ca291bab1cf8563c579_cppui381,
                        0x16f7232f80059cf103b8aa1a4908baa29776200b62f638bbf4c31c8f1dc3a3ef3d7b46f7fc704cc32f6f5a2664a7503d_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x16b54372d94f1571758a6290442b0ce1b56f842d0ac3c7b994c9d863e5b6a9add637ce360d189b8253c096e3141c8f45_cppui381,
                        0x110d7cd8299d438b36752b5e7539cc2b8330c43c09397193bcf643ac76b5f82313dee59cf2e65c1bcba11932323ea251_cppui381),
                    fq2_value_type(
                        0x049209eba43cc8e939832adfbe4c762d3c06a1d48f24a909f161433d4809abe90afb6e0ce5b0638304f05608400969de_cppui381,
                        0x0b9756c54b7d2866da5b9d22a29ca23abfd5bc6946e08dfecd00b0b07f174e4bb08f96913b37d7a7d9f8f60e25c3080e_cppui381),
                    fq2_value_type(
                        0x11e79273751964ab0601d57c7ddd4fdb7c3d32b9cb08ee507ba16b9f00d9f59228dc50c4bd9e10079f3edae149c45218_cppui381,
                        0x098c0ab152f5243075b84c57d0831ab00e6badf052ea517ef07c6cfe8335f938771dbc5f4519f64c805b87369fc836b3_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x0578b0ce1c12310c89e78573042b224b55b106826063bce4486c350afebd67f2e5ad11a4d05176cb48258626621ab615_cppui381,
                        0x0dfbe96ed0d2e708dae148e6ddebb0c3b789378af791cf8a6f9a44340e51f0f4ac83dba32db1bfea6e301ba6fbf9d510_cppui381),
                    fq2_value_type(
                        0x13aa0fd7f5b9cea485e7d9d16f7205eec4a533954d4c162a5a67fbd3ce698fced217ff17fc32308a0d5fd4349b581d78_cppui381,
                        0x131d6c897e1cb3acb17c83645ba9ea1fca3fcac9cd45b948b1d7cacca9f31dcadbdac1f6d74ad5bf22754b68b33bb504_cppui381),
                    fq2_value_type(
                        0x0878df44890f4097924d9eda5d1529602e770b75b57cb7560c911d7075f9582d2112034680419197f37efd61efebd8e8_cppui381,
                        0x177e78cb4c7f868dab61eb61a9c8b54daef67d2c8047c33646c0fea9177ee892b5a1a4176a006a131776b468aa5bc45b_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x17e1c7376fcc1d8e890310fbf48d52d0de565de348691120befc7477220908a7ea36d0dd5bbdca517f6cb5912d5c8da4_cppui381,
                        0x0d23f6c5fb259828e09edf873366a390ff4b976616eeb687e656719233bb14850419f238790abbfe173e4ace519cf0db_cppui381),
                    fq2_value_type(
                        0x06bfd2bcd807e8256ddc90d8875cd2b21ebe6a40b2f0291f7a40cd2d4816a200adb790147bbeaeb5da22c8496d12a32b_cppui381,
                        0x0a99ed28de9d13fb6c6b9d2bd17575ba080c97b0902a71a78f5341d12ea46fc08920b724f143e5b9c43c1ceaa136e511_cppui381),
                    fq2_value_type(
                        0x0c30d54ab51c3f63590c9d4b4cdad6e31221675092483a4478ce128448b398640e93a7ec9d3251f844df93a842db2283_cppui381,
                        0x01d4b8b604282d91d98cde7bcfdad4caa7e31d0f203d2a0c776ac775acb698bd4e2bc20993d682b5b3c0f38919afb8f3_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x12320fdcf1a1c2e54dcbe4f0bda294b52931f8a5eed82e6e052927ce75f578719d153b6cb1006dcadd3e22140cc0e6d2_cppui381,
                        0x034ab2124020db9adfcd59020442881ba7856fade5756d30a4c1c289cb6893cfb1d24eb54853dee13d6ed51e528a29f6_cppui381),
                    fq2_value_type(
                        0x17d7210f5dd42c46fbf0e0e9f5543f0ed3dc42fd54acbe28b9ff8ec83861b6e9edae445f7b740f9af0f85a30045afa8d_cppui381,
                        0x113f29ea7afcc1012bbf5ad3c60411231e5e6ab12101ae2e5b0b920b2f0fbdc25555cbe67927844ed3dc58a21523f1bd_cppui381),
                    fq2_value_type(
                        0x053bfd84179beb5028185b23e3b2e0cd1c21047f1ecd79273f1d2f9dff09cd837c7016768ec052c1ce897187db5f4c07_cppui381,
                        0x01262f7bdf84f75f012aa826a120120ba1d094ccac8e6301faa31718af5937ae57215e5566de8e86e193a51e9a2d0e61_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x0b11bae91f6b969c364f4365752e15c5309d317d5b6386d59b8da732f23f186b7c7fee3ef0ba2df800f0d96ef8ed917c_cppui381,
                        0x0e94f76116cd2936f91eb7e758fb0ca34127fb135aa60748c4f7a878c964625cc7cccd7f27cd8d72278dd9e1aba48688_cppui381),
                    fq2_value_type(
                        0x0382ac6fb6f360b5f3b76c6c02c4a05fb55213758d8252684cc68b6d50b76866cbe3346e6f8e3b1f956f3413ce7f33b0_cppui381,
                        0x0f3b2651d1142e4794e22d3cad36278839b1bca57a82100e9682a88501ce01bb53e99f26ded23f31fb355061a5899e73_cppui381),
                    fq2_value_type(
                        0x03853cda18ccd9f1a6a27d938c312e7d141b944cd6b38cff562636fcc04009c334f6282ab1341eefe887454e6e65a2c1_cppui381,
                        0x0e9d8bc6e621361814010bfb5baadaa6f6014dffd7c65a4275a0c22378b4c56ab6a0688ef0f3b17bdaa12fd0a98305c3_cppui381)))),
    };
    std::vector<std::pair<G1_value_type, G1_value_type>> gp_z_c = {
        std::make_pair(
            G1_value_type(
                0x00356ef47a6a688a8832dd47fad2f8b5981a564d3b7dc77b33f13dff52dbb4536b6108510785304da9fbda39bfdc0bb3_cppui381,
                0x110ce13acd56d5f9188faf09684b5e299b848615ad9be48dec0702e42ff794730417d92c7d437ddb1ba82869b5b6fb60_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x11d1f6fa158a0424684bb00c08be8f01c6eb6835a1fbb6ac06606799e517b2752b0b047b70266013b9d932198ced0930_cppui381,
                0x0d6d40a9e4c8aa3f41d50f3204216c78c5959e5d0aaa08fb0276665b50efa7e90749cf7ae48d353c2beb29a7d9703ed1_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x17f33645e50acb5c20888955b496c67bed513e0b844b02628d978b8b37a813e33328f329cd9c0f10eda20cbff4758e1d_cppui381,
                0x106b96a3cfb2fd59f1d171d5d956498c24fbeb6be8ee12e7d6432b8dc3869598e771a56eaf9ab8a0001a1da658df7f09_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x145033766369f79f01c3ae44050c57b90ef20892e9eb73da1efffff9c8257fa82ed55051ea26ef4801268e55f1ae2987_cppui381,
                0x01793eabe34fce514a38b6ed3fdf9dcefc3754caa1efadd577137a1b7182f793374e7040e5cf3d9911f056720c9a0756_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x01bea501f76061a67001ca3c5586aebaafef12130b375d2f12088ef376fe28aacf542d0ce26d01f3cdbc10c5a6b0d6cc_cppui381,
                0x0cb0d723875d30aa8e7c0bd11b30613cc5f40fc0575315171b383ab3508bfb1cf4d764307d32b44c3b74e5ad2bf3f2b8_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x13f158cb09a4dee7c65a345c7f2173e337756c1d286687fa9661c432cae1191927fea54ed47648c38ca1ff52c4d20eed_cppui381,
                0x0d851ce999581e11e4930335dc31241ecf004ac30c1adb4a60424d0d29748c01c4d04be6bea6c26c389c9450139a381e_cppui381,
                fq_value_type::one())),
    };
    G1_value_type gp_final_a = G1_value_type(
        0x0e8fa2b057e92406ee207fb49d5206dc169bca2ed70df83a70c1a14a2813cfc0e3af3505a878479cd76d84c28ccea7cf_cppui381,
        0x15dfc2c8db04ecacf69d7fec04ff641f50064b886bdbe1870ed8fcdb585eb6fe8915bdd29a7fdcf9fcfbaece14d85d33_cppui381,
        fq_value_type::one());
    G2_value_type gp_final_b = G2_value_type(
        fq2_value_type(
            0x00af5b0a0f7004410575e0fa27c27dda035de622ef4bdb0a1132ace3f453be45a68b9c5cfc586caad9901e399a1e9501_cppui381,
            0x0bca883f2a3089607567e2a0adff0a128c4fe32bdb18e9fb10ceccaeb174d67494b36abeab981950b0e864441fe6b9f8_cppui381),
        fq2_value_type(
            0x06889d8d13078eb3f761da2b5cf53736bf8d2e58a4972ca7e58fd50d951689ad6bf1264d9d41c813d1eb9fbf0c7d2389_cppui381,
            0x1399770a311376df72bb55004795c619258767b59ee7fb2a942f8a57806a0bacb0fe1228a6252ec74bb1d59273b5c4c2_cppui381),
        fq2_value_type::one());
    G1_value_type gp_final_c = G1_value_type(
        0x084791edc406a3f22688cbb2b037e1ceb6326b5923f0e0d325166f7aff6a3a49d445bfd9bf7424eaaea21e8aadccb9a2_cppui381,
        0x10b85fa7ea5d2477ea414b7d693df5aeae258f401fe0bc8754c5a06c7182c7b2bba42a4a166a46fb3deb55becc466de6_cppui381,
        fq_value_type::one());
    std::pair<G2_value_type, G2_value_type> gp_final_vkey = std::make_pair(
        G2_value_type(
            fq2_value_type(
                0x182abf0fec3c7d47f4ce807cb3e1392cf7140591e891b5177a287a9dfbd0260f5dac227621ef6d8a60cc9bcfbdf5fa13_cppui381,
                0x0272aa23725df98efcf4c9e5c3706e91129c5d8ba0a93c528f787db124e90f0d9087a3e610882e03a5cfe7f61dc97dc6_cppui381),
            fq2_value_type(
                0x0c816f6952f4ea048ca681082a9315d2b455874da75f1780f8fdbdf8c135de783b91a633671f92a9c8989c12de1f491e_cppui381,
                0x01bcfeeeb78d21339e7a32406bc15a961d3494cdcba1ad0525a58c1a09908ccff78cfbd33234f23fbe089241fa7a8a9b_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0876f0583fe644557ae2059ee8cdb5f8771e596e98f8daa9ed579371918ef4f52aa4f30bd1f1ff75479c8425f61a320b_cppui381,
                0x0a1b7c06b0c91d35cc69a9d64c5561d5408e73dd040a51762f5853c2cb2873a4c5b994470a54ca45429acef0f92688ba_cppui381),
            fq2_value_type(
                0x04dd9bd93186e54199d3b41a6348d73f516734611390325a478c636659c886c0f88f7ae15ca80b31dc9284b2c1135c8a_cppui381,
                0x00000ff4aa4580802a632b61ce364dfabac4b2e3aac4edff9cb199c2396b36aacd5b2e26ea0f19db2a2e6fd5ff4f13ec_cppui381),
            fq2_value_type::one()));
    std::pair<G1_value_type, G1_value_type> gp_final_wkey = std::make_pair(
        G1_value_type(
            0x14006b4350de0de70c5b8b7b35e0103298c7afbab44b4cdc49979f188cdf8c2ac713a8778b7d731b12c41da259819a50_cppui381,
            0x0128fc84e299c6b2965c56e381dc10b3e5b36fc2ed27de8e4bf56aa73f2273b1ff21f8af74f90d64dd21ebe6ef443d07_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x07760bcae08fcaaa51dd8712cbe38ab449198f356399c3ad86b46f69d0373d6c20d2c81054cad4df71c0397375ad8e6b_cppui381,
            0x01dcadbe7a8ea3c463c52f50197a9363fe31a96a8ee4d6e3b06a37270d95ec4ba29ddbc363290da25d25788c29fb4eaa_cppui381,
            fq_value_type::one()));

    BOOST_CHECK_EQUAL(challenges, ch);
    BOOST_CHECK_EQUAL(challenges_inv, ch_inv);
    BOOST_CHECK_EQUAL(g_proof.nproofs, gp_n);
    BOOST_CHECK(g_proof.comms_ab == gp_comms_ab);
    BOOST_CHECK(g_proof.comms_c == gp_comms_c);
    BOOST_CHECK(g_proof.z_ab == gp_z_ab);
    BOOST_CHECK(g_proof.z_c == gp_z_c);
    BOOST_CHECK_EQUAL(g_proof.final_a, gp_final_a);
    BOOST_CHECK_EQUAL(g_proof.final_b, gp_final_b);
    BOOST_CHECK_EQUAL(g_proof.final_c, gp_final_c);
    BOOST_CHECK_EQUAL(g_proof.final_vkey, gp_final_vkey);
    BOOST_CHECK_EQUAL(g_proof.final_wkey, gp_final_wkey);
}

BOOST_AUTO_TEST_CASE(bls381_prove_tipp_mipp_test) {
    constexpr std::size_t n = 8;
    constexpr scalar_field_value_type u(0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255);
    constexpr scalar_field_value_type v(0x43131d0617d95a6fbd46c1f9055f60e8028acaae2e6e7e500a471ed47553ecfe_cppui255);

    auto w1 = structured_generators_scalar_power<g1_type>(n, u);
    auto w2 = structured_generators_scalar_power<g1_type>(n, v);
    r1cs_gg_ppzksnark_ipp2_wkey<curve_type> wkey {w1, w2};

    auto v1 = structured_generators_scalar_power<g2_type>(n, u);
    auto v2 = structured_generators_scalar_power<g2_type>(n, v);
    r1cs_gg_ppzksnark_ipp2_vkey<curve_type> vkey {v1, v2};

    constexpr scalar_field_value_type foo_in_tr(
        0x70ba0c24f7ef40a196a336804288ebe616f02e36c9ff599a6ab759cd4a0a5712_cppui255);

    std::string application_tag_str = "snarkpack";
    std::vector<std::uint8_t> application_tag(application_tag_str.begin(), application_tag_str.end());
    std::string domain_separator_str = "random-r";
    std::vector<std::uint8_t> domain_separator(domain_separator_str.begin(), domain_separator_str.end());

    transcript<> tr(application_tag.begin(), application_tag.end());
    tr.write_domain_separator(domain_separator.begin(), domain_separator.end());
    tr.write<scalar_field_type>(foo_in_tr);

    constexpr std::array<G1_value_type, n> a = {
        G1_value_type(
            0x19382d09ee3fbfb35c5a7784acd3a8b7e26e3c4d2ca1e3b9b954a19961ddf5a04bc3ee1e964b3df3995290247c348ec7_cppui381,
            0x0e1429c57d0b11abeed302fe450ee728b9944a731765408533ea89b81f868ea1086c9d7e62909640641d7c916b19ad33_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0d76e41234948369334b432362d0704bd88599200d80645a69ed47acf10464822776a5ba8efaad891d98bf9b104f9d24_cppui381,
            0x08a8c2ae10d589f38a9d983feba2241cbf0d292d44bc082e8fc9ff872f8eb280f6c6cfd1c34928fa81274781a4f4770e_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x02e080ea7883f56025b965fe7fa27315af7bf0f532fb031075467cc78dbce6319645e23e8febb6660cc864ba9e985afd_cppui381,
            0x0f25c2c8aaceff02da0d5b85030767c64b3ed2ffd3e3f69e9aee42025c737e95fce00d5269eb151c4d22a5f77ef8c815_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0d3541b03376d07cbb7f9f48b3a1cc43cf48160152c20c00c7bad75986839b0f9ef7cc71f1ffb4d254d9ec15ce6bf336_cppui381,
            0x01e48935c827f8ec79129124e8baf1deccf99d8ca0324fae41e037f4854ff4f389a4df3bc9ab2549b6ef949e4acdedb7_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x100462d4d96fcf47dd6f6dd3957f8c2d15cc72fe0f2ab0540813e73a16c74b4bb932722e96a33e2a26ca1ab9bc879e49_cppui381,
            0x0b2d223ea7a3275108aa52b3e4eaba948dc93cb6ae29c3c472a022eab55356e51755a6486e7fa94f3b8b4a06b3ea735c_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x1320c3ca0de8f268ff78f461e5b342960432064eec51743c386fe93f2f1ff8d4592d04605092b7302c217a72e6137632_cppui381,
            0x1613b77929282de9c0a3baf3285394260a50660b2f5168c6924973b44f35dc1a236796b3251c5a748039b78d0b377576_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x16bfa39559ac6ddfd3c63ef03bfd11ae6de4d08e66f82dc4ec4e2ca4318c266a705134204f2aaf99b91f95610d356bdb_cppui381,
            0x0c2dccca4ef18b3cf50f18ff13de4443eb6f5e6160ae985568fc5557232c892599e27285254360f797e4b59da1c19406_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x09f4ebbbaaaf5d2ea52abcb591412f6851539e1919d34de4f00900e60591438a6668d48070b5fb22c3b59a3cdae45799_cppui381,
            0x0aad9a2d04fbced844ab0811af6deefb18e9d67660073ec96954f2f0edf3a884a4ddcef6d8b7889a9bfbf7e2f151b1b5_cppui381,
            fq_value_type::one()),
    };
    constexpr std::array<G2_value_type, n> b = {
        G2_value_type(
            fq2_value_type(
                0x0badfb692a2a7ca4970d2733fc2565afa8e09428453ef5cc916a6d5ab43b8be8b9ef920af378f1823f426bafd1d096c9_cppui381,
                0x0d523776965ea36bab19da0387d38305d628d63fb7da6736f4620b7fce92539fcbaafe7dabd96e98693d9973ecf0544a_cppui381),
            fq2_value_type(
                0x020203c10b37edef960e6921c624ee57a3c2b256385b3c68f8fd611f1deba8ab91cea15d77452639429c74086a322eb7_cppui381,
                0x1498dcc1d84eb92d7e41ee99596e1825901ea430fcb0ff64d346e19375981ba8579d6ebf325c8809f1aee58542bd6c98_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x1634b13dec932a66d5b3ea6406bacd702e020970d533c29a3d6fd80a4ce1e8138744eb41b0f1e66e956fbace9af6a151_cppui381,
                0x0a4edb2465192b1b32c84bd6791aa9795b8533df963b1626c8ee548bb5f7430a563d0e662b3053cc12cd256f9e8471a4_cppui381),
            fq2_value_type(
                0x049004fe74f14513aa607d429e78203f86e08100dc70243fef9fe73cf9f04f9c3793b3fbc1d4833f9db371ee94e60bc2_cppui381,
                0x0f2277dafecdf791e560c89086d7abc21e5f0314fabd492a0926e588acf7a34d30c0713ee2cb03054f44a7dae8288694_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0147be5fd09e02e8d64eec3e6737b40d4099ccfdd88651c692c7d4407a2822c35756ba40ca412f61e201b5cb649391a6_cppui381,
                0x165fd26d77e79da63ffbfaa5771426f4fc6c925a92bd593d1075e84ae1db5e9cb0a7dffaea46dd46a44f6cf904cb873a_cppui381),
            fq2_value_type(
                0x1507d32ecb1783a069322547839ffeadd5bc4e04562dc36914686df787f6f82d5a84f32786996fd56ab2ed75e25264cb_cppui381,
                0x0302e3dd0ef0b642fc55af194e4906d57bcbcfa1a3822f078fd7fa1ea0d665ef6f60531068bd7a6834b92618db91ea23_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x04c0d40f727b43aa40d5a66de08182abf5c15f6d3726a9f43085c7a9c8b535ab17bafbc6d90a6677905271c845768ff2_cppui381,
                0x10e288228d368ee8fbfe240e2a0ac3214bc232334d901feb02f41fbb459c11ae6fb381a4022232b66f8a98ec5ed2425e_cppui381),
            fq2_value_type(
                0x0285029f076803949ea0d635d716ddff562a8ba9a652e43da0e1df737978432082cce2435e857a2b78c886fa7a6dce84_cppui381,
                0x0a52fcec1a0fc4ec51022181a0e1e44aee18f8d2cda18c8ce5acc789838b03205919870c83b4ec54cc523d89a40ef62f_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x113b921ff6a06df8c8ee87288df68472b00f7f8dc243c12731f1177ecb8780fbd3765069e0fd5a8c1c7a67649b00d2a0_cppui381,
                0x12d96c166c7292b72c7bb9e0e9e91ffdf7ca3926f67ce4894f0b7ae0d826d397c7fb8bba8e2e29abcb8aa9e7de01c42b_cppui381),
            fq2_value_type(
                0x0b9231a10b1066269677672e76235e7864d7bc0bc99d9de649c1ecca732e887c6c5975c486b44fae713541d130497bf6_cppui381,
                0x011a97bd656717d31c74a17fec650e2a04894d04631792f14183ccacee8db3ddd731f4ced99488a133f66d12a66d2eaa_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x159a7f20fc1f1fe0f794fa735c6ee28b2837aa5d70d70d1f53f1d7cbae31ca04782e9261818ae6bda542076fb61c8bb1_cppui381,
                0x03d48c028b98f10345bd40a59c2bf27229947241472986bbff174ea87d1a1d4721e2a03ccd0af2fad6d014fbc93f55d9_cppui381),
            fq2_value_type(
                0x0c5b2aa2ac824a6a3df42b895d61832e71202b8fa896eb7bd52e4f1360c696385db9fb84783aaea4e8ad86f80e2703a9_cppui381,
                0x07fc3cf1d974627a821f223dac339045ede041850e3b6b542dc66b0d3bfd3a582c68c65ace31bb3986c70b4f59754e62_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0f228b023d7881ed41446c45cbc1fd05aecb0708291131bb189a6d826921780e1c28864cb0d84f68d4d1933d5bb57c15_cppui381,
                0x14292b6aaa6b19596e452bef413171d6fbf68e1d7642dc0e815c8dda280c32d63279dcb9bd16effa5789722dd403c188_cppui381),
            fq2_value_type(
                0x05e1e5b8555c4d238726565fbca0b37042fd10cf5b7f6e0396d71f5660db2aeaa053b0be570f33c1349503829695eb98_cppui381,
                0x0896a44ec87960d640a89fde02f969a079c781ecf6c29f8c3115f6792cdd20eb5046ae8aaedab29b0b6d12728b9863a9_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x108b91795a87e98f1fee29fa53b60f7bd6f397f6e716654e508303a0f5cf9adf44cda4c8698319da3b7f2f417823e127_cppui381,
                0x1389b59456bc26b56b1ec04cd3deb42033519f78255e3569231d551c121bee2b42151c2ef3513c48851519133c7b24be_cppui381),
            fq2_value_type(
                0x13d4e1d3f953e836bdf9602d2fbb7496b8a922638cbca415d171de4a7df0a9ce630c9d14e3804a662ee558d415308993_cppui381,
                0x0b154e4f42109dd3a7857f02cd95c480d205ba5427fd49389051f7fa927ea6e2b6c4373c145349e8cbd9ca1098fba447_cppui381),
            fq2_value_type::one()),
    };
    constexpr std::array<G1_value_type, n> c = {
        G1_value_type(
            0x0ae765904fababf7bd5d5edab78752b69917962c150f3b0311446579a083a667412ea18f009817a6051cf852e09e9c40_cppui381,
            0x127fb89d20a2b31725091c033f14986b33878ef4853806987412126bd8135731c09d5222fddf44441eb4e04cee8b9469_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x140e91d114a6dbb835d2ae1ab50729b0553e3e988ca0451b29ac1458caf71b1f1c47ef2255814b4a3ccfb924f57cbe33_cppui381,
            0x0ac830f2ed3435b2b9b3900d0bc0d74407467abdde9f72e922859ae1d2cb094299a7ad467680e7eff331e8a6f92df194_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x186aabfcbe235db4a2dcbacbdd571d0b2e857ada26ee83f0a4121c1bed70ee6609bc0f24b3ffc6ea8af50b1b4de25af5_cppui381,
            0x053ea1258a76b5dc15460676bd2380558bd26cbd98266cb04bbe3d18656f68b8ea11c6db24fdffc28470fa8778e08882_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0642350f1aae9598397a7da3190e07b7b896696682c37641cbbede18f05495bcc822cc8bf34b87709372f3b8cb895a38_cppui381,
            0x140f5cb0dc31c1db82e845f53882f8a7a0679380acb7262411d8f9b7877586192f1d306f5eba7b42fe937c3885542c1e_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x04eecaeb1aab1d88696f17a3fb205e7d0bf517c16ccce694f196cf456b45a3983fe40aebbd2c0a5da701c63933d0c388_cppui381,
            0x18dd9108754b69d09b2ad191b8c4f431431030619765f109a0ab1fc9a64e71d483ad96c95a777a0e73aa72703b97f59f_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x16dd473a6acb01617eb7b690657196e837013062c9a20d0afb16f8604882182b65ab55e112265e510b4a0a95ca2fe1e1_cppui381,
            0x1937d9afd12b5a1334475224f967fae496c1b7ad9277845cfe9acb789d9d207d7bd3c2464b337669c9ffb3d5f643a163_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x19bd07f7ce52c9efe33aa9e93c98c9bc2ddaa4c762c52f988064438ed82dff92c49b5799124116af8ea46d9dab5cd5f6_cppui381,
            0x08f805c413e0a8087b32052148a63dda612c34a988e42e8cd12b3fb3d72942201571bf46298c6dc697c1e51be539295a_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x00352edd966153a5fd28fe8ac333ddc95a4dd00a6ef16f7b59095e705c3bd5d6e8805071f3c8ab2a66f70e7a703233bc_cppui381,
            0x0499e107ae36ceb8da7e1da2b83a8217b428976311420b4281bd428bc18b0db518e125d8a21e92efe1d68bc766ac4ffe_cppui381,
            fq_value_type::one()),
    };
    constexpr std::array<scalar_field_value_type, n> r = {
        0x05beb4119e1356ef39f98c7a7115452a3c4c1e2a48975c85d875aae91185fa25_cppui255,
        0x256d4004ff9591bbaeaaf85cac883eed808de37eff2b45c6d05e6670b3cd1fdc_cppui255,
        0x3973e132b07e7b2244f1172a11387054f7c9593b3b258475db005459a0e4bcff_cppui255,
        0x669073a3f8b48ee66412051fc614f73fa8e4e967a81e82562d23bfe430d1e2b4_cppui255,
        0x2d571b235843a47ecc75978a95b3cceb9fb28a6a2919e0304eb79201c4ef0352_cppui255,
        0x622551c093e4773c3e1ffb69e99fcd4a31a1f727369f47b1df49b03b9534a8ad_cppui255,
        0x0b8cb847f81048e85f5843218c1e273b56ce2608d7d9947cd1527a1fca0001f8_cppui255,
        0x3dd77c298708150d79e47bc4afccf78a6e2f32a17bbbcab1ea41e05551c0e96e_cppui255,
    };

    // setup_fake_srs
    constexpr scalar_field_value_type alpha =
        0x66d3bcd37b8ce4dbc7efc5bcbb6111f5593c2a173f60a2935bf958efcc099c88_cppui255;
    constexpr scalar_field_value_type beta =
        0x01f39625fe789118b73750642f16a60224a2a86a4d0487a0df75795c3269e3fd_cppui255;
    r1cs_gg_ppzksnark_aggregate_srs<curve_type> srs(n, alpha, beta);
    auto [pk, vk] = srs.specialize(n);

    tipp_mipp_proof<curve_type> tmp =
        prove_tipp_mipp(pk, tr, a.begin(), a.end(), b.begin(), b.end(), c.begin(), c.end(), wkey, r.begin(), r.end());

    G2_value_type tmp_final_vkey_0 = G2_value_type(
        fq2_value_type(
            0x11a94db67997dbc16d3264f65713f9c91631bcc0a41b40d939daa48e473185f3b30dcb58736cae7960e7a90ccacbee74_cppui381,
            0x0c901bc14c169c61ca8da1bdba6a9eef854d459c979e39ddce9c2dac1c641292ba9c03df6e9c8ebae66631b57be768e0_cppui381),
        fq2_value_type(
            0x0352cf50478240133767d087078812622e6f267e966c9c4154fed5d825fc03578b1215c1bdee071bf8215b6ba1b6a282_cppui381,
            0x14df34d9d13b6e0a4293c3c8a6cc2202f47451345fe2029cdb21a80060abc510e9b5aee8f7214693fd64292f30dbad7a_cppui381),
        fq2_value_type::one());
    G2_value_type tmp_final_vkey_1 = G2_value_type(
        fq2_value_type(
            0x0b96d26d779c06a9b2450c1379bb24201491a85735f25a6c1302ada345a444fd4501c88beea6c468765be32dea1f913d_cppui381,
            0x12addb94b450327370b28c0166aacd86451ac1d0a7ef10d00f64f2f595e9af7c1dffdf84c6b74c64ad72eafbfde73709_cppui381),
        fq2_value_type(
            0x1373290404e2b988334697787eebb3e1be4b1a92f8c58295625fd535885774951cc8efb2c31e650b69242b04c9fccaad_cppui381,
            0x0a4381086a8ce37cee50bc3f05b573f242e0055b58bc7aad2956582148270f573e0c7042b5d1c160bad05e627f8f4793_cppui381),
        fq2_value_type::one());
    G1_value_type tmp_final_wkey_0 = G1_value_type(
        0x0801b62235fc889ac1b82372d71899cf163c1df212dc0e1f7121d2a7a67f5eea7d6562136782746d19cd9fe07233c125_cppui381,
        0x177bc3d5fa4f75ae6b3f761df8faeda0ca9cd69fa6ab0ee2fa880c2367f699d24d86277132a56e8d5940b3f40ea0b60a_cppui381,
        fq_value_type::one());
    G1_value_type tmp_final_wkey_1 = G1_value_type(
        0x142bb1955ebae7a2ba3951137605da96ca427c33f6c86eda9aeba7c922ffb26c3cbc79312191644548fcd7fb08f49918_cppui381,
        0x05cc2acbe11059daffa817815a9cf2749a3aed561560aeac0a3e5c08f694544b9464535631da702126c25b555950acd6_cppui381,
        fq_value_type::one());
    std::size_t tmipp_gp_n = 8;
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>,
                          r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>>
        tmipp_gp_comms_ab = {
            std::make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x0957532c8d02eb95c0627eb17b0e6bb14d932aefdd6d76d38dfd3fe2077b263d06d82918260190f644fe576e6e976fc5_cppui381,
                                0x02587b67a0e6b12d3d7c461962d33fb18e3c593c9ac36689a02d8b73d89084a8b692db4b6ea092b9134c74dcbd3e46a4_cppui381),
                            fq2_value_type(
                                0x093c33d017e2ff996c35061ab21b4e36e968e6eab1bc21dad3e33639438f7bceb7e4c7c8bce8a04d1342c4d0ee31bc40_cppui381,
                                0x0582576fbd38a08b23fca59d91f15597c842d48168e26d8056ebe692dd2769fc630d6fe5086490babb38bcf85550aa61_cppui381),
                            fq2_value_type(
                                0x14579081ea0d470221bbba37c3699bccf31a044340e7d1fac1e7fddf2cae9d40a50dcfc723e976d18d86d46d10498751_cppui381,
                                0x0c6449dc3964b034054223de8977499dcec1acf6b7fdbd5ec9bbacffdb03fbd48bc52ed6f1da99b3517c8ee6bfbbd690_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x053e936386ae83584778282cbdce80f183ee757e515b76b9f384c38eddf75be5a87047bf239f5678cf7cda6e7534143d_cppui381,
                                0x06988693f7f232e3a27c80abf562b2353bbffb18bd87c9635621ac756a4f5ddb19f6a2259f789f073717d5a6320022f8_cppui381),
                            fq2_value_type(
                                0x0d2c79ca9245a3f02669d57396775710b4928e920e751aaed4b2c85b76b5cc52c1f310f2acce01207e05760e70720ed6_cppui381,
                                0x000836a24857b0bcb2944176457c32f60762630fd97305b415681c73800243f96835b6771d333829e59d29f2d31ad75e_cppui381),
                            fq2_value_type(
                                0x18030873862d91c08c54fad4c511d12c8a617be4dbb142a30f1652eb687d1bcc6413bf474aecbbe6fbb0a227dfae6ed7_cppui381,
                                0x0aaf091bdb18be326e3ed80cc65e966bf45b83e0b692be10a7dfcd33331d379720093a2510a73c4d66c87a244faa140a_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x088bd4349c8a9ce80a029e4c30818ab25d919b25b5fb753175012a423260f101c410d0f8e4072c30d54b4ce3f70a9fe2_cppui381,
                                0x123c094cd7bcbdad08336e1eab34418ef3b75c62662b7130a5583a3150802bb2a4c0d9174ac062702d728e35f59ef049_cppui381),
                            fq2_value_type(
                                0x05313d19ae86e54f2a84f097982f808f190c485832aa2424b9001c3941f21d1de1c2e11ac8c260d49fe4f7a8fb4109b6_cppui381,
                                0x170265c68b46da3144d107318dfbccca0ff831964dbcecda9bbd87f88c0e38c88cf93b69025b0315098fd6fbc0762c6d_cppui381),
                            fq2_value_type(
                                0x1793cdea1394964c5ba8890e58dce7a556c737793b82e46f5288703594f11775674f98e85eedd94d7b06f56086eccdd1_cppui381,
                                0x0e06ecb20e3c9c6aeef7d59eadf416fe7721d0a8578b0e0b4594ad3c8f682c08adad78d1ab1a5e3f26c0764913544dba_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x172c2036f67767dd888cbfbf82354dc3cebf7630855fe1f4f93438584f18c0d6de1d9c34a5c7c98d6d0600d606bbf178_cppui381,
                                0x14a8d8b6a3e969b8b0fa3a1b4eeda8410d756b4732edc80059c4af8b63c7cc6e6ac7910d141707dc812a34e873ceda21_cppui381),
                            fq2_value_type(
                                0x03ffd62c5037391900f0f0f544aa3daaf03bec1545f1b966c49b5c1643b5ad3f6eb9816aa85e45f5c3b66fff6f23c37d_cppui381,
                                0x09261a65d552b85fd64613a6667c0b77c5b106a265ae1d87280c12c57b2863959a74b4098c557d77d3931fa30c353e71_cppui381),
                            fq2_value_type(
                                0x0912e182cdb82304d1d5e92337a6a8f6b30227aa6dd447b544315900b31b021771fd4887280649b596f8a0cb0cb80a3c_cppui381,
                                0x0a87a923d841b32f68e12484ab4730e308d2267511f4b76b12a0dde77ac8de2cea56495dabcdfeeeed506739f40cf1b0_cppui381)))),
                std::
                    make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x00fe4b71ffa4137b4f38cd1cfa620a4a4d53a336c2dbd9fca07638ab6c6008170a671f80153147f5aaf4877d159aaeeb_cppui381,
                                    0x025811f675f731e173e4d30a92ad5854f60d080b2d4ada40cce2c0abc57990d16159d49b50a2cdc069eb6e75332d02cf_cppui381),
                                fq2_value_type(
                                    0x07740d3555f5d523bca3c568aae61a460e1047260de655e4a03d0c0f90a7ea1b8128989ebb635d0632bae43c69583ce7_cppui381,
                                    0x08b03a8db7ed17a90338fd70d03d66dff90a5db16d225ec9ae0b0611c0b3b40d8eb31236af58198d60e9feeb0b087598_cppui381),
                                fq2_value_type(
                                    0x16fe849a1a844e70f6aa1b98d0a14e9ce13568a3d7b76881fd63220fed7bb2c91cf3d5854edb244fe7d5170eb7de3bf7_cppui381,
                                    0x191aaf792613e3f2033317be817c2c71ff6aa2eabca853a27a3a256c7fe8d3c1c7e191f7146db95903ca9661f118183f_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x158ee8bac07cae83ecd40c072bebfb651cae01bc65b0a19ae974e5b0b0c887d774f9df02f50802b8e02996feeffb7508_cppui381,
                                    0x0903e76c0e37a5d416ee7fbe57e4d06bc21b9dc3f932776bdac0a433756c31f7d4b738d59cd8ddedf93a9a60bef55835_cppui381),
                                fq2_value_type(
                                    0x110d0df783583c5ba0b6b4f00c1fa40c496df4d97e1aae1fb0a1d811e34c93f006a666788a7add38c17560ad1f3f8fda_cppui381,
                                    0x0f5c6bb6496f3c69fd9402679e11f584d404234d5903d361154b3d275c8b47222e324d9df2f851497d985b5a83bd6e13_cppui381),
                                fq2_value_type(
                                    0x0900d3f664aa042672c0b6860790db5c74c8628dad996f7c83f8836cab1fa976cbadc749a8ecf85ede5b5bf67794c675_cppui381,
                                    0x0a9db1cf9da24df7cfadee0f658badb29af4fd9e273723639d47cd10734f92cfc438f731ae4505ef62df071e9e8cbd39_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x16305214e8b8083778d253ae9bf8ee30a11419beb9469f0031ae8b29d28139e9b4b7b8d790004bf9efa503016387cc59_cppui381,
                                    0x14da7b4414c9a73388cf5cfd6454975e93f7aa2a3027d3ae96bbe4164639f2713817f0aa627230a9c483cb7e200ba860_cppui381),
                                fq2_value_type(
                                    0x155eabe7500b83f47309466ce86cca7bde55165651a7ce058ec6ef5ac0d6afaac88a67b3654c615d0fb78800e41e176a_cppui381,
                                    0x1959b1a4b02b1db436b39bae4e3887f7580a4035b3b65cc48b812e6e850ebfab96560521c2bf2418ef24efea9ee78f98_cppui381),
                                fq2_value_type(
                                    0x0f1525dd4ded5e30c113119742fbbae6a1dd2705cf410821c7ebd57e12cd8afe938d6beba3555ad84f4454100333049b_cppui381,
                                    0x178040453bbf6e73c4acbcf46e3bc053fa26d678762132a70407d6929ae1b19a54d00f9ca58f058a3f4b14e6f14a3ed5_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x011fd5c0d0ff818b3285dd924169d90615f631eefd370c529a7703d51f440c805190c15b8ec3cfdcdf59cd67fd81ecf0_cppui381,
                                    0x1763e7d98226e2003307197b3c1cec084af340d17f392b74bb5119090d534f420bd2aae92d03268d044308b3c501b35f_cppui381),
                                fq2_value_type(
                                    0x09f454230d61a6e626e01d20168e6199db6345888b829a0653dfc18afb7c224d36a9070edffa2c99d859b7df5ed91e11_cppui381,
                                    0x089e677f497fff7247e001db9926026095751a31bdfbf9244249c1613d9eae8b507848874534c28692d0321859710f6e_cppui381),
                                fq2_value_type(
                                    0x0ab900f602fda0715066768b55b2d0620077e57a0aebe58f9b520818a12ef6129438d130c17e3ed5f9227f82e12621f3_cppui381,
                                    0x0d7848ce6209410a5046e3f9046a7c9c6a0b730b3ec45dd91e7f791ee408896eee4ecbb8c4bcf6a78280305637668ec7_cppui381))))),
            std::make_pair(std::make_pair(fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x156e1bc01e9bf7f5fbdb240eba8618bbea8c1e4e02424302705e8792db700366a8e39f06dddd9f73804ecbef790345dd_cppui381, 0x055a5bf7d588660a879cceeafe2e03f77fdca228cc692da9c4e22bd4dff4b3fa7fef82cb03d19abe85e49da56dbd06e1_cppui381), fq2_value_type(0x189639597109dabac78406e60c15ccffa7084d310b197d6f59c60955c04d263d1ca4c2b0d94beeb50a3ce2ec10a9cc88_cppui381, 0x15a0c0b0824785ea57a685eb0af39d1478cfe947f57e8691e94d15f660a617b526ad3b0527f95df6d586363ff6a6554a_cppui381), fq2_value_type(0x147ed58c1ba4663879f4b4df925a2e94987067b7eee50c6d49952df0291f834604d87f8a9cc87e44e4558ab5f80c5c89_cppui381, 0x17af81b920871eab1f38a577485c44c7c09b640372dd96958da9b2b4837040fd628faaa0a1b72a1bd7300a96eb2c5c42_cppui381)), fq6_value_type(fq2_value_type(0x0ede6c6073ec86d4939b5b5599de443bcfc85392606b9809767612c7b07bb1c0e08eaec2b492516b7faaf188bdbe3e38_cppui381, 0x1675c0948c9985fae3bcc8e0d4ee5c0a1858d33f7fde863bf29d35970016db19d72ef000ddcabeab2cf776cf43f8f078_cppui381), fq2_value_type(0x0aff723543c7fb1c786ce9c387db34bfdfbd7482351b4db92090a3c1c1d2e56e56bd3cae39319156c9b292933b050e15_cppui381, 0x0e39f41a308a27cd580a6d1dc37c8115e437bc6598193814d1c7e5d5d28050b10decdcbefdbf5436a7a44920f1660304_cppui381), fq2_value_type(0x1817aeee6af71229f109558831d3f8c548577ece71658d5731daf069ff4fbef8a384445c820add288b9695a8fa5c5568_cppui381, 0x152bbe92c49ed9d8aaf7e71bc196a9943568730dd034e191e6ef93e2bd5546ce4ff0057d9c465147511ffcb4f66cd3be_cppui381))),
                                          fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x1310cd0eafab9b09e91803d930e926a0dc3d89fece355e1a8101673c885f1b86e9361fd2f2dedbc6edc73db336537d8f_cppui381, 0x116bcd6589ace54f061964a4ce85a929577fca43fd3d97cfb518f69af121d074f64523a1cbe03c064e54fb27692ed7a0_cppui381), fq2_value_type(0x0548a0c69aa99874043f35e7e168db5caf325a45faf5d99b2a0b251eb75f29925eef5a85ef540f519f8e76c421c7efd6_cppui381, 0x051fbf6a5275c86f33b8405cd76a7b0347d5c4974e43e468e74a8d287d531cb751c7e3b68be8f01aca4d1fa3a4ede275_cppui381), fq2_value_type(0x0421e6d957f1be56ecbc4e46fe3bcd878fe96ea904da7ab7cee7ec01b78805e914a7f5f87edaf372323da7adc422bea3_cppui381, 0x10168429dafe94d57b489ac7f6397ca55b5dfb00ae4991076ef465a48da98acfbd89485616ad50db9d722632c4f60f6e_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x142d381d10a9c58284a41835bce6ae63a205185a51ded39a6552d820b7607987e994ca2955a87e6cafaac24b1de2b6d6_cppui381, 0x179ef5865e5638fee9ca1907430d70e435a27335ac2a67c4bddd53bfea7941f929effcfa5cf16541a0927ea22fcffed7_cppui381),
                                                  fq2_value_type(0x072da45ff84238c87099aa21c6b2184719707e80c4a715f1cfebb0267a18c16c3167560ff55b9a7c5d30609deb1f0e77_cppui381,
                                                                 0x186003ec211c3e6abab26ba6e27de48f6cefb576528c780a97d4facc8156dec281229c551a6746ff652ab282888b7c9d_cppui381),
                                                  fq2_value_type(0x00b461a33d25a5c64a90abe32b9265dce184400b1ab70fdbc36ff3324ca613e98422247d766f9c8a67558f3257a1271f_cppui381,
                                                                 0x051728d4ea553931c3c8a87e776eda82d2f62f63fef88783178fc141849c6cb8146c6850712a40bc5b82a399daedd5bb_cppui381)))),
                           std::make_pair(
                               fq12_value_type(fq6_value_type(fq2_value_type(0x13ea098057e177102953db1df0589348a6655295006656c06bfa3390c9eb835dc860fa057204307df9150fae29a61f96_cppui381, 0x0f596824e576ab4c4bf8d97558b9dd4fe0fba650a0e50100058656ce90fa84fbe8059bcb33db75f4ea1cfe9551899e46_cppui381), fq2_value_type(0x15ae32b40c56157884f87610c7b23083d19bf1a279ac57bce705be662d90a02566f1606f54fc3a14b80ef68bd10ab4c5_cppui381, 0x1133ea72e53f69fdf916c68b8b6000660191a3c915e87418267df115f6587d612cfe635cfe111c3655c3382ec7c63ff1_cppui381),
                                                              fq2_value_type(
                                                                  0x0b53e05e2d076ec151848698293e0b1a41b6c1fe5deac89f61fddae1647a2da7c9d239238a481ddeed94e7f06f3189b9_cppui381,
                                                                  0x0ab2513c0eeeaf4466d6b346688bda400b885efba592f23b4d3d96c5b9d4e87e654954f121a214c74c567612ccda9f49_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x08a6144c53f747e0dda05d35562849d1ec46034bf43f42f8136e9a8ff3c854cfb7dfebb18982c3b6f0407c187b8956d3_cppui381, 0x13bdcf2ae88835a1b7d972e456a45904fbd08b0093679012bd6ce3f54dd801cac4621fe387067b6d5da937f396eaf608_cppui381),
                                                   fq2_value_type(
                                                       0x0504208dbe8a6fc93d1b2ac17418f28daac115b36bf836834bab568ab794bd223ef947d4ca99339efc9f7ad713e0f9f2_cppui381,
                                                       0x0b0a177954d9166485dbd39b41fffaec6d4a43e10f68eb2345d932a06a2a79c38d20c63a5698b0e69249948af41197e5_cppui381),
                                                   fq2_value_type(
                                                       0x0f5dfdceb42c403e7b5450b8b9c8b7959a42b4129cb1c6a7bb0b85c27624a577cf077cb5cba6da2bbfba8b3cfb6f41fc_cppui381,
                                                       0x0224e3e4f499afc21fc8c55015c8d186c344866340676f89a3a542990258fa85d5f9dfb869989bf06f630752c5b02ffc_cppui381))),
                               fq12_value_type(
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x046bbd0b03da2b070991eb44cadbd7911ecdfb41790cd99005398bc1255bea324c162ef11083a7eb549d0fa3b36bc728_cppui381,
                                           0x10907290040d1825884e29638c86ba1a938090d2110c9d68dea715eae9ae733fe802eaf5a5d72d3eac73fa699fcde518_cppui381),
                                       fq2_value_type(
                                           0x050485ecf55fc524bf10e9845b4bb0138d151aa80a9a65190557d17906fe34b0d182b77ac3aad730a9d2aa51ce9dedca_cppui381,
                                           0x0dd212f5a44a9b6c29dd0ceb718520f214e1ca05da5970cc8f999226c0000dbf6991770b06549d3927acd1c2b0508d5f_cppui381),
                                       fq2_value_type(
                                           0x023f3c120d9728a0ab7ebdc2d3e929f757f581449186881d935da1b5128dadc9fe9952b2aa9fb1be2365b94fe8efabdf_cppui381,
                                           0x10330d931a92ef2971a0268dee6d8012e43c8dced067d9b97bb5c0c5800a75cc8ed18eed9fb17bb957c4e7ac2c165ddb_cppui381)),
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x06a098b569741a7a9c7ceb3592229d118ea5bec6b4c152db2d4b2097822a0bef9f8498bfe6bd3a68b88bdbb15ecf46be_cppui381,
                                           0x0c2ba20d6e83d0bc9bf1e5e71d71fb2f7a29ae232df626f76feb0248d1172f8d99ee77e31aa450b8f8cf3fa3a0b1fe3f_cppui381),
                                       fq2_value_type(
                                           0x10f9dcced6b992ab5a27396e26393ea1007c1c92feba80e603c5d7bc6f0dffa3f13be85deb938767ef7cbfb7f82a09d4_cppui381,
                                           0x19f72da9170d935d28c048ada8b806506cd088484b873fe0d88a0298bc6960cda75c1f07779b9fa4f702ec0bdc47e7fc_cppui381),
                                       fq2_value_type(
                                           0x0084c03e3085f77d751fb5dba32ac67fd5b257f19a448dd54a4339e3cd53e550674b7b745f31ba35297bc64c16af9f66_cppui381,
                                           0x12c3e1c362125f24761da9b2953cec8bbc742227118f0ad236430882efd27727dbed2f470f996ce2a86055b18933c596_cppui381))))),
            std::
                make_pair(std::make_pair(fq12_value_type(
                                             fq6_value_type(fq2_value_type(0x11636ded8a28e71c4ec534b21f25630c4432bee1d8bb4c12589b562390215bd05e0a5d36027b75ea1ebee52fdbd30999_cppui381, 0x0c91c9c3a2fbc87c918c250e8e690deca092bfbfdaadc545f0a8562c4b41c1ff26e1a998aa8f8cea9823e957f737c95f_cppui381), fq2_value_type(0x169f54075fe64793c5d28f67f0b3c26ebea2231144cc35ebd998fbe4822b6a7b97238a71c43b070476732c20f59ce8dd_cppui381, 0x00bdc66235aca5675b415f67e70c1273a5c79325102113546b19c6af66e5d7eb9795aa00eca3d52d6e924df262a854aa_cppui381), fq2_value_type(0x00085900d93bbff3d2fdca81a7751d7f8ae70b6fa65a401672d1ef36d837182f8405f82fafb6aa1f208e0515f549b113_cppui381, 0x12c2ca1c15c4a8666cca16f4747cefe67a2a4cf52d05d894868a5789fd326b0c651931aa49286e018099f449cba406bb_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               fq2_value_type(0x059dcfca66157c202444dabb92d3b07c53b1757fb4c9fc03ba66c0a029a56480a17200b4a7eab1529c56bc2cd734c83d_cppui381, 0x0245c89492eade1b0ea9e38f7c7fc3c4a8c2e6ceca32f8ceab88d98b35d9d03739c7fba4138d84e6c8baadc55643d722_cppui381), fq2_value_type(0x19cdfe3738f8421b5c3144c21272994a96ebf8efa22dda8a71763ef7e1c8914334a1ef8a8b672334e3f4e35bc0007838_cppui381, 0x0ddc1d5a912a677505265fb7b89c7c9f297f60dabd29e520349c82f33f54ac8ce28c665ff3b3566f2e959898d9e0872b_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x16429ddc15224a7a121948f3323f07e2cf5f683f0c0ae73f9407795f964e762db8493b322dc8f27d7a8e585dac935127_cppui381, 0x15573eecb41236f429b3acafb198ded663407adcf5bfbd6f0f3722000d94993f07ffa373dec967dbdd23351bb2c6fab3_cppui381))),
                                         fq12_value_type(
                                             fq6_value_type(fq2_value_type(0x054120cd7a23cba24c173d8c8e91f98b0d420e9fc2e7ab67dcc5bb5463c3909f3d36353174d7ec3601dcbbeaecd9c8da_cppui381,
                                                                           0x11d4c1592365acc081b5f6ff5ae88f4962a7bbf7b9b2504e10853c34c605273a9a08f75fa73516fba4dd096df58722a0_cppui381),
                                                            fq2_value_type(0x17f3d78c977530c6828b91967c7d3d5a95b4d7343046f3cd0027e0ce956aeaf8f02392dcc6ea71b29f57385eeae54132_cppui381,
                                                                           0x0cc7f4fe8b96076ad89c40a35e070d3f668c0f84f6b5ac7bd715e90b2839ee19694e53187e5777d619bc66cb0de25ba6_cppui381),
                                                            fq2_value_type(
                                                                0x1624650546e8fa3655bb73fd483de18512d5bd10c7207c0a9102ad057515ace8a383b9f56090b4193e153c27758dd45e_cppui381,
                                                                0x191bb4c835e30b15503dc114a605679297f1dfd9f1e54a247889427cd2c5ff7149fff03430e8e20514ae6227b22891b8_cppui381)),
                                             fq6_value_type(
                                                 fq2_value_type(
                                                     0x19dd51662e0c7f3cc3c6bba83586b08af9b7fc0c6b169f1296aadc9c84390edd3541b3112fc4b9c8e1a17924cedb9895_cppui381,
                                                     0x1676fa2cde58c7b32e2c0cdb25c318d2276556bb6751648155f161f4a0f52189b2ed3218dab3a5bbacc6bd0d2a938a8e_cppui381),
                                                 fq2_value_type(
                                                     0x0c37cb4e9ae4913f212e5a051a78a962992d931114dfd59cb82e0564703ce13ea3777a84a674be490a505ec8980bae2b_cppui381,
                                                     0x14f1abb3edae9566a53f67f14f564d4914f3e8e99a036ffc7094085407daefa8156db0cc884c0fb543d52b11a2367918_cppui381),
                                                 fq2_value_type(
                                                     0x1433bb62b65c2d2ed30676b1191f7009f13602567dc5c7d3726f1715e5ee4360ebcfb9877453473c2d0a304127ed3078_cppui381,
                                                     0x06e27fb53d7c6935b501a4f5a0a3ea25e4e88d8c8652fbd4a2de2a03ad66a88b28d47dae2fc248ed68ea69b1310ff687_cppui381)))),
                          std::make_pair(fq12_value_type(
                                             fq6_value_type(fq2_value_type(0x139dd779524372b96bb40c710d1e4c42e5e7eb6c2a24cd985ca0dbc22512d307630fbf129ce1fbc1a5cd4132f696867a_cppui381, 0x0c0d8dcb348d44a162f1f91c4934ba484b0f89c030795fe8fcdc5aaa5c449b27852a001f2932997f001dca6f379a39c6_cppui381), fq2_value_type(0x014a092244795b1a4574bcf8f3f68c138c898a18a7c5fb09b4f6cd5ef92465f3d2731d6eefe4f0e6e434fb7f9e797826_cppui381, 0x01c26d6c33619e83ef214d95fb64b53888af5f9ab7d8500a3ba7453bfb8373c0ac338b1f61604adc55916266470b143f_cppui381), fq2_value_type(0x032a40e66f3eb3219a88322cc1a672d0a4bab7688665a8cf5629a8ceeaec151cc69c5381ca841f7371716c72a8755720_cppui381, 0x144b384eb544fdb22bdacb0f548126a0108da553e2b264edf5e7fe018107568e393edc9e64ca8896dc27a1ca1c7c575c_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               fq2_value_type(0x10284f4e83f16439adaed1efddb79fe9d280885a0cded5eb5940d93dcfbe318bdd8fb56e69c98e6f8232d3c3d2f59d3e_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              0x058422d0b4fe6eb5752561a91e4a8960b1ffc667a65a2c18f31684772c8e65b594b4b8687831c2aa6e716722b3050765_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x0e66d58687e71d2e0741cda1c8df641415356a394764eef69e0cefc3cde2b820a8d816efe9012ff57b8d2c9926deae32_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x01c913beb56011f4d41bc05222350fac1b77710ed11cc693ee02c9617feab15cd250ffb213a14d7c3097d53e61679a66_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x17be5d11bd2aa3e0da7d4c77e11a54420379a0eb9c2a2db42d9f14904b4a8d896274fdeb00178698e62a5cd4ad85af82_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x07a35d77b81022ce61d03549895bd181892994ec28bf07e9fa33c84c541aec0ce0b92bcd5c964b0e97920826c01a702f_cppui381))),
                                         fq12_value_type(
                                             fq6_value_type(
                                                 fq2_value_type(
                                                     0x098460d358cd4b4776d0b962b3e23cfd338e2dca66afbab837f90f4cf5072c8d3fbc97b5d78d6a039024ed85b9afa60d_cppui381,
                                                     0x0abab264807f67f1b0fa283237868a6d9b4735cd93d00a93b4b8f15dc8a274ded9e1767e13083257659a8af19b4bf0fe_cppui381),
                                                 fq2_value_type(
                                                     0x13d0fcc3fb0a3d4398948986824ec71d9596c4f9b11f39be8c3eeed668aa3451646f68abf92ccc94ea6f2d33764de96f_cppui381,
                                                     0x077907e13946c298451b4c624015e5e18f0cdfa6b7bed500500d2e6fe6016b787eee7ad8d464bc775439c676fc5c8d49_cppui381),
                                                 fq2_value_type(
                                                     0x06cd66c7dfa70c5c11a1ca5ff0b00a62c01eea92a4c7efc5ffa2f0946cc7dd82688fcbc1a3d91121ae369b4040912356_cppui381,
                                                     0x19686988bad7e7a7fee0394a719fb135a6256d832999c3325af45fb6877c6a9e452aa4c33d738e0e43d239cfe81f030d_cppui381)),
                                             fq6_value_type(
                                                 fq2_value_type(
                                                     0x10c632bd0a49755d7f3cb392d7528be8e535c1eaa78b6320d58884dfc9d04bf8065a18554ccb3f9b078d81b47d28b598_cppui381,
                                                     0x166b6c5bbc7deada98cd1aa096101b2a0c3da0e75480fb633d9188fcc086888e49dd1b6c286c62bf5eebf6e4d4d61930_cppui381),
                                                 fq2_value_type(
                                                     0x17da0b5e7c2cbf59d5acd35d8be5d6afa323e9f3ef1032de53da1896db56414084549fcd878ede90aad2b2312f2d7935_cppui381,
                                                     0x08eeedbfc0d9fe50e3f36077e4a1939afe6d67029f790168c3e1e765537556fee20fb4a2e91ee990e6a5fcc8ac968926_cppui381),
                                                 fq2_value_type(
                                                     0x026c536d1017d9a222e82b13694ae8152197a2a93150735b3e237dee99f0676ad7c6b664b3ea3550ff475ca67447af69_cppui381,
                                                     0x0efa39882816548d60cacb966d2f6f03c67c22a00b5a9bce42f80cd908bf18b9fe3789c1e9a1d1b3a0a65879db02fe13_cppui381))))),
        };
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>,
                          r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>>
        tmipp_gp_comms_c = {
            std::make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x09f4196e5ae2e24dfe000ebbfb373dd2d1130818db01c12d9890116da1dcac5ad7ec510915864d0ed84ec83ba7b1a158_cppui381,
                                0x14de7a792c6b1158a5e9f6d5046deadfa470e60fddb34af053c87ca6bdac8434460576e37388a1c56484cae823d7aad7_cppui381),
                            fq2_value_type(
                                0x111940a5cc516a7e4fd66fbd45d16d3d8b7dde9e8114d23b8a3efd3fa7f73e2c53c665159b4a17a4a3e6cac41c41c9a6_cppui381,
                                0x13f219ab7e4079c7106a11c1e43b2430984550c58dde716aa134190e08457148e05f90eef95111563baf83b62d92afec_cppui381),
                            fq2_value_type(
                                0x030571df0bf5ae3f7c2c9fe15a6270a9440f0458199e3c0764786107d8aa655b354d3d94f2bd2deec142b1530d7d8601_cppui381,
                                0x14a5d24e21b7fd584b06157b0238e0c915741da0ce5d7f1b8ded8ea3ef095728526032cbe5617898b6cb442aba10c336_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x09898cc2590f8ac7e5ad06605ab0189a5c0f3062b5435e56c0838c21e1ea829007a3287ce5dbafcfefa1b1b00eca1add_cppui381,
                                0x15f8f007599f868959d30e9dc60a91a91d656061b4e4f2f04d16153d0ef87cefda97dc162647ef6649770f159c1466aa_cppui381),
                            fq2_value_type(
                                0x1388393e62471d3c4fef1900bc647fca273c9601a2022219e4216064f5ec54268592393d4503be7c177240e21939d4b7_cppui381,
                                0x0cb19a28e448e5da5895f6ff4f877516fed83f35f407abe9d61a3f0733064fbd023362d6765fc606fc9ae0b42b94532b_cppui381),
                            fq2_value_type(
                                0x17fb7388c421bc5e460c6aff8371c1227d0188623f61772515728d4f5c48bcad0b0b1f81c7942402b8f928dfbd1a7294_cppui381,
                                0x1421a05bfa57e1c5bd5520639e7873b2569d2d8e303cee2bcd440c43fb0abb1b8b108ef08b5577580900ca416da1dbca_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x0b67fc0d3f5bbc594403484f779e7bd896c40657f350f2ef724d8c68e241a7d08cc44be605fff1d0029ced4b8b16a440_cppui381,
                                0x07c10e44fe5a3830bc66cdbd1f68a05f4577c0573e9c35b971cb12e29a252e74700675c1bf78b8972778cbfc616bd23e_cppui381),
                            fq2_value_type(
                                0x19ce14ac8760d6793118657e9a7ea6cf0de196e4b946620679c26bb98e02ab127aacf1d888c0869bb1f3cefb0f11c80a_cppui381,
                                0x027115e304b98412aad798e2ae349dd5ce8e2266b2c721f176d18432be33c797906cce7e580d4faf1ca60e5f3e663ccb_cppui381),
                            fq2_value_type(
                                0x0fecf76d39d4802ca84e46c94b6594e4adff883f4896e0b55527c71f8890d9303f8b60dca0af65596ea24cbe29bfae6b_cppui381,
                                0x16fb5d3895c99229e7bca49b1fa6054da54db05956230a26b4d6d2cc3d0162cd2b1fed8d94f4a38ab0e9ec1474371b78_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x14bb5e5db3e3a76eb33ca772a7568e2ea7ff0494a15aae69671b9d72482934bb586c682d9c8eb38bae7cbfc321a510d5_cppui381,
                                0x126e98654f3498d48d67dac2e77c213a2fd2e3e7130ac61380b1f9d7fc50bd3519065a6a2e05031ee3233b463e50a279_cppui381),
                            fq2_value_type(
                                0x06589e8cc2998b1d5d978d52c9b2f8f974fba419616ad0c1e0d70542369f1a8fa986a673668f3e79f689b72e0ecdbff3_cppui381,
                                0x0287a86cda9734c1488fecbc77bdb9e75f4cceed6309ba9f0dbcd2c030e0bcc938615f9692e7d75f78620e5763d9c544_cppui381),
                            fq2_value_type(
                                0x137ac65166ec0f5cb4a5b49d75eef67353e772810d1f6bf187c249e775b2cf73de73c62b7db7c9587cf1e88e29dfb399_cppui381,
                                0x0fdd37ee79d99c19131540ad796e0ae9d1cf23e4adf0887327fe3691c1873319556b0a48a563760d2d1f07ad58355845_cppui381)))),
                std::
                    make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x1705512e571e8ecb125eb2fe3aae8c9687031b48c3c20ff55aeecb5566264dcdc9f847590dcabc63b3fd80e7b664e37e_cppui381,
                                    0x0d2d947c1edb3c2b4965cfbca6f8731ded8a1a86b2adc93b2c42111c1c5fb0baee6d2fd53518f438bc4dbb53753bbb5b_cppui381),
                                fq2_value_type(
                                    0x17631dd1eb74351ccd9232560e2c4620a568fea30dd06febe64be841358ccfa0c14301b42eeefaa3b9abb1f2e6cd602b_cppui381,
                                    0x09387fdd8f7c6bbf3795899dce1c511dad8d51412423ba7e6ddcbf90f55a3080c5ca5aa1fd02354ec52e0ba830d4a1f6_cppui381),
                                fq2_value_type(
                                    0x10b14c1504e1f3ced02f2887caf96c430363ba43332bfe05268ac007888eaae478077d04807fa2ab55482a0e1b595dff_cppui381,
                                    0x0a100ee70649187d6904f4273bde81ea0ea2568774e29290182f2bf4f0b38b4cfd70d2abcea88fa019ef6f6ea426e8ac_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x0c7a04b4c0e509031426f583d9fdec0260898043037f25efd98a2d0b9574d85cffbeece20acac69f0d12afed3549efe0_cppui381,
                                    0x08eb58319046ed71343b59c5a9380e518d5ddedfc29d60df7b1e83c106553a4e760886830562769509ff28977d350222_cppui381),
                                fq2_value_type(
                                    0x0f38b984a1d6a982a6bd14b05baff37b25a485d532f80dd9482f0441a859e25d06a4ef86278c1d9267374e79471c76cc_cppui381,
                                    0x0c3a608aca392192523f2ef59f61240f205f996ee983620b48fce06a5e0038bcf3ee2f4de7f5f6a7abf07d214a247753_cppui381),
                                fq2_value_type(
                                    0x14b5438c6b9e8766205d79e25e772874c3e884ce7510da9f436e71b698052ef4fba99f8c2deb1040357ef92300ac471a_cppui381,
                                    0x17528aab1d4b1391e0b09bb557a54dd2822488b35386ec0039b906789770345c0b6aa21bd274ffbf52954ce7a923b079_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x0ed9437cd41d4831c5c2473917ffab0f6fa9d5d21aff666957b767a708bf370c1bdc46d7499e8b95ff5ae539205db5a0_cppui381,
                                    0x11c87e7a6b21b4d8217bb251a83a1b88250a38d683754ee48d7a9476aad2b534efac8e8b6fde8fa19c2152b00fd71e50_cppui381),
                                fq2_value_type(
                                    0x036233bf470a563a58af26ec791ddb6c361581cb94c36ceb289423874beb134c2b7a621cb42cfc213a14d3fd65c5f756_cppui381,
                                    0x07d57a65d13f8ab324412e5207cfd82c137a110d343a7cdf3e40dbced712d9f8a0b641687567fa050bef53723e9db79a_cppui381),
                                fq2_value_type(
                                    0x06bc9b70e5378a8e2e516177b9e7470e62d25278e467b6f8f2d2098c22c257c0236e041290e0cd3c721d2f77b3fafaea_cppui381,
                                    0x054a3abd24deb9dad6f039af6991fe9efe6d3f93b408b1e1069de1551bb38fafb87268a85251d336c4ef002b82d172fc_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x1705aa4618891aa01d9f5be3e34283b62ebe65ab370c001a26a3794ba41baa212d7c6e8f4609bebeb2fa59ed5a33bf3e_cppui381,
                                    0x065a85de96adf5d8fbf9d41cb0195dffb0a8f8e030f545ac76c84e5578c0fd07935fc8cc8e3b534ec4cfb2e7dede08a6_cppui381),
                                fq2_value_type(
                                    0x139f33cf02359f4c69ae705f7366b558ca01c16105c7ad5d17aae0eb59cc68634ada7ed201ce356d39bf82377ccfc584_cppui381,
                                    0x17a05fe4f3a5397f715935db724d8ddff01051af8aa1c2533753362661fec5bf5f6e8e98e738ef6becef63f369f07e54_cppui381),
                                fq2_value_type(
                                    0x14343543b4fb41c39d049271e38862026e9293ee8e20128cb08948360c619e3da1bb20839cd0d5584125ab2769c7d5f7_cppui381,
                                    0x074233b64e29ccead63272bdab4278c477b7efcc4b887489233514afed0c29c366793c6510583559830f3f6fed4fce7b_cppui381))))),
            std::make_pair(std::make_pair(fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x065c53c8bb2d00ab09f63c46667109ea047795a4841e182d78702a19ba24d6682be7ef14a32ca7c72de3b3d2345a7b62_cppui381, 0x0c18af9af392dcba801c52ed2766ddf818a004043f0a03e2fb0488fa5eeb357fd1482435fedd320d30f6b960e6ab622d_cppui381), fq2_value_type(0x190e5e7819701a8d6775478762b6fcac09ae5d38c06e6af811c239bd31292b178d61fb07eb06f0802249e7dc6ecbde40_cppui381, 0x044ed5531d7f469506a2213c48ec0cc5994a4fb0a4d7f7b8a7f0c1348dd404e73455230be575cd09d8f87887adb4b302_cppui381), fq2_value_type(0x18cb61c96a086bdd8702850569c4b6f54838a0ff7e4684982b45d432066bb7cd5b8a5125b12fb40bea1eaa91f7593b90_cppui381, 0x093d1e653c01ee68412487b57bfffcebdfa50a283ff326b7b1427a3e8306149ad1a40e5b895677af0cb21d85e37224bf_cppui381)), fq6_value_type(fq2_value_type(0x00cc706b671d7c653d3331f2e68e79e02ed8f7e295a621ff02ca1d7761f71505dc618839a43eb1cbc56d3b4001a1d223_cppui381, 0x0870acf52b08530c66f9fea0719e4211c80f5ec1100ff81a602cc5966fdb5f86f8d3b8927a2c1c80168914b5e964f594_cppui381), fq2_value_type(0x118c2f64ff95809c89324ea1f21065e2bec3aee1f01dbd4a858421047b3d63829e8fffa3c221339d16604c31a0e6743c_cppui381, 0x11bbc2ca511d06409053b7395f071bcb8bcd80089a788d89a9e1fdf20b51cf7312ba49a58dbb68e6b53b92a9bbce6aa7_cppui381), fq2_value_type(0x16e56dab60ef746c48be6f98632b8aad24859c6de9deeb20dd2092a9134d9018018bea2f4ba3da11d530aa880953623f_cppui381, 0x132930a777cbac72c382dc6b7bbc32b0a3d05a524a34f6793bf1f469f65f67fc8a691e0bf7591f69761c7bc734076431_cppui381))),
                                          fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x09d054960da1dc78f70ab3b71e7b6248aca47ef6004b9987ffc3513153158d52279122d9d79d395008bc4a989f95b08f_cppui381, 0x02fc878bbcb5ba839a1da397c8be9a2498f05589cd8356479d38c759a1cf5d6e19100e96be647d286b5dacf230fb1e25_cppui381), fq2_value_type(0x0574ab4c1cf1301e852dacbfba1e68f060ef334b3028004a8e07c173a7a54202733ab74a027771e6c0132529120667f6_cppui381, 0x04c368e41be1ce332b22ec693ec99a655b4b44b9ac37fa4f026cb11ac96c624706ba32a7f91c338f4ad36ef22ba8c40f_cppui381), fq2_value_type(0x13e1454fe720bf84b1246b1494f7a9a955fbfd53638e3c145746d9039602a6230ffa40fd4c8adf8c0c8ca52edc9bc8c0_cppui381, 0x1262649c45b556f477d46268d923cf9da7900198732d9ab6c397a56ee84410292e95a3bd5d3ef158ff6feafbea8b4e80_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x13eecab13e389bdac3ea5f3ad660bd13b069294d774666016ca143d4dd7c6ef223a8f24980a4138fb56df14855d2b841_cppui381, 0x0904cb4c080295575d8ccea88f58ca71d7aa177aa262cc7cc90ec93803b0d0f87c5f50c7cf2e2e689a05c01e01442c20_cppui381),
                                                  fq2_value_type(0x15afe840115b621cd48b62a452624434d6a924068fad122dd2231bcdd79fe587ade17326d2de85adfa029e22f650626b_cppui381,
                                                                 0x00b075566e5f148600de3378500290a56f0801ea60aadbb7f72ac1db6ef782b051bf30e5634dd24314d786b973aeb4b6_cppui381),
                                                  fq2_value_type(0x1170814f8f7eae5d20c9c8dffda1c2ec24f2807e15a5faf1f41e5f43d0a3889dd36253e78c4f50e6a2c8225d6a58a578_cppui381,
                                                                 0x0b583ca36821e66912297faacd31b0e42b265fde9adfd77a77e95949e1f5cdb8c4eb3519b95d97af4032bd6d41ef658a_cppui381)))),
                           std::make_pair(
                               fq12_value_type(fq6_value_type(fq2_value_type(0x0f001de8a7441bc29a89d1f301393a8ad9d79a6bb04e42ec218080dae1a02067b7e0c750a74f1b5519b82b286ea4d399_cppui381, 0x02d6142af5ab4fb87d72597a5c16129310ca3c2e7663152ea2ed7362f7b03b9b30ee53f14a2a4f4147e5a6c12ff4d592_cppui381), fq2_value_type(0x0ed1e2ca47b6d98a6859091d2e1fd80eb818111c27895d081041179503cac79bd98404e5ba35f16fb2599a819b1b8ba9_cppui381, 0x0bea9231f17bf581f6d99ba3987b6185672b5b234640f1e3924e304024f1d6601c967dbda2aec476e707253827bb5116_cppui381),
                                                              fq2_value_type(
                                                                  0x0b6c1792d51fe5f629d0ce4d37bf0cf1fd58403176e954ea2185718f0cb3345fa3bb31e3a5ec02c2f28cd21bc455a10c_cppui381,
                                                                  0x05eb00868c5ba82c90dccc2566dcd04ea6823b2fdcb6c8558311ca877a0ebaa81f37ace1bdf92888228514f9547375fb_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x097ec801438ec91ca846d43989032090cc834a16dd8e8135a2a7fd967614d2db317c1103796f3e642fb2b583d7910d17_cppui381, 0x0a1ab47a0aced870e88e303aa69b476c77b122097a80f4263fabeb7148a82213a9cb2f0bf3d44dbebd221f86cbf94f53_cppui381),
                                                   fq2_value_type(
                                                       0x01ae6fb57afe6ab624aa7914d01a977423c3d06443c5385c9393cdb39dda4679ea5325942b3500daa109b0a498d0ccf2_cppui381,
                                                       0x06b0111ecac88f941693004d7441bdb3bf23edd1900aa410f9b63d53f5c7fa8f1f67024bf90323b1c94210405b4428f8_cppui381),
                                                   fq2_value_type(
                                                       0x0203d66d40255e2ef0bfec90f98f0cd2f41f3643ec4bb745f076d0df0872ad1ddb10dfdb6b571f3ae2f1646ad7675e89_cppui381,
                                                       0x18462d3e3388c7572cdeea8554f2690f6e6fc01a730a7a0c3cbd1fc9fc7e7820e02b133ccc25f4ae001e38a9723e0dd6_cppui381))),
                               fq12_value_type(
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x17e64c84bdb951d8610a11c36afd498eae03f1ff2deb07af060308bd13fac15f3c93972ead4f9465511a9353abc74bff_cppui381,
                                           0x06023d577ed8176cc07f0a71ca9301bd3f8a272bf57f8743f38f5a881690cb64e0abe39a7dbf92ab867bdcd8bee38a07_cppui381),
                                       fq2_value_type(
                                           0x190abfe96bcf146f23a5f69692adcb08eeb9582e6fea485c803896ebd43aa32037990f6c8db4543a3003b41865de72b4_cppui381,
                                           0x12d70b88af84f46199575d76c4975ad01b0f2f14d5359f9ca1812825b63268a2f93973477168fbb9401d93dd056438c0_cppui381),
                                       fq2_value_type(
                                           0x0a95071995132ed8129baa5cd0e0d5033c57213ea02827e4158f240426313e2adb093cd9fbad4c610ea78d1b8e430700_cppui381,
                                           0x0a7f8d785f9323bd36551956fffb0a4c764a1caf5ee2d16663ca009426f0f858cace48d7707e6a15c2485ccf595e2c47_cppui381)),
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x197ef60f5da19de3533cfba4a261344a370a42da6975c4fc17b73df4720ac108715f99aa14c3a78381d6be6f7045cd11_cppui381,
                                           0x14e0109d23522f6618913029c48c83a414ba85e32978c4a094b36340d285259545184260186b11d7b4e4bb191ccc43cd_cppui381),
                                       fq2_value_type(
                                           0x0e306b73a44d4a6b6d5e45eba86bb5d4031e9de27273e882a524865c002f148853b2564efabcc739fe0e71ffbfefa29d_cppui381,
                                           0x10c97d18145539741bb9d0b36f650f30bed5190a21f1182732aa4aebd33c0a195e9618ed4c616efc0da61eaf1faa39b6_cppui381),
                                       fq2_value_type(
                                           0x121e85ea553fe3018a374e40b87c1bd32bbe434e9446a39280e893fb53736f9530981ef82f1516070a2d8e6c08eab3de_cppui381,
                                           0x118bcdb4b1ca527cf3f3a8335bb5a3e7d4b43791ca571faf06ec3a0c1c06c0a21406ed766a351b6c7c30aa8ae3fbb66c_cppui381))))),
            std::
                make_pair(std::make_pair(fq12_value_type(
                                             fq6_value_type(fq2_value_type(0x1053078f1dca8e21e67fe990ca54774c754b6605b533901da5377081e633901fb178565b6d036b84c1d23d4e354dadde_cppui381, 0x0c91dd3b91b97f40f99a9f95bbf03d31121923fc3b193a9cfb46b6dbab75f24d979949766d2b10174258ac857712ec10_cppui381), fq2_value_type(0x169835fd43016616b9d5db2d23008087af11813e0e50323bf79e162bde4c860fd54d58ea967cf76d9d8426edc4cbabf1_cppui381, 0x01ee0bee5d0568528bfb0fcd790c612d1195c471959efa3906e1b84234ef587e0f26a433903111d0b9b7b9a6a2bbfbb4_cppui381), fq2_value_type(0x0e1a09e26aa899cc835f78c64cb352bc228aaf929580c271e7267f32d09a6ab22c4ee7f0552c4d1740f451b50527bc99_cppui381, 0x0b92de9fe153181a64ce45b4f39f9d0410804a7033980d1afbcda61749cb1db9c4105f6d87be656206482ec9e3bc9b90_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               fq2_value_type(0x08b6d38903d92c1176c0cb915eaf65879a2a4090feb19633ebdec3c0dcaebfda97270dd6b5e9ba44b6bd1c825d96bafd_cppui381, 0x1743bdbfc16ca5ce00e39ed450b699fbed1f004ab75e54c93453a4efd05a6ca7c1a8e3611ead74eab2de1bcf6404efa6_cppui381), fq2_value_type(0x0d422eee5db5c6e1423bdec571c86de52773534b2ddd9db1fbaa5d8780df33c5a7980ae29424e403fb4346afbd3fdb01_cppui381, 0x033400c16e3244bc253b5fad70a4e47ce42e7e66488c95fee14949bd91dd6eaf8f4e8cb222a9498c91b287d9bc8e8090_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x12df9a4a429e18c8207df99fadc5468f14e1579450b09f0f55443172ef8fb70e19ee2fa41382c8f07c51cd73c9e4cc21_cppui381, 0x0e484ecea089099176261b39c34cdae1c974cb85ea72cf9f4ff0886714e670e49edcbbc9fd660d50252f11a3c1d4c47c_cppui381))),
                                         fq12_value_type(
                                             fq6_value_type(fq2_value_type(0x14e63b2a67a07cc1cec73cea0848c87831f586309e5b345c825064d9243f16f193b899f50d545260789fd94219e54962_cppui381,
                                                                           0x15df4b4c4343a68a6d1631e4397e3fbae05eca8d06ae3e15d1bad2009a62be02075e8212cb4595c0b834c03c88c7d552_cppui381),
                                                            fq2_value_type(0x1565b0b60d7cc06526efd367a2ef636bed8f3a4eef2b30d60ae69380884ad57fa3593dc731b42d3a00a57612c672a151_cppui381,
                                                                           0x0927d3f23c726fa6ba32ebe6a84c9b43ce50da0e59011c7a985ac202ad4101f8eda538e9643e6886cefaee1255e99c9f_cppui381),
                                                            fq2_value_type(
                                                                0x16c144ddc9330f07c33466ba7f8a5693345b4ab95d1d05e6ebcc80276f69a2602083b03919f8b322ae093dad48376591_cppui381,
                                                                0x085bb6feaf972bdf812f01aad6e300b16686bdf2d51018d75c869fb053ef1b47de05177d21d13b8bc933d2a1d2301dd1_cppui381)),
                                             fq6_value_type(
                                                 fq2_value_type(
                                                     0x02aa6d7498c5b2115b8f21fe01807da31d427695db8493e9ec4d4642aba78078da80271ff90e7ac8632d497a7ec761db_cppui381,
                                                     0x124802596e462913a38781a89c6a8c3849b93b8449f9d1a4586405111fd6c53b23376929d0f1f1dd4ac0ace302520b7a_cppui381),
                                                 fq2_value_type(
                                                     0x0ed4b7f92b0f555191007e6c1617bc67a6bce2526066db8002160867c7418581e95282c748506b26343b1d7aed0c3afa_cppui381,
                                                     0x13e6dcbffd190514c7b02d14a26af791e52d4fce9ac40938799d4369f2f6eb5e9e72ff9cbaed6abb1c045440beb90715_cppui381),
                                                 fq2_value_type(
                                                     0x14d7722b78d34b909c11b7081131deb6c07f54abe62ae64d238ad11c1ac93fd44e54c1837511954c79fdd4b14b091a06_cppui381,
                                                     0x0dd13ef3f8a0aa1da902f33132acc4a2380757cbbc076d101dc623e7c87838ecc631f4a67078d4a952eb922f57b1ddee_cppui381)))),
                          std::make_pair(fq12_value_type(
                                             fq6_value_type(fq2_value_type(0x058af8cf182fab8fa2569d50874a0b459b293cb5ebaf799ea526458f34bdfdac511e19524fdbe0769d7701fc08b0408b_cppui381, 0x0e4a4a150c2cf7035b84d207c5952523bdec4ec109ac6c5b72e17e427c7f80767d5cf2f5b539edfed61493ab764bd374_cppui381), fq2_value_type(0x11e9adaa91b7925f378de6738411729fd8ba6271c495c5699e0ee9164ae26934e9c7389eeb2bec6dc80b1906e580022c_cppui381, 0x07403f5ca0015f2a87a07d6c77337952def21a4967cfdfa6c336ea332b2e53cbd58089a3252fc4fa2c69af350e578731_cppui381), fq2_value_type(0x0649b9b12c25e5fe3de854257b60ea8cb92a1356e18895455b70c5929fddf59b34a29018ff12db534a15f3ac86910166_cppui381, 0x0f7f015596193b076a64e02764b71f7260742039f44909732dc532a8d3c06253a0d58a5c49d7b07c10fe7b156a640fb3_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               fq2_value_type(0x07421e0e1d8fc614579a562f5e492bdbc55bd13690c5273e7d92f2d556b6a854d1437e1c6ef5817868ff11f7a214859c_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              0x1864fee6b0258f12ae274f116a97aed6638950162ed7b74f3beb07b89101f9da4779d2cfff9167389d5b537adaa60572_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x000b81d2287de5264816bbd051ee5f712d4b31ac4bea97b0d416d431c0e330f17266abaab1af0cf609b46ffb3c0e2689_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x0c340f1d081c98826dd701f095677573ab6b386560312ef5cdc42576d3b1d51a98eeb2110311635c2da267af1a61fe86_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x0105af3b9a3aca403100ebf814e9a88731cfb6898150a745062f992ee59bf8937d0dcd649abae228eda9c6824860f2da_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x11d1d034333ee910563031103c771438310196499294d6f95024df0cf0ef2836b6218f1d16e028b6cc49dc3cb93239c1_cppui381))),
                                         fq12_value_type(
                                             fq6_value_type(
                                                 fq2_value_type(
                                                     0x031cc0a0e8a10d47a5af87a9bcc167ce5afd34663d8bcceaa4c0324430b37b098b10034479539c42c77377e0963ccf0f_cppui381,
                                                     0x0ebbbc427eaf2cf9b5a57438fcc488b43bc58687e454b37a2fb8d00405e1ac4e3e27cbae2b18ccdec0db732f70c0271c_cppui381),
                                                 fq2_value_type(
                                                     0x0789bea4172c8680a5a9643b91da8a91da4f785311cbb4a0692c6fbc5a55725eb57f14b9f325ee494918140b218e6c8f_cppui381,
                                                     0x027912399bb68611e8de6637fe08cb72959f648b1a8ed0f8b7f2a1d4ae4186fd2fa63e80a208cebfb62ce0f3f03ba586_cppui381),
                                                 fq2_value_type(
                                                     0x1696e6d6ad196714afc1ff54c47787ac6ad4ccd8cd5410ddc504b2ff97b7db90a5ad2667637f8dad659f015c4f7c9634_cppui381,
                                                     0x09e92342f4f5ac91b15d610a17800633c06e8f80b24cc38aa5585426b3ceeee6a7d0d1fa66918370babc6fa3b81e777b_cppui381)),
                                             fq6_value_type(
                                                 fq2_value_type(
                                                     0x15f86d487109455c22d316a69fdfba9b4290c63c2c3486ee2f027efedc981d1e4c41452ae32ae1138644d253772d15d8_cppui381,
                                                     0x16596779de4ede0014d2ffb7b8aed13d7453dc24b28e7fed885e9729c329a3189242bc3500c115ff80f865fe22a825cd_cppui381),
                                                 fq2_value_type(
                                                     0x02489f16c8af84e6524ebdcdcad1b549ca7d4aec5d51ed553eac6ab9bf77657733f72efd06fccd56bdc642abc4ed8aef_cppui381,
                                                     0x03d3006b63d70c94feeff2f1546d8b8dd6462a64d2bece1d49ad7fb5d0a101b1306fa73009677440f27328955e69f27f_cppui381),
                                                 fq2_value_type(
                                                     0x00d1ef16723ea8a1463a16799acfa4ca141cf843b61e0533a99a8570f229f8d980a907af1f3cbdd2c0e01d9eafd96580_cppui381,
                                                     0x1670c4b5b58fdaaf8c8f8e401188a9c5effc7eabcda654b5758ed681839571ab65d870dbfcafe296a72c8962b9df339f_cppui381))))),
        };
    std::vector<std::pair<fq12_value_type, fq12_value_type>> tmipp_gp_z_ab = {
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x1788826b397708b027ad4d28d617f2bdcfaa4bdd9e8ed558eb0e2793bbc7ca92e161fedb8d7d4e899928edd018b9c4e1_cppui381,
                        0x0e5ff5ac95f10e80f0d450459608e81cd8790ded433e89b54b148aba9ee51d3b903c0d6e8151fbda77e080ff0e2ded81_cppui381),
                    fq2_value_type(
                        0x15ab6ecce8f643d8040a160b28a88cc354d0f00a0e36f08d8cf9d0be7498d58049d9efd5a6e1500a847e51b953bb5422_cppui381,
                        0x18ace269e554de2b091e1bf93fe6f49943cd8d933a5ff07c44b74a5919b19003096689adfd70d95bb67e76b898e64ded_cppui381),
                    fq2_value_type(
                        0x055d9b8d6422d95ef658133c5c420428757d798ba2a4f3726a966b8f465f1ced397f342835c604b246c1a35f95652ab7_cppui381,
                        0x08d481eb22d5099d849fab89cd08a204ebea62645ea16b00a5b186a85272585e9ddcbd17a97fcfae5723ed9eed3ecb73_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x13f74e51b80987e58a315930ed5c9bc4ec889b658d7fb1346985335c203ab26e45677cd9f0b270aae0f13579f37dbf0e_cppui381,
                        0x154d0f0200afbc37a60263bfaf2113724b5a418ed775d006347fb689f6e1e5bf9994f29525479a8592fe13507bd013a4_cppui381),
                    fq2_value_type(
                        0x0587bcb5d491260467ed5c4b2f61587b4cdcde1f95bd019a44812493a70d43e8973c9f8fe4d3efe5d1357868bbf6a9d3_cppui381,
                        0x0aac99645c6315981ac98aa22fcd9e5b793a98e9ad4a4303e3509b838f105af4b76c29fcd27876413cc8a32125414d3a_cppui381),
                    fq2_value_type(
                        0x0fbafed0658844cd1b17a8256243fd52b59ae0301bc2ac7448ce9995b35326a16d9607ec7c6d6df93a139e3fc9775f0e_cppui381,
                        0x0d25b354fc9056f541dbbb04557c2bd7c798a104b0532d630ca4a51f479bccfcc7145d1a38358dc4f1c715ed93715969_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x0ee181afb0aaee4aff5e1f376ea7d439777d256497e6b2f98f4503ed7cd57511425fae9c35b5f79db8e6cb9b38793895_cppui381,
                        0x102537a00e697edaa60b7867d87998739ef9cddfe187457648c0a2be3fd05c92b8ef19329bd7c07c61010965e7bef8a3_cppui381),
                    fq2_value_type(
                        0x15bbf319ef5876460c111365bd6478d7e0c569ebf23a68afc9f877e29760042347e4e4aab02dacc71068b41d8b58910b_cppui381,
                        0x187682bad5baab7ae6bfdfd33ef84a0882cbee0980d5369df1538dd0761ed8dcab020fac9a0a4c5a027ad89f4eea5db7_cppui381),
                    fq2_value_type(
                        0x057142517f230eaa05b21cb517f67b5317ae73ae2944a904f64f888239fe63488fe5c657cbb56f3b5d1f2dc678e49200_cppui381,
                        0x101ad09dcdb181b32a1cd4f24d24dcc01978170243650e64d53b838fd828ef5e8bdbd0a9406323cb14cb29a0b787797f_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x1299f190879a96636bde6755bd4d9f45904273b95637c4188ef3aad491d90561ce2d3d79d0598314f462e46fa0631ab4_cppui381,
                        0x1546ca2af0e225be968677ca9fdfccce7f94f2a235ad79f881da67f8e38ee2b01114c52ed579a69ecde37e7517baee53_cppui381),
                    fq2_value_type(
                        0x10f2b3b749f94880c47b7f1d7025f2309da774aed1ae8a9736867fbb681de22e825e275f242691151018103797399948_cppui381,
                        0x04e5051ccfaff5b87864f3917a92f5ab654d35ed7d2b5834ce01d3854dbb64e627126a0d3ffc56f1a504c41bd8f90d3e_cppui381),
                    fq2_value_type(
                        0x194ceb66c0592dfa69c1dcae1947acd98a2b215c89e66ceb16a20857659e66969e81b1b783e6e55d17d516e331ed22b6_cppui381,
                        0x1063386db2d0ecab4c52fa3a83dcc07afde71e86c78acc6a92c389ca5c0c01b2842e79dfa789ae4e35e5ffa2ae8d07cd_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x19f1b8f6a03682198c18c32d747a03b8a5c7173db2f0ac69b9ad0b26a9bbd9dcef06982d7840e13adec3bb15b2acd77b_cppui381,
                        0x0362cdc0b3cbfd077c832bb0684852a2271566a527d885aff8f862250bda230c4b718e26c9d529cf08e5f04f7821ee22_cppui381),
                    fq2_value_type(
                        0x067b9cfd9837da2315f4d32c965795dc07055b467ff7b4b498bc2da512e08f9f2a4d80c1e9e3f89bd0b68c6cf396fce2_cppui381,
                        0x00f4d1b975803f0fd15afcb9d4514f48c742f46a81179e22cdfc307080491decce0a4c55cea84f035f01477ac524c83d_cppui381),
                    fq2_value_type(
                        0x0b1005b2726ba6a30a8eec37063adf03297426314949fe267d9bcd4d7b6930185c796549c4e11521210b95303e1e3e7e_cppui381,
                        0x0dec864d963f23f563b7c727416b5deb27f261fc5ac3c4c4332fd780d8dfe5259b92e63084eea41c7298d8e69e8d1b58_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x03ecd0c7506029ae473df06e8f59b5786c630fdee5ccea677b8d005f238e8ee7e573152f9bf6ef1118dfdf11e7eabce0_cppui381,
                        0x053fb1d22d4f000da162d6eaae60baacf9edd626f32ed54f4fe8aaa6d795e7b5a336053aeb9c5f2781fe431a1822af6d_cppui381),
                    fq2_value_type(
                        0x00ecd51b11a1936147fd612794c814c53645c40d5b860147e25b4bb26ea1b32be947e07f4d19b267927cbc3e4321c983_cppui381,
                        0x11698628d730b5fda5250785c26a713e4361ba83eb2b2f9a49887ff066ff734584d944e69de4fd369de68bb9d3eb4ee2_cppui381),
                    fq2_value_type(
                        0x0e78b84c59a06e355d0116d97e014d75abdffcd2e3946b09aa4975009e885f05236d5a75c2394268aefa7c6e08caa355_cppui381,
                        0x0cede1aa5ee65400cc2ef30b083d6c5ebc83a36f1f9deec661fa5be68449f6e0a90fbeb32a593e717005cd6d697dde29_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x00b9d9899882ac57445b4fd07aa9113723698350de68efdbf08bc4a17c1ab319eeb46f55fcf7ff1b3033ca6085a148a1_cppui381,
                        0x0c0767b8cf8ec11100b904c4a2baf6f71e829c5d83b6f52bd8f240601289a660e3de419b28c87261a6d465501b573a56_cppui381),
                    fq2_value_type(
                        0x16648e296b016c5eadca4dc03b086b6a2f16615403294c57fa286127a91c86bb74324469f7f697f04710a35554a1144f_cppui381,
                        0x03ce35154d47de78f16948738ec1a850560a45f7859115a7bc5d607f0e3e0375bbd2fb164d97727e4f0660f77e16b285_cppui381),
                    fq2_value_type(
                        0x05670a4100105a09ea4a3879b609c1f02c40389387fb51db854e96dd09f6fe824adc5a9800e57125b370dd88c977bc4f_cppui381,
                        0x0e5297f8542edcd18e561849c30260f15b3e36fee82788d7335c541830b306f310a2f70d1c2e878e77382539cbd9517f_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x054a2b51d150e6b86e426c1a7e95d9021ca8b4a2d53ab47d63e7d00025e08c2d6be0edc38c1ba4bf8e59d3bc357703b8_cppui381,
                        0x01ccb39c94290487328c84c999282375fe6b8d6eef862f172632a4d0d783bc37f93ed34f27408dfa7be6e5bff81cd2a2_cppui381),
                    fq2_value_type(
                        0x09cd6ca365331fd71323c6ac8d7a12617e44b8db043de286a7204a193eda47a6e1065c309331e4c2a2086f4ae12f2072_cppui381,
                        0x0817fd81a8a38b28f665384fd7d4ca01dd970bc051bd85d58496066d4e54f94acbbe91eaaecd76866cb5ef7425329d05_cppui381),
                    fq2_value_type(
                        0x1021a266ddc09f5473e7196124facc398887d22c93c1a84ee3df8f344fca760c5173d90907748247c75780f94f90d84d_cppui381,
                        0x1775fdad6cf55f9ddb48e6431d78c20b486e3ca59e6bf413e69537b481c7256032614909994d81242a1a695c1b6338d3_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x18ee977c47aaf6c7aa71fd4ec4749f06ac3d86b55f7780ebe01e5c4a7616ebf4c114a8302df791846664fa7fe6b728b5_cppui381,
                        0x185a9a9659ce8843bc69bd59bf5ea40315988e571e5e75e36e1de11c2580e817cbd17bece84808d93d4cf299d01c5558_cppui381),
                    fq2_value_type(
                        0x012a219116e33dca6b7d516b23c516af99adb29cba5f82502c8d47576a0b3743c13ad830f20eb7c95d9856e2e0160a74_cppui381,
                        0x0cdc20a4d7c82ba9aadb2b5c41f679552850085a647a1ed289bbdd0b6fee2e723bf480d01fb07d8bcf8fec808d4d0b82_cppui381),
                    fq2_value_type(
                        0x01a064f407c42c4e6e7bbea5ca84fb7d31b41c544de4d0f4388ae1dd187bedf9832d8f825fefcdc5879b529f09a3e316_cppui381,
                        0x01c039f12535c58c2027c98c8149b1129a79c97619b3322b6fe53e34ecfb5aa2164f76853fb70aa060ce67c45fffa171_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x129272e1918dd4d038abf0fb5e2a13eb477f8fb0f5bdc4c5c009dbe8138465d0cded85dff4643e5045d6e53ee58e13a5_cppui381,
                        0x03d8d0af65c0111006cbd7399dc49a81f9ada13bc011f00e91708ecb2cf7dfaa87497a276c8d1a776e66f6b90e9454b5_cppui381),
                    fq2_value_type(
                        0x0158aa9b2d41dc421c8d553f14d77b1d503ecc700e356d75e2b510befee0029e95bc7838b9052b4d384ec3b4987942e6_cppui381,
                        0x02b6904c900007171f8274ed1382b580ba0459943d4c15159de7903015646e2ad0a0f91444a14809e85814838bf00d0e_cppui381),
                    fq2_value_type(
                        0x02bafeed0e1601f550b530d54ff29e27552e0b4acbcfe39eb41bca4ec454f9715c46bde3ca3cb487a572a86935842fcc_cppui381,
                        0x0194e79042c4789500202f452044650548ad37a0ace43425077acc28d6088f18c2071d99c05f931927809ad7ca03fe45_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x07eba3209bfb8059d8604e4fb9a3ea478890c8113149b2a3ac4770a84ab4315a776898cf519e1007d12c60ccab74972a_cppui381,
                        0x0096524ffe899fe8d59a67c82c48053b143b04917ddbf641db69af9e6bc11fee79eaed26feaec287fbbe43e1a5bb6606_cppui381),
                    fq2_value_type(
                        0x0865b3f04c25310c3149a10592590dfb8c4f491cd0d591c2bda301382ab63eaf30ef40d9c25ff82d6df4fb76b2290368_cppui381,
                        0x0d21f1d9cb8a13f4bf2bac4a933ff68ebafdc7c7665ebad1b81c25d3231fd7a5031c41204179b1354f609bd2c64342e7_cppui381),
                    fq2_value_type(
                        0x10aac69f15f1646f9fc9debdedec7809af6e4b579bda5a5e6fde058978e0454ecf73dc1f77711b34b5a387492e8984ba_cppui381,
                        0x168c2d2dd49610e45214c1d8b3ba55742b4db11fbec779d392211bd55af7134b829f83f93ab4168e1021e55e38030760_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x01939b04d9752ed9e012b11779539e4f0276daf50ff98b4ce4d9a7cd5df8aeede11f066449ae85791b0dbf50dc794a4d_cppui381,
                        0x18a22969a75c5d48f40ccd4514ca07a87879c4e56137526dd02ef9d87199f428535d7e8941b6bfa33be9b2f89441e4ca_cppui381),
                    fq2_value_type(
                        0x0bac1b4ee539a7b05fb986b9090fa8be89aa150b920f19dfa952cce6d6151a0d059a022c81987ae926e7303690d35c7e_cppui381,
                        0x002b80e78965bc2461a33e9ce8b54a8a2b0f019927dd47b06b8fd3cd56124a0c94cbbc70046cb124477f61bdfdee9809_cppui381),
                    fq2_value_type(
                        0x050188c029062c9d982b576d3763554257a6d2ec801933937dd768783ee7aaa22ddebeffbe8839138e32003f2d0f4e13_cppui381,
                        0x0b25b63b649c9ab56746deb85067edda70403333a7050545c1333e3d8e4e0801c408d0327585a1ea24a9aef780c2888f_cppui381)))),
    };
    std::vector<std::pair<G1_value_type, G1_value_type>> tmipp_gp_z_c = {
        std::make_pair(
            G1_value_type(
                0x00356ef47a6a688a8832dd47fad2f8b5981a564d3b7dc77b33f13dff52dbb4536b6108510785304da9fbda39bfdc0bb3_cppui381,
                0x110ce13acd56d5f9188faf09684b5e299b848615ad9be48dec0702e42ff794730417d92c7d437ddb1ba82869b5b6fb60_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x11d1f6fa158a0424684bb00c08be8f01c6eb6835a1fbb6ac06606799e517b2752b0b047b70266013b9d932198ced0930_cppui381,
                0x0d6d40a9e4c8aa3f41d50f3204216c78c5959e5d0aaa08fb0276665b50efa7e90749cf7ae48d353c2beb29a7d9703ed1_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x12dcde8659ef48bd2c3a97a1cf83482ebba995a45151bbccbd4c7c67c40394bb6e17dfb831087b58230edcaf2e6fb1dd_cppui381,
                0x09e1e629881f8ca21b232e789536a1886af564ed99962507c26713f5f89996b8f2b4df5a4dd3bac68aa22db9cdca8018_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x0d59c9b4e2c5eb23d592aca6d1566b86344822141cb1795727d56a4d7e077bfb02d082253cf8b3f5c2195c54130b1ebf_cppui381,
                0x082ab17c22f98fbe932fe192ff59a238745334bdc1cd3205fb36528f045ae2c822e40a02324c3f6240fdaecfeb57be16_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x099d68bb24b4eb1a3dfb7a7a58cc6aa9ed9387522e3b85cf6e961ef90fc4c036b2e11a9eb97c49cbed2faad45b7b2285_cppui381,
                0x0c36aaf264d471feab21cc492c3da8ebb113b5e0d6bcb0f7bfd33387124f9c200044ed12f610c4884409861d4454d2c9_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x08875e3cc7412133fc32e0a11de22f0fdadfc9f9d8171bf8be7b6a989983c09e2d8a5f94758fcd8c91b1dc5b634f7071_cppui381,
                0x085c74e6bf33a19ec050533fdfce080e22c287caca4c564bf425f969ec063da9a57a95b07670aafb9a7f4b3550a7f22c_cppui381,
                fq_value_type::one())),
    };
    G1_value_type tmipp_gp_final_a = G1_value_type(
        0x16677a33cf13bb52300de2eeb5b7ee6d8881dc2c92c5d530af32a24b4b42133870e05755e14b7f67c52376e12f11b088_cppui381,
        0x04571811f397f733bb55d426f2446a05ce90731d70e20d9c93580e425608d8b173103d5044aba2edb193e9d41547d180_cppui381,
        fq_value_type::one());
    G2_value_type tmipp_gp_final_b = G2_value_type(
        fq2_value_type(
            0x00ba1d9ac90c782327e89e3e90903f2fce97fba19edda36a300aadf4c6ee9ce7829dfb3959147fd395e74602b00473ae_cppui381,
            0x1805551b2192eac55ecf0c0f2893fea211f472de862f1107edc0f06e9c838832058b439001d32486e56fd10347696017_cppui381),
        fq2_value_type(
            0x09328337ea6dc20868f8a0218d6cc0198ea4059dfad5bc867a5e5bef1372e4d3b976bef79bcb99e58872d43ed2d59398_cppui381,
            0x0019a9a18d511e5d115fccc250239bf8b45b395294491662e5b755cfd4c7192335f7067797eed7ccb67823ea553d75f7_cppui381),
        fq2_value_type::one());
    G1_value_type tmipp_gp_final_c = G1_value_type(
        0x149e3091be2f84f85d2b44843aeace9f30ddb3494c844d61ee3ac30c86f84af357264525196e403fb484d128e7382c9e_cppui381,
        0x17fd55dc172afac253132fc05a4d80a11003c1a33ebc5395b669342a3cde5b8a55333539acea6724b18471621426db97_cppui381,
        fq_value_type::one());
    std::pair<G2_value_type, G2_value_type> tmipp_gp_final_vkey = std::make_pair(
        G2_value_type(
            fq2_value_type(
                0x0b97d76ed73bf157cc80f949a4aa6db46f76916b6fcef9aa9b8033574155d291c3cbec6d206d294b888f1f162c9c36ab_cppui381,
                0x132abdb0a598ce209156b847b8670f20b124e8e617fdfbabca12c7705f8fd4a76728d69569ff8ff4779803320d8cf831_cppui381),
            fq2_value_type(
                0x0d058517aa6da0d0304f8d760b110db4b82241e6b2920152886886b1f44d84e51c5ecde215ffa0e432a708196e8bada4_cppui381,
                0x070f638b8b7f2ebfb6e18dd45903c2e51456a6e864bde5538bd09099766693566edc8f23969ba9e2a1cb244711db7e43_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x10d8f80502ef9ec601d70736bc5aad2983cfb20fe603f849f85591198e51c8aef58cf5359df138a2a3a9f8049f987d18_cppui381,
                0x15f1486e59fa64f00b6540b7748ab734d968956187e44de6d2c3815e5983e603caa5492f1aadb7b67a8ea4eccf61e746_cppui381),
            fq2_value_type(
                0x0e48a24a8e13189722a6b97581e0c0047c43dd8f8ea145be717ce532d7507411d4be62b5ac98c095d3be05351dcdf3f5_cppui381,
                0x109a6017d1d97927bfc371480d05c02994db816c6c5f4957c4e8bfb4cb8611cb6df76f46e024660b0f3c34c1095ad883_cppui381),
            fq2_value_type::one()));
    std::pair<G1_value_type, G1_value_type> tmipp_gp_final_wkey = std::make_pair(
        G1_value_type(
            0x19100904cf14f2dc549a8cc752929208ffba6ed67fa3c187a1816b2c2ae30ce26e5ecb530366f1c2c55a14c235663c43_cppui381,
            0x19cdca0efcc4ecc2bc5a45a7741b7806106a5f0b9dacbb10c547af7ab4236aaeaea16a01c6b1e354fcc45108e1cc6271_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x078fa9d726a3aebcec5f1a5b1142544c22c352d8084cb7a7664502226e1a6c62eff689a2d022faaa4f322b6186a74a96_cppui381,
            0x047c3e9b88ba11ef0dd4fd3956c43f4e200d5cde83459bc1ef1407340d28ac5b58afe21ec4b51c599e5ddbf6dbb0da38_cppui381,
            fq_value_type::one()));

    BOOST_CHECK_EQUAL(tmp_final_vkey_0, tmp.vkey_opening.first);
    BOOST_CHECK_EQUAL(tmp_final_vkey_1, tmp.vkey_opening.second);
    BOOST_CHECK_EQUAL(tmp_final_wkey_0, tmp.wkey_opening.first);
    BOOST_CHECK_EQUAL(tmp_final_wkey_1, tmp.wkey_opening.second);
    BOOST_CHECK_EQUAL(tmp.gipa.nproofs, tmipp_gp_n);
    BOOST_CHECK(tmp.gipa.comms_ab == tmipp_gp_comms_ab);
    BOOST_CHECK(tmp.gipa.comms_c == tmipp_gp_comms_c);
    BOOST_CHECK(tmp.gipa.z_ab == tmipp_gp_z_ab);
    BOOST_CHECK(tmp.gipa.z_c == tmipp_gp_z_c);
    BOOST_CHECK_EQUAL(tmp.gipa.final_a, tmipp_gp_final_a);
    BOOST_CHECK_EQUAL(tmp.gipa.final_b, tmipp_gp_final_b);
    BOOST_CHECK_EQUAL(tmp.gipa.final_c, tmipp_gp_final_c);
    BOOST_CHECK_EQUAL(tmp.gipa.final_vkey, tmipp_gp_final_vkey);
    BOOST_CHECK_EQUAL(tmp.gipa.final_wkey, tmipp_gp_final_wkey);
}

BOOST_AUTO_TEST_CASE(bls381_aggregate_proofs) {
    constexpr std::size_t n = 8;

    // setup_fake_srs
    constexpr scalar_field_value_type alpha =
        0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255;
    constexpr scalar_field_value_type beta =
        0x43131d0617d95a6fbd46c1f9055f60e8028acaae2e6e7e500a471ed47553ecfe_cppui255;
    r1cs_gg_ppzksnark_aggregate_srs<curve_type> srs(n, alpha, beta);
    auto [pk, vk] = srs.specialize(n);

    r1cs_gg_ppzksnark_proof<curve_type> proof0 {
        G1_value_type(
            0x0ad9ab904d539e688d51dfd985c3ae5b48fe28b95503191282d47d6b366e2a53e21ae890306f52749d21666b98371708_cppui381,
            0x1345e24d804d6be02cf1b3a941b916446d137b97c1a92fd36d3ea125d2faf000dcf622e3f602f558524c87546bc11483_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x026aeb313ea0d77bcfb724fd0898bb830365001a6b17c10e6926511c59af9c36dee091f5c5a8ef1dcaa2c242ca013159_cppui381,
                0x1954c22621c04f4e80283616ca8e024a86c58062aed69c053849584a17ea39baefe2e3a6d9a81d771cf5240bf277bfc7_cppui381),
            fq2_value_type(
                0x00c2b1a57ca24010cd4b5eb1b7a3765bba0e16bba8e79bd137b5f3ee7b93c72f2a6f19aa74b30c05de75314c6027af8d_cppui381,
                0x01334537a911f0f56d111198f3d1fa4f6d229e67acc36239e3880cbc298b2b400d75d2a35b9b190c31223e8dc77df6df_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x01fa9d8671ec6696ae5766c83d7bfa9508ad0d94b36df00ada865979bfd005c60113655fcd19f37992eb842bb4bcae66_cppui381,
            0x17df4c2aa0d841a72cc3187eb82ad56f83dcd1a392bfa175ef7da90a26963ab3f1cf3b364a0f1a9c8f1e74902451a96d_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof1 {
        G1_value_type(
            0x04950b72c0fbc98ed63bf338d331f95018e65821b0b63fe4776c8e189453da8a71de4ed86be50c3729f17642dcac7579_cppui381,
            0x00b1f015a6c9c93805ecb0a8143e0c202d5b086f31f4420d91d7eda4e19d744f29b5dcae6313d088098a7376e7f1d38d_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0dce4e7e35ed6949e7132c280ead2bd33bea3d5afd8d5ae33ddd71fd81b6624d4baa4aa50bb4fc61ab3b6475dce4ecc3_cppui381,
                0x08da12416a18cb4fad2a56ae2be196187d48b9f733c4a9f8f0383fddf6b06e37e46c41d5b62ddb976315864ee51a351f_cppui381),
            fq2_value_type(
                0x14f633126ba39da981d4f3676c0ad2d0879abcdfba33c122bab88ff0494a7c425793164cc07b42d13127f26b28301e01_cppui381,
                0x0c7d788fbb2a93b89bee19a9f51903507a3b1bade0045d4827fc52d4ad9effc6a972bc55ae8a4418949bf582a7e57f3f_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x100fad40d4778047cb2c02c53afecd6b25204d7cce9d11e3ea2f7844accf6380ec9b421d5f0656a8c9be03a58ac0e78b_cppui381,
            0x0ebc959bd8afb8eefe2904f9cf7831fe95bc946f8dfeb7c2f6f4e3d39bb99f2d966df2ed51580b8536cbd24cd042037e_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof2 {
        G1_value_type(
            0x13959f8f1cf314f0d36de6fcf1a37e3c8c3fc31c7087613d6e209a56e48b6cad49d1ac0b9a522a1e397b05e33a606496_cppui381,
            0x0e1ce1604e9a6bab679a7a6e60c2d8ca1553e5daa493b14a652817c903b0db4e923a483fd31eb433e2c26e28d669d3fd_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0371fb9497ccc88fd0a002f32b7b25dfafabda8f1e199e3b782bf298bd6e3090ca1e2428017ec810c1f8e230a23199b0_cppui381,
                0x0d0ba3656cc98288785f04078f95f26d44a4986998cf70566e2fb951abb12dd597f650f9cfb2ccb0ea02d009b00d71d1_cppui381),
            fq2_value_type(
                0x18878ec7f9cc8af17133d57bc9037e5f85959d60354c499c60f28d09835e25bcbe3d1cc51a0afba06272ac4d48e46c64_cppui381,
                0x0e35c4a708d02101b8aff1356e580f5b5ef57d6be16502002d5576bdb2210450a46db93e1fff3161064d486b92b086d7_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x049ec2af3342cc36e49f5533488d495cb7222121d0836952fc879f3fb46f073a3f6c4328a4acac5d86a99a784c188718_cppui381,
            0x02c9a8fe286b1b976549d57fd3d677f393b630cc1357b5f90c11b0482cebaa97e8e0b927a4b2b8c39eb4b1af85c144ba_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof3 {
        G1_value_type(
            0x09f1a68bb0428c34179c3c375ebb2c3f8c8b25975163ecaa6e71e690f76c2fa2d5022e20ca8035f6ae4231e36c9194c8_cppui381,
            0x06df98360b6aa4f1ca6c3e96dad4544be0119c7ed208224a1201ce03759813daec68d5a940e1095cd5f1661c2c6c68a2_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x06aab594ec527722a6541fad603b5fb788e1806d750560e1c4ad95e43305de35f1fc56ad9e45458df56c9fa78936cdac_cppui381,
                0x1988328897e57d1fa847d2dbacbc46e0ab1c936e595e726d81a451e932de637420d8499a11fea29a50792fd8ef4347e1_cppui381),
            fq2_value_type(
                0x106c544e28d5d00accc9f6ac307d3ef08933969cf352682baab21e60589e8581115131207b18280026b78807d6a49f1e_cppui381,
                0x03082285d382aaa13230a4895dd3da142a25fdce91165eac137901ac2c1964278fa9de8313039bc1f28e8f3af0e5f6e8_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x1140867bb1399cc013b41291e4127f926e1400281e533e4eb0586052622d51ae135f91eb21c4aa8ed5d85cb68129cc4a_cppui381,
            0x0e59f5f7cdf0605c0bb524256c3fa9c8186ec31024b6eb71c01ee9da576678a7d83f777feebf11c470484daf2e78c04f_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof4 {
        G1_value_type(
            0x07eebe2a51ff54027dc2e9333736203449cf0fef6cc7b4539f8962e8f803e98d01d308984c8a437cf38636586c954646_cppui381,
            0x09677592e47aaf01cb77fa2fd567389c3c06ab63944fd43d6538b5da3405d9c152869535abfe1bae1820f0ae744e71f6_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x15276efc1aa8908a0e13029274887e6e599603cf6ec63c3293f2178bf282fc5cd8ad4e2ee971eb945063719cdc67b655_cppui381,
                0x13164f607512d0035923ac0f34333328917f598fb74e30fba45bfae098ed39e43a7b299fa871a91f1d2e3aa28d546577_cppui381),
            fq2_value_type(
                0x0234b5566ba1443b3d71a4d597b984c5e0401ab0c92394521152ffed6a15e6bb616cf454b2597f37d1d6d0825d99a460_cppui381,
                0x0c28c5010a6ac31f5af16ce861fef465d978c534d602b3042e42b766997521a965afb25a00e3d91aa393482f81e87a2a_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x0b39ea2f3908a057e90045269c343aa12c7c755fd7cb5f23a6774f4dd0e23097ae77b984d4b59d5e585161e759777c79_cppui381,
            0x0c76a611c26bf59d9edc44baac48a21ddb3e45c65ec845da57c5d7c683bb18154459b42aa305bed45462014157dcbe5f_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof5 {
        G1_value_type(
            0x0e6d89bd7ef0b93907916d3903b6c49adb1535071d6f681e03e687dfe90d9c7e74a0f55be0bcc42c9b16e2e99653504c_cppui381,
            0x03413cf7e4d3c43f02ffbce3682dc7886793f821efb7bb28000537b1f7b4951f34f3293013f6fd3c211979966b5fac69_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x058ecb344b1465e18c0ef4893bd06f7f323a56120e948c04488fdffd27b511db0bac296a81b46c660957dd3a923ba51d_cppui381,
                0x10c18ef70e107e145a254406337969dc20cc85bc22ea6acb14d39394760ed95f5a37b8fa6495bb347986e50678b9432d_cppui381),
            fq2_value_type(
                0x04c87764181d768e4b6ae9997cc9c62188e856fd650cfdfb260ff4a917da064d9429978b33012de0caafb1b3d4134547_cppui381,
                0x07bee15dbe062c38b2dd97bad78c2bcd36b1d09228a0581fd38493873b4e22654114d2320e25afb7136857355bfe3bc8_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x095b0c84330dbd160a40254ecadf867204780ac0324b4912a90e75e0224c4457dfa4d4d4d6231f6520d93480b0b43a63_cppui381,
            0x0430bc5b9127edd363bd0adcc3f957dd4fae7410a36a0b599f87eebaaf304fa23c8c392ad6902793f358f57e1acfa5ec_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof6 {
        G1_value_type(
            0x16dafd3b138ce9789864f661810d80f3a27559d59fc7c7c2423a8a2e5d12c319d362f74d6231d998a8b1d3f5858b85a2_cppui381,
            0x0d68d83c3beb8e6ae1bae0f6069246d9138a39bb49714fe1dbdac7ec72db27b2535cf62d9d316a2715c0be92df37c9c4_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x063473ae18d079f24f7fde90e0e613e7d1d736f761c00399767260637fad11ab995c6f45c600307f8b43e9e39db3efb1_cppui381,
                0x091f08c799bb8ee1e3e3e9a7aed1bfe320e2a44db3b09e35fc72647155af6d11dc45661a4a231bde00b1750cf8f5fd94_cppui381),
            fq2_value_type(
                0x162465ff561f7eddb102f9b79ff9022c2046489602dad7ce1a6347c10868324d2f0bff43dd3cbcd637050afe6813588f_cppui381,
                0x0eba1cc671c6e28c2558a8a8de94ca3828b6ef68821d0329becd029d57a4dedc4b6b8e107512b95d8b0864d017c91f75_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x0c65859ee85e435fd159631a5cdb53c81746d75b8bd39bcda4290b774cdef5a45fc136e29e85ae604065f2a95ee120c4_cppui381,
            0x10044930ad3a76b06c0965b63e3ce70777bc5e0e1a471cdcf60cbbbbd85bde3cabea6def846ff8b29824ba6ab8e0fe70_cppui381,
            fq_value_type::one())};
    r1cs_gg_ppzksnark_proof<curve_type> proof7 {
        G1_value_type(
            0x14b8d9ff73badbeb796cf47a06178948d6f2aae6115dc7033e2f24835c3d81a0abb143c13cd4f5ec97bd7972008572ea_cppui381,
            0x16743804ee158723da1b39a549bdbfc29ab503f4e8015e7f83cb0f7e486e9907e721b5319ba117b54a81712a7029b1fc_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0be8424bd528ad671ec62204e1d8bf1a633e40a9271535fab37992aaa2523003e2e8fb22136f4e5b5205c2df7a0f40e8_cppui381,
                0x092c9c93a278821ce9d7d0dad3dd01457ef2acbedf3d51596180ebfeac0f49956690c84b09d66f05287632c1b98edd5f_cppui381),
            fq2_value_type(
                0x06b7812dac5bd4cdc995e6a07972aae556e0a1f63e8402b8b6f64064a57d27fee410079e5a1f64dea586903ebab7d4c5_cppui381,
                0x0e83148931c3a1e5215f68bca10b70fe0c1ae09e1de0f3076d19532a08877af35c12ae87b1dcee68cb7d089d70c37d77_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x0661e59a523ad7c7a6753f1e70a6aa3eca1a1a650dcc6941e18194821681719496b8f2c10b976db51fc9e296418e1ae7_cppui381,
            0x13727560e334f46eff7575d562ef0aebd34d9b174767a8fa99e0c96afce0749cd629a801bf2951a28b8e15238044a655_cppui381,
            fq_value_type::one())};
    std::array<r1cs_gg_ppzksnark_proof<curve_type>, n> proofs_vec {
        {proof0, proof1, proof2, proof3, proof4, proof5, proof6, proof7}};

    std::array<std::uint8_t, 3> tr_inc {1, 2, 3};

    // r1cs_gg_ppzksnark_aggregate_proof<curve_type> agg_proof =
    //     aggregate_proofs<curve_type>(pk, tr_inc.begin(), tr_inc.end(), proofs_vec.begin(), proofs_vec.end());
    auto agg_proof =
        prove<scheme_type, hashes::sha2<256>>(pk, tr_inc.begin(), tr_inc.end(), proofs_vec.begin(), proofs_vec.end());

    std::size_t prf_gp_n = 8;
    fq12_value_type prf_ip_ab = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x06e382f2b5821951b0194812b08f3d6e7515e204ef39b8d4abedb85c6e8533ccea8cda1ff55a1d5bc46611fc81aa5224_cppui381,
                0x17073262593261ee2ee5b05dff3cb7b2c775e4d8d6b67ee8a6ec86d38a461915f749646165fc7906e0f63a4a68f11379_cppui381),
            fq2_value_type(
                0x0ae1f55007b1d9eec7a4269f5532b2b26c3c618d8e0b18b54aa9cc9c8968f0fa55e3bc0664737734eab9b6280592659b_cppui381,
                0x18ef647c9a850f7c069c6e699e09879a8fc078ff57eb2a70652c7f6c481d9a8db047871749c3fd7ab90bcc222c21af12_cppui381),
            fq2_value_type(
                0x17610a19b1994fcb5707d40c1f0af1d56084c28a8ba209dd241c694e9651776c60d2e6bf5ee947a1475b3d95b2138b0d_cppui381,
                0x0ff40ac478ebaac8888ac0607f40362c4b7321e30c7ad2ed8fffce36675fb44811e27de762c9cfff7bf80bba56b03c8c_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x17cba7860f256536081c131b2b19ef98d1916fa60b08d7a87bcd821110cf9fea46c85202a3f296b420f290168215b750_cppui381,
                0x131fdd3ee9f2510fbd5b42612ac9086edb31ce97cb1eba625f484ebde4c77b19cbb57e620af065466d892cfa8c29822f_cppui381),
            fq2_value_type(
                0x04ad75d70807cc5521beea75a4ddb5bf4b64b45b3fff6bb38f400c537a8b5f7f756f230f6332fb7cc119627f5f59b84e_cppui381,
                0x12ed6b1a90b2c014ad27da31d9e117b09ea79e0361a90eb093bf2e0791539e122e8080d00dbca76a62a3ade0df571429_cppui381),
            fq2_value_type(
                0x02b2df29004ca3853fdc12342f145dca4b6ab977fbe3e5dc8b1a2280d95ea79d8ebe4d87ac75d7f05f4b5dcc546bd87b_cppui381,
                0x05711b1370bf0584b4e2332c1705b98fff292fabfd3647753c856d0a815fc126e5e72813d342df67223879ec6794376a_cppui381)));
    G1_value_type prf_agg_c = G1_value_type(
        0x079e716292f9040c956f9d576c9070d173c4cdaef39e248e24f0ab10c17807892a43d1cad35f90c29be6035e171c4577_cppui381,
        0x07d4ffd556911a0a12eee0693c34dcc23935dda6acd9158241c66e5c9b626941ff3812181929b4cd79746cb30a944412_cppui381,
        fq_value_type::one());
    r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type> prf_com_ab = std::make_pair(
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x0f7f86700fba25905cc7727397ac7754c0408e35b50d4b6331d05a779df7aff08d6bd3ae6bf7a2ba089cf0f4a676807e_cppui381,
                    0x0e398ab7e0c2ec1f8285e48fed66c971bef33de4608b36fb90820c5bf5a589023cfb2119f92e30a9cc36baff880c7361_cppui381),
                fq2_value_type(
                    0x18ee824c51763bda9d3b45f6bfdd17137417203a09b9f03d31f4d9649ba2298d41f1c52a8a844e19dcea520a706fcad7_cppui381,
                    0x050dc7c2c4b5175aa76a1806ce5f29398588c4f0c1b87db0e12e3eb931bb6bb6891a7f6ab89549c3faa8982dff8488c2_cppui381),
                fq2_value_type(
                    0x02411f8bb63301a05bd37fddcf04ce98aa505e2e15bde17f76d39abbeb4664bd7065a9f36b0e96ed32c9b02feaabaff6_cppui381,
                    0x1985fcbd91ed5730857355410053844cac0dd39b739705d9c806f4ca730bf710963a567b07dba0ef41d03bbeeb6e140b_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x1173078dee8cea5b37e46919f743c60165ecbb76339d51daad8c5931cd090edaaf945c890c9ba4823570177183c490da_cppui381,
                    0x06e055db81f375171f6908f674d9a85e7c78255f2d86bca7f88597e9644244026bf3513bd4d3077a5b340020c55262b0_cppui381),
                fq2_value_type(
                    0x001ce1f34b1bf03eaca88598d7236e8ac3c5384ad1ad99be7ba061c82a27bcd72fb2d81e59f9257c00594bd1922428f8_cppui381,
                    0x075c8e7805804a3fcb2b4504cadc66a3d8f344b7847157e55d8b147e0a7cdc00d28a6ba7cb70cf690db135f5bbd05953_cppui381),
                fq2_value_type(
                    0x05169b67be0491b0fce790693798894c8756941bbe937ac98135bb1d1bcacb4942e62512135c6a4738a11608e82e78da_cppui381,
                    0x17871da12d59765097a9f63af94dec572530d2a6b19214b0df06f987cbb7ba8c10e94c3871d5ca0943ccc96cf25b4172_cppui381))),
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x196f7025147d05340d2923fdbfba1fe7d8b1f9507c4b4af9fafb0c8b6935bd626fd36763506367ff42050150112bac95_cppui381,
                    0x00375573932e5691bcb9a4964b32fb8c10c5016e2eba58c6d862ee55cc4d84b0f93cecc331cadcdf23d24459cadaffc1_cppui381),
                fq2_value_type(
                    0x0e5baedd265322c895a9bbeba20bda3d8baa45b9dad2f92f38297234f72788d828cb5f4d6528e9d33c9e1de614f21e38_cppui381,
                    0x13baff0694488c6a795547b4358a10fa19a33b99134d1b6c41d0fe7ed2691395ac2bdf38c9a6d6bee575d01180db7bed_cppui381),
                fq2_value_type(
                    0x033c545927810f35b47036f14a2d7a3b5cc6ba4352851fe716e3bacf3279add22658f3362dd9f03c1bdfdc3107141af8_cppui381,
                    0x0d45b86dd6f7687ab04deea8b3b3775dd9815fc6f1a56d32ca02cc8e7179e5d2331f52fc3c758ee9ad71d470f5385800_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x19c8e6e82af38b425bbc423020935c64ce11d8a171c8b0688e4d4bee01780ca6df091879e03f85a40b3ab7cbd8d4459a_cppui381,
                    0x077761b1d7538edebc7915959234d2300400e187d6d17f10c4ead17ff21d6e1c5567dbdebbfe837e26a77901b731e73b_cppui381),
                fq2_value_type(
                    0x0249b8586a5ecefea5ed29666f29f0bbeff7262a25e3b1e5d3cc2841e62178ab3159946effc6ba374778fc9b175d4f95_cppui381,
                    0x05d27b5a2470e83e67497139d78c40f09ce64a5011c48227ab7bc6e0b04abbb555b2ad8469aa512fd9854562047fae2e_cppui381),
                fq2_value_type(
                    0x19a87170609c7ec1a291d535da29affced5d698344938f50ac1cc65da8f915ebb541369aa71fde54298b635a046d70bc_cppui381,
                    0x09451099402904c365f803d1c1eacdd9a54ac4e08b5c034c660f72654894f0997c6aea51c60061bd55072e3a06d7fe68_cppui381))));
    r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type> prf_com_c = std::make_pair(
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x03b24655c4bd2db92adfe5d271d286983f22a1a6d60e5f166afecfa73e05585c50c67ff0e73700db5e4d3baa18763332_cppui381,
                    0x16517afbb7ff2395eb918ff88cb8be27bf39fb9773a0997b04512784c4f8505966baff58ca44a5caf750944c8b68e4c6_cppui381),
                fq2_value_type(
                    0x05b147dd7a9e0c70543d0eb7f6e7ed8f768396169c46b6da48ae82c440c5fc848ddc6ff239c99d0b4c703b1792405ec4_cppui381,
                    0x0fc43ef927118a8d6ac088a9ea77ed1e003b41f4ca000030811f7ef79bc2313af8b0bc3599976e2b944084912db7a55b_cppui381),
                fq2_value_type(
                    0x069bfff0e3c91efe2bcf45ca64ee588dbd74ef0ad1cbe7bc05b8547a788c69b2875c7f7fb3afc357c270c4330f2d894b_cppui381,
                    0x14d8ebc721ed1aefbc4ecc316bc6a1191c61e9c6e8cc0788b29f8f9a062afa8ab1b492a2c5ff29a6ac25586ff9ec103a_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x0459f47c8da5d144f1e00a824f0e545b00225972d292e63da47b6aa4b1029ad9f5cf9b3a71ae8a48539c3e2629e4d7a6_cppui381,
                    0x0a169c462a52f8ab95e436f718da4c3ab027ce86abf929e9596ab28619b7bb07a7b451c528fd8f12fc254b36b0e5a7f8_cppui381),
                fq2_value_type(
                    0x122a0ab0d6860312334e11d729942e1dd61437aadb7e3043dbb5e69c12e9ba939594ebdcbf09f4e01ef7dbc40b5c2758_cppui381,
                    0x13262d348adf899bf789e48907891b6b89872e8d16564434b26d1dacf6f000128a4f1af4a6a9e5f715c39c9d5e439406_cppui381),
                fq2_value_type(
                    0x0f2f7fa303476732aaff2408968bf1601840bbe5f8b17a97392b0f80564c172a680e57d4391be0b3ad0956249b86ac0e_cppui381,
                    0x10834cb16d1b8d2d2d391dcc898561eb902366947ab94e71661765480803c14d3313c0e779d6ac7ee180c8a5d3d32934_cppui381))),
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x0050fee93436b258b96d75ed8a8bdf8954ea10939d453af35c674c142b6b37a3ee3485559710aa4a8186d6cedb2eda67_cppui381,
                    0x1293520bdffa93f2f3bc8b6dce60a9a9559b82ab1e37d15f729fbb1298ce7f39f588f2232327e0eb469aa3c5fcd335c0_cppui381),
                fq2_value_type(
                    0x16d2f7e0a50d7d6197add277fd1afc793923d4c5e1a6ea25e82715d5dbe49f5444534e229ccf9a46f310e3a36ff3d6ee_cppui381,
                    0x18657b26a4dfb850ec57bf05d16a552baf979fd4a05f92bc074e9c69a733ec75ef0547753cf56a514973afbfa86b3097_cppui381),
                fq2_value_type(
                    0x0bf9573cdb71a0a4aa5487d9e9625676ec55c1e1a253edd667376243594d1d0dcbd6b59aa3d9695cccf7c70cc1e748f3_cppui381,
                    0x129b2ff95aabbed897e32e4e7f20f517a18e95dbe00327804eaa40f3b3d8bf7c5fef8f7f551a7d10bb04d8209960b287_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x0fdca1b3741cf230901a1500496acb92e03636f6a2be37e00cec0c92a69388a62919458b7a52ed53893699e7f2167998_cppui381,
                    0x0ab068b3dccc9d66302b0d2f2539938ab7a277187454a514b91ae950a7d9a5104c3a5ae344fb76e92899c86cdba59225_cppui381),
                fq2_value_type(
                    0x005779c1e4d9a60e0821566b23dedbbb63983f82aeea1156b33401cb079689f414f2e59a7f21b9f1867ebf0223828602_cppui381,
                    0x07c508924036dd76645ef7a52cc1b89a4a6f13793ffcdbb479fb8ff2e1b097736ecd7b27fad806e204a8c4f335e90946_cppui381),
                fq2_value_type(
                    0x17a1083b57c1307a6355987fba76454a195e16e85557c001d607e1bc621b69472d4b2200bcc6ceb1a5f646a80d78e6ef_cppui381,
                    0x06011eccd873cd132fca77b92c6f805e253a2785a32c3a94a9325c003e5695af172011ebc02b61b2368040d1dc9b7ce5_cppui381))));
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>,
                          r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>>
        prf_gp_comms_ab = {
            std::make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x005171366c26279ac5d47d6803c2f825aaad9490de6040781b7098fd0be30c30444dab0b4d59539bc0d58101f50c222d_cppui381,
                                0x1596da39ea384a41f9d4cf7f73d663b470ad6a8be067db8e2ebadd696c747407ba0c7b7b918651a81aa9803ee0ba3d3f_cppui381),
                            fq2_value_type(
                                0x0db4726ea584a31603d0e9cbe804fba06efe0cb862dce77114134b415c54e03956715d6ee9669297c0ee8ba9f429fa2b_cppui381,
                                0x17c1bb6d8531fc5f1df275a937fb83e232dec6e2b2338687ae5050fed615e68908b68638fd36f2667e31cd33379d5398_cppui381),
                            fq2_value_type(
                                0x018c83967a068d0830c612fd98739bb62628f36e16c947d9881ab3b75e72aa12d9226927811207f34db9c5772bdb79a2_cppui381,
                                0x08a0a58011edc06d955cb5ac82e42d8ca1e7b1b128f71ec7ea889efba895c83b663d73d20c6be7455f0ec1068db0acb1_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x07acc3c8d9dde5a9c62440fa2327140e5ccba6ed122e451120d43058baa88409f0144543b45547659ea80efea013f514_cppui381,
                                0x183c254ea5f8ab63819599cf3e78659bcf21b3d9fc184a72aeebb1d69ed4614f28d24892640223461cc7fd728988d4d4_cppui381),
                            fq2_value_type(
                                0x0180c7130567c7e91d538aa137f977c904cf3cb7b16b5343787ed68c818760eadda3388967c6bf3a41ee031b75bba114_cppui381,
                                0x001813f3652b1324b41043bbd5bf17dd5693e180a1d8ecd3224780b143b34f0ab7ac2c1efae2666f370ed1a04cfeea6d_cppui381),
                            fq2_value_type(
                                0x0e806940b799eefc2312de4adf4f2a0652d9db610c947e0f8884f199dbf186988334442c3922f4b0744b59549ee3f2d7_cppui381,
                                0x190ad4e8691474a919b7db5b171de455beab5907b83ba9615324a377143979fd0fc15099a68554e1bc5b13ddecabce5c_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x121df3a10a9d030535deceec87f4d7d02f340d3fba22621be9ace057d5d8638274a49dffc62625ec16ab8a5548cc0126_cppui381,
                                0x0706af71f761d2d7530b38f5ca1b30371cd956e08e61d8ab5d1835c6ed27274dd14f7ba05364491d06d841255766882e_cppui381),
                            fq2_value_type(
                                0x04e93d124763f316e135705ffbb241a67cceecd8390e9d84e7395d0072266597decd963c7131e1121c0531be40940e62_cppui381,
                                0x0218d1b77f39120c504fd90ddce3639e6db4ac0051f86e038f5b8b8ec330739f216b2ac5817aed016449eb6e2455df49_cppui381),
                            fq2_value_type(
                                0x15bd7423abe93e0d4bd59b88a98bbe693388753f09cfd9f0bb6132bf5e96551c84fb0f58c21fec746451de9cf99abe65_cppui381,
                                0x17ef1666d64ad15999e7cc3d30579ff3534d586200bae0dc13e3c56e3143382e42b82f7a0c690721ce8fa52a91a4f986_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x091b037c2292f191abb27f75277344a04ddcdf30000746867d58b3b824c8f20780ccd4eaf8556c8c41a1fbe3f60af39b_cppui381,
                                0x059a6d711af1463611e3d9b19dd7855586c3c0118162c7ad18654a131aa88917fcd7d7c2bd9895fd9f4db7cebf04b520_cppui381),
                            fq2_value_type(
                                0x0c0feea9e55599453b18c6eaa5efd712526ae447a7456c95b47dbefb772e480ba34260a95e2f3c4d650f5bdab16f8c60_cppui381,
                                0x149a6491e56b6544686b100a113aeee959b4d48452382e4f12a9b5eee23a3fc9dd14b623baa9348569feec6770e0a376_cppui381),
                            fq2_value_type(
                                0x12fa68da8f44fd228486ae3678ea271c17588f1b0e492b57194c40cafeccc97f3cf98b2fa155b222d51c22a9aa83a784_cppui381,
                                0x0524294bb2342b2dc9a691540aad0457867298123b10d754832d6fd1448a1156969f012b3e0d1ed20f6fd41894c74aa2_cppui381)))),
                std::
                    make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x0c3c509289e990c62ab18898995ba40d22e72151697b779542dda1afd3fbc4337b553bd21239e5da7f8d791d132bd24c_cppui381,
                                    0x11a7bc72e5f43c95bf62bce9d50db6422e1fb99bf321d739fd0a191c371678a98bf52eb2d343d7ef6402ccc4d3ab68ec_cppui381),
                                fq2_value_type(
                                    0x0d25da2f3b350d682122d7f06a20c58df74fb5705e452577c3a02d79e4bbe1df36aa980042705917600881de7dd1adb0_cppui381,
                                    0x0938e75658f0f42811aee03c59cbb2fd171475da59831bc3ccae6817177f5e17fcf160a1c1cf6fb4e16da426841eb5fd_cppui381),
                                fq2_value_type(
                                    0x048de0d2799b15e364e4e9ee673d3990ed54e33887470a399def55ade45cbca2ab7710cec8de76e96ab4478d08c19f5c_cppui381,
                                    0x18b69a1e1a5a6f47e9aff310e241c43ba46a539fb0f5b269473606c2e5cc5452b0d1f3f7d20884c4861839bfd19d5acd_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x096dca135a39681e4a77f96eb458aa4ff8619b10d821a161b8d6c1ae6f94901e4a0c5872ccdf500da3b068343d5c3b71_cppui381,
                                    0x13ae4d8578701cb3d0a1667e9bdcb34a3998b830f34cf59144257b7d5f2627fd4605fad76df08881d8606568e304ed78_cppui381),
                                fq2_value_type(
                                    0x13328b5d3a12ec71b113eb5cfc0b25436334c568d9d9d37dd2b3fffb5b499b0f7b81e8d948f5bf658e80df366109c99e_cppui381,
                                    0x0bd4fbc7b45978e25f138651e8405b149f193e7d91e15dbcd6895750bff59d7ef03caacd0834e0ec8fe4ce91d7fd3ae9_cppui381),
                                fq2_value_type(
                                    0x0d9e6edc7abae46488f31bcbb84c1e49a3c11b431329c93bbee3ea5dd41f6de992144f9afc134beb8f79146b27a94283_cppui381,
                                    0x0ae49b29f9dc4c072692f25bb40bcebfb3571e24964ac719c81d2b1d6e87b27864bd00d5c5f2f354402280dbe2466e1c_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x178308b01d2449c2fc2bc5a246710e96348332dec7a11bf37bd65338aadadfde22391ad18635efee715c21af503dbb86_cppui381,
                                    0x0ba095f88702e8e3af0761fc84110c94b97fcd77c2c243bbf0efc2957db1ced41237ed7c82c0ed6d4eb463328ecf4302_cppui381),
                                fq2_value_type(
                                    0x0a028bb3145a5a73f7df15ad564abaebb046d2b99d82e1afb0f7abdf93fe14391fa1dad638925b0e6b928f503366ac1d_cppui381,
                                    0x03d240004d0c03eeb6f9196c1eb9a29ea04396e417630c3cc33311fa0e3695eb943994ac48ec5329dd3522da8ab5d802_cppui381),
                                fq2_value_type(
                                    0x16b60cb32da156f52d9ad6b745130685ed51588d6cc28c165436cb0077bfb345a8e5aab9c7914c1d72f21af00c6d54f7_cppui381,
                                    0x18f07c1330036d6a77bc30acf04d6b9b3479625c4292b47d272a6c138226cd15376a5100419e192292640a7f2da8d1a8_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x0ee8232bdbae78404fb3d04bb5d32201caa0dafc9352a092f6233441e83b1c12628eae989c81bdece1710050f414016b_cppui381,
                                    0x151588146e9663110b0d4f7d237ee457337f49d9f406dc9eb15d9df1b459f8ad79c23ab8da378dbec738c5f6a6550570_cppui381),
                                fq2_value_type(
                                    0x16fa3f7b2857db201c2b36eb5c2c63e0191250ea6489b5861211317cbd0a1411ccaa8b188478e941bfcc3baeea221476_cppui381,
                                    0x0d22164bc53d6bb553e8f4bb778e88337ec5938530eb0b5015a9f3bf3b7b46b6f12cd52be8593f1cba4c9db167e3bc2b_cppui381),
                                fq2_value_type(
                                    0x184f797a03c626f0a30eea9afb35122df2e635af1b2afeb214925078a9df88b22bddd1f55a01e6d6a23a95195833f8c8_cppui381,
                                    0x0e4abc9f6fb3d17050ab9ae93a95056748c05da9107e7821064f2b1fd6903fba537d5274c5b328bab0cdafb60c651eaa_cppui381))))),
            std::make_pair(std::make_pair(fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x043c5330e71bfb5ce6e923795e7fb6d6628eb39d51498c44ee621425eafb326105fbe755509f9c6ba745d3d5b4415674_cppui381, 0x141ba964279f3d5f4327ba04c4f8848acec479258e5058c8a207bb43a348de5fca532a8e310ae9c220ae4a0ce05ea830_cppui381), fq2_value_type(0x0a456511fa23aae810d4c1f1112fb0e1d0b008789ae59481ceb9aebb976726208d8f2c16c1829aea2febb9f847bd7dc7_cppui381, 0x023cdaad124e21466776864d917dcead85ca7463d668f8cdd92949c8ce1bf0a81ab5f49121b158e774e8d0835034f198_cppui381), fq2_value_type(0x02a736547ae54e2705b324474742e88db57a5ed4defce7f5fcc129307864d377136b34c869610616d6e95d19d977c6d6_cppui381, 0x093f31ac7eea687f45e8607e69963cc38f643d43ed16b11e3d752b14d39bfb3a4fe2ba4cbef01c51f32480e8f12fa682_cppui381)), fq6_value_type(fq2_value_type(0x04d912752485ebc38bbbd88db6514050c2323cea025d9a0d0195ad7df76ef7d16c1fad74d04e125b8b90ea9115a42d1f_cppui381, 0x1700ff80462487faa02387867f3a379db214cfd25387e8de330a85948682b3abe52d9daee21f916e7c046f64c71113dd_cppui381), fq2_value_type(0x18978f46f9b0e1b9ca5fb3a6f9f6e797448ec2ea55298e1ddb63e0dccc203c013dc4a8e835ebdab0d6b6a749a959c4c0_cppui381, 0x116141a2852dfe1d8975dd21cb938d741c73a17d8cd33cae69ccab7a0204e04b876dc7e013b4f0f24864b67bdd320fea_cppui381), fq2_value_type(0x13b8b123c4c4edaee5aab3a21baea04c5eb50036b402669cc73b564c330066c6187d07c9e13436420e9b9a35407d665a_cppui381, 0x046b9358226a2e3378d74be97e4f22801680ec747cb0148f6ce740a4cc8938c57e9266be7463c3656b8a4da7fbc6039d_cppui381))),
                                          fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x1058b84e5a27670bb2d3975a9200d6828143fe70c994168e4a0b7423ca4559ac50b1e5390d3e5b1e352c213e9ede35f1_cppui381, 0x07942b2f6ef470f1cc58a5ea651988fc9ecf22afcfa7814c975676920db6376bd8b0d97eb1ef411de8e1c06ed0219b18_cppui381), fq2_value_type(0x0f674a4b6089aac668d72b1f67d76a8e0a1772610fda1ad4929a66eb58a551901c5f5677c31b2afbfd2d84405d6b5982_cppui381, 0x0aa4db924381b8dc055487c067989b52a8ba40f6c7326410a94b5e05c95ad477424d8524cf73d32c9b59aef7f7342014_cppui381), fq2_value_type(0x007cea626bb5cffcb9fa593ffb4acb127496b0874a921ba9825914dd63918f33beb5275d35a67e2f2cbc001b669b389d_cppui381, 0x023725d7616717e9e5b1023fd7679f322822385141d985a36639d9f8ef6246086bd746fdaf0bab71de618c414ce2241d_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x06c2ac02c9ae1b80ca20fd9d0b1973068901dafab305bb4cd5dbe6f4086a7629ecbd8381a0192c668a89f74778f6a411_cppui381, 0x09410255a5474f331adaa32da5ac7d943769dc7e02ca6da68a020031df1ed8155bd2b2202687bfb78ead0e296cf4a694_cppui381),
                                                  fq2_value_type(0x117796d2339c9834924b52d04d4b5ecd5bf84e3a16de827c1d41c9b05d4b135b4c97f331db019e1905f3fce0ba6968a1_cppui381,
                                                                 0x01ba2fc7634da06460c8cda364fa795027cb5737c06c01dc49a87e82e68d341c11cfab86dc38e052cda17d64b771ed81_cppui381),
                                                  fq2_value_type(0x11ffabfe4fb2acb09992627a01722bcd1a76d48ce85d435057a83c2251ca9c703bd99b75747bdfa6a60c057c13ee2987_cppui381,
                                                                 0x00840059d1e7c3e8945b6332a1fe043786ed35c44395b9d06bc5549dd52d51262791306fb5b1a9254c5daf2955debc0c_cppui381)))),
                           std::make_pair(
                               fq12_value_type(fq6_value_type(fq2_value_type(0x125db7da1c1320cff1e4ca398f994f31735e7b55318ec967812feb5c7865a58d51b221582bbf3699dcdaa88bbc7f9fa9_cppui381, 0x0a090237dc140a2c7db49426dba4fced4083f329e8d899a460e6a427005eb4a60eb507ff6fe234106d1d3711dc052e2c_cppui381), fq2_value_type(0x0e753dcb9d994090493a33bd9eae55b5ce43f2185e56099385cab759b419dd893a3ce508fe7cfcbeba983e3ec18d928a_cppui381, 0x0af1cb913d12b8dcb7de93d455738b59e1ff8b51d2c6c1d40dc081cd0d90b1b346977b7f0b44e355e13b85545f69e596_cppui381),
                                                              fq2_value_type(
                                                                  0x05e7d476ebe1910b5e2ee9046b2d04bcbe0c09ce00cd98bb591ef40bb69e9e1bc01c2422977c758d620efb0617fb599f_cppui381,
                                                                  0x0cdcf6b7a4459dbf435b5e6e765fd6cfb885dbcbc2f30690ca4ea4aeaffbd1ea0b7ad42cc4f3f7efd966f2678e092141_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x17ecc804ae7dbc2e2e90d33e83d5c8d26c67001ed5015cbe0d46bdb4de877593daf02d6b3f2bd733f50a9c21cdf970db_cppui381, 0x08d7320155a5392b3959494b9724a025f6928aa155166bc0fb61a6a37889ee28d0fb0cba66fedb0fa2dc2cdf2fbace22_cppui381),
                                                   fq2_value_type(
                                                       0x15e1374a440336203fcd65b7f1366e9bbce40c40dd2b3e32eccd4e7b18043ea3ab5050bac9a194f4eef6533c71d48d7e_cppui381,
                                                       0x115559b03a9ab8ff9f720dd6ef0932ec598c24c2ae122274a6e43561ed133a4678d4c10aca79098d435bd5f3861e72c1_cppui381),
                                                   fq2_value_type(
                                                       0x0cee13761384961ee27a91b5dad2b439312c29bde30b8d7562807ec169e3fba901955a22bf02a5f93a45145b9cce4640_cppui381,
                                                       0x1619f34d7be4d7d44ddfd92628a454019a65b670b44fdf596c8e0f9cd2dc1c2c56e1eae49a8febff443c741a910b9141_cppui381))),
                               fq12_value_type(
                                   fq6_value_type(
                                       fq2_value_type(0x14640a28c221e652ea01ac88f13413222ecf150224a43d06b54e6863f0b4e2ed40eac37c9743d163da03530a50b0b9a3_cppui381, 0x1665bfe57db268de177a93ac2832be895dc2d240dd51e4536a2fa6baab1401ebdcec05b608812863cdf11cac5fc0f895_cppui381),
                                       fq2_value_type(
                                           0x0b601e729fe2bde484de77252032bdd5ad1da0e76ab2429609e7e39f45f3058ec660b75aa05f39def238a9b8d704f7d7_cppui381,
                                           0x11762f956a2cc35e122815486b9a1dddbeeb7ae516ff86c283c4614a9aeb6fdc5f6137f3f5ceaaccb270effa4a486ab4_cppui381),
                                       fq2_value_type(
                                           0x0991dbcfcbfd12c137dde4b2226814610a487fc377b6aef4e6faf018d1d10a453ceda63e09e873c417384d4dca0cfda0_cppui381,
                                           0x0e8ca630d8d208e5717895793f812ba65c7b4a76c53c117f090e80d5f5e4f03422ee668046aff7f2cab22bbed56e866f_cppui381)),
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x11c74fedcd869bcd60ea6cacb9944a93bed3ffd8df88c0e81ff9e0489250b80422d03be3faa5387b0044025b36399326_cppui381,
                                           0x16e12b97c6880bb714d76c8a81c5bdfe1fdd68ce505d4ba1fe282eec953c452205f51bae70b1d02a2b36136076c0b92b_cppui381),
                                       fq2_value_type(
                                           0x0667b56e01602eb46a7556d5765ff76f63208960c048586b4f98086976f70066a181ed5face372f3c839a8f6e85bd768_cppui381,
                                           0x0a9ca4f64c590c63417d189a0495a100fd8b80c4d61c72deb969519db0d7042bd66fe5d4d59e3c34497ebcab0e7c8ac3_cppui381),
                                       fq2_value_type(
                                           0x1633288fea58a317df87690bef2d0905b35c3ec2c6a427d8dcb93b7018b2787bc48203cb6392b5cd752661ae75012e8d_cppui381,
                                           0x0860486ea3e6f362e6588b58693d20e3d81eb9b65c85e24e201cee68f5b99b5059947c3717ea61bc8a217b70b31f52c7_cppui381))))),
            std::
                make_pair(std::make_pair(fq12_value_type(
                                             fq6_value_type(
                                                 fq2_value_type(0x177e0fd5a76fb5c5f6dc1730cfef8f9db491d8811922ed5f993a561ae1d9bf915ce95ddf05ad29f9704045ec30b143dd_cppui381, 0x196ceb633fd03103e9baee645f893c8dfa471d629e1e7550ec28bb0afa6bcc50432249c022a703058e1ab1aa3f148f91_cppui381), fq2_value_type(0x0ec7a7c70901ad7c6e963983a5a7a125970ea281df5b021583170d85719b6c0c1e70c542f7b6c8c0641a1cab95213ce3_cppui381, 0x0a03089ac1cce96384e91fa94ed78c11ff939d95354511daa90cea93a37db8d85eb181df2106fd6220e04ab6a5783b02_cppui381), fq2_value_type(0x0a70b914d0f4959d9f132b5856bb8bb99ffad52cbb7032724a01edc39336345106bd1820d48e8ecdc6dfeb0c9fbd4b00_cppui381, 0x14cc1b39396d70fecb1e921faa0959e814f668a2fbae3ac77b249d1b05d9bfc054d299afd1696b690c5bec9067fb0d05_cppui381)),
                                             fq6_value_type(fq2_value_type(0x07acc35e4026e32f922a0594efa289955987f0f0b449b45f63ae6b32647ea69b2b9839e0284690576a25d83f63c74acc_cppui381,
                                                                           0x008131a04439a62e484312797930723559dc4431cd10b9048492948c681ed696e702fb06f3e708abdb2cd388a46f13e6_cppui381),
                                                            fq2_value_type(0x0a7aada2f918cb35d88faff7325f99e5aaa9a08bb5ba0f17591c01b36dd4405d1116202f8b1785bbe8c176e9fb874ae8_cppui381,
                                                                           0x18fba1e2686c2d1514ad54137aa2a6c071d3d485a9b91ae69fbac945cfa38f39b2e75b6b3a0c2af853124673c4b9faf4_cppui381),
                                                            fq2_value_type(0x1075da6d4cc923fe0c419fb790b11804240bb6a1ffe4952ed0d9f59957224959355afe0aef326ce5c1047158264f104a_cppui381,
                                                                           0x03897ecdd3b6e3a4ee6a1b819ae0660cdc9b6d3a5ec02f9b3f40fc0c8096fbb08d26fdbd8e4d269fbca2929f0ab0fb11_cppui381))),
                                         fq12_value_type(fq6_value_type(fq2_value_type(0x10384944410ba651f8342133daa89073c2b99702715ceedd4f66347c6b2a76623bf5adafcf2790311b1a655f8775194b_cppui381, 0x0e7dc62df8272334de4499865060a458c5c1748b835bcd57bf8e6efc7bf9f64efd2225551ae92a66d50fea8d8056f083_cppui381), fq2_value_type(0x05b3cd2f7c2dbef51b1298bb7bbb2ed3f4b66e7492b3777043f04a7e946dc0537a11672fe489a9dce0babebe77a6445f_cppui381, 0x06f6a966c9ab97fa4c778ee4bffca9ac1bcf80e54fd78a82b12a3dd1b4a26ab4f24e1e1e91a076d4fc0307a8af29977e_cppui381), fq2_value_type(0x0c5bc3000c337811f9cb8a6004578be2fbe3910046e066a1366e8c78d06b054eaec95207e7e16c2ba8621ef1de300eb1_cppui381, 0x162a68a8e2b216b64932d32e634993367d4009a38e043c97d81320aed6f9120d5b5465236fb5a9cd13bf1190ee2434a1_cppui381)), fq6_value_type(fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          0x0ac964dc11a324808280142f03ea588b96a4a230bef85617be3666c0b8ffd886678de41d2599eb668fc7a7e96637ac43_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          0x18d38d751b0b97f01737ab7fad6cbc9a3d12d7f7d4005760e2ea911f91fa5d037c178fc58e8bd96bd0aca508d95cf6b5_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          0x1861ee37d6e6a406d5401793dbd1e48a67b8133e1851fdb2adcdf52045ed516857eec6a2d7ede1dd47baa0afba000fe1_cppui381, 0x07a19aced9ae096ef8af9e6d31b77ef6e4c115618169fa396abe0fc95d57bfdb9d6d963857bf4b9bec99a7ad3e96f302_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      fq2_value_type(0x1320b632dd321ab597e52136bb8ccebe47b73fbf2fbad470a563aa3fa156ffdf1ed114f2364a5699412f9e406ca68aaf_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     0x0fa7a7b6d87063413d8098ff116e9984cde3e5d8f84a217701b395060603e8bd16020ec67a9eff6f7f5dcd386d749f37_cppui381)))),
                          std::
                              make_pair(
                                  fq12_value_type(
                                      fq6_value_type(
                                          fq2_value_type(
                                              0x061c2baaefbefe3f558e105b8633f05f9f48f360aaa2f736c318b93a13c65e1f96332e38c91b2d1376c36f32596995d2_cppui381,
                                              0x0d84681c2abb8b041831db5f77a977ea6c10a775c1022a664064bf6d486fe0257c02f15f59ca24128e0c4b722b6f42be_cppui381),
                                          fq2_value_type(
                                              0x049ceac4612ac5797326d863ddbb413adace9f24f2c7ab7212d781e74d2a4289ade78332f0a32b2ec7310c4a8c854f43_cppui381,
                                              0x065ea06e2bf55ab3e275ded870be62058c167b3a4ecaee3bc87e60c3a2f4479f00f26ef277541cde337bcdb0690c567f_cppui381),
                                          fq2_value_type(
                                              0x0e8796c8e3c7377a7404d4290de1bdfc3aeb8cd6652499b2e33683fefc9372d237aebe2d322ebe7ef8d4775da1b90621_cppui381,
                                              0x0e43db9d0e5cc8a0f265066d88be7b0e8c77230fe3ed64b2ca29728942973dee7d820c496ca0f8f8573305140c9fe9e0_cppui381)),
                                      fq6_value_type(
                                          fq2_value_type(
                                              0x05c23dddde09e67de1fa9826a8fd112a83bde34553e1ecf75308a865c6e6a3a6af198dc6c3dde019013c320f1df73e51_cppui381,
                                              0x05f0c90ffec97a61d5ddfacc185668f61d83e2474ddbf27b6b3fbd189eae7c89cb2977f60ec64034314108b10d54dd9b_cppui381),
                                          fq2_value_type(
                                              0x10b2e24e9f12e0a4dc72798fe58ee46c98a15898f601ae907258d9e4e17a7d0658f409307f1e1d03b2794ddfd231cfa1_cppui381,
                                              0x088df46efe6ff738b01a480fdec339ad6c1d63e8f8f59f036db5f401129976b62abcc21b54b100cb63594345f15cd944_cppui381),
                                          fq2_value_type(
                                              0x18fce451ac171917b5a635cee8d6dd1a2fa54e6bbc7c51d6a33da55f99a28ac38e405ef1c2837250e293039e5ad17cc7_cppui381,
                                              0x052d8b5700bb5d61103a4dab1167117bae116db7be271f87361e85605200667cab269b354cdd109cc2f9cca44def58bc_cppui381))),
                                  fq12_value_type(
                                      fq6_value_type(
                                          fq2_value_type(
                                              0x1342152652b7565fc3967db9c1e2a1016706a16f196d465133ae7f70af663f1d189e1faacdc88bb1a02346d87aa8bcb8_cppui381,
                                              0x0ea20b92c2bcea5972cec24b5fd872b2ba8b99693b81369a16a0487fc2c147534cda919980827f9379887c2ce13e0759_cppui381),
                                          fq2_value_type(
                                              0x02c70d3946ab946d2d0ef16d0e2abff83210d18654c20fc48d5d31b33f55387c253935efdf22c7a568902b7915516295_cppui381,
                                              0x18f7b897dc2bbfbf6442a79894dd54dda9b4ac319686282668ed52b1a39293d90c69ee9f8e501fd0f94224c0eecca66f_cppui381),
                                          fq2_value_type(
                                              0x037b3354eb3e7810fe2498a299173e82acb2f42400b004e97de842c1e397b876c44f023cadc7049636f2ee58a49e73ce_cppui381,
                                              0x175f5eb8c8849882005291192fae39e67ed2d3acbc597e0eaa4bdeabb3649d3dc6f25996a51fd796cdf6b6a896e17c21_cppui381)),
                                      fq6_value_type(
                                          fq2_value_type(
                                              0x04018918fc2651f3da38fe555b0b0fbb97a0d1876c0e725ef4d15c6d4a443bee61208c6f824a9f292f0e5d322b891811_cppui381,
                                              0x0737645e400120e4383af41d9bda3a4d4474f01ca716968ddcb97550ed166b2376fae234dddea9d344df04752c457fdc_cppui381),
                                          fq2_value_type(
                                              0x0fc9dbcf340265515779ec9fcc1439f579b6ac883d848caf41c431f7bd869fdcd1ddae2f9b24e9128b63764e06869339_cppui381,
                                              0x0dfaa1b73b35aaff7ae7a0d748934b839c2f89b0d98a753248e85d54f650c53e93c57f0c7e046eecd88d9a1871c398a8_cppui381),
                                          fq2_value_type(
                                              0x0cde71dd1d338f0890ef4fd6a897e806b7bf3ea795331034d13f3f97c05433f8c8aefbd13e5632209c91d656f2121da6_cppui381,
                                              0x0562d8702ef0a1fc40d7b25c7f1eb322427b9a73aa899f32500e9dd84196ff6c3551b9ceb8b292cf169be9dd45b2bff1_cppui381))))),
        };
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>,
                          r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>>
        prf_gp_comms_c = {
            std::make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x10ed67bd0b63f67d986834c36ac3f2037ba0ad90201faed858f9eac88089d786542a130fdbd51445f87560708229fd99_cppui381,
                                0x069e7c8268cc30fb130f4dcfd6ef0f7060592f56a56027de904c0bda34c81c01168f4650f55fe0b808d8597a88ff7521_cppui381),
                            fq2_value_type(
                                0x196b6880be4af60aa312387b6a98e0b7c043c40408d16907d4762638ee039e63fe4e223d192b0cfa9c4a05257283f24e_cppui381,
                                0x08619e5d5c45dc91d6a9a74ffb540bc7da63680a8b407090e5ca0b23b706e0ed96fd12a108cc2ac7d7a18b2649065778_cppui381),
                            fq2_value_type(
                                0x0725a15a2ab090e49f90f4a6ef1f1598ec05623b2cc3e97438fc518132a8985b883429f24f9ca53f4d3ef431f4f880ef_cppui381,
                                0x00c2f0276989afae607a6970d57dbdab344b8f4fefb5a9b0c8c7108bb03e00628131a33484bffd1a7975fb9a7f459b5d_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x133662f7dfffd9149e01313c9dad9e6833af6230d81bdcd15db9b43606f0514230f791fdb0565a64927f3dadd8872e89_cppui381,
                                0x1407357f60dd7516d6c7a6cf4a108335c74bd99912be2888cdcd89d1f2bb1c649191d4e336496563f96fde9b763ae5f7_cppui381),
                            fq2_value_type(
                                0x10208a198ef7b0af86e4ff3a458d9fca1a7826ffbb7362f080fe1906dfdc9d90b3877dbbec536bbca8510677e1eb39eb_cppui381,
                                0x049e35694c813261d977fd4ff1293c4e8370c2dd44a74e4b301217a8bd934218daba682b087adceec9f78450bbe84675_cppui381),
                            fq2_value_type(
                                0x17524ce81161cdaf38749e98c31fb443ddec79499f902d3ed58ffc0d3dfdf60a3b0f4ce07912e44262a6c93f1f160822_cppui381,
                                0x11c26beb7dfe3d670cb69fefd4aa9381527a4a792ca0b6d4da6d9c248bcd665dd7672c225416d0f12a853b69fb312141_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x18c6d2d4bfc39da958a277f912bcff65ae340b41d757dd6641a8857a2281f070fcc7129de69c812340dd38fbaf720085_cppui381,
                                0x033d45b33e0342b7ab12bb7bc0405c77586bc91be194e5d15cb5947e054d32ca822b3aab958d33692d1c5dd802e0bff7_cppui381),
                            fq2_value_type(
                                0x11d509da92743cc89eaea024bf0855c7d4de80a31f4e210c77c4366ab80ec089cf81be0059560c6cb83d54a1fd851bf8_cppui381,
                                0x141669a31e8e65df813411f59ce80ab387707ba43157b5d2753c41754e93aadb0cc45566acb969946de3b0c6a841ef5a_cppui381),
                            fq2_value_type(
                                0x061d99684ea4e2ba35b4fedc26f6b4359809302934aa36ecabc637586e0d181fa369b661f44f13b51cdecabca0d5f73e_cppui381,
                                0x0535d73f27942ef090b917193e7659d4258b3d041318ea04ec98a1622b9b5edc7ac1a332fb7e84c20165714ef9277a74_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x07329eaedb32ac2ba5654e50cf496a22431d52ec3cece7d8e648bb80e4503841ae2ba7cd1bbe8e71859a2db5ef16cf1d_cppui381,
                                0x004c6b8e52b346ae6bda69785a78e50af1a6a13789d657d899d67af8b81016b8fbe706bfb416184165c34bd9a61b8f32_cppui381),
                            fq2_value_type(
                                0x157ba424ce6ee22e4f37a1a753762a001e381cc6cc54dde88cdcd0942aa7a11567d296308b48f717e988b6d5ed72f9ee_cppui381,
                                0x173acb29afcc9a5c88c7e973c38296311f68973ded3122e07cbec75fab77a098d5bd8fc57715c61f1cc3491fb4ffaf3a_cppui381),
                            fq2_value_type(
                                0x060a19f034eead10945b38178e607dbcc5a387ebb31c7086aaa7a6ab6438f373ba99d0fd2773e07ffa032a7362615787_cppui381,
                                0x0ca399f2c2b37c7dac9601db9f0c008007e2f7e5374aa35ff9c99ee63aff30b41c294d78ddbb879b4993dc01502c67e7_cppui381)))),
                std::
                    make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x17b81ce7baba6489359718e1371b0f18fdded1bddc462fe86b1469b43aace1e7a86d39697d9a47b11a5af4e9d748d4f6_cppui381,
                                    0x0c206ab61781143b18252a9bbb9cff5f6ccfc319476ccefffaae72a5d0687d3d540e52add9fc8886e392bb0975cb03dc_cppui381),
                                fq2_value_type(
                                    0x135cdaa402c73d5713a3622db4472ba5bce78fce57768bdfc8ecbdb13b638dc1c48e3b65339cb775b987a7e50df58860_cppui381,
                                    0x032ca67e8fe7e72fc196f28114122bbd4aa78d84b27639368013e9f38d8de9863bd1b8bdff0df64e6558782f9ac28683_cppui381),
                                fq2_value_type(
                                    0x03f635a0c4e3e4a263519195fc11e27955fb5ff7e7bad1b3bcb56f7997935eacc4f32eb339e7e942b5b7d4547383e0ec_cppui381,
                                    0x048947b762fb9d8a558a4b95cc96d2d8060a4f86a13457ba96a344f65731db1f2551cc2635e767c0db53bf2de26ea548_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x033442ea170492e958b9a33e4dbc95680d042ba05ef1c36fb81be68481efff3edd30b479390783afa5c014e5660b0d21_cppui381,
                                    0x073eae137f43015e8290f409179534808d18f8b66404dea13ecba290079123df9c6b020758e2d7833d0b0101b1382552_cppui381),
                                fq2_value_type(
                                    0x032f8b18afcea0e4a213e2da1868b1e80daaed10e714a7b3a778656f8fb46e2620feb23a93ac8297693d7bef98d8c0d7_cppui381,
                                    0x09cf66fc553943fc7766cd86c871241d59c3e5e20df45e6244ef2f1d2da9442afa0fb86e4ad71c4541227ce47002cbb4_cppui381),
                                fq2_value_type(
                                    0x109a4087f5d8ddd8ec10410111e2f8dd0dc2c0fa4975451452f1cd391980b9888f2b19e634f40affca3d1b519ca5fad1_cppui381,
                                    0x0386402810c6abdfbb7830cf4cbe52265f4ccad3a1f1b475be7607a6a4efba3aece654b159179b42dd016eb58ba6f0ae_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x1080b5e8e167517cbb8bb80d3d72fde629b6e29bce4b2e83f0034776d59602a42c635abbbe0096093509e64f8fb20280_cppui381,
                                    0x1521526af8ac6a4eb5614b890f3d1bd0c5afcfbe2fca328747259322ae795ccf327d96dbdb61af35a4fb39fb9910ac5b_cppui381),
                                fq2_value_type(
                                    0x0f77cddeb9f28a92418b7e8b2f0e47d9750e13717431e02cf02c095a23ff809a6ac6d245e571c2c4efe7c0da89ae486d_cppui381,
                                    0x0a1bb04516c45c0a8fe0ba08b2cc53768f7e8af0dfae460a06e1c92c066eb713cb5ca34a0a1f8802b0c6250a38391e9d_cppui381),
                                fq2_value_type(
                                    0x0a93b752ea77031c398a33a21532ea0e4a0ad8110143fa0862aae8a132a43e2ac6dc671c78168a6108fc1077a81a5e4b_cppui381,
                                    0x088578395b91e1894e2fa3747c7677d6acc11caa51dcd4d61a61bd1c2e71d3a284a70ae20efcbfc733b7f118dd90681d_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x190a34b49778e6ba7764d4c6d950ccd6ab2234cc1d0c4b93f5967069af0b5b151c872980ad0733465b3d713faee35d56_cppui381,
                                    0x153bd2d950a0f875cbee06d480e6a52c26902f8388168054144b830e98316c0537a70d455ceaf4abe9b58e6f596bef98_cppui381),
                                fq2_value_type(
                                    0x1115454485c7c3168cb035d769fe52cd684fd3612380897d704c81cd1d6dc4e08f1c7bbb57688964fab096dd2c5352d2_cppui381,
                                    0x0b26a72372d226e1aeddca8897a27c5325e162c04a70a5daeb4e63114e00ff2977306c3dc4f50a4c4a284100078934b4_cppui381),
                                fq2_value_type(
                                    0x193d0c11752111f9fd767602157d787ba295facd0425a278a2fe9866242d3d030101e228846e5bc8d3be897dac3993bb_cppui381,
                                    0x074918f35c174078c7b30274c2cfda335de1135400206ccbcc5863161a9c1e87ea8b44605ce6497d46670c7214f92c47_cppui381))))),
            std::make_pair(std::make_pair(fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x00cd02b53f694b1a851bf0df1aa681a0f853dbbc8e36075bb8503428fffcef90a2bcca8cd3cbbd85938d7693cbd8ee95_cppui381, 0x140feb6a0e87b95e1066f986e61bcf0e155085f573e3ce6953e9f6eb7bf0da43ff944ecdee49e4ff07c6ef371fffe69f_cppui381), fq2_value_type(0x11bf6b576dc85512297c890d7db6094f5adc3de7c58daf686e9a681085b4152685afa64b2eeacca3f473026c48bab1c4_cppui381, 0x17f685f39ce930a8a4f85c711540abf6e58a0a55291fc098430f10673f6a235f043d54fa7f30bcdd935f1d048a9d38bb_cppui381), fq2_value_type(0x0bab1207d935191985ffc605354c309f4ec6100348d91b77aacdd2ae5bfe51e87eff8474c0e09bc9b0377a42d9ab887e_cppui381, 0x066e5659b0560951d0e63e640f317bec0d9de916f701ca3377fa8a1f1c72001808d04c3b78597d7fcc607b66dbe4ab61_cppui381)), fq6_value_type(fq2_value_type(0x0994bbfeba3680f607ef688816c17a72b1fb08fbe3ad6ffb6bcd3fbbc81b3183d61949fb7a77eac59fc33bcbf6a40503_cppui381, 0x185a593ae89638d8578576309bfbb0ce53ae66c6af1bcf28bdc6d815678852cbddc7cb4630f44b79653f5de0799b9673_cppui381), fq2_value_type(0x066321b303ae08e98a656e378e96d3f2abc4fefd6b39a16f161ef9b3fe8e66b2b7b9b97f58924684afc97143681aa93b_cppui381, 0x1798915ec92dbf49b578aae63caa938f047374d7843afb9d5bd170fe194d3eb4bb57882890ef084cac5690bcc578e53d_cppui381), fq2_value_type(0x0cef8f02eec0326fb9755a9b8bfbeb886733a796d21692d50d60d2a9df64ec12a1db908a2a9c041fcb5ec2d10caf4a49_cppui381, 0x00ba17d787706ca24dcb7c04504802c4cfd58202c5b18e816407794cd62e1063bdb9f7528e12a0d5ea770a9947832298_cppui381))),
                                          fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x06289e93e44a1f090a8e6d8366d6ac723ea5082b349a1321b1acdca8e1902d165ab7e84861286795abbc6d848721e44f_cppui381, 0x0d68f1fba4098fc6bc57dbecdd318862dbd2d339be6112a036abf3f8fa98f33476334540140b86bffecd9883bcd5f3e3_cppui381), fq2_value_type(0x0e6a6f08850c16823f7511758041ab52e3727cefe624150e5eaa3fb96ac80ffd55805de5259dc8ac81db8788600f0b1b_cppui381, 0x092bb3dd5a6865c86e050ea7414823021cd7eee3efd6a40d1e59f84f916af3b49fd0988050b9b669b8a5e5c353a0cab4_cppui381), fq2_value_type(0x00aeada84f5d058c3e44a7c3e90a8cb5ebbd5251e5ddd97b72f757fd20f4fdcc39f4172fee3b8f543061ffecaf536eda_cppui381, 0x16067019047eb683cf3a271d6d8f544bfdb4cce61caee90278c7ca6c7521e26e3d3eb2a112e25888ee7306bbe7cc2dac_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x0b86c9301cbaec27f72357021fd609cbece937bd247d4d3613fe1c5a167467e8c646668f17ba22f3fc77a8ddbc7cd64c_cppui381, 0x053eb955cbf20eb9ccbb8bfd136632eb1628c9667a2f87218424229945ce42ad4a01b855bbc66c7f578e4034e889ffa8_cppui381),
                                                  fq2_value_type(0x07733a893ff37d7d9e53a6155733406ba6e1931ae1a802ac632b540fd3e0cbbf6a7863d97435c208960767d8c03b539b_cppui381,
                                                                 0x1580abf5c7aaff0261a561a5d4cb7eb9bef8348fa9fe3dc8f1365db10470b2d9a3323353adfe2b38b90c4a9367ffb255_cppui381),
                                                  fq2_value_type(0x018fd046d712339252313c04626d8ddd34f56b2f4ccff59f58a473fb211e4c4eb1576814fe464f6cc31335a26d26d1e6_cppui381,
                                                                 0x198de2cfeb262028d3eef3c51c84cdaf9bb9b2298d3180b151c85e483ebfb84bfa7f32d74ab0703d43422b3de6e298d1_cppui381)))),
                           std::make_pair(
                               fq12_value_type(fq6_value_type(fq2_value_type(0x091bf93f93eac70088ee29e573218f886f226634d357d4efe0dbaa6735cb2d8770348507678576c8f4d4982cebf40712_cppui381, 0x11f16a79384f02bf27f2e673113210e648e710f0a2bfed8b8d1aad8f582b987468621fb8c2e5da00f4d691ef1ec3ceac_cppui381), fq2_value_type(0x154039a51d7ee64e5264bc45c33d4fdbabb6c4ce9e341d10a8912b1fc97989ed92b1cd4e18951128a9e9ce78bc9bf874_cppui381, 0x13073a917f2d877c549d2d42729d04b22138585079a0d5a88a19d49102b6bdd2bdba6de292ddd5164d74cb2fb401da8c_cppui381),
                                                              fq2_value_type(
                                                                  0x0bd604ae47c5f6d4f955552f78babecdc486a02329fd0c4489abe6f36dd5bf827254fca72c612ec9f05d0f851752aaca_cppui381,
                                                                  0x18615c8ae7878795c04447c06b6343e2a2e6548068c2de684305b0b44a9bdf1127cf6bf93206d592e511f2f39400bc81_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x0fdaa6abf7a0fe05b237f50dd4b367a3e7471cd77d1109636d8f72fc1ff04c1731757795f3f5f4df93d06ab00bf26e4f_cppui381, 0x186d3be356d9531fe5157e3a763cc110945b5016e818138794debb1fcbb0d78a286a1826f6da770a4fab503827396938_cppui381),
                                                   fq2_value_type(
                                                       0x06e0263f268d519d06291ab508fa1fe19183d39fcde48c91025ccf9d95bea6fc2d430142cf6d4d6e28cd384997f8e4d3_cppui381,
                                                       0x0f35e28ab5138f378f0b48c8755ec665de57f5e5ba62819e4ca0b11dd2905c3642b2b7165649ef2b4fe1ed338fa0a28e_cppui381),
                                                   fq2_value_type(
                                                       0x00503cb86c324e1a2dec2655efb336e06a4f4aac1e6fcc0f0be5a6a2fe564ddd696c660d2f6bc42c901267ea0a34e8d6_cppui381,
                                                       0x09455e38db2072edcb7c67cd308111f99108f3506f92ba29297dc306bb79dfe26d94b7da0c572d2c524dd76b47c8f752_cppui381))),
                               fq12_value_type(
                                   fq6_value_type(
                                       fq2_value_type(0x16c5825097c134fbb314ff272bae3c9e44d8bb53e3876a0c9862e4c65916991dc29fafa3d679fedaceea2734fd2d7d0a_cppui381, 0x0be1faf775b50b9f3fec8e3de6d1251b8bb88d3d3026ca3710ca206ee047a935c438d9dca2c9dce874ae95f8e4b6e8c3_cppui381),
                                       fq2_value_type(
                                           0x025bbbb4e3f42734ad89afd255a86d4a7b44fa67b3151ebdbaf3258af574ec61f5c129db71eb1b209cd0a33e49b950d6_cppui381,
                                           0x15416a76fca7b035e9dfb0246964bd6f655607daf43f8001cd5d2b933f0a557991ee51f78e0e40437f55f79e47f5e0b6_cppui381),
                                       fq2_value_type(
                                           0x0252ae00a3724d005d21741a17a4c9299b0907715d92bd8c9981ee9efd9ccf54c92643a07968187e606996d8504d3042_cppui381,
                                           0x11a37ecd4bb0d04929cd199b14e83eff0b320f4be3de4f088346e2c80ed84407cc3f76e23f8cf2f2ad54c22f9bc4370c_cppui381)),
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x0b8937236d70b06038085128cb755a03718e9d221f9460b7bf6b920bac9ef8e1a6433e87a6eb3507341ac79bf6810128_cppui381,
                                           0x0320165b7a986f8f2c0927e6a63bcbb40167c42538d01203d7b5d2d2936fea2f5b9b42bc939c110023d9c3c4e68e8f45_cppui381),
                                       fq2_value_type(
                                           0x02ec7a67197bb1c50d58d53f34971c1aa94ae5a92b74dd498317e271c287d72ab0afb385a10e5f097c2f0b6d5c1c6508_cppui381,
                                           0x1797fe9ff1a58c3bc0c2cf9967ddfb8ac5ae8b948fc8a077775ca0db525813efea1c9ae4413d0ad26f7b53266ca357dd_cppui381),
                                       fq2_value_type(
                                           0x1365bf62a7178f16169a04a03f3bc34cfd89168300ac68c8d794da77f418b51641dcb175eb85a33228b911009f251286_cppui381,
                                           0x13250aaf3a30b2d5588d207ee2d63fe285d465f145bb929802bc7b6f6ca556d84252cb2f0fdebd97df436f161c8476e5_cppui381))))),
            std::
                make_pair(std::make_pair(fq12_value_type(
                                             fq6_value_type(
                                                 fq2_value_type(0x08dd0baf4cc4c55021fdbf8bcd38d27c83c32f1a8f2420e3d017e14f8036029dce4b47960f4fc8fc6bf7afa91be69786_cppui381, 0x06357e6e9524296b36c9c6cc5af30b2a0c1ff45578bd1eca61121b6fd0966611819af112d55fbcecc4cc71da7d86adfc_cppui381), fq2_value_type(0x0f997e9e9d34738cea97c195b306d07235767cc63003d60af6c6b18d030c6bc46ea928498a3f7ba96a7c327a9fe34ebf_cppui381, 0x15444304c6d940d83e7f0dd0e0ab9f528d82738726089da10300a6dfa1fb6eb66c4dd760ecae1e75eeaa48ef6eb29103_cppui381), fq2_value_type(0x1588fca489c1c013a9e78dfadf1f0b126d9a1764a99fa0478875c7025f90f4827ca8bb203133b795a0aaa90df34e3699_cppui381, 0x1485952c24f16f864671b4d6c143ef8daef69d402ea93acca4b3c168349b20a820c3ad32658fd3c89515b676e8202356_cppui381)),
                                             fq6_value_type(fq2_value_type(0x11c90fac4fc1e3908a484c66f320547ecb517db17c62d9b9d8ec4a4a57aa98da490130ab59b93179ed5545d503c612f5_cppui381,
                                                                           0x10300a9b011ab7a2834ce2dfa93830aae20e4b85727d28ee5f5b59c24fa453eeaa0ea4a78814d6c024ba17c986e2763c_cppui381),
                                                            fq2_value_type(0x0cd16d4877b9e65b377fa9d3b47d8cb5a5c0ed0282bb5a4bc5b2a60beb12fcce5ffb2f9d75d6bd582309f65d75e06c79_cppui381,
                                                                           0x03396813e004b74711e8285b45e809f3e2833c9895ccfd30afac7f47dc741ce5f4a9cdd28a2a8f2e257cddafb68757e2_cppui381),
                                                            fq2_value_type(0x0e5076adabf1e281e5ce7d000f43294dbaecf2842c474a8a06a7078652145ff376182743d11289ace4ba83386c81f572_cppui381,
                                                                           0x0a6d7c45532b1a5ec8f69c7cd4ff78bdc94a7a3d00906f7f00cbbeaaaef4cb574c05587f617842c130bc42eca098af51_cppui381))),
                                         fq12_value_type(fq6_value_type(fq2_value_type(0x159f089315703e2aefb16fa4aea24c64838eacc7310edab6f77ca2554d4302b5570511aaef4d9d751d316de4304828ae_cppui381, 0x064244a2309f7fe1aa66bc9df4a337597c55e5791b5b02ec21ff0eb8076c4dc8f87739409afa3b6eba77405bd0b313f0_cppui381), fq2_value_type(0x0ef9c735e1af2d26a684783ae0b730642fc0d3d691f5998fc854c73643001709530f0893e49a258a1ba0cd3ce0aa27b1_cppui381, 0x09e25b9707ee53b9b18aa441368ecf0d79d4c9f464613a17cfe869bc094e9ddb03b6b8dcafae03413d888edd8a4de865_cppui381), fq2_value_type(0x0ea2624da7a7def6e791f0a4eb3a9f76f66d861df5208ffa4c37b5eefa10d5f2a82d059c7002f1a5985ffcac9c2935db_cppui381, 0x17a94557a70dcf590a104eb033a2cc92df7ee0135dfe21c51c6e197c6432ce32119d745e29d6a34e5e61c8b442446288_cppui381)), fq6_value_type(fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          0x01dc01a6745a3944d241ff50c00646174c842e1c0027819be6e7c1826ffd9cf44d7d2ceca1d7f27e76213f45d6b7e980_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          0x0f18ce5e2a3dc1a4f8c1f2ff9519c87fe386138b6eb6b36bdafedf63d43c206c4e4b34d4ed919f220928aef9efcb467e_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          0x18ccfe922cb1f77adb6b24ff40eb995bd54d522629395b3929f0cf98a3a21c6442a41b9f778d78415957d72dfdf8ba43_cppui381, 0x0eafc73663c4558da4e54ab01551a9fdafce32f5c56992e11c3c85b89c92bcd3cb5e3649fd60f35ca98b455455604ee1_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      fq2_value_type(0x1143774b3ef69def99f7d4e2b1e971e581c538e6db2d01420b1037f169eea9c0cd9d2fb4531b735d35e265ee186a798c_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     0x0bbc868064be0ba9bae5804af675a0927fce83caf64b6937d277bb7d7d7aa1ce3e23ada0eaadee28c326b5644677ca38_cppui381)))),
                          std::
                              make_pair(
                                  fq12_value_type(
                                      fq6_value_type(
                                          fq2_value_type(
                                              0x0df1ff4f82018bfe1cfd879bdbc8aa66f42d07e78badb345ca804c320e14b593f55567aef00fdf6ada5e096ae38e5656_cppui381,
                                              0x133d5671ff5915bb541937c6f188150ed7545041d34138748de789a72cb3f48fb9461c3d3f737a3110c242225fb96d38_cppui381),
                                          fq2_value_type(
                                              0x0edfed06e1ea698794252092f1968c4bb18c7ff388b70db9e7f9b1b14f690581ce50d1020122e157ec92e1144649e81f_cppui381,
                                              0x0f1c6ed1e65a9a5bf4b84e0eae5e0a18cc701438966aec2643ced3760266ddc54c22dc5a421111f62f66038d7b552a2b_cppui381),
                                          fq2_value_type(
                                              0x037ecc3d63a0a1df33aa8ba2af6dfe2f63ea0418ddda51c7f5c3c19b527704d2af48e6af9976bb6af43bd866b041107e_cppui381,
                                              0x09cd0a0635f4723dd6401df07f6da09783ef8ac2206fc2eff5dd69d8daafb9d0514528751fad7cd4fbc5280021cb6f0d_cppui381)),
                                      fq6_value_type(
                                          fq2_value_type(
                                              0x0998c7d54a67abb5d49438a1c964ba41c97443b500c6f05578bef4656e34549078d4db7db82f32cf104c7583cb59a30c_cppui381,
                                              0x03fb13d0599f286d73197fdc49ba4ac17337a19b7b3e0034c28aac0b29ab14923b5d3bd23953d607c8761ad2a74292f0_cppui381),
                                          fq2_value_type(
                                              0x11c43bb1b8a41d198101012f2c87f4248d4b0a714da37215dc0dfb9d619adaf8afe50d7cd8a8675d3f3ab828150d109d_cppui381,
                                              0x16579444d29882a2471491f2bd413914bdf8afbb6646d3f6c33c0978c31bec9919b5b6fd08f2f218e0c1634e296dadcc_cppui381),
                                          fq2_value_type(
                                              0x0cd273e525a01b0ba847beaa413c1d87e640a794185575deae98f4a4c32e4e36386f0d2478be6cc3bcb41f9113e99586_cppui381,
                                              0x04ced2941685b97a5fa763c0df6c8e41bc53700bb7334f7648e9cbf51fdf637639f979e481ff4b5dce565ef623746b6b_cppui381))),
                                  fq12_value_type(
                                      fq6_value_type(
                                          fq2_value_type(
                                              0x164bcb92b4ec4782513bc30c122be365c2e74eaadb0035cd621988e6b1e1a5b1035ed030e3c47d8404ce13eedc36ddac_cppui381,
                                              0x16e5a378b57a78724c00709036d075e6dfdfdbc52bf3f697fa41208d76e88d862111da45bcd4f7ad2cf1e1f63f99ded3_cppui381),
                                          fq2_value_type(
                                              0x15ca4c2066a322d885a0715b589adbdc4ff08c6f3e73e53002f04e88ee1ea2483c4fa81a5496568d1e9ebdaf5102a4d1_cppui381,
                                              0x078d68ca700bea300310148e86b2c5e67b4013cc4326ae76f047047bd6a3f17ae787aa98d89b497b42da073f8e900da4_cppui381),
                                          fq2_value_type(
                                              0x15c422b4b59d3641675e83294b50080d353c1ac882ad5dff9e169f295d564167d406b6a781c4e860ef02bd6a8ccd0c9c_cppui381,
                                              0x0c71c2aa2643a71b09d3ebd535cca5f345abdabef6890a2f9f9d5cc2eef1559d11cf81a90aa3c84394f334871cf4f0ca_cppui381)),
                                      fq6_value_type(
                                          fq2_value_type(
                                              0x103d3e9e7773178bac69c29aab093a153bd0c4a2dd542f29ba1e6e8df906d81fc09810b4c6e9e6006b3f15d43f101708_cppui381,
                                              0x1428ba2ee1704eddb5bc89fae3c1e6914a5a30e5588995a892e23bcc242e9950119f6886bc6e4571ed685021545a15d1_cppui381),
                                          fq2_value_type(
                                              0x105fbc5a3bdc0c5e23ee423a142eeaa36144597bc119c98be7282beb7ff79c5838afe711eb7fa8509a8d52d1310dd1cf_cppui381,
                                              0x0b464223972eb42d4f7b327e091fc31f39448e9717ff457c4dd3cf01b6c50b0671f2b1b1d4a6ffe357d553de02a6500f_cppui381),
                                          fq2_value_type(
                                              0x0887d566eaee0c1b5fbe3f023f4e069f542d8f09aaa8934e6dc9d82e11b5e5b0a0f183dcc830961a480bdb77e4008a1f_cppui381,
                                              0x093fecfd59f5c1bbcde139a46fb9c60ad42f4a3a7b216b356986af0a5f2a2736c5f55aa36add7d423673a6a872e1aeac_cppui381))))),
        };
    std::vector<std::pair<fq12_value_type, fq12_value_type>> prf_gp_z_ab = {
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x00b1aef1e45160612cf1c331d72fdcf90a48a792aaa6bf6ba4fa461e7ba278dd9e05b7a8d6f69de7bac3475a3a372867_cppui381,
                        0x09e2b087e9e3b05f570484e4eaf709932adbbd951ca67e1a1908485ed074d39428223fe7a38848268aae3af9eb8ffb5e_cppui381),
                    fq2_value_type(
                        0x19f2ea85309809b27d841c578def76fe8ad526f4f8152892532194e4c1aa2b2f5528d8a2100659389c56c56a8b0ef721_cppui381,
                        0x1265e45cf8861d1fcb8d2b124947d04f26f6c7f6a25983747ff3a13c2b7cde13916e72a2631a826fb129325250ae8307_cppui381),
                    fq2_value_type(
                        0x14fefc023f6a08955e8193f8c88f510ef170faa5dbc47a17af6092540a5596d6a4a2a3a69d3e2f02a8af0c59f8b39f28_cppui381,
                        0x0b530bb9baa032ffbc4e9b4d5c379d56c668593412c46945f6ad87dd8ef05e94248357ff853ea03fb5529e3dc2de197b_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x157d46ed431d4e40e9b159e0a15201eaf1d6d45a637282f4ed05ca46a7a3ebbb3168150850f155460c57b05a61ea1db2_cppui381,
                        0x1777f0b6a46363c415560afccd64b00ac785031999506270b92a034473e9d282b937a44ab384b298c776ecdfcdc60fe0_cppui381),
                    fq2_value_type(
                        0x01e6d08890062215a1e63ad250572cccee5d840a56d93de276c6bae17353e8d98d6cfb2cb9ba62ef75ef98826fe4c7d6_cppui381,
                        0x04764c9adabe8ad8b8684d8d63c1581e7ab3252a9b9edd961fb1be840eed9efa46e675961cedda3b0384c29d58c6a17a_cppui381),
                    fq2_value_type(
                        0x12c361445d2b0b942d8ae634c684c31578409264ecc835194bb3b43665705f8ee82897db2d40c17236efa28541d9eb4a_cppui381,
                        0x15ed70ae38ba0cbfffb99e76d276e45b3b49157cf670e651501dc96f69980012046afb3e81f2bfbe079486e399409f46_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x01b2d5935a79b332bcb2299dfb78890a56ed571210600b3030b4be6825dcb208a0b6eaad277f044f5b70ad65bee27725_cppui381,
                        0x15c401d194d21b5f6bf2691c8726fa73f288a28e72c77d9c8386194bb36ec89e6dddc3772b77793d3104b89a5618d0e7_cppui381),
                    fq2_value_type(
                        0x076786ad2668ff99ecb68ad1dcbd762bfe7b62987022eb90120a6997954ca7c3faa1834c7dedddca559d0162236e09f9_cppui381,
                        0x081b53dcef5837a6fbb94b8bccda9395847c9a6ed3080b0458ad72031601f71b7f23b04f8e593f21f43244237b09e0ce_cppui381),
                    fq2_value_type(
                        0x1363007eeda768b8d6d9ea1bab6accef3e5f3b851bf0715b04f7317dd9a09f2af5dca1bc5efe8434ced4235b2da7636a_cppui381,
                        0x0e843bcb1b06308ea9beb5071f4de6e8dc1226011ef22afd9f682aca5db03f78bc407f4b5863c4612cfbca191d8d5264_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x09e95f183037e02512e994a0044e4c2bf373e9a8edfbfdf6425f0d610106d3b88c32d8da0e85f32ad84c038b5c20ce80_cppui381,
                        0x09d3f02536c1922e7c33f1686f43177a66d0d567bf2ecafcd47d538cc2523bc8fa03a85350fa766faefe33b118a34185_cppui381),
                    fq2_value_type(
                        0x15414baaa52b6952275aa8b31572a8f82e3472a735a697aa2168e46c2ff4f9ef5f6b4bffe03cc843a02c215438d10527_cppui381,
                        0x0fd23ec0c163b1d456808f8ecbf19bc8f3b138190efe5732fb0823d9702f137a7d0353406336446df0e555d5d3a42d26_cppui381),
                    fq2_value_type(
                        0x16969d63ddce6e18c9aa33454ca0dd1ed9328fc6c690ca8a9771d760e1b801f251afc59eefed8957e30fd51aaa65267d_cppui381,
                        0x1328d04762db65b76e3dbebc930a4a3e1ebbfb1d596f670e95fde50fadf5eaddfa609fc6567c8440fb6b17a6262b4e1c_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x1601da1e0d9872d0fcf6ee1397e428101d1d4cc1e875982d091e3259da14e26e36e1452e4c084c3afe6922cf66c64102_cppui381,
                        0x0476be604483fa858416710bf0844ec5dad78625426ecf02a30b7d6a62d3ab92f05a53306168637790859e7fd751d794_cppui381),
                    fq2_value_type(
                        0x013adb66561d6bc6b11b79767cbeb7409540fdfb245c4d8f5b9ea802e4cc191b7fccae561b9fc995e259743b6ce41b7b_cppui381,
                        0x1752d2eb4feea2244bedb2eb4905c3df92b708ea7e0ea3d0b35b69894939f871d73e7d1ade15dd5c12d7d756be336fa4_cppui381),
                    fq2_value_type(
                        0x176cda123a05f85db65bca810d8bde65d304442c4b0c6a55b73a4ff1eaf466658d8591708fb12e9bc54de92ff2b4f3c3_cppui381,
                        0x01a5e0ad1f0e699d4154693d9aec72f73b4cc564329c12b63c27412ae4e258e1dfd71bdaf4e8ccc7b5624dd48a776ba6_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x097731a9641d507c5052ca1845b5cc6be3ec532d5dfc25a8b1b58bcede42ee776ae8a9dd8689962db3cd89a70015e0d7_cppui381,
                        0x121d0a0853908e1e5661da47c6d22ac6d803071a7d58da6aff6b2c9dea4f4b25fe75e68c56bcd8ca87d8fc63746125d5_cppui381),
                    fq2_value_type(
                        0x0680482a5fd3467e3ebc4ed545e5e4ed283553eef52004d47c7aa26c83fd91564708f9c4988e2b127477b4f25653e108_cppui381,
                        0x14f561c56f436407dd973d97aa11657125d91180686e9de942d6a976910fb7163769d143b1af2b004910e5bec05090f8_cppui381),
                    fq2_value_type(
                        0x02032ab591e4e4f68b300065faf1d47d907aac74fefb97717ce1a9aac1f4e187e30a073e4279d8969f42b6520e3d8fe1_cppui381,
                        0x15dd6bcc29111d943b782083c0c021426d02cf0d476e563600ba48e26fa367b644f1c0600c448f7cf059aebb8c72cb8a_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x0a448fe3b7bb0bb53a7d8254a6f24aa9145608aa2f3598035947d09757954a7d14154e27a1e347d00c939bb6e1b800f5_cppui381,
                        0x199dcdeac49aef35d2d93fd7979e604c00d87159072b34c4b03381c5cb31843687a4179021572818751e4cb94875cd60_cppui381),
                    fq2_value_type(
                        0x0450dfd0dd9a364c11b2f986c10302a7d0900e667846636187ce746741a7b1be758643ba6a265e78a91a523044b18f93_cppui381,
                        0x04ba74e0af496807b29ff97582d800e5fd61aef2f4405c865ef9d6cbaecfc6bca2ad6f4ce0b6a92404783d5dc0cec4ca_cppui381),
                    fq2_value_type(
                        0x1032d1301cd8867d516c747a21663f736866bfa69539c1f5efb3598f27eba06b19e0cced6a7c97234c485783e51314dd_cppui381,
                        0x0d5eeb11fe035c8b79e8b8077e3d30a565c1c5b0a05febdcbaa32e10466519b1c9ce20399b0b3b78c895248cf26c1099_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x0457378d02c761f1589b5c4c05149d50c7a62a7bf370a7786f61fcc9a8ffbf7189033f7e40efff5124e7ecf180a38bb8_cppui381,
                        0x12760b6d51064deea64675bbd8ac39ebeeef3c8908a601ffd67418fe8f65d40449ae7b9a8e438bb9014676a767d7557b_cppui381),
                    fq2_value_type(
                        0x12887f08d80c60f1d69a3f0e4aa36118b1b43c33ab74ce5839de9cc4eb9378c37a53a4a3d13ccacc153b9e373ec1446c_cppui381,
                        0x15c173581eb0ce890b568e5a3575d5ae1fae665cbee6ebd88a512bad49d3afb2be3e669691a5aa5f1442e219c946ec17_cppui381),
                    fq2_value_type(
                        0x0b0ea524c1cd333c0e4cc65088d7981021feb364f441f213d418e668be41b57c698f7a731b3745ac581efd338ae27471_cppui381,
                        0x0c51c5ff592ff7a5e9be5531884a558bc17a1a079ff5297bd2b82d2a3b1920e3dd7b477a538908ade8015cb49c41da95_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x12346c1f7fde0a6481edf3f6350e2d9f39692e3770d032beb09edfb9149e237704358fa73381f0dd78f740a4b0033d37_cppui381,
                        0x0ff9e150077015c44da9a06aab2cabd1aca3dfe6e75c40f9e7b524f228c2c68b5dfb9274006aba7453e8fc6c18b72a43_cppui381),
                    fq2_value_type(
                        0x053e48b8ac981a1349e4533c1ff3e54e49d910789950eaa8f1e5b9c7db001c37b63e9fcca8109a0061e528bb2e4bb2e9_cppui381,
                        0x159d39a1835f517405528a4be8e4c6449a2da103b74e380d70088917ca4422e5d2791080d73e55ed5680016c4aaa3387_cppui381),
                    fq2_value_type(
                        0x12ee315437814f6f2e44f5a799878e5c10830e55a7be4514a8e14eae81e269dddb0908ba3fff66f0acee68935ae19142_cppui381,
                        0x13f30af8e898f773f2a2148efc7fa4d822f70ebda7ae6e378b5d9fb8f59c6ce9ee65b83234939386b461d044ff9840d8_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x166df020c015f6276e5204b4e2ca0ac3f8f65a768dcc98074d7ebccd6c88420ae9dfc38357c4f2c234ddb3af6d3f67a0_cppui381,
                        0x0a140fcbaf24ab8445dbbba62b07a82f6493d5f18010fad9de743d733ffcc8666f5991a4ce972eae98ecd988ef8c800e_cppui381),
                    fq2_value_type(
                        0x16508a375db841cf6db5ff5e6b89bd4e270bdf8ef3c47a8a122aaccf9626a8f0d09f95428d7b9a3f84ce301c32ed7b94_cppui381,
                        0x12dbc882092d092790413662b65ab05a72ee56606ae41aba7fe40a374162b4cb6239a4d33b286e5a4063b15ae29241fd_cppui381),
                    fq2_value_type(
                        0x0c575fc736f1ef394259031ad9f5a794469bea5f021c21aaaf80d591abd31cd7b08ed3ba691b9da81a4b125eaead4f9b_cppui381,
                        0x01ed73bdb5cfee0bb4f07a7d7e5d77c7d0c3ed2ce4209884ed3862f0fbe9350ed4a539f068952365a1761dca3815adba_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x1848f80569f51b1f51ed93b2e0b431c569dd46ff57e23b22463f4a31867e1c5ccb24fa4f5c8495acf27b673f8323bedc_cppui381,
                        0x15c234722d22e01afc249ee359f35e4500e0839be921ede8508db97ba412052d994a091c34276c6fc9022daa05f6a8a5_cppui381),
                    fq2_value_type(
                        0x151b69278602d041f5aab6aeda3f4d3e9d053396c0a4e770f9d3adaf1bcd8a6443376780838c4c520e0d7cc7ba6fce5a_cppui381,
                        0x0529847a8c4437832aabe0b4e1849b6267fdf1b1ba0672922fb2d6350d92c841a9af6837853f393af529f49561d0a75e_cppui381),
                    fq2_value_type(
                        0x0b2f999417b9d18478e67fb1026222d2aa536daffe9643898cdd280fd2458cc4aa6835d34ffce61ccc5e02d3b4a77431_cppui381,
                        0x152c179609332a6e00e49798f1ffa6bda798bc6023868bd0068b79dfbc2d2785807d932712855f2c2db2a1cbdba62364_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x117bc119a684a48051549bdd32f847984a565b884e6d4c5b40fb493bcae9bc6bb4a92ca5154ff51a35af126b936ca6e3_cppui381,
                        0x13587757d4ffefc27cc39b03caad6d18e8995a2cdd37fa96064b961426783b897c48b41783134b448e24960b3fd34b86_cppui381),
                    fq2_value_type(
                        0x16a4ba21b3b72631eb6eeef07b182ce2e42274a097e4bf3dabdaafb7db56dfd8120bf46d3d3e7473f85992e0876b33b0_cppui381,
                        0x12f9eb10ea1fa853ea2bc5d637c377f0bd4913a8cbf3d8f9ef864a28b4f35143d8d05f85162096257722d6eec6b5dbd2_cppui381),
                    fq2_value_type(
                        0x0db902674d16436db18d9c9fcb2c1ac721bf03b5c03dc748a17b5b01580bafbd4d5050b1e0d0aa4b720846d5ecb80227_cppui381,
                        0x15559199b2da460902c95f6b03012236c1cd1a4b3690ffe9fcd7555fbb71f54956e9b2146612a9c0f96c305d745a04d4_cppui381)))),
    };
    std::vector<std::pair<G1_value_type, G1_value_type>> prf_gp_z_c = {
        std::make_pair(
            G1_value_type(
                0x0268c098d516d238a5b98b417a4eafddd74a015afdd71b5ec8e77f65968747109d973bd4692b78cbdce709e2c8e58831_cppui381,
                0x02d266a82b527cb98d009df3a7007566458bc9875c3c7d832799e6359d7caeb07d62e8b9148d648e256dd42df80ab9c8_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x098d0136c4faf97019ea68d9c71378bb2ea6a525c0f4583841308a27d59ce236dbab7e737c24c2a926d58f24866a7366_cppui381,
                0x1645739768e311f9387031ef77c95c32bb06414feba6a32b59eeafd42590db1e2d3bea5b3ecdd35c01bb2f70f8ab0483_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x033d6764df97ba59955c490b3f465883332341ba981c3b15cca0df597b1900845cfe2738c555429ffe80eb2fe11949db_cppui381,
                0x152b60036ef237ea6f7c7983a4b3d8049ebcd642c564dc2b7353084ec137d99288bb8b1a5cce09ee584bafed2b561d4b_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x021dbef38dd8f6497801a51450a0c77567cbdeef18efc308a57c74781071ca7cc22272b2ace07668267e42cd22a8995e_cppui381,
                0x1191941d6c16ab9cb46c5f0766fe3838700f0c963b447e36510cbee174261073ef8094ba9de1c608cad095517a15989e_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x05a4381eddf7fb3b55ac1863ad3f60448725be71dbc41e02720c69f765d03ed208e7366cf97a9da68c8942c04c743b0c_cppui381,
                0x060eda7c5abe405f4522ab429d3abd53201b04abc135e78610b4180f21279d714b9b89121ddc4512a81479387e755eb5_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x14785323043adf296ccfab046f108fa83bfa330b207a2208f3f6c644811b0e2d79f43e8cfb99cb5b8d2a1e74f68d5169_cppui381,
                0x04ded3c8b339f1c646f09c41f0d24f7295d3242d78a6eb33641968717b5ca8a6db87ad13fbb0a787f18c68c9b9ea5889_cppui381,
                fq_value_type::one())),
    };
    G1_value_type prf_gp_final_a = G1_value_type(
        0x150bfcccbc039842dd1f95a36a6c96a3fcfc32e148f116b80b3a6d56563453e25e6640415beaa94049254dec9e8f2602_cppui381,
        0x0b12915368319e9e1ccded4c7d1c53668adfb878ccf19c7f6f074a25ff2e7d74dd192212d4b83dce4cc5113606e3d187_cppui381,
        fq_value_type::one());
    G2_value_type prf_gp_final_b = G2_value_type(
        fq2_value_type(
            0x151257911ca2d7491165a30070ced08d0460ec10a4be856f8f7cd095494febebd99bb09a9e21f2a12918715ab47ffe6f_cppui381,
            0x07ec37f83f717ea2471c333762e211fabf76505fe39c120a7b67aea5005f28fbe331c4b36ec2a629ac307533af4ce8cb_cppui381),
        fq2_value_type(
            0x11164b8f17d47e0ad531717116d6d7bec1a74dc01eae24e9f3a9d2a86daf711a67243496062352ac030c32c148a35a7d_cppui381,
            0x0f0b3053676c7dc55b22bcc08e5a006f377bb5844f3e161411bd1abcfae90fe68b0c752069b73795a69ee0ff0fed7a42_cppui381),
        fq2_value_type::one());
    G1_value_type prf_gp_final_c = G1_value_type(
        0x19e65ad0b31685e1e2b47587d76e53731a65b26747b8148c8698c8794966c57bca94fb098a187657f4255bd5909732ba_cppui381,
        0x1110759792228497552cc9e27b29749125d45eb17072ef793a1e694b46fb8911ab3d28f29289dfaefc12964543f33127_cppui381,
        fq_value_type::one());
    std::pair<G2_value_type, G2_value_type> prf_gp_final_vkey = std::make_pair(
        G2_value_type(
            fq2_value_type(
                0x00cdd5416f7078a07e864d7496a6090ed86c3a96d4de3eaad8954cb4eba7e7e1f47e87643ce8d9ee1b44bc237c2e3cb7_cppui381,
                0x0c373f6210978b647242a5130ad9b693625f599efcccaf5480f54f8f0664f817bbc3b63ea896b8564bb6877d087a5dc2_cppui381),
            fq2_value_type(
                0x11d122f060ca5912c955b6089a7a385baacbee8815c4bef8961c367b7360b2640c4cdc878b7dcb813f0056872282ca00_cppui381,
                0x1289ad91102723fd00ed8be6665f9e45231cc670bd04fdfb1e195e3a8189badef4107cf29bb231c8858825d7bc713587_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x01da08a660916a97871d26b13c65d4410cb15af373198f71fd48f47d7d91bd9c8ec29e69ac6e6718f302d871201d6349_cppui381,
                0x07f3de6622d9beda60fb13eab19a7b9aaff9c8652dbf03365addd80fd6606646cbde8e39330081297bb1c39dc5e102cd_cppui381),
            fq2_value_type(
                0x05f9e1779a7c4af9421a46ecf31917288ebbde532dbfc3ba76905d722facdfb3fca483f7bad5e55584a676b71b622075_cppui381,
                0x0587f5f68a3b5e237c0e52979b7fd84e358c65dd9d23aa11a46a09295b405827eea5ae23ae0d518d603c13967955f311_cppui381),
            fq2_value_type::one()));
    std::pair<G1_value_type, G1_value_type> prf_gp_final_wkey = std::make_pair(
        G1_value_type(
            0x16f9457eaf8b55535a407ba4b9196af162fcda3813ab6284beb72a5fa7c20699f4f2056b2fbee325117590d441c6ba48_cppui381,
            0x054960f9e8db822e588ce9739ce0bc429abd306a785d451c6a394177a5b0a9f73420c4493f0a72a4cf76bd6811d6e069_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x106aecab790664fedb0482e933d416463dd5f3cf80a87a0e93a533708db006dec149efb85ea2900798206350fa612a86_cppui381,
            0x067c919b9e9290b62bc7caafe3862e11cedef9282960d5a7825d7101fd5103fca4e2f278a9c1511ee502f7d2a4ba5756_cppui381,
            fq_value_type::one()));
    std::pair<G2_value_type, G2_value_type> prf_tmp_vkey_opening = std::make_pair(
        G2_value_type(
            fq2_value_type(
                0x1793259d17c94f22ca7266ec6cf3e092fcaba6ea3e16a84740669b4a970947e65598bd048080612d6dbadc3fb7f97132_cppui381,
                0x136a06edf6d4c48c43ffc427bc3307d95f9db165c64a271ae9b878be2ee052fe27b73ac01f08a7d84b79e0603c962086_cppui381),
            fq2_value_type(
                0x149f50b3e949b6bd5a78fc6d4f84f539e5533f4b91a0c7f165aaa64767a4cebc0df7134e8d12578fb6b1e6a1b46c0645_cppui381,
                0x07b520f1cee938a333fd4a90245aa77ef82fc7c376048ab4932c06d465eae0c61489c617d18171f4f63b8203c2c89ea9_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x1625e28fa50298a985caa12889a641130ded675101aba6b2bea2dc6622a8a241f8ff50b35af0f7de0c962414a4e1ea7a_cppui381,
                0x0d8f5dcd8981717b07c93a0234e28446161ec25bbc6446e81a26a999149c8d77ee72267276f91cee69cffb54612ad7c9_cppui381),
            fq2_value_type(
                0x198ab322e1f90ee79d568479eb43e45e9c99e25cfa1a971fdd94a7c8613e164e0e41b0c7a22c802787c8935de6afc8e5_cppui381,
                0x192e723117432a0117eddc105a9d51271c0d98a7e678352ab03b8a4a2516458d4a929f2521604d54c8efc47a913b7c3a_cppui381),
            fq2_value_type::one()));
    std::pair<G1_value_type, G1_value_type> prf_tmp_wkey_opening = std::make_pair(
        G1_value_type(
            0x0fef3bcb3be0690d6fb73351058eb5531d305e2d2b743060a900688edf15a3c5604e9d895a4309d6c8947718b5df9cae_cppui381,
            0x0bafbf431a9aaba5d6c0b91ce4da4e24bbe3d375516faf7e81b7525bade40a8e57b73ab92be9fdd14865e16bf8dfaf65_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0e8cb9990147d608cf2d410989e421f8d53d807eefc80ec7f2fb4104c7373e0a14fddd2807ca2c2f820d6046f2071371_cppui381,
            0x175fe5d48268e68c35d95ec592a67ba7bc495471c87b882f115395242de818cfa8433d3b807d58422786477e33aaa339_cppui381,
            fq_value_type::one()));

    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.nproofs, prf_gp_n);
    BOOST_CHECK_EQUAL(prf_ip_ab, agg_proof.ip_ab);
    BOOST_CHECK_EQUAL(prf_agg_c, agg_proof.agg_c);
    BOOST_CHECK(prf_com_ab == agg_proof.com_ab);
    BOOST_CHECK(prf_com_c == agg_proof.com_c);
    BOOST_CHECK(prf_tmp_vkey_opening == agg_proof.tmipp.vkey_opening);
    BOOST_CHECK(prf_tmp_wkey_opening == agg_proof.tmipp.wkey_opening);
    BOOST_CHECK(agg_proof.tmipp.gipa.comms_ab == prf_gp_comms_ab);
    BOOST_CHECK(agg_proof.tmipp.gipa.comms_c == prf_gp_comms_c);
    BOOST_CHECK(agg_proof.tmipp.gipa.z_ab == prf_gp_z_ab);
    BOOST_CHECK(agg_proof.tmipp.gipa.z_c == prf_gp_z_c);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_a, prf_gp_final_a);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_b, prf_gp_final_b);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_c, prf_gp_final_c);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_vkey, prf_gp_final_vkey);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_wkey, prf_gp_final_wkey);
    // TODO: shrink
}

BOOST_AUTO_TEST_CASE(bls381_verification) {
    constexpr std::size_t n = 8;
    constexpr scalar_field_value_type alpha =
        0x57aa5df37b9bd97a5e5f84f4797eac33e5ebe0c6e2ca2fbca1b3b3d7052ce35d_cppui255;
    constexpr scalar_field_value_type beta =
        0x43131d0617d95a6fbd46c1f9055f60e8028acaae2e6e7e500a471ed47553ecfe_cppui255;

    // setup_fake_srs
    r1cs_gg_ppzksnark_aggregate_srs<curve_type> srs(n, alpha, beta);
    auto [pk, vk] = srs.specialize(n);

    std::vector<G2_value_type> pk_vkey_a = {
        G2_value_type(
            fq2_value_type(
                0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8_cppui381,
                0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e_cppui381),
            fq2_value_type(
                0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801_cppui381,
                0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x13e5257ffce3eed808841bcaba1a63f907e51c5452ed1d712d2a80ad5b25054a85b921708f89c7192344e81ef4c2d18e_cppui381,
                0x09843c0db7c3e6376559357d41d1d17049e22557e678eca1eeb8d46edb02049159a2a16f3a74aa49fb2b1aabe13e882f_cppui381),
            fq2_value_type(
                0x08f60d805b4372d432b2083614477fc24ba9bfcd450f86d05e4634139ad11307fb8a39679f837db216620320c40dd10d_cppui381,
                0x0059498ec17559ff4e7f19c9601a8fc6d1100680acdad1b332575bdef424daed6b989e18ad96e7f15858a336730d23a0_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x07cc3cecf1bf7b4302b549e6094806c3e92c83ab71885ea649d7bea56722a79cd5001ecc8bd7719f5dac452fde2dc27d_cppui381,
                0x155ba4651c0c2b45d4791035947c0416579d9dfe604c94e26f15acfe1c6a4bb3ba5193ef7ef31dbf458571704f8beee5_cppui381),
            fq2_value_type(
                0x14f94da9ed09785f1041a7b998cabd45f472f3f499f9f48d6aac1660809c8a6d0dfb4f16a4ddca70125b61369d4e96b0_cppui381,
                0x04272ed3d067c55f4c3e140e8333ae3711e6b82db32fc5a1f7f7da144499b8a7af62f7fcbf49b53f1b0f068be7eccfd0_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x09825619542ee8320ff4f5ba380fd3282ec16026beff6651648162cce26452e187c30be5fbd5f929f3f32c0c02860ca1_cppui381,
                0x0cc2ee914ca20bf39af2e0f3c0193ae301a2a3b978f55df8f87d2c7b9512ec0d83185450ce7b83e4da4a5276bf1de448_cppui381),
            fq2_value_type(
                0x135a5110ab1d4581f1d213909b0e36efa8e0009de0065a6bd68374429ea80a9767172f12420ad616d4edd7346942cb6e_cppui381,
                0x0317f9c89ca98f293f8c52b8350938fdd1cd9de5d0e7fd67db5ee0daaf60dedd7504741a7dd2548520eab87a082739c8_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x02e1b72552a6bb211c01ca8701d58a62d9e43110853bd12bac43b76244b41ed90a112585169938ce675106e205b9f984_cppui381,
                0x017a3560faca0a1a19017debea64721060a4299ab0e9839a7cbc436d47ad8551652fdb9b34814d8fd4d56d191f7f965a_cppui381),
            fq2_value_type(
                0x0e14db737c6803325d53f89823090a4310ab2deaa428cfb07dbc8563ff3dee66d67c5872923c863c03a44f7e73fadcbc_cppui381,
                0x04893331cc41c22fc44daadfbaa8ee50757ca1ae5753fb8ff92323fd1da33459974bb3eb433b54076e52a2ec85ab0ba8_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x01ff99b80855d463be989bf8afe767a8dd3d99ba24e26d337c5ed0c8cb52aed049354122e55a58215783a539ff6f14e7_cppui381,
                0x082ca3714156b517d6554fe1ff1a68a8684e988c0bf359bc5373cbd63724da39197f1590f83efd437d81e5dc66dfc05f_cppui381),
            fq2_value_type(
                0x06b7875ef9235e62a37801738d05502341ee0a0a407ba1a85918f5cc3c31f0c62b6ba63169c1fb03230995527eda1b32_cppui381,
                0x0ba03538196408591e4ac5335ecd09d104a18944d81d0fd174f9d2beaafe4b65efedb88b514589ae615f0549cadca6a8_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x05cb7cb2ff51aa91b53e62decb5170e2bd6646aec10c729aae308b9601d961b2f2a8d360e247ed6b8e32dbfbc186ecfc_cppui381,
                0x13c560f1b44a70ab6cb5543bbe006e729c6d47f6ebf264561aad33aa057be5cd63152d0fb309be094ce5a4a64eb8a74a_cppui381),
            fq2_value_type(
                0x170c77d828c1a5a7c8b26646a3efdc37090f0462a4c16018a0b87767e1267ba474c7b0209651b9fedd4529a1eabb3be1_cppui381,
                0x0950f2624a4f3a5005c5af43de19cd884629310e9cf62c1f837e2817909facd930ff58736b852fbcdda8a3f67be12cc5_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x1292443c76f4a68cf038d74fb109f8d53b9f0e3b3be75212eea3e25c5386f89fb68ab9d4561c1a534a02adf161fe2cc8_cppui381,
                0x03b936274a14066ee633a18d73cf519dbaa84e92053d589d86387ff6a8cf97d3737be7bb903392a2d8510fa2f5983ca4_cppui381),
            fq2_value_type(
                0x03b395cd1c619f2802fae59fd092f65ee7aaede32a92c7d7748ea6676e9348c817144a08e768f7efe5c6b2d13cb54303_cppui381,
                0x198d3968741b6c662dce9942866b4fff9522b8184f1e7456da72e89c5721916416a981e2413499b942713cf09fcdf99d_cppui381),
            fq2_value_type::one()),
    };
    std::vector<G2_value_type> pk_vkey_b = {
        G2_value_type(
            fq2_value_type(
                0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8_cppui381,
                0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e_cppui381),
            fq2_value_type(
                0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801_cppui381,
                0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x1092d6886f816dad06c1d0ee93a168d5523a293d7c3e96a817ba1e5936b3837d37bd3d7d8b452e69c042422ccff49730_cppui381,
                0x107e20fcd6e9794de121a9d4105059576811160e1995e6d72fe9a8a1b61079eb144d41bf2e72a2fec9bdafac618fdfd6_cppui381),
            fq2_value_type(
                0x0759d4b33c9d00e6dcc14b95259490cc57b47ed16790904cebb6bf0f7233e15914acc00010efbfe06620e91e623100da_cppui381,
                0x11cdaa6f9efba3c17423d84313e24f411f5a571870943eb488521c3286c0896281275340ba0d4b0ed5ac93fa9fa6f454_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0a76040f2f322bbe0b4c5c158f353f8187aa17b7f29e5d92fbafa17444dd46fcdb8053a6991609178964e185f7010416_cppui381,
                0x109886af215cbcb89e8eb03285e5af5be32e7594a71d6e8f76cab81c165516afa1c729d5d3cbaa18f32b888e4dc8b8e3_cppui381),
            fq2_value_type(
                0x085bfd4c5f113ebe52cfb78900438aa67f2e515f729f72b5d01ebb6a7b2fb238f1519912f1ee07948faa2182455155b4_cppui381,
                0x19cb1b61514f2293a7eded56d7ed72e6f5e701f69c1aaa443e53fea17489c305c142df0c7856b363fdfb6b6807662713_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0ef902393a8a91fda1a7f2a309007aa05734166b37e5c4be462444da3193c18ca7cc486cbb8b283ea2988e0f8915a2db_cppui381,
                0x02202489dee2f690205cdf8c2c574ecd39dd1ec3aee67ab0eeddbdd64dc40db580ce52c473ca3116a74e5610be62498f_cppui381),
            fq2_value_type(
                0x02b12927688ca7378015b66eec9bb70261d9ddd0dd12ca910dfff26c37e4b12164fa75b356d61ef1ddebb3c949af0956_cppui381,
                0x0b8fc8269fe35645cf44a8b50d268939f9ff91e8a3e5c330d005e51db2af3a8da8682b116bd4d42598b710ea42422cc2_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x177fa050dc1878e000b4b04db340284dd026e7cadedbdf8dc126cafbdc4bb7ad329f0acc1b19260a92f1f680c85dc0cf_cppui381,
                0x063380010a1e3cdb9445952921485e4e3ce6ae21b9eae41e108f96f105123a8c7e3b95b5ae43e3923b9afbcbb213a414_cppui381),
            fq2_value_type(
                0x050ee2081d62b70dfc3681f20461d7f0419d5dd77d05da0eaa76f07d6d0a12fcffc4c9246f1160d86392c3dceeb06d6d_cppui381,
                0x0153c9fccfb018f4bc403458ca1ad2c50214746df68e3bd5254e2e6710e7fc621cf3b4e41aad46bbe1c9683728411fc4_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x10e5eee5ade590a567426ff7d9f536ccd9bcf1f4778b8523e226ee72e323ea0755b9703d99aa41c88ade3553400ce5b5_cppui381,
                0x07543c642fcb2c1be9452002fca1f841b882ff49e9ac3d7f376e19b470ba9055fd311772fb811159b6449f9263e42142_cppui381),
            fq2_value_type(
                0x19b89423df5fdf0556acbda2683ddf03692af4fe843b940d8e792c1869448c152608d726652dea0016d111a29103e59b_cppui381,
                0x0f560b3e1647ba37816a1fcafe8cb7924177ad8839d0dfd4eb767b6a6f07b76ba1e4415303e6a52d16ba6a5f7485f25c_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0ef5d4e85c3a8fa73f4e7262599a9f7bac7243a9fed5650e58b4c00a7a908975126fbd20df4830c22d7a8a4299894891_cppui381,
                0x01e51e57dfb30ccfc5d6a0bcd574747e70e9c87fce5c198dd46318bd81e34fd6ef0c2380878e71ae330ea7f6d0e998f7_cppui381),
            fq2_value_type(
                0x123ac807285a456cce114701b10230d169bd0ed876d7624f7a4c9824e2b53d97c2cd09d8cbe1d7c362007a2aeefa01a6_cppui381,
                0x061947176e5c9f8f650bd781d51015369cbe9fdb1c5fb6711ef37b66e4705837116c3c71c53cbfaa1e44814b1a0442fa_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0b0b09a27a9c6aa5a68773934499882058b9b5a2ce4f873ec70de8a8fbe586d409537fd14add0cf2bb3c4b2749f0306f_cppui381,
                0x064cb42e6c5bc8891c044cb5695c3b3824a926d66fbf9806a3811b072a1ea46e0fc1dcb8c7b4df902b6f86bd5d497063_cppui381),
            fq2_value_type(
                0x0b9e9bcaa0c3ce9b91e0dbb85d3fbf21674c93bd26c64c22445ca9819b1a7139f45b4422dc13c0239acaada16f8b1c23_cppui381,
                0x128acf27eab87ac625ff0ca89705c8fc4c26d35cc645dd87145ff244a859bd1d706790c07122a4203e0016a1e472fd39_cppui381),
            fq2_value_type::one()),
    };
    std::vector<G1_value_type> pk_wkey_a = {
        G1_value_type(
            0x0b522ca98912012126ad986195512d8d9259553fabd1cfdd926d671c4aa8db8b6427f2479e18dfdba1c9b46c81bb5e17_cppui381,
            0x014cd687b9641dc21b9bae8a26ec95c9501a5bc5c7d710878ae81bbe2cf7ec14e17d7188882a571edcc3e185815414bd_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0d806df34d7ba36af7569b2c936b27c8a292242e0da0f9dfd0d6bcb0bf858401c949fd1b7bbe391b306f5d95e126916a_cppui381,
            0x082fdd273edffa8a82960b9a77685c9edaa202ac9ded5f6a40bbfc83901baac57e84001ca731ce2dd28ceab9299d1023_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x015d332f8ae2a232e0e41eaee8e718db07d360aa4e7efa10524b97f2e209e03405910e94abf3cbaa91ea54ebed391b99_cppui381,
            0x04dbab44c5d1a057a65fb4c98d88e43358e4de735e0fc575379a99764167fb34b05558e093ddcf81c10e48c791213f5c_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x009ab2fa2fc3c370245b8e860672efb118248c8851566dde51e979e78a3fe7925bf0c1286a8091b70498b14695257263_cppui381,
            0x1321ecd8b5990ff6519e090b033f3a6a3e57f501bb71b359acd0a9521219b559f6a2b3354f93928385eda276e84e6530_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x017e3a7e26a60a6edcb460c79f337f37b292029ea396fcfde82bafed31edc205937bc145e5d69c8eecf87d894584c791_cppui381,
            0x127975318f793df99a10a3ace2b49706a29bbb9a6a974d205aad427d3e98ea263fc2a0dcd8b647d9b36b9241d3e653f9_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0a9d2406465e2197ea5ad674fbf51cd16d6f885a98c6500dfe572dffcd31cbaf4063778692a4f6111118627cb24437c6_cppui381,
            0x048c954b203cd7403f46be13699c0bd8b295c0e5a112e56fe37f367a9115cdb72ce8d7691e9869a92b51f3556258f52c_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x087b91d367dbc6b564d8b43e4370e22bba590d5c56c21c23ff16d7a8b220b30f5e46f6ab8104ff9193b5edd93bd37044_cppui381,
            0x1105d394dcc72fdbc1e4609c98b59f33979be317305ae2ab1e10a9ffd58c4dcf2484cd1842d7b02575358b552b1155fb_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x12e26639adc0ea9afb6a833e9e5fa60f7315787803189d438a4070371a011623c47718f34e24656d9fa105c54b0e327a_cppui381,
            0x0c84c30fc69070f4d367010b6a07a604446144af73a8a7c681d35a5e43f8be9d327b324a699464fdd57cfa5248e5196f_cppui381,
            fq_value_type::one()),
    };
    std::vector<G1_value_type> pk_wkey_b = {
        G1_value_type(
            0x18d26cba6cfb23c442c58d0137fa35e080c458b1fdfbd3088e666306f965a4e32aa3f7a077b22a9af6ba4ba5614b241e_cppui381,
            0x06c0e13143d4b7c802064c54097165e5be9b091125e513c9927f9452521bde82004516d2a6e38fd7e5ae3fd10e2eb549_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x03f8962168d7f9ccb1cfa4232f669b2ddf7695386ae5a684c88ae96ef9be862d52afb315bd9b361643cdccdfc7a7db10_cppui381,
            0x03264c2a67ed8aa5649788ae48348c0fe50a9743a7d20fbfc927dd601648df09571dc58b3d2b3519b66ba9c5920facfb_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0a955178688ab5b8a82620a97193079199be803d26214d35e350685b5c40fecb184e0f54026e8c0482f264a5d076591e_cppui381,
            0x10a23cbc888b71b92a9fc336ca7a7f2c7b09de6468e032285558fc2e73616849ed23931b9803bf049b0ee45e8c20cff0_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x15d02caa8cbb5c58a7997ea859d7d8abd1bc8d5b5e42e4a9a1cfdd09a3e40107cffc81a1e4e3275bafef1130124a95c6_cppui381,
            0x00bc9edd53e769309c4217a83813eeb49f4cffa1a6dc88f436b1b45e5d8fc4fc4784e4927f3f8ef43ef3ef52970c07ee_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x15fc65285a90a3b665f1cea98c7b5e8ffe6baed2a55474ab825a128a145437abdd5362047d2771b40e4028f6eb44055e_cppui381,
            0x0e93e516cc6592b003c6cdb33157fe920a25972b6275735a7183fd1eb3be495d0b13aa6467b4fbb4f36663609db07b5c_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0fd5d25aeda51c5ecf03aa7b399a7e5df53c7a9dd05daba949bcc46e8c8bea53281b20970c1051295820c212563d27f8_cppui381,
            0x078fb03694b51834eefb217699a8ec4dc61f8b3532b327a45fd52991c885df3e9197b632c2f1e1bb6ac0ebfa45ec1c51_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x06d4d645adbaf6f308b0a5bde1b88b9dc53705398885a29c8a47186e84784fdc53b6019c6e55ed8aa17fce508b16ca4e_cppui381,
            0x0fc0ea575892e2426ba0ab18187eb71cb991207e28306f365f8c1ca5316cc790aac99935ae77223ab16be61fedd59839_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0a3e9a3b12ced9477656db04236d14d9e9c65fa43f34d1a0bb317ed469210b137ec4728f48bb156e8b8dea8d3e64bc1c_cppui381,
            0x0a1abc5aac3dadb984bc3e116f0906c59393da9905edeaa173ae06f8327ea25689973d0311ccf8909d090403db038637_cppui381,
            fq_value_type::one()),
    };

    BOOST_CHECK(pk_vkey_a == pk.vkey.a);
    BOOST_CHECK(pk_vkey_b == pk.vkey.b);
    BOOST_CHECK(pk_wkey_a == pk.wkey.a);
    BOOST_CHECK(pk_wkey_b == pk.wkey.b);

    G1_value_type vk_alpha_g1 = G1_value_type(
        0x00dbb88261e862ff316a63b8cacfa558a5aa7e6388a085fc85fa8d27b06759a548a0aedf3c9ac0dddab13b3ff3d80cc1_cppui381,
        0x030f05f9cc508bf38dbe76fc6d8a9ed218e5959f5ccff54a28a02a80457a47596d99bd0f5f6c3885d518d4dbdfc2dd37_cppui381,
        fq_value_type::one());
    G2_value_type vk_beta_g2 = G2_value_type(
        fq2_value_type(
            0x068ded40c1a55dba490d3b49fb644f7e43662ba502165e84e50294b7ca82d4d7bdb5d93a35702b12984c8d600091ec18_cppui381,
            0x06de2178c3bba1698dc0e1b8de6032bf70b5927c1a7cdd7c902c7faf1e78db8dd732d430458cf019c94fccaef3c0ee6a_cppui381),
        fq2_value_type(
            0x00f901d1cd3f52c6ce5c44533dbf86fc80326e9976d07199be08505cf1f3cc8a7a97d4d284b0ffb6f8fb2cfd74c83c60_cppui381,
            0x176dc9153e5d9f1ffd2873db39b7e2fc2e61df272227fb184f6b654232ed1ac25227f5460669284d01005453e3f5de10_cppui381),
        fq2_value_type::one());
    fq12_value_type vk_alpha_g1_beta_g2 = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x15e21266f7c5ea7867820d42b45b4f9dbdada05f4e37cbc8ad33c02139b1b6d1d81425efaac363937c8246c11516be83_cppui381,
                0x19e0d83cf285adb06309cb20e1ddf4cfdd78665891fcbe49b4b0b98d10e82816e5fe7c700f07908a52b981f1f2028b92_cppui381),
            fq2_value_type(
                0x099c1f3d824c2ce11fb86b091c24c1e1148dbdef4745118a8b0a8d38d770e34c13ba8960486050dad506ae333ecf91fc_cppui381,
                0x006eb8e6184705a1f3d1c612e3e28a31b005b72d4efa0a38a9b4762731a5e274e2ef0b3d62b547411628e14a6c6be1ae_cppui381),
            fq2_value_type(
                0x0726c2a051280332c32aafa6194b0415b3ea2368c8879ccc004b0ac8b89b45d507f571173cfd901375c62a20568dd481_cppui381,
                0x135edcae93eb5ac85010e967510101f58d339e6048f18f8b16a6f0eac490bd88b414c6612e75fe469b92cc277f308527_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x0151a2bd2fa29771bf5188d9c33175979ba7c55586830e659f8d5976215265f2bdf2c3eb1d2f302fe83e1995f2a5edec_cppui381,
                0x10dff806f415c174c43b0daf6586da7547aaa2960e80ac1fdd3e7a0b1a34f0f260466a2070bc4e8079398ebb30281477_cppui381),
            fq2_value_type(
                0x14a6097c017bc7500b737f6d7331049f37c893854316795fcc23e6d90ae5516180210edc024f8d979886d7c47ca65da8_cppui381,
                0x16ade7495122dd7c6ec113e0527c0333830f393ba40e0158c0dc58ad43459287bf9eecd7a3eaa8146442f73803035711_cppui381),
            fq2_value_type(
                0x0464c688647b6de6fbd5a134ec479fb6ecf873c441a983b38ed7b1146823258ece76ab68d3f873f4983f09d86cc9f0b7_cppui381,
                0x07420be6059e97d7ab30072b6a90703f1534037c2a62d40d1acd28f83fa93a516d1775b131ed8bc46f67691597dc3a97_cppui381)));
    G2_value_type vk_gamma_g2 = G2_value_type(
        fq2_value_type(
            0x1333bbde340c3be8d29537fbf8a661b22027743ef5cee4635b800a273afe98b62f708355dbb45187034180a46d9e6196_cppui381,
            0x051da15946eb469ba6f3e8f225d06250207fb757c4ae0df9521ecf11903eb70864376a664cfee29867b4869119c1cfbe_cppui381),
        fq2_value_type(
            0x0baab12c979dc4d9917948b2c24002038e4c304a3914327ceb80aa76bb8b8e9665927d46f882692d5e8923551a44f5d4_cppui381,
            0x149ce899cce09392073f6f04b022b0278db3c3d0130de1b689ce51b25379946de9a0ee5576c3514561b667937c4980c6_cppui381),
        fq2_value_type::one());
    G2_value_type vk_delta_g2 = G2_value_type(
        fq2_value_type(
            0x1104d524c9b324fb1e15679c73df5930d71a2c89ba81ea5ec5857a988acea848472dc8ffbae686bbe267676174c6306c_cppui381,
            0x09bf8db82396247f9b8884c59ac6cb9022c2b2921987f92b72e6152c2d7e27208a7a87d879a13d2e3dfd4c28b66b7c8f_cppui381),
        fq2_value_type(
            0x1792b5390b2aba808de3f6c93be32b44b6f7a49303cdf33eedd7ad0a418684c7f94249ffbbd0bca178c0e6864d899ca0_cppui381,
            0x047c55f72a491f8476b5b4848e124b3bc1faea631d931d97951e580f51fa22c27a150f7efa689fa7ea92a2818410b7c0_cppui381),
        fq2_value_type::one());
    std::vector<G1_value_type> vk_ic = {
        G1_value_type(
            0x0b95ffa1d9439d039bec038f3e17e29431fd4d34f6eed612212c4f44c2096a6546316cc3d1081f812fa0ca2e648a03a2_cppui381,
            0x046a85977315abd58c098ad06187b9f58d809e01650b409ed162611daa90fe51aa4c4e52504e809dbe43e8951f05bc4a_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x049736baaec290149456d283601a3bbc49e52a0d8c405f21e12cb6dc7c00a1cb58776ffc4b2b8d8eceaa55a18dc50eb2_cppui381,
            0x03cc5850cca5dfdd069e6d3526fce72de086b777248e5246ece4e19667f31749f40a27e49ad4ea3c51cbd32f3cbab575_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x13bb5d0780f4aa12e1c05007a6c4f67f43484256919444202ad57fdb13c967780faa17e9a7ea6b3e2d6f4589b09e8ddd_cppui381,
            0x0656d1ef5d8ec8ec2b198fb3c86033fd18fc480756f43aaf8a88e39b844230db5bb785a3c2d02d9f0e18dc90902c6b04_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x09ec91e9f3cba5b818ec629925a7090cfc34b7c9346107cb9a07b55499c2bc573b9c84d954d914af5e81b2ae8252b8f0_cppui381,
            0x0da66aab492dc5aafef10f399e949ca797b94cc1d424e9e66917917b209ca891e66d11d5286caf3b3dbb4ea079ea2a88_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0d36fa8e1b57756031ba096af6fbb22e99b30e1bb428cb440ef864e786be477f21a9191c36affc230e9fda0a7d17b9d0_cppui381,
            0x1354a82cd96022a2473b8f218e3dd3195f54e2a703c0dc69c58358a76ae1eb220711c55399b677dbb583df25bb167c2b_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x036b2788dc31357a8c9cbf642120760b5ab8d3253aff9bf6fb4785261ca1d5c7e7e235dea4c002332fa3cf9e2922a51f_cppui381,
            0x121964e53798a19a8e6954d85ec7575343980ddce3003d691fd007c38bb12bdd23ae674b35a539917d0304e73d741b42_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x15e49f2b4234214aeec15c58d05b620bd401c4fa1a5a0056fe9d284a21dd6dd43216e72fb34109268995a55435b9b811_cppui381,
            0x057c5970ba87501884835739f9af3612b965f1e896c4e88dd1bb63a318ea4fbd7742eb83c08c789ce945f87a305c814e_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x131ca5515ce5658f28d31fe0affe1711fdf2e2e0e2fc2efd80aeecbf6e09dd06d01fe4c78c305387569e0eacadd1301f_cppui381,
            0x0fc80af454299b5313f6c0e1a6f0de00022f4a8b98b1872f1bed4208146ec9ff182e65ebe3f2bbd9e97e9a8993633927_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x14e72b027c5576502a3a0218b5671aeffafb4d99b5c609cd90a46e2f96d058f1e3c9e4b1c619542a28e7ac8bc472c459_cppui381,
            0x05bb8f0d5c5bb84f43776639bc59c851cf68847ad3496508394d1561d754be3f04b5acb7da2653d3b6c2f28f1b643b28_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x19ab93d470e562494353aed2af8c70d2b08aafc156b1c6e24080879c5b2d69322b34b1a7baf12703efd9c6e9f96097ab_cppui381,
            0x03ad762e493a59e8d3608cad7540dfd3015d44790f1e29946d8978b6ec06bb292d335e5c728c59a40831a7d44422eafb_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x16085dc79607d139d810a48c82a977445d4aa65251e9a47ff51d51e05fa3d8ed5626b43afbb0e3218b5bb8b350ffe57d_cppui381,
            0x05885c33ec46d1844f5154d9419c38592b17f8ae4c2d0de36c9d42cdd1cafa29380d148e02aa46e33c124ed572aa0966_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0732e6a4527a2c68a78525cc337794e4d676c7514f3f9dd393f079215a072189b5ad42a1ec400e2259321b6e60eabde1_cppui381,
            0x1422e269997071400763b3e7482ffe2a53b0a5a42f745a9abad0a85df129a21996f09f831c7dc405c50a37eda3939d9a_cppui381,
            fq_value_type::one()),
    };
    accumulation_vector<g1_type> vk_acc_ic(std::forward<G1_value_type>(vk_ic[0]),
                                           std::vector<G1_value_type>(vk_ic.begin() + 1, vk_ic.end()));
    r1cs_gg_ppzksnark_aggregate_verification_key<curve_type> pvk(vk_alpha_g1, vk_beta_g2, vk_gamma_g2, vk_delta_g2,
                                                                 vk_acc_ic);

    r1cs_gg_ppzksnark_proof<curve_type> proof0(
        G1_value_type(
            0x13dac7f44870025445d816a75cf691b7ceff3a43c749e6330e3276eb8b68fee59d97b5f3ab8b61c222ecb11020372153_cppui381,
            0x11eb5400aa91fa11f3e79aff666e4a2efead41d46672fc58bd6efb3ce3e14ca079b3e8f0a3da237015d99a0e9915e55c_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0fd92267608c708eb20055a068152a3eaf9b49df3e951060b941ff63bf2453be443c86d60f29aee4297c1d24cc53853c_cppui381,
                0x05ea088000f639b762269469b2e9250325c86be0321fd6d1d20f073d0ab2e745ef9ef4b458e739aa7d146248b9af3aa2_cppui381),
            fq2_value_type(
                0x070483d78db24a0340143c82b869fd9083b4cd47155a57c3f45438e744b28a50c1abcf84a24abeff727c2f6c62d68184_cppui381,
                0x0766ac1879431ae641b34d0c5c7e989a725cb993b97ef500534a108478b849fef6e9f7461a62a398d38bec273dbd9b1f_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x04ba84bf8d18cea7832ccace14b8182cd363518dd592b2f88325d1d6fa24b61bd7d76c768119426f74e7150afbb6aff4_cppui381,
            0x0f12ddcc76e0b3ef817588c303792add681fe90257e63837530368e6877d5736305744b6ed9621f128703748c23809e7_cppui381,
            fq_value_type::one()));
    std::vector<scalar_field_value_type> statement0 = {
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000300000_cppui255,
    };
    r1cs_gg_ppzksnark_proof<curve_type> proof1(
        G1_value_type(
            0x19a43f8dda558f4a60db82edd8b13c34668d99bcc9262abd1a7992c643082453af605e9e0a63b470e05d0ec3177450af_cppui381,
            0x0382858cf155f0849d846b5207cef9cf400961c242ba5dd50f3f3ddc18b7c20c7e775f56630fc3c22e3742ddaf2a6072_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x00ece8a6a94a310d1929e8db3b59fa0eb7690934c525daae7825bd55641cdf5618ec6344259141c4a59955937f2aec33_cppui381,
                0x126f50c73a14638e7e22d510911afad8258fc132eff9f5ea973094d45fa7e26df44055bbfd2f64cd898f7c517260c857_cppui381),
            fq2_value_type(
                0x06ea69a39622705bbb6bd886642b677eba34f529548cffb46674fef54dea0afe177eee72fc73f70b587aeaf54850c08a_cppui381,
                0x0be1e1d6100c1ca38d94961bb48b018a05b01ee10e3dc11ac6f8d526da5f26c8a1457ef0850d99f75c94b0f74658c0eb_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x08216f93edf127d450129c6da0ef4c34fa5b29928f9da0522189f5d113b2196dbbb1011bbcce0b2cd06e2d4882b9c4a9_cppui381,
            0x0004fe1f2f409e9c7586e6b0ea9af02c5160a7877fcf9eb677a9afd759a1c59f6173c5ae327af9bde42f0a63fa269dc6_cppui381,
            fq_value_type::one()));
    std::vector<scalar_field_value_type> statement1 = {
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000300000_cppui255,
    };
    r1cs_gg_ppzksnark_proof<curve_type> proof2(
        G1_value_type(
            0x10e2e117f5d0e0b0a8c50a194121c1cedeb4e05c4c7984032d0faf1db007360989312b52db73a0de165a3100d4d06ac1_cppui381,
            0x0a74c846d1b849d693bd2e8c3a5ab7fe3998b3c8677fbd56b4940bb50ca80ac9883a3ccc7b58ed177710e79009940f3a_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x12edc68562cd4a7c351c1cf3ebbb35f204c8d4f7e491535fcf82a8ed0ba05146e8e32a6a4ad65839a6abc7e8fb979b88_cppui381,
                0x165e9341256950a17da3541eafeee06cabb4d6a95782fc1d9a01b3da945a6e40022dff8d571bef682e19420db50b1d4e_cppui381),
            fq2_value_type(
                0x13fe56f562a5677f4c23b93ca221adde3cb4f19199fb7c9a24b4d48466920184e9714ef9b20adab97bce9d4d58ada78b_cppui381,
                0x07f5b89ad04d0b7ac5ab497a58066dc50c6990863ad234cee79b5b0217533f79c3da18981503de59eb205315507fa848_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x0e718446d244ccd4514e64f98b2a8ccde8124a686d9f489b771cfbf60f19db43e7ad6d6f916878c842bea4eb9c7c2ef1_cppui381,
            0x024471468db54f72a61348bd887e13407f42617d7c3bed8d3d8c6dba3e92c899a5867690a8c944e2306134aec7df37a3_cppui381,
            fq_value_type::one()));
    std::vector<scalar_field_value_type> statement2 = {
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000300000_cppui255,
    };
    r1cs_gg_ppzksnark_proof<curve_type> proof3(
        G1_value_type(
            0x184ea507b7d84429b047921dbc1f167d57cde86343b098637248fa6b9468093dd10caac84b4b7c65e96b21b76965837a_cppui381,
            0x06647a340eb73e29d2c806f57520b5df2eb8ffa4065afcf3c3bd4094365968af15143ce1afca2c14c6c72cf576461f76_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x19455a20edc11ad12bf05785a20927cbb6ced5d994182f3f1ef3d5dd1761ac40db62976ffd8c445b23928dc4003f2310_cppui381,
                0x04c080ec3527e90b22e37051be239544d99eb3b91e81d3a3303c72b1ae63fe46c3016b261e0900e866ee8c48402f8989_cppui381),
            fq2_value_type(
                0x198af500c968b721f40450c165f9775ac632a3bdb626a5e3fe1ab381475c49cb950aff85b861f37b5e35990dc05b90fc_cppui381,
                0x108e243685a29bc6bb6af53ecf483d1a6d0068df6e84028a53489e4d55ca0c3239e097ab4229fd9f4d11ce9d3aed8008_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x0f2464c5d9dd74babcb8985210df727593ac622745c78e53321e16ce60c73658502baeec77c5e75b2632ec9d9292725d_cppui381,
            0x104a076f63f0855047fb71d45587297d0233a04eb20a6a2d3e90906e63daebf1f410a2c62e6ccdbb7ebe0c05cee1b59f_cppui381,
            fq_value_type::one()));
    std::vector<scalar_field_value_type> statement3 = {
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000300000_cppui255,
    };
    r1cs_gg_ppzksnark_proof<curve_type> proof4(
        G1_value_type(
            0x17f36c1c6ae991a5e3c7ba129b6e49eed8776c29469394afc76e19ae9b926b1c63d67d7c05cd6852f2a9eb5cb5f26f55_cppui381,
            0x045081c8b18cf7cf0875f37352c7ed583b8205fb11f07e9b4a9581e04e1f1e935e10ea968b00684a0c99f8e5ccd6e830_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x126cdca0cf7d3ae9ed4fe538df8bb1ba9669899fd4a822e377682354490e7146ed474ccb96ac6095e060245f6009e489_cppui381,
                0x0747fa48f440255068bc724e3096cc570f23da12e8510f30b61ebe9b3d2f7658cacb471365815d2a2c07de09b9c51a14_cppui381),
            fq2_value_type(
                0x08a483e832b9e1d0f4fb70b8cf027b640e503d09fc39b730b87007f6b0eac51f56a5c323e4703ec2d2b38101eddca085_cppui381,
                0x0c722ebbdf18a7a8974d3ae2e8fba991b77ffe15814061f80fba34cce803c411a1c134c9bada856c7018b96a8985636b_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x18c7b7f92e57efa6c0712e2b47e9893b639757b09c12057fb93a48068dc95f55eb4b4246cda0f9234f86db1062637530_cppui381,
            0x01f20a6681a1ec639e6ec280a35f274f859e5df114635d5da68b05f12d0d556036d4fae1c478a37f3f9369309a5d3702_cppui381,
            fq_value_type::one()));
    std::vector<scalar_field_value_type> statement4 = {
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000300000_cppui255,
    };
    r1cs_gg_ppzksnark_proof<curve_type> proof5(
        G1_value_type(
            0x1770723fb3ae99fecc9a3ff8e1e437c9e02b905cb8436ae822b737d246d5132f8c0b60d5fdb07b6a463b38e3931af491_cppui381,
            0x091f4b72e0063c4e6d688dd2674f412e08c98bc4a835220ed05cc3bd87231deef9568eceb2db63931c4978d742a23c65_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0654542ab14023b03bdab2bd94d894a8cbf3f35638ab47b1c7efaac8220d75993397d73259ade10f1dc732b277afdcdc_cppui381,
                0x17a7e225a880d2fbf279e1e4a137867991b8cce2e1ab8879585c22f385f39d4fdca864d894ed45ea6d6bc1adefa6b2e1_cppui381),
            fq2_value_type(
                0x14f53e605e54d056b613723c6caa224df7260abf012d085dbc5fc097a4c9721f578efdd8a8f0b552755adc31251232c5_cppui381,
                0x136d84270ba8b2b952196f4c25a3f2554e38a75fdd93331db085a6fe7060ef1b5ea7e55ac4b4f97626b1aff465223622_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x0edb772cfa3d59051b51a9da9fffbb451c3d3b3383748f5ea3d132bbeb835b3c74616990142c5972ac074dc1f1f1d2c4_cppui381,
            0x0cbe6b7d7fb2cd86370f609c1c220fd42505fbcb2f30b33fb65ce2319a5d76a522fbbebf2a3b088ed24287ce0f520be7_cppui381,
            fq_value_type::one()));
    std::vector<scalar_field_value_type> statement5 = {
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000300000_cppui255,
    };
    r1cs_gg_ppzksnark_proof<curve_type> proof6(
        G1_value_type(
            0x13969ab74ceabd253d6345fa7e49386b1e82ed9214a5c2d3725ff55c36ebf7ab9e7fca7ed0d420bd556edd53a5088989_cppui381,
            0x031231ee5ed0a3a0fd0ce384f564fe5bc8ed7fa156e7a9a642855ced86b4dfc1c91b38d317ca852beba4912497b1fb51_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x031dcd7b08df20c93474b3883aa42b4e7921055a5c17263af57bb7661f0a9dd438f650a59b1e81e13fff0ac3714ee3d4_cppui381,
                0x15203fb4fec67ce68cb87116def30b84a7d7d8a9f15583f878e7657e907a91c7a13704c0e32d005a31544b6a67be3779_cppui381),
            fq2_value_type(
                0x01e43c896ff6f2cd3d6d57709d8c8cea581163fd68728cb1339f3e74a289852f257ca7b05916b947e7f98917565f6abc_cppui381,
                0x025651e5d33a8ce6bf08e4fb2845611e9d6930871774ab64040f648696bf7caaf5afd5570f0da8c77be06c9d50b9a9c0_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x06aec97a6923f181b083a9c2a44580ae2114c63ccfd911e8a6d7d6bc5e299aff31f5e631156746314a0a80d71694ee98_cppui381,
            0x06e63fc9d146bea9c62af2dedee947eefa5eabe8fd5ef63e64b5e860102482f170db30e6dfe6e0f53ef02f5a9937d5d4_cppui381,
            fq_value_type::one()));
    std::vector<scalar_field_value_type> statement6 = {
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000300000_cppui255,
    };
    r1cs_gg_ppzksnark_proof<curve_type> proof7(
        G1_value_type(
            0x0838dd40f3792d967ed840c60b51162d4c0c745aa953075117dc07444262617e9fd58cad4595036d5b815d87ffe287b2_cppui381,
            0x058fad8c362ca1f416b7f13329782eed775868ad9724f1f312d60a3fc5469964fabf1b6fa85cdb266de14002074cfe11_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x16ca9728c4dc860c70a9907823ec600c70a6aad0e7e58a97ff5548d6c0c28e0be6d2b32a9a11a5effc6a6664ae729a78_cppui381,
                0x0640ca9dff5a2f611f6375745b51db9d15d1379bba2ece7cb958f04bb330e75f537922c9f6bbaaed51eea279f2256225_cppui381),
            fq2_value_type(
                0x130914c2436684cb13844d4abe4c3ee721abefa16608a0b6950de5f01d5b1b84181b94bbf2d50fceada7a034911858c0_cppui381,
                0x016a4e0c35de9ba5097a643861d02e33c24d016ed38695e8be69c8c342808938b8177fae45b46d1233ec5ebc86eb35fc_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x08acfba9b2913a24c3f421c794dbf100fae344c9da1a790c9212021d20ae1002c750917c42e5e8cfea24a5c7345ae96d_cppui381,
            0x0c527ce8192336834bab92a8d7963aa2f504cf86de24c29aaed66d1682c8a74a93ada21545debffc25dc09372999713b_cppui381,
            fq_value_type::one()));
    std::vector<scalar_field_value_type> statement7 = {
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000000004_cppui255,
        0x0000000000000000000000000000000000000000000000000000000000300000_cppui255,
    };
    std::vector<r1cs_gg_ppzksnark_proof<curve_type>> proofs {
        proof0, proof1, proof2, proof3, proof4, proof5, proof6, proof7,
    };
    std::vector<std::vector<scalar_field_value_type>> statements {
        statement0, statement1, statement2, statement3, statement4, statement5, statement6, statement7,
    };
    std::vector<std::uint8_t> tr_include {1, 2, 3};

    // r1cs_gg_ppzksnark_aggregate_proof<curve_type> agg_proof =
    //     aggregate_proofs<curve_type>(pk, tr_include.begin(), tr_include.end(), proofs.begin(), proofs.end());
    auto agg_proof =
        prove<scheme_type, hashes::sha2<256>>(pk, tr_include.begin(), tr_include.end(), proofs.begin(), proofs.end());

    fq12_value_type ip_ab = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x15252e258c8a254162aa0713bb76b78dceb590bd54a222c5cad3d0a13adf93d45be071beae8f4caa66e27bb7343e2c00_cppui381,
                0x0d56df5892c84ad3ed483859d6afcf28338975350084beee6d20256ab57d492b8abad9b73d2ae776995589c6646f0b00_cppui381),
            fq2_value_type(
                0x18370c4988d1f03c331c0186eb562f3d21bd3c60a06aba6e7129ca07cf0ceb586ebc949aa2f4653e3407e0017b0d93f2_cppui381,
                0x08d3f06b80b77a84ca89f28901a46f533012d6ceab10a312a907d251c60cb62bfe8c62bbff5beeab08d706952e80e315_cppui381),
            fq2_value_type(
                0x0fa1557f82f9759e5d09122f5397f04f84923bfae26c553de3d597aeba214588ffc209f2105868a91beaeadf5a139ae7_cppui381,
                0x00d441c1b438714a40c0ef990976ffbdd35041b4f5f1b19b71ef1b27655fc6ee2d2308ea954e6d5fc52e3658da1b4b57_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x0bb9debb1f46a12857b5ee200dee7fb1407dc46f0b6f2033003471ec5a374a70c2b829d37967fe64016ae52c40e29f6a_cppui381,
                0x1120eafcbc20a2197ba3a72c1e45fbf439b388b589a14df2e72e396ac7dd587ea6c7ca5e0c92823be3c6a9ef07d25bf2_cppui381),
            fq2_value_type(
                0x0d0351b20e3e456163078dc71d00871c03e8a1f8aaeae4ca9e5a84892654253178619a9117d27e8f4489ce50c8006fc8_cppui381,
                0x01645839c061ab603b6f2986dabc01f34703c51d7665dc049de32cb9edc3d19c4c6bba61f5bd9e547338314f48d23771_cppui381),
            fq2_value_type(
                0x1790f2b2540fee819d211e539d7680e7aeab3a9cf83a562f496fa951ed8e2d5bfb597c7e952cd5d549b2b768e3785f1d_cppui381,
                0x14f7b9db7a10270ce2462e8b44f4b1688ff2cdee66c35b4013746a87a15a41945fc0ed72c2e0b886d05f93c8e04b97f2_cppui381)));
    G1_value_type agg_c = G1_value_type(
        0x04dcf2ded167d1b951bc10d1c4a15aa6f9b0cf228e44e197a9f0a588703241175006b04680d99d271c09c14d754ff5fb_cppui381,
        0x010185ed049608e00f66fe27230967cab64aad05e7488cd5a46bc581b159488af6c711d4b9ce85f7ddc1a9b43cc611a6_cppui381,
        fq_value_type::one());
    std::size_t gp_n = 8;
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>,
                          r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>>
        gp_comms_ab = {
            std::make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x13091d70ceb2c2901145ecb1342d954a96e2c05d3c952ce775768645e709ab46fd821b5d8cc61402750307423aead6cd_cppui381,
                                0x0546adcae5fbf133379902abcf64a45ba4ba32c9ba315dc7549a385d7557d3e1fdcfc250b457a69471a70054ea6a5157_cppui381),
                            fq2_value_type(
                                0x02c3ea9f0a071e62ac2b88251b553a4fdacd0386192dc82653498719ea7f2c47c10e6c500f845d6e49c6faafefbb8f58_cppui381,
                                0x02a5f3c7da7f364d5359626d7c91119654b3ceebbef6cb36799efa698ce5d28b223b5f771168194150ee2958b975bfbe_cppui381),
                            fq2_value_type(
                                0x1648bbcbac0518c6305fd738841902786179a98b93bda72978255bc58938ab43c49cbc3fa9587631196633f66830c02d_cppui381,
                                0x0acf83e424bf4792962b87067bd29d97c1b6abb53e2633d51dfbb86924de8080ebd1f4b852e7a4c08db06debeb1a0279_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x16d4c9818e0861650aff4041e78088bfaccbd67900a020e03c525ffe2caa69d9b387d8a08ad47899588079e34012b50c_cppui381,
                                0x11dbe1269397900f0e7eb64160817bd96cf7ca4dcd2c2615b38b10e79c4168d511db4113984417f3ccefeab868c061af_cppui381),
                            fq2_value_type(
                                0x167296f59ac1d4be32d7febae0f261cf4f95588891df8008faec834f028eb6ef75ebba3c0e778522b45b7e3a4c1ba656_cppui381,
                                0x0e31ffcc2f2d317a0c84e7aeb2a9f2f507a5bc398cc8536d3bbdbd0c489c938e88414b0b30e7477cd6bbc57be899754b_cppui381),
                            fq2_value_type(
                                0x01921fdd165f2d604dd9126dc6859f513014445cd17bf5a4ca35c65fbe22ab8fd5f1358e60e78e367c114df6f56decf1_cppui381,
                                0x02c83df2a4fad2f0bd457a524e636a4bb40229ddbae30c5017c4a496424d4263f30ef3f96e9bdbdb8584de2b25097db1_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x0afe248b9bb700cc566caa87c4e80f2ba98e288a924ad4553b009a77f0e72daa108a91293a23781ca95eaac4befa9ab7_cppui381,
                                0x1016af82da70c56cc28b332c3d7e96ab05e1a3c910c17f9154c3ccf5f1ac0e3312f81f58cd40b5441f67dbbfe58943a1_cppui381),
                            fq2_value_type(
                                0x0d760206eb007d7c70fbd5bc0f29de6b85497f1b468ede2a078c81faf8ec961232442e550ec8f09f62e407504c123e2c_cppui381,
                                0x100b864328cae15ed7f68f8f7f1e312d116293479c8b69298f31fc1478f232be54b819e15f371c4550b7b77d599e19c0_cppui381),
                            fq2_value_type(
                                0x15e012d1ad37933394e6cae1d3ad4376e12d2ccd0dcf2a01da15fc75bdd559586894e3486932d5c718cc9ab3b0174f19_cppui381,
                                0x09c35cf86db16062af544a3980aab2bb5a85f7123306188c32214d231ec69c71c12c9b3f0f3478a8cad53c22ab06f9f8_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x041ea2166a96ae447336287c94a6c33ae1b6a8a94a7f7a4abbdebacec447620bf6f85fa50556cf52665cdf30ab30e825_cppui381,
                                0x089ee10c52ec4f7256076f5dd865c5b7de2adab17377d2564bb5ede1efcfb33a6c22662eac51eb02cc946f2219ffb5e8_cppui381),
                            fq2_value_type(
                                0x04d79103c67e812fdcaa5e348afaf5c9d6588e087db842dc75e16a910dd3fb39d50bc46b1ac07f1716fc7937703da9c2_cppui381,
                                0x12d45499d5288837419e95a22aa015dc8bd26aa1a91e3cb825feb1b98dd9a6d921572fd25b33c3f93bf81579b74b3690_cppui381),
                            fq2_value_type(
                                0x0807a6dffe07f268d70f55d7d9a9a9ad13019d46935af00aa00e3b391d8fa003cb606adb4c80f9a07d8c82d19e7a56da_cppui381,
                                0x0035396ff8113f52c6aaf71f8321a8ef6e07ae85675b819ca8581f2668a19abc954b08eb5795eaede8060f8387938900_cppui381)))),
                std::
                    make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x0738baf0101e602caadb09708668dda040abe458ec040c31ec8ed63308dd22a3f8b8c7d4452b1ad27593a0b053c589e4_cppui381,
                                    0x0c7245f72fd0fdb9b4bd3a2ed14ec285d43e9289d239811c40b026d53b453296d7da0fda56618dc0b1e3891340887779_cppui381),
                                fq2_value_type(
                                    0x013df249fa027600707ebe4b5bba95f2ca4e177218fb15292d81b8c1a35a75a40832d7508b78f99da1608b8d0fed5e9d_cppui381,
                                    0x071707c005e6cca4ca6dd8d27a5ddd673cb5a34f9d25991047e399ed94654e8d5c18335fa430c23965578833662fa8ab_cppui381),
                                fq2_value_type(
                                    0x1078257df06c9597bf058babaeec318f3b98c475180de46103e4e5a61bd11c10315cf46450a2eb2a6347d996aed22087_cppui381,
                                    0x140bbad1222271b3069448bb11c5c5d872b1ba874c47e96e22e520f9a4053b848654b8aefd3bbfc842634cb9a1dcf804_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x08af54936eb856de0d785123ea2bad5ef0e35b9872ed23deb69fd7f1311ece79f49ff4be3e2b3e1c1962d94ae95ac2f3_cppui381,
                                    0x1945e657f32145ef5412d3c375f3afa3c816ea319407a7917582165d8d3981e6be1922c661eb93d4e4d664c9513f1394_cppui381),
                                fq2_value_type(
                                    0x00f29356d9f2fdb7d88ac466dc7b4fc566853f100ba905b4f1219a17904bfbd487015b4073c8af81fe2dd34b1d3af885_cppui381,
                                    0x0bc5fb7b6de53e2a8a225a1c253ded5fd1d3f3c08bb915d503b1e6af7a5d2a19016c817ea897999e28b9ef8093539297_cppui381),
                                fq2_value_type(
                                    0x082c2f5570da3bd8e5053c48398fc92970d5281ab70a772c8a0c460e329640b71e406ca067aa9e717471d016a5d573de_cppui381,
                                    0x04a05065c01db76ec132046115798dad8984fc7d1bba1f0fe82c353ed8f7853a753ad7df9b1f9e7300f33ae2d8b6bb31_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x009768689b88e6107799b48e906156569610ef751b74d64f1d6d8d537d8344d7e4cea4c269376ea2363f94e21340ec29_cppui381,
                                    0x15cab72faa784a4b4ecf7f84593748bd4671fdda6ff1e2a9e8c447ae9bde2ebbd089e5b174e6913c226f12fdddeb8c4c_cppui381),
                                fq2_value_type(
                                    0x0e588b08b331beaadd6afc54242ce9e7712268ac886037e87847fd919b92d8c7834f19438829278dfadb1279fe82000d_cppui381,
                                    0x0e645c6e86aaab1397cbf3c614a57371161ece8cd9d01aff3cd7aa4e917aedf758cafadde4525c0259957c04db0c2cc2_cppui381),
                                fq2_value_type(
                                    0x173baa189f6ea98a1a0d8483462cd4a34777545f9575c693d25277a4c663779dd55becca6e57f48b2ffc8553ab9fe79e_cppui381,
                                    0x0f2a437a44bdd64bb9e9b87e8d16a3d99e5a3cb0c82e508cc46094a37e2d82c3eadd79b446c241857357d8744d2ec79d_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x15d439f18b7b24da43834640cdd75e5d29b9b97dc3494a454390b29884b780c4d53757ac557f76b9fac22c086dc7378e_cppui381,
                                    0x0d9668854faa9becf78ded5159d863a416d1dd69f5b78b27f5be182fba0298bdc59fad64c10971d38cea238984ef1c60_cppui381),
                                fq2_value_type(
                                    0x15abd3550400968c3a307bb94650400b98da0857793bebfb216594411c207f3fe5f124274b3ddeede427e6f91e366c96_cppui381,
                                    0x0bf1d69b218c60a0b5f195da1b59fdd4748c0f08de3c8a6513ab8cdf120496e7c7effcf3e9236a7b67e17ef3a2366a72_cppui381),
                                fq2_value_type(
                                    0x0001bd08cb55c7b178c05399b7b438af900b98bc64f9b7f0ea32f6a6e9c094938407c248b4817a6c2fb15c9774907fd9_cppui381,
                                    0x18e9444a03b8c432647d60c7efb1355143eb92b87c293619d5dc6814b1b3ff81ff0b5735aa216ecc0d086d7a2f55a46c_cppui381))))),
            std::make_pair(std::make_pair(fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x06584a5c6d20e0af83af47d3bd49dc8966031c1a5ab6e8c8fc861f1b55902f7718eff9235cb16c37fee22e552ba2f46a_cppui381, 0x128b676ae705745d4b0bf3540de1ef1284fc36b3cbb67290160555e054e46ce7d8948e47fb20fa6e56a4f75f8fcf74b9_cppui381), fq2_value_type(0x02bb70cf0812e8c97f2b09bfadb650dc133b0ea651a64eb5a7eab09ea4efa900300f45a2d5cead5d9596006b21a88157_cppui381, 0x0b129d9c8c5f1103fc1541b51c2e6c056e98fbf9101e866c934b0de6c410683ba8a98ab4ea43765e5c5362688260b0cf_cppui381), fq2_value_type(0x196740eca7c5347b841afe46f06a1a45b8810d1e680485d4507cc7f80eee80a05b814af337839eaec5ccf4bec0798456_cppui381, 0x0ef60cfbe532b6d2b201de82de106d7fd4b808f30442a65230420031cd7411ce9ff39f76005ced3db3d2a3a6f44e2f48_cppui381)), fq6_value_type(fq2_value_type(0x198e2fa9c90091d1ca5406f562294fe3a0b9e5990f5bb498f028b321620611f0f1be25203c1ddbb24d560f40779dd469_cppui381, 0x15756a219430399125e54b7aaeceaf0d4b976f2988b2c0e6f576e9f3c7b7f7c341a68097090f0cf83cfd0d86c9d350e3_cppui381), fq2_value_type(0x154dc2874939ae724c102c6ae28c2e3a866a180f8c02ceee88f2905e043aa3d03c32e27e66d1a229473db8ecf69457e1_cppui381, 0x067b240560afb3e45c8463e9f927f1277cb75390330e7f5930f984e20f8648ca89190ab6035c0e2de27f7734b6cb4a37_cppui381), fq2_value_type(0x1759e945d499a7899dfe6c47a1212562c0e0c6c95aed3ab961eb249690504de98bdf93197bf37bc91a1f5e7c87609d52_cppui381, 0x02ee70dff2d1ef493ec3e7fbecc4fcbaac3144a1de34accf304ae8acd18d10bfd3e5e3166d9afb6f041310b6595713b0_cppui381))),
                                          fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x199caae90d77298fa58a6948b3444b03a96f0cff25c86325930dd2df85d74b87843b1e7cc56698d8e4f1b60a6ea643b4_cppui381, 0x1494a4c52337211aaa590365d23c7f6409b88218d3c926cc89405ae6ebc6baa064479efe6afa705c743fa5c485a1c4ab_cppui381), fq2_value_type(0x16899e194a101c774948f3c5a2bc74c6238071ff6ecf84f9d284a110b7e0a6531b2dccfa01450d48215e6565557e2e03_cppui381, 0x0d171d6dc9db50c39bf770d39fcbee178d3e6cc72b976f97311491144cdf901a5c59dc074baa40fc163d8611cf090e3e_cppui381), fq2_value_type(0x104297fea3b547c24beb6f0efe1852ad06d1dffe1fc617dfe36ac8f038f87d98bda0ccba7118dd2a961c145c4a8fe1a3_cppui381, 0x038aa53fb6a88a9311b69f09c0af2b90d13f9e23922d49414639f9f0b2a65d21ff3e5a971ca009ed8d91c14f14823593_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x10f99c01f6769b135c6908371ecb5b63710c965d3abd21d5d63368b9f927bcd88b6fcd796feeca9a27a9c7fec5581cc0_cppui381, 0x120372109a8d121c2138c40940755a1122acf3e493bc6db34ccbf6e97bb6e9c6c35987c6aa5bb74e84c2abd54485d059_cppui381),
                                                  fq2_value_type(0x07bf602d1fc28109c15692160108d4f2c9253e69b176562322e1ac7dda39c55de17a5da4bb88b30ac668fbf461217161_cppui381,
                                                                 0x1809201ae5a2cce3ef23b791bdcffffeeb6871e2296254c79306c6c7f1d4174135cd8cb694d2fead2f88ee2031927ef8_cppui381),
                                                  fq2_value_type(0x0c083963e96ccb03923a53eefc1db6adf6bfc0c92cc8657ea0b1c3dfb21cd5722cf762620f68edf2cb1d29236c4f90a8_cppui381,
                                                                 0x10ef87bcbfde5af702ff8928b2d8bb656b590b8d1acaa89a14bc9b4c5d9000fe40af12b2e83d9ae7e8c78e0576cd2f1b_cppui381)))),
                           std::make_pair(
                               fq12_value_type(fq6_value_type(fq2_value_type(0x0af0e92e574de68843324051b1d701f0cb170c6e03e390d6e9f6dff60ce40df61519629af63027c6eb2b4a6a5e36cbe8_cppui381, 0x003f9c06fb1baa84ea2c28b0f3c8aaf34a517273dbd1784a90b3e1ffee88a3f43451bad392a7bd5737497e1a87f9dec7_cppui381), fq2_value_type(0x139f114c7fc292108d53441f4bafce07cad4150f105c4e88745b9fbce18318ea0a31665cf2ba53fac2a29a0d8c5bf854_cppui381, 0x0a298792082e4500a3f852564930d0ca2e91ceed3fa806ed53f3518c475d76e3b5f4827cdb723dd620829716f7a31829_cppui381),
                                                              fq2_value_type(
                                                                  0x1322c120e44df964b1244d2b12cf65208f1050e81d0ef743f68b50eea7213c31619b20e7ebfc782721ec0d0a25ffb6bc_cppui381, 0x1655f0bacbfb0c9fdb6fd33362f146a23cee22d2146e4b794d139f4e4c3ca17fe9aef6520c8e5a6dd9accd5b3a5c49d3_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x14202be4f536a233ef085d72287fd18be6a8c21413b2e7565b39e1745699de70db205f9e435bc16e22264c2487eaa5f8_cppui381, 0x09f337217faaa4ac49c5f13bb6c0f495261aebd9c3a6be4a1cf4b4e2544e5097e5c1fa6cadce98c044a2a50e31a36586_cppui381),
                                                   fq2_value_type(
                                                       0x11d89c77ece239c72f4582bd8a3cadda647d28a4390e281f6333869a733be304e6404c1eeebb9c510321aea854a5eea6_cppui381,
                                                       0x0425b0f614c67bee580a358b17330fd9f4383be69efa79fc4ddc62d47220ec9ef89ca2537d5c6334f7d50aa6c86f6819_cppui381),
                                                   fq2_value_type(
                                                       0x0ffc20aba78fa6c638ba31f9fe44126202fd37dece3598c85680c7b7b8a87c4921f99a70d0f595725433d17e74bc11ed_cppui381,
                                                       0x0e33dcc151a12aa89d179d5b79eecce5f624b7bc4ab63afa1ff8957afec17ebfc756f71136279c18b1058b4d7afb12ce_cppui381))),
                               fq12_value_type(
                                   fq6_value_type(
                                       fq2_value_type(0x154031ce4bdf117de9d46d75a4886f1745d74bd0b7c9f4fa651b56471a1f0d97ad1edfd9f8eea426eb17c2c8d7deed45_cppui381, 0x16d75b56249ea949dc59438b063b1bc6a12f5fc03d9997e0e02bfb6b8c400557e723bd5e57fb78802c606ee4a448e832_cppui381),
                                       fq2_value_type(
                                           0x15a9eda509a1ff96507bf24d154ad52c2bace12f3f48ae6b2ea834741bb8bce5f24237c5f2c2e4e70ec7de0c40c6f77b_cppui381,
                                           0x0fa8d7899ad29e706e5074e05a904c2783bfd804bdc531bbda7ad68b47bf3ce77c216c2761425fadbf1716a699e9e99e_cppui381),
                                       fq2_value_type(
                                           0x016c3df57b100288f04627e9f3ed8855daf60e70da2e2e1a17889c24a27befbbd0881eb482fadf11703d94a1678d598c_cppui381,
                                           0x159abda015a758d22cd05f5b020e6fa44aa05fad71bcd54910356b196402db558d2ba98ff13987d3d7e191a4d4be511c_cppui381)),
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x1515a5a45a3e4d523d1ba9ca173f562b7911052f1014eea2e4a656bad2290e04b2f2a8747085819ca6d9f093f79f1a40_cppui381,
                                           0x04cc8a33bb550608a64c67fc6f3a989d723e305af6965e919a6f74db260902dd01679c76c982303031a8e5a6504b8990_cppui381),
                                       fq2_value_type(
                                           0x1347150944ff18f8f1458264fec476300463df235cbbaf849aab64f0e45a42acd7d6be55fee6a7f440e272a096b9c941_cppui381,
                                           0x0fea7ffb7e3fe1e7f1ffdc1a54308ec1800f85bae62e09af72a3b254fa5b0ebd5573add843d476df9649209337ba2342_cppui381),
                                       fq2_value_type(
                                           0x0feec2d5e01b904567d3fd849f75a5fcd88599667a4f6fb9feabc62d8780af6c43867e7f93fc6828d5f91bd150f3c87f_cppui381,
                                           0x0d6f5112ec236a822618f3bb097ac2a6b601656710137494c9b80490fc0af3972f2ffde0e53e8dd90cb28d766ff2373e_cppui381))))),
            std::
                make_pair(
                    std::
                        make_pair(fq12_value_type(
                                      fq6_value_type(fq2_value_type(0x044ceaa25c3328472ccf4f55841bd07a847043f68e72e362347d02aec4aa85753184b79c5b8e2ccac3ea116b40a154e1_cppui381, 0x1276606e95633e39f83c6152a756ca2ccc4d2634155b411d9b1cadfb2b7d0b4d2c3aa33681030d67881f6de6b053b1fb_cppui381), fq2_value_type(0x00446da6836a3103d7ba66e17e743c67c9fee20ad5f0b54f1026c50c4086b5e8a1a1bec8da6c1acb55a7d5663600d07e_cppui381, 0x089a231238147f063179c1407c92e4d30c37082badbdc4641e749505c0cfd44a96a0721231b2729921d45566927c3132_cppui381), fq2_value_type(0x0100de2369ebe5a29708d6daff191c853f65b7b7d8b715d17fc8d05ecd85fadcff900cc6dafe315f354ad4fe86664ed6_cppui381, 0x06f980b2abc16964345c23016efe9a0d5b902d5dd2c6c911d50ba338f41012e35d64667b10a9468a187b879c8b76bc7c_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0296f1c792f68f61e77a7d55572e8b64bd13083d9f8970dd3355e2940787bfa4331c7057ea2c9863357d49679f61bc71_cppui381, 0x11cb86de82463894d5e7ce5536473db8acfc596085cf85c298cbd7bbd3795d9499af8b52ad71086d1893606c13699f91_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0e4eb9715728514a28a9123c96b23483a523fb0956aac97262fe327b6b19adefd2ccc2083434aa0c9b507ec72c691a12_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x09fc27fd3dc1296ecc07614200be0afd77a26f50270f64d534fb4a429a23d05caa818408a329cb25adbdf0a7e6d2b148_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x183f4008b7c9bec94ce4b8c0719bcc1471db5f1073a0b9b607ea808380aeb54655c0bf083edbaf6d0b2c169ef41d0ffe_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0fcbe0415ebf79e45f5dfbe4ccec9771c1067eef60c1e7e4e760c9eb0c9d8a5b9a20ca2a0722ce8f990ee8eebc5204c0_cppui381))),
                                  fq12_value_type(fq6_value_type(fq2_value_type(0x17daf739b73b404894b845d40e1d6831d71e39643ee778996b7a3cc37c607544d04caf29173e790191729753db4e4d54_cppui381, 0x062f708b0341fab4429ce3fab361e95693beac585ba2962531809cd7dca1e894a49e3fb178ac85fc3c48c09d53d26a38_cppui381), fq2_value_type(0x0aa322168abbd4051032ebf60fd3ebed1615bb38df7fffcdadc492be85c543eef88261682193246c7a390f2289fe3e73_cppui381, 0x1889bccb1a2272e6f0687600ec46f62a1f696058d91fe8cdd3bbdb2630e58319e8c1ca96c49434b082c2ce0c1d476f29_cppui381), fq2_value_type(0x08aacac980e86f5a6b23cac5c2aa6d6050e7ad9eb52a9b8aefa1a1aff5adaff1a78938d7e6810f201a398ec2a48cbe2b_cppui381, 0x16a677791e7515b77710b80aef18927dcd826a44dca508f03154095049acab12b1d0cc069e98c6acda31f4dd13d34674_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x066454606a954a3c3b15bd4279adf004c462feb3f2f88eacb175ce1e1e18264f23e77bc1bb1e28a444b2e4cda7833451_cppui381, 0x096b3539fb4f08e948afc398f6b4174a1f92a6614a2089678416083c77e7f618cbd8389de670b22d26183528612f009e_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x013da953bd3edb1bfc80847d7679cd7ff54f56393b2f50dabb3b8f9d997434dabdcec38ac0f7e92a7e8ddc985bdf1d55_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x08c88cd22ae99a9af6fd05c5863995b7aef8858cb0b59920d946d0bcf13673a96a178c57e2a9e556623fc239e5c54e5c_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(0x1768be79c1cf4156cf950401d20cbb507b3586e18e4c168149ce78787eced3fba5b9f8afc07ce439c70b9e77f79df945_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x0ad4a3c6303b74cb15018ef61c0dcc5e7770812df865d37fd7e957ecfada77d4b0165201309a60affd8bc6d77d0e939b_cppui381)))),
                    std::make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x094c04de2a8351e801459f65d8c97d7ea94cf4ad67fcba80082aaf9fb12dca1435717c0e0300f14aa773efbe6e5fffb9_cppui381,
                                    0x1961a7b961ba4a0ef226ea083b6970e09d589dc2026645e1eb18b48a12d528b468633b33fbd34b7953d55a38f6e8a15b_cppui381),
                                fq2_value_type(
                                    0x1811a498a3f949fd9327a3445db7bf19cdcf448feb599e5c5dd23d5f946a5f6178abb231d1a9dc51c30d07e7c45e1896_cppui381,
                                    0x002022d9c084dac31c2040666a5817d17638be6d015096a488f33ce7c4b07fa7192f6b4ca1eb442ef6e9ef6d1e5c4570_cppui381),
                                fq2_value_type(
                                    0x0c79a244305fee7a046cb8bc68ecf3b6c309d686acdf6fe72edb44b3ba341fd46cfd008864a6a44d9a8b69a2801974d2_cppui381,
                                    0x07b65699836d57232a00cc6144058e24f80caea061cbded34e90469935f3e2892855dd58f9dd943c25f93dd6738cb562_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x03a36bcf8132b7714ab14044be8a3e29a25ae79552d38f290a31cbdf57327228459079d25151219b08151bd2a739d066_cppui381,
                                    0x18cad32f0f640ba3a48788aac850f02b4d81c51e1854ab2d5c805f5315f7d745af07c75a76805645e2365e6e5893352f_cppui381),
                                fq2_value_type(
                                    0x07f5730b8a2b909bc7b70d9615c3928e9a6a5f3696116437a6742cbaec4c81fb609971b848b79daf085811734d69a49c_cppui381,
                                    0x0f15c36bf7766413d2801e3726fadf0610e3359a6bccb5aaa6d40ba66b333737071ad044828f10a78feed196e0d9dee4_cppui381),
                                fq2_value_type(
                                    0x0364a2e361136f7b3c57982ef96a443026d8b62243b42bec6600750b75a22baf5cca57fb7c0f855874c8caad7c6714aa_cppui381,
                                    0x08c3ee8d7080d19d87ca49424f644ed620e31e47d5b7867252421740a3f7740c2f3b84b281482c64d75583ba7ae1e512_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x18873237a5ed21cac97d93162f22444c28a795652b1e5bb676cf4f5c4d85cb28f40c9f8486fef24a1ef8ad22eeb96012_cppui381,
                                    0x0ce4080dfcbbe663677838889f6a7e9676f5331c5f5a22b4479d2f6cec9404f9d377cffecf6c2b415bebfbc3bd15a297_cppui381),
                                fq2_value_type(
                                    0x00ae5e1e9a7baf6decc11f0762cad8b03edae65343205f07b3e73f0227417fa184eb5b799a524fc24dc0a881aaa004a9_cppui381,
                                    0x1655cfc8084c9f9a460b52b1c062e08d99a0d99e59df69734591ffb0e4924d283892220f25b86c20982be11b1494afae_cppui381),
                                fq2_value_type(
                                    0x01420dd09785b2bbbda21d0ad66e70260a16a647be0bc0584718855ddbec6f67c8a415981d7d834f699c2c5447babd6e_cppui381,
                                    0x0bfa596b2b5685cdaba67ed3b8a0bfeaa1da01ede2046c9182fc0473dc85c2d1cf5abb79edcaa943d2cebef9b564cbb9_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x1917bfc611ea0be1235d62ada1b6c9b1427304989b68897277689a39c76df1b5735fb00c68e722b06c490710581da6e8_cppui381,
                                    0x0a36e3095915477f5575feed970b99190baa3c25ff4b3c2f822b8fe03772a5290bd9434ae130df91599c54ca107d530d_cppui381),
                                fq2_value_type(
                                    0x1559b7ec780f306c491dc8518da6c94001dd7abcc6e44edc35cb2d9b599cf8420391376850e8ebfe5d468dab410e49a8_cppui381,
                                    0x146024d7ca26e8f5e47cf37a1bf15df96e9467d3cee9cb8b5966b8c27b8ac5449a5b147f17e7298a5b50a9505c087922_cppui381),
                                fq2_value_type(
                                    0x14b6d5a7362981bd18df9a9fce3adac79f156ea0151c17cd679ed8edbd48ecde2120a36a395af322dfa13f2ea7ca28e8_cppui381,
                                    0x09ff254b6d12544f4a45417739de4729c303a8ef56adab5cbe2ad10c5fa13eacab39bec326948caea3e9b7cebc5cb04c_cppui381))))),
        };
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>,
                          r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>>
        gp_comms_c = {
            std::make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x0d12d2bee01ac5b64527ae0dcfa4e9a0d3d9c5c287286fe19f16610eead64ce64578a79f163f36bff3578d4ab22253bc_cppui381,
                                0x123e6bf487e3c0bb6450c3dd5ba9cd86a3170289eaa7c8b2ed6fbf5ac225df9ca696f52660c65906a5f27250a42c5434_cppui381),
                            fq2_value_type(
                                0x07e5c3e380cd818f49d88911d2928a50dfc8f6cde5abedf545d2fa2d9b5d98879fbe2925da1839b3c1c26fd6e98198fc_cppui381,
                                0x15fc476ee64a98b6c2109458d886fbac425524d15e1892b475eacb7594e0b3a9b36571f1cfd193c192e1fb8a559ff600_cppui381),
                            fq2_value_type(
                                0x191bbeef154bcd63eb073954a2fef00c81751d53754d9e036d61aae4e4f6b98309e480d18bf7c0fa5deaa7e7e07602d0_cppui381,
                                0x14a6ecb4ba5a34f8a9356b730caccd695a34386a9a3c1b6ed3a007d4b1eb74eba44e2c1410759a22f207a4ce230d7274_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x094adb5c3f51e229e126ad531cb6be71ef60b085a4b8cb27ae9472876d679388382704e6900fcded60bdd0b00632ac34_cppui381,
                                0x147e992b04b1a5dbf217397069d64bb962f405cdde58de385d29fe059974d6ea30ce75c39a4a356ba79715329396b6c3_cppui381),
                            fq2_value_type(
                                0x1057d1baab28b50da5eea462e3a99f443154188ed2269578fa3b18631a85b0456de41fb8a2f2cc196fee35c057ebe116_cppui381,
                                0x16f1f382fe6e979707fff56f6d29d88ac4773722e14bf135eaeb608389f96c5d60f4b7a4e5ca0079b9d6b6a6fffffc3c_cppui381),
                            fq2_value_type(
                                0x19bda9502645ab7b11b465ab6ea91022506da45398a893950b8facdfe066add136b226050a6f40a24c43c02dfcb7b27c_cppui381,
                                0x14c056d0007ff2b534e0342e2fee914797b939086fc591dd3832f0b8306b65bc4dae72c94093c300b1b37b8ee55eaaec_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x0d1b0fd60aae3c8723a2f24aa5d6564ebde24c4bb4814ab91e8e5811440991a1a3e3cbfc8e6b8d545db53dcf588abfe8_cppui381,
                                0x15581d9e64200ebe120b13e0efba6d9ce0bd52042cc24857854b9e5da2fd9ccea07c2deed350387058fbc2caefa2fd6d_cppui381),
                            fq2_value_type(
                                0x02336eabd86f7f354fd6d03d33def5af788b1e54bc168b21751bf47f3db3a0fa4ce2801e2a72d841cdd66d878c065ae8_cppui381,
                                0x0d7a52a07697df3fb93515af565833f57a0b565a0e117cc805d8f271f9072ce7b2ff14f31b8612bd205f71db44aa263c_cppui381),
                            fq2_value_type(
                                0x0aec958e7d8a3da598a8bac814f3f016b850558559bcab4820a4b05e42bad24ba494f413f5a3ac13660221ea244fa913_cppui381,
                                0x0b5676c895f1d918f1673c3456186fcde03ec2833a312881b8a599131f8f30f09de7dfdbbc20d8430bff3625716adcb0_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x07aaf431c787b4618b5298a4795e3294ffbab710c930df7431dc858e3df1525581bbda2df9e635e8bd4c5f1fb3afa467_cppui381,
                                0x14d9d60673ddbe2ce35969f3e4dd0c34211ad33f2b0cafa0ea696698f410b44cbe8c2db66e6a4031b012f755659588e9_cppui381),
                            fq2_value_type(
                                0x153ff3814e5c5e5890da40746ad9e978cd4bfc14acad0d7b1de0ea0696f5a47771dd201d34d7afd4ca5f0bb373c3fa75_cppui381,
                                0x07eca38d6d755370adf94f735c689055732461970d06e05e340691e5a8fc6ccf0987139a7c4f37b3d3df3dcf10f5ede4_cppui381),
                            fq2_value_type(
                                0x1463ddd2753760074091fc716d05b494e3645cafd369cfc8cf3838cfccf20a62692f25cb6fb03b9ae793219ff2f9515e_cppui381,
                                0x1944ae53f78633abc6e1ba6e72b7a7ec07c98cc5b375ff24bd49265ee8064439eb1c412e01cc11a69e46ca538a03e180_cppui381)))),
                std::
                    make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x010443b653092d8da7f10f5eadea1a1a62e58ab1253d751562eca9caeceafbd9882d2eb59223481cb6c084b98f75b18c_cppui381,
                                    0x0c52f059b37756845296f0cb851e6129b319e39be8416a9347ea04d988c4b01652c35595d426fd3827258152519bb4e9_cppui381),
                                fq2_value_type(
                                    0x0898b8669612d1b8254f184a5daa62effc7634f073a49fa1b9787baa476786185fa267a86211e2a47c17f5503e6a9914_cppui381,
                                    0x01280310c7d084ffe6edd14fad7d18e2f12b324afa98f5253e8a4ba766d5355beec807217bf2f5348b3f52bbf404295d_cppui381),
                                fq2_value_type(
                                    0x16d2113cd7a2b5bb2f0b42e1118d93b709a8d67d702fce8f2fcf2e7a91e03a211910813c81d3526b76d32bbcbbc1c04e_cppui381,
                                    0x07a5ae033337f3b92f737756d9d8442ee00272909b3a0efa5f3f20c58b5dd01d7fa9004a9cbcf639cf91a1c14faa0ff0_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x0c5127e214318ca34230681597bb0f09cfd78953a315051523b1e3f858db252dd71ce1fc62361aa9243b6efcb4bd3bb0_cppui381,
                                    0x04e01eb8ec903ee97e7cbdcce3480718626428de324bd64c9c71403e0a5d556dc42fa41bebee25d82ce30662ef682074_cppui381),
                                fq2_value_type(
                                    0x0ad786c2835ef95e9bf5337db3b6f8fdd617a00595c08ca16bf17777e967072de6385a237a011224abde5f259ec93a73_cppui381,
                                    0x18846df8cc0001fd6ccdda949e1d30c750221242a2c27da0b3688b17b67a848a41b36e5c4a6bf6598766d65493a62a09_cppui381),
                                fq2_value_type(
                                    0x078210cd7496ab064b33c7e075c05ae43e3dca6811d99fb6d41dbc0b4f46a82911bef71cc38710d258e20ce7c28154cc_cppui381,
                                    0x15841113b718398c942f90667af358b2f1f7aec321fffaf4fcefca9cd7a4961e468336badce9162771f5dc10d74f61b6_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x16a7e8d2945755151d30d3cf2a0d9048ac59502cc5537169e9ce1c392849136f9721555093bc02bee4aa7426391e3457_cppui381,
                                    0x119038f8b34afef6fcbeff5a49ccad1ec36da65e68a887cb8c5f33cf4f7a02b9359b809df0982463838a6b43824fdc69_cppui381),
                                fq2_value_type(
                                    0x149958a008cbf7d7e5cd21d4abdfee62092ec2588714ddcad5a6bafff5cead7f7951e80a40b92c1466e7d1d0a04081cc_cppui381,
                                    0x02458eb21383dd0ba8082b01900d475e0a5191cf3fe57f63c05261e3ae4013ae2570900386a77ea49626c28495d852ff_cppui381),
                                fq2_value_type(
                                    0x0f5c667134b343cd05ab78ea2b49a1264b9bb377e8a0de206c9e932fb0715229914f1d81eb6609929f32cb61475eb984_cppui381,
                                    0x10a1cb5524e8c73856f8081431323a6e1cdb8809fe753a78b2be2b7a122eac0d90027f21929f0b3de6aabf81fb8319af_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x04c6bdd2c4bef0faa1a536f2db9e1de1b63b87d7d41b67728583e190d67f140596316539a4719d99dfd7e4c58b0e15d7_cppui381,
                                    0x0c2da023fd63cc4a46f6c1eed2210d40f67f2f3d70143d165e8c62b95b573c57858e2b8fd4b255743463c4e89dc24b71_cppui381),
                                fq2_value_type(
                                    0x0ecf23fbb64f43e54c0d150ed81e192539ffa05be9eba1b317f244f9c3458403db1bb32f5bb64dce3787ed243c227e87_cppui381,
                                    0x0d2a11cd13487f988b76b27594215d75359b388a47b2b37bc25bb2b78188318d69e9ba98ddb9616baf89e548981e3ea8_cppui381),
                                fq2_value_type(
                                    0x0b093b91a7d1046c5b69d673fbbb16c5f6ff8ac3ef420b9b3f89ed40ed97208ac7949ea3ccb31f568bebf01507fe8f95_cppui381,
                                    0x189a2fbeca18a7c39881330e522ddcd1b25eea965ed5a4ab73d720dbfdad1ed2463560d4296b1ecf58bd05c212d6886b_cppui381))))),
            std::make_pair(std::make_pair(fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x09f4b8949ce57f93b628ce81fc12c3abc3c2471fd953367e5586eb183d7ab776bbaea41de7dd1a705867c06bca6e0485_cppui381, 0x0e5008627a9fb643c244f303bedf1926edfb5a77afe8a33b3f33d4b4971155d2b59d0507c2752e723df9b75173b5aad9_cppui381), fq2_value_type(0x0425b538e9e7da61271a7d06fb865e69d86ce8691bdae04f9789d0b22fc4298b2cde8f0241b5b9c0d635ac6ed9833f77_cppui381, 0x163c56c38978149ab1960c0502036823daff6c622bba5fd894698a7e09f236e89c60669cad46787a5c470aaab397bc7b_cppui381), fq2_value_type(0x091dbaa99b3622707a82dd8b19a8878985021cb73f70f7d2e96b8625bb10d6a27d20cfcb355c28ab633b34bdf5f02fa2_cppui381, 0x02cd8ddf7eb45a94cafebf401fd6076c64bf7e51ef613ca37e5d3be9acb8fc7bb1c68bd9a59d3c044094b93e1212b587_cppui381)), fq6_value_type(fq2_value_type(0x139a2955225fc994912ef75532214c23f95fc00f432e8ec62d5475bbd24a814cdb94edb5a5913aad8d9792c8d9672d8b_cppui381, 0x1760cd2b408d98dac5d4e6b8e56f2ed20b7abab437e1da3fcfc59f9a681c74e90f0e29b7bff6918dcf4bdbd80e3f8cda_cppui381), fq2_value_type(0x0b0210f4c02bc1ab42749a00a38fb19203a813e0a4b407c31255451095d37b1a73c4fe5cc57323842baa4a14d6068feb_cppui381, 0x01ab8cd4f72a52baaf1757fe3770c5e092d7cac3be7ef14c0d4496b20af3d8d5e4129f6742e0726b4bec0cd2a159219b_cppui381), fq2_value_type(0x060ae34a91c22fd4dda9790717ff0ca146b36444a40a83a9189c6154cd7c747e1cbac015f4ec749612a58fabf2e42653_cppui381, 0x0f21b747b6d0079c234bdf0dbe0b070d066e0ee48d26201dc9d8c7d6c8e6e65cd9fd5b42535c68c1020a438fbc92e8a5_cppui381))),
                                          fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x0383401d70ee979a2a95632f31a9dfa9968fe643d104bd8327b3eb7c2ff1f23bd799844e0f3b682d46fda2e556b68c3c_cppui381, 0x1686a68fc0a6b62d8d3d028a34ac27b99d9c81284e2e13a4bf4b333b376f6f7aa81222fe750f4a1281dccfa66b683cbb_cppui381), fq2_value_type(0x137ef24e6aaec4eddbad15c747acfb508dca590d94cb4847e55299623097d7cdbfbad1c00b8d7a9ed666b1ac9c6bb4c1_cppui381, 0x0fe3d75592f1e7237f427625b31dfdb718b78edd4134e697fd7518098d452d4569bc1bd0d9f82b9b141e3f795dd7d9e5_cppui381), fq2_value_type(0x0c205f7dd1121060d639e904dadba233b1445d240dc494376246d3a1acdafc26fde1ac82470659acbb472daa623a8d98_cppui381, 0x0dad634f60df35dfdbef583d94d1d0b5efd896910d06616330777264aa62a082ed11f7137564c8a81cf2b1fa071eef49_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x1349b2abcb8159568adda2c3067b897beee0a42933feecb6471b7eff2465ee1456c6b0f60468b299ed488d65f7df9388_cppui381, 0x0f13684422bbf6714450c96ffa9dacf0cb81b53066a288b3e17336f5d1b92e4985d08608a3aa169c5317b4b5f7d278ed_cppui381),
                                                  fq2_value_type(0x0caca4623725d01ab43b2c8d835f63d76a42fe52117c75c03389fdc05cb9360c980721766083aadde649363b46d14d7a_cppui381,
                                                                 0x019e9514413714d262095d572fea608bfb3bc1a9a6f4e333b12db962d29e43c36e442ca6d3f78bb5b82b0026f0d3a983_cppui381),
                                                  fq2_value_type(0x03a4e6b13ccc8000a1957432dfa578d3d529736c584b7fe2d7b46b264cebd7a954b20f3b4543dfd36ffcaee615e020c0_cppui381,
                                                                 0x023f270f89f962c820598d5b56af95e8d08eea18db00bc78cd2cbc0b8af13f7089695d1668784784f6e3e37cac157f5f_cppui381)))),
                           std::make_pair(
                               fq12_value_type(fq6_value_type(fq2_value_type(0x14d69f03fe7c909b61e59c538f8666a523f74a1172327b878f6666562c65c15b75481b8fc940f5600e67ec1fd2291c97_cppui381, 0x122b4f54741d74747a01aa5b552a50f1952c27086255d21c6998e9b340239e9a9b344b6f4169ab75dc08764777e1c9f6_cppui381), fq2_value_type(0x00f90b248d044f5a01125bc54bbcb581e091a288be9de2619fc2a17587affba4551199aa2943d51d42127b174fa8d3eb_cppui381, 0x0bc93b870e4ff73dce9a0b1b2f68a58244c96b44897c79f0bd37aa28c80444d063b2f6c893ce47052028bdd92c18d9d4_cppui381),
                                                              fq2_value_type(
                                                                  0x1508fbea2648360d82b97e76559869ab8040e07d9615cb29ac1bd6dddf3525ce53e4c2934ba2fba7007087e6e6374097_cppui381, 0x09554b997e20579469e8bc8f88674799cfb12ce7fa5b3fb5d61adde714b09eb6ab139c666eb3876b1cd05adca05c5d4f_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x14dd3fcf582aa58cd78cc7dd140024910bb9b5c8f58265dcaf7f3a9cfa2d5086625cd5a281fd7d856d0bb1e48a39dc70_cppui381, 0x0c2815eb4559780068238042ba2e4dc9bafb2253e791a7bb5cbb744a796d84713386d5cfc59989e1e42757a9f6f06b5d_cppui381),
                                                   fq2_value_type(
                                                       0x0eeea36ae288e6ff0581b6c419a9ee26beccef7fef44f24aa6c0ca318c1d6d5d9b59489aa90db2415e9b1532573ec01c_cppui381,
                                                       0x06d12827f353094726edc27b1c9b69844701c6c5fa221bd022db466988befeefaad4d2a9a50bd73608a960680c31511b_cppui381),
                                                   fq2_value_type(
                                                       0x1961dd4e1c3cc85d267c7e5996b4cfe64cd698f51c1a156db853433f5741434b523e86e5d08616bba5b4f8832a29de36_cppui381,
                                                       0x036528afbcef565a56fe049cb83a783cc2bbe0d8c39634389ef28155d087ba47cf7e19ffc7a0c595d6876457f412016e_cppui381))),
                               fq12_value_type(
                                   fq6_value_type(
                                       fq2_value_type(0x157252235dec81da0a495d148f207ff49a0d27869aa533a94c3c4c3924648f3c03683997e84c4aa9ad7ae5b4b6158af6_cppui381, 0x03ce7c00ae439c351151aa9bac43d75f1a1d67983c373b2ea9d35a2966f1575fc4f59570aa246a004d331d5309c0e94b_cppui381),
                                       fq2_value_type(
                                           0x001d7a51f935f79c80e7bf5f0973a551616338096b73c299bb59800c3c961a10937b3603f41d20475c76326891046563_cppui381,
                                           0x07651f45d6cf69e70af4b9229a6f74d8d8a99411ca1d633b1ee25f64ed9484501f96de0811226d0541969bbcb5ecea00_cppui381),
                                       fq2_value_type(
                                           0x07073970fcb4e3e69fc0a3f544edcdef6e8418fce8cc592bbb3cc2486e981b0469c76db6134efbb5c9fb5d09087ef380_cppui381,
                                           0x0a23acfa75ee73cc07069328e5d09ee02783cfc2c48e55f47daa381469ff3f248235a59519e0693c0c2e7cd9f784ddf6_cppui381)),
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x05e4ddbbdba3414f159c51bb7d88e8deda28ccbb4ea22b76a2b5ea6087b8b89d8af358eff0eee79fcb9b3972d51f9cf0_cppui381,
                                           0x0ea9ef9f652a39a99afa597c211fd8563f99915ad478b779c928fbfa48778f099038d3ff47a6cb307ac1e41dc32b03d0_cppui381),
                                       fq2_value_type(
                                           0x136eb14946ac90bb0e9fa8855d147ea74e089f09308b69e14325ac90e7683df9f308b5cd3c2556d9dc2734ee9d308c28_cppui381,
                                           0x065c08c4eb0e3c2de50a7371fa2d4b86355ac7c5830373db4d90ff1f6053d2527d4884793c689fdd3433d71446cfea31_cppui381),
                                       fq2_value_type(
                                           0x06b3481e7e4904ef6c4904f3271c536c955c084b49638d01e1786c0facd490c49ef13801b881ea1dfeb46980d91694e8_cppui381,
                                           0x0f1d3d1895d6d301a373fbf667eac97fbfbb32a472c98e7ac3b20847486063c15a9dcba16af862eb61d714787a691c7e_cppui381))))),
            std::
                make_pair(
                    std::
                        make_pair(fq12_value_type(
                                      fq6_value_type(fq2_value_type(0x006d5f306b474770dadb37ef96ddc9a11e49fce55c4e2836bb5c24aeb9f7a9755af8097aca4190809e579989302bc26a_cppui381, 0x18268851d5de23f03f4cae626a3332dd129f56ed8dcb06b34ec9dd65eb28eaf4fa622d53fc1655261cdf73da3d5c5148_cppui381), fq2_value_type(0x04dc2ee4ba0f5c554ce712ff9625f10a3976ca9cf4e406641aca2cfed24a7f43ba3716c0719f0c96647e19d8dbc348ed_cppui381, 0x123c833851a5267031eb586285d5123cc1a6a259cbb442f4dee46abead3652d8c8e0bc7b02a72aefde0bb11b58e359f9_cppui381), fq2_value_type(0x13de3ddedf20e649a2a8009f73d7c7cd9c2dd409c02e26d11b3ef4d4fdf5e6916047b48c494c55b269b007985969c7f6_cppui381, 0x1504de6c8bde7a743f4670ac18705a2d2f92db0474100b0b8d83cba5ad1231a93b8e7cf53e0725973440ac880a01d47c_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0cec7183c040e13938c9af3efe56b1d52249b40dae5abdbf6839c4ab603a85d2c567344f7dbe80f67c142eeed4f02acf_cppui381, 0x184cae7426d67b6f6690bee00a9c7d86b28fa87d96af297a4fb1522d85d91273ad71ce6fc63be593661a3add416004d8_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x043975fd00b8155725802f6fe66c26da30974ad50bf1302de5fa42a2c695962d26ae9451ffc10cb1bb1073b08c3a46b1_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x189d53fcafd148650524590749b7e92d083f8d0dc6acc8fe10dc76e2d65758125f31674a8d5fe05f1b9e453a1da5739b_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x012b3de04edbec5ade5ac3a2bb974f6a6c9fdb8a895419b0a0a9b153359c011fa68b92510ec4096d1ec96537e17befe5_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x109b067c2e2672d1353ca20b743bc97c81af2f64b0e36daa6bbe3e4a7a4083867b0b74462dc5836fb901a13ad4a1d59d_cppui381))),
                                  fq12_value_type(fq6_value_type(fq2_value_type(0x177fa509fbb38841dde81a3bfa63b725f107071f31571a7e1f73eeece14b20bdd81577cfa0e20e3c4b3f08175fbaf176_cppui381, 0x13fee217f19c8c5c03a20a7fc1fcb0eb921a499bac996ca810f550b8d72c24a09a8eaac19a13cac926b3ed3bd789dcb2_cppui381), fq2_value_type(0x18ed93310813c7f1a549af1b32afbf924dbbfb9f3d66f75643773b77597d51d5f5c0c045e46459d4aad67702b67f996c_cppui381, 0x026dc9f38d03a4a68bf07c0fd435b6e72afc3092c1dbd23b993d3445517bb6fc0ed74ecb99eea0819895bc930d119392_cppui381), fq2_value_type(0x0537cbc113176f2ac31f2b1936a32bb4e6fbcab949411c77e8267779887f3ff68a795f8cf462a8fe536ce3696d58b456_cppui381, 0x04b718f42c75251da847fa8a60d864b68fa03217dcaf7308b8f25d2c79f937bf2b06f5f9f344da079fb040667b8f691a_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x014b36005a296169b31e1d291c3ef4c009993dee6927691030ace7436a199c42788a271b83493b6d0f8f158ebb72bdfe_cppui381, 0x0a43042562b84d60a88b3a49f03f309a612cc1a5ffbc0f38f49bf13a23318385c2dff00f2018f9f8e4bea628dc4036d2_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x04a82ca72b3b8cc74b13b62d0f815263ee0dceed090a73082e915a936846fd20977a0d82c663196cd773b09c4bff0ded_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x0b2d0c0effd3b2db83760262cf1f29fc791ca63d95dba662ee7e0483e9d48c87e708956967a56eba5ab4c039fb67549e_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(0x178b986381961ff531531e485dd0ebe428cb7c2a599931fe830160406ccc1aeb9adc6eb884d24ca65f9961bf0264cc07_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x12602873608ff64ffd37f9f473b8b1bad8d0d790d5a44ecd4a0fa9540d85eb4e06d8e84d178684d1ef02dd86a43ab52d_cppui381)))),
                    std::make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x0c60a39239083d40eb8710c7caae10e02952734193e51c362047879eb4d68f9f3263a4c395aabe0c36fd44fa25e7de9a_cppui381,
                                    0x03a72839cb6a39f46fa763ca017e66349cf906dd68a6c6608aad5c396b35f7d03edc569b18a479b4b367f994dd408019_cppui381),
                                fq2_value_type(
                                    0x0ab34d95c400220c5a3da96b5b3551ae94531c64ca722b5d16c515e50ea81a7206c0270a6eabd59f3ea8a03ad59cb2f9_cppui381,
                                    0x17c304d7d58c002f71e199a1d18325173901367409a6fac772b5ab2fbb40f0bbc319ef87eb3c2cf44cd6a0e62b957519_cppui381),
                                fq2_value_type(
                                    0x184baa9478d6b2b71a0ff476424d30b55f2d02f38ef629983238344e00baec9dc9da0050745cc9525cf597c09b2fbd11_cppui381,
                                    0x010d046de543904f28c47897775e3ce7fed7622c42b1102dfcd0d11b2b9015576d8a2c5fc88b412f4e03b4bdaceb30ab_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x01f2e88adcede8f70d40931a94f310d9cfa39e90d9ea9fef81e582bc267c7bf14c4a0bd12fe6433f1758e3391af84987_cppui381,
                                    0x0f5e62907df26c42deb8fdda6d2a6840354700853015ac6b5888c16f1289c84ed477626831e9c3c3337ac0f035901784_cppui381),
                                fq2_value_type(
                                    0x0e24b4e3d6ad5d0067c7bffa7d1f883c790cabfb4e3c348dafd734fd3d42b765548080d132d75eeb910d13846d71c8dc_cppui381,
                                    0x176cce68c59a86c1ed636f85f5fcef7f9130ea6d868b2e68d3c75279780568c6a575691099af9b8d7d98d1d0e4dea06a_cppui381),
                                fq2_value_type(
                                    0x18afe2d336a530d9b91f2772ce7779fb0d6c13866ae613f68388ea0853b2b5a04db75cbbb93f9e6219e0bfb28c38d2e2_cppui381,
                                    0x0be7364ef7fe506ed4459abcec9a556e6457e2c82af2661b6d7257da54edda27590029f75a79b5070bb572e2c9ba3d15_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x17dc19aad3a8b97738ae33ca717e506f6db25c841293be08366b6075bd13d6e020a28ccae6513fd6188632e3e3c15bb4_cppui381,
                                    0x14212a3b4eea84e3c46f709ccc2804bd41f15ad488e732a34121377fa57e946ee003d6b8208116128cbfe2ea98449ef9_cppui381),
                                fq2_value_type(
                                    0x152c680d7aab95f1514aad3265b56972ce9d266276b043f60fbaf21bfa7a43cc038a223f74587532f0854e39d5ba5e37_cppui381,
                                    0x1914f8d4e3cfcea1cc2af3a094ac413b12f5d914be984a3124560b8b3480b723eacbbf8f57c12330334c7ff3fe7a62e3_cppui381),
                                fq2_value_type(
                                    0x12280f133c2028a54637a43b105709a789f3c0275ec4e25632a53875ab54ae606ee91e3e0a2769c78744562dfd04039c_cppui381,
                                    0x170cd2b13e9a1196451bb19123be414201e93bfa6e4d0969b39324b49d518fe697886cdeaef496d44401f0fa71860aa8_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x151fb7645023873602d56cbfc401c7e1a61a841eca5f180da91e2f706fa57a05fe9b6c9680c834f41c40c32eb2934290_cppui381,
                                    0x0035aedceb5709b64356db3f4c0efdd1edecb042d88256e486423db4172178a8741e0e7b94959ffcf9cfe2c5f9dc1033_cppui381),
                                fq2_value_type(
                                    0x0c5e65c587ed7a6130841eda1311f47273a89056a48801cdcd9d836daf8673529ed486243f7a3869aab5fc5c1755dedd_cppui381,
                                    0x158c2ac494b4494b6c3202751f4195d4a054929c6e83e3eee4007b14bc497511e14818700590aac7a426799c7e324e9f_cppui381),
                                fq2_value_type(
                                    0x16ceaffbfde93f9176478100cf118613fbb63932dcf68461ee8ba252166c912c80284a7f2c5caa8231d7e4a47cd0caae_cppui381,
                                    0x0b567d218679433ded34f7178952755e312befee0e0407b396873c1e4fff320f12ad9886ed9f2d8d369e868b61d58cc4_cppui381))))),
        };
    std::vector<std::pair<fq12_value_type, fq12_value_type>> gp_z_ab = {
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x08f9073c0775a009e4e4ef14741e99852294d17d775a1a8af061eb6d3a4cdfde8983a417105adf0160431fa096046219_cppui381,
                        0x019afd97da798d3c11c5dbba307bf31d589f267d9cab1eba321128dbf4a2c6336b3bd5efa5e523c555635b07ebfc9a43_cppui381),
                    fq2_value_type(
                        0x0dd372d1f9d389a429f17f6c69c9d66a9ebabdc893e4d59e5d8566e528eb667c75b4f8bffc5469a996d067a76eac867e_cppui381,
                        0x134a7722149f4e80a3d66582ee977f70bcf1870ac3575d8a550decf04c0ebb49a25cc9c79ef5f1a9640941d79cc179b9_cppui381),
                    fq2_value_type(
                        0x111a3d19c23548f8af8891cdf2c993ee7755dedc9b91ea38b7792943911ce699c3941f3d2bbae5bdaa57649251ce5525_cppui381,
                        0x0a6a61281a8fa7c44af33e1b4ee0141baeae41b9440e51405f06b899d06c4ada5adaaa10d7e09276b001669696c09d15_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x02ee5660cfe9ce0ab768c07b5076891d18958fe020fa2da0467e8572aa73ad7fb49b191f4f88b56ccd209441682b71ad_cppui381,
                        0x0ba6c3f8f57c304983cff355f2d151cf1ae83a3a691c8af2e690f8cdfcb4c7c32adc2e73f6afed33e12fb74052ee9b6a_cppui381),
                    fq2_value_type(
                        0x10068f0bcc586f7ee257e844a082a664e46d7d33bc0cf756077cd71770b23c48ff63e588a21927ee06e9691e8ed25e60_cppui381,
                        0x12dee0b4dfecac74513d47203a88cf3559c0f668762e1ef79242e61ebce5d6d7485959f73291d61a69b32a092c00ead1_cppui381),
                    fq2_value_type(
                        0x0f797059da69a2aac6d611f8c26fcce0bf4d0c7672690e05c7aea73cf0d36f79b2f4a9e3cdb45015ece5e50770fb57ca_cppui381,
                        0x14a179d096a7383b049d86dae4670aa242ad0e7decdabc6f0feda3395779feb60ba53bb2f274ab7596424e2c6119b38d_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x0f4010a6ceb4ecd70a2f47d2d90c32604819b6890282f75d0a964aaf6a1fec3d60ab26e61667e49b4a37146f45fa9c68_cppui381,
                        0x186bd13811295ce750c5cea7c81e9f3e53571e703873ed57ce23fb6fc7c826d451668197ab05360dd722563f75e721df_cppui381),
                    fq2_value_type(
                        0x01ca0a12c9a1e09bf9bd00a50d3c6f14ef9a121a8adedc4a374661f1c2aaa87d26b4b2258dca0a208e244991196a10d7_cppui381,
                        0x052923b27e2fe2031f78e1381001f6111fc8a05fb5ec0f6d114bd06a3ded82f09d76208cf37175fc83d9e39aff9df23f_cppui381),
                    fq2_value_type(
                        0x05b109b5492879cfb3aba57a7221674daa1c84f3ca063d770ffb26150fd1f3f24ddfe21f342edcf2adffd232bdc68792_cppui381,
                        0x0ceccc3815fbfc283af8836f7da64969ea19975b6f68206dc7a9b9ec2af9a74473157eba4acf37fb36e9d099664b0960_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x0dd93d143ba91d56e03b08df97df9d8196ea6dcc9cd52dc33ab284fb1474d58329a103b16b5b35751b8d8dcc85a54639_cppui381,
                        0x021727257d3e11fd1a97ef0eadccecfa4a25e099ca7272058000c623c3cb70bf20ac0feb5c7d97ddfc5b9fa9a6e58016_cppui381),
                    fq2_value_type(
                        0x181abb082290d93f362b7872a4066ac3f76fe39e07373094089815f6ec2f15abe9e98da274f8196eab5c4bf16f210c55_cppui381,
                        0x090a968b4b81d4d0605d75177d2105b1f79949700abdbc8517ed0ec3fe934428344723b4077fd960494985c5d1463790_cppui381),
                    fq2_value_type(
                        0x15937bac482d13c9f53c025f11e5190b0f13dd3014b33fac42dc40f4b1cdb56f6e84a74674b8d7f1703808c5dd9cb5db_cppui381,
                        0x0e71da28c8ad7055776d3e89bb08260869108574e55c61eb537e82a79986339dd6d466444611278b616b9af6ccc4983a_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x1575569d8aa93c4539b3d555c72a59d812f2cc4f8ac77f4636b70602391fbe653ee313c65c3a3a97ef30176797090f2e_cppui381,
                        0x030e6818975890540ea2cf48b5ab288a075529ce7e967a7a6eadbf2511db763aeff57e76624d869543cd971b9cd15a5f_cppui381),
                    fq2_value_type(
                        0x13a9f2ef96517d6e5320027f8e57a344d4ca8dc94031303cea0ce02f780edf5a565633f54139e57535d88aee255b155e_cppui381,
                        0x171a5b83960fb121be36b9ea9fa82799e7cb0ab2986052353d67d28fe3baa4754632a38f85602cb173dd7ad048df76cc_cppui381),
                    fq2_value_type(
                        0x12f635d40fa64fb3c6b9fca1ff753136b1c0e09908b98f7fd1100ff235854494fbc62aea76dffc1dd4d869d51f2a88a5_cppui381,
                        0x17b00950f0a259e027b6828e7f59d96376f2d9642496f58040779adcd29fa1bf37a87427153c136dc704a005c270c442_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x0bb33b8a527a332f8ccbb5ee7a6dbaf17ed8ec6e5f0d5c3e84c1d994a0a6facf3a20e9493f05fdb08d6651c25fc8de4c_cppui381,
                        0x083f3e32f2a48c016a29e09a896e357f32fcd16db631c3005626c255d2d5bb0eeda54529510f8d4e94d9b2687630cdf7_cppui381),
                    fq2_value_type(
                        0x093edad037781b9bb503f44ae4a2c12e874fadfa69e09feb03ae3325ea911ef58d1a51c1c771235db662b262e838ffab_cppui381,
                        0x036ef42721079c143eddda66ffd5ff90a56c52d88a32d4f92d0361cba6d08262936bbed88a7229f9c1f6fd3d4b05bfde_cppui381),
                    fq2_value_type(
                        0x154bb3ba3010bc9adf83ee93d1d894c2da3bf2288f107c535452f719d83a803d14799d675841541b292639cd39056129_cppui381,
                        0x094063d1fa4295928329b835e198dcbd7c895275174dd7a6e250eeb6a10109f161faeaf224084145b59dcc12abf2ecf4_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x17c730e3ddd4e091ee9c803e69850cd058a5c0efb422fd3805c080fe7d42037826fcd9eda6f19ee25710e0a7699d6818_cppui381,
                        0x0114f715b4bcdf98a72e58edcc669339c4daf644f89629adcdae25377469d9f1931ba469f334f470e6814dcc75c13f8e_cppui381),
                    fq2_value_type(
                        0x082e7a8e8c72a5123f8f2793666171593f75e19b8be16146ffca9ef10e6bd9d9f926e0a317e0475f8767551c699055ce_cppui381,
                        0x1682ffd0b557a67c9cb50a667b7b44cec5e1050fb162fffb66f28b73e075d1f2e21e7bc635064cafb555c9b193cd90b4_cppui381),
                    fq2_value_type(
                        0x058fc782de29595ee450b8d9b7ed55e5c9c3ad1ff5958563492ea7237ad1c2148d8b0f4ac961bfbb58afc5b0ae554717_cppui381,
                        0x10983c3b4484083e92e1f63be4158937249d77b22cbba541103f8897e947646d598948771268bb1ac812b3c42a5256f1_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x0de5da5ec03c3de2995c5897972ecbf68902e8b5531b1aaa7cda6026c597fadcf781917af77f5570015448b2bedb0c3c_cppui381,
                        0x14a5181e6c51146873e388f144e3663c9172ac92ffb960bd59a5d441f23dfb98adec2908da4e19a48025fcfc099ce6e1_cppui381),
                    fq2_value_type(
                        0x0e8865d56c3f291bf77807f1e26987e0bdcdf1ad4280e0e1ba394b996ca14dfe1e5b81ae5f5596b526ebe5ffd1d9def2_cppui381,
                        0x0260065b9b022bae050c5971e9c27dc70574a3be01ae32b12430f2431ecf966ce8a485185833e12b328dd799a091ad8a_cppui381),
                    fq2_value_type(
                        0x00488b4e169f7bb6e47020106fe71491417a1c5bf7202920dfd7f48f6dd965ee1e54481535e32ae5a69dd9615f3e3223_cppui381,
                        0x02d2cac9461d150153d9e8b6c863c4cb11eab1259d207d167b4d9f38010b45722b950f054533c366136166e0509f7633_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x123c02bfeedc4f8ea0992056df6b6f4fda5a2ad1656561d7fe3edafa5a3fa8b7604f617587b8d2c3537d8e037061c2a4_cppui381,
                        0x0fd284dd926d7873d120232087c39b41203627a6aa7afc527e0dbe688315b2f8cc17c4928a08a5ab989198bc51ecefd5_cppui381),
                    fq2_value_type(
                        0x1399215028214fd250f3639f9a2be87e4ef4d6a79f4cb81e0363644027119b4a2516bfa0a5012d276a05749b80144c06_cppui381,
                        0x09af4ed233b37c01cf8dcd5f48030c34e09a7329c2f8b204435daf5975d8e6b99deb71046d6fc71bb8511a97db0dae8e_cppui381),
                    fq2_value_type(
                        0x0d4bb65d7396c2add4a2535e4df821f03f370911efe713e50bb9de2445eb226438677a3e2b7940add0f4374f64473d99_cppui381,
                        0x1859e2e35e469f60a3cb901cdee3f105f6a7917fa252ebfcb98bc0c518a9170ba9e6bc6c54f0bc317f5eadfa2ad8531d_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x179269ee91717b72c93d411b169457cb2c25648b2f761ffd9c52d66874942eb8d67926cfd128e9e865f6e59d63d86235_cppui381,
                        0x12c599b9a30e3b5430a58fba79994b80a5e2094c393bcc6a31f6fd5f2303ce8fe873b98d7c23d5f478464eb51dbb4aff_cppui381),
                    fq2_value_type(
                        0x184a9233829a5652225673d043b612d75a7fb49e0b69cb9d44ffb35c12a1c66c70238e75128aac8f7209f4d4192e1bc3_cppui381,
                        0x11f98b10c61957a655eefb9a28d898f321e0483222b04b1242b3d9369eb783d2713cfb9431eea71e55669afabb8bb78a_cppui381),
                    fq2_value_type(
                        0x18db7aa336ee287227d0bb84c11018079c3ecd05e2e9e7d991fa419d874b4bca347a20cdbd74faa4bcec39892d4d32c9_cppui381,
                        0x10a62a1d7fbd0cae7dea00b02b82f1167637f68d02123153418f9c52693fcf5c59bd88fade8bd2a1a09017a3bfed88df_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x0698718e1e0ef63b893800d0d82e26a7f2f2714f80a54e1341f7f790ab91a80d37a04338fc2f8298068c28e77ff67c83_cppui381,
                        0x076d476a55b32dde259f0b654a33ecd52828b948abf72ec0d7889e39e8a06888ae598e10fc4399093f008a2858da339e_cppui381),
                    fq2_value_type(
                        0x119feceda0d283ded93911564149778d7f7b7cd28b86a6293fa784f04a67ba2d3b3efb14a4f7b840338adda0e40c0783_cppui381,
                        0x154f9decba8a3f68fcd339c72da233f71fa089c1ca31b87daae8fde856ea029125fcbf579277308e24382381a947c105_cppui381),
                    fq2_value_type(
                        0x09b83d533c30fd2d1b30feff20add25ab7834dee055db7d9f15123d0c19367f0f0916b217aa12d5572d49022f605e3e3_cppui381,
                        0x06058ffda7dfdbcca1fd15825131a7b533a0ee25e2b08dac4049d59076f520464f11e481bc225b7720aa60792cbe442d_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x187a1cc2c0ec0ac7097d25a48444431f2ce6b7aacdc77945659029a54633f9e9d3da31ecebf9b920a2c0791c3192061c_cppui381,
                        0x0d3cef4b7ea8b25fd960b47b2a855931067741dbeebb702584c0c2f15ee2e7c042bff57222b2fcee4632420724f0f568_cppui381),
                    fq2_value_type(
                        0x12f72eac80b1d15b8421b8d2157690247792381401ad90c753982baade5a62fda91f0d1794deeca3e4f8c337317306e0_cppui381,
                        0x1429844bc38ce46cf8c3382ba253fcadc7322b8f61a1ee1a42ab1fee49fba6a122a858c1439115016f48da1f9118947c_cppui381),
                    fq2_value_type(
                        0x04392327de52f85a0913a26502d9a7744f01aee8f321ac61063008cb3c1d8b43b8cc0776d3bae66eaa0e38f0433cab99_cppui381,
                        0x04497542b82ca27b26226e9406a108f962674f86665211f8e764c13d730e5e0ef1d0a969383039b64e9342d61e4ba80d_cppui381)))),
    };
    std::vector<std::pair<G1_value_type, G1_value_type>> gp_z_c = {
        std::make_pair(
            G1_value_type(
                0x16fb57594b1c4280a3ae03f69cc7b8489af6771379c9b5e260a63e8c19f7ff8be3c254932fe0aad28f816ba7052e4967_cppui381,
                0x05e90d0b869a06653ccc8834afd2233bfb2d9c09a75e7e2dd39ffc090a226462b79d108440474902b921fdc56840845b_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x16a09499cb5dc71cb167dcba20ebdd0ecbf861037c095b8199a1216962bf295c9262fc9936042f1161c344d04e1dad8b_cppui381,
                0x0b705a88efe7cbed33e7c1979d6ace7a28c19860fab650267f935a5ff09b56bfb15c1973dc71b80e62009dd516dc6674_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x044be96c66a6a39b0c849d8958565dc1aac145158141ed92baafd18e150597f9af674bb8d04710ac3749884bc918df6b_cppui381,
                0x093cda4320c79039ae2dc14c8943b0b81f4a041a008e2a637b647ca892f3a953cbc8f82813ecfbb35578a4f8ea122a63_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x10dd1a464c0e531d3525df1f53693d03d3d688e0e3ecc0913e8bb5bdb093ab2c9a366f02e50679036a2c73034db021da_cppui381,
                0x19db45be54bae534b874b4a1b2fb0897f43d89554ecc43072a94405e6ac3b69fbef222843236a9a106f9488be7e9a2fb_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x0be458417c6fc8409fa231013345b4a3dc5e8151c28c9aff0403486ce026a22f05384c4848066ea1181830de6542a559_cppui381,
                0x042c0bc4428de68ef5a0f75f90fa167dbe38082b15cd30c10491c60e474190c33cfa118a683c53731ff70fe2af2d434c_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x15b1f2d6cd147fe30d3c9d2c6cd95210c00ab9462ad7fc1dd9fbf54313716670ed9c5de28b8dd993cd91c29235c7a144_cppui381,
                0x0a2e3ae1709822d12bcd35862a83f783e0d5213f89880e49bd316ba8e436ee42ed7741322240e633a83a305ec40c5d11_cppui381,
                fq_value_type::one())),
    };
    G1_value_type gp_final_a = G1_value_type(
        0x08ca154549965608909c78bcc6aa8b4ef8397080d14b54427bbb94747af18f25e465dda637f6fc94c02b9ef86b9f5b2b_cppui381,
        0x008db311c46bddd36d8f3113e4ef4559c5ce70bb9b8f7799651583ca7a756f44bfcb9d40d46e41fa22946fe9945f8bb8_cppui381,
        fq_value_type::one());
    G2_value_type gp_final_b = G2_value_type(
        fq2_value_type(
            0x15e12a977ff8033b2c7538a6eff9e114873f6abaa3a5f8619fe2368de1388e697e805784fa4b2190b4cd3154cc49dde2_cppui381,
            0x05432d9d17e7c76a3d350a3d5e9e8f91a119b5afe5a9e7156566fda0447c459d1c7fb8f38fb625edf48440f5e0e9e5b3_cppui381),
        fq2_value_type(
            0x13372bdb38df1eec444c50f8739828cc206f63d1e5e4aecedc24b8a7e6434119e7f5c1f059c1737b61d148476701261d_cppui381,
            0x07a4d623d8d8393d3037f350fc1936ab0ac01153dac4d485581a5dc14e176b749afb1f8497f8bd0de992c36173f92ad7_cppui381),
        fq2_value_type::one());
    G1_value_type gp_final_c = G1_value_type(
        0x107306008c787eb50a0810ca13a179bb98ac5e35ab4c4401f61af09f2449396f77d0bce5d5b1fc1d034efea92da17bb8_cppui381,
        0x0eb9995e51a43a4d1bcd287f11fc66f377aeb5fd62517ec761e68a2436da85e72bd17e853c1e4744ede998e654fc33af_cppui381,
        fq_value_type::one());
    std::pair<G2_value_type, G2_value_type> gp_final_vkey = std::make_pair(
        G2_value_type(
            fq2_value_type(
                0x112a8fae0f862be4c8f290115c1e2c75a9e279a66f498e216f3a10ef69ff815ce3ec39edbeb4b281ebe05b2f20a0769b_cppui381,
                0x1114c03d275b4bce13a954742a8988ba333722b009ac36efe925a8e3c19afc6f9ce8c7484bf8993f52eb49aaa4f8ec09_cppui381),
            fq2_value_type(
                0x08b7d6c40385cfe57b3e05532dd386fc88fbd6cd58596933af51eeb06314b673250180f31f403572f070a613086a14f3_cppui381,
                0x17c3ac21f996cfe2a3cf7366b4a0fa6c78845d210c96244732122361b034ebb021aa8b423d0f0740447201f12b05650c_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x1597377c04c85cd3e7977df8ebbffb69b494513a6a4748539701e6d28897b3bd58481ccd321b165a8a959a79471ea091_cppui381,
                0x12fbdefb39729ad71c89c30bdc125801400ff52408d2b062f8850bfe529bfc1c9be8e4e4a7053bd10fb0812df0681f5d_cppui381),
            fq2_value_type(
                0x0d5dd66edc1319984052ff2e000a00aeeefcdfc0a919663ef9a3c864aa4d32a4fbf40676a97be7571c12348c321ec00e_cppui381,
                0x0af4511e311ec1c421f6d7068d449c39ea90579bd0c1dc0893543598263fce17993d85e8f5aae8f1e161302d4d45f9d0_cppui381),
            fq2_value_type::one()));
    std::pair<G1_value_type, G1_value_type> gp_final_wkey = std::make_pair(
        G1_value_type(
            0x0f735b82eba2a4cd6392dc33dbf4d7959cc90e638b45a5c1b83391c8ea528d491f8294ea2583c718d9c5cf7752be5079_cppui381,
            0x0545f5094822746ba24e25590552f113fb1bdc20ea92ba1671d956bca258c5a7258f26444b8a442f996e98f5563a0857_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x148bfb9e0752eac87883fe95c7a8899cdbeaa9af0ad3d623238a04774eb5de17b5cd55b6b53beac54cb3644c02c4c3a5_cppui381,
            0x082c949d608c7ddebd587403529d3a5159205431ab8e5a196690b4537c2aa937727ed30592e56fa120dd0a3fc934a989_cppui381,
            fq_value_type::one()));
    r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type> com_ab = std::make_pair(
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x005bfb5383703f7ad7c8cebab8b70d9a4c09c6ecac88fe88f2e021cd407878444110eda3447da20614420f0b96ef6de6_cppui381,
                    0x17ac2edc973972b88a578c4c30d6191710666e46cc50cf669b9552c7811b5a3e35d2e87d04218e2ad6ea37fd7804ad80_cppui381),
                fq2_value_type(
                    0x0bc40aef94a0f54822ad79056a793c6693af11650a9ee887a5e4433af3f8a34565ed06323023062b4ea11bf15f443731_cppui381,
                    0x15524cb05539c1b2712a45c1cea484ca7426aec52d731a834da5d26e19ed33c48a180f181b623cf59cc37ce0e697ee3d_cppui381),
                fq2_value_type(
                    0x03023c334dd1e8bcb3c4be0d57c5fc8edcbb4d9373a512f4e735197a68595670d90719577c827a1b62e9d517637c51a6_cppui381,
                    0x17d6804dba136c55babb7e1110d31e639968584e6797c680c2db0c162a987172d906ae0e766ff2f05c9c0d95fc1b1359_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x0983db425b34168ea7e037e7b5d8d658359a9d136451c1ce3c20bd569e0eab4508339da97bdf502d3e4887a091453a4e_cppui381,
                    0x0c3e3d72109d23ebf2daad34b121cc7203e4e9f0dea2a8da41d96233c63314bbdc076c11ccf2800c3364572a5357664b_cppui381),
                fq2_value_type(
                    0x0ad7c8032d3bdc3776d9188f10d06e7369cb8d0c6d0dc00ce087fae972130d65ffaf517a4feff868b18ae2c0babcf250_cppui381,
                    0x08a1b24102da727f5f5174681c212547b5ef3b2e950b29883ec8effb49689e215b292d6df2a5429ce003dc46b85e9664_cppui381),
                fq2_value_type(
                    0x13996beb56c2513c733a911a529e84fdcdc3687450b23f6ffe235af71f09bf3abbafd25bd7aa7ffaa04321df6d69e5ee_cppui381,
                    0x030253acdcbe194d3258acaec3c30aff8d46cf5bc9fb5a16fc56ad86f82e9bbf7f8f478d22a31e65cd433ec8cc2c3de9_cppui381))),
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x0822bfad9e1aa1679876d19309beb064c54dfdccb87f3522f069ffef6516f9b1c5c38ef0f17054d0217d42ca6208cd7e_cppui381,
                    0x06634373ccd257e7ae22d120c37b58c39cbc1b0e6c3735391c3971e1f5b8683c3b8b5840c8e6c991d1989b603eec6b6c_cppui381),
                fq2_value_type(
                    0x04be17f88eec6aaec776615c93ea64904b2d35fe6b825ffa5c9eb6a382bcaaff596a487509c732a1fc762d5a97b1836b_cppui381,
                    0x04aafd05b0ad6e5aa44a4112a4429afeda9c0b8f74ef8f41c6df111aa044d27a3909a212ecdde4038c67da42a802e94b_cppui381),
                fq2_value_type(
                    0x03455e5fa32e7a9508a0b20bdee6f58a70869fd7492dbd18aa97ae525c1ad110fe0b9318e9277229b0fd55288db58995_cppui381,
                    0x1768950613a4b5f99a43c703014f664cbe8fd63f55bf730fd077b928c50f2d42cf920dafe73f9b1b1ab9ef16aff08ded_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x0c8a2fab8d47cf662105373cd871445ad3c691052c1d33ea0b03e8954654f4b6634ab7e75c82d4c860b0ff0d290c2299_cppui381,
                    0x0279df9dbfbcb0cc129142742d5284a25ca3798ed8f4b66aa5296b566aed8c6cd893b8f785f299519d96d407561a83bf_cppui381),
                fq2_value_type(
                    0x04e71cf408c5391c5204e55d9dc007e9efca1bc7582a5f6b044f56bd30b546e895580b43aa22376eca06170f84c76d9e_cppui381,
                    0x051857bc18ce932c2a32d8c7a7b11e3cba5e3975a46b1efc2c2be138b051fb3f701daed78fad3b2e5a64d2b5b70c9adb_cppui381),
                fq2_value_type(
                    0x178221c4b804561b7e35b96589583b63804c79dc22af1b37b505fdf7b3bf0bf9b48811d3f060b211b29b3c46d7ce7a28_cppui381,
                    0x088367d8e5e8bfe3a21d1209c583fcbc4cdcf337c1eb68a4f5161eadbd160e10360b0320ee8d1034d61c46787e701fc0_cppui381))));
    r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type> com_c = std::make_pair(
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x14e486224695b9ba0a0f0a34f0b95d43e0e887039738e823cefb22debe11b3d53f34dcf7015df9c568a7ae1d2358fd8e_cppui381,
                    0x091bd348a453717f080fa10d26d696ce02765a9268a9c1c8d746bed8150609092b3f8c0873ce5f4bb69e5b4b2e8f21ac_cppui381),
                fq2_value_type(
                    0x0f34d88c2f7dd3aa28eff3f0d39ad7fc48c6ba325e22e5eae3e8b5c15e3341f94f63ff58f5f5579b97b811f498e577e3_cppui381,
                    0x183522f3ecdfc14ce2e029559d772c84e0990072573325209efad169031217bab42beafe23c5b3958304a530ee15911c_cppui381),
                fq2_value_type(
                    0x0398a2a70a2377d2456e85e70521d50e684abdb1b2c5a52f8df12639d5f8494c99cc71f86c0bb7022b18b71c5336bc81_cppui381,
                    0x017c68ba9a7306f68f38a4569cf526c7f134c03471bbd78c757b6e74a01d5a18c2af6d0b74205634cf8a5845f490fc13_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x0b5d04761a0438f85adffb6d6fb5829293cf8e4a0cacca12e92d4944dba1afdc3c39d58a49c45570f97dcebdcb456e7b_cppui381,
                    0x0ee19534ff533e286e8951730990d712d16e706a37c8628bd74bf89df28282a6e2c59560f83fdf15e504f5e3fbf81263_cppui381),
                fq2_value_type(
                    0x163c63d3e9a55fc3cc917efe436f83051062825eb9e0900d350824b3b708e05effcb7d88648e7dfbb91d63ef9f85578c_cppui381,
                    0x0fb04351458afb1787e529964a827bb46e1f6c1d60c1b66f8c390fa9d58f3e98d40243cc22853a15ce9f3db9cbb3651c_cppui381),
                fq2_value_type(
                    0x070b66af497d4c4376890e7b2a69e6154b12e65c66125c15f490d063b4bda91ccec5bffe0dfe027c939746cd9ca9c975_cppui381,
                    0x15707d235af8fdc27d04a8ac856ae69fa276dc7b2ffdfd20980099c49dd6c2b7de86b06f9615b064f3328424097cedc6_cppui381))),
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x19829f73caf54fac2272aa68373f60cd3cae166c6e0bcc973734920d4e87a6511c260da7c818b5a3a544fb9c9d73b155_cppui381,
                    0x0b8de7c8c93a92fdc765cdcb691d3688c0a768c1cdac94bdbcf453dbcb8f4eb0d5cc71ee6c7e49863e9c636e456f3b03_cppui381),
                fq2_value_type(
                    0x17f87e06f83e536c18fba9783efbd2201a70deb47cbcd1224038634640f9312e9023c06a528632e223b16059a630e9c3_cppui381,
                    0x151f83a2ecae887ae25ca2436cd969f9fcd04f8813f97b2bb20d92c77acf0d777c3c63a9a333edf82e62dc15392feaa5_cppui381),
                fq2_value_type(
                    0x0419cf89fa02405417cc2a60171f3989e2487b306344311975852323119a3ee374778931824ea19c4b80ef9485e2ca1e_cppui381,
                    0x13bd49d44ba8fec4a3cca254d8346e82488580604695eed8d7241e2f2fd3774ee7c834e4594ee2b3adfde3d32ca9a63b_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x0202df25cb6dc8a839e253e4246d2429876d450d4eb35f3b245eecd169a3d94f1f0bfdd66a406ebdf98510704fdce154_cppui381,
                    0x05e140dcab111c0e22cb637f0bce05e23f326b89a725d8c45166d6490c9b66f922ee37df96d5205e7d03ad55e1a5d30b_cppui381),
                fq2_value_type(
                    0x104eee248fa5bd0be12d72117ee7c532fa928b3cc7395e037aa8c820b6c000b3f87730e57f112d218daa69e102247a9c_cppui381,
                    0x0a1caa6b30195ec2042dbdcba293d8ca67e4e9410527b74ec48521a36389f5e2b199ed74baeda1c251e1217420fb9a0d_cppui381),
                fq2_value_type(
                    0x1295d4059a7db2cedf575fb5bdc3af888e58924f80610864623049f7dcc6acc4f650a088318bef43e943652baaad093e_cppui381,
                    0x0bd6c542d12a367acf2dd1b2686d97be7753ac8287bf037c6b125b637d82fcfd39e59a6d5fa3fbe5b73684aa15aa20a6_cppui381))));
    std::pair<G2_value_type, G2_value_type> tmipp_vkey_opening = std::make_pair(
        G2_value_type(
            fq2_value_type(
                0x0bf836c22b7a8d26cbaba707395a794d239dfb9cfa97e7a7ecdfc5274cc9098aa2dfdbc399de7eb791f64ee409719b01_cppui381,
                0x12752efdd994c43a66c1268fbb39a7b6c3dad8fb851c2014d5da7e498317fd9fd607328f39d656d0e227c94fde609d22_cppui381),
            fq2_value_type(
                0x14ae39024c52755274550db97e7891c8e6a736ade285654c0d73af80aaceae7ad4b5e638d00d5f505a70ba609fef3ca4_cppui381,
                0x05d677d834e065a0556c071bf9dacfe212f0651a346b8c81845a4a1b0e4a6ea857eca87ff1377a80659f036b3660045b_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x12fdd9d8ccd97710e32d8a6c9044f9f00d1a85526d95eeaf16c7c3537e6a7443c89443f4251993ad7069dadf6f61c9b3_cppui381,
                0x11f8bbb43685da92a45707f68db5e3531cf7625ee42bf04532c06650f4545fd52a83c5f90fd20c49bb31530ce8475a82_cppui381),
            fq2_value_type(
                0x0ed17b243806f7d9cdad57356cb2778d82d63a33f49f7d4cb97a6586a7a1a238aee473c0ff4d608caff2f9cd768b1f9d_cppui381,
                0x0fd093a68d37a2b05629d3ab18aacc6a6092ae55b2076ee95d483a9bd596eb1d2e22931662b26b7a7e938eeaba4da9eb_cppui381),
            fq2_value_type::one()));
    std::pair<G1_value_type, G1_value_type> tmipp_wkey_opening = std::make_pair(
        G1_value_type(
            0x1412c46b8d2e943efd0fc938578ff78ed81be9e8eace8ec41180c4e1a2f3ade006fc0f842601bc5af69e87b48a4aabb6_cppui381,
            0x0f5c2ae2fda9d7875a2dfa6947a610e46989520e078ccf6b5141910a6e3d57e2043a9d65af32b89296f40b4af35a8163_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x0e9f58f6b33e7cf12381016627c215f9f70623ccc4d48a434ec6f4328baa6d4aa51515063a4648386a6cac6fe97bdc85_cppui381,
            0x1438310d775365786376197fe53805816b5d7dcb7a92138f0384d392ad11f2453d002d2332062370ebd8f48c3c117ac6_cppui381,
            fq_value_type::one()));

    BOOST_CHECK_EQUAL(ip_ab, agg_proof.ip_ab);
    BOOST_CHECK_EQUAL(agg_c, agg_proof.agg_c);
    BOOST_CHECK(com_ab == agg_proof.com_ab);
    BOOST_CHECK(com_c == agg_proof.com_c);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.nproofs, gp_n);
    BOOST_CHECK(agg_proof.tmipp.gipa.comms_ab == gp_comms_ab);
    BOOST_CHECK(agg_proof.tmipp.gipa.comms_c == gp_comms_c);
    BOOST_CHECK(agg_proof.tmipp.gipa.z_ab == gp_z_ab);
    BOOST_CHECK(agg_proof.tmipp.gipa.z_c == gp_z_c);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_a, gp_final_a);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_b, gp_final_b);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_c, gp_final_c);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_vkey, gp_final_vkey);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_wkey, gp_final_wkey);
    BOOST_CHECK(agg_proof.tmipp.vkey_opening == tmipp_vkey_opening);
    BOOST_CHECK(agg_proof.tmipp.wkey_opening == tmipp_wkey_opening);

    // BOOST_CHECK(verify_aggregate_proof<curve_type>(vk, pvk, statements, agg_proof, tr_include.begin(),
    // tr_include.end()));
    bool verify_res = verify<scheme_type, DistributionType, GeneratorType, hashes::sha2<256>>(
        vk, pvk, statements, agg_proof, tr_include.begin(), tr_include.end());
    BOOST_CHECK(verify_res);

    // Invalid transcript inclusion
    std::vector<std::uint8_t> wrong_tr_include = {4, 5, 6};
    // BOOST_CHECK(!verify_aggregate_proof<curve_type>(vk, pvk, statements, agg_proof, wrong_tr_include.begin(),
    // wrong_tr_include.end()));
    verify_res = verify<scheme_type, DistributionType, GeneratorType, hashes::sha2<256>>(
        vk, pvk, statements, agg_proof, wrong_tr_include.begin(), wrong_tr_include.end());
    BOOST_CHECK(!verify_res);

    // 3. aggregate invalid proof content (random A, B, and C)
    proofs[0].g_A = random_element<g1_type>();
    r1cs_gg_ppzksnark_aggregate_proof<curve_type> agg_proof_rand_a =
        aggregate_proofs<curve_type>(pk, tr_include.begin(), tr_include.end(), proofs.begin(), proofs.end());
    // BOOST_CHECK(!verify_aggregate_proof<curve_type>(vk, pvk, statements, agg_proof_rand_a, tr_include.begin(),
    // tr_include.end()));
    verify_res = verify<scheme_type, DistributionType, GeneratorType, hashes::sha2<256>>(
        vk, pvk, statements, agg_proof_rand_a, tr_include.begin(), tr_include.end());
    BOOST_CHECK(!verify_res);
    proofs[0].g_A = proof0.g_A;

    proofs[0].g_B = random_element<g2_type>();
    r1cs_gg_ppzksnark_aggregate_proof<curve_type> agg_proof_rand_b =
        aggregate_proofs<curve_type>(pk, tr_include.begin(), tr_include.end(), proofs.begin(), proofs.end());
    // BOOST_CHECK(!verify_aggregate_proof<curve_type>(vk, pvk, statements, agg_proof_rand_b, tr_include.begin(),
    // tr_include.end()));
    verify_res = verify<scheme_type, DistributionType, GeneratorType, hashes::sha2<256>>(
        vk, pvk, statements, agg_proof_rand_b, tr_include.begin(), tr_include.end());
    BOOST_CHECK(!verify_res);
    proofs[0].g_B = proof0.g_B;

    proofs[0].g_C = random_element<g1_type>();
    r1cs_gg_ppzksnark_aggregate_proof<curve_type> agg_proof_rand_c =
        aggregate_proofs<curve_type>(pk, tr_include.begin(), tr_include.end(), proofs.begin(), proofs.end());
    // BOOST_CHECK(!verify_aggregate_proof<curve_type>(vk, pvk, statements, agg_proof_rand_c, tr_include.begin(),
    // tr_include.end()));
    verify_res = verify<scheme_type, DistributionType, GeneratorType, hashes::sha2<256>>(
        vk, pvk, statements, agg_proof_rand_c, tr_include.begin(), tr_include.end());
    BOOST_CHECK(!verify_res);
    proofs[0].g_C = proof0.g_C;

    // 4. verify with invalid aggregate proof
    // first invalid commitment
    agg_proof.agg_c = random_element<g1_type>();
    // BOOST_CHECK(!verify_aggregate_proof<curve_type>(vk, pvk, statements, agg_proof, tr_include.begin(),
    // tr_include.end()));
    verify_res = verify<scheme_type, DistributionType, GeneratorType, hashes::sha2<256>>(
        vk, pvk, statements, agg_proof, tr_include.begin(), tr_include.end());
    BOOST_CHECK(!verify_res);
    agg_proof.agg_c = agg_c;

    // 5. invalid gipa element
    agg_proof.tmipp.gipa.final_a = random_element<g1_type>();
    // BOOST_CHECK(!verify_aggregate_proof<curve_type>(vk, pvk, statements, agg_proof, tr_include.begin(),
    // tr_include.end()));
    verify_res = verify<scheme_type, DistributionType, GeneratorType, hashes::sha2<256>>(
        vk, pvk, statements, agg_proof, tr_include.begin(), tr_include.end());
    BOOST_CHECK(!verify_res);
    agg_proof.tmipp.gipa.final_a = gp_final_a;
}

BOOST_AUTO_TEST_CASE(bls381_verification_mimc) {
    constexpr std::size_t n = 8;
    constexpr scalar_field_value_type alpha =
        0x70cf8b38ee6c80d852532b676a1a9a6bcb5c730acf8d374603aa7a3f7582a318_cppui255;
    constexpr scalar_field_value_type beta =
        0x252c17e40f6978eddcfcf95e3134923554ff29176eba269cfa22d647230b12a8_cppui255;

    // setup_fake_srs
    r1cs_gg_ppzksnark_aggregate_srs<curve_type> srs(n, alpha, beta);
    auto [pk, vk] = srs.specialize(n);

    r1cs_gg_ppzksnark_proof<curve_type> proof0(
        G1_value_type(
            0x1399f72bba486cd041f2ba7355b8b989c2d3a0f88ce2585e00e70e556da1a25f07215556ff951d8ccfda5b12f3ac90cf_cppui381,
            0x0a75ffef452c78ff85c7eac1e7341a9c76c251b856fa14ee2eff9d078c70f064b3d06c0b8b6e00bc41f2333a1307164f_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0668d14a879e05415e963933971291f7d463bded5b0c7f569ac21d1c18047206107e41485f7633c2fb6b50155675ecdc_cppui381,
                0x0d4caa0f825d207f175bdf853165324ced69244027f3f25d99791aee0fb605941d1e691b304fdff532d5a1cbbdefaba8_cppui381),
            fq2_value_type(
                0x08f758fb9760a5121ee6899e9253c0bbc344fc52c6e1a4f53a621100b5beaf53a860c07d347fadef5e715008b87560b3_cppui381,
                0x093b43b47f9a581a05fe203d8039a85c91d01dfc110aef48127c6c97ec537dcdc4c8d020b6e5e1f7feaa6ac25df8b149_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x09f277c9c245679f4917f03f032d107745136a36553c6664dfaafb33b8010667cec0fab82d816ff62fdc93264431498b_cppui381,
            0x15f870848e4534ecbd74702e6d79e8b61b68395b6d5f72721b0cf4c9c296f20f72a80f40e8069af926e87ae67341f47b_cppui381,
            fq_value_type::one()));
    constexpr scalar_field_value_type statement0(
        0x676d98b785b2289a12720011f76b9891eddc6e3d77c8eb2fe97b5f5511208065_cppui255);
    r1cs_gg_ppzksnark_proof<curve_type> proof1(
        G1_value_type(
            0x02ef1ec1a2d0c37897dabe8b13d2fa2fcfa9c915097eb91745d6d4e54be221dd367b24d11c522ae2a16fe1a92bbba3f9_cppui381,
            0x0c74829f28e9adf5b4313c02734ee878d2ef7fe0458b0aa7baff576dd204d3d20c3db4eace869bb2445d7c3694581d8b_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x0a0cb52de299b7fda5bea1266d9278a1a3c66666cdd121d62bdbc48a45322d79eddd3af032282b49d7f38c41d5ba0afe_cppui381,
                0x08e675240eaa1ca4d8bc73ab280c9263196bdc9785136422b07c69b38fd594a12a2ca922db16c0fa5bbb9dd7409f4ea4_cppui381),
            fq2_value_type(
                0x105990daac7ce1b7094e5ed6a9ec8a76f76a73823ab272e1274d7c2be5cbe353401b71fd12205db66862b6f80e27ccde_cppui381,
                0x17704237a1535078a657e1f9e950c773615c105a52c071ab290299da5d267ea9cdcdb441bc2bb5f5a8b3c610217c8e2b_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x08d2e6e5680aaabe762712d2beb827c0a459d9d000ca6c386842389a9aa9b36e7d438cf9dca4b5f5935798797c851db6_cppui381,
            0x179452ac9b2dbe5b4fdc942678f5b529d1270872fef5232bce94ca2c4f5b04cef4c9b1deb1870e4433ef73c333824a1f_cppui381,
            fq_value_type::one()));
    constexpr scalar_field_value_type statement1(
        0x1adf834e2bb0455f07b7293cd301a59ee0489e8ea89ab2b268ca62905b60910a_cppui255);
    r1cs_gg_ppzksnark_proof<curve_type> proof2(
        G1_value_type(
            0x0329ae094857dfec93a6bc51e28b606f1d935e22dbf2284d280200e5c00025c13778a153729225b36e95301a26ba36b6_cppui381,
            0x17c3bb71db38454d4453ec60560a265af5cc516deefbb2525268ae9170a843786ab7bdd64e47a530c0af1ad455374bce_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x12f18e127906c95a9820038a6282f01ad57865e031fb520cd9dc4b3c426a5c256491b16cf6d6f638589ff29e6255f104_cppui381,
                0x0601b0633b944f6788db5231c8d51ecc9b6480eff808befcdb9346c80837592d3e9de1fe025e5cf6badf83c752070485_cppui381),
            fq2_value_type(
                0x1150fbbe8eb6d0c662263c3f8853d1a65b73276937f90f214c9130859cf8c451c031b703935a41a2eb655693fb36bf56_cppui381,
                0x01d8458efe86f4cde17645930a66e22145b5a1cefc3b323ed251a52e963ad4e7222757462b9621af0ef52915dcbb169e_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x04c9e7133e46f37ad3b4200cdc1606abbf130db8e168af114bfa12b4cd7abd4de9bc50f7a28d242662ec47b16022ce66_cppui381,
            0x0449b00806db1d5eaddcdaaefe794c0ee5f2aaa7c01d1f7df1fd9b7971cdb76ec755c227f87bc5935fccd6a4716058ac_cppui381,
            fq_value_type::one()));
    constexpr scalar_field_value_type statement2(
        0x3f2738f0b087b2967e479483e052b614671802a0ad3ddf6a04fb86e32a125c77_cppui255);
    r1cs_gg_ppzksnark_proof<curve_type> proof3(
        G1_value_type(
            0x0e54089a438030c10200850c8f900f2cc631270044d4bb607f59bf84564d6be3bf315e7b6c253de1060adad71b5d42e3_cppui381,
            0x0844609d89967590354634de4b93e3a1f187c9a8919859278009ba506cb48346926bd072fc30241a0fc771d707bdf99f_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x022c9f24480c22d736c37c973fe696be08c533f598c4401b82288bfe62cafd920deb3b8536e4c0cd00933163a1830b68_cppui381,
                0x0c0a72697a5820fc5388f3a92871d2881431e0978c90f5bbb2f6a313cd063b25850178e159271229f2e963f9233a30b4_cppui381),
            fq2_value_type(
                0x1377a842ab4bb30d8299315bb763cb617af6904526c1a6a90a6b3b443a2ffc57883f83a006328599070ba30ad9c68194_cppui381,
                0x0c92ab2f18bdcc2178d9fd56ba783bd942f7311ca1d1634db2b645b2ff8a2d1ab733558b6f4836dce626d7f2b8517ec3_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x0213ef2fdde74b15b2b066829a331cab1d8a7e6d7efa0094be4ef7f2f5658209b09627ff3ddbddd96b69d992853cf889_cppui381,
            0x040dc8edacc46608f9587f9c9b658f1b2c2627f570c538f428423c731aa10ef8e828531f4bda6b0734ad35a2a9d7d51f_cppui381,
            fq_value_type::one()));
    constexpr scalar_field_value_type statement3(
        0x69be6aab659e93cbd70e94cb23ff4be9d42cfbcdf9c955145a2d2f20c8a9b031_cppui255);
    r1cs_gg_ppzksnark_proof<curve_type> proof4(
        G1_value_type(
            0x0d6eece4630b049c30c50ccdc9750f11c9cd15aca43554700045ebc81b03cdaf8a7daed7a9c5870189c4c593fa109f05_cppui381,
            0x0b085d537ad0cca263d560dce8d041bde490c95d2ff29cbf9fcd7c376ca3ab554d219ca9633f0b5e056aa35ef6e887ae_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x181c65c65ad8c0b504942f5740a7c175e0142226b7d441cc8cac836b4b6f713056cef60dca010d4d5e775fdd8bd339fa_cppui381,
                0x1515267c97507db065a264c0d5a1b4f22b2d87502ecda11771fc097ab2665406ccdd0feb7ba57e53c4c3e8415d6bc6d3_cppui381),
            fq2_value_type(
                0x0fd7ffd768080edbc6830400f159e681c596a619746795ba5a9ad03b6dfd18047d3d1738784405c3c05e4bd9c5150790_cppui381,
                0x17191a92cbe9c9acc873872162ab60ce5d01dab26280a96bec0cc04c628c47ed56d643906428de68fd5696b8bf39078d_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x128ef42d1399ba429d4c79606321b98bfbeb984342221fe8b231bdc3a6a47673bcddb5205f5cc7a501034931a3ed08e3_cppui381,
            0x0d515563f0840600c7b863b16536a3901084ea4714ca4fee4c906079c5c8d6acb28c1617d762a20e155f3cd9b9ac75ea_cppui381,
            fq_value_type::one()));
    constexpr scalar_field_value_type statement4(
        0x668f0a74247e78898b4b160ad3d63d8a209ab4bd151ebd93d04178c803e8bbfb_cppui255);
    r1cs_gg_ppzksnark_proof<curve_type> proof5(
        G1_value_type(
            0x0f464d0971c96b7f52196d111a389350682c5758f941e0425c041fbac3593121ffb0c5e20249c790edfafe160f7d7106_cppui381,
            0x1980374d3f569b32cb8b001b8ba9eec741e4835336e145263cc84ee14239f2fa38c9bf4f1c0c16638276518f5b8bb901_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x196a554c6af4aae8c58e871e453f9134ab8755a1dbdf10ee88ff0e7b678b8c0c696f5d2a7c9d0bbdf6bc44c9f039d552_cppui381,
                0x115ca6da99922e86fe7d58317ba8e106dc23b1b970eee21f11a07fd2962fccb69c4a26fcaf8e17f04030e2c2c10df817_cppui381),
            fq2_value_type(
                0x002c3d0ee2f62aa0c44eb32c913472e6c1e86b372337f21ecb1e44d00b99a2b6f2de78df7c2ba6a4fb5c36f0e03d7cc1_cppui381,
                0x0d4115c34a549c05223076219c2d030756511433c8e428ef26446847e427dd3c78706375df5df02378b9e212a69fc584_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x04a89866a20de75b2a326f4c4a5b283cbfc431a51eb4bf2a9230ae66edd772179dd4e0c74b4ec59f0017ad5f21fbfaef_cppui381,
            0x056c29dee82c9cec67fce45e4eba0484e4ce47722d7ddf4f62e827f580770777999926017fb5fa2481c04f7aaa787d20_cppui381,
            fq_value_type::one()));
    constexpr scalar_field_value_type statement5(
        0x3f2202b2e3a6f87cc7bd57565b30b78f08dc1ad79e1cc6a9f372dc7639bc1aaf_cppui255);
    r1cs_gg_ppzksnark_proof<curve_type> proof6(
        G1_value_type(
            0x170695ec2cd19303a822fb5480f19e82721af04b18d38bb9a8c71f816c47c7bedc6c2866b9581437a93e14f289573699_cppui381,
            0x07dd012681a3ad0cc0859a73a3be4bddcf5bbf6b504d058fb0e3ba7fc0e9536ebab103cb5d7d2287e62604feef4afb96_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x16b5a5d6209f8fcbd6df06790f3f6c2f34322a4c7f52a5e3c2a1ffc9f0f1782278a63794571b3169181d8412457dc3bf_cppui381,
                0x0ab1b302be43dbaa4a136eea7c8c484d4b144880ced9e474cdc7ee77c493761653c280612a7b4da8fc6cf03dc5c07a1f_cppui381),
            fq2_value_type(
                0x0e7f082279be6fb5447314329fae7e72986b263cf47b292c141ca662a0302481f14905648ab45679d9fe93a8d5fff627_cppui381,
                0x046d0d3a1f489f32e8bf8f7cbb90a99ab17cdfb1b06194c9a60d2aa78bde45e26911b54451741aae28eec06ad96ba5ba_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x118ed7dab64142f556effee3cbc5e4b7a71c28a98caa84767909bb7e367dff5c4ed49cd1c463aeac9058724e52132d9e_cppui381,
            0x103cff37739ac1fb7b244ab5055ca49af28360127d33245e8f986417761b33afbe44a9ebd453092e364d87339c5cd0c2_cppui381,
            fq_value_type::one()));
    constexpr scalar_field_value_type statement6(
        0x10103523c670a127c25e5d5ff5d3eacf87cc5a5671a7833901b2a1fcf678df65_cppui255);
    r1cs_gg_ppzksnark_proof<curve_type> proof7(
        G1_value_type(
            0x19d92ff555f7086784eeccd0c272a0baa68643a24a0df76621b84fb7c54501fa2397b02e91349837a2ea4edda2552ee8_cppui381,
            0x14f218d14352a62d689cdf649feccfab09893969105dd073cab767ed9a2e18deb47a7f7fd02d8d7f9de33615fb62543f_cppui381,
            fq_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x110bf3f7b38d9777d3e66add2abc886823ce7fd89131fa1fe02c2c78aa12db5a4bd0d6f38d4122a68d2bcd3d9d64247f_cppui381,
                0x0b0344d55966166e208754977ac8770a2e5b41e4a32dc73ca9171c5a0cba8cdddacce5627661539804409a6babbff97a_cppui381),
            fq2_value_type(
                0x16d3135e5907b37b87aa965128413ba872bbb2150b463a8f502693a95c6dce0031aa73479bccbfaabed12945656d50e4_cppui381,
                0x0fc6d03d2b43fffab73cb912fc16274d8cf57d6474f3458f09fc8d6fc8bea4bd552c6aafed6b87c120407188da3dcbf9_cppui381),
            fq2_value_type::one()),
        G1_value_type(
            0x18a8945437db0c8a921e9cf68d32c325ccc401105bb00b4e0982b3f4706417b911a1d6db4aa92eabc4422e61ae08a638_cppui381,
            0x198b25f849acdb8344d14e206457b051c90bf9b03b71e4523950a31b9b7a026f035c3fa4a4797e8d5ca5ba511492c2be_cppui381,
            fq_value_type::one()));
    constexpr scalar_field_value_type statement7(
        0x4e2f20ac210798cc3c691edbdca3cd7ba6fc4fc706a49ecf26aa326517e35634_cppui255);
    std::vector<r1cs_gg_ppzksnark_proof<curve_type>> proofs {
        proof0, proof1, proof2, proof3, proof4, proof5, proof6, proof7,
    };
    std::vector<std::vector<scalar_field_value_type>> statements {
        {statement0}, {statement1}, {statement2}, {statement3}, {statement4}, {statement5}, {statement6}, {statement7},
    };
    std::vector<std::uint8_t> tr_include {1, 2, 3};

    fq12_value_type vk_alpha_g1_beta_g2 = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x185e44039dfb814a94541ffc8d1d34c8cbc3c4aff9694d7a433aa811afe2ff0b6bbd5d486791706c73d34f7891c7b7b1_cppui381,
                0x0dc20dafd483fc2d0c4400819f63dc880c7987c59d45e30343ab523e1298352d0477ca225e44d39d3839489287944e3b_cppui381),
            fq2_value_type(
                0x0ceed0815b9184e3eddfc01ad9049088a6bc7ed11240eddc9f5c9904aa895bf41dc652d6140a8afae2727012801f5322_cppui381,
                0x0ec1abeec3a7dfc704d6b18f402f95fee082e6f79a493cadf5bba38713b23dba7f66e5cdcf35e277622304003273bd04_cppui381),
            fq2_value_type(
                0x02433b5eda2f4ceea8ff8b1d57dcbff43a7a7d569e57283bf6413c4db1c4b810305d24e304a294ac3f27d096fcc0c84b_cppui381,
                0x06fda28b12cd3c65b51d10162b32317047f28228f96ed0c46b76a22120974b88b1508915e0fc27572185c7e8d9caa6f0_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x0c41e2862295b03b61a7c1181843698347f2c9e2b0de45442b7262f02886f954bd4d442f5cb37ec87c5a1716522d3442_cppui381,
                0x056fe72dfc01d18d31b19349cb5718120ddd96a82fbefc1d4ed986372d4dcbbfab113fce0a097f44df81addf083f9b92_cppui381),
            fq2_value_type(
                0x0f2bab80d7b0eb6d20a4c894e20974b412bfdfbc9b6f0a2dc140310374fef821d6f9ea8e675760f16adb86bf2b983645_cppui381,
                0x0f174bb36f12cce1f13195cb47f7dd9f49d82f07f78d8f022c2091b01e818cea2bdb3c23b0dcb16d4b8631d9149a60cd_cppui381),
            fq2_value_type(
                0x11d09591eebb8787e4a74fd31863ed716cf2ee57e3d7b82a5b7bffabffa78830b0f2e0137fe6b2db1c745b811f1cf7a2_cppui381,
                0x006fae93c5e4b31f21082e3bc097c316b216810f6ccde888075654753304578b6c721318bf21da6d73bd8d257cebc5f4_cppui381)));
    G2_value_type vk_gamma_g2 = G2_value_type(
        fq2_value_type(
            0x0d545a55b2391f0f4e8b5ff92df2190b32c6f8e3c99aefd96204e2e3e245c23fab958a0a53d71cd6b6ecdb93c1e21174_cppui381,
            0x0084f673066de86c62f4475e32eeca0f359e8e177b2e67f216a26318cfdd0bcd14dda9124f2ff372effc94c0a319c8bb_cppui381),
        fq2_value_type(
            0x04da577f4c3e1a1719730427ba645211ba3645a05e1ba3fbf27baf6d88e582234e04c22657ff48b4947bc68557258249_cppui381,
            0x0074a994e0677c68e0df1e75ef45caf6af2994795608be411e7a09f8398cfc32f0078a531e04379c0654e1dcab4ba55c_cppui381),
        fq2_value_type::one());
    G2_value_type vk_delta_g2 = G2_value_type(
        fq2_value_type(
            0x0ab77c38fa7cfbae21eaf2c682b337ff7ec5262a48974748e322ee4bd80c5a0df3a3966a4626881625db1d1a49fbc222_cppui381,
            0x13c483b705659cf7fae52464298ec0c34f0f875cd4ae30d3c6d493a5d397b4e1a5b14cace259d4a809afd3064a930175_cppui381),
        fq2_value_type(
            0x16a71a9e52003641067339931c2b3a687d418e15d1cdc9fed776863d764fccf7b25b7dc284be6d376bc5811ee185ba8c_cppui381,
            0x18cf536fcc888c50a2f3dd9433b960971d8ac3c2e014db7b202edffdb0aa25d4399f97944ad6880fac3eedb3fca1dc46_cppui381),
        fq2_value_type::one());
    G1_value_type vk_alpha_g1 = G1_value_type(
        0x055b3e622b91e71857f1d93940d54c5ab3cdf5f766fd478dad7894a003a78f1638d9552c494808d3263961052ef031ee_cppui381,
        0x0f4e76ff6aa08eac42a244a7af07758858fbbd6f78d26df16440b6492e54a07cc0034767ec91ee0159cddf2aec3a0ab7_cppui381,
        fq_value_type::one());
    G2_value_type vk_beta_g2 = G2_value_type(
        fq2_value_type(
            0x04d8589ff38165e0e0171b53869216805a30dedc3cd04642df29240bc98a51ff3d4db7e902ccfc7fc186113e68b553d7_cppui381,
            0x17e9145008e5cf84f69519a84181d7e41519d241f12c553bb4a2cc7e74634f22041387926a88c5aa73f643b85314db24_cppui381),
        fq2_value_type(
            0x152dd5fa53c95960dfe8a7b8214668d577c832ea7eff9f4344eef321770aabb74e2b4f33a7b11c146a4d1109184c594c_cppui381,
            0x0e48183088c9f0bedc1a8fd899fc8fc9a000fa42bf68c0c0d2edaea7c2d5b05d9f54be402deb2f989f499cdefc258add_cppui381),
        fq2_value_type::one());
    std::vector<G1_value_type> vk_ic = {
        G1_value_type(
            0x072d9bf38d16790fe06dd960d90ae1e33095eb56e77703ae87324de7cc0691fbb0cf4029da532bb0202e64046efbe8aa_cppui381,
            0x19314e160e79ae8c86f55e826183ec1b1b8530e72e62df12dab45cc82bcaa49c30a7483459a29b522b1c8238dc2e7f11_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x06aab200db211c7c93d63929be9170d4b063f76f689d975d7d33cb8132f7b7fd90c9f8e7542658a2483c4fff6dfbf074_cppui381,
            0x0e41380a7c46a9245def32d330144cd99d8516ee38fb021555843f1e0fa2b4e3a4f9b12ad1af0f4727d23b108c72ccbc_cppui381,
            fq_value_type::one()),
    };
    accumulation_vector<g1_type> vk_acc_ic(std::forward<G1_value_type>(vk_ic[0]),
                                           std::vector<G1_value_type>(vk_ic.begin() + 1, vk_ic.end()));
    r1cs_gg_ppzksnark_aggregate_verification_key<curve_type> pvk(vk_alpha_g1, vk_beta_g2, vk_gamma_g2, vk_delta_g2,
                                                                 vk_acc_ic);

    auto agg_proof =
        prove<scheme_type, hashes::sha2<256>>(pk, tr_include.begin(), tr_include.end(), proofs.begin(), proofs.end());

    fq12_value_type ip_ab = fq12_value_type(
        fq6_value_type(
            fq2_value_type(
                0x0b651d531af67c48741c2896e21acb272c89d2cb0288a84a82c569a80b17317db12b3bcdbc20504bf18110f1a1f65cea_cppui381,
                0x0318fca5b0e3cda6844c3bff03e2dc641cc8243b6ea5961689de891b2f4ac4fe461ac31bb9ad743cd7763f99a2516a12_cppui381),
            fq2_value_type(
                0x1079cb3f7b20a45f1a9efc0185b80c89e931bd60a34fc01ac40c34c0c59488deb5f07d9e2db09f96a436543c3c642835_cppui381,
                0x0d1ac7b85bf328ee7d74c6ae7d44f714f9754d3f2fc0a4dbb759ec40a05ef2e41cadb93949d8303b32d291c6d6ebe517_cppui381),
            fq2_value_type(
                0x0a280ff5b37af55776eb9870ed1fddff8c1707dbf4d424097a9569d5ae1b439c36cc1b3b609177d7068eeef0e58bafdb_cppui381,
                0x14b95a9296cffbc9b123bf554b3c82720b10f8b572f1e8fb85c7bca9a6b81652c94623f6a20a57d80b057446f999f5ac_cppui381)),
        fq6_value_type(
            fq2_value_type(
                0x047e72bee4172c3531c10746fd6ad73fe047d8f4aaa7c9e050e7c15f0bb2a70ef3a3c39e73cac32d433e4a7e87b7481d_cppui381,
                0x16751d310b7f8bd98200210627da1f6b74b1c9e5e2d3c733f0ac34ebf2760b23b9aefef3ce745a9c52168a8f35593bdc_cppui381),
            fq2_value_type(
                0x11bf60e0012119678199196ce43fbd538c69e34c31b48efef70653ca7b8fcb4bd6b3dbdedb53d365c25117a19d777ae2_cppui381,
                0x148b01af1c9d3da2a8811c0d1d428a2bd48c083d33383c89bcebd5e3990eca6b7b1a3c80880ecb49aed4acd1d2b2acf6_cppui381),
            fq2_value_type(
                0x1207d04dcbe7dfce8588b618f9fe26f6b5b82be8ac4e08438aff014dea82b5ada7905e2f44bae34814ac1b124804ab53_cppui381,
                0x188cc860b35dea3244e17f0c5184ff3f07644690a02b5d31ea0952e8f4f63d7fc7789179ba834d42ec26432774fbdc1f_cppui381)));
    G1_value_type agg_c = G1_value_type(
        0x0034802068b3d1e4182f9b4a9aba124693d02599cdcb98a556f5835f6f81ce6071743f64e4054dca9beca6a98e93d11b_cppui381,
        0x0c3b7c4e47a76f90ad22c5000ef930de2b6be5aed847ecca569b7d3bd35bfef71fd0f3c71a3c3857c8d0392d6a2925d6_cppui381,
        fq_value_type::one());
    std::size_t gp_n = 8;
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>,
                          r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>>
        gp_comms_ab = {
            std::make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x09f2702ff7132e35f7a3296e588df0ec39b73c5829eed980d85f95e4d51b3d0fe85c35536480dade0221125a6565ab55_cppui381,
                                0x0a050f0003117e9ef0dc8376acb77ce86977ae230280b436572e10a69a98a2cd1c32800d1a8498050ae3f778e0bfab64_cppui381),
                            fq2_value_type(
                                0x17ce94c42add05c664b047fd439b11390141ce7430b63c5bee1b79abc7d27db59bcaa5a4535e9049bc6a030d1b7dda12_cppui381,
                                0x09f567e7b46df9b25591c094d2830c8f15b075f228fa1faa9aa28b491db07bc7ac69816b97cfefd04a051488ece097dd_cppui381),
                            fq2_value_type(
                                0x1336be0fdce42ccdcd2444230a88ba94a66635559daf70556c93ec882039f88e2e20d7e73521239158d9c78fa08fa416_cppui381,
                                0x1761083f82e8a2907bfd3f8e82da2261acc67dd37d362feeca3bbae447278aea27363435dcf784b2a58101b57a50ae13_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x19b34f8f58b84b9b7394f55733a66da5dddafe349b95d312ec32620ed50186931c7b6e7fc5b003f749a25fca398f6ff3_cppui381,
                                0x1412acdfbd1e92fc733e0480e7bb183dbff2c297f9b36490a8b8b0de8dad11d3b1854d781b3346ae4fa73322006fabf7_cppui381),
                            fq2_value_type(
                                0x0e015c981d00bd544355d4ee3d334197490b9b4a873c1a6d0004d952b72d0d836ceb98d6ef9415a97d058b9bd1809730_cppui381,
                                0x14ceb06402a567ce053d9d0c0750834e66b98e317cc2bea0365e66fcb570c38d27c01ac6a7765133f17dfbb5662cd122_cppui381),
                            fq2_value_type(
                                0x12850c62b6f1638e875b72b118de58f2736e544b26c0c459e3c4b117c87b9693341fb09ca633b0b11640ade0c77a41d5_cppui381,
                                0x09a579897bbc64a08263c3b9c82386fb9a4afb448939cb83af6fe9be08710ec49c9da76b2c6f711ebd18057ba9709bc6_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x0516e3067ba3a7f52c0b8ddb9e1783b2fcd4cfa8448aa19172712c620c3bf8e26c98e4b5acb2c7578be5029f466d398d_cppui381,
                                0x0ef193e0ce6f10ddc68f7e4fb353ec8fd07b9c382476adb5a755103d70e6816736757f87f09c6ada6ccc619c7d54e037_cppui381),
                            fq2_value_type(
                                0x1819fc602d2dd10c6f53fa3d36d78d081536af8c03b6525362a976c2a8428df4485fd0e48e6254fea53254777c99bd78_cppui381,
                                0x04708d36596ca470528eda9690f9f5aa4066bd0ac78b0cf6497bad94464265e03ea3ca31fce40572ba4fa061f25b48f2_cppui381),
                            fq2_value_type(
                                0x06e8c05ffa4b88e4f7f606120eb599a69a1eddab266e9ad79768845cef345f802bee5376565c213e03cb6b27c88caa3b_cppui381,
                                0x168709d507ba32a7da79bcf77b1633b71a4ac96a868cf8e9883e5025097349e20226b1aa07857a8e17b6e9d7ffc0e78f_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x013f5131b3024acf61cbe3c70e09e02da464e7133ba954d56c55f41ce63c2d18b015ce38260ace34068d6223305536db_cppui381,
                                0x041bfb73d4d99513c897352931fc567d0a3d5d3899a5c8e68002f23f81f5f3b7f646dc5cbd9064f42ff4b961266bf0d7_cppui381),
                            fq2_value_type(
                                0x002726427bae373e19e3360558e76c18a79165c0efbf3a3a74ac445911141367778bb6139d487767c66a25abc2206452_cppui381,
                                0x151ec7ca6cb0995f1baca2fa99831c0032a98a1b715420118e7d822b7018390d104ef515701cd789f7c5f5d07d188e7c_cppui381),
                            fq2_value_type(
                                0x184908e05b1dca17708c70f7c3450d2e9947a8864c7fe0ccf251832dd69b5fd24b26aa1b49de7e5f929268a09454e68f_cppui381,
                                0x1925cd66976849caeb84570a3e241b02fd7d4309e626a3579c6318869581fa2c91007193516faaee36cffbe704a926cc_cppui381)))),
                std::
                    make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x06e8d25e2e30279b1d8b1261b5abd73461f239ef9676d5a384e2d5c9156dbf5981b8307a1df6b7d764142c3ff2068f9f_cppui381,
                                    0x14f303e133d7883f6c7af642fc0cd5e790cfee4886dbd39712c2c71f1724c16f369d06d4d754fe40dedccdf1d7f752ef_cppui381),
                                fq2_value_type(
                                    0x010d4256b870a29758701ccfa4a8c2603f294a1ee4f5989fb7ecf46891201286c6bfd1fee210a0793f5e91720c109d13_cppui381,
                                    0x0fcd51c729f0a4c3e9a5a2f4a3db7f2276284c903342c730d8cd6b8df827aeab1405f11586d3aed8b80cf689c6289d27_cppui381),
                                fq2_value_type(
                                    0x0600619f7dcf3dc1d20c5af2d280dab8415a84c6d1f7f65bb79d9b6558372b09a5eb642f5d5a63bd096709199f478433_cppui381,
                                    0x083f873550a317b9852f4f6f67dec62580f517f0449c5df5c970690d27abcac2d24b011c6431f7c3e79c67be15ab8272_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x1972d3d171d81fa9879125bc494b02de883d62ceb5e8c9ee9d888c50bbed5d4dfd9914681d608d9e7befe48349371b65_cppui381,
                                    0x0a276507e76b52a22dbf028dff54a324422c4cb67b8a40890bab9aa8c886f201f490581954f28ec3f94cdb538f0aa2de_cppui381),
                                fq2_value_type(
                                    0x00161821db897544a8614f10ce3d9c0e67c646be82a02002385ec552584d6954153c54fef1b0870c9710dbd5e36a7f65_cppui381,
                                    0x17845d674fe047c3d1dc3f9266f3e34f1716a8d587e735a6a5d53fcbb0fcf2b1d223f84a1bd5dd0716e486a0bffaf932_cppui381),
                                fq2_value_type(
                                    0x0f37830dec9122c2d1ab995b033a9407d3787ebb0e040a33c8515c83581c607831d2c0480f5a28e9a76bf6e501bcf19f_cppui381,
                                    0x0ad7de79ab04b560ddd70bd963022a7c67b72926716de35ec122ccfba03bdae919954e878ca14237587a280dd0520ab1_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x0069002eb3bf9510c03f555251b6aaffb6369afbaa26902000719a2e6793ce95c3ee3476eb98e7323f86e187bcbfcda1_cppui381,
                                    0x0569eedf66ef98b94e8037ea670a1c73dc12c60d83f35a859fe2b390ebdee91a7049de7c6233ee6e1a91296a38f3e60f_cppui381),
                                fq2_value_type(
                                    0x18d5c0ee280f2549fe62acc83dbf6a76c17c0c5d144d82fa927fb2492c1d41bc220be3d3854faf1896f77d57638787d9_cppui381,
                                    0x18c3148323f1a04aaab6dae84362c4aba48dcae376eca2d5089b2df98268f20ef4053fe8a12656b59ffcd930a1353ef3_cppui381),
                                fq2_value_type(
                                    0x00698c72d9e34a5f75f525ac738e4efc8f0177792f0a4f2825025a931eeab3d158c78df7fd2613c61bb5216e0d0f0da7_cppui381,
                                    0x0879d4b791594d7b76e0963b23ed6a1fd157dd0695b88f7dd1fd399bab2dd88cf2683c854d0e90fdb4f3ea98b0990ac2_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x07a8aa469fccf18f374b72718d5f9996bf06e55230eb8604fe4febf0413089439839ed38f7a4b404825741c8208e0ce7_cppui381,
                                    0x03091f175dfec84468264ef0d252777035aa6027868f3be2706264a6c704048ac4f4522d4aab30743862674b79247754_cppui381),
                                fq2_value_type(
                                    0x1020ce13bacc67aed10a3fa70a3579568925d3a3c937cbaacc0bebc6344dd5db432f1297dd7748cefab5450f333e68ca_cppui381,
                                    0x10f63846a44fe863ada8301a3d8dd7deafeedff12405e40c2de03bed40d2f80717a4482a618c9ea076e73b1ef7e76ba3_cppui381),
                                fq2_value_type(
                                    0x0dbbe962242ef2fa7c2f0d1033824bd30fb379bf7e4be16f33fc08494a5715ccf6f8efaef57e60988be9138668f0362a_cppui381,
                                    0x06ff728fa1dfd8fd6cbdcab2642e65690aba7bde8fc3ee5002a710b67e8eac2104e10427c3c866ac0c7c7c0e5f5de17b_cppui381))))),
            std::make_pair(std::make_pair(fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x1852796660667a51a0c2071cefa9e8f5b9ff8a47ee5762586000e9238fdc825061544e2162192b5751083d06e9466119_cppui381, 0x113256b4fe8528cc9d1a174efd5cbfb77deee2781387d835ce4a9c0dde7b3089b4f8312085e15af08d1658a56439b4d8_cppui381), fq2_value_type(0x0faee8705097846240ff8657cdbeb1f6d8456ccf542ac622806f041593bfd748c383df871db0998f273a79f0cf916ec9_cppui381, 0x0390e476a5de709046c47a19b0abb8a985a0c76b09691ae0d415f60b49f719d6d6c91c863e5b34cf31e753e9da577520_cppui381), fq2_value_type(0x1397212e9af000970eff603feae0fb6e71bc54540eb44332ac6a48c3262cf8643824641e6202edca7bb659df095fe6b3_cppui381, 0x09c69bd15c9a4416318f3e2b0af137aa460e2713d0376def59c6356a96551a25120815dc9d3fab26c7565d7654fa0535_cppui381)), fq6_value_type(fq2_value_type(0x0d30d2735f91528c9f170b00707a977c8c9a5bf9648456508d07018dc7b77d04c669fb801f39acf291122d3a92af1cd6_cppui381, 0x0a5ab1427d4dee4a8596f5d447d713829baace88b75760123ebc0f13d473f15956b70a197ca7b802158989c98661ab0e_cppui381), fq2_value_type(0x06da230ae1b6d2e765956eab7d821de3365ee69062fd7f9bd466c2b35cc0fa8c08c2b659d54967ce6b83ad04b8ac12e8_cppui381, 0x0e28148bdadf0530691d69b4de49e8cc65bd7667054f502a9fecc110e31a28a8df5698d62763bbdd17138275e3016420_cppui381), fq2_value_type(0x0e3ac1346e53febe7915b26f6ec376937df4c824017a6e8447c292204ef3207d67f87088cbd171eb2c93a378be6d60b0_cppui381, 0x16fcd0e7e1cb84a3952716daa8215c4711ac08f86300e2644f5795caf870eee6780b1a373116a5f875fe6c5c9437f450_cppui381))),
                                          fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x15792583dad78658a7d2daf61966dcd14237bb33aa55f6276e3238b01db154d0a19ff47a7eb51dd0ae9b04e5f0484398_cppui381, 0x155c3e27184b07d4a38c29700c3d3482b5ef9f33d3d55e6c106ca51d5c1c57844cd7711e0ffeaef59130f4538e3d2af1_cppui381), fq2_value_type(0x0bad0d16235713391f1c18c2a6b3660552d96dced221f78fa954f316a6a8b3d53b4c03c58e57d7beacfdbc4b17ca35a5_cppui381, 0x06df3fd4503f18248d47078026f9737fc2e96b3a42d1c93be2bcff3d02c887a5d7b6e39f1fada154dcfd1eddb13b541c_cppui381), fq2_value_type(0x0f061d1fa9bf661ec5ffe7366627c168410dd0fc813a65aaa471576358311dfdfd97fa31657b48944e01c744ba8237d5_cppui381, 0x1059558c21d6bf4eeb0f8802e9c97a0a76d896ecd3a26157fa8e3bf905ab61b6813c5c06c9ff0a5e502f05be022bbcfc_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x097c0f8033bfa18c5405f2182a01a48d7295179b4fb805c959e2461e5062678bf20e9f265dc11f818db7df6926df150c_cppui381, 0x057f7dbe6a76181210ed8e29586d48f821a054494c16401514f806961609ab8aad625d5aa345de7349c3acc9247401ad_cppui381),
                                                  fq2_value_type(0x1480578d2a7f85051e867267794e8bd1f313b5c5152b0f5cf81a966c13823909e14f1b2d21e5a4ec78e02cf88751dcff_cppui381,
                                                                 0x113d18c38a26c45a60f596e6f4b10f1019f63fe4980bb981edf1d17db3c79829e71a41ed16ff460f9280af70882d8c5f_cppui381),
                                                  fq2_value_type(0x0b0920ed9fc779b7a76eaeb651a298b8f9fb7c6fe378ec0580da51ebe6183be84676da7e20a2624b2dfdac63c9f7ac1b_cppui381,
                                                                 0x09041b8e1b4ca9017d86e11e261a4fccd9768349710add0bff5dc3feba32b79f7d0a8386f31aa466142e94281d0de4d7_cppui381)))),
                           std::make_pair(
                               fq12_value_type(fq6_value_type(fq2_value_type(0x09bb36cd80eab6f12694c4ca4550d16e2af9ea16289308927931cbb9401bce30d96d107540a60d60caef2632e3b6c6bf_cppui381, 0x02b27984d891074cae019ab2456c9aed2aee2854cf5e6a17449ddf76d94d072035e1cb74bdfd18d6a44ca58d1572d2d3_cppui381), fq2_value_type(0x12df2452cf3aeda37b4bee4d7c94be9c280118bb632602a45f980b2700a95ad11377262c90a5da4270430162b98d4e44_cppui381, 0x0d6db13cdc6418687fb342c1a1cad92a74428af8cba1c5cd9c1c621663960d739b03b71df7cd97cbd21dcb68757ccef8_cppui381),
                                                              fq2_value_type(
                                                                  0x128b372c0b575c00b519ad78d3a2a8115ab13cad2c218021f97311b1f6e1d0f64b8645c4bb2f7d175c62995e14eec5ec_cppui381, 0x0d49fa41962f4a792d65db8cf7636d5d41a51f0eb813ab3830ba0b7cdc58d6129a25f473d238a691378137ae2e442d7a_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x130629d1992307191405d0da48df876ca0df83cf7bdaee667eea3fb956c80d3f2dd452fbfe85d57423b94b427a31c54b_cppui381, 0x0cb67292c5b6f1aea4a0dc256b042f8bff495e969d302f564c58dc24cbbd3cb6bd2f90783fbdf6616be351a200a8ac6a_cppui381),
                                                   fq2_value_type(
                                                       0x13892607ef6b0ed83e268c24267c5ea4ff95b7034e6c775bab54b06c6c084c2721ff69d7ade9f913ba055bbf335b9338_cppui381,
                                                       0x13a9a57f8215ba95c26003d0615f9d2f9fe6bb16bf46d6a480b650a482867e68039a0c1fc28583a396920443042ce3dd_cppui381),
                                                   fq2_value_type(
                                                       0x0df5ef7761d5ba02d5e1abe1187d4e84893b2ef6dc5b4e12c229d36a46332a4001e55c8952ec7b15e76f457b53088a20_cppui381,
                                                       0x029b1ad8a8dae8836e02e038750964d1ad266521f9afac81ab8ab590403dd072186f5cdcb1c23859c632f6eb110c578c_cppui381))),
                               fq12_value_type(
                                   fq6_value_type(
                                       fq2_value_type(0x18910203dce07177d48648de3fa56bdbd5e2f48c3035233aebbd8d80bf1c962c2db8021ca7283e5dc83e3689cfa99312_cppui381, 0x15d937215193ccdd295b601da530efd4ac06b5d65a84d25ee6c2ba6a3db27add36029b82c971411b62b22afc63c9a645_cppui381),
                                       fq2_value_type(
                                           0x0965f919df8abd4ac9e3c1796b3e119bed0eb7b64039908aa83d49d7fdac95dea6fd89fd9f4c84c79854909a1621ff8b_cppui381,
                                           0x0d49ec3527dd81e171f4451bb7f7cb07f4f1e8b7ab6a706887af082218272cc5b95ebd24346a2f3b3a513348f5ee065b_cppui381),
                                       fq2_value_type(
                                           0x0eaed4c89dd6fef003183b91b164254e086f629571e24b3997f64f268d20fa182ae7d60cc49312ea781ca3033c61306b_cppui381,
                                           0x00d28794edcb599b56505eb4b3f3cbc47ca8a6768b4fd53fe80fdac2008203963c47f3871bc3bd246fdd2fbe8c937013_cppui381)),
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x198fdf087c2860bb93325066183f661247dd99443161bce488159f45d486e32fe2f9f549fb7ac64e79ac33f1a283d2ef_cppui381,
                                           0x11dbda70c5d26a97a697a9c6a7c979bad96065375018e719a77f727f995bb442779a34c735b5fe5d0d0c21c5cefdcaaa_cppui381),
                                       fq2_value_type(
                                           0x109ce59323eede2e20fd03947305763b75eaa83f10d554a351b17eb571dde499a767bc882e17e67f3bf3141416cde13b_cppui381,
                                           0x15c268b03243dcb9e6500d0bbb43c6a4d9bc5aac5611b1ec351f033a0e1ee506f1f1cba9930cb55f40fef0cc7f842663_cppui381),
                                       fq2_value_type(
                                           0x18d76caceb0941e1cc6dd2bb359bd9b30fee9ef9235016f9169220eb6f521a7b5acf5607de2c0b9fb45d32c81b5aec55_cppui381,
                                           0x075e9c4a549562cebc3141f4aaf60362729ba394092374cd6f5bebdfafe8861669b295647e7793afa254fdca10b7dc45_cppui381))))),
            std::
                make_pair(
                    std::
                        make_pair(fq12_value_type(
                                      fq6_value_type(fq2_value_type(0x06f321d906b79b5812154a28ddf0f3de4cd657336038d141ee75acd4ed8b79a1177ad6b1261f8d04efae29e2532c840c_cppui381, 0x078b72c0c7b4fab7c46756cc75d5737f58e1095cd3bcf3ad68ecb96381476ccced2a9493c1e05cbc0fb084451e9ca6a0_cppui381), fq2_value_type(0x198c195dbd1d992e8466d5f6c88a39dd72a03392f7d85359b00b40d9220344fb0daac4b2c47af41596e2c4263ef2ef69_cppui381, 0x0614f9469fe4144cf2f29d138a9410673ad84c77d302b61a7311d2f39a4b4508f1302754b7b1e8bb9c90d44d761f499f_cppui381), fq2_value_type(0x059869004a8b1104377250553c76f81a6158153428be4ed5d76fef949f75976b38abc57d61138c83d47a9f02bead4b88_cppui381, 0x13f81d53a2268483d709c67a87b878fba2cebbdc1a84401f0df6bd426848f43a7a2d1352b7097d700738cf5cbba1169e_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0be20ed9ff538023b7d6d30497424eedd6423fe5a28a4b80cdbe8dc52fa75c6f5499eff849bd23df8df5c985d41da993_cppui381, 0x14627c1b47ff13759f280516dd24659e1743b857534ddc3024883bd375ce2329c38f01183b98918980b4863878410412_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0b0de23ff8b46698081ab21cb08051fbd6b6a7409efdbc3307d314d13b748d9a7d6a6375da56dd3bd6f733acf5bae51d_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0bcb619091ff45a58b85a56b2571c624633300ce299f4086f48867f596b91724c02eb6cafaa5b3a15dadd425ecf8ee14_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0cbd58a763e04c1ce797f95f2e00ccc4af804abc5720a0b29ce4414b5f754a3f1d2bd5491559cd0cbf23f4879146a60d_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x10ecb14051b56638ac008a980836dd3d214505226829a1c691b7981f02fd063ac3d18de32fc3b2905cd508124970f215_cppui381))),
                                  fq12_value_type(fq6_value_type(fq2_value_type(0x071353e6993d74a98d13c11d0584aba8d18b2d77ce0a848bc6aee2b01b81ae2f1a5852b1abe11cfac04c1912ae48210c_cppui381, 0x179ad4ef71997ec157c8e7f15111d4b013cad3cd271089ae0581ea1ee50ad0f575a3a85223d309f259721f993e383260_cppui381), fq2_value_type(0x17c056a495eb1b931f2041b3b82138085e00d257ca6d1e0adae62d810bb79a28ba945599cce6d15ec11b37e5118d6252_cppui381, 0x064fef2cf96b4b3dfa4f55d70a438cfd0a017836225e893560ca34a3d3555932fd6a75398877fb8e9eb27919a00b5aab_cppui381), fq2_value_type(0x158a4dd69a3aec0dd9cf3ae11e65a6cbdbc77bdc05cd7c1da38d773f2cabc85fe11b5ff491089493b02609df81cf40b9_cppui381, 0x0434d7e43b5457547a4e618322aa80417a88b9835793f8b09ddf12ff3f016be8581ab079502ba694131016f8b7663b44_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x13cbcfd7e188529463acb2be9d9660dbf901477e670a3179d62c8c21964a7d8c0ac867f2e5085ebb24713cb373709843_cppui381, 0x01e1268844f15ae9aaa31cc6de89b0a4d938a0bfd5f21509e28982ee2d93fecb78a468756135f3c16d1c81ed708df139_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x196655bf7d593f45797d274569647be8a1e383c0d60f02886352b5a130d1d5a1abe3548c5828c9b739cdcc17e04cf8d6_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x0ab7b2cf01a7de6e9378ca52bd3bf759ec565d65ab7c32531107b4d0f6a04fc125cdaaf1ba1cf1fd095d51993b7e4c24_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(0x113da3ff7bcaea6249cd9d7836f1ce0835f6cc60d229eee004add1fc56fcf9aa122a2c0d40542345f04952b0833920ec_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x0d5eb9ee3e91a373184eb4a1b7e71f19c31ef288e22325cdd524daff9d43631eeee5f7924edb61f073b7246a03c17ddd_cppui381)))),
                    std::make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x132d751ab5babc2a8543ae8d6d3f7856f99bf5c2a9175a434baff1c4ad4f8ca7be81fed8f69bed7973fd9043ac17d303_cppui381,
                                    0x0de339262382ae18568687047056280843e05de48028e4ed4a02d6e16f775c31b1501598619aa4cbc0c794ee81a74fee_cppui381),
                                fq2_value_type(
                                    0x1497c6fec99d952b0440ecc2300f090e1281c28abda0393a698304fb6d934f261059a21c48ffbbb3c817e2587faa0e0c_cppui381,
                                    0x144d933f46645e4b09549ce3d5caf3e09809084f7797b7184755d5d636d2f8f6e9ccd57b086bc3185727f26b38dca95c_cppui381),
                                fq2_value_type(
                                    0x05b0ea429dad01c93babb50015a363d1f3d3d9a64e78396266cdda7a88239f9fd4fb48f47dd67b9934380c637bc7eaee_cppui381,
                                    0x0abc4f2a97ac6db34202fd5f7f7a724bd18068b2255e93db33c7685c20459a4f9b6103948b4e8e4b518f54660d644810_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x0071126b1695b57907e02cea8928e6b91549e48744f1402789513527c992fce32c1cb6126b744a9a33063512ac7925e4_cppui381,
                                    0x125e254e6f28ef225cc4ed5da30662212142d233fc61e531afa399e8b04dd909b3a86156f3baaaeb7eed7bc13fb137af_cppui381),
                                fq2_value_type(
                                    0x0395bd0c77c91b133dce209ebe92099891a55578df2f22777f1b08765d08df70e93afc113ed7538dff97998228056e3d_cppui381,
                                    0x06a7e06d3ac2480bd847400edaf1dd405f8d9cfd1f18df42aa833b51801f9ba127ca1d29340875d148b49b0629ec4fc7_cppui381),
                                fq2_value_type(
                                    0x0147fa2938d5fd958715fdb6b1950adac27d03a1c156bee7d514cfc6d940fa9e55bc7222cea029b0fc0e7983c6d3fe27_cppui381,
                                    0x16c1029926cddc450309f3ed78d45cb3347b86379a3d16b0bd87fb45fd1539584d45e109391dda6232f3c41e9c9b5b1e_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x1279edcb98bc45b079509ee80de855b63c6c7e017284a04c96310cb85592956055306737ee49efcae0b3aac9d463d015_cppui381,
                                    0x0199bdec2e08c95e64ecbd37851ee950aa1cdf851130f355aa7e3fc334a839bee7b3c94d39f4c2a37974dcfa733061af_cppui381),
                                fq2_value_type(
                                    0x133d8a2bdb821e20be0170499e79e873c9fb4eb5b482f5e1a3e57d390bac9f5a9d9fd001062be71ce6dee34b6caaa956_cppui381,
                                    0x190a0b9e3980fe2ea8bf9f1caeff90ccb43b46d77aa23d11b9d615c08a0c851ab20ed854bc89267e20c3a437a5f8fe18_cppui381),
                                fq2_value_type(
                                    0x0b72a81cb35bc5f4a53c951f6e0062f4e2265b85debcfb975673545e6a28c3067998482baf5175799b738240eb47e4b1_cppui381,
                                    0x17c59d1573eb3cbe6704695e57b8e3982b3eddba61ea1e82e6a2cd8b25178a3b0a35f894083fcc36c4fd1d2adadfeba8_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x0a6cde7faa847091de38ed6c766c4221198aa8cba43a024767c73c06998177f27d2b051c70f0f443bbbb51ad6207507d_cppui381,
                                    0x0b2f0e721f6dae157eddb0730872966422d423220e2a0919cbce19c49c9ea52e4de5c53e0f582d07898dde508429b43a_cppui381),
                                fq2_value_type(
                                    0x0b27390e2a391ddd460c8edea66447ee6050a95e888fd8854a90bc991f0e31cc00db69108a4a0cb3b7fdaa39fb00d3ea_cppui381,
                                    0x0a2a83c7c83b7d39ed0f1f0a796523c47693dd5dcdaf7da67a5d35aa8d9eae53b896baa19836a86323fcb0e793d0433c_cppui381),
                                fq2_value_type(
                                    0x09c9d0a7a7b62ce6f69e447e07f8eef68bd7410f0554edae4598f801c57c243b7d54be4e72da8c6c286c40db7dd7e802_cppui381,
                                    0x1730de7718555a9cb0fd7ca00505def263c451125e2bdec4937210154a8b6cfae0274eecff840784249a66463e00cfb8_cppui381))))),
        };
    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>,
                          r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type>>>
        gp_comms_c = {
            std::make_pair(
                std::make_pair(
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x1302304e6e28332a7459d2635d403f5edd6fd7de5f535380c5dddfa71aae09901fe8d2f9378aa14436e1083814f3c2a4_cppui381,
                                0x08fc52391dedfe4cd69df6cbfc2b68400c9a07ff2a5a3d004c9857a138b7801ba9b4b8ab7b12f296c01d20de74b4820c_cppui381),
                            fq2_value_type(
                                0x0c920cfc51c5cbd16cb68b772e3c0d56a7e196d5e9a989c51036d71c5e62e99bc02dcb0dadd7f53ccc5ede290e7c7166_cppui381,
                                0x0009d2f162880d496b8787adacea02a3feb39467bae4b711e43a5d5726ecd15dab3efaf2f6c428a312249d352d832907_cppui381),
                            fq2_value_type(
                                0x12c5da016c5d010d89cca9f49e44888f09872cf82410704c0e2532df16a531492db7b8457aefd3c1a74a1d413890dfd1_cppui381,
                                0x187e547e48e24be03dee399fbc26199ad8e5de6629db5e709807556d814c5640a8c58747c4c5a8f14dd999777efe1fe3_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x040249ceaa66475d73b3d1b28360882c4668b6e217eed809fe6320f5a8ea18ace6f65a28714f681f7fc049aa6f88f9a4_cppui381,
                                0x16d5a56f0e7b00fd257b37cc56dad8f632a7c552392ec0fbd6479a7771882e40d593c8f56b99799113f02917880b9402_cppui381),
                            fq2_value_type(
                                0x0b2de7c7cf19b158a28ae3c16ecdf5b25f3a47c1ccc8797d38c216cbdade572571fdf35f0ffeebc94874b754e2d771c2_cppui381,
                                0x04674c429d66ffc496a3e8833e5ec22954f8aa5b176696336ccaa2208f207a05182ac7d1cc0cb1434540b132d03fd908_cppui381),
                            fq2_value_type(
                                0x0d4616e0545bdf0b2acd91a61d9461427accc911047449cfb12976639a91899179cf50bf4f87183930a1abacec75f4a3_cppui381,
                                0x117f05380040849733892641de565fc1f29ec1d4172b54057299279dfca5cfd2fd61d26ab66ecbeec2e6a6b4ededa211_cppui381))),
                    fq12_value_type(
                        fq6_value_type(
                            fq2_value_type(
                                0x01e38c35eb4f4192d859a6cbe31ca07ec905c2ac9577060c927f9c1908e2b7be245d1507c10dc1a552c9e1350729a7de_cppui381,
                                0x081ba9fe7dc8b73c8cf83a6bc8a386b9f9cb1c5811acbb79c20930f67ad5be8e4d1ddb944a39bd21fcd61ded130df478_cppui381),
                            fq2_value_type(
                                0x187aedcb8e01fca3ccb1e637e238ab2c7d0dac2ab2e8748682129285fd0ced301bc12ce324f70c2c938672f4e2281110_cppui381,
                                0x140a31bbbe41896ef3d831d0fff390dbc9c333033b63c59f864b6b8b01cbe0916fca3bcbbb109f7d9c5d90a60c3a15f4_cppui381),
                            fq2_value_type(
                                0x080f7afd14d5ac8ec0fc751d636ecc73f8cbcbbb7708938f8cb20153c5f22fa10230880300fe12f7e3e66132131420c1_cppui381,
                                0x16e675cf6ab819bebb6777fd940bf2c17608ee7b74871d75b07f303c6a26176a7346a55146aef7e85f6f1757aedc2a9b_cppui381)),
                        fq6_value_type(
                            fq2_value_type(
                                0x1940fd423f42fdaff353660493dd6be588c37f8834d6b3dd0ea4300d4e039263650645c212fb5cca8ffa70bd8de4fe9e_cppui381,
                                0x0441f5ad4bb3e7e9ea51946b3e3b24d28d5c97d7137a656df5ddc674b72b9bf6e606e0cefdf26dca1c4bd1bfae33c199_cppui381),
                            fq2_value_type(
                                0x195943b0c07baeadedd4a0c54e1fc60494c8b15dfd50dc070dc107412e6fbdb41984bac2d56962b6b9d280ab0e3c1232_cppui381,
                                0x00aac7504cc57d3135e4e27191a124c7888dbae6e8929e132b5b353809c0620cc59abcd5e440eaf1c09f901b408ea617_cppui381),
                            fq2_value_type(
                                0x005a52ceae5e4c099e51682785a6a25666ac89c42936ab8662fa17006992a8fe102041a37b81b0644897636fbb21ff44_cppui381,
                                0x01f16d4db6b8aa06df93bbabe7e3aa5e9c3e9d6409f8b2e1936ad76c126f4fec5c382ea81ba6d7d7ba3af14ce7331a47_cppui381)))),
                std::
                    make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x017760f59824e060848b4a506f3b4fd452b27fab157f356348a0e3fd49e6d2bf0ac64319062b69eac1d58fbddb5367a3_cppui381,
                                    0x0f8b5cebb4dc67856a6d9ecbb12aadb04e2fe9bf3323b77d9be238c863c15062d9884bd6cd59d0d86526dc788d974fae_cppui381),
                                fq2_value_type(
                                    0x17288f95d7c42782b8f8a7bbcdaf8770fedf17ec89b35840ce22079d29d97324b2a8f128380fc22ff7fc8c506f24d832_cppui381,
                                    0x00376666557e1eee19b5aebb7773bce591c2586ffa67f83bac959393c3a552a55d1713c6e31fcb4a7c146fc2a515059a_cppui381),
                                fq2_value_type(
                                    0x090f84fd3b71f35d6ec3da6ddd2b2339b5fa73e62316c4bf1e1d37951b1579376aa138a9645d5ab6e6a7625a3902af11_cppui381,
                                    0x06f56437ce1d7f76493a57f96cb2b2f0673165a614641fd2b1ba1e221f9c7acc5044e68c989ac36f221d6f0c0688a775_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x0324de275bfe28bada7d5397c6b0e88f761f6f96d19deae13c1ca9e74edac8fdafd7e5168b74dac715f0b14e15120786_cppui381,
                                    0x015050406369c0eb807f6360f29343e0ee8214266923a6557adbb7fdc1d5068ddbf8b33208508d9cd696bab90be90548_cppui381),
                                fq2_value_type(
                                    0x17293ce656641eab01401ce64ab3cb38bd9ff0c75dfe534680fabb3299966516c8e250a0e9731e20ddfbadb6afdc29e3_cppui381,
                                    0x038bbd9542eb0dd2543100aad6eb3fea981f7023ce16a990e0651c7226f9a9733d8e8078c0696187df530a6c545484c4_cppui381),
                                fq2_value_type(
                                    0x03ec9e240c474ed6f729b0d7a69f87ee8e2624144f752dd954db62a162b41c0e04bdf0d5d9975b80d1dcc45d87c490c9_cppui381,
                                    0x0f513249f1a350be65b21de0b5c67f2e165febbab0f8b96ec794fca61a7f69a0c21bfae624daf1d7154cf2e94aef218e_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x10ab10cb06737ab54f2a7428e7be1c1496e2b017ce57fc62c06f68541a0f08294728537d83a63c1c3844ef2c2f4ab2de_cppui381,
                                    0x127d40cbb56080effbaa61faf34ce4fcb19d3d7da62216e0d143b0bda23a678d4e266298a37146955ac68478c37792b5_cppui381),
                                fq2_value_type(
                                    0x169b947a693cb132d58a7044a1f00a0bf73c54aa46982f1865d4922bbd0ddddd191b8b41e9692c0416e2220151743675_cppui381,
                                    0x0b96e829f950991af68fc5048ee0590be821ae0075a0172141cd5ab0c93dc4d5fb673d2a19d67ced1428921365ecefcf_cppui381),
                                fq2_value_type(
                                    0x0e8ed67dbe55da6dc0f4bde94d88f4395524d30a340b61eb130da242be50d110a54e91ec4f037c5f1a8d26cc0fcb98a6_cppui381,
                                    0x0a4920a012a1fd91075ff90c1740408fd8ac9802b0c1b8dda4f53ba627fc2088c786ba8f9b1df98211786b8afb6d180b_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x01aa7cf0cf542a9f6e1c2e63cd729955ed9d7299b5ccc9343d64811934caec9086f9fa8b9d019322344f639443d846c9_cppui381,
                                    0x0547c42a6ee31146a8941850d6e8ad6b1b7c62594f2efa00e794a6eb77a033d491703ec69a349fb9bcbe68914e1faebe_cppui381),
                                fq2_value_type(
                                    0x0312644c58f670dc3eb7cf4375c1f3b7f96b021df916ba8fdc4adc73b22cf39aab734487837e4712786f42e5a48c9785_cppui381,
                                    0x11290145623d78b0e25c4b25a750fd800da9678ce9320344644307f97c8d4d4caf53fd27da42a2ab1d55febcf67bb853_cppui381),
                                fq2_value_type(
                                    0x033dcee3c4f44175f5d07506bb89ad3a9443f6b52f26944607f1a664f735aef30373629f8b11f28229fa62a3a16fb6be_cppui381,
                                    0x0dc901adb2d5a2e16386945777b6cf6689e6da5b7dfc6a6c62b8f9281a72f42d018fb18b2d5361565d58286f2acb8d66_cppui381))))),
            std::make_pair(std::make_pair(fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x0e6fc2fe271d965895ab3490c328f66d7462a64094ea9d80ae23b64e94e1f14f116580a5abea53a0035de8f0e054b705_cppui381, 0x099718bdc61adee66df108fe5440fa76b2db180791a3e32398d784aeeac23b957d890ae578ad3751fbb40ff387a6c30b_cppui381), fq2_value_type(0x1421387b26d4ef24edfea0d391c72882757772953985635630705b84ecfb1c45cb55f03cfd3fe75173fdad0231494e6a_cppui381, 0x19012dba4824606d99dfb0a3955a1091dc738d0615054b99ea2071c641e7d075b5b0037e5ad3f0ca479bd627b5bd4b6d_cppui381), fq2_value_type(0x028c155e68d90a74a689ac499262fd444c4f85e8d17592c18bb40fde581c72274e5ef41f7fb761f18f745c644e1507d8_cppui381, 0x0e32b73f5f08e9b3f84668793766a5a7b51d20ec1856d5f7502e37e119ce6539c62c149ef8ab1c75ec9a83a6cb4f3c61_cppui381)), fq6_value_type(fq2_value_type(0x151b40c6e8e43fa5ccb7797e19b60111c2d76042411b599418e3eeecb99fe0fb47de5950783435195c5122ffd0abaa5c_cppui381, 0x022a12f01b7e0e6d4d0694cc47cefd1b1117f75e118b562021799842ebbefa89b9d0236e216ee4899446e97e7c781fec_cppui381), fq2_value_type(0x17d32f37a731f8dba9516ebbc840f14ab5a51c0920308aa10338f6251580946d3e6a3c61948eb892c7b6f6f7df84f0d7_cppui381, 0x12d112384d2fd05a71f54fbc4d67e270a41efdcb256bb753981fabeb50fb8fd4fa1cf9800df4c1364cb50e824230e85d_cppui381), fq2_value_type(0x115b0b32cdaaa33b246e562b4654d2eae616702b0aa55bd31e5b58919469497387fb46e61ed3dede0edf598892b4a452_cppui381, 0x0883288eae7b46b83394003d96a11a3b5fd6c729a608a58bb4596ec6cc74d0f75f6028211d75fed6c7b36e15f6f659de_cppui381))),
                                          fq12_value_type(
                                              fq6_value_type(fq2_value_type(0x1382f572d0d1a153487c9a77090c8a8870ad5d4ce7b8b1ffa24f09d178888fc490c2442e3ec9e64e2255a5d108711180_cppui381, 0x051dd8211d97d800cff47b7ca515669ea462a0fa4f2fd056da3460423f1351d3e644639e0804d23828eb6e0d5885fbb0_cppui381), fq2_value_type(0x142fae3fcd65304ef2c0e67d4a26d618a9599b5203d024c6649a662c6e72454b9f0fa8ecf9ffa731cb26c0522ae3fd07_cppui381, 0x06673dfe79627261e144cdd168db1fcc6f71459580d32c6b24811817ddfb00880767d8aa2688746080dd47ede13bdafa_cppui381), fq2_value_type(0x057234e19f1b700f0e3a1178f61ecf68185677ab94e25e07f4095608e44d16ad31bb24e01df941fe22e45be0207bdd15_cppui381, 0x033d37d4bf97c1a132520a396849caa06aebde195a9bd5feed81ff0d7aa3eb86cc60561774b27d86e8f24de18b617deb_cppui381)),
                                              fq6_value_type(
                                                  fq2_value_type(
                                                      0x025998f75a3e007d0a08f7a79ac7d6cf80ea37804b8017a725234b8738e10556264dccfa7027f7750003841fb4c10b38_cppui381, 0x056a9eac729beba70fda9c71780b37f12b01c043f38d7be4f9e129d290d8b69b5e6bd749b66db1bc58f817fc03e71b3f_cppui381),
                                                  fq2_value_type(0x03211af1a3b143d78742ddd222283cd78658be295a9d4e50488bf6ffefd8d3b8078ab229cb81e33b0d1f2bca399cc2a1_cppui381,
                                                                 0x0a87caa2e5d4ab7175c524690c441d3e2c08b6d839657cc5057d076ec7e89130bdcac807b2c18dc4a374a78faea4f0e5_cppui381),
                                                  fq2_value_type(0x1874766bc415088877f70e3202cdf5c39ec09c15f0e0374f7fe7ff8fc44400ac26799ab5432b6478dfc214dd483f2595_cppui381,
                                                                 0x108a4553948407ece5f81e7a9fd68f5149539f05b84e0185cc92ff17ddea29e4d34d94c4c450c069a240b35ab594a5dc_cppui381)))),
                           std::make_pair(
                               fq12_value_type(fq6_value_type(fq2_value_type(0x18376cf1ccd125f8393fea8f341a6b62e2b9baf17e4b7201e836efce9a6a9bcf78e0aebbe84d9972109ddfa960e638db_cppui381, 0x05cc07e3dd54146d3d8db8bff3c79fa7307454332d9522beaadf215b93788c24de3a21b4e14a94e0ebbfe8216644ac2d_cppui381), fq2_value_type(0x1830b774d1dc559e770f3bfdcc60aa981b27dc5505dbba74b79183b5dc21a2b96d721a72f1ae12d61d41597cd5d6e217_cppui381, 0x1428d0e15547d52848eb50da618c477691913376deb87638cd8f4ed07a76168913dadeb63e820033f4913c8dbc0802fa_cppui381),
                                                              fq2_value_type(
                                                                  0x1943e624109a95ea892c8bae3b7579d8c8f2be3e82cd6b3a40f85dc55d29829da201b5f43def92edd303481635ca5e54_cppui381, 0x0469a5ec7f7bb7a3279f643795b49267ab861f650badffcb321be6506f06b3eef5af8a2392d94dc29d53ef885d7ba517_cppui381)),
                                               fq6_value_type(
                                                   fq2_value_type(0x00a82590732fdead4e76bd1a203b2d0d86aa82dcc336ff43801bb4d835d7d7279c35756028d8c428f6d3a585dd0bb0ca_cppui381, 0x1346e6edb6d18ca90e478616afb42a3013d259edf37b6f6b8ac551bc716a29d7d8a72a51970ca8fe8549f3b53bc5c639_cppui381),
                                                   fq2_value_type(
                                                       0x120844acb209890ba835f8002e011677c26720ca058cf9f414df42fff39ba17149a372535f763d25a4693841fa491238_cppui381,
                                                       0x17dba6290fe070ae0e2466404964c8d7baea6803152443aadd25c2bf8a01d15777f561a0528c0d9b9442ec9e1c324b9e_cppui381),
                                                   fq2_value_type(
                                                       0x10ba46c06a21b63c6ea1b9cbda7551702cd3e602d3d9d74364454ddd03083b93407a0f33059117a65e3d9f1ba2f01249_cppui381,
                                                       0x03504bc7e7fb392a25a4090ca6ecccc9bd73f851064bf38191f9f691931c48420452ca776fefe77ab701b320df7fadc5_cppui381))),
                               fq12_value_type(
                                   fq6_value_type(
                                       fq2_value_type(0x1634b0535614e652cda371df912e26dd64c8a39cc81c1649a8611d37c3f884b64fcc1329bf2b08a905628c84795322dd_cppui381, 0x0fbff0ef4186fe1b8861f7d93ab9acff6a64f44427f5ecab78f22e4543ff6656485abfac6bfc47e8fcadd36e6034bcf5_cppui381),
                                       fq2_value_type(
                                           0x1542195a391ea0950c9a4663d985be099fc4666f7df2c34753e68ed8a5b664d16e2025ae8220dba9406b730b078590b7_cppui381,
                                           0x18246d3b59889cc8b0edef7ee55290299fd5a0080e8716db341931e3d222eaf2c0784f6366b7300a2e2a1f2f6c4da4b5_cppui381),
                                       fq2_value_type(
                                           0x0c00f8b8d7152d39338142b6da1b5359a0c450a5fa8429d35d625802cc295ef55f718fb02b0454007ef5cfc83338746a_cppui381,
                                           0x0709bf3e9d7f008ff6e1d93b3453ad2cb66168921ba36361903361af22d5fca1d6d29b990cb1d2caa8f0c02f86a13531_cppui381)),
                                   fq6_value_type(
                                       fq2_value_type(
                                           0x119c2e12fee299f327357048097b0fd267f249ce49199d123ec0b34f82769a9e6a9ebc9922cc5a63c156ed0af1f2bab8_cppui381,
                                           0x006253f43315f87f5c7de6ea4537ad330ee441c11107e1e267bf517bf30cb8193c015d7956d3cfa8a8f0152727ea7733_cppui381),
                                       fq2_value_type(
                                           0x0cd1080a75dd5428f170f360cedd6a09bf6786a16faa78f32086966849a4b1dde0dd5dc930b785f040f857aafa6e75ab_cppui381,
                                           0x088a7f4fb837357d4de41e53ddb55345fc63acff883a6cc3e6955970c64be3bf6a30a389a07c2ad6f83bc7a97d1f2ff9_cppui381),
                                       fq2_value_type(
                                           0x18fdfb6c24745c8adf60b2d4da3c7fa8d7c1bb2d5e10c2911369eaee725ce6511e547ed433088fca9539a840ded39570_cppui381,
                                           0x135d7730beab103b469029145cfbd4f039150e0294f98943e134c95138ef719436b4ed0c83d815b0b5b885b18d92448b_cppui381))))),
            std::
                make_pair(
                    std::
                        make_pair(fq12_value_type(
                                      fq6_value_type(fq2_value_type(0x12fd5ed0a76a16350608014441c7963af6c58f5204841220d02c120c857d72339140994eaa4a2074c46df38c289dfe7e_cppui381, 0x06b8b2c060e427d3857e3382db6ea5702d4008ebc9cdbcbb205e9e8b660f209672a68f66f6eb2f3fd87ad503af494c62_cppui381), fq2_value_type(0x09579277912400c143be4d18263816fc0f018d7a51724fd9a4d8676070b07b2b016c775b23a455e40f0fe1aee2715c3e_cppui381, 0x0ff9e895637cd5fc197a265c729b0198db906448b26d48d8a511ef66fc6c8d5f83591d8ac460cd20f4647bdbedc97326_cppui381), fq2_value_type(0x191bf0df7f7d1185b6e2f0eec8c7a6447164d3166e3fef3b2dd544d5503a44f66113c4f155e021f44245500b7922f241_cppui381, 0x190401c0e0ed8b3296bc410287e2107b4f2922f469fc21e7f4002cf980ca59ff200a2e0820a98451e1181afd2d4f271f_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x177bd02cddb71e610b8e73b23ff5ac26ee6591c927761649d3c700a4f3a5e0b73d609716892eb199973d9b505cdb4a06_cppui381, 0x1822bd21fd0acee0343343595c4e99af3967bddb8d4c7efcb57fe02665d8bf5ee55e6369c6c95babfb6cac2c6cf914c7_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x088519ddb9dfe63a075bef3a98a732b5f0bcf5af47459596545768bd35e3f92c0ced42f0789b2966dbca3354e0feb373_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0f2e83a97a068e0fb29720bd328d9a0e9fab1571a7caade92a212df909f22f6bbf7623b70716dd506028a3b18fc75290_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x0d87d1a7ae8aabdad6d8861357161a4905503be0dfbefb2b8a135eadf9bc439c29f23c813ba823818d7e1964ba594a1b_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0x14dcd0603959b0da5bf35253e20364d9d2993e07c9dd78b6c6edeab00f58c6073629d03eccb3ce2652529a8a58772bd9_cppui381))),
                                  fq12_value_type(fq6_value_type(fq2_value_type(0x03fc3846e0e8982b6326add7c363d56dfc7fcf2e1ff6faf0b0f9fc0150276dc5942508a7d54358659cbdd6aec7af36a3_cppui381, 0x109bbcce08978c9e3c3a21d674948ade88fb8a8f23687ad716a6c59cbce728e6a72a77d7558a58d4f1c461c784bf499d_cppui381), fq2_value_type(0x0ee1e281ef65d9fe4a064c3b96e560c9ff0e0d51bd8abe50b4a3d40a434cc36c0a5b696bada1198bbff0f89b2a575ea6_cppui381, 0x0443c983945decfc94d1ba2bcad6414c6d71e3f1f9424d32002b374bacf29a48fab10bc318f1b124b54cdc957fd18080_cppui381), fq2_value_type(0x0cf6e0df6ba546778eaaefcad302518fa5b9e91a395f22ca566fba9a484ad9257c0fd9ec8a1fae269cf5519eb873651e_cppui381, 0x17be74b9603e0d670bc7280877675e2a7759f30dfdad39c6f56639826096f73906054ff1ef1ed7529903d58520e5fe0c_cppui381)), fq6_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x05c363e71fee370496ce63581e1a2353d693febc7dcba50a814e0afd41362cc5861ba05b6aa785f79023f856a1852e14_cppui381, 0x15283427f8057e38d8cbb453f3b98e4b26828438e345e0100643229b52ab7703b1adf952af09f75f3ad5c2a721b9e0a2_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x07c3b5b79d43601ac881280b0264078f137524a2511b43462bb5db1ace2071a148823e8d800e9a29da8fe147005a0a29_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0x0806b3ae25853ce81d5d3a37cc92ff63026ac76d644fbebf570dffab8d08b157c8899a7c6dfb902b29065c9ae6773bd6_cppui381),
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    fq2_value_type(0x06adc03cf2b46f5167bb43d755ad20f75deb5fb3d29f7c7098a94552657ae094c86e8a7681e4358fa330f192b9dc4c67_cppui381,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0x04260c55a008a80e8e434d5abd57380d1e9287605d734e7bb984bfcdbda929f5f52486c9fd97ea273438f1886fb4ac2a_cppui381)))),
                    std::make_pair(
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x14bb7ddbeba4908783d6feb7a548702541eeb568f99a04893f9e90381078c135b6194b1a8e002ff7dbbb6bea2d112f04_cppui381,
                                    0x0e5cf73253e3b6522e7616f7fc81d3679000f2c82bc1e4650e528e8b1815da1eb1ca74a0e1f147e9e9ee5afecaf7b75e_cppui381),
                                fq2_value_type(
                                    0x16e5e8804bf3faf4ed8ac4bc08dd18c512dfa1d38cd70366d619fed3ad86110dcb579152126313ab3f9175c653199a9b_cppui381,
                                    0x1643968f88aaa23e7ef8aa9971ca131fe766b7cb0f101c75691b00875598811fe2f85e3e4632821c9869e4db8615e64b_cppui381),
                                fq2_value_type(
                                    0x0ef37b6a804485a17f433b9637fc0666a2e5b44710804f88d04f69b6d61d343dc3473e92a7ab5ffac18157110ea25a28_cppui381,
                                    0x0ae0281de5215487dd076937c9ae34e07531896a0d133c825c946dbb65568e45da316d5ff0e9c19b120ed5307fddd5ea_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x04b4437093d036084bd44ade2383d9f80a3753b85563d4ec723efb00575167d1700848ee8ccf779918830b727bd6e04a_cppui381,
                                    0x02eb16e846db4d99489298242db20234d7b08679a358b3b687b199e1e9f1a79f05a3d22e26558f63ef2bfac1650a2dbb_cppui381),
                                fq2_value_type(
                                    0x163b5d637d6614bf95056c2a6f40fd5b77675b40b33831075ab956a7915b50c2784dd3e9eae62e8e7710dece5b4e5cbb_cppui381,
                                    0x075c630b96f6e47c65dcb8fe2eb7ace6db46fe7f824423a62b134775cc179d1cfabb476b06404cd8f2fae5653b0dbdb0_cppui381),
                                fq2_value_type(
                                    0x04f7a4d7fccd5b85c8f8af6764cbd63124f1079084b907b06596a01e1e3fbf05e424cce303b081bab7a8a30c72215748_cppui381,
                                    0x0ba15e1d5d7e69b85ef295f64d95b68f96716e3c5052df78227a86fd90432c8569d8d07ac0b2821a8d6a25cb2fbb161a_cppui381))),
                        fq12_value_type(
                            fq6_value_type(
                                fq2_value_type(
                                    0x0c082a09cc4de431832046231a3c9ddf5b5beb5c842c2d6b665f406480828f545eb791a5154a9cbeb19d4b4ec8fbef5b_cppui381,
                                    0x104b0366fd45deb2425345d4369d4a5a5e274ee30cf42895a76aac7173d7d0f9477cff64a233ee66d1b974832ded4432_cppui381),
                                fq2_value_type(
                                    0x0b850a3606ecaf7bd030bd9369827132d037f9a6c0536044747661bda381e829d53dcf7ee6be49c73ecbae0d46df39b6_cppui381,
                                    0x08ce262e8b91eaca41f3f91cc223e06539eb6463632e40555178f9e96929e8abe7e414115893a3e83c8ddc43bc3114b2_cppui381),
                                fq2_value_type(
                                    0x0764fc9cc35a550bfe674f02dfb83e2fb9a479e26988b98d751e6bbc7f1039fb28c58aebb099dee819d2e108d5a9d014_cppui381,
                                    0x00792e491f933e2af94549eac5b86c732e328e942d57d91df077cb0e494310044365f5f9cf1cce09efc5893064f75748_cppui381)),
                            fq6_value_type(
                                fq2_value_type(
                                    0x0cface8554679360fd2a2ee77b4db2cc3426539f1bff889c545956674864e90e86ee7185dfc3e9edb28f32c7a142ea63_cppui381,
                                    0x0f330a60215c38df03c90dbeac8096a6166d0a0a2bff2b17da0a2f47618f6914779800558fa17f5283b8264a2e39449c_cppui381),
                                fq2_value_type(
                                    0x08793419745a56961712d18afcf91a9a60e8b34080f15bbd8c9c48e7d67d098dbe545a253cd628c32f3157f641806c3d_cppui381,
                                    0x01ea7d3cd5d129e341fad5dc390e75e00828935a2c5041108dd6ac9430d2a246bf9566ae11aded72512892c1bd0804a9_cppui381),
                                fq2_value_type(
                                    0x1716895aa2ce83971569725cfa75021980d0e9ba9cf6d6c3778354acc73f2392b8ee0e25ad46603afe01f559fec7058c_cppui381,
                                    0x0d08d4cbaf970ccd7da5d59c91ca6897d4516260e6efa2bffe82ace16e9592f132a4e6b8d199dbf9ffb208965cb36b9c_cppui381))))),
        };
    std::vector<std::pair<fq12_value_type, fq12_value_type>> gp_z_ab = {
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x1718116040ceeae31d4be8a8a9652e225f9288f06e1b11fc56879019a7fa7ecdc63e3a3d22d63bec596a8d2cc93bb539_cppui381,
                        0x007abf9364156230bb220e856905716e48d1ded59420098e38bac0f73a19cea50c210746b13867d1cb57374d6c77848c_cppui381),
                    fq2_value_type(
                        0x10e94a7072e7b49cfa35fe8cb93ae758184e4c79a4c60e1226bd5b58afd1b53d1ba70fa6dd340a6d4519b0af11056bc8_cppui381,
                        0x097e294b81c3089daa9c6a75cf9f8958b36b3857a9b209472c3cbff37b7669c4cfdc4c3c5638172b06e198f6d023aa2a_cppui381),
                    fq2_value_type(
                        0x0b8cd3ec915f7390b86a566068e1b2b054f229239375fa84910e61dca491664ea8cf9f189e6e58b3f9846659e35a8f6c_cppui381,
                        0x15a1c1754752dcf72308601a7ba3567ecae27476bdc9f9b9bcdfa99c85dd1ae23bd4a69b7d0d4046eab6cd56965d09a8_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x03ade125dbf2d12c7c901e209ca3f4ad3b5d804e2047ba79b3d6227aca3cfdd422e231a89e9d42b70fe106ff84dcdf88_cppui381,
                        0x19a6b0242756339d70bfda590e5aa38c7787473a481b15a9a55da5fbcc70ae580dcae38e49dd3c314044570bde03dba5_cppui381),
                    fq2_value_type(
                        0x19caa5c8e29f8901db81f5736cfae919db533a3adc85d48e010f005c8b248c50e18840e6f86ac4387285687f8dd78f21_cppui381,
                        0x095f22044de825fe7d5182fc6f6d74eda6a63b98d938f3a13cf9bdaeace1e347596ec1a3f72fee8fa1649c0704de73b8_cppui381),
                    fq2_value_type(
                        0x15c533c5e6fed1bacb31ec03e88fe41a3036a13e62be5325d5f7eb60a53aeb03a8ada2e3b28319609709d62b0c6b18db_cppui381,
                        0x19550061f9e92de28e18a3d24eb1b2882987944b8482fa0fe4d2c5e05d03f9ff099909018751ea8d9463d24c0fde26a4_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x068c1952047295ec2d622eb704fa83998547d0e635d4899a62c928319030e6f0dad9a5724e37b4a55a80e36570ecc699_cppui381,
                        0x04407771c03deac7ffe093fb75174ef253b5393720b07f0a479cdc1fee4ad2a4e01d61650f0699bad3912f1e4d23ec44_cppui381),
                    fq2_value_type(
                        0x00767776619842d37dc154a0d1f1e44d0dd2d68ee72aae89e5defc82e3c69c0a96b48fc76ca033dadeab1bba44b08264_cppui381,
                        0x0d5b3bf61b8b51a09168e2feccf939a6534fe87633aff57dd7928cc593eaec390ffd3d21d84d98b1193baa43cf9612ab_cppui381),
                    fq2_value_type(
                        0x1736e7b5ea4adba0bdd191174fd53412fd73dc59969e174092ba28beca003d11437f3930bfb0d286ee98fd482f8c7bf6_cppui381,
                        0x042f5db4be193bbf88421ade0d450fc87378fc9003fd133598b5da6a800e53602b8a002a85206af9b3d982b83273520a_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x053cca51e1fa7754c5e1d17965a7703a65021faf05db203288cd5a0887cfff79ce99cffa7d4c7524c8a8ae40d93bf229_cppui381,
                        0x14aff8da928aa88a92b3f146024b275f773fd409a31a16a2bc24869b09acf372f96afb2fedbb0a422672eca8c56e3559_cppui381),
                    fq2_value_type(
                        0x084e20aa49145df560f8d274e1edabbb0921c4010cee1a2f04f6fcbfd7d260454ace0c99b84e51d60fd3573c9275fed7_cppui381,
                        0x0c50ffa596f08944e469361ea2b08b5d73c0f5a1d981fe05f9f43265830a84aa84392a601782a6ebda9dcc9acf55ec8b_cppui381),
                    fq2_value_type(
                        0x0a0e9fa90be56a1430a3975926c5125908485ba78181f6d72e689090852d8f1b72f157040ca99f58ccb737052cb422f5_cppui381,
                        0x0764fc11a4a9d1b574198a895e6d7bf231f8ec143903302d0dab141546c4727b40771209cfc017afabc4ecfa3b6cc727_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x1763e5abffdabd0b985c0ddf51e38f0b130a1675917a51ab24995c7133fcbdff665d7fc3fdeab9a35329728eaa2487c0_cppui381,
                        0x09bf6bb6e7d77e8502233d9080bdc5819cddef652c4a2f81367c99ea77cea4ccdaffa771cd927b45f6d5357f3162fd47_cppui381),
                    fq2_value_type(
                        0x051762070642205542fa6de6ac50f1be4c1e9eaf7bb1139f43226996c77e205d8a0983e4458796a32738259989fe9b55_cppui381,
                        0x0ac72ab24ada457e597093800afb99428096b38a7ec5c86509e20c3022ae4cb98f0e252bd3fc98692fe89d5689d07036_cppui381),
                    fq2_value_type(
                        0x08759900ccba56c00ecd0053d7be02e7203b651252ea3cedbfff5658931f1e1881e3a9045c0a90032f9126664d5bedea_cppui381,
                        0x118219f6bd374135fefddec3d77b56a96f3a84ed7ecaa37a919311403d3fa827dcbcfb30517a80c1296a1e1d056d0a4d_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x10d55a0bda7815871aabe2210655b6dbd5e62da3a4850aab73c3a6af8f2b6b5c411e6901a6d7167907cc18450214ec54_cppui381,
                        0x0c3cff90fece5679e377cd2231a7086e8b39052729339b281a3d882913c69197b135ad64aa2c187528800a506d6e3e47_cppui381),
                    fq2_value_type(
                        0x09152f27c3bb2645c6a510cc9734eac01adcf68655016636fad1541081fb427e380508a5430e248502db4f398fb3ca57_cppui381,
                        0x0253e0d15072611fe63584484231348d4ccc0942aed4826061897a3c14e5bbe860d384165ee435532beed454f80d51a2_cppui381),
                    fq2_value_type(
                        0x0042993aefdb19f4a4cea0a0ad4f6a9b7c0942e704fe6cb9c2e0d4b5c1744888a18a47dd359f83bd8668c9152199d54e_cppui381,
                        0x0403ca90810b9bdb3d64e16d994fc0374571574c7f2414763cddee58d339d2ef94f56637d218459c526cfc9a41e2f94a_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x1326e02dcc002f83652f9ae2a21128070bb67467842007fc3dce148fbecc8251303871bf52849bb9b1117deae2ac6909_cppui381,
                        0x160c4aebfb5daa7c8827df4456f1caed71e9c6eb36c4e38335ef5737907ca169b146cf98aaef0d263a4336764a7f5c9f_cppui381),
                    fq2_value_type(
                        0x16b1ebad8aea35d9494788b430dee9f727731a9ccb61a1c82dc23af351fcc4fe184605bf6511a09e594621b46f02f290_cppui381,
                        0x08a2d114e1d45e6a78891b92efb57c0fdff42a5b78e1e41c47dd04b59538297250398f8f2aeaf66f7133cd9ccbb7666b_cppui381),
                    fq2_value_type(
                        0x09f207c5728afb33780f1c95a706b2bdf7d95ad136b9384de2353a3b402dd4b36ddc0af74c5da5502b177548d955bc12_cppui381,
                        0x017ed246c225f9d3ad09689f7a6357853f1d3b25bfbc8f4fde45cf91e5899432d3357997e741e7b54b0d107cd76182dd_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x13ac0921ecebd91522681f39d53174de399809677395c01c3a718bea8ccadf0192ab3445a2302b81532f002c5b5cb789_cppui381,
                        0x17fd0a8cb6cfb92773fa6cba16e0e1ef25b873b19657db520059d9fea0c16449b4a9eae194aaa3e4e62fa2ab9c4bb058_cppui381),
                    fq2_value_type(
                        0x12188747d2c0c173160f2c70cb1a7744efc351c66dec2cb4897b525edaf96b4b11b6cd8f7f96185d14b68f90f1892f0a_cppui381,
                        0x160adadcaa9c4535766cf059d000a3bec963b49d7a196dc9e0b273f0e380524ef0fa3778cd05f91d37dc3e3610b25ef4_cppui381),
                    fq2_value_type(
                        0x0b0aec8750f6fa904037a66899d7bb74157d66eaaa620500c8ac19330f7fa2381f8bb7bf948fcc0cb3164ca5111a57be_cppui381,
                        0x1571de225c6a6b1c05d1d1d1556960c9d8f1d33372de8823a7362a19c8d7bd9f21d8f7a946c8b68201b1964f161ad9ee_cppui381)))),
        std::make_pair(
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x0c1b46645e07f02149535e57c714bfeae7e5c6a6dae657f1bec66e0d2c370088a44b4142c9af9703f4a9140185b8ed16_cppui381,
                        0x121333adbcd6580d59b6f7f4a1d2b00e372df87425f8e23afe782a07aa28c2ac1dee010fd46565c3212dfd2d25aba7f3_cppui381),
                    fq2_value_type(
                        0x0055cc12db8971034a9ce1d8107ca4b8d4d5d7417b246d4814a8be358343a0540c5baa69283a9a2014810b876785e098_cppui381,
                        0x12f500db08771ad5b99ad670e86b07707da6f066b0f4bfebdac9d2d4a456f0f85cb962ab42b0de1437e9bf0fad01717d_cppui381),
                    fq2_value_type(
                        0x02db83dc318c076b1ed46bc49b8c6d489c35554f00a7a1e011fd740326d1f97123d03056e84d4198d0dccc98dfb2b4a4_cppui381,
                        0x11fba6d6f3f6755809779dedfff82c03799918c1e9f4f20139f11b43012abaa92a2c889c6978f5e03ed6ca129bedefee_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x05a517bb0873e1849733759c1352ce11b99eea1f4b14850729166a9a710d92b1d5d976f76d1e31b5bbe896e25b491f5b_cppui381,
                        0x168811463cbfd398603f0cd9600ad2ae2272d2ab432091b16341d9754c62c320e5a16847deffe7d2165127e51f403ad7_cppui381),
                    fq2_value_type(
                        0x0a909f2d324f012584816c1c1edd486551ac2640106236c1a01d47bd2b63ac6f6ae9fbbc99ab6f0de74d364b6b1ef9bb_cppui381,
                        0x0486a82e51356eab57e1842a23098ac1ff87bfbe47ee6b24b5c13dbf3ba5b0563e94917e4c1bdb90b198fd6f2a7202b9_cppui381),
                    fq2_value_type(
                        0x13bd859779632fb6c12ec2797f8b44dd6cd2af3a1bb601493ee50de1e49b2ef6c920a3bd3d23a396d9945c1d282d6d8e_cppui381,
                        0x13bb1971cfef27d5778bba7272e9fe80b13aa73f274e3ff03c7ebf70fdcf9582c83ed6056ef128925b6bc87284c2e72d_cppui381))),
            fq12_value_type(
                fq6_value_type(
                    fq2_value_type(
                        0x1847fd1f3f2172b8d68dd6f3dbd9271f30d96837b307aa8e2a39ba2e86b6605c0fc59bb7777c4802bb7d8c56e7ebf93e_cppui381,
                        0x0c963f2ade97da76fb39777e548e2c20a7ca39a45b2c41f1977e59d157ba809805c3088577aa940121139192a1eb778a_cppui381),
                    fq2_value_type(
                        0x053ec1965be1bb101063317754bf621e88aeae1c0f744eb8a7684b46cecea81304092d804b02e026bd27356f543c3ed1_cppui381,
                        0x0ed51dcd2f7bbb469bb814c40ff3d146f4a537297a83d6f866ab9e344add8173f97156f2f1cde4f3dab9eda6ca9267aa_cppui381),
                    fq2_value_type(
                        0x005604be71269b704f9b0c157f8fad78ac62fef470ab4f8507761d11189ce9786238653068d3b25a1ab2fc042309ae83_cppui381,
                        0x0ae0dd5496948ca18a99e37078f0b0e742873adcadd6aed8c68459fa520cbe8d245907fd86675484d86c821fe9e04576_cppui381)),
                fq6_value_type(
                    fq2_value_type(
                        0x023205ffdbe7dc1569e3a39855e8d83fad5deeb6d9aedeb1ff296e189260002a78b9930363b6704a5ed5dfdc51162668_cppui381,
                        0x088a1750f46f0dd74e5ea8eefdcda6ef07e462dc9e435b6219cb5515688307d15057b9a07aaa93d16a82758ecc03f3f6_cppui381),
                    fq2_value_type(
                        0x0b46157cbd8c46dac48778b3771e0d8a9b4559bd3ba59177faf6abde2786e3b22b02dcc8b285d8460cdba93b3ad8323a_cppui381,
                        0x1317124459e2829c60f16cb4bd696c16c7075c074eafcf0e0d9141ec952fec300e16c3e339b39773b79400fbe4183fad_cppui381),
                    fq2_value_type(
                        0x0c5a70b575d1c10439efb5d1dcd5d5063132fc1fa3317813315dc745b5397ea2265e2edb96890935ebeb1fca80d5c65c_cppui381,
                        0x18d6a68e0769879dc96783fa331ba7612fcb9c5e0379f1fd1ebb8590c5acf34e818d63999e858978f5eca04bd987ec94_cppui381)))),
    };
    std::vector<std::pair<G1_value_type, G1_value_type>> gp_z_c = {
        std::make_pair(
            G1_value_type(
                0x173ec2137ad89c47ea4d955ad1f1e111470718712477afd752012187ff3d421fa48a261d9bde15a7fa62d16b28a83f8e_cppui381,
                0x0b17112f9450252963865ff4ae81d7c019896f02c73979b8ca931b871c78b6a6656c5eee34f6b3bb3f7e2a8517a7912b_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x0284506672cd85e39d65dba1f7da2795487fedf366b721fa91e930638996f139a5c7a628979501d31189ccc8c9698875_cppui381,
                0x09fbada478b96848437e8b755b10f330a3f24d175fdf8f7c42e8ea7fed25f79bc2148ea74a2ea041377e9c691ae2e7eb_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x10ba7fc7e73393ca7598d2e9b12b39de6dbfcd81ad36e428a35b994bbde3e9ab1cd9d9e97943effc439e4987e984fc51_cppui381,
                0x140910a05cad86cffad281385f121f64c3da7c1c59bca46ce9c03fb9f3258517cc92d60b5b2ffd7f4b3110ef7d81adc5_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x01ebe25de68bf860fbd8b002565b6d3639252ba5065c4fd91fc41281e0fdfce31713a6abcfabefb30f0f0791639aae65_cppui381,
                0x12b4a070dab2aa7a3e0fb9cb7996dca5e8e9db368f6b2e284c7a5b8c79ca740a41d4bb58d1dee5d3f9e4fe47ed19eb16_cppui381,
                fq_value_type::one())),
        std::make_pair(
            G1_value_type(
                0x0d8aff668125450adb702647fc1fd00e7ca3ecddf12070463e18b40dadccdce8d475ea33d0888c35982a4882a2931414_cppui381,
                0x0ccfd47ee24216fc4c547076203a0074026130aa9762f48ec93ab804e8e1710126cc6d98f59ca21f349ee9826d9ca1aa_cppui381,
                fq_value_type::one()),
            G1_value_type(
                0x0bbda681a431b6483edbd012fbcadab103507cfbe60a419f7b0c93fed614df9be98c943f92d05f9dc8380dff52a4300e_cppui381,
                0x0c89f7e6ea1a34d23938e2e28ea23f08e75242d4b8e9b47d03466d65b97cd8d927f6a38b08556b057a6d9dff909d8f25_cppui381,
                fq_value_type::one())),
    };
    G1_value_type gp_final_a = G1_value_type(
        0x17538459e8caafbf6f7378d88ea07521b160265df16e4b8fbf159ed69aedb7e4242e909e4eeeeb721b76051b1926d208_cppui381,
        0x0ac1bc8b817d77bcff0e68d06fe3886673dc844691daa41d8f019d10b1723c8ca159505e62ac73ebc80e7b47e9f18d6d_cppui381,
        fq_value_type::one());
    G2_value_type gp_final_b = G2_value_type(
        fq2_value_type(
            0x06c55bb292162b4914d8c8189c0c35906f1e0ddf5adc94e7a4b0e90587efecc1fb870af9ddeff14c6ec763effccc5169_cppui381,
            0x0b74ea554d536fc132d9a5d818c3afb1bef2988002b520f21e85d14a33a0f754326f854e2920fa46d5e7e46b65e4aea3_cppui381),
        fq2_value_type(
            0x1877bc193ec10b531ba56dae27f6c4484fada5413e1afb9b3d80b5cb1b829207ab93064c6bb92708381a28c77c4fbdfc_cppui381,
            0x0ed5efc48efadbde502960b92e31e3c4cd224fe2a761cd361fdacfd05c72afa702c6e4225db37ecb115dc8cd8e27a2b5_cppui381),
        fq2_value_type::one());
    G1_value_type gp_final_c = G1_value_type(
        0x0115eba1ba9c44e21a9cb2b9f6c76932bc306ca0037e7712f8f4dac47bc60f0c5f88078c2c6dd94fbc0056eef670ce54_cppui381,
        0x114ac476be3bf0f1e1f420c8fc1cb1f2bb762cd93c9c3440a8392d7c8a2ca32ca15c3975dfca6b753ba895951c6b414e_cppui381,
        fq_value_type::one());
    std::pair<G2_value_type, G2_value_type> gp_final_vkey = std::make_pair(
        G2_value_type(
            fq2_value_type(
                0x01634dd81fd9ded259e8727141a265ac217877f7c5d5925ab6997e962b05e4b2c9d2c85c32a57cca9ae8daa62b171b30_cppui381,
                0x007829a0bb526d9bf3fb39a34ed106e30045383f4bdf28c821cdffc4fa62f2ba01291a511cc1ff9549a14cb3a6253ba4_cppui381),
            fq2_value_type(
                0x007fa43a344eb4f2c0db80c590a2332896068dd8c447e011122bf52b881e749c6f6c0b02532c65f67af2e1b60566bd38_cppui381,
                0x0958f9ecc4af1e61138df07455189f489449633062684e081265c0188ff5f6ccef136a64ef110e799031c545845f729a_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x01f926264f5a3892055b01ac24e634067ecdee7a9e1ade06e27bb0da9996fe37d3ced88ea7fbc5b0ab7589d7178fcfa1_cppui381,
                0x0a4e360a3dc354b04b4d7951501b989caed7f27ecaa4bea387798a525d0cff68d3a12dc94664646d8fd459270f36d59c_cppui381),
            fq2_value_type(
                0x09c0d648df794e3995352f1d285ab8a61d6ade4d6278fe473f21f79c610a112b4eb25a5a2e3565b756a76f236bf939b6_cppui381,
                0x039831d4cc1b6dc3214bbd4bcc1cd7a1dc6f871a1322e894d385e68ed672b072cfc9e87bad9c418a51db0a34c7dfab52_cppui381),
            fq2_value_type::one()));
    std::pair<G1_value_type, G1_value_type> gp_final_wkey = std::make_pair(
        G1_value_type(
            0x091185d97c3b8d91c936b624099f9169df6db7acc2f828b5ca00f2ef8221624f5570f12124484a038f2168143463e842_cppui381,
            0x0cd29e9bff8b7485f9146218ad386d241ed329f855dc8ca5d8b5f5eb7d2adacd464115ffa6af5d7db2a4eb2a29a212da_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x015dbb6ebd9b9c1dffbe6cc60295540005e0d8a42062288a50e0a2b8dbe6a7e4d9f71d01a6cf4baa9485c812a967f0cc_cppui381,
            0x134c3f11b342e6c3186bff0e72984323110313638473ffce74ed48a0c02fc0d5a6a6564f4d06247daff005649163987f_cppui381,
            fq_value_type::one()));
    r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type> com_ab = std::make_pair(
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x09438df2eed168e525cd161732bf4349ed6bfcdaa8461e93674f061ca9cffcd8cc75b77a9d6dfdb209d581d0c07e7ee4_cppui381,
                    0x041c2011b6779255cf4583d0d3218a6f56f4127d7422351746b114d96ab67867843d36bc48dc1e4fdbdec5dc4c2bfa36_cppui381),
                fq2_value_type(
                    0x158c7065a17b3927a828bd3c0aa549101155e62c532ab389136a3e7c27766b0387d78cc6b889fb7f3cea1fa7ac348059_cppui381,
                    0x0ee242744a21aeb01dcef6c06a016597635ea490daa48c3e1d1a8f600be0e1cbc1a59bfcf85a8ecf7a621934870b7fba_cppui381),
                fq2_value_type(
                    0x18fa1c9b16ecfcd0909b47e3f65add175ec6d400844ce635316562b99bce87de35ffb0f6d7a6d84474d494741d0106f3_cppui381,
                    0x06ad1691ec33738d338a706913868ddda06cfd045c99147c3ac56b7e432ad09f77a4c9e6e74850e4d4ab9953db4cfc0a_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x13ad400debdb06b30620f03778d046533e477bcfbbe346df34df6c15e3c77a5ad0b31131f8ead8b96c6cfc4d02a1c389_cppui381,
                    0x15583230a90604aada461a69890ca54dca55b49cc4a9aa6273c78cba351ad44958533f825fb67c466ba6eb55fdf6b4f3_cppui381),
                fq2_value_type(
                    0x00f1db5c9cce09dd51d214b6b1239159a932c74d08f7d377c4ba269cef1bbec61946f917d737406d5f7a268b10713283_cppui381,
                    0x0462874a3ac8cd9a628c404dc3968643c731c6180681e3587dd9f25599d2631da0a905a457e0e561fe4e16b326743518_cppui381),
                fq2_value_type(
                    0x008f0a48d565eb3f795482ffc080c478c5f47eadc2baad11a09bceab87e2cdfae0a9222dcc2ae3e75c7ac6c3bae31ee5_cppui381,
                    0x089330c302fc3baf321034f54b50d688464b932407f4d78c16a34dbae61df924179e21129075745c63b9757bfd25f05b_cppui381))),
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x01f85b39387fceff47591576f952fb9e6419f021b06cccb4e3872cbc80577348f0473ba81922483cce06b54a8b23acf7_cppui381,
                    0x0e4506272365ed06076b3aba0fae145387abad75c03782c47aadd917e4408b7e4cb4b1e46d5340600202522fe29f376c_cppui381),
                fq2_value_type(
                    0x0421e02496308c78ca48043f267b8ead249ac3231fd564fdb86ad21eb94b7675fd2f4aa4f85b9fce53b10e680592dd7d_cppui381,
                    0x06256d4fb220220163925d28bedd5bac9d5c01f0c548e2e3f2ad726d79a69b9e417330bb862796248a175c52a4d119ff_cppui381),
                fq2_value_type(
                    0x17f988c31e464166b556ac828463fc9eba97bc3d315c31172e61b852905f8c6ebe47d18d8852ebd3dc5df38b6dfc68d2_cppui381,
                    0x0125c3640e74ed2d07ea34e60a511753689233eb3224e70e6b2fcf6267662ed740e5fe39e506607797422ebe45ea4a77_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x150c32bfc286cc3c8bdd2527b989ffa89759b79277e0c53214e7d598b768b7bfc942c82d8923321db5249b916abe0662_cppui381,
                    0x0740df21f60ce5267ad4018856ed2b6bbadb914e0723035ad8faf2bd25343707bf5557b371b2636497406680f72bb483_cppui381),
                fq2_value_type(
                    0x17c3f4d53f282cd6a94234cc704e58e4f246e0bed26c340ab7a9dd21a86cc3675807138a2411d509e14f2cda6bf8e1e0_cppui381,
                    0x142097e3b6a8bd576fadaab0375a9f5596bc9c8edca79c6478eded81ac6b0a8bdb1371e07c426448447f2274dea81c86_cppui381),
                fq2_value_type(
                    0x0d1599375a802ef65799d25667577bc132d204996fc6cc9cb975647373187951346bada49c52bc984dfa74635420ddb6_cppui381,
                    0x12f162ebd20f8136d0e2ff7b66a752fc79134069cdc131ab0cf188ba774ba97ee6a7dc79d9dcd5fe93f6830d27377c34_cppui381))));
    r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type> com_c = std::make_pair(
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x0d1569717ac252ea42031630d1d86b8208abc0928210c9d19116f23ddbd653017ac0ef2f57acadd27aa8cca81438f843_cppui381,
                    0x17df99b57ef9a374fd73cec88e19f74d4e1f83b5b1c973d9b472c194cffed516c0eb53c681d3c21ce29699e35c244cc5_cppui381),
                fq2_value_type(
                    0x121aaea362ab02e8379a362437b4e83f2343c293b7f925bd46c6d50876fbdd48086595705221cdc7ac126939b7e32f6d_cppui381,
                    0x0da0ba3ebc44afb6a38729640264213e37fbf2e7cb40acfb0017c9f3def58fb4037a504ef582df83feff07ba138687bc_cppui381),
                fq2_value_type(
                    0x0250eee41b14f959399aa5fd0f0fee31c1197bb8c016d32fbd819b7d143953d5b0423996493a2ddd782f42b8bafac22c_cppui381,
                    0x0680ffcb49eabc8ee85555f4cc3482900ad261051aeb33d56643c50da0d1bbcbc1452d8993673d0e86312a44641e7233_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x17a2635821fb36738d222bc7615de6da7c2e23e3fd6d81c43f9d8948637f48455021f08544a6ab2baccbb66aaa01eaa8_cppui381,
                    0x0b464c1f228d6a279de9debcbb03d643af592a7bad75199b6d2c09b76de8b04f8d2def4c51455a455c0c327090c0d252_cppui381),
                fq2_value_type(
                    0x0d0fde04945b173830356053368613cf6f25c8df4aaea77c797a10f39c47a5b63fa8abab80f2d42f009b4d21deac2172_cppui381,
                    0x199cd2b4e7d5a7f3c79bffd7c412df7b7a066ab27c163a34f9c876690b34e595f33317c756ef6bea2f6874a04294bac0_cppui381),
                fq2_value_type(
                    0x12529873ef3324a4423d03ce1b3b7d01068d302487dfb7c44bbf80fda3abe138e7812753c80c4de759aa4724fd84e957_cppui381,
                    0x01aea6515a4965d9abe3bd2369f2f25a80aa40a1594eec6b3e32f889be269e3c95269becf1c6752ce27a7f12dc1861fd_cppui381))),
        fq12_value_type(
            fq6_value_type(
                fq2_value_type(
                    0x11a0288351d88bc79b270177235a2c99dbe8925602d4c222217becb34b01ad855f47fb52708aea96ee40d633b59702a5_cppui381,
                    0x16c0a1f83f624a0ac8f2e6b001caa92e85f4f3612f60a5c16be5c5adbe2b7250c758448718848e9049a64ab1b8c6a665_cppui381),
                fq2_value_type(
                    0x00e48ee23098a59ac449a3913fc2dcfd4b52f2c77b208e0ac2432c08b64850d5a0e99f886225d7b72daf714d490f5283_cppui381,
                    0x0f94203b49e62c5e5889935af96380633922314365f1995346062df5b5982d0c7177da840556ca0babcc90abd7f0b2d8_cppui381),
                fq2_value_type(
                    0x16c5639bf79cdcf1f9f2663fb5145d47086b82033463d7146cf88d6ebd924500f5c8ca00a1917e52bd041f8bc29cae74_cppui381,
                    0x06e24ce65b13b39e5ca60aa9275cf060663c19160d6d7187d414b2f03e34798646f724de19d153bd4f42ad813c4e6f9f_cppui381)),
            fq6_value_type(
                fq2_value_type(
                    0x0ca27275c25e692b173b0a837d26e74f4f323e7504a2a9b7ae5151c0967579ab687f0f3055be6d72de2b2b05d3f6814a_cppui381,
                    0x119cbafb2577a5b0a0f2b765f11b03dbd0ad6aaa8974c8a68094d575f279a2305538e14bbd606c1a2a2a2fba21022cb6_cppui381),
                fq2_value_type(
                    0x04925dc41f55a8808e355178e3678189f9d39af465a40fc72d68c41281b449d45048f08eae4482947c5e3841e020acab_cppui381,
                    0x19dc30ef0f8c4d504ee76148232c0aab1afeb669d0798760bad8822bd09458b91f45be56b00a9a88ddc0c80ebeab81d8_cppui381),
                fq2_value_type(
                    0x1567468a9ac691aeda25e7637d17585f86a714d8a921f3659cea7a9479ffceea7fef903ed13095ef85e4f03141871bc8_cppui381,
                    0x16f5b6c09576cc7277640207a4dde23b02ccf457c54114e41ca6be95d9167a8c66e0c5d3d923a2d84f5c18d60810c7c8_cppui381))));
    std::pair<G2_value_type, G2_value_type> tmipp_vkey_opening = std::make_pair(
        G2_value_type(
            fq2_value_type(
                0x03ad15badd1d845acdfdc99c73633a03fc3a4a68cc52fc0247115e70c3ace6cd4c92715984dd70e6648bea4248c1c15b_cppui381,
                0x10aa55d7dbe362b69e21ec1ba54c4173cc4a7e4e62eacce1053595f6f0d037bdca088537def2ae0a03ce0ecabb2c0a75_cppui381),
            fq2_value_type(
                0x093940da4a706bcf27a73885ba50b450073aa4fecd8ece8b9cf1f6432229e0140a152acb596276bd53fe3c4dda23a3ac_cppui381,
                0x090320e2a3dccea5b870d1ef80c0bcb1e6850d9eea0be87072bee0268501840227688fa380bc013f44bbb00912541d51_cppui381),
            fq2_value_type::one()),
        G2_value_type(
            fq2_value_type(
                0x11e68a527689b4b136defff43544c462d27e315991947fa59e1104aa6823bb975e578cd34a24192abd8aae1893610f9b_cppui381,
                0x137ba0dd76e9cdc0a25bc4594cd461720140adcd7ec36f53aa12e210614951a42c27664e0e0ef8428feb56dd66f75544_cppui381),
            fq2_value_type(
                0x08e0d621b3a8786e329287aa695fe54e1f86e4747574113562aeffeffe7ec0485ece3e5f3475677d53e97f644bfc5a66_cppui381,
                0x13a6371c49b093f9e90be0a1d10c94e8db018c37abd09f0d8207f8d1347ac4de544af34ffd0e76e835eb84cffc0d0390_cppui381),
            fq2_value_type::one()));
    std::pair<G1_value_type, G1_value_type> tmipp_wkey_opening = std::make_pair(
        G1_value_type(
            0x0e9acd7993fbd343074b99e268e7bddd30d095981f8272a6a843670a15967537f3ea6c54f7f9290b308ba5c88c5d1b7e_cppui381,
            0x1648288ac64ddcda8a2f129da1e869f95b0cdec1fdfb34103eb09b6adbb804d1c31fcbeb7185628c57f2de3059068c52_cppui381,
            fq_value_type::one()),
        G1_value_type(
            0x13b9051f592110c431fc91d9f2c485f343d4a35cbb311753c1d57e673678a9a9ebafbd6af1175ec764c7cb4414244f25_cppui381,
            0x0984164d7f949e15e6cba14ebbf8ddf946eb4f676f42202156b0ab9536750a1e2a11f9a51153c85add517f645bfe4b78_cppui381,
            fq_value_type::one()));

    BOOST_CHECK_EQUAL(ip_ab, agg_proof.ip_ab);
    BOOST_CHECK_EQUAL(agg_c, agg_proof.agg_c);
    BOOST_CHECK(com_ab == agg_proof.com_ab);
    BOOST_CHECK(com_c == agg_proof.com_c);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.nproofs, gp_n);
    BOOST_CHECK(agg_proof.tmipp.gipa.comms_ab == gp_comms_ab);
    BOOST_CHECK(agg_proof.tmipp.gipa.comms_c == gp_comms_c);
    BOOST_CHECK(agg_proof.tmipp.gipa.z_ab == gp_z_ab);
    BOOST_CHECK(agg_proof.tmipp.gipa.z_c == gp_z_c);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_a, gp_final_a);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_b, gp_final_b);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_c, gp_final_c);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_vkey, gp_final_vkey);
    BOOST_CHECK_EQUAL(agg_proof.tmipp.gipa.final_wkey, gp_final_wkey);
    BOOST_CHECK(agg_proof.tmipp.vkey_opening == tmipp_vkey_opening);
    BOOST_CHECK(agg_proof.tmipp.wkey_opening == tmipp_wkey_opening);

    bool verify_res = verify<scheme_type, DistributionType, GeneratorType, hashes::sha2<256>>(
        vk, pvk, statements, agg_proof, tr_include.begin(), tr_include.end());
    BOOST_CHECK(verify_res);
}

BOOST_AUTO_TEST_SUITE_END()
