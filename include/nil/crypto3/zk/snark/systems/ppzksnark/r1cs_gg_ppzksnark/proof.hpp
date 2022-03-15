//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_PROOF_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_PROOF_HPP

#include <nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct r1cs_gg_ppzksnark_proof {
                    typedef CurveType curve_type;

                    typename CurveType::template g1_type<>::value_type g_A;
                    typename CurveType::template g2_type<>::value_type g_B;
                    typename CurveType::template g1_type<>::value_type g_C;

                    r1cs_gg_ppzksnark_proof() {
                        using g1_type = typename CurveType::template g1_type<>;
                        using g2_type = typename CurveType::template g2_type<>;

                        // invalid proof with valid curve points
                        this->g_A = g1_type::value_type::one();
                        this->g_B = g2_type::value_type::one();
                        this->g_C = g1_type::value_type::one();
                    }
                    r1cs_gg_ppzksnark_proof(const typename CurveType::template g1_type<>::value_type &g_A,
                                            const typename CurveType::template g2_type<>::value_type &g_B,
                                            const typename CurveType::template g1_type<>::value_type &g_C) :
                        g_A(g_A),
                        g_B(g_B), g_C(g_C) {};
                    r1cs_gg_ppzksnark_proof(typename CurveType::template g1_type<>::value_type &&g_A,
                                            typename CurveType::template g2_type<>::value_type &&g_B,
                                            typename CurveType::template g1_type<>::value_type &&g_C) :
                        g_A(std::move(g_A)),
                        g_B(std::move(g_B)), g_C(std::move(g_C)) {};

                    std::size_t G1_size() const {
                        return 2;
                    }

                    std::size_t G2_size() const {
                        return 1;
                    }

                    std::size_t size_in_bits() const {
                        using g1_type = typename CurveType::template g1_type<>;
                        using g2_type = typename CurveType::template g2_type<>;

                        return G1_size() * g1_type::value_bits + G2_size() * g2_type::value_bits;
                    }

                    bool is_well_formed() const {
                        return (g_A.is_well_formed() && g_B.is_well_formed() && g_C.is_well_formed());
                    }

                    bool operator==(const r1cs_gg_ppzksnark_proof &other) const {
                        return (this->g_A == other.g_A && this->g_B == other.g_B && this->g_C == other.g_C);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
