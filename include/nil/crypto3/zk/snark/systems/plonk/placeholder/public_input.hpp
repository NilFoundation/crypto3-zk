//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PUBLIC_INPUT_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_PUBLIC_INPUT_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename PlaceholderParams>
                struct public_input_processor{
                    using field_type = typename PlaceholderParams::field_type;
                    using public_input_gate_type = typename PlaceholderParams::constraint_system_type::public_input_gate_type;
                    using common_data_type = const typename placeholder_public_preprocessor<field_type, PlaceholderParams>::preprocessed_data_type::common_data_type;
                    using policy_type = detail::placeholder_policy<field_type, PlaceholderParams>;
                    using assignment_type = plonk_polynomial_dfs_table<field_type, typename PlaceholderParams::arithmetization_params>;
                    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename PlaceholderParams::transcript_hash_type>;
                    using variable_type = plonk_variable<typename field_type::value_type>;
                    using proof_type = placeholder_proof<field_type, PlaceholderParams>;

                    static inline math::polynomial_dfs<typename field_type::value_type> prove(
                        const public_input_gate_type &public_input_gate,
                        const common_data_type &common_data,
                        const assignment_type &assignments,
                        transcript_type &transcript
                    ){
                        math::polynomial_dfs<typename field_type::value_type> result;
                        if(public_input_gate.size() == 0){
                            return result;
                        }
                        auto alpha = transcript.template challenge<field_type>();
                        for(std::size_t i = 0; i < public_input_gate.size(); i++){
                            const auto &var = public_input_gate[i];
                            math::polynomial_dfs<typename field_type::value_type> l;

                            if(var.type == variable_type::witness){
                                l = assignments.witness(var.index);
                            } else if (var.type == variable_type::public_input){
                                l = assignments.public_input(var.index);
                            } else if (var.type == variable_type::constant){
                                l = assignments.constant(var.index);
                            } else if (var.type == variable_type::selector){
                                l = assignments.selector(var.index);
                            } else {
                            }
                            l -=  typename field_type::value_type(l[0]);
                            l *=  math::polynomial_shift(common_data.lagrange_0, var.rotation, common_data.basic_domain->m);
                            result *= alpha;
                            result += l;
                        }
                        return result;
                    }

                    static inline typename field_type::value_type verify(
                        const std::vector<typename field_type::value_type> &public_input,
                        typename policy_type::evaluation_map &columns_at_y,
                        typename field_type::value_type challenge,
                        const public_input_gate_type &public_input_gate,
                        const common_data_type &common_data,
                        transcript_type &transcript
                    ){
                        if(public_input_gate.size() == 0){
                            return field_type::value_type::zero();
                        }
                        BOOST_ASSERT(public_input_gate.size() == public_input.size());

                        typename field_type::value_type result;
                        auto alpha = transcript.template challenge<field_type>();

                        for(std::size_t i = 0; i < public_input_gate.size(); i++){
                            const auto &var = public_input_gate[i];
                            auto key = std::tuple(var.index, var.rotation, var.type);
                            auto value = columns_at_y[key] - public_input[i];
                            value *= math::polynomial_shift(common_data.lagrange_0, var.rotation, common_data.basic_domain->m).evaluate(challenge);
                            result *= alpha;
                            result += value;
                        }
                        return result;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // #ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PUBLIC_INPUT_ARGUMENT_HPP