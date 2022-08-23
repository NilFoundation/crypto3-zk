//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP

#include <unordered_map>
#include <unordered_set>
#include <set>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/math/non_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename ParamsType, std::size_t ArgumentSize = 1>
                struct placeholder_gates_argument;

                template<typename FieldType>
                struct hash_for_coeff
                {
                    std::size_t operator()(const typename plonk_variable<FieldType>::assignment_type &value) const {
                        std::size_t seed = 0;
                        boost::hash_combine(seed, static_cast<std::size_t>(value.data));
                        return seed;
                    }
                };

                struct hash_for_pair
                {
                    std::size_t operator()(const std::pair<std::uint8_t, std::size_t> &pair) const {
                        std::size_t seed = 0;
                        boost::hash_combine(seed, pair.first);
                        boost::hash_combine(seed, pair.second);
                        return seed;
                    }
                };

                template<typename FieldType, typename ParamsType>
                struct placeholder_gates_argument<FieldType, ParamsType, 1> {

                    typedef typename ParamsType::transcript_hash_type transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

                    using arithmetization_params = typename ParamsType::arithmetization_params;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;

                    using var = plonk_variable<FieldType>;

                    using nlt_type = typename math::non_linear_term<var>;
                    using nlc_type = typename math::non_linear_combination<var>;

                    constexpr static const std::size_t argument_size = 1;

                    static inline std::array<math::polynomial<typename FieldType::value_type>, argument_size>
                        prove_eval(typename policy_type::constraint_system_type &constraint_system,
                                   const plonk_polynomial_dfs_table<FieldType,
                                        typename ParamsType::arithmetization_params> &column_polynomials,
                                        std::shared_ptr<math::evaluation_domain<FieldType>> domain,
                                   transcript_type &transcript = transcript_type()) { //TODO: remove domain 

                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> ans;

                        // nonlinear combination of constraints
                        nlc_type F(FieldType::value_type::zero());

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        const std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> gates = constraint_system.gates();

                        //////////////////////////////OLD ALGORITHM///////////////////////////
                        auto start = std::chrono::high_resolution_clock::now();
                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> check;
                        check[0] = math::polynomial<typename FieldType::value_type>(FieldType::value_type::zero());
                        for (std::size_t i = 0; i < gates.size(); i++) {
                            math::polynomial_dfs<typename FieldType::value_type> gate_result(
                                0, domain->m, FieldType::value_type::zero());

                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                gate_result =
                                    gate_result + gates[i].constraints[j].evaluate(column_polynomials, domain) * theta_acc;
                                theta_acc *= theta;
                            }

                            gate_result = gate_result * column_polynomials.selector(gates[i].selector_index);

                            check[0] = check[0] + math::polynomial<typename FieldType::value_type>(gate_result.coefficients());
                        }

                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
                        std::cout << "check: " << duration.count() << "ms" << std::endl;
                        //////////////////////////////OLD ALGORITHM///////////////////////////

                        start = std::chrono::high_resolution_clock::now();
                        
                        theta_acc = FieldType::value_type::one();
                        for (std::size_t i = 0; i < gates.size(); i++) {
                            nlc_type gate_res = nlc_type(FieldType::value_type::zero());
                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                gate_res = gate_res + nlc_type(gates[i].constraints[j]) * nlc_type(var(gates[i].selector_index, 0, true, var::column_type::selector)) * theta_acc;
                                theta_acc *= theta;
                            }

                            F = F + gate_res;
                        }
                        F.sort();

                        // columns for linearization
                        std::unordered_set<std::pair<std::uint8_t, std::size_t>, hash_for_pair> columns;
                        for (std::size_t i = 0; i < arithmetization_params::WitnessColumns; ++i) {
                            columns.insert(std::pair<std::uint8_t, std::size_t>(0, i));
                        }
                        for (std::size_t i = 0; i < arithmetization_params::ConstantColumns; ++i) {
                            columns.insert(std::pair<std::uint8_t, std::size_t>(2, i));
                        }

                        // monomials - combining by coeffs - TODO - use in linearization
                        // std::unordered_map<typename var::assignment_type, nlc_type, hash_for_coeff<FieldType>> monomials_by_coeff;
                        // for (auto term : F) {
                        //     auto search = monomials_by_coeff.find(term.coeff);
                        //     if (search != monomials_by_coeff.end()) {
                        //         monomials_by_coeff[term.coeff] = search->second + nlt_type(term.vars);
                        //     } else {
                        //         monomials_by_coeff[term.coeff] = nlt_type(term.vars);
                        //     }
                        // }

                        // linearization
                        using key_type = std::pair<typename var::column_type, std::size_t>;
                        std::unordered_map<key_type, nlc_type, hash_for_pair> linearized;
                        nlc_type const_term;
                        for (const auto &term : F) {
                            std::vector<var> evaluated;
                            std::vector<var> unevaluated;
                            for (auto var : term.vars) {
                                auto search = columns.find(key_type(var.type, var.index));
                                if (search != columns.end()) {
                                    evaluated.push_back(var);
                                } else {
                                    unevaluated.push_back(var);
                                }
                            }
                            assert(unevaluated.size() <= 1);

                            nlc_type c = nlc_type(term.coeff);//nlc_type(term);
                            for (auto var : evaluated) {
                                c = c * nlc_type(var);
                            }
                            if (unevaluated.empty()) {
                                const_term = const_term + c;
                            } else {
                                auto var = unevaluated[0];
                                // if (var.relative) {
                                //     assert(var.rotation == 0);
                                // }
                                assert(var.rotation == 0); // why? 
                                if (linearized.find(key_type(var.type, var.index))
                                    == linearized.end()) {
                                        linearized[key_type(var.type, var.index)] = 
                                            nlc_type(FieldType::value_type::zero());
                                }
                                linearized[key_type(var.type, var.index)] =
                                            linearized[key_type(var.type, var.index)] + c;
                            }
                        }

                        // evaluation
                        for (auto lin : linearized) {
                            auto eval_result = plonk_constraint<FieldType>(lin.second).evaluate(column_polynomials, domain);
                            auto lin_multiplier = nlc_type(var(lin.first.second, 0, true, lin.first.first));
                            auto eval_lin_multiplier = plonk_constraint<FieldType>(lin_multiplier).evaluate(column_polynomials, domain);

                            if (eval_result.degree() > eval_lin_multiplier.degree()) {
                                eval_lin_multiplier.resize(eval_result.degree());
                            } else if (eval_result.degree() < eval_lin_multiplier.degree()) {
                                eval_result.resize(eval_result.degree());
                            }
                            ans[0] = ans[0] + math::polynomial<typename FieldType::value_type>((eval_result * eval_lin_multiplier).coefficients());
                        }

                        duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
                        std::cout << "eval: " << duration.count() << "ms" << std::endl;

                        return ans;
                    }

                    static inline std::array<typename FieldType::value_type, argument_size>
                        verify_eval(const std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> &gates,
                                    typename policy_type::evaluation_map &evaluations,
                                    typename FieldType::value_type challenge,
                                    transcript_type &transcript = transcript_type()) {
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::array<typename FieldType::value_type, argument_size> F;

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        for (std::size_t i = 0; i < gates.size(); i++) {
                            typename FieldType::value_type gate_result = {0};

                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                gate_result = gate_result + gates[i].constraints[j].evaluate(evaluations) * theta_acc;
                                // std::cout << gates[i].constraints[j].evaluate(evaluations).data << '\n';
                                theta_acc *= theta;
                            }

                            std::tuple<std::size_t,
                                           int,
                                           typename var::column_type>
                                selector_key = std::make_tuple(gates[i].selector_index, 0,
                                    var::column_type::selector);

                            gate_result =
                                gate_result * evaluations[selector_key];

                            F[0] = F[0] + gate_result;
                        }

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
