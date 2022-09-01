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

                template<typename FieldType>
                struct hash_for_var
                {
                    std::size_t operator()(const plonk_variable<FieldType> &var) const {
                        std::size_t seed = 0;
                        boost::hash_combine(seed, var.type);
                        boost::hash_combine(seed, var.index);
                        boost::hash_combine(seed, var.rotation);
                        return seed;
                    }
                };

                template<typename FieldType>
                struct hash_for_vars
                {
                    std::size_t operator()(const std::vector<plonk_variable<FieldType>> &vars) const {
                        std::size_t seed = 0;
                        for (auto var : vars) {
                            boost::hash_combine(seed, var.type);
                            boost::hash_combine(seed, var.index);
                            boost::hash_combine(seed, var.rotation);
                        }
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

                    static inline void print_var(const var& var) {
                        std::cout << "(column " << var.type << ", row " << var.index << ") ";
                    }

                    static inline std::array<math::polynomial<typename FieldType::value_type>, argument_size>
                        prove_eval(typename policy_type::constraint_system_type &constraint_system,
                                   const plonk_polynomial_dfs_table<FieldType,
                                        typename ParamsType::arithmetization_params> &column_polynomials,
                                        std::shared_ptr<math::evaluation_domain<FieldType>> domain,
                                   transcript_type &transcript = transcript_type()) { //TODO: remove domain 
                        // auto start = std::chrono::high_resolution_clock::now();

                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> ans0;

                        // nonlinear combination of constraints
                        std::unordered_map<var, nlc_type, hash_for_var<FieldType>> map_for_sel;

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        const std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> gates = constraint_system.gates();
                        
                        for (std::size_t i = 0; i < gates.size(); i++) {
                            auto selector_var = var(gates[i].selector_index, 0, true, var::column_type::selector);
                            nlc_type gate_res = nlc_type(FieldType::value_type::zero());
                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                gate_res = gate_res + nlc_type(gates[i].constraints[j]) * theta_acc;
                                theta_acc *= theta;
                            }
                            if (map_for_sel.find(selector_var)
                                == map_for_sel.end()) {
                                    map_for_sel[selector_var] = 
                                        nlc_type(FieldType::value_type::zero());
                            }
                            map_for_sel[selector_var] =
                                        map_for_sel[selector_var] + gate_res; 
                        }
                        // std::size_t f_map_size = 0;
                        // for (auto f : map_for_sel) {
                        //     f.second.sort();
                        //     f_map_size += f.second.terms.size();
                        //     std::cout << "new term\n";
                        //     for (auto term : f.second.terms) {
                        //         for (auto var : term.vars) {
                        //             print_var(var);
                        //         }
                        //         std::cout << '\n';
                        //     }
                        // }

                        auto start = std::chrono::high_resolution_clock::now();
                        for (auto f : map_for_sel) {
                            f.second.sort();
                            auto eval_result = plonk_constraint<FieldType>(f.second).evaluate(column_polynomials, domain);
                            auto lin_multiplier = nlc_type(f.first);
                            auto eval_lin_multiplier = plonk_constraint<FieldType>(lin_multiplier).evaluate(column_polynomials, domain);

                            if (eval_result.degree() > eval_lin_multiplier.degree()) {
                                eval_lin_multiplier.resize(eval_result.degree());
                            } else if (eval_result.degree() < eval_lin_multiplier.degree()) {
                                eval_result.resize(eval_result.degree());
                            }

                            ans0[0] = ans0[0] + math::polynomial<typename FieldType::value_type>((eval_result * eval_lin_multiplier).coefficients());
                        }
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
                        // std::cout << "first: " << duration.count() << "ms" << std::endl;

                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> ans;
                        start = std::chrono::high_resolution_clock::now();
                        std::unordered_map<std::vector<var>, nlc_type, hash_for_vars<FieldType>> map_for_vars;
                        for (auto f : map_for_sel) {
                            for (auto term : f.second.terms) {
                                std::vector<var> key = {f.first};
                                if (term.vars.size()) {
                                    key.push_back(term.vars[0]);
                                    term.vars.erase(term.vars.begin());
                                }
                                if (map_for_vars.find(key)
                                    == map_for_vars.end()) {
                                        map_for_vars[key] = 
                                            nlc_type(FieldType::value_type::zero());
                                }
                                map_for_vars[key] =
                                            map_for_vars[key] + term;
                            }
                        }

                        for (auto f : map_for_vars) {
                            // f.second.sort();
                            auto eval_result = plonk_constraint<FieldType>(f.second).evaluate(column_polynomials, domain);
                            nlc_type lin_multiplier = nlc_type(f.first[0]);
                            for (std::size_t i = 1; i < f.first.size(); ++i) {
                                lin_multiplier = lin_multiplier * f.first[i];
                            }
                            auto eval_lin_multiplier = plonk_constraint<FieldType>(lin_multiplier).evaluate(column_polynomials, domain);

                            // if (eval_result.degree() > eval_lin_multiplier.degree()) {
                            //     eval_lin_multiplier.resize(eval_result.degree());
                            // } else if (eval_result.degree() < eval_lin_multiplier.degree()) {
                            //     eval_result.resize(eval_result.degree());
                            // }

                            ans[0] = ans[0] + math::polynomial<typename FieldType::value_type>((eval_result * eval_lin_multiplier).coefficients());
                        }
                        duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
                        // std::cout << "second: " << duration.count() << "ms" << std::endl;

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
