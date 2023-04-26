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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_VERIFIER_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_VERIFIER_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename ParamsType>
                class placeholder_verifier {

                    constexpr static const std::size_t witness_columns = ParamsType::witness_columns;
                    constexpr static const std::size_t public_input_columns = ParamsType::public_input_columns;
                    constexpr static const std::size_t constant_columns = ParamsType::constant_columns;
                    constexpr static const std::size_t selector_columns = ParamsType::selector_columns;

                    using merkle_hash_type = typename ParamsType::merkle_hash_type;
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;

                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;

                    constexpr static const std::size_t lambda = ParamsType::commitment_params_type::lambda;
                    constexpr static const std::size_t r = ParamsType::commitment_params_type::r;
                    constexpr static const std::size_t m = ParamsType::commitment_params_type::m;

                    using commitment_scheme_type = typename ParamsType::runtime_size_commitment_scheme_type;
                    using public_preprocessor_type = placeholder_public_preprocessor<FieldType, ParamsType>;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t lookup_parts = 5;
                    constexpr static const std::size_t f_parts = 9;

                public:
                    static inline bool process(
                        const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data,
                        placeholder_proof<FieldType, ParamsType> &proof,
                        plonk_constraint_system<FieldType, typename ParamsType::arithmetization_params>
                            &constraint_system,
                        const typename ParamsType::commitment_params_type &fri_params) {
                        
                        // 1. Add circuit definition to transcript
                        // transcript(short_description);
                        std::vector<std::uint8_t> transcript_init {};
                        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(transcript_init);

                        // 3. append witness commitments to transcript
                        transcript(proof.variable_values_commitment);

                        // 4. prepare evaluaitons of the polynomials that are copy-constrained
                        std::size_t permutation_size = (proof.eval_proof.combined_value.z[3].size() - 2 - constant_columns - selector_columns) / 2;
                        std::vector<typename FieldType::value_type> f(permutation_size);

                        for (std::size_t i = 0; i < permutation_size; i++) {
                            std::size_t zero_index = 0;
                            for (int v: preprocessed_public_data.common_data.columns_rotations[i]) {
                                if (v == 0)
                                    break;
                                ++zero_index;
                            }
                            if (i < witness_columns + public_input_columns) {
                                f[i] = proof.eval_proof.combined_value.z[0][i][zero_index];
                            } else if (i < witness_columns + public_input_columns + constant_columns) {
                                std::size_t idx = i - witness_columns - public_input_columns + permutation_size*2;
                                f[i] = proof.eval_proof.combined_value.z[3][idx][zero_index];
                            }
                        }

                        // 5. permutation argument
                        if (preprocessed_public_data.common_data.lagrange_0.evaluate(proof.eval_proof.challenge) !=
                            proof.eval_proof.lagrange_0) {
                            return false;
                        }
                        std::array<typename FieldType::value_type, permutation_parts> permutation_argument =
                            placeholder_permutation_argument<FieldType, ParamsType>::verify_eval(
                                preprocessed_public_data, proof.eval_proof.challenge, f,
                                proof.eval_proof.combined_value.z[1][0][0], proof.eval_proof.combined_value.z[1][0][1],
                                proof.v_perm_commitment, transcript);

                        typename policy_type::evaluation_map columns_at_y;
                        for (std::size_t i = 0; i < witness_columns; i++) {
                            std::size_t i_global_index = i;
                            std::size_t j = 0;
                            for (int rotation: preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<FieldType>::column_type::witness);
                                columns_at_y[key] = proof.eval_proof.combined_value.z[0][i][j];
                                ++j;
                            }
                        }
                        
                        for (std::size_t i = 0; i < 0 + public_input_columns; i++) {
                            std::size_t i_global_index = witness_columns + i;

                            std::size_t j = 0;
                            for (int rotation: preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<FieldType>::column_type::public_input);
                                columns_at_y[key] = proof.eval_proof.combined_value.z[0][witness_columns + i][j];
                                ++j;
                            }
                        }

                        for (std::size_t i = 0; i < 0 + constant_columns; i++) {
                            std::size_t i_global_index = witness_columns + public_input_columns + i;
                            std::size_t j = 0;
                            for (int rotation: preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<FieldType>::column_type::constant);
                                columns_at_y[key] = proof.eval_proof.combined_value.z[3][i + permutation_size*2][j];
                                ++j;
                            }
                        }

                        for (std::size_t i = 0; i < selector_columns; i++) {
                            std::size_t i_global_index = witness_columns + constant_columns + public_input_columns + i;
                            std::size_t j = 0;
                            for (int rotation: preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<FieldType>::column_type::selector);
                                columns_at_y[key] = proof.eval_proof.combined_value.z[3][i + permutation_size*2 + constant_columns][j];
                                ++j;
                            }
                        }

                        // 6. lookup argument
                        bool use_lookup = constraint_system.lookup_gates().size() > 0;
                        std::array<typename FieldType::value_type, lookup_parts> lookup_argument;
                        if (use_lookup) {
                            for (std::size_t i = 0; i < lookup_parts; i++) {
                                lookup_argument[i] = 0;
                            }
                            // lookup_argument = placeholder_lookup_argument<
                            //     FieldType, permutation_commitment_scheme_type,
                            //     ParamsType>::verify_eval(preprocessed_public_data, constraint_system.lookup_gates(),
                            //                              proof.eval_proof.challenge, columns_at_y,
                            //                              proof.eval_proof.lookups[1].z[0][0],
                            //                              proof.eval_proof.lookups[1].z[0][1],
                            //                              proof.eval_proof.lookups[2].z[0][0],
                            //                              proof.eval_proof.lookups[0].z[0][0],
                            //                              proof.eval_proof.lookups[0].z[0][1],
                            //                              proof.input_perm_commitment, proof.value_perm_commitment,
                            //                              proof.v_l_perm_commitment, transcript);
                        } else {
                            for (std::size_t i = 0; i < lookup_parts; i++) {
                                lookup_argument[i] = 0;
                            }
                        }

                        // 7. gate argument
                        std::array<typename FieldType::value_type, 1> gate_argument =
                            placeholder_gates_argument<FieldType, ParamsType>::verify_eval(
                                constraint_system.gates(), columns_at_y, proof.eval_proof.challenge, transcript);

                        // 8. alphas computations
                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<FieldType, f_parts>();

                        // 9. Evaluation proof check
                        transcript(proof.T_commitment);

                        typename FieldType::value_type challenge = transcript.template challenge<FieldType>();

                        if (challenge != proof.eval_proof.challenge) {
                            return false;
                        }

                        typename FieldType::value_type omega =
                            preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

                        std::vector<std::vector<typename FieldType::value_type>>
                            variable_values_evaluation_points(witness_columns + public_input_columns);

                        // variable_values polynomials (table columns)
                        for (std::size_t variable_values_index = 0; variable_values_index < witness_columns + public_input_columns; variable_values_index++) {
                            std::set<int> variable_values_rotation =
                                preprocessed_public_data.common_data.columns_rotations[variable_values_index];

                            for (int rotation: variable_values_rotation) {
                                variable_values_evaluation_points[variable_values_index].push_back(
                                    challenge * omega.pow(rotation));
                            }
                        }
                        // permutation
                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_permutation = {{challenge,
                                                                                                     challenge * omega}};
                        // lookup
                        if (use_lookup) {
                            // TODO: Check if commitments roots are used correctly.
                            //      test crypto3_zk_systems_plonk_placeholder_placeholder_test calls it only with
                            //      use_lookup == false
                            // std::vector<typename FieldType::value_type> evaluation_points_v_l = {challenge,
                            //                                                                      challenge * omega};
                            // if (!algorithms::verify_eval<permutation_commitment_scheme_type>(
                            //         evaluation_points_v_l,
                            //         proof.eval_proof.lookups[0],
                            //         proof.v_l_perm_commitment,
                            //         fri_params,
                            //         transcript)) {
                            //     return false;
                            // }

                            // std::vector<typename FieldType::value_type> evaluation_points_input = {
                            //     challenge, challenge * omega.inversed()};
                            // if (!algorithms::verify_eval<permutation_commitment_scheme_type>(
                            //         evaluation_points_input,
                            //         proof.eval_proof.lookups[1],
                            //         proof.input_perm_commitment,
                            //         fri_params,
                            //         transcript)) {
                            //     return false;
                            // }

                            // std::vector<typename FieldType::value_type> evaluation_points_value = {challenge};
                            // if (!algorithms::verify_eval<permutation_commitment_scheme_type>(
                            //         evaluation_points_value,
                            //         proof.eval_proof.lookups[2],
                            //         proof.value_perm_commitment,
                            //         fri_params,
                            //         transcript)) {
                            //     return false;
                            // }
                        }

                        std::vector<typename FieldType::value_type> challenge_point = {challenge};

                        // quotient
                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_quotient = {challenge_point};

                        // public data
                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_public;

                        for (std::size_t k = 0; k < preprocessed_public_data.identity_polynomials.size(); k++) {
                            evaluation_points_public.push_back(challenge_point);
                        }
                        
                        for (std::size_t k = 0; k < preprocessed_public_data.identity_polynomials.size(); k++) {
                            evaluation_points_public.push_back(challenge_point);
                        }

                        // constant columns may be rotated
                        for (std::size_t k = 0; k < constant_columns; k ++){
                            std::set<int> rotations =
                                preprocessed_public_data.common_data.columns_rotations[witness_columns + public_input_columns + k];
                            std::vector<typename FieldType::value_type> point;

                            for (int rotation: rotations) {
                                point.push_back( challenge * omega.pow(rotation));
                            }
                            evaluation_points_public.push_back(point);
                        }
                        
                        // selector columns may be rotated
                        for (std::size_t k = 0; k < selector_columns; k ++){
                            std::set<int> rotations =
                                preprocessed_public_data.common_data.columns_rotations[witness_columns + public_input_columns + constant_columns + k];
                            std::vector<typename FieldType::value_type> point;

                            for (int rotation: rotations) {
                                point.push_back( challenge * omega.pow(rotation));
                            }
                            evaluation_points_public.push_back(point);
                        }

                        // Evaluation points for special selectors q_last and q_blind
                        evaluation_points_public.push_back(challenge_point); // for q_last
                        evaluation_points_public.push_back(challenge_point); // for q_blind

                        std::array<std::vector<std::vector<typename FieldType::value_type>>, 4> evaluations_points =
                        {variable_values_evaluation_points, evaluation_points_permutation, evaluation_points_quotient, evaluation_points_public};
                        std::array<typename commitment_scheme_type::commitment_type, 4> commitments = 
                        {proof.variable_values_commitment, 
                         proof.v_perm_commitment,
                         proof.T_commitment, 
                         preprocessed_public_data.common_data.commitments.fixed_values
                        };
                        
                        if( proof.fixed_values_commitment != preprocessed_public_data.common_data.commitments.fixed_values )
                            return false;

                        if (!algorithms::verify_eval<commitment_scheme_type>(
                            evaluations_points,
                            proof.eval_proof.combined_value,
                            commitments,
                            fri_params, transcript)
                        ) {
                            return false;
                        }

                        // 10. final check
                        std::array<typename FieldType::value_type, f_parts> F;
                        F[0] = permutation_argument[0];
                        F[1] = permutation_argument[1];
                        F[2] = permutation_argument[2];
                        F[3] = lookup_argument[0];
                        F[4] = lookup_argument[1];
                        F[5] = lookup_argument[2];
                        F[6] = lookup_argument[3];
                        F[7] = lookup_argument[4];
                        F[8] = gate_argument[0];

                        typename FieldType::value_type F_consolidated = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < f_parts; i++) {
                            F_consolidated = F_consolidated + alphas[i] * F[i];
                        }

                        typename FieldType::value_type T_consolidated = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < proof.eval_proof.combined_value.z[2].size(); i++) {
                            T_consolidated = T_consolidated + proof.eval_proof.combined_value.z[2][i][0] *
                                                                  challenge.pow((fri_params.max_degree + 1) * i);
                        }

                        // Z is polynomial -1, 0 ...., 0, 1
                        typename FieldType::value_type Z_at_challenge = preprocessed_public_data.common_data.Z.evaluate(challenge);                     
                        if (F_consolidated != Z_at_challenge * T_consolidated) {
                            return false;
                        }

                        return true;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_VERIFIER_HPP
