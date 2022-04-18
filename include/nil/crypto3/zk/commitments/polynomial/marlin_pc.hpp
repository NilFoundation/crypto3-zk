//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_COMMITMENTS_MARLIN_PC_HPP
#define CRYPTO3_ZK_COMMITMENTS_MARLIN_PC_HPP

#include <tuple>
#include <vector>
#include <numeric>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/iterator/zip_iterator.hpp>
#include <boost/accumulators/accumulators.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/pairing/pairing_policy.hpp>

using namespace nil::crypto3::math;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                struct marlin_pc {

                    typedef CurveType curve_type;
                    typedef algebra::pairing::pairing_policy<curve_type> pairing;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    using base_field_value_type = typename curve_type::base_field_type::value_type;
                    using scalar_field_value_type = typename curve_type::scalar_field_type::value_type;

                    using commitment_key_type =
                        std::pair<std::vector<typename curve_type::template g1_type<>::value_type>,
                                  std::vector<typename curve_type::template g1_type<>::value_type>>;
                    using verification_key_type = std::pair<typename curve_type::template g1_type<>::value_type,
                                                            typename curve_type::template g2_type<>::value_type>;
                    using commitment_type = typename curve_type::template g1_type<>::value_type;
                    using proof_type = commitment_type;

                    struct params_type {
                        base_field_value_type beta;

                        base_field_value_type gamma;
                    };

                    static std::pair<commitment_key_type, verification_key_type>
                        setup(const std::size_t n,
                              params_type params,
                              typename curve_type::template g1_type<>::value_type g =
                                  curve_type::template g1_type<>::value_type::one(),
                              typename curve_type::template g1_type<>::value_type gamma_g =
                                  curve_type::template g1_type<>::value_type::one()) {

                        commitment_key_type commitment_key =
                            std::make_pair(std::vector<typename curve_type::template g1_type<>::value_type> {g},
                                           std::vector<typename curve_type::template g1_type<>::value_type> {gamma_g});
                        verification_key_type verification_key =
                            std::make_pair(gamma_g, curve_type::template g2_type<>::value_type::one() * params.beta);

                        for (std::size_t i = 0; i < n; i++) {
                            std::get<0>(commitment_key).push_back(params.beta * std::get<0>(commitment_key)[i]);

                            std::get<1>(commitment_key).push_back(params.beta * std::get<1>(commitment_key)[i]);
                        }
                        return std::make_pair(commitment_key, verification_key);
                    }

                    static std::pair<std::vector<std::pair<commitment_type, commitment_type>>,
                                     std::vector<std::pair<commitment_type, commitment_type>>>
                        commit(const commitment_key_type &commitment_key, const size_t &n, const std::vector<size_t> &d,
                               const std::vector<polynomial<base_field_value_type>> &f,
                               const std::vector<polynomial<base_field_value_type>> &w,
                               const std::vector<polynomial<base_field_value_type>> &ws) {

                        std::vector<std::pair<commitment_type, commitment_type>> c;
                        std::vector<std::pair<commitment_type, commitment_type>> r;
                        std::pair<commitment_type, commitment_type> commitment;
                        std::pair<commitment_type, commitment_type> commitment_shifted;
                        std::size_t shift_power;
                        for (size_t i = 0; i < f.size(); i++) {
                            commitment = commit_s(commitment_key, f[i], w[i], 0);
                            shift_power = n - d[i];
                            commitment_shifted = commit_s(commitment_key, f[i], ws[i], shift_power);
                            c.push_back(std::make_pair(commitment.first, commitment_shifted.first));
                            r.push_back(std::make_pair(commitment.second, commitment_shifted.second));
                        }
                        return std::make_pair(c, r);
                    }

                    static polynomial<base_field_value_type>
                        shift_polynomial_coeffs(const polynomial<base_field_value_type> &p, std::size_t shift) {
                        std::vector<base_field_value_type> v(shift, base_field_value_type(0));
                        v.insert(v.end(), p.data.begin(), p.data.end());
                        polynomial<base_field_value_type> p_shifted = v;
                        return p_shifted;
                    }

                    static std::pair<commitment_type, commitment_type>
                        commit_s(const commitment_key_type &commitment_key,
                                 const polynomial<base_field_value_type> &f,
                                 const polynomial<base_field_value_type> &w,
                                 std::size_t shift_powers) {

                        commitment_type commitment = f[0] * commitment_key.first[shift_powers];
                        commitment_type randomness = w[0] * commitment_key.second[shift_powers];

                        for (std::size_t i = 1; i < f.size(); i++) {
                            commitment = commitment + f[i] * commitment_key.first[i + shift_powers];
                        }
                        for (std::size_t i = 1; i < w.size(); i++) {
                            randomness = randomness + w[i] * commitment_key.second[i + shift_powers];
                        }
                        return std::make_pair(commitment, randomness);
                    }

                    static std::pair<proof_type, base_field_value_type>
                        proof_eval(const commitment_key_type &commitment_key, size_t n, std::vector<size_t> &d,
                                   typename curve_type::base_field_type::value_type x,
                                   std::vector<typename curve_type::base_field_type::value_type> y,
                                   base_field_value_type eps, const std::vector<polynomial<base_field_value_type>> &f,
                                   const std::vector<polynomial<base_field_value_type>> &w) {
                        polynomial<base_field_value_type> q = {0};
                        polynomial<base_field_value_type> q_shifted = {0};
                        polynomial<base_field_value_type> p = {0};
                        polynomial<base_field_value_type> p_shifted = {0};
                        polynomial<base_field_value_type> wp;

                        std::vector<base_field_value_type> shift(n + 1, base_field_value_type(0));

                        polynomial<base_field_value_type> x_shift;

                        base_field_value_type eps_scaled = eps;
                        for (size_t i = 0; i < f.size(); i++) {

                            wp = create_witness(x, y[i], f[i]);

                            x_shift = wp;
                            for (size_t j = 0; j < x_shift.size(); j++) {
                                x_shift[j] = x_shift[j] * eps_scaled;
                            }
                            q = q + x_shift;

                            x_shift = w[i];
                            for (size_t j = 0; j < x_shift.size(); j++) {
                                x_shift[j] = x_shift[j] * eps_scaled;
                            }
                            p = p + x_shift;
                            eps_scaled = eps_scaled * eps;
                        }
                        for (size_t i = 0; i < w.size(); i++) {
                            shift = {};
                            shift.insert(shift.begin(), n - d[i], base_field_value_type(0));
                            shift.insert(shift.end(), f[i].begin(), f[i].end());
                            shift[n - d[i]] = shift[n - d[i]] + y[i];
                            x_shift = create_witness(x, polynomial<base_field_value_type>(shift).evaluate(x),
                                                     polynomial<base_field_value_type>(shift));
                            for (size_t j = 0; j < x_shift.size(); j++) {
                                x_shift[j] = x_shift[j] * eps_scaled;
                            }
                            q_shifted = q_shifted + x_shift;
                            shift = {};
                            shift.insert(shift.begin(), n - d[i], base_field_value_type(0));
                            shift.insert(shift.end(), w[i].begin(), w[i].end());
                            x_shift = shift;
                            for (size_t j = 0; j < x_shift.size(); j++) {
                                x_shift[j] = x_shift[j] * eps_scaled;
                            }
                            p_shifted = p_shifted + x_shift;
                            eps_scaled = eps_scaled * eps;
                        }

                        polynomial<base_field_value_type> p_res =
                            (p - p.evaluate(x) + p_shifted - p_shifted.evaluate(x)) /
                            polynomial<base_field_value_type> {-x, 1};
                        return std::make_pair(commit_s(commitment_key, q + q_shifted, p_res),
                                              p.evaluate(x) + p_shifted.evaluate(x));
                    }

                    static polynomial<base_field_value_type>
                        create_witness(typename curve_type::base_field_type::value_type x,
                                       typename curve_type::base_field_type::value_type y,
                                       const polynomial<base_field_value_type> &f) {

                        const polynomial<base_field_value_type> denominator_polynom = {-x, 1};

                        const polynomial<base_field_value_type> q =
                            (f - polynomial<base_field_value_type> {y}) / denominator_polynom;

                        return q;
                    }

                    static bool verify_eval(const std::pair<commitment_key_type, verification_key_type> &keys,
                                            typename curve_type::base_field_type::value_type x,
                                            std::vector<typename curve_type::base_field_type::value_type> y,
                                            base_field_value_type eps,
                                            std::vector<std::pair<commitment_type, commitment_type>> C_f,
                                            std::pair<proof_type, base_field_value_type> p, std::vector<size_t> d,
                                            size_t n) {
                        base_field_value_type eps_scaled = eps;
                        commitment_type cl = eps_scaled * std::get<0>(C_f[0]);
                        for (size_t i = 1; i < C_f.size(); i++) {
                            eps_scaled = eps_scaled * eps;
                            cl = cl + eps_scaled * std::get<0>(C_f[i]);
                        }
                        eps_scaled = eps_scaled * eps;
                        commitment_type cr =
                            eps_scaled * (std::get<1>(C_f[0]) - y[0] * std::get<0>(std::get<0>(keys))[n - d[0]]);
                        for (size_t i = 1; i < C_f.size(); i++) {
                            eps_scaled = eps_scaled * eps;
                            cr = cr +
                                 eps_scaled * (std::get<1>(C_f[i]) - y[i] * std::get<0>(std::get<0>(keys))[n - d[i]]);
                        }
                        base_field_value_type Y = base_field_value_type(0);
                        eps_scaled = eps;
                        for (size_t i = 0; i < y.size(); i++) {
                            Y = Y + eps_scaled * y[i];
                            eps_scaled = eps_scaled * eps;
                        }

                        commitment_type C = cl + cr;
                        typename curve_type::gt_type::value_type gt1 =
                            algebra::pair<curve_type>(C - std::get<0>(std::get<1>(keys)) * std::get<1>(p) -
                                                          curve_type::template g1_type<>::value_type::one() * Y,
                                                      curve_type::template g2_type<>::value_type::one());

                        typename curve_type::gt_type::value_type gt2 = algebra::pair<curve_type>(
                            std::get<0>(p),
                            std::get<1>(std::get<1>(keys)) - curve_type::template g2_type<>::value_type::one() * x);

                        return gt1 == gt2;
                    }
                };
            };    // namespace snark
        }         // namespace zk
    }             // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_MARLIN_PC_HPP
