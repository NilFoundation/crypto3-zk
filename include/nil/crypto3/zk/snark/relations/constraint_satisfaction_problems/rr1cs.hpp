//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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
// @file Declaration of interfaces for:
//
// - a relaxed R1CS constraint,
// - a relaxed R1CS variable assignment, and
// - a relaxed R1CS constraint system.
//
// Above, R1CS stands for "Rank-1 Constraint System".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_RR1CS_HPP
#define CRYPTO3_ZK_RR1CS_HPP

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <nil/crypto3/zk/snark/relations/variable.hpp>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /*!
                 * @brief
                 * @tparam FieldType
                 *
                 * A Relaxed R1CS constraint is a formal expression of the form
                 *
                 *                < A , X > * < B , X > = < C , X > + E,
                 *
                 * where X = (x_0,x_1,...,x_m) is a vector of formal variables and A,B,C each
                 * consist of 1+m elements in <FieldType>.
                 *
                 * A Relaxed R1CS constraint is used to construct a Relaxed R1CS constraint system (see below).
                 *
                 * @see https://eprint.iacr.org/2021/370.pdf
                 */
                template<typename FieldType>
                struct rr1cs_constraint {
                    typedef FieldType field_type;

                    linear_combination<FieldType> a, b, c;
                    std::vector<typename FieldType::value_type> e;

                    rr1cs_constraint() = default;

                    rr1cs_constraint(const r1cs_constaint<FieldType> &r1cs) :
                        a(r1cs.a), b(r1cs.b), c(r1cs.c), e(typename FieldType::value_type::zero()) {
                    }

                    rr1cs_constraint(const linear_combination<FieldType> &a,
                                     const linear_combination<FieldType> &b,
                                     const linear_combination<FieldType> &c,
                                     const std::vector<typename FieldType::value> &e) :
                        a(a),
                        b(b), c(c), e(e) {
                    }

                    rr1cs_constraint(const std::initializer_list<linear_combination<FieldType>> &A,
                                     const std::initializer_list<linear_combination<FieldType>> &B,
                                     const std::initializer_list<linear_combination<FieldType>> &C,
                                     const std::initializer_list<std::vector<typename FieldType::value>> &E) {
                        for (auto lc_A : A) {
                            a.terms.insert(a.terms.end(), lc_A.terms.begin(), lc_A.terms.end());
                        }
                        for (auto lc_B : B) {
                            b.terms.insert(b.terms.end(), lc_B.terms.begin(), lc_B.terms.end());
                        }
                        for (auto lc_C : C) {
                            c.terms.insert(c.terms.end(), lc_C.terms.begin(), lc_C.terms.end());
                        }
                        for (auto ie : E) {
                            e.insert(e.end(), ie.begin(), ie.end());
                        }
                    }

                    bool operator==(const rr1cs_constraint<FieldType> &other) const {
                        return (this->a == other.a && this->b == other.b && this->c == other.c && this->e == other.e);
                    }
                };

                /**
                 * A Committed Relaxed R1CS constraint is a formal expression of the form
                 *
                 *                < A , X > * < B , X > = < C , X > + E,
                 *
                 * where X = (x_0,x_1,...,x_m) is a vector of formal variables and A,B,C each
                 * consist of 1+m elements in <FieldType>.
                 *
                 * A Committed Relaxed R1CS constraint is used to construct a Relaxed R1CS constraint system (see below).
                 */
                 /*!
                  * @brief
                  * @tparam FieldType
                  */
                template<typename FieldType>
                struct committed_rr1cs_constraint {
                    typedef FieldType field_type;

                    linear_combination<FieldType> a, b, c;
                    std::vector<typename FieldType::value_type> e;

                    committed_rr1cs_constraint() = default;

                    committed_rr1cs_constraint(const r1cs_constaint<FieldType> &r1cs) :
                        a(r1cs.a), b(r1cs.b), c(r1cs.c), e(typename FieldType::value_type::zero()) {
                    }

                    committed_rr1cs_constraint(const linear_combination<FieldType> &a,
                                              const linear_combination<FieldType> &b,
                                              const linear_combination<FieldType> &c,
                                              const std::vector<typename FieldType::value> &e) :
                        a(a),
                        b(b), c(c), e(e) {
                    }

                    committed_rr1cs_constraint(const std::initializer_list<linear_combination<FieldType>> &A,
                                              const std::initializer_list<linear_combination<FieldType>> &B,
                                              const std::initializer_list<linear_combination<FieldType>> &C,
                                              const std::initializer_list<std::vector<typename FieldType::value>> &E) {
                        for (auto lc_A : A) {
                            a.terms.insert(a.terms.end(), lc_A.terms.begin(), lc_A.terms.end());
                        }
                        for (auto lc_B : B) {
                            b.terms.insert(b.terms.end(), lc_B.terms.begin(), lc_B.terms.end());
                        }
                        for (auto lc_C : C) {
                            c.terms.insert(c.terms.end(), lc_C.terms.begin(), lc_C.terms.end());
                        }
                        for (auto ie : E) {
                            e.insert(e.end(), ie.begin(), ie.end());
                        }
                    }

                    bool operator==(const rr1cs_constraint<FieldType> &other) const {
                        return (this->a == other.a && this->b == other.b && this->c == other.c && this->e == other.e);
                    }
                };

                /************************* R1CS variable assignment **************************/

                /**
                 * A R1CS variable assignment is a vector of <FieldType> elements that represents
                 * a candidate solution to a R1CS constraint system (see below).
                 */

                /* TODO: specify that it does *NOT* include the constant 1 */
                template<typename FieldType>
                using rr1cs_primary_input = std::vector<typename FieldType::value_type>;

                template<typename FieldType>
                using rr1cs_auxiliary_input = std::vector<typename FieldType::value_type>;

                template<typename FieldType>
                using rr1cs_variable_assignment = std::vector<typename FieldType::value_type>;

                /************************* R1CS constraint system ****************************/

                /**
                 * A system of Relaxed R1CS constraints looks like
                 *
                 *     { < A_k , X > * < B_k , X > = E_k + < C_k , X > }_{k=1}^{n}  .
                 *
                 * In other words, the system is satisfied if and only if there exist a
                 * USCS variable assignment for which each R1CS constraint is satisfied.
                 *
                 * NOTE:
                 * The 0-th variable (i.e., "x_{0}") always represents the constant 1.
                 * Thus, the 0-th variable is not included in num_variables.
                 */
                template<typename FieldType>
                struct rr1cs_constraint_system {
                    typedef FieldType field_type;

                    std::size_t primary_input_size;
                    std::size_t auxiliary_input_size;

                    std::vector<rr1cs_constraint<FieldType>> constraints;

                    rr1cs_constraint_system(const r1cs_constraint_system<FieldType> &r1cs) :
                        primary_input_size(r1cs.primary_input_size), auxiliary_input_size(r1cs.auxiliary_input_size) {
                        for (const auto &v : r1cs.constraints) {
                            constraints.template emplace_back(v);
                        }
                    }

                    rr1cs_constraint_system() : primary_input_size(0), auxiliary_input_size(0) {
                    }

                    std::size_t num_inputs() const {
                        return primary_input_size;
                    }

                    std::size_t num_variables() const {
                        return primary_input_size + auxiliary_input_size;
                    }

                    std::size_t num_constraints() const {
                        return constraints.size();
                    }

                    bool is_valid() const {
                        if (this->num_inputs() > this->num_variables())
                            return false;

                        for (const auto &v : constraints) {
                            if (!(v.a.is_valid(this->num_variables()) && v.b.is_valid(this->num_variables()) &&
                                  v.c.is_valid(this->num_variables()))) {
                                return false;
                            }
                        }

                        return true;
                    }

                    bool is_satisfied(const r1cs_primary_input<FieldType> &primary_input,
                                      const r1cs_auxiliary_input<FieldType> &auxiliary_input) const {
                        BOOST_ASSERT(primary_input.size() == num_inputs());
                        BOOST_ASSERT(primary_input.size() + auxiliary_input.size() == num_variables());

                        rr1cs_variable_assignment<FieldType> full_variable_assignment = primary_input;
                        full_variable_assignment.insert(
                            full_variable_assignment.end(), auxiliary_input.begin(), auxiliary_input.end());

                        for (std::size_t c = 0; c < constraints.size(); ++c) {
                            const typename FieldType::value_type ares =
                                constraints[c].a.evaluate(full_variable_assignment);
                            const typename FieldType::value_type bres =
                                constraints[c].b.evaluate(full_variable_assignment);
                            const typename FieldType::value_type cres =
                                constraints[c].c.evaluate(full_variable_assignment);

                            if (!(ares * bres == cres)) {
                                return false;
                            }
                        }

                        return true;
                    }

                    void add_constraint(const r1cs_constraint<FieldType> &c) {
                        constraints.emplace_back(c);
                    }

                    void swap_AB_if_beneficial() {
                        std::vector<bool> touched_by_A(this->num_variables() + 1, false),
                            touched_by_B(this->num_variables() + 1, false);

                        for (std::size_t i = 0; i < this->constraints.size(); ++i) {
                            for (std::size_t j = 0; j < this->constraints[i].a.terms.size(); ++j) {
                                touched_by_A[this->constraints[i].a.terms[j].index] = true;
                            }

                            for (std::size_t j = 0; j < this->constraints[i].b.terms.size(); ++j) {
                                touched_by_B[this->constraints[i].b.terms[j].index] = true;
                            }
                        }

                        std::size_t non_zero_A_count = 0, non_zero_B_count = 0;
                        for (std::size_t i = 0; i < this->num_variables() + 1; ++i) {
                            non_zero_A_count += touched_by_A[i] ? 1 : 0;
                            non_zero_B_count += touched_by_B[i] ? 1 : 0;
                        }

                        if (non_zero_B_count > non_zero_A_count) {
                            for (std::size_t i = 0; i < this->constraints.size(); ++i) {
                                std::swap(this->constraints[i].a, this->constraints[i].b);
                            }
                        }
                    }

                    bool operator==(const rr1cs_constraint_system<FieldType> &other) const {
                        return (this->constraints == other.constraints &&
                                this->primary_input_size == other.primary_input_size &&
                                this->auxiliary_input_size == other.auxiliary_input_size);
                    }
                };

                /**
                 * A system of Commited Relaxed R1CS constraints looks like
                 *
                 *     { < A_k , X > * < B_k , X > = E_k + < C_k , X > }_{k=1}^{n}  .
                 *
                 * In other words, the system is satisfied if and only if there exist a
                 * USCS variable assignment for which each R1CS constraint is satisfied.
                 *
                 * NOTE:
                 * The 0-th variable (i.e., "x_{0}") always represents the constant 1.
                 * Thus, the 0-th variable is not included in num_variables.
                 */
                template<typename FieldType>
                struct committed_rr1cs_constraint_system {
                    typedef FieldType field_type;

                    std::size_t primary_input_size;
                    std::size_t auxiliary_input_size;

                    std::vector<rr1cs_constraint<FieldType>> constraints;

                    committed_rr1cs_constraint_system(const r1cs_constraint_system<FieldType> &r1cs) :
                        primary_input_size(r1cs.primary_input_size), auxiliary_input_size(r1cs.auxiliary_input_size) {
                        for (const auto &v : r1cs.constraints) {
                            constraints.template emplace_back(v);
                        }
                    }

                    committed_rr1cs_constraint_system() : primary_input_size(0), auxiliary_input_size(0) {
                    }

                    std::size_t num_inputs() const {
                        return primary_input_size;
                    }

                    std::size_t num_variables() const {
                        return primary_input_size + auxiliary_input_size;
                    }

                    std::size_t num_constraints() const {
                        return constraints.size();
                    }

                    bool is_valid() const {
                        if (this->num_inputs() > this->num_variables())
                            return false;

                        for (const auto &v : constraints) {
                            if (!(v.a.is_valid(this->num_variables()) && v.b.is_valid(this->num_variables()) &&
                                  v.c.is_valid(this->num_variables()))) {
                                return false;
                            }
                        }

                        return true;
                    }

                    bool is_satisfied(const r1cs_primary_input<FieldType> &primary_input,
                                      const r1cs_auxiliary_input<FieldType> &auxiliary_input) const {
                        BOOST_ASSERT(primary_input.size() == num_inputs());
                        BOOST_ASSERT(primary_input.size() + auxiliary_input.size() == num_variables());

                        rr1cs_variable_assignment<FieldType> full_variable_assignment = primary_input;
                        full_variable_assignment.insert(
                            full_variable_assignment.end(), auxiliary_input.begin(), auxiliary_input.end());

                        for (std::size_t c = 0; c < constraints.size(); ++c) {
                            const typename FieldType::value_type ares =
                                constraints[c].a.evaluate(full_variable_assignment);
                            const typename FieldType::value_type bres =
                                constraints[c].b.evaluate(full_variable_assignment);
                            const typename FieldType::value_type cres =
                                constraints[c].c.evaluate(full_variable_assignment);

                            if (!(ares * bres == cres)) {
                                return false;
                            }
                        }

                        return true;
                    }

                    void add_constraint(const r1cs_constraint<FieldType> &c) {
                        constraints.emplace_back(c);
                    }

                    void swap_AB_if_beneficial() {
                        std::vector<bool> touched_by_A(this->num_variables() + 1, false),
                            touched_by_B(this->num_variables() + 1, false);

                        for (std::size_t i = 0; i < this->constraints.size(); ++i) {
                            for (std::size_t j = 0; j < this->constraints[i].a.terms.size(); ++j) {
                                touched_by_A[this->constraints[i].a.terms[j].index] = true;
                            }

                            for (std::size_t j = 0; j < this->constraints[i].b.terms.size(); ++j) {
                                touched_by_B[this->constraints[i].b.terms[j].index] = true;
                            }
                        }

                        std::size_t non_zero_A_count = 0, non_zero_B_count = 0;
                        for (std::size_t i = 0; i < this->num_variables() + 1; ++i) {
                            non_zero_A_count += touched_by_A[i] ? 1 : 0;
                            non_zero_B_count += touched_by_B[i] ? 1 : 0;
                        }

                        if (non_zero_B_count > non_zero_A_count) {
                            for (std::size_t i = 0; i < this->constraints.size(); ++i) {
                                std::swap(this->constraints[i].a, this->constraints[i].b);
                            }
                        }
                    }

                    bool operator==(const committed_rr1cs_constraint_system<FieldType> &other) const {
                        return (this->constraints == other.constraints &&
                                this->primary_input_size == other.primary_input_size &&
                                this->auxiliary_input_size == other.auxiliary_input_size);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_HPP
