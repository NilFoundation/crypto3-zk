//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for the FOORAM CPU checker component.
//
// The component checks the correct operation for the CPU of the FOORAM architecture.
//
// In FOORAM, the only instruction is FOO(x) and its encoding is x.
// The instruction FOO(x) has the following semantics:
// - if x is odd: reg <- [2*x+(pc+1)]
// - if x is even: [pc+x] <- reg+pc
// - increment pc by 1
//
// Starting from empty memory, FOORAM performs non-trivial pseudo-random computation
// that exercises both loads, stores, and instruction fetches.
//
// E.g. for the first 200 steps on 16 cell machine we get 93 different memory configurations.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_FOORAM_CPU_CHECKER_HPP
#define CRYPTO3_ZK_FOORAM_CPU_CHECKER_HPP

#include <cstddef>
#include <memory>

#include <nil/crypto3/zk/snark/component.hpp>
#include <nil/crypto3/zk/snark/components/basic_components.hpp>
#include <nil/crypto3/zk/snark/components/cpu_checkers/fooram/components/bar_component.hpp>
#include <nil/crypto3/zk/snark/components/cpu_checkers/fooram/components/fooram_blueprint.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/memory/memory_interface.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class fooram_cpu_checker : public fooram_component<FieldType> {
                public:
                    blueprint_variable_vector<FieldType> prev_pc_addr;
                    blueprint_variable_vector<FieldType> prev_pc_val;
                    blueprint_variable_vector<FieldType> prev_state;
                    blueprint_variable_vector<FieldType> guess;
                    blueprint_variable_vector<FieldType> ls_addr;
                    blueprint_variable_vector<FieldType> ls_prev_val;
                    blueprint_variable_vector<FieldType> ls_next_val;
                    blueprint_variable_vector<FieldType> next_state;
                    blueprint_variable_vector<FieldType> next_pc_addr;
                    variable<FieldType> next_has_accepted;

                    blueprint_variable<FieldType> zero;
                    blueprint_variable<FieldType> packed_next_pc_addr;
                    blueprint_linear_combination_vector<FieldType> one_as_addr;
                    std::shared_ptr<packing_component<FieldType>> pack_next_pc_addr;

                    blueprint_variable<FieldType> packed_load_addr;
                    blueprint_variable<FieldType> packed_store_addr;
                    blueprint_variable<FieldType> packed_store_val;

                    std::shared_ptr<bar_component<FieldType>> increment_pc;
                    std::shared_ptr<bar_component<FieldType>> compute_packed_load_addr;
                    std::shared_ptr<bar_component<FieldType>> compute_packed_store_addr;
                    std::shared_ptr<bar_component<FieldType>> compute_packed_store_val;

                    blueprint_variable<FieldType> packed_ls_addr;
                    blueprint_variable<FieldType> packed_ls_prev_val;
                    blueprint_variable<FieldType> packed_ls_next_val;
                    blueprint_variable<FieldType> packed_prev_state;
                    blueprint_variable<FieldType> packed_next_state;
                    std::shared_ptr<packing_component<FieldType>> pack_ls_addr;
                    std::shared_ptr<packing_component<FieldType>> pack_ls_prev_val;
                    std::shared_ptr<packing_component<FieldType>> pack_ls_next_val;
                    std::shared_ptr<packing_component<FieldType>> pack_prev_state;
                    std::shared_ptr<packing_component<FieldType>> pack_next_state;

                    fooram_cpu_checker(fooram_blueprint<FieldType> &pb,
                                       blueprint_variable_vector<FieldType> &prev_pc_addr,
                                       blueprint_variable_vector<FieldType> &prev_pc_val,
                                       blueprint_variable_vector<FieldType> &prev_state,
                                       blueprint_variable_vector<FieldType> &ls_addr,
                                       blueprint_variable_vector<FieldType> &ls_prev_val,
                                       blueprint_variable_vector<FieldType> &ls_next_val,
                                       blueprint_variable_vector<FieldType> &next_state,
                                       blueprint_variable_vector<FieldType> &next_pc_addr,
                                       blueprint_variable<FieldType> &next_has_accepted);

                    void generate_r1cs_constraints();

                    void generate_r1cs_witness() {
                        assert(0);
                    }

                    void generate_r1cs_witness_address();

                    void generate_r1cs_witness_other(fooram_input_tape_iterator &aux_it,
                                                     const fooram_input_tape_iterator &aux_end);

                    void dump() const;
                };

                template<typename FieldType>
                fooram_cpu_checker<FieldType>::fooram_cpu_checker(fooram_blueprint<FieldType> &pb,
                                                                  blueprint_variable_vector<FieldType> &prev_pc_addr,
                                                                  blueprint_variable_vector<FieldType> &prev_pc_val,
                                                                  blueprint_variable_vector<FieldType> &prev_state,
                                                                  blueprint_variable_vector<FieldType> &ls_addr,
                                                                  blueprint_variable_vector<FieldType> &ls_prev_val,
                                                                  blueprint_variable_vector<FieldType> &ls_next_val,
                                                                  blueprint_variable_vector<FieldType> &next_state,
                                                                  blueprint_variable_vector<FieldType> &next_pc_addr,
                                                                  blueprint_variable<FieldType> &next_has_accepted) :
                    fooram_component<FieldType>(pb),
                    prev_pc_addr(prev_pc_addr), prev_pc_val(prev_pc_val), prev_state(prev_state), ls_addr(ls_addr),
                    ls_prev_val(ls_prev_val), ls_next_val(ls_next_val), next_state(next_state),
                    next_pc_addr(next_pc_addr), next_has_accepted(next_has_accepted) {
                    /* increment PC */
                    packed_next_pc_addr.allocate(pb);
                    pack_next_pc_addr.reset(new packing_component<FieldType>(pb, next_pc_addr, packed_next_pc_addr));

                    one_as_addr.resize(next_pc_addr.size());
                    one_as_addr[0].assign(this->pb, 1);
                    for (std::size_t i = 1; i < next_pc_addr.size(); ++i) {
                        one_as_addr[i].assign(this->pb, 0);
                    }

                    /* packed_next_pc_addr = prev_pc_addr + one_as_addr */
                    increment_pc.reset(new bar_component<FieldType>(
                        pb, prev_pc_addr, FieldType::value_type::zero(), one_as_addr, FieldType::value_type::zero(), packed_next_pc_addr));

                    /* packed_store_addr = prev_pc_addr + prev_pc_val */
                    packed_store_addr.allocate(pb);
                    compute_packed_store_addr.reset(new bar_component<FieldType>(
                        pb, prev_pc_addr, FieldType::value_type::zero(), prev_pc_val, FieldType::value_type::zero(), packed_store_addr));

                    /* packed_load_addr = 2 * x + next_pc_addr */
                    packed_load_addr.allocate(pb);
                    compute_packed_load_addr.reset(new bar_component<FieldType>(
                        pb, prev_pc_val, typename FieldType::value_type(2), next_pc_addr, FieldType::value_type::zero(), packed_load_addr));

                    /*
                      packed_ls_addr = x0 * packed_load_addr + (1-x0) * packed_store_addr
                      packed_ls_addr ~ ls_addr
                    */
                    packed_ls_addr.allocate(pb);
                    pack_ls_addr.reset(new packing_component<FieldType>(pb, ls_addr, packed_ls_addr));

                    /* packed_store_val = prev_state_bits + prev_pc_addr */
                    packed_store_val.allocate(pb);
                    compute_packed_store_val.reset(new bar_component<FieldType>(
                        pb, prev_state, FieldType::value_type::zero(), prev_pc_addr, FieldType::value_type::zero(), packed_store_val));

                    /*
                      packed_ls_next_val = x0 * packed_ls_prev_val + (1-x0) * packed_store_val
                      packed_ls_next_val ~ ls_next_val
                    */
                    packed_ls_prev_val.allocate(pb);
                    pack_ls_prev_val.reset(new packing_component<FieldType>(this->pb, ls_prev_val, packed_ls_prev_val));
                    packed_ls_next_val.allocate(pb);
                    pack_ls_next_val.reset(new packing_component<FieldType>(this->pb, ls_next_val, packed_ls_next_val));

                    /*
                      packed_next_state = x0 * packed_ls_prev_val + (1-x0) * packed_prev_state
                      packed_next_state ~ next_state
                      packed_prev_state ~ prev_state
                    */
                    packed_prev_state.allocate(pb);
                    pack_prev_state.reset(new packing_component<FieldType>(pb, prev_state, packed_prev_state));

                    packed_next_state.allocate(pb);
                    pack_next_state.reset(new packing_component<FieldType>(pb, next_state, packed_next_state));

                    /* next_has_accepted = 1 */
                }

                template<typename FieldType>
                void fooram_cpu_checker<FieldType>::generate_r1cs_constraints() {
                    /* packed_next_pc_addr = prev_pc_addr + one_as_addr */
                    pack_next_pc_addr->generate_r1cs_constraints(false);
                    increment_pc->generate_r1cs_constraints();

                    /* packed_store_addr = prev_pc_addr + prev_pc_val */
                    compute_packed_store_addr->generate_r1cs_constraints();

                    /* packed_load_addr = 2 * x + next_pc_addr */
                    compute_packed_load_addr->generate_r1cs_constraints();

                    /*
                      packed_ls_addr = x0 * packed_load_addr + (1-x0) * packed_store_addr
                      packed_ls_addr - packed_store_addr = x0 * (packed_load_addr - packed_store_addr)
                      packed_ls_addr ~ ls_addr
                    */
                    pack_ls_addr->generate_r1cs_constraints(false);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        prev_pc_val[0], packed_load_addr - packed_store_addr, packed_ls_addr - packed_store_addr));

                    /* packed_store_val = prev_state_bits + prev_pc_addr */
                    compute_packed_store_val->generate_r1cs_constraints();

                    /*
                      packed_ls_next_val = x0 * packed_ls_prev_val + (1-x0) * packed_store_val
                      packed_ls_next_val - packed_store_val = x0 * (packed_ls_prev_val - packed_store_val)
                      packed_ls_next_val ~ ls_next_val
                    */
                    pack_ls_prev_val->generate_r1cs_constraints(false);
                    pack_ls_next_val->generate_r1cs_constraints(false);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        prev_pc_val[0], packed_ls_prev_val - packed_store_val, packed_ls_next_val - packed_store_val));

                    /*
                      packed_next_state = x0 * packed_ls_prev_val + (1-x0) * packed_prev_state
                      packed_next_state - packed_prev_state = x0 * (packed_ls_prev_val - packed_prev_state)
                      packed_next_state ~ next_state
                      packed_prev_state ~ prev_state
                    */
                    pack_prev_state->generate_r1cs_constraints(false);
                    pack_next_state->generate_r1cs_constraints(false);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        prev_pc_val[0], packed_ls_prev_val - packed_prev_state, packed_next_state - packed_prev_state));

                    /* next_has_accepted = 1 */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(1, next_has_accepted, 1));
                }

                template<typename FieldType>
                void fooram_cpu_checker<FieldType>::generate_r1cs_witness_address() {
                    one_as_addr.evaluate(this->pb);

                    /* packed_next_pc_addr = prev_pc_addr + one_as_addr */
                    increment_pc->generate_r1cs_witness();
                    pack_next_pc_addr->generate_r1cs_witness_from_packed();

                    /* packed_store_addr = prev_pc_addr + prev_pc_val */
                    compute_packed_store_addr->generate_r1cs_witness();

                    /* packed_load_addr = 2 * x + next_pc_addr */
                    compute_packed_load_addr->generate_r1cs_witness();

                    /*
                      packed_ls_addr = x0 * packed_load_addr + (1-x0) * packed_store_addr
                      packed_ls_addr - packed_store_addr = x0 * (packed_load_addr - packed_store_addr)
                      packed_ls_addr ~ ls_addr
                    */
                    this->pb.val(packed_ls_addr) =
                        (this->pb.val(prev_pc_val[0]) * this->pb.val(packed_load_addr) +
                         (FieldType::value_type::zero() - this->pb.val(prev_pc_val[0])) * this->pb.val(packed_store_addr));
                    pack_ls_addr->generate_r1cs_witness_from_packed();
                }

                template<typename FieldType>
                void fooram_cpu_checker<FieldType>::generate_r1cs_witness_other(
                    BOOST_ATTRIBUTE_UNUSED fooram_input_tape_iterator &aux_it,
                    BOOST_ATTRIBUTE_UNUSED const fooram_input_tape_iterator &aux_end) {
                    /* fooram memory contents do not depend on program/input. */

                    /* packed_store_val = prev_state_bits + prev_pc_addr */
                    compute_packed_store_val->generate_r1cs_witness();

                    /*
                      packed_ls_next_val = x0 * packed_ls_prev_val + (1-x0) * packed_store_val
                      packed_ls_next_val - packed_store_val = x0 * (packed_ls_prev_val - packed_store_val)
                      packed_ls_next_val ~ ls_next_val
                    */
                    pack_ls_prev_val->generate_r1cs_witness_from_bits();
                    this->pb.val(packed_ls_next_val) =
                        (this->pb.val(prev_pc_val[0]) * this->pb.val(packed_ls_prev_val) +
                         (FieldType::value_type::zero() - this->pb.val(prev_pc_val[0])) * this->pb.val(packed_store_val));
                    pack_ls_next_val->generate_r1cs_witness_from_packed();

                    /*
                      packed_next_state = x0 * packed_ls_prev_val + (1-x0) * packed_prev_state
                      packed_next_state - packed_prev_state = x0 * (packed_ls_prev_val - packed_prev_state)
                      packed_next_state ~ next_state
                      packed_prev_state ~ prev_state
                    */
                    pack_prev_state->generate_r1cs_witness_from_bits();
                    this->pb.val(packed_next_state) =
                        (this->pb.val(prev_pc_val[0]) * this->pb.val(packed_ls_prev_val) +
                         (FieldType::value_type::zero() - this->pb.val(prev_pc_val[0])) * this->pb.val(packed_prev_state));
                    pack_next_state->generate_r1cs_witness_from_packed();

                    /* next_has_accepted = 1 */
                    this->pb.val(next_has_accepted) = FieldType::value_type::zero();
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FOORAM_CPU_CHECKER_HPP
