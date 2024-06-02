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
// @file Declaration of interfaces for trace-line variables.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TRACE_LINES_HPP_
#define CRYPTO3_ZK_TRACE_LINES_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/components/basic_components.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A memory line contains variables for the following:
                 * - timestamp
                 * - address
                 * - contents_before
                 * - contents_after
                 *
                 * Memory lines are used by memory_checker_component.
                 */
                template<typename RAMType>
                class memory_line_variable_component : public ram_component_base<RAMType> {
                public:
                    typedef ram_base_field<RAMType> FieldType;

                    std::shared_ptr<dual_variable_component<FieldType>> timestamp;
                    std::shared_ptr<dual_variable_component<FieldType>> address;
                    std::shared_ptr<dual_variable_component<FieldType>> contents_before;
                    std::shared_ptr<dual_variable_component<FieldType>> contents_after;

                public:
                    memory_line_variable_component(ram_blueprint<RAMType> &pb,
                                                   const std::size_t timestamp_size,
                                                   const ram_architecture_params<RAMType> &ap);

                    void generate_r1cs_constraints(const bool enforce_bitness = false);
                    void generate_r1cs_witness_from_bits();
                    void generate_r1cs_witness_from_packed();

                    blueprint_variable_vector<FieldType> all_vars() const;
                };

                /**
                 * An execution line inherits from a memory line and, in addition, contains
                 * variables for a CPU state and for a flag denoting if the machine has accepted.
                 *
                 * Execution lines are used by execution_checker_component.
                 */
                template<typename RAMType>
                class execution_line_variable_component : public memory_line_variable_component<RAMType> {
                public:
                    typedef ram_base_field<RAMType> FieldType;

                    blueprint_variable_vector<FieldType> cpu_state;
                    variable<FieldType> has_accepted;

                    execution_line_variable_component(ram_blueprint<RAMType> &pb,
                                                      const std::size_t timestamp_size,
                                                      const ram_architecture_params<RAMType> &ap);
                };

                template<typename RAMType>
                memory_line_variable_component<RAMType>::memory_line_variable_component(
                    ram_blueprint<RAMType> &pb,
                    const std::size_t timestamp_size,
                    const ram_architecture_params<RAMType> &ap) :
                    ram_component_base<RAMType>(pb) {
                    const std::size_t address_size = ap.address_size();
                    const std::size_t value_size = ap.value_size();

                    timestamp.reset(new dual_variable_component<FieldType>(pb, timestamp_size));
                    address.reset(new dual_variable_component<FieldType>(pb, address_size));
                    contents_before.reset(new dual_variable_component<FieldType>(pb, value_size));
                    contents_after.reset(new dual_variable_component<FieldType>(pb, value_size));
                }

                template<typename RAMType>
                void memory_line_variable_component<RAMType>::generate_r1cs_constraints(const bool enforce_bitness) {
                    timestamp->generate_r1cs_constraints(enforce_bitness);
                    address->generate_r1cs_constraints(enforce_bitness);
                    contents_before->generate_r1cs_constraints(enforce_bitness);
                    contents_after->generate_r1cs_constraints(enforce_bitness);
                }

                template<typename RAMType>
                void memory_line_variable_component<RAMType>::generate_r1cs_witness_from_bits() {
                    timestamp->generate_r1cs_witness_from_bits();
                    address->generate_r1cs_witness_from_bits();
                    contents_before->generate_r1cs_witness_from_bits();
                    contents_after->generate_r1cs_witness_from_bits();
                }

                template<typename RAMType>
                void memory_line_variable_component<RAMType>::generate_r1cs_witness_from_packed() {
                    timestamp->generate_r1cs_witness_from_packed();
                    address->generate_r1cs_witness_from_packed();
                    contents_before->generate_r1cs_witness_from_packed();
                    contents_after->generate_r1cs_witness_from_packed();
                }

                template<typename RAMType>
                blueprint_variable_vector<ram_base_field<RAMType>> memory_line_variable_component<RAMType>::all_vars() const {
                    blueprint_variable_vector<FieldType> r;
                    r.insert(r.end(), timestamp->bits.begin(), timestamp->bits.end());
                    r.insert(r.end(), address->bits.begin(), address->bits.end());
                    r.insert(r.end(), contents_before->bits.begin(), contents_before->bits.end());
                    r.insert(r.end(), contents_after->bits.begin(), contents_after->bits.end());

                    return r;
                }

                template<typename RAMType>
                execution_line_variable_component<RAMType>::execution_line_variable_component(
                    ram_blueprint<RAMType> &pb,
                    const std::size_t timestamp_size,
                    const ram_architecture_params<RAMType> &ap) :
                    memory_line_variable_component<RAMType>(pb, timestamp_size, ap) {
                    const std::size_t cpu_state_size = ap.cpu_state_size();

                    cpu_state.allocate(pb, cpu_state_size);
                    has_accepted.allocate(pb);
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // TRACE_LINES_HPP_
