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
// @file Declaration of interfaces for memory_checker_component, a component that verifies the
// consistency of two accesses to memory that are adjacent in a "memory sort".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MEMORY_CHECKER_COMPONENT_HPP
#define CRYPTO3_ZK_MEMORY_CHECKER_COMPONENT_HPP

#include <nil/crypto3/zk/snark/reductions/ram_to_r1cs/components/trace_lines.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename RAMType>
                class memory_checker_component : public ram_component_base<RAMType> {
                private:
                    typedef ram_base_field<RAMType> FieldType;

                    variable<FieldType> timestamps_leq;
                    variable<FieldType> timestamps_less;
                    std::shared_ptr<comparison_component<FieldType>> compare_timestamps;

                    variable<FieldType> addresses_eq;
                    variable<FieldType> addresses_leq;
                    variable<FieldType> addresses_less;
                    std::shared_ptr<comparison_component<FieldType>> compare_addresses;

                    variable<FieldType> loose_contents_after1_equals_contents_before2;
                    variable<FieldType> loose_contents_before2_equals_zero;
                    variable<FieldType> loose_timestamp2_is_zero;

                public:
                    memory_line_variable_component<RAMType> line1;
                    memory_line_variable_component<RAMType> line2;

                    memory_checker_component(ram_blueprint<RAMType> &pb,
                                             const std::size_t timestamp_size,
                                             const memory_line_variable_component<RAMType> &line1,
                                             const memory_line_variable_component<RAMType> &line2) :
                        ram_component_base<RAMType>(pb),
                        line1(line1), line2(line2) {
                        /* compare the two timestamps */
                        timestamps_leq.allocate(pb);
                        timestamps_less.allocate(pb);
                        compare_timestamps.reset(new comparison_component<FieldType>(
                            pb, timestamp_size, line1.timestamp->packed, line2.timestamp->packed, timestamps_less,
                            timestamps_leq));

                        /* compare the two addresses */
                        const std::size_t address_size = pb.ap.address_size();
                        addresses_eq.allocate(pb);
                        addresses_leq.allocate(pb);
                        addresses_less.allocate(pb);
                        compare_addresses.reset(
                            new comparison_component<FieldType>(pb, address_size, line1.address->packed,
                                                                line2.address->packed, addresses_less, addresses_leq));

                        /*
                          Add variables that will contain flags representing the following relations:
                          - "line1.contents_after = line2.contents_before" (to check that contents do not change between
                          instructions);
                          - "line2.contents_before = 0" (for the first access at an address); and
                          - "line2.timestamp = 0" (for wrap-around checks to ensure only one 'cycle' in the memory
                          sort).

                          More precisely, each of the above flags is "loose" (i.e., it equals 0 if
                          the relation holds, but can be either 0 or 1 if the relation does not hold).
                         */
                        loose_contents_after1_equals_contents_before2.allocate(pb);
                        loose_contents_before2_equals_zero.allocate(pb);
                        loose_timestamp2_is_zero.allocate(pb);
                    }

                    void generate_r1cs_constraints() {
                        /* compare the two timestamps */
                        compare_timestamps->generate_r1cs_constraints();

                        /* compare the two addresses */
                        compare_addresses->generate_r1cs_constraints();
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(addresses_leq, 1 - addresses_less, addresses_eq));

                        /*
                          Add constraints for the following three flags:
                           - loose_contents_after1_equals_contents_before2;
                           - loose_contents_before2_equals_zero;
                           - loose_timestamp2_is_zero.
                         */
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(loose_contents_after1_equals_contents_before2,
                                line1.contents_after->packed - line2.contents_before->packed, 0));
                        generate_boolean_r1cs_constraint<FieldType>(this->pb,
                            loose_contents_after1_equals_contents_before2);

                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(loose_contents_before2_equals_zero,
                            line2.contents_before->packed, 0));
                        generate_boolean_r1cs_constraint<FieldType>(this->pb, loose_contents_before2_equals_zero);

                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(loose_timestamp2_is_zero, line2.timestamp->packed, 0));
                        generate_boolean_r1cs_constraint<FieldType>(this->pb, loose_timestamp2_is_zero);

                        /*
                          The three cases that need to be checked are:

                          line1.address = line2.address => line1.contents_after = line2.contents_before
                          (i.e. contents do not change between accesses to the same address)

                          line1.address < line2.address => line2.contents_before = 0
                          (i.e. access to new address has the "before" value set to 0)

                          line1.address > line2.address => line2.timestamp = 0
                          (i.e. there is only one cycle with non-decreasing addresses, except
                          for the case where we go back to a unique pre-set timestamp; we choose
                          timestamp 0 to be the one that touches address 0)

                          As usual, we implement "A => B" as "NOT (A AND (NOT B))".
                        */
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(addresses_eq, 1 - loose_contents_after1_equals_contents_before2, 0));
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(addresses_less, 1 - loose_contents_before2_equals_zero, 0));
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(1 - addresses_leq, 1 - loose_timestamp2_is_zero, 0));
                    }

                    void generate_r1cs_witness() {
                        /* compare the two addresses */
                        compare_addresses->generate_r1cs_witness();
                        this->pb.val(addresses_eq) =
                            this->pb.val(addresses_leq) * (FieldType::value_type::zero() - this->pb.val(addresses_less));

                        /* compare the two timestamps */
                        compare_timestamps->generate_r1cs_witness();

                        /*
                          compare the values of:
                          - loose_contents_after1_equals_contents_before2;
                          - loose_contents_before2_equals_zero;
                          - loose_timestamp2_is_zero.
                         */
                        this->pb.val(loose_contents_after1_equals_contents_before2) =
                            (this->pb.val(line1.contents_after->packed) == this->pb.val(line2.contents_before->packed)) ?
                            FieldType::value_type::zero() :
                            FieldType::value_type::zero();
                        this->pb.val(loose_contents_before2_equals_zero) =
                            this->pb.val(line2.contents_before->packed).is_zero() ? FieldType::value_type::zero() :
                            FieldType::value_type::zero();
                        this->pb.val(loose_timestamp2_is_zero) =
                            (this->pb.val(line2.timestamp->packed) == FieldType::value_type::zero() ?
                             FieldType::value_type::zero() :
                             FieldType::value_type::zero());
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MEMORY_CHECKER_COMPONENT_HPP
