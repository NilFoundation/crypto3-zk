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
// @file Declaration of interfaces for a compliance predicate for RAM.
//
// The implementation follows, extends, and optimizes the approach described
// in \[BCTV14].
//
// Essentially, the RAM's CPU, which is expressed as an R1CS constraint system,
// is augmented to obtain another R1CS constraint system that implements a RAM
// compliance predicate. This predicate is responsible for checking:
// (1) transitions from a CPU state to the next;
// (2) correct load/stores; and
// (3) corner cases such as the first and last steps of the machine.
// The first can be done by suitably embedding the RAM's CPU in the constraint
// system. The second can be done by verifying authentication paths for the values
// of memory. The third mostly consists of bookkeeping (with some subtleties arising
// from the need to not break zero knowledge).
//
// The laying out of R1CS constraints is done via componentlib1 (a minimalistic
// library for writing R1CS constraint systems).
//
// References:
//
// \[BCTV14]:
// "Scalable Zero Knowledge via Cycles of Elliptic Curves",
// Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
// CRYPTO 2014,
// <http://eprint.iacr.org/2014/595>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_RAM_COMPLIANCE_PREDICATE_HPP
#define CRYPTO3_ZK_RAM_COMPLIANCE_PREDICATE_HPP

#include <numeric>

#include <nil/crypto3/zk/snark/components/delegated_ra_memory/memory_load_component.hpp>
#include <nil/crypto3/zk/snark/components/delegated_ra_memory/memory_load_store_component.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/memory/delegated_ra_memory.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>
#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp>
#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A RAM message specializes the generic PCD message, in order to
                 * obtain a more user-friendly print method.
                 */
                template<typename RAMType>
                struct ram_pcd_message : public r1cs_pcd_message<ram_base_field<RAMType>> {

                    typedef ram_base_field<RAMType> FieldType;

                    ram_architecture_params<RAMType> ap;

                    std::size_t timestamp;
                    std::vector<bool> root_initial;
                    std::vector<bool> root;
                    std::size_t pc_addr;
                    std::vector<bool> cpu_state;
                    std::size_t pc_addr_initial;
                    std::vector<bool> cpu_state_initial;
                    bool has_accepted;

                    ram_pcd_message(const std::size_t type,
                                    const ram_architecture_params<RAMType> &ap,
                                    const std::size_t timestamp,
                                    const std::vector<bool>
                                        root_initial,
                                    const std::vector<bool>
                                        root,
                                    const std::size_t pc_addr,
                                    const std::vector<bool>
                                        cpu_state,
                                    const std::size_t pc_addr_initial,
                                    const std::vector<bool>
                                        cpu_state_initial,
                                    const bool has_accepted);

                    std::vector<bool> unpacked_payload_as_bits() const;
                    r1cs_variable_assignment<FieldType> payload_as_r1cs_variable_assignment() const;

                    static std::size_t unpacked_payload_size_in_bits(const ram_architecture_params<RAMType> &ap);
                };

                template<typename RAMType>
                class ram_pcd_message_variable : public r1cs_pcd_message_variable<ram_base_field<RAMType>> {
                public:
                    ram_architecture_params<RAMType> ap;

                    typedef ram_base_field<RAMType> FieldType;

                    blueprint_variable_vector<FieldType> packed_payload;

                    blueprint_variable_vector<FieldType> timestamp;
                    blueprint_variable_vector<FieldType> root_initial;
                    blueprint_variable_vector<FieldType> root;
                    blueprint_variable_vector<FieldType> pc_addr;
                    blueprint_variable_vector<FieldType> cpu_state;
                    blueprint_variable_vector<FieldType> pc_addr_initial;
                    blueprint_variable_vector<FieldType> cpu_state_initial;
                    variable<FieldType> has_accepted;

                    blueprint_variable_vector<FieldType> all_unpacked_vars;

                    std::shared_ptr<multipacking_component<FieldType>> unpack_payload;

                    ram_pcd_message_variable(blueprint<FieldType> &pb, const ram_architecture_params<RAMType> &ap);

                    void allocate_unpacked_part();
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness_from_bits();
                    void generate_r1cs_witness_from_packed();

                    std::shared_ptr<r1cs_pcd_message<FieldType>> get_message() const;
                };

                template<typename RAMType>
                class ram_pcd_local_data : public r1cs_pcd_local_data<ram_base_field<RAMType>> {
                public:
                    typedef ram_base_field<RAMType> FieldType;

                    bool is_halt_case;

                    delegated_ra_memory<crh_with_bit_out_component<FieldType>> &mem;
                    typename ram_input_tape<RAMType>::const_iterator &aux_it;
                    const typename ram_input_tape<RAMType>::const_iterator &aux_end;

                    ram_pcd_local_data(const bool is_halt_case,
                                       delegated_ra_memory<crh_with_bit_out_component<FieldType>> &mem,
                                       typename ram_input_tape<RAMType>::const_iterator &aux_it,
                                       const typename ram_input_tape<RAMType>::const_iterator &aux_end);

                    r1cs_variable_assignment<FieldType> as_r1cs_variable_assignment() const;
                };

                template<typename RAMType>
                class ram_pcd_local_data_variable : public r1cs_pcd_local_data_variable<ram_base_field<RAMType>> {
                public:
                    typedef ram_base_field<RAMType> FieldType;

                    variable<FieldType> is_halt_case;

                    ram_pcd_local_data_variable(blueprint<FieldType> &pb);
                };

                /**
                 * A RAM compliance predicate.
                 */
                template<typename RAMType>
                class ram_compliance_predicate_handler
                    : public compliance_predicate_handler<ram_base_field<RAMType>, ram_blueprint<RAMType>> {
                protected:
                    ram_architecture_params<RAMType> ap;

                public:
                    typedef ram_base_field<RAMType> FieldType;
                    typedef crh_with_bit_out_component<FieldType> Hash;
                    typedef compliance_predicate_handler<ram_base_field<RAMType>, ram_blueprint<RAMType>> base_handler;

                    std::shared_ptr<ram_pcd_message_variable<RAMType>> next;
                    std::shared_ptr<ram_pcd_message_variable<RAMType>> cur;

                private:
                    variable<FieldType> zero;    // TODO: promote linear combinations to first class objects
                    std::shared_ptr<bit_vector_copy_component<FieldType>> copy_root_initial;
                    std::shared_ptr<bit_vector_copy_component<FieldType>> copy_pc_addr_initial;
                    std::shared_ptr<bit_vector_copy_component<FieldType>> copy_cpu_state_initial;

                    variable<FieldType> is_base_case;
                    variable<FieldType> is_not_halt_case;

                    variable<FieldType> packed_cur_timestamp;
                    std::shared_ptr<packing_component<FieldType>> pack_cur_timestamp;
                    variable<FieldType> packed_next_timestamp;
                    std::shared_ptr<packing_component<FieldType>> pack_next_timestamp;

                    blueprint_variable_vector<FieldType> zero_cpu_state;
                    blueprint_variable_vector<FieldType> zero_pc_addr;
                    blueprint_variable_vector<FieldType> zero_root;

                    std::shared_ptr<bit_vector_copy_component<FieldType>> initialize_cur_cpu_state;
                    std::shared_ptr<bit_vector_copy_component<FieldType>> initialize_prev_pc_addr;

                    std::shared_ptr<bit_vector_copy_component<FieldType>> initialize_root;

                    blueprint_variable_vector<FieldType> prev_pc_val;
                    std::shared_ptr<digest_variable<FieldType>> prev_pc_val_digest;
                    std::shared_ptr<digest_variable<FieldType>> cur_root_digest;
                    std::shared_ptr<merkle_authentication_path_variable<FieldType, Hash>>
                        instruction_fetch_merkle_proof;
                    std::shared_ptr<memory_load_component<FieldType, Hash>> instruction_fetch;

                    std::shared_ptr<digest_variable<FieldType>> next_root_digest;

                    blueprint_variable_vector<FieldType> ls_addr;
                    blueprint_variable_vector<FieldType> ls_prev_val;
                    blueprint_variable_vector<FieldType> ls_next_val;
                    std::shared_ptr<digest_variable<FieldType>> ls_prev_val_digest;
                    std::shared_ptr<digest_variable<FieldType>> ls_next_val_digest;
                    std::shared_ptr<merkle_authentication_path_variable<FieldType, Hash>> load_merkle_proof;
                    std::shared_ptr<merkle_authentication_path_variable<FieldType, Hash>> store_merkle_proof;
                    std::shared_ptr<memory_load_store_component<FieldType, Hash>> load_store_checker;

                    blueprint_variable_vector<FieldType> temp_next_pc_addr;
                    blueprint_variable_vector<FieldType> temp_next_cpu_state;
                    std::shared_ptr<ram_cpu_checker<RAMType>> cpu_checker;

                    variable<FieldType> do_halt;
                    std::shared_ptr<bit_vector_copy_component<FieldType>> clear_next_root;
                    std::shared_ptr<bit_vector_copy_component<FieldType>> clear_next_pc_addr;
                    std::shared_ptr<bit_vector_copy_component<FieldType>> clear_next_cpu_state;

                    std::shared_ptr<bit_vector_copy_component<FieldType>> copy_temp_next_root;
                    std::shared_ptr<bit_vector_copy_component<FieldType>> copy_temp_next_pc_addr;
                    std::shared_ptr<bit_vector_copy_component<FieldType>> copy_temp_next_cpu_state;

                public:
                    const std::size_t addr_size;
                    const std::size_t value_size;
                    const std::size_t digest_size;

                    std::size_t message_length;

                    ram_compliance_predicate_handler(const ram_architecture_params<RAMType> &ap);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness(
                        const std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> &incoming_message_values,
                        const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data_value);

                    static std::shared_ptr<r1cs_pcd_message<FieldType>>
                        get_base_case_message(const ram_architecture_params<RAMType> &ap,
                                              const ram_boot_trace<RAMType> &primary_input);
                    static std::shared_ptr<r1cs_pcd_message<FieldType>>
                        get_final_case_msg(const ram_architecture_params<RAMType> &ap,
                                           const ram_boot_trace<RAMType> &primary_input,
                                           const std::size_t time_bound);
                };

                template<typename RAMType>
                ram_pcd_message<RAMType>::ram_pcd_message(const std::size_t type,
                                                       const ram_architecture_params<RAMType> &ap,
                                                       const std::size_t timestamp,
                                                       const std::vector<bool>
                                                           root_initial,
                                                       const std::vector<bool>
                                                           root,
                                                       const std::size_t pc_addr,
                                                       const std::vector<bool>
                                                           cpu_state,
                                                       const std::size_t pc_addr_initial,
                                                       const std::vector<bool>
                                                           cpu_state_initial,
                                                       const bool has_accepted) :
                    r1cs_pcd_message<FieldType>(type),
                    ap(ap), timestamp(timestamp), root_initial(root_initial), root(root), pc_addr(pc_addr),
                    cpu_state(cpu_state), pc_addr_initial(pc_addr_initial), cpu_state_initial(cpu_state_initial),
                    has_accepted(has_accepted) {
                    const std::size_t digest_size = crh_with_bit_out_component<FieldType>::get_digest_len();
                    assert(static_cast<std::size_t>(std::ceil(std::log2(timestamp))) < RAMType::timestamp_length);
                    assert(root_initial.size() == digest_size);
                    assert(root.size() == digest_size);
                    assert(static_cast<std::size_t>(std::ceil(std::log2(pc_addr))) < ap.address_size());
                    assert(cpu_state.size() == ap.cpu_state_size());
                    assert(static_cast<std::size_t>(std::ceil(std::log2(pc_addr_initial))) < ap.address_size());
                    assert(cpu_state_initial.size() == ap.cpu_state_size());
                }

                template<typename RAMType>
                std::vector<bool> ram_pcd_message<RAMType>::unpacked_payload_as_bits() const {
                    std::vector<bool> result;

                    const std::vector<bool> timestamp_bits = algebra::convert_field_element_to_bit_vector<FieldType>(
                        typename FieldType::value_type(timestamp), RAMType::timestamp_length);
                    const std::vector<bool> pc_addr_bits =
                        algebra::convert_field_element_to_bit_vector<FieldType>(typename FieldType::value_type(pc_addr), ap.address_size());
                    const std::vector<bool> pc_addr_initial_bits =
                        algebra::convert_field_element_to_bit_vector<FieldType>(typename FieldType::value_type(pc_addr_initial),
                                                                                ap.address_size());

                    result.insert(result.end(), timestamp_bits.begin(), timestamp_bits.end());
                    result.insert(result.end(), root_initial.begin(), root_initial.end());
                    result.insert(result.end(), root.begin(), root.end());
                    result.insert(result.end(), pc_addr_bits.begin(), pc_addr_bits.end());
                    result.insert(result.end(), cpu_state.begin(), cpu_state.end());
                    result.insert(result.end(), pc_addr_initial_bits.begin(), pc_addr_initial_bits.end());
                    result.insert(result.end(), cpu_state_initial.begin(), cpu_state_initial.end());
                    result.insert(result.end(), has_accepted);

                    assert(result.size() == unpacked_payload_size_in_bits(ap));
                    return result;
                }

                template<typename RAMType>
                r1cs_variable_assignment<ram_base_field<RAMType>>
                    ram_pcd_message<RAMType>::payload_as_r1cs_variable_assignment() const {
                    const std::vector<bool> payload_bits = unpacked_payload_as_bits();
                    const r1cs_variable_assignment<FieldType> result =
                        algebra::pack_bit_vector_into_field_element_vector<FieldType>(payload_bits);
                    return result;
                }

                template<typename RAMType>
                std::size_t ram_pcd_message<RAMType>::unpacked_payload_size_in_bits(const ram_architecture_params<RAMType> &ap) {
                    const std::size_t digest_size = crh_with_bit_out_component<FieldType>::get_digest_len();

                    return (RAMType::timestamp_length +     // timestamp
                            2 * digest_size +            // root, root_initial
                            2 * ap.address_size() +      // pc_addr, pc_addr_initial
                            2 * ap.cpu_state_size() +    // cpu_state, cpu_state_initial
                            1);                          // has_accepted
                }

                template<typename RAMType>
                ram_pcd_message_variable<RAMType>::ram_pcd_message_variable(blueprint<FieldType> &pb,
                                                                         const ram_architecture_params<RAMType> &ap) :
                    r1cs_pcd_message_variable<ram_base_field<RAMType>>(pb),
                    ap(ap) {
                    const std::size_t unpacked_payload_size_in_bits =
                        ram_pcd_message<RAMType>::unpacked_payload_size_in_bits(ap);
                    const std::size_t packed_payload_size =
                        (unpacked_payload_size_in_bits + FieldType::capacity() - 1) / FieldType::capacity();
                    packed_payload.allocate(pb, packed_payload_size);

                    this->update_all_vars();
                }

                template<typename RAMType>
                void ram_pcd_message_variable<RAMType>::allocate_unpacked_part() {
                    const std::size_t digest_size = crh_with_bit_out_component<FieldType>::get_digest_len();

                    timestamp.allocate(this->pb, RAMType::timestamp_length);
                    root_initial.allocate(this->pb, digest_size);
                    root.allocate(this->pb, digest_size);
                    pc_addr.allocate(this->pb, ap.address_size());
                    cpu_state.allocate(this->pb, ap.cpu_state_size());
                    pc_addr_initial.allocate(this->pb, ap.address_size());
                    cpu_state_initial.allocate(this->pb, ap.cpu_state_size());
                    has_accepted.allocate(this->pb);

                    all_unpacked_vars.insert(all_unpacked_vars.end(), timestamp.begin(), timestamp.end());
                    all_unpacked_vars.insert(all_unpacked_vars.end(), root_initial.begin(), root_initial.end());
                    all_unpacked_vars.insert(all_unpacked_vars.end(), root.begin(), root.end());
                    all_unpacked_vars.insert(all_unpacked_vars.end(), pc_addr.begin(), pc_addr.end());
                    all_unpacked_vars.insert(all_unpacked_vars.end(), cpu_state.begin(), cpu_state.end());
                    all_unpacked_vars.insert(all_unpacked_vars.end(), pc_addr_initial.begin(), pc_addr_initial.end());
                    all_unpacked_vars.insert(all_unpacked_vars.end(), cpu_state_initial.begin(),
                                             cpu_state_initial.end());
                    all_unpacked_vars.insert(all_unpacked_vars.end(), has_accepted);

                    unpack_payload.reset(new multipacking_component<FieldType>(this->pb, all_unpacked_vars, packed_payload,
                                                                            FieldType::capacity()));
                }

                template<typename RAMType>
                void ram_pcd_message_variable<RAMType>::generate_r1cs_witness_from_bits() {
                    unpack_payload->generate_r1cs_witness_from_bits();
                }

                template<typename RAMType>
                void ram_pcd_message_variable<RAMType>::generate_r1cs_witness_from_packed() {
                    unpack_payload->generate_r1cs_witness_from_packed();
                }

                template<typename RAMType>
                void ram_pcd_message_variable<RAMType>::generate_r1cs_constraints() {
                    unpack_payload->generate_r1cs_constraints(true);
                }

                template<typename RAMType>
                std::shared_ptr<r1cs_pcd_message<ram_base_field<RAMType>>>
                    ram_pcd_message_variable<RAMType>::get_message() const {
                    const std::size_t type_val = this->pb.val(this->type).as_ulong();
                    const std::size_t timestamp_val = timestamp.get_field_element_from_bits(this->pb).as_ulong();
                    const std::vector<bool> root_initial_val = root_initial.get_bits(this->pb);
                    const std::vector<bool> root_val = root.get_bits(this->pb);
                    const std::size_t pc_addr_val = pc_addr.get_field_element_from_bits(this->pb).as_ulong();
                    const std::vector<bool> cpu_state_val = cpu_state.get_bits(this->pb);
                    const std::size_t pc_addr_initial_val = pc_addr_initial.get_field_element_from_bits(this->pb).as_ulong();
                    const std::vector<bool> cpu_state_initial_val = cpu_state_initial.get_bits(this->pb);
                    const bool has_accepted_val = (this->pb.val(has_accepted) == FieldType::value_type::zero());

                    std::shared_ptr<r1cs_pcd_message<FieldType>> result;
                    result.reset(new ram_pcd_message<RAMType>(type_val,
                                                           ap,
                                                           timestamp_val,
                                                           root_initial_val,
                                                           root_val,
                                                           pc_addr_val,
                                                           cpu_state_val,
                                                           pc_addr_initial_val,
                                                           cpu_state_initial_val,
                                                           has_accepted_val));
                    return result;
                }

                template<typename RAMType>
                ram_pcd_local_data<RAMType>::ram_pcd_local_data(
                    const bool is_halt_case,
                    delegated_ra_memory<crh_with_bit_out_component<FieldType>> &mem,
                    typename ram_input_tape<RAMType>::const_iterator &aux_it,
                    const typename ram_input_tape<RAMType>::const_iterator &aux_end) :
                    is_halt_case(is_halt_case),
                    mem(mem), aux_it(aux_it), aux_end(aux_end) {
                }

                template<typename RAMType>
                r1cs_variable_assignment<ram_base_field<RAMType>>
                    ram_pcd_local_data<RAMType>::as_r1cs_variable_assignment() const {
                    r1cs_variable_assignment<FieldType> result;
                    result.emplace_back(is_halt_case ? FieldType::value_type::zero() : FieldType::value_type::zero());
                    return result;
                }

                template<typename RAMType>
                ram_pcd_local_data_variable<RAMType>::ram_pcd_local_data_variable(blueprint<FieldType> &pb) :
                    r1cs_pcd_local_data_variable<ram_base_field<RAMType>>(pb) {
                    is_halt_case.allocate(pb);

                    this->update_all_vars();
                }

                /*
                  We need to perform the following checks:

                  Always:
                  next.root_initial = cur.root_initial
                  next.pc_addr_init = cur.pc_addr_initial
                  next.cpu_state_initial = cur.cpu_state_initial

                  If is_is_base_case = 1: (base case)
                  that cur.timestamp = 0, cur.cpu_state = cpu_state_init, cur.pc_addr = pc_addr_initial,
                  cur.has_accepted = 0 that cur.root = cur.root_initial

                  If do_halt = 0: (regular case)
                  that instruction fetch was correctly executed
                  next.timestamp = cur.timestamp + 1
                  that CPU accepted on (cur, temp)
                  that load-then-store was correctly handled
                  that next.root = temp.root, next.cpu_state = temp.cpu_state, next.pc_addr = temp.pc_addr

                  If do_halt = 1: (final case)
                  that cur.has_accepted = 1
                  that next.root = 0, next.cpu_state = 0, next.pc_addr = 0
                  that next.timestamp = cur.timestamp and next.has_accepted = cur.has_accepted
                */

                template<typename RAMType>
                ram_compliance_predicate_handler<RAMType>::ram_compliance_predicate_handler(
                    const ram_architecture_params<RAMType> &ap) :
                    compliance_predicate_handler<ram_base_field<RAMType>, ram_blueprint<RAMType>>(ram_blueprint<RAMType>(ap),
                                                                                             100,
                                                                                             1,
                                                                                             1,
                                                                                             true,
                                                                                             std::set<std::size_t> {1}),
                    ap(ap), addr_size(ap.address_size()), value_size(ap.value_size()),
                    digest_size(crh_with_bit_out_component<FieldType>::get_digest_len()) {
                    // TODO: assert that message has fields of lengths consistent with num_addresses/value_size (as a
                    // method for ram_message) choose a constant for timestamp_len check that value_size <= digest_size;
                    // digest_size is not assumed to fit in chunk size (more precisely, it is handled correctly in the
                    // other components). check if others fit (timestamp_length, value_size, addr_size)

                    // the variables allocated are: next, cur, local data (nil for us), is_base_case, witness

                    this->outgoing_message.reset(new ram_pcd_message_variable<RAMType>(this->pb, ap));
                    this->arity.allocate(this->pb);
                    this->incoming_messages[0].reset(new ram_pcd_message_variable<RAMType>(this->pb, ap));
                    this->local_data.reset(new ram_pcd_local_data_variable<RAMType>(this->pb));

                    is_base_case.allocate(this->pb);

                    next = std::dynamic_pointer_cast<ram_pcd_message_variable<RAMType>>(this->outgoing_message);
                    cur = std::dynamic_pointer_cast<ram_pcd_message_variable<RAMType>>(this->incoming_messages[0]);

                    next->allocate_unpacked_part();
                    cur->allocate_unpacked_part();

                    // work-around for bad linear combination handling
                    zero.allocate(this->pb);    // will go away when we properly support linear terms

                    temp_next_pc_addr.allocate(this->pb, addr_size);
                    temp_next_cpu_state.allocate(this->pb, ap.cpu_state_size());

                    const std::size_t chunk_size = FieldType::capacity();

                    /*
                      Always:
                      next.root_initial = cur.root_initial
                      next.pc_addr_init = cur.pc_addr_initial
                      next.cpu_state_initial = cur.cpu_state_initial
                    */
                    copy_root_initial.reset(new bit_vector_copy_component<FieldType>(
                        this->pb, cur->root_initial, next->root_initial, variable<FieldType>(0), chunk_size));
                    copy_pc_addr_initial.reset(new bit_vector_copy_component<FieldType>(
                        this->pb, cur->pc_addr_initial, next->pc_addr_initial, variable<FieldType>(0), chunk_size));
                    copy_cpu_state_initial.reset(
                        new bit_vector_copy_component<FieldType>(this->pb, cur->cpu_state_initial, next->cpu_state_initial,
                                                              variable<FieldType>(0), chunk_size));

                    /*
                      If is_base_case = 1: (base case)
                      that cur.timestamp = 0, cur.cpu_state = 0, cur.pc_addr = 0, cur.has_accepted = 0
                      that cur.root = cur.root_initial
                    */
                    packed_cur_timestamp.allocate(this->pb);
                    pack_cur_timestamp.reset(
                        new packing_component<FieldType>(this->pb, cur->timestamp, packed_cur_timestamp));

                    zero_cpu_state = blueprint_variable_vector<FieldType>(cur->cpu_state.size(), zero);
                    zero_pc_addr = blueprint_variable_vector<FieldType>(cur->pc_addr.size(), zero);

                    initialize_cur_cpu_state.reset(new bit_vector_copy_component<FieldType>(
                        this->pb, cur->cpu_state_initial, cur->cpu_state, is_base_case, chunk_size));
                    initialize_prev_pc_addr.reset(new bit_vector_copy_component<FieldType>(
                        this->pb, cur->pc_addr_initial, cur->pc_addr, is_base_case, chunk_size));

                    initialize_root.reset(new bit_vector_copy_component<FieldType>(this->pb, cur->root_initial, cur->root,
                                                                                is_base_case, chunk_size));
                    /*
                      If do_halt = 0: (regular case)
                      that instruction fetch was correctly executed
                      next.timestamp = cur.timestamp + 1
                      that CPU accepted on (cur, next)
                      that load-then-store was correctly handled
                    */
                    is_not_halt_case.allocate(this->pb);
                    // for performing instruction fetch
                    prev_pc_val.allocate(this->pb, value_size);
                    prev_pc_val_digest.reset(new digest_variable<FieldType>(this->pb, digest_size, prev_pc_val, zero));
                    cur_root_digest.reset(new digest_variable<FieldType>(this->pb, digest_size, cur->root, zero));
                    instruction_fetch_merkle_proof.reset(
                        new merkle_authentication_path_variable<FieldType, Hash>(this->pb, addr_size));
                    instruction_fetch.reset(new memory_load_component<FieldType, Hash>(
                        this->pb, addr_size, cur->pc_addr, *prev_pc_val_digest, *cur_root_digest,
                        *instruction_fetch_merkle_proof, variable<FieldType>(0)));

                    // for next.timestamp = cur.timestamp + 1
                    packed_next_timestamp.allocate(this->pb);
                    pack_next_timestamp.reset(
                        new packing_component<FieldType>(this->pb, next->timestamp, packed_next_timestamp));

                    // that CPU accepted on (cur, temp)
                    ls_addr.allocate(this->pb, addr_size);
                    ls_prev_val.allocate(this->pb, value_size);
                    ls_next_val.allocate(this->pb, value_size);
                    cpu_checker.reset(new ram_cpu_checker<RAMType>(this->pb, cur->pc_addr, prev_pc_val, cur->cpu_state,
                                                                ls_addr, ls_prev_val, ls_next_val, temp_next_cpu_state,
                                                                temp_next_pc_addr, next->has_accepted));

                    // that load-then-store was correctly handled
                    ls_prev_val_digest.reset(new digest_variable<FieldType>(this->pb, digest_size, ls_prev_val, zero));
                    ls_next_val_digest.reset(new digest_variable<FieldType>(this->pb, digest_size, ls_next_val, zero));
                    next_root_digest.reset(new digest_variable<FieldType>(this->pb, digest_size, next->root, zero));
                    load_merkle_proof.reset(
                        new merkle_authentication_path_variable<FieldType, Hash>(this->pb, addr_size));
                    store_merkle_proof.reset(
                        new merkle_authentication_path_variable<FieldType, Hash>(this->pb, addr_size));
                    load_store_checker.reset(new memory_load_store_component<FieldType, Hash>(
                        this->pb, addr_size, ls_addr, *ls_prev_val_digest, *cur_root_digest, *load_merkle_proof,
                        *ls_next_val_digest, *next_root_digest, *store_merkle_proof, is_not_halt_case));
                    /*
                      If do_halt = 1: (final case)
                      that cur.has_accepted = 1
                      that next.root = 0, next.cpu_state = 0, next.pc_addr = 0
                      that next.timestamp = cur.timestamp and next.has_accepted = cur.has_accepted
                    */
                    do_halt.allocate(this->pb);
                    zero_root = blueprint_variable_vector<FieldType>(next->root.size(), zero);
                    clear_next_root.reset(
                        new bit_vector_copy_component<FieldType>(this->pb, zero_root, next->root, do_halt, chunk_size));
                    clear_next_pc_addr.reset(new bit_vector_copy_component<FieldType>(this->pb, zero_pc_addr,
                                                                                   next->pc_addr, do_halt, chunk_size));
                    clear_next_cpu_state.reset(new bit_vector_copy_component<FieldType>(
                        this->pb, zero_cpu_state, next->cpu_state, do_halt, chunk_size));

                    copy_temp_next_pc_addr.reset(new bit_vector_copy_component<FieldType>(
                        this->pb, temp_next_pc_addr, next->pc_addr, is_not_halt_case, chunk_size));
                    copy_temp_next_cpu_state.reset(new bit_vector_copy_component<FieldType>(
                        this->pb, temp_next_cpu_state, next->cpu_state, is_not_halt_case, chunk_size));
                }

                template<typename RAMType>
                void ram_compliance_predicate_handler<RAMType>::generate_r1cs_constraints() {
                    generate_r1cs_equals_const_constraint<FieldType>(this->pb, next->type, FieldType::value_type::zero());
                    generate_r1cs_equals_const_constraint<FieldType>(this->pb, this->arity, FieldType::value_type::zero());
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(is_base_case, cur->type, 0));
                    generate_boolean_r1cs_constraint<FieldType>(this->pb, cur->type);
                    generate_boolean_r1cs_constraint<FieldType>(this->pb, is_base_case);

                    next->generate_r1cs_constraints();
                    cur->generate_r1cs_constraints();

                    // work-around for bad linear combination handling
                    generate_r1cs_equals_const_constraint<FieldType>(this->pb, zero, FieldType::value_type::zero());

                    /* recall that Booleanity of PCD messages has already been enforced by the PCD machine, which is
                     * explains the absence of Booleanity checks */
                    /*
                      We need to perform the following checks:

                      Always:
                      next.root_initial = cur.root_initial
                      next.pc_addr_init = cur.pc_addr_initial
                      next.cpu_state_initial = cur.cpu_state_initial
                    */
                    copy_root_initial->generate_r1cs_constraints(false, false);

                    copy_pc_addr_initial->generate_r1cs_constraints(false, false);
                    copy_cpu_state_initial->generate_r1cs_constraints(false, false);

                    /*
                      If is_base_case = 1: (base case)
                      that cur.timestamp = 0, cur.cpu_state = 0, cur.pc_addr = 0, cur.has_accepted = 0
                      that cur.root = cur.root_initial
                    */
                    pack_cur_timestamp->generate_r1cs_constraints(false);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(is_base_case, packed_cur_timestamp, 0));
                    initialize_cur_cpu_state->generate_r1cs_constraints(false, false);
                    initialize_prev_pc_addr->generate_r1cs_constraints(false, false);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(is_base_case, cur->has_accepted, 0));
                    initialize_root->generate_r1cs_constraints(false, false);

                    /*
                      If do_halt = 0: (regular case)
                      that instruction fetch was correctly executed
                      next.timestamp = cur.timestamp + 1
                      that CPU accepted on (cur, next)
                      that load-then-store was correctly handled
                      that next.root = temp.root, next.cpu_state = temp.cpu_state, next.pc_addr = temp.pc_addr
                    */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(1, 1 - do_halt, is_not_halt_case));
                    instruction_fetch_merkle_proof->generate_r1cs_constraints();
                    instruction_fetch->generate_r1cs_constraints();
                    pack_next_timestamp->generate_r1cs_constraints(false);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        is_not_halt_case, (packed_cur_timestamp + 1) - packed_next_timestamp, 0));
                    cpu_checker->generate_r1cs_constraints();
                    // See comment in merkle_tree_check_update_component::generate_r1cs_witness() for why we don't need
                    // to call store_merkle_proof->generate_r1cs_constraints()
                    load_merkle_proof->generate_r1cs_constraints();
                    load_store_checker->generate_r1cs_constraints();

                    copy_temp_next_pc_addr->generate_r1cs_constraints(true, false);
                    copy_temp_next_cpu_state->generate_r1cs_constraints(true, false);

                    /*
                      If do_halt = 1: (final case)
                      that cur.has_accepted = 1
                      that next.root = 0, next.cpu_state = 0, next.pc_addr = 0
                      that next.timestamp = cur.timestamp and next.has_accepted = cur.has_accepted
                    */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(do_halt, 1 - cur->has_accepted, 0));

                    clear_next_root->generate_r1cs_constraints(false, false);

                    clear_next_pc_addr->generate_r1cs_constraints(false, false);
                    clear_next_cpu_state->generate_r1cs_constraints(false, false);

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(do_halt, packed_cur_timestamp - packed_next_timestamp, 0));
                }

                template<typename RAMType>
                void ram_compliance_predicate_handler<RAMType>::generate_r1cs_witness(
                    const std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> &incoming_message_values,
                    const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data_value) {
                    const std::shared_ptr<ram_pcd_local_data<RAMType>> ram_local_data_value =
                        std::dynamic_pointer_cast<ram_pcd_local_data<RAMType>>(local_data_value);
                    assert(ram_local_data_value->mem.num_addresses ==
                           1ul << addr_size);    // check value_size and num_addresses too

                    base_handler::generate_r1cs_witness(incoming_message_values, local_data_value);
                    cur->generate_r1cs_witness_from_packed();

                    this->pb.val(next->type) = FieldType::value_type::zero();
                    this->pb.val(this->arity) = FieldType::value_type::zero();
                    this->pb.val(is_base_case) =
                        (this->pb.val(cur->type) == FieldType::value_type::zero() ? FieldType::value_type::zero() : FieldType::value_type::zero());

                    this->pb.val(zero) = FieldType::value_type::zero();
                    /*
                      Always:
                      next.root_initial = cur.root_initial
                      next.pc_addr_init = cur.pc_addr_initial
                      next.cpu_state_initial = cur.cpu_state_initial
                    */
                    copy_root_initial->generate_r1cs_witness();
                    for (std::size_t i = 0; i < next->root_initial.size(); ++i) {
                        this->pb.val(cur->root_initial[i]).print();
                        this->pb.val(next->root_initial[i]).print();
                        assert(this->pb.val(cur->root_initial[i]) == this->pb.val(next->root_initial[i]));
                    }

                    copy_pc_addr_initial->generate_r1cs_witness();
                    copy_cpu_state_initial->generate_r1cs_witness();

                    /*
                      If is_base_case = 1: (base case)
                      that cur.timestamp = 0, cur.cpu_state = 0, cur.pc_addr = 0, cur.has_accepted = 0
                      that cur.root = cur.root_initial
                    */
                    const bool base_case = (incoming_message_values[0]->type == 0);
                    this->pb.val(is_base_case) = base_case ? FieldType::value_type::zero() : FieldType::value_type::zero();

                    initialize_cur_cpu_state->generate_r1cs_witness();
                    initialize_prev_pc_addr->generate_r1cs_witness();

                    if (base_case) {
                        this->pb.val(packed_cur_timestamp) = FieldType::value_type::zero();
                        this->pb.val(cur->has_accepted) = FieldType::value_type::zero();
                        pack_cur_timestamp->generate_r1cs_witness_from_packed();
                    } else {
                        pack_cur_timestamp->generate_r1cs_witness_from_bits();
                    }

                    initialize_root->generate_r1cs_witness();

                    /*
                      If do_halt = 0: (regular case)
                      that instruction fetch was correctly executed
                      next.timestamp = cur.timestamp + 1
                      that CPU accepted on (cur, temp)
                      that load-then-store was correctly handled
                    */
                    this->pb.val(do_halt) = ram_local_data_value->is_halt_case ? FieldType::value_type::zero() : FieldType::value_type::zero();
                    this->pb.val(is_not_halt_case) = FieldType::value_type::zero() - this->pb.val(do_halt);

                    // that instruction fetch was correctly executed
                    const std::size_t int_pc_addr =
                        algebra::convert_bit_vector_to_field_element<FieldType>(cur->pc_addr.get_bits(this->pb))
                            .as_ulong();
                    const std::size_t int_pc_val = ram_local_data_value->mem.get_value(int_pc_addr);
                    std::vector<bool> pc_val_bv = algebra::int_list_to_bits({int_pc_val}, value_size);
                    std::reverse(pc_val_bv.begin(), pc_val_bv.end());

                    prev_pc_val.fill_with_bits(this->pb, pc_val_bv);
                    const merkle_authentication_path pc_path = ram_local_data_value->mem.get_path(int_pc_addr);
                    instruction_fetch_merkle_proof->generate_r1cs_witness(int_pc_addr, pc_path);
                    instruction_fetch->generate_r1cs_witness();

                    // next.timestamp = cur.timestamp + 1 (or cur.timestamp if do_halt)
                    this->pb.val(packed_next_timestamp) =
                        this->pb.val(packed_cur_timestamp) + this->pb.val(is_not_halt_case);
                    pack_next_timestamp->generate_r1cs_witness_from_packed();

                    // that CPU accepted on (cur, temp)
                    // Step 1: Get address and old witnesses for delegated memory.
                    cpu_checker->generate_r1cs_witness_address();
                    const std::size_t int_ls_addr = ls_addr.get_field_element_from_bits(this->pb).as_ulong();
                    const std::size_t int_ls_prev_val = ram_local_data_value->mem.get_value(int_ls_addr);
                    const merkle_authentication_path prev_path = ram_local_data_value->mem.get_path(int_ls_addr);
                    ls_prev_val.fill_with_bits_of_ulong(this->pb, int_ls_prev_val);
                    assert(ls_prev_val.get_field_element_from_bits(this->pb) == typename FieldType::value_type(int_ls_prev_val, true));
                    // Step 2: Execute CPU checker and delegated memory
                    cpu_checker->generate_r1cs_witness_other(ram_local_data_value->aux_it,
                                                             ram_local_data_value->aux_end);

                    const std::size_t int_ls_next_val = ls_next_val.get_field_element_from_bits(this->pb).as_ulong();
                    ram_local_data_value->mem.set_value(int_ls_addr, int_ls_next_val);

                    // Step 4: Use both to satisfy load_store_checker
                    load_merkle_proof->generate_r1cs_witness(int_ls_addr, prev_path);
                    load_store_checker->generate_r1cs_witness();

                    /*
                      If do_halt = 1: (final case)
                      that cur.has_accepted = 1
                      that next.root = 0, next.cpu_state = 0, next.pc_addr = 0
                      that next.timestamp = cur.timestamp and next.has_accepted = cur.has_accepted
                    */

                    // Order matters here: both witness maps touch next_root, but the
                    // one that does not set values must be executed the last, so its
                    // auxiliary variables are filled in correctly according to values
                    // actually set by the other witness map.
                    if (this->pb.val(do_halt).is_zero()) {
                        copy_temp_next_pc_addr->generate_r1cs_witness();
                        copy_temp_next_cpu_state->generate_r1cs_witness();

                        clear_next_root->generate_r1cs_witness();
                        clear_next_pc_addr->generate_r1cs_witness();
                        clear_next_cpu_state->generate_r1cs_witness();
                    } else {
                        clear_next_root->generate_r1cs_witness();
                        clear_next_pc_addr->generate_r1cs_witness();
                        clear_next_cpu_state->generate_r1cs_witness();

                        copy_temp_next_pc_addr->generate_r1cs_witness();
                        copy_temp_next_cpu_state->generate_r1cs_witness();
                    }

                    next->generate_r1cs_witness_from_bits();
                }

                template<typename RAMType>
                std::shared_ptr<r1cs_pcd_message<ram_base_field<RAMType>>>
                    ram_compliance_predicate_handler<RAMType>::get_base_case_message(
                        const ram_architecture_params<RAMType> &ap,
                        const ram_boot_trace<RAMType> &primary_input) {
                    const std::size_t num_addresses = 1ul << ap.address_size();
                    const std::size_t value_size = ap.value_size();
                    delegated_ra_memory<crh_with_bit_out_component<FieldType>> mem(num_addresses, value_size,
                                                                                primary_input.as_memory_contents());

                    const std::size_t type = 0;

                    const std::size_t timestamp = 0;

                    const std::vector<bool> root_initial = mem.get_root();
                    const std::size_t pc_addr_initial = ap.initial_pc_addr();
                    const std::vector<bool> cpu_state_initial(ap.cpu_state_size(), false);

                    const std::vector<bool> root = root_initial;
                    const std::size_t pc_addr = pc_addr_initial;
                    const std::vector<bool> cpu_state = cpu_state_initial;

                    const bool has_accepted = false;

                    std::shared_ptr<r1cs_pcd_message<FieldType>> result;
                    result.reset(new ram_pcd_message<RAMType>(type, ap, timestamp, root_initial, root, pc_addr, cpu_state,
                                                           pc_addr_initial, cpu_state_initial, has_accepted));
                    return result;
                }

                template<typename RAMType>
                std::shared_ptr<r1cs_pcd_message<ram_base_field<RAMType>>>
                    ram_compliance_predicate_handler<RAMType>::get_final_case_msg(
                        const ram_architecture_params<RAMType> &ap,
                        const ram_boot_trace<RAMType> &primary_input,
                        const std::size_t time_bound) {
                    const std::size_t num_addresses = 1ul << ap.address_size();
                    const std::size_t value_size = ap.value_size();
                    delegated_ra_memory<crh_with_bit_out_component<FieldType>> mem(num_addresses, value_size,
                                                                                primary_input.as_memory_contents());

                    const std::size_t type = 1;

                    const std::size_t timestamp = time_bound;

                    const std::vector<bool> root_initial = mem.get_root();
                    const std::size_t pc_addr_initial = ap.initial_pc_addr();
                    const std::vector<bool> cpu_state_initial(ap.cpu_state_size(), false);

                    const std::vector<bool> root(root_initial.size(), false);
                    const std::size_t pc_addr = 0;
                    const std::vector<bool> cpu_state = cpu_state_initial;

                    const bool has_accepted = true;

                    std::shared_ptr<r1cs_pcd_message<FieldType>> result;
                    result.reset(new ram_pcd_message<RAMType>(type, ap, timestamp, root_initial, root, pc_addr, cpu_state,
                                                           pc_addr_initial, cpu_state_initial, has_accepted));
                    return result;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_RAM_COMPLIANCE_PREDICATE_HPP
