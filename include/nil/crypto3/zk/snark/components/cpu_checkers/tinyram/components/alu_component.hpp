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
// @file Declaration of interfaces for the TinyRAM ALU component.
//
// The component checks the correct execution of a given TinyRAM instruction.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_ALU_COMPONENT_HPP
#define CRYPTO3_ZK_ALU_COMPONENT_HPP

#include <nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/alu_arithmetic.hpp>
#include <nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/alu_control_flow.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class ALU_component : public tinyram_standard_component<FieldType> {
                private:
                    std::vector<std::shared_ptr<tinyram_standard_component<FieldType>>> components;

                public:
                    blueprint_variable_vector<FieldType> opcode_indicators;
                    word_variable_component<FieldType> pc;
                    word_variable_component<FieldType> desval;
                    word_variable_component<FieldType> arg1val;
                    word_variable_component<FieldType> arg2val;
                    blueprint_variable<FieldType> flag;
                    blueprint_variable_vector<FieldType> instruction_results;
                    blueprint_variable_vector<FieldType> instruction_flags;

                    ALU_component<FieldType>(tinyram_blueprint<FieldType> &pb,
                                          const blueprint_variable_vector<FieldType> &opcode_indicators,
                                          const word_variable_component<FieldType> &pc,
                                          const word_variable_component<FieldType> &desval,
                                          const word_variable_component<FieldType> &arg1val,
                                          const word_variable_component<FieldType> &arg2val,
                                          const blueprint_variable<FieldType> &flag,
                                          const blueprint_variable_vector<FieldType> &instruction_results,
                                          const blueprint_variable_vector<FieldType> &instruction_flags) :
                        tinyram_standard_component<FieldType>(pb),
                        opcode_indicators(opcode_indicators), pc(pc), desval(desval), arg1val(arg1val),
                        arg2val(arg2val), flag(flag), instruction_results(instruction_results),
                        instruction_flags(instruction_flags) {
                        components.resize(1ul << pb.ap.opcode_width());

                        /* arithmetic */
                        components[tinyram_opcode_AND].reset(new ALU_and_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_AND], instruction_flags[tinyram_opcode_AND]));

                        components[tinyram_opcode_OR].reset(new ALU_or_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_OR], instruction_flags[tinyram_opcode_OR]));

                        components[tinyram_opcode_XOR].reset(new ALU_xor_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_XOR], instruction_flags[tinyram_opcode_XOR]));

                        components[tinyram_opcode_NOT].reset(new ALU_not_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_NOT], instruction_flags[tinyram_opcode_NOT]));

                        components[tinyram_opcode_ADD].reset(new ALU_add_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_ADD], instruction_flags[tinyram_opcode_ADD]));

                        components[tinyram_opcode_SUB].reset(new ALU_sub_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_SUB], instruction_flags[tinyram_opcode_SUB]));

                        components[tinyram_opcode_MOV].reset(new ALU_mov_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_MOV], instruction_flags[tinyram_opcode_MOV]));

                        components[tinyram_opcode_CMOV].reset(new ALU_cmov_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_CMOV], instruction_flags[tinyram_opcode_CMOV]));

                        components[tinyram_opcode_CMPA].reset(new ALU_cmp_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_CMPE], instruction_flags[tinyram_opcode_CMPE],
                            instruction_results[tinyram_opcode_CMPA], instruction_flags[tinyram_opcode_CMPA],
                            instruction_results[tinyram_opcode_CMPAE], instruction_flags[tinyram_opcode_CMPAE]));

                        components[tinyram_opcode_CMPG].reset(new ALU_cmps_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_CMPG], instruction_flags[tinyram_opcode_CMPG],
                            instruction_results[tinyram_opcode_CMPGE], instruction_flags[tinyram_opcode_CMPGE]));

                        components[tinyram_opcode_UMULH].reset(new ALU_umul_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_MULL], instruction_flags[tinyram_opcode_MULL],
                            instruction_results[tinyram_opcode_UMULH], instruction_flags[tinyram_opcode_UMULH]));

                        components[tinyram_opcode_SMULH].reset(new ALU_smul_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_SMULH], instruction_flags[tinyram_opcode_SMULH]));

                        components[tinyram_opcode_UDIV].reset(new ALU_divmod_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_UDIV], instruction_flags[tinyram_opcode_UDIV],
                            instruction_results[tinyram_opcode_UMOD], instruction_flags[tinyram_opcode_UMOD]));

                        components[tinyram_opcode_SHR].reset(new ALU_shr_shl_component<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_SHR], instruction_flags[tinyram_opcode_SHR],
                            instruction_results[tinyram_opcode_SHL], instruction_flags[tinyram_opcode_SHL]));

                        /* control flow */
                        components[tinyram_opcode_JMP].reset(new ALU_jmp_component<FieldType>(
                            pb, pc, arg2val, flag, instruction_results[tinyram_opcode_JMP]));

                        components[tinyram_opcode_CJMP].reset(new ALU_cjmp_component<FieldType>(
                            pb, pc, arg2val, flag, instruction_results[tinyram_opcode_CJMP]));

                        components[tinyram_opcode_CNJMP].reset(new ALU_cnjmp_component<FieldType>(
                            pb, pc, arg2val, flag, instruction_results[tinyram_opcode_CNJMP]));
                    }

                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < 1ul << this->pb.ap.opcode_width(); ++i) {
                            if (components[i]) {
                                components[i]->generate_r1cs_constraints();
                            }
                        }
                    }

                    void generate_r1cs_witness() {
                        for (std::size_t i = 0; i < 1ul << this->pb.ap.opcode_width(); ++i) {
                            if (components[i]) {
                                components[i]->generate_r1cs_witness();
                            }
                        }
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_ALU_COMPONENT_HPP
