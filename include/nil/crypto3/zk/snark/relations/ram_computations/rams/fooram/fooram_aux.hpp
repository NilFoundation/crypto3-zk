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
// @file Declaration of auxiliary functions for FOORAM.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_FOORAM_AUX_HPP_
#define CRYPTO3_ZK_FOORAM_AUX_HPP_

#include <iostream>
#include <vector>

#include <nil/crypto3/zk/snark/relations/ram_computations/memory/memory_interface.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                typedef std::vector<std::size_t> fooram_program;
                typedef std::vector<std::size_t> fooram_input_tape;
                typedef typename std::vector<std::size_t>::const_iterator fooram_input_tape_iterator;

                class fooram_architecture_params {
                public:
                    std::size_t w;
                    fooram_architecture_params(const std::size_t w = 16);

                    std::size_t num_addresses() const;
                    std::size_t address_size() const;
                    std::size_t value_size() const;
                    std::size_t cpu_state_size() const;
                    std::size_t initial_pc_addr() const;

                    memory_contents initial_memory_contents(const fooram_program &program,
                                                            const fooram_input_tape &primary_input) const;

                    std::vector<bool> initial_cpu_state() const;
                    bool operator==(const fooram_architecture_params &other) const;
                };

                fooram_architecture_params::fooram_architecture_params(const std::size_t w) : w(w) {
                }

                std::size_t fooram_architecture_params::num_addresses() const {
                    return 1ul << w;
                }

                std::size_t fooram_architecture_params::address_size() const {
                    return w;
                }

                std::size_t fooram_architecture_params::value_size() const {
                    return w;
                }

                std::size_t fooram_architecture_params::cpu_state_size() const {
                    return w;
                }

                std::size_t fooram_architecture_params::initial_pc_addr() const {
                    return 0;
                }

                memory_contents
                    fooram_architecture_params::initial_memory_contents(const fooram_program &program,
                                                                        const fooram_input_tape &primary_input) const {
                    memory_contents m;
                    /* fooram memory contents do not depend on program/input. */
                    BOOST_ATTRIBUTE_UNUSED(program, primary_input);
                    return m;
                }

                std::vector<bool> fooram_architecture_params::initial_cpu_state() const {
                    std::vector<bool> state;
                    state.resize(w, false);
                    return state;
                }

                bool fooram_architecture_params::operator==(const fooram_architecture_params &other) const {
                    return (this->w == other.w);
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // FOORAM_AUX_HPP_
