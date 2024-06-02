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
// @file Declaration of interfaces for a random-access memory.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_RA_MEMORY_HPP_
#define CRYPTO3_ZK_RA_MEMORY_HPP_

#include <nil/crypto3/zk/snark/relations/ram_computations/memory/memory_interface.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A random-access memory maintains the memory's contents via a map (from addresses to values).
                 */
                class ra_memory : public memory_interface {
                public:
                    memory_contents contents;

                    ra_memory(const std::size_t num_addresses, const std::size_t value_size);
                    ra_memory(const std::size_t num_addresses, const std::size_t value_size,
                              const std::vector<std::size_t> &contents_as_vector);
                    ra_memory(const std::size_t num_addresses, const std::size_t value_size, const memory_contents &contents);

                    std::size_t get_value(const std::size_t address) const;
                    void set_value(const std::size_t address, const std::size_t value);
                };

                ra_memory::ra_memory(const std::size_t num_addresses, const std::size_t value_size) :
                    memory_interface(num_addresses, value_size) {
                }

                ra_memory::ra_memory(const std::size_t num_addresses,
                                     const std::size_t value_size,
                                     const std::vector<std::size_t> &contents_as_vector) :
                    memory_interface(num_addresses, value_size) {
                    /* copy std::vector into std::map */
                    for (std::size_t i = 0; i < contents_as_vector.size(); ++i) {
                        contents[i] = contents_as_vector[i];
                    }
                }

                ra_memory::ra_memory(const std::size_t num_addresses,
                                     const std::size_t value_size,
                                     const memory_contents &contents) :
                    memory_interface(num_addresses, value_size),
                    contents(contents) {
                }

                std::size_t ra_memory::get_value(const std::size_t address) const {
                    assert(address < num_addresses);
                    auto it = contents.find(address);
                    return (it == contents.end() ? 0 : it->second);
                }

                void ra_memory::set_value(const std::size_t address, const std::size_t value) {
                    contents[address] = value;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RA_MEMORY_HPP_
