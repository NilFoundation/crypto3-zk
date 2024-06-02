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
// @file Declaration of interfaces for a delegated random-access memory.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_DELEGATED_RA_MEMORY_HPP_
#define CRYPTO3_ZK_DELEGATED_RA_MEMORY_HPP_

#include <map>
#include <memory>
#include <vector>

#include <nil/crypto3/zk/snark/merkle_tree.hpp>

#include <nil/crypto3/zk/snark/relations/ram_computations/memory/memory_interface.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename Hash>
                class delegated_ra_memory : public memory_interface {
                private:
                    std::vector<bool> int_to_tree_elem(const std::size_t i) const;
                    std::size_t int_from_tree_elem(const std::vector<bool> &v) const;

                    std::unique_ptr<merkle_tree<Hash>> contents;

                public:
                    delegated_ra_memory(const std::size_t num_addresses, const std::size_t value_size);
                    delegated_ra_memory(const std::size_t num_addresses, const std::size_t value_size,
                                        const std::vector<std::size_t> &contents_as_vector);
                    delegated_ra_memory(const std::size_t num_addresses, const std::size_t value_size,
                                        const memory_contents &contents_as_map);

                    std::size_t get_value(std::size_t address) const;
                    void set_value(std::size_t address, std::size_t value);

                    typename Hash::hash_value_type get_root() const;
                    typename Hash::merkle_authentication_path_type get_path(const std::size_t address) const;

                    void dump() const;
                };

                template<typename Hash>
                std::vector<bool> delegated_ra_memory<Hash>::int_to_tree_elem(const std::size_t i) const {
                    std::vector<bool> v(value_size, false);
                    for (std::size_t k = 0; k < value_size; ++k) {
                        v[k] = ((i & (1ul << k)) != 0);
                    }
                    return v;
                }

                template<typename Hash>
                std::size_t delegated_ra_memory<Hash>::int_from_tree_elem(const std::vector<bool> &v) const {
                    std::size_t result = 0;
                    for (std::size_t i = 0; i < value_size; ++i) {
                        result |= (v[i] ? 1ul : 0ul) << i;
                    }

                    return result;
                }

                template<typename Hash>
                delegated_ra_memory<Hash>::delegated_ra_memory(const std::size_t num_addresses, const std::size_t value_size) :
                    memory_interface(num_addresses, value_size) {
                    contents.reset(new merkle_tree<Hash>(static_cast<std::size_t>(std::ceil(std::log2(num_addresses))),
                                                          value_size));
                }

                template<typename Hash>
                delegated_ra_memory<Hash>::delegated_ra_memory(const std::size_t num_addresses,
                                                                const std::size_t value_size,
                                                                const std::vector<std::size_t> &contents_as_vector) :
                    memory_interface(num_addresses, value_size) {
                    std::vector<std::vector<bool>> contents_as_bit_vector_vector(contents.size());
                    std::transform(contents_as_vector.begin(),
                                   contents_as_vector.end(),
                                   contents_as_bit_vector_vector,
                                   [this](std::size_t value) { return int_to_tree_elem(value); });
                    contents.reset(new merkle_tree<Hash>(static_cast<std::size_t>(std::ceil(std::log2(num_addresses))),
                                                          value_size, contents_as_bit_vector_vector));
                }

                template<typename Hash>
                delegated_ra_memory<Hash>::delegated_ra_memory(const std::size_t num_addresses,
                                                                const std::size_t value_size,
                                                                const std::map<std::size_t, std::size_t> &contents_as_map) :
                    memory_interface(num_addresses, value_size) {
                    std::map<std::size_t, std::vector<bool>> contents_as_bit_vector_map;
                    for (auto &it : contents_as_map) {
                        contents_as_bit_vector_map[it.first] = int_to_tree_elem(it.second);
                    }

                    contents.reset(new merkle_tree<Hash>(static_cast<std::size_t>(std::ceil(std::log2(num_addresses))),
                                                          value_size, contents_as_bit_vector_map));
                }

                template<typename Hash>
                std::size_t delegated_ra_memory<Hash>::get_value(std::size_t address) const {
                    return int_from_tree_elem(contents->get_value(address));
                }

                template<typename Hash>
                void delegated_ra_memory<Hash>::set_value(std::size_t address, std::size_t value) {
                    contents->set_value(address, int_to_tree_elem(value));
                }

                template<typename Hash>
                typename Hash::hash_value_type delegated_ra_memory<Hash>::get_root() const {
                    return contents->get_root();
                }

                template<typename Hash>
                typename Hash::merkle_authentication_path_type
                    delegated_ra_memory<Hash>::get_path(const std::size_t address) const {
                    return contents->get_path(address);
                }

                template<typename Hash>
                void delegated_ra_memory<Hash>::dump() const {
                    contents->dump();
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // DELEGATED_RA_MEMORY_HPP_
