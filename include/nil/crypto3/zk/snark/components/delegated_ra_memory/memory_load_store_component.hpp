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
// @file Declaration of interfaces for the memory load&store component.
//
// The component can be used to verify a memory load, followed by a store to the
// same address, from a "delegated memory".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MEMORY_LOAD_STORE_COMPONENT_HPP
#define CRYPTO3_ZK_MEMORY_LOAD_STORE_COMPONENT_HPP

#include <nil/crypto3/zk/snark/components/merkle_tree/merkle_tree_check_update_components.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename Hash>
                using memory_load_store_component = merkle_tree_check_update_component<FieldType, Hash>;

            }
        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MEMORY_LOAD_STORE_COMPONENT_HPP