//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_HPP

#include <algorithm>

#include <nil/crypto3/zk/snark/arithmetization/plonk/padding.hpp>

namespace nil {
    namespace blueprint {
        template<typename ArithmetizationType, std::size_t... BlueprintParams>
        class assignment;
    }    // namespace blueprint
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ArithmetizationParams>
                struct plonk_constraint_system;

                template<typename FieldType>
                using plonk_column = std::vector<typename FieldType::value_type>;

                template<typename FieldType, typename ArithmetizationParams, typename ColumnType>
                struct plonk_table;

                template<typename FieldType, typename ArithmetizationParams, typename ColumnType>
                struct plonk_private_table {

                    using witnesses_container_type = std::array<ColumnType, ArithmetizationParams::witness_columns>;

                protected:
                    witnesses_container_type _witnesses;

                public:
                    plonk_private_table(witnesses_container_type witness_columns = {}) : _witnesses(witness_columns) {
                    }

                    std::uint32_t witnesses_amount() const {
                        return _witnesses.size();
                    }

                    std::uint32_t witness_column_size(std::uint32_t index) const {
                        return _witnesses[index].size();
                    }

                    ColumnType witness(std::uint32_t index) const {
                        assert(index < ArithmetizationParams::witness_columns);
                        return _witnesses[index];
                    }

                    witnesses_container_type witnesses() const {
                        return _witnesses;
                    }

                    ColumnType operator[](std::uint32_t index) const {
                        if (index < ArithmetizationParams::witness_columns)
                            return _witnesses[index];
                        index -= ArithmetizationParams::witness_columns;
                        return {};
                    }

                    constexpr std::uint32_t size() const {
                        return witnesses_amount();
                    }

                    friend std::uint32_t basic_padding<FieldType, ArithmetizationParams, ColumnType>(
                        plonk_table<FieldType, ArithmetizationParams, ColumnType> &table);

                    friend struct nil::blueprint::assignment<plonk_constraint_system<FieldType, ArithmetizationParams>>;
                };

                template<typename FieldType, typename ArithmetizationParams, typename ColumnType>
                struct plonk_public_table {

                    using public_input_container_type =
                        std::array<ColumnType, ArithmetizationParams::public_input_columns>;
                    using constant_container_type = std::array<ColumnType, ArithmetizationParams::constant_columns>;
                    using selector_container_type = std::vector<ColumnType>;

                protected:
                    public_input_container_type _public_inputs;
                    constant_container_type _constants;
                    selector_container_type _selectors;

                public:
                    plonk_public_table(public_input_container_type public_input_columns = {},
                                       constant_container_type constant_columns = {},
                                       selector_container_type selector_columns = {}) :
                        _public_inputs(public_input_columns),
                        _constants(constant_columns), _selectors(selector_columns) {
                    }

                    std::uint32_t public_inputs_amount() const {
                        return _public_inputs.size();
                    }

                    std::uint32_t public_input_column_size(std::uint32_t index) const {
                        return _public_inputs[index].size();
                    }

                    ColumnType public_input(std::uint32_t index) const {
                        assert(index < public_inputs_amount());
                        return _public_inputs[index];
                    }

                    public_input_container_type public_inputs() const {
                        return _public_inputs;
                    }

                    std::uint32_t constants_amount() const {
                        return _constants.size();
                    }

                    std::uint32_t constant_column_size(std::uint32_t index) const {
                        return _constants[index].size();
                    }

                    ColumnType constant(std::uint32_t index) const {
                        assert(index < constants_amount());
                        return _constants[index];
                    }

                    constant_container_type constants() const {
                        return _constants;
                    }

                    constexpr std::uint32_t selectors_amount() const {
                        return _selectors.size();
                    }

                    std::uint32_t selector_column_size(std::uint32_t index) const {
                        return _selectors[index].size();
                    }

                    ColumnType selector(std::uint32_t index) const {
                        assert(index < selectors_amount());
                        return _selectors[index];
                    }

                    selector_container_type selectors() const {
                        return _selectors;
                    }

                    ColumnType operator[](std::uint32_t index) const {
                        if (index < public_inputs_amount())
                            return public_input(index);
                        index -= public_inputs_amount();
                        if (index < constants_amount())
                            return constant(index);
                        index -= constants_amount();
                        if (index < selectors_amount()) {
                            return selector(index);
                        }
                        index -= selectors_amount();
                        return {};
                    }

                    constexpr std::uint32_t size() const {
                        return public_inputs_amount() + constants_amount() + selectors_amount();
                    }

                    friend std::uint32_t basic_padding<FieldType, ArithmetizationParams, ColumnType>(
                        plonk_table<FieldType, ArithmetizationParams, ColumnType> &table);

                    friend struct nil::blueprint::assignment<plonk_constraint_system<FieldType, ArithmetizationParams>>;
                };

                template<typename FieldType, typename ArithmetizationParams, typename ColumnType>
                struct plonk_table {

                    using private_table_type = plonk_private_table<FieldType, ArithmetizationParams, ColumnType>;
                    using public_table_type = plonk_public_table<FieldType, ArithmetizationParams, ColumnType>;

                protected:
                    private_table_type _private_table;
                    public_table_type _public_table;

                public:
                    plonk_table(private_table_type private_table = private_table_type(),
                                public_table_type public_table = public_table_type()) :
                        _private_table(private_table),
                        _public_table(public_table) {
                    }

                    ColumnType witness(std::uint32_t index) const {
                        return _private_table.witness(index);
                    }

                    ColumnType public_input(std::uint32_t index) const {
                        return _public_table.public_input(index);
                    }

                    ColumnType constant(std::uint32_t index) const {
                        return _public_table.constant(index);
                    }

                    ColumnType selector(std::uint32_t index) const {
                        return _public_table.selector(index);
                    }

                    ColumnType operator[](std::uint32_t index) const {
                        if (index < _private_table.size())
                            return _private_table[index];
                        index -= _private_table.size();
                        if (index < _public_table.size())
                            return _public_table[index];
                        return {};
                    }

                    private_table_type private_table() const {
                        return _private_table;
                    }

                    public_table_type public_table() const {
                        return _public_table;
                    }

                    std::uint32_t size() const {
                        return _private_table.size() + _public_table.size();
                    }

                    std::uint32_t witnesses_amount() const {
                        return _private_table.witnesses_amount();
                    }

                    std::uint32_t witness_column_size(std::uint32_t index) const {
                        return _private_table.witness_column_size(index);
                    }

                    std::uint32_t public_inputs_amount() const {
                        return _public_table.public_inputs_amount();
                    }

                    std::uint32_t public_input_column_size(std::uint32_t index) const {
                        return _public_table.public_input_column_size(index);
                    }

                    std::uint32_t constants_amount() const {
                        return _public_table.constants_amount();
                    }

                    std::uint32_t constant_column_size(std::uint32_t index) const {
                        return _public_table.constant_column_size(index);
                    }

                    std::uint32_t selectors_amount() const {
                        return _public_table.selectors_amount();
                    }

                    std::uint32_t selector_column_size(std::uint32_t index) const {
                        return _public_table.selector_column_size(index);
                    }

                    std::uint32_t rows_amount() const {
                        std::uint32_t rows_amount = 0;

                        for (std::uint32_t w_index = 0; w_index < witnesses_amount(); w_index++) {
                            rows_amount = std::max(rows_amount, witness_column_size(w_index));
                        }

                        for (std::uint32_t pi_index = 0; pi_index < public_inputs_amount(); pi_index++) {
                            rows_amount = std::max(rows_amount, public_input_column_size(pi_index));
                        }

                        for (std::uint32_t c_index = 0; c_index < constants_amount(); c_index++) {
                            rows_amount = std::max(rows_amount, constant_column_size(c_index));
                        }

                        for (std::uint32_t s_index = 0; s_index < selectors_amount(); s_index++) {
                            rows_amount = std::max(rows_amount, selector_column_size(s_index));
                        }

                        return rows_amount;
                    }

                    friend std::uint32_t
                        basic_padding<FieldType, ArithmetizationParams, ColumnType>(plonk_table &table);
                };

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_private_assignment_table =
                    plonk_private_table<FieldType, ArithmetizationParams, plonk_column<FieldType>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_public_assignment_table =
                    plonk_public_table<FieldType, ArithmetizationParams, plonk_column<FieldType>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_assignment_table = plonk_table<FieldType, ArithmetizationParams, plonk_column<FieldType>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_private_polynomial_table =
                    plonk_private_table<FieldType,
                                        ArithmetizationParams,
                                        math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_public_polynomial_table =
                    plonk_public_table<FieldType,
                                       ArithmetizationParams,
                                       math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_polynomial_table =
                    plonk_table<FieldType, ArithmetizationParams, math::polynomial<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_private_polynomial_dfs_table =
                    plonk_private_table<FieldType,
                                        ArithmetizationParams,
                                        math::polynomial_dfs<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_public_polynomial_dfs_table =
                    plonk_public_table<FieldType,
                                       ArithmetizationParams,
                                       math::polynomial_dfs<typename FieldType::value_type>>;

                template<typename FieldType, typename ArithmetizationParams>
                using plonk_polynomial_dfs_table =
                    plonk_table<FieldType, ArithmetizationParams, math::polynomial_dfs<typename FieldType::value_type>>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_TABLE_HPP
