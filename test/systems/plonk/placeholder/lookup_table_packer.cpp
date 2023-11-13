//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin
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

#include <cstddef>
#define BOOST_TEST_MODULE zk_lookup_table_packer_test

#include <iostream>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

class test_lookup_table : public lookup_table_definition<algebra::curves::pallas::base_field_type> {
public:
    std::size_t rows_amount;
    std::size_t columns_amount;

    test_lookup_table(std::size_t _rows_amount, std::size_t _columns_amount) :
        lookup_table_definition<algebra::curves::pallas::base_field_type>(
            "test_table" + std::to_string(_rows_amount) + "_" + std::to_string(_columns_amount)),
        rows_amount(_rows_amount),
        columns_amount(_columns_amount) {
            std::vector<std::size_t> column_indices(columns_amount);
            std::iota(column_indices.begin(), column_indices.end(), 0);
            this->subtables["full"] = {column_indices, 0, rows_amount - 1};
        }

    void generate() override {
        _table.resize(columns_amount);
        for (std::size_t i = 0; i < columns_amount; i++) {
            _table[i].resize(rows_amount);
        }
        for (std::size_t i = 0; i < columns_amount; ++i) {
            for (std::size_t j = 0; j < rows_amount; j++) {
                this->_table[i][j] = i * rows_amount + j;
            }
        }
    }

    std::size_t get_columns_number() override {
        return columns_amount;
    }
    virtual std::size_t get_rows_number() override {
        return rows_amount;
    }
};

BOOST_AUTO_TEST_SUITE(lookup_table_packer_test_suite)

BOOST_AUTO_TEST_CASE(horizontal_lookup_table_packer_test) {
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 33;
    constexpr std::size_t SelectorColumns = 50;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams = plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = plonk_constraint_system<FieldType, ArithmetizationParams>;
    plonk_constraint_system<FieldType, ArithmetizationParams> bp;
    plonk_assignment_table<FieldType, ArithmetizationParams> assignment;

    std::map<std::string, std::shared_ptr<lookup_table_definition<FieldType>>> lookup_tables;
    std::map<std::string, std::size_t> lookup_table_ids;

    std::vector<std::size_t> constant_columns_ids(ConstantColumns);
    std::iota(constant_columns_ids.begin(), constant_columns_ids.end(), 0);

    test_lookup_table table(4, 5);
    lookup_tables[table.table_name] = std::make_shared<test_lookup_table>(table);
    lookup_table_ids[table.table_name + "/full"] = 1;

    const std::size_t rows_amount = pack_lookup_tables_horizontal<FieldType, ArithmetizationParams>(
        lookup_table_ids,
        lookup_tables,
        bp,
        assignment,
        constant_columns_ids,
        0,
        2);
    // Check that the folding scheme worked correctly
    const auto &values = table.get_table();
    const auto &constants = assignment.constants();
    for (std::size_t column = 0; column < table.get_columns_number(); column++) {
        for (std::size_t row = 0; row < table.get_rows_number(); row++) {
            const std::size_t assignment_row = 1 + row % 2;
            const std::size_t assignment_column = column + row / 2 * table.columns_amount;
            BOOST_CHECK_EQUAL(constants[assignment_column][assignment_row], values[column][row]);
        }
    }
    // Check that the selector is ther
    const auto &selectors = assignment.selectors();
    BOOST_CHECK_EQUAL(selectors[1][0], 0);
    for (std::size_t row = 1; row < 3; row++) {
        BOOST_CHECK_EQUAL(selectors[1][row], 1);
    }
}

BOOST_AUTO_TEST_SUITE_END()


