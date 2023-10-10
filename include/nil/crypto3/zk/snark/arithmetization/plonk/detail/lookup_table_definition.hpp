//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_DETAIL_LOOKUP_TABLE_DEFINITION_HPP
#define CRYPTO3_ZK_PLONK_DETAIL_LOOKUP_TABLE_DEFINITION_HPP

#include <string>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {                    
                    // Interf-ace for lookup table definitions.
                    template<typename FieldType>
                    class lookup_subtable_definition{
                    public:
                        std::vector<std::size_t> column_indices;
                        std::size_t begin;
                        std::size_t end;
                    };

                    template<typename FieldType>
                    class lookup_table_definition{
                    public:
                        std::string table_name;
                        std::vector<std::vector<typename FieldType::value_type>> table;
                        std::map<std::string, lookup_subtable_definition<FieldType>> subtables;
                    //  Interface for lookup table generation as access to table
                    };

                    // Returned value -- new usable_rows.
                    // All tables are necessary for circuit generation.
                    template<typename FieldType, typename ArithmetizationParams>
                    std::size_t pack_lookup_tables(
                        const std::map<std::string, lookup_table_definition<FieldType>> &lookup_tables, 
                        plonk_constraint_system<FieldType, ArithmetizationParams> &bp,
                        plonk_assignment_table<FieldType, ArithmetizationParams> &assignment,
                        const std::vector<std::size_t> &constant_columns_ids,
                        std::size_t usable_rows
                    ){
                        std::size_t usable_rows_after = usable_rows;

                        // Compute first selector index.
                        std::size_t cur_selector_id = 0;
                        for(const auto &gate: bp.gates()){
                            cur_selector_id = std::max(cur_selector_id, gate.selector_index);
                        }
                        for(const auto &lookup_gate: bp.lookup_gates()){
                            cur_selector_id = std::max(cur_selector_id, lookup_gate.tag_index);
                        }
                        cur_selector_id++;

                        // Allocate constant columns
                        std::vector<plonk_column<FieldType>> constant_columns(constant_columns_ids.size());
                        std::vector<plonk_column<FieldType>> selector_columns;
                        for(std::size_t i = 0; i < constant_columns.size(); i++){
                            constant_columns[i] = plonk_column<FieldType>(usable_rows, FieldType::value_type::zero());
                        }

                        std::size_t start_row = 1;
                        std::size_t table_index = 0;
                        for( const auto&[k, table]:lookup_tables ){
                            // Place table into constant_columns.
                            for( std::size_t i = 0; i < table.table.size(); i++ ){
                                if(constant_columns[i].size() < start_row + table.table[i].size()){
                                    constant_columns[i].resize(start_row + table.table[i].size());
                                    if( usable_rows_after < start_row + table.table[i].size() ){
                                        usable_rows_after = start_row + table.table[i].size();
                                    }
                                }
                                for( std::size_t j = 0; j < table.table[i].size(); j++ ){
                                    constant_columns[i][start_row + j] = table.table[i][j];
                                }
                            }

                            for( const auto &[subtable_name, subtable]:table.subtables ){
                                // Create selector
                                plonk_column<FieldType> selector_column(usable_rows_after, FieldType::value_type::zero());
                                for(std::size_t k = subtable.begin; k <= subtable.end; k++){
                                    selector_column[start_row + k] = FieldType::value_type::one();
                                }
                                plonk_lookup_table<FieldType> lookup_table(subtable.column_indices.size(), cur_selector_id);
                                std::vector<plonk_variable<typename FieldType::value_type>> option;
                                for( const auto &column_index:subtable.column_indices ){
                                    plonk_variable<typename FieldType::value_type> var(
                                        constant_columns_ids[column_index], 0, false, plonk_variable<typename FieldType::value_type>::column_type::constant
                                    );
                                    option.push_back(var);
                                }
                                lookup_table.append_option(option);
                                bp.add_lookup_table(lookup_table);

                                assignment.fill_selector(cur_selector_id, selector_column);
                                selector_columns.push_back(selector_column);
                                // Create table declaration
                                table_index++;
                                cur_selector_id++;
                            }
                            start_row += table.table[0].size();
                        }
                        for( std::size_t i = 0; i < constant_columns.size(); i++ ){
                            assignment.fill_constant(constant_columns_ids[i], constant_columns[i]);
                        }
                        return usable_rows_after;
                    }
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_DETAIL_LOOKUP_TABLE_HPP
