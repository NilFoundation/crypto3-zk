//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_ZK_MATH_EXPRESSION_HASHER_HPP
#define CRYPTO3_ZK_MATH_EXPRESSION_HASHER_HPP

#include <vector>
#include <boost/variant/static_visitor.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <nil/crypto3/zk/math/expression.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            template<typename VariableType>
            class expression_hashing_visitor 
                : public boost::static_visitor<std::size_t> {
            public:
                expression_hashing_visitor() {}

                std::size_t hash(
                        const math::expression<VariableType>& expr) const {
                    return boost::apply_visitor(*this, expr.expr);
                }

                std::size_t operator()(
                        const math::term<VariableType>& term) const {
                    std::size_t result = coeff_hasher(term.coeff);
                    auto vars = term.vars;
                    sort(vars.begin(), vars.end());
                    for (const auto& var: vars) {
                        boost::hash_combine(result, vars_hasher(var));
                    }
                    return result;
                }

                std::size_t operator()(
                        const math::pow_operation<VariableType>& pow) const {
                    std::size_t result = boost::apply_visitor(*this, pow.expr.expr);
                    boost::hash_combine(result, pow.power);
                    return result;
                }

                std::size_t operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) const {
                    std::size_t result = boost::apply_visitor(*this, op.expr_left.expr);
                    boost::hash_combine(result, boost::apply_visitor(*this, op.expr_right.expr));
                    boost::hash_combine(result, (std::size_t)op.op);
                    return result;
                }

                private:
                    std::hash<VariableType> vars_hasher;
                    std::hash<typename VariableType::assignment_type> coeff_hasher;
            };

        }    // namespace math
    }    // namespace crypto3
}    // namespace nil

namespace std {

    template <typename VariableType>
    struct std::hash<nil::crypto3::math::term<VariableType>>
    {
        nil::crypto3::math::expression_hashing_visitor<VariableType> hasher;
    
        std::size_t operator()(const nil::crypto3::math::term<VariableType>& term) const
        {
            return hasher.hash(term);
        }
    };
    
    template <typename VariableType>
    struct std::hash<nil::crypto3::math::expression<VariableType>>
    {
        nil::crypto3::math::expression_hashing_visitor<VariableType> hasher;
    
        std::size_t operator()(const nil::crypto3::math::expression<VariableType>& expr) const
        {
            return hasher.hash(expr);
        }
    };

} // namespace std

#endif    // CRYPTO3_ZK_MATH_EXPRESSION_HASHER_HPP
