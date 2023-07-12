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

#ifndef CRYPTO3_ZK_MATH_EXPRESSION_EVALUATOR_HPP
#define CRYPTO3_ZK_MATH_EXPRESSION_EVALUATOR_HPP

#include <vector>
#include <boost/variant/static_visitor.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_hasher.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            // Evaluates a given expression, running over the expression tree.
            template<typename VariableType>
            class expression_evaluator : public boost::static_visitor<typename VariableType::assignment_type> {
            public:
                using ValueType = typename VariableType::assignment_type;
    
                /*
                 * @param expr - the expression that will be evaluated.
                 *  @param get_var_value - A function which can return the value for a given variable.
                 */
                expression_evaluator(
                    const math::expression<VariableType>& expr,
                    std::function<ValueType(const VariableType&)> get_var_value)
                        : expr(expr)
                        , get_var_value(get_var_value) {
                }

                ValueType evaluate() const {
                    return boost::apply_visitor(*this, expr.expr);
                }

                ValueType operator()(const math::term<VariableType>& term) const {
                    ValueType result = term.coeff;
                    for (const VariableType& var : term.vars) {
                        result *= get_var_value(var);
                    }
                    return result;
                }

                ValueType operator()(
                        const math::pow_operation<VariableType>& pow) const {
                    ValueType result = boost::apply_visitor(*this, pow.expr.expr);
                    return result.pow(pow.power);
                }

                ValueType operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) const {
                    
                    ValueType result = boost::apply_visitor(*this, op.expr_left.expr);
                    switch (op.op) {
                        case ArithmeticOperator::ADD:
                            result += boost::apply_visitor(*this, op.expr_right.expr);
                            break;
                        case ArithmeticOperator::SUB:
                            result -= boost::apply_visitor(*this, op.expr_right.expr);
                            break;
                        case ArithmeticOperator::MULT:
                            result *= boost::apply_visitor(*this, op.expr_right.expr);
                            break;
                    }
                    return result;
                }

            private:
                const math::expression<VariableType>& expr;

                // A function used to retrieve the value of a variable.
                std::function<ValueType(const VariableType &var)> get_var_value;

           };

            // Counts how many times each subexpression appears in a given expression.
            template<typename VariableType>
            class subexpression_counter : public boost::static_visitor<void> {
            public:
                using ValueType = typename VariableType::assignment_type;
    
                subexpression_counter(
                    const math::expression<VariableType>& expr)
                        : expr(expr) {
                }

                std::unordered_map<math::expression<VariableType>, size_t> count() {
                    boost::apply_visitor(*this, expr.expr);
                    return std::move(_counts);
                }

                void operator()(const math::term<VariableType>& term) {
                    _counts[term]++;
                }

                void operator()(
                        const math::pow_operation<VariableType>& pow) {
                    _counts[pow]++;
                    boost::apply_visitor(*this, pow.expr.expr);
                }

                void operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                    _counts[op]++;
                    boost::apply_visitor(*this, op.expr_left.expr);
                    boost::apply_visitor(*this, op.expr_right.expr);
                }

            private:
                const math::expression<VariableType>& expr;

                // Maps each subexpression to the number of occurences.
                std::unordered_map<math::expression<VariableType>, size_t> _counts;
            };

            // Evaluates a given expression, running over the expression tree twice.
            // On the first run, for each node we store how many times it appeared,
            // then on second run we cache evaluation values for nodes that appeared more than once, 
            // so they can be reused.
            template<typename VariableType>
            class cached_expression_evaluator : public boost::static_visitor<typename VariableType::assignment_type> {
            public:
                using ValueType = typename VariableType::assignment_type;

                /** \Brief Later this class can optimize the given expression 
                           before starting the evaluation.
                 * @param expr - the expression that will be evaluated.
                 *  @param get_var_value - A function which can return the value for a given variable.
                 */
                cached_expression_evaluator(
                    const math::expression<VariableType>& expr,
                    std::function<ValueType(const VariableType&)> get_var_value)
                        : _expr(expr)
                        , _get_var_value(get_var_value) {
                }

                ValueType evaluate() {
                    // First compute how many times each subexpression will appear.
                    subexpression_counter<VariableType> counter(_expr); 
                    _counts = counter.count(); 
       
                    return boost::apply_visitor(*this, _expr.expr);
                }

                ValueType operator()(const math::term<VariableType>& term) {
                    auto iter = _cache.find(term);
                    if (iter != _cache.end()) {
                        return iter->second;
                    }
                    ValueType result = term.coeff;
                    for (const VariableType& var : term.vars) {
                        result *= _get_var_value(var);
                    }
                    if (_counts[term] > 1) {
                        _cache[term] = result;
                    }
                    return result;
                }

                ValueType operator()(
                        const math::pow_operation<VariableType>& pow) {
                    auto iter = _cache.find(pow);
                    if (iter != _cache.end()) {
                        return iter->second;
                    }
                    ValueType result = boost::apply_visitor(*this, pow.expr.expr);
                    if (_counts[pow] > 1) {
                        _cache[pow] = result;
                    }
                    return result.pow(pow.power);
                }

                ValueType operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                    auto iter = _cache.find(op);
                    if (iter != _cache.end()) {
                        return iter->second;
                    }
 
                    ValueType result = boost::apply_visitor(*this, op.expr_left.expr);
                    switch (op.op) {
                        case ArithmeticOperator::ADD:
                            result += boost::apply_visitor(*this, op.expr_right.expr);
                            break;
                        case ArithmeticOperator::SUB:
                            result -= boost::apply_visitor(*this, op.expr_right.expr);
                            break;
                        case ArithmeticOperator::MULT:
                            result *= boost::apply_visitor(*this, op.expr_right.expr);
                            break;
                    }
                    if (_counts[op] > 1) {
                        _cache[op] = result;
                    }
                    return result;
                }

            private:
                const math::expression<VariableType>& _expr;

                // A function used to retrieve the value of a variable.
                std::function<ValueType(const VariableType &var)> _get_var_value;

                // Shows how many times each subexpression appears.
                std::unordered_map<math::expression<VariableType>, size_t> _counts;

                // Stores evaluation results for some subexpressions.
                std::unordered_map<math::expression<VariableType>, ValueType> _cache;
            };
        }    // namespace math
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MATH_EXPRESSION_EVALUATOR_HPP
