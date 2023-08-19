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

#ifndef CRYPTO3_ZK_STUB_PLACEHOLDER_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_STUB_PLACEHOLDER_COMMITMENT_SCHEME_HPP

#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/eval_storage.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                template<typename FieldType, typename CommitmentType> 
                struct commitment_scheme_params_type{
                    using commitment_type = CommitmentType;
                    using field_type = FieldType;
                };

                template<typename ParamsType, typename TranscriptType> 
                class polys_evaluator{
                public:
                    using params_type = ParamsType;
                    using commitment_type = typename ParamsType::commitment_type;
                    using field_type = typename ParamsType::field_type;
                    using transcript_type = TranscriptType;
                    using poly_type = typename math::polynomial_dfs<typename field_type::value_type>;

                    struct proof_type{
                        eval_storage<field_type> z;
                    };

                    eval_storage<field_type> _z;
                    polys_evaluator(){}
                protected:
                    std::map<std::size_t, std::vector<math::polynomial_dfs<typename field_type::value_type>>> _polys;
                    std::map<std::size_t, bool> _locked; // _locked[batch] is true after it is commited
                    std::map<std::size_t, std::vector<std::vector<typename field_type::value_type>>> _points;
                protected:
                    math::polynomial<typename field_type::value_type> get_V(const std::vector<typename field_type::value_type> &points) const{
                        math::polynomial<typename field_type::value_type> V = {1};
  //                      return V;
                        for( std::size_t xi_index = 0; xi_index < points.size(); xi_index++ ){
                            V = V * math::polynomial<typename field_type::value_type>({-points[xi_index], 1});
                        }
                        return V;
                    }
                    math::polynomial<typename field_type::value_type> get_U(std::size_t b_ind, std::size_t poly_ind) const{
//                        return {0};
                        auto &points = _points.at(b_ind)[poly_ind];
                        BOOST_ASSERT(points.size() == this->_z.get_poly_points_number(b_ind, poly_ind));
                        std::vector<std::pair<typename field_type::value_type,typename field_type::value_type>> U_interpolation_points;

                        U_interpolation_points.resize(points.size());
                        for(std::size_t k = 0; k < points.size(); k++){
                            U_interpolation_points[k] = std::make_pair( points[k], this->_z.get(b_ind, poly_ind, k) );
                        }

                        return math::lagrange_interpolation(U_interpolation_points);
                    }
                    std::vector<std::vector<typename field_type::value_type>> get_unique_points_list() const{
                        std::vector<std::vector<typename field_type::value_type>> unique_points;

                        for(auto const &it:_points){
                            auto k = it.first;
                            for( std::size_t i = 0; i < _points.at(k).size(); i++ ){
                                bool found = false;
                                for( std::size_t j = 0; j < unique_points.size(); j++ ){
                                    if( unique_points[j] == _points.at(k)[i] ){
                                        found = true;
                                        break;
                                    }
                                }
                                if( !found ){
                                    unique_points.push_back(_points.at(k)[i]);
                                }
                            }
                        }
                        return unique_points;
                    }

                    std::map<std::size_t, std::vector<std::size_t>> get_eval_map( const std::vector<std::vector<typename field_type::value_type>> unique_points ) const{
                        std::map<std::size_t, std::vector<std::size_t>> eval_map;

                        for(auto const &it:_points){
                            auto k = it.first;
                            eval_map[k] = {};
                            for( std::size_t i = 0; i < _points.at(k).size(); i++ ){
                                bool found = false;
                                for( std::size_t j = 0; j < unique_points.size(); j++ ){
                                    if( unique_points[j] == _points.at(k)[i] ){
                                        eval_map[k].push_back(j);
                                        found = true;
                                        break;
                                    }
                                }
                                BOOST_ASSERT(found);
                            }
                        }
                        return eval_map;
                    }


                    void state_commited(std::size_t index){
                        _locked[index] = true;
                        _points[index].resize(_polys[index].size());
                    }
                    void eval_polys(){
                        for(auto it = _polys.begin(); it != _polys.end(); ++it){
                            _z.set_batch_size(it->first, it->second.size());
                            BOOST_ASSERT(it->second.size() == _points.at(it->first).size() || _points.at(it->first).size() == 1);
                            for( std::size_t i = 0; i < it->second.size(); i++ ){
                                _z.set_poly_points_number(it->first, i, _points.at(it->first)[i].size());
                                for(std::size_t j = 0; j < _points.at(it->first)[i].size(); j++){
                                    _z.set(it->first, i, j, it->second[i].evaluate(_points.at(it->first)[i][j]));
                                }
                            }
                        } 
                    }
                public:
                    void setup(transcript_type &transcript){}

                    void append_to_batch(std::size_t index, const poly_type& poly){
                        if( _locked.find(index) == _locked.end() ) _locked[index] = false;
                        BOOST_ASSERT(!_locked[index]); // We cannot modify batch after commitment
                        _polys[index].push_back(std::move(poly));
                    }

                    template<typename container_type>
                    void append_to_batch(std::size_t index, const container_type& polys){
                        if( _locked.find(index) == _locked.end() ) _locked[index] = false;
                        BOOST_ASSERT(!_locked[index]); // We cannot modify batch after commitment
                        _polys[index].insert(std::end(_polys[index]), std::begin(polys), std::end(polys));
                    }

                    void append_eval_point(std::size_t batch_id, typename field_type::value_type point){
                        BOOST_ASSERT(_locked[batch_id]); // We can add points only after polynomails are commited.
                        for(std::size_t i = 0; i < _points[batch_id].size(); i++){
                            _points[batch_id][i].push_back(point);
                        }
                    }

                    void append_eval_point(std::size_t batch_id, std::size_t poly_id, typename field_type::value_type point){
                        BOOST_ASSERT(_locked[batch_id]); // We can add points only after polynomails are commited.
                        _points[batch_id][poly_id].push_back(point);
                    }

                    // This function don't check evaluation points repeats
                    void append_eval_points(std::size_t batch_id, std::set<typename field_type::value_type> points){
                        BOOST_ASSERT(_locked[batch_id]); // We can add points only after polynomails are commited.
                        for(std::size_t i = 0; i < _points[batch_id].size(); i++){
                            _points[batch_id][i].insert(points.first(), points.last());
                        }
                    }

                    // This function don't check evaluation points repeats
                    void append_eval_points(std::size_t batch_id, std::size_t poly_id, std::set<typename field_type::value_type> points){
                        BOOST_ASSERT(_locked[batch_id]); // We can add points only after polynomails are commited.
                        _points[batch_id][poly_id].insert(points.first(), points.last());
                    }

                    void set_batch_size(std::size_t batch_id, std::size_t batch_size){
                        if( _points.find(batch_id) == _points.end() ){
                            _points[batch_id] = {};
                        }
                        _points[batch_id].resize(batch_size);
                        _locked[batch_id] = true;
                    }

                    commitment_type commit(
                        std::size_t index
                    ){
                        state_commited(index);
                        std::vector<std::uint8_t> arr = {std::uint8_t(index)};

                        return commitment_type(arr);
                    }

                    proof_type proof_eval(
                        transcript_type &transcript
                    ){
                        eval_polys();
                        return proof_type({_z});
                    }

                    bool verify_eval(
                        const proof_type &proof,
                        const std::map<std::size_t, commitment_type> &commitments,
                        transcript_type &transcript
                    ) const {
                        return true;
                    }
                };

                namespace algorithms{
                    // TODO check, that SchemeType has commitment_type and commit functions
                    template<typename FieldType, typename SchemeType>
                    static void setup(SchemeType &scheme, typename SchemeType::transcript_type &transcript ){
                        return scheme.setup(transcript);
                    }

                    // TODO check, that SchemeType has commitment_type and commit functions
                    template<typename FieldType, typename SchemeType>
                    static typename SchemeType::commitment_type commit(
                        SchemeType &scheme, 
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>> &polynomials,
                        std::size_t index
                    ){
                        return scheme.commit(polynomials, index);
                    }

                    // TODO check, that SchemeType has proof_type and proof_eval functions
                    template<typename FieldType, typename SchemeType>
                    static typename SchemeType::proof_type proof_eval(
                        SchemeType &scheme, 
                        const std::vector<std::vector<std::vector<FieldType>>> &evaluation_points,
                        typename SchemeType::transcript_type &transcript
                    ){
                        return scheme.proof_eval(evaluation_points);
                    }

                    // TODO check, that SchemeType has proof_type and verify_eval functions
                    template<typename FieldType, typename SchemeType>
                    static bool verify_eval(
                        SchemeType &scheme, 
                        const typename SchemeType::proof_type &proof,
                        const std::map<std::size_t, std::vector<std::vector<FieldType>>> &evaluation_points,
                        const std::map<std::size_t, typename SchemeType::commitment_type> &commitments,
                        typename SchemeType::transcript_type &transcript
                    ){
                        return scheme.verify_eval(proof, evaluation_points, commitments);
                    }

                }
            }
        }
    }
}

#endif // CRYPTO3_ZK_STUB_PLACEHOLDER_COMMITMENT_SCHEME_HPP