//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_PICKLES_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_PICKLES_COMMITMENT_SCHEME_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                template<typename CurveType, typename MultiexpMethod>
                class pedersen {
                public:
                    typedef typename CurveType::scalar_field_type field_type;
                    typedef typename CurveType::template g1_type<> group_type;
                    typedef typename field_type::value_type evaluation_type;
                    typedef typename group_type::value_type commitment_type;
                    typedef typename MultiexpMethod multiexp;

                    struct openning_type {
                        //setup as an open key (non trusted, so uniform for both sides)
                        int n = 0;                      //n - number of parties
                        int k = 0;                      //k <= n - number of parties needed to open the secret message
                        commitment_type g = 0;
                        commitment_type h = 0;
                    };

                    struct private_key {
                        evaluation_type s;              //power of g
                        evaluation_type t;              //power of h
                    };

                    struct proof_type {
                        commitment_type E_0 = 0;        //initial commitment
                        std::vector<commitment_type> E; //commitments open for everyone
                        std::vector<private_key> pk;    //private keys for each party
                    };

                    static openning_type key_generator(int n, int k, commitment_type g = 1, commitment_type h = 1) {
                        //evaluates setup for current protocol
                        if (g == 1) {
                            g = random_element<group_type>();
                        }
                        if (h == 1) {
                            h = random_element<group_type>();
                            while (g == h) {
                                h = random_element<group_type>();
                            }
                        }
                        return openning_type(n, k, g, h);
                    }

                    static commitment_type commit(openning_type op, private_key pk) {
                        //pedersen commitment: g^s * h^t
                        return profile_multiexp<group_type, field_type, multiexp>({op.g, op.h}, {pk.s, pk.t});
                    }

                    std::vector<evaluation_type> poly_eval(openning_type op, std::vector<evaluation_type> coeffs) {
                        //computes F(i) for i in range 1..n for polynom F of degree k - proof.E
                        std::vector<evaluation_type> p_i;
                        evaluation_type spare;
                        evaluation_type sum;
                        for (int i = 1; i <= op.n; ++i) {
                            spare = 1;
                            sum = coeffs[0];
                            for (int j = 1; j < op.k; ++ j) {
                                spare *= i;
                                sum += spare * coeffs[j];
                            }
                            p_i.push_back(sum);
                        }
                        return p_i;
                    }

                    static proof_type proof_eval(openning_type op, evaluation_type w) {
                        //evaluates proof according to pedersen commitment '81
                        proof_type prf;

                        evaluation_type t = random_element<field_type>();
                        prf.E_0 = commitment(op, private_key(w, t));

                        std::vector<evaluation_type> f_coeffs;
                        f_coeffs.push_back(w);
                        std::vector<evaluation_type> g_coeffs;
                        g_coeffs.push_back(t);
                        evaluation_type spare;
                        for (int i = 1; i < op.k; ++i) {
                            spare = random_element<field_type>();
                            f_coeffs.push_back(spare);
                            spare = random_element<field_type>();
                            g_coeffs.push_back(spare);
                        }
                        std::vector<evaluation_type> s_i = poly_eval(op, f_coeffs); //pair (s_i[j], t_i[j]) is given exclusively
                        std::vector<evaluation_type> t_i = poly_eval(op, g_coeffs); //to party number j
                        for (int i = 0; i < op.n; ++i) {
                            prf.pk.push_back(PrivateKey(s_i[i], t_i[i]));
                        }
                        for (int i = 1; i < op.k; ++ i) {
                            prf.E.push_back(commitment(op, private_key(f_coeffs[i], g_coeffs[i])));
                        }

                        return prf;

                    }

                    static bool verify_eval(openning_type op, proof_type prf) {
                        //vefifies that everyone is sure one knows the secret message
                        bool answer = true;

                        evaluation_type pow;
                        commitment_type E;
                        commitment_type mult;
                        for (int i = 1; i <= op.n; ++i) {
                            E = commitment(op, prf.pk[i -1]);
                            mult = op.E_0;
                            pow = 1;
                            for (int j = 1; j < op.k; ++j) {
                                pow *= i;
                                mult *= profile_multiexp<group_type, field_type, multiexp>({pubk.E[j - 1]}, {pow});
                            }
                            answer *= (E == mult);
                        }

                        return answer;
                    }

                    static evaluation_type message_eval(openning_type op, proof_type prf, std::vector<int> idx) {
                        //for a given number of people learns if they can open message
                        //and if so, opens it
                        if ((idx.size() < op.k) || (!verify_eval(op, prf))) {
                            return 0;
                        }

                        evaluation_type sum = 0;
                        evaluation_type mult = 1;
                        for (int j = 0; j < op.k; ++j) {
                            mult = 1;
                            for (int l = 0; l < op.k; ++l) {
                                if (l != j) {
                                    mult *= static_cast<field_type>(idx[l]) * static_cast<field_type>(idx[l] - idx[j]).inversed();
                                }
                            }
                            sum += mult * prf.pk[idx[j] - 1].s;
                        }
                        return sum;
                    }

                };

            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PICKLES_COMMITMENT_SCHEME_HPP
