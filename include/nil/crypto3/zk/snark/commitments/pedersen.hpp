#include <random>
#include <vector>
#include <iostream>
#include <algorithm>

/*a non-interactive verifiable (k, n)-threshold scheme
secret message s is spread among n parties
such that any k of them can reveal it,
but any m < k cannot.
*/

template <typename CurveType>
struct PublicKey {
    int n = 0;      //n - number of parties
    int k = 0;      //k <= n
    CurveType::template g1_type<>::value_type g = 0;
    CurveType::template g1_type<>::value_type h = 0;
    CurveType::template g1_type<>::value_type E_0 = 0;
    std::vector<CurveType::template g1_type<>::value_type> E;
};
template <typename CurveType>
struct PrivateKey {
    CurveType::basic_field_type::value_type s;
    CurveType::basic_field_type::value_type t;

    PrivateKey() : s(0), t(0) {}
    PrivateKey(CurveType::basic_field_type::value_type a, CurveType::basic_field_type::value_type b) : s(a), t(b) {}
};

template <typename CurveType, typename MultiexpMethod>
CurveType::template g1_type<>::value_type commitment(const PublicKey& pubk, const PrivateKey& prik) {
    //computes E(s,p) = g^s * h^t, where s - message
    // return power(pubk.g, prik.s) * power(pubk.h, prik.t);
    return profile_multiexp<CurveType::template g1_type<>, CurveType::basic_field_type, MultiexpMethod>({pubk.g, pubk.h}, {prik.s, prik.t});
}

template <typename CurveType>
std::vector<CurveType::basic_field_type::value_type> protocol(int n, int k, std::vector<CurveType::basic_field_type::value_type> coeffs) {
    //computes F(i) for i in range 1..n for polynom F of degree k
    std::vector<CurveType::basic_field_type::value_type> p_i;
    CurveType::basic_field_type::value_type spare;
    CurveType::basic_field_type::value_type sum;
    for (int i = 1; i <= n; ++i) {
        spare = 1;
        sum = coeffs[0];
        for (int j = 1; j < k; ++ j) {
            spare *= i;
            sum += spare * coeffs[j];
        }
        p_i.push_back(sum);
    }
    return p_i;
}

template <typename CurveType, typename MultiexpMethod>
void scheme(PublicKey& pubk, std::vector<PrivateKey>& prik, PrivateKey& prik_0) {
	pubk.E_0 = commitment<CurveType, MultiexpMethod>(pubk, prik_0);
    
    std::vector<CurveType::basic_field_type::value_type> f_coeffs;
    f_coeffs.push_back(prik_0.s);
    std::vector<CurveType::basic_field_type::value_type> g_coeffs;
    g_coeffs.push_back(prik_0.t);
    Field<> spare;
    for (int i = 1; i < pubk.k; ++i) {
        spare = random_element<field_type>();
        f_coeffs.push_back(spare);
        spare = random_element<field_type>();
        g_coeffs.push_back(spare);
    }

    std::vector<CurveType::basic_field_type::value_type> s_i = protocol<CurveType>(pubk.n, pubk.k, f_coeffs); //pair (s_i[j], t_i[j]) is given exclusively
    std::vector<CurveType::basic_field_type::value_type> t_i = protocol<CurveType>(pubk.n, pubk.k, g_coeffs); //to party number j
    for (int i = 0; i < pubk.n; ++i) {
        prik.push_back(PrivateKey(s_i[i], t_i[i]));
    }
    for (int i = 1; i < pubk.k; ++ i) {
    	//all k-1 commitments are public
        pubk.E.push_back(commitment<CurveType, MultiexpMethod>(pubk, PrivateKey(f_coeffs[i], g_coeffs[i])));
    }
}
