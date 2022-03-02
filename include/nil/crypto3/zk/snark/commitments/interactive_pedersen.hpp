#include <random>
#include <vector>
#include <iostream>

/*an interactive verifiable scheme
of type commitment = g^s * h^t */


template <typename CurveType>
struct PublicKey {
    CurveType::template g1_type<>::value_type g = 0;
    CurveType::template g1_type<>::value_type h = 0;
    CurveType::template g1_type<>::value_type E_0 = 0;      // E(s, t)
    CurveType::template g1_type<>::value_type E_1 = 0;      // E(x, y)
    CurveType::basic_field_type::value_type e = 0;          // random value chosen by reciever
    CurveType::basic_field_type::value_type u = 0;          // s_1 + e * s
    CurveType::basic_field_type::value_type v = 0;          // t_1 + e * t
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
    //computes E(s,p) = g^s * h^t
    // return power(pubk.g, prik.s) * power(pubk.h, prik.t);
    return profile_multiexp<CurveType::template g1_type<>, CurveType::basic_field_type, MultiexpMethod>({pubk.g, pubk.h}, {prik.s, prik.t});
}

template <typename CurveType, typename MultiexpMethod>
void scheme(PublicKey& pubk, PrivateKey& prik_0, PrivateKey& prik_1) {
	pubk.E_0 = commitment<CurveType, MultiexpMethod>(pubk, prik_0);
    pubk.E_1 = commitment<CurveType, MultiexpMethod>(pubk, prik_1);
    
    pubk.u = prik_1.s + pubk.e * prik_0.s;
    pubk.v = prik_1.t + pubk.e * prik_0.t;
}