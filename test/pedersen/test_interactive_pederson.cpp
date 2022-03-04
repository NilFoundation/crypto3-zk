#include <nil/crypto3/zk/snark/commitments/interactive_pedersen.hpp>

template <typename CurveType, typename MultiexpMethod>
bool check(const PublicKey& pubk) {
    GroupType::value_type left;
    GroupType::value_type right;

    left = profile_multiexp<CurveType::template g1_type<>, CurveType::basic_field_type, MultiexpMethod>({pubk.g, pubk.h}, {pubk.u, pubk.v});
    right = profile_multiexp<CurveType::template g1_type<>, CurveType::basic_field_type, MultiexpMethod>({pubk.E_0, pubk.E_1}, {pubk.e, 1});

    return (left == right);
}

int main() {
    using curve_type = algebra::curves::bls12<381>;
    using curve_group_type = curve_type::template g1_type<>;
    using field_type = typename curve_type::basic_field_type;
    using multiexp = policies::multiexp_method_naive_plain;

    PublicKey pubk;
    PrivateKey prik_0;
    PrivateKey prik_1;

    //random field values for private verifier key
    prik_0.s = random_element<field_type>();
    prik_0.t = random_element<field_type>();
    prik_1.s = random_element<field_type>();
    prik_1.t = random_element<field_type>();
    //random group members
    pubk.g = random_element<curve_group_type>();
    pubk.h = random_element<curve_group_type>();

    bool ans = 1;
    for (int i = 0; i < 1000; ++i) {
        pubk.e = random_element<field_type>();
        scheme<curve_type, multiexp>(pubk, prik_0, prik_1);
        ans *= check<curve_type, multiexp>(pubk);
    }
    std::cout << (ans ? "true" : "false") << '\n';

	return 0;
}