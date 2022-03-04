#include <nil/crypto3/zk/snark/commitments/pedersen.hpp>

template <typename CurveType, typename MultiexpMethod>
bool single_check(const PublicKey& pubk, const std::vector<PrivateKey>& prik) {
    //for each i check that E(s_i, t_i) = E_0 * E_1^(i^1) * ... * E_(k-1)^(i^(k-1))
    bool ans = 1;
    CurveType::basic_field_type::value_type pow;
    CurveType::template g1_type<>::value_type E;
    CurveType::template g1_type<>::value_type mult;
    for (int i = 1; i <= pubk.n; ++i) {
	    E = commitment<CurveType, MultiexpMethod>(pubk, prik[i - 1]);
	    mult = pubk.E_0;
	    pow = 1;
	    for (int j = 1; j < pubk.k; ++j) {
	        pow *= i;
	        mult *= profile_multiexp<CurveType::template g1_type<>, CurveType::basic_field_type, MultiexpMethod>({pubk.E[j - 1]}, {pow});
	    }
	    ans *= (E == mult);
	}
	return ans;
}

template <typename CurveType>
std::vector<CurveType::basic_field_type::value_type> random_idx(const PublicKey& pubk) {
    std::vector<CurveType::basic_field_type::value_type> idx;
    std::vector<int> v;
    for (int i = 0; i < pubk.n; ++i) {
        v.push_back(i + 1);
    }
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(v.begin(), v.end(), g);

    for (int i = 0; i < pubk.k; ++i) {
        idx.push_back(v[i]);
    }
    return idx;
}

template <typename CurveType>
bool complex_check(const PublicKey& pubk, const std::vector<PrivateKey>& prik, const PrivateKey& prik_0) {
	//check that k parties can retrieve s
    bool ans = 1;
    CurveType::basic_field_type::value_type sum;
    CurveType::basic_field_type::value_type mult;
    std::vector<CurveType::basic_field_type::value_type> idx;
    for (int times = 0; times < 100; ++times) {
        idx = random_idx(pubk);
    	sum = 0;
    	mult = 1;
    	for (int j = 0; j < pubk.k; ++j) {
    		mult = 1;
    		for (int l = 0; l < pubk.k; ++l) {
    			if (l != j) {
    				mult *= idx[l] * (idx[l] - idx[j]).inversed();
    			}
    		}
    		sum += mult * prik[static_cast<int>(idx[j]) - 1].s;
    	}
    	ans *= (sum == prik_0.s);
    }
    return ans;
}

int main() {
    using curve_type = algebra::curves::bls12<381>;
    using curve_group_type = curve_type::template g1_type<>;
    using field_type = typename curve_type::basic_field_type;
    using multiexp = policies::multiexp_method_naive_plain;

    bool ans_single = 1;
    bool ans_complex = 1;

	PrivateKey prik_0;
    PublicKey pubk;
    std::vector<PrivateKey> prik;

    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(1, 300);

    for (int times = 0; times < 100; ++times) {
	    //define n and k - number of parties and how many we need to open the message
	    pubk.n = dist(rng);
	    pubk.k = dist(rng);
	    if (pubk.n < pubk.k) std::swap(pubk.n, pubk.k);

	    //secret message
	    prik_0.s = random_element<field_type>();
	    prik_0.t = random_element<field_type>();
	    //group members
	    pubk.g = random_element<curve_group_type>();
	    pubk.h = random_element<curve_group_type>();

	    scheme<curve_type, multiexp>(pubk, prik, prik_0);

	    ans_single *= single_check<curve_type, multiexp>(pubk, prik);
	    ans_complex *= complex_check<curve_type>(pubk, prik, prik_0);
	}

	std::cout << "single check: " << (ans_single ? "true" : "false") << '\n';
	std::cout << "complex check: " << (ans_complex ? "true" : "false") << '\n';

	return 0;
}
