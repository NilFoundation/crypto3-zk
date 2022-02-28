#include <random>
#include <vector>
#include <iostream>

/*a non-interactive verifiable (k, n)-threshold scheme
secret message s is spread among n parties
such that any k of them can reveal it,
but any m < k cannot.
*/

template <typename CurveType>
struct PublicKey {
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

template <typename CurveType>
Group<> commitment(const PublicKey& pubk, const PrivateKey& prik) {
    //computes E(s,p) = g^s * h^t, where s - message
    return power(pubk.g, prik.s) * power(pubk.h, prik.t);
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

template <typename CurveType>
void scheme(int& n, int& k, PrivateKey& prik_0, PublicKey& pubk, std::vector<PrivateKey>& prik) {
	pubk.E_0 = commitment(pubk, prik_0);
    
    std::vector<CurveType::basic_field_type::value_type> f_coeffs;
    f_coeffs.push_back(prik_0.s);
    std::vector<CurveType::basic_field_type::value_type> g_coeffs;
    g_coeffs.push_back(prik_0.t);
    Field<> spare;
    for (int i = 1; i < k; ++i) {
        random(spare);
        f_coeffs.push_back(spare);
        random(spare);
        g_coeffs.push_back(spare);
    }

    std::vector<CurveType::basic_field_type::value_type> s_i = protocol(n, k, f_coeffs); //pair (s_i[j], t_i[j]) is given exclusively
    std::vector<CurveType::basic_field_type::value_type> t_i = protocol(n, k, g_coeffs); //to party number j
    for (int i = 0; i < n; ++i) {
        prik.push_back(PrivateKey(s_i[i], t_i[i]));
    }
    for (int i = 1; i < k; ++ i) {
    	//all k-1 commitments are public
        pubk.E.push_back(commitment(pubk, PrivateKey(f_coeffs[i], g_coeffs[i])));
    }
}

template <typename CurveType>
bool single_check(int n, int k, const PublicKey& pubk, const std::vector<PrivateKey>& prik) {
    //for each i check that E(s_i, t_i) = E_0 * E_1^(i^1) * ... * E_(k-1)^(i^(k-1))
    bool ans = 1;
    for (int i = 1; i <= n; ++i) {
	    CurveType::template g1_type<>::value_type E = commitment(pubk, prik[i - 1]);
	    CurveType::template g1_type<>::value_type mult(pubk.E_0);
	    int pow = 1;
	    for (int j = 1; j < k; ++j) {
	        pow *= i;
	        mult *= power(pubk.E[j - 1], pow);
	    }
	    ans *= (E == mult);
	    // std::cout << (E == mult) << ' ';
	}
	return ans;
}

template <typename CurveType>
bool complex_check(int k, const std::vector<CurveType::basic_field_type::value_type>& indeces, const std::vector<PrivateKey>& prik, const PrivateKey& prik_0) {
	//check that k parties can retrieve s
	CurveType::basic_field_type::value_type sum = 0;
	CurveType::basic_field_type::value_type mult = 1;
	for (int j = 0; j < k; ++j) {
		mult = 1;
		for (int l = 0; l < k; ++l) {
			if (l != j) {
				mult *= indeces[l] * inverse(indeces[j] - indeces[l]);
			}
		}
		sum += mult * prik[j].s;
	}
	return (sum == prik_0.s);
}