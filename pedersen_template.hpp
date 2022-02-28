#include <random>
#include <vector>
#include <iostream>

/*a non-interactive verifiable (k, n)-threshold scheme
secret message s is spread among n parties
such that any k of them can reveal it,
but any m < k cannot.
*/

const int p = 1000003; //big prime number
const int q = 166667; //prime number, divides (p-1)


// template<int MOD = q>
// struct Field {
// 	int value;
// 	static const int mod_value = MOD;

// 	Field(long long v = 0) { 
// 		value = v % mod_value; 
// 		if (value < 0) value += mod_value;
// 	}

//     Field& operator+=(Field const& b) {
//         value += b.value; 
//         if (value >= mod_value) value -= mod_value; 
//         return *this;
//     }
//     Field& operator-=(Field const& b) {
//         value -= b.value; 
//         if (value < 0) value += mod_value;
//         return *this;
//     }
//     Field& operator*=(Field const& b) {
//         value = (long long)value * b.value % mod_value;
//         return *this;
//     }

//     friend Field power(Field a, long long e) {
//         Field res = 1;
//         while (e > 0) { 
//             if (e % 2 == 0) {
//                 a *= a;
//                 e /= 2;
//             } else {
//                 res *= a;
//                 e -= 1;
//             }
//         }
//         return res;
//     }
//     friend Field power(Field a, Field b) {
//         long long e = (long long)b.value;
//         return power(a, e);
//     }
//     friend Field inverse(Field a) { 
//     	return power(a, mod_value - 2); 
//     }

//     friend Field operator+(Field a, Field const b) { return a += b; }
//     friend Field operator-(Field a, Field const b) { return a -= b; }
//     friend Field operator-(Field const a) { return 0 - a; }
//     friend Field operator*(Field a, Field const b) { return a *= b; }
//     friend std::ostream& operator<<(std::ostream& os, Field const& a) {return os << a.value;}
//     friend bool operator==(Field const& a, Field const& b) {return a.value == b.value;}
//     friend bool operator!=(Field const& a, Field const& b) {return a.value != b.value;}
    
//     friend void random(Field& a) {
//         std::random_device rd;
//         std::mt19937 gen(rd());
//         std::uniform_int_distribution<> distrib(1, a.mod_value);
//         a = Field(distrib(gen));
//     }
// };

// template<int MOD = p, int BASE = q>
// struct Group {
// 	int value;
// 	static const int mod_value = MOD;
// 	static const int base_value = BASE;

//     Group(long long v = 0) { 
//     	value = v % mod_value; 
//     	if (value < 0) value += mod_value;
//     }

// 	Group& operator*=(Group const& b) {
//         value = (long long)value * b.value % mod_value;
//         return *this;
//     }

//     friend Group power(const Group& a, long long e) {
//         Group res = 1;
//         e %= base_value;
//         if (e < base_value) {
//         	e += base_value;
//         }
//         Group s(a);
//         while (e > 0) { 
//             if (e % 2 == 0) {
//                 s *= s;
//                 e /= 2;
//             } else {
//                 res *= s;
//                 e -= 1;
//             }
//         }
//         return res;
//     }
//     friend Group power(const Group& a, const Field<>& b) {
//         long long e = (long long)b.value;
//         return power(a, e);
//     }

//     friend Group operator*(Group a, Group const b) 
//     { 
//     	return a *= b; 
//     }
//     friend std::ostream& operator<<(std::ostream& os, Group const& a) {return os << a.value;}
//     friend bool operator==(Group const& a, Group const& b) {return a.value == b.value;}
// };

template <typename CurveType>
f1 (typename CurveType::template g1_type<>::value_type a){
    typename CurveType::template g1_type<>::value_type c = a + CurveType::template g1_type<>::value_type::one();
}

template <typename CurveType>
f2 (typename CurveType::basic_field_type::value_type a){
    typename CurveType::basic_field_type::value_type c = a + CurveType::basic_field_type::value_type::one();
}



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

    // std::cout << "coefficients: ";
    // for (int i = 0; i < k; ++i) {
    //     std::cout << f_coeffs[i] << ' ';
    // }
    // std::cout << '\n';

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