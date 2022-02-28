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


template<int MOD = q>
struct Field {
	int value;
	static const int mod_value = MOD;

	Field(long long v = 0) { 
		value = v % mod_value; 
		if (value < 0) value += mod_value;
	}

    Field& operator+=(Field const& b) {
        value += b.value; 
        if (value >= mod_value) value -= mod_value; 
        return *this;
    }
    Field& operator-=(Field const& b) {
        value -= b.value; 
        if (value < 0) value += mod_value;
        return *this;
    }
    Field& operator*=(Field const& b) {
        value = (long long)value * b.value % mod_value;
        return *this;
    }

    friend Field power(Field a, long long e) {
        Field res = 1;
        while (e > 0) { 
            if (e % 2 == 0) {
                a *= a;
                e /= 2;
            } else {
                res *= a;
                e -= 1;
            }
        }
        return res;
    }
    friend Field power(Field a, Field b) {
        long long e = (long long)b.value;
        return power(a, e);
    }
    friend Field inverse(Field a) { 
    	return power(a, mod_value - 2); 
    }

    friend Field operator+(Field a, Field const b) { return a += b; }
    friend Field operator-(Field a, Field const b) { return a -= b; }
    friend Field operator-(Field const a) { return 0 - a; }
    friend Field operator*(Field a, Field const b) { return a *= b; }
    friend std::ostream& operator<<(std::ostream& os, Field const& a) {return os << a.value;}
    friend bool operator==(Field const& a, Field const& b) {return a.value == b.value;}
    friend bool operator!=(Field const& a, Field const& b) {return a.value != b.value;}
    
    friend void random(Field& a) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(1, a.mod_value);
        a = Field(distrib(gen));
    }
};

template<int MOD = p, int BASE = q>
struct Group {
	int value;
	static const int mod_value = MOD;
	static const int base_value = BASE;

    Group(long long v = 0) { 
    	value = v % mod_value; 
    	if (value < 0) value += mod_value;
    }

	Group& operator*=(Group const& b) {
        value = (long long)value * b.value % mod_value;
        return *this;
    }

    friend Group power(const Group& a, long long e) {
        Group res = 1;
        e %= base_value;
        if (e < base_value) {
        	e += base_value;
        }
        Group s(a);
        while (e > 0) { 
            if (e % 2 == 0) {
                s *= s;
                e /= 2;
            } else {
                res *= s;
                e -= 1;
            }
        }
        return res;
    }
    friend Group power(const Group& a, const Field<>& b) {
        long long e = (long long)b.value;
        return power(a, e);
    }

    friend Group operator*(Group a, Group const b) 
    { 
    	return a *= b; 
    }
    friend std::ostream& operator<<(std::ostream& os, Group const& a) {return os << a.value;}
    friend bool operator==(Group const& a, Group const& b) {return a.value == b.value;}
};

struct PublicKey {
    Group<> g = 0;
    Group<> h = 0;
    Group<> E_0 = 0;
    std::vector<Group<>> E;
};
struct PrivateKey {
    Field<> s;
    Field<> t;

    PrivateKey() : s(0), t(0) {}
    PrivateKey(Field<> a, Field<> b) : s(a), t(b) {}
};

Group<> commitment(const PublicKey& pubk, const PrivateKey& prik) {
    //computes E(s,p) = g^s * h^t, where s - message
    return power(pubk.g, prik.s) * power(pubk.h, prik.t);
}

std::vector<Field<>> protocol(int n, int k, std::vector<Field<>> coeffs) {
    //computes F(i) for i in range 1..n for polynom F of degree k
    std::vector<Field<>> p_i;
    Field<> spare;
    Field<> sum;
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

void scheme(int& n, int& k, PrivateKey& prik_0, PublicKey& pubk, std::vector<PrivateKey>& prik) {
	pubk.E_0 = commitment(pubk, prik_0);
    
    std::vector<Field<>> f_coeffs;
    f_coeffs.push_back(prik_0.s);
    std::vector<Field<>> g_coeffs;
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

    std::vector<Field<>> s_i = protocol(n, k, f_coeffs); //pair (s_i[j], t_i[j]) is given exclusively
    std::vector<Field<>> t_i = protocol(n, k, g_coeffs); //to party number j
    for (int i = 0; i < n; ++i) {
        prik.push_back(PrivateKey(s_i[i], t_i[i]));
    }
    for (int i = 1; i < k; ++ i) {
    	//all k-1 commitments are public
        pubk.E.push_back(commitment(pubk, PrivateKey(f_coeffs[i], g_coeffs[i])));
    }
}

bool single_check(int n, int k, const PublicKey& pubk, const std::vector<PrivateKey>& prik) {
    //for each i check that E(s_i, t_i) = E_0 * E_1^(i^1) * ... * E_(k-1)^(i^(k-1))
    bool ans = 1;
    for (int i = 1; i <= n; ++i) {
	    Group<> E = commitment(pubk, prik[i - 1]);
	    Group<> mult(pubk.E_0);
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

bool complex_check(int k, const std::vector<Field<>>& indeces, const std::vector<PrivateKey>& prik, const PrivateKey& prik_0) {
	//check that k parties can retrieve s
	Field<> sum = 0;
	Field<> mult = 1;
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

int main() {
	//define n and k - number of parties and how many we need to open the message
    int n = 600;
    int k = 5;

    PrivateKey prik_0;
    PublicKey pubk;
    std::vector<PrivateKey> prik;

    //secret message
    random(prik_0.s);
    //group members
    pubk.g = 14;
    pubk.h = 114;
    //random t
    random(prik_0.t);
    // std::cout << "s, t: " << prik_0.s << ' ' << prik_0.t << '\n';

    scheme(n, k, prik_0, pubk, prik);

    std::cout << "single check: " << (single_check(n, k, pubk, prik) ? "true" : "false") << '\n';

    std::vector<Field<>> idx = {1, 2, 3, 4, 5};
    std::cout << "complex check: " << (complex_check(k, idx, prik, prik_0) ? "true" : "false") << '\n';

	return 0;
}

int check() {
	int k =5;
	std::vector<Field<>> idx = {Field<>(1), Field<>(2), Field<>(3), Field<>(4), Field<>(5)};
	std::vector<PrivateKey> prik;
	prik.push_back(PrivateKey(154442, 1));
	prik.push_back(PrivateKey(47637, 1));
	prik.push_back(PrivateKey(1731, 1));
	prik.push_back(PrivateKey(92796, 1));
	prik.push_back(PrivateKey(34104, 1));
	prik.push_back(PrivateKey(9462, 1));

	PrivateKey prik_0(49941, 1);

	std::cout << complex_check(k, idx, prik, prik_0);

	// std::cout << inverse(Field<>(-2)) <<'\n';
	return 0;
}