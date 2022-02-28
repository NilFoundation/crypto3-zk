#include <random>
#include <vector>
#include <iostream>

/*a non-interactive verifiable (k, n)-threshold scheme
secret message s is spread among n parties
such that any k of them can reveal it,
but anu m < k cannot.
*/

const int p = 1000003;
const int q = 166667;

// struct Field {
//     int base;

//     Field() = delete;
//     Field(int base_) : base(base_) {}
// };

// struct Elem : Field {
//     int elem;

//     Elem() = delete;
//     Elem(int num) : elem(num) {}

//     Elem operator+(Elem& lhs, Elem& rhs) {
//         return Elem((lhs.elem + rhs.elem) % base);
//     }
//     Elem operator+=(Elem& rhs) {
//         *this = *this + rhs;
//         return *this;
//     }

//     Elem operator*(Elem& lhs, Elem& rhs) {
//         return Elem(lhs.elem * rhs.elem % base);
//     }
//     Elem operator*=(Elem& rhs) {
//         *this = *this * rhs;
//         return *this;
//     }
// };

struct PublicKey {
    int g = 0;
    int h = 0;
    int E_0 = 0;
    std::vector<int> E;
};
struct PrivateKey {
    int s;
    int t;

    PrivateKey() : s(0), t(0) {}
    PrivateKey(int a, int b) : s(a), t(b) {}
};

int power(int base, int exp) {
    if (exp == 0) {
        return 1;
    }
    int ans = 1;
    int spare = base;
    while (exp > 0) {
        if (exp % 2 == 0) {
            spare = spare * spare % q;
            exp /= 2;
        } else {
            ans = ans * spare % q;
            exp -= 1;
        }
    }
    return ans;
}

int commitment(const PublicKey& pubk, const PrivateKey& prik) {
    return power(pubk.g, prik.s) * power(pubk.h, prik.t) % q;
}

std::vector<int> protocol(int n, int k, std::vector<int> coeffs) {
    std::vector<int> p_i;
    int spare;
    int sum;
    for (int i = 1; i <= n; ++i) {
        spare = 1;
        sum = 0;
        for (int j = 1; j < k; ++ j) {
            spare = spare * i % q;
            sum = (sum + spare * coeffs[i]) % q;
        }
        p_i.push_back(sum);
    }
    return p_i;
}

void scheme(int& n, int& k, PrivateKey& prik_0, PublicKey& pubk, std::vector<PrivateKey>& prik) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(1, q - 1);

    prik_0.s = distrib(gen);
    prik_0.t = distrib(gen);
    pubk.g = distrib(gen);
    pubk.h = distrib(gen);
    pubk.E_0 = commitment(pubk, prik_0); //E(s, t) - public commitment

    std::vector<int> f_coeffs;
    f_coeffs.push_back(prik_0.s);
    std::vector<int> g_coeffs;
    g_coeffs.push_back(prik_0.t);
    for (int i = 0; i < k - 1; ++i) {
        f_coeffs.push_back(distrib(gen));
        g_coeffs.push_back(distrib(gen));
    }

    for (int i = 1; i <= n; ++ i) {
        pubk.E.push_back(commitment(pubk, PrivateKey(f_coeffs[i], g_coeffs[i])));  //all n commitments are public
    }

    std::vector<int> s_i = protocol(n, k, f_coeffs); //pair (s_i[j], t_i[j]) is given exclusively
    std::vector<int> t_i = protocol(n, k, g_coeffs); //to party number j
    for (int i = 0; i < n; ++i) {
        prik.push_back(PrivateKey(s_i[i], t_i[i]));
    }
}

bool single_check(int i, int k, const PublicKey& pubk, const PrivateKey& prik_i) {
    //for given i check that E(s_i, t_i) = E_0 * E_1^(i^1) * ... * E_(k-1)^(i^(k-1))
    int E = commitment(pubk, prik_i);
    int mult = pubk.E_0;
    for (int j = 1; j < k; ++j) {
        int pow = power(i, j);
        mult = mult * power(pubk.E[j], pow) % q;
    }
    return E == mult;
}

void collective_check() {
    //k+ parties can open s

}

int main() {
    //p = 1000003 - big prime
    //q = 166667 - divides (p-1) and is prime
    // Field q(166667);

    //define n and k - number of parties and how many we need to open the message
    int n = 10;
    int k = 5;
    std::cout << "in main done\n";

    PublicKey pubk;
    std::vector<PrivateKey> prik;
    PrivateKey prik_0;
    scheme(n, k, prik_0, pubk, prik);
    std::cout << "scheme done\n";
    for (int i = 1; i < n; ++i) {
        std::cout << single_check(i, k, pubk, prik[i]) << ' ';
    }

    return 0;
}