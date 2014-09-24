#include <iostream>
#include <random>
#include <chrono>
#include <gmpxx.h>
#include "rfc3526.h"

using namespace std;
using namespace std::chrono;

gmp_randclass mt_gen{gmp_randinit_mt};

// Reseed long before we hit 624
const int reseed_countdown_reset = 42;
int reseed_countdown = 0;

void rand_reseed()
{
    random_device rd;
    unsigned long seed = ((unsigned long) rd() << 32) ^ rd() ^
        high_resolution_clock::now().time_since_epoch().count();
    
    mt_gen.seed(seed);
}

mpz_class rand_range(mpz_class n)
{
    if(reseed_countdown <= 0) {
        rand_reseed();
        reseed_countdown = reseed_countdown_reset;
    }
    --reseed_countdown;
    return mt_gen.get_z_range(n);
}

int main()
{
    auto start = high_resolution_clock::now();

    const mpz_class Fq = 23,
                    UFq = Fq - 1,
                    g = 2_mpz;

    const vector<mpz_class>::size_type n = 10, t = 5;

    auto secret_polynomials = vector<vector<mpz_class>>(n),
         secret_shares = vector<vector<mpz_class>>(n),
         verification_commitments = vector<vector<mpz_class>>(n);

    mpz_class public_key = 1_mpz;

    for(vector<mpz_class>::size_type i = 0; i < n; ++i) {
        secret_polynomials[i] = vector<mpz_class>(t);

        cout << "Party " << i << " polynomial: ";
        for(vector<mpz_class>::size_type j = 0; j < t; ++j) {
            secret_polynomials[i][j] = rand_range(Fq - 1) + 1;
            cout << secret_polynomials[i][j] << "z^" << j;
            if(j != t-1) cout << " + ";
        }
        cout << endl;

        cout << "Party " << i << " secret shares: ";
        secret_shares[i] = vector<mpz_class>(n);
        for(vector<mpz_class>::size_type j = 0; j < n; ++j) {
            secret_shares[i][j] = 0_mpz;
            for(vector<mpz_class>::size_type k = 0; k < t; ++k) {
                secret_shares[i][j] = (secret_shares[i][j] + secret_polynomials[i][k] * pow(j, k)) % UFq;
            }
            cout << secret_shares[i][j] << " ";
        }
        cout << endl;

        cout << "Party " << i << " verification commitments: ";
        verification_commitments[i] = vector<mpz_class>(n);
        for(vector<mpz_class>::size_type j = 0; j < t; ++j) {
            mpz_powm(verification_commitments[i][j].get_mpz_t(), g.get_mpz_t(), secret_polynomials[i][j].get_mpz_t(), Fq.get_mpz_t());
            cout << verification_commitments[i][j] << " ";
        }
        cout << endl;

        public_key = public_key * verification_commitments[i][0] % Fq;
    }

    cout << "Shares check out?" << endl;
    for(vector<mpz_class>::size_type i = 0; i < n; ++i) {
        for(vector<mpz_class>::size_type j = 0; j < n; ++j) {
            mpz_class gxij, prodc = 1_mpz;
            mpz_powm(gxij.get_mpz_t(), g.get_mpz_t(), secret_shares[i][j].get_mpz_t(), Fq.get_mpz_t());
            for(vector<mpz_class>::size_type k = 0; k < t; ++k) {
                mpz_class cjk, jk = pow(j, k);
                mpz_powm(cjk.get_mpz_t(), verification_commitments[i][k].get_mpz_t(), jk.get_mpz_t(), Fq.get_mpz_t());

                prodc = prodc * cjk % Fq;
            }

            cout << (gxij == prodc ? "y" : "n") << " ";
        }
        cout << endl;
    }

    cout <<
        "Service public key:    " << public_key << endl;

    // Encryption
    mpz_class message = rand_range(Fq),
              client_secret = rand_range(Fq - 1) + 1,
              shared_secret, ciphertext_1, ciphertext_2;

    mpz_powm(shared_secret.get_mpz_t(), public_key.get_mpz_t(), client_secret.get_mpz_t(), Fq.get_mpz_t());
    mpz_powm(ciphertext_1.get_mpz_t(), g.get_mpz_t(), client_secret.get_mpz_t(), Fq.get_mpz_t());
    ciphertext_2 = message * shared_secret % Fq;

    cout <<
        "Client message:        " << message << endl <<
        "Client random secret:  " << client_secret << endl <<
        "Client shared secret:  " << shared_secret << endl <<
        "Client ciphertext 1:   " << ciphertext_1 << endl <<
        "Client ciphertext 2:   " << ciphertext_2 << endl;

    // Decryption
    mpz_class private_key = 0_mpz, s2, s_inv, m2;

    for(vector<mpz_class>::size_type i = 0; i < n; ++i) private_key = (private_key + secret_polynomials[i][0]) % UFq;

    cout <<
        "Private key:           " << private_key << endl;

    mpz_powm(s2.get_mpz_t(), ciphertext_1.get_mpz_t(), private_key.get_mpz_t(), Fq.get_mpz_t());
    mpz_invert(s_inv.get_mpz_t(), s2.get_mpz_t(), Fq.get_mpz_t());
    m2 = ciphertext_2 * s_inv % Fq;

    cout <<
        "Shared secrets match:  " << (shared_secret == s2 ? "yes" : "no") << endl <<
        "Messages match:        " << (message == m2 ? "yes" : "no") << endl <<
        "Run time:              " << duration_cast<duration<double>>(high_resolution_clock::now() - start).count() << endl;

    return 0;
}
