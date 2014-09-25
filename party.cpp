#include <iostream>

#include <gmpxx.h>
#include "tlc.h"
#include "party.h"
#include "rand_range.h"

using namespace std;

namespace tlc {

party::party(party_id_t id, vector<party>::size_type num_parties, vector<mpz_class>::size_type secret_share_threshold) :
    id{id},
    polynomial(secret_share_threshold),
    secret_shares(num_parties),
    verification_commitments(num_parties)
{
    cout << "Party " << id << " info: " << endl << "  polynomial: ";
    cout << "BTW polynomial size is " << polynomial.size();
    for(size_t j = 0; j < secret_share_threshold; ++j) {
        polynomial[j] = rand_range(finite_field_order - 1) + 1;
        cout << polynomial[j] << "z^" << j;
        if(j != secret_share_threshold-1) cout << " + ";
    }
    cout << endl;

    cout << "  secret shares: ";
    for(vector<mpz_class>::size_type j = 0; j < num_parties; ++j) {
        secret_shares[j] = 0;
        for(vector<mpz_class>::size_type k = 0; k < secret_share_threshold; ++k) {
            secret_shares[j] = (secret_shares[j] + polynomial[k] * pow(j, k)) % field_units_group_order;
        }
        cout << secret_shares[j] << " ";
    }
    cout << endl;

    cout << "  verification commitments: ";
    for(vector<mpz_class>::size_type j = 0; j < secret_share_threshold; ++j) {
        mpz_powm(verification_commitments[j].get_mpz_t(), field_units_group_generator.get_mpz_t(), polynomial[j].get_mpz_t(), finite_field_order.get_mpz_t());
        cout << verification_commitments[j] << " ";
    }
    cout << endl;
}

}