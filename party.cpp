#include <iostream>

#include <stdexcept>
#include <set>
#include <map>
#include <gmpxx.h>
#include "tlc.h"
#include "party.h"
#include "rand_range.h"

using namespace std;

namespace tlc {

party::party(party_id_t id, set<party_id_t> party_ids, vector<mpz_class>::size_type secret_sharing_threshold) :
    id(id),
    party_ids(party_ids),
    polynomial(secret_sharing_threshold),
    secret_shares(),
    verification_commitments(secret_sharing_threshold)
{
    if(id == 0) throw invalid_argument("party id can't be 0");

    cout << "Party " << id << " info: " << endl << "  polynomial: [ ";
    for(auto& coefficient : polynomial) {
        coefficient = rand_range(finite_field_order - 1) + 1;
        cout << coefficient << " ";
    }
    cout << "]" << endl;

    cout << "  secret shares: [ ";
    for(auto party_id : party_ids) {
        if(party_id == 0) throw logic_error("no party id in party ids can be 0");

        mpz_class secret_share = 0;
        for(vector<mpz_class>::size_type k = 0; k < secret_sharing_threshold; ++k) {
            secret_share = (secret_share + polynomial[k] * pow(party_id, k)) % field_units_group_order;
        }
        secret_shares[party_id] = secret_share;
        cout << secret_share << " ";
    }
    cout << "]" << endl;

    cout << "  verification commitments: [ ";
    for(vector<mpz_class>::size_type j = 0; j < secret_sharing_threshold; ++j) {
        mpz_powm(verification_commitments[j].get_mpz_t(), field_units_group_generator.get_mpz_t(), polynomial[j].get_mpz_t(), finite_field_order.get_mpz_t());
        cout << verification_commitments[j] << " ";
    }
    cout << "]"  << endl;
}

}