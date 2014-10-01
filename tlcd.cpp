#include <iostream>
#include <iterator>
#include <chrono>
#include <gmpxx.h>
#include <map>
#include <set>
#include <tuple>

#include "tlc.h"
#include "party.h"
#include "rfc3526.h"
#include "rand_range.h"

using namespace std;
using namespace std::chrono;
using namespace tlc;

int main()
{
    auto start = high_resolution_clock::now();

    const vector<party>::size_type n = 9;
    const vector<mpz_class>::size_type t = 5;

    auto party_ids = vector<party_id_t>();

    for (party_id_t i = 1; i <= n; ++i)
        party_ids.push_back(i);

    auto verification_commitments = map<party_id_t, vector<mpz_class>>();
    auto secret_share_disputes = vector<tuple<party_id_t, party_id_t, mpz_class>>();
    auto disqualification_votes = map<party_id_t, set<party_id_t>>();
    auto qualified_party_ids = vector<party_id_t>();
    auto private_key_parts = map<party_id_t, mpz_class>();
    auto secret_shares = map<party_id_t, map<party_id_t, mpz_class>>();
    auto computed_private_keys = map<party_id_t, mpz_class>();

    auto parties = vector<party>();

    auto start_construction = high_resolution_clock::now();
    for(const auto& party_id : party_ids) {
        parties.push_back(
            party(
                party_id,
                party_ids,
                t,
                verification_commitments,
                secret_share_disputes,
                disqualification_votes,
                qualified_party_ids,
                private_key_parts,
                secret_shares,
                computed_private_keys));
    }
    cout << "Average construction time: " <<
        duration_cast<duration<double>>(high_resolution_clock::now() - start_construction).count() / n << endl;

    LOG("Sending secret shares appropriately:" << endl);
    for(auto& party1 : parties)
        for(auto& party2 : parties)
            party1.send_secret_share(party2);

    auto start_share_checking = high_resolution_clock::now();
    LOG("Checking shares" << endl);
    for(auto& party : parties)
        party.check_recieved_secret_shares();
    cout << "Average share checking time: " <<
        duration_cast<duration<double>>(high_resolution_clock::now() - start_share_checking).count() / n << endl;

    LOG("Share disputes:" << endl);
    for(auto& dispute : secret_share_disputes)
        LOG(get<0>(dispute) << " < " << get<1>(dispute) << ": " << get<2>(dispute) << endl);

    for(auto& party : parties)
        party.submit_disqualification_votes();

    LOG("Disqualification votes:" << endl);

    auto disqualification_tally = map<party_id_t, size_t>();
    for(const auto& party_id : party_ids) {
        LOG(party_id << ": [ ");
        for(auto& dq_vote : disqualification_votes[party_id]) {
            ++disqualification_tally[dq_vote];
            LOG(dq_vote << " ");
        }
        LOG("]" << endl);
    }

    for(const auto& party_id : party_ids) {
        LOG(party_id << " has " << disqualification_tally[party_id] << " votes for disqualification." << endl);
        if(disqualification_tally[party_id] <= n / 2) {
            qualified_party_ids.push_back(party_id);
        } else LOG(party_id << " has been disqualified." << endl);
    }

    mpz_class public_key = 1;

    for(const auto& party_id : qualified_party_ids) {
        public_key = public_key * verification_commitments[party_id][0] % finite_field_order;
    }

    LOG("Service public key:    " << public_key << endl);

    // Encryption
    mpz_class message = rand_range(finite_field_order),
              client_secret = rand_range(finite_field_order - 1) + 1,
              shared_secret, ciphertext_1, ciphertext_2;

    mpz_powm(shared_secret.get_mpz_t(), public_key.get_mpz_t(), client_secret.get_mpz_t(), finite_field_order.get_mpz_t());
    mpz_powm(ciphertext_1.get_mpz_t(), field_units_group_generator.get_mpz_t(), client_secret.get_mpz_t(), finite_field_order.get_mpz_t());
    ciphertext_2 = message * shared_secret % finite_field_order;

    LOG(
        "Client message:        " << message << endl <<
        "Client random secret:  " << client_secret << endl <<
        "Client shared secret:  " << shared_secret << endl <<
        "Client ciphertext 1:   " << ciphertext_1 << endl <<
        "Client ciphertext 2:   " << ciphertext_2 << endl
    );

    // Private key reconstruction
    for(auto& party : parties)
        party.post_private_key_part_and_secret_shares();

    for(auto& party : parties)
        party.compute_private_key();

    auto private_key_count = map<mpz_class, size_t>();

    for(const auto& party_id : qualified_party_ids) {
        if(computed_private_keys.count(party_id))
            ++private_key_count[computed_private_keys[party_id]];
    }

    mpz_class private_key;
    size_t most_votes = 0;
    LOG("Key candidates:" << endl);
    for(const auto& key_count_pair : private_key_count) {
        LOG(key_count_pair.first << " has " << key_count_pair.second << " votes." << endl);
        if(most_votes < key_count_pair.second) {
            private_key = key_count_pair.first;
            most_votes = key_count_pair.second;
        }
    }


    // Decryption
    mpz_class s2, s_inv, m2;
    mpz_powm(s2.get_mpz_t(), ciphertext_1.get_mpz_t(), private_key.get_mpz_t(), finite_field_order.get_mpz_t());
    mpz_invert(s_inv.get_mpz_t(), s2.get_mpz_t(), finite_field_order.get_mpz_t());
    m2 = ciphertext_2 * s_inv % finite_field_order;

    LOG(
        "Shared secrets match:  " << (shared_secret == s2 ? "yes" : "no") << endl <<
        "Messages match:        " << (message == m2 ? "yes" : "no") << endl
    );

    cout << "Total run time: " << duration_cast<duration<double>>(high_resolution_clock::now() - start).count() << endl;

    return 0;
}
