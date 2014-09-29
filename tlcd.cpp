#include <iostream>
#include <iterator>
#include <chrono>
#include <gmpxx.h>
#include <map>
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

    const vector<party>::size_type n = 1;
    const vector<mpz_class>::size_type t = 5000;

    auto party_ids = vector<party_id_t>();

    for (party_id_t i = 1; i <= n; ++i)
        party_ids.push_back(i);

    auto verification_commitments = map<party_id_t, vector<mpz_class>>();
    auto secret_share_disputes = vector<tuple<party_id_t, party_id_t, mpz_class>>();

    auto parties = vector<party>();

    auto start_construction = high_resolution_clock::now();
    for(auto& party_id : party_ids) {
        party p(party_id, party_ids, t, verification_commitments, secret_share_disputes);
        parties.push_back(p);
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

    mpz_class public_key = 1;

    for(auto& party_id : party_ids) {
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

    // Decryption
    mpz_class private_key = 0, s2, s_inv, m2;

    for(auto& party : parties)
        private_key = (private_key + party.polynomial[0]) % field_units_group_order;

    LOG("Private key:           " << private_key << endl);

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
