#ifndef PARTY_H
#define PARTY_H

#include <gmpxx.h>

using namespace std;

namespace tlc {

typedef size_t party_id_t;

class party
{
public:
    size_t id;
    vector<party>::size_type num_parties;
    vector<mpz_class>::size_type secret_share_threshold;
    vector<mpz_class> polynomial,
                      secret_shares,
                      verification_commitments;

    party(party_id_t id, vector<party>::size_type num_parties, vector<mpz_class>::size_type secret_share_threshold);

    void init();
};

}

#endif