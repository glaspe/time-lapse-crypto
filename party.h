#ifndef PARTY_H
#define PARTY_H

#include <set>
#include <map>
#include <gmpxx.h>

using namespace std;

namespace tlc {

typedef size_t party_id_t;

class party
{
public:
    party_id_t id;
    set<party_id_t> party_ids;
    vector<mpz_class> polynomial;
    map<party_id_t, mpz_class> secret_shares;
    vector<mpz_class> verification_commitments;

    party(party_id_t id, set<party_id_t> party_ids, vector<mpz_class>::size_type secret_sharing_threshold);
};

}

#endif