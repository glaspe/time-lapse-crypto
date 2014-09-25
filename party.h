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
    const set<party_id_t>& party_ids;
    vector<mpz_class> polynomial;
    map<party_id_t, mpz_class> secret_shares;

    const map<party_id_t, vector<mpz_class>>& verification_commitments;

    party(party_id_t id, const set<party_id_t>& party_ids, const size_t secret_sharing_threshold,
          map<party_id_t, vector<mpz_class>>& verification_commitments);


};

}

#endif