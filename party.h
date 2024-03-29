#ifndef PARTY_H
#define PARTY_H

#include <map>
#include <set>
#include <tuple>
#include <vector>
#include <gmpxx.h>

using namespace std;

namespace tlc {

typedef size_t party_id_t;

class party
{
    const vector<party_id_t>& party_ids;
    map<party_id_t, vector<mpz_class>>& verification_commitments;
    vector<tuple<party_id_t, party_id_t, mpz_class>>& secret_share_disputes;
    map<party_id_t, set<party_id_t>>& disqualification_votes;
    vector<party_id_t>& qualified_party_ids;
    map<party_id_t, mpz_class>& private_key_parts;
    map<party_id_t, map<party_id_t, mpz_class>>& secret_shares;
    map<party_id_t, mpz_class>& computed_private_keys;
    vector<mpz_class> polynomial;
    map<party_id_t, mpz_class> computed_secret_shares, recieved_secret_shares;

public:
    const party_id_t id;

    party(const party_id_t id, const vector<party_id_t>& party_ids, const size_t secret_sharing_threshold,
          map<party_id_t, vector<mpz_class>>& verification_commitments,
          vector<tuple<party_id_t, party_id_t, mpz_class>>& secret_share_disputes,
          map<party_id_t, set<party_id_t>>& disqualification_votes,
          vector<party_id_t>& qualified_party_ids,
          map<party_id_t, mpz_class>& private_key_parts,
          map<party_id_t, map<party_id_t, mpz_class>>& secret_shares,
          map<party_id_t, mpz_class>& computed_private_keys);

    void send_secret_share(party& reciever);
    void check_recieved_secret_shares();
    void submit_disqualification_votes();
    void post_private_key_part_and_secret_shares();
    void compute_private_key();
};

}

#endif