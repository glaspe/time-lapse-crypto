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
public:
    const vector<party_id_t>& party_ids;
    map<party_id_t, vector<mpz_class>>& verification_commitments;
    vector<tuple<party_id_t, party_id_t, mpz_class>>& secret_share_disputes;
    map<party_id_t, set<party_id_t>>& disqualification_votes;
    vector<mpz_class> polynomial;
    map<party_id_t, mpz_class> computed_secret_shares, recieved_secret_shares;

    const party_id_t id;

    party(const party_id_t id, const vector<party_id_t>& party_ids, const size_t secret_sharing_threshold,
          map<party_id_t, vector<mpz_class>>& verification_commitments,
          vector<tuple<party_id_t, party_id_t, mpz_class>>& secret_share_disputes,
          map<party_id_t, set<party_id_t>>& disqualification_votes);

    void send_secret_share(party& reciever);
    void check_recieved_secret_shares();
    void submit_disqualification_votes();
};

}

#endif