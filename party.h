#ifndef PARTY_H
#define PARTY_H

#include <map>
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
    vector<mpz_class> polynomial;
    map<party_id_t, mpz_class> computed_secret_shares, recieved_secret_shares;

    const party_id_t id;

    party(const party_id_t id, const vector<party_id_t>& party_ids, const size_t secret_sharing_threshold,
          map<party_id_t, vector<mpz_class>>& verification_commitments,
          vector<tuple<party_id_t, party_id_t, mpz_class>>& secret_share_disputes);

    void send_secret_share(party& reciever);
    void check_recieved_secret_shares();
};

}

#endif