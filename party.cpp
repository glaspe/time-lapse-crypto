#include <iostream>

#include <stdexcept>
#include <map>
#include <set>
#include <tuple>
#include <vector>
#include <cmath>
#include <gmpxx.h>
#include "tlc.h"
#include "party.h"
#include "rand_range.h"

using namespace std;

namespace tlc {

bool secret_share_matches_verification_commitment_vector(const party_id_t reciever_id, mpz_class& secret_share,
                                                         vector<mpz_class>& verification_commitment_vector)
{
    mpz_class gxij, prodc = 1;
    mpz_powm(gxij.get_mpz_t(), field_units_group_generator.get_mpz_t(), secret_share.get_mpz_t(), finite_field_order.get_mpz_t());

    for(vector<mpz_class>::size_type k = 0; k < verification_commitment_vector.size(); ++k) {
        mpz_class cjk, id_k, id_z = reciever_id, k_z = k;
        mpz_powm(id_k.get_mpz_t(), id_z.get_mpz_t(), k_z.get_mpz_t(), field_units_group_order.get_mpz_t());
        mpz_powm(cjk.get_mpz_t(), verification_commitment_vector[k].get_mpz_t(), id_k.get_mpz_t(), finite_field_order.get_mpz_t());

        prodc = prodc * cjk % finite_field_order;
    }

    return gxij == prodc;
}

party::party(const party_id_t id, const vector<party_id_t>& party_ids, const size_t secret_sharing_threshold,
             map<party_id_t, vector<mpz_class>>& verification_commitments,
             vector<tuple<party_id_t, party_id_t, mpz_class>>& secret_share_disputes,
             map<party_id_t, set<party_id_t>>& disqualification_votes) :
    party_ids(party_ids),
    verification_commitments(verification_commitments),
    secret_share_disputes(secret_share_disputes),
    disqualification_votes(disqualification_votes),
    polynomial(secret_sharing_threshold),
    computed_secret_shares(),
    recieved_secret_shares(),
    id(id)
{
    if(id == 0) throw invalid_argument("party id can't be 0");

    LOG("Party " << id << " info: " << endl << "  polynomial: [ ");
    for(auto& coefficient : polynomial) {
        coefficient = rand_range(finite_field_order - 1) + 1;
        LOG(coefficient << " ");
    }
    LOG("]" << endl);

    LOG("  secret shares: [ ");
    for(auto party_id : party_ids) {
        if(party_id == 0) throw logic_error("no party id in party ids can be 0");

        mpz_class secret_share = 0;
        for(vector<mpz_class>::size_type k = 0; k < secret_sharing_threshold; ++k) {
            mpz_class party_id_k, party_id_z = party_id, k_z = k;
            mpz_powm(party_id_k.get_mpz_t(), party_id_z.get_mpz_t(), k_z.get_mpz_t(), field_units_group_order.get_mpz_t());
            secret_share = (secret_share + polynomial[k] * party_id_k) % field_units_group_order;
        }
        computed_secret_shares[party_id] = secret_share;
        LOG(secret_share << " ");
    }
    LOG("]" << endl);

    vector<mpz_class> vcs(secret_sharing_threshold);
    LOG("  verification commitments: [ ");
    for(vector<mpz_class>::size_type j = 0; j < secret_sharing_threshold; ++j) {
        mpz_powm(vcs[j].get_mpz_t(), field_units_group_generator.get_mpz_t(), polynomial[j].get_mpz_t(), finite_field_order.get_mpz_t());
        LOG(vcs[j] << " ");
    }
    LOG("]"  << endl);

    verification_commitments[id] = vcs;

    disqualification_votes[id] = set<party_id_t>();
}

void party::send_secret_share(party& reciever)
{
    if(rand_range(100) < 2) {
        reciever.recieved_secret_shares[id] = rand_range(field_units_group_order);
        return;
    }

    if(computed_secret_shares.count(reciever.id))
        reciever.recieved_secret_shares[id] = computed_secret_shares[reciever.id];
    else
        throw logic_error(string("party ") + to_string(id) + " has no computed secret share for " + to_string(reciever.id));
}

void party::check_recieved_secret_shares()
{
    for(const auto& party_id : party_ids) {
        bool qualified = secret_share_matches_verification_commitment_vector(id, recieved_secret_shares[party_id], verification_commitments[party_id]);
        LOG((qualified ? "y" : "n") << " ");

        if(!qualified)
            secret_share_disputes.push_back(tuple<party_id_t, party_id_t, mpz_class>(id, party_id, recieved_secret_shares[party_id]));
    }
    LOG(endl);
}

void party::submit_disqualification_votes()
{
    for(auto& dispute : secret_share_disputes) {
        party_id_t reciever_id = get<0>(dispute), sender_id = get<1>(dispute);
        bool share_correct = secret_share_matches_verification_commitment_vector(reciever_id, get<2>(dispute), verification_commitments[sender_id]);
        if(!share_correct)
            disqualification_votes[id].insert(sender_id);
    }
}

}