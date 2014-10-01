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

party::party(const party_id_t id, const vector<party_id_t>& party_ids, const size_t secret_sharing_threshold,
             map<party_id_t, vector<mpz_class>>& verification_commitments,
             vector<tuple<party_id_t, party_id_t, mpz_class>>& secret_share_disputes,
             map<party_id_t, set<party_id_t>>& disqualification_votes,
             vector<party_id_t>& qualified_party_ids,
             map<party_id_t, mpz_class>& private_key_parts,
             map<party_id_t, map<party_id_t, mpz_class>>& secret_shares,
             map<party_id_t, mpz_class>& computed_private_keys) :
    party_ids(party_ids),
    verification_commitments(verification_commitments),
    secret_share_disputes(secret_share_disputes),
    disqualification_votes(disqualification_votes),
    qualified_party_ids(qualified_party_ids),
    private_key_parts(private_key_parts),
    secret_shares(secret_shares),
    computed_private_keys(computed_private_keys),
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
            mpz_class party_id_k, party_id_z = party_id;//, k_z = k;
            //mpz_powm(party_id_k.get_mpz_t(), party_id_z.get_mpz_t(), k_z.get_mpz_t(), field_units_group_order.get_mpz_t());
            mpz_pow_ui(party_id_k.get_mpz_t(), party_id_z.get_mpz_t(), k);
            secret_share = (secret_share + polynomial[k] * party_id_k);// % field_units_group_order;
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
    secret_shares[id] = map<party_id_t, mpz_class>();
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

void party::post_private_key_part_and_secret_shares()
{
    if(rand_range(100) < 10) {
        return;
    }

    private_key_parts[id] = polynomial[0];
    for(const auto& party_id : qualified_party_ids)
        secret_shares[party_id][id] = recieved_secret_shares[party_id];
}

void party::compute_private_key()
{
    mpz_class private_key = 0;

    for(const auto& party_id : qualified_party_ids) {
        mpz_class x, vc;

        if(private_key_parts.count(party_id)) {
            x = private_key_parts[party_id];
        } else {
            LOG("Party " << party_id << " did not post private key part" << endl);
            auto interpolation_party_ids = vector<party_id_t>();
            for(const auto& reciever_id : qualified_party_ids) {
                if(secret_shares[party_id].count(reciever_id)) {
                    interpolation_party_ids.push_back(reciever_id);
                }
                if(interpolation_party_ids.size() >= polynomial.size()) break;
            }
            if(interpolation_party_ids.size() != polynomial.size()) {
                LOG("Not enough information to interpolate " << party_id << "'s polynomial" << endl);
            }

            LOG("Interpolating set: [ ");
            for(const auto& party_id : interpolation_party_ids)
                LOG(party_id << " ");
            LOG("]" << endl);

            x = 0;
            LOG("Sum terms:" << endl);
            for(const auto& party1_id : interpolation_party_ids) {
                mpz_class Pj = secret_shares[party_id][party1_id];
                LOG(Pj);
                for(const auto& party2_id : interpolation_party_ids) {
                    if(party1_id != party2_id) {
                        LOG(" * " << party2_id << "/(" << party2_id << "-" << party1_id << ")[");
                        mpz_class inv_d, denominator = party2_id;
                        denominator -= party1_id; // HACK: size_t's fuck everything up
                        LOG(denominator << "]{");
                        mpz_invert(inv_d.get_mpz_t(), denominator.get_mpz_t(), finite_field_order.get_mpz_t());
                        LOG(inv_d << "}");
                        Pj = Pj * party2_id * inv_d % finite_field_order;
                    }
                }
                x = (x + Pj) % finite_field_order;
                LOG(endl);
            }
        }
        mpz_powm(vc.get_mpz_t(), field_units_group_generator.get_mpz_t(), x.get_mpz_t(), finite_field_order.get_mpz_t());

        if(vc == verification_commitments[party_id][0])
            private_key = (private_key + x) % field_units_group_order;
        else
            LOG(party_id << " posted invalid private key part/shares (" <<
                field_units_group_generator << "^" << x << " != " << verification_commitments[party_id][0] << ")" << endl);
    }

    LOG(id << "'s computed private key: " << private_key << endl);

    computed_private_keys[id] = private_key;
}

}