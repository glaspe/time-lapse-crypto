#include <iostream>
#include <random>
#include <chrono>
#include <gmpxx.h>

using namespace std;
using namespace std::chrono;

// https://www.ietf.org/rfc/rfc3526.txt
const mpz_class
    modp_1536 { "0x"
        "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
        "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
        "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
        "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
        "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
        "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
        "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
        "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"
    },
    modp_2048 { "0x"
        "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
        "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
        "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
        "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
        "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
        "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
        "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
        "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
        "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
        "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
        "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
    },
    modp_3072 { "0x"
        "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
        "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
        "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
        "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
        "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
        "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
        "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
        "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
        "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
        "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
        "15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64"
        "ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7"
        "ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B"
        "F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
        "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31"
        "43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF"
    },
    modp_4096 { "0x"
        "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
        "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
        "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
        "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
        "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
        "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
        "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
        "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
        "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
        "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
        "15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64"
        "ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7"
        "ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B"
        "F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
        "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31"
        "43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7"
        "88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA"
        "2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6"
        "287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED"
        "1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9"
        "93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199"
        "FFFFFFFF FFFFFFFF"
    },
    modp_6144 { "0x"
        "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
        "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
        "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
        "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
        "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
        "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
        "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
        "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
        "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
        "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
        "15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64"
        "ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7"
        "ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B"
        "F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
        "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31"
        "43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7"
        "88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA"
        "2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6"
        "287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED"
        "1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9"
        "93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492"
        "36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD"
        "F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831"
        "179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B"
        "DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF"
        "5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6"
        "D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3"
        "23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA"
        "CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328"
        "06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C"
        "DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE"
        "12BF2D5B 0B7474D6 E694F91E 6DCC4024 FFFFFFFF FFFFFFFF"

    },
    modp_8192 { "0x"
        "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
        "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
        "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
        "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
        "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
        "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
        "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
        "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
        "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
        "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
        "15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64"
        "ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7"
        "ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B"
        "F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
        "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31"
        "43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7"
        "88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA"
        "2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6"
        "287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED"
        "1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9"
        "93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492"
        "36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD"
        "F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831"
        "179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B"
        "DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF"
        "5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6"
        "D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3"
        "23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA"
        "CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328"
        "06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C"
        "DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE"
        "12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4"
        "38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300"
        "741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568"
        "3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9"
        "22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B"
        "4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A"
        "062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36"
        "4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1"
        "B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92"
        "4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47"
        "9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71"
        "60C980DD 98EDD3DF FFFFFFFF FFFFFFFF"
    };

gmp_randclass mt_gen{gmp_randinit_mt};

// TODO: Use secure PRNG
void rand_init()
{
    random_device rd;
    unsigned long seed = ((unsigned long) rd() << 32) ^ rd() ^
        high_resolution_clock::now().time_since_epoch().count();
    
    mt_gen.seed(seed);
}

mpz_class rand_range(mpz_class n)
{
    return mt_gen.get_z_range(n);
}

int main()
{
    rand_init();

    auto start = high_resolution_clock::now();

    const mpz_class Fq = 23,
                    UFq = Fq - 1,
                    g = 2_mpz;

    const vector<mpz_class>::size_type n = 10, t = 5;

    auto secret_polynomials = vector<vector<mpz_class>>(n),
         secret_shares = vector<vector<mpz_class>>(n),
         verification_commitments = vector<vector<mpz_class>>(n);

    mpz_class public_key = 1_mpz;

    for(vector<mpz_class>::size_type i = 0; i < n; ++i) {
        secret_polynomials[i] = vector<mpz_class>(t);

        cout << "Party " << i << " polynomial: ";
        for(vector<mpz_class>::size_type j = 0; j < t; ++j) {
            secret_polynomials[i][j] = rand_range(Fq - 1) + 1;
            cout << secret_polynomials[i][j] << "z^" << j;
            if(j != t-1) cout << " + ";
        }
        cout << endl;

        cout << "Party " << i << " secret shares: ";
        secret_shares[i] = vector<mpz_class>(n);
        for(vector<mpz_class>::size_type j = 0; j < n; ++j) {
            secret_shares[i][j] = 0_mpz;
            for(vector<mpz_class>::size_type k = 0; k < t; ++k) {
                secret_shares[i][j] = (secret_shares[i][j] + secret_polynomials[i][k] * pow(j, k)) % UFq;
            }
            cout << secret_shares[i][j] << " ";
        }
        cout << endl;

        cout << "Party " << i << " verification commitments: ";
        verification_commitments[i] = vector<mpz_class>(n);
        for(vector<mpz_class>::size_type j = 0; j < t; ++j) {
            mpz_powm(verification_commitments[i][j].get_mpz_t(), g.get_mpz_t(), secret_polynomials[i][j].get_mpz_t(), Fq.get_mpz_t());
            cout << verification_commitments[i][j] << " ";
        }
        cout << endl;

        public_key = public_key * verification_commitments[i][0] % Fq;
    }

    cout << "Shares check out?" << endl;
    for(vector<mpz_class>::size_type i = 0; i < n; ++i) {
        for(vector<mpz_class>::size_type j = 0; j < n; ++j) {
            mpz_class gxij, prodc = 1_mpz;
            mpz_powm(gxij.get_mpz_t(), g.get_mpz_t(), secret_shares[i][j].get_mpz_t(), Fq.get_mpz_t());
            for(vector<mpz_class>::size_type k = 0; k < t; ++k) {
                mpz_class cjk, jk = pow(j, k);
                mpz_powm(cjk.get_mpz_t(), verification_commitments[i][k].get_mpz_t(), jk.get_mpz_t(), Fq.get_mpz_t());

                prodc = prodc * cjk % Fq;
            }

            cout << (gxij == prodc ? "y" : "n") << " ";
        }
        cout << endl;
    }

    cout <<
        "Service public key:    " << public_key << endl;

    // Encryption
    mpz_class message = rand_range(Fq),
              client_secret = rand_range(Fq - 1) + 1,
              shared_secret, ciphertext_1, ciphertext_2;

    mpz_powm(shared_secret.get_mpz_t(), public_key.get_mpz_t(), client_secret.get_mpz_t(), Fq.get_mpz_t());
    mpz_powm(ciphertext_1.get_mpz_t(), g.get_mpz_t(), client_secret.get_mpz_t(), Fq.get_mpz_t());
    ciphertext_2 = message * shared_secret % Fq;

    cout <<
        "Client message:        " << message << endl <<
        "Client random secret:  " << client_secret << endl <<
        "Client shared secret:  " << shared_secret << endl <<
        "Client ciphertext 1:   " << ciphertext_1 << endl <<
        "Client ciphertext 2:   " << ciphertext_2 << endl;

    // Decryption
    mpz_class private_key = 0_mpz, s2, s_inv, m2;

    for(vector<mpz_class>::size_type i = 0; i < n; ++i) private_key = (private_key + secret_polynomials[i][0]) % UFq;

    cout <<
        "Private key:           " << private_key << endl;

    mpz_powm(s2.get_mpz_t(), ciphertext_1.get_mpz_t(), private_key.get_mpz_t(), Fq.get_mpz_t());
    mpz_invert(s_inv.get_mpz_t(), s2.get_mpz_t(), Fq.get_mpz_t());
    m2 = ciphertext_2 * s_inv % Fq;

    cout <<
        "Shared secrets match:  " << (shared_secret == s2 ? "yes" : "no") << endl <<
        "Messages match:        " << (message == m2 ? "yes" : "no") << endl <<
        "Run time:              " << duration_cast<duration<double>>(high_resolution_clock::now() - start).count() << endl;

    return 0;
}
