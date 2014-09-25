#include <random>
#include <chrono>
#include <gmpxx.h>

using namespace std;
using namespace std::chrono;

namespace tlc {

gmp_randclass mt_gen{gmp_randinit_mt};

// Reseed long before we hit 624
const int reseed_countdown_reset = 42;
int reseed_countdown = 0;

void rand_reseed()
{
    random_device rd;
    unsigned long seed = ((unsigned long) rd() << 32) ^ rd() ^
        high_resolution_clock::now().time_since_epoch().count();
    
    mt_gen.seed(seed);
}

mpz_class rand_range(mpz_class n)
{
    if(reseed_countdown <= 0) {
        rand_reseed();
        reseed_countdown = reseed_countdown_reset;
    }
    --reseed_countdown;
    return mt_gen.get_z_range(n);
}

}
