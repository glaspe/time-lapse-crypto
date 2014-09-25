#ifndef TLC_H
#define TLC_H

#include <gmpxx.h>

using namespace std;

namespace tlc {

const mpz_class
    finite_field_order = 23,
    field_units_group_order = finite_field_order - 1,
    field_units_group_generator = 2;

}

#endif