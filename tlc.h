#ifndef TLC_H
#define TLC_H

//#define DEBUGGING

#ifdef DEBUGGING
#include <iostream>
#define LOG(x) do { \
    std::cout << x; \
} while (0)
#else
#define LOG(x)
#endif

#include "rfc3526.h"
#include <gmpxx.h>

using namespace std;

namespace tlc {

const mpz_class
    finite_field_order = modp_3072,
    field_units_group_order = finite_field_order - 1,
    field_units_group_generator = 2;

}

#endif