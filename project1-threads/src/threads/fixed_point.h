# ifndef THREADS_FIXED_POINT_H
# define THREADS_FIXED_POINT_H

# include <stdint.h>

# define F (1 << 14)
typedef int fixed_point;

int int_to_fp (int n) {
  return n * F;
}

int fp_towards_zero (fixed_point x) {
  return x / F;
}

int fp_to_near (fixed_point x) {
  return x >= 0 ? (x + F / 2) / F : (x - F / 2) / F; 
}

int add_fp (fixed_point x, fixed_point y) {
  return x + y;
}

int sub_fp (fixed_point x, fixed_point y) {
  return x - y;
}

int add_mixed (fixed_point x, int n) {
  return x + n * F;
}

int sub_mixed (fixed_point x, int n) {
  return x - n * F;
}

int mul_fp (fixed_point x, fixed_point y) {
  return ((int64_t)x) * y / F;
}

int mul_mixed (fixed_point x, int n) {
  return x * n;
}

int div_fp (fixed_point x, fixed_point y) {
  return ((int64_t)x) * F / y;
}

int div_mixed (fixed_point x, int n) {
  return x / n;
}

# endif