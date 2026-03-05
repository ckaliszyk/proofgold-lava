#include "secp256k1.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_const_impl.h"
#include "int128_impl.h"
#include "scratch_impl.h"

#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/custom.h>
#include <caml/fail.h>


static struct custom_operations pt_ops = {
  (char*)"pt",
  custom_finalize_default,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default
};
#define Pt_val(v) ((secp256k1_ge *)Data_custom_val(v))
static value alloc_pt() {
  return (caml_alloc_custom(&pt_ops, sizeof(secp256k1_ge), 0, 1));
}

static struct custom_operations s2n_ops = {
  (char*)"s2n",
  custom_finalize_default,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default
};
#define S2n_val(v) ((secp256k1_fe *)Data_custom_val(v))
static value alloc_s2n() {
  return (caml_alloc_custom(&s2n_ops, sizeof(secp256k1_fe), 0, 1));
}

value c_secp256_curve_y(value odd, value x){
  CAMLparam2 (odd,x);
  CAMLlocal1(r);
  r = alloc_pt();
  secp256k1_ge_set_xo_var(Pt_val(r), S2n_val(x), Bool_val(odd));
  CAMLreturn(r);
}

value c_secp256_pt_of_xy(value x, value y){
  CAMLparam2 (x,y);
  CAMLlocal1(r);
  r = alloc_pt();
  secp256k1_ge_set_xy(Pt_val(r), S2n_val(x), S2n_val(y));
  CAMLreturn(r);
}

value c_secp256_pt_to_xyo(value g){
  CAMLparam1 (g);
  if (Pt_val(g)->infinity) CAMLreturn(Val_unit);
  CAMLlocal4(r,t,x,y);
  x = alloc_s2n();
  memcpy(S2n_val(x), &Pt_val(g)->x, sizeof(secp256k1_fe));
  secp256k1_fe_normalize(S2n_val(x));
  y = alloc_s2n();
  memcpy(S2n_val(y), &Pt_val(g)->y, sizeof(secp256k1_fe));
  secp256k1_fe_normalize(S2n_val(y));
  t = caml_alloc_tuple(2);
  Field(t, 0) = x;
  Field(t, 1) = y;
  r = caml_alloc(1, 0); //Val_some(t);
  Field(r, 0) = t;
  CAMLreturn(r);
}

value c_secp256_smulp(value s, value p){
  CAMLparam2 (s,p);
  unsigned char xxx[32];
  secp256k1_fe_get_b32(xxx, S2n_val(s));
  secp256k1_scalar xx1;
  secp256k1_scalar_set_b32(&xx1, xxx, NULL);
  secp256k1_gej r;
  secp256k1_ecmult_const(&r, Pt_val(p), &xx1);
  CAMLlocal1(o);
  o = alloc_pt();
  secp256k1_ge_set_gej(Pt_val(o), &r);
  CAMLreturn(o);
}

value c_secp256_add_pt(value x, value y){
  CAMLparam2(x,y);
  secp256k1_gej rj,xj,yj;
  secp256k1_gej_set_ge(&xj, Pt_val(x));
  secp256k1_gej_set_ge(&yj, Pt_val(y));
  secp256k1_gej_add_var(&rj, &xj, &yj, NULL);
  CAMLlocal1(r);
  r = alloc_pt();
  secp256k1_ge_set_gej(Pt_val(r), &rj);
  CAMLreturn(r);
}
