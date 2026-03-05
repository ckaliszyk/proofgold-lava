#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/custom.h>
#include <arpa/inet.h>
#include <caml/fail.h>

#include "secp256k1.h"
#include "hash_impl.h"

static struct custom_operations sha_buffer_ops = {
  (char*)"sha_buffer",
  custom_finalize_default,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default
};

#define ShaB_val(v) ((secp256k1_sha256 *)Data_custom_val(v))
static value alloc_sha_buffer() {
  return (caml_alloc_custom(&sha_buffer_ops, sizeof(secp256k1_sha256), 0, 1));
}

value c_sha256_buffer(value unit){
  CAMLparam1(unit);
  CAMLlocal1(ret);
  ret = alloc_sha_buffer();
  secp256k1_sha256_initialize(ShaB_val(ret));
  CAMLreturn(ret);
}

void c_sha256_add_s1(value b, value s){
  CAMLparam2(b, s);
  secp256k1_sha256_write(ShaB_val(b), (const unsigned char*)(Bytes_val(s)), 1);
  CAMLreturn0;
}

void c_sha256_add_s4(value b, value s){
  CAMLparam2(b, s);
  secp256k1_sha256_write(ShaB_val(b), (const unsigned char*)(Bytes_val(s)), 4);
  CAMLreturn0;
}

void c_sha256_add_s32(value b, value s){
  CAMLparam2(b, s);
  secp256k1_sha256_write(ShaB_val(b), (const unsigned char*)(Bytes_val(s)), 32);
  CAMLreturn0;
}

void c_sha256_add_i32(value b, value i){
  CAMLparam2(b, i);
  const uint32_t j = htonl((uint32_t)(Int32_val(i)));
  secp256k1_sha256_write(ShaB_val(b), (const unsigned char*)(&j), 4);
  CAMLreturn0;
}

value c_sha256_finalize(value b){
  CAMLparam1(b);
  CAMLlocal1(r);
  r = caml_alloc_string(32);
  secp256k1_sha256_finalize(ShaB_val(b), (unsigned char*)(Bytes_val(r)));
  CAMLreturn(r);
}

value c_sha256_bebits(value s){
  CAMLparam1(s);
  secp256k1_sha256 hasher;
  secp256k1_sha256_initialize(&hasher);
  secp256k1_sha256_write(&hasher, (const unsigned char*)(Bytes_val(s)), caml_string_length(s));
  CAMLlocal1(r);
  r = caml_alloc_string(32);
  secp256k1_sha256_finalize(&hasher, (unsigned char*)(Bytes_val(r)));
  CAMLreturn(r);
}

#define hd(a) Field(a, 0)
#define tl(a) Field(a, 1)

value c_sha256_list_bebits(value l){
  CAMLparam1(l);
  secp256k1_sha256 hasher;
  secp256k1_sha256_initialize(&hasher);
  for (; l != Val_emptylist; l = tl(l))
    secp256k1_sha256_write(&hasher, (const unsigned char*)(Bytes_val(hd(l))), caml_string_length(hd(l)));
  CAMLlocal1(r);
  r = caml_alloc_string(32);
  secp256k1_sha256_finalize(&hasher, (unsigned char*)(Bytes_val(r)));
  CAMLreturn(r);
}

value c_sha256_round(value chv, value cb){
  CAMLparam2(chv,cb);
  // Supposed to be big endian already
  int32_t s[8] = {Int32_val(Field(chv,0)),Int32_val(Field(chv,1)),Int32_val(Field(chv,2)),Int32_val(Field(chv,3)),
                   Int32_val(Field(chv,4)),Int32_val(Field(chv,5)),Int32_val(Field(chv,6)),Int32_val(Field(chv,7))};
  // In host order but library needs big
  int32_t cc[16] = {htonl(Int32_val(Field(cb,0))),htonl(Int32_val(Field(cb,1))),htonl(Int32_val(Field(cb,2))),htonl(Int32_val(Field(cb,3))),
                    htonl(Int32_val(Field(cb,4))),htonl(Int32_val(Field(cb,5))),htonl(Int32_val(Field(cb,6))),htonl(Int32_val(Field(cb,7))),
                    htonl(Int32_val(Field(cb,8))),htonl(Int32_val(Field(cb,9))),htonl(Int32_val(Field(cb,10))),htonl(Int32_val(Field(cb,11))),
                    htonl(Int32_val(Field(cb,12))),htonl(Int32_val(Field(cb,13))),htonl(Int32_val(Field(cb,14))),htonl(Int32_val(Field(cb,15)))};
  secp256k1_sha256_transform((uint32_t*)s, (uint32_t*)cc);
  CAMLlocal4(a,b,c,d);
  a = caml_copy_int32(s[0]);
  b = caml_copy_int32(s[1]);
  c = caml_copy_int32(s[2]);
  d = caml_copy_int32(s[3]);
  CAMLlocal4(e,f,g,h);
  e = caml_copy_int32(s[4]);
  f = caml_copy_int32(s[5]);
  g = caml_copy_int32(s[6]);
  h = caml_copy_int32(s[7]);
  CAMLlocal1 (r);
  r = caml_alloc_tuple(8);
  Field(r, 0) = a;
  Field(r, 1) = b;
  Field(r, 2) = c;
  Field(r, 3) = d;
  Field(r, 4) = e;
  Field(r, 5) = f;
  Field(r, 6) = g;
  Field(r, 7) = h;
  CAMLreturn (r);
}

#include "ripemd160.h"

value c_ripemd160_be_be(value s){
  CAMLparam1(s);
  if (caml_string_length(s) != 32)
    caml_invalid_argument("c_ripemd160_be_be : only accepts strings of length 32");
  CAMLlocal1 (r);
  r = caml_alloc_string(20);
  ripemd160_initialize((uint32_t*)((void*)(Bytes_val(r))));
  int32_t cc[16];
  memcpy(cc, (Bytes_val(s)), 8 * sizeof(uint32_t));
  memset(&cc[9], 0, 7 * sizeof(uint32_t)); cc[8] = 0x80; cc[14] = 256;
  ripemd160_transform((uint32_t*)((void*)(Bytes_val(r))), (uint32_t*)cc);
  CAMLreturn (r);
}
