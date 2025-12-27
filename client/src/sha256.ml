(* Copyright (c) 2021 The Proofgold Lava developers *)
(* Copyright (c) 2015 The Qeditas developers *)
(* Copyright (c) 2017-2019 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

(* This code is an implementation of the SHA-256 hash function. *)

open Utils
open Ser
open Hashaux
open Zarithint

(* Type definition for an 8-tuple of 32-bit integers, used in the SHA-256 implementation. *)
(* Following the description in http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf *)
type int32p8 = int32 * int32 * int32 * int32 * int32 * int32 * int32 * int32

(* Calculates the SHA-256 hash of a given string. *)
let sha256str s = Hashbtc.sha256 s

(* Calculates the SHA-256 hash of a given double-hashed string. *)
let sha256dstr s = Hashbtc.sha256 (Be256.to_string (Hashbtc.sha256 s))

(* Deserializes an 8-tuple of 32-bit integers from a byte stream. *)
let sei_int32p8 i c =
  let (h0,c) = sei_int32 i c in
  let (h1,c) = sei_int32 i c in
  let (h2,c) = sei_int32 i c in
  let (h3,c) = sei_int32 i c in
  let (h4,c) = sei_int32 i c in
  let (h5,c) = sei_int32 i c in
  let (h6,c) = sei_int32 i c in
  let (h7,c) = sei_int32 i c in
  ((h0,h1,h2,h3,h4,h5,h6,h7),c)

(* Converts an 8-tuple of 32-bit integers to a big integer. *)
let int32p8_big_int h =
  let (h0,h1,h2,h3,h4,h5,h6,h7) = h in
  let x0 = int32_big_int_bits h0 224 in
  let x1 = or_big_int x0 (int32_big_int_bits h1 192) in
  let x2 = or_big_int x1 (int32_big_int_bits h2 160) in
  let x3 = or_big_int x2 (int32_big_int_bits h3 128) in
  let x4 = or_big_int x3 (int32_big_int_bits h4 96) in
  let x5 = or_big_int x4 (int32_big_int_bits h5 64) in
  let x6 = or_big_int x5 (int32_big_int_bits h6 32) in
  or_big_int x6 (int32_big_int_bits h7 0)

(* Generates a random 8-tuple of 32-bit integers. *)
let rand_int32p8 () =
  if not !random_initialized then initialize_random_seed();
  let m0 = rand_int32() in
  let m1 = rand_int32() in
  let m2 = rand_int32() in
  let m3 = rand_int32() in
  let m4 = rand_int32() in
  let m5 = rand_int32() in
  let m6 = rand_int32() in
  let m7 = rand_int32() in
  (m0,m1,m2,m3,m4,m5,m6,m7)

(* Generates a random 256-bit integer. *)
let rand_256 () =
  int32p8_big_int (rand_int32p8 ())

(* Generates a random big-endian 256-bit integer. *)
let rand_be256 () =
  Be256.of_int32p8 (rand_int32p8 ())

(* Generates a cryptographically strong random 256-bit integer. *)
let strong_rand_256 () =
  match !Config.randomseed with
  | Some(_) -> rand_256()
  | None ->
     if Sys.file_exists "/dev/random" then
       begin
         let dr = open_in_bin "/dev/random" in
         let (n,_) = sei_int32p8 seic (dr,None) in
         close_in_noerr dr;
         int32p8_big_int n
       end
     else
       raise (Failure "Cannot generate cryptographically strong random numbers")
