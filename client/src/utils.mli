(* Copyright (c) 2021 The Proofgold Core developers *)
(* Copyright (c) 2020 The Proofgold developers *)
(* Copyright (c) 2016 The Qeditas developers *)
(* Copyright (c) 2017-2018 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

val exitfn : (int -> unit) ref

val log : out_channel ref
val log_string : string -> unit
val openlog : unit -> unit
val closelog : unit -> unit

val era : int64 -> int
val maxblockdeltasize : int64 -> int
val late2020hardforkheight1 : int64
val late2020hardforkheight2 : int64
val lockingfixsoftforkheight : int64
val jan2025forkheight : int64

val random_initialized : bool ref
val initialize_random_seed : unit -> unit
val rand_bit : unit -> bool
val rand_int32 : unit -> int32
val rand_int64 : unit -> int64

val base64decode: string -> int list
val base64encode: int list -> string

val forward_from_ltc_block : string option ref
