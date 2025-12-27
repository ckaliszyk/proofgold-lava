(* Copyright (c) 2021 The Proofgold Lava developers *)
(* Copyright (c) 2015 The Qeditas developers *)
(* Copyright (c) 2017-2019 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

type int32p8 = int32 * int32 * int32 * int32 * int32 * int32 * int32 * int32

val sha256str : string -> Be256.t
val sha256dstr : string -> Be256.t

val int32p8_big_int : int32p8 -> Z.t
val strong_rand_256 : unit -> Z.t
val rand_256 : unit -> Z.t
val rand_be256 : unit -> Be256.t
