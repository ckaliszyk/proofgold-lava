(* Copyright (c) 2021 The Proofgold Lava developers *)
(* Copyright (c) 2021 The Proofgold Core developers *)
(* Copyright (c) 2015-2016 The Qeditas developers *)
(* Copyright (c) 2017-2019 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

open Json
open Hash
open Db
open Mathdata
open Assets
open Script

type tx = addr_assetid list * addr_preasset list

val hashtx : tx -> hashval
val tx_inputs : tx -> addr_assetid list
val tx_outputs : tx -> addr_preasset list

val no_dups : 'a list -> bool
val tx_inputs_valid : addr_assetid list -> bool
val tx_outputs_valid : addr_preasset list -> bool
val tx_valid : tx -> bool
val tx_valid_oc : out_channel -> tx -> bool

type gensignat_or_ref = GenSignatReal of gensignat | GenSignatRef of int
type txsigs = gensignat_or_ref option list * gensignat_or_ref option list
type stx = tx * txsigs

exception BadOrMissingSignature

val check_spend_obligation_upto_blkh : int64 option -> addr -> Z.t -> gensignat -> obligation -> bool * int64 option * int64 option * int64 option * hashval list
val check_spend_obligation : int64 option -> addr -> int64 -> int64 -> Z.t -> gensignat -> obligation -> hashval list option
val check_move_obligation : addr -> Z.t -> gensignat -> obligation -> preasset -> addr_preasset list -> bool
val tx_signatures_valid : int64 -> int64 -> asset list -> stx -> hashval list option
val tx_signatures_valid_asof_blkh : asset list -> stx -> int64 option * int64 option * int64 option * hashval list
val estimate_required_signatures : asset list -> tx -> int

val txout_update_ottree : addr_preasset list -> ttree option -> ttree option
val txout_update_ostree : addr_preasset list -> stree option -> stree option

val seo_tx : (int -> int -> 'a -> 'a) -> tx -> 'a -> 'a
val sei_tx : (int -> 'a -> int * 'a) -> 'a -> tx * 'a
val seo_txsigs : (int -> int -> 'a -> 'a) -> gensignat_or_ref option list * gensignat_or_ref option list -> 'a -> 'a
val sei_txsigs : (int -> 'a -> int * 'a) -> 'a -> (gensignat_or_ref option list * gensignat_or_ref option list) * 'a
val seo_stx : (int -> int -> 'a -> 'a) -> stx -> 'a -> 'a
val sei_stx : (int -> 'a -> int * 'a) -> 'a -> stx * 'a

val hashtxsigs : txsigs -> hashval

val hashstx : stx -> hashval

val stxsize : stx -> int

module DbSTx :
    sig
      val dbinit : unit -> unit
      val dbget : Hash.hashval -> stx
      val dbexists : Hash.hashval -> bool
      val dbput : Hash.hashval -> stx -> unit
      val dbdelete : Hash.hashval -> unit
      val dbkeyiter : (hashval -> unit) -> unit
    end

val json_tx : tx -> jsonval
val json_txsigs : txsigs -> jsonval
val json_stx : stx -> jsonval

val tx_from_json : jsonval -> tx
