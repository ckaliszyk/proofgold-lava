(* Copyright (c) 2021-2025 The Proofgold Lava developers *)
(* Copyright (c) 2021 The Proofgold Core developers *)
(* Copyright (c) 2020 The Proofgold developers *)
(* Copyright (c) 2017-2018 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

open Hash
open Sha256

val alertcandidatetxs : string list ref
val ltc_oldest_to_consider : hashval ref
val ltc_oldest_to_consider_time : int64 ref

val unburned_headers : (hashval,(hashval * hashval) -> unit) Hashtbl.t
val unburned_deltas : (hashval,(hashval * hashval) -> unit) Hashtbl.t

module DbInvalidatedBlocks :
  sig
    val dbinit : unit -> unit
    val dbget : hashval -> bool
    val dbexists : hashval -> bool
    val dbput : hashval -> bool -> unit
    val dbdelete : hashval -> unit
  end

type poburn =
  | Poburn of hashval * hashval * int64 * int64 * hashval * int32 (** ltc block hash id, ltc tx hash id, ltc block median time, number of litoshis burned, txid of firsttxid input spent, vout of first input spent **)

val hashpoburn : poburn -> hashval
val seo_poburn : (int -> int -> 'a -> 'a) -> poburn -> 'a -> 'a
val sei_poburn : (int -> 'a -> int * 'a) -> 'a -> poburn * 'a

val ltctestnet : unit -> unit

type ltcpfgstatus = LtcPfgStatusPrev of hashval | LtcPfgStatusNew of (int64 * (hashval * hashval * hashval * int64 * int64) list) list

module DbLtcPfgStatus :
    sig
      val dbinit : unit -> unit
      val dbget : hashval -> ltcpfgstatus
      val dbexists : hashval -> bool
      val dbput : hashval -> ltcpfgstatus -> unit
      val dbdelete : hashval -> unit
    end

val ltcpfgstatus_dbget : hashval -> hashval * ((int64 * (hashval * hashval * hashval * int64 * int64) list) list)

val remdups_pfg_status_height_entries : (hashval * hashval * hashval * int64 * int64) list -> (hashval * hashval * hashval * int64 * int64) list -> (hashval * hashval * hashval * int64 * int64) list

module DbLtcBurnTx :
    sig
      val dbinit : unit -> unit
      val dbget : hashval -> int64 * hashval * hashval * hashval * int32
      val dbexists : hashval -> bool
      val dbput : hashval -> int64 * hashval * hashval * hashval * int32 -> unit
      val dbdelete : hashval -> unit
    end

module DbLtcBlock :
    sig
      val dbinit : unit -> unit
      val dbget : hashval -> hashval * int64 * int64 * hashval list
      val dbexists : hashval -> bool
      val dbput : hashval -> hashval * int64 * int64 * hashval list -> unit
      val dbdelete : hashval -> unit
    end

val ltc_getbestblockhash : unit -> string
val ltc_getblockheight : string -> int64
val ltc_getblock : string -> string * int64 * int64 * string list * string option
val ltc_getburntransactioninfo : string -> int64 * hashval * hashval * string option * int option * string * int
val ltc_getburntransactioninfo2cache : string -> string option

type ltcutxo =
  | LtcP2shSegwit of (string * int * string * string * string * int64)
  | LtcBech32 of (string * int * string * string * int64)

val ltc_listunspent : unit -> ltcutxo list
val ltc2_listunspent : unit -> ltcutxo list

exception InsufficientLtcFunds
exception NotAnLtcBurnTx

val ltc_createburntx : hashval -> hashval -> int64 -> string
val ltc_createburntx_spec : ltcutxo -> hashval -> hashval -> int64 -> string
val ltc_signrawtransaction : string -> string
val ltc_sendrawtransaction : string -> string

val ltc_process_block : string -> unit

val ltc_bestblock : hashval ref

val ltc_medtime : unit -> int64

val ltc_synced : unit -> bool

val ltc_tx_confirmed : string -> int option

val ltc_tx_confirmed2 : string -> (int * (string * int64) option) option

val ltc_tx_poburn : string -> poburn

val ltc_best_chaintips : unit -> hashval list list

val find_pfg_header_ltc_burn : hashval -> poburn * hashval option

val retractltcblock : string -> unit

val ltc_forward_from_block : string -> unit
val ltc_forward_from_oldest : unit -> unit

val swapcandidatetxs : string list ref
type swapbuyoffertype =
  | SimpleSwapBuyOffer of string * addr * int64 * int64

val swapbuyoffers : (hashval * float * swapbuyoffertype) list ref
val allswapbuyoffers_by_rev_time : (int64 * hashval * float * swapbuyoffertype) list ref
val allswapbuyoffers_by_forw_time : (int64 * hashval * float * swapbuyoffertype) list ref
val allswapbuyoffers_by_price : (int64 * hashval * float * swapbuyoffertype) list ref
val allswapexec : (hashval,int64 * hashval * hashval) Hashtbl.t
val allswapexec_have : (hashval,unit) Hashtbl.t

val ltc_scanforswapbuyoffers : int -> unit
val ltc_getswaptransactioninfo : string -> unit
val ltc_cancelswapbuyoffer : string -> unit
val ltc_createswapoffertx : addr -> int64 -> int64 -> string
val ltc_unspent : string -> int -> bool

val blnum32 : int32 -> int list
val blnum64 : int64 -> int list

val broadcast_alert_via_ltc : char -> string -> string
val ltc_process_alert_tx : string -> unit
val search_ltc_bootstrap_url : unit -> unit

val initialize_historic_swap_info : unit -> unit
