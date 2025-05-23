(* Copyright (c) 2021 The Proofgold Lava developers *)
(* Copyright (c) 2020-2021 The Proofgold Core developers *)
(* Copyright (c) 2020 The Proofgold developers *)
(* Copyright (c) 2015-2016 The Qeditas developers *)
(* Copyright (c) 2017-2019 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

open Ser
open Sha256
open Hash
open Net
open Db
open Zarithint
open Logic
open Mathdata
open Assets
open Signat
open Ltcrpc
open Cryptocurr
open Tx
open Ctre
open Ctregraft

(* Define a type for stakemod, which is a 256-bit hash value *)
type stakemod = hashval

(*** The genesis stakemod should be the 32 bytes (64 hex chars) of the block hash for a particular litecoin block with height preannounced.
 ***)
let genesisstakemod : stakemod ref = ref (hexstring_hashval "0000000000000000000000000000000000000000000000000000000000000000")

(*** max target/min difficulty: 2^206 (for mainnet) ***)
let max_target = ref (shift_left_big_int unit_big_int 206)
let genesistarget = ref (shift_left_big_int unit_big_int 205)
let genesisledgerroot : hashval ref = ref (hexstring_hashval "e348bc89a2ef4c949a41636a945dffac4418c510d38eb3764b95ea21892a688a")

(*** base reward of 50 bars like bitcoin (but finer, 50 bars = 5 trillion atoms) ***)
let basereward = 5000000000000L

(*** the block reward begins at 50 bars (half to staker and half to bounty) and halves with each era until era 43 when it is 0 ***)
let rewfn blkh = Int64.shift_right basereward (Utils.era blkh)

(* Define a function to serialize a stakemod value *)
let seo_stakemod o sm c = seo_hashval o sm c

(* Define a function to deserialize a stakemod value *)
let sei_stakemod i c = sei_hashval i c

(*** one round of sha256 combining the timestamp (least significant 32 bits only), the hash value of the stake's assetid and the stake modifier, then converted to a big_int to do arithmetic ***)
let hitval tm h sm =
  let d = hashpair (hashtag sm (Int64.to_int32 tm)) h in
  hashval_big_int d

(*** target (big_int, but assumed to be at most 256 bits ***)
type targetinfo = Z.t

(* Define functions to serialize and deserialize target information *)
let targetinfo_string tar = string_of_big_int tar

let eq_tinfo z w = eq_big_int z w

let hashtargetinfo tar = big_int_hashval tar
let seo_targetinfo o ti c = seo_big_int_256 o ti c
let sei_targetinfo i c = sei_big_int_256 i c

(* Define a function to calculate the proof-of-burn stakemod *)
let poburn_stakemod p =
  match p with
  | Poburn(h,k,_,_,_,_) -> hashpair h k

(* Define a ref for optional messages sent to an out_channel while checking validity of blocks *)
let verbose_blockcheck = ref None

(* Define a function to send optional messages to an out_channel while checking validity of blocks *)
let vbc f =
  match !verbose_blockcheck with
  | Some(c) -> f c; flush c
  | None -> ()

let vbcv v f = vbc f; v

let vbcb v f g = if v then vbc f else vbc g; v

type blockheaderdata = {
    prevblockhash : (hashval * poburn) option;
    pureburn : (hashval * int32) option;
    newtheoryroot : hashval option;
    newsignaroot : hashval option;
    newledgerroot : hashval;
    stakeaddr : p2pkhaddr;
    stakeassetid : hashval;
    timestamp : int64;
    deltatime : int32;
    tinfo : targetinfo;
    prevledger : ctree;
    blockdeltaroot : hashval;
  }

(* Define a type for block header signature *)
type blockheadersig = {
    blocksignat : signat;
    blocksignatrecid : int;
    blocksignatfcomp : bool;
    blocksignatendorsement : (p2pkhaddr * int * bool * signat) option;
  }

(* Define a type for block header *)
type blockheader = blockheaderdata * blockheadersig

(* Define functions to serialize and deserialize block header data *)
let seo_blockheaderdata o bh c =
  let c = seo_option (seo_prod seo_hashval seo_poburn) o bh.prevblockhash c in
  let c = seo_option (seo_prod seo_hashval seo_int32) o bh.pureburn c in
  let c = seo_option seo_hashval o bh.newtheoryroot c in
  let c = seo_option seo_hashval o bh.newsignaroot c in
  let c = seo_hashval o bh.newledgerroot c in
  let c = seo_be160 o bh.stakeaddr c in (*** p2pkh addresses are md160 ***)
  let c = seo_hashval o bh.stakeassetid c in
  let c = seo_int64 o bh.timestamp c in
  let c = seo_int32 o bh.deltatime c in
  let c = seo_targetinfo o bh.tinfo c in
  let c = seo_ctree o bh.prevledger c in
  let c = seo_hashval o bh.blockdeltaroot c in
  c

let seo_blockheaderdata0 o bh c =
  let c = seo_option (seo_prod seo_hashval seo_poburn) o bh.prevblockhash c in
  let c = seo_option (seo_prod seo_hashval seo_int32) o bh.pureburn c in
  let c = seo_option seo_hashval o bh.newtheoryroot c in
  let c = seo_option seo_hashval o bh.newsignaroot c in
  let c = seo_hashval o bh.newledgerroot c in
  let c = seo_be160 o bh.stakeaddr c in (*** p2pkh addresses are md160 ***)
  let c = seo_hashval o bh.stakeassetid c in
  let c = seo_int64 o bh.timestamp c in
  let c = seo_int32 o bh.deltatime c in
  let c = seo_targetinfo o bh.tinfo c in
  let c = seo_ctree0 o bh.prevledger c in
  let c = seo_hashval o bh.blockdeltaroot c in
  c

let sei_blockheaderdata i c =
  let (x0,c) = sei_option (sei_prod sei_hashval sei_poburn) i c in
  let (x0a,c) = sei_option (sei_prod sei_hashval sei_int32) i c in
  let (x1,c) = sei_option sei_hashval i c in
  let (x2,c) = sei_option sei_hashval i c in
  let (x3,c) = sei_hashval i c in
  let (x4,c) = sei_be160 i c in (*** p2pkh addresses are md160 ***)
  let (x5,c) = sei_hashval i c in
  let (x7,c) = sei_int64 i c in
  let (x8,c) = sei_int32 i c in
  let (x9,c) = sei_targetinfo i c in
  let (x10,c) = sei_ctree i c in
  let (x11,c) = sei_hashval i c in
  let bhd : blockheaderdata =
    { prevblockhash = x0;
      pureburn = x0a;
      newtheoryroot = x1;
      newsignaroot = x2;
      newledgerroot = x3;
      stakeaddr = x4;
      stakeassetid = x5;
      timestamp = x7;
      deltatime = x8;
      tinfo = x9;
      prevledger = x10;
      blockdeltaroot = x11;
    }
  in
  (bhd,c)

let sei_blockheaderdata0 i c =
  let (x0,c) = sei_option (sei_prod sei_hashval sei_poburn) i c in
  let (x0a,c) = sei_option (sei_prod sei_hashval sei_int32) i c in
  let (x1,c) = sei_option sei_hashval i c in
  let (x2,c) = sei_option sei_hashval i c in
  let (x3,c) = sei_hashval i c in
  let (x4,c) = sei_be160 i c in (*** p2pkh addresses are md160 ***)
  let (x5,c) = sei_hashval i c in
  let (x7,c) = sei_int64 i c in
  let (x8,c) = sei_int32 i c in
  let (x9,c) = sei_targetinfo i c in
  let (x10,c) = sei_ctree0 i c in
  let (x11,c) = sei_hashval i c in
  let bhd : blockheaderdata =
    { prevblockhash = x0;
      pureburn = x0a;
      newtheoryroot = x1;
      newsignaroot = x2;
      newledgerroot = x3;
      stakeaddr = x4;
      stakeassetid = x5;
      timestamp = x7;
      deltatime = x8;
      tinfo = x9;
      prevledger = x10;
      blockdeltaroot = x11;
    }
  in
  (bhd,c)

let seo_blockheadersig o bhs c = 
  let c = seo_signat o bhs.blocksignat c in
  let c = o 2 bhs.blocksignatrecid c in
  let c = seo_bool o bhs.blocksignatfcomp c in
  let c = seo_option (seo_prod4 seo_be160 seo_varintb seo_bool seo_signat) o bhs.blocksignatendorsement c in
  c

let sei_blockheadersig i c = 
  let (x,c) = sei_signat i c in
  let (r,c) = i 2 c in
  let (f,c) = sei_bool i c in
  let (e,c) = sei_option (sei_prod4 sei_be160 sei_varintb sei_bool sei_signat) i c in
  let bhs : blockheadersig =
    { blocksignat = x;
      blocksignatrecid = r;
      blocksignatfcomp = f;
      blocksignatendorsement = e;
    }
  in
  (bhs,c)

let seo_blockheader o bh c = seo_prod seo_blockheaderdata seo_blockheadersig o bh c
let sei_blockheader i c = sei_prod sei_blockheaderdata sei_blockheadersig i c

let seo_blockheader0 o bh c = seo_prod seo_blockheaderdata0 seo_blockheadersig o bh c
let sei_blockheader0 i c = sei_prod sei_blockheaderdata0 sei_blockheadersig i c
                        
type blockdelta = {
    stakeoutput : addr_preasset list;
    prevledgergraft : cgraft;
    blockdelta_stxl : stx list
  }

(* Define a type for block *)
type block = blockheader * blockdelta

(* Define functions to serialize and deserialize block delta *)
let seo_blockdelta o bd c =
  let c = seo_list seo_addr_preasset o bd.stakeoutput c in
  let c = seo_cgraft o bd.prevledgergraft c in
  let c = seo_list seo_stx o bd.blockdelta_stxl c in
  c

let seo_blockdelta0 o bd c =
  let c = seo_list seo_addr_preasset o bd.stakeoutput c in
  let c = seo_cgraft0 o bd.prevledgergraft c in
  let c = seo_list seo_stx o bd.blockdelta_stxl c in
  c

(* Code to deserialize block delta *)
let sei_blockdelta i c =
  let (stko,c) = sei_list sei_addr_preasset i c in
  let (cg,c) = sei_cgraft i c in
  let (stxl,c) = sei_list sei_stx i c in
  ({ stakeoutput = stko;
     prevledgergraft = cg;
     blockdelta_stxl = stxl;
   },
   c)

(* Code to deserialize block delta without prevledgergraft *)
let sei_blockdelta0 ctree_pl i c =
  let (stko,c) = sei_list sei_addr_preasset i c in
  let (cg,c) = sei_cgraft0 ctree_pl i c in
  let (stxl,c) = sei_list sei_stx i c in
  ({ stakeoutput = stko;
     prevledgergraft = cg;
     blockdelta_stxl = stxl;
   },
   c)

(* Define functions to serialize and deserialize block *)
let seo_block o b c = seo_prod seo_blockheader seo_blockdelta o b c
let sei_block i c = sei_prod sei_blockheader sei_blockdelta i c

(* Define modules for database operations on block header and block delta *)
module DbBlockHeader = Dbmbasic (struct type t = blockheader let basedir = "blockheader" let seival = sei_blockheader seis let seoval = seo_blockheader seosb end)
module DbBlockDelta = Dbmbasic (struct type t = blockdelta let basedir = "blockdelta" let seival = sei_blockdelta seis let seoval = seo_blockdelta seosb end);;

have_header_p_fn := DbBlockHeader.dbexists;;

(* Define functions to get block header data, signature, and delta from the database *)
let get_blockheaderdata h = 
  try
    let (d,s) = DbBlockHeader.dbget h in d
  with Not_found -> (*** request it and fail ***)
    find_and_send_requestdata GetHeader h;
    raise GettingRemoteData

let get_blockheadersig h = 
  try
    let (d,s) = DbBlockHeader.dbget h in
    s
  with Not_found -> (*** request it and fail ***)
    find_and_send_requestdata GetHeader h;
    raise GettingRemoteData

let get_blockheader h = 
  try
    DbBlockHeader.dbget h
  with Not_found -> (*** request it and fail ***)
    find_and_send_requestdata GetHeader h;
    raise GettingRemoteData

let get_blockdelta h = 
  try
    DbBlockDelta.dbget h
  with Not_found -> (*** request it and fail ***)
    if DbBlockHeader.dbexists h then
      find_and_send_requestdata GetBlockdelta h
    else
      find_and_send_requestdata GetHeader h;
    raise GettingRemoteData

(***
 hitval computes a big_int by hashing the timestamp (in seconds), the stake's asset id and the current stake modifier.
 If there is no proof of burn, then there's a hit if the hitval is less than the target times the stake.
 If there is proof of burn, the number of litecoin satoshis * 1000000 is added to the stake.
***)
let check_hit_b blkh bday obl v csm tar tmstmp stkid stkaddr burned =
  let minamt =
    if blkh < 5000L then
      0L
    else if blkh < 16000L then
      10000000000L
    else if blkh < 18000L then
      100000000000L
    else if blkh < 20000L then
      1000000000000L
    else
      10000000000000L
  in
  let v =
    if v < minamt then
      0L
    else
      Int64.add v (Int64.mul (min burned 100000000000L) 1000000L) (*** burning more than 1000 ltc still counts as "only" 1000 ***)
  in
  if bday > 0L then
    lt_big_int (hitval tmstmp stkid csm) (mult_big_int tar (coinage blkh bday obl v))
  else
    lt_big_int (hitval tmstmp stkid csm) (mult_big_int tar (big_int_of_int64 v))

(* Code to check if a block is a valid hit *)
let check_hit blkh csm tinf bh bday obl v burned =
  check_hit_b blkh bday obl v csm tinf bh.timestamp bh.stakeassetid bh.stakeaddr burned

(* Define a function to get the coin stake from a block *)
let coinstake b =
  let ((bhd,bhs),bd) = b in
  ([p2pkhaddr_addr bhd.stakeaddr,bhd.stakeassetid],bd.stakeoutput)

(* Define functions to hash block header data and signature *)
let hash_blockheaderdata bh =
  hashtag
    (hashopair2
       (match bh.prevblockhash with
       | None -> None
       | Some(h,pob) -> Some(hashpair h (hashpoburn pob)))
       (hashlist
	  [hashopair2 bh.newtheoryroot
	     (hashopair2 bh.newsignaroot bh.newledgerroot);
	   hashctree0 bh.prevledger;
	   bh.blockdeltaroot;
	   hashaddr (p2pkhaddr_addr bh.stakeaddr);
	   bh.stakeassetid;
	   hashtargetinfo bh.tinfo;
	   hashint64 bh.timestamp;
	   hashint32 bh.deltatime]))
    1028l

  (* Code to hash block header signature *)
let hash_blockheadersig bhs =
  hashopair1
    (hashpair
       (hashsignat bhs.blocksignat)
       (hashtag
	  (hashint32 (Int32.of_int bhs.blocksignatrecid))
	  (if bhs.blocksignatfcomp then 1029l else 1030l)))
    (match bhs.blocksignatendorsement with
    | None -> None
    | Some(alpha,i,b,s) ->
	Some(hashtag
	       (hashlist [hashaddr (p2pkhaddr_addr alpha);hashint32 (Int32.of_int i); hashsignat s])
	       (if b then 1031l else 1032l)))

  (* Code to hash block header *)
let hash_blockheader (bhd,bhs) =
  hashpair (hash_blockheaderdata bhd) (hash_blockheadersig bhs)

(* Define a function to get the block header ID *)
let blockheader_id bh = hash_blockheader bh

(* Define a function to check if a genesis block header is valid *)
let valid_genesisheader bhd =
  match tx_octree_trans false false 1L ([(p2pkhaddr_addr bhd.stakeaddr,bhd.stakeassetid)],[]) (Some(bhd.prevledger)) with
  | Some(c) -> ctree_hashroot c = !genesisledgerroot
  | None -> false

(* Define a function to check if a block header is valid *)
let valid_blockheader_allbutsignat blkh csm tinfo bhd (aid,bday,obl,u) lmedtm burned =
  if bhd.prevblockhash = None && not (valid_genesisheader bhd) then
    vbcv false (fun c -> Printf.fprintf c "Invalid genesis header\n")
  else if bhd.timestamp > lmedtm then
    vbcv false (fun c -> Printf.fprintf c "Block header has timestamp %Ld after median litecoin time %Ld\n" bhd.timestamp lmedtm)
  else if not (bhd.stakeassetid = aid) then
    vbcv false (fun c -> Printf.fprintf c "Block header asset id mismatch. Found %s. Expected %s.\n" (hashval_hexstring bhd.stakeassetid) (hashval_hexstring aid))
  else if blkh >= 730L && bday = 0L then (** additional constraint to avoid potential bugs when staking with fake pure burn assets **)
    vbcv false (fun c -> Printf.fprintf c "Blocks cannot be created by pure burns after height 730.\n")
  else
    match u with
    | Currency(v) ->
	begin
	  if not (check_hit blkh csm tinfo bhd bday obl v burned) then
	    vbcv false (fun c -> Printf.fprintf c "Block header not a hit.\nblkh = %Ld\ncsm = %s\ntinfo = %s\nbday = %Ld\nobl = %s\nv = %Ld\nburned = %Ld\n" blkh (hashval_hexstring csm) (targetinfo_string tinfo) bday (obligation_string obl) v burned)
	  else if not (bhd.deltatime > 0l) then
	    vbcv false (fun c -> Printf.fprintf c "Block header has a bad deltatime %ld\n" bhd.deltatime)
	  else
	    true
      end
  | _ ->
      vbcv false (fun c -> Printf.fprintf c "staked asset %s of block header was not a currency asset\n" (hashval_hexstring aid))

(* Code to check if a block header signature is valid *)
let valid_blockheader_signat (bhd,bhs) (aid,bday,obl,v) =
  let bhdh = hash_blockheaderdata bhd in (*** check that it signs the hash of the data part of the header, distinct form blockheader_id which combines hash of data with hash of sig ***)
  if (try DbInvalidatedBlocks.dbget bhdh with Not_found -> false) then (*** explicitly marked as invalid ***)
    vbcv false (fun c -> Printf.fprintf c "Block %s explicitly marked as invalid.\n" (hashval_hexstring bhdh))
  else
    begin
      match bhs.blocksignatendorsement with
      | None -> verify_p2pkhaddr_signat (hashval_big_int bhdh) bhd.stakeaddr bhs.blocksignat bhs.blocksignatrecid bhs.blocksignatfcomp
      | Some(beta,recid,fcomp,esg) -> (*** signature via endorsement ***)
	  begin
	    (verifybitcoinmessage bhd.stakeaddr recid fcomp esg ("endorse " ^ (addr_pfgaddrstr (p2pkhaddr_addr beta)))
	       &&
	     verify_p2pkhaddr_signat (hashval_big_int bhdh) beta bhs.blocksignat bhs.blocksignatrecid bhs.blocksignatfcomp)
	  || (!Config.testnet (*** allow fake endorsements in testnet ***)
		&&
	      verifybitcoinmessage (Be160.of_int32p5 (-916116462l, -1122756662l, 602820575l, 669938289l, 1956032577l)) recid fcomp esg ("fakeendorsement " ^ (addr_pfgaddrstr (p2pkhaddr_addr beta)) ^ " (" ^ (addr_pfgaddrstr (p2pkhaddr_addr bhd.stakeaddr)) ^ ")")
		&&
	      verify_p2pkhaddr_signat (hashval_big_int bhdh) beta bhs.blocksignat bhs.blocksignatrecid bhs.blocksignatfcomp)
	  end
    end

(* Code to check if a block header is valid *)
let valid_blockheader_a blkh csm tinfo (bhd,bhs) (aid,bday,obl,v) lmedtm burned =
  let b1 = valid_blockheader_signat (bhd,bhs) (aid,bday,obl,v) in
  if b1 then
    valid_blockheader_allbutsignat blkh csm tinfo bhd (aid,bday,obl,v) lmedtm burned
  else
    vbcv false (fun c -> Printf.fprintf c "block header has invalid signature\n")

(* Define exceptions for block header validation *)
exception HeaderNoStakedAsset
exception HeaderStakedAssetNotMin

(* Define a function to get the staked asset from a block header *)
let blockheader_stakeasset bhd =
  let bl = (0,p2pkhaddr_addr bhd.stakeaddr) in
  match ctree_lookup_asset false false false bhd.stakeassetid bhd.prevledger bl with (** do not be strict here precisely because we *want* to skip abstracted assets **)
  | Some(a) ->
      let (aid,_,_,_) = a in
      vbc (fun c -> Printf.fprintf c "found staked asset %s\n" (hashval_hexstring aid));
      if minimal_asset_supporting_ctree bhd.prevledger bl aid 50 then (*** ensure that the ctree contains no extra information; this is a condition to prevent headers from being large by including unnecessary information; also only allow the first 50 assets held at an address to be used for staking ***)
	a
      else
	begin
	  vbc (fun c -> Printf.fprintf c "ctree in header not minimal for staked asset\n");
	  raise HeaderStakedAssetNotMin
	end
  | _ ->
      vbc (fun c -> Printf.fprintf c "No staked asset found\n");
      raise HeaderNoStakedAsset
	
(* Code to validate a block header *)
let valid_blockheader blkh csm tinfo (bhd,bhs) lmedtm burned txid1 vout1 =
  try
    vbc (fun c -> Printf.fprintf c "valid_blockheader %Ld %Ld %Ld\n" blkh lmedtm burned);
    match bhd.pureburn with
    | None ->
       valid_blockheader_a blkh csm tinfo (bhd,bhs) (blockheader_stakeasset bhd) lmedtm burned
    | Some(txidh,vout) ->
       if blkh > 730L then (** pure burns only allowed in the first 730 blocks, roughly a month **)
         false
       else if (txidh = txid1) && (vout = vout1) then
         let aid = hashtag txidh vout in
         if aid = bhd.stakeassetid then
           let a = (aid,0L,None,Currency(0L)) in (** temporary asset pretending to be staked **)
           if blockheader_stakeasset bhd = a then
             valid_blockheader_a blkh csm tinfo (bhd,bhs) a lmedtm burned
           else
             false
         else
           false
       else
         false
  with
  | HeaderStakedAssetNotMin -> false
  | HeaderNoStakedAsset -> false


(* This function validates a block header, considering the possibility of a pure burn. *)
let valid_blockheader_ifburn blkh csm tinfo (bhd,bhs) lmedtm burned =
  try
    (* Print debugging information. *)
    vbc (fun c -> Printf.fprintf c "valid_blockheader %Ld %Ld %Ld\n" blkh lmedtm burned);
    match bhd.pureburn with
    | None ->
       valid_blockheader_a blkh csm tinfo (bhd,bhs) (blockheader_stakeasset bhd) lmedtm burned
    | Some(txidh,vout) ->
       let aid = hashtag txidh vout in
       if aid = bhd.stakeassetid then
         let a = (aid,0L,None,Currency(0L)) in (** temporary asset pretending to be staked **)
         if blockheader_stakeasset bhd = a then
           valid_blockheader_a blkh csm tinfo (bhd,bhs) a lmedtm burned
         else
           false
       else
         false
  with
  | HeaderStakedAssetNotMin -> false
  | HeaderNoStakedAsset -> false
                             
(** just check that the staked asset is there and that the signature is valid **)
let sanity_check_header (bhd,bhs) =
  try
    valid_blockheader_signat (bhd,bhs) (blockheader_stakeasset bhd)
  with _ -> false

(* This function creates a commitment tree (ctree) from a block. *)
let ctree_of_block (b:block) =
  let ((bhd,bhs),bd) = b in
  ctree_cgraft bd.prevledgergraft bhd.prevledger

(* These functions extract all inputs and outputs from a list of signed transactions. *)
let rec stxs_allinputs stxl =
  match stxl with
  | ((inpl,_),_)::stxr -> inpl @ stxs_allinputs stxr
  | [] -> []

let rec stxs_alloutputs stxl =
  match stxl with
  | ((_,outpl),_)::stxr -> outpl @ stxs_alloutputs stxr
  | [] -> []

(*** all txs of the block combined into one big transaction; used for checking validity of blocks ***)
let tx_of_block b =
  let ((bhd,_),bd) = b in
  let (ci,co) = coinstake b in
  (ci @ stxs_allinputs bd.blockdelta_stxl,co @ stxs_alloutputs bd.blockdelta_stxl)

(* This function extracts the coinstake transaction and the list of signed transactions from a block. *)
let txl_of_block b =
  let (_,bd) = b in
  (coinstake b,List.map (fun (tx,_) -> tx) bd.blockdelta_stxl)

(* This function calculates the Merkle root of a list of signed transactions. *)
let rec stxl_hashroot stxl =
  merkle_root (List.map hashstx stxl)

(* This function calculates the Merkle root of a blockdelta. *)
let blockdelta_hashroot bd =
  hashpair
    (hashlist (List.map hash_addr_preasset bd.stakeoutput))
    (hashopair1
       (hashcgraft0 bd.prevledgergraft)
       (stxl_hashroot bd.blockdelta_stxl))

(* This function validates a block, considering various aspects such as the block header, transactions, and rewards. *)
let valid_block_a tht sigt blkh csm tinfo b ((aid,bday,obl,u) as a) p2pkhstkaddr stkaddr lmedtm burned =
  let ((bhd,bhs),bd) = b in
  let pthyaddr = (** address for reward bounty, if there is one **)
    if bhd.prevblockhash = None then (** genesis, no reward bounty **)
      None
    else if blkh >= Utils.late2020hardforkheight2 then (* no bounty *)
      None
    else if blkh >= Utils.late2020hardforkheight1 then (* special address for funding bounties manually *)
      Some(hashval_p2pkh_addr csm) (** holding address, no key **)
    else
      try
        let (_,_,p) = Checking.reward_bounty_prop blkh csm in
        let hfthyid = Checking.hfthyid in
        let ppureid = tm_hashroot p in
        let pthyid = hashtag (hashopair2 (Some(hfthyid)) ppureid) 33l in
        let pthyaddr = hashval_term_addr pthyid in
        Some(pthyaddr)
      with _ -> None (** in exception case, no reward bounty (probably never happens) **)
  in
  let reward = rewfn blkh in
  let reward2 = Int64.shift_right reward 1 in (** half reward goes to staker, half goes to bounty (or burned) **)
  let reward = if pthyaddr = None then reward2 else reward in
  (*** The header is valid. ***)
  if (vbcb (valid_blockheader_a blkh csm tinfo (bhd,bhs) (aid,bday,obl,u) lmedtm burned) (fun c -> Printf.fprintf c "header valid\n") (fun c -> Printf.fprintf c "header invalid\n")
	&&
      vbcb (tx_outputs_valid bd.stakeoutput) (fun c -> Printf.fprintf c "stakeoutput valid\n") (fun c -> Printf.fprintf c "stakeoutput invalid\n")
        &&
      vbcb (blockdelta_hashroot bd = bhd.blockdeltaroot) (fun c -> Printf.fprintf c "delta Merkle root valid\n") (fun c -> Printf.fprintf c "delta Merkle root invalid\n") (*** the header commits to the blockdelta (including all txs and their signatures) ***)
	&&
      (*** ensure that if the stake has an explicit obligation (e.g., it is borrowed for staking), then the obligation isn't changed; otherwise the staker could steal the borrowed stake; unchanged copy should be first output ***)
          begin
            match pthyaddr with
            | None ->
               begin
                 vbc (fun c -> Printf.fprintf c "No reward bounty expected.\n");
	         match a with
	         | (_,_,Some(beta,n,r),Currency(v)) -> (*** stake may be on loan for staking ***)
	            begin
	              match bd.stakeoutput with
	              | (alpha2,(Some(beta2,n2,r2),Currency(v2)))::remouts -> (*** the first output must recreate the loaned asset. It's a reward iff it was already a reward. ***)
		         r2 = r
		         &&
		           alpha2 = stkaddr
		         &&
		           beta2 = beta
		         &&
		           n2 = n
		         &&
		           v2 = v
		         &&
		           begin
		             try (*** all other outputs must be marked as rewards; they also must acknowledge they cannot be spent for at least reward_locktime many blocks ***)
		               ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> (match preasset_units v with Some(u) when u < 0L -> true | _ -> false) | _ -> true) remouts);
		               false
		             with Not_found -> true
		           end
	              | _ ->
		         false
	            end
	         | (_,bday,None,Currency(v)) when bday <= 0L -> (*** pretend stake for pure burn ***)
                    begin
                      vbc (fun c -> Printf.fprintf c "Pure burn.\n");
	              try
	                ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) bd.stakeoutput);
                        vbc (fun c -> Printf.fprintf c "Pure burn stakeoutput problem.\n");
	                false
	              with Not_found -> true
                    end
	         | (_,_,None,Currency(v)) -> (*** stake has the default obligation ***)
	            begin (*** the first output is optionally the stake with the default obligation (not a reward, immediately spendable) with all other outputs must be marked as rewards; they also must acknowledge they cannot be spent for at least reward_locktime many blocks ***)
	              match bd.stakeoutput with
	              | (alpha2,(_,Currency(v2)))::remouts -> (*** allow the staker to choose the new obligation for the staked asset [Feb 2016] ***)
		         begin
		           alpha2 = stkaddr
		           &&
		             v2 = v
		           &&
		             try
		               ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) remouts);
		               false
		             with Not_found -> true
		         end
	              | _ ->
		         try
		           ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) bd.stakeoutput);
		           false
		         with Not_found -> true
	            end
	         | _ -> false (*** this means the staked asset isn't currency, which is not allowed ***)
               end
            | Some(pthyaddr) when termaddr_p pthyaddr -> (** bounty reward **)
               begin
                 vbc (fun c -> Printf.fprintf c "Reward bounty to %s expected.\n" (addr_pfgaddrstr pthyaddr));
	         match a with
	         | (_,_,Some(beta,n,r),Currency(v)) -> (*** stake may be on loan for staking ***)
	            begin
	              match bd.stakeoutput with
	              | (alpha2,(Some(beta2,n2,r2),Currency(v2)))::(alpha3,(None,Bounty(v3)))::remouts -> (*** the first output must recreate the loaned asset. It's a reward iff it was already a reward. the second output must be the reward bounty ***)
		         r2 = r
		         &&
		           alpha2 = stkaddr
		         &&
		           beta2 = beta
		         &&
		           n2 = n
		         &&
		           v2 = v
                         &&
                           alpha3 = pthyaddr
                         &&
                           v3 = reward2
		         &&
		           begin
		             try (*** all other outputs must be marked as rewards; they also must acknowledge they cannot be spent for at least reward_locktime many blocks ***)
		               ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) remouts);
		               false
		             with Not_found -> true
		           end
	              | _ ->
		         false
	            end
	         | (_,bday,None,Currency(v)) when bday <= 0L -> (*** pretend stake for pure burn ***)
                    begin
	              match bd.stakeoutput with
	              | (alpha3,(None,Bounty(v3)))::remouts -> (*** the first output must be the reward bounty **)
                         alpha3 = pthyaddr
                         &&
                           v3 = reward2
                         &&
                           begin
	                     try
	                       ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) remouts);
	                       false
	                     with Not_found -> true
                           end
                      | _ -> false
                    end
	         | (_,_,None,Currency(v)) -> (*** stake has the default obligation ***)
	            begin (*** the first output is optionally the stake with the default obligation (not a reward, immediately spendable) with all other outputs must be marked as rewards; they also must acknowledge they cannot be spent for at least reward_locktime many blocks ***)
	              match bd.stakeoutput with
	              | (alpha2,(_,Currency(v2)))::(alpha3,(None,Bounty(v3)))::remouts -> (*** allow the staker to choose the new obligation for the staked asset [Feb 2016] ; the second output is the reward bounty ***)
		         begin
		           alpha2 = stkaddr
		           &&
		             v2 = v
		           &&
                             alpha3 = pthyaddr
                           &&
                             v3 = reward2
                           &&
                             begin
		               try
		                 ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) remouts);
		                 false
		               with Not_found -> true
                             end
		         end
	              | (alpha3,(None,Bounty(v3)))::remouts ->
                         alpha3 = pthyaddr
                         &&
                           v3 = reward2
                         &&
                           begin
		             try
		               ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) remouts);
		               false
		             with Not_found -> true
                           end
                      | _ -> false
	            end
	         | _ -> false (*** this means the staked asset isn't currency, which is not allowed ***)
               end
            | Some(pthyaddr) -> (** special fund for manual bounties **)
               begin
                 vbc (fun c -> Printf.fprintf c "Reward bounty to %s expected.\n" (addr_pfgaddrstr pthyaddr));
	         match a with
	         | (_,_,Some(beta,n,r),Currency(v)) -> (*** stake may be on loan for staking ***)
	            begin
	              match bd.stakeoutput with
	              | (alpha2,(Some(beta2,n2,r2),Currency(v2)))::(alpha3,(Some(alpha4,n3,r3),Currency(v3)))::remouts -> (*** the first output must recreate the loaned asset. It's a reward iff it was already a reward. the second output must be the reward bounty ***)
		         r2 = r
		         &&
		           alpha2 = stkaddr
		         &&
		           beta2 = beta
		         &&
		           n2 = n
		         &&
		           v2 = v
                         &&
                           alpha3 = pthyaddr
                         &&
                           v3 = reward2
                         &&
                           alpha4 = (let (contraddr,_) = Script.bountyfundveto p2pkhstkaddr in p2shaddr_payaddr contraddr)
                         &&
                           n3 = 0L
                         &&
                           r3 = false
		         &&
		           begin
		             try (*** all other outputs must be marked as rewards; they also must acknowledge they cannot be spent for at least reward_locktime many blocks ***)
		               ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) remouts);
		               false
		             with Not_found -> true
		           end
	              | _ ->
		         false
	            end
	         | (_,bday,None,Currency(v)) when bday <= 0L -> (*** pretend stake for pure burn ***)
                    begin
	              match bd.stakeoutput with
	              | (alpha3,(Some(alpha4,n3,r3),Currency(v3)))::remouts -> (*** the first output must be the reward bounty **)
                         alpha3 = pthyaddr
                         &&
                           v3 = reward2
                         &&
                           alpha4 = (let (contraddr,_) = Script.bountyfundveto p2pkhstkaddr in p2shaddr_payaddr contraddr)
                         &&
                           n3 = 0L
                         &&
                           r3 = false
                         &&
                           begin
	                     try
	                       ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) remouts);
	                       false
	                     with Not_found -> true
                           end
                      | _ -> false
                    end
	         | (_,_,None,Currency(v)) -> (*** stake has the default obligation ***)
	            begin (*** the first output is optionally the stake with the default obligation (not a reward, immediately spendable) with all other outputs must be marked as rewards; they also must acknowledge they cannot be spent for at least reward_locktime many blocks ***)
	              match bd.stakeoutput with
	              | (alpha2,(_,Currency(v2)))::(alpha3,(Some(alpha4,n3,r3),Currency(v3)))::remouts -> (*** allow the staker to choose the new obligation for the staked asset [Feb 2016] ; the second output is the reward bounty ***)
		         begin
		           alpha2 = stkaddr
		           &&
		             v2 = v
		           &&
                             alpha3 = pthyaddr
                           &&
                             v3 = reward2
                           &&
                             alpha4 = (let (contraddr,_) = Script.bountyfundveto p2pkhstkaddr in p2shaddr_payaddr contraddr)
                           &&
                             n3 = 0L
                           &&
                             r3 = false
                           &&
                             begin
		               try
		                 ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) remouts);
		                 false
		               with Not_found -> true
                             end
		         end
	              | (alpha3,(Some(alpha4,n3,r3),Currency(v3)))::remouts ->
                         alpha3 = pthyaddr
                         &&
                           v3 = reward2
                         &&
                           alpha4 = (let (contraddr,_) = Script.bountyfundveto p2pkhstkaddr in p2shaddr_payaddr contraddr)
                         &&
                           n3 = 0L
                         &&
                           r3 = false
                         &&
                           begin
		             try
		               ignore (List.find (fun (alpha3,(obl,v)) -> match obl with Some(_,n,r) when r && n >= Int64.add blkh reward_locktime -> false | _ -> true) remouts);
		               false
		             with Not_found -> true
                           end
                      | _ -> false
	            end
	         | _ -> false (*** this means the staked asset isn't currency, which is not allowed ***)
               end
          end)
  then
    let tr = ctree_of_block b in (*** let tr be the ctree of the block, used often below ***)
    let counter = ref 0 in
    if ((try let z = ctree_supports_tx counter false false false tht sigt blkh [] (coinstake b) tr in (*** the ctree must support the tx without the need to expand hashes using the database or requesting from peers; Note: the coinstake won't have any props that should have been proven since it has only one input and that input is a p2pkh address. So we give ctree_supports_tx the empty list of propids here. ***)
             vbc (fun c -> Printf.fprintf c "Comparing z %Ld to %Ld.\n" z reward);
             z >= reward
         with NotSupported -> false)
        &&
          (*** There are no duplicate transactions. (Comparing the signatures would be an error since they contain abstract values.) ***)
	no_dups (List.map (fun (tau,_) -> tau) bd.blockdelta_stxl)
	  &&
	(*** The cgraft is valid. ***)
	cgraft_valid bd.prevledgergraft
	  &&
	let stakein = (stkaddr,bhd.stakeassetid) in
	(*** Each transaction in the delta has supported elaborated assets and is appropriately signed. ***)
	(*** Also, each transaction in the delta is valid and supported without a reward. ***)
	(*** Also, no transaction has the stake asset as an input. ***)
	(*** None of the outputs say they are rewards. ***)
	begin
          vbc (fun c -> Printf.fprintf c "Checking other txs.\n");
	  try
	    List.fold_left
	      (fun sgvb stau ->
		match stau with
		| ((inpl,outpl) as tau,_) ->
		    let norew =
		      begin
			try
			  ignore (List.find 
				    (fun (a,(obl,v)) ->
				      match obl with
				      | Some(_,_,r) when r -> true
				      | _ -> false)
				    outpl);
			  false
			with Not_found -> true
		      end
		    in
		    let aal = ctree_lookup_input_assets false false false inpl tr (fun _ _ -> ()) in
		    let al = List.map (fun (_,a) -> a) aal in
                    if norew && sgvb && not (List.mem stakein inpl) then
                      begin
                        match tx_signatures_valid blkh bhd.timestamp al stau with
                        | Some(prvnl) ->
                           tx_valid tau && ctree_supports_tx_2 counter false false false tht sigt blkh prvnl tau aal al tr <= 0L
                        | None -> false
                      end
                    else
                      false)
	      true
	      bd.blockdelta_stxl
	  with NotSupported -> false
	end
	  &&
	(*** No distinct transactions try to spend the same asset. ***)
	(*** Also, ownership is not created for the same address alpha by two txs in the block. ***)
	begin
          vbc (fun c -> Printf.fprintf c "No double spends.\n");
	  try
	    let stxlr = ref bd.blockdelta_stxl in
	    while not (!stxlr = []) do
	      match !stxlr with
	      | ((inpl1,outpl1),_)::stxr ->
		  let hl1 = List.map (fun (_,h) -> h) inpl1 in
		  let oo1 = ref [] in
		  let op1 = ref [] in
		  List.iter
		    (fun (alpha1,(obl1,u1)) ->
		      match u1 with
		      | OwnsObj(_,_,_) -> oo1 := alpha1::!oo1
		      | OwnsProp(_,_,_) -> op1 := alpha1::!op1
		      | _ -> ())
		    outpl1;
		  stxlr := stxr;
		  List.iter
		    (fun ((inpl2,outpl2),_) ->
		      List.iter
			(fun (_,h) ->
			  if List.mem h hl1 then
			    raise NotSupported (*** This is a minor abuse of this exception. There could be a separate exception for this case. ***)
			) inpl2;
		      List.iter
			(fun (alpha2,(obl2,u2)) ->
			  match u2 with
			  | OwnsObj(_,_,_) ->
			      if List.mem alpha2 !oo1 then raise NotSupported
			  | OwnsProp(_,_,_) ->
			      if List.mem alpha2 !op1 then raise NotSupported
			  | _ -> ()
			)
			outpl2
		    )
		    stxr
	      | [] -> ()
	    done;
	    true
	  with NotSupported -> false
	end
	  &&
	(*** Ownership is not created for the same address alpha by the coinstake and a tx in the block. ***)
	begin
          vbc (fun c -> Printf.fprintf c "Ownership 1\n");
	  try
	    List.iter
	      (fun (alpha,(obl,u)) ->
		match u with
		| OwnsObj(_,_,_) ->
		    List.iter
		      (fun ((_,outpl2),_) ->
			List.iter
			  (fun (alpha2,(obl2,u2)) ->
			    if alpha = alpha2 then
			      match u2 with
			      | OwnsObj(_,_,_) -> raise NotSupported
			      | _ -> ())
			  outpl2)
		      bd.blockdelta_stxl
		| OwnsProp(_,_,_) ->
		    List.iter
		      (fun ((_,outpl2),_) ->
			List.iter
			  (fun (alpha2,(obl2,u2)) ->
			    if alpha = alpha2 then
			      match u2 with
			      | OwnsProp(_,_,_) -> raise NotSupported
			      | _ -> ())
			  outpl2)
		      bd.blockdelta_stxl
		| _ -> ()
	      )
	      bd.stakeoutput;
	    true
	  with NotSupported -> false
	end)
    then
      if (begin (*** The root of the transformed ctree is the newledgerroot in the header. ***)
	let (cstk,txl) = txl_of_block b in (*** the coinstake tx is performed last, i.e., after the txs in the block. ***)
	try
          begin
            vbc (fun c -> Printf.fprintf c "transforming ledger\n");
	    match tx_octree_trans false false blkh cstk (txl_octree_trans false false blkh txl (Some(tr))) with (*** "false false" disallows database lookups and remote requests ***)
	    | Some(tr2) ->
               vbc (fun c -> Printf.fprintf c "comparing computed root %s to declared root %s\n" (hashval_hexstring (ctree_hashroot tr2)) (hashval_hexstring bhd.newledgerroot));
	       bhd.newledgerroot = ctree_hashroot tr2
	    | None -> false
          end
	with MaxAssetsAtAddress -> false (** extra condition preventing addresses from holding too many assets **)
      end)
      then
	(*** The total inputs and outputs match up with the declared fee. ***)
	let tau = tx_of_block b in (*** let tau be the combined tx of the block ***)
	let (inpl,outpl) = tau in
	let aal = ctree_lookup_input_assets false false false inpl tr (fun _ _ -> ()) in
	let al = List.map (fun (_,a) -> a) aal in
	(*** Originally I added totalfees to the out_cost, but this was wrong since the totalfees are in the stake output which is already counted in out_cost. I don't really need totalfees to be explicit. ***)
	if out_cost outpl = Int64.add (asset_value_sum blkh al) reward then
	  let newtht = txout_update_ottree outpl tht in
	  let newsigt = txout_update_ostree outpl sigt in
          vbc (fun c -> Printf.fprintf c "comparing computed tht root %s to declared tht root %s\n" (match ottree_hashroot newtht with None -> "None" | Some(h) -> hashval_hexstring h) (match bhd.newtheoryroot with None -> "None" | Some(h) -> hashval_hexstring h));
	  if bhd.newtheoryroot = ottree_hashroot newtht
	      &&
	    bhd.newsignaroot = ostree_hashroot newsigt
	  then
	    Some(newtht,newsigt)
	  else
	    None
	else
	  None
      else
	None
    else
      None
  else
    None

(* This function validates a block given its theoretical hash tree (tht), signature tree (sigt), block height (blkh), consensus state machine (csm), transaction info (tinfo), the block itself (b), the median time of the last 11 blocks (lmedtm), the amount burned in the block (burned), and the transaction ID and output index of the pure burn (txid1 and vout1). *)
let valid_block tht sigt blkh csm tinfo (b:block) lmedtm burned txid1 vout1 =
  let ((bhd,_) as bh,_) = b in
  vbc (fun c -> Printf.fprintf c "Checking if block %s at height %Ld is valid.\n" (hashval_hexstring (blockheader_id bh)) blkh);
  let stkaddr = p2pkhaddr_addr bhd.stakeaddr in
  try
    match bhd.pureburn with
    | None ->
       valid_block_a tht sigt blkh csm tinfo b (blockheader_stakeasset bhd) bhd.stakeaddr stkaddr lmedtm burned
    | Some(txidh,vout) ->
       vbc (fun c -> Printf.fprintf c "pureburn %s %ld\ncomparing to %s %ld\n" (hashval_hexstring txidh) vout (hashval_hexstring txid1) vout1);
       if blkh > 5000L then (** pure burns only allowed in the first 5000 blocks, roughly half a year **)
         None
       else if (txidh = txid1) && (vout = vout1) then
         let aid = hashtag txidh vout in
         if aid = bhd.stakeassetid then
           let a = (aid,0L,None,Currency(0L)) in (** temporary asset pretending to be staked **)
           if blockheader_stakeasset bhd = a then
             valid_block_a tht sigt blkh csm tinfo b a bhd.stakeaddr stkaddr lmedtm burned
           else
             raise HeaderNoStakedAsset
         else
           raise HeaderNoStakedAsset
       else
         raise HeaderNoStakedAsset
  with
  | HeaderStakedAssetNotMin -> None
  | HeaderNoStakedAsset -> None


(* This function validates a block considering the possibility of a pure burn. *)
let valid_block_ifburn tht sigt blkh csm tinfo (b:block) lmedtm burned =
  let ((bhd,_) as bh,_) = b in
  vbc (fun c -> Printf.fprintf c "Checking if block %s at height %Ld is valid.\n" (hashval_hexstring (blockheader_id bh)) blkh);
  let stkaddr = p2pkhaddr_addr bhd.stakeaddr in
  try
    match bhd.pureburn with
    | None ->
       valid_block_a tht sigt blkh csm tinfo b (blockheader_stakeasset bhd) bhd.stakeaddr stkaddr lmedtm burned
    | Some(txidh,vout) ->
       if blkh > 5000L then (** pure burns only allowed in the first 5000 blocks, roughly half a year **)
         None
       else
         let aid = hashtag txidh vout in
         if aid = bhd.stakeassetid then
           let a = (aid,0L,None,Currency(0L)) in (** temporary asset pretending to be staked **)
           if blockheader_stakeasset bhd = a then
             valid_block_a tht sigt blkh csm tinfo b a bhd.stakeaddr stkaddr lmedtm burned
           else
             raise HeaderNoStakedAsset
         else
           raise HeaderNoStakedAsset
  with
  | HeaderStakedAssetNotMin -> None
  | HeaderNoStakedAsset -> None

let retargetdenom = big_int_of_int (200000 + 3600)

(* This function calculates the new target difficulty based on the current target and the time elapsed since the last block. *)
(* target 1 hour blocks *)
let retarget tar deltm =
  min_big_int
    !max_target
    (div_big_int
       (mult_big_int tar
	  (big_int_of_int32 (Int32.add 200000l deltm)))
       retargetdenom)

(* This function calculates the difficulty given the current target. *)
let difficulty tar =
  div_big_int !max_target tar

(* This function checks if a block header is a valid successor to a previous block header. *)
let blockheader_succ_a prevledgerroot tmstamp1 tinfo1 bh2 =
  let (bhd2,bhs2) = bh2 in
  vbc (fun c -> Printf.fprintf c "Checking if header is valid successor\n");
  let prevledgerroot2 =
    begin
      if bhd2.pureburn = None then
        Some(ctree_hashroot bhd2.prevledger)
      else
        match tx_octree_trans false false 1L ([(p2pkhaddr_addr bhd2.stakeaddr,bhd2.stakeassetid)],[]) (Some(bhd2.prevledger)) with
        | Some(prevledger2) -> Some(ctree_hashroot prevledger2)
        | None -> None
    end
  in
  vbcb (prevledgerroot2 = Some(prevledgerroot)) (fun c -> Printf.fprintf c "hashroot of prevledger matches\n") (fun c -> Printf.fprintf c "prevledger mismatch: computed in bhd2 %s ; prevledgerroot given as %s\n" (match prevledgerroot2 with None -> "None" | Some(r) -> hashval_hexstring r) (hashval_hexstring prevledgerroot))
    &&
  vbcb (bhd2.timestamp = Int64.add tmstamp1 (Int64.of_int32 bhd2.deltatime)) (fun c -> Printf.fprintf c "timestamp matches\n") (fun c -> Printf.fprintf c "timestamp mismatch bhd2 %Ld is not prev %Ld plus delta %ld\n" bhd2.timestamp tmstamp1 bhd2.deltatime)
    &&
  vbcb (eq_big_int bhd2.tinfo (retarget tinfo1 bhd2.deltatime)) (fun c -> Printf.fprintf c "target info matches\n") (fun c -> Printf.fprintf c "target info mismatch %s vs (retarget %s %ld) = %s\n" (string_of_big_int bhd2.tinfo) (string_of_big_int tinfo1) bhd2.deltatime (string_of_big_int (retarget tinfo1 bhd2.deltatime)))

let blockheader_succ_b pbh1 lr1 tmstmp1 tar1 bh2 =
  let (bhd2,_) = bh2 in
  match bhd2.prevblockhash with
  | Some(pbh,Poburn(lblkh,ltxh,lmedtm,burned,txid1,vout1)) ->
     tmstmp1 <= lmedtm
     &&
       pbh = pbh1 (*** the next block must also commit to the previous header with signature since the id hashes both the data and signature ***)
     &&
       blockheader_succ_a lr1 tmstmp1 tar1 bh2
  | None -> false

let blockheader_succ_c pbh1 lr1 tmstmp1 tar1 bh2 txid1a vout1a =
  let (bhd2,_) = bh2 in
  match bhd2.prevblockhash with
  | Some(pbh,Poburn(lblkh,ltxh,lmedtm,burned,txid1,vout1)) ->
     tmstmp1 <= lmedtm
     &&
       txid1a = txid1
     &&
       vout1a = vout1
     &&
       pbh = pbh1 (*** the next block must also commit to the previous header with signature since the id hashes both the data and signature ***)
     &&
       blockheader_succ_a lr1 tmstmp1 tar1 bh2
  | None -> false
     
let blockheader_succ bh1 bh2 =
  let (bhd1,_) = bh1 in
  match bhd1.pureburn with
  | None ->
     blockheader_succ_b (blockheader_id bh1) bhd1.newledgerroot bhd1.timestamp bhd1.tinfo bh2
  | Some(txid1,vout1) ->
     blockheader_succ_c (blockheader_id bh1) bhd1.newledgerroot bhd1.timestamp bhd1.tinfo bh2 txid1 vout1

let rec collect_header_inv_nbhd m h tosend =
  if m > 0 then
    begin
      try
	let (bhd,_) = DbBlockHeader.dbget h in
	collect_header_inv_nbhd_2 m h bhd tosend
      with Not_found -> ()
    end
and collect_header_inv_nbhd_2 m h bhd tosend =
  tosend := (int_of_msgtype Headers,h)::!tosend;
  if DbCTreeElt.dbexists bhd.newledgerroot then tosend := (int_of_msgtype CTreeElement,bhd.newledgerroot)::!tosend;
  if DbCTreeAtm.dbexists bhd.newledgerroot then tosend := (int_of_msgtype CTreeElement,bhd.newledgerroot)::!tosend; (** slightly dishonest, but don't want a new message type for atoms **)
  if DbBlockDelta.dbexists h then tosend := (int_of_msgtype Blockdelta,h)::!tosend;
  begin
    match bhd.prevblockhash with
    | Some(k,_) -> collect_header_inv_nbhd (m-1) k tosend
    | _ -> ()
  end

