(* Copyright (c) 2021 The Proofgold Lava developers *)
(* Copyright (c) 2021 The Proofgold Core developers *)
(* Copyright (c) 2020 The Proofgold developers *)
(* Copyright (c) 2015-2016 The Qeditas developers *)
(* Copyright (c) 2017-2019 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

open Zarithint
open Json
open Ser
open Sha256
open Hash
open Net
open Db
open Mathdata
open Assets
open Secp256k1
open Cryptocurr
open Signat
open Script

(* Define a type for transactions, which consist of a list of inputs and a list of outputs. *)
type tx = addr_assetid list * addr_preasset list

(* Compute the hash of a transaction by hashing its inputs and outputs. *)
let hashtx (inpl,outpl) =
  hashpair
    (hashlist (List.map hash_addr_assetid inpl))
    (hashlist (List.map hash_addr_preasset outpl))

(* Extract the inputs and outputs from a transaction. *)
let tx_inputs ((inpl,outpl):tx) = inpl
let tx_outputs ((inpl,outpl):tx) = outpl

(* Check whether a list contains any duplicate elements. *)
let rec no_dups l =
  match l with
  | [] -> true
  | x::r when List.mem x r -> false
  | _::r -> no_dups r

(* Check whether a transaction has at least one input and no duplicate inputs. *)
let tx_inputs_valid inpl =
  match inpl with
  | [] -> false
  | _ -> no_dups inpl

(* Check whether a transaction has at least one input and no duplicate inputs, and print an error message if it does not. *)
let tx_inputs_valid_oc oc inpl =
  match inpl with
  | [] ->
      Printf.fprintf oc "tx invalid since 0 inputs\n";
      false
  | _ ->
      if no_dups inpl then
	true
      else
	begin
	  Printf.fprintf oc "tx invalid since duplicate inputs\n";
	  false
	end

(* Ensure at most one owner is declared for each object/proposition. *)
let rec tx_outputs_valid_one_owner outpl ool pol nol =
  match outpl with
  | (alpha,(_,OwnsObj(h,beta,io)))::outpr ->
      if List.mem h ool then
	false
      else
	tx_outputs_valid_one_owner outpr (h::ool) pol nol
  | (alpha,(_,OwnsProp(h,beta,io)))::outpr ->
      if List.mem h pol then
	false
      else
	tx_outputs_valid_one_owner outpr ool (h::pol) nol
  | (alpha,(_,OwnsNegProp))::outpr ->
      if List.mem alpha nol then
	false
      else
	tx_outputs_valid_one_owner outpr ool pol (alpha::nol)
  | _::outpr -> tx_outputs_valid_one_owner outpr ool pol nol
  | [] -> true

(* Ensure at most one owner is declared for each object/proposition, and print an error message if there are any duplicates. *)
let rec tx_outputs_valid_one_owner_oc oc outpl ool pol nol =
  match outpl with
  | (alpha,(_,OwnsObj(h,beta,io)))::outpr ->
      if List.mem h ool then
	(Printf.fprintf oc "tx invalid since two OwnObj given for %s\n" (hashval_hexstring h);
	 false)
      else
	tx_outputs_valid_one_owner_oc oc outpr (h::ool) pol nol
  | (alpha,(_,OwnsProp(h,beta,io)))::outpr ->
      if List.mem h pol then
	(Printf.fprintf oc "tx invalid since two OwnsProp given for %s\n" (hashval_hexstring h);
	 false)
      else
	tx_outputs_valid_one_owner_oc oc outpr ool (h::pol) nol
  | (alpha,(_,OwnsNegProp))::outpr ->
      if List.mem alpha nol then
	(Printf.fprintf oc "tx invalid since two owners for OwnsNegProp given: %s\n" (Cryptocurr.addr_pfgaddrstr alpha);
	 false)
      else
	tx_outputs_valid_one_owner_oc oc outpr ool pol (alpha::nol)
  | _::outpr -> tx_outputs_valid_one_owner_oc oc outpr ool pol nol
  | [] -> true

(* Ensure ownership deeds are sent to term addresses and publications are sent to publication addresses. *)
let rec tx_outputs_valid_addr_cats outpl =
  match outpl with
  | (alpha,(_,Currency(_)))::outpr -> payaddr_p alpha && tx_outputs_valid_addr_cats outpr (*** currency should only be published to pay addresses ***)
  | (alpha,(_,Bounty(_)))::outpr -> termaddr_p alpha && tx_outputs_valid_addr_cats outpr (*** bounties should only be published to term addresses ***)
  | (alpha,(_,OwnsObj(h,beta,u)))::outpr -> hashval_term_addr h = alpha && tx_outputs_valid_addr_cats outpr
  | (alpha,(_,OwnsProp(h,beta,u)))::outpr -> hashval_term_addr h = alpha && tx_outputs_valid_addr_cats outpr
  | (alpha,(_,OwnsNegProp))::outpr -> termaddr_p alpha && tx_outputs_valid_addr_cats outpr
  | (alpha,(_,TheoryPublication(beta,h,dl)))::outpr ->
     begin
       match hashtheory (theoryspec_theory dl) with
       | Some(dlh) ->
	  alpha = hashval_pub_addr dlh && tx_outputs_valid_addr_cats outpr
       | None -> false
     end
  | (alpha,(_,SignaPublication(beta,h,th,dl)))::outpr ->
     alpha = hashval_pub_addr (hashopair2 th (hashsigna (signaspec_signa dl))) && tx_outputs_valid_addr_cats outpr
  | (alpha,(_,DocPublication(beta,h,th,dl)))::outpr ->
     (alpha = hashval_pub_addr (hashopair2 th (hashdoc dl)) && tx_outputs_valid_addr_cats outpr)
  | (alpha,(_,Marker))::outpr -> (pubaddr_p alpha || termaddr_p alpha) && tx_outputs_valid_addr_cats outpr (*** markers should only be published to publication addresses, since they're used to prepublish an intention to publish; but allow the output to be a term address as a way to indicate full_needed for a term address (for OP_PROVEN) ***)
  | _::outpr -> tx_outputs_valid_addr_cats outpr
  | [] -> true

(* Ensure ownership deeds are sent to term addresses and publications are sent to publication addresses, and print an error message if there are any violations. *)
let rec tx_outputs_valid_addr_cats_oc oc outpl =
  match outpl with
  | (alpha,(_,Currency(_)))::outpr ->
      if payaddr_p alpha then (* currency should only be published to pay addresses *)
	tx_outputs_valid_addr_cats outpr
      else
	(Printf.fprintf oc "tx invalid since Currency should be sent to a pay address, not %s\n" (Cryptocurr.addr_pfgaddrstr alpha); false)
  | (alpha,(_,Bounty(_)))::outpr ->
      if termaddr_p alpha then (*** bounties should only be published to term addresses ***)
	tx_outputs_valid_addr_cats outpr
      else
	(Printf.fprintf oc "tx invalid since Bounty should be sent to a term address, not %s\n" (Cryptocurr.addr_pfgaddrstr alpha); false)
  | (alpha,(_,OwnsObj(h,beta,u)))::outpr ->
      let alpha2 = hashval_term_addr h in
      if alpha2 = alpha then
	tx_outputs_valid_addr_cats_oc oc outpr
      else
	(Printf.fprintf oc "tx invalid since OwnsObj %s should be sent to %s not %s\n" (hashval_hexstring h) (Cryptocurr.addr_pfgaddrstr alpha2) (Cryptocurr.addr_pfgaddrstr alpha); false)
  | (alpha,(_,OwnsProp(h,beta,u)))::outpr ->
      let alpha2 = hashval_term_addr h in
      if alpha2 = alpha then
	tx_outputs_valid_addr_cats_oc oc outpr
      else
	(Printf.fprintf oc "tx invalid since OwnsProp %s should be sent to %s not %s\n" (hashval_hexstring h) (Cryptocurr.addr_pfgaddrstr alpha2) (Cryptocurr.addr_pfgaddrstr alpha); false)
  | (alpha,(_,OwnsNegProp))::outpr ->
      if termaddr_p alpha then 
	tx_outputs_valid_addr_cats_oc oc outpr
      else
	(Printf.fprintf oc "tx invalid since OwnsNegProp should be sent to a term address\n"; false)
  | (alpha,(_,TheoryPublication(beta,h,dl)))::outpr ->
     begin
       match hashtheory (theoryspec_theory dl) with
       | Some(dlh) ->
	  if alpha = hashval_pub_addr dlh then
	    tx_outputs_valid_addr_cats_oc oc outpr
	  else
	    (Printf.fprintf oc "tx invalid since Theory should be sent to %s\n" (Cryptocurr.addr_pfgaddrstr (hashval_pub_addr dlh)); false)
       | None -> false
     end
  | (alpha,(_,SignaPublication(beta,h,th,dl)))::outpr ->
     if alpha = hashval_pub_addr (hashopair2 th (hashsigna (signaspec_signa dl))) then
       tx_outputs_valid_addr_cats_oc oc outpr
     else
       (Printf.fprintf oc "tx invalid since Signature should be sent to %s\n" (Cryptocurr.addr_pfgaddrstr (hashval_pub_addr (hashopair2 th (hashsigna (signaspec_signa dl))))); false)
  | (alpha,(_,DocPublication(beta,h,th,dl)))::outpr ->
     if alpha = hashval_pub_addr (hashopair2 th (hashdoc dl)) then
       tx_outputs_valid_addr_cats_oc oc outpr
     else
       (Printf.fprintf oc "tx invalid since Document should be sent to %s\n" (Cryptocurr.addr_pfgaddrstr (hashval_pub_addr (hashopair2 th (hashdoc dl)))); false)
  | (alpha,(_,Marker))::outpr ->
      if pubaddr_p alpha then
	tx_outputs_valid_addr_cats_oc oc outpr (*** markers should only be published to publication addresses, since they're used to prepublish an intention to publish ***)
      else
	(Printf.fprintf oc "tx invalid since Marker not sent to a publication address\n"; false)
  | _::outpr -> tx_outputs_valid_addr_cats_oc oc outpr
  | [] -> true

(* Check whether a transaction's outputs are valid by ensuring that there is at most one owner for each object/proposition and that ownership deeds are sent to term addresses and publications are sent to publication addresses. *)
let tx_outputs_valid (outpl: addr_preasset list) =
  tx_outputs_valid_one_owner outpl [] [] []
    &&
  tx_outputs_valid_addr_cats outpl
    &&
  not (List.exists (fun (alpha,(_,u)) -> match preasset_units u with Some(u) when u < 0L -> true | _ -> false) outpl)

(* Check whether a transaction's outputs are valid by ensuring that there is at most one owner for each object/proposition and that ownership deeds are sent to term addresses and publications are sent to publication addresses, and print an error message if there are any violations. *)
let tx_outputs_valid_oc oc (outpl: addr_preasset list) =
  tx_outputs_valid_one_owner_oc oc outpl [] [] []
    &&
  tx_outputs_valid_addr_cats_oc oc outpl 
    &&
  not (List.exists (fun (alpha,(_,u)) -> match preasset_units u with Some(u) when u < 0L -> true | _ -> false) outpl)

(* Check whether a transaction is valid by checking that its inputs and outputs are valid. *)
let tx_valid tau = tx_inputs_valid (tx_inputs tau) && tx_outputs_valid (tx_outputs tau)

(* Check whether a transaction is valid by checking that its inputs and outputs are valid, and print an error message if it is not. *)
let tx_valid_oc oc tau = tx_inputs_valid_oc oc (tx_inputs tau) && tx_outputs_valid_oc oc (tx_outputs tau)

(* Define a type for signatures, which can either be a real signature or a reference to a signature in a list. *)
type gensignat_or_ref = GenSignatReal of gensignat | GenSignatRef of int

(* Define a type for signed transactions, which consist of a transaction and a list of input and output signatures. *)
type txsigs = gensignat_or_ref option list * gensignat_or_ref option list
type stx = tx * txsigs

(* Raise an exception if a signature is missing or invalid. *)
exception BadOrMissingSignature

(* Compute the maximum of two optional big integers. *)
let opmax b1 b2 =
  match (b1,b2) with
  | (Some(b1),Some(b2)) -> if b1 > b2 then Some(b1) else Some(b2)
  | (_,None) -> b1
  | _ -> b2

(* Check whether a signature satisfies a spending obligation up to a certain block height. *)
let check_spend_obligation_upto_blkh obday alpha (txhe:Z.t) s obl =
  match obl with
  | None -> (* defaults to alpha with no block height restriction *)
      let (b,mbh,mtm,provenl) = verify_gensignat obday txhe s alpha in
      if b then
	(true,mbh,mbh,mtm,provenl)
      else
	raise BadOrMissingSignature
  | Some(gamma,lkh,_) ->
      let (b,mbh,mtm,provenl) = verify_gensignat obday txhe s (Hash.payaddr_addr gamma) in
      if b then
	(b,mbh,opmax mbh (Some(lkh)),mtm,provenl)
      else
	raise BadOrMissingSignature

(* Check whether a signature satisfies a spending obligation up to a certain block height, given the transaction's stxid. *)
let check_spend_obligation_upto_blkh2 obday alpha stxid (txhe:Z.t) s obl =
  match obl with
  | None -> (* defaults to alpha with no block height restriction *)
      let (b,mbh,mtm,provenl) = verify_gensignat2 obday stxid txhe s alpha in
      if b then
	(true,mbh,mbh,mtm,provenl)
      else
	raise BadOrMissingSignature
  | Some(gamma,lkh,_) ->
      let (b,mbh,mtm,provenl) = verify_gensignat2 obday stxid txhe s (Hash.payaddr_addr gamma) in
      if b then
	(b,mbh,opmax mbh (Some(lkh)),mtm,provenl)
      else
	raise BadOrMissingSignature

(* Check whether a signature satisfies a spending obligation for a given block height and time. *)
let check_spend_obligation obday alpha blkh tm (txhe:Z.t) s obl =
  try
    let (b,mbh1,mbh2,mtm,provenl) = check_spend_obligation_upto_blkh obday alpha txhe s obl in
    if b then
      if blkh < Utils.lockingfixsoftforkheight then (* lock was actually ignored before this height due to a bug *)
        if (match (mbh1,mtm) with
            | (Some(bh2),Some(tm2)) -> bh2 <= blkh && tm2 <= tm
            | (Some(bh2),None) -> bh2 <= blkh
            | (None,Some(tm2)) -> tm2 <= tm
            | (None,None) -> true)
        then
          Some(provenl)
        else
          None
      else
        if (match (mbh2,mtm) with
            | (Some(bh2),Some(tm2)) -> bh2 <= blkh && tm2 <= tm
            | (Some(bh2),None) -> bh2 <= blkh
            | (None,Some(tm2)) -> tm2 <= tm
            | (None,None) -> true)
        then
          Some(provenl)
        else
          None
    else
      None
  with BadOrMissingSignature -> None

(* Check whether a signature satisfies a move obligation. *)
let check_move_obligation alpha txhe s obl2 u2 outpl =
  try
    if not (payaddr_p alpha) then raise Not_found; (* things held and termaddrs and pubaddrs should not be "moved" in this way *)
    ignore (List.find (fun z -> let (beta,(obl,u)) = z in obl = obl2 && u = u2) outpl);
    let (b,mbh,mtm,provenl) = verify_gensignat None txhe s alpha in
    b && mbh = None && mtm = None && provenl = [] (* insist that moves do not depend on the time or block height or proven props (for simplicity) *)
  with Not_found -> false

(* Extract a signature from a list of signatures, given its index. *)
let getsig s rl =
  match s with
  | Some(GenSignatReal(s)) -> (s,s::rl)
  | Some(GenSignatRef(i)) -> (* only allow up to 64K signatures on the list; should be much less than this in practice *)
      if i < 65535 && i >= 0 then
	(List.nth rl i,rl)
      else
	raise BadOrMissingSignature
  | None ->
      raise BadOrMissingSignature

(* Check whether an asset pre is a marker or a bounty. *)
let marker_or_bounty_p a =
  match assetpre a with
  | Marker -> true
  | Bounty(_) -> true
  | _ -> false

(* Check whether a transaction's inputs are valid and have valid signatures, and compute the maximum block height and time specified in the signatures. *)
let rec check_tx_in_signatures txhe outpl inpl al sl rl propowns =
  match inpl,al,sl with
  | [],[],[] -> (true,None,None,None)
  | (alpha,k)::inpr,(a::ar),sl when marker_or_bounty_p a -> (*** don't require signatures to spend markers and bounties; but there are conditions for the tx to be supported by a ctree ***)
      if assetid a = k then
	begin
	  match a with
	  | (_,bday,Some(_,_,_),Bounty(_)) when not (List.mem alpha propowns) -> (*** if a is a Bounty and there is no corresponding ownership being spent, then require a signature (allow bounties to be collected according to the obligation after lockheight has passed) ***)
	      begin
		try
		  match sl with
		  | s::sr ->
		      let (s1,rl1) = getsig s rl in
		      let (b,mbha,mbhb,mtm) = check_tx_in_signatures txhe outpl inpr ar sr rl1 propowns in
		      if b then
			let (b,mbh2a,mbh2b,mtm2,provenl2) = check_spend_obligation_upto_blkh (Some(bday)) alpha txhe s1 (assetobl a) in
			if b then
			  (true,opmax mbha mbh2a,opmax mbhb mbh2b,opmax mtm mtm2)
			else
			  (false,None,None,None)
		      else
			(false,None,None,None)
		  | [] -> raise Not_found
		with Not_found -> raise BadOrMissingSignature
	      end		      
	  | _ ->
	      check_tx_in_signatures txhe outpl inpr ar sl rl propowns
	end
      else
	raise BadOrMissingSignature
  | (alpha,k)::inpr,(a::ar),(s::sr) ->
      begin
	try
	  let (s1,rl1) = getsig s rl in
	  if assetid a = k then
	    let (b,mbha,mbhb,mtm) = check_tx_in_signatures txhe outpl inpr ar sr rl1 propowns in
	    if b then
	      begin
		try
		  let (b,mbh2a,mbh2b,mtm2,provenl2) = check_spend_obligation_upto_blkh (Some(assetbday a)) alpha txhe s1 (assetobl a) in
		  if b then
		    (true,opmax mbha mbh2a,opmax mbhb mbh2b,opmax mtm mtm2)
		  else
		    (false,None,None,None)
		with BadOrMissingSignature ->
		  if check_move_obligation alpha txhe s1 (assetobl a) (assetpre a) outpl then
		    (true,mbha,mbhb,mtm)
		  else
		    raise BadOrMissingSignature
	      end
	    else
	      raise BadOrMissingSignature
	  else
	    raise BadOrMissingSignature
	with Not_found -> raise BadOrMissingSignature
      end
  | _,_,_ ->
      raise BadOrMissingSignature

(* Check whether a transaction's inputs are valid and have valid signatures, given the transaction's stxid, and compute the maximum block height and time specified in the signatures. *)
let rec check_tx_in_signatures2 stxid txhe outpl inpl al sl rl propowns =
  match inpl,al,sl with
  | [],[],[] -> (true,None,None,None,[])
  | (alpha,k)::inpr,(a::ar),sl when marker_or_bounty_p a -> (*** don't require signatures to spend markers and bounties; but there are conditions for the tx to be supported by a ctree ***)
      if assetid a = k then
	begin
	  match a with
	  | (_,bday,Some(_,_,_),Bounty(_)) when not (List.mem alpha propowns) -> (*** if a is a Bounty and there is no corresponding ownership being spent, then require a signature (allow bounties to be collected according to the obligation after lockheight has passed) ***)
	      begin
		try
		  match sl with
		  | s::sr ->
		      let (s1,rl1) = getsig s rl in
		      let (b,mbha,mbhb,mtm,provenl) = check_tx_in_signatures2 stxid txhe outpl inpr ar sr rl1 propowns in
		      if b then
			let (b,mbh2a,mbh2b,mtm2,provenl2) = check_spend_obligation_upto_blkh2 (Some(bday)) alpha stxid txhe s1 (assetobl a) in
			if b then
			  (true,opmax mbha mbh2a,opmax mbhb mbh2b,opmax mtm mtm2,provenl @ provenl2)
			else
			  (false,None,None,None,[])
		      else
			(false,None,None,None,[])
		  | [] -> raise Not_found
		with Not_found -> raise BadOrMissingSignature
	      end		      
	  | _ ->
	      check_tx_in_signatures2 stxid txhe outpl inpr ar sl rl propowns
	end
      else
	raise BadOrMissingSignature
  | (alpha,k)::inpr,(a::ar),(s::sr) ->
      begin
	try
	  let (s1,rl1) = getsig s rl in
	  if assetid a = k then
	    let (b,mbha,mbhb,mtm,provenl) = check_tx_in_signatures2 stxid txhe outpl inpr ar sr rl1 propowns in
	    if b then
	      begin
		try
		  let (b,mbh2a,mbh2b,mtm2,provenl2) = check_spend_obligation_upto_blkh2 (Some(assetbday a)) alpha stxid txhe s1 (assetobl a) in
		  if b then
		    (true,opmax mbha mbh2a,opmax mbhb mbh2b,opmax mtm mtm2,provenl @ provenl2)
		  else
		    (false,None,None,None,[])
		with BadOrMissingSignature ->
		  if check_move_obligation alpha txhe s1 (assetobl a) (assetpre a) outpl then
		    (true,mbha,mbhb,mtm,provenl)
		  else
		    raise BadOrMissingSignature
	      end
	    else
	      raise BadOrMissingSignature
	  else
	    raise BadOrMissingSignature
	with Not_found -> raise BadOrMissingSignature
      end
  | _,_,_ ->
      raise BadOrMissingSignature

(* Check whether a transaction's outputs have valid signatures. *)
let rec check_tx_out_signatures txhe outpl sl rl =
  match outpl,sl with
  | [],[] -> true
  | [],(_::_) -> false
  | (_,(_,TheoryPublication(alpha,n,thy)))::outpr,[] -> false
  | (_,(_,TheoryPublication(alpha,n,thy)))::outpr,s::sr ->
      begin
	try
	  let (s1,rl1) = getsig s rl in
	  if check_tx_out_signatures txhe outpr sr rl1 then
	    let (b,mbh,mtm,provenl) = verify_gensignat None txhe s1 (payaddr_addr alpha) in
	    if b && mbh = None && mtm = None then (*** output signatures should never depend on the time or block height ***)
	      true
	    else
	      false
	  else
	    false
	with Not_found -> false
      end
  | (_,(_,SignaPublication(alpha,n,th,si)))::outpr,[] -> false
  | (_,(_,SignaPublication(alpha,n,th,si)))::outpr,s::sr ->
      begin
	try
	  let (s1,rl1) = getsig s rl in
	  if check_tx_out_signatures txhe outpr sr rl1 then
	    let (b,mbh,mtm,provenl) = verify_gensignat None txhe s1 (payaddr_addr alpha) in
	    if b && mbh = None && mtm = None then (*** output signatures should never depend on the time or block height ***)
	      true
	    else
	      false
	  else
	    false
	with Not_found -> false
      end
  | (_,(_,DocPublication(alpha,n,th,d)))::outpr,[] -> false
  | (_,(_,DocPublication(alpha,n,th,d)))::outpr,s::sr ->
      begin
	try
	  let (s1,rl1) = getsig s rl in
	  if check_tx_out_signatures txhe outpr sr rl1 then
	    let (b,mbh,mtm,provenl) = verify_gensignat None txhe s1 (payaddr_addr alpha) in
	    if b && mbh = None && mtm = None then (*** output signatures should never depend on the time or block height ***)
	      true
	    else
	      false
	  else
	    false
	with Not_found -> false
      end
  | _::outpr,_ ->
      check_tx_out_signatures txhe outpr sl rl

(* Compute the serialization of a transaction. *)
let seo_tx o g c = seo_prod (seo_list seo_addr_assetid) (seo_list seo_addr_preasset) o g c

(* Deserialize a transaction. *)
let sei_tx i c = sei_prod (sei_list sei_addr_assetid) (sei_list sei_addr_preasset) i c

(* Compute the serialization of a signature. *)
let seo_gensignat_or_ref o g c =
  match g with
  | GenSignatReal(s) ->
      let c = o 1 0 c in
      seo_gensignat o s c
  | GenSignatRef(i) ->
      let c = o 1 1 c in
      seo_varintb o i c

(* Deserialize a signature. *)
let sei_gensignat_or_ref i c =
  let (b,c) = i 1 c in
  if b = 0 then
    let (s,c) = sei_gensignat i c in
    (GenSignatReal(s),c)
  else
    let (j,c) = sei_varintb i c in
    (GenSignatRef(j),c)

(* Compute the serialization of a list of signatures. *)
let seo_txsigs o g c = seo_prod (seo_list (seo_option seo_gensignat_or_ref)) (seo_list (seo_option seo_gensignat_or_ref)) o g c

(* Deserialize a list of signatures. *)
let sei_txsigs i c = sei_prod (sei_list (sei_option sei_gensignat_or_ref)) (sei_list (sei_option sei_gensignat_or_ref)) i c

(* Compute the serialization of a signed transaction. *)
let seo_stx o g c = seo_prod seo_tx seo_txsigs o g c

(* Deserialize a signed transaction. *)
let sei_stx i c = sei_prod sei_tx sei_txsigs i c

(* Compute the hash of a signed transaction. *)
let hashtxsigs g =
  let s = Buffer.create 1000 in
  seosbf (seo_txsigs seosb g (s,None));
  sha256str_hashval (Buffer.contents s)


(***
 The hash of signed tx does depend on the signatures, and this hash is used as the id of the tx
 (e.g., by Inv, STx and GetSTx network messages).
 But the assetid created by the tx only depends on the hashtx of tau (see add_vout in assets.ml).
 Since the assetid is what is referenced when spent by future txs, we have behavior like segwit.
***)

(* Compute the hash of a signed transaction, which is used as its ID. *)
let hashstx (tau,tausigs) = hashpair (hashtx tau) (hashtxsigs tausigs)

(* Check whether a signed transaction's signatures are valid as of a certain block height. *)
let tx_signatures_valid_asof_blkh al stau =
  let (tau,(sli,slo)) = stau in
  let stxh = hashstx stau in
  let txh = if !Config.testnet then hashtag (hashtx tau) 288l else hashtx tau in (*** sign a modified hash for testnet ***)
  let txhe = hashval_big_int txh in
  let rec get_propowns tauin al =
    match tauin,al with
    | ((alpha,aid1)::tauinr),((aid2,_,_,OwnsProp(_,_,_))::ar) when aid1 = aid2 -> alpha::get_propowns tauinr ar
    | ((alpha,aid1)::tauinr),((aid2,_,_,OwnsNegProp)::ar) when aid1 = aid2 -> alpha::get_propowns tauinr ar
    | ((_,aid1)::tauinr),((aid2,_,_,_)::ar) when aid1 = aid2 -> get_propowns tauinr ar
    | [],[] -> []
    | _,_ -> raise BadOrMissingSignature (*** actually this means the asset list does not match the inputs ***)
  in
  let (b,mbha,mbhb,mtm,provenl) = check_tx_in_signatures2 stxh txhe (tx_outputs tau) (tx_inputs tau) al sli [] (get_propowns (tx_inputs tau) al) in
  if b then
    if check_tx_out_signatures txhe (tx_outputs tau) slo [] then
      (mbha,mbhb,mtm,provenl)
    else
      raise BadOrMissingSignature
  else
    raise BadOrMissingSignature

(* Estimate the number of required input signatures for a transaction. *)
let rec estimate_required_in_signatures al =
  match al with
  | [] -> 0
  | (a::ar) when marker_or_bounty_p a -> estimate_required_in_signatures ar
  | (a::ar) -> 1+ estimate_required_in_signatures ar

(* Estimate the number of required output signatures for a transaction. *)
let rec estimate_required_out_signatures outpl =
  match outpl with
  | [] -> 0
  | (_,(_,TheoryPublication(alpha,n,thy)))::outpr -> 1 + estimate_required_out_signatures outpr
  | (_,(_,SignaPublication(alpha,n,th,si)))::outpr -> 1 + estimate_required_out_signatures outpr
  | (_,(_,DocPublication(alpha,n,th,d)))::outpr -> 1 + estimate_required_out_signatures outpr
  | _::outpr -> estimate_required_out_signatures outpr

(* Estimate the total number of required signatures for a transaction. *)
let estimate_required_signatures al (tauin,tauout) =
  estimate_required_in_signatures al + estimate_required_out_signatures tauout

(* Check whether a signed transaction's signatures are valid for a given block height and time. *)
let tx_signatures_valid blkh tm al stau =
  try
    let (mbha,mbhb,mtm,provenl) = tx_signatures_valid_asof_blkh al stau in
    if blkh < Utils.lockingfixsoftforkheight then
      if (match (mbha,mtm) with
          | (Some(bh2),Some(tm2)) -> bh2 <= blkh && tm2 <= tm
          | (Some(bh2),None) -> bh2 <= blkh
          | (None,Some(tm2)) -> tm2 <= tm
          | (None,None) -> true)
      then
        Some([])
      else
        None
    else
      if (match (mbhb,mtm) with
          | (Some(bh2),Some(tm2)) -> bh2 <= blkh && tm2 <= tm
          | (Some(bh2),None) -> bh2 <= blkh
          | (None,Some(tm2)) -> tm2 <= tm
          | (None,None) -> true)
      then
        Some(provenl)
      else
        None
  with BadOrMissingSignature -> None

(* Update an obligation tree with the theories published in a transaction's outputs. *)
let rec txout_update_ottree outpl tht =
  match outpl with
  | [] -> tht
  | (alpha,(obl,TheoryPublication(gamma,nonce,d)))::outpr ->
      let thy = theoryspec_theory d in
      begin
	match hashtheory thy with
	| Some(thyh) ->
	    txout_update_ottree outpr (Some(ottree_insert tht (hashval_bitseq thyh) thy))
	| _ -> txout_update_ottree outpr tht
      end
  | _::outpr -> txout_update_ottree outpr tht

(* Update an obligation tree with the theories published in a transaction's outputs. *)
let tx_update_ottree tau tht = txout_update_ottree (tx_outputs tau) tht

(* Update an obligation tree with the signatures published in a transaction's outputs. *)
let rec txout_update_ostree outpl sigt =
  match outpl with
  | [] -> sigt
  | (alpha,(obl,SignaPublication(gamma,nonce,th,d)))::outpr ->
      let sg = signaspec_signa d in
      let thsgh = hashopair2 th (hashsigna sg) in
      txout_update_ostree outpr (Some(ostree_insert sigt (hashval_bitseq thsgh) (th,sg)))
  | _::outpr -> txout_update_ostree outpr sigt

(* Update an obligation tree with the signatures published in a transaction's outputs. *)
let tx_update_ostree tau sigt = txout_update_ostree (tx_outputs tau) sigt

(* Compute the size of a signed transaction. *)
let stxsize stau =
  let b = Buffer.create 1000 in
  seosbf (seo_stx seosb stau (b,None));
  String.length (Buffer.contents b)

(* Define a module for storing and retrieving signed transactions in a database. *)
module DbSTx = Dbmbasic (struct type t = stx let basedir = "stx" let seival = sei_stx seis let seoval = seo_stx seosb end)

(* Serialize an address-assetid pair to JSON. *)
let json_addr_assetid (alpha,h) =
  JsonObj([("address",JsonStr(addr_pfgaddrstr alpha));("assetid",JsonStr(hashval_hexstring h))])

(* Deserialize an address-assetid pair from JSON. *)
let addr_assetid_from_json j =
  match j with
  | JsonObj(al) ->
      let alpha = addr_from_json(List.assoc "address" al) in
      let h = hashval_from_json(List.assoc "assetid" al) in
      (alpha,h)
  | _ -> raise (Failure("not a pair of an address with an asset id"))

(* Serialize an address-preasset pair to JSON. *)
let json_addr_preasset (alpha,(obl,u)) =
  match obl with
  | None ->
      JsonObj([("address",JsonStr(addr_pfgaddrstr alpha));
	       ("preasset",json_preasset u)])
  | Some(gamma,lh,r) ->
      JsonObj([("address",JsonStr(addr_pfgaddrstr alpha));
	       ("obligation",JsonObj([("lockaddr",JsonStr(addr_pfgaddrstr (payaddr_addr gamma)));
				      ("lockheight",JsonNum(Int64.to_string lh));
				      ("reward",JsonBool(r))]));
	       ("preasset",json_preasset u)])

(* Serialize a list of transaction outputs to JSON. *)
let rec json_txouts txh txouts i =
  match txouts with
  | [] -> []
  | (alpha,(obl,u))::txoutr ->
      let aid = hashpair txh (hashint32 (Int32.of_int i)) in
      let j =
	match json_obligation obl with
	| None ->
	    JsonObj([("address",JsonStr(addr_pfgaddrstr alpha));
		     ("assetid",JsonStr(hashval_hexstring aid));
		     ("preasset",json_preasset u)])
	| Some(jobl) ->
	    JsonObj([("address",JsonStr(addr_pfgaddrstr alpha));
		     ("assetid",JsonStr(hashval_hexstring aid));
		     ("obligation",jobl);
		     ("preasset",json_preasset u)])
      in
      j::json_txouts txh txoutr (i+1)

(* Serialize a transaction to JSON. *)
let json_tx (inpl,outpl) =
  JsonObj([("vin",JsonArr(List.map json_addr_assetid inpl));("vout",JsonArr(json_txouts (hashtx (inpl,outpl)) outpl 0))])

(* Deserialize a transaction from JSON. *)
let tx_from_json j =
  match j with
  | JsonObj(al) ->
      begin
	match List.assoc "vin" al,List.assoc "vout" al with
	| JsonArr(jvinl),JsonArr(jvoutl) ->
	    (List.map addr_assetid_from_json jvinl,
	     List.map
	       (fun jvout ->
		 match jvout with
		 | JsonObj(bl) ->
		     begin
		       let alpha = addr_from_json (List.assoc "address" bl) in
		       let u = preasset_from_json (List.assoc "preasset" bl) in
		       let jobl =
			 try
			   let jobl = List.assoc "obligation" bl in
			   Some(jobl)
			 with Not_found -> None
		       in
		       let obl = obligation_from_json jobl in
		       (alpha,(obl,u))
		     end
		 | _ -> raise Not_found)
	       jvoutl)
	| _,_ -> raise (Failure("not a tx"))
      end
  | _ -> raise (Failure("not a tx"))

(* Serialize a gensignat_or_ref option to JSON. *)
let json_gensignat_or_ref_option s =
  match s with
  | Some(GenSignatReal(gs)) -> json_gensignat gs
  | Some(GenSignatRef(n)) -> JsonNum(string_of_int n)
  | None -> JsonObj([])

(* Serialize a txsigs value to JSON. *)
let json_txsigs (insigs,outsigs) =
  JsonObj([("insigs",JsonArr(List.map json_gensignat_or_ref_option insigs));("outsigs",JsonArr(List.map json_gensignat_or_ref_option outsigs))])

(* Serialize a signed transaction to JSON. *)
let json_stx (tau,stau) = JsonObj([("type",JsonStr("stx"));("tx",json_tx tau);("txsigs",json_txsigs stau)])
