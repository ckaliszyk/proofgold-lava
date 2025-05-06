(* Copyright (c) 2021-2023 The Proofgold Lava developers *)
(* Copyright (c) 2020 The Proofgold developers *)
(* Copyright (c) 2016 The Qeditas developers *)
(* Copyright (c) 2017-2018 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

open Json
open Ser
open Sha256
open Hash
open Db
open Htree
open Logic
open Zarithint

let term_hfbuiltin_objid : (hashval,hashval) Hashtbl.t = Hashtbl.create 10
let term_theory_objid_history_table : (hashval,hashval option * hashval * hashval) Hashtbl.t = Hashtbl.create 10
let term_theory_objid_bkp : (hashval option * hashval,hashval) Hashtbl.t = Hashtbl.create 10
let term_theory_objid : (hashval option * hashval,hashval) Hashtbl.t = Hashtbl.create 10
let propid_conj_pub_history_table : (hashval,hashval * addr) Hashtbl.t = Hashtbl.create 10
let propid_conj_pub_bkp : (hashval,addr) Hashtbl.t = Hashtbl.create 10
let propid_conj_pub : (hashval,addr) Hashtbl.t = Hashtbl.create 10

let term_addr_hashval : (addr,hashval) Hashtbl.t = Hashtbl.create 10
let propid_neg_propid : (hashval,hashval) Hashtbl.t = Hashtbl.create 10

let enter_term_addr_hashval h = Hashtbl.replace term_addr_hashval (hashval_term_addr h) h

let preimage_of_term_addr_json alpha al =
  try
    let h = Hashtbl.find term_addr_hashval alpha in
    ("preimagehash",JsonStr(hashval_hexstring h))::al
  with Not_found -> al

let printlist l = List.iter (fun ((x, y), z) -> Printf.printf "%s " (hashval_hexstring x)) l

(** ** tp serialization ***)
let rec seo_tp o m c =
  match m with
  | TpArr(m0,m1) -> (*** 0 0 ***)
    let c = o 2 0 c in
    let c = seo_tp o m0 c in
    let c = seo_tp o m1 c in
    c
  | Prop -> (*** 0 1 ***)
    o 2 2 c
  | Base(x) when x < 65536 -> (*** 1 ***)
    let c = o 1 1 c in
    seo_varintb o x c
  | Base(_) -> raise (Failure("Invalid base type"))

let tp_to_str m =
  let c = Buffer.create 1000 in
  seosbf (seo_tp seosb m (c,None));
  Buffer.contents c

let hashtp m = hashtag (sha256str_hashval (tp_to_str m)) 64l

let rec sei_tp i c =
  let (b,c) = i 1 c in
  if b = 0 then
    let (b,c) = i 1 c in
    if b = 0 then
      let (m0,c) = sei_tp i c in
      let (m1,c) = sei_tp i c in
      (TpArr(m0,m1),c)
    else
      (Prop,c)
  else
    let (x,c) = sei_varintb i c in
    (Base(x),c)

(** ** tp list serialization ***)
let seo_tpl o al c = seo_list seo_tp o al c
let sei_tpl i c = sei_list sei_tp i c

let tpl_to_str al =
  let c = Buffer.create 1000 in
  seosbf (seo_tpl seosb al (c,None));
  Buffer.contents c

let hashtpl al =
  if al = [] then
    None
  else
    Some(hashtag (sha256str_hashval (tpl_to_str al)) 65l)

(** ** tm serialization ***)
let rec seo_tm o m c =
  match m with
  | TmH(h) -> (*** 000 ***)
    let c = o 3 0 c in
    let c = seo_hashval o h c in
    c
  | DB(x) when x >= 0 && x <= 65535 -> (*** 001 ***)
    let c = o 3 1 c in
    seo_varintb o x c
  | DB(x) ->
    raise (Failure "seo_tm - de Bruijn out of bounds");
  | Prim(x) when x >= 0 && x <= 65535 -> (*** 010 ***)
    let c = o 3 2 c in
    let c = seo_varintb o x c in
    c
  | Prim(x) ->
    raise (Failure "seo_tm - Prim out of bounds");
  | Ap(m0,m1) -> (*** 011 ***)
    let c = o 3 3 c in
    let c = seo_tm o m0 c in
    let c = seo_tm o m1 c in
    c
  | Lam(m0,m1) -> (*** 100 ***)
    let c = o 3 4 c in
    let c = seo_tp o m0 c in
    let c = seo_tm o m1 c in
    c
  | Imp(m0,m1) -> (*** 101 ***)
    let c = o 3 5 c in
    let c = seo_tm o m0 c in
    let c = seo_tm o m1 c in
    c
  | All(m0,m1) -> (*** 110 ***)
    let c = o 3 6 c in
    let c = seo_tp o m0 c in
    let c = seo_tm o m1 c in
    c
  | Ex(a,m1) -> (*** 111 0 ***)
    let c = o 4 7 c in
    let c = seo_tp o a c in
    let c = seo_tm o m1 c in
    c
  | Eq(a,m1,m2) -> (*** 111 1 ***)
    let c = o 4 15 c in
    let c = seo_tp o a c in
    let c = seo_tm o m1 c in
    let c = seo_tm o m2 c in
    c

let tm_to_str m =
  let c = Buffer.create 1000 in
  seosbf (seo_tm seosb m (c,None));
  Buffer.contents c

let hashtm m = hashtag (sha256str_hashval (tm_to_str m)) 66l

let rec sei_tm i c =
  let (x,c) = i 3 c in
  if x = 0 then
    let (h,c) = sei_hashval i c in
    (TmH(h),c)
  else if x = 1 then
    let (z,c) = sei_varintb i c in
    (DB(z),c)
  else if x = 2 then
    let (z,c) = sei_varintb i c in
    (Prim(z),c)
  else if x = 3 then
    let (m0,c) = sei_tm i c in
    let (m1,c) = sei_tm i c in
    (Ap(m0,m1),c)
  else if x = 4 then
    let (m0,c) = sei_tp i c in
    let (m1,c) = sei_tm i c in
    (Lam(m0,m1),c)
  else if x = 5 then
    let (m0,c) = sei_tm i c in
    let (m1,c) = sei_tm i c in
    (Imp(m0,m1),c)
  else if x = 6 then
    let (m0,c) = sei_tp i c in
    let (m1,c) = sei_tm i c in
    (All(m0,m1),c)
  else
    let (y,c) = i 1 c in
    if y = 0 then
      let (a,c) = sei_tp i c in
      let (m0,c) = sei_tm i c in
      (Ex(a,m0),c)
    else
      let (a,c) = sei_tp i c in
      let (m0,c) = sei_tm i c in
      let (m1,c) = sei_tm i c in
      (Eq(a,m0,m1),c)

(** ** pf serialization ***)
let rec seo_pf o m c =
  match m with
  | Hyp(x) when x >= 0 && x <= 65535 -> (*** 001 ***)
    let c = o 3 1 c in
    seo_varintb o x c
  | Hyp(x) ->
    raise (Failure "seo_pf - Hypothesis out of bounds");
  | Known(h) -> (*** 010 ***)
    let c = o 3 2 c in
    let c = seo_hashval o h c in
    c
  | TmAp(m0,m1) -> (*** 011 ***)
    let c = o 3 3 c in
    let c = seo_pf o m0 c in
    let c = seo_tm o m1 c in
    c
  | PrAp(m0,m1) -> (*** 100 ***)
    let c = o 3 4 c in
    let c = seo_pf o m0 c in
    let c = seo_pf o m1 c in
    c
  | PrLa(m0,m1) -> (*** 101 ***)
    let c = o 3 5 c in
    let c = seo_tm o m0 c in
    let c = seo_pf o m1 c in
    c
  | TmLa(m0,m1) -> (*** 110 ***)
    let c = o 3 6 c in
    let c = seo_tp o m0 c in
    let c = seo_pf o m1 c in
    c
  | Ext(a,b) -> (*** 111 ***)
    let c = o 3 7 c in
    let c = seo_tp o a c in
    let c = seo_tp o b c in
    c

let pf_to_str m =
  let c = Buffer.create 1000 in
  seosbf (seo_pf seosb m (c,None));
  Buffer.contents c

let hashpf m = hashtag (sha256str_hashval (pf_to_str m)) 67l

let rec sei_pf i c =
  let (x,c) = i 3 c in
  if x = 0 then
    failwith "GPA"
  else if x = 1 then
    let (z,c) = sei_varintb i c in
    (Hyp(z),c)
  else if x = 2 then
    let (z,c) = sei_hashval i c in
    (Known(z),c)
  else if x = 3 then
    let (m0,c) = sei_pf i c in
    let (m1,c) = sei_tm i c in
    (TmAp(m0,m1),c)
  else if x = 4 then
    let (m0,c) = sei_pf i c in
    let (m1,c) = sei_pf i c in
    (PrAp(m0,m1),c)
  else if x = 5 then
    let (m0,c) = sei_tm i c in
    let (m1,c) = sei_pf i c in
    (PrLa(m0,m1),c)
  else if x = 6 then
    let (m0,c) = sei_tp i c in
    let (m1,c) = sei_pf i c in
    (TmLa(m0,m1),c)
  else
    let (a,c) = sei_tp i c in
    let (b,c) = sei_tp i c in
    (Ext(a,b),c)

(** ** theoryspec serialization ***)
let seo_theoryitem o m c =
  match m with
  | Thyprim(a) -> (* 0 0 *)
    let c = o 2 0 c in
    seo_tp o a c
  | Thydef(a,m) -> (* 0 1 *)
    let c = o 2 2 c in
    let c = seo_tp o a c in
    seo_tm o m c
  | Thyaxiom(m) -> (* 1 *)
    let c = o 1 1 c in
    seo_tm o m c

let sei_theoryitem i c =
  let (b,c) = i 1 c in
  if b = 0 then
    let (b,c) = i 1 c in
    if b = 0 then
      let (a,c) = sei_tp i c in
      (Thyprim(a),c)
    else
      let (a,c) = sei_tp i c in
      let (m,c) = sei_tm i c in
      (Thydef(a,m),c)
  else
    let (m,c) = sei_tm i c in
    (Thyaxiom(m),c)

let seo_theoryspec o dl c = seo_list seo_theoryitem o dl c
let sei_theoryspec i c = sei_list sei_theoryitem i c

let theoryspec_to_str m =
  let c = Buffer.create 1000 in
  seosbf (seo_theoryspec seosb m (c,None));
  Buffer.contents c

(** ** signaspec serialization ***)
let seo_signaitem o m c =
  match m with
  | Signasigna(h) -> (** 00 **)
    let c = o 2 0 c in
    seo_hashval o h c
  | Signaparam(h,a) -> (** 01 **)
    let c = o 2 1 c in
    let c = seo_hashval o h c in
    seo_tp o a c
  | Signadef(a,m) -> (** 10 **)
    let c = o 2 2 c in
    let c = seo_tp o a c in
    seo_tm o m c
  | Signaknown(m) -> (** 11 **)
    let c = o 2 3 c in
    seo_tm o m c

let sei_signaitem i c =
  let (b,c) = i 2 c in
  if b = 0 then
    let (h,c) = sei_hashval i c in
    (Signasigna(h),c)
  else if b = 1 then
    let (h,c) = sei_hashval i c in
    let (a,c) = sei_tp i c in
    (Signaparam(h,a),c)
  else if b = 2 then
    let (a,c) = sei_tp i c in
    let (m,c) = sei_tm i c in
    (Signadef(a,m),c)
  else
    let (m,c) = sei_tm i c in
    (Signaknown(m),c)

let seo_signaspec o dl c = seo_list seo_signaitem o dl c
let sei_signaspec i c = sei_list sei_signaitem i c

let signaspec_to_str m =
  let c = Buffer.create 1000 in
  seosbf (seo_signaspec seosb m (c,None));
  Buffer.contents c

(** ** doc serialization ***)
let seo_docitem o m c =
  match m with
  | Docsigna(h) -> (** 00 0 **)
    let c = o 3 0 c in
    seo_hashval o h c
  | Docparam(h,a) -> (** 00 1 **)
    let c = o 3 4 c in
    let c = seo_hashval o h c in
    seo_tp o a c
  | Docdef(a,m) -> (** 01 **)
    let c = o 2 1 c in
    let c = seo_tp o a c in
    seo_tm o m c
  | Docknown(m) -> (** 10 0 **)
    let c = o 3 2 c in
    seo_tm o m c
  | Docconj(m) -> (** 10 1 **)
    let c = o 3 6 c in
    seo_tm o m c
  | Docpfof(m,d) -> (** 11 **)
    let c = o 2 3 c in
    let c = seo_tm o m c in
    seo_pf o d c

let sei_docitem i c =
  let (b,c) = i 2 c in
  if b = 0 then
    let (b,c) = i 1 c in
    if b = 0 then
      let (h,c) = sei_hashval i c in
      (Docsigna(h),c)
    else
      let (h,c) = sei_hashval i c in
      let (a,c) = sei_tp i c in
      (Docparam(h,a),c)
  else if b = 1 then
    let (a,c) = sei_tp i c in
    let (m,c) = sei_tm i c in
    (Docdef(a,m),c)
  else if b = 2 then
    let (b,c) = i 1 c in
    if b = 0 then
      let (m,c) = sei_tm i c in
      (Docknown(m),c)
    else
      let (m,c) = sei_tm i c in
      (Docconj(m),c)
  else
    let (m,c) = sei_tm i c in
    let (d,c) = sei_pf i c in
    (Docpfof(m,d),c)

let seo_doc o dl c = seo_list seo_docitem o dl c
let sei_doc i c = sei_list sei_docitem i c

let doc_to_str m =
  let c = Buffer.create 1000 in
  seosbf (seo_doc seosb m (c,None));
  Buffer.contents c

let hashdoc m = hashtag (sha256str_hashval (doc_to_str m)) 70l

(** ** serialization of theories ***)
let seo_theory o (al,kl) c =
  let c = seo_tpl o al c in
  seo_list seo_hashval o kl c

let sei_theory i c =
  let (al,c) = sei_tpl i c in
  let (kl,c) = sei_list sei_hashval i c in
  ((al,kl),c)

let theory_to_str thy =
  let c = Buffer.create 1000 in
  seosbf (seo_theory seosb thy (c,None));
  Buffer.contents c

module DbTheory = Dbmbasic (struct type t = theory let basedir = "theory" let seival = sei_theory seis let seoval = seo_theory seosb end)

module DbTheoryTree =
  Dbmbasic
    (struct
      type t = hashval option * hashval list
      let basedir = "theorytree"
      let seival = sei_prod (sei_option sei_hashval) (sei_list sei_hashval) seis
      let seoval = seo_prod (seo_option seo_hashval) (seo_list seo_hashval) seosb
    end)

(** * computation of hash roots ***)
let rec tm_hashroot m =
  match m with
  | TmH(h) -> h
  | Prim(x) -> hashtag (hashint32 (Int32.of_int x)) 96l
  | DB(x) -> hashtag (hashint32 (Int32.of_int x)) 97l
  | Ap(m,n) -> hashtag (hashpair (tm_hashroot m) (tm_hashroot n)) 98l
  | Lam(a,m) -> hashtag (hashpair (hashtp a) (tm_hashroot m)) 99l
  | Imp(m,n) -> hashtag (hashpair (tm_hashroot m) (tm_hashroot n)) 100l
  | All(a,m) -> hashtag (hashpair (hashtp a) (tm_hashroot m)) 101l
  | Ex(a,m) -> hashtag (hashpair (hashtp a) (tm_hashroot m)) 102l
  | Eq(a,m,n) -> hashtag (hashpair (hashpair (hashtp a) (tm_hashroot m)) (tm_hashroot n)) 103l

let rec pf_hashroot d =
  match d with
  | Known(h) -> hashtag h 128l
  | Hyp(x) -> hashtag (hashint32 (Int32.of_int x)) 129l
  | TmAp(d,m) -> hashtag (hashpair (pf_hashroot d) (tm_hashroot m)) 130l
  | PrAp(d,e) -> hashtag (hashpair (pf_hashroot d) (pf_hashroot e)) 131l
  | PrLa(m,d) -> hashtag (hashpair (tm_hashroot m) (pf_hashroot d)) 132l
  | TmLa(a,d) -> hashtag (hashpair (hashtp a) (pf_hashroot d)) 133l
  | Ext(a,b) -> hashtag (hashpair (hashtp a) (hashtp b)) 134l

let rec docitem_hashroot d =
  match d with
  | Docsigna(h) -> hashtag h 172l
  | Docparam(h,a) -> hashtag (hashpair h (hashtp a)) 173l
  | Docdef(a,m) -> hashtag (hashpair (hashtp a) (tm_hashroot m)) 174l
  | Docknown(m) -> hashtag (tm_hashroot m) 175l
  | Docconj(m) -> hashtag (tm_hashroot m) 176l
  | Docpfof(m,d) -> hashtag (hashpair (tm_hashroot m) (pf_hashroot d)) 177l

let rec doc_hashroot dl =
  match dl with
  | [] -> hashint32 180l
  | d::dr -> hashtag (hashpair (docitem_hashroot d) (doc_hashroot dr)) 181l

let hashtheory (al,kl) =
  hashopair
    (ohashlist (List.map hashtp al))
    (ohashlist kl)

let hashgsigna (tl,kl) =
  hashpair
    (hashlist
       (List.map (fun z ->
	          match z with
	          | ((h,a),None) -> hashtag (hashpair h (hashtp a)) 160l
	          | ((h,a),Some(m)) -> hashtag (hashpair h (hashpair (hashtp a) (hashtm m))) 161l)
	         tl))
    (hashlist (List.map (fun (k,p) -> (hashpair k (hashtm p))) kl))

let hashsigna (sl,(tl,kl)) = hashpair (hashlist sl) (hashgsigna (tl,kl))

let seo_gsigna o s c =
  seo_prod
    (seo_list (seo_prod_prod seo_hashval seo_tp (seo_option seo_tm)))
    (seo_list (seo_prod seo_hashval seo_tm))
    o s c

let sei_gsigna i c =
  sei_prod
    (sei_list (sei_prod_prod sei_hashval sei_tp (sei_option sei_tm)))
    (sei_list (sei_prod sei_hashval sei_tm))
    i c

let seo_signa o s c =
  seo_prod (seo_list seo_hashval) seo_gsigna o s c

let sei_signa i c =
  sei_prod (sei_list sei_hashval) sei_gsigna i c

let signa_to_str s =
  let c = Buffer.create 1000 in
  seosbf (seo_signa seosb s (c,None));
  Buffer.contents c

module DbSigna = Dbmbasic (struct type t = hashval option * signa let basedir = "signa" let seival = sei_prod (sei_option sei_hashval) sei_signa seis let seoval = seo_prod (seo_option seo_hashval) seo_signa seosb end)

module DbSignaTree =
  Dbmbasic
    (struct
      type t = hashval option * hashval list
      let basedir = "signatree"
      let seival = sei_prod (sei_option sei_hashval) (sei_list sei_hashval) seis
      let seoval = seo_prod (seo_option seo_hashval) (seo_list seo_hashval) seosb
    end)

(** * htrees to hold theories and signatures **)

type ttree = theory htree
type stree = (hashval option * signa) htree

let ottree_insert t bl thy =
  match t with
  | Some(t) -> htree_insert t bl thy
  | None -> htree_create bl thy

let ostree_insert t bl s =
  match t with
  | Some(t) -> htree_insert t bl s
  | None -> htree_create bl s

let ottree_hashroot t = ohtree_hashroot hashtheory 256 t

let ostree_hashroot t = ohtree_hashroot (fun (th,s) -> Some(hashopair2 th (hashsigna s))) 256 t

let ottree_lookup (t:ttree option) h =
  match t, h with
  | Some(t), Some(h) ->
    begin
	    match htree_lookup (hashval_bitseq h) t with
	    | None -> raise Not_found
	    | Some(thy) -> thy
    end
  | _,None -> ([],[])
  | _,_ -> raise Not_found

let ostree_lookup (t:stree option) h =
  match t, h with
  | Some(t), Some(h) ->
    begin
	    match htree_lookup (hashval_bitseq h) t with
	    | None -> raise Not_found
	    | Some(sg) -> sg
    end
  | _,None -> (None,([],([],[])))
  | _,_ -> raise Not_found

(** * operations including type checking and proof checking ***)

let rec import_signatures th (str:stree) hl sg imported =
  match hl with
  | [] -> Some (sg,imported)
  | (h::hr) ->
    if List.mem h imported then
      (import_signatures th str hr sg imported)
    else
      match htree_lookup (hashval_bitseq h) str with 
      | Some(th2,(sl,(tptml2,kl2))) when th = th2 ->
	  begin
	    match import_signatures th str (sl @ hr) sg (h::imported) with
            | Some ((tptml3,kl3),imported) -> Some ((tptml3 @ tptml2,kl3 @ kl2), imported)
            | None -> None
	  end
      | Some(th2,(sl,(tptml2,kl2))) -> raise (Failure "Signatures are for different theories and so cannot be combined.")
      | _ -> None

let rec print_tp t base_types =
  match t with
  | Base i -> Printf.printf "base %d %d " i base_types
  | TpArr (t1, t2) -> (Printf.printf "tparr "; print_tp t1 base_types; print_tp t2 base_types)
  | Prop -> Printf.printf "prop "

let rec print_trm ctx sgn t thy =
  match t with
  | DB i -> Printf.printf "(DB %d %d )" (List.length ctx) i
  | TmH h ->
    printlist (fst sgn);
      Printf.printf "\n";
      Printf.printf "(TmH %s)" (hashval_hexstring h)
  | Prim i -> Printf.printf "(Prim %d %d )" (List.length thy) i
  | Ap (t1, t2) -> (Printf.printf "ap "; print_trm ctx sgn t1 thy; print_trm ctx sgn t2 thy)
  | Lam (a1, t1) -> (Printf.printf "lam "; print_tp a1 (List.length thy); print_trm ctx sgn t1 thy)
  | Imp (t1, t2) -> (Printf.printf "imp "; print_trm ctx sgn t1 thy; print_trm ctx sgn t2 thy)
  | All (b, t1) -> (Printf.printf "all "; print_tp b (List.length thy); print_trm ctx sgn t1 thy)
  | Ex (b, t1) -> (Printf.printf "ex "; print_tp b (List.length thy); print_trm ctx sgn t1 thy)
  | Eq (b, t1, t2) -> (Printf.printf "eq "; print_tp b (List.length thy); print_trm ctx sgn t1 thy; print_trm ctx sgn t2 thy)

let rec print_pf ctx phi sg p thy =
  match p with
  | Known h -> Printf.printf "known %s " (hashval_hexstring h)
  | Hyp i -> Printf.printf "hypoth %d\n" i
  | PrAp (p1, p2) ->
    Printf.printf "proof ap (";
    print_pf ctx phi sg p1 thy;
    print_pf ctx phi sg p2 thy;
    Printf.printf ")"
  | TmAp (p1, t1) ->
    Printf.printf "trm ap (";
    print_pf ctx phi sg p1 thy;
    print_trm ctx sg t1 thy;
    Printf.printf ")"
  | PrLa (s, p1) ->
    Printf.printf "proof lam (";
    print_pf ctx (s :: phi) sg p1 thy;
    print_trm ctx sg s thy;
    Printf.printf ")"
  | TmLa (a1, p1) ->
    Printf.printf "trm lam (";
    print_pf (a1::ctx) phi sg p1 thy; (* (List.map (fun x -> uptrm x 0 1) phi) *)
    print_tp a1 (List.length thy);
    Printf.printf ")"
  | Ext (a, b) ->
    Printf.printf "ext (";
    print_tp a (List.length thy);
    print_tp b (List.length thy);
    Printf.printf ")"

exception CheckingFailure

(** * conversion of theoryspec to theory and signaspec to signa **)
let rec theoryspec_primtps_r dl =
  match dl with
  | [] -> []
  | Thyprim(a)::dr -> a::theoryspec_primtps_r dr
  | _::dr -> theoryspec_primtps_r dr
  
let theoryspec_primtps dl = List.rev (theoryspec_primtps_r dl)

let rec theoryspec_hashedaxioms dl =
  match dl with
  | [] -> []
  | Thyaxiom(m)::dr -> tm_hashroot m::theoryspec_hashedaxioms dr
  | _::dr -> theoryspec_hashedaxioms dr

let theoryspec_theory thy = (theoryspec_primtps thy,theoryspec_hashedaxioms thy)

let hashtheory (al,kl) =
  hashopair
    (ohashlist (List.map hashtp al))
    (ohashlist kl)

let rec signaspec_signas s =
  match s with
  | [] -> []
  | Signasigna(h)::r -> h::signaspec_signas r
  | _::r -> signaspec_signas r

let rec signaspec_trms s =
  match s with
  | [] -> []
  | Signaparam(h,a)::r -> ((h, a), None)::signaspec_trms r
  | Signadef(a,m)::r -> ((tm_hashroot m, a), Some(m))::signaspec_trms r
  | _::r -> signaspec_trms r

let rec signaspec_knowns s =
  match s with
  | [] -> []
  | Signaknown(p)::r -> (tm_hashroot p,p)::signaspec_knowns r
  | _::r -> signaspec_knowns r

let signaspec_signa s = (signaspec_signas s, (signaspec_trms s, signaspec_knowns s))

let theory_burncost thy =
  Int64.mul 2100000000L (Int64.of_int (String.length (theory_to_str thy)))
  
let theoryspec_burncost s = theory_burncost (theoryspec_theory s)

let signa_burncost s =
  Int64.mul 2100000000L (Int64.of_int (String.length (signa_to_str s)))

let signaspec_burncost s = signa_burncost (signaspec_signa s)

(** * extract which objs/props are used/created by signatures and documents, as well as full_needed needed to globally verify terms have a certain type/knowns are known **)

let adj x l = if List.mem x l then l else x::l

let rec signaspec_uses_objs_aux (dl:signaspec) r : (hashval * hashval) list =
  match dl with
  | Signaparam(h,a)::dr -> signaspec_uses_objs_aux dr (adj (h,hashtp a) r)
  | _::dr -> signaspec_uses_objs_aux dr r
  | [] -> r

let signaspec_uses_objs (dl:signaspec) : (hashval * hashval) list = signaspec_uses_objs_aux dl []

let rec signaspec_uses_props_aux (dl:signaspec) r : hashval list =
  match dl with
  | Signaknown(p)::dr -> signaspec_uses_props_aux dr (adj (tm_hashroot p) r)
  | _::dr -> signaspec_uses_props_aux dr r
  | [] -> r

let signaspec_uses_props (dl:signaspec) : hashval list = signaspec_uses_props_aux dl []

let rec doc_uses_objs_aux (dl:doc) r : (hashval * hashval) list =
  match dl with
  | Docparam(h,a)::dr -> doc_uses_objs_aux dr (adj (h,hashtp a) r)
  | _::dr -> doc_uses_objs_aux dr r
  | [] -> r

let doc_uses_objs (dl:doc) : (hashval * hashval) list = doc_uses_objs_aux dl []

let rec doc_uses_props_aux (dl:doc) r : hashval list =
  match dl with
  | Docknown(p)::dr -> doc_uses_props_aux dr (adj (tm_hashroot p) r)
  | _::dr -> doc_uses_props_aux dr r
  | [] -> r

let doc_uses_props (dl:doc) : hashval list = doc_uses_props_aux dl []

let rec doc_creates_objs_aux (dl:doc) r : (hashval * hashval) list =
  match dl with
  | Docdef(a,m)::dr -> doc_creates_objs_aux dr (adj (tm_hashroot m,hashtp a) r)
  | _::dr -> doc_creates_objs_aux dr r
  | [] -> r

let doc_creates_objs (dl:doc) : (hashval * hashval) list = doc_creates_objs_aux dl []

let rec doc_creates_props_aux (dl:doc) r : hashval list =
  match dl with
  | Docpfof(p,d)::dr -> doc_creates_props_aux dr (adj (tm_hashroot p) r)
  | _::dr -> doc_creates_props_aux dr r
  | [] -> r

let doc_creates_props (dl:doc) : hashval list = doc_creates_props_aux dl []

let falsehashprop = tm_hashroot (All(Prop,DB(0)))
let neghashprop = tm_hashroot (Lam(Prop,Imp(DB(0),TmH(falsehashprop))))

let invert_neg_prop p =
  match p with
  | Imp(np,f) when tm_hashroot f = falsehashprop -> np
  | Ap(n,np) when tm_hashroot n = neghashprop -> np
  | _ -> raise Not_found

let neg_prop p =
  try
    invert_neg_prop p
  with Not_found -> Imp(p,All(Prop,DB(0)))

let rec doc_creates_neg_props_aux (dl:doc) r : hashval list =
  match dl with
  | Docpfof(p,d)::dr ->
      begin
	try
	  let np = invert_neg_prop p in
	  doc_creates_neg_props_aux dr (adj (tm_hashroot np) r)
	with Not_found -> doc_creates_neg_props_aux dr r
      end
  | _::dr -> doc_creates_neg_props_aux dr r
  | [] -> r

let doc_creates_neg_props (dl:doc) : hashval list = doc_creates_neg_props_aux dl []

let rec json_stp a =
  match a with
  | Base(i) -> JsonObj([("type",JsonStr("stp"));("stpcase",JsonStr("base"));("base",JsonNum(string_of_int i))])
  | TpArr(a1,a2) -> JsonObj([("type",JsonStr("stp"));("stpcase",JsonStr("tparr"));("dom",json_stp a1);("cod",json_stp a2)])
  | Prop -> JsonObj([("type",JsonStr("stp"));("stpcase",JsonStr("prop"))])

let rec json_trm m =
  match m with
  | DB(i) -> JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("db"));("db",JsonNum(string_of_int i))])
  | TmH(h) -> JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("tmh"));("trmroot",JsonStr(hashval_hexstring h))])
  | Prim(i) -> JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("prim"));("prim",JsonNum(string_of_int i))])
  | Ap(m,n) -> JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("ap"));("func",json_trm m);("arg",json_trm n)])
  | Lam(a,m) -> JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("lam"));("dom",json_stp a);("body",json_trm m)])
  | Imp(m,n) -> JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("imp"));("ant",json_trm m);("suc",json_trm n)])
  | All(a,m) -> JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("all"));("dom",json_stp a);("body",json_trm m)])
  | Ex(a,m) -> JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("ex"));("dom",json_stp a);("body",json_trm m)])
  | Eq(a,m,n) -> JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("eq"));("stp",json_stp a);("lhs",json_trm m);("rhs",json_trm n)])

let rec json_pf d =
  match d with
  | Known(h) -> JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("known"));("trmroot",JsonStr(hashval_hexstring h))])
  | Hyp(i) -> JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("hyp"));("hyp",JsonNum(string_of_int i))])
  | PrAp(d,e) -> JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("prap"));("func",json_pf d);("arg",json_pf e)])
  | TmAp(d,m) -> JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("tmap"));("func",json_pf d);("arg",json_trm m)])
  | PrLa(m,d) -> JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("prla"));("dom",json_trm m);("body",json_pf d)])
  | TmLa(a,d) -> JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("tmla"));("dom",json_stp a);("body",json_pf d)])
  | Ext(a,b) -> JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("ext"));("dom",json_stp a);("cod",json_stp b)])

let json1_theoryitem x =
  match x with
  | Thyprim(a) -> JsonObj([("type",JsonStr("theoryitem"));("theoryitemcase",JsonStr("thyprim"));("stp",json_stp a)])
  | Thyaxiom(p) -> JsonObj([("type",JsonStr("theoryitem"));("theoryitemcase",JsonStr("thyaxiom"));("prop",json_trm p)])
  | Thydef(a,m) -> JsonObj([("type",JsonStr("theoryitem"));("theoryitemcase",JsonStr("thydef"));("stp",json_stp a);("def",json_trm m)])

let json1_signaitem th x =
  match x with
  | Signasigna(h) -> JsonObj([("type",JsonStr("signaitem"));("signaitemcase",JsonStr("signasigna"));("signaroot",JsonStr(hashval_hexstring h))])
  | Signaparam(h,a) ->
      let objid = hashtag (hashopair2 th (hashpair h (hashtp a))) 32l in
      JsonObj([("type",JsonStr("signaitem"));("signaitemcase",JsonStr("signaparam"));("trmroot",JsonStr(hashval_hexstring h));("objid",JsonStr(hashval_hexstring objid));("stp",json_stp a)])
  | Signadef(a,m) ->
      let trmroot = tm_hashroot m in
      let objid = hashtag (hashopair2 th (hashpair trmroot (hashtp a))) 32l in
      JsonObj([("type",JsonStr("signaitem"));("signaitemcase",JsonStr("signadef"));("stp",json_stp a);("trmroot",JsonStr(hashval_hexstring trmroot));("objid",JsonStr(hashval_hexstring objid));("def",json_trm m)])
  | Signaknown(p) ->
      let trmroot = tm_hashroot p in
      let propid = hashtag (hashopair2 th trmroot) 33l in
      JsonObj([("type",JsonStr("signaitem"));("signaitemcase",JsonStr("signaknown"));("trmroot",JsonStr(hashval_hexstring trmroot));("propid",JsonStr(hashval_hexstring propid));("prop",json_trm p)])

let json1_docitem th x =
  match x with
  | Docsigna(h) -> JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docsigna"));("signaroot",JsonStr(hashval_hexstring h))])
  | Docparam(h,a) ->
      let objid = hashtag (hashopair2 th (hashpair h (hashtp a))) 32l in
      JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docparam"));("trmroot",JsonStr(hashval_hexstring h));("objid",JsonStr(hashval_hexstring objid));("stp",json_stp a)])
  | Docdef(a,m) ->
      let trmroot = tm_hashroot m in
      let objid = hashtag (hashopair2 th (hashpair trmroot (hashtp a))) 32l in
      JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docdef"));("stp",json_stp a);("trmroot",JsonStr(hashval_hexstring trmroot));("objid",JsonStr(hashval_hexstring objid));("def",json_trm m)])
  | Docknown(p) ->
      let trmroot = tm_hashroot p in
      let propid = hashtag (hashopair2 th trmroot) 33l in
      JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docknown"));("trmroot",JsonStr(hashval_hexstring trmroot));("propid",JsonStr(hashval_hexstring propid));("prop",json_trm p)])
  | Docpfof(p,d) ->
      let trmroot = tm_hashroot p in
      let propid = hashtag (hashopair2 th trmroot) 33l in
      JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docpfof"));("trmroot",JsonStr(hashval_hexstring trmroot));("propid",JsonStr(hashval_hexstring propid));("prop",json_trm p);("pf",json_pf d)])
  | Docconj(p) ->
      let trmroot = tm_hashroot p in
      let propid = hashtag (hashopair2 th trmroot) 33l in
      JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docconj"));("trmroot",JsonStr(hashval_hexstring trmroot));("propid",JsonStr(hashval_hexstring propid));("prop",json_trm p)])

let json1_theoryspec ts = JsonArr(List.map json1_theoryitem ts)

let json1_signaspec th ss = JsonArr(List.map (json1_signaitem th) ss)

let json1_doc th d = JsonArr (List.map (json1_docitem th) d)

let rec stp_from_json j =
  match j with
  | JsonObj(al) ->
      let c = List.assoc "stpcase" al in
      if c = JsonStr("base") then
	Base(int_from_json(List.assoc "base" al))
      else if c = JsonStr("tparr") then
	TpArr(stp_from_json(List.assoc "dom" al),stp_from_json(List.assoc "cod" al))
      else if c = JsonStr("prop") then
	Prop
      else
	raise (Failure("not an stp"))
  | _ -> raise (Failure("not an stp"))

let rec trm_from_json j =
  match j with
  | JsonObj(al) ->
      let c = List.assoc "trmcase" al in
      if c = JsonStr("db") then
	DB(int_from_json(List.assoc "db" al))
      else if c = JsonStr("tmh") then
	TmH(hashval_from_json(List.assoc "trmroot" al))
      else if c = JsonStr("prim") then
	Prim(int_from_json(List.assoc "prim" al))
      else if c = JsonStr("ap") then
	Ap(trm_from_json(List.assoc "func" al),trm_from_json(List.assoc "arg" al))
      else if c = JsonStr("lam") then
	Lam(stp_from_json(List.assoc "dom" al),trm_from_json(List.assoc "body" al))
      else if c = JsonStr("imp") then
	Imp(trm_from_json(List.assoc "ant" al),trm_from_json(List.assoc "suc" al))
      else if c = JsonStr("all") then
	All(stp_from_json(List.assoc "dom" al),trm_from_json(List.assoc "body" al))
      else if c = JsonStr("ex") then
	Ex(stp_from_json(List.assoc "dom" al),trm_from_json(List.assoc "body" al))
      else if c = JsonStr("eq") then
	Eq(stp_from_json(List.assoc "stp" al),trm_from_json(List.assoc "lhs" al),trm_from_json(List.assoc "rhs" al))
      else
	raise (Failure("not a trm"))
  | _ -> raise (Failure("not a trm"))

let rec pf_from_json j =
  match j with
  | JsonObj(al) ->
      let c = List.assoc "pfcase" al in
      if c = JsonStr("known") then
	Known(hashval_from_json(List.assoc "trmroot" al))
      else if c = JsonStr("hyp") then
	Hyp(int_from_json(List.assoc "hyp" al))
      else if c = JsonStr("prap") then
	PrAp(pf_from_json(List.assoc "func" al),pf_from_json(List.assoc "arg" al))
      else if c = JsonStr("tmap") then
	TmAp(pf_from_json(List.assoc "func" al),trm_from_json(List.assoc "arg" al))
      else if c = JsonStr("prla") then
	PrLa(trm_from_json(List.assoc "dom" al),pf_from_json(List.assoc "body" al))
      else if c = JsonStr("tmla") then
	TmLa(stp_from_json(List.assoc "dom" al),pf_from_json(List.assoc "body" al))
      else if c = JsonStr("ext") then
	Ext(stp_from_json(List.assoc "dom" al),stp_from_json(List.assoc "cod" al))
      else
	raise (Failure("not a pf"))
  | _ -> raise (Failure("not a pf"))

let theoryitem_from_json j =
  match j with
  | JsonObj(al) ->
      let c = List.assoc "theoryitemcase" al in
      if c = JsonStr("thyprim") then
	Thyprim(stp_from_json(List.assoc "stp" al))
      else if c = JsonStr("thyaxiom") then
	Thyaxiom(trm_from_json(List.assoc "prop" al))
      else if c = JsonStr("thydef") then
	Thydef(stp_from_json(List.assoc "stp" al),trm_from_json(List.assoc "def" al))
      else
	raise (Failure("not a theoryitem"))
  | _ -> raise (Failure("not a theoryitem"))

let signaitem_from_json j =
  match j with
  | JsonObj(al) ->
      let c = List.assoc "signaitemcase" al in
      if c = JsonStr("signasigna") then
	Signasigna(hashval_from_json(List.assoc "signaroot" al))
      else if c = JsonStr("signaparam") then
	Signaparam(hashval_from_json(List.assoc "trmroot" al),stp_from_json(List.assoc "stp" al))
      else if c = JsonStr("signadef") then
	Signadef(stp_from_json(List.assoc "stp" al),trm_from_json(List.assoc "def" al))
      else if c = JsonStr("signaknown") then
	Signaknown(trm_from_json(List.assoc "prop" al))
      else
	raise (Failure("not a signaitem"))
  | _ -> raise (Failure("not a signaitem"))

let docitem_from_json j =
  match j with
  | JsonObj(al) ->
      let c = List.assoc "docitemcase" al in
      if c = JsonStr("docsigna") then
	Docsigna(hashval_from_json(List.assoc "signaroot" al))
      else if c = JsonStr("docparam") then
	Docparam(hashval_from_json(List.assoc "trmroot" al),stp_from_json(List.assoc "stp" al))
      else if c = JsonStr("docdef") then
	Docdef(stp_from_json(List.assoc "stp" al),trm_from_json(List.assoc "def" al))
      else if c = JsonStr("docknown") then
	Docknown(trm_from_json(List.assoc "prop" al))
      else if c = JsonStr("docpfof") then
	Docpfof(trm_from_json(List.assoc "prop" al),pf_from_json(List.assoc "pf" al))
      else if c = JsonStr("docconj") then
	Docconj(trm_from_json(List.assoc "prop" al))
      else
	raise (Failure("not a docitem"))
  | _ -> raise (Failure("not a docitem"))

let theoryspec_from_json j =
  match j with
  | JsonArr(jl) -> List.map theoryitem_from_json jl
  | _ -> raise (Failure("not a theoryspec"))

let signaspec_from_json j =
  match j with
  | JsonArr(jl) -> List.map signaitem_from_json jl
  | _ -> raise (Failure("not a signaspec"))

let doc_from_json j =
  match j with
  | JsonArr(jl) -> List.map docitem_from_json jl
  | _ -> raise (Failure("not a doc"))

(** print 'nice' megalodon style terms **)
let mgnice = ref false;;
let mgnicestp = ref false;;
let mgnatnotation = ref false;;

let hfthyroot = hexstring_hashval "6ffc9680fbe00a58d70cdeb319f11205ed998131ce51bb96f16c7904faf74a3d";;
let egalthyroot = hexstring_hashval "29c988c5e6c620410ef4e61bcfcbe4213c77013974af40759d8b732c07d61967";;
let mizthyroot = hexstring_hashval "5ab3df7b0b4ef20889de0517a318df8746940971ad9b2021e54c820eb9e74dce";;
let hoasthyroot = hexstring_hashval "513140056e2032628f48d11e221efe29892e9a03a661d3b691793524a5176ede";;

(** built in hf set theory for pow style bounties **)
let hfprimnamesa = [| "Eps_i";
"False";
"True";
"not";
"and";
"or";
"iff";
"In";
"Subq";
"Empty";
"Union";
"Power";
"Repl";
"TransSet";
"atleast2";
"atleast3";
"atleast4";
"atleast5";
"atleast6";
"exactly2";
"exactly3";
"exactly4";
"exactly5";
"exu_i";
"reflexive_i";
"irreflexive_i";
"symmetric_i";
"antisymmetric_i";
"transitive_i";
"eqreln_i";
"per_i";
"linear_i";
"trichotomous_or_i";
"partialorder_i";
"totalorder_i";
"strictpartialorder_i";
"stricttotalorder_i";
"If_i";
"exactly1of2";
"exactly1of3";
"nIn";
"nSubq";
"UPair";
"Sing";
"binunion";
"SetAdjoin";
"famunion";
"Sep";
"ReplSep";
"binintersect";
"setminus";
"inj";
"bij";
"atleastp";
"equip";
"In_rec_poly_G_i";
"In_rec_poly_i";
"ordsucc";
"nat_p";
"nat_primrec";
"add_nat";
"mul_nat";
"ordinal";
"V_";
"Inj1";
"Inj0";
"Unj";
"combine_funcs";
"setsum";
"proj0";
"proj1";
"binrep";
"lam";
"setprod";
"ap";
"setsum_p";
"tuple_p";
"Pi";
"setexp";
"Sep2";
"set_of_pairs";
"lam2";
"PNoEq_";
"PNoLt_";
"PNoLt";
"PNoLe";
"PNo_downc";
"PNo_upc";
"SNoElts_";
"SNo_";
"PSNo";
"SNo";
"SNoLev";
"SNoEq_";
"SNoLt";
"SNoLe";
"binop_on";
"Loop";
"Loop_with_defs";
"Loop_with_defs_cex1";
"Loop_with_defs_cex2";
"combinator";
"combinator_equiv";
"equip_mod" |]

let hflegend : (hashval,string) Hashtbl.t = Hashtbl.create 100;;
Hashtbl.add hflegend (hexstring_hashval "59c584807067a366bc9b0408e8ad8ee5430ea169d30808760e97247fa5bc77d2") "exp_nat";;
Hashtbl.add hflegend (hexstring_hashval "8170ad5e6535f2661f0d055afe32d84d876773f4e8519ce018687f54b2ba9159") "u1";;
Hashtbl.add hflegend (hexstring_hashval "3bd7f72ec38573ff1d3910239a4aa349e3832908ab08202cf114451bffd7d17d") "u2";;
Hashtbl.add hflegend (hexstring_hashval "1da7b5b024a841d0694168c01df8b0cada113e9c4616f1555b257b978dff46cc") "u3";;
Hashtbl.add hflegend (hexstring_hashval "49a969133c762ca2fac37597b3afdcab1b1e649590cedb91d8374c24cff5d964") "b1";;
Hashtbl.add hflegend (hexstring_hashval "d14a1d88649c33f9ac821da125ac52b76779621e4468a60cfdd77882097ccb51") "b2";;
Hashtbl.add hflegend (hexstring_hashval "43c397cc3acd46d68bad9f005dcf1167643fa534e29f0dadfb13ab62d207edee") "b4";;
Hashtbl.add hflegend (hexstring_hashval "72f91fa0b48423c802285f423fa1dd5444bcb49f91ce5bb7733bd820d29b05f8") "b3";;
Hashtbl.add hflegend (hexstring_hashval "26357d8a95647af6f217eb40b74f66989b0e13e478b6ec103fbdcda0dea97e85") "b5";;
Hashtbl.add hflegend (hexstring_hashval "b6995beb796cca596c8f7e0bbac89cedc45b155245444541cf8cafa49563a7d8") "b6";;
Hashtbl.add hflegend (hexstring_hashval "559ed402fd8d4026a83ca7788b417078c8fa4f6cb6e143c0da08263a5e6da961") "b7";;
Hashtbl.add hflegend (hexstring_hashval "1de91a2c4dd2bb70bb868ea17697f2759797a7fe015e182857a6dc9c8177f513") "b8";;
Hashtbl.add hflegend (hexstring_hashval "b30632159e8f8c891c96e04bed8b9710e011ff925ed20fc322778b2ee79fee36") "b9";;
Hashtbl.add hflegend (hexstring_hashval "1cb8f95949672444aebd6b6575459e4ef9d354fab6e05a84c028eb3221cbd882") "b10";;
Hashtbl.add hflegend (hexstring_hashval "945dc35ae11274f7169fd9214975d15f3f01c1485e62357f1ca40db75444b792") "b11";;
Hashtbl.add hflegend (hexstring_hashval "62b2f8bc5b8a62836e68c32319bffec28a1899cecb4a6f8c2d909628289afa07") "b12";;
Hashtbl.add hflegend (hexstring_hashval "e700a36d664a41da627c21269098b234a43214de13f43685ff74b0a3e5f9d970") "b13";;
Hashtbl.add hflegend (hexstring_hashval "51d44d0786d68737bcd79719d7e6752a660f1bc899610e86464768d6f647a56a") "b14";;
Hashtbl.add hflegend (hexstring_hashval "256a879578243a07024b89741c257175a2ae75b16ed50ec59fc2f790455554c7") "b15";;
Hashtbl.add hflegend (hexstring_hashval "29062050175f5d6d2334c297a9db2143b60d62f4382706549dabaa14f7094022") "b16";;

let hoasprimnamesa = [| "pair"; "bind" |];;
let hoaslegend : (hashval,string) Hashtbl.t = Hashtbl.create 100;;

let egalprimnamesa = [| "Eps_i"; "In"; "Empty"; "Union"; "Power"; "Repl"; "UnivOf" |];;

let mizprimnamesa = [| "the"; "In"; "UPair"; "Union" |];;
let mizlegend : (hashval,string) Hashtbl.t = Hashtbl.create 100;;
Hashtbl.add mizlegend (hexstring_hashval "9018ff5b96ad378f36dab276f58bdc7d8fc18222c596ca3177be08a1acee9d2e") "Power";;
Hashtbl.add mizlegend (hexstring_hashval "80d24834aa9f66bdb9a5e1bbd38abd569c0980b113318e3a60b061de5affc484") "omega";;
Hashtbl.add mizlegend (hexstring_hashval "b8ff52f838d0ff97beb955ee0b26fad79602e1529f8a2854bda0ecd4193a8a3c") "miz_If";;
Hashtbl.add mizlegend (hexstring_hashval "174b78e53fc239e8c2aab4ab5a996a27e3e5741e88070dad186e05fb13f275e5") "the";;
Hashtbl.add mizlegend (hexstring_hashval "f55f90f052decfc17a366f12be0ad237becf63db26be5d163bf4594af99f943a") "UPair";;
Hashtbl.add mizlegend (hexstring_hashval "ee0b09fbfbda76156511ec03a1fc7c909693103f062263776c2c98a655837c92") "Sing";;
Hashtbl.add mizlegend (hexstring_hashval "7491fed394c0760ecce5d4e1df80fe76188bef2528794da082e0223de99066ce") "Empty'";;
Hashtbl.add mizlegend (hexstring_hashval "2ef0dbc560f4aba05346926782e584726ed94e6cc5f65568b80a37ddbfa5d716") "Empty";;
Hashtbl.add mizlegend (hexstring_hashval "35f96b90a9e6ba4d68debc67d325a43189a9073090012db0b4258b69dea9ca6f") "toset";;
Hashtbl.add mizlegend (hexstring_hashval "3041a1cb0e073a46422f794fe16feb7d39d077e3958b5d236feecb2341d4ca6f") "Repl";;
Hashtbl.add mizlegend (hexstring_hashval "bf4f61e2fabe0a1fcc27644aebe41c2c9f551c7841eb70b7ea8aea9ec77c0617") "ReplSep";;
Hashtbl.add mizlegend (hexstring_hashval "dd6eb054d2698e36085f2efc8acc57db2d0c170e482ca8d2a2c46b9a31a9d484") "binintersect";;
Hashtbl.add mizlegend (hexstring_hashval "bdca5215bf0579642a4306b01a0f2340cb539f141f6dcbd4cd5121a880441e10") "toset'";;
Hashtbl.add mizlegend (hexstring_hashval "fea72b9a680f666e24da732d2835c8d83e82d65c993a1597aca84bda2f745970") "Repl'";;
Hashtbl.add mizlegend (hexstring_hashval "8324d6b2a87d5e233d35100511422a76274b918c35d0c1ca109b0c52f6b24d83") "Sep";;
Hashtbl.add mizlegend (hexstring_hashval "7f5ba2b987e7d7cf10ad34e82699aa594573af19f242f0e85c661d42702f3dfd") "ReplSep'";;
Hashtbl.add mizlegend (hexstring_hashval "2ea0d769308e9d70b1f022110cce5a8144bba808781e62f7b5aa03428aa24c01") "ReplSep2";;
Hashtbl.add mizlegend (hexstring_hashval "74c1c1a65001c3d95fa8106e185261aaaa20ee485febbb42517c5b2aa1027534") "ReplSep3";;
Hashtbl.add mizlegend (hexstring_hashval "304e78affb4024981b5c312ecaa5db54d0f381d44cc6b4850ee9f61c765285a5") "ReplSep4";;
Hashtbl.add mizlegend (hexstring_hashval "cc8cc72802470f9fe71a90032c89d059e8f649989d3c134d829630a4e4662ee0") "ReplSep5";;
Hashtbl.add mizlegend (hexstring_hashval "c512d4fc02176acd7ab322b3a38225a539b03467e1d824203de55c70edb7a0de") "ReplSep6";;
Hashtbl.add mizlegend (hexstring_hashval "b753854b84399d9aad5df80ada15b09f8bfe17a2ed354d778c78587c89402572") "ReplSep7";;
Hashtbl.add mizlegend (hexstring_hashval "427f0ef5742440a1124da6fe660e4e6f938faefd3128a4f2808ba54586c9b9b6") "mk_struct";;
Hashtbl.add mizlegend (hexstring_hashval "fdd7cea73081c5804d71aa2eed69ef25c62c22a9cb24cdcba24c59f1a1ead504") "strict_struct_p";;
Hashtbl.add mizlegend (hexstring_hashval "bb1c4bb2e7b5e9ffd2978980d2b27d615cbc8bb8a123decb3fd54fb80dc2fcb9") "Power'";;
Hashtbl.add mizlegend (hexstring_hashval "859e7011bdff89bb687e84e00cdf046122d077684a4e029a72b72931a8ccf2fd") "binunion";;
Hashtbl.add mizlegend (hexstring_hashval "90f614dd739d25d3ef425e964a31a540881f2cf48870dbbd385b87ffbffb0e90") "binintersect";;
Hashtbl.add mizlegend (hexstring_hashval "905e14778dc45ba874b5f3f5f516dc7dcb7b42823b510bde2e8463b6dfba641f") "ordsucc";;
Hashtbl.add mizlegend (hexstring_hashval "54f5b491560ccfc13fb2334a544117bd0f7903fe3f22751e4485e0b838a1016c") "omega'";;
Hashtbl.add mizlegend (hexstring_hashval "502f21ab0254e47362b0daca5e5c363f6666d6df40de65626e202f564a8b6b8d") "TransSet_clos";;
Hashtbl.add mizlegend (hexstring_hashval "e1e47685e70397861382a17f4ecc47d07cdab63beca11b1d0c6d2985d3e2d38b") "inv";;
Hashtbl.add mizlegend (hexstring_hashval "8c8f550868df4fdc93407b979afa60092db4b1bb96087bc3c2f17fadf3f35cbf") "If_i";;
Hashtbl.add mizlegend (hexstring_hashval "a6e81668bfd1db6e6eb6a13bf66094509af176d9d0daccda274aa6582f6dcd7c") "Descr_ii";;
Hashtbl.add mizlegend (hexstring_hashval "dc42f3fe5d0c55512ef81fe5d2ad0ff27c1052a6814b1b27f5a5dcb6d86240bf") "Descr_iii";;
Hashtbl.add mizlegend (hexstring_hashval "9909a953d666fea995cf1ccfe3d98dba3b95210581af4af82ae04f546c4c34a5") "Descr_iio";;
Hashtbl.add mizlegend (hexstring_hashval "322bf09a1711d51a4512e112e1767cb2616a7708dc89d7312c8064cfee6e3315") "Descr_Vo1";;
Hashtbl.add mizlegend (hexstring_hashval "cc8f114cf9f75d4b7c382c62411d262d2241962151177e3b0506480d69962acc") "Descr_Vo2";;
Hashtbl.add mizlegend (hexstring_hashval "e76df3235104afd8b513a92c00d3cc56d71dd961510bf955a508d9c2713c3f29") "If_ii";;
Hashtbl.add mizlegend (hexstring_hashval "53034f33cbed012c3c6db42812d3964f65a258627a765f5bede719198af1d1ca") "If_iii";;
Hashtbl.add mizlegend (hexstring_hashval "33be70138f61ae5ce327b6b29a949448c54f06c2da932a4fcf7d7a0cfc29f72e") "If_Vo1";;
Hashtbl.add mizlegend (hexstring_hashval "216c935441f8678edc47540d419667fe9e5ab01fda1f1afbc64eacaea6a9cbfc") "If_iio";;
Hashtbl.add mizlegend (hexstring_hashval "8117f6db2fb9c820e5905451e109f8ef633101b911baa48945806dc5bf927693") "If_Vo2";;
Hashtbl.add mizlegend (hexstring_hashval "f97da687c51f5a332ff57562bd465232bc70c9165b0afe0a54e6440fc4962a9f") "In_rec_i";;
Hashtbl.add mizlegend (hexstring_hashval "4d137cad40b107eb0fc2c707372525f1279575e6cadb4ebc129108161af3cedb") "In_rec_ii";;
Hashtbl.add mizlegend (hexstring_hashval "222f1b8dcfb0d2e33cc4b232e87cbcdfe5c4a2bdc5326011eb70c6c9aeefa556") "In_rec_iii";;
Hashtbl.add mizlegend (hexstring_hashval "2cb990eb7cf33a7bea142678f254baf1970aa17b7016039b89df7652eff72aba") "In_rec_iio";;
Hashtbl.add mizlegend (hexstring_hashval "45519cf90ff63f7cea32c7ebbbae0922cfc609d577dc157e25e68e131cddf2df") "In_rec_Vo1";;
Hashtbl.add mizlegend (hexstring_hashval "e249fde27e212bc28b301523be2eee37636e29fc084bd9b775cb02f921e2ad7f") "In_rec_Vo2";;
Hashtbl.add mizlegend (hexstring_hashval "5b91106169bd98c177a0ff2754005f1488a83383fc6fc918d8c61f613843cf0f") "If_Vo3";;
Hashtbl.add mizlegend (hexstring_hashval "2e63292920e9c098907a70c431c7555afc9d4d26c8920d41192c83c02196acbe") "Descr_Vo3";;
Hashtbl.add mizlegend (hexstring_hashval "058168fdbe0aa41756ceb986449745cd561e65bf2dd594384cd039169aa7ec90") "In_rec_Vo3";;
Hashtbl.add mizlegend (hexstring_hashval "6dc2e406a4ee93aabecb0252fd45bdf4b390d29b477ecdf9f4656d42c47ed098") "If_Vo4";;
Hashtbl.add mizlegend (hexstring_hashval "28ea4ee0409fe1fc4b4516175b2254cb311b9609fd2a4015768b4a520fe69214") "Descr_Vo4";;
Hashtbl.add mizlegend (hexstring_hashval "65bb4bac5d306fd1707029e38ff3088a6d8ed5aab414f1faf79ba5294ee2d01e") "In_rec_Vo4";;
Hashtbl.add mizlegend (hexstring_hashval "3578b0d6a7b318714bc5ea889c6a38cf27f08eaccfab7edbde3cb7a350cf2d9b") "exactly1of2";;
Hashtbl.add mizlegend (hexstring_hashval "d2a0e4530f6e4a8ef3d5fadfbb12229fa580c2add302f925c85ede027bb4b175") "exactly1of3";;
Hashtbl.add mizlegend (hexstring_hashval "dc4124cb3e699eb9154ce37eaa547c4d08adc8fd41c311d706024418f4f1c8d6") "ZermeloWO";;
Hashtbl.add mizlegend (hexstring_hashval "b37c45ca1b39ef7beb231562b95d8f2008d19d737d0aa5c61951d33806a71055") "famunion";;
Hashtbl.add mizlegend (hexstring_hashval "ab8fa98efe29083fe30a0fab65506354f55a312c53182074393bc5eb5aed1e5d") "setminus";;
Hashtbl.add mizlegend (hexstring_hashval "e4db582992b58a1e96691e3fdeb7a4f0e2e4537c05d49535dca535d4b6fbfea0") "PNo_bd";;
Hashtbl.add mizlegend (hexstring_hashval "0366322107205cee179dc9160736ef0dcbea4f3083f5a3b649fd0e2613455d26") "PNo_pred";;
Hashtbl.add mizlegend (hexstring_hashval "6ef383d5a7cb35543ea97d8dc82d7a31042cc5b5c46d5b7b595e4698bd595edd") "SNo_rec_i";;
Hashtbl.add mizlegend (hexstring_hashval "621bdb08871e5a330c5df471c8ce7da9e0c8c5afca5ef3a2bd60ecaca464b79f") "SNo_rec_ii";;
Hashtbl.add mizlegend (hexstring_hashval "5adf8716eaff9e6c8321bcafd1a9b899940159053310f63d7d7e91d3b47e773c") "SNo_rec2";;
Hashtbl.add mizlegend (hexstring_hashval "81bff9e86e9cf23d200aa5d2dd18b7ce6d2c0f1c3189f4f3aaead447314d80dc") "pack_e";;
Hashtbl.add mizlegend (hexstring_hashval "32918f9589cd95495375a45cd1a0126dc0816663aeb01184c87abd2395d42f70") "unpack_e_i";;
Hashtbl.add mizlegend (hexstring_hashval "d64b764ad19ac93ecb12cd580ba5fa0dd123d9f616850a510f59a45d7a0e0452") "unpack_e_o";;
Hashtbl.add mizlegend (hexstring_hashval "864b625dd5e1221afa0f442857187dc1f0f89c20e305c1d0393c247694208203") "pack_u";;
Hashtbl.add mizlegend (hexstring_hashval "e7ea477592868d1906eb956978d7782b15cac5385f54a9b0be37fcf7c1dbed7e") "unpack_u_i";;
Hashtbl.add mizlegend (hexstring_hashval "21f987cc4b6725533cb934ec669325061fa0dc49828307825a3fa475b9e11f7d") "unpack_u_o";;
Hashtbl.add mizlegend (hexstring_hashval "51ae9a7f5f4dcff068cb2634562b52abc695fafd17015732a82b13afe460251d") "pack_b";;
Hashtbl.add mizlegend (hexstring_hashval "578102c1363550de89ff1c61cb3c5b8c936495697c5f285e6053341f4a782993") "unpack_b_i";;
Hashtbl.add mizlegend (hexstring_hashval "cf16b0122a9be531c7846cd4d6b77594cdb22a2fbbcf066bbf14296994c5ef2b") "unpack_b_o";;
Hashtbl.add mizlegend (hexstring_hashval "9d4d182c3f14abfbb6b1a3d8ff8363585088b756aa9ca252fe66e02383087dbc") "pack_p";;
Hashtbl.add mizlegend (hexstring_hashval "556cb9bacb99f8a0e27bb5c3b331b7e1741388ec87fd081d5b37c894995197f1") "unpack_p_i";;
Hashtbl.add mizlegend (hexstring_hashval "a714fa9fb6b2a1c888b7bd6c477c3640cc07b82537ffa1e6ee1030f33201b4eb") "unpack_p_o";;
Hashtbl.add mizlegend (hexstring_hashval "80f050c82feadd1be16bfbc3da8d4ea2cc65349552892806687e04b05b861f0e") "pack_r";;
Hashtbl.add mizlegend (hexstring_hashval "14d10b881f4c23f85978f5b31625c2f22ec76bd18abcb62a5cd29d5ae3ace598") "unpack_r_i";;
Hashtbl.add mizlegend (hexstring_hashval "92919cdeb9315ce58115e6dac3239b1db2fc46c5878c30776444856213838d56") "unpack_r_o";;
Hashtbl.add mizlegend (hexstring_hashval "56ea1298314bc2fa1c196fcf83840e8ceaa6fb4d2b5a4005c445ac3d49c8897d") "pack_c";;
Hashtbl.add mizlegend (hexstring_hashval "72e48f0f2e2e0291bab12e6f2a9320686efc323232306eb261abec8d73af22a7") "unpack_c_i";;
Hashtbl.add mizlegend (hexstring_hashval "970f250aaca60a4686a01408e371ec6de7c390afc1fdf74d98085e55f40a6a87") "unpack_c_o";;
Hashtbl.add mizlegend (hexstring_hashval "4a59caa11140eabb1b7db2d3493fe76a92b002b3b27e3dfdd313708c6c6ca78f") "NatsP";;
Hashtbl.add mizlegend (hexstring_hashval "b2707c82b8b416a22264d2934d5221d1115ea55732f96cbb6663fbf7e945d3e3") "FieldP";;
Hashtbl.add mizlegend (hexstring_hashval "be660f6f1e37e7325ec2a39529b9c937b61a60f864e85f0dabdf2bddacb0986e") "FieldP_minus";;
Hashtbl.add mizlegend (hexstring_hashval "1195f96dcd143e4b896b4c1eb080d1fb877084debc58a8626d3dcf7a14ce8df7") "OrderedFieldP";;
Hashtbl.add mizlegend (hexstring_hashval "f97b150093ec13f84694e2b8f48becf45e4b6df2b43c1085ae7a99663116b9a6") "natOfOrderedField_p";;
Hashtbl.add mizlegend (hexstring_hashval "82aa95de2af7a7c566e5ddc82fcb83d49c4c7c2ed89187c92e336c3336c4336e") "RealsP";;
Hashtbl.add mizlegend (hexstring_hashval "8d03ffa66c36a375acccc24b9221193d63a739a47abf4c40d0447fb3d4f9dcf3") "ComplexP";;
Hashtbl.add mizlegend (hexstring_hashval "12f05b568c0f56f989dc6a0c5648798ad4485d3e81e8996637959f85a4e60e05") "minus_SNo";;
Hashtbl.add mizlegend (hexstring_hashval "cc4158122f794f7a188c196719c6c4dc8e69cea21aaa898aa886a389ba38744d") "add_SNo";;
Hashtbl.add mizlegend (hexstring_hashval "0ea81ebfa1c27bc09304df458175ee1baa8cd7e5182011b1dd57da69a62c91c0") "mul_SNo";;
Hashtbl.add mizlegend (hexstring_hashval "f81b3934a73154a8595135f10d1564b0719278d3976cc83da7fda60151d770da") "True";;
Hashtbl.add mizlegend (hexstring_hashval "1db7057b60c1ceb81172de1c3ba2207a1a8928e814b31ea13b9525be180f05af") "False";;
Hashtbl.add mizlegend (hexstring_hashval "f30435b6080d786f27e1adaca219d7927ddce994708aacaf4856c5b701fe9fa1") "not";;
Hashtbl.add mizlegend (hexstring_hashval "2ba7d093d496c0f2909a6e2ea3b2e4a943a97740d27d15003a815d25340b379a") "and";;
Hashtbl.add mizlegend (hexstring_hashval "9577468199161470abc0815b6a25e03706a4e61d5e628c203bf1f793606b1153") "or";;
Hashtbl.add mizlegend (hexstring_hashval "98aaaf225067eca7b3f9af03e4905bbbf48fc0ccbe2b4777422caed3e8d4dfb9") "iff";;
Hashtbl.add mizlegend (hexstring_hashval "81c0efe6636cef7bc8041820a3ebc8dc5fa3bc816854d8b7f507e30425fc1cef") "Subq";;
Hashtbl.add mizlegend (hexstring_hashval "ea71e0a1be5437cf5b03cea5fe0e2b3f947897def4697ae7599a73137f27d0ee") "nSubq";;
Hashtbl.add mizlegend (hexstring_hashval "7a075c65ed759cc57c89e2408bcb9ca416a05fbc433cf5204e05ac7c56201261") "KPair";;
Hashtbl.add mizlegend (hexstring_hashval "bbda1ae9bd57abda18ac5533ada1af23ea1500d41d92258309cb7f0385cd2756") "equip";;
Hashtbl.add mizlegend (hexstring_hashval "36808cca33f2b3819497d3a1f10fcc77486a0cddbcb304e44cbf2d818e181c3e") "nIn";;
Hashtbl.add mizlegend (hexstring_hashval "f58a8ecd78b82f5c1e8775b8884794de01262f226039f92120a122e6209fc5f4") "setlike";;
Hashtbl.add mizlegend (hexstring_hashval "103e3fdceef110a6b59ea5a4e36c289ccb5bec8ef0bb80346a27c795149d8f58") "ocs";;
Hashtbl.add mizlegend (hexstring_hashval "b6e4d7339fcaf2bb03f7162518113e0d602c92679e3316b665eeb4015b0b0d4c") "equ_struct";;
Hashtbl.add mizlegend (hexstring_hashval "5adfc97f877949e850303ccf97106d86d5b789a2ef2cf28e8d614e0a469ac80b") "empty";;
Hashtbl.add mizlegend (hexstring_hashval "8a0092f826bb053ae993bc9ef0232ef9b3ff2dcead23a4d3359b62e78979ae3b") "Element_of";;
Hashtbl.add mizlegend (hexstring_hashval "538bb76a522dc0736106c2b620bfc2d628d5ec8a27fe62fc505e3a0cdb60a5a2") "TransSet";;
Hashtbl.add mizlegend (hexstring_hashval "ee28d96500ca4c012f9306ed26fad3b20524e7a89f9ac3210c88be4e6a7aed23") "ordinal";;
Hashtbl.add mizlegend (hexstring_hashval "c4281e0db17259b1601ca9cea224e015831e08edc7d4ec67ef057d564c2b4c4d") "nat_p";;
Hashtbl.add mizlegend (hexstring_hashval "802b4141ffaf64ea3f1527fa60bc0c380bbe11046f5013a17627d74914165841") "Union_nat_reln";;
Hashtbl.add mizlegend (hexstring_hashval "76bef6a46d22f680befbd3f5ca179f517fb6d2798abc5cd2ebbbc8753d137948") "bij";;
Hashtbl.add mizlegend (hexstring_hashval "615c0ac7fca2b62596ed34285f29a77b39225d1deed75d43b7ae87c33ba37083") "bigintersect";;
Hashtbl.add mizlegend (hexstring_hashval "6a6dea288859e3f6bb58a32cace37ed96c35bdf6b0275b74982b243122972933") "reflexive";;
Hashtbl.add mizlegend (hexstring_hashval "e2ea25bb1daaa6f56c9574c322ff417600093f1fea156f5efdcbe4a9b87e9dcf") "irreflexive";;
Hashtbl.add mizlegend (hexstring_hashval "309408a91949b0fa15f2c3f34cdd5ff57cd98bb5f49b64e42eb97b4bf1ab623b") "symmetric";;
Hashtbl.add mizlegend (hexstring_hashval "9a8a2beac3ecd759aebd5e91d3859dec6be35a41ec07f9aba583fb9c33b40fbe") "antisymmetric";;
Hashtbl.add mizlegend (hexstring_hashval "b145249bb4b36907159289e3a9066e31e94dfa5bb943fc63ff6d6ca9abab9e02") "transitive";;
Hashtbl.add mizlegend (hexstring_hashval "25d55803878b7ce4c199607568d5250ff00ee63629e243e2a1fd20966a3ee92c") "eqreln";;
Hashtbl.add mizlegend (hexstring_hashval "5754c55c5ad43b5eaeb1fb67971026c82f41fd52267a380d6f2bb8487e4e959b") "per";;
Hashtbl.add mizlegend (hexstring_hashval "9db35ff1491b528184e71402ab4646334daef44c462a5c04ab2c952037a84f3f") "linear";;
Hashtbl.add mizlegend (hexstring_hashval "cc2c175bc9d6b3633a1f1084c35556110b83d269ebee07a3df3f71e3af4f8338") "trichotomous_or";;
Hashtbl.add mizlegend (hexstring_hashval "406b89b059127ed670c6985bd5f9a204a2d3bc3bdc624694c06119811f439421") "partialorder";;
Hashtbl.add mizlegend (hexstring_hashval "0e5ab00c10f017772d0d2cc2208e71a537fa4599590204be721685b72b5d213f") "totalorder";;
Hashtbl.add mizlegend (hexstring_hashval "ee5d8d94a19e756967ad78f3921cd249bb4aefc510ede4b798f8aa02c5087dfa") "strictpartialorder";;
Hashtbl.add mizlegend (hexstring_hashval "42a3bcd22900658b0ec7c4bbc765649ccf2b1b5641760fc62cf8a6a6220cbc47") "stricttotalorder";;
Hashtbl.add mizlegend (hexstring_hashval "71bff9a6ef1b13bbb1d24f9665cde6df41325f634491be19e3910bc2e308fa29") "reflclos";;
Hashtbl.add mizlegend (hexstring_hashval "e5853602d8dd42d777476c1c7de48c7bfc9c98bfa80a1e39744021305a32f462") "ZermeloWOstrict";;
Hashtbl.add mizlegend (hexstring_hashval "e6bbd7cbc84b9785792b40d9c0813a8bf15c7ec4265316ecce40981ed0df0049") "SetAdjoin";;
Hashtbl.add mizlegend (hexstring_hashval "3be1c5f3e403e02caebeaf6a2b30d019be74b996581a62908316c01702a459df") "nat_primrec";;
Hashtbl.add mizlegend (hexstring_hashval "d7158bc94e7dec2854598d6404ce27f85dc5b8f1c8c40e34392db63bb52fe67c") "add_nat";;
Hashtbl.add mizlegend (hexstring_hashval "c723c7f4596c1c10adf0dc53219d228a75bfe10710eca1be45175bc20e8b3ad3") "mul_nat";;
Hashtbl.add mizlegend (hexstring_hashval "a1aabb874779a8ea4da9c718a39596b071ad762b3be209af5a16c9d0e64fd666") "Inj1";;
Hashtbl.add mizlegend (hexstring_hashval "4c80c4fdb74216b058b0462eaac5ec3c45e1f41cc715e7b9ae9fa0d544f4c694") "Inj0";;
Hashtbl.add mizlegend (hexstring_hashval "5b0210832e4fc3df53e5d17f5bfbe0994424666ae5b8c807cfa2d9e2a9940dfa") "Unj";;
Hashtbl.add mizlegend (hexstring_hashval "3d3c80a6b9afb8d2e7c183ab6fa60ff99ed1d7042b1d115d04570a6e468f38ca") "setsum";;
Hashtbl.add mizlegend (hexstring_hashval "ea4bb82c84472d1640bd899c73e577f4f78a4814467eaef0d715f5ad1fff7127") "combine_funcs";;
Hashtbl.add mizlegend (hexstring_hashval "5656d632dabc070d4470680108581c457c772b89911f6be1ddc80b7c80ee4daf") "proj0";;
Hashtbl.add mizlegend (hexstring_hashval "589fdc943bbc23971b7e7136d4c66058dbbf089d48e19ab8efd3287917476c2b") "proj1";;
Hashtbl.add mizlegend (hexstring_hashval "f01798c6fd1f6c623c7614d5fc2327ec574132342740fedf7acd902bec5fe7e7") "Sigma";;
Hashtbl.add mizlegend (hexstring_hashval "cd5ebea2b179757ab4562caaa90f57f411338c43bb3a87d206c27c602fac8b6d") "setprod";;
Hashtbl.add mizlegend (hexstring_hashval "03db16cc9a6872669b42bad25bc47241eb3229b803ddbbb64fe5fc41c508c3af") "ap";;
Hashtbl.add mizlegend (hexstring_hashval "ddd00f55060947e95b73ad985e6fafce1d7f9892b1721f61d0481f18d1a28c7a") "pair_p";;
Hashtbl.add mizlegend (hexstring_hashval "937fe75e110c88cf364eb7f21fe808f8c1f1f40c5b977ea4c6d297cc1c9251f2") "tuple_p";;
Hashtbl.add mizlegend (hexstring_hashval "eca70658775ddb87705bdcfdbe538d1c7f5827d3079170e0157b5ded26ad0a9c") "Pi";;
Hashtbl.add mizlegend (hexstring_hashval "c045b96c0e4613bdc87922cab68e9bad8eb0fdfa8970d381269f29e438e11fda") "setexp";;
Hashtbl.add mizlegend (hexstring_hashval "ba4a218bbcb4862e3c20999bf13eb3cb654b764e9b480a9ba7e0b0312e500736") "Sep2";;
Hashtbl.add mizlegend (hexstring_hashval "74625969ea0457f6e5a8f8e5e3128d917ceb4d6415db4ba5934d29903999a9a3") "set_of_pairs";;
Hashtbl.add mizlegend (hexstring_hashval "2e184eb7c814565a44364cafff4ab4f4c9ed5a49467beb4d792aaf75b13b8cef") "lam2";;
Hashtbl.add mizlegend (hexstring_hashval "f01798c6fd1f6c623c7614d5fc2327ec574132342740fedf7acd902bec5fe7e7") "encode_u";;
Hashtbl.add mizlegend (hexstring_hashval "03db16cc9a6872669b42bad25bc47241eb3229b803ddbbb64fe5fc41c508c3af") "decode_u";;
Hashtbl.add mizlegend (hexstring_hashval "efd72b0014f9230b21c06c05b68845dc02c1db2ef7047bb30fb084f8c5eb3e88") "encode_b";;
Hashtbl.add mizlegend (hexstring_hashval "6571a39e7bd829426999e4ed027887be8b45762bf7ebd95ce3f3510fae5928f0") "decode_b";;
Hashtbl.add mizlegend (hexstring_hashval "da98b582b06ed7e84a25bdac946c6310e931cc500e9c18c33b40a7d20304e6f9") "encode_p";;
Hashtbl.add mizlegend (hexstring_hashval "02231a320843b92b212e53844c7e20e84a5114f2609e0ccf1fe173603ec3af98") "decode_p";;
Hashtbl.add mizlegend (hexstring_hashval "b439438860718edd83a6b5f5110848c9e9a8ff21a3fe5b693d5e12231ef073ce") "encode_r";;
Hashtbl.add mizlegend (hexstring_hashval "2cc21f2b2eb80215fe9d0c1445e5bab8f21d0b1a930f1d9052f9e8933c284d4f") "decode_r";;
Hashtbl.add mizlegend (hexstring_hashval "879a511924b042356f7d6bae9742392d0245c6bd9d02284aff1e6337b9f2353c") "encode_c";;
Hashtbl.add mizlegend (hexstring_hashval "47a1eff65bbadf7400d8f2532141a437990ed7a8581fea1db023c7edd06be32c") "decode_c";;
Hashtbl.add mizlegend (hexstring_hashval "20c61c861cf1a0ec40aa6c975b43cd41a1479be2503a10765e97a8492374fbb0") "EpsR_i_i_1";;
Hashtbl.add mizlegend (hexstring_hashval "eced574473e7bc0629a71e0b88779fd6c752d24e0ef24f1e40d37c12fedf400a") "EpsR_i_i_2";;
Hashtbl.add mizlegend (hexstring_hashval "1d3fd4a14ef05bd43f5c147d7966cf05fd2fed808eea94f56380454b9a6044b2") "DescrR_i_io_1";;
Hashtbl.add mizlegend (hexstring_hashval "768eb2ad186988375e6055394e36e90c81323954b8a44eb08816fb7a84db2272") "DescrR_i_io_2";;
Hashtbl.add mizlegend (hexstring_hashval "d7d95919a06c44c69c724884cd5a474ea8f909ef85aae19ffe4a0ce816fa65fd") "PNoEq_";;
Hashtbl.add mizlegend (hexstring_hashval "34de6890338f9d9b31248bc435dc2a49c6bfcd181e0b5e3a42fbb5ad769ab00d") "PNoLt_";;
Hashtbl.add mizlegend (hexstring_hashval "3f3b0daff21825ab64a155fcbcbd009cb91c1cd517735d92ce0cd3d7f6d4fc4a") "PNoLt";;
Hashtbl.add mizlegend (hexstring_hashval "921c61c5fd9c6dd60dc57bd33115b794b22bd2c869fa2424b2c28b6906062a51") "PNoLe";;
Hashtbl.add mizlegend (hexstring_hashval "1205d652201d31efccb8bde983da1e463890717c93feebf6d4bcf2126c5ba5ef") "PNo_downc";;
Hashtbl.add mizlegend (hexstring_hashval "420e937512f3ee6241d565b8e0d97c3ad79766f4b28c549677f2c06ba8acdb73") "PNo_upc";;
Hashtbl.add mizlegend (hexstring_hashval "c244266e38a0520b4930b79b6ac8ed36914e96cd2cb1b91d0a4f62df8e2b41cf") "PNoLt_pwise";;
Hashtbl.add mizlegend (hexstring_hashval "3fea203371cb3b7bd0d875c42bfbb50c53f9cd32b6931d28c981fa01cd91839b") "PNo_rel_strict_upperbd";;
Hashtbl.add mizlegend (hexstring_hashval "bb7495d5ae728bb2f01c1a99f52f8ffa876c6fb6e9afff87e6ea9507fb5c29cc") "PNo_rel_strict_lowerbd";;
Hashtbl.add mizlegend (hexstring_hashval "94d70ad3facb6c3c68054b9fe2ce17dbbde7f53493a3cb46fa1c249673c83c85") "PNo_rel_strict_imv";;
Hashtbl.add mizlegend (hexstring_hashval "94e5f53cfbc063b09032c32d05d8177f546c9282fc63ad169c9a99d8be938bac") "PNo_rel_strict_uniq_imv";;
Hashtbl.add mizlegend (hexstring_hashval "a289c496e4b7b7b4a982fb5f2ab82db1821207e84204582555cb339fe047f7ba") "PNo_rel_strict_split_imv";;
Hashtbl.add mizlegend (hexstring_hashval "009fa745aa118f0d9b24ab4efbc4dc3a4560082e0d975fd74526e3c4d6d1511f") "PNo_lenbdd";;
Hashtbl.add mizlegend (hexstring_hashval "697eeff8ff015da7260b2799e821a356c27c8a1e3a3733279ca83c5378817f54") "PNo_strict_upperbd";;
Hashtbl.add mizlegend (hexstring_hashval "0e0c43d3b8ad2f9b3b39e8e307cf7e640b6fd297297b01fe527be78819a71369") "PNo_strict_lowerbd";;
Hashtbl.add mizlegend (hexstring_hashval "fbba9ec3b07ac802b32aa0ac04958171e2871cbea611988e06b6d34ab8fec792") "PNo_strict_imv";;
Hashtbl.add mizlegend (hexstring_hashval "4dcb7e8221003367a29c5474960200afa4f9c2ebecc01780ec304ddf72a16214") "PNo_least_rep";;
Hashtbl.add mizlegend (hexstring_hashval "a6ed3a6d70ea409ef40ec4f9989a6cd242e17e4f0492ca6aef8e7bb021cdcd90") "PNo_least_rep2";;
Hashtbl.add mizlegend (hexstring_hashval "8cea2fe64392ef2aad5ad762df9a13e7c190aedc35917de3dc42367db9a1dbb0") "PNoCutL";;
Hashtbl.add mizlegend (hexstring_hashval "7f2c9ed8ad091a01f5539b8f5d472ea37aa226e03a514de449a2daf2460ff760") "PNoCutR";;
Hashtbl.add mizlegend (hexstring_hashval "8d19eabadc2e8075f248b81f3de0821a70b4b8d42503aac725dae84680d622af") "SNoElts_";;
Hashtbl.add mizlegend (hexstring_hashval "3284eaa7302bd4aeb407b0e0118426807b5880f771ed3f91ae5d3e43eebc5276") "SNo_";;
Hashtbl.add mizlegend (hexstring_hashval "e2cefcf66e1f34aa4b196bcfe688c77ba428094e81104418e2afea96abab709f") "PSNo";;
Hashtbl.add mizlegend (hexstring_hashval "48e40dd533c67da9735cdd527220fb9c62b4c26e2a8c711aebdb5fab99cb84a0") "SNo";;
Hashtbl.add mizlegend (hexstring_hashval "609fe5eb724e259a487d97e86fd72fb18e63a4a0917f9edfdb40c2dfaa4ecb3d") "SNoLev";;
Hashtbl.add mizlegend (hexstring_hashval "5f11e279df04942220c983366e2a199b437dc705dac74495e76bc3123778dd86") "SNoEq_";;
Hashtbl.add mizlegend (hexstring_hashval "b6a57cff8a9eaea05441f13e52d80c3f594d0f551c82a77a1164ad79009cd856") "SNo_pair";;
Hashtbl.add mizlegend (hexstring_hashval "d65fc70321bf6fa4d97673af4fa271574a94af7301e8e0965af85fb0d22b30ff") "SNoLt";;
Hashtbl.add mizlegend (hexstring_hashval "769093acd4f97fa4dd94919d356d27db1d300af833adc38efad2c51e264676d1") "SNoLe";;
Hashtbl.add mizlegend (hexstring_hashval "3fe3f477f681c8492089d7b561bf40b0f7dc23a06db9d96530bce71259b519c4") "SNoCut";;
Hashtbl.add mizlegend (hexstring_hashval "dd8c009880f90196e4b562c0d497bc96e335ab2dbf1ed9e1b6d8599502af86bb") "SNoCutP";;
Hashtbl.add mizlegend (hexstring_hashval "11f9855449f3f1a56ed1c7a86b3f2678951a6cff4ddccaaa43286a7165da939b") "SNoS_";;
Hashtbl.add mizlegend (hexstring_hashval "4daa400ebfe98cab0aef587b3849cce8e91ca839c88bc5f67c8bfe0b49bb1ad8") "SNoL";;
Hashtbl.add mizlegend (hexstring_hashval "4c926e10b2a60623c1dddddb8653bf02edd5e224d4108e4d33d82e1365ab3070") "SNoR";;
Hashtbl.add mizlegend (hexstring_hashval "1cac1addd141821ed55a4347a527182e9f2f2c80a69111b0753285c97910f8a6") "SNo_extend0";;
Hashtbl.add mizlegend (hexstring_hashval "485b1d1c51c729c134acc2970483c89e9b29d8f3583d1546ae9b38a461501d73") "SNo_extend1";;
Hashtbl.add mizlegend (hexstring_hashval "4cb762c0089c09c210031b6d1db01f9b7880d95a8ce93a6499104439430715d0") "struct_e";;
Hashtbl.add mizlegend (hexstring_hashval "4d32c7cd9f49d3fd55e844f8618d77ebf9199dff7e8137f266326827cd0e95f1") "struct_u";;
Hashtbl.add mizlegend (hexstring_hashval "583be38d326f2592e303ca0639d30fe2d0a35ef979e831c3db053b14c036bea9") "struct_b";;
Hashtbl.add mizlegend (hexstring_hashval "fc47a40a67ced784f89b19c00b9ed9ef9ea5d651668077b7470a2781ddf2d72b") "struct_p";;
Hashtbl.add mizlegend (hexstring_hashval "6e0110c837e15c22f0fcca8225da7bc67cd0046a5a418ed093c3b2a5d57388ba") "struct_r";;
Hashtbl.add mizlegend (hexstring_hashval "36891be37ef814bb7887e47fdb9bb40d933731fd7fd0912a9b36c422b62544a0") "struct_c";;
Hashtbl.add mizlegend (hexstring_hashval "d326e5351e117c7374d055c5289934dc3a6e79d66ed68f1c6e23297feea0148e") "lt";;
Hashtbl.add mizlegend (hexstring_hashval "6f914051244cea0c90d08d02e3a232598c11ce2ecbc5ce21f99c3bccac3e3d53") "div_SNo";;
Hashtbl.add mizlegend (hexstring_hashval "8d0a0b96e88ef4275c1ff3c1e8e10e031c4d6e2d90436d00acb2c7702796cd5a") "real";;
Hashtbl.add mizlegend (hexstring_hashval "c45aef588990b86ed7ab87db9df9bb9b18565f39f71add4f5e9baeeb53e09ab6") "CSNo";;
Hashtbl.add mizlegend (hexstring_hashval "025b7a2a1ddb67d3556d5a83efe2a90d5b881445b441dc0247ec605dfd6f927e") "Complex_i";;
Hashtbl.add mizlegend (hexstring_hashval "c83febc64753a408432806a1a7d32a539ffbbeff7680350a33dfe8d6331f7389") "CSNo_Re";;
Hashtbl.add mizlegend (hexstring_hashval "a231d8c4a73f28ec6032139b845f5af0bb9c9d4948ae07bcce8826f8bd03fe53") "CSNo_Im";;
Hashtbl.add mizlegend (hexstring_hashval "8a6ab18ea24b3c5d648fd1078a11ec38f1153862d2020d1aa54d587fca9589d7") "minus_CSNo";;
Hashtbl.add mizlegend (hexstring_hashval "06b1142cd53fe4475d171b27073b6cc7dc563e0532a6c67a58f7240db58a54bd") "add_CSNo";;
Hashtbl.add mizlegend (hexstring_hashval "0d31de70f222ca39f1d1c336d40ab195bd6c42fbab3152d81ea39c12d85436d6") "mul_CSNo";;
Hashtbl.add mizlegend (hexstring_hashval "f008f3584f9d4cd2be2dc08f1f40558adb0fa332178f3cc1e8147ba512867a6d") "div_CSNo";;
Hashtbl.add mizlegend (hexstring_hashval "b88ac30b5173dd9c7db378849e848e02593235aa57396fe45241b49cb5a1c1d0") "complex";;
Hashtbl.add mizlegend (hexstring_hashval "c1a599e9b12c65adc32d61572ba25ca64437b2acc10abb630b0ef79ca11319a1") "int";;
Hashtbl.add mizlegend (hexstring_hashval "d18e4c87f2f4dc381eb449e2bfcd69b8492dcdefa0f52064c496ea443236999d") "rat";;
Hashtbl.add mizlegend (hexstring_hashval "3fb69ddeda4015beaf7f7c87c8a3bd6baa90e5f67f3f933189267f3c3edd9c19") "Sum";;
Hashtbl.add mizlegend (hexstring_hashval "ea2cd1c82a42f92be4a1311abe4320310ddc2b2d1a133b45c122af9136ee960a") "Prod";;
Hashtbl.add mizlegend (hexstring_hashval "19043aec9cd19235befab2698aecb56ec899722f50cbe2d51d3738ba20ab5fc3") "ordsucc";;
Hashtbl.add mizlegend (hexstring_hashval "3828378f54d092a4eb3a7645cd8c22019202c50241d1dbee65a720f73be8d9ed") "binunion";;
Hashtbl.add mizlegend (hexstring_hashval "ec9394dc0cd84355682ca93f9e80c8aa367ef9c3479874f5f04da125c87db1f1") "Sing";;

Hashtbl.add hoaslegend (hexstring_hashval "d58762d200971dcc7f1850726d9f2328403127deeba124fc3ba2d2d9f7c3cb8c") "pair";;
Hashtbl.add hoaslegend (hexstring_hashval "73c9efe869770ab42f7cde0b33fe26bbc3e2bd157dad141c0c27d1e7348d60f5") "bind";;
Hashtbl.add hoaslegend (hexstring_hashval "12416cbd3669c203e78de2e86a20ada61c922789c8b0237c9a44fabd6648ded6") "ap";;
Hashtbl.add hoaslegend (hexstring_hashval "a5d296b1e9e06c7ce81fcf9551752dcf1df3e65ad5e6a154d9482cff66b213c3") "lam";;
Hashtbl.add hoaslegend (hexstring_hashval "99150b81e4a521b80c18c89ac070eaec0950a5681bfb2763ccd9242a0c494577") "ulamp";;
Hashtbl.add hoaslegend (hexstring_hashval "a06c3e3ad02db2033bcc67daa01f79353685d1074364878aafd74fa6356432b0") "beta1";;
Hashtbl.add hoaslegend (hexstring_hashval "8d3ae485028a6bdfde787a7a897017c9ddbafb3aada7665217f4796334322029") "betared";;
Hashtbl.add hoaslegend (hexstring_hashval "2d3cc68944e13d8dcc308c927df8692e96bafd5416e6b56b8917501586ae2e68") "eqclos";;
Hashtbl.add hoaslegend (hexstring_hashval "41f06e3729cccfa7b02732f0543b15de35e8bb683487b9bd533284224f75d4ab") "betaeq";;
Hashtbl.add hoaslegend (hexstring_hashval "1db7057b60c1ceb81172de1c3ba2207a1a8928e814b31ea13b9525be180f05af") "False";;
Hashtbl.add hoaslegend (hexstring_hashval "f81b3934a73154a8595135f10d1564b0719278d3976cc83da7fda60151d770da") "True";;
Hashtbl.add hoaslegend (hexstring_hashval "f30435b6080d786f27e1adaca219d7927ddce994708aacaf4856c5b701fe9fa1") "not";;
Hashtbl.add hoaslegend (hexstring_hashval "2ba7d093d496c0f2909a6e2ea3b2e4a943a97740d27d15003a815d25340b379a") "and";;
Hashtbl.add hoaslegend (hexstring_hashval "9577468199161470abc0815b6a25e03706a4e61d5e628c203bf1f793606b1153") "or";;
Hashtbl.add hoaslegend (hexstring_hashval "98aaaf225067eca7b3f9af03e4905bbbf48fc0ccbe2b4777422caed3e8d4dfb9") "iff";;
Hashtbl.add hoaslegend (hexstring_hashval "9df9f5874fbda4a771917dc812185b9572b721f68696ce3f4f0bf21fff135a93") "emp";;
Hashtbl.add hoaslegend (hexstring_hashval "94ef3ac3ae73a819629a12fd3ed2ddf579e696faedd154679d87de8af45377f0") "adj";;
Hashtbl.add hoaslegend (hexstring_hashval "aab3e75b2d33c16ff408635d0e3e6a326e222a5d56e2bdeebc2b93e37ee6d49c") "nil";;
Hashtbl.add hoaslegend (hexstring_hashval "c33c21a7a47248ea46536481bb638c9cf11ca20924ba7e32a9483a5beac21d0d") "transclos";;
Hashtbl.add hoaslegend (hexstring_hashval "881089a9834dbc0832897c0b4c62c7d2ea1bdbebe9fa270d6615289e02711eb4") "iden";;
Hashtbl.add hoaslegend (hexstring_hashval "b00c69416be698cd384463bf2b4ab83e77ed1a5dfebb0f2d752b0935df460e7d") "comp";;
Hashtbl.add hoaslegend (hexstring_hashval "b182add419efc7133ea1ebd4414b57632d09ce950dd6d18196007601f96db9bd") "one";;
Hashtbl.add hoaslegend (hexstring_hashval "eab9f38281fc2906a5455a8b6e0d63fad2e08eb8f22db66ce0186750b78a214f") "sum";;
Hashtbl.add hoaslegend (hexstring_hashval "b75815b1b06935852710f3a0d2d2bf61c58754a7f634c11204e1aa107bf6ad3e") "prod";;
Hashtbl.add hoaslegend (hexstring_hashval "1c80e83dda8c01cf526caa672bf35e0698d264d6364f56fc252670bc1360b542") "unit";;
Hashtbl.add hoaslegend (hexstring_hashval "e794fda5a43783fe1fbb6cd13fbd7e9e7f0be7f4266719ef548ddb26d7009673") "injl";;
Hashtbl.add hoaslegend (hexstring_hashval "78b5030c8c07834f3b79a2257b443ba585e2fbd479f00461068277548e6e7433") "injr";;
Hashtbl.add hoaslegend (hexstring_hashval "6e2107d6467a85a4433ef53fad80121d25ec88ddcfc1b10394823addd2231383") "case";;
Hashtbl.add hoaslegend (hexstring_hashval "41d0f5f1610559debaae713e07b8bb2a6ea173c33eed7115c51be93791f157e5") "spair";;
Hashtbl.add hoaslegend (hexstring_hashval "4983a751de6fd4a1b6e58b8a1ca81b1f630f17eac890f1f697402b9d213c4c47") "take";;
Hashtbl.add hoaslegend (hexstring_hashval "848d465e2f6228909168aadfe8dbea2dbf3644770d9865e50b236896765cc0d9") "drop";;
Hashtbl.add hoaslegend (hexstring_hashval "e274df1fd3a0e9723a6450ef21325b004d60f30f1785499c044dc25ed84e181f") "type_p";;
Hashtbl.add hoaslegend (hexstring_hashval "fdbc8bfd03e70ac1344aa0700d1ee3e17b26424d044bccc22d432e59b518e5e8") "term_p";;
Hashtbl.add hoaslegend (hexstring_hashval "7fece3e55c722eff30bb1a1978e838c234ac7f8a42ad8ee641ef97ac1ae869a8") "of";;

let mgifthenelse : (hashval,unit) Hashtbl.t = Hashtbl.create 1;;
let mgbinder : (hashval,string) Hashtbl.t = Hashtbl.create 100;;
let mgprefixop : (hashval,string) Hashtbl.t = Hashtbl.create 100;;
let mgpostfixop : (hashval,string) Hashtbl.t = Hashtbl.create 100;;
let mginfixop : (hashval,string) Hashtbl.t = Hashtbl.create 100;;
let mgimplop : (hashval,unit) Hashtbl.t = Hashtbl.create 100;;

let mglegendt : (hashval,string) Hashtbl.t = Hashtbl.create 100;;
let mglegend : (hashval,string) Hashtbl.t = Hashtbl.create 100;;
let mglegendp : (hashval,string) Hashtbl.t = Hashtbl.create 100;;

let mgrootassoc : (hashval,hashval) Hashtbl.t = Hashtbl.create 100;;
Hashtbl.add mgrootassoc (hexstring_hashval "c8ed7d3ad63a4a29ebc88ac0ccb02bfd5f4c0141eebc8a7a349ed7115a3a3eb9") (hexstring_hashval "be3dc11d683b255bfbd9127adb3c6087d074a17cb0e31c91d602b5ae49893e97");;
Hashtbl.add mgrootassoc (hexstring_hashval "cf0ad1ee32827718afb13bd3eaf6f0a23dac224e237a5287cf6770bed71314d0") (hexstring_hashval "8a2958081ef9384f7ae14223d1b2eae8a7b40e054a6e8404700b3282c5cc73fc");;
Hashtbl.add mgrootassoc (hexstring_hashval "e8b6c46a7320708ff26c3ecf5b9d4028cd895a2df98bc04c5a259452e7b00b34") (hexstring_hashval "cecdcdbb34d99cbd63719b23fce489fa60013beaacbc82f82b45e1606f0d1426");;
Hashtbl.add mgrootassoc (hexstring_hashval "86f6b28b2b2a1b90a5036bb57cb5f553f82ab78abb048d7e2522f53d81acbd88") (hexstring_hashval "61615bbcd83cd6e76a996b08056ac5bd3cd58b6c5b586478d704bf0537a4748b");;
Hashtbl.add mgrootassoc (hexstring_hashval "5464b7e71f123afa197a52bc970117045fff5b6a90742c9eb1ff74c34f0e0c2d") (hexstring_hashval "53c61dca9054178c8513437f9e74d9f9b4b0aa10fad14313f0e9d976581ab872");;
Hashtbl.add mgrootassoc (hexstring_hashval "4a4f5564e1f9c7fb2b12e56a1864cd6c43fcc91411a6f3721b647c2151d1c48b") (hexstring_hashval "6c4402a34385d781c71500d4dd7eadd33a08d4201d17fb8cd84f5eee15ec3916");;
Hashtbl.add mgrootassoc (hexstring_hashval "9375f3488fbda29540c9e42afd4900f9ea67af8ac1d360ef40205b31d0145793") (hexstring_hashval "5859b297cb5cc9c269636d4463f6eea002362fffb3ed217d560882b1ce2791b0");;
Hashtbl.add mgrootassoc (hexstring_hashval "4f4f678745170f14dee4f914c2e70b43bebb6c676dbb189a06f00b0656946a6c") (hexstring_hashval "059f268a2c9da5fcca9461e81c6b5b4f04b6ac0fbd1a18078ddbe8af58a60832");;
Hashtbl.add mgrootassoc (hexstring_hashval "47feaf65da0fb35ed52a3e646f9231ac1476c38f0e91d79850d45e8cc7580520") (hexstring_hashval "79c5894fa21b27f3c49563792759dd6d0087c766e76688ed47d170a9518ddfe0");;
Hashtbl.add mgrootassoc (hexstring_hashval "9dfc2adb8ff80515a79ba1b90379bbd0cea718993442413b2cb120bb9bf2d4fe") (hexstring_hashval "c0f03c208aec64069e4148d3c2de0500d5aa1784cfb14b2ca8b0b012e330b7dd");;
Hashtbl.add mgrootassoc (hexstring_hashval "9579111144263dda4d1a69686bd1cd9e0ef4ffaecf2b279cf431d0a9e36f67ab") (hexstring_hashval "96edb4f2610efd412654278db08e16550670a674fc2dc2b8ce6e73dcc46bbeab");;
Hashtbl.add mgrootassoc (hexstring_hashval "5d0201189805d03fc856c2fa62f35171b88a531f7deeee6199625094c02eddd7") (hexstring_hashval "44ed079d6a65865657792e1cc515b76a1121cfdc9af8f6c21f8cc848fa700837");;
Hashtbl.add mgrootassoc (hexstring_hashval "d6f688b87f520e20f883436520c684182d8140f8ad0fdc595e075122f758500e") (hexstring_hashval "e62fb376978eab6f3a437ccbcbf7db7e720c6d825a9ac34a47cc1290a4483e8a");;
Hashtbl.add mgrootassoc (hexstring_hashval "e815783558526a66c8f279c485040d57663745bc5f9348b1ebc671af74c2a305") (hexstring_hashval "a84fd92c3d7f64da963df3dac4615300170cb17ff896ccef2f8dd00066ec3d02");;
Hashtbl.add mgrootassoc (hexstring_hashval "acf0f04c6a55a143e3ed8404c0fa6b09b323d938c83532f081b47091e31c4eb3") (hexstring_hashval "352304ebb6c77dbc4e2a952e767857a98538e43de1c35fb4bcd6c99fca02ae7e");;
Hashtbl.add mgrootassoc (hexstring_hashval "8085cf0170b86729cab30e095b013215757a3930981428ca9b33ed00255b3e5b") (hexstring_hashval "dd69f4b569545c4beb1b440df404a181508406955eb862b17b28cf09de44afcf");;
Hashtbl.add mgrootassoc (hexstring_hashval "21bb26399802c128b4a27a6184c81e80a2bb391015d712920b939216289ef0b6") (hexstring_hashval "22f45af3c10db238bb5d9aa702e24179a9c1a79a5635eeec0be511465bc55bf4");;
Hashtbl.add mgrootassoc (hexstring_hashval "c122725011fe4f3c33a788d8c61749ddad5e2b721eb2d0d6a40087e7cc070520") (hexstring_hashval "cb2fbaf509f40d85b77e5e2f5591d9b013ddca260991b95e6744f8c8b5ab29c5");;
Hashtbl.add mgrootassoc (hexstring_hashval "d45c1fe6a3dff7795ce0a3b891aea8946efc8dceebae3c8b8977b41878b0e841") (hexstring_hashval "368935f3a5f424f35961c43f39985442e0a4fe403f656e92d8a87b20af68c0d7");;
Hashtbl.add mgrootassoc (hexstring_hashval "a11d43d40b40be26b4beae6694eb8d4748ce3fc4c449b32515fa45b747927e92") (hexstring_hashval "e28a50fa106e9771b4a531f323fb606ae0f38ca80387125677a2ce0395e064ba");;
Hashtbl.add mgrootassoc (hexstring_hashval "070862b0ccc9135ae23bdde1c11a01e0c0b72cd75efa4d430a1d263e3fdee115") (hexstring_hashval "65a74ed591a17d2a6a3d7082efcf2dcf55e00b35c38c988bf0c3bcef7417c289");;
Hashtbl.add mgrootassoc (hexstring_hashval "d75651ef535ae407614897001d784e4b70fa69476f5658eb076b9a809fe4d3d5") (hexstring_hashval "418c446fce2262b8d8aa01b8290d603fce77ec2af134e5730ce3fa40bfc92ff1");;
Hashtbl.add mgrootassoc (hexstring_hashval "a7ed72144cefda0957baa33b821766b4dfe468731094cdca6edcf0a9613fc7c8") (hexstring_hashval "469fedb3c0890bbe6f1968a679e8940fd80553c3929ed17a6b7130c588aa8e13");;
Hashtbl.add mgrootassoc (hexstring_hashval "4f2499da40ea8dc632e09e9b02458d9b4815b33cd62e821fb48a89bbf313a247") (hexstring_hashval "18bf6135f63a7e75bcc2c737fad485290a9696ac94bd59032138e192ab092b03");;
Hashtbl.add mgrootassoc (hexstring_hashval "fdae77d1a5079ae1a09aaeb23343f4bd6081907e9fe81a573b7244a35af0d909") (hexstring_hashval "e188a394359450645dfdce85a0b30e951da4f945117188395c3ab12bb228e33d");;
Hashtbl.add mgrootassoc (hexstring_hashval "9283cafc90df46790d36399d9c4a27aec79cadc0fd1a9b2f654b0465ca1d1659") (hexstring_hashval "8f2fbe77e432c151f468828696bc88cfbde14365208ec6d40c57d57f47201c42");;
Hashtbl.add mgrootassoc (hexstring_hashval "8627a945e60408d81c3094008f07f651db6b692c34fa1ffa9753e39b66d38044") (hexstring_hashval "174a19a576b89f1308ff59f6dd7de2117117f98e28682f4bbd15fbb1975ae6f0");;
Hashtbl.add mgrootassoc (hexstring_hashval "90c303e6b6cca396b2d8ddeff62cda2c0954a43d45ad666e7b8ea21c1d8fa73a") (hexstring_hashval "b635bdf22563c31dfe7ebe5ef5db6659c84c46d4448fbd36c50ffb05669d7a72");;
Hashtbl.add mgrootassoc (hexstring_hashval "0cc8a8cbd38e8ba1ee07ccfd5533e5863ca3585fcd0f824fb201b116adadea99") (hexstring_hashval "e67bc4d0a725995ed2ec3098468550e926fee1bce25684449381d154f0ee8440");;
Hashtbl.add mgrootassoc (hexstring_hashval "e4ed700f88c7356f166d3aaad35c3007fde4361ccaa00c752a1b65ddb538052e") (hexstring_hashval "a40e2bf43bfaedcb235fbe9cf70798d807af253c9fbdaca746d406eede069a95");;
Hashtbl.add mgrootassoc (hexstring_hashval "944de6e799f202bde0a6c9ed7626d6a7b2530cb8ff1b9c9a979548e02c1a4b81") (hexstring_hashval "d911abc76bc46c5334e7c773fdba8df1c33d0156234b37084c9e6526851c30b9");;
Hashtbl.add mgrootassoc (hexstring_hashval "b618dfe4a17334147263c506b2138f51d0d2c7b154efad7f4f29ccbe49e432f3") (hexstring_hashval "9f6ce4075c92a59821f6cfbfc8f86cc2c3b8a00b532253e0c92520fca04ab97b");;
Hashtbl.add mgrootassoc (hexstring_hashval "b25dda61a9e31c2b6c19744c16c5af120939ef77a89fe6bcea622a7b6ba6ce78") (hexstring_hashval "b430b61db2900bb60168d91af644ce9e8886b53b9fc1d812f4f50f301fbaf2ad");;
Hashtbl.add mgrootassoc (hexstring_hashval "037a74a15834f7850061137e15b24c1545b3cec27cea76d5a22e5f66ad2e9ff1") (hexstring_hashval "5b8f1bcabb96c729d6120f7525c02179f8baf007a2bc04b7f8efb36fff497cf6");;
Hashtbl.add mgrootassoc (hexstring_hashval "de8fdf3d1593629dc04bc929fc51714e9acdbd4d4b7e5ac4f6e31798f074955a") (hexstring_hashval "161e94d84ccfb9b03f97f8dd48da7489affeb461b5931fee82f582ce63054de8");;
Hashtbl.add mgrootassoc (hexstring_hashval "e67bc4f46a82d2da832c0b1ea8593b15f1d43cb42c47c14bedf3224d91bb4039") (hexstring_hashval "390fc4600463d505da84a02614562715ec110f50b35ef60c795a3e8cf5642e76");;
Hashtbl.add mgrootassoc (hexstring_hashval "6cadd576448ecca7f8b8557effae12a4bd794c5aa18b83ca53ffc8b7af0e15e3") (hexstring_hashval "e480d744d3179a41e70b5a7b752a6f52ecf23e43a4b122c913fdbe24cb157faf");;
Hashtbl.add mgrootassoc (hexstring_hashval "fefa5747998b1aff604d1d96d49720a05d617de50559dbd3ac8255126a0ad111") (hexstring_hashval "9780e99b41e7f1c76d8a848b89316a2544367adddc2bfa53ba8861a7c547df4c");;
Hashtbl.add mgrootassoc (hexstring_hashval "b2802dc1dc959cc46c5e566581c2d545c2b5a3561771aa668725f1f9fddbc471") (hexstring_hashval "2a005aa89167824a5dc8b5af9fa6c5b6fbef0387c949149d9dd5e521f0b69bc2");;
Hashtbl.add mgrootassoc (hexstring_hashval "9c4c8fb6534463935b80762d971c1b53a5e09263a04814f932ce1b52243bee43") (hexstring_hashval "3ef0783d3dd1a33ac200500d1349e48add7a96a58afc37c9b1085fd6a99362fa");;
Hashtbl.add mgrootassoc (hexstring_hashval "cad2197ffbf0740521cd7e3d23adb6a1efe06e48e6f552650023373d05078282") (hexstring_hashval "666e54e52662d60e53e1542e53129f9cc131ba191c38c8522ceb22df27c747df");;
Hashtbl.add mgrootassoc (hexstring_hashval "a57e6e17457680064de7365f74da64f0485246f6d234a87c6c73dd3985024e8b") (hexstring_hashval "41dbc343dbbf91f10cdd7dd0de9eafbda94687837270649efbb00c50d4d9b008");;
Hashtbl.add mgrootassoc (hexstring_hashval "0004027ff960a5996b206b1e15d793ecc035e3e376badaabddcd441d11184538") (hexstring_hashval "3e793684b1addcd218212526a72be5635db67ed49f73be3529ff95ab37b73cdd");;
Hashtbl.add mgrootassoc (hexstring_hashval "19cb92902316fefe9564b22e5ce76065fbd095d1315d8f1f0b3d021882224579") (hexstring_hashval "60aefac59c434b445557f59a5f298a1d61d61ad0031f82a7d9edf7f876a42eb2");;
Hashtbl.add mgrootassoc (hexstring_hashval "0efe3f0f0607d97b545679e4520a6cde4c15ac7e4a727dc042ece6c2644b0e6c") (hexstring_hashval "48e721f6c014994d2a8e56ef386bce6509646843f54cb3a21879389b013a29cd");;
Hashtbl.add mgrootassoc (hexstring_hashval "b699fe9c93bde46c2759367ced567ecede534ceb75fd04d714801123d3b13f11") (hexstring_hashval "b13d5e1e98748dcd622528baef5051c4390df27729fee3052d7113e65406686d");;
Hashtbl.add mgrootassoc (hexstring_hashval "b9e0ea161ee21f88a84c95005059c00cd5e124bcc79d40246d55522004b1e074") (hexstring_hashval "347e91ae466507edd75be2b71e68c97116b6e517d87886ab0e8ddce2f54ae399");;
Hashtbl.add mgrootassoc (hexstring_hashval "ae387c8a22b3bccf4137b456bd82b48485621f5c64fbec884db6cad3567b3e4e") (hexstring_hashval "0310fef5d6de3aefcdedd7233952666c0defc336e65e64aab369ae29825983db");;
Hashtbl.add mgrootassoc (hexstring_hashval "060534f892d9b0f266b9413fa66ec52856a3a52aa8d5db4349f318027729ae5f") (hexstring_hashval "10c7edbdfea7c668fd8a51d3c28767488294039d754a8302ce4d30439b2fc428");;
Hashtbl.add mgrootassoc (hexstring_hashval "38cf2b6266d554cd31716ea889acb59281f11b53add172f75942eb1ac6f37184") (hexstring_hashval "1d0e19a029951bdf020ea05e5f97e89c29ccf2711bb9fb68c3149244d13ec43c");;
Hashtbl.add mgrootassoc (hexstring_hashval "602e9ea9914dd8708f439fa3eab201948083d6398b3c9cea8be23b8f5c5d802e") (hexstring_hashval "80fb70a8d1dff15e44796b1e78303eaa7ef179f797be1749888a9834e52dc5fa");;
Hashtbl.add mgrootassoc (hexstring_hashval "389c29db46c524c2f7c446c09f08884cc0698e87a428507089f0bdcb6eed53bc") (hexstring_hashval "027e53400db56db5263421743bf167ef29c835dce9328a41fd2dbf3ebdb50e65");;
Hashtbl.add mgrootassoc (hexstring_hashval "71bcdf9baad76c82fa10a8abc4f36775b4001d57b788efddbe8d65a2d09121c4") (hexstring_hashval "8e13f5f4e1b64ff341da653d34bc05443520f675b29d811d26387a4f468f5f30");;
Hashtbl.add mgrootassoc (hexstring_hashval "1b68d0f2576e74f125932288b6b18c1fd8c669d13e374be1a07cff98d22e82c3") (hexstring_hashval "8aecb427840b61e6757025949c6ddd68aacc216c16733b2f403726e79ae67f06");;
Hashtbl.add mgrootassoc (hexstring_hashval "5b760f2c6da13ba6d57564ce0129f63b011cb0c5d9093d105881647d0fe653c6") (hexstring_hashval "58721dc378c372050967fa1dbdd26f97b73b4ea335cef8cc307de7283e300909");;
Hashtbl.add mgrootassoc (hexstring_hashval "db5c0384aad42841c63f72320c6661c6273d0e9271273803846c6030dbe43e69") (hexstring_hashval "9fd0c0e101e8c20fff753a8b23b3328a26c4db803c1d08b1c8b0854ba1bbed02");;
Hashtbl.add mgrootassoc (hexstring_hashval "e6d60afaf4c887aa2ef19bbb5d0b14adcf2fc80a65243e0bd04503f906ffbcd5") (hexstring_hashval "4326139c530c640a1854bd9a222317e596a3f805e2f3d33fd3d6aec1eb6bd2b0");;
Hashtbl.add mgrootassoc (hexstring_hashval "b065a005c186ce9758376f578f709a7688d5dac8bf212d24fe5c65665916be27") (hexstring_hashval "28f76ac430eb06168c4c601a7adf978dee4cca2388c112e42ba0ebe69697075e");;
Hashtbl.add mgrootassoc (hexstring_hashval "63a0843b702d192400c6c82b1983fdc01ad0f75b0cbeca06bf7c6fb21505f65c") (hexstring_hashval "3da5b52bd58bc965d9d06af6ff011a0d48fda67cb1671518f30c198dd087b3e3");;
Hashtbl.add mgrootassoc (hexstring_hashval "3f0a420bc7dbef1504c77a49b6e39bb1e65c9c4046172267e2ba542b60444d4b") (hexstring_hashval "0042facabef0b8b2cd0b88e11f395dd64cedb701439e02dc42ea070eda126194");;
Hashtbl.add mgrootassoc (hexstring_hashval "364557409a6e9656b7ffdd5f218b8f52fdb1cfebf9ed6a29b130c00de7b86eeb") (hexstring_hashval "20ef164993077693d21dfbd3e184930447dc5651b7b2514d5e70c3d4c7e57c4b");;
Hashtbl.add mgrootassoc (hexstring_hashval "2c8d6cdb20b24974e920070c509ee09fd0e46783833f792290fc127772cf8465") (hexstring_hashval "0031e96c6fb0d6adf4896553d0f0c34914a51053aec23f189557736115dc381d");;
Hashtbl.add mgrootassoc (hexstring_hashval "0b944a0863a8fa5a4e2bb6f396c3be22e69da9f8d9d48014d2506065fe98964b") (hexstring_hashval "a061aec6f47b710c4ca02cbbe64e04ebdbf3d2f3e693a1f5011156d8141c0362");;
Hashtbl.add mgrootassoc (hexstring_hashval "13462e11ed9328a36e7c1320b28647b94fe7aa3502f8f4aa957a66dbbfe5a502") (hexstring_hashval "1a579654987eb474745f353a17ddddecd95ec26b0fc30b877208d2ad805e5173");;
Hashtbl.add mgrootassoc (hexstring_hashval "66332731028f49429fbc07af9b0a51758f1e705e46f6161a6cfc3dfbc16d1a1c") (hexstring_hashval "9158242b0270a8215bc2d3d246afb94a99f6df13ca5b875d772a23f990d03b91");;
Hashtbl.add mgrootassoc (hexstring_hashval "11c17953d6063f86b26972edfb529598953033eefb266682147b3e1fc6359396") (hexstring_hashval "197e22d9a67ce8a150759817ee583505c0b5c8f3fa51b9b7cebec8a33dcd22cc");;
Hashtbl.add mgrootassoc (hexstring_hashval "c621cd3b8adca6611c926416fa83cfb7e8571e4fc5f9c044b66c32c0b4566b1b") (hexstring_hashval "5dac273214220bb7cf68bcdd1f6d902199114ed29ae013fbbae5631af0250fa4");;
Hashtbl.add mgrootassoc (hexstring_hashval "1bc98ccdfd4f38a6e7b2e8a4c7ed385c842363c826f9e969ccb941927cc8603b") (hexstring_hashval "3e6db9a7cdd7b129997426465647488f6080a894eabd9aa3370cb4d1948627f5");;
Hashtbl.add mgrootassoc (hexstring_hashval "c923a08399746a1635331e9585846e0557df71a9960cf7865bead6fdc472eeaa") (hexstring_hashval "9a8c41e920575c2183e58d43541add604cdaf897fa2e63df2c4952570c921345");;
Hashtbl.add mgrootassoc (hexstring_hashval "57cb735bc8fdaaa91a2570d66fec402838bb40de2a930269c1f4e5eba724d1b1") (hexstring_hashval "b2b4376c2aafcf9ce2e4fafee8df0ca2a4757a1bd7c4f4e6ff449c599f50c922");;
Hashtbl.add mgrootassoc (hexstring_hashval "614e4521d55bb22391f5f70f5f8665cbd665893678ce4af60fafefe0a790a3d9") (hexstring_hashval "27b4e486614b631c78d53b90890e751a7118c014ade0c494181ca4a238a0a125");;
Hashtbl.add mgrootassoc (hexstring_hashval "4809fc07e16e7911a96e76c3c360a245de4da3b38de49206e2cdd4e205262c8f") (hexstring_hashval "f3ce4893f17fbef8e7a751fbdf8a27525539382822e747dbaff3580a378783d1");;
Hashtbl.add mgrootassoc (hexstring_hashval "b491d40ed9c90739375b88e8e41597fd692cb43b900ff6f44a0d801a3810e501") (hexstring_hashval "a260f9fcd13ea68a450a898d00ffca56b944add47cc2bfd87e244adddce77ef7");;
Hashtbl.add mgrootassoc (hexstring_hashval "a2b47513ee6d043349470d50ec56d91024a5cb46e7d1a454edd83ca825c6a673") (hexstring_hashval "f1bae9eff0a83e28c138e078dba11b9bf5d2d9afdfd90f3bed6c5e36d76ab489");;
Hashtbl.add mgrootassoc (hexstring_hashval "427ff0017dcd4f8496dda259976e1e8ea7bf40bd148a324f5896dc89af9af2fc") (hexstring_hashval "b2fea87533731ce218fc5ab4344d14278bf5c7611bfb8d8dd1bc7d9ae4358fb9");;
Hashtbl.add mgrootassoc (hexstring_hashval "b66998352219cce4acba8e11648502b25d799b0d48aed14359ff8c79bd5cbbcc") (hexstring_hashval "8bbdca2f1fb0cd8481d71a5579d35a1fa36119fdb70456f98f852feef3c9bc13");;
Hashtbl.add mgrootassoc (hexstring_hashval "ed8c93098b878e39f3f8c40d30427fe880959e876df703ca5e56f9eccb18b3fe") (hexstring_hashval "d41df825e4d90bfb9a810bc6deaf5d72dc98485e9c021daab862a2ba54856a2b");;
Hashtbl.add mgrootassoc (hexstring_hashval "284ea4b4a1cfda7254613d57c521a51c4166f414dd0d475dd3590fcf0f62d7b3") (hexstring_hashval "6fa39970893ec9507b6d91cf7bba7b13c3c4a9dd71cd645b3a682eb5ae854bee");;
Hashtbl.add mgrootassoc (hexstring_hashval "6e5fd5f81bd22b7a196e96a2bda29df9fdefda1b8a6920456c0f39f4d8bec0c8") (hexstring_hashval "fe61aee6c1263ac187993eb19e568d32ef3f7fb60226597da4d0d12912f9e16a");;
Hashtbl.add mgrootassoc (hexstring_hashval "908b7a89beb09326c39fc22e257aa237073fc8a02b46df12c282134194a99ddb") (hexstring_hashval "fa1f8d6ec8951bb56e8b4d21e233cc1496384102ea4df35398bd2b621cb27ed7");;
Hashtbl.add mgrootassoc (hexstring_hashval "1c9222fbad61f836b4b4632c4227c6a28bbb48861f2053f45cfd5ef008940d7f") (hexstring_hashval "2a1620b714f2fde572a044a1c5f6902a5e8fc266fba947bb21a2d9eced0abc58");;
Hashtbl.add mgrootassoc (hexstring_hashval "a590c29f883bbbff15e1687f701a8e085351f71cf576ee2ad41366bdf814ad05") (hexstring_hashval "bb9a233e1cfe76bcd0deb8a66ade981305b41de49e53fc6583ada8cade8ba59e");;
Hashtbl.add mgrootassoc (hexstring_hashval "c1fc8dca24baedb5ff2d9ae52685431d3e44b9e4e81cef367ebf623a6efa32da") (hexstring_hashval "9fab64b226f13e289c0af13e939c25a7a85be482c5212135f556aa43dbf82402");;
Hashtbl.add mgrootassoc (hexstring_hashval "de4d3c080acf7605ab9373bdda9ab7742cdc6270e0addec4cd69788e44035ecc") (hexstring_hashval "041760e519fd5b52ebf68b01d72aeb4c74724ded24aca463849705946b70a954");;
Hashtbl.add mgrootassoc (hexstring_hashval "04c96d41ac71dd346efdcaf411b33bdf46261fe3f21aeaf2c2db6737bf882477") (hexstring_hashval "075c344e49e0edd4421630e6f9a4bb1828247b9a4838724ceb3a11be867b4c93");;
Hashtbl.add mgrootassoc (hexstring_hashval "e3048d3645615bbcae450f4336907ef1274e3d37a16e483a3a7b3fffa99df564") (hexstring_hashval "90b348d67415c0609774ada4126c8ca7aed2228cd31f027bbf9174acba7a30d9");;
Hashtbl.add mgrootassoc (hexstring_hashval "eb423a79b2d46776a515f9329f094b91079c1c483e2f958a14d2c432e381819e") (hexstring_hashval "5799d138e050dcc93847fcf8fcab1826b22a666be5d10e02f4231dedbd9350a3");;
Hashtbl.add mgrootassoc (hexstring_hashval "3dca39119b52c60678ddc1f4b537255be377eb6f8e3df97b482a917f1c0d9c43") (hexstring_hashval "724c10411795d3293da878b57f1e2683f37409e924e76cb5779118a48e908568");;
Hashtbl.add mgrootassoc (hexstring_hashval "0492808b6a8765162db7f075ac2593264198464c84cd20992af33f4805175496") (hexstring_hashval "4e95b2dd2888b8ee5c306bfe8140a9db3071f253b29775dcaa9644fed6cf9f7c");;
Hashtbl.add mgrootassoc (hexstring_hashval "d53de96c47ffaba052fe0dc73d899a0fc5fd675367b39ecbf6468f7c94d97443") (hexstring_hashval "91dec9684ffbf80c5812ce3b1466150e658399284964922623267ff1c14d5cdd");;
Hashtbl.add mgrootassoc (hexstring_hashval "bd6bf5dff974189ab987ecb61f8e3e98533ea55a4f57bde320344f6f3059947f") (hexstring_hashval "107cc6685376714d6f273e53f3fa3cb90dc3fb6729a156dca1dcdd9fef6f1b4d");;
Hashtbl.add mgrootassoc (hexstring_hashval "1f289d381c78ce2899140a302a0ff497414f2db252b1a57d94a01239193294e6") (hexstring_hashval "81dc7fcbb73b82e3d98455d8ff2b9bc61777b03ab6271d6c7dc0f25556888fb3");;
Hashtbl.add mgrootassoc (hexstring_hashval "bdeeaf26473237ff4d0b8c83251ca88f469d05d4e6b6a9134e86dae797ae7fdc") (hexstring_hashval "33658b2c2b6d21d1170663c29fc2f1d2ddc9799c17a1051cd4c4fb8dc4affcce");;
Hashtbl.add mgrootassoc (hexstring_hashval "46273e3280756faf73eb2136bf0d6e0dcfcd5bd6914a469dd940bda98f520a41") (hexstring_hashval "c37e75acd07ea78a4136072aa775d5d4dfde506a4d783cbf8f7f5e6183389b0a");;
Hashtbl.add mgrootassoc (hexstring_hashval "a2e30b14982c5dfd90320937687dea040d181564899f71f4121790ade76e931c") (hexstring_hashval "8fe8c719cbf98deb6b6a2c70f8a7fa6baf20ed652cd67241181a6c1013fa357b");;
Hashtbl.add mgrootassoc (hexstring_hashval "f7180c2205788883f7d0c6adc64a6451743bab4ac2d6f7c266be3b1b4e72fd1f") (hexstring_hashval "077fe8eb3c54f448498bdb665bd6aeca1ccf894226d42fdf3bcdb737b9f3954c");;
Hashtbl.add mgrootassoc (hexstring_hashval "aeb0bbf26673f685cab741f56f39d76ee891145e7e9ebebfa2b0e5be7ff49498") (hexstring_hashval "076668a30dcbec81d5339dad5ed42265abd91a2e3312bee6c2fdd193d58b511f");;
Hashtbl.add mgrootassoc (hexstring_hashval "fe2e94e9780bfbd823db01f59ca416fff3dca4262c00703aeae71f16c383b656") (hexstring_hashval "35b4665b9c982227d6e608a6dbe9bff49021ecd08d247b8d6491670fe4619156");;
Hashtbl.add mgrootassoc (hexstring_hashval "1612ef90db05ae8c664e138bc97fb33b49130fb90cdf3b1c86c17b5f6d57ab06") (hexstring_hashval "3f0f9d7d8d1dda3e6b14b5f1a55262df088b79d68b38836664c561b0fcc4f814");;
Hashtbl.add mgrootassoc (hexstring_hashval "b7625cf2696e5523826bd42e2658761eefffdbad656dfc5a347f1aae33d5c255") (hexstring_hashval "98dd51e79bd2edcbc3ad7a14286fea01cabaa5519b2c87dca3fd99cecb8cffaf");;
Hashtbl.add mgrootassoc (hexstring_hashval "76ad2b43a7ddd0851ab8273a0e8922d37e1cc96d5aacbb9854acde184289537f") (hexstring_hashval "3d222d526695d68917009e55e42b3e3376f01eff89abe36e8a6d56c854818947");;
Hashtbl.add mgrootassoc (hexstring_hashval "b75ffa1b350a850f8416223e733674302de28dcf0ea44a9897e3b7adf8502588") (hexstring_hashval "c70bb56759cdec1ec590d99361b77498331cdce9b840801676e9b9d4b3cb31e9");;
Hashtbl.add mgrootassoc (hexstring_hashval "c1b8c5cd667cfdd2a9b00d5431f805e252e5c7fd02444f7c2033c6bfb44747ab") (hexstring_hashval "70ac687e1861704c6a1fa22ebbbb054d154870fb64dbe6ba3855c1e41a99f696");;
Hashtbl.add mgrootassoc (hexstring_hashval "51931da307bf20b618a1aa8efb36b7ce482ede5747241a20988443f5ab2b53fd") (hexstring_hashval "4dd31b5c4e92a67021b9e43deb98c3fefe9a4f74123e901531456d67138e5b7f");;
Hashtbl.add mgrootassoc (hexstring_hashval "5473767e0c0c27ccaea348fbc10b4504a7f62737b6368428e8074b679c65151c") (hexstring_hashval "90e28dc98e7ddb59e750b598c7a1fcc3968d4e4ae47e692760b1a2dc84e386f6");;
Hashtbl.add mgrootassoc (hexstring_hashval "922c08b52255e99209b7604bddb310b8dedcdc9a5a912ffba91d7bc1ef425c3c") (hexstring_hashval "822fd0482c7d142bc157c71c4cdb903956e06eaefe0685c746428d608c2102cd");;
Hashtbl.add mgrootassoc (hexstring_hashval "19c01351df87a86dbef2a06e599620d7dbe907e1a1a43666166575ed7ec78a21") (hexstring_hashval "ae2d9d50642b996b0503fd539520a49bd62670a5c58b878847916ab5d64ff858");;
Hashtbl.add mgrootassoc (hexstring_hashval "e3a0ef959396c34457affae8f71e1c51ff76d58c3a3fb98abdf2bf81e4c9024a") (hexstring_hashval "163c3fe98bb9b2ff8f06e5dfabc321124619cf7611eb786523d1022bd4e8f66b");;
Hashtbl.add mgrootassoc (hexstring_hashval "1a12c2b231aebc0f76cfe28063c1c394e62eea0dd383f04ad9c9ba9061e06c6f") (hexstring_hashval "774b38fe03ec4b4038c40905929738d1ef98b3e58c02ae656fb009bc56df8c37");;
Hashtbl.add mgrootassoc (hexstring_hashval "7fc7616128fb2078dc12d009e92c2060985b08ddf5f039c9ad0c1afdeefaa21a") (hexstring_hashval "b57e669b209cd96d0ef04fd9242923c0a1b44ffda69f288956baa1b3d0641e4d");;
Hashtbl.add mgrootassoc (hexstring_hashval "7a05733d2df294b5b3e594d61c8b85792bf659e73fc565d4699872c48b405a0c") (hexstring_hashval "a917c2d3c4a47a2b146ae1923e2ce6e20a47465d74851c933b04fa530ba48efe");;
Hashtbl.add mgrootassoc (hexstring_hashval "8f02b83ee383e75297abde50c4bc48de13633f8bb6f686417f6cbe2c6398c22f") (hexstring_hashval "de2c54e24ed23aa406d5a0de2e5b23a867b8d05e621b79616ceb89e0a9571e13");;
Hashtbl.add mgrootassoc (hexstring_hashval "8d1ff97700f5aea5abd57ec53e8960d324745c2d51505eaf2a66b384fab861ba") (hexstring_hashval "ea586d49f5dc3ec7909d111fcd5e884f4c9a5642931ac65f9623f252999c1274");;
Hashtbl.add mgrootassoc (hexstring_hashval "3a002cccf7156dbd087a73eb48d6502dc8558d109034c4328e3ad65747e98c24") (hexstring_hashval "5b87672babb9eeda4f773be7b2d75d6d39b47a1c3d606154005cb48f87e8e2fc");;
Hashtbl.add mgrootassoc (hexstring_hashval "367c563ec5add12bec5211c2b81f2fdeb34e67d99cdc91f57fabe0063a9b221d") (hexstring_hashval "f394f9533d4df8855dc80f298cbf8fa1d1ae0ad0f7c5f5a3764577a9a7211fee");;
Hashtbl.add mgrootassoc (hexstring_hashval "9847fb1e481709bdc99e87b11793438720dd15ea1326b3a4103e19eda0dc1cdb") (hexstring_hashval "9bdf7a97858c8bf12661153c4c4819a807571b736f426637022a92d7bd8a211d");;
Hashtbl.add mgrootassoc (hexstring_hashval "da834566cdd017427b9763d3ead8d4fbb32c53ecde3cf097890523fba708f03d") (hexstring_hashval "eb06ec3cb313acb45973122fd831d60631005ca29456b63d4a9bc1db8adcd84d");;
Hashtbl.add mgrootassoc (hexstring_hashval "f0596c8373caad482c29efa0aa8f976884b29b8ac253a3035f7717f280d87eeb") (hexstring_hashval "270f1d0a513ca45e05ccd6aa8730174cbe7403b3e84d91a2074d85563e15db80");;
Hashtbl.add mgrootassoc (hexstring_hashval "4226760658369037f829d8d114c11d005df17bdef824f378b20a18f3bdc34388") (hexstring_hashval "7f07b505a46c88313ffb3848b6d0cdaff50136dc9e36adaefe3dbaad692497fe");;
Hashtbl.add mgrootassoc (hexstring_hashval "1a4c81bd335aef7cac8fade8ef9dbc01ca842e2c14e95b2c56aaa0f5e4209c38") (hexstring_hashval "a71f1dc174c9d7f27040ca69b0b5e9fe74b071767b7f0e9a0f6cbd1ae8b88d59");;
Hashtbl.add mgrootassoc (hexstring_hashval "82be13ec00a4f6edd5ac968986acbcac51f0611d6382e24bff64622726380a9a") (hexstring_hashval "8c2d24fa7bc03d18bf085ae6345b4c14addd886c8c9ce0d98c8be142ad0f06fc");;
Hashtbl.add mgrootassoc (hexstring_hashval "ff2519c5a99ff630d6bc11f4a8e2c92f5c4337d4fade1233416c9f8be29b97bf") (hexstring_hashval "02b6133ee53d7e7d7eb62e214eac872c6b9418588d34817e28cf6819bfcb1c2d");;
Hashtbl.add mgrootassoc (hexstring_hashval "9fa6776b13418f86298bca6497a3815dcce3638ebaf454a17f787318cf5617f2") (hexstring_hashval "eff39931af660839589da49f300a321e79e5e54d78d23eeab73dac6fbeeb4365");;
Hashtbl.add mgrootassoc (hexstring_hashval "b3e0e4c50d5183f60f5e1f9e3f0d75c0c37812b79811f9dcf9d873c2555dcaca") (hexstring_hashval "1f153865a8d6a20ed9347058840bdb7a4b3f6a543f506858f293d5796b874dc5");;
Hashtbl.add mgrootassoc (hexstring_hashval "2fb7e4a1c28151491d64daa8b325cd7de4169f199bffae696aa7c9dffd759afb") (hexstring_hashval "6548d02ff816addb040c2bab6dedd0a068455af7b6f674aa15d2189eab9229a5");;
Hashtbl.add mgrootassoc (hexstring_hashval "c20cd8d43c72408b805de4056229616e0928e4353b4a57b5c3bb31877997887f") (hexstring_hashval "ab64e006a3fa2542dfaf03e7ecc61d720a7dd2a4235519a21323f30e754ae95e");;
Hashtbl.add mgrootassoc (hexstring_hashval "8b052af19200cd8c3a36c76223b25d75acc4ba4f8d78dc4ef6bc25fea7ecaaf1") (hexstring_hashval "3feb38bfced1866d8a371d5836249e3b5629ad77220dea694122080f3cff81af");;
Hashtbl.add mgrootassoc (hexstring_hashval "0fe73cd2b0cec489d9a87927620630b30f0b4f99db8fcdca0b2d8742cb718d03") (hexstring_hashval "3d692af3c89826e9da7752a23e66092858664d9d7c5deabb0f8d8343a74b84d0");;
Hashtbl.add mgrootassoc (hexstring_hashval "9140bd6ad18cfea50ff6b8e3198e4054e212e5186106a57724e9cdd539cc3d83") (hexstring_hashval "c41f763e311b783ef78fa60b4965eb0be401787c03c40049184a7dddbef41bcd");;
Hashtbl.add mgrootassoc (hexstring_hashval "7bbd83ee703beff55fa6d91793e356dea499739b8dc6c6642775f0d8dd89fc3f") (hexstring_hashval "8fe6b919a961202632ceac4e83dfcc72fed170314aaf7bb573e334c2d5b3bdb8");;
Hashtbl.add mgrootassoc (hexstring_hashval "67895c4dbdd3e430920ac9eab45940631f86074839dc93dbf23c0770d9d3d9dd") (hexstring_hashval "e2724da4f32fcc3a5f2b94a5506cac8359a57f3653a4accb86408487d2f02699");;
Hashtbl.add mgrootassoc (hexstring_hashval "f6af43db50fc4694c5cce6241c374aeb673754e28c11aa67daa0824c7f06d9ac") (hexstring_hashval "6916555459e8d833282592d7fadf17b37b8b6d2d9123e1f8d40c2ef770f4c32f");;
Hashtbl.add mgrootassoc (hexstring_hashval "0e96766c20d57f4082ccb3e6b37fb7b5f31f609f2c591308b0729e108bab32f9") (hexstring_hashval "5635b41ed14760c834c090cf0c1e2fa654de2dc143825c3b635fdccf379e5b32");;
Hashtbl.add mgrootassoc (hexstring_hashval "c097a1c8fc0e2cc5f3b3be0c15271d8a72541dc13814f54effd3ed789663baeb") (hexstring_hashval "c8d168bd212b8e2d295be133eee17acc830eb999371846485c9a055b70136f93");;
Hashtbl.add mgrootassoc (hexstring_hashval "9b0c4e2b1f6e52860f677062ba4561775249abc5b83cdba4311c137194f84794") (hexstring_hashval "b1b9c7973d18de0bdacd0494a2e91299815cba0f37cd7d905682d3fa374a5c11");;
Hashtbl.add mgrootassoc (hexstring_hashval "d9d0d8e1199ebd2be1b86dc390394db08d187e201e5f5e1190d3bb913f014bd3") (hexstring_hashval "f4a6ff5a667a3651c01242a3020b2e161af79c5ad170c804d6575c189402a57d");;
Hashtbl.add mgrootassoc (hexstring_hashval "802e9aef398ccfcad3b898857daba5acecbefb209538dd46033512ff7101f226") (hexstring_hashval "aba7492454eba44196d725cf42d18130c354708136c573e78cd29651f643ac9c");;
Hashtbl.add mgrootassoc (hexstring_hashval "9d129e1d51ce2f5e54ee31cb6d6812228907cc0d0265c1a798c1568a995b1c5d") (hexstring_hashval "9f6182a9e7b378137d16faddb447c36f68b16c0832febf5ebc231139cf4eb273");;
Hashtbl.add mgrootassoc (hexstring_hashval "f6aac57396921ec19739fdda24c0a3c0791d8b6b18d75fa7cbbbc656753db3d1") (hexstring_hashval "7549918eb10fc58235f0c46b18a30c9cf84a23dccdc806011298697c6cdca26c");;
Hashtbl.add mgrootassoc (hexstring_hashval "afe9253a057d9ebfbb9c22cbeb88839282a10abfbe2fad7dbc68a0cc89bff870") (hexstring_hashval "e3d07ed8be5ae2cfe58e7b45a7024f44da4ccf5856bbf40f9cd1eea0b64e2fd0");;
Hashtbl.add mgrootassoc (hexstring_hashval "583e7896f2b93cba60da6d378d43e24557322e603737fcd59017740ef7227039") (hexstring_hashval "7904aefeeb335a0c58df3664195d8f4dee000facb5c017007c240ca1a14b6544");;
Hashtbl.add mgrootassoc (hexstring_hashval "b2f9749e7ac03b1ecc376e65c89c7779052a6ead74d7e6d7774325509b168427") (hexstring_hashval "546009d11d59ac41fa9d3c8ef2eff46d28c48a3cd482fac9d1980125c73fa11c");;
Hashtbl.add mgrootassoc (hexstring_hashval "f35b679c6bab1e6cf0fdcf922094790594854b8da194ab1c6b10991183d51c1a") (hexstring_hashval "3f1821f85d08e8012e699b09efeb0773942fcc2adacfea48bc8f23b31eb6673d");;
Hashtbl.add mgrootassoc (hexstring_hashval "fd9743c836fc84a35eca7120bf513d8be118e8eff433fbcc8ca5369662cda164") (hexstring_hashval "9b2dee6442140d530f300f187f315d389cfa416a087e15c1677d3bf02f85f063");;
Hashtbl.add mgrootassoc (hexstring_hashval "5b5295c9462608ca7d9fadeeeb12ef2ff33e0abce6c5f3d21bb914b84b707340") (hexstring_hashval "d93492debcc941aa529306666dc15e8b90e1c35700eba39acf35c9b597743caf");;
Hashtbl.add mgrootassoc (hexstring_hashval "ac22e99093b43e0b6246d1a60c33b72b22acf28c29494701ebd52fa3ba6ac8bc") (hexstring_hashval "ddbfe293c94f63568d97903ab92695c5b104ee51e1b7d4e7dd29a87510065054");;
Hashtbl.add mgrootassoc (hexstring_hashval "c0b415a5b0463ba8aadaf1461fdc1f965c8255153af1d823b1bbd04f8393b554") (hexstring_hashval "0aae59672cd58c2e839eeb483f6d823f8c69400c45e67edc458d965b50b1e024");;
Hashtbl.add mgrootassoc (hexstring_hashval "8ef0c99a5963876686d1094450f31dbe9efe1a156da75cc7b91102c6465e8494") (hexstring_hashval "79dd5e6f76039b44f818ee7d46c6b7a8635d836a78e664d3850db33f0c3ffaa7");;
Hashtbl.add mgrootassoc (hexstring_hashval "6b9515512fbad9bcde62db15e567102296545e37426a6ebbf40abc917c3ca78f") (hexstring_hashval "4b0864f933a1ac571ac0fb1acffcf816273110e426dba5d21cab3ae9c7c4b22b");;
Hashtbl.add mgrootassoc (hexstring_hashval "1d1c1c340eef2e4f17fd68c23ff42742c492212f4387d13a5eb5c85697990717") (hexstring_hashval "083de41b8563c219f20c031d31476936c0d8efb368f1cc435222350877aea8c7");;
Hashtbl.add mgrootassoc (hexstring_hashval "57caf1876fca335969cded64be88fe97218f376b2563fa22de6892acebecd6c8") (hexstring_hashval "f937ba0b5e96a63b3b47a830a64e1aac438ba69213c231806bafe7ffe25a53f4");;
Hashtbl.add mgrootassoc (hexstring_hashval "fa6fcaff8c08d173f4c5fc1c7d3d3384bb0b907765662ba5613feb3ec9203b80") (hexstring_hashval "a290dddd19b77391bcdbb970300fedc33af288c11500743c0157cf51badb17eb");;
Hashtbl.add mgrootassoc (hexstring_hashval "bb42af02625c947315da0cad8dfb202966b1ecd2386812628852e0adf9c04c16") (hexstring_hashval "f533207f71a5177d7249765eaeade947ad50cf92e2283c0da9dc069894f6f162");;
Hashtbl.add mgrootassoc (hexstring_hashval "aa77e5577fc2ce6a3c73b87382bd659aefd97ffae837e35547f34b606166c999") (hexstring_hashval "78ffabab9f01508fc81bc36a5c0dfcc5d2cace556d216f6d6aab9389f42d4476");;
Hashtbl.add mgrootassoc (hexstring_hashval "64673bc8a8882720c2818d2bf776ca95f2a94e00547422df4e502e2c1ea48675") (hexstring_hashval "71ade8643726a6e7f38cc8ef90bf356e854b17e60a87a5799b556e53a948c155");;
Hashtbl.add mgrootassoc (hexstring_hashval "5eb8d74e40adaa48efa3692ec9fea1f1d54c1351307f2a54296ed77ac37af686") (hexstring_hashval "40f47924a1c2c540d43c739db83802689c2dd8fe91b5277b7ee16229de2ef804");;
Hashtbl.add mgrootassoc (hexstring_hashval "867cefaf5174f81d00155c1e4d6b4f11276a74cce9dfe9b6f967df42422d03d0") (hexstring_hashval "c43c5ae4e26913b92bd4aa542143ea63b9acdbd1a8a3c545e682da38491db765");;
Hashtbl.add mgrootassoc (hexstring_hashval "6d86bb255886d154fd0886829fc7d7f8411add3db54738041d14766df3b5c4fa") (hexstring_hashval "947fb9a2bd96c9c3a0cefb7f346e15d36deca0943732fc3ea9bc3a588c7ad8f8");;
Hashtbl.add mgrootassoc (hexstring_hashval "0b45fcf3d1875079a5444d1fc3394e8b181d424e1b77602a553a5f03e8351721") (hexstring_hashval "fe76b47a5f32ff63e53ad37345050d53c5d1a01e5329020a0bf0ef19cc813da7");;
Hashtbl.add mgrootassoc (hexstring_hashval "66241e5ccfbbd32429c1f14526f03d9d37590fe4ddf66171a76fae8bb5f8b113") (hexstring_hashval "7a516cda4555ee314bd599299eac983d7d569296583a629b47918e19d4a0f71f");;
Hashtbl.add mgrootassoc (hexstring_hashval "81fa4107fe53377c8e9932359ab17b6be1f49b6646daa701ee0c5525e8489bca") (hexstring_hashval "2a783d5aa30540222437cf12bcd2250d09379447bbcfb2424ca047f449bf06b4");;
Hashtbl.add mgrootassoc (hexstring_hashval "a7eb4561b2cb31701ce7ec9226931f7d9eae8f8b49a5a52f5987c7cac14cdcb3") (hexstring_hashval "fa055287e35da0dbdfea4eda00e6036e98d3ddf3a436e0535f56582c21372e8e");;
Hashtbl.add mgrootassoc (hexstring_hashval "3cbeb3771776e1d1a12e3cb64dcc555d3ff2cc4de57d951cb6799fd09f57d004") (hexstring_hashval "af2de1d69c59ef5054cf8b6dce9a93a630001f055010b2d9b5c0f0945e37d127");;
Hashtbl.add mgrootassoc (hexstring_hashval "ce0f39eb54c9fcc3c8025cbe688bc7bd697a0c77e023c724aa4ea22edcdfaa0f") (hexstring_hashval "4d5ccc56a929ac0c8f71c494d50309dfb6da04c7178c3bc993cde3ebf042a891");;
Hashtbl.add mgrootassoc (hexstring_hashval "f7b5ffe5245726f4af7381ced353e716ac8d1afab440daf56cd884ec8e25f3ac") (hexstring_hashval "09c26abdb88570cbb608edfbe57d30576c9a90b0d04071630aa0d3b62d9c634b");;
Hashtbl.add mgrootassoc (hexstring_hashval "dacefbd6851dd6711e6ed263045ec145efad7c6f5bfe7e5223ba6c7c5533e61e") (hexstring_hashval "992db04f3545ca6059e54ab6da6f2ea553db0f23228f7fec0d787191aaa7a699");;
Hashtbl.add mgrootassoc (hexstring_hashval "fe7b8011fa04942e98e7459bad1082ace0dfdd32285ea0719af3aef0e9417e40") (hexstring_hashval "8d98a4d4dfcb8d45bfdcd349a4735f18958f85477c7c78e7af7b858830ea91e7");;
Hashtbl.add mgrootassoc (hexstring_hashval "c03c309131c67756afa0fda4d4c84047a8defc43f47980c44c05639208cbaa8e") (hexstring_hashval "95f5d0914858066458ab42966efbfe1dd0f032e802a54f602e8e5407ac56ace7");;
Hashtbl.add mgrootassoc (hexstring_hashval "5e6da24eb2e380feb39c79acefdce29d92c5faf26abed0e1ca071eaf6e391f2f") (hexstring_hashval "5fc070d127ffae798f70b712dd801ce996aeab3cec7aa3b427979e46f34030ae");;
Hashtbl.add mgrootassoc (hexstring_hashval "8170ad5e6535f2661f0d055afe32d84d876773f4e8519ce018687f54b2ba9159") (hexstring_hashval "338dd245674671b9ed7925015246c4c4be0e334151ccd1c7d5a3567f5c4461a5");;
Hashtbl.add mgrootassoc (hexstring_hashval "3bd7f72ec38573ff1d3910239a4aa349e3832908ab08202cf114451bffd7d17d") (hexstring_hashval "e6513b6b7dacfb379ee35c71b72ff5e0713f783ff08590c7fabcc4c48daf9f2e");;
Hashtbl.add mgrootassoc (hexstring_hashval "1da7b5b024a841d0694168c01df8b0cada113e9c4616f1555b257b978dff46cc") (hexstring_hashval "e803b40f939f4fe15fb61b29ded3bee1206757349f3b808c5103467101bdab9a");;
Hashtbl.add mgrootassoc (hexstring_hashval "07f6b9e7ce1ef1900b104985e2aa47323bd902e38b2b479799fb998db97ff197") (hexstring_hashval "889a1e76b981b1a33cf68477e7b8b953867e63c9dca7b1aeb36f1c325e9b2a89");;
Hashtbl.add mgrootassoc (hexstring_hashval "98e246907ff1cee98e10366044c2b784e01f55f3a758acab213d3e2ec3fb3388") (hexstring_hashval "5c491c9addfc95c6b9d569a2be553029fe085eeae41ee78922d29695364b8620");;
Hashtbl.add mgrootassoc (hexstring_hashval "5c2a16cdb094537a2fafee11c4bc651c9fb5d6c4e4cb5153e4b4d2abeb392dfd") (hexstring_hashval "f44edc3a0f316d5a784e3afbfb9fec2f3ce4a1f6f80d2f7df61dd3cd3466ad24");;
Hashtbl.add mgrootassoc (hexstring_hashval "b494b403a7bc654ac1ab63d560d5a7782a4857b882ac7cf6d167021892aa5c7e") (hexstring_hashval "87f97477b702b285f58d167931d33cb8f6519093005283206f8f65979fcc9825");;
Hashtbl.add mgrootassoc (hexstring_hashval "7a7688d6358f93625a885a93e92c065257968a83dad53f42a5517baa820cd98c") (hexstring_hashval "cd79716d8923d293cac26e380f44bd1d637c5275ecfc89b47177ddf0a6ed1145");;
Hashtbl.add mgrootassoc (hexstring_hashval "0ecea12529c16388abbd7afd132dcfc71eca000587337d9afd56ea93c40ef1ef") (hexstring_hashval "aa871d3c16738e850e661e7791d77b5210205ae2e9b96f7d64017e0c1bcfaddc");;
Hashtbl.add mgrootassoc (hexstring_hashval "c56bb54dd1f4c2c13129be6ed51c6ed97d3f990956b0c22589aad20ca952e3f1") (hexstring_hashval "1c27141255c5e4ce9a14b5e70f8fabf8ff3c86efed2a9ac48a29895445e76e74");;
Hashtbl.add mgrootassoc (hexstring_hashval "43d5a5a4f39e7d12224bd097d0c832dd4aaf8f489be08729063779862e4dc905") (hexstring_hashval "c2241877df31adb020e1f82396d9042ddca43113930b506db5bf275d368c9cba");;
Hashtbl.add mgrootassoc (hexstring_hashval "c52d30b6fcd1a5e24fb5eb74ade252f6f9aeac6121955aa617e586ddb4760173") (hexstring_hashval "2ad23cacd85ada648391b1e57574e71fea972c2263aff41d810ca1743540443f");;
Hashtbl.add mgrootassoc (hexstring_hashval "2e737a3b857301a25389cf7e02bb12d25fab5e9eda6266671eaec9b91ed87775") (hexstring_hashval "9a20092e34f76c3487a8ba76804c9325515e6c119eea9f7411777ec0a733bf91");;
Hashtbl.add mgrootassoc (hexstring_hashval "7456b6c71eb4ddcebbca14f4614c76d44aff25ab9cffb2ae54f53cc5f4f73fab") (hexstring_hashval "78818644393f655899ed66a6ea1895888ada3b8d13ff9c597d58fa85a63bf0f6");;
Hashtbl.add mgrootassoc (hexstring_hashval "a77aece4cebaf8d8bb332a4fb87637d997f5b502af1a67214219293f72df800a") (hexstring_hashval "b8834674a20323fbc2d5825fbc6a8f71f60ca89b2847624a5b6872e9c48e11d4");;
Hashtbl.add mgrootassoc (hexstring_hashval "f15783baeb7e85a1ff545f53d5ddb4c43d32933da197ebc12c53bd1d42508ff9") (hexstring_hashval "f4473533e314bd79e52e2ad034f93ae6514ae52d8d531b25e6164bae6fd82270");;
Hashtbl.add mgrootassoc (hexstring_hashval "12a33904568297deaf1153b453b55716649c42ac90ce8657680c698f26a9f0f0") (hexstring_hashval "0a6cac81bce852e736d6b82b3b6f39dd40e22fb40f6a2ff61db83d6690d96db4");;
Hashtbl.add mgrootassoc (hexstring_hashval "ab3472b02ca4d827176430c88e964d24d10e60efdbc4f0b4419f2a010ab50512") (hexstring_hashval "3959cd2f6345dfd2436fc0f14e7195f03a659eb8d2bad14a0f8553bf608babb8");;
Hashtbl.add mgrootassoc (hexstring_hashval "6d417fedd6d555ad7eec25e387d6169e63b2edc45904a166c0bd82509c15477f") (hexstring_hashval "9525b165c57c6ce8d3ef7b3e934ea0d9cf6692b3e47ae3d710b1ea3918ed5e5c");;
Hashtbl.add mgrootassoc (hexstring_hashval "b555db6a29f26067dc40fe4e520b59d54b383bb569df8d2c2ecd29eb59cecb62") (hexstring_hashval "4a416c300490417e8ece016ed53c17101fe43bc504c347a764187fe78914ad80");;
Hashtbl.add mgrootassoc (hexstring_hashval "1b9989d8800eb504998ec9186972523482dfb1196e9fcfa977829a7441933b07") (hexstring_hashval "3d648415982d7a2c88de9b694c5f6d0601c327c0c1518eaa124233e63cb71f9b");;
Hashtbl.add mgrootassoc (hexstring_hashval "d9df1855ea1cbccc825d39ce94c4897ef89d5414d5f78ef91215284a99288b15") (hexstring_hashval "2f634e0f6e4da49b080a57d9d63394dc0edb54d858fc4ffef41415fec06d7f4d");;
Hashtbl.add mgrootassoc (hexstring_hashval "fc696ee296a5705053ec9dcfe3e687b841fa4f8cde3da3f3280c0d017c713934") (hexstring_hashval "4b8b63c3ba4e95b67f471222c348d11a6da8cff4cdf83578d1e8915a996cede4");;
Hashtbl.add mgrootassoc (hexstring_hashval "d2032a77eca4ddc09bc0c643339fee859f064abe56b27ebc34a2d231dd8d81cc") (hexstring_hashval "43bffa47d33d3351f9a01602835d114662f93783aec1f86f5a67af5d8412eb99");;
Hashtbl.add mgrootassoc (hexstring_hashval "21043bfe96f4dd260d43acf312ddc620d72380bb200d8964d2e48ed20d24a035") (hexstring_hashval "b17eb6af7aa4617931c9615a7364c3569b31f15b8b2be887e7fdf9badc8233aa");;
Hashtbl.add mgrootassoc (hexstring_hashval "89516cb6526b30e3bc47b049b1bc0f9e4597d00f3cc04dfd664319d596702ea1") (hexstring_hashval "34d7281a94b25b3f967cf580c5d7460c809a7d1773c12a24f0462718fcb16497");;
Hashtbl.add mgrootassoc (hexstring_hashval "8df5963f09ee56878fcd1721c2a6b6d85923ec76837de3fcb1475b38e7950836") (hexstring_hashval "0a3ef2ada763be6ad4715f754378644a116f0425cc512cca42d557bef370bc82");;
Hashtbl.add mgrootassoc (hexstring_hashval "448f520ff0fcea08b45c8008bb1bcd0cbfe2bc4aa4c781ff4ef609913102c76d") (hexstring_hashval "c50ac166524e3a0d5b6cbf6bbe63d2fef925de37e83a88d0421cf3b4e36c557e");;
Hashtbl.add mgrootassoc (hexstring_hashval "953e3e515ad08a798e7b709ccd8b0b0b72bef9885b73df52b282277033ff10b7") (hexstring_hashval "656fb5759c216079c715bdde6aae12d605d2cdb4674ee7d6acf5fb7e80a7215c");;
Hashtbl.add mgrootassoc (hexstring_hashval "e4c408921a783c09fddc92ef0ced73b5275a3226c25013abdac69c9d3f45eb9e") (hexstring_hashval "01be3dcd489c8e287fcd3a12d7206895f21d2c0bb962adcc70119c9e0f7e1e18");;
Hashtbl.add mgrootassoc (hexstring_hashval "344c04a8dc99cbd652cc7bb39079338374d367179e2b0a8ef0f259d7f24cecbf") (hexstring_hashval "8ed37c1af3aa4c34701bdc05dc70d9cff872020ede24370792b71aafc1a4c346");;
Hashtbl.add mgrootassoc (hexstring_hashval "8f006ff8d9191047d4fbd1bd8991167e1e29662de1be89f969121efe0697f534") (hexstring_hashval "dbcd9174a6cf85c5c53371cfe053393987371d6f5cf8eba63c30b99749b79bb8");;
Hashtbl.add mgrootassoc (hexstring_hashval "78a3304952070979d83ccc1dcdd6a714eaa8a23528a717619f46db81dab1b370") (hexstring_hashval "73ee7ba9707457f40d011b81c7652140f63595c4412ae3e192184cad52938e9e");;
Hashtbl.add mgrootassoc (hexstring_hashval "23993eac63f1f42057c0efc20dd50b3e0b0121cccf3b7ad419eacb85ac09a4d4") (hexstring_hashval "587ac67fa53cfb7918e883326c97d406c8dcb17938eed2ad92b4e5cb4a1b88aa");;
Hashtbl.add mgrootassoc (hexstring_hashval "471876e0ce0238e7e357dc909e9edc26836fc98c4a9d31c4a5dca4903c33f243") (hexstring_hashval "6e82609d929cbf65d37ac5c9a63327bfc218bf48484ccd1c1a92959708684c1f");;
Hashtbl.add mgrootassoc (hexstring_hashval "5723e1bd9769bdc20e653c6593cab5981c06326be07adf7b67065825803f072d") (hexstring_hashval "3bb85a0e759e20dfb0ccbf91dc0e4a0cc2ae61cef5f0cf348e012d671b9c6851");;
Hashtbl.add mgrootassoc (hexstring_hashval "4ddf969f8959eaa958bf7ffd170b5c201116b0dede4e32eb7f39735e9d390d37") (hexstring_hashval "bcab47b2b3d713d80a55ef4b19ca509fea59a061bd4003d15c0d26c951ab04f9");;
Hashtbl.add mgrootassoc (hexstring_hashval "2a50602e0a09f647d85d3e0968b772706a7501d07652bb47048c29a7df10757a") (hexstring_hashval "45876439a0ebffabe974dfc224bfb5fcf7cdefbe1842d969001ec0615838c25b");;
Hashtbl.add mgrootassoc (hexstring_hashval "ab34eea44c60018e5f975d4318c2d3e52e1a34eb29f14ca15ff8cefeb958c494") (hexstring_hashval "c28a4cc056045e49139215cfe5c8d969033f574528ca9155b0d4b2645f0bfb5c");;
Hashtbl.add mgrootassoc (hexstring_hashval "02709d69b879f00cff710051a82db11b456805f2bfe835c5d14f8c542276ac60") (hexstring_hashval "2198544dc93adcfb7a0840e80ac836eba8457b7bbb3ccbbb3bc46e9112667304");;
Hashtbl.add mgrootassoc (hexstring_hashval "dabe1f95706bff9070b574624aec00bcc50706d76fd50e4a3929fd40311a5efa") (hexstring_hashval "d20c7898f6bed20c2c5c2498f5ac0756d84e8e11ea47f6b6e0b8ca2759026026");;
Hashtbl.add mgrootassoc (hexstring_hashval "eb5db5f738ad7aa7a16e5fd9f1201ca51305373920f987771a6afffbc5cda3de") (hexstring_hashval "f4d68b947c391fb202fb8df5218ea17bcff67d9bbb507885bfc603a34fd5f054");;
Hashtbl.add mgrootassoc (hexstring_hashval "e73271112c979d5c0e9c9345f7d93a63015c1e7231d69df1ea1f24bf25f50380") (hexstring_hashval "f0613075cf2c8e12b3b9b185e03d97ed180930a161841752b5dd6458da73341b");;
Hashtbl.add mgrootassoc (hexstring_hashval "d09d227a13baf82dd9fb97506200eec56009ace6e9b5e539a544c04594b1dd10") (hexstring_hashval "d674aae9b36429b77aa0beac613e8e3128541a54504e9f2add615405e55adb13");;
Hashtbl.add mgrootassoc (hexstring_hashval "e4c128d492933589c3cc92b565612fcec0e08141b66eea664bfaaeae59632b46") (hexstring_hashval "70b68c440811243759b8b58f10e212c73c46e3d1fee29b1b7f1e5816ea8880f0");;
Hashtbl.add mgrootassoc (hexstring_hashval "a3f36bad79e57c9081031632e8600480e309d3c9330d5a15f3c8b4bec7c2d772") (hexstring_hashval "19018c380b66420394ca729649acf033fd428b60774d2c01e275f9300c6ad13c");;
Hashtbl.add mgrootassoc (hexstring_hashval "37ac57f65c41941ca2aaa13955e9b49dc6219c2d1d3c6aed472a28f60f59fed4") (hexstring_hashval "813c91891171c9e2ebc16f745a3c38ce142f3eed6b33e907b14dc15dc3732841");;
Hashtbl.add mgrootassoc (hexstring_hashval "83e7e1dec223e576ffbd3a4af6d06d926c88390b6b4bbe5f6d4db16b20975198") (hexstring_hashval "ae1e1b0c86cebae1f9b3a1770183528d91f067a075ed4218d4359926c8bac5ac");;
Hashtbl.add mgrootassoc (hexstring_hashval "5c3986ee4332ef315b83ef53491e4d2cb38a7ed52b7a33b70161ca6a48b17c87") (hexstring_hashval "4fe2c39e67b687a4cffa0d8bc17cabdfec622da8c39b788b83deb466e6dddfaa");;
Hashtbl.add mgrootassoc (hexstring_hashval "4daffb669546d65312481b5f945330815f8f5c460c7278516e497b08a82751e5") (hexstring_hashval "8062568df0fbf4a27ab540f671ff8299e7069e28c0a2a74bd26c0cb9b3ed98fb");;
Hashtbl.add mgrootassoc (hexstring_hashval "f81b3934a73154a8595135f10d1564b0719278d3976cc83da7fda60151d770da") (hexstring_hashval "5867641425602c707eaecd5be95229f6fd709c9b58d50af108dfe27cb49ac069");;
Hashtbl.add mgrootassoc (hexstring_hashval "1db7057b60c1ceb81172de1c3ba2207a1a8928e814b31ea13b9525be180f05af") (hexstring_hashval "5bf697cb0d1cdefbe881504469f6c48cc388994115b82514dfc4fb5e67ac1a87");;
Hashtbl.add mgrootassoc (hexstring_hashval "f30435b6080d786f27e1adaca219d7927ddce994708aacaf4856c5b701fe9fa1") (hexstring_hashval "058f630dd89cad5a22daa56e097e3bdf85ce16ebd3dbf7994e404e2a98800f7f");;
Hashtbl.add mgrootassoc (hexstring_hashval "2ba7d093d496c0f2909a6e2ea3b2e4a943a97740d27d15003a815d25340b379a") (hexstring_hashval "87fba1d2da67f06ec37e7ab47c3ef935ef8137209b42e40205afb5afd835b738");;
Hashtbl.add mgrootassoc (hexstring_hashval "9577468199161470abc0815b6a25e03706a4e61d5e628c203bf1f793606b1153") (hexstring_hashval "cfe97741543f37f0262568fe55abbab5772999079ff734a49f37ed123e4363d7");;
Hashtbl.add mgrootassoc (hexstring_hashval "98aaaf225067eca7b3f9af03e4905bbbf48fc0ccbe2b4777422caed3e8d4dfb9") (hexstring_hashval "9c60bab687728bc4482e12da2b08b8dbc10f5d71f5cab91acec3c00a79b335a3");;
Hashtbl.add mgrootassoc (hexstring_hashval "81c0efe6636cef7bc8041820a3ebc8dc5fa3bc816854d8b7f507e30425fc1cef") (hexstring_hashval "8a8e36b858cd07fc5e5f164d8075dc68a88221ed1e4c9f28dac4a6fdb2172e87");;
Hashtbl.add mgrootassoc (hexstring_hashval "538bb76a522dc0736106c2b620bfc2d628d5ec8a27fe62fc505e3a0cdb60a5a2") (hexstring_hashval "e7493d5f5a73b6cb40310f6fcb87d02b2965921a25ab96d312adf7eb8157e4b3");;
Hashtbl.add mgrootassoc (hexstring_hashval "57561da78767379e0c78b7935a6858f63c7c4be20fe81fe487471b6f2b30c085") (hexstring_hashval "54850182033d0575e98bc2b12aa8b9baaa7a541e9d5abc7fddeb74fc5d0a19ac");;
Hashtbl.add mgrootassoc (hexstring_hashval "8b9cc0777a4e6a47a5191b7e6b041943fe822daffc2eb14f3a7baec83fa16020") (hexstring_hashval "5a811b601343da9ff9d05d188d672be567de94b980bbbe0e04e628d817f4c7ac");;
Hashtbl.add mgrootassoc (hexstring_hashval "5574bbcac2e27d8e3345e1dc66374aa209740ff86c1db14104bc6c6129aee558") (hexstring_hashval "962d14a92fc8c61bb8319f6fe1508fa2dfbe404fd3a3766ebce0c6db17eeeaa1");;
Hashtbl.add mgrootassoc (hexstring_hashval "1bd4aa0ec0b5e627dce9a8a1ddae929e58109ccbb6f4bb3d08614abf740280c0") (hexstring_hashval "43f34d6a2314b56cb12bf5cf84f271f3f02a3e68417b09404cc73152523dbfa0");;
Hashtbl.add mgrootassoc (hexstring_hashval "36808cca33f2b3819497d3a1f10fcc77486a0cddbcb304e44cbf2d818e181c3e") (hexstring_hashval "2f8b7f287504f141b0f821928ac62823a377717763a224067702eee02fc1f359");;
Hashtbl.add mgrootassoc (hexstring_hashval "1f3a09356e470bff37ef2408148f440357b92f92f9a27c828b37d777eb41ddc6") (hexstring_hashval "153bff87325a9c7569e721334015eeaf79acf75a785b960eb1b46ee9a5f023f8");;
Hashtbl.add mgrootassoc (hexstring_hashval "458be3a74fef41541068991d6ed4034dc3b5e637179369954ba21f6dff4448e4") (hexstring_hashval "25c483dc8509e17d4b6cf67c5b94c2b3f3902a45c3c34582da3e29ab1dc633ab");;
Hashtbl.add mgrootassoc (hexstring_hashval "ee28d96500ca4c012f9306ed26fad3b20524e7a89f9ac3210c88be4e6a7aed23") (hexstring_hashval "dab6e51db9653e58783a3fde73d4f2dc2637891208c92c998709e8795ba4326f");;
Hashtbl.add mgrootassoc (hexstring_hashval "264b04a8ece7fd74ec4abb7dd2111104a2e6cde7f392363afe4acca8d5faa416") (hexstring_hashval "2ce94583b11dd10923fde2a0e16d5b0b24ef079ca98253fdbce2d78acdd63e6e");;
Hashtbl.add mgrootassoc (hexstring_hashval "4b68e472ec71f7c8cd275af0606dbbc2f78778d7cbcc9491f000ebf01bcd894c") (hexstring_hashval "2be3caddae434ec70b82fad7b2b6379b3dfb1775433420e56919db4d17507425");;
Hashtbl.add mgrootassoc (hexstring_hashval "76bef6a46d22f680befbd3f5ca179f517fb6d2798abc5cd2ebbbc8753d137948") (hexstring_hashval "b2487cac08f5762d6b201f12df6bd1872b979a4baefc5f637987e633ae46675d");;
Hashtbl.add mgrootassoc (hexstring_hashval "9bb9c2b375cb29534fc7413011613fb9ae940d1603e3c4bebd1b23c164c0c6f7") (hexstring_hashval "6f4d9bb1b2eaccdca0b575e1c5e5a35eca5ce1511aa156bebf7a824f08d1d69d");;
Hashtbl.add mgrootassoc (hexstring_hashval "eb44199255e899126f4cd0bbf8cf2f5222a90aa4da547822cd6d81c671587877") (hexstring_hashval "5719b3150f582144388b11e7da6c992f73c9f410c816893fdc1019f1b12097e0");;
Hashtbl.add mgrootassoc (hexstring_hashval "04632dc85b4cfa9259234453a2464a187d6dfd480455b14e1e0793500164a7e3") (hexstring_hashval "0498e68493e445a8fce3569ba778f96fe83f914d7905473f18fe1fee01869f5f");;
Hashtbl.add mgrootassoc (hexstring_hashval "313e7b5980d710cf22f2429583d0c3b8404586d75758ffcab45219ac373fbc58") (hexstring_hashval "7b21e4abd94d496fba9bd902c949754d45c46d1896ef4a724d6867561c7055ed");;
Hashtbl.add mgrootassoc (hexstring_hashval "ea71e0a1be5437cf5b03cea5fe0e2b3f947897def4697ae7599a73137f27d0ee") (hexstring_hashval "f275e97bd8920540d5c9b32de07f69f373d6f93ba6892c9e346254a85620fa17");;
Hashtbl.add mgrootassoc (hexstring_hashval "615c0ac7fca2b62596ed34285f29a77b39225d1deed75d43b7ae87c33ba37083") (hexstring_hashval "322bf09a1711d51a4512e112e1767cb2616a7708dc89d7312c8064cfee6e3315");;
Hashtbl.add mgrootassoc (hexstring_hashval "6a6dea288859e3f6bb58a32cace37ed96c35bdf6b0275b74982b243122972933") (hexstring_hashval "161886ed663bc514c81ed7fe836cca71861bfe4dfe4e3ede7ef3a48dbc07d247");;
Hashtbl.add mgrootassoc (hexstring_hashval "e2ea25bb1daaa6f56c9574c322ff417600093f1fea156f5efdcbe4a9b87e9dcf") (hexstring_hashval "3e5bc5e85f7552688ed0ced52c5cb8a931e179c99646161ada3249216c657566");;
Hashtbl.add mgrootassoc (hexstring_hashval "309408a91949b0fa15f2c3f34cdd5ff57cd98bb5f49b64e42eb97b4bf1ab623b") (hexstring_hashval "591ebe2d703dc011fd95f000dd1ad77b0dca9230146d2f3ea2cb96d6d1fba074");;
Hashtbl.add mgrootassoc (hexstring_hashval "9a8a2beac3ecd759aebd5e91d3859dec6be35a41ec07f9aba583fb9c33b40fbe") (hexstring_hashval "e66ec047c09acdc1e824084ea640c5c9a30ab00242f4c1f80b83c667c930e87e");;
Hashtbl.add mgrootassoc (hexstring_hashval "b145249bb4b36907159289e3a9066e31e94dfa5bb943fc63ff6d6ca9abab9e02") (hexstring_hashval "8f39e0d849db8334a6b514454a2aef6235afa9fc2b6ae44712b4bfcd7ac389cc");;
Hashtbl.add mgrootassoc (hexstring_hashval "25d55803878b7ce4c199607568d5250ff00ee63629e243e2a1fd20966a3ee92c") (hexstring_hashval "0609dddba15230f51d1686b31544ff39d4854c4d7f71062511cc07689729b68d");;
Hashtbl.add mgrootassoc (hexstring_hashval "5754c55c5ad43b5eaeb1fb67971026c82f41fd52267a380d6f2bb8487e4e959b") (hexstring_hashval "4a0f686cd7e2f152f8da5616b417a9f7c3b6867397c9abde39031fa0217d2692");;
Hashtbl.add mgrootassoc (hexstring_hashval "9db35ff1491b528184e71402ab4646334daef44c462a5c04ab2c952037a84f3f") (hexstring_hashval "4267a4cfb6e147a3c1aa1c9539bd651e22817ab41fd8ab5d535fbf437db49145");;
Hashtbl.add mgrootassoc (hexstring_hashval "cc2c175bc9d6b3633a1f1084c35556110b83d269ebee07a3df3f71e3af4f8338") (hexstring_hashval "f3818d36710e8c0117c589ed2d631e086f82fbcbf323e45d2b12a4eaddd3dd85");;
Hashtbl.add mgrootassoc (hexstring_hashval "406b89b059127ed670c6985bd5f9a204a2d3bc3bdc624694c06119811f439421") (hexstring_hashval "5057825a2357ee2306c9491a856bb7fc4f44cf9790262abb72d8cecde03e3df4");;
Hashtbl.add mgrootassoc (hexstring_hashval "0e5ab00c10f017772d0d2cc2208e71a537fa4599590204be721685b72b5d213f") (hexstring_hashval "f3976896fb7038c2dd6ace65ec3cce7244df6bf443bacb131ad83c3b4d8f71fb");;
Hashtbl.add mgrootassoc (hexstring_hashval "ee5d8d94a19e756967ad78f3921cd249bb4aefc510ede4b798f8aa02c5087dfa") (hexstring_hashval "35f61b92f0d8ab66d988b2e71c90018e65fc9425895b3bae5d40ddd5e59bebc1");;
Hashtbl.add mgrootassoc (hexstring_hashval "42a3bcd22900658b0ec7c4bbc765649ccf2b1b5641760fc62cf8a6a6220cbc47") (hexstring_hashval "b90ec130fa720a21f6a1c02e8b258f65af5e099282fe8b3927313db7f25335ed");;
Hashtbl.add mgrootassoc (hexstring_hashval "71bff9a6ef1b13bbb1d24f9665cde6df41325f634491be19e3910bc2e308fa29") (hexstring_hashval "4c63a643ae50cae1559d755c98f03a6bb6c38ac5a6dec816459b5b59516ceebc");;
Hashtbl.add mgrootassoc (hexstring_hashval "e5853602d8dd42d777476c1c7de48c7bfc9c98bfa80a1e39744021305a32f462") (hexstring_hashval "afc9288c444053edafe3dc23515d8286b3757842ec5b64ed89433bbd5ca5f5fd");;
Hashtbl.add mgrootassoc (hexstring_hashval "3be1c5f3e403e02caebeaf6a2b30d019be74b996581a62908316c01702a459df") (hexstring_hashval "9161ec45669e68b6f032fc9d4d59e7cf0b3f5f860baeb243e29e767a69d600b1");;
Hashtbl.add mgrootassoc (hexstring_hashval "afa8ae66d018824f39cfa44fb10fe583334a7b9375ac09f92d622a4833578d1a") (hexstring_hashval "e4d45122168d3fb3f5723ffffe4d368988a1be62792f272e949c6728cec97865");;
Hashtbl.add mgrootassoc (hexstring_hashval "35a1ef539d3e67ef8257da2bd992638cf1225c34d637bc7d8b45cf51e0445d80") (hexstring_hashval "7a45b2539da964752f7e9409114da7fc18caef138c5d0699ec226407ece64991");;
Hashtbl.add mgrootassoc (hexstring_hashval "1b17d5d9c9e2b97e6f95ec4a022074e74b8cde3e5a8d49b62225063d44e67f4f") (hexstring_hashval "d4edc81b103a7f8386389b4214215e09786f1c39c399dd0cc78b51305ee606ce");;
Hashtbl.add mgrootassoc (hexstring_hashval "729ee87b361f57aed9acd8e4cdffcb3b80c01378d2410a0dabcf2c08b759e074") (hexstring_hashval "894d319b8678a53d5ba0debfa7c31b2615043dbd1e2916815fe1b2e94b3bb6c4");;
Hashtbl.add mgrootassoc (hexstring_hashval "73e637446290a3810d64d64adc8380f0b3951e89a2162b4055f67b396b230371") (hexstring_hashval "f46477c44dcfe374993facabf649272a115d5e757dd2941d7747f2318d2c7508");;
Hashtbl.add mgrootassoc (hexstring_hashval "37c5310c8da5c9f9db9152285b742d487f1a5b1bd7c73a4207d40bcd4f4d13fb") (hexstring_hashval "4ce015b98f266293ef85ef9898e1d8f66f4d9664bd9601197410d96354105016");;
Hashtbl.add mgrootassoc (hexstring_hashval "1725096a59f3309a3f55cd24aaa2e28224213db0f2d4e34a9d3e5f9741529a68") (hexstring_hashval "c758296e4891fbb62efb32bda417ae34bed1e02445864c8b4d39d5939b0b1155");;
Hashtbl.add mgrootassoc (hexstring_hashval "8358baafa9517c0278f00333f8801296b6383390ea4814caaadcff0dec35238d") (hexstring_hashval "01785692f7c1817cb9f3d1d48f63b046656276ec0216ce08c9e0f64a287359ad");;
Hashtbl.add mgrootassoc (hexstring_hashval "ff333a6e581c2606ed46db99bd40bdd3a1bab9a80526a0741eba5bddd37e1bba") (hexstring_hashval "6c35cb0ee031168df375090511d1596b9b36a05385e339fda705a0e2d77fc3fc");;
Hashtbl.add mgrootassoc (hexstring_hashval "8f0026627bca968c807e91fff0fdc318bc60691e5ae497542f92c8e85be9fd7d") (hexstring_hashval "fb5286197ee583bb87a6f052d00fee2b461d328cc4202e5fb40ec0a927da5d7e");;
Hashtbl.add mgrootassoc (hexstring_hashval "8143218ffde429ff34b20ee5c938914c75e40d59cd52cc5db4114971d231ca73") (hexstring_hashval "3585d194ae078f7450f400b4043a7820330f482343edc5773d1d72492da8d168");;
Hashtbl.add mgrootassoc (hexstring_hashval "f202c1f30355001f3665c854acb4fdae117f5ac555d2616236548c8309e59026") (hexstring_hashval "d3f7df13cbeb228811efe8a7c7fce2918025a8321cdfe4521523dc066cca9376");;
Hashtbl.add mgrootassoc (hexstring_hashval "afe37e3e9df1ab0b3a1c5daa589ec6a68c18bf14b3d81364ac41e1812672537a") (hexstring_hashval "b260cb5327df5c1f762d4d3068ddb3c7cc96a9cccf7c89cee6abe113920d16f1");;
Hashtbl.add mgrootassoc (hexstring_hashval "ccac4354446ce449bb1c967fa332cdf48b070fc032d9733e4c1305fb864cb72a") (hexstring_hashval "f0267e2cbae501ea3433aecadbe197ba8f39c96e80326cc5981a1630fda29909");;
Hashtbl.add mgrootassoc (hexstring_hashval "21a4888a1d196a26c9a88401c9f2b73d991cc569a069532cb5b119c4538a99d7") (hexstring_hashval "877ee30615a1a7b24a60726a1cf1bff24d7049b80efb464ad22a6a9c9c4f6738");;
Hashtbl.add mgrootassoc (hexstring_hashval "7aba21bd28932bfdd0b1a640f09b1b836264d10ccbba50d568dea8389d2f8c9d") (hexstring_hashval "dc75c4d622b258b96498f307f3988491e6ba09fbf1db56d36317e5c18aa5cac6");;
Hashtbl.add mgrootassoc (hexstring_hashval "8acbb2b5de4ab265344d713b111d82b0048c8a4bf732a67ad35f1054a4eb4642") (hexstring_hashval "93592da87a6f2da9f7eb0fbd449e0dc4730682572e0685b6a799ae16c236dcae");;
Hashtbl.add mgrootassoc (hexstring_hashval "fc0b600a21afd76820f1fb74092d9aa81687f3b0199e9b493dafd3e283c6e8ca") (hexstring_hashval "ecef5cea93b11859a42b1ea5e8a89184202761217017f3a5cdce1b91d10b34a7");;
Hashtbl.add mgrootassoc (hexstring_hashval "c7aaa670ef9b6f678b8cf10b13b2571e4dc1e6fde061d1f641a5fa6c30c09d46") (hexstring_hashval "58c1782da006f2fb2849c53d5d8425049fad551eb4f8025055d260f0c9e1fe40");;
Hashtbl.add mgrootassoc (hexstring_hashval "ade2bb455de320054265fc5dccac77731c4aa2464b054286194d634707d2e120") (hexstring_hashval "dac986a57e8eb6cc7f35dc0ecc031b9ba0403416fabe2dbe130edd287a499231");;
Hashtbl.add mgrootassoc (hexstring_hashval "83d48a514448966e1b5b259c5f356357f149bf0184a37feae52fc80d5e8083e5") (hexstring_hashval "091d1f35158d5ca6063f3c5949e5cbe3d3a06904220214c5781c49406695af84");;
Hashtbl.add mgrootassoc (hexstring_hashval "40f1c38f975e69e2ae664b3395551df5820b0ba6a93a228eba771fc2a4551293") (hexstring_hashval "8ab5fa18b3cb4b4b313a431cc37bdd987f036cc47f175379215f69af5977eb3b");;
Hashtbl.add mgrootassoc (hexstring_hashval "1de7fcfb8d27df15536f5567084f73d70d2b8526ee5d05012e7c9722ec76a8a6") (hexstring_hashval "fcd77a77362d494f90954f299ee3eb7d4273ae93d2d776186c885fc95baa40dc");;
Hashtbl.add mgrootassoc (hexstring_hashval "b86d403403efb36530cd2adfbcacc86b2c6986a54e80eb4305bfdd0e0b457810") (hexstring_hashval "0775ebd23cf37a46c4b7bc450bd56bce8fc0e7a179485eb4384564c09a44b00f");;
Hashtbl.add mgrootassoc (hexstring_hashval "f0b1c15b686d1aa6492d7e76874c7afc5cd026a88ebdb352e9d7f0867f39d916") (hexstring_hashval "04c0176f465abbde82b7c5c716ac86c00f1b147c306ffc6b691b3a5e8503e295");;
Hashtbl.add mgrootassoc (hexstring_hashval "f73bdcf4eeb9bdb2b6f83670b8a2e4309a4526044d548f7bfef687cb949027eb") (hexstring_hashval "dc7715ab5114510bba61a47bb1b563d5ab4bbc08004208d43961cf61a850b8b5");;
Hashtbl.add mgrootassoc (hexstring_hashval "8acbb2b5de4ab265344d713b111d82b0048c8a4bf732a67ad35f1054a4eb4642") (hexstring_hashval "93592da87a6f2da9f7eb0fbd449e0dc4730682572e0685b6a799ae16c236dcae");;
Hashtbl.add mgrootassoc (hexstring_hashval "c7aaa670ef9b6f678b8cf10b13b2571e4dc1e6fde061d1f641a5fa6c30c09d46") (hexstring_hashval "58c1782da006f2fb2849c53d5d8425049fad551eb4f8025055d260f0c9e1fe40");;
Hashtbl.add mgrootassoc (hexstring_hashval "4c89a6c736b15453d749c576f63559855d72931c3c7513c44e12ce14882d2fa7") (hexstring_hashval "21324eab171ba1d7a41ca9f7ad87272b72d2982da5848b0cef9a7fe7653388ad");;
Hashtbl.add mgrootassoc (hexstring_hashval "1024fb6c1c39aaae4a36f455b998b6ed0405d12e967bf5eae211141970ffa4fa") (hexstring_hashval "86e649daaa54cc94337666c48155bcb9c8d8f416ab6625b9c91601b52ce66901");;
Hashtbl.add mgrootassoc (hexstring_hashval "f336a4ec8d55185095e45a638507748bac5384e04e0c48d008e4f6a9653e9c44") (hexstring_hashval "f7e63d81e8f98ac9bc7864e0b01f93952ef3b0cbf9777abab27bcbd743b6b079");;
Hashtbl.add mgrootassoc (hexstring_hashval "02231a320843b92b212e53844c7e20e84a5114f2609e0ccf1fe173603ec3af98") (hexstring_hashval "0bdf234a937a0270a819b1abf81040a3cc263b2f1071023dfbe2d9271ad618af");;
Hashtbl.add mgrootassoc (hexstring_hashval "17bc9f7081d26ba5939127ec0eef23162cf5bbe34ceeb18f41b091639dd2d108") (hexstring_hashval "b1fb9de059c4e510b136e3f2b3833e9b6a459da341bf14d8c0591abe625c04aa");;
Hashtbl.add mgrootassoc (hexstring_hashval "f2f91589fb6488dd2bad3cebb9f65a57b7d7f3818091dcc789edd28f5d0ef2af") (hexstring_hashval "e25e4327c67053c3d99245dbaf92fdb3e5247e754bd6d8291f39ac34b6d57820");;
Hashtbl.add mgrootassoc (hexstring_hashval "02824c8d211e3e78d6ae93d4f25c198a734a5de114367ff490b2821787a620fc") (hexstring_hashval "fbf1e367dd7bcf308e6386d84b0be4638eb2a000229a92ad9993ce40104edbe7");;
Hashtbl.add mgrootassoc (hexstring_hashval "47a1eff65bbadf7400d8f2532141a437990ed7a8581fea1db023c7edd06be32c") (hexstring_hashval "0ba7fb67bc84cc62e2c8c6fbe525891c5ba5b449d1d79661cc48ec090122f3cf");;
Hashtbl.add mgrootassoc (hexstring_hashval "d7d95919a06c44c69c724884cd5a474ea8f909ef85aae19ffe4a0ce816fa65fd") (hexstring_hashval "ac96e86902ef72d5c44622f4a1ba3aaf673377d32cc26993c04167cc9f22067f");;
Hashtbl.add mgrootassoc (hexstring_hashval "34de6890338f9d9b31248bc435dc2a49c6bfcd181e0b5e3a42fbb5ad769ab00d") (hexstring_hashval "f36b5131fd375930d531d698d26ac2fc4552d148f386caa7d27dbce902085320");;
Hashtbl.add mgrootassoc (hexstring_hashval "ac6311a95e065816a2b72527ee3a36906afc6b6afb8e67199361afdfc9fe02e2") (hexstring_hashval "f91c31af54bc4bb4f184b6de34d1e557a26e2d1c9f3c78c2b12be5ff6d66df66");;
Hashtbl.add mgrootassoc (hexstring_hashval "93dab1759b565d776b57c189469214464808cc9addcaa28b2dbde0d0a447f94d") (hexstring_hashval "e59af381b17c6d7665103fc55f99405c91c5565fece1832a6697045a1714a27a");;
Hashtbl.add mgrootassoc (hexstring_hashval "5437127f164b188246374ad81d6b61421533c41b1be66692fb93fdb0130e8664") (hexstring_hashval "eb5699f1770673cc0c3bfaa04e50f2b8554934a9cbd6ee4e9510f57bd9e88b67");;
Hashtbl.add mgrootassoc (hexstring_hashval "ae448bdfa570b11d4a656e4d758bc6703d7f329c6769a116440eb5cde2a99f6f") (hexstring_hashval "8b40c8c4336d982e6282a1024322e7d9333f9d2c5cf49044df61ef6c36e6b13d");;
Hashtbl.add mgrootassoc (hexstring_hashval "dc1665d67ed9f420c2da68afc3e3be02ee1563d2525cbd6ab7412038cd80aaec") (hexstring_hashval "e3c1352956e5bf2eaee279f30cd72331033b9bd8d92b7ea676e3690a9a8ff39a");;
Hashtbl.add mgrootassoc (hexstring_hashval "e5a4b6b2a117c6031cd7d2972902a228ec0cc0ab2de468df11b22948daf56892") (hexstring_hashval "bc8218c25b0a9da87c5c86b122421e1e9bb49d62b1a2ef19c972e04205dda286");;
Hashtbl.add mgrootassoc (hexstring_hashval "64ce9962d0a17b3b694666ef1fda22a8c5635c61382ad7ae5a322890710bc5f8") (hexstring_hashval "59afcfba9fdd03aeaf46e2c6e78357750119f49ceee909d654321be1842de7c6");;
Hashtbl.add mgrootassoc (hexstring_hashval "23c9d918742fceee39b9ee6e272d5bdd5f6dd40c5c6f75acb478f608b6795625") (hexstring_hashval "c12e8ab3e6933c137bb7f6da0ea861e26e38083cba3ed9d95d465030f8532067");;
Hashtbl.add mgrootassoc (hexstring_hashval "217d179d323c5488315ded19cb0c9352416c9344bfdfbb19613a3ee29afb980d") (hexstring_hashval "78a3bf7ecddc538557453ade96e29b8ff44a970ec9a42fd661f64160ff971930");;
Hashtbl.add mgrootassoc (hexstring_hashval "009fa745aa118f0d9b24ab4efbc4dc3a4560082e0d975fd74526e3c4d6d1511f") (hexstring_hashval "41a47127fd3674a251aaf14f866ade125c56dc72c68d082b8759d4c3e687b4fd");;
Hashtbl.add mgrootassoc (hexstring_hashval "6913bd802b6ead043221cf6994931f83418bb29a379dc6f65a313e7daa830dcc") (hexstring_hashval "23550cc9acffc87f322ad317d1c98641dca02e97c9cac67a1860a4c64d0825fe");;
Hashtbl.add mgrootassoc (hexstring_hashval "87fac4547027c0dfeffbe22b750fcc4ce9638e0ae321aeaa99144ce5a5a6de3e") (hexstring_hashval "7401799183ed959352a65e49de9fe60e8cc9f883b777b9f6486f987bc305367b");;
Hashtbl.add mgrootassoc (hexstring_hashval "ee97f6fc35369c0aa0ddf247ea2ee871ae4efd862b662820df5edcc2283ba7e3") (hexstring_hashval "69ce10766e911ed54fa1fda563f82aefcfba7402ed6fd8d3b9c63c00157b1758");;
Hashtbl.add mgrootassoc (hexstring_hashval "0711e2a692a3c2bdc384654882d1195242a019a3fc5d1a73dba563c4291fc08b") (hexstring_hashval "8050b18a682b443263cb27b578f9d8f089d2bc989740edf6ac729e91f5f46f64");;
Hashtbl.add mgrootassoc (hexstring_hashval "1f6dc5b1a612afebee904f9acd1772cd31ab0f61111d3f74cfbfb91c82cfc729") (hexstring_hashval "d3592c771464826c60ca07f5375f571afb7698968b3356c8660f76cd4df7f9c6");;
Hashtbl.add mgrootassoc (hexstring_hashval "d272c756dc639d0c36828bd42543cc2a0d93082c0cbbe41ca2064f1cff38c130") (hexstring_hashval "2bbc4c092e4068224ebeab631b4f771854c9e79f5e4e099a03bd86720a30e782");;
Hashtbl.add mgrootassoc (hexstring_hashval "ff28d9a140c8b282282ead76a2a40763c4c4800ebff15a4502f32af6282a3d2e") (hexstring_hashval "532306fb5aa1dc9d3b05443f5276a279750222d4115d4e3e9e0b1acc505bbb99");;
Hashtbl.add mgrootassoc (hexstring_hashval "c0ec73850ee5ffe522788630e90a685ec9dc80b04347c892d62880c5e108ba10") (hexstring_hashval "1e55e667ef0bb79beeaf1a09548d003a4ce4f951cd8eb679eb1fed9bde85b91c");;
Hashtbl.add mgrootassoc (hexstring_hashval "4ab7e4afd8b51df80f04ef3dd42ae08c530697f7926635e26c92eb55ae427224") (hexstring_hashval "3bbf071b189275f9b1ce422c67c30b34c127fdb067b3c9b4436b02cfbe125351");;
Hashtbl.add mgrootassoc (hexstring_hashval "3657ae18f6f8c496bec0bc584e1a5f49a6ce4e6db74d7a924f85da1c10e2722d") (hexstring_hashval "89e534b3d5ad303c952b3eac3b2b69eb72d95ba1d9552659f81c57725fc03350");;
Hashtbl.add mgrootassoc (hexstring_hashval "5f11e279df04942220c983366e2a199b437dc705dac74495e76bc3123778dd86") (hexstring_hashval "6f17daea88196a4c038cd716092bd8ddbb3eb8bddddfdc19e65574f30c97ab87");;
Hashtbl.add mgrootassoc (hexstring_hashval "0c801be26da5c0527e04f5b1962551a552dab2d2643327b86105925953cf3b06") (hexstring_hashval "42f58f2a7ea537e615b65875895df2f1fc42b140b7652f8ea8e9c6893053be73");;
Hashtbl.add mgrootassoc (hexstring_hashval "46e7ed0ee512360f08f5e5f9fc40a934ff27cfd0c79d3c2384e6fb16d461bd95") (hexstring_hashval "0d574978cbb344ec3744139d5c1d0d90336d38f956e09a904d230c4fa06b30d1");;
Hashtbl.add mgrootassoc (hexstring_hashval "ddf7d378c4df6fcdf73e416f8d4c08965e38e50abe1463a0312048d3dd7ac7e9") (hexstring_hashval "09cdd0b9af76352f6b30bf3c4bca346eaa03d280255f13afb2e73fe8329098b6");;
Hashtbl.add mgrootassoc (hexstring_hashval "ec849efeaf83b2fcdbc828ebb9af38820604ea420adf2ef07bb54a73d0fcb75b") (hexstring_hashval "0e3071dce24dfee0112b8d48d9e9fc53f835e6a5b50de4c25d1dfd053ad33bf1");;
Hashtbl.add mgrootassoc (hexstring_hashval "c083d829a4633f1bc9aeab80859255a8d126d7c6824bf5fd520d6daabfbbe976") (hexstring_hashval "b102ccc5bf572aba76b2c5ff3851795ba59cb16151277dbee9ce5a1aad694334");;
Hashtbl.add mgrootassoc (hexstring_hashval "d5069aa583583f8fbe5d4de1ba560cc89ea048cae55ea56270ec3dea15e52ca0") (hexstring_hashval "7df1da8a4be89c3e696aebe0cabd8b8f51f0c9e350e3396209ee4a31203ddcab");;
Hashtbl.add mgrootassoc (hexstring_hashval "8cd812b65c6c466abea8433d21a39d35b8d8427ee973f9bb93567a1402705384") (hexstring_hashval "08c87b1a5ce6404b103275d893aba544e498d2abfb545b46ce0e00ad2bb85cd5");;
Hashtbl.add mgrootassoc (hexstring_hashval "73b2b912e42098857a1a0d2fc878581a3c1dcc1ca3769935edb92613cf441876") (hexstring_hashval "df0c7f1a5ed1eb8adafd81d6ecc1616d8afbec6fb8f400245c819ce49365279f");;
Hashtbl.add mgrootassoc (hexstring_hashval "997d9126455d5de46368f27620eca2e5ad3b0f0ecdffdc7703aa4aafb77eafb6") (hexstring_hashval "e94a939c86c866ea378958089db656d350c86095197c9912d4e9d0f1ea317f09");;
Hashtbl.add mgrootassoc (hexstring_hashval "464e47790f44cd38285279f563a5a918d73224c78a9ef17ae1a46e62a95b2a41") (hexstring_hashval "680d7652d15d54f0a766df3f997236fe6ea93db85d1c85bee2fa1d84b02d9c1d");;
Hashtbl.add mgrootassoc (hexstring_hashval "5e992a3fe0c82d03dd3d5c5fbd76ae4e09c16d4ce8a8f2bbff757c1617d1cb0b") (hexstring_hashval "1334e1f799a3bc4df3f30aff55240fb64bdadbf61b47f37dcd8b8efae8f50607");;
Hashtbl.add mgrootassoc (hexstring_hashval "d335d40e85580857cc0be3657b910d5bce202e0fab6875adec93e2fc5e5e57e4") (hexstring_hashval "a439fd04fdf53a240bd30662af698e730d4b04b510adff1d4a286718c31431e4");;
Hashtbl.add mgrootassoc (hexstring_hashval "df14296f07f39c656a6467de607eb3ced299a130355447584c264061b5275b93") (hexstring_hashval "5f8f4c8326fb150e4602e1f88fbe7bacc34f447e140c05d6f871baeb3b8edd0b");;
Hashtbl.add mgrootassoc (hexstring_hashval "54dbd3a1c5d7d09ab77e3b5f4c62ce5467ada0cf451d47ee29b7359cc44017cc") (hexstring_hashval "8362706412591cb4be4f57a479e94d2219507374d13076e2e8c6636ab9c4fc08");;
Hashtbl.add mgrootassoc (hexstring_hashval "b927035076bdb3f2b856017733102a46ad6a0c52f1f4808b6c0cc6bde29328b6") (hexstring_hashval "1d236ab2eeffe5c2a0b53d462ef26ecaca94bfe3e1b51cd50fc0253d7c98b44a");;
Hashtbl.add mgrootassoc (hexstring_hashval "2c39441e10ec56a1684beb291702e235e2a9e44db516e916d62ce426108cfd26") (hexstring_hashval "40bec47cb8d77d09a8db5316dde8cb26bd415be5a40f26f59f167843da58eb63");;
Hashtbl.add mgrootassoc (hexstring_hashval "9e6b18b2a018f4fb700d2e18f2d46585471c8c96cd648d742b7dbda08c349b17") (hexstring_hashval "6b9d57d639bb4c40d5626cf4d607e750e8cce237591fcc20c9faaf1e4b9791b2");;
Hashtbl.add mgrootassoc (hexstring_hashval "a887fc6dd84a5c55d822e4ceb932c68ead74c9292ff8f29b32a732a2ee261b73") (hexstring_hashval "d23ef8d936222dbc756f3c008b84bd90768aedacd2047612cf55f004eb3081de");;
Hashtbl.add mgrootassoc (hexstring_hashval "8d7cd4bd6b239e3dc559142aa4d11d731c7a888de9faa3b9eeec2e7d5651c3fb") (hexstring_hashval "958089f3e058bcb3465dabe167a1b593b111674f5614bd5833e43ac29c8d296f");;
Hashtbl.add mgrootassoc (hexstring_hashval "0edee4fe5294a35d7bf6f4b196df80681be9c05fa6bb1037edb8959fae208cea") (hexstring_hashval "0468dca95ec4be8ac96ef7403d2ff5ab46e4fb35910b2cb3e91f4678a96ee700");;
Hashtbl.add mgrootassoc (hexstring_hashval "8a818c489559985bbe78176e9e201d0d162b3dd17ee57c97b44a0af6b009d53b") (hexstring_hashval "d4536073da584640c235142889018ef88e09ae5d8e2ae2540429a7098386db30");;
Hashtbl.add mgrootassoc (hexstring_hashval "e8cf29495c4bd3a540c463797fd27db8e2dfcc7e9bd1302dad04b40c11ce4bab") (hexstring_hashval "1413d570a65b1a0bb39cfa82195ce6bfe1cf2629ef19576660144b83c0058199");;
Hashtbl.add mgrootassoc (hexstring_hashval "05d54a9f11f12daa0639e1df1157577f57d8b0c6ede098282f5eca14026a360f") (hexstring_hashval "840b320b81131d2c96c0be569366bb3d2755e13c730d99e916d0e782f1d79cfb");;
Hashtbl.add mgrootassoc (hexstring_hashval "3bcfdf72871668bce2faf4af19b82f05b1ff30e94a64bbc83215c8462bc294ca") (hexstring_hashval "417bbf2a3b32835172581302b58bedd04d725d0fe24111e9e92e754cec48eaa3");;
Hashtbl.add mgrootassoc (hexstring_hashval "c9c27ca28ffd069e766ce309b49a17df75d70111ce5b2b8e9d836356fb30b20a") (hexstring_hashval "6786d5a0f6a22ba660cb51b8b290647cb3c631915e64df2754d965e64409fd78");;
Hashtbl.add mgrootassoc (hexstring_hashval "4f273e5c6c57dff24b2d1ca4088c333f4bbd2647ab77e6a03beedd08f8f17eb9") (hexstring_hashval "33e4dfd6e9c8aa8f4a80915c383a6800ce85c764d8dfdb150a1f298de0e03931");;
Hashtbl.add mgrootassoc (hexstring_hashval "1cb8f85f222724bb5ee5926c5c1c0da8acd0066ba3fa91c035fe2fb8d511a035") (hexstring_hashval "e10185af3a88e49d71e743ea82475d6554773226cac49474c80699c3eb396d7a");;
Hashtbl.add mgrootassoc (hexstring_hashval "994c6976ade70b6acb23366d7ac2e5d6cf47e35ce09a6d71154e38fd46406ad1") (hexstring_hashval "bdd6c063a68fe9b4e7edca091295194f155337cf583292b903a3668956034b73");;
Hashtbl.add mgrootassoc (hexstring_hashval "1dd206bf7d1aea060662f06e19ec29564e628c990cb17f043a496e180cf094e8") (hexstring_hashval "22371ff2f4e6e9c19b7ed88ae95db4f48e76c8d62e02b9155963dfa603bbb416");;
Hashtbl.add mgrootassoc (hexstring_hashval "071c71e291b8c50d10f9d7f5544da801035d99ff3a68c9e5386b4087d22b5db2") (hexstring_hashval "bab2523b317499704341a2ba21c21cbb7bd14322e0aa8442a4413c3d162c6a23");;
Hashtbl.add mgrootassoc (hexstring_hashval "b5e0e5eb78d27c7fd8102e3c6741350d4444905a165833aa81250cef01a1acea") (hexstring_hashval "d0704adab893835ea07508bce4c1d592fef7011d08c75258289cc4c02d37e922");;
Hashtbl.add mgrootassoc (hexstring_hashval "683becb457be56391cd0ea1cefb5016e2185efebd92b7afd41cd7b3a4769ac57") (hexstring_hashval "a9c7e15fe98424e705cb0d068b2befa60d690c47614ba90840accce2ce0f5abe");;
Hashtbl.add mgrootassoc (hexstring_hashval "8d6a0ebb123230b9386afac5f3888ea2c3009a7caabad13e57153f9a737c8d0b") (hexstring_hashval "9bb91e70f92c96bf494419ba4a922d67c81d172ff21d3569e6ae4e818abf2ad4");;
Hashtbl.add mgrootassoc (hexstring_hashval "971902aba30554ada3e97388da3b25c677413e2b4df617edba4112889c123612") (hexstring_hashval "6ff32368f770786cf00ab7ee4313339ebfa68b64e74fdac8eb8098f8a09e6c90");;
Hashtbl.add mgrootassoc (hexstring_hashval "759fd51778137326dda8cf75ce644e3ec8608dfa7e59c54b364069dd6cf6dd0d") (hexstring_hashval "f0ca19ea365100ff839421e05ae49ccdd46dabe2f9816d15f2b3debd74c3f747");;
Hashtbl.add mgrootassoc (hexstring_hashval "49803500fa75d5030dddbb3d7a18d03eeebfdd720d57630629384cec6d8b3afc") (hexstring_hashval "22eb661b544952a77782f641e48dba4e884d9db233a82d26f12e3035c9b8667e");;
Hashtbl.add mgrootassoc (hexstring_hashval "f0bb69e74123475b6ecce64430b539b64548b0b148267ea6c512e65545a391a1") (hexstring_hashval "e93ef2d99ea2bdae1c958288fc8e8dd480db306b692306df9415934b45bea9dd");;
Hashtbl.add mgrootassoc (hexstring_hashval "6968cd9ba47369f21e6e4d576648c6317ed74b303c8a2ac9e3d5e8bc91a68d9d") (hexstring_hashval "67a43eaf6a510480f8a95092b8b3a8f7711ce9c72f89848a5e4ff4c0f289f5f6");;
Hashtbl.add mgrootassoc (hexstring_hashval "163d1cc9e169332d8257b89d93d961798c6847300b6756e818c4906f0e37c37f") (hexstring_hashval "165bc92fa1d80cb626b134669a07b299a610c1b07e1b1bb5ac7d526201f9eb77");;
Hashtbl.add mgrootassoc (hexstring_hashval "3bc46030cc63aa36608ba06b3b00b696e1a1eb1de5346ff216ca33108220fbda") (hexstring_hashval "66d6ff98b3b79e75764e0259456712f461f681f34bd2e06d15175c9fb6118148");;
Hashtbl.add mgrootassoc (hexstring_hashval "727fd1e7d5e38e7145387c0a329b4de2b25f2de5d67989f11e8921bc96f4b6bd") (hexstring_hashval "ab6fe04f7ecce2b84fd00da24fdf63f7b85c87bd5a39aa2318a9c79594293b69");;
Hashtbl.add mgrootassoc (hexstring_hashval "da14f3f79323b9ad1fb102c951a6ba616694bc14e5602b46a53c3b0e4928a55e") (hexstring_hashval "38672ae5bc51bdee97d38fdd257157ac49b953dff12e82e7ecc51e186840d372");;
Hashtbl.add mgrootassoc (hexstring_hashval "7e80cba90c488f36c81034790c30418111d63919ffb3a9b47a18fd1817ba628e") (hexstring_hashval "c74b1964ecbb13155957c27f290e3ec0ccce445c78e374a6f5af3c90eaffff13");;
Hashtbl.add mgrootassoc (hexstring_hashval "61bbe03b7930b5642e013fa138d7c8e2353bab0324349fce28b7cbce8edce56a") (hexstring_hashval "06ba79b59a1c5d8417b904d7136e5961bff5940f6051d2348b8eb4590aced43a");;
Hashtbl.add mgrootassoc (hexstring_hashval "e5405bc7309f2aa971bcab97aadae821ba1e89825a425c7bf10000998c5266c9") (hexstring_hashval "87f273bb045ac2b48d904cec78ee4e82959c3d32eb1081efdd1318df0a7e7b05");;
Hashtbl.add mgrootassoc (hexstring_hashval "e87205d21afb0774d1a02a5d882285c7554f7b824ee3d6ff0a0c0be48dac31d6") (hexstring_hashval "809c76c877e95fa3689fdea2490efbf0cfe1fabfb574cc373345cbc95fb2b9b6");;
Hashtbl.add mgrootassoc (hexstring_hashval "38dd910342442210ba796f0e96ab9a7e6b36c17352f74ba8c9c2db4da2aebf0e") (hexstring_hashval "9e04de3e48671039f5d41907fd55a69827dabfc35f8f1d4ae1e89058d3036a6b");;
Hashtbl.add mgrootassoc (hexstring_hashval "9f7755a326e730a1c98395c05032d068f1d3a5762700ae73598c3c57a6bd51ea") (hexstring_hashval "1f295d11712271bb0a9460c247e2e5e5076be5b0c5b72cd8dd131012a9ea1570");;
Hashtbl.add mgrootassoc (hexstring_hashval "d326e5351e117c7374d055c5289934dc3a6e79d66ed68f1c6e23297feea0148e") (hexstring_hashval "e0b6a1bb35f28a4f8c8e08c3084bce18be3e437d9f29a8ee67a6320d405c2c40");;
Hashtbl.add mgrootassoc (hexstring_hashval "bacdefb214268e55772b42739961f5ea4a517ab077ed4b168f45f4c3d4703ec4") (hexstring_hashval "a2018a84f3971e0797308c555d45c13ffe35b4c176861fb8ad8372a1cb09473d");;
Hashtbl.add mgrootassoc (hexstring_hashval "f0bb69e74123475b6ecce64430b539b64548b0b148267ea6c512e65545a391a1") (hexstring_hashval "e93ef2d99ea2bdae1c958288fc8e8dd480db306b692306df9415934b45bea9dd");;
Hashtbl.add mgrootassoc (hexstring_hashval "6968cd9ba47369f21e6e4d576648c6317ed74b303c8a2ac9e3d5e8bc91a68d9d") (hexstring_hashval "67a43eaf6a510480f8a95092b8b3a8f7711ce9c72f89848a5e4ff4c0f289f5f6");;
Hashtbl.add mgrootassoc (hexstring_hashval "4b4b94d59128dfa2798a2e72c886a5edf4dbd4d9b9693c1c6dea5a401c53aec4") (hexstring_hashval "ab3dfeb9395a1e303801e2bc8d55caf8d8513c9573264975ac8e4266deed9436");;
Hashtbl.add mgrootassoc (hexstring_hashval "61f7303354950fd70e647b19c486634dc22d7df65a28d1d6893007701d7b3df4") (hexstring_hashval "437d66ccb8e151afd5a5c752cbe4a8868996aa3547b18d720cc64249a47da230");;
Hashtbl.add mgrootassoc (hexstring_hashval "57e734ae32adddc1f13e75e7bab22241e5d2c12955ae233ee90f53818028312a") (hexstring_hashval "961c68425fb06db92e20b192ab8ef8a77db1dbc5d8807be8184193fe540784ca");;
Hashtbl.add mgrootassoc (hexstring_hashval "b079d3c235188503c60077e08e7cb89a17aa1444006788a8377caf62b43ea1ea") (hexstring_hashval "82a25088c21c988ed9a4541afc7233b70b575b4b0b2067bf8de07a88abd55d02");;
Hashtbl.add mgrootassoc (hexstring_hashval "b84ca72faca3a10b9b75c38d406768819f79488fbad8d9bee8b765c45e35823c") (hexstring_hashval "9fa747a53a5d1a2323ed6693fc43f28239dfe66a29852bf4137b17cc6149ce69");;
Hashtbl.add mgrootassoc (hexstring_hashval "c7b84fda1101114e9994926a427c957f42f89ae1918086df069cb1a030519b46") (hexstring_hashval "79ab0162b4fff65d19da20ee951647019f994fb6f3c417fd2e754597f4a5f2a5");;
Hashtbl.add mgrootassoc (hexstring_hashval "f0bb69e74123475b6ecce64430b539b64548b0b148267ea6c512e65545a391a1") (hexstring_hashval "e93ef2d99ea2bdae1c958288fc8e8dd480db306b692306df9415934b45bea9dd");;
Hashtbl.add mgrootassoc (hexstring_hashval "6968cd9ba47369f21e6e4d576648c6317ed74b303c8a2ac9e3d5e8bc91a68d9d") (hexstring_hashval "67a43eaf6a510480f8a95092b8b3a8f7711ce9c72f89848a5e4ff4c0f289f5f6");;
Hashtbl.add mgrootassoc (hexstring_hashval "4b4b94d59128dfa2798a2e72c886a5edf4dbd4d9b9693c1c6dea5a401c53aec4") (hexstring_hashval "ab3dfeb9395a1e303801e2bc8d55caf8d8513c9573264975ac8e4266deed9436");;
Hashtbl.add mgrootassoc (hexstring_hashval "61f7303354950fd70e647b19c486634dc22d7df65a28d1d6893007701d7b3df4") (hexstring_hashval "437d66ccb8e151afd5a5c752cbe4a8868996aa3547b18d720cc64249a47da230");;
Hashtbl.add mgrootassoc (hexstring_hashval "57e734ae32adddc1f13e75e7bab22241e5d2c12955ae233ee90f53818028312a") (hexstring_hashval "961c68425fb06db92e20b192ab8ef8a77db1dbc5d8807be8184193fe540784ca");;
Hashtbl.add mgrootassoc (hexstring_hashval "29d9e2fc6403a0149dee771fde6a2efc8a94f848a3566f3ccd60af2065396289") (hexstring_hashval "fe600fee4888e854b519619f9d314569f986253bb2b5db02807f68aa12bf7c5a");;
Hashtbl.add mgrootassoc (hexstring_hashval "6271864c471837aeded4c4e7dc37b9735f9fc4828a34ac9c7979945da815a3c7") (hexstring_hashval "00e0580a8881b84ea1ef7f67247f59ec145448a850064052345ecd4ecb637071");;
Hashtbl.add mgrootassoc (hexstring_hashval "831192b152172f585e3b6d9b53142cba7a2d8becdffe4e6337c037c027e01e21") (hexstring_hashval "0378e7d3c30718f11d428c213208a3f296fde75753deb6d56a50c1962b895a2a");;
Hashtbl.add mgrootassoc (hexstring_hashval "c432061ca96824037858ab07c16171f5e5a81ee7bf3192521c5a0f87199ec5f7") (hexstring_hashval "864d4a98ea59e1f9e8ce1c34394b59aefcee4d7ea9ba7fb1b48ea27d336dd8e6");;
Hashtbl.add mgrootassoc (hexstring_hashval "5f401f6d84aeff20334d10330efdc9bb3770d636d6c18d803bce11a26288a60d") (hexstring_hashval "76c5220b796595b575de2f72242dc5298e7150c68685df217acb84651b8cd860");;
Hashtbl.add mgrootassoc (hexstring_hashval "d24599d38d9bd01c24454f5419fe61db8cc7570c68a81830565fbfa41321648f") (hexstring_hashval "09d9d2e8ec7b938178f5c92107aa3acdcbfd74d8aeacc2f7f79b3248203c7ef7");;
Hashtbl.add mgrootassoc (hexstring_hashval "16510b6e91dc8f8934f05b3810d2b54c286c5652cf26501797ea52c33990fa93") (hexstring_hashval "92a56a0f4680f62291a5420bbb5c8878605fd96283094663ba30661ca618a193");;
Hashtbl.add mgrootassoc (hexstring_hashval "cc51438984361070fa0036749984849f690f86f00488651aabd635e92983c745") (hexstring_hashval "6ec032f955c377b8953cff1c37d3572125487a6587167afb5fdec25c2350b3c3");;
Hashtbl.add mgrootassoc (hexstring_hashval "c35281fa7c11775a593d536c7fec2695f764921632445fa772f3a2a45bdf4257") (hexstring_hashval "4a34d6ddf18af8c0c2f637afb2ddadaa240273c85b9410fcb82cd0782bab13d7");;
Hashtbl.add mgrootassoc (hexstring_hashval "d0c55cfc8a943f26e3abfa84ecab85911a27c5b5714cd32dcda81d104eb92c6e") (hexstring_hashval "6c7fc05bbe5807883e5035b06b65b9a669c2f2a8ba2ba952ab91a9a02f7ea409");;
Hashtbl.add mgrootassoc (hexstring_hashval "9481cf9deb6efcbb12eccc74f82acf453997c8e75adb5cd83311956bcc85d828") (hexstring_hashval "1be0cda46d38c27e57488fdb9a2e54ccd2b8f9c133cbfc27af57bf54206ada12");;
Hashtbl.add mgrootassoc (hexstring_hashval "5dad3f55c3f3177e2d18188b94536551b7bfd38a80850f4314ba8abb3fd78138") (hexstring_hashval "8bf86a17c9a6ce157ed3de4762edc8cbee3acc11e18b41f458f34ca9d1983803");;
Hashtbl.add mgrootassoc (hexstring_hashval "9c138ddc19cc32bbd65aed7e98ca568d6cf11af8ab01e026a5986579061198b7") (hexstring_hashval "d91e2c13ce03095e08eaa749eebd7a4fa45c5e1306e8ce1c6df365704d44867f");;
Hashtbl.add mgrootassoc (hexstring_hashval "30acc532eaa669658d7b9166abf687ea3e2b7c588c03b36ba41be23d1c82e448") (hexstring_hashval "87078b7ac24bf8933a19e084290a2389879a99a0c1e88735fb5de288e047db0c");;
Hashtbl.add mgrootassoc (hexstring_hashval "e40da52d94418bf12fcea785e96229c7cfb23420a48e78383b914917ad3fa626") (hexstring_hashval "be6a968dce01facef568dc993eb13308d0ad11a1122ff3b96873947b912d1ffe");;
Hashtbl.add mgrootassoc (hexstring_hashval "98e51ea2719a0029e0eac81c75004e4edc85a0575ad3f06c9d547c11b354628c") (hexstring_hashval "0f7e46aa15c5d530e6dda8f4782c3ec58bdb13c8e9886c1af9b20f3eeaf5b828");;
Hashtbl.add mgrootassoc (hexstring_hashval "d8ee26bf5548eea4c1130fe0542525ede828afda0cef2c9286b7a91d8bb5a9bd") (hexstring_hashval "25738f488b1c0f60ff0e89d0682b4a48a770f3bed3bf5659ebfc92e57f86fb45");;
Hashtbl.add mgrootassoc (hexstring_hashval "db3d34956afa98a36fc0bf6a163888112f6d0254d9942f5a36ed2a91a1223d71") (hexstring_hashval "0d0ea84c1939a93708c1651a29db38a9fbde345c33b5995c4fdaf497e58d1b21");;
Hashtbl.add mgrootassoc (hexstring_hashval "d542f60aebdbe4e018abe75d8586699fd6db6951a7fdc2bc884bfb42c0d77a22") (hexstring_hashval "08195fc95542b2be3e25b7fdef814f4e54290bd680ae0917923b0e44786a0214");;
Hashtbl.add mgrootassoc (hexstring_hashval "9971dcf75f0995efe4245a98bcdf103e4713261d35432146405052f36f8234bf") (hexstring_hashval "d29e0a271e279bed247f0e5ec6895735ab27f7eeabc9cb00a1366d5d7e7da6ca");;
Hashtbl.add mgrootassoc (hexstring_hashval "f0bb69e74123475b6ecce64430b539b64548b0b148267ea6c512e65545a391a1") (hexstring_hashval "e93ef2d99ea2bdae1c958288fc8e8dd480db306b692306df9415934b45bea9dd");;
Hashtbl.add mgrootassoc (hexstring_hashval "6968cd9ba47369f21e6e4d576648c6317ed74b303c8a2ac9e3d5e8bc91a68d9d") (hexstring_hashval "67a43eaf6a510480f8a95092b8b3a8f7711ce9c72f89848a5e4ff4c0f289f5f6");;
Hashtbl.add mgrootassoc (hexstring_hashval "4b4b94d59128dfa2798a2e72c886a5edf4dbd4d9b9693c1c6dea5a401c53aec4") (hexstring_hashval "ab3dfeb9395a1e303801e2bc8d55caf8d8513c9573264975ac8e4266deed9436");;
Hashtbl.add mgrootassoc (hexstring_hashval "e59503fd8967d408619422bdebda4be08c9654014309b60880a3d7acf647e2b4") (hexstring_hashval "0d90e9f1543e4460b11fd7539e39b4d40e21b02cbbfababad2dde50ffee3eb93");;
Hashtbl.add mgrootassoc (hexstring_hashval "57e734ae32adddc1f13e75e7bab22241e5d2c12955ae233ee90f53818028312a") (hexstring_hashval "961c68425fb06db92e20b192ab8ef8a77db1dbc5d8807be8184193fe540784ca");;
Hashtbl.add mgrootassoc (hexstring_hashval "7aa92281bc38360837d18b9ec38ff8359d55a8c6ef4349c5777aab707e79589b") (hexstring_hashval "520b74715d23e4ce89f2ff9de5106772f592f32c69a1d405949d1ee275f54e53");;
Hashtbl.add mgrootassoc (hexstring_hashval "3a46d8baa691ebb59d2d6c008a346206a39f4baae68437520106f9673f41afc6") (hexstring_hashval "ce8fc217ed019e51034965be8f01d9d3c004bec41e2a93735103475c80a80984");;
Hashtbl.add mgrootassoc (hexstring_hashval "18dcd68b13ac8ef27a4d8dfec8909abfa78ffbb33539bea51d3397809f365642") (hexstring_hashval "2aba4a11f886ed7d2772a4203e4b5b3ed92efb7b762aac4e88b7ed51e515b123");;
Hashtbl.add mgrootassoc (hexstring_hashval "9b1a146e04de814d3707f41de0e21bf469d07ef4ce11ae2297f43acd3cb43219") (hexstring_hashval "b0e8808f901785e107bc3632d567898ab45796640529b6f2c87277724088bf59");;
Hashtbl.add mgrootassoc (hexstring_hashval "96c4c45b8c7f933c096a5643362b6a5eeb1d9e4d338d9854d4921130e6c8cdbe") (hexstring_hashval "773a1a70ae02bc1cfc69d95fd643cd68afd9aa7499bb85ee3a00b62275b1969e");;
Hashtbl.add mgrootassoc (hexstring_hashval "4857fdedbdc33f33b2c088479c67bbbceae1afd39fca032cb085f9f741cedca6") (hexstring_hashval "cfd938e7e6de3a95f672a143ea3573f7ee1b4a7cc593e33232315e1cd1dfe553");;
Hashtbl.add mgrootassoc (hexstring_hashval "7e897f0ce092b0138ddab8aa6a2fc3352b0c70d9383c22f99340c202779c7a39") (hexstring_hashval "362f66ac196e7ef2d566a5c7f32090e9dc169b9f381c11faff61cc2bdeb6d843");;
Hashtbl.add mgrootassoc (hexstring_hashval "90ee851305d1ba4b80424ec6e2760ebabb1fd3e399fcb5c6b5c814d898138c16") (hexstring_hashval "f7cd39d139f71b389f61d3cf639bf341d01dac1be60ad65b40ee3aa5218e0043");;
Hashtbl.add mgrootassoc (hexstring_hashval "73933450ffb3d9fb3cb2acad409d6391a68703e7aab772a53789ef666168b1d7") (hexstring_hashval "7f00417f03c3fced94bff1def318bc3df6b92da42dc1953409d4d5fd16e5bb57");;
Hashtbl.add mgrootassoc (hexstring_hashval "66d2d10b199cf5a3b4dfb5713cc4133cfbc826169169bd617efe7895854be641") (hexstring_hashval "772e9c2d17c93514d9930b0a3a98a287703684d1fe782a98a34117d0e0ee0a9c");;
Hashtbl.add mgrootassoc (hexstring_hashval "c5d86cf97e40aa1fd6c7b0939b0974f704b1c792393b364c520e0e4558842cf6") (hexstring_hashval "aab220c89625a268d769430a9bd1c5242495f378775d11b8e61bd9148d917e80");;
Hashtbl.add mgrootassoc (hexstring_hashval "163602f90de012a7426ee39176523ca58bc964ccde619b652cb448bd678f7e21") (hexstring_hashval "3578b0d6a7b318714bc5ea889c6a38cf27f08eaccfab7edbde3cb7a350cf2d9b");;
Hashtbl.add mgrootassoc (hexstring_hashval "aa4bcd059b9a4c99635877362627f7d5998ee755c58679934cc62913f8ef06e0") (hexstring_hashval "d2a0e4530f6e4a8ef3d5fadfbb12229fa580c2add302f925c85ede027bb4b175");;
Hashtbl.add mgrootassoc (hexstring_hashval "b8ff52f838d0ff97beb955ee0b26fad79602e1529f8a2854bda0ecd4193a8a3c") (hexstring_hashval "8c8f550868df4fdc93407b979afa60092db4b1bb96087bc3c2f17fadf3f35cbf");;
Hashtbl.add mgrootassoc (hexstring_hashval "74243828e4e6c9c0b467551f19c2ddaebf843f72e2437cc2dea41d079a31107f") (hexstring_hashval "80aea0a41bb8a47c7340fe8af33487887119c29240a470e920d3f6642b91990d");;
Hashtbl.add mgrootassoc (hexstring_hashval "bd01a809e97149be7e091bf7cbb44e0c2084c018911c24e159f585455d8e6bd0") (hexstring_hashval "158bae29452f8cbf276df6f8db2be0a5d20290e15eca88ffe1e7b41d211d41d7");;
Hashtbl.add mgrootassoc (hexstring_hashval "5e1ac4ac93257583d0e9e17d6d048ff7c0d6ccc1a69875b2a505a2d4da305784") (hexstring_hashval "0a445311c45f0eb3ba2217c35ecb47f122b2301b2b80124922fbf03a5c4d223e");;
Hashtbl.add mgrootassoc (hexstring_hashval "b3e3bf86a58af5d468d398d3acad61ccc50261f43c856a68f8594967a06ec07a") (hexstring_hashval "d772b0f5d472e1ef525c5f8bd11cf6a4faed2e76d4eacfa455f4d65cc24ec792");;
Hashtbl.add mgrootassoc (hexstring_hashval "f336a4ec8d55185095e45a638507748bac5384e04e0c48d008e4f6a9653e9c44") (hexstring_hashval "f7e63d81e8f98ac9bc7864e0b01f93952ef3b0cbf9777abab27bcbd743b6b079");;
Hashtbl.add mgrootassoc (hexstring_hashval "ec807b205da3293041239ff9552e2912636525180ddecb3a2b285b91b53f70d8") (hexstring_hashval "f627d20f1b21063483a5b96e4e2704bac09415a75fed6806a2587ce257f1f2fd");;
Hashtbl.add mgrootassoc (hexstring_hashval "da098a2dd3a59275101fdd49b6d2258642997171eac15c6b60570c638743e785") (hexstring_hashval "816cc62796568c2de8e31e57b826d72c2e70ee3394c00fbc921f2e41e996e83a");;
Hashtbl.add mgrootassoc (hexstring_hashval "b2abd2e5215c0170efe42d2fa0fb8a62cdafe2c8fbd0d37ca14e3497e54ba729") (hexstring_hashval "8cf6b1f490ef8eb37db39c526ab9d7c756e98b0eb12143156198f1956deb5036");;
Hashtbl.add mgrootassoc (hexstring_hashval "c68e5a1f5f57bc5b6e12b423f8c24b51b48bcc32149a86fc2c30a969a15d8881") (hexstring_hashval "cc569397a7e47880ecd75c888fb7c5512aee4bcb1e7f6bd2c5f80cccd368c060");;
Hashtbl.add mgrootassoc (hexstring_hashval "65d8837d7b0172ae830bed36c8407fcd41b7d875033d2284eb2df245b42295a6") (hexstring_hashval "9db634daee7fc36315ddda5f5f694934869921e9c5f55e8b25c91c0a07c5cbec");;
Hashtbl.add mgrootassoc (hexstring_hashval "6fc30ac8f2153537e397b9ff2d9c981f80c151a73f96cf9d56ae2ee27dfd1eb2") (hexstring_hashval "39cdf86d83c7136517f803d29d0c748ea45a274ccbf9b8488f9cda3e21f4b47c");;
Hashtbl.add mgrootassoc (hexstring_hashval "896fa967e973688effc566a01c68f328848acd8b37e857ad23e133fdd4a50463") (hexstring_hashval "e1e47685e70397861382a17f4ecc47d07cdab63beca11b1d0c6d2985d3e2d38b");;
Hashtbl.add mgrootassoc (hexstring_hashval "3bae39e9880bbf5d70538d82bbb05caf44c2c11484d80d06dee0589d6f75178c") (hexstring_hashval "a6e81668bfd1db6e6eb6a13bf66094509af176d9d0daccda274aa6582f6dcd7c");;
Hashtbl.add mgrootassoc (hexstring_hashval "ca5fc17a582fdd4350456951ccbb37275637ba6c06694213083ed9434fe3d545") (hexstring_hashval "dc42f3fe5d0c55512ef81fe5d2ad0ff27c1052a6814b1b27f5a5dcb6d86240bf");;
Hashtbl.add mgrootassoc (hexstring_hashval "e8e5113bb5208434f24bf352985586094222b59a435d2d632e542c768fb9c029") (hexstring_hashval "9909a953d666fea995cf1ccfe3d98dba3b95210581af4af82ae04f546c4c34a5");;
Hashtbl.add mgrootassoc (hexstring_hashval "615c0ac7fca2b62596ed34285f29a77b39225d1deed75d43b7ae87c33ba37083") (hexstring_hashval "322bf09a1711d51a4512e112e1767cb2616a7708dc89d7312c8064cfee6e3315");;
Hashtbl.add mgrootassoc (hexstring_hashval "a64b5b4306387d52672cb5cdbc1cb423709703e6c04fdd94fa6ffca008f7e1ab") (hexstring_hashval "cc8f114cf9f75d4b7c382c62411d262d2241962151177e3b0506480d69962acc");;
Hashtbl.add mgrootassoc (hexstring_hashval "17057f3db7be61b4e6bd237e7b37125096af29c45cb784bb9cc29b1d52333779") (hexstring_hashval "e76df3235104afd8b513a92c00d3cc56d71dd961510bf955a508d9c2713c3f29");;
Hashtbl.add mgrootassoc (hexstring_hashval "3314762dce5a2e94b7e9e468173b047dd4a9fac6ee2c5f553c6ea15e9c8b7542") (hexstring_hashval "53034f33cbed012c3c6db42812d3964f65a258627a765f5bede719198af1d1ca");;
Hashtbl.add mgrootassoc (hexstring_hashval "2bb1d80de996e76ceb61fc1636c53ea4dc6f7ce534bd5caee16a3ba4c8794a58") (hexstring_hashval "33be70138f61ae5ce327b6b29a949448c54f06c2da932a4fcf7d7a0cfc29f72e");;
Hashtbl.add mgrootassoc (hexstring_hashval "bf2fb7b3431387bbd1ede0aa0b590233207130df523e71e36aaebd675479e880") (hexstring_hashval "216c935441f8678edc47540d419667fe9e5ab01fda1f1afbc64eacaea6a9cbfc");;
Hashtbl.add mgrootassoc (hexstring_hashval "6cf28b2480e4fa77008de59ed21788efe58b7d6926c3a8b72ec889b0c27b2f2e") (hexstring_hashval "8117f6db2fb9c820e5905451e109f8ef633101b911baa48945806dc5bf927693");;
Hashtbl.add mgrootassoc (hexstring_hashval "fac413e747a57408ad38b3855d3cde8673f86206e95ccdadff2b5babaf0c219e") (hexstring_hashval "f97da687c51f5a332ff57562bd465232bc70c9165b0afe0a54e6440fc4962a9f");;
Hashtbl.add mgrootassoc (hexstring_hashval "f3c9abbc5074c0d68e744893a170de526469426a5e95400ae7fc81f74f412f7e") (hexstring_hashval "4d137cad40b107eb0fc2c707372525f1279575e6cadb4ebc129108161af3cedb");;
Hashtbl.add mgrootassoc (hexstring_hashval "9b3a85b85e8269209d0ca8bf18ef658e56f967161bf5b7da5e193d24d345dd06") (hexstring_hashval "222f1b8dcfb0d2e33cc4b232e87cbcdfe5c4a2bdc5326011eb70c6c9aeefa556");;
Hashtbl.add mgrootassoc (hexstring_hashval "8465061e06db87ff5ec9bf4bd2245a29d557f6b265478036bee39419282a5e28") (hexstring_hashval "2cb990eb7cf33a7bea142678f254baf1970aa17b7016039b89df7652eff72aba");;
Hashtbl.add mgrootassoc (hexstring_hashval "e9c5f22f769cd18d0d29090a943f66f6006f0d132fafe90f542ee2ee8a3f7b59") (hexstring_hashval "45519cf90ff63f7cea32c7ebbbae0922cfc609d577dc157e25e68e131cddf2df");;
Hashtbl.add mgrootassoc (hexstring_hashval "8bc8d37461c7653ced731399d140c0d164fb9231e77b2824088e534889c31596") (hexstring_hashval "e249fde27e212bc28b301523be2eee37636e29fc084bd9b775cb02f921e2ad7f");;
Hashtbl.add mgrootassoc (hexstring_hashval "73dd2d0fb9a3283dfd7b1d719404da0bf605e7b4c7b714a2b4e2cb1a38d98c6f") (hexstring_hashval "5b91106169bd98c177a0ff2754005f1488a83383fc6fc918d8c61f613843cf0f");;
Hashtbl.add mgrootassoc (hexstring_hashval "f25ee4a03f8810e3e5a11b184db6c8f282acaa7ef4bfd93c4b2de131431b977c") (hexstring_hashval "2e63292920e9c098907a70c431c7555afc9d4d26c8920d41192c83c02196acbe");;
Hashtbl.add mgrootassoc (hexstring_hashval "80f7da89cc801b8279f42f9e1ed519f72d50d76e88aba5efdb67c4ae1e59aee0") (hexstring_hashval "058168fdbe0aa41756ceb986449745cd561e65bf2dd594384cd039169aa7ec90");;
Hashtbl.add mgrootassoc (hexstring_hashval "1a8f92ceed76bef818d85515ce73c347dd0e2c0bcfd3fdfc1fcaf4ec26faed04") (hexstring_hashval "6dc2e406a4ee93aabecb0252fd45bdf4b390d29b477ecdf9f4656d42c47ed098");;
Hashtbl.add mgrootassoc (hexstring_hashval "8b81abb8b64cec9ea874d5c4dd619a9733a734933a713ef54ed7e7273510b0c3") (hexstring_hashval "28ea4ee0409fe1fc4b4516175b2254cb311b9609fd2a4015768b4a520fe69214");;
Hashtbl.add mgrootassoc (hexstring_hashval "d82c5791815ca8155da516354e8f8024d8b9d43a14ce62e2526e4563ff64e67f") (hexstring_hashval "65bb4bac5d306fd1707029e38ff3088a6d8ed5aab414f1faf79ba5294ee2d01e");;
Hashtbl.add mgrootassoc (hexstring_hashval "36a362f5d7e56550e98a38468fb4fc4d70ea17f4707cfdd2f69fc2cce37a9643") (hexstring_hashval "dc4124cb3e699eb9154ce37eaa547c4d08adc8fd41c311d706024418f4f1c8d6");;
Hashtbl.add mgrootassoc (hexstring_hashval "20c61c861cf1a0ec40aa6c975b43cd41a1479be2503a10765e97a8492374fbb0") (hexstring_hashval "ddf851fd1854df71be5ab088768ea86709a9288535efee95c3e876766b3c9195");;
Hashtbl.add mgrootassoc (hexstring_hashval "eced574473e7bc0629a71e0b88779fd6c752d24e0ef24f1e40d37c12fedf400a") (hexstring_hashval "73402bd7c3bf0477017bc48f6f236eef4ba9c1b3cffe34afb0a7b991fea12054");;
Hashtbl.add mgrootassoc (hexstring_hashval "1d3fd4a14ef05bd43f5c147d7966cf05fd2fed808eea94f56380454b9a6044b2") (hexstring_hashval "1f005fdad5c6f98763a15a5e5539088f5d43b7d1be866b0b204fda1ce9ed9248");;
Hashtbl.add mgrootassoc (hexstring_hashval "768eb2ad186988375e6055394e36e90c81323954b8a44eb08816fb7a84db2272") (hexstring_hashval "28d8599686476258c12dcc5fc5f5974335febd7d5259e1a8e5918b7f9b91ca03");;
Hashtbl.add mgrootassoc (hexstring_hashval "8f57a05ce4764eff8bc94b278352b6755f1a46566cd7220a5488a4a595a47189") (hexstring_hashval "2336eb45d48549dd8a6a128edc17a8761fd9043c180691483bcf16e1acc9f00a");;
Hashtbl.add mgrootassoc (hexstring_hashval "ed76e76de9b58e621daa601cca73b4159a437ba0e73114924cb92ec8044f2aa2") (hexstring_hashval "1b39e85278dd9e820e7b6258957386ac55934d784aa3702c57a28ec807453b01");;
Hashtbl.add mgrootassoc (hexstring_hashval "b2d51dcfccb9527e9551b0d0c47d891c9031a1d4ee87bba5a9ae5215025d107a") (hexstring_hashval "be07c39b18a3aa93f066f4c064fee3941ec27cfd07a4728b6209135c77ce5704");;
Hashtbl.add mgrootassoc (hexstring_hashval "11faa7a742daf8e4f9aaf08e90b175467e22d0e6ad3ed089af1be90cfc17314b") (hexstring_hashval "87d7604c7ea9a2ae0537066afb358a94e6ac0cd80ba277e6b064422035a620cf");;
Hashtbl.add mgrootassoc (hexstring_hashval "293b77d05dab711767d698fb4484aab2a884304256765be0733e6bd5348119e8") (hexstring_hashval "bf1decfd8f4025a2271f2a64d1290eae65933d0f2f0f04b89520449195f1aeb8");;
Hashtbl.add mgrootassoc (hexstring_hashval "be45dfaed6c479503a967f3834400c4fd18a8a567c8887787251ed89579f7be3") (hexstring_hashval "352082c509ab97c1757375f37a2ac62ed806c7b39944c98161720a584364bfaf");;
Hashtbl.add mgrootassoc (hexstring_hashval "e148e62186e718374accb69cda703e3440725cca8832aed55c0b32731f7401ab") (hexstring_hashval "030b1b3db48f720b8db18b1192717cad8f204fff5fff81201b9a2414f5036417");;
Hashtbl.add mgrootassoc (hexstring_hashval "7d10ab58310ebefb7f8bf63883310aa10fc2535f53bb48db513a868bc02ec028") (hexstring_hashval "9c6267051fa817eed39b404ea37e7913b3571fe071763da2ebc1baa56b4b77f5");;
Hashtbl.add mgrootassoc (hexstring_hashval "dd8f2d332fef3b4d27898ab88fa5ddad0462180c8d64536ce201f5a9394f40dd") (hexstring_hashval "faab5f334ba3328f24def7e6fcb974000058847411a2eb0618014eca864e537f");;
Hashtbl.add mgrootassoc (hexstring_hashval "91fff70be2f95d6e5e3fe9071cbd57d006bdee7d805b0049eefb19947909cc4e") (hexstring_hashval "933a1383079fba002694718ec8040dc85a8cca2bd54c5066c99fff135594ad7c");;
Hashtbl.add mgrootassoc (hexstring_hashval "8e748578991012f665a61609fe4f951aa5e3791f69c71f5a551e29e39855416c") (hexstring_hashval "f3affb534ca9027c56d1a15dee5adcbb277a5c372d01209261fee22c6dd6eab2");;
Hashtbl.add mgrootassoc (hexstring_hashval "119d13725af3373dd508f147836c2eff5ff5acf92a1074ad6c114b181ea8a933") (hexstring_hashval "9575c80a2655d3953184d74d13bd5860d4f415acbfc25d279378b4036579af65");;
Hashtbl.add mgrootassoc (hexstring_hashval "111dc52d4fe7026b5a4da1edbfb7867d219362a0e5da0682d7a644a362d95997") (hexstring_hashval "4e62ce5c996f13a11eb05d8dbff98e7acceaca2d3b3a570bea862ad74b79f4df");;
Hashtbl.add mgrootassoc (hexstring_hashval "eb32c2161bb5020efad8203cd45aa4738a4908823619b55963cc2fd1f9830098") (hexstring_hashval "22baf0455fa7619b6958e5bd762f4085bae580997860844329722650209d24bf");;
Hashtbl.add mgrootassoc (hexstring_hashval "855387af88aad68b5f942a3a97029fcd79fe0a4e781cdf546d058297f8a483ce") (hexstring_hashval "e007d96601771e291e9083ce21b5e97703bce4ff5257fec59b7ed3dbb05b5319");;
Hashtbl.add mgrootassoc (hexstring_hashval "b3bb92bcc166500c6f6465bf41e67a407d3435b2ce2ac6763fb02fac8e30640e") (hexstring_hashval "2890e728fd41ee56580615f32603326f19352dda5a1deea69ef696e560d62300");;
Hashtbl.add mgrootassoc (hexstring_hashval "0601c1c35ff2c84ae36acdecfae98d553546d98a227f007481baf6b962cc1dc8") (hexstring_hashval "0fa2c67750f22ef718feacbb3375b43caa7129d02200572180f9cfe7abf54cec");;
Hashtbl.add mgrootassoc (hexstring_hashval "d5afae717eff5e7035dc846b590d96bd5a7727284f8ff94e161398c148ab897f") (hexstring_hashval "3c539dbbee9d5ff440b9024180e52e9c2adde77bbaa8264d8f67d724d8c8cb25");;
Hashtbl.add mgrootassoc (hexstring_hashval "dda44134499f98b412d13481678ca2262d520390676ab6b40e0cb0e0768412f6") (hexstring_hashval "e24c519b20075049733185165766605b441fbcc5ee0900c9bd48c0c792ba5859");;
Hashtbl.add mgrootassoc (hexstring_hashval "30f11fc88aca72af37fd2a4235aa22f28a552bbc44f1fb01f4edf7f2b7e376ac") (hexstring_hashval "4b92ca0383b3989d01ddc4ec8bdf940b54163f9a29e460dfd502939eb880162f");;
Hashtbl.add mgrootassoc (hexstring_hashval "217a7f92acc207b15961c90039aa929f0bd5d9212f66ce5595c3af1dd8b9737e") (hexstring_hashval "39d80099e1b48aed4548f424ae4f1ff25b2d595828aff4b3a5abe232ca0348b5");;
Hashtbl.add mgrootassoc (hexstring_hashval "3ace9e6e064ec2b6e839b94e81788f9c63b22e51ec9dec8ee535d50649401cf4") (hexstring_hashval "8e3580f89907c6b36f6b57ad7234db3561b008aa45f8fa86d5e51a7a85cd74b6");;
Hashtbl.add mgrootassoc (hexstring_hashval "e3e6af0984cda0a02912e4f3e09614b67fc0167c625954f0ead4110f52ede086") (hexstring_hashval "8d2ef9c9e522891d1fe605a62dffeab8aefb6325650e4eab14135e7eee8002c5");;
Hashtbl.add mgrootassoc (hexstring_hashval "cd75b74e4a07d881da0b0eda458a004806ed5c24b08fd3fef0f43e91f64c4633") (hexstring_hashval "545700730c93ce350b761ead914d98adf2edbd5c9f253d9a6df972641fee3aed");;
Hashtbl.add mgrootassoc (hexstring_hashval "a01360cac9e6ba0460797b632a50d83b7fadb5eadb897964c7102639062b23ba") (hexstring_hashval "61506fb3d41686d186b4403e49371053ce82103f40b14367780a74e0d62e06bf");;
Hashtbl.add mgrootassoc (hexstring_hashval "939baef108d0de16a824c79fc4e61d99b3a9047993a202a0f47c60d551b65834") (hexstring_hashval "de068dc4f75465842d1d600bf2bf3a79223eb41ba14d4767bbaf047938e706ec");;
Hashtbl.add mgrootassoc (hexstring_hashval "24615c6078840ea77a483098ef7fecf7d2e10585bf1f31bd0c61fbaeced3ecb8") (hexstring_hashval "7830817b065e5068a5d904d993bb45fa4ddb7b1157b85006099fa8b2d1698319");;
Hashtbl.add mgrootassoc (hexstring_hashval "185d8f16b44939deb8995cbb9be7d1b78b78d5fc4049043a3b6ccc9ec7b33b41") (hexstring_hashval "aa0da3fb21dcb8f9e118c9149aed409bb70d0408a316f1cce303813bf2428859");;
Hashtbl.add mgrootassoc (hexstring_hashval "cd4f601256fbe0285d49ded42c4f554df32a64182e0242462437212fe90b44cd") (hexstring_hashval "3727e8cd9a7e7bc56ef00eafdefe3e298cfb2bd8340a0f164b9611ce2f2e3b2a");;
Hashtbl.add mgrootassoc (hexstring_hashval "612d4b4fd0d22dd5985c10cf0fed7eda4e18dce70710ebd2cd5e91acf3995937") (hexstring_hashval "f61cccfd432116f3443aff9f776423c64eaa3691d3634bf423d5ddd89caaa136");;
Hashtbl.add mgrootassoc (hexstring_hashval "3fb62f75e778736947d086a36d35ebe45a5d60bf0a340a0761ba08a396d4123a") (hexstring_hashval "4a59caa11140eabb1b7db2d3493fe76a92b002b3b27e3dfdd313708c6c6ca78f");;
Hashtbl.add mgrootassoc (hexstring_hashval "a61e60c0704e01255992ecc776a771ad4ef672b2ed0f4edea9713442d02c0ba9") (hexstring_hashval "5ec40a637f9843917a81733636ffe333120e9a78db0c1236764d271d8704674a");;
Hashtbl.add mgrootassoc (hexstring_hashval "9683ebbbd2610b6b9f8f9bb32a63d9d3cf8c376a919e6989444d6d995da2aceb") (hexstring_hashval "8bf54ee811b0677aba3d56bc61913a6d81475e1022faa43989b56bfa7aed2021");;
Hashtbl.add mgrootassoc (hexstring_hashval "7cf43a3b8ce0af790f9fc86020fd06ab45e597b29a7ff1dbbe8921910d68638b") (hexstring_hashval "a5462d7cd964ae608154fbea57766c59c7e8a63f8b6d7224fdacf7819d6543b7");;
Hashtbl.add mgrootassoc (hexstring_hashval "c14dd5291f7204df5484a3c38ca94107f29d636a3cdfbd67faf1196b3bf192d6") (hexstring_hashval "96a3e501560225fd48b85405b64d8f27956fb33c35c2ef330600bc21c1ef0f6b");;
Hashtbl.add mgrootassoc (hexstring_hashval "ec4f9ffffa60d2015503172b35532a59cebea3390c398d0157fd3159e693eb97") (hexstring_hashval "55e8bac8e9f8532e25fccb59d629f4f95d54a534cc861e1a106d746d54383308");;
Hashtbl.add mgrootassoc (hexstring_hashval "cbcee236e6cb4bea1cf64f58905668aa36807a85032ea58e6bb539f5721ff4c4") (hexstring_hashval "37d77be7592c2812416b2592340280e577cddf5b5ea328b2cb4ded30e0361515");;
Hashtbl.add mgrootassoc (hexstring_hashval "aa9e02604aeaede16041c30137af87a14a6dd9733da1e227cc7d6b966907c706") (hexstring_hashval "d4477da9be2011c148b7904162d5432e65ca0aa4565b8bb2822c6fa0a63f4fea");;
Hashtbl.add mgrootassoc (hexstring_hashval "2f43ee814823893eab4673fb76636de742c4d49e63bd645d79baa4d423489f20") (hexstring_hashval "243cf5991540062f744d26d5acf1f57122889c3ec2939d5226591e58b27a1669");;
Hashtbl.add mgrootassoc (hexstring_hashval "51b1b6cf343b691168d1f26c39212233b95f9ae7efa3be71d53540eaa3c849ab") (hexstring_hashval "119dceedb8bcb74f57da40dcfdf9ac97c6bea3532eab7e292bcfdd84f2505ae9");;
Hashtbl.add mgrootassoc (hexstring_hashval "83e7eeb351d92427c0d3bb2bd24e83d0879191c3aa01e7be24fb68ffdbb9060c") (hexstring_hashval "e617a2c69bd7575dc6ebd47c67ca7c8b08c0c22a914504a403e3db24ee172987");;
Hashtbl.add mgrootassoc (hexstring_hashval "c9ca029e75ae9f47e0821539f84775cc07258db662e0b5ccf4a423c45a480766") (hexstring_hashval "0c2f8a60f76952627b3e2c9597ef5771553931819c727dea75b98b59b548b5ec");;
Hashtbl.add mgrootassoc (hexstring_hashval "755e4e2e4854b160b8c7e63bfc53bb4f4d968d82ce993ef8c5b5c176c4d14b33") (hexstring_hashval "0dcb26ac08141ff1637a69d653711c803f750140584a4da769aefebb168b9257");;
Hashtbl.add mgrootassoc (hexstring_hashval "7004278ccd490dc5f231c346523a94ad983051f8775b8942916378630dd40008") (hexstring_hashval "1c031505cc8bf49a0512a2238ae989977d9857fddee5960613267874496a28be");;
Hashtbl.add mgrootassoc (hexstring_hashval "b94d6880c1961cc8323e2d6df4491604a11b5f2bf723511a06e0ab22f677364d") (hexstring_hashval "81ac7e6231b8c316b5c2cb16fbb5f8038e2425b2efd9bd0fc382bc3d448a259d");;
Hashtbl.add mgrootassoc (hexstring_hashval "6859fb13a44929ca6d7c0e598ffc6a6f82969c8cfe5edda33f1c1d81187b9d31") (hexstring_hashval "0ca5ba562d2ab04221b86aded545ed077bf3a2f06e21344f04ba0b43521b231e");;
Hashtbl.add mgrootassoc (hexstring_hashval "7685bdf4f6436a90f8002790ede7ec64e03b146138f7d85bc11be7d287d3652b") (hexstring_hashval "af2850387310cf676e35267e10a14affc439a209ad200b7edc42d8142611fcd4");;
Hashtbl.add mgrootassoc (hexstring_hashval "0708055ba3473c2f52dbd9ebd0f0042913b2ba689b64244d92acea4341472a1d") (hexstring_hashval "78cabd5521b666604d7b8deee71a25d12741bbd39d84055b85d0a613ef13614c");;
Hashtbl.add mgrootassoc (hexstring_hashval "1bcc21b2f13824c926a364c5b001d252d630f39a0ebe1f8af790facbe0f63a11") (hexstring_hashval "eb93435a79c01148fc12dd7779795d68cc2251130dc7633623f16664d25ed072");;
Hashtbl.add mgrootassoc (hexstring_hashval "32dcc27d27b5003a86f8b13ba9ca16ffaec7168a11c5d9850940847c48148591") (hexstring_hashval "b2707c82b8b416a22264d2934d5221d1115ea55732f96cbb6663fbf7e945d3e3");;
Hashtbl.add mgrootassoc (hexstring_hashval "5be570b4bcbe7fefd36c2057491ddcc7b11903d8d98ca54d9b37db60d1bf0f7e") (hexstring_hashval "be660f6f1e37e7325ec2a39529b9c937b61a60f864e85f0dabdf2bddacb0986e");;
Hashtbl.add mgrootassoc (hexstring_hashval "a18f7bca989a67fb7dc6df8e6c094372c26fa2c334578447d3314616155afb72") (hexstring_hashval "1195f96dcd143e4b896b4c1eb080d1fb877084debc58a8626d3dcf7a14ce8df7");;
Hashtbl.add mgrootassoc (hexstring_hashval "f1c45e0e9f9df75c62335865582f186c3ec3df1a94bc94b16d41e73bf27899f9") (hexstring_hashval "f97b150093ec13f84694e2b8f48becf45e4b6df2b43c1085ae7a99663116b9a6");;
Hashtbl.add mgrootassoc (hexstring_hashval "2c81615a11c9e3e301f3301ec7862ba122acea20bfe1c120f7bdaf5a2e18faf4") (hexstring_hashval "e5dee14fc7a24a63555de85859904de8dc1b462044060d68dbb06cc9a590bc38");;
Hashtbl.add mgrootassoc (hexstring_hashval "9072a08b056e30edab702a9b7c29162af6170c517da489a9b3eab1a982fdb325") (hexstring_hashval "cad943ad3351894d7ba6a26fa37c5f118d52cb5656335ca3b111d786455306e6");;
Hashtbl.add mgrootassoc (hexstring_hashval "33f36e749d7a3683affaed574c634802fe501ef213c5ca5e7c8dc0153464ea3e") (hexstring_hashval "721b554268a9a69ec4ddc429f9be98a164c8910b662e21de0b0a667d19ac127f");;
Hashtbl.add mgrootassoc (hexstring_hashval "9216abdc1fcc466f5af2b17824d279c6b333449b4f283df271151525ba7c9aca") (hexstring_hashval "dd4f4556431118d331981429937597efc8bf48e610d5e8046b728dd65002585d");;
Hashtbl.add mgrootassoc (hexstring_hashval "597c2157fb6463f8c1c7affb6f14328b44b57967ce9dff5ef3c600772504b9de") (hexstring_hashval "12676b0afcebdd531bf5a99c2866d8f7da6b16c994f66eb12f1405c9fd63e375");;
Hashtbl.add mgrootassoc (hexstring_hashval "15c0a3060fb3ec8e417c48ab46cf0b959c315076fe1dc011560870c5031255de") (hexstring_hashval "c932a6d0f2ee29b573c0be25ba093beec021e0fc0b04c4e76b8d0c627a582f33");;
Hashtbl.add mgrootassoc (hexstring_hashval "4b1aa61ecf07fd27a8a97a4f5ac5a6df80f2d3ad5f55fc4cc58e6d3e76548591") (hexstring_hashval "84039222ea9e2c64fdc0a7ed6ea36601e7a743d9f5d57a381275ce025b4ab636");;
Hashtbl.add mgrootassoc (hexstring_hashval "55cacef892af061835859ed177e5442518c93eb7ee28697cde3deaec5eafbf01") (hexstring_hashval "76c3f5c92d9fb5491c366bf4406686f6bb2d99a486ebe880c2b1d491036f79c0");;
Hashtbl.add mgrootassoc (hexstring_hashval "bacb8536bbb356aa59ba321fb8eade607d1654d8a7e0b33887be9afbcfa5c504") (hexstring_hashval "552d05a240b7958c210e990f72c4938aa612373e1d79a5d97fa37f80e3d844b3");;
Hashtbl.add mgrootassoc (hexstring_hashval "268a6c1da15b8fe97d37be85147bc7767b27098cdae193faac127195e8824808") (hexstring_hashval "6d39c64862ac40c95c6f5e4ed5f02bb019279bfb0cda8c9bbe0e1b813b1e876c");;
Hashtbl.add mgrootassoc (hexstring_hashval "127d043261bd13d57aaeb99e7d2c02cae2bd0698c0d689b03e69f1ac89b3c2c6") (hexstring_hashval "29b9b279a7a5b776b777d842e678a4acaf3b85b17a0223605e4cc68025e9b2a7");;
Hashtbl.add mgrootassoc (hexstring_hashval "48d05483e628cb37379dd5d279684d471d85c642fe63533c3ad520b84b18df9d") (hexstring_hashval "f56bf39b8eea93d7f63da529dedb477ae1ab1255c645c47d8915623f364f2d6b");;
Hashtbl.add mgrootassoc (hexstring_hashval "34f6dccfd6f62ca020248cdfbd473fcb15d8d9c5c55d1ec7c5ab6284006ff40f") (hexstring_hashval "9f9389c36823b2e0124a7fe367eb786d080772b5171a5d059b10c47361cef0ef");;
Hashtbl.add mgrootassoc (hexstring_hashval "8efb1973b4a9b292951aa9ca2922b7aa15d8db021bfada9c0f07fc9bb09b65fb") (hexstring_hashval "94ec6541b5d420bf167196743d54143ff9e46d4022e0ccecb059cf098af4663d");;
Hashtbl.add mgrootassoc (hexstring_hashval "89fb5e380d96cc4a16ceba7825bfbc02dfd37f2e63dd703009885c4bf3794d07") (hexstring_hashval "9841164c05115cc07043487bccc48e1ce748fa3f4dfc7d109f8286f9a5bce324");;
Hashtbl.add mgrootassoc (hexstring_hashval "b3a2fc60275daf51e6cbe3161abaeed96cb2fc4e1d5fe26b5e3e58d0eb93c477") (hexstring_hashval "3db063fdbe07c7344b83deebc95b091786045a06e01e2ce6e2eae1d885f574af");;
Hashtbl.add mgrootassoc (hexstring_hashval "98aa98f64160bebd5622706908b639f9fdfe4056f2678ed69e5b099b8dd7b888") (hexstring_hashval "606d31b0ebadd0ba5b2644b171b831936b36964cb4ca899eebfac62651e1c270");;
Hashtbl.add mgrootassoc (hexstring_hashval "e1df2c6881a945043093f666186fa5159d4b31d68340b37bd2be81d10ba28060") (hexstring_hashval "ea953ac10b642a9da289025dff57d46f78a32954a0c94609646f8f83d8119728");;
Hashtbl.add mgrootassoc (hexstring_hashval "5e5ba235d9b0b40c084850811a514efd2e7f76df45b4ca1be43ba33c41356d3b") (hexstring_hashval "c60ee42484639ad65bdabfeeb7220f90861c281a74898207df2b83c9dbe71ee3");;
Hashtbl.add mgrootassoc (hexstring_hashval "736c836746de74397a8fa69b6bbd46fc21a6b3f1430f6e4ae87857bf6f077989") (hexstring_hashval "c934b0a37a42002a6104de6f7753559507f7fc42144bbd2d672c37e984e3a441");;
Hashtbl.add mgrootassoc (hexstring_hashval "255c25547da742d6085a5308f204f5b90d6ba5991863cf0b3e4036ef74ee35a2") (hexstring_hashval "9134ada3d735402039f76383770584fc0f331d09a6678c60511c4437b58c8986");;
Hashtbl.add mgrootassoc (hexstring_hashval "fcf3391eeb9d6b26a8b41a73f701da5e27e74021d7a3ec1b11a360045a5f13ca") (hexstring_hashval "ff30733afb56aca63687fac2b750743306c2142ffbfafc95a8ecc167da4fd5fa");;
Hashtbl.add mgrootassoc (hexstring_hashval "e26ffa4403d3e38948f53ead677d97077fe74954ba92c8bb181aba8433e99682") (hexstring_hashval "0d955384652ad934e09a854e236e549b47a140bb15c1ad93b6b63a51593ab579");;

let mgsubq = hexstring_hashval "81c0efe6636cef7bc8041820a3ebc8dc5fa3bc816854d8b7f507e30425fc1cef";;
let mgordsucc = hexstring_hashval "65d8837d7b0172ae830bed36c8407fcd41b7d875033d2284eb2df245b42295a6";;

let church_tuple_type a =
  match a with
  | TpArr(TpArr(b1,TpArr(b2,b3)),c) when b1 = c && b2 = c ->
     let rec church_tuple_type_r b n =
       if b = c then
         Some(c,n)
       else
         match b with
         | TpArr(b1,b2) when b1 = c ->
            church_tuple_type_r b2 (n+1)
         | _ -> None
     in
     church_tuple_type_r b3 2
  | _ -> None

let mghtml_nice_stp th a =
  let par p s =
    if p then Printf.sprintf "(%s)" s else s
  in
  let rec mghtml_nice_stp_r a p =
    match church_tuple_type a with
    | Some(b,n) ->
       par p (Printf.sprintf "<span title='church tuple type' class='churchtupletp'>CT%d %s</span>" n (mghtml_nice_stp_r b true))
    | _ ->
       match a with
       | Base(0) -> "<span title='base type' class='base'>&iota;</span>"
       | Base(i) -> Printf.sprintf "<span title='base type' class='base'>base%d</span>" i
       | Prop -> "<span title='type of propositions' class='prop'>&omicron;</span>"
       | TpArr(TpArr(b,b2),TpArr(b3,b4)) when not (b = Base(0)) && b = b2 && b = b3 && b = b4 -> par p (Printf.sprintf "<span title='church num type' class='churchnumtp1'>CN %s</span>" (mghtml_nice_stp_r b true))
       | TpArr(b,TpArr(TpArr(b2,b3),b4)) when not (b = Base(0)) && b = b2 && b = b3 && b = b4 -> par p (Printf.sprintf "<span title='church num type' class='churchnumtp2'>CN' %s</span>" (mghtml_nice_stp_r b true))
       | TpArr(a1,a2) -> par p (Printf.sprintf "<span title='function type' class='arrtp'>%s &rarr; %s</span>" (mghtml_nice_stp_r a1 true) (mghtml_nice_stp_r a2 false))
  in
  mghtml_nice_stp_r a false

let mg_stp a =
  let par p s =
    if p then Printf.sprintf "(%s)" s else s
  in
  let rec mg_stp_r a p =
    match a with
    | Base(0) -> "set"
    | Base(i) -> Printf.sprintf "base%d" i
    | Prop -> "prop"
    | TpArr(a1,a2) -> par p (Printf.sprintf "%s -> %s" (mg_stp_r a1 true) (mg_stp_r a2 false))
  in
  mg_stp_r a false

let mg_n_stp a =
  if !mgnicestp then
    mghtml_nice_stp None a
  else
    mg_stp a

let mg_fin_ord m =
  let rec mg_fin_ord_r m n =
    match m with
    | Prim(2) -> Some(n)
    | Ap(TmH(h),m2) when h = mgordsucc -> mg_fin_ord_r m2 (n+1)
    | _ -> None
  in
  mg_fin_ord_r m 0

let hf_fin_ord m =
  let rec hf_fin_ord_r m n =
    match m with
    | Prim(9) -> Some(n)
    | Ap(Prim(57),m2) -> hf_fin_ord_r m2 (n+1)
    | _ -> None
  in
  hf_fin_ord_r m 0

let rec free_in i m =
  match m with
  | DB(j) -> j = i
  | Ap(m1,m2) -> free_in i m1 || free_in i m2
  | Imp(m1,m2) -> free_in i m1 || free_in i m2
  | Eq(_,m1,m2) -> free_in i m1 || free_in i m2
  | Lam(_,m1) -> free_in (i+1) m1
  | All(_,m1) -> free_in (i+1) m1
  | Ex(_,m1) -> free_in (i+1) m1
  | _ -> false

let mg_abbrv s = Printf.sprintf "<span class='noname'>%s</span>" (String.sub s 0 5 ^ "..");;

(** copied from Megalodon with modifications BEGIN **)
type setinfixop = InfMem | InfSubq

type infixop =
  | InfSet of setinfixop
  | InfNam of string

type asckind = AscTp | AscSet | AscSubeq

type atree =
  | Byte of int
  | String of string
  | QString of string
  | Na of string
  | Nu of bool * string * string option * string option
  | Le of string * (asckind * atree) option * atree * atree
  | LeM of string * string list * atree * atree
  | Bi of string * (string list * (asckind * atree) option) list * atree
  | Preo of string * atree
  | Posto of string * atree
  | Info of infixop * atree * atree
  | Implop of atree * atree
  | Sep of string * setinfixop * atree * atree
  | Rep of string * setinfixop * atree * atree
  | SepRep of string * setinfixop * atree * atree * atree
  | SetEnum of atree list
  | MTuple of atree * atree list
  | Tuple of atree * atree * atree list
  | IfThenElse of atree * atree * atree

type ltree =
  | ByteL of int
  | StringL of string
  | QStringL of string
  | NaL of string
  | NuL of bool * string * string option * string option
  | LeL of string * (asckind * ltree) option * ltree * ltree
  | LeML of string * string list * ltree * ltree
  | BiL of string * string * (string list * (asckind * ltree) option) list * ltree
  | PreoL of string * ltree
  | PostoL of string * ltree
  | InfoL of infixop * ltree * ltree
  | ImplopL of ltree * ltree
  | SepL of string * setinfixop * ltree * ltree
  | RepL of string * setinfixop * ltree * ltree
  | SepRepL of string * setinfixop * ltree * ltree * ltree
  | SetEnumL of ltree list
  | MTupleL of ltree * ltree list
  | ParenL of ltree * ltree list
  | IfThenElseL of ltree * ltree * ltree

let rec binderishp (a:ltree) : bool =
  match a with
  | BiL(_) -> true
  | LeL(_) -> true
  | LeML(_) -> true
  | IfThenElseL(_) -> true
  | PreoL(x,a) -> binderishp a
  | InfoL(i,a,b) -> binderishp b
  | _ -> false

let setinfixop_string i =
  match i with
  | InfMem -> "&in;"
  | InfSubq -> "&sube;"

let asckind_string i =
  match i with
  | AscTp -> ":"
  | AscSet -> "&in;"
  | AscSubeq -> "&sube;"

(** modified to put into buffer instead of output to channel **)
let rec buffer_ltree ch a =
  match a with
  | ByteL(x) -> Buffer.add_string ch (Printf.sprintf "\\x%02x" x)
  | StringL(x) -> Buffer.add_char ch '"'; Buffer.add_string ch x; Buffer.add_char ch '"'
  | QStringL(x) -> Buffer.add_char ch '?'; Buffer.add_string ch x; Buffer.add_char ch '?'
  | NaL(x) -> Buffer.add_string ch x
  | NuL(b,x,None,None) ->
      begin
	if b then Buffer.add_char ch '-';
	Buffer.add_string ch x;
      end
  | NuL(b,x,Some y,None) ->
      begin
	if b then Buffer.add_char ch '-';
	Buffer.add_string ch x;
	Buffer.add_char ch '.';
	Buffer.add_string ch y;
      end
  | NuL(b,x,None,Some z) ->
      begin
	if b then Buffer.add_char ch '-';
	Buffer.add_string ch x;
	Buffer.add_char ch 'E';
	Buffer.add_string ch z;
      end
  | NuL(b,x,Some y,Some z) ->
      begin
	if b then Buffer.add_char ch '-';
	Buffer.add_string ch x;
	Buffer.add_char ch '.';
	Buffer.add_string ch y;
	Buffer.add_char ch 'E';
	Buffer.add_string ch z;
      end
  | LeL(x,None,a,c) ->
      Buffer.add_string ch "let ";
      Buffer.add_string ch x;
      Buffer.add_string ch " := ";
      buffer_ltree ch a;
      Buffer.add_string ch " in ";
      buffer_ltree ch c
  | LeL(x,Some (i,b),a,c) ->
      Buffer.add_string ch "let ";
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (asckind_string i);
      Buffer.add_char ch ' ';
      buffer_ltree ch b;
      Buffer.add_string ch " := ";
      buffer_ltree ch a;
      Buffer.add_string ch " in ";
      buffer_ltree ch c
  | LeML(x,xl,a,c) ->
      Buffer.add_string ch "let [";
      Buffer.add_string ch x;
      List.iter (fun y -> Buffer.add_char ch ','; Buffer.add_string ch y) xl;
      Buffer.add_string ch "] := ";
      buffer_ltree ch a;
      Buffer.add_string ch " in ";
      buffer_ltree ch c
  | BiL(x,m,[(xl,None)],c) ->
      Buffer.add_string ch x;
      List.iter (fun y -> Buffer.add_char ch ' '; Buffer.add_string ch y) xl;
      Buffer.add_char ch ' ';
      Buffer.add_string ch m;
      Buffer.add_char ch ' ';
      buffer_ltree ch c
  | BiL(x,m,[(xl,Some(i,b))],c) ->
      Buffer.add_string ch x;
      List.iter (fun y -> Buffer.add_char ch ' '; Buffer.add_string ch y) xl;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (asckind_string i);
      Buffer.add_char ch ' ';
      buffer_ltree ch b;
      Buffer.add_char ch ' ';
      Buffer.add_string ch m;
      Buffer.add_char ch ' ';
      buffer_ltree ch c
  | BiL(x,m,vll,c) ->
      Buffer.add_string ch x;
      List.iter
	(fun vl ->
	  Buffer.add_string ch " (";
	  let nfst = ref false in
	  begin
	    match vl with
	    | (xl,None) ->
		List.iter (fun y -> if !nfst then Buffer.add_char ch ' '; nfst := true; Buffer.add_string ch y) xl;
	    | (xl,Some(AscTp,b)) ->
		List.iter (fun y -> if !nfst then Buffer.add_char ch ' '; nfst := true; Buffer.add_string ch y) xl;
		Buffer.add_string ch " : ";
		buffer_ltree ch b
	    | (xl,Some(AscSet,b)) ->
		List.iter (fun y -> if !nfst then Buffer.add_char ch ' '; nfst := true; Buffer.add_string ch y) xl;
		Buffer.add_string ch " :e ";
		buffer_ltree ch b
	    | (xl,Some(AscSubeq,b)) ->
		List.iter (fun y -> if !nfst then Buffer.add_char ch ' '; nfst := true; Buffer.add_string ch y) xl;
		Buffer.add_string ch " c= ";
		buffer_ltree ch b
	  end;
	  Buffer.add_char ch ')';
	  )
	vll;
      Buffer.add_char ch ' ';
      Buffer.add_string ch m;
      Buffer.add_char ch ' ';
      buffer_ltree ch c
  | PreoL(x,a) ->
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      buffer_ltree ch a
  | PostoL(x,a) ->
      buffer_ltree ch a;
      Buffer.add_char ch ' ';
      Buffer.add_string ch x
  | InfoL(InfSet i,a,b) ->
      buffer_ltree ch a;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (setinfixop_string i);
      Buffer.add_char ch ' ';
      buffer_ltree ch b
  | InfoL(InfNam x,a,b) ->
      buffer_ltree ch a;
      Buffer.add_char ch ' ';
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      buffer_ltree ch b
  | ImplopL(a,b) ->
      buffer_ltree ch a;
      Buffer.add_char ch ' ';
      buffer_ltree ch b
  | SepL(x,i,a,b) ->
      Buffer.add_char ch '{';
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (setinfixop_string i);
      Buffer.add_char ch ' ';
      buffer_ltree ch a;
      Buffer.add_char ch '|';
      buffer_ltree ch b;
      Buffer.add_char ch '}';
  | RepL(x,i,a,b) ->
      Buffer.add_char ch '{';
      buffer_ltree ch a;
      Buffer.add_char ch '|';
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (setinfixop_string i);
      Buffer.add_char ch ' ';
      buffer_ltree ch b;
      Buffer.add_char ch '}';
  | SepRepL(x,i,a,b,c) ->
      Buffer.add_char ch '{';
      buffer_ltree ch a;
      Buffer.add_char ch '|';
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (setinfixop_string i);
      Buffer.add_char ch ' ';
      buffer_ltree ch b;
      Buffer.add_char ch ',';
      buffer_ltree ch c;
      Buffer.add_char ch '}';
  | SetEnumL(al) ->
      begin
	Buffer.add_char ch '{';
	match al with
	| [] -> Buffer.add_char ch '}';
	| (a::bl) ->
	    buffer_ltree ch a;
	    List.iter (fun b -> Buffer.add_char ch ','; buffer_ltree ch b) bl;
	    Buffer.add_char ch '}';
      end
  | MTupleL(a,bl) ->
      Buffer.add_char ch '[';
      buffer_ltree ch a;
      List.iter (fun b -> Buffer.add_char ch ','; buffer_ltree ch b) bl;
      Buffer.add_char ch ']';
  | ParenL(a,bl) ->
      Buffer.add_char ch '(';
      buffer_ltree ch a;
      List.iter (fun b -> Buffer.add_char ch ','; buffer_ltree ch b) bl;
      Buffer.add_char ch ')';
  | IfThenElseL(a,b,c) ->
      Buffer.add_string ch "if ";
      buffer_ltree ch a;
      Buffer.add_string ch " then ";
      buffer_ltree ch b;
      Buffer.add_string ch " else ";
      buffer_ltree ch c

let rec buffer2_ltree ch a =
  match a with
  | ByteL(x) -> Buffer.add_string ch (Printf.sprintf "<span title='byte term' class='byte'>\\x%02x</span>" x)
  | StringL(x) -> Buffer.add_string ch "<span title='string term' class='string'>"; Buffer.add_char ch '"'; Buffer.add_string ch x; Buffer.add_char ch '"'; Buffer.add_string ch "</span>";
  | QStringL(x) -> Buffer.add_string ch "<span title='blank term' class='qstring'>"; Buffer.add_char ch '?'; Buffer.add_string ch x; Buffer.add_char ch '?'; Buffer.add_string ch "</span>";
  | NaL(x) ->
     (* Buffer.add_string ch "<span class='name'>"; *)
     Buffer.add_string ch x;
     (* Buffer.add_string ch "</span>"; *)
  | NuL(b,x,None,None) ->
      begin
        Buffer.add_string ch "<span title='integer term' class='num'>"; 
	if b then Buffer.add_char ch '-';
	Buffer.add_string ch x;
        Buffer.add_string ch "</span>";
      end
  | NuL(b,x,Some y,None) ->
      begin
        Buffer.add_string ch "<span title='number term' class='num'>"; 
	if b then Buffer.add_char ch '-';
	Buffer.add_string ch x;
	Buffer.add_char ch '.';
	Buffer.add_string ch y;
        Buffer.add_string ch "</span>";
      end
  | NuL(b,x,None,Some z) ->
      begin
        Buffer.add_string ch "<span title='number term' class='num'>"; 
	if b then Buffer.add_char ch '-';
	Buffer.add_string ch x;
	Buffer.add_char ch 'E';
	Buffer.add_string ch z;
        Buffer.add_string ch "</span>";
      end
  | NuL(b,x,Some y,Some z) ->
      begin
        Buffer.add_string ch "<span title='number term' class='num'>"; 
	if b then Buffer.add_char ch '-';
	Buffer.add_string ch x;
	Buffer.add_char ch '.';
	Buffer.add_string ch y;
	Buffer.add_char ch 'E';
	Buffer.add_string ch z;
        Buffer.add_string ch "</span>";
      end
  | LeL(x,None,a,c) ->
      Buffer.add_string ch "<span title='let term' class='let'>"; 
      Buffer.add_string ch "let ";
      Buffer.add_string ch x;
      Buffer.add_string ch " := ";
      buffer2_ltree ch a;
      Buffer.add_string ch " in ";
      buffer2_ltree ch c;
      Buffer.add_string ch "</span>";
  | LeL(x,Some (i,b),a,c) ->
      Buffer.add_string ch "<span title='let term' class='let'>"; 
      Buffer.add_string ch "let ";
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (asckind_string i);
      Buffer.add_char ch ' ';
      buffer2_ltree ch b;
      Buffer.add_string ch " := ";
      buffer2_ltree ch a;
      Buffer.add_string ch " in ";
      buffer2_ltree ch c;
      Buffer.add_string ch "</span>";
  | LeML(x,xl,a,c) ->
      Buffer.add_string ch "<span title='let term for church tuples' class='mlet'>"; 
      Buffer.add_string ch "let [";
      Buffer.add_string ch x;
      List.iter (fun y -> Buffer.add_char ch ','; Buffer.add_string ch y) xl;
      Buffer.add_string ch "] := ";
      buffer2_ltree ch a;
      Buffer.add_string ch " in ";
      buffer2_ltree ch c;
      Buffer.add_string ch "</span>";
  | BiL(x,m,[(xl,None)],c) ->
      Buffer.add_string ch "<span title='binder term' class='binder'>"; 
      Buffer.add_string ch x;
      List.iter (fun y -> Buffer.add_char ch ' '; Buffer.add_string ch y) xl;
      Buffer.add_char ch ' ';
      Buffer.add_string ch m;
      Buffer.add_char ch ' ';
      buffer2_ltree ch c;
      Buffer.add_string ch "</span>";
  | BiL(x,m,[(xl,Some(i,b))],c) ->
      Buffer.add_string ch "<span title='binder term' class='binder'>"; 
      Buffer.add_string ch x;
      List.iter (fun y -> Buffer.add_char ch ' '; Buffer.add_string ch y) xl;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (asckind_string i);
      Buffer.add_char ch ' ';
      buffer2_ltree ch b;
      Buffer.add_char ch ' ';
      Buffer.add_string ch m;
      Buffer.add_char ch ' ';
      buffer2_ltree ch c;
      Buffer.add_string ch "</span>";
  | BiL(x,m,vll,c) ->
      Buffer.add_string ch "<span title='binder term' class='binder'>"; 
      Buffer.add_string ch x;
      List.iter
	(fun vl ->
	  Buffer.add_string ch " (";
	  let nfst = ref false in
	  begin
	    match vl with
	    | (xl,None) ->
		List.iter (fun y -> if !nfst then Buffer.add_char ch ' '; nfst := true; Buffer.add_string ch y) xl;
	    | (xl,Some(AscTp,b)) ->
		List.iter (fun y -> if !nfst then Buffer.add_char ch ' '; nfst := true; Buffer.add_string ch y) xl;
		Buffer.add_string ch " : ";
		buffer2_ltree ch b
	    | (xl,Some(AscSet,b)) ->
		List.iter (fun y -> if !nfst then Buffer.add_char ch ' '; nfst := true; Buffer.add_string ch y) xl;
		Buffer.add_string ch " :e ";
		buffer2_ltree ch b
	    | (xl,Some(AscSubeq,b)) ->
		List.iter (fun y -> if !nfst then Buffer.add_char ch ' '; nfst := true; Buffer.add_string ch y) xl;
		Buffer.add_string ch " c= ";
		buffer2_ltree ch b
	  end;
	  Buffer.add_char ch ')';
	  )
	vll;
      Buffer.add_char ch ' ';
      Buffer.add_string ch m;
      Buffer.add_char ch ' ';
      buffer2_ltree ch c;
      Buffer.add_string ch "</span>";
  | PreoL(x,a) ->
      Buffer.add_string ch "<span title='prefix operator term' class='prefixop'>"; 
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      buffer2_ltree ch a;
      Buffer.add_string ch "</span>";
  | PostoL(x,a) ->
      Buffer.add_string ch "<span title='postfix operator term' class='postfixop'>"; 
      buffer2_ltree ch a;
      Buffer.add_char ch ' ';
      Buffer.add_string ch x;
      Buffer.add_string ch "</span>";
  | InfoL(InfSet i,a,b) ->
      Buffer.add_string ch "<span title='infix operator term' class='infixop'>"; 
      buffer2_ltree ch a;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (setinfixop_string i);
      Buffer.add_char ch ' ';
      buffer2_ltree ch b;
      Buffer.add_string ch "</span>";
  | InfoL(InfNam x,a,b) ->
      Buffer.add_string ch "<span title='infix operator term' class='infixop'>"; 
      buffer2_ltree ch a;
      Buffer.add_char ch ' ';
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      buffer2_ltree ch b;
      Buffer.add_string ch "</span>";
  | ImplopL(a,b) ->
      Buffer.add_string ch "<span title='implicit operator term' class='implicitop'>"; 
      buffer2_ltree ch a;
      Buffer.add_char ch ' ';
      buffer2_ltree ch b;
      Buffer.add_string ch "</span>";
  | SepL(x,i,a,b) ->
      Buffer.add_string ch "<span title='Zermelo separation set term' class='separation'>"; 
      Buffer.add_char ch '{';
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (setinfixop_string i);
      Buffer.add_char ch ' ';
      buffer2_ltree ch a;
      Buffer.add_char ch '|';
      buffer2_ltree ch b;
      Buffer.add_char ch '}';
      Buffer.add_string ch "</span>";
  | RepL(x,i,a,b) ->
      Buffer.add_string ch "<span title='Fraenkel replacement set term' class='replacement'>"; 
      Buffer.add_char ch '{';
      buffer2_ltree ch a;
      Buffer.add_char ch '|';
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (setinfixop_string i);
      Buffer.add_char ch ' ';
      buffer2_ltree ch b;
      Buffer.add_char ch '}';
      Buffer.add_string ch "</span>";
  | SepRepL(x,i,a,b,c) ->
      Buffer.add_string ch "<span title='ZF replacement with separation term' class='separationreplacement'>"; 
      Buffer.add_char ch '{';
      buffer2_ltree ch a;
      Buffer.add_char ch '|';
      Buffer.add_string ch x;
      Buffer.add_char ch ' ';
      Buffer.add_string ch (setinfixop_string i);
      Buffer.add_char ch ' ';
      buffer2_ltree ch b;
      Buffer.add_char ch ',';
      buffer2_ltree ch c;
      Buffer.add_char ch '}';
      Buffer.add_string ch "</span>";
  | SetEnumL(al) ->
      Buffer.add_string ch "<span title='finite enumeration term' class='setenum'>"; 
      begin
	Buffer.add_char ch '{';
	match al with
	| [] -> Buffer.add_char ch '}';
	| (a::bl) ->
	    buffer2_ltree ch a;
	    List.iter (fun b -> Buffer.add_char ch ','; buffer2_ltree ch b) bl;
	    Buffer.add_char ch '}';
      end;
      Buffer.add_string ch "</span>";
  | MTupleL(a,bl) ->
      Buffer.add_string ch "<span title='church tuple' class='mtuple'>"; 
      Buffer.add_char ch '[';
      buffer2_ltree ch a;
      List.iter (fun b -> Buffer.add_char ch ','; buffer2_ltree ch b) bl;
      Buffer.add_char ch ']';
      Buffer.add_string ch "</span>";
  | ParenL(a,bl) ->
      if bl = [] then
        Buffer.add_string ch "<span class='paren'>"
      else
        Buffer.add_string ch "<span title='tuple term' class='tuple'>"; 
      Buffer.add_char ch '(';
      buffer2_ltree ch a;
      List.iter (fun b -> Buffer.add_char ch ','; buffer2_ltree ch b) bl;
      Buffer.add_char ch ')';
      Buffer.add_string ch "</span>";
  | IfThenElseL(a,b,c) ->
      Buffer.add_string ch "<span title='if-then-else term' class='ifthenelse'>"; 
      Buffer.add_string ch "if ";
      buffer2_ltree ch a;
      Buffer.add_string ch " then ";
      buffer2_ltree ch b;
      Buffer.add_string ch " else ";
      buffer2_ltree ch c;
      Buffer.add_string ch "</span>"
let prefixpriorities : (int,unit) Hashtbl.t = Hashtbl.create 100
let disallowedprefixpriorities : (int,unit) Hashtbl.t = Hashtbl.create 100
let rightinfixpriorities : (int,unit) Hashtbl.t = Hashtbl.create 100
let disallowedrightinfixpriorities : (int,unit) Hashtbl.t = Hashtbl.create 100
let penv_preop : (string,int) Hashtbl.t = Hashtbl.create 100
type picase = Postfix | InfixNone | InfixLeft | InfixRight
let penv_postinfop : (string,int * picase) Hashtbl.t = Hashtbl.create 100
let penv_binder : (string,unit) Hashtbl.t = Hashtbl.create 100;;

Hashtbl.add penv_binder "&lambda;" ();;
Hashtbl.add penv_binder "&forall;" ();;
Hashtbl.add penv_binder "&exist;" ();;
Hashtbl.add penv_preop "&#x00ac;" 700;;
Hashtbl.add penv_preop "-" 358;;
Hashtbl.add penv_postinfop "&#x2227;" (780,InfixLeft);;
Hashtbl.add penv_postinfop "&#x2228;" (785,InfixLeft);;
Hashtbl.add penv_postinfop "&#x2194;" (805,InfixNone);;
Hashtbl.add penv_postinfop "&#x2260;" (502,InfixNone);;
Hashtbl.add penv_postinfop "&#x2209;" (502,InfixNone);;
Hashtbl.add penv_postinfop "&#x2288;" (502,InfixNone);;
Hashtbl.add penv_postinfop "&#x222a;" (345,InfixLeft);;
Hashtbl.add penv_postinfop "&#x2229;" (340,InfixLeft);;
Hashtbl.add penv_postinfop "&#x2216;" (350,InfixNone);;
Hashtbl.add penv_postinfop "&#x002b;" (450,InfixLeft);;
Hashtbl.add penv_postinfop "&#x2a2f;" (440,InfixLeft);;
Hashtbl.add penv_postinfop "&#x2264;" (490,InfixNone);;
Hashtbl.add penv_postinfop "<" (490,InfixNone);;
Hashtbl.add penv_postinfop "+" (360,InfixRight);;
Hashtbl.add penv_postinfop "*" (355,InfixRight);;

Hashtbl.add penv_postinfop "&in;" (500,InfixNone);;
Hashtbl.add penv_postinfop "&sube;" (500,InfixNone);;
Hashtbl.add penv_postinfop "=" (502,InfixNone);;
Hashtbl.add penv_postinfop "&rarr;" (800,InfixRight);;
Hashtbl.add penv_postinfop "&xrarr;" (800,InfixRight);;
Hashtbl.add penv_postinfop "^" (342,InfixRight);;
Hashtbl.add rightinfixpriorities 800 ();;
Hashtbl.add rightinfixpriorities 790 ();;
Hashtbl.add disallowedprefixpriorities 800 ();;
Hashtbl.add disallowedprefixpriorities 790 ();;

(*** auxiliary function to add parens if needed ***)
let a2l_paren q (a,p) : ltree =
  if p <= q then
    a
  else
    ParenL(a,[])

(***
    convert an atree to an ltree (using penv info);
    return a level to determine where parens are needed
 ***)
let rec atree_to_ltree_level (a:atree) : ltree * int =
  match a with
  | Byte(x) -> (ByteL(x),0)
  | String(x) -> (StringL(x),0)
  | QString(x) -> (QStringL(x),0)
  | Na(x) -> (NaL(x),0)
  | Nu(b,x,y,z) -> (NuL(b,x,y,z),0)
  | Le(x,None,a,c) ->
      let al = a2l_paren 1010 (atree_to_ltree_level a) in
      let cl = a2l_paren 1010 (atree_to_ltree_level c) in
      (LeL(x,None,al,cl),1)
  | Le(x,Some(i,b),a,c) ->
      let al = a2l_paren 1010 (atree_to_ltree_level a) in
      let bl = a2l_paren 1010 (atree_to_ltree_level b) in
      let cl = a2l_paren 1010 (atree_to_ltree_level c) in
      (LeL(x,Some(i,bl),al,cl),1)
  | LeM(x,xl,a,c) ->
      let al = a2l_paren 1010 (atree_to_ltree_level a) in
      let cl = a2l_paren 1010 (atree_to_ltree_level c) in
      (LeML(x,xl,al,cl),1)
  | Bi(x,vll,a) ->
     begin
       let mtokstr = "." in
       let vlll = List.map (fun (xl,o) ->
	              match o with
	              | Some(i,b) -> (xl,Some(i,a2l_paren 1010 (atree_to_ltree_level b)))
	              | None -> (xl,None)
		    ) vll
       in
       let al = a2l_paren 1010 (atree_to_ltree_level a) in
       (BiL(x,mtokstr,vlll,al),1)
     end
  | Preo(x,a) ->
     begin
       try
         let p = Hashtbl.find penv_preop x in
	 (PreoL(x,a2l_paren (p+1) (atree_to_ltree_level a)),p+1)
       with Not_found ->
	 raise (Failure ("Undeclared prefix operator " ^ x))
     end
  | Posto(x,a) -> (*** if binderishp al ... ***)
      begin
       try
         let (p,pic) = Hashtbl.find penv_postinfop x in
         if pic = Postfix then
	   let al = a2l_paren (p+1) (atree_to_ltree_level a) in
	   if binderishp al then
	     (PostoL(x,ParenL(al,[])),p+1)
	   else
	     (PostoL(x,al),p+1)
         else
           raise (Failure ("Infix operator used as postfix " ^ x))
       with Not_found -> raise (Failure ("Undeclared postfix operator " ^ x))
      end
  | Info(InfSet i,a,b) -> (*** if binderishp al ... ***)
      let al = a2l_paren 500 (atree_to_ltree_level a) in
      let bl = a2l_paren 500 (atree_to_ltree_level b) in
      if binderishp al then
	(InfoL(InfSet i,ParenL(al,[]),bl),501)
      else
	(InfoL(InfSet i,al,bl),501)
  | Info(InfNam x,a,b) -> (*** if binderishp al ... ***)
      begin
       try
         let (p,pic) = Hashtbl.find penv_postinfop x in
         match pic with
         | Postfix -> raise (Failure ("Postfix op used as infix " ^ x))
         | InfixNone ->
	    let al = a2l_paren p (atree_to_ltree_level a) in
	    let bl = a2l_paren p (atree_to_ltree_level b) in
	    if binderishp al then
	      (InfoL(InfNam x,ParenL(al,[]),bl),p+1)
	    else
	      (InfoL(InfNam x,al,bl),p+1)
	| InfixLeft ->
	    let al = a2l_paren (p+1) (atree_to_ltree_level a) in
	    let bl = a2l_paren p (atree_to_ltree_level b) in
	    if binderishp al then
	      (InfoL(InfNam x,ParenL(al,[]),bl),p+1)
	    else
	      (InfoL(InfNam x,al,bl),p+1)
	| InfixRight ->
	    let al = a2l_paren p (atree_to_ltree_level a) in
	    let bl = a2l_paren (p+1) (atree_to_ltree_level b) in
	    if binderishp al then
	      (InfoL(InfNam x,ParenL(al,[]),bl),p+1)
	    else
	      (InfoL(InfNam x,al,bl),p+1)
	with Not_found -> raise (Failure ("Undeclared infix operator " ^ x))
      end
  | Implop(a,b) ->
      let al = a2l_paren 1 (atree_to_ltree_level a) in
      let bl = a2l_paren 0 (atree_to_ltree_level b) in
      if (binderishp al) then
	(ImplopL(ParenL(al,[]),bl),1)
      else
	(ImplopL(al,bl),1)
  | Sep(x,i,a,b) ->
      let al = a2l_paren 500 (atree_to_ltree_level a) in
      let bl = a2l_paren 1010 (atree_to_ltree_level b) in
      (SepL(x,i,al,bl),0)
  | Rep(x,i,a,b) ->
      let al = a2l_paren 1010 (atree_to_ltree_level a) in
      let bl = a2l_paren 500 (atree_to_ltree_level b) in
      (RepL(x,i,al,bl),0)
  | SepRep(x,i,a,b,c) ->
      let al = a2l_paren 1010 (atree_to_ltree_level a) in
      let bl = a2l_paren 500 (atree_to_ltree_level b) in
      let cl = a2l_paren 1010 (atree_to_ltree_level c) in
      (SepRepL(x,i,al,bl,cl),0)
  | SetEnum(al) ->
      (SetEnumL(List.map
		  (fun a ->
		    let (l,_) = atree_to_ltree_level a in
		    l)
		  al),0)
  | MTuple(a,cl) ->
      let (al,_) = atree_to_ltree_level a in
      (MTupleL(al,List.map
		(fun a ->
		  let (l,_) = atree_to_ltree_level a in
		  l)
		cl),0)
  | Tuple(a,b,cl) ->
      let (al,_) = atree_to_ltree_level a in
      let (bl,_) = atree_to_ltree_level b in
      (ParenL(al,bl::List.map
		       (fun a ->
			 let (l,_) = atree_to_ltree_level a in
			 l)
		       cl),0)
  | IfThenElse(a,b,c) ->
      let al = a2l_paren 1010 (atree_to_ltree_level a) in
      let bl = a2l_paren 1010 (atree_to_ltree_level b) in
      let cl = a2l_paren 1010 (atree_to_ltree_level c) in
      (IfThenElseL(al,bl,cl),1)

let atree_to_ltree (a:atree) : ltree =
  let (l,_) = atree_to_ltree_level a in
  l

(** copied from Megalodon with modifications END **)

let mgnicetrmbuf : Buffer.t = Buffer.create 1000;;

let mghtml_nice_trm th m =
  let inegal = (th = Some(egalthyroot)) in
  let inhf = (th = Some(hfthyroot)) in
  let inmiz = (th = Some(mizthyroot)) in
  let inhoas = (th = Some(hoasthyroot)) in
  let check_objid_legend_cond p h =
    try
      let objid = Hashtbl.find term_theory_objid (th,h) in
      p objid
    with Not_found -> false
  in
  let rec mghtml_nice_stp_r a =
    match a with
    | Base(0) -> Na("&iota;")
    | Base(i) -> Na(Printf.sprintf "base%d" i)
    | Prop -> Na("&omicron;")
    | TpArr(a1,a2) -> Info(InfNam("&rarr;"),mghtml_nice_stp_r a1,mghtml_nice_stp_r a2)
  in
  let rec mghtml_nice_trm_r m cx =
    let lastcases () =
       match m with
       | DB(i) ->
          begin
            try
              Na(Printf.sprintf "<span title='variable term'>%s</span>" (List.nth cx i))
            with Failure(_) ->
              Na(Printf.sprintf "<span title='variable term (de Bruijn)'>DB%d</span>" i)
          end
       | TmH(h) ->
          begin
            try
              let objid = Hashtbl.find term_theory_objid (th,h) in
              begin
                Na(Printf.sprintf "<span title='abbreviation term'><a href=\"q.php?b=%s\">%s</a></span>" (hashval_hexstring objid)
                     (try
                        Hashtbl.find mglegend objid
                      with Not_found ->
                        mg_abbrv (hashval_hexstring objid)))
              end
            with Not_found ->
              Na(Printf.sprintf "<span title='abbreviation term'><a href=\"q.php?b=%s\">%s</a></span>" (hashval_hexstring h) (mg_abbrv (hashval_hexstring h)))
          end
       | Ap(Ap(Ap(TmH(h),m1),m2),m3) when check_objid_legend_cond (fun objid -> Hashtbl.mem mgifthenelse objid) h ->
          IfThenElse(mghtml_nice_trm_r m1 cx,mghtml_nice_trm_r m2 cx,mghtml_nice_trm_r m3 cx)
       | Ap(TmH(h),m1) when check_objid_legend_cond (fun objid -> Hashtbl.mem mgprefixop objid) h ->
          let objid = Hashtbl.find term_theory_objid (th,h) in
          let opstr = Hashtbl.find mgprefixop objid in
          Preo(opstr,mghtml_nice_trm_r m1 cx)
       | Ap(TmH(h),m1) when check_objid_legend_cond (fun objid -> Hashtbl.mem mgpostfixop objid) h ->
          let objid = Hashtbl.find term_theory_objid (th,h) in
          let opstr = Hashtbl.find mgpostfixop objid in
          Posto(opstr,mghtml_nice_trm_r m1 cx)
       | Ap(Ap(TmH(h),m1),m2) when check_objid_legend_cond (fun objid -> Hashtbl.mem mgimplop objid) h ->
          Implop(mghtml_nice_trm_r m1 cx,mghtml_nice_trm_r m2 cx)
       | Ap(Ap(TmH(h),m1),m2) when check_objid_legend_cond (fun objid -> Hashtbl.mem mginfixop objid) h ->
          let objid = Hashtbl.find term_theory_objid (th,h) in
          Info(InfNam(Hashtbl.find mginfixop objid),mghtml_nice_trm_r m1 cx,mghtml_nice_trm_r m2 cx)
       | Ap(Ap(Prim(1),m1),m2) when inegal ->
          Info(InfSet(InfMem),mghtml_nice_trm_r m1 cx,mghtml_nice_trm_r m2 cx)
       | Ap(Ap(TmH(h),m1),m2) when inegal && h = mgsubq ->
          Info(InfSet(InfSubq),mghtml_nice_trm_r m1 cx,mghtml_nice_trm_r m2 cx)
       | Ap(Ap(Prim(5),m1),Lam(Base(0),m2)) when inegal -> (** Replacement **)
          let x = Printf.sprintf "x%d" (List.length cx) in
          Rep(x,InfMem,mghtml_nice_trm_r m2 (x::cx),mghtml_nice_trm_r m1 cx)
       | Ap(Ap(TmH(h),m1),Lam(Base(0),m2)) when inegal && h = hexstring_hashval "f336a4ec8d55185095e45a638507748bac5384e04e0c48d008e4f6a9653e9c44" -> (** Sep **)
          let x = Printf.sprintf "x%d" (List.length cx) in
          Sep(x,InfMem,mghtml_nice_trm_r m1 cx,mghtml_nice_trm_r m2 (x::cx))
       | Ap(Ap(Ap(TmH(h),m1),Lam(Base(0),m2)),Lam(Base(0),m3)) when inegal && h = hexstring_hashval "ec807b205da3293041239ff9552e2912636525180ddecb3a2b285b91b53f70d8" ->
          let x = Printf.sprintf "x%d" (List.length cx) in
          SepRep(x,InfMem,mghtml_nice_trm_r m3 (x::cx),mghtml_nice_trm_r m1 cx,mghtml_nice_trm_r m2 (x::cx))
       | Prim(i) ->
          begin
            let h = tm_hashroot (Prim(i)) in
            try
              let objid = Hashtbl.find term_theory_objid (th,h) in
              try
                let name = Hashtbl.find mglegend objid in
                Na(Printf.sprintf "<span title='primitive term (%d)'><a href=\"q.php?b=%s\">%s</a></span>" i (hashval_hexstring objid) name)
              with Not_found ->
                let objidh = hashval_hexstring objid in
                Na(Printf.sprintf "<span title='primitive term (constant)'><a href=\"q.php?b=%s\">prim%d</a></span>" objidh i)
            with Not_found ->
              let hh = hashval_hexstring h in
              Na(Printf.sprintf "<span title='primitive term (constant)'><a href=\"q.php?b=%s\">prim%d</a></span>" hh i)
          end
       | Ap(m1,m2) ->
          Implop(mghtml_nice_trm_r m1 cx,mghtml_nice_trm_r m2 cx)
       | Lam(a,m1) ->
          let x = Printf.sprintf "x%d" (List.length cx) in
          mghtml_nice_lam_r a m1 [x] (x::cx)
       | Imp(m1,m2) ->
          Info(InfNam("&xrarr;"),mghtml_nice_trm_r m1 cx,mghtml_nice_trm_r m2 cx)
       | All(Prop,Imp(All(a,Imp(m1,DB(1))),DB(0))) when not (free_in 1 m1) ->
          let x = Printf.sprintf "x%d" (List.length cx) in
          mghtml_nice_ex_r a m1 [x] (x::"_"::cx)
       | All(TpArr(a,TpArr(a2,Prop)),Imp(Ap(Ap(DB(0),lhs),rhs),Ap(Ap(DB(0),rhs2),lhs2))) when a2 = a && lhs = lhs2 && rhs = rhs2 && not (free_in 0 lhs) && not (free_in 0 rhs) ->
          Info(InfNam("="),mghtml_nice_trm_r lhs ("_"::cx),mghtml_nice_trm_r rhs ("_"::cx))
       | All(a,m1) ->
          let x = Printf.sprintf "x%d" (List.length cx) in
          mghtml_nice_all_r a m1 [x] (x::cx)
       | Ex(a,m1) ->
          let x = Printf.sprintf "x%d" (List.length cx) in
          mghtml_nice_ex_r a m1 [x] (x::cx)
       | Eq(a,m1,m2) ->
          Info(InfNam("="),mghtml_nice_trm_r m1 cx,mghtml_nice_trm_r m2 cx)
    in
    match if inegal && !mgnatnotation then mg_fin_ord m else if inhf && !mgnatnotation then hf_fin_ord m else None with
    | Some(n) -> Nu(false,Printf.sprintf "%d" n,None,None)
    | None -> lastcases()
  and mghtml_nice_lam_r a m newvars cx =
    match m with
    | Lam(b,m1) ->
       if a = b then
         let x = Printf.sprintf "x%d" (List.length cx) in
         mghtml_nice_lam_r a m1 (x::newvars) (x::cx)
       else if a = Base(0) then
         Bi("&lambda;",[(List.rev newvars,None)],mghtml_nice_trm_r m cx)
       else
         Bi("&lambda;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],mghtml_nice_trm_r m cx)
    | _ ->
       if a = Base(0) then
         Bi("&lambda;",[(List.rev newvars,None)],mghtml_nice_trm_r m cx)
       else
         Bi("&lambda;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],mghtml_nice_trm_r m cx)
  and mghtml_nice_all_r a m newvars cx =
    match m with
    | All(b,m1) ->
       if a = b then
         let x = Printf.sprintf "x%d" (List.length cx) in
         mghtml_nice_all_r a m1 (x::newvars) (x::cx)
       else if a = Base(0) then
         Bi("&forall;",[(List.rev newvars,None)],mghtml_nice_trm_r m cx)
       else
         Bi("&forall;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],mghtml_nice_trm_r m cx)
    | _ ->
       if a = Base(0) then
         Bi("&forall;",[(List.rev newvars,None)],mghtml_nice_trm_r m cx)
       else
         Bi("&forall;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],mghtml_nice_trm_r m cx)
  and mghtml_nice_ex_r a m newvars cx =
    match m with
    | Ex(b,m1) ->
       if a = b then
         let x = Printf.sprintf "x%d" (List.length cx) in
         mghtml_nice_ex_r a m1 (x::newvars) (x::cx)
       else if a = Base(0) then
         Bi("&exist;",[(List.rev newvars,None)],mghtml_nice_trm_r m cx)
       else
         Bi("&exist;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],mghtml_nice_trm_r m cx)
    | All(Prop,Imp(All(b,Imp(m1,DB(1))),DB(0))) when not (free_in 1 m1) ->
       if a = b then
         let x = Printf.sprintf "x%d" (List.length cx) in
         mghtml_nice_ex_r a m1 (x::newvars) (x::"_"::cx)
       else if a = Base(0) then
         Bi("&exist;",[(List.rev newvars,None)],mghtml_nice_trm_r m cx)
       else
         Bi("&exist;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],mghtml_nice_trm_r m cx)
    | _ ->
       if a = Base(0) then
         Bi("&exist;",[(List.rev newvars,None)],mghtml_nice_trm_r m cx)
       else
         Bi("&exist;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],mghtml_nice_trm_r m cx)
  in
  Buffer.clear mgnicetrmbuf;
  buffer2_ltree mgnicetrmbuf (atree_to_ltree (mghtml_nice_trm_r m []));
  Buffer.contents mgnicetrmbuf

let json2_signaitem th x =
  match x with
  | Signasigna(h) -> JsonObj([("type",JsonStr("signaitem"));("signaitemcase",JsonStr("signasigna"));("signaroot",JsonStr(hashval_hexstring h))])
  | Signaparam(h,a) ->
     begin
       try
         let objid = Hashtbl.find term_theory_objid (th,h) in
         JsonObj([("type",JsonStr("signaitem"));("signaitemcase",JsonStr("signaparam"));("trmroot",JsonStr(hashval_hexstring h));("objid",JsonStr(hashval_hexstring objid));("stp",JsonStr(mghtml_nice_stp th a))])
       with Not_found ->
             let objid = hashtag (hashopair2 th (hashpair h (hashtp a))) 32l in
             JsonObj([("type",JsonStr("signaitem"));("signaitemcase",JsonStr("signaparam"));("trmroot",JsonStr(hashval_hexstring h));("objid",JsonStr(hashval_hexstring objid));("stp",JsonStr(mghtml_nice_stp th a))])
     end
  | Signadef(a,m) ->
     begin
       let trmroot = tm_hashroot m in
       try
         let objid = Hashtbl.find term_theory_objid (th,trmroot) in
         JsonObj([("type",JsonStr("signaitem"));("signaitemcase",JsonStr("signadef"));("stp",JsonStr(mghtml_nice_stp th a));("trmroot",JsonStr(hashval_hexstring trmroot));("objid",JsonStr(hashval_hexstring objid));("def",JsonStr(mghtml_nice_trm th m))])
       with Not_found ->
             let objid = hashtag (hashopair2 th (hashpair trmroot (hashtp a))) 32l in
             JsonObj([("type",JsonStr("signaitem"));("signaitemcase",JsonStr("signadef"));("stp",JsonStr(mghtml_nice_stp th a));("trmroot",JsonStr(hashval_hexstring trmroot));("objid",JsonStr(hashval_hexstring objid));("def",JsonStr(mghtml_nice_trm th m))])
     end
  | Signaknown(p) ->
      let trmroot = tm_hashroot p in
      let propid = hashtag (hashopair2 th trmroot) 33l in
      JsonObj([("type",JsonStr("signaitem"));("signaitemcase",JsonStr("signaknown"));("trmroot",JsonStr(hashval_hexstring trmroot));("propid",JsonStr(hashval_hexstring propid));("prop",JsonStr(mghtml_nice_trm th p))])

let json2_docitem th x =
  let inegal = (th = Some(egalthyroot)) in
  match x with
    | Docsigna(h) -> JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docsigna"));("signaroot",JsonStr(hashval_hexstring h))])
    | Docparam(h,a) ->
       begin
         try
           let objid = Hashtbl.find term_theory_objid (th,h) in
           let names = Hashtbl.find_all mglegend objid in
           JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docparam"));("trmroot",JsonStr(hashval_hexstring h));("objid",JsonStr(hashval_hexstring objid));("stp",JsonStr(mghtml_nice_stp th a)); ("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))])
         with Not_found ->
           let objid = hashtag (hashopair2 th (hashpair h (hashtp a))) 32l in
           let names = Hashtbl.find_all mglegend objid in
           JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docparam"));("trmroot",JsonStr(hashval_hexstring h));("objid",JsonStr(hashval_hexstring objid));("stp",JsonStr(mghtml_nice_stp th a)); ("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))])
       end
    | Docdef(a,m) ->
       let trmroot = tm_hashroot m in
       begin
         try
           let objid = Hashtbl.find term_theory_objid (th,trmroot) in
           let names = Hashtbl.find_all mglegend objid in
           JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docdef"));("stp",JsonStr(mghtml_nice_stp th a));("trmroot",JsonStr(hashval_hexstring trmroot));("objid",JsonStr(hashval_hexstring objid));("def",JsonStr(mghtml_nice_trm th m)); ("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))])
         with Not_found ->
               let objid = hashtag (hashopair2 th (hashpair trmroot (hashtp a))) 32l in
               let names = Hashtbl.find_all mglegend objid in
               JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docdef"));("stp",JsonStr(mghtml_nice_stp th a));("trmroot",JsonStr(hashval_hexstring trmroot));("objid",JsonStr(hashval_hexstring objid));("def",JsonStr(mghtml_nice_trm th m)); ("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))])
       end
    | Docknown(p) ->
        let trmroot = tm_hashroot p in
        let propid = hashtag (hashopair2 th trmroot) 33l in
        let names = Hashtbl.find_all mglegendp propid in
        JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docknown"));("trmroot",JsonStr(hashval_hexstring trmroot));("propid",JsonStr(hashval_hexstring propid));("prop",JsonStr(mghtml_nice_trm th p)); ("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))])
    | Docpfof(p,d) ->
        let trmroot = tm_hashroot p in
        let propid = hashtag (hashopair2 th trmroot) 33l in
        let names = Hashtbl.find_all mglegendp propid in
        let usesknowns = ref [] in
        let rec f d =
          match d with
          | Known(h) -> if not (List.mem h !usesknowns) then usesknowns := h :: !usesknowns
          | PrAp(d1,d2) -> f d1; f d2
          | TmAp(d1,_) -> f d1
          | PrLa(_,d1) -> f d1
          | TmLa(_,d1) -> f d1
          | _ -> ()
        in
        f d;
        let robj = ref [] in
        if !usesknowns = [] then
          robj := [("type",JsonStr("docitem"));("docitemcase",JsonStr("docpfof"));("trmroot",JsonStr(hashval_hexstring trmroot));("propid",JsonStr(hashval_hexstring propid));("prop",JsonStr(mghtml_nice_trm th p));("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))]
        else
          begin
            let usesknowns2 =
              List.map
                (fun trmroot ->
                  let propid = hashtag (hashopair2 th trmroot) 33l in
                  let names = Hashtbl.find_all mglegendp propid in
                  if names = [] then
                    JsonObj([("trmroot",JsonStr(hashval_hexstring trmroot));
                             ("propid",JsonStr(hashval_hexstring propid))])
                  else
                    JsonObj([("trmroot",JsonStr(hashval_hexstring trmroot));
                             ("propid",JsonStr(hashval_hexstring propid));
                             ("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))]))
                !usesknowns
            in
            robj := [("type",JsonStr("docitem"));("docitemcase",JsonStr("docpfof"));("trmroot",JsonStr(hashval_hexstring trmroot));("propid",JsonStr(hashval_hexstring propid));("prop",JsonStr(mghtml_nice_trm th p));("pfusesknowns",JsonArr(usesknowns2));("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))];
          end;
        JsonObj(!robj)
    | Docconj(p) ->
        let trmroot = tm_hashroot p in
        let propid = hashtag (hashopair2 th trmroot) 33l in
        let names = Hashtbl.find_all mglegendp propid in
        JsonObj([("type",JsonStr("docitem"));("docitemcase",JsonStr("docconj"));("trmroot",JsonStr(hashval_hexstring trmroot));("propid",JsonStr(hashval_hexstring propid));("prop",JsonStr(mghtml_nice_trm th p)); ("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))])

let json2_theoryspec th ts =
  let al = ref [] in
  let cnt = ref 0 in
  let sg = ref [] in
  List.iter
    (fun x ->
      match x with
      | Thyprim(_) -> incr cnt
      | _ -> ())
    ts;
  List.iter
    (fun x ->
      match x with
      | Thyprim(a) ->
         decr cnt;
         let tmr = tm_hashroot (Prim(!cnt)) in
         sg := (tmr,a)::!sg;
         let objid = hashtag (hashopair2 th (hashpair tmr (hashtp a))) 32l in
         let names = Hashtbl.find_all mglegend objid in
         al := JsonObj([("type",JsonStr("theoryitem"));("theoryitemcase",JsonStr("thyprim"));("primnum",JsonNum(string_of_int !cnt));("objid",JsonStr(hashval_hexstring objid));("stp",JsonStr(mghtml_nice_stp th a));("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))])::!al
      | Thyaxiom(p) ->
         let tmr = tm_hashroot p in
         let propid = hashtag (hashopair2 th tmr) 33l in
         let names = Hashtbl.find_all mglegendp propid in
         al := JsonObj([("type",JsonStr("theoryitem"));("theoryitemcase",JsonStr("thyaxiom"));("propid",JsonStr(hashval_hexstring propid));("prop",JsonStr(mghtml_nice_trm th p));("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))])::!al
      | Thydef(a,m) ->
         let tmr = tm_hashroot m in
         sg := (tmr,a)::!sg;
         let objid = hashtag (hashopair2 th (hashpair tmr (hashtp a))) 32l in
         let names = Hashtbl.find_all mglegend objid in
         al := JsonObj([("type",JsonStr("theoryitem"));("theoryitemcase",JsonStr("thydef"));("objid",JsonStr(hashval_hexstring objid));("stp",JsonStr(mghtml_nice_stp th a));("def",JsonStr(mghtml_nice_trm th m));("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))])::!al)
    ts;
  JsonArr(!al)

let json2_signaspec th ss = JsonArr(List.map (json2_signaitem th) ss)

let json2_doc th d = JsonArr(List.map (json2_docitem th) d)

let json_theoryitem x = json1_theoryitem x
let json_signaitem th x = json1_signaitem th x
let json_docitem th x = json1_docitem th x
let json_theoryspec d =
  if !mgnice then
    let thy = theoryspec_theory d in
    let th = hashtheory thy in
    json2_theoryspec th d
  else
    json1_theoryspec d
let json_signaspec th d = if !mgnice then json2_signaspec th d else json1_signaspec th d
let json_doc th d = if !mgnice then json2_doc th d else json1_doc th d

let printenv_as_legend () =
  Hashtbl.iter (fun k v -> Printf.printf "X %s %s\n" (hashval_hexstring k) v) mglegend;
  Hashtbl.iter (fun k v -> Printf.printf "P %s %s\n" (hashval_hexstring k) v) mglegendp;
  Hashtbl.iter (fun k v -> Printf.printf "ITE %s\n" (hashval_hexstring k)) mgifthenelse;
  Hashtbl.iter (fun k v -> Printf.printf "B %s %s\n" (hashval_hexstring k) v) mgbinder;
  Hashtbl.iter (fun k v -> Printf.printf "PRE %s %s\n" (hashval_hexstring k) v) mgprefixop;
  Hashtbl.iter (fun k v -> Printf.printf "POST %s %s\n" (hashval_hexstring k) v) mgpostfixop;
  Hashtbl.iter (fun k v -> Printf.printf "INF %s %s\n" (hashval_hexstring k) v) mginfixop;
  Hashtbl.iter (fun k v -> Printf.printf "IMPLICIT %s\n" (hashval_hexstring k)) mgimplop;
  Hashtbl.iter (fun k v -> Printf.printf "PREFIXNAME %s %d\n" k v) penv_preop;
  Hashtbl.iter
    (fun k v ->
      match v with
        (pri,Postfix) -> Printf.printf "POSTFIXNAME %s %d\n" k pri
      | (pri,InfixNone) -> Printf.printf "INFIXNONENAME %s %d\n" k pri
      | (pri,InfixLeft) -> Printf.printf "INFIXLEFTNAME %s %d\n" k pri
      | (pri,InfixRight) -> Printf.printf "INFIXRIGHTNAME %s %d\n" k pri)
    penv_postinfop;
  Hashtbl.iter (fun k v -> Printf.printf "BINDERNAME %s\n" k) penv_binder

let rec json_trm_partial pubaddr pubitem th m szlim loclist vcx =
  if szlim <= 0 then
    let (loclen,locnum) = loclist_to_code (List.rev loclist) in
    (JsonObj([("type",JsonStr("abbrevtm"));("pubaddr",JsonStr(pubaddr));("pubitem",JsonNum(string_of_int pubitem));("loclen",JsonNum(string_of_int loclen));("locnum",JsonStr(string_of_big_int locnum))]),0)
  else
    match m with
    | DB(i) -> (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("db"));("db",JsonNum(string_of_int i));("dblevel",JsonNum(string_of_int (List.length vcx - i - 1)))]),szlim-1)
    | TmH(h) ->
       begin
         try
           let objid = Hashtbl.find term_theory_objid (th,h) in
           let names = Hashtbl.find_all mglegend objid in
           if names = [] then
             (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("tmh"));("trmroot",JsonStr(hashval_hexstring h))]),szlim-1)
           else
             (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("tmh"));("trmroot",JsonStr(hashval_hexstring h));("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))]),szlim-1)
         with Not_found ->
           (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("tmh"));("trmroot",JsonStr(hashval_hexstring h))]),szlim-1)
       end
    | Prim(i) ->
       begin
         let h = tm_hashroot (Prim(i)) in
         try
           let objid = Hashtbl.find term_theory_objid (th,h) in
           let names = Hashtbl.find_all mglegend objid in
           if names = [] then
             (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("prim"));("prim",JsonNum(string_of_int i))]),szlim-1)
           else
             (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("prim"));("prim",JsonNum(string_of_int i));("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))]),szlim-1)
         with Not_found ->
           (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("prim"));("prim",JsonNum(string_of_int i))]),szlim-1)
       end
    | Ap(m,n) ->
       let (jm,szlim) = json_trm_partial pubaddr pubitem th m szlim (Some(false)::loclist) vcx in
       let (jn,szlim) = json_trm_partial pubaddr pubitem th n (szlim-1) (Some(true)::loclist) vcx in
       (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("ap"));("func",jm);("arg",jn)]),szlim-1)
    | Lam(a,m) ->
       let x = Printf.sprintf "x%d" (List.length vcx) in
       let (jm,szlim) = json_trm_partial pubaddr pubitem th m (szlim-1) (None::loclist) (x::vcx) in
       (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("lam"));("dom",json_stp a);("body",jm)]),szlim)
    | Imp(m,n) ->
       let (jn,szlim) = json_trm_partial pubaddr pubitem th n szlim (Some(true)::loclist) vcx in
       let (jm,szlim) = json_trm_partial pubaddr pubitem th m (szlim-1) (Some(false)::loclist) vcx in
       (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("imp"));("ant",jm);("suc",jn)]),szlim)
    | All(a,m) ->
       let x = Printf.sprintf "x%d" (List.length vcx) in
       let (jm,szlim) = json_trm_partial pubaddr pubitem th m (szlim-1) (None::loclist) (x::vcx) in
       (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("all"));("dom",json_stp a);("body",jm)]),szlim)
    | Ex(a,m) ->
       let x = Printf.sprintf "x%d" (List.length vcx) in
       let (jm,szlim) = json_trm_partial pubaddr pubitem th m (szlim-1) (None::loclist) (x::vcx) in
       (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("ex"));("dom",json_stp a);("body",jm)]),szlim)
    | Eq(a,m,n) ->
       let (jm,szlim) = json_trm_partial pubaddr pubitem th m (szlim-1) (Some(false)::loclist) vcx in
       let (jn,szlim) = json_trm_partial pubaddr pubitem th n (szlim-1) (Some(true)::loclist) vcx in
       (JsonObj([("type",JsonStr("trm"));("trmcase",JsonStr("eq"));("stp",json_stp a);("lhs",jm);("rhs",jn)]),szlim)

let rec json_pf_partial pubaddr pubitem th d szlim loclist vcx hcx =
  if szlim <= 0 then
    let (loclen,locnum) = loclist_to_code (List.rev loclist) in
    (JsonObj([("type",JsonStr("abbrevpf"));("pubaddr",JsonStr(pubaddr));("pubitem",JsonNum(string_of_int pubitem));("loclen",JsonNum(string_of_int loclen));("locnum",JsonStr(string_of_big_int locnum))]),0)
  else
    match d with
    | Known(h) ->
       let propid = hashtag (hashopair2 th h) 33l in
       let names = Hashtbl.find_all mglegendp propid in
       if names = [] then
         (JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("known"));("trmroot",JsonStr(hashval_hexstring h))]),szlim-1)
       else
         (JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("known"));("trmroot",JsonStr(hashval_hexstring h)); ("defaultnames",JsonArr(List.map (fun x -> JsonStr(x)) names))]),szlim-1)
    | Hyp(i) ->
       (JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("hyp"));("hyp",JsonNum(string_of_int i));("hyplevel",JsonNum(string_of_int (List.length hcx - i - 1)))]),szlim-1)
    | PrAp(d,e) ->
       let (jd,szlim) = json_pf_partial pubaddr pubitem th d szlim (Some(false)::loclist) vcx hcx in
       let (je,szlim) = json_pf_partial pubaddr pubitem th e (szlim-1) (Some(true)::loclist) vcx hcx in
       (JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("prap"));("func",jd);("arg",je)]),szlim-1)
    | TmAp(d,m) ->
       let (jd,szlim) = json_pf_partial pubaddr pubitem th d szlim (Some(false)::loclist) vcx hcx in
       let (jm,szlim) = json_trm_partial pubaddr pubitem th m (szlim-1) (Some(true)::loclist) vcx in
       let mhtml = mghtml_nice_trm th m in
       (JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("tmap"));("func",jd);("arg",jm);("arghtml",JsonStr(mhtml))]),szlim-1)
    | PrLa(m,d) ->
       let (jm,szlim) = json_trm_partial pubaddr pubitem th m (szlim-1) (Some(false)::loclist) vcx in
       let h = Printf.sprintf "H%d" (List.length hcx) in
       let (jd,szlim) = json_pf_partial pubaddr pubitem th d (szlim-1) (Some(true)::loclist) vcx (h::hcx) in
       (JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("prla"));("dom",jm);("body",jd)]),szlim)
    | TmLa(a,d) ->
       let x = Printf.sprintf "x%d" (List.length vcx) in
       let (jd,szlim) = json_pf_partial pubaddr pubitem th d (szlim-1) (None::loclist) (x::vcx) hcx in
       (JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("tmla"));("dom",json_stp a);("body",jd)]),szlim)
    | Ext(a,b) ->
       (JsonObj([("type",JsonStr("pf"));("pfcase",JsonStr("ext"));("dom",json_stp a);("cod",json_stp b)]),szlim-1)

let html_trm_partial pubaddr pubitem th m szlim loclist vcx =
  let inegal = (th = Some(egalthyroot)) in
  let inhf = (th = Some(hfthyroot)) in
  let inmiz = (th = Some(mizthyroot)) in
  let inhoas = (th = Some(hoasthyroot)) in
  let check_objid_legend_cond p h =
    try
      let objid = Hashtbl.find term_theory_objid (th,h) in
      p objid
    with Not_found -> false
  in
  let rec mghtml_nice_stp_r a =
    match a with
    | Base(0) -> Na("&iota;")
    | Base(i) -> Na(Printf.sprintf "base%d" i)
    | Prop -> Na("&omicron;")
    | TpArr(a1,a2) -> Info(InfNam("&rarr;"),mghtml_nice_stp_r a1,mghtml_nice_stp_r a2)
  in
  let rec html_trm_partial_r m szlim loclist vcx =
    let lastcases () =
       match m with
       | DB(i) ->
          begin
            try
              (Na(Printf.sprintf "<span title='variable term' class='var'>%s</span>" (List.nth vcx i)),szlim-1)
            with Failure(_) ->
              (Na(Printf.sprintf "<span title='variable term (de Bruijn)' class='db'>DB%d" i),szlim-1)
          end
       | TmH(h) ->
          begin
            try
              let objid = Hashtbl.find term_theory_objid (th,h) in
              begin
                (Na(Printf.sprintf "<span title='abbreviation term'><a href=\"q.php?b=%s\">%s</a></span>" (hashval_hexstring objid)
                      (try
                         Hashtbl.find mglegend objid
                       with Not_found ->
                         mg_abbrv (hashval_hexstring objid))),szlim-1)
              end
            with Not_found ->
              (Na(Printf.sprintf "<span title='abbreviation term'><a href=\"q.php?b=%s\">%s</a></span>" (hashval_hexstring h) (mg_abbrv (hashval_hexstring h))),szlim-1)
          end
       | Ap(Ap(Ap(TmH(h),m1),m2),m3) when check_objid_legend_cond (fun objid -> Hashtbl.mem mgifthenelse objid) h ->
          let (r1,szlim) = html_trm_partial_r m1 szlim (Some(true)::Some(false)::Some(false)::loclist) vcx in
          let (r2,szlim) = html_trm_partial_r m2 szlim (Some(true)::Some(false)::loclist) vcx in
          let (r3,szlim) = html_trm_partial_r m3 szlim (Some(true)::loclist) vcx in
          (IfThenElse(r1,r2,r3),szlim-1)
       | Ap(TmH(h),m1) when check_objid_legend_cond (fun objid -> Hashtbl.mem mgprefixop objid) h ->
          let objid = Hashtbl.find term_theory_objid (th,h) in
          let opstr = Hashtbl.find mgprefixop objid in
          let (r1,szlim) = html_trm_partial_r m1 (szlim-1) (Some(true)::loclist) vcx in
          (Preo(opstr,r1),szlim)
       | Ap(TmH(h),m1) when check_objid_legend_cond (fun objid -> Hashtbl.mem mgpostfixop objid) h ->
          let objid = Hashtbl.find term_theory_objid (th,h) in
          let opstr = Hashtbl.find mgpostfixop objid in
          let (r1,szlim) = html_trm_partial_r m1 (szlim-1) (Some(true)::loclist) vcx in
          (Posto(opstr,r1),szlim)
       | Ap(Ap(TmH(h),m1),m2) when check_objid_legend_cond (fun objid -> Hashtbl.mem mgimplop objid) h ->
          let (r1,szlim) = html_trm_partial_r m1 szlim (Some(true)::Some(false)::loclist) vcx in
          let (r2,szlim) = html_trm_partial_r m2 (szlim-1) (Some(true)::loclist) vcx in
          (Implop(r1,r2),szlim)
       | Ap(Ap(TmH(h),m1),m2) when check_objid_legend_cond (fun objid -> Hashtbl.mem mginfixop objid) h ->
          let objid = Hashtbl.find term_theory_objid (th,h) in
          let (r1,szlim) = html_trm_partial_r m1 (szlim-1) (Some(true)::Some(false)::loclist) vcx in
          let (r2,szlim) = html_trm_partial_r m2 (szlim-1) (Some(true)::loclist) vcx in
          (Info(InfNam(Hashtbl.find mginfixop objid),r1,r2),szlim)
       | Ap(Ap(Prim(1),m1),m2) when inegal ->
          let (r1,szlim) = html_trm_partial_r m1 (szlim-1) (Some(true)::Some(false)::loclist) vcx in
          let (r2,szlim) = html_trm_partial_r m2 (szlim-1) (Some(true)::loclist) vcx in
          (Info(InfSet(InfMem),r1,r2),szlim)
       | Ap(Ap(TmH(h),m1),m2) when inegal && h = mgsubq ->
          let (r1,szlim) = html_trm_partial_r m1 (szlim-1) (Some(true)::Some(false)::loclist) vcx in
          let (r2,szlim) = html_trm_partial_r m2 (szlim-1) (Some(true)::loclist) vcx in
          (Info(InfSet(InfSubq),r1,r2),szlim)
       | Ap(Ap(Prim(5),m1),Lam(Base(0),m2)) when inegal -> (** Replacement **)
          let x = Printf.sprintf "x%d" (List.length vcx) in
          let (r1,szlim) = html_trm_partial_r m1 (szlim-1) (Some(true)::Some(false)::loclist) vcx in
          let (r2,szlim) = html_trm_partial_r m2 (szlim-1) (None::Some(true)::loclist) (x::vcx) in
          (Rep(x,InfMem,r2,r1),szlim)
       | Ap(Ap(TmH(h),m1),Lam(Base(0),m2)) when inegal && h = hexstring_hashval "f336a4ec8d55185095e45a638507748bac5384e04e0c48d008e4f6a9653e9c44" -> (** Sep **)
          let x = Printf.sprintf "x%d" (List.length vcx) in
          let (r1,szlim) = html_trm_partial_r m1 (szlim-1) (Some(true)::Some(false)::loclist) vcx in
          let (r2,szlim) = html_trm_partial_r m2 (szlim-1) (None::Some(true)::loclist) (x::vcx) in
          (Sep(x,InfMem,r1,r2),szlim)
       | Ap(Ap(Ap(TmH(h),m1),Lam(Base(0),m2)),Lam(Base(0),m3)) when inegal && h = hexstring_hashval "ec807b205da3293041239ff9552e2912636525180ddecb3a2b285b91b53f70d8" ->
          let x = Printf.sprintf "x%d" (List.length vcx) in
          let (r1,szlim) = html_trm_partial_r m1 (szlim-1) (Some(true)::Some(false)::Some(false)::loclist) vcx in
          let (r2,szlim) = html_trm_partial_r m2 (szlim-1) (None::Some(true)::Some(false)::loclist) (x::vcx) in
          let (r3,szlim) = html_trm_partial_r m3 (szlim-1) (None::Some(true)::loclist) (x::vcx) in
          (SepRep(x,InfMem,r3,r1,r2),szlim)
       | Prim(i) ->
          begin
            let h = tm_hashroot (Prim(i)) in
            try
              let objid = Hashtbl.find term_theory_objid (th,h) in
              try
                let name = Hashtbl.find mglegend objid in
                (Na(Printf.sprintf "<a href=\"q.php?b=%s\">%s</a>" (hashval_hexstring objid) name),szlim-1)
              with Not_found ->
                let objidh = hashval_hexstring objid in
                (Na(Printf.sprintf "<a href=\"q.php?b=%s\">prim%d</a>" objidh i),szlim-1)
            with Not_found ->
              let hh = hashval_hexstring h in
              (Na(Printf.sprintf "<a href=\"q.php?b=%s\">prim%d</a>" hh i),szlim-1)
          end
       | Ap(m1,m2) ->
          let (r1,szlim) = html_trm_partial_r m1 szlim (Some(false)::loclist) vcx in
          let (r2,szlim) = html_trm_partial_r m2 (szlim-1) (Some(true)::loclist) vcx in
          (Implop(r1,r2),szlim)
       | Lam(a,m1) ->
          let x = Printf.sprintf "x%d" (List.length vcx) in
          html_lam_partial_r a m1 [x] szlim (None::loclist) (x::vcx)
       | Imp(m1,m2) ->
          let (r2,szlim) = html_trm_partial_r m2 szlim (Some(true)::loclist) vcx in
          let (r1,szlim) = html_trm_partial_r m1 (szlim-1) (Some(false)::loclist) vcx in
          (Info(InfNam("&xrarr;"),r1,r2),szlim)
       | All(Prop,Imp(All(a,Imp(m1,DB(1))),DB(0))) when not (free_in 1 m1) ->
          let x = Printf.sprintf "x%d" (List.length vcx) in
          html_ex_partial_r a m1 [x] szlim (Some(false)::None::Some(false)::None::loclist) (x::"_"::vcx)
       | All(TpArr(a,TpArr(a2,Prop)),Imp(Ap(Ap(DB(0),lhs),rhs),Ap(Ap(DB(0),rhs2),lhs2))) when a2 = a && lhs = lhs2 && rhs = rhs2 && not (free_in 0 lhs) && not (free_in 0 rhs) ->
          let (r1,szlim) = html_trm_partial_r lhs (szlim-1) (Some(true)::Some(false)::Some(false)::None::loclist) ("_"::vcx) in
          let (r2,szlim) = html_trm_partial_r rhs (szlim-1) (Some(true)::Some(false)::None::loclist) ("_"::vcx) in
          (Info(InfNam("="),r1,r2),szlim)
       | All(a,m1) ->
          let x = Printf.sprintf "x%d" (List.length vcx) in
          html_all_partial_r a m1 [x] szlim (None::loclist) (x::vcx)
       | Ex(a,m1) ->
          let x = Printf.sprintf "x%d" (List.length vcx) in
          html_ex_partial_r a m1 [x] szlim (None::loclist) (x::vcx)
       | Eq(a,m1,m2) ->
          let (r1,szlim) = html_trm_partial_r m1 (szlim-1) (Some(false)::loclist) vcx in
          let (r2,szlim) = html_trm_partial_r m2 (szlim-1) (Some(true)::loclist) vcx in
          (Info(InfNam("="),r1,r2),szlim)
    in
    match if inegal && !mgnatnotation then mg_fin_ord m else if inhf && !mgnatnotation then hf_fin_ord m else None with
    | Some(n) -> (Nu(false,Printf.sprintf "%d" n,None,None),szlim-1)
    | None ->
       if szlim <= 0 then
         let (loclen,locnum) = loclist_to_code (List.rev loclist) in
         let locnums = string_of_big_int locnum in
         (Na(Printf.sprintf "<span><span class='note'></span><span class='tmabbrev' id='loc_%s_%d_%d_%s' onclick='g(this,\"%s\",%d,%d,\"%s\")'>...</span></span>" pubaddr pubitem loclen locnums pubaddr pubitem loclen locnums),0)
       else
         lastcases()
  and html_lam_partial_r a m newvars szlim loclist vcx =
    match m with
    | Lam(b,m1) ->
       if a = b then
         let x = Printf.sprintf "x%d" (List.length vcx) in
         html_lam_partial_r a m1 (x::newvars) szlim (None::loclist) (x::vcx)
       else if a = Base(0) then
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&lambda;",[(List.rev newvars,None)],r1),szlim-1)
       else
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&lambda;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],r1),szlim-1)
    | _ ->
       if a = Base(0) then
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&lambda;",[(List.rev newvars,None)],r1),szlim-1)
       else
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&lambda;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],r1),szlim-1)
  and html_all_partial_r a m newvars szlim loclist vcx =
    match m with
    | All(b,m1) ->
       if a = b then
         let x = Printf.sprintf "x%d" (List.length vcx) in
         html_all_partial_r a m1 (x::newvars) szlim (None::loclist) (x::vcx)
       else if a = Base(0) then
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&forall;",[(List.rev newvars,None)],r1),szlim-1)
       else
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&forall;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],r1),szlim-1)
    | _ ->
       if a = Base(0) then
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&forall;",[(List.rev newvars,None)],r1),szlim-1)
       else
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&forall;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],r1),szlim-1)
  and html_ex_partial_r a m newvars szlim loclist vcx =
    match m with
    | Ex(b,m1) ->
       if a = b then
         let x = Printf.sprintf "x%d" (List.length vcx) in
         html_ex_partial_r a m1 (x::newvars) szlim (None::loclist) (x::vcx)
       else if a = Base(0) then
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&exist;",[(List.rev newvars,None)],r1),szlim-1)
       else
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&exist;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],r1),szlim-1)
    | All(Prop,Imp(All(b,Imp(m1,DB(1))),DB(0))) when not (free_in 1 m1) ->
       if a = b then
         let x = Printf.sprintf "x%d" (List.length vcx) in
         html_ex_partial_r a m1 (x::newvars) szlim (Some(false)::None::Some(false)::None::loclist) (x::"_"::vcx)
       else if a = Base(0) then
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&exist;",[(List.rev newvars,None)],r1),szlim-1)
       else
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&exist;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],r1),szlim-1)
    | _ ->
       if a = Base(0) then
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&exist;",[(List.rev newvars,None)],r1),szlim-1)
       else
         let (r1,szlim) = html_trm_partial_r m (szlim-1) loclist vcx in
         (Bi("&exist;",[(List.rev newvars,Some(AscTp,mghtml_nice_stp_r a))],r1),szlim-1)
  in
  Buffer.clear mgnicetrmbuf;
  let (ltr,szlim) = html_trm_partial_r m szlim loclist vcx in
  buffer2_ltree mgnicetrmbuf (atree_to_ltree ltr);
  (Buffer.contents mgnicetrmbuf,szlim)

type tm_or_pf = Tm of trm * bool option list | Pf of pf * bool option list

let rec pf_head_spine d sp loclist =
  match d with
  | TmAp(d1,m2) -> pf_head_spine d1 (Tm(m2,Some(true)::loclist)::sp) (Some(false)::loclist)
  | PrAp(d1,d2) -> pf_head_spine d1 (Pf(d2,Some(true)::loclist)::sp) (Some(false)::loclist)
  | _ -> (d,loclist,sp)

let rec html_pf_partial_r pubaddr pubitem th d szlim loclist vcx hcx : string * int =
  if szlim <= 0 then
    let (loclen,locnum) = loclist_to_code (List.rev loclist) in
    let locnums = string_of_big_int locnum in
    (Printf.sprintf "<div><div class='note'></div><div class='pfabbrev' id='loc_%s_%d_%d_%s' onclick='g(this,\"%s\",%d,%d,\"%s\")'>...</div></div>" pubaddr pubitem loclen locnums pubaddr pubitem loclen locnums,0)
  else
    match d with
    | PrLa(m1,d2) ->
       let (r1,szlim) = html_trm_partial pubaddr pubitem th m1 (szlim-1) (Some(false)::loclist) vcx in
       let h = Printf.sprintf "H%d" (List.length hcx) in
       let (r2,szlim) = html_pf_partial_r pubaddr pubitem th d2 (szlim-1) (Some(true)::loclist) vcx (h::hcx) in
       (Printf.sprintf "<div class='pfassume'>Assume %s: %s.</div>\n%s" h r1 r2,szlim-1)
    | TmLa(a1,d2) ->
       let x = Printf.sprintf "x%d" (List.length vcx) in
       let (r2,szlim) = html_pf_partial_r pubaddr pubitem th d2 (szlim-1) (None::loclist) (x::vcx) hcx in
       (Printf.sprintf "<div class='pflet'>Let %s of type %s be given.</div>\n%s" x (mghtml_nice_stp th a1) r2,szlim-1)
    | _ ->
       let (dh,loclist,sp) = pf_head_spine d [] loclist in
       html_pf_partial_head_spine pubaddr pubitem th dh sp szlim loclist vcx hcx
and html_pf_partial_head_spine pubaddr pubitem th d sp szlim loclist vcx hcx =
  let pfsb = Buffer.create 10 in
  let applycases name =
    let insttms = ref [] in
    let subpfs = ref [] in
    List.iter
      (fun spi ->
        match spi with
        | Tm(ma,daloclist) -> insttms := (ma,daloclist)::!insttms
        | Pf(da,daloclist) -> subpfs := (da,daloclist)::!subpfs)
      sp;
    let szlimr = ref (szlim-1) in
    begin
      match List.rev !subpfs with
      | [] ->
         if !insttms = [] then
           Buffer.add_string pfsb (Printf.sprintf "<div class='applydone'>The subproof is completed by applying %s.</div>\n" name)
         else
           let fst = ref true in
           begin
             Buffer.add_string pfsb (Printf.sprintf "<div class='applydone'>The subproof is completed by applying %s with" name);
             List.iter
               (fun (ma,maloclist) ->
                 let (ra,szlim) = html_trm_partial pubaddr pubitem th ma !szlimr maloclist vcx in
                 szlimr := szlim;
                 if !fst then
                   fst := false
                 else
                   Buffer.add_char pfsb ',';
                 Buffer.add_char pfsb ' ';
                 Buffer.add_string pfsb ra)
               (List.rev !insttms);
             Buffer.add_string pfsb (Printf.sprintf ".</div>\n")
           end
      | [(da,daloclist)] ->
         if !insttms = [] then
           begin
             Buffer.add_string pfsb (Printf.sprintf "<div class='applysub'>Apply %s.\n" name);
             let (ra,szlim) = html_pf_partial_r pubaddr pubitem th da !szlimr daloclist vcx hcx in
             szlimr := szlim;
             Buffer.add_string pfsb ra;
             Buffer.add_string pfsb "</div>\n";
           end
         else          
           let fst = ref true in
           begin
             Buffer.add_string pfsb (Printf.sprintf "<div class='applysub'>Apply %s with" name);
             List.iter
               (fun (ma,maloclist) ->
                 let (ra,szlim) = html_trm_partial pubaddr pubitem th ma !szlimr maloclist vcx in
                 szlimr := szlim;
                 if !fst then
                   fst := false
                 else
                   Buffer.add_char pfsb ',';
                 Buffer.add_char pfsb ' ';
                 Buffer.add_string pfsb ra)
               (List.rev !insttms);
             Buffer.add_string pfsb (Printf.sprintf ".\n");
             let (ra,szlim) = html_pf_partial_r pubaddr pubitem th da !szlimr daloclist vcx hcx in
             szlimr := szlim;
             Buffer.add_string pfsb ra;
             Buffer.add_string pfsb "</div>\n";
           end;
      | sbpfl ->
         if !insttms = [] then
           begin
             Buffer.add_string pfsb (Printf.sprintf "<div class='applysub'>Apply %s leaving %d subgoals.\n" name (List.length sbpfl));
             List.iter
               (fun (da,daloclist) ->
                 Buffer.add_string pfsb "<div class='subpf'>";
                 let (ra,szlim) = html_pf_partial_r pubaddr pubitem th da !szlimr daloclist vcx hcx in
                 szlimr := szlim;
                 Buffer.add_string pfsb ra;
                 Buffer.add_string pfsb "</div>\n")
               sbpfl;
             Buffer.add_string pfsb "</div>\n";
           end
         else          
           let fst = ref true in
           begin
             Buffer.add_string pfsb (Printf.sprintf "<div class='applysub'>Apply %s with" name);
             List.iter
               (fun (ma,maloclist) ->
                 let (ra,szlim) = html_trm_partial pubaddr pubitem th ma !szlimr maloclist vcx in
                 szlimr := szlim;
                 if !fst then
                   fst := false
                 else
                   Buffer.add_char pfsb ',';
                 Buffer.add_char pfsb ' ';
                 Buffer.add_string pfsb ra)
               (List.rev !insttms);
             Buffer.add_string pfsb (Printf.sprintf " leaving %s.\n" (if List.length sbpfl > 1 then Printf.sprintf "%d subgoals" (List.length sbpfl) else "1 subgoal"));
             List.iter
               (fun (da,daloclist) ->
                 Buffer.add_string pfsb "<div class='subpf'>";
                 let (ra,szlim) = html_pf_partial_r pubaddr pubitem th da !szlimr daloclist vcx hcx in
                 szlimr := szlim;
                 Buffer.add_string pfsb ra;
                 Buffer.add_string pfsb "</div>\n")
               sbpfl;
             Buffer.add_string pfsb "</div>\n";
           end;
    end;
    (Buffer.contents pfsb,!szlimr)
  in
  match d with
  | PrLa(m1,d2) ->
     begin
       match sp with
       | [] ->
          html_pf_partial_r pubaddr pubitem th d szlim loclist vcx hcx
       | Pf(da,daloclist)::spr ->
          let l = Printf.sprintf "L%d" (List.length hcx) in
          let (r3,szlim) = html_pf_partial_head_spine pubaddr pubitem th d2 spr szlim (Some(true)::loclist) vcx (l::hcx) in
          let (r1,szlim) = html_trm_partial pubaddr pubitem th m1 (szlim-1) (Some(false)::loclist) vcx in
          let (r2,szlim) = html_pf_partial_r pubaddr pubitem th da (szlim-1) daloclist vcx hcx in
          (Printf.sprintf "<div class='claim'><div class='claimstatement'>Claim %s: %s</div>\n<div class='claimpf'>%s</div>\n</div>\n%s\n" l r1 r2 r3,szlim-1)
       | _ ->
          ("bug1",szlim-1)
     end
  | TmLa(a1,d2) ->
     begin
       match sp with
       | [] ->
          html_pf_partial_r pubaddr pubitem th d szlim loclist vcx hcx
       | Tm(ma,daloclist)::spr ->
          let y = Printf.sprintf "y%d" (List.length vcx) in
          let (r2,szlim) = html_pf_partial_head_spine pubaddr pubitem th d2 spr szlim (Some(true)::loclist) (y::vcx) hcx in
          let (r1,szlim) = html_trm_partial pubaddr pubitem th ma (szlim-1) daloclist vcx in
          (Printf.sprintf "<div class='set'>set %s to be %s</div>\n%s\n" y r1 r2,szlim-1)
       | _ ->
          ("bug2",szlim-1)
     end
  | Known(h) ->
     begin
       let propid = hashtag (hashopair2 th h) 33l in
       let names = Hashtbl.find_all mglegendp propid in
       let name =
         match names with
         | (name::_) -> name
         | [] -> Printf.sprintf "unknownprop_%s" (hashval_hexstring h)
       in
       applycases name
     end
  | Hyp(i) ->
     begin
       try
         let name = List.nth hcx i in
         applycases name
       with Failure(_) ->
         applycases (Printf.sprintf "Hyp%d" i)
     end
  | Ext(_,_) ->
     applycases "functional extensionality"
  | _ ->
     let (dh,loclist,sp) = pf_head_spine d sp loclist in
     html_pf_partial_head_spine pubaddr pubitem th dh sp szlim loclist vcx hcx

let html_pf_partial pubaddr pubitem th d szlim loclist vcx hcx =
  let (r,szlim) = html_pf_partial_r pubaddr pubitem th d szlim loclist vcx hcx in
  if loclist = [] then
    (Printf.sprintf "<div class='pf'><div class='pfcontent'>%s</div>&#x25a0;</div>\n" r,szlim)
  else
    (r,szlim)
