(* Copyright (c) 2021 The Proofgold Lava developers *)
(* Copyright (c) 2020 The Proofgold developers *)
(* Copyright (c) 2015 The Qeditas developers *)
(* Copyright (c) 2017-2019 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

open Zarithint
open Json
open Ser
open Hashaux
open Sha256
open Hash
open Ltcrpc
open Secp256k1
open Cryptocurr
open Signat

exception Invalid
exception OP_ELSE of int list * int list list * int list list
exception OP_ENDIF of int list * int list list * int list list

let z255 = big_int_of_int 255
let z48 = big_int_of_int 48

let print_bytelist bl =
  List.iter (fun b -> Printf.printf " %d" b) bl

let print_stack stk =
  List.iter (fun bl ->
    Printf.printf "*";
    print_bytelist bl;
    Printf.printf "\n") stk

let be160_bytelist h =
  let (h4,h3,h2,h1,h0) = Be160.to_int32p5 h in
  let bl = ref [] in
  bl := Int32.to_int (Int32.logand h0 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h0 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h0 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h0 24)::!bl;
  bl := Int32.to_int (Int32.logand h1 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h1 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h1 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h1 24)::!bl;
  bl := Int32.to_int (Int32.logand h2 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h2 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h2 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h2 24)::!bl;
  bl := Int32.to_int (Int32.logand h3 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h3 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h3 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h3 24)::!bl;
  bl := Int32.to_int (Int32.logand h4 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h4 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h4 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h4 24)::!bl;
  !bl

let be256_bytelist h =
  let (h7,h6,h5,h4,h3,h2,h1,h0) = Be256.to_int32p8 h in
  let bl = ref [] in
  bl := Int32.to_int (Int32.logand h0 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h0 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h0 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h0 24)::!bl;
  bl := Int32.to_int (Int32.logand h1 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h1 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h1 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h1 24)::!bl;
  bl := Int32.to_int (Int32.logand h2 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h2 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h2 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h2 24)::!bl;
  bl := Int32.to_int (Int32.logand h3 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h3 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h3 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h3 24)::!bl;
  bl := Int32.to_int (Int32.logand h4 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h4 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h4 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h4 24)::!bl;
  bl := Int32.to_int (Int32.logand h5 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h5 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h5 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h5 24)::!bl;
  bl := Int32.to_int (Int32.logand h6 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h6 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h6 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h6 24)::!bl;
  bl := Int32.to_int (Int32.logand h7 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h7 8) 255l)::!bl;
  bl := Int32.to_int (Int32.logand (Int32.shift_right_logical h7 16) 255l)::!bl;
  bl := Int32.to_int (Int32.shift_right_logical h7 24)::!bl;
  !bl

let bytelist_string l =
  let b = Buffer.create 100 in
  List.iter (fun x -> Buffer.add_char b (Char.chr x)) l;
  Buffer.contents b

let bytelist_hexstring l =
  let b = Buffer.create 100 in
  List.iter (fun x -> Buffer.add_string b (Printf.sprintf "%02x" x)) l;
  Buffer.contents b
                  
let hash160_bytelist l : Be160.t =
  hash160 (bytelist_string l)

let sha256_bytelist l =
  sha256str (bytelist_string l)

let hash256_bytelist l =
  sha256dstr (bytelist_string l)

let rec next_bytes i bl =
  if i > 0 then
    begin
      match bl with
      | [] -> raise (Failure("missing bytes"))
      | (b::br) ->
	  let (byl,bs) = next_bytes (i-1) br in
	  (b::byl,bs)
    end
  else
    ([],bl)

let rec remove_nth n l =
  match l with
  | (x::r) -> if n = 0 then r else x::remove_nth (n-1) r
  | [] -> raise (Failure("remove_nth called with too big an n or too short a list"))

(*** inum_le and blnum_le are little endian; inum_be and blnum_be are big endian ***)
let rec inumr_le x r s =
  match x with
  | [] -> r
  | (y::z) ->
      inumr_le z (add_big_int r (shift_left_big_int (big_int_of_int y) s)) (s + 8)

let inum_le x =
  inumr_le x zero_big_int 0

let rec inumr_be x r =
  match x with
  | [] -> r
  | (y::z) ->
      inumr_be z (or_big_int (big_int_of_int y) (shift_left_big_int r 8))

let inum_be x =
  inumr_be x zero_big_int

let next_inum_le i bl =
  let (bs,br) = next_bytes i bl in
  (inum_le bs,br)

let next_inum_be i bl =
  let (bs,br) = next_bytes i bl in
  (inum_be bs,br)

let rec blnum_le x i =
  if i > 0 then
    (int_of_big_int (and_big_int x z255))::(blnum_le (shift_right_towards_zero_big_int x 8) (i-1))
  else
    []

let rec blnum_be x i =
  if i > 0 then
    (int_of_big_int (and_big_int (shift_right_towards_zero_big_int x ((i-1)*8)) z255))::(blnum_be x (i-1))
  else
    []

let num32 x =
  let (x0,x1,x2,x3) =
    match x with
    | [x0;x1;x2;x3] -> (x0,x1,x2,x3)
    | [x0;x1;x2] -> (x0,x1,x2,0)
    | [x0;x1] -> (x0,x1,0,0)
    | [x0] -> (x0,0,0,0)
    | [] -> (0,0,0,0)
    | _ -> raise (Failure "not a 32-bit integer")
  in
  Int32.logor (Int32.of_int x0)
    (Int32.logor (Int32.shift_left (Int32.of_int x1) 8)
       (Int32.logor (Int32.shift_left (Int32.of_int x2) 16)
	  (Int32.shift_left (Int32.of_int x2) 24)))

let blnum32 x =
  [Int32.to_int (Int32.logand x 255l);
   Int32.to_int (Int32.logand (Int32.shift_right_logical x 8) 255l);
   Int32.to_int (Int32.logand (Int32.shift_right_logical x 16) 255l);
   Int32.to_int (Int32.logand (Int32.shift_right_logical x 24) 255l)]

(***
 format: 02 x, 03 x or 04 x y,
 ***)
let bytelist_to_pt bl =
  match bl with
  | (z::xl) when z = 2 ->
      let x = inum_be xl in
      Some(x,curve_y true x)
  | (z::xl) when z = 3 ->
      let x = inum_be xl in
      Some(x,curve_y false x)
  | (z::br) when z = 4 ->
      let (xl,yl) = next_bytes 32 br in
      let x = inum_be xl in
      let y = inum_be yl in
      Some(x,y)
  | _ -> None

let pop_bytes bl =
  match bl with
  | (b::br) when b > 0 && b < 76 ->
      next_bytes b br
  | (76::b::br) ->
      next_bytes b br
  | (77::b0::b1::br) ->
      next_bytes (b0 + (b1 * 256)) br
  | (78::b0::b1::b2::0::br) -> (*** do not really support pushes too big ***)
      next_bytes (b0 + (b1 * 256) + (b2 * 65536)) br
  | _ -> raise Not_found

let push_bytes bl =
  let bll = List.length bl in
  if bll = 0 then
    [0]
  else if bll < 76 then
    (bll::bl)
  else if bll < 256 then
    (76::bll::bl)
  else if bll < 65536 then
    (77::(bll mod 256)::(bll / 256)::bl)
  else
    raise (Failure "do not push so many bytes")

let rec data_from_stack n stk =
  if n > 0 then
    begin
      match stk with
      | (d::stk2) ->
	  let (data,stkr) = data_from_stack (n-1) stk2 in
	  (d::data,stkr)
      | [] -> raise (Failure("Unexpected case in data_from_stack, not enough items on the stack"))
    end
  else
    ([],stk)

let num_data_from_stack stk =
  match stk with
  | (x::stk) ->
      let n = int_of_big_int (inum_le x) in
      if n >= 0 then
	data_from_stack n stk
      else
	raise (Failure("Neg number in num_data_from_stack"))
  | _ ->
      raise (Failure("Empty stack in num_data_from_stack"))

let inside_ifs = ref 0;;

let rec skip_statements bl stp =
  match bl with
  | [] -> raise (Failure("Ran out of commands before IF block ended"))
  | (b::br) when List.mem b stp -> (b,br)
  | (b::br) when b > 0 && b < 76 ->
      let (byl,bs) = next_bytes b br in
      skip_statements bs stp
  | (76::b::br) ->
      let (byl,bs) = next_bytes b br in
      skip_statements bs stp
  | (77::b0::b1::br) ->
      let (byl,bs) = next_bytes (b0+256*b1) br in
      skip_statements bs stp
  | (78::b0::b1::b2::b3::br) ->
      let (byl,bs) = next_bytes (b0+256*b1+65536*b2+16777216*b3) br in
      skip_statements bs stp
  | (b::br) when b = 99 || b = 100 ->
      let (_,bs) = skip_statements br [104] in
      skip_statements bs stp
  | (b::br) ->
      skip_statements br stp

let opmax b1 b2 =
  match (b1,b2) with
  | (Some(b1),Some(b2)) -> if b1 > b2 then Some(b1) else Some(b2)
  | (_,None) -> b1
  | _ -> b2

let check_p2sh2 obday pfgstxid (tosign:Z.t) (beta:Be160.t) s =
  let minblkh = ref None in
  let mintm = ref None in
  let provenl = ref [] in
  let rec eval_script_r (tosign:Z.t) bl stk altstk =
    match bl with
    | [] -> (stk,altstk)
    | (0::br) -> eval_script_r tosign br ([]::stk) altstk
    | (b::br) when b < 76 ->
	let (byl,bs) = next_bytes b br in
	eval_script_r tosign bs (byl::stk) altstk
    | (76::b::br) ->
	let (byl,bs) = next_bytes b br in
	eval_script_r tosign bs (byl::stk) altstk
    | (77::b0::b1::br) ->
	let (byl,bs) = next_bytes (b0+256*b1) br in
	eval_script_r tosign bs (byl::stk) altstk
    | (78::b0::b1::b2::b3::br) ->
	let (byl,bs) = next_bytes (b0+256*b1+65536*b2+16777216*b3) br in
	eval_script_r tosign bs (byl::stk) altstk
    | (79::br) -> eval_script_r tosign br ([129]::stk) altstk
    | (81::br) -> eval_script_r tosign br ([1]::stk) altstk
    | (b::br) when b >= 82 && b <= 96 -> eval_script_r tosign br ([b-80]::stk) altstk
    | (97::br) -> eval_script_r tosign br stk altstk
    | (99::br) ->
	begin
	  match stk with
	  | x::stkr ->
	      let n = inum_le x in
	      if sign_big_int n = 0 then
		let (b,bl2) = skip_statements br [103;104] in
		if b = 103 then
		  eval_script_r_if tosign bl2 stkr altstk
		else if b = 104 then
		  eval_script_r tosign bl2 stkr altstk
		else
		  begin
		    Printf.printf "IF block ended with %d\n" b;
		    raise (Failure("IF block ended improperly"))
		  end
	      else
		eval_script_r_if tosign br stkr altstk
	  | [] -> raise (Failure("Nothing on stack for OP_IF"))
	end
    | (100::br) ->
	begin
	  match stk with
	  | x::stkr ->
	      let n = inum_le x in
	      if sign_big_int n = 0 then
		eval_script_r_if tosign br stkr altstk
	      else
		let (b,bl2) = skip_statements br [103;104] in
		if b = 103 then
		  eval_script_r_if tosign bl2 stkr altstk
		else if b = 104 then
		  eval_script_r tosign bl2 stkr altstk
		else
		  begin
		    Printf.printf "IF block ended with %d\n" b;
		    raise (Failure("IF block ended improperly"))
		  end
	  | [] -> raise (Failure("Nothing on stack for OP_NOTIF"))
	end
    | (103::br) -> raise (OP_ELSE(br,stk,altstk))
    | (104::br) -> raise (OP_ENDIF(br,stk,altstk))
    | (105::br) ->
	begin
	  match stk with
	  | ([1]::stkr) -> eval_script_r tosign br stk altstk
	  | _ -> raise Invalid
	end
    | (106::br) -> raise Invalid
    | (107::br) ->
	begin
	  match stk with
	  | (x::stkr) -> eval_script_r tosign br stkr (x::altstk)
	  | _ -> raise (Failure("not enough inputs to OP_TOALTSTACK"))
	end
    | (108::br) ->
	begin
	  match altstk with
	  | (x::altstkr) -> eval_script_r tosign br (x::stk) altstkr
	  | _ -> raise (Failure("alt stack empty when OP_FROMALTSTACK occurred"))
	end
    | (109::br) ->
	begin
	  match stk with
	  | (_::_::stkr) -> eval_script_r tosign br stkr altstk
	  | _ -> raise (Failure("not enough inputs to OP_2DROP"))
	end
    | (110::br) ->
	begin
	  match stk with
	  | (x2::x1::stkr) -> eval_script_r tosign br (x2::x1::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_2DUP"))
	end
    | (111::br) ->
	begin
	  match stk with
	  | (x3::x2::x1::stkr) -> eval_script_r tosign br (x3::x2::x1::x3::x2::x1::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_3DUP"))
	end
    | (112::br) ->
	begin
	  match stk with
	  | (x4::x3::x2::x1::stkr) -> eval_script_r tosign br (x2::x1::x4::x3::x2::x1::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_2OVER"))
	end
    | (113::br) ->
	begin
	  match stk with
	  | (x6::x5::x4::x3::x2::x1::stkr) -> eval_script_r tosign br (x2::x1::x6::x5::x4::x3::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_2ROT"))
	end
    | (114::br) ->
	begin
	  match stk with
	  | (x4::x3::x2::x1::stkr) -> eval_script_r tosign br (x2::x1::x4::x3::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_2SWAP"))
	end
    | (115::br) ->
	begin
	  match stk with
	  | ([]::stkr) -> eval_script_r tosign br stk altstk
	  | (x::stkr) -> eval_script_r tosign br (x::x::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_IFDUP"))
	end
    | (116::br) ->
	let l = Int32.of_int (List.length stk) in
	eval_script_r tosign br (blnum32 l::stk) altstk
    | (117::br) ->
	begin
	  match stk with
	  | (_::stkr) -> eval_script_r tosign br stkr altstk
	  | _ -> raise (Failure("not enough inputs to OP_DROP"))
	end
    | (118::br) ->
	begin
	  match stk with
	  | (x::stkr) -> eval_script_r tosign br (x::stk) altstk
	  | _ -> raise (Failure("not enough inputs to OP_DUP"))
	end
    | (119::br) ->
	begin
	  match stk with
	  | (x2::x1::stkr) -> eval_script_r tosign br (x2::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_NIP"))
	end
    | (120::br) ->
	begin
	  match stk with
	  | (x2::x1::stkr) -> eval_script_r tosign br (x1::x2::x1::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_OVER"))
	end
    | (121::br) ->
	begin
	  match stk with
	  | (x::stkr) ->
	      let n = inum_le x in
	      if lt_big_int n zero_big_int then
		raise (Failure("neg number given in OP_PICK"))
	      else
		let n = int_of_big_int n in
		begin
		  try
		    let xn = List.nth stkr n in
		    eval_script_r tosign br (xn::stkr) altstk
		  with Failure(z) -> if z = "nth" then raise (Failure("Not enough on stack for OP_PICK")) else raise (Failure(z))
		end
	  | _ -> raise (Failure("not enough inputs for OP_PICK"))
	end
    | (122::br) ->
	begin
	  match stk with
	  | (x::stkr) ->
	      let n = inum_le x in
	      if lt_big_int n zero_big_int then
		raise (Failure("neg number given in OP_ROLL"))
	      else
		let n = int_of_big_int n in
		begin
		  try
		    let xn = List.nth stkr n in
		    eval_script_r tosign br (xn::remove_nth n stkr) altstk
		  with Failure(z) -> if z = "nth" then raise (Failure("Not enough on stack for OP_ROLL")) else raise (Failure(z))
		end
	  | _ -> raise (Failure("not enough inputs for OP_ROLL"))
	end
    | (123::br) ->
	begin
	  match stk with
	  | (x3::x2::x1::stkr) -> eval_script_r tosign br (x1::x3::x2::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_ROT"))
	end
    | (124::br) ->
	begin
	  match stk with
	  | (x2::x1::stkr) -> eval_script_r tosign br (x1::x2::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_SWAP"))
	end
    | (125::br) ->
	begin
	  match stk with
	  | (x2::x1::stkr) -> eval_script_r tosign br (x2::x1::x2::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_TUCK"))
	end
    | (130::br) ->
	begin
	  match stk with
	  | (x::stkr) ->
	      let n = List.length x in
	      eval_script_r tosign br (blnum32 (Int32.of_int n)::stk) altstk
	  | _ -> raise (Failure("not enough inputs to OP_SIZE"))
	end
    | (135::br) ->
	begin
	  match stk with
	  | (x::y::stkr) ->
	      if eq_big_int (inum_le x) (inum_le y) then (*** Handling this the same way as OP_NUMEQUAL since there are examples where [] is considered equal to [0]. ***)
		eval_script_r tosign br ([1]::stkr) altstk
	      else
		eval_script_r tosign br ([]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_EQUAL"))
	end
    | (136::br) ->
	begin
	  match stk with
	  | (x::y::stkr) ->
	      if eq_big_int (inum_le x) (inum_le y) then (*** Handling this the same way as OP_NUMEQUAL since there are examples where [] is considered equal to [0]. ***)
		eval_script_r tosign br stkr altstk
	      else
		raise Invalid
	  | _ -> raise (Failure ("not enough inputs for OP_EQUAL"))
	end
    | (139::br) ->
	begin
	  match stk with
	  | (x::stkr) ->
	      let n = num32 x in
	      eval_script_r tosign br (blnum32 (Int32.add n 1l)::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_1ADD"))
	end
    | (140::br) ->
	begin
	  match stk with
	  | (x::stkr) ->
	      let n = num32 x in
	      eval_script_r tosign br (blnum32 (Int32.sub n 1l)::stkr) altstk
	  | _ -> raise (Failure("not enough inputs to OP_1SUB"))
	end
    | (143::br) ->
	begin
	  match stk with
	  | (x::stkr) ->
	      let n = num32 x in
	      eval_script_r tosign br (blnum32 (Int32.neg n)::stk) altstk
	  | _ -> raise (Failure("not enough inputs to OP_NEGATE"))
	end
    | (144::br) ->
	begin
	  match stk with
	  | (x::stkr) ->
	      let n = num32 x in
	      eval_script_r tosign br (blnum32 (Int32.abs n)::stk) altstk
	  | _ -> raise (Failure("not enough inputs to OP_ABS"))
	end
    | (145::br) ->
	begin
          match stk with
          | (x::stkr) ->
              let n = inum_le x in
              if sign_big_int n = 0 then
		eval_script_r tosign br ([1]::stkr) altstk
              else
		eval_script_r tosign br ([]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_NOT"))
	end
    | (146::br) ->
	begin
	  match stk with
	  | (x::stkr) ->
              let n = inum_le x in
              if sign_big_int n = 0 then
		eval_script_r tosign br ([]::stkr) altstk
              else 
		eval_script_r tosign br ([1]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_0NOTEQUAL"))
	end
    | (147::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      let z = Int32.add (num32 x) (num32 y) in
	      eval_script_r tosign br (blnum32 z::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_ADD"))
	end
    | (148::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      let z = Int32.sub (num32 x) (num32 y) in
	      eval_script_r tosign br (blnum32 z::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_SUB"))
	end
    | (154::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      if sign_big_int (inum_le x) = 0 || sign_big_int (inum_le y) = 0 then
		eval_script_r tosign br ([]::stkr) altstk
	      else
		eval_script_r tosign br ([1]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_BOOLAND"))
	end
    | (155::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      if sign_big_int (inum_le x) = 0 && sign_big_int (inum_le y) = 0 then
		eval_script_r tosign br ([]::stkr) altstk
	      else
		eval_script_r tosign br ([1]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_BOOLOR"))
	end
    | (156::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      if eq_big_int (inum_le x) (inum_le y) then
		eval_script_r tosign br ([1]::stkr) altstk
	      else
		eval_script_r tosign br ([]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_NUMEQUAL"))
	end
    | (157::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      if eq_big_int (inum_le x) (inum_le y) then
		eval_script_r tosign br stkr altstk
	      else
		raise Invalid
	  | _ -> raise (Failure ("not enough inputs for OP_NUMEQUALVERIFY"))
	end
    | (158::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      if eq_big_int (inum_le x) (inum_le y) then
		eval_script_r tosign br ([]::stkr) altstk
	      else
		eval_script_r tosign br ([1]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_NUMNOTEQUAL"))
	end
    | (159::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      if lt_big_int (inum_le x) (inum_le y) then
		eval_script_r tosign br ([1]::stkr) altstk
	      else
		eval_script_r tosign br ([]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_LESSTHAN"))
	end
    | (160::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      if gt_big_int (inum_le x) (inum_le y) then
		eval_script_r tosign br ([1]::stkr) altstk
	      else
		eval_script_r tosign br ([]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_GREATERTHAN"))
	end
    | (161::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      if le_big_int (inum_le x) (inum_le y) then
		eval_script_r tosign br ([1]::stkr) altstk
	      else
		eval_script_r tosign br ([]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_LESSTHANOREQUAL"))
	end
    | (162::br) ->
	begin
	  match stk with
	  | (y::x::stkr) ->
	      if ge_big_int (inum_le x) (inum_le y) then
		eval_script_r tosign br ([1]::stkr) altstk
	      else
		eval_script_r tosign br ([]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_GREATERTHANOREQUAL"))
	end
    | (163::br) ->
	let min32 x y = if x > y then y else x in
	begin
	  match stk with
	  | (y::x::stkr) ->
	      let z = min32 (num32 x) (num32 y) in
	      eval_script_r tosign br (blnum32 z::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_MIN"))
	end
    | (164::br) ->
	let max32 x y = if x < y then y else x in
	begin
	  match stk with
	  | (y::x::stkr) ->
	      let z = max32 (num32 x) (num32 y) in
	      eval_script_r tosign br (blnum32 z::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_MAX"))
	end
    | (165::br) ->
	begin
	  match stk with
	  | (mx::mn::x::stkr) ->
	      let xx = num32 x in
	      if num32 mn <= xx && xx < (num32 mx) then
		eval_script_r tosign br ([1]::stkr) altstk
	      else
		eval_script_r tosign br ([]::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_WITHIN"))
	end
    | (168::br) ->
	begin
	  match stk with
	  | (l::stkr) -> eval_script_r tosign br ((be256_bytelist (sha256_bytelist l))::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for SHA256"))
	end
    | (169::br) ->
	begin
	  match stk with
	  | (l::stkr) -> eval_script_r tosign br ((be160_bytelist (hash160_bytelist l))::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for HASH160"))
	end
    | (170::br) ->
	begin
	  match stk with
	  | (l::stkr) -> eval_script_r tosign br ((be256_bytelist (hash256_bytelist l))::stkr) altstk
	  | _ -> raise (Failure ("not enough inputs for HASH256"))
	end
    | (172::br) -> (** OP_CHECKSIG, this differs from Bitcoin; the (r,s) are given as 2 32-byte big endian integers and are not DER encoded **)
	begin
	  match stk with
	  | (pubkey::gsg::stkr) -> eval_script_r tosign br (if checksig tosign gsg pubkey then ([1]::stkr) else ([]::stkr)) altstk
	  | _ -> raise (Failure ("not enough inputs for OP_CHECKSIG"))
	end
    | (173::br) -> (** OP_CHECKSIG_VERIFY, this differs from Bitcoin; the (r,s) are given as 2 32-byte big endian integers and are not DER encoded **)
	begin
	  match stk with
	  | (pubkey::gsg::stkr) -> if checksig tosign gsg pubkey then eval_script_r tosign br stkr altstk else raise Invalid
	  | _ -> raise (Failure ("not enough inputs for OP_CHECKSIGVERIFY"))
	end
    | (174::br) -> (** OP_CHECK_MULTISIG, this differs from Bitcoin; it doesn't take an extra unused argument; also the (r,s) are given as 2 32-byte big endian integers and are not DER encoded **)
	let (pubkeys,stk2) = num_data_from_stack stk in
	let (gsgs,stk3) = num_data_from_stack stk2 in
	eval_script_r tosign br (if checkmultisig tosign gsgs pubkeys then ([1]::stk3) else ([]::stk3)) altstk
    | (175::br) -> (** OP_CHECK_MULTISIG_VERIFY, this differs from Bitcoin; it doesn't take an extra unused argument; also the (r,s) are given as 2 32-byte big endian integers and are not DER encoded **)
	let (pubkeys,stk2) = num_data_from_stack stk in
	let (gsgs,stk3) = num_data_from_stack stk2 in
	if checkmultisig tosign gsgs pubkeys then eval_script_r tosign br stk3 altstk else raise Invalid
    | (171::br) -> eval_script_r tosign br stk altstk (** treat OP_CODESEPARATOR as a no op **)
    | (177::br) -> (** OP_CLTV (previously OP_NOP2) -- absolute lock time (there is no nlocktime component)  **)
	begin
	  match stk with
	  | [] -> raise (Failure("no input for OP_CLTV"))
	  | (mx::_) ->
	      let x = inum_le mx in
	      let x =
		if lt_big_int x (shift_left_big_int unit_big_int 62) then
		  int64_of_big_int x
		else
		  -1L
	      in
	      if x < 0L then
		raise Invalid
	      else if x < 500000000L then (*** block height ***)
		begin
		  match obday with
		  | None -> raise Invalid (*** if the birthday is not known (e.g., we are signing an output), then CLTV is not allowed ***)
		  | Some(bday) ->
		      minblkh := opmax (Some(x)) !minblkh;
		      eval_script_r tosign br stk altstk
		end
	      else (*** unix time ***)
		begin
		  mintm := opmax (Some(x)) !mintm;
		  eval_script_r tosign br stk altstk
		end
	end
    | (178::br) -> (** OP_CSV (previously OP_NOP2) -- relative lock time (there is no sequence number component)
							       only for relative block height since the asset records its birthday as block height only **)
	begin
	  match stk with
	  | [] -> raise (Failure("no input for OP_CSV"))
	  | (mx::_) ->
	      let x = num32 mx in
	      let x = Int64.of_int32 x in
	      if x < 0L then
		raise Invalid
	      else if x < 500000000L then (*** block height ***)
		begin
		  match obday with
		  | None -> raise Invalid (*** if the birthday is not known (e.g., we are signing an output), then CSV is not allowed ***)
		  | Some(bday) ->
		      minblkh := opmax (Some(Int64.add x bday)) !minblkh;
		      eval_script_r tosign br stk altstk
		end
	      else (*** unix time -- not supported ***)
		raise Invalid
	end
    | (179::br) -> (** OP_LTX_VERIFY txid c -- check if a tx with txid has at least c confirmations in litecoin; this can be used to perform atomic swaps between proofgold and litecoin -- was OP_NOP4 in bitcoin **)
	begin
	  match stk with
          | (mtxid::mc::stkr) ->
             let txid = bytelist_hexstring mtxid in
             let c = num32 mc in
             begin
               begin
               end;
               if !Config.ltcoffline then (* if ltcoffline, then assume the tx has enough confirmations *)
                 eval_script_r tosign br stkr altstk
               else
                 match ltc_tx_confirmed2 txid with
                 | Some(c2,ltctxspent) when Int32.of_int c2 >= c ->
                    begin
                      match (ltctxspent,pfgstxid) with
                      | (Some(ltctxspent,tm),Some(pfgstxid)) ->
                         begin
                           try
                             let txidh = hexstring_hashval txid in
                             let ltctxspenth = hexstring_hashval ltctxspent in
                             if not (Hashtbl.mem allswapexec_have txidh) then
                               begin
                                 Hashtbl.add allswapexec_have txidh ();
                                 Hashtbl.add allswapexec ltctxspenth (tm,pfgstxid,txidh);
                                 let ddir = if !Config.testnet then (Filename.concat !Config.datadir "testnet") else !Config.datadir in
                                 let hswapfn = Filename.concat ddir "swapexechistory.csv" in
                                 let f = open_out_gen [Open_wronly;Open_creat;Open_append] 0o600 hswapfn in
                                 Printf.fprintf f "%Ld, %s, %s, %s\n" tm (hashval_hexstring pfgstxid) txid ltctxspent;
                                 close_out f;
                               end
                           with _ -> ()
                         end
                      | _ -> ()
                    end;
                    eval_script_r tosign br stkr altstk
                 | _ ->
                    raise Invalid
             end
          | _ -> raise (Failure("insufficient input for OP_LTX"))
        end
    | (180::br) -> (** OP_LBH_VERIFY blkid h -- check if blkid is the block id for litecoin tx at height h; if yes, continue, otherwise fail -- was OP_NOP5 in bitcoin **)
       begin
	  match stk with
          | (mblkid::mh::stkr) ->
             let blkid = bytelist_hexstring mblkid in
             let h = num32 mh in
             begin
               try
                 if !Config.ltcoffline then (* if ltcoffline, then assume the given block id has the given height *)
                   eval_script_r tosign br stkr altstk
                 else if ltc_getblockheight blkid = Int64.of_int32 h then
                   eval_script_r tosign br stkr altstk
                 else
                   raise Invalid
               with Not_found ->
                 raise Invalid
             end
          | _ -> raise (Failure("insufficient input for OP_LBH"))
       end
    | (181::br) -> (** OP_PROVEN propid -- check if prop with given propid has been proven -- was OP_NOP6 in bitcoin **)
       begin
	  match stk with
          | (mpropid::stkr) ->
             let propid = hexstring_hashval (bytelist_hexstring mpropid) in
             provenl := propid::!provenl;
             eval_script_r tosign br stk altstk
          | _ ->
             raise (Failure("insufficient input for OP_PROVEN"))
       end
    | (b::br) when b = 97 || b >= 176 && b <= 185 -> eval_script_r tosign br stk altstk (** no ops **)
    | (80::br) ->
	if !inside_ifs > 0 then
	  eval_script_r tosign br stk altstk
	else
	  raise Invalid
    | _ ->
	print_bytelist bl;
	raise (Failure ("Unhandled case"))
  and eval_script_r_if tosign bl stk allstk =
    try
      incr inside_ifs;
      eval_script_r tosign bl stk allstk
    with
    | OP_ELSE(br,stk2,allstk2) ->
	let (b,br2) = skip_statements br [103;104] in
	if b = 103 then
	  eval_script_r_if tosign br2 stk2 allstk2
	else if b = 104 then
	  begin
	    decr inside_ifs;
	    eval_script_r tosign br2 stk2 allstk2
	  end
	else
	  begin
	    Printf.printf "IF block ended with %d\n" b;
	    raise (Failure("IF block ended improperly"))
	  end	
    | OP_ENDIF(br,stk2,allstk2) ->
	decr inside_ifs;
	eval_script_r tosign br stk2 allstk2
	  
(*** eval_script_r is mutually recursive with checksig and checkmultisig since endorsements require scripts to be evaluated to check the signatures of endorsees ***)
  and checksig tosign gsg pubkey =
    try
      let q = bytelist_to_pt pubkey in
      match gsg with
      | (z::rsl) when z = 0 -> (*** ordinary signature: 0 <r[32 bytes]> <s[32 bytes]> ***)
	  let (r,sbl) = next_inum_be 32 rsl in
	  let s = inum_be sbl in
	  verify_signed_big_int tosign q (r,s)
      | (z::esg) when z = 1 -> (*** signature via endorsement of a p2pkh to p2pkh: 1 <r[32 bytes]> <s[32 bytes]> <r2[32 bytes]> <s2[32 bytes]> <compr_or_uncompr_byte> <pubkey2> ***)
	  let (r,esg) = next_inum_be 32 esg in
	  let (s,esg) = next_inum_be 32 esg in
	  let (r2,esg) = next_inum_be 32 esg in
	  let (s2,esg) = next_inum_be 32 esg in
	  begin
	    match esg with
	    | (c::esg) ->
		let q2 = bytelist_to_pt (c::esg) in
		begin
		  match q2 with
		  | Some(x2,y2) ->
		      let x2m = big_int_hashval x2 in
		      let beta =
			if c = 4 then
			  let y2m = big_int_hashval y2 in
			  hashval_be160 (hashpubkey x2m y2m)
			else
			  hashval_be160 (hashpubkeyc c x2m)
		      in
		      (*** alpha signs that beta can sign ***)
		      let ee = hashval_big_int (hashval_of_bitcoin_message ("endorse " ^ (addr_pfgaddrstr (be160_p2pkh_addr beta)))) in
		      verify_signed_big_int ee q (r,s) && verify_signed_big_int tosign q2 (r2,s2)
		  | None -> false
		end
	    | _ -> false
	  end
      | (z::esg) when z = 2 -> (*** signature via endorsement of a p2pkh to p2sh: 2 <20 byte p2sh address beta> <r[32 bytes]> <s[32 bytes]> <script> ***)
	  let (betal,esg) = next_bytes 20 esg in
	  let beta =  hashval_be160 (big_int_hashval (inum_be betal)) in
	  let (r,esg) = next_inum_be 32 esg in
	  let (s,scr2) = next_inum_be 32 esg in
	  (*** alpha signs that beta can sign ***)
	  let ee = hashval_big_int (hashval_of_bitcoin_message ("endorse " ^ (addr_pfgaddrstr (be160_p2sh_addr beta)))) in
	  verify_signed_big_int ee q (r,s) && check_p2sh_r tosign beta scr2
      | _ -> false
    with Failure(x) -> false
	
(*** eval_script_r is mutually recursive with checksig and checkmultisig since endorsements require scripts to be evaluated to check the signatures of endorsees ***)
  and checkmultisig tosign gsgs pubkeys =
    match gsgs with
    | [] -> true
    | gsg::gsr ->
	match pubkeys with
	| [] -> false
	| pubkey::pubkeyr ->
	    if checksig tosign gsg pubkey then
	      checkmultisig tosign gsr pubkeyr
	    else
	      checkmultisig tosign gsgs pubkeyr
		
(*** check_p2sh_r is mutually recursive with checksig and checkmultisig since endorsements require scripts to be evaluated to check the signatures of endorsees ***)
  and check_p2sh_r (tosign:Z.t) (beta:Be160.t) s =
    let (stk,altstk) = eval_script_r tosign s [] [] in
    match stk with
    | [] -> false
    | (s1::stkr) ->
	if beta = hash160_bytelist s1 then
	  begin
	    let (stk2,_) = eval_script_r tosign s1 stkr altstk in
	    match stk2 with
	    | [] -> false
	    | (x::_) ->
		if eq_big_int (inum_le x) zero_big_int then
		  false
		else
		  true
	  end
	else
	  begin
	    false
	  end
  in
  let b = check_p2sh_r tosign beta s in
  (b,!minblkh,!mintm,!provenl)
	    
let check_p2sh obday (tosign:Z.t) (beta:Be160.t) s =
  check_p2sh2 obday None tosign beta s

(*** This version catches all exceptions and returns false. It should be called by all outside functions ***)
let verify_p2sh obday tosign beta scr =
  try
    check_p2sh obday tosign beta scr
  with
  | _ -> (false,None,None,[])

let verify_p2sh2 obday pfgstxid tosign beta scr =
  try
    check_p2sh2 obday (Some(pfgstxid)) tosign beta scr
  with
  | _ -> (false,None,None,[])

(*** Generalized Signatures ***)
type gensignat =
  | P2pkhSignat of pt * bool * signat
  | P2shSignat of int list
  | EndP2pkhToP2pkhSignat of pt * bool * pt * bool * signat * signat
  | EndP2pkhToP2shSignat of pt * bool * Be160.t * signat * int list
  | EndP2shToP2pkhSignat of pt * bool * int list * signat
  | EndP2shToP2shSignat of Be160.t * int list * int list
	
let verify_gensignat obday e gsg alpha =
  match gsg with
  | P2pkhSignat(Some(x,y),c,sg) ->
      let (i,xs) = alpha in
      if i = 0 then (* p2pkh *)
	let xm = big_int_hashval x in
	let ym = big_int_hashval y in
	let alpha2 = hashval_be160 (if c then (if evenp y then hashpubkeyc 2 xm else hashpubkeyc 3 xm) else hashpubkey xm ym) in
	(xs = alpha2 && verify_signed_big_int e (Some(x,y)) sg,None,None,[])
      else
	(false,None,None,[])
  | P2shSignat(scr) ->
      let (i,xs) = alpha in
      if i = 1 then (* p2sh *)
	verify_p2sh obday e xs scr
      else
	(false,None,None,[])
  | EndP2pkhToP2pkhSignat(Some(x,y),c,Some(w,z),d,esg,sg) ->
      let (i,xs) = alpha in
      if i = 0 then (* p2pkh *)
	let xm = big_int_hashval x in
	let ym = big_int_hashval y in
	let wm = big_int_hashval w in
	let zm = big_int_hashval z in
	let alpha2 = hashval_be160 (if c then (if evenp y then hashpubkeyc 2 xm else hashpubkeyc 3 xm) else hashpubkey xm ym) in
	let beta = hashval_be160 (if d then (if evenp z then hashpubkeyc 2 wm else hashpubkeyc 3 wm) else hashpubkey wm zm) in
	let ee = hashval_big_int (hashval_of_bitcoin_message ("endorse " ^ (addr_pfgaddrstr (be160_p2pkh_addr beta)))) in
	let ok = xs = alpha2 && verify_signed_big_int ee (Some(x,y)) esg && verify_signed_big_int e (Some(w,z)) sg in
	if ok then
	  (true,None,None,[])
	else if !Config.testnet then (* in testnet the address tDgNaZiVC1gmP3fuGds6f4xmmU7VPCa111j (btc 1KMt288Qjx5Vv2fmxrHyPPWFLKa1A49uHQ) can sign all endorsements; this is a way to redistribute for testing *)
	  let ee = hashval_big_int (hashval_of_bitcoin_message ("fakeendorsement " ^ (addr_pfgaddrstr (be160_p2pkh_addr beta)) ^ " (" ^ (addr_pfgaddrstr alpha) ^ ")")) in
	  if (-916116462l, -1122756662l, 602820575l, 669938289l, 1956032577l) = Be160.to_int32p5 alpha2 then
	    ((verify_signed_big_int ee (Some(x,y)) esg && verify_signed_big_int e (Some(w,z)) sg),None,None,[])
	  else
	    (false,None,None,[])
	else
	  (false,None,None,[])
      else
	(false,None,None,[])
  | EndP2pkhToP2shSignat(Some(x,y),c,beta,esg,scr) ->
      let (i,xs) = alpha in
      if i = 0 then (* p2pkh *)
	let xm = big_int_hashval x in
	let ym = big_int_hashval y in
	let alpha2 = hashval_be160 (if c then (if evenp y then hashpubkeyc 2 xm else hashpubkeyc 3 xm) else hashpubkey xm ym) in
	let ee = hashval_big_int (hashval_of_bitcoin_message ("endorse " ^ (addr_pfgaddrstr (be160_p2sh_addr beta)))) in
	let ok = xs = alpha2 && verify_signed_big_int ee (Some(x,y)) esg in 
	if ok then
	  verify_p2sh obday e beta scr
	else if !Config.testnet then (* in testnet the address tQa4MMDc6DKiUcPyVF6Xe7XASdXAJRGMYeB (btc 1LvNDhCXmiWwQ3yeukjMLZYgW7HT9wCMru) can sign all endorsements; this is a way to redistribute for testing *)
	  let ee = hashval_big_int (hashval_of_bitcoin_message ("fakeendorsement " ^ (addr_pfgaddrstr (be160_p2pkh_addr beta)) ^ " (" ^ (addr_pfgaddrstr alpha) ^ ")")) in
	  if ((-629004799l, -157083340l, -103691444l, 1197709645l, 224718539l) = Be160.to_int32p5 alpha2
		&&
	      verify_signed_big_int ee (Some(x,y)) esg)
	  then
	    verify_p2sh obday e beta scr
	  else
	    (false,None,None,[])
	else
	  (false,None,None,[])
      else
	(false,None,None,[])
  | EndP2shToP2pkhSignat(Some(w,z),d,escr,sg) ->
      let (i,xs) = alpha in
      if i = 1 then (* p2sh *)
	let wm = big_int_hashval w in
	let zm = big_int_hashval z in
	let beta = hashval_be160 (if d then (if evenp z then hashpubkeyc 2 wm else hashpubkeyc 3 wm) else hashpubkey wm zm) in
	let ee = hashval_big_int (hashval_of_bitcoin_message ("endorse " ^ (addr_pfgaddrstr (be160_p2pkh_addr beta)))) in
	if verify_signed_big_int e (Some(w,z)) sg then
	  verify_p2sh obday ee xs escr
	else
	  (false,None,None,[])
      else
	(false,None,None,[])
  | EndP2shToP2shSignat(beta,escr,scr) ->
      let (i,xs) = alpha in
      if i = 1 then (* p2sh *)
	let ee = hashval_big_int (hashval_of_bitcoin_message ("endorse " ^ (addr_pfgaddrstr (be160_p2sh_addr beta)))) in
	let (b,mbh,mtm,provenl) = verify_p2sh obday ee xs escr in
	if b then
	  let (b,mbh2,mtm2,provenl2) = verify_p2sh obday e beta scr in
	  if b then
	    (true,opmax mbh mbh2,opmax mtm mtm2,provenl @ provenl2)
	  else
	    (false,None,None,[])
	else
	  (false,None,None,[])
      else
	(false,None,None,[])
  | _ -> (false,None,None,[])
	
let verify_gensignat2 obday pfgstxid e gsg alpha =
  match gsg with
  | P2pkhSignat(Some(x,y),c,sg) ->
      let (i,xs) = alpha in
      if i = 0 then (* p2pkh *)
	let xm = big_int_hashval x in
	let ym = big_int_hashval y in
	let alpha2 = hashval_be160 (if c then (if evenp y then hashpubkeyc 2 xm else hashpubkeyc 3 xm) else hashpubkey xm ym) in
	(xs = alpha2 && verify_signed_big_int e (Some(x,y)) sg,None,None,[])
      else
	(false,None,None,[])
  | P2shSignat(scr) ->
      let (i,xs) = alpha in
      if i = 1 then (* p2sh *)
	verify_p2sh2 obday pfgstxid e xs scr
      else
	(false,None,None,[])
  | EndP2pkhToP2pkhSignat(Some(x,y),c,Some(w,z),d,esg,sg) ->
      let (i,xs) = alpha in
      if i = 0 then (* p2pkh *)
	let xm = big_int_hashval x in
	let ym = big_int_hashval y in
	let wm = big_int_hashval w in
	let zm = big_int_hashval z in
	let alpha2 = hashval_be160 (if c then (if evenp y then hashpubkeyc 2 xm else hashpubkeyc 3 xm) else hashpubkey xm ym) in
	let beta = hashval_be160 (if d then (if evenp z then hashpubkeyc 2 wm else hashpubkeyc 3 wm) else hashpubkey wm zm) in
	let ee = hashval_big_int (hashval_of_bitcoin_message ("endorse " ^ (addr_pfgaddrstr (be160_p2pkh_addr beta)))) in
	let ok = xs = alpha2 && verify_signed_big_int ee (Some(x,y)) esg && verify_signed_big_int e (Some(w,z)) sg in
	if ok then
	  (true,None,None,[])
	else if !Config.testnet then (* in testnet the address tDgNaZiVC1gmP3fuGds6f4xmmU7VPCa111j (btc 1KMt288Qjx5Vv2fmxrHyPPWFLKa1A49uHQ) can sign all endorsements; this is a way to redistribute for testing *)
	  let ee = hashval_big_int (hashval_of_bitcoin_message ("fakeendorsement " ^ (addr_pfgaddrstr (be160_p2pkh_addr beta)) ^ " (" ^ (addr_pfgaddrstr alpha) ^ ")")) in
	  if (-916116462l, -1122756662l, 602820575l, 669938289l, 1956032577l) = Be160.to_int32p5 alpha2 then
	    ((verify_signed_big_int ee (Some(x,y)) esg && verify_signed_big_int e (Some(w,z)) sg),None,None,[])
	  else
	    (false,None,None,[])
	else
	  (false,None,None,[])
      else
	(false,None,None,[])
  | EndP2pkhToP2shSignat(Some(x,y),c,beta,esg,scr) ->
      let (i,xs) = alpha in
      if i = 0 then (* p2pkh *)
	let xm = big_int_hashval x in
	let ym = big_int_hashval y in
	let alpha2 = hashval_be160 (if c then (if evenp y then hashpubkeyc 2 xm else hashpubkeyc 3 xm) else hashpubkey xm ym) in
	let ee = hashval_big_int (hashval_of_bitcoin_message ("endorse " ^ (addr_pfgaddrstr (be160_p2sh_addr beta)))) in
	let ok = xs = alpha2 && verify_signed_big_int ee (Some(x,y)) esg in 
	if ok then
	  verify_p2sh2 obday pfgstxid e beta scr
	else if !Config.testnet then (* in testnet the address tQa4MMDc6DKiUcPyVF6Xe7XASdXAJRGMYeB (btc 1LvNDhCXmiWwQ3yeukjMLZYgW7HT9wCMru) can sign all endorsements; this is a way to redistribute for testing *)
	  let ee = hashval_big_int (hashval_of_bitcoin_message ("fakeendorsement " ^ (addr_pfgaddrstr (be160_p2pkh_addr beta)) ^ " (" ^ (addr_pfgaddrstr alpha) ^ ")")) in
	  if ((-629004799l, -157083340l, -103691444l, 1197709645l, 224718539l) = Be160.to_int32p5 alpha2
		&&
	      verify_signed_big_int ee (Some(x,y)) esg)
	  then
	    verify_p2sh obday e beta scr
	  else
	    (false,None,None,[])
	else
	  (false,None,None,[])
      else
	(false,None,None,[])
  | EndP2shToP2pkhSignat(Some(w,z),d,escr,sg) ->
      let (i,xs) = alpha in
      if i = 1 then (* p2sh *)
	let wm = big_int_hashval w in
	let zm = big_int_hashval z in
	let beta = hashval_be160 (if d then (if evenp z then hashpubkeyc 2 wm else hashpubkeyc 3 wm) else hashpubkey wm zm) in
	let ee = hashval_big_int (hashval_of_bitcoin_message ("endorse " ^ (addr_pfgaddrstr (be160_p2pkh_addr beta)))) in
	if verify_signed_big_int e (Some(w,z)) sg then
	  verify_p2sh obday ee xs escr
	else
	  (false,None,None,[])
      else
	(false,None,None,[])
  | EndP2shToP2shSignat(beta,escr,scr) ->
      let (i,xs) = alpha in
      if i = 1 then (* p2sh *)
	let ee = hashval_big_int (hashval_of_bitcoin_message ("endorse " ^ (addr_pfgaddrstr (be160_p2sh_addr beta)))) in
	let (b,mbh,mtm,provenl1) = verify_p2sh obday ee xs escr in
	if b then
	  let (b,mbh2,mtm2,provenl2) = verify_p2sh2 obday pfgstxid e beta scr in
	  if b then
	    (true,opmax mbh mbh2,opmax mtm mtm2,provenl1 @ provenl2)
	  else
	    (false,None,None,[])
	else
	  (false,None,None,[])
      else
	(false,None,None,[])
  | _ -> (false,None,None,[])
	
let seo_gensignat o gsg c =
  match gsg with
  | P2pkhSignat(p,b,sg) -> (* 00 *)
      let c = o 2 0 c in
      seo_prod3 seo_pt seo_bool seo_signat o (p,b,sg) c
  | P2shSignat(scr) -> (* 01 *)
      let c = o 2 1 c in
      seo_list seo_int8 o scr c
  | EndP2pkhToP2pkhSignat(p,b,q,d,esg,sg) -> (* 10 0 *)
      let c = o 3 2 c in
      seo_prod6 seo_pt seo_bool seo_pt seo_bool seo_signat seo_signat o (p,b,q,d,esg,sg) c
  | EndP2pkhToP2shSignat(p,b,beta,esg,scr) -> (* 10 1 *)
      let c = o 3 6 c in
      seo_prod5 seo_pt seo_bool seo_be160 seo_signat (seo_list seo_int8) o (p,b,beta,esg,scr) c
  | EndP2shToP2pkhSignat(q,d,escr,sg) -> (* 11 0 *)
      let c = o 3 3 c in
      seo_prod4 seo_pt seo_bool (seo_list seo_int8) seo_signat o (q,d,escr,sg) c
  | EndP2shToP2shSignat(beta,escr,scr) -> (* 11 1 *)
      let c = o 3 7 c in
      seo_prod3 seo_be160 (seo_list seo_int8) (seo_list seo_int8) o (beta,escr,scr) c
	
let sei_gensignat i c =
  let (x,c) = i 2 c in
  if x = 0 then
    let ((p,b,sg),c) = sei_prod3 sei_pt sei_bool sei_signat i c in
    (P2pkhSignat(p,b,sg),c)
  else if x = 1 then
    let (scr,c) = sei_list sei_int8 i c in
    (P2shSignat(scr),c)
  else if x = 2 then
    let (x,c) = i 1 c in
    if x = 0 then
      let ((p,b,q,d,esg,sg),c) = sei_prod6 sei_pt sei_bool sei_pt sei_bool sei_signat sei_signat i c in
      (EndP2pkhToP2pkhSignat(p,b,q,d,esg,sg),c)
    else
      let ((p,b,beta,esg,scr),c) = sei_prod5 sei_pt sei_bool sei_be160 sei_signat (sei_list sei_int8) i c in
      (EndP2pkhToP2shSignat(p,b,beta,esg,scr),c)
  else
    let (x,c) = i 1 c in
    if x = 0 then
      let ((q,d,escr,sg),c) = sei_prod4 sei_pt sei_bool (sei_list sei_int8) sei_signat i c in
      (EndP2shToP2pkhSignat(q,d,escr,sg),c)
    else
      let ((beta,escr,scr),c) = sei_prod3 sei_be160 (sei_list sei_int8) (sei_list sei_int8) i c in
      (EndP2shToP2shSignat(beta,escr,scr),c)
	
let json_pt p =
  match p with
  | None -> JsonStr("infpt")
  | Some(x,y) -> JsonObj([("type",JsonStr("pt"));("x",JsonStr(hexstring_of_big_int x 64));("y",JsonStr(hexstring_of_big_int y 64))])
	
let json_signat sg =
  let (r,s) = sg in
  JsonObj([("type",JsonStr("ecdsasig"));("r",JsonStr(hexstring_of_big_int r 64));("s",JsonStr(hexstring_of_big_int s 64))])
    
let json_gensignat gs =
  match gs with
  | P2pkhSignat(p,c,sg) ->
      JsonObj([("type",JsonStr("gensignat"));("gensignattype",JsonStr("p2pkh"));("pubkey",json_pt p);("compressed",JsonBool(c));("signat",json_signat(sg))])
  | P2shSignat(scr) ->
      JsonObj([("type",JsonStr("gensignat"));("gensignattype",JsonStr("p2sh"));("script",JsonArr(List.map (fun x -> JsonNum(string_of_int x)) scr))])
  | EndP2pkhToP2pkhSignat(p,c,q,d,esg,sg) ->
      JsonObj([("type",JsonStr("gensignat"));("gensignattype",JsonStr("endp2pkhtop2pkh"));
	       ("pubkey1",json_pt p);("compressed1",JsonBool(c));
	       ("pubkey2",json_pt q);("compressed1",JsonBool(d));
	       ("endorsementsignat",json_signat(esg));
	       ("signat",json_signat(sg))])
  | EndP2pkhToP2shSignat(p,c,beta,esg,scr) ->
      JsonObj([("type",JsonStr("gensignat"));("gensignattype",JsonStr("endp2pkhtop2sh"));
	       ("pubkey1",json_pt p);("compressed1",JsonBool(c));
	       ("p2sh",JsonStr(addr_pfgaddrstr (be160_p2sh_addr beta)));
	       ("script",JsonArr(List.map (fun x -> JsonNum(string_of_int x)) scr))])
  | EndP2shToP2pkhSignat(q,d,escr,sg) ->
      JsonObj([("type",JsonStr("gensignat"));("gensignattype",JsonStr("endp2shtop2pkh"));
	       ("pubkey2",json_pt q);("compressed1",JsonBool(d));
	       ("endorsementscript",JsonArr(List.map (fun x -> JsonNum(string_of_int x)) escr));
	       ("signat",json_signat(sg))])
  | EndP2shToP2shSignat(beta,escr,scr) ->
      JsonObj([("type",JsonStr("gensignat"));("gensignattype",JsonStr("endp2shtop2sh"));
	       ("p2sh",JsonStr(addr_pfgaddrstr (be160_p2sh_addr beta)));
	       ("endorsementscript",JsonArr(List.map (fun x -> JsonNum(string_of_int x)) escr));
	       ("script",JsonArr(List.map (fun x -> JsonNum(string_of_int x)) scr))])
	
let createatomicswapcsv ltxid alpha beta tmlock =
  let scrl =
    [0x63; (** OP_IF **)
     0x01; 0x03; (** PUSH 3 onto the stack, requiring 3 ltc confirmations **)
     0x20] (** PUSH 32 bytes (the ltc tx id) onto the stack **)
    @ be256_bytelist ltxid
    @ [0xb3; (** OP_LTX_VERIFY to ensure the ltc tx has at least 3 confirmations **)
       0x76; (** OP_DUP -- duplicate the given pubkey for alpha **)
       0xa9; (** OP_HASH160 -- hash the given pubkey **)
       0x14] (** PUSH 20 bytes (should be hash of pubkey for alpha) onto the stack **)
    @ be160_bytelist alpha
    @ [0x67; (** OP_ELSE **)
       0x04] (** PUSH 4 bytes onto the stack (lock time) **)
    @ blnum_le (big_int_of_int32 tmlock) 4
    @ [0xb2] (** CSV to check if this branch is valid yet **)
    @ [0x75; (** OP_DROP, drop the locktime from the stack **)
       0x76; (** OP_DUP -- duplicate the given pubkey for beta **)
       0xa9; (** OP_HASH160 -- hash the given pubkey **)
       0x14] (** PUSH 20 bytes (should be hash of pubkey for beta) onto the stack **)
    @ be160_bytelist beta
    @ [0x68; (** OP_ENDIF **)
       0x88; (** OP_EQUALVERIFY -- to ensure the given pubkey hashes to the right value **)
       0xac] (** OP_CHECKSIG **)
  in
  let gamma = hash160_bytelist scrl in
  (gamma,scrl)

let bountyfundveto alpha =
  let scrl =
    [0x63; (** OP_IF **)
     0x76; (** OP_DUP -- duplicate the given pubkey for alpha **)
     0xa9; (** OP_HASH160 -- hash the given pubkey **)
     0x14] (** PUSH 20 bytes (should be hash of pubkey for alpha) onto the stack **)
    @ be160_bytelist alpha
    @ [0x67; (** OP_ELSE **)
       0x04] (** PUSH 4 bytes onto the stack (lock time) **)
    @ blnum_le z48 4
    @ [0xb2] (** CSV to check if this branch is valid yet **)
    @ [0x75; (** OP_DROP, drop the locktime from the stack **)
       0x76; (** OP_DUP -- duplicate the given pubkey for beta **)
       0xa9; (** OP_HASH160 -- hash the given pubkey **)
       0x14] (** PUSH 20 bytes (should be hash of pubkey for beta) onto the stack **)
    @ be160_bytelist bountyfund
    @ [0x68; (** OP_ENDIF **)
       0x88; (** OP_EQUALVERIFY -- to ensure the given pubkey hashes to the right value **)
       0xac] (** OP_CHECKSIG **)
  in
  let gamma = hash160_bytelist scrl in
  (gamma,scrl)
