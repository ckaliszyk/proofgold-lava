(* Copyright (c) 2021 The Proofgold Core developers *)
(* Copyright (c) 2020 The Proofgold developers *)
(* Copyright (c) 2016 The Qeditas developers *)
(* Copyright (c) 2017-2019 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

(* A reference to the exit function, which can be changed by other modules. *)
let exitfn : (int -> unit) ref = ref (fun n -> exit n);;

(* A reference to the log file, initialized to the standard error channel. *)
let log : out_channel ref = ref stderr

(* Opens the log file for writing. *)
let openlog () =
  log := open_out_gen [Open_wronly;Open_creat;Open_append] 0o600 (!Config.datadir ^ (if !Config.testnet then "/testnet/debug.log" else "/debug.log"))

(* Closes the log file. *)
let closelog () =
  close_out_noerr !log

let safe_log_string x =
  let m = Unix.localtime(Unix.time()) in
  let oc = open_out (!Config.datadir ^ (if !Config.testnet then "/testnet/error.log" else "/error.log"))
  Printf.fprintf oc "[%d-%d-%d %d:%02d:%02d %02d] %s" (1900+m.tm_year) (1+m.tm_mon) (m.tm_mday)  (m.tm_hour) (m.tm_min) (m.tm_sec) (Thread.id (Thread.self ())) x;
  close_out oc;;

(* Logs a string to the log file, with a timestamp. *)
let log_string x =
  try
    let m=Unix.localtime(Unix.time()) in
    Printf.fprintf !log "[%d-%d-%d %d:%02d:%02d %02d] %s%!" (1900+m.tm_year) (1+m.tm_mon) (m.tm_mday)  (m.tm_hour) (m.tm_min) (m.tm_sec) (Thread.id (Thread.self ())) x;
  with
    _ -> safe_log_string x;;
(*  if pos_out !log > 100000000 then (*** prevent debug.log from becoming more than 100MB ***)
    begin
      closelog ();
      let prevlog = (!Config.datadir ^ (if !Config.testnet then "/testnet/debug.log.1" else "/debug.log.1")) in
      if Sys.file_exists prevlog then (*** if the previous log file has not been moved or deleted, then stop the node; this is to prevent the log files from piling up ***)
	!exitfn 9
      else
	begin
	  Sys.rename (!Config.datadir ^ (if !Config.testnet then "/testnet/debug.log" else "/debug.log")) prevlog;
	  openlog()
	end
    end
*)

(* Calculates the era of a block, based on its height. *)
(***
 era ranges from 0 to 43
 era 0 from block 0 to block 209999
 era n from block 210000*n to block 210000*(n+1) - 1
 era 43 from 9030000 on
 with a 1 hour block time each era should last roughly 24 years,
 reaching the final era after 1030 years
 ***)
let era blkh =
  if blkh < 9030000L then
    let blki = Int64.to_int blkh in
    (blki / 210000)
  else
    43

(* Calculates the maximum block size for a given block height. *)
(* the max block size is 500K during era 0 and doubles with each era, with a final max block size of 512M. *)
let maxblockdeltasize blkh =
  5000000 lsl (era blkh)

(* A flag indicating whether the random number generator has been initialized. *)
let random_initialized : bool ref = ref false;;

(* Converts a hex character to its corresponding integer value. *)
let hexchar_inv x =
  match x with
  | '0' -> 0
  | '1' -> 1
  | '2' -> 2
  | '3' -> 3
  | '4' -> 4
  | '5' -> 5
  | '6' -> 6
  | '7' -> 7
  | '8' -> 8
  | '9' -> 9
  | 'A' -> 10
  | 'B' -> 11
  | 'C' -> 12
  | 'D' -> 13
  | 'E' -> 14
  | 'F' -> 15
  | 'a' -> 10
  | 'b' -> 11
  | 'c' -> 12
  | 'd' -> 13
  | 'e' -> 14
  | 'f' -> 15
  | _ -> raise (Failure("not a hexit: " ^ (string_of_int (Char.code x))))

(* Initializes the random number generator with a seed. *)
let initialize_random_seed () =
  match !Config.randomseed with
  | Some(r) ->
      if not (String.length r = 64) then raise (Failure "bad randomseed given, should be 32 bytes as 64 hex chars");
      let a = Array.make 32 0 in
      for i = 0 to 31 do
	a.(i) <- 16 * hexchar_inv (r.[2*i]) + hexchar_inv (r.[2*i+1])
      done;
      Random.full_init a;
      random_initialized := true
  | None ->
      if Sys.file_exists "/dev/random" then
	let r = open_in_bin "/dev/random" in
	let a = Array.make 32 0 in
	if not !Config.daemon then (Printf.printf "Computing random seed, this may take a while.\n"; flush stdout);
	for i = 0 to 31 do
	  a.(i) <- input_byte r
	done;
	close_in_noerr r;
	Random.full_init a;
	random_initialized := true
      else
	begin
	  raise (Failure("Since /dev/random is not on your system (Windows?), you must give some random seed with -randomseed\nMake sure the seed is really random or serious problems could result.\n"))
	end

(* Generates a random bit. *)
let rand_bit () =
  if not !random_initialized then initialize_random_seed();
  Random.bool()

(* Generates a random 32-bit integer. *)
let rand_int32 () =
  if not !random_initialized then initialize_random_seed();
  Int32.logor (Int32.shift_left (Random.int32 65536l) 16) (Random.int32 65536l)

(* Generates a random 64-bit integer. *)
let rand_int64 () =
  if not !random_initialized then initialize_random_seed();
  Int64.logor (Int64.shift_left (Random.int64 4294967296L) 32) (Random.int64 4294967296L)

(* Constants for hard fork heights. *)
let late2020hardforkheight1 = 5000L
let late2020hardforkheight2 = 15000L
let lockingfixsoftforkheight = 13500L

(* Decodes a base64-encoded string. *)
(*** Following code in util.cpp in bitcoin ***)
let decode64table = [|
        -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
        -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
        -1; -1; -1; 62; -1; -1; -1; 63; 52; 53; 54; 55; 56; 57; 58; 59; 60; 61; -1; -1;
        -1; -1; -1; -1; -1;  0;  1;  2;  3;  4;  5;  6;  7;  8;  9; 10; 11; 12; 13; 14;
        15; 16; 17; 18; 19; 20; 21; 22; 23; 24; 25; -1; -1; -1; -1; -1; -1; 26; 27; 28;
        29; 30; 31; 32; 33; 34; 35; 36; 37; 38; 39; 40; 41; 42; 43; 44; 45; 46; 47; 48;
        49; 50; 51; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
        -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
        -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
        -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
        -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
        -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
        -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1
 |];;

(* Encodes a base64-encoded string. *)
let encode64table = [|'A'; 'B'; 'C'; 'D'; 'E'; 'F'; 'G'; 'H'; 'I'; 'J'; 'K'; 'L'; 'M'; 'N'; 'O';
  'P'; 'Q'; 'R'; 'S'; 'T'; 'U'; 'V'; 'W'; 'X'; 'Y'; 'Z'; 'a'; 'b'; 'c'; 'd';
  'e'; 'f'; 'g'; 'h'; 'i'; 'j'; 'k'; 'l'; 'm'; 'n'; 'o'; 'p'; 'q'; 'r'; 's';
  't'; 'u'; 'v'; 'w'; 'x'; 'y'; 'z'; '0'; '1'; '2'; '3'; '4'; '5'; '6'; '7';
  '8'; '9'; '+'; '/'|];;

(* Decodes a base64-encoded string, handling padding. *)
let base64decode_end s l i mode lft =
  if mode = 0 then (*** something extra is in the string, but shouldn't be. ***)
    raise (Failure("not a proper base64 string 0"))
  else if mode = 1 then (*** 4n+1 base64 character processed: according to util.ccp, this is impossible ***)
    raise (Failure("not a proper base64 string 1"))
  else if mode = 2 then (*** 4n+2 base64 characters processed: according to util.cpp, require '==' ***)
    if l = i + 2 && lft = 0 && s.[i] = '=' && s.[i+1] = '=' then
      []
    else
      raise (Failure("not a proper base64 string 2"))
  else if mode = 3 then (*** 4n+3 base64 characters processed: according to util.cpp, require '=' ***)
    if l = i + 1 && lft = 0 && s.[i] = '=' then
      []
    else
      raise (Failure("not a proper base64 string 3"))
  else (*** should never happen ***)
    raise (Failure("not a proper base64 string"))

(* Decodes a base64-encoded string, accumulating the result in a list. *)
let rec base64decode_a s l i mode lft =
  if i < l then
    let dec = decode64table.(Char.code(s.[i])) in
    if dec = -1 then
      base64decode_end s l i mode lft
    else
      if mode = 0 then
	base64decode_a s l (i+1) 1 dec
      else if mode = 1 then
	((lft lsl 2) lor (dec lsr 4))::(base64decode_a s l (i+1) 2 (dec land 15))
      else if mode = 2 then
	((lft lsl 4) lor (dec lsr 2))::(base64decode_a s l (i+1) 3 (dec land 3))
      else
	((lft lsl 6) lor dec)::(base64decode_a s l (i+1) 0 0)
  else if mode = 0 then
    []
  else
    raise (Failure("base64 string ended in wrong mode"))

(* Decodes a base64-encoded string. *)
let base64decode s =
  base64decode_a s (String.length s) 0 0 0

(* Converts a list of bytes to a list of octets. *)
let rec bytelist_to_octetlist bl =
  match bl with
  | (by1::by2::by3::br) ->
      let (ol,pad) = bytelist_to_octetlist br in
      (by1 lsr 2::(((by1 land 3) lsl 4) lor (by2 lsr 4))::(((by2 land 15) lsl 2) lor (by3 lsr 6))::by3 land 63::ol,pad)
  | [by1;by2] ->
      ([by1 lsr 2;(((by1 land 3) lsl 4) lor (by2 lsr 4));((by2 land 15) lsl 2)],1)
  | [by1] ->
      ([by1 lsr 2;(by1 land 3) lsl 4],2)
  | [] -> ([],0)

(* Encodes a list of bytes as a base64-encoded string. *)
let base64encode bl =
  let (ol,pad) = bytelist_to_octetlist bl in
  let bu = Buffer.create 30 in
  List.iter (fun i -> Buffer.add_char bu (encode64table.(i))) ol;
  for i = 1 to pad do Buffer.add_char bu '=' done;
  Buffer.contents bu

(* A reference to the block height at which the Proofgold chain forks from the Litecoin chain. *)
let forward_from_ltc_block = ref None
