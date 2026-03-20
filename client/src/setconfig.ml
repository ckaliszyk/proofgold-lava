(* Copyright (c) 2021-2025 The Proofgold Lava developers *)
(* Copyright (c) 2020 The Proofgold developers *)
(* Copyright (c) 2015 The Qeditas developers *)
(* Copyright (c) 2017-2018 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

open Hash
open Cryptocurr

let stringconfigvars = [
("lastcheckpoint",fun x -> Config.lastcheckpoint := x);
("prompt",fun x -> Config.prompt := x);
("rpcuser",fun x -> Config.rpcuser := x);
("rpcpass",fun x -> Config.rpcpass := x);
("ltcrpcip",fun x -> Config.ltcrpcip := x);
("ltcrpcuser",fun x -> Config.ltcrpcuser := x);
("ltcrpcpass",fun x -> Config.ltcrpcpass := x);
("ltcrpcip2",fun x -> Config.ltcrpcip2 := x);
("ltcrpcuser2",fun x -> Config.ltcrpcuser2 := x);
("ltcrpcpass2",fun x -> Config.ltcrpcpass2 := x);
("curl",fun x -> Config.curl := x);
("bootstrapurl",fun x -> Config.bootstrapurl := x)
];;
let boolconfigvars = [
("genesis",fun x -> Config.genesis := x);
("explorer",fun x -> Config.explorer := x);
("offline",fun x -> Config.offline := x);
("ltcoffline",fun x -> Config.ltcoffline := x);
("daemon",fun x -> Config.daemon := x);
("staking",fun x -> Config.staking := x);
("swapping",fun x -> Config.swapping := x);
("ipv6",fun x -> Config.ipv6 := x);
("extraindex",fun x -> Config.extraindex := x);
("generatenewrewardaddresses",fun x -> Config.generatenewrewardaddresses := x);
("stakewithrewards",fun x -> Config.stakewithrewards := x);
("offlinestakerewardsdest",fun x -> Config.offlinestakerewardsdest := x);
("independentbootstrap",fun x -> Config.independentbootstrap := x);
("fullnode",fun x -> Config.fullnode := x);
("ltcrpcavoidcurl",fun x -> Config.ltcrpcavoidcurl := x)
];;
let intconfigvars = [
("waitforblock",fun x -> Config.waitforblock := x);
("max_conn_pow_tries",fun x -> Config.max_conn_pow_tries := x);
("min_conn_pow_target",fun x -> Config.min_conn_pow_target := Int32.of_int x);
("min_conns_pow",fun x -> Config.min_conns_pow := x);
("gc_space_overhead",fun x -> Config.gc_space_overhead := x);
("gc_stack_limit",fun x -> Config.gc_stack_limit := x);
("db_max_in_cache",fun x -> Config.db_max_in_cache := x);
("port",fun x -> Config.port := x);
("onionlocalport",fun x -> Config.onionlocalport := x);
("onionremoteport",fun x -> Config.onionremoteport := x);
("socksport",fun x -> Config.socksport := x);
("rpcport",fun x -> Config.rpcport := x);
("ltcrpcport",fun x -> Config.ltcrpcport := x);
("ltcrpcport2",fun x -> Config.ltcrpcport2 := x);
("ltcversion",fun x -> Config.ltcversion := x);
("ltcsubversion",fun x -> Config.ltcsubversion := x);
("maxconns",fun x -> Config.maxconns := x);
("minconnstostake",fun x -> Config.minconnstostake := x)
];;
let int64configvars = [
("maxburn",fun x -> Config.maxburn := x);
("ltctxfee",fun x -> Config.ltctxfee := x);
("minltctxfee",fun x -> Config.minltctxfee := x);
("reward_lock_relative",fun x -> Config.reward_lock_relative := Some(x));
("reward_lock_absolute",fun x -> Config.reward_lock_absolute := Some(x))
];;
let atomsofbarsconfigvars = [
("minrelayfee",fun x -> Config.minrelayfee := x);
("defaulttxfee",fun x -> Config.defaulttxfee := x)
];;
let stringoptionconfigvars = [
("ltcwallet",fun x -> Config.ltcwallet := x);
("ltcwallet2",fun x -> Config.ltcwallet2 := x);
("proxyip",fun x -> Config.proxyip := x);
("ip",fun x -> Config.ip := x);
("reallistenip",fun x -> Config.reallistenip := x);
("onion",fun x -> Config.onion := x);
("ltcrpconion",fun x -> Config.ltcrpconion := x);
("ltcrpconion2",fun x -> Config.ltcrpconion2 := x);
("randomseed",fun x -> Config.randomseed := x);
("offlinestakerewardslock",fun x -> Config.offlinestakerewardslock := x);
];;
let intoptionconfigvars = [
("socks",fun x -> Config.socks := x)
];;
let stringlistconfigvars = [
    ("ltcaddress",fun x ->
                  if List.mem x !Config.ltctradeaddresses then
                    Printf.printf "WARNING: %s is already an ltc trade address, so not adding as an address for staking/burning.\n" x
                  else
                    Config.ltcaddresses := x::!Config.ltcaddresses);
    ("ltctradeaddress",fun x ->
                       if String.length x > 30 && x.[0] = 'l' then
                         if List.mem x !Config.ltctradeaddresses then
                           Printf.printf "WARNING: %s is already an ltc address for staking/burning, so not adding as an address for trading.\n" x
                         else
                           Config.ltctradeaddresses := x::!Config.ltctradeaddresses
                       else
                         Printf.printf "WARNING: %s is not a bech32 address, so not using it as an ltctradeaddress" x);
    ("invalidateblock",fun x -> Config.invalidatedblocks := x::!Config.invalidatedblocks);
    ("validateblock",fun x -> Config.validatedblocks := x::!Config.validatedblocks)
];;

exception Done

let setl = ref []

let process_config_line l =
  let ll = String.length l in
  if ll > 0 && l.[0] <> '#' then
  begin
    try
      List.iter
	(fun (v,r) ->
	  let vl = String.length v in
	  if ll >= 1 + vl && String.sub l 0 (vl) = v && l.[vl] = '=' then
	    begin
	      setl := v::!setl;
	      r (String.sub l (vl+1) (ll-(vl+1)));
	      raise Done
	    end
	  )
	stringconfigvars;
      List.iter
	(fun (v,r) ->
	  let vl = String.length v in
	  if l = v then
	    begin
	      setl := v::!setl;
	      r true;
	      raise Done
	    end
	  else if ll > 1 + vl && String.sub l 0 (vl) = v && l.[vl] = '=' then
	    let s = String.sub l (vl+1) (ll-(vl+1)) in
	    begin
	      setl := v::!setl;
	      r (s = "1" || s = "t" || s = "true");
	      raise Done
	    end
	  )
	boolconfigvars;
      List.iter
	(fun (v,r) ->
	  let vl = String.length v in
	  if ll > 1 + vl && String.sub l 0 (vl) = v && l.[vl] = '=' then
	    begin
	      setl := v::!setl;
	      r (int_of_string (String.sub l (vl+1) (ll-(vl+1))));
	      raise Done
	    end
	  )
	intconfigvars;
      List.iter
	(fun (v,r) ->
	  let vl = String.length v in
	  if ll > 1 + vl && String.sub l 0 (vl) = v && l.[vl] = '=' then
	    begin
	      setl := v::!setl;
	      r (Int64.of_string (String.sub l (vl+1) (ll-(vl+1))));
	      raise Done
	    end
	  )
	int64configvars;
      List.iter
	(fun (v,r) ->
	  let vl = String.length v in
	  if ll > 1 + vl && String.sub l 0 (vl) = v && l.[vl] = '=' then
	    begin
	      setl := v::!setl;
	      r (atoms_of_bars (String.sub l (vl+1) (ll-(vl+1))));
	      raise Done
	    end
	  )
	atomsofbarsconfigvars;
      List.iter
	(fun (v,r) ->
	  let vl = String.length v in
	  if ll > 1 + vl && String.sub l 0 (vl) = v && l.[vl] = '=' then
	    begin
	      setl := v::!setl;
	      r (Some(String.sub l (vl+1) (ll-(vl+1))));
	      raise Done
	    end
	  )
	stringoptionconfigvars;
      List.iter
	(fun (v,r) ->
	  let vl = String.length v in
	  if ll > 1 + vl && String.sub l 0 (vl) = v && l.[vl] = '=' then
	    begin
	      setl := v::!setl;
	      r (Some(int_of_string (String.sub l (vl+1) (ll-(vl+1)))));
	      raise Done
	    end
	  )
	intoptionconfigvars;
      List.iter
	(fun (v,r) ->
	  let vl = String.length v in
	  if ll > 1 + vl && String.sub l 0 (vl) = v && l.[vl] = '=' then
	    begin
	      setl := v::!setl;
	      r (String.sub l (vl+1) (ll-(vl+1)));
	      raise Done
	    end
	  )
	stringlistconfigvars;
      raise Not_found
    with Done -> ()
  end

let datadir () = if !Config.testnet then (Filename.concat !Config.datadir "testnet") else !Config.datadir

let process_config_file () =
  let fn = Filename.concat (datadir()) "proofgold.conf" in
  if Sys.file_exists fn then
    begin
      let ch = open_in fn in
      try
	while true do
	  let l = input_line ch in
	  try
	    if String.length l > 0 && not (l.[0] = '%') then
	      process_config_line l
	  with Not_found ->
	    Printf.printf "Do not understand %s in proofgold.conf; skipping\n" l
	done
      with End_of_file -> close_in_noerr ch
    end
  else
    Printf.printf "No proofgold.conf file found. Using default configuration.\n";;

let datadir_from_command_line () =
  let a = Array.length Sys.argv in
  for i = 1 to a-1 do
    let arg = Sys.argv.(i) in
    try
      if String.length arg > 9 && String.sub arg 0 9 = "-datadir=" then
	Config.datadir := String.sub arg 9 (String.length arg - 9);
      if arg = "-testnet" || arg = "-testnet=1" then (*** if testnet, then change some default values ***)
        begin
          Config.testnet := true;
          if not (List.mem "port" !setl) then Config.port := 20804;
        end
    with Not_found -> ()
  done;;

exception CheckLedger of int;;
exception BuildExtraIndex of int;;
exception NetLogReport of int;;

let recent_ltc_blocks = ref None;;

let snapshot_dir = ref None;;
let snapshot_headers = ref [];;
let snapshot_blocks = ref [];;
let snapshot_ledgerroots = ref [];;
let snapshot_full = ref true;;
let snapshot_addresses = ref [];;
let snapshot_shards = ref None;;
let check_ledger = ref None;;
let build_extraindex = ref None;;
let netlogreport = ref None;;

let process_config_args () =
  let a = Array.length Sys.argv in
  try
    for i = 1 to a-1 do
      let arg = Sys.argv.(i) in
      let vl = String.length arg in
      if vl > 17 && String.sub arg 0 17 = "-recentltcblocks=" then
	recent_ltc_blocks := Some(String.sub arg 17 (vl - 17))
      else if vl > 21 && String.sub arg 0 21 = "-forwardfromltcblock=" then
	Utils.forward_from_ltc_block := Some(String.sub arg 21 (vl - 21))
      else if arg = "-checkledger" then
	raise (CheckLedger(i))
      else if arg = "-buildextraindex" then
	raise (BuildExtraIndex(i))
      else if arg = "-netlogreport" then
	raise (NetLogReport(i))
      else if String.length arg > 1 && arg.[0] = '-' then
	try
	  process_config_line (String.sub arg 1 ((String.length arg) - 1))
	with Not_found -> ()
    done
  with
  | CheckLedger(i) ->
      if not (i = a-2) then
	begin
	  Printf.printf "Expected -checkledger <ledgerroot>\n";
	  exit 1
	end;
      check_ledger := Some(hexstring_hashval Sys.argv.(i+1))
  | BuildExtraIndex(i) ->
      if not (i = a-2) then
	begin
	  Printf.printf "Expected -buildextraindex <ledgerroot>\n";
	  exit 1
	end;
      build_extraindex := Some(hexstring_hashval Sys.argv.(i+1))
  | NetLogReport(i) -> (*** proofgold is being started only to generate a readable report of network activity from reclog* files and sentlog file ***)
      let fl = ref [] in
      for j = a-1 downto i+1 do
	fl := Sys.argv.(j) :: !fl
      done;
      netlogreport := Some(!fl)
      
