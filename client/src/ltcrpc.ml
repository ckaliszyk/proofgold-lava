(* Copyright (c) 2021-2025 The Proofgold Lava developers *)
(* Copyright (c) 2021 The Proofgold Core developers *)
(* Copyright (c) 2020 The Proofgold developers *)
(* Copyright (c) 2017-2019 The Dalilcoin developers *)
(* Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php. *)

open Ser
open Hashaux
open Hash
open Sha256
open Json
open Net
open Db
open Cryptocurr

let ltcdust = 2940L

let knownbootstrapurl : (string,unit) Hashtbl.t = Hashtbl.create 10
let ignorebootstrapurl : (string,unit) Hashtbl.t = Hashtbl.create 10
let bootstrapurls : string list ref = ref []
let ltcrpcauthstr : string option ref = ref None
let ltcrpcauthstr2 : string option ref = ref None

let ltcrpcauth () =
  match !ltcrpcauthstr with
  | Some(s) -> s
  | None ->
     let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
     let s = Utils.base64encode (string_bytelist userpass) in
     ltcrpcauthstr := Some(s);
     s

let ltcrpcauth2 () =
  match !ltcrpcauthstr2 with
  | Some(s) -> s
  | None ->
     let userpass = !Config.ltcrpcuser2 ^ ":" ^ !Config.ltcrpcpass2 in
     let s = Utils.base64encode (string_bytelist userpass) in
     ltcrpcauthstr2 := Some(s);
     s

let ltcrpc_connect () =
  match !Config.ltcrpconion with
  | Some(onionaddr) ->
     begin
       let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
       try
         Unix.connect s (Unix.ADDR_INET(Unix.inet_addr_loopback, !Config.socksport));
         let sin = Unix.in_channel_of_descr s in
         let sout = Unix.out_channel_of_descr s in
         set_binary_mode_in sin true;
         set_binary_mode_out sout true;
         output_byte sout 4;
         output_byte sout 1;
         (** port, big endian **)
         output_byte sout ((!Config.ltcrpcport asr 8) land 255);
         output_byte sout (!Config.ltcrpcport land 255);
         (** fake ip for socks4a **)
         output_byte sout 0;
         output_byte sout 0;
         output_byte sout 0;
         output_byte sout 1;
         output_byte sout 0; (** empty string **)
         (** onion addr **)
         for i = 0 to String.length onionaddr - 1 do
           output_byte sout (Char.code onionaddr.[i])
         done;
         output_byte sout 0; (** terminate string **)
         flush sout;
         try
           let by = input_byte sin in
           if not (by = 0) then raise (Failure "server did not give initial null byte");
           let by = input_byte sin in
           if by = 0x5b then raise (Failure "request rejected or failed");
           if by = 0x5c then raise (Failure "request failed because client is not running identd (or not reachable from the server)");
           if by = 0x5d then raise (Failure "request failed because client's identd could not confirm the user ID string in the request");
           if not (by = 0x5a) then raise (Failure "bad status byte from server");
           let rport1 = input_byte sin in
           let rport0 = input_byte sin in
           let rport = rport1 * 256 + rport0 in
           let _ (* ip0 *) = input_byte sin in
           let _ (* ip1 *) = input_byte sin in
           let _ (* ip2 *) = input_byte sin in
           let _ (* ip3 *) = input_byte sin in
           Printf.fprintf sout "POST /%s HTTP/1.1\n" (match !Config.ltcwallet with None -> "" | Some(w) -> Printf.sprintf "wallet/%s" w);
           Printf.fprintf sout "Host: %s:%d\n" onionaddr rport;
           Printf.fprintf sout "Authorization: Basic %s\n" (ltcrpcauth());
           Printf.fprintf sout "User-Agent: Proofgold/0.2.8\n";
           Printf.fprintf sout "Accept: */*\n";
           Printf.fprintf sout "content-type: text/plain;\n";
           (s,sin,sout)
         with e ->
           Unix.close s;
           Utils.log_string (Printf.sprintf "Failed to connect to %s:%d : %s\n" onionaddr !Config.ltcrpcport (Printexc.to_string e));
           raise Exit
       with exn ->
         Unix.close s;
         raise exn         
     end
  | None ->
     let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
     try
       let ia = Unix.inet_addr_of_string !Config.ltcrpcip in
       Unix.connect s (Unix.ADDR_INET(ia, !Config.ltcrpcport));
       let sin = Unix.in_channel_of_descr s in
       let sout = Unix.out_channel_of_descr s in
       set_binary_mode_in sin true;
       set_binary_mode_out sout true;
       Printf.fprintf sout "POST /%s HTTP/1.1\n" (match !Config.ltcwallet with None -> "" | Some(w) -> Printf.sprintf "wallet/%s" w);
       Printf.fprintf sout "Host: %s:%d\n" !Config.ltcrpcip !Config.ltcrpcport;
       Printf.fprintf sout "Authorization: Basic %s\n" (ltcrpcauth());
       Printf.fprintf sout "User-Agent: Proofgold/0.2.8\n";
       Printf.fprintf sout "Accept: */*\n";
       Printf.fprintf sout "content-type: text/plain;\n";
       (s,sin,sout)
     with exn ->
           Unix.close s;
           raise exn

let ltcrpc2_connect () =
  match !Config.ltcrpconion2 with
  | Some(onionaddr) ->
     begin
       let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
       try
         Unix.connect s (Unix.ADDR_INET(Unix.inet_addr_loopback, !Config.socksport));
         let sin = Unix.in_channel_of_descr s in
         let sout = Unix.out_channel_of_descr s in
         set_binary_mode_in sin true;
         set_binary_mode_out sout true;
         output_byte sout 4;
         output_byte sout 1;
         (** port, big endian **)
         output_byte sout ((!Config.ltcrpcport2 asr 8) land 255);
         output_byte sout (!Config.ltcrpcport2 land 255);
         (** fake ip for socks4a **)
         output_byte sout 0;
         output_byte sout 0;
         output_byte sout 0;
         output_byte sout 1;
         output_byte sout 0; (** empty string **)
         (** onion addr **)
         for i = 0 to String.length onionaddr - 1 do
           output_byte sout (Char.code onionaddr.[i])
         done;
         output_byte sout 0; (** terminate string **)
         flush sout;
         try
           let by = input_byte sin in
           if not (by = 0) then raise (Failure "server did not give initial null byte");
           let by = input_byte sin in
           if by = 0x5b then raise (Failure "request rejected or failed");
           if by = 0x5c then raise (Failure "request failed because client is not running identd (or not reachable from the server)");
           if by = 0x5d then raise (Failure "request failed because client's identd could not confirm the user ID string in the request");
           if not (by = 0x5a) then raise (Failure "bad status byte from server");
           let rport1 = input_byte sin in
           let rport0 = input_byte sin in
           let rport = rport1 * 256 + rport0 in
           let _ (* ip0 *) = input_byte sin in
           let _ (* ip1 *) = input_byte sin in
           let _ (* ip2 *) = input_byte sin in
           let _ (* ip3 *) = input_byte sin in
           Printf.fprintf sout "POST /%s HTTP/1.1\n" (match !Config.ltcwallet with None -> "" | Some(w) -> Printf.sprintf "wallet/%s" w);
           Printf.fprintf sout "Host: %s:%d\n" onionaddr rport;
           Printf.fprintf sout "Authorization: Basic %s\n" (ltcrpcauth2());
           Printf.fprintf sout "User-Agent: Proofgold/0.2.8\n";
           Printf.fprintf sout "Accept: */*\n";
           Printf.fprintf sout "content-type: text/plain;\n";
           (s,sin,sout)
         with e ->
           Unix.close s;
           Utils.log_string (Printf.sprintf "Failed to connect to %s:%d : %s\n" onionaddr !Config.ltcrpcport2 (Printexc.to_string e));
           raise Exit
       with exn ->
         Unix.close s;
         raise exn         
     end
  | None ->
     let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
     try
       let ia = Unix.inet_addr_of_string !Config.ltcrpcip2 in
       Unix.connect s (Unix.ADDR_INET(ia, !Config.ltcrpcport2));
       let sin = Unix.in_channel_of_descr s in
       let sout = Unix.out_channel_of_descr s in
       set_binary_mode_in sin true;
       set_binary_mode_out sout true;
       Printf.fprintf sout "POST /%s HTTP/1.1\n" (match !Config.ltcwallet2 with None -> "" | Some(w) -> Printf.sprintf "wallet/%s" w);
       Printf.fprintf sout "Host: %s:%d\n" !Config.ltcrpcip2 !Config.ltcrpcport2;
       Printf.fprintf sout "Authorization: Basic %s\n" (ltcrpcauth2());
       Printf.fprintf sout "User-Agent: Proofgold/0.2.8\n";
       Printf.fprintf sout "Accept: */*\n";
       Printf.fprintf sout "content-type: text/plain;\n";
       (s,sin,sout)
     with exn ->
           Unix.close s;
           raise exn

let skip_to_blankline sin =
  try
    while true do
      let l = input_line sin in
      if l = "" || l = "\r" then raise Exit
    done
  with Exit -> ()

let alertcandidatetxs : string list ref = ref []

let swapcandidatetxs : string list ref = ref []
type swapbuyoffertype =
  | SimpleSwapBuyOffer of string * addr * int64 * int64

let swapbuyoffers : (hashval * float * swapbuyoffertype) list ref = ref []

let allswapbuyoffers_by_rev_time : (int64 * hashval * float * swapbuyoffertype) list ref = ref []
let allswapbuyoffers_by_forw_time : (int64 * hashval * float * swapbuyoffertype) list ref = ref []
let allswapbuyoffers_by_price : (int64 * hashval * float * swapbuyoffertype) list ref = ref []
let allswapbuyoffers_have : (hashval,unit) Hashtbl.t = Hashtbl.create 500

let allswapexec : (hashval,int64 * hashval * hashval) Hashtbl.t = Hashtbl.create 500
let allswapexec_have : (hashval,unit) Hashtbl.t = Hashtbl.create 500

let allalerts : (int64 * hashval * string) list ref = ref []
let allalerts_have : (hashval,unit) Hashtbl.t = Hashtbl.create 500

let alllisteners : (string,int64) Hashtbl.t = Hashtbl.create 500
let alllisteners_have : (hashval,unit) Hashtbl.t = Hashtbl.create 500

let ltc_insert_swap_buyoffer tm ltctxid pr sbo =
  if not (Hashtbl.mem allswapbuyoffers_have ltctxid) then
    begin
      Hashtbl.add allswapbuyoffers_have ltctxid ();
      allswapbuyoffers_by_price := List.merge (fun (_,_,p1,_) (_,_,p2,_) -> compare p2 p1) [(tm,ltctxid,pr,sbo)] !allswapbuyoffers_by_price;
      allswapbuyoffers_by_rev_time := List.merge (fun (tm1,_,_,_) (tm2,_,_,_) -> compare tm2 tm1) [(tm,ltctxid,pr,sbo)] !allswapbuyoffers_by_rev_time;
      allswapbuyoffers_by_forw_time := List.merge (fun (tm1,_,_,_) (tm2,_,_,_) -> compare tm1 tm2) [(tm,ltctxid,pr,sbo)] !allswapbuyoffers_by_forw_time
    end

let unburned_headers : (hashval,(hashval * hashval) -> unit) Hashtbl.t = Hashtbl.create 100
let unburned_deltas : (hashval,(hashval * hashval) -> unit) Hashtbl.t = Hashtbl.create 100

module DbInvalidatedBlocks = Dbmbasic (struct type t = bool let basedir = "invalidatedblocks" let seival = sei_bool seis let seoval = seo_bool seosb end)

type poburn =
  | Poburn of hashval * hashval * int64 * int64 * hashval * int32 (** ltc block hash id, ltc tx hash id, ltc block median time, number of litoshis burned, txid of firsttxid input spent, vout of first input spent **)

let hashpoburn p =
  match p with
  | Poburn(h,k,x,y,txid,vout) -> hashtag (hashpair (hashpair h k) (hashpair (hashpair (hashint64 x) (hashint64 y)) (hashtag txid vout))) 194l

let seo_poburn o p c =
  match p with
  | Poburn(h,k,x,y,txid,vout) ->
      let c = seo_hashval o h c in
      let c = seo_hashval o k c in
      let c = seo_int64 o x c in
      let c = seo_int64 o y c in
      let c = seo_hashval o txid c in
      let c = seo_int32 o vout c in
      c

let sei_poburn i c =
  let (h,c) = sei_hashval i c in
  let (k,c) = sei_hashval i c in
  let (x,c) = sei_int64 i c in
  let (y,c) = sei_int64 i c in
  let (txid,c) = sei_hashval i c in
  let (vout,c) = sei_int32 i c in
  (Poburn(h,k,x,y,txid,vout),c)

(*** mainnet ***)
let ltc_oldest_to_consider = ref (hexstring_hashval "ccca3ef9b5dcb0a01de0d776ae6d3bde0febda0b581553e768d91d1029e82cd5") (** block on June 8 2020 **)
let ltc_oldest_to_consider_time = ref 1591626833L (** median time on June 8 2020 **)
let ltc_oldest_to_consider_height = ref 1855917L (** block height on June 8 2020 **)

(*** testnet ***)
let ltctestnet () =
  ltc_oldest_to_consider := hexstring_hashval "0c1b15b7531f59417705457be47152d4278471036e4745f135c41600c9c94742";
  ltc_oldest_to_consider_time := 1591290167L;
  ltc_oldest_to_consider_height := 1494039L

let ltc_bestblock = ref zerohashval

let burntx : (hashval,string) Hashtbl.t = Hashtbl.create 100

type ltcpfgstatus = LtcPfgStatusPrev of hashval | LtcPfgStatusNew of (int64 * (hashval * hashval * hashval * int64 * int64) list) list

let ltcrpc_url () =
  match !Config.ltcrpconion with
  | Some(o) ->
      "http://" ^ o ^ ":" ^ (string_of_int !Config.ltcrpcport) ^ "/"
  | None ->
      "http://" ^ !Config.ltcrpcip ^ ":" ^ (string_of_int !Config.ltcrpcport) ^ "/"

let ltcrpc2_url () =
  match !Config.ltcrpconion2 with
  | Some(o) ->
      "http://" ^ o ^ ":" ^ (string_of_int !Config.ltcrpcport2) ^ "/"
  | None ->
      "http://" ^ !Config.ltcrpcip2 ^ ":" ^ (string_of_int !Config.ltcrpcport2) ^ "/"

let seo_ltcpfgstatus o s c =
  match s with
  | LtcPfgStatusPrev(h) ->
      let c = o 1 0 c in
      seo_hashval o h c
  | LtcPfgStatusNew(l) ->
      let c = o 1 1 c in
      seo_list (seo_prod seo_int64 (seo_list (seo_prod5 seo_hashval seo_hashval seo_hashval seo_int64 seo_int64))) o l c

let sei_ltcpfgstatus i c =
  let (x,c) = i 1 c in
  if x = 0 then
    let (h,c) = sei_hashval i c in
    (LtcPfgStatusPrev(h),c)
  else
    let (l,c) = sei_list (sei_prod sei_int64 (sei_list (sei_prod5 sei_hashval sei_hashval sei_hashval sei_int64 sei_int64))) i c in
    (LtcPfgStatusNew(l),c)

let ltcpfgstatush : (hashval,ltcpfgstatus) Hashtbl.t = Hashtbl.create 1000

module DbLtcPfgStatus = Dbmbasic (struct type t = ltcpfgstatus let basedir = "ltcpfgstatus" let seival = sei_ltcpfgstatus seis let seoval = seo_ltcpfgstatus seosb end)

(*** h is the id of an ltcblock, so it should always uniquely determine the ltcpfgstatus (all proofgold blockid burns from the past week in order). ***)
let rec ltcpfgstatus_dbget h =
  try
    let z =
      try
	Hashtbl.find ltcpfgstatush h
      with Not_found ->
	let z = DbLtcPfgStatus.dbget h in
	Hashtbl.add ltcpfgstatush h z;
	z
    in
    match z with
    | LtcPfgStatusPrev(k) ->
	ltcpfgstatus_dbget k
    | LtcPfgStatusNew(l) -> (h,l)
  with Not_found -> (!ltc_oldest_to_consider,[])

let json_assoc_string k al =
  match List.assoc k al with
  | JsonStr(x) -> x
  | _ -> raise Not_found

let json_assoc_int64 k al =
  match List.assoc k al with
  | JsonNum(x) -> Int64.of_string x
  | _ -> raise Not_found

let json_assoc_int k al =
  match List.assoc k al with
  | JsonNum(x) -> int_of_string x
  | _ -> raise Not_found

let litecoins_of_litoshis v =
  let w = Int64.div v 100000000L in
  let d = Int64.to_string (Int64.rem v 100000000L) in
  let dl = String.length d in
  let ez = ref 0 in
  begin
    try
      for i = dl-1 downto 0 do
	if d.[i] = '0' then
	  incr ez
	else
	  raise Exit
      done
    with Exit -> ()
  end;
  let b = Buffer.create 20 in
  Buffer.add_string b (Int64.to_string w);
  Buffer.add_char b '.';
  for i = 1 to 11 - dl do
    Buffer.add_char b '0'
  done;
  for i = 0 to dl - (1 + !ez) do
    Buffer.add_char b d.[i]
  done;
  Buffer.contents b

let litoshis_of_litecoins s =
  let f = ref 0L in
  let w = ref true in
  let c = ref 0L in
  let d = ref 10000000L in
  let n = String.length s in
  let i = ref 0 in
  while !i < n do
    let cc = Char.code s.[!i] in
    incr i;
    if !w then
      if cc = 46 then
	w := false
      else if cc >= 48 && cc < 58 then
	f := Int64.add (Int64.mul !f 10L) (Int64.of_int (cc-48))
      else
	raise (Failure ("cannot interpret " ^ s ^ " as a number of litecoins"))
    else
      if cc >= 48 && cc < 58 then
	begin
	  c := Int64.add !c (Int64.mul !d (Int64.of_int (cc-48)));
	  d := Int64.div !d 10L
	end
      else
	raise (Failure ("cannot interpret " ^ s ^ " as a number of litecoins"))
  done;
  Int64.add (Int64.mul !f 100000000L) !c

let json_assoc_litoshis k al =
  match List.assoc k al with
  | JsonNum(x) -> litoshis_of_litecoins x
  | _ -> raise Not_found

let ltc_getbestblockhash () =
  try
    if !Config.ltcoffline then
      begin
	Printf.printf "call getbestblockhash in ltc\n>> "; flush stdout;
	let h = read_line() in
	h
      end
    else
      begin
        let call = "{\"jsonrpc\": \"1.0\", \"id\":\"gbbh\", \"method\": \"getbestblockhash\", \"params\": [] }" in
        try
          if !Config.ltcrpcavoidcurl then
            begin
              let (s,sin,sout) = ltcrpc_connect () in
              Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
              Printf.fprintf sout "%s\n" call;
              flush sout;
              skip_to_blankline sin;
              let l = input_line sin in
              shutdown_close s;
              match parse_jsonval l with
              | (JsonObj(al),_) -> json_assoc_string "result" al
              | _ ->
                 (Utils.log_string (Printf.sprintf "problem return from ltc getbestblockhash:\n%s\n" l));
	         raise Exit (* retry using curl *)
            end
          else
            raise Exit
        with
        | Exit -> (* fall back on curl *)
           let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
           let url = ltcrpc_url() in
           let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
           let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
           let l = input_line inc in
           ignore (Unix.close_process_full (inc,outc,errc));
           match parse_jsonval l with
           | (JsonObj(al),_) -> json_assoc_string "result" al
           | _ ->
              (Utils.log_string (Printf.sprintf "problem return from ltc getbestblockhash:\n%s\n" l));
	      raise Not_found
      end
  with _ ->
    raise Not_found

let proofgold_candidate_p h =
  String.length h = 64 && h.[0] = '5' && h.[1] = '0' && h.[2] = '6' && h.[3] = '6'

let proofgold_swap_candidate_p h =
  String.length h = 64 && h.[0] = '5' && h.[1] = '0' && h.[2] = '5' && h.[3] = '3'

let proofgold_alert_candidate_p h =
  String.length h = 64 && h.[0] = '5' && h.[1] = '0' && h.[2] = '4' && h.[3] = '1'

let ltc_getblockheight h =
  try
    let l =
      if !Config.ltcoffline then
	begin
	  Printf.printf "call getblock %s in ltc\n>> " h; flush stdout;
	  read_line()
	end
      else
        begin
	  let call = "{\"jsonrpc\": \"1.0\", \"id\":\"gb\", \"method\": \"getblock\", \"params\": [\"" ^ h ^ "\"] }" in
          try
            if !Config.ltcrpcavoidcurl then
              begin
                let (s,sin,sout) = ltcrpc_connect () in
                Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                Printf.fprintf sout "%s\n" call;
                flush sout;
                skip_to_blankline sin;
                let l = input_line sin in
                shutdown_close s;
                l
              end
            else
              raise Exit
          with
          | Exit -> (* fall back on curl *)
	     let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
	     let url = ltcrpc_url() in
	     let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
	     let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
	     let l = input_line inc in
	     ignore (Unix.close_process_full (inc,outc,errc));
	     l
        end
    in
    match parse_jsonval l with
    | (JsonObj(al),_) ->
	begin
	  match List.assoc "result" al with
	  | JsonObj(bl) ->
	      begin
		let hght = json_assoc_int64 "height" bl in
                hght
	      end
	  | _ ->
	      (Utils.log_string (Printf.sprintf "problem return from ltc getblock:\n%s\n" l));
	      raise Not_found
	end
    | _ ->
	(Utils.log_string (Printf.sprintf "problem return from ltc getblock:\n%s\n" l));
	raise Not_found
  with _ ->
    raise Not_found
  
let ltc_getblock h =
  try
    let l =
      if !Config.ltcoffline then
	begin
	  Printf.printf "call getblock %s in ltc\n>> " h; flush stdout;
	  read_line()
	end
      else
        begin
	  let call = "{\"jsonrpc\": \"1.0\", \"id\":\"gb\", \"method\": \"getblock\", \"params\": [\"" ^ h ^ "\"] }" in
          try
            if !Config.ltcrpcavoidcurl then
              begin
                let (s,sin,sout) = ltcrpc_connect () in
                Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                Printf.fprintf sout "%s\n" call;
                flush sout;
                skip_to_blankline sin;
                let l = input_line sin in
                shutdown_close s;
                l
              end
            else
              raise Exit
          with Exit -> (* fall back on curl *)
	    let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
	    let url = ltcrpc_url() in
	    let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
	    let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
	    let l = input_line inc in
	    ignore (Unix.close_process_full (inc,outc,errc));
	    l
        end
    in
    match parse_jsonval l with
    | (JsonObj(al),_) ->
	begin
	  match List.assoc "result" al with
	  | JsonObj(bl) ->
	      begin
		let pbh = json_assoc_string "previousblockhash" bl in
		let nbh =
                  try
                    Some(json_assoc_string "nextblockhash" bl)
                  with Not_found -> None
                in
		let tm = json_assoc_int64 "mediantime" bl in
		let hght = json_assoc_int64 "height" bl in
		let txl = ref [] in
		match List.assoc "tx" bl with
		| JsonArr(txs) ->
		    begin
		      List.iter
			(fun jtxh ->
			  match jtxh with
			  | JsonStr(txh) when proofgold_candidate_p txh -> txl := txh::!txl
                          | JsonStr(txh) when proofgold_swap_candidate_p txh -> swapcandidatetxs := txh::!swapcandidatetxs
                          | JsonStr(txh) when proofgold_alert_candidate_p txh ->
                             alertcandidatetxs := txh::!alertcandidatetxs
			  | _ -> ())
			txs;
		      (pbh,tm,hght,!txl,nbh)
		    end
		| _ ->
		    (Utils.log_string (Printf.sprintf "problem return from ltc getblock:\n%s\n" l));
		    raise Not_found
	      end
	  | _ ->
	      (Utils.log_string (Printf.sprintf "problem return from ltc getblock:\n%s\n" l));
	      raise Not_found
	end
    | _ ->
	(Utils.log_string (Printf.sprintf "problem return from ltc getblock:\n%s\n" l));
	raise Not_found
  with _ ->
    raise Not_found

type ltcutxo =
  | LtcP2shSegwit of (string * int * string * string * string * int64)
  | LtcBech32 of (string * int * string * string * int64)

let ltc_listunspent_gen addrl =
  try
    let l =
      if !Config.ltcoffline then
	begin
	  Printf.printf "call listunspent in ltc\n>> "; flush stdout;
	  read_line()
	end
      else
        begin
	  let addrlb = Buffer.create 40 in
	  let fstaddr = ref true in
	  List.iter
	    (fun a ->
	      if !fstaddr then fstaddr := false else Buffer.add_char addrlb ',';
	      Buffer.add_char addrlb '"';
	      Buffer.add_string addrlb a;
	      Buffer.add_char addrlb '"')
            addrl;
          let call = "{\"jsonrpc\": \"1.0\", \"id\":\"lu\", \"method\": \"listunspent\", \"params\": [1,9999999,[" ^ (Buffer.contents addrlb) ^ "]] }" in
          try
            if !Config.ltcrpcavoidcurl then
              begin
                let (s,sin,sout) = ltcrpc_connect () in
                Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                Printf.fprintf sout "%s\n" call;
                flush sout;
                skip_to_blankline sin;
                let l = input_line sin in
                shutdown_close s;
                l
              end
            else
              raise Exit
          with Exit -> (* fall back on curl *)
	    let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
	    let url = ltcrpc_url() in
            let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
	    let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
	    let l = input_line inc in
	    ignore (Unix.close_process_full (inc,outc,errc));
	    l
        end
    in
    let utxol = ref [] in
    match parse_jsonval l with
    | (JsonObj(al),_) ->
	begin
	  match List.assoc "result" al with
	  | JsonArr(ul) ->
	      begin
		List.iter
		  (fun u ->
		    match u with
		    | JsonObj(bl) ->
			begin
			  try
			    let ltcaddr = json_assoc_string "address" bl in
			    if ltcaddr = "" then raise Not_found;
			    if ltcaddr.[0] = 'M' || (!Config.testnet && ltcaddr.[0] = 'Q') then (*** p2sh segwit ***)
			      let txh = json_assoc_string "txid" bl in
			      let vout = json_assoc_int "vout" bl in
			      let rs = json_assoc_string "redeemScript" bl in
			      let spk = json_assoc_string "scriptPubKey" bl in
			      let amt = json_assoc_litoshis "amount" bl in
			      utxol := LtcP2shSegwit(txh,vout,ltcaddr,rs,spk,amt)::!utxol
			    else if ltcaddr.[0] = 'l' || (!Config.testnet && ltcaddr.[0] = 't') then (*** bech32 ***)
			      let txh = json_assoc_string "txid" bl in
			      let vout = json_assoc_int "vout" bl in
			      let spk = json_assoc_string "scriptPubKey" bl in
			      let amt = json_assoc_litoshis "amount" bl in
			      utxol := LtcBech32(txh,vout,ltcaddr,spk,amt)::!utxol
			    else
			      raise Not_found
			  with Not_found ->
			    ()
			end
		    | _ -> ())
		  ul;
		!utxol
	      end
	  | _ ->
	      (Utils.log_string (Printf.sprintf "problem return from ltc listunspent:\n%s\n" l));
	      raise Not_found
	end
    | _ ->
	(Utils.log_string (Printf.sprintf "problem return from ltc listunspent:\n%s\n" l));
	raise Not_found
  with _ ->
    raise Not_found

let ltc_listunspent () = ltc_listunspent_gen !Config.ltcaddresses

let ltc2_listunspent_gen addrl =
  try
    let l =
      if !Config.ltcoffline then
	begin
	  Printf.printf "call listunspent in ltc\n>> "; flush stdout;
	  read_line()
	end
      else
        begin
	  let addrlb = Buffer.create 40 in
	  let fstaddr = ref true in
	  List.iter
	    (fun a ->
	      if !fstaddr then fstaddr := false else Buffer.add_char addrlb ',';
	      Buffer.add_char addrlb '"';
	      Buffer.add_string addrlb a;
	      Buffer.add_char addrlb '"')
            addrl;
          let call = "{\"jsonrpc\": \"1.0\", \"id\":\"lu\", \"method\": \"listunspent\", \"params\": [1,9999999,[" ^ (Buffer.contents addrlb) ^ "]] }" in
          try
            if !Config.ltcrpcavoidcurl then
              begin
                let (s,sin,sout) = ltcrpc2_connect () in
                Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                Printf.fprintf sout "%s\n" call;
                flush sout;
                skip_to_blankline sin;
                let l = input_line sin in
                shutdown_close s;
                l
              end
            else
              raise Exit
          with Exit -> (* fall back on curl *)
	    let userpass = !Config.ltcrpcuser2 ^ ":" ^ !Config.ltcrpcpass2 in
	    let url = ltcrpc2_url() in
            let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
	    let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
	    let l = input_line inc in
	    ignore (Unix.close_process_full (inc,outc,errc));
	    l
        end
    in
    let utxol = ref [] in
    match parse_jsonval l with
    | (JsonObj(al),_) ->
	begin
	  match List.assoc "result" al with
	  | JsonArr(ul) ->
	      begin
		List.iter
		  (fun u ->
		    match u with
		    | JsonObj(bl) ->
			begin
			  try
			    let ltcaddr = json_assoc_string "address" bl in
			    if ltcaddr = "" then raise Not_found;
			    if ltcaddr.[0] = 'M' || (!Config.testnet && ltcaddr.[0] = 'Q') then (*** p2sh segwit ***)
			      let txh = json_assoc_string "txid" bl in
			      let vout = json_assoc_int "vout" bl in
			      let rs = json_assoc_string "redeemScript" bl in
			      let spk = json_assoc_string "scriptPubKey" bl in
			      let amt = json_assoc_litoshis "amount" bl in
			      utxol := LtcP2shSegwit(txh,vout,ltcaddr,rs,spk,amt)::!utxol
			    else if ltcaddr.[0] = 'l' || (!Config.testnet && ltcaddr.[0] = 't') then (*** bech32 ***)
			      let txh = json_assoc_string "txid" bl in
			      let vout = json_assoc_int "vout" bl in
			      let spk = json_assoc_string "scriptPubKey" bl in
			      let amt = json_assoc_litoshis "amount" bl in
			      utxol := LtcBech32(txh,vout,ltcaddr,spk,amt)::!utxol
			    else
			      raise Not_found
			  with Not_found ->
			    ()
			end
		    | _ -> ())
		  ul;
		!utxol
	      end
	  | _ ->
	      (Utils.log_string (Printf.sprintf "problem return from ltc listunspent:\n%s\n" l));
	      raise Not_found
	end
    | _ ->
	(Utils.log_string (Printf.sprintf "problem return from ltc listunspent:\n%s\n" l));
	raise Not_found
  with _ ->
    raise Not_found

let ltc2_listunspent () = ltc2_listunspent_gen !Config.ltcaddresses

exception InsufficientLtcFunds

let le_num24 x =
  let strb = Buffer.create 3 in
  Buffer.add_char strb (Char.chr (x land 255));
  Buffer.add_char strb (Char.chr ((x lsr 8) land 255));
  Buffer.add_char strb (Char.chr ((x lsr 16) land 255));
  Buffer.contents strb

let findpfgtx txs1 txs2 =
  let i = ref (-1) in
  let rtxid = ref (0l,0l,0l,0l,0l,0l,0l,0l) in
  let txs = ref "" in
  let pfgid ri =
    let (_,_,_,_,_,_,_,x) = ri in
    Int32.logand x 0xffffl = 0x6650l
  in
  while not (pfgid !rtxid) do
    incr i;
    if !i >= 16777216 then raise Not_found; (** probably will never happen **)
    txs := txs1 ^ (le_num24 !i) ^ txs2;
    rtxid := Be256.to_int32p8 (Sha256.sha256dstr !txs)
  done;
  (!i,!rtxid,!txs);;

let findpfgswaptx txs1 txs2 =
  let i = ref (-1) in
  let rtxid = ref (0l,0l,0l,0l,0l,0l,0l,0l) in
  let txs = ref "" in
  let pfgswapid ri =
    let (_,_,_,_,_,_,_,x) = ri in
    Int32.logand x 0xffffl = 0x5350l
  in
  while not (pfgswapid !rtxid) do
    incr i;
    if !i >= 16777216 then raise Not_found; (** probably will never happen **)
    txs := txs1 ^ (le_num24 !i) ^ txs2;
    rtxid := Be256.to_int32p8 (Sha256.sha256dstr !txs)
  done;
  (!i,!rtxid,!txs);;

let blnum32 x =
  [Int32.to_int (Int32.logand x 255l);
   Int32.to_int (Int32.logand (Int32.shift_right_logical x 8) 255l);
   Int32.to_int (Int32.logand (Int32.shift_right_logical x 16) 255l);
   Int32.to_int (Int32.logand (Int32.shift_right_logical x 24) 255l)]

let blnum64 x =
  [Int64.to_int (Int64.logand x 255L);
   Int64.to_int (Int64.logand (Int64.shift_right_logical x 8) 255L);
   Int64.to_int (Int64.logand (Int64.shift_right_logical x 16) 255L);
   Int64.to_int (Int64.logand (Int64.shift_right_logical x 24) 255L);
   Int64.to_int (Int64.logand (Int64.shift_right_logical x 32) 255L);
   Int64.to_int (Int64.logand (Int64.shift_right_logical x 40) 255L);
   Int64.to_int (Int64.logand (Int64.shift_right_logical x 48) 255L);
   Int64.to_int (Int64.logand (Int64.shift_right_logical x 56) 255L)]

let ltc_createburntx_spec u h1 h2 toburn =
  let toburn_plus_fee = Int64.add toburn !Config.ltctxfee in
  let createburntx txid vout spk amt redeemfn =
    let changeamt = Int64.sub amt toburn_plus_fee in
    let txs1b = Buffer.create 100 in
    let txs2b = Buffer.create 100 in
    let txs3b = Buffer.create 100 in
    Buffer.add_string txs1b "\001"; (*** assume one input ***)
    let txidrh = hashval_rev (hexstring_hashval txid) in
    ignore (seo_hashval seosb txidrh (txs1b,None));
    List.iter (fun z -> Buffer.add_char txs1b (Char.chr z)) (blnum32 (Int32.of_int vout));
    let txs1 = Buffer.contents txs1b in
    redeemfn txs1b;
    if changeamt >= ltcdust then (** only create change if it is not dust **)
      Buffer.add_string txs2b "\255\255\255\255\002"
    else
      Buffer.add_string txs2b "\255\255\255\255\001";
    List.iter (fun z -> Buffer.add_char txs2b (Char.chr z)) (blnum64 toburn);
    let extradata = "" in
    let extradata = (*** before the May 2019 hard fork, do not burn enough to require pushing more than 75 bytes in the burn tx (and wait an extra day before burning more than 75 bytes even after the hard fork time, out of abundance of caution) ***)
      if 67 + String.length extradata > 80 then (** ltc will not relay OP_RETURN with more than 80 bytes; increase this if it changes **)
	""
      else
	extradata
    in
    let datalen = 67 + String.length extradata in
    if datalen > 252 then raise (Failure "too much data to burn");
    if datalen < 76 then
      begin
	Buffer.add_char txs2b (Char.chr (datalen+2));
	Buffer.add_char txs2b (Char.chr 0x6a); (*** OP_RETURN ***)
	Buffer.add_char txs2b (Char.chr datalen); (*** PUSH datalen ***)
      end
    else if datalen > 65535 then
      raise (Failure "too much data to burn")
    else if datalen > 255 then
      begin
	Buffer.add_char txs2b (Char.chr (datalen+3));
	Buffer.add_char txs2b (Char.chr 0x6a); (*** OP_RETURN ***)
	Buffer.add_char txs2b (Char.chr 77); (*** PUSH datalen ***)
	Buffer.add_char txs2b (Char.chr (datalen mod 256));
	Buffer.add_char txs2b (Char.chr (datalen / 256));
      end
    else 
      begin
	Buffer.add_char txs2b (Char.chr (datalen+3));
	Buffer.add_char txs2b (Char.chr 0x6a); (*** OP_RETURN ***)
	Buffer.add_char txs2b (Char.chr 76); (*** PUSH datalen ***)
	Buffer.add_char txs2b (Char.chr datalen);
      end;
    ignore (seo_hashval seosb h1 (txs2b,None));
    ignore (seo_hashval seosb h2 (txs2b,None));
    for i = 0 to (String.length extradata) - 1 do
      Buffer.add_char txs2b extradata.[i]
    done;
    if changeamt >= ltcdust then
      begin
        List.iter (fun z -> Buffer.add_char txs3b (Char.chr z)) (blnum64 changeamt);
        let spks = hexstring_string spk in
        Buffer.add_char txs3b (Char.chr (String.length spks));
        Buffer.add_string txs3b spks;
      end;
    Buffer.add_string txs3b "\000\000\000\000"; (*** locktime ***)
    let txs2 = Buffer.contents txs2b in
    let txs3 = Buffer.contents txs3b in
    let (i,rtxid,txs) = findpfgtx ("\002\000\000\000" ^ (Buffer.contents txs1b) ^ txs2) txs3 in
    let txsb = Buffer.create 100 in
    Buffer.add_string txsb "\002\000\000\000";
    Buffer.add_string txsb txs1;
    Buffer.add_string txsb "\000";
    Buffer.add_string txsb txs2;
    Buffer.add_string txsb (le_num24 i);
    Buffer.add_string txsb txs3;
    let s = Buffer.contents txsb in
    Hashtbl.add burntx h2 s;
    s
  in
  match u with
  | LtcP2shSegwit(txid,vout,_,rs,spk,amt) ->
     let rs2 = hexstring_string rs in
     let rsl = String.length rs2 in
     if rsl < 1 || rsl > 75 then raise Not_found;
     createburntx
       txid vout spk amt
       (fun txs1b ->
	 Buffer.add_char txs1b (Char.chr (1 + rsl));
	 Buffer.add_char txs1b (Char.chr rsl);
	 Buffer.add_string txs1b rs2)
  | LtcBech32(txid,vout,ltcaddr,spk,amt) ->
     createburntx
       txid vout spk amt
       (fun txs1b ->
	 Buffer.add_char txs1b '\000')
       
let ltc_createburntx h1 h2 toburn =
  let utxol = ltc2_listunspent () in
  let toburn_plus_fee = Int64.add toburn !Config.ltctxfee in
  try
    Hashtbl.find burntx h2
  with Not_found ->
    try
      (Utils.log_string (Printf.sprintf "Searching for an unspent litecoin tx with at least %Ld litoshis.\n" toburn_plus_fee));
      let u = (*** only consider single spends ***)
	List.find
	  (fun u ->
	    match u with
	    | LtcP2shSegwit(txid,vout,_,_,_,amt) -> amt >= toburn_plus_fee
	    | LtcBech32(txid,vout,_,_,amt) -> amt >= toburn_plus_fee)
	  utxol
      in
      ltc_createburntx_spec u h1 h2 toburn
    with Not_found -> raise InsufficientLtcFunds

let ltc_signrawtransaction txs =
  try
    let l =
      if !Config.ltcoffline then
	begin
	  Printf.printf "call signrawtransaction %s in ltc\n>> " txs; flush stdout;
	  read_line()
	end
      else
	let call =
	  if !Config.ltcversion >= 17 then
	    "{\"jsonrpc\": \"1.0\", \"id\":\"srtx\", \"method\": \"signrawtransactionwithwallet\", \"params\": [\"" ^ txs ^ "\"] }"
	  else
	    "{\"jsonrpc\": \"1.0\", \"id\":\"srtx\", \"method\": \"signrawtransaction\", \"params\": [\"" ^ txs ^ "\"] }"
	in
        begin
          try
            if !Config.ltcrpcavoidcurl then
              begin
                let (s,sin,sout) = ltcrpc2_connect () in
                Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                Printf.fprintf sout "%s\n" call;
                flush sout;
                skip_to_blankline sin;
                let l = input_line sin in
                shutdown_close s;
                l
              end
            else
              raise Exit
          with Exit -> (* fall back on curl *)
	    let userpass = !Config.ltcrpcuser2 ^ ":" ^ !Config.ltcrpcpass2 in
	    let url = ltcrpc2_url() in
	    let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
	    let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
	    let l = input_line inc in
	    ignore (Unix.close_process_full (inc,outc,errc));
	    l
        end
    in
    match parse_jsonval l with
    | (JsonObj(al),_) ->
	begin 
	  match List.assoc "result" al with
	  | JsonObj(bl) -> json_assoc_string "hex" bl
	  | _ ->
	      (Utils.log_string (Printf.sprintf "problem return from ltc signrawtransaction:\n%s\n" l));
	      raise Not_found
	end
    | _ ->
	(Utils.log_string (Printf.sprintf "problem return from ltc signrawtransaction:\n%s\n" l));
	raise Not_found
  with _ -> raise Not_found

let ltc_sendrawtransaction txs =
  try
    let l =
      if !Config.ltcoffline then
	begin
	  Printf.printf "call sendrawtransaction %s in ltc\n>> " txs; flush stdout;
	  read_line()
	end
      else
        let call = "{\"jsonrpc\": \"1.0\", \"id\":\"srtx\", \"method\": \"sendrawtransaction\", \"params\": [\"" ^ txs ^ "\"] }" in
        begin
          try
            if !Config.ltcrpcavoidcurl then
              begin
                let (s,sin,sout) = ltcrpc_connect () in
                Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                Printf.fprintf sout "%s\n" call;
                flush sout;
                skip_to_blankline sin;
                let l = input_line sin in
                shutdown_close s;
                l
              end
            else
              raise Exit
          with Exit -> (* fall back on curl *)
	    let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
	    let url = ltcrpc_url() in
	    let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
	    let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
	    let l = input_line inc in
	    ignore (Unix.close_process_full (inc,outc,errc));
	    l
        end
    in
    match parse_jsonval l with
    | (JsonObj(al),_) -> json_assoc_string "result" al
    | _ ->
	(Utils.log_string (Printf.sprintf "problem return from ltc sendrawtransaction:\n%s\n" l));
	raise Not_found
  with _ -> raise Not_found

exception NotAnLtcBurnTx

let donotretrypeer : (string,unit) Hashtbl.t = Hashtbl.create 100;;

let ltc_getburntransactioninfo h =
  let l =
    if !Config.ltcoffline then
      begin
	Printf.printf "call getrawtransaction %s in ltc\n>> " h; flush stdout;
	read_line()
      end
    else
      let call = "{\"jsonrpc\": \"1.0\", \"id\":\"grtx\", \"method\": \"getrawtransaction\", \"params\": [\"" ^ h ^ "\",1] }" in
      begin
        try
          if !Config.ltcrpcavoidcurl then
              begin
                let (s,sin,sout) = ltcrpc_connect () in
                Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                Printf.fprintf sout "%s\n" call;
                flush sout;
                skip_to_blankline sin;
                let l = input_line sin in
                shutdown_close s;
                l
              end
          else
            raise Exit
        with Exit -> (* fall back on curl *)
          let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
          let url = ltcrpc_url() in
          let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
          let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
          let l = input_line inc in
          ignore (Unix.close_process_full (inc,outc,errc));
          l
      end
  in
  try
    begin
      match parse_jsonval l with
      | (JsonObj(al),_) ->
         begin
	   match List.assoc "result" al with
	   | JsonObj(bl) ->
	      begin
	        match List.assoc "vout" bl with
	        | JsonArr(JsonObj(vout1)::_) ->
		   let litoshisburned = json_assoc_litoshis "value" vout1 in
		   begin
		     match List.assoc "scriptPubKey" vout1 with
		     | JsonObj(cl) ->
		        let hex = json_assoc_string "hex" cl in
		        if String.length hex >= 132 && hex.[0] = '6' && hex.[1] = 'a' && hex.[2] = '4' then
			  begin
			    let hex =
			      if hex.[3] = 'c' then (*** pushing up to 255 bytes ***)
			        String.sub hex 6 ((String.length hex) - 6)
			      else if hex.[3] = 'd' then (*** pushing up to 64K bytes ***)
			        String.sub hex 8 ((String.length hex) - 8)
			      else
			        String.sub hex 4 ((String.length hex) - 4)
			    in
			    let lprevtx = hexstring_hashval (String.sub hex 0 64) in
			    let dnxt = hexstring_hashval (String.sub hex 64 64) in
			    begin
			      let hexl = String.length hex in
			      if hexl > 132 then
			        let extradata = hexstring_string (String.sub hex 128 ((String.length hex) - 128)) in
			        if extradata.[0] = 'o' then
				  begin
				    if List.length !netconns < !Config.maxconns then
				      begin
				        let onionaddr = Buffer.create 10 in
				        try
					  for i = 1 to ((String.length extradata) - 1) do
					    if extradata.[i] = '.' then
					      begin
					        let peer = Printf.sprintf "%s.onion:20808" (Buffer.contents onionaddr) in
                                                if not (Hashtbl.mem donotretrypeer peer) then
                                                  begin
                                                    Hashtbl.add donotretrypeer peer ();
                                                    try
                                                      ignore (tryconnectpeer peer);
						      ignore (addknownpeer (Int64.of_float (Unix.time())) peer);
                                                    with BannedPeer -> ()
                                                  end;
					        raise Exit
					      end
					    else if extradata.[i] = ':' then
					      begin
					        if i+2 < String.length extradata then
						  begin
						    let port = (Char.code extradata.[i+1]) * 256 + (Char.code extradata.[i+2]) in
						    let peer = Printf.sprintf "%s.onion:%d" (Buffer.contents onionaddr) port in
                                                    if not (Hashtbl.mem donotretrypeer peer) then
                                                      begin
                                                        Hashtbl.add donotretrypeer peer ();
                                                        try
						          ignore (tryconnectpeer peer);
						          ignore (addknownpeer (Int64.of_float (Unix.time())) peer);
                                                        with BannedPeer -> ()
                                                      end
						  end
					        else
						  raise Exit
					      end
					    else
					      Buffer.add_char onionaddr extradata.[i]
					  done
				        with Exit -> ()
				      end
				  end
			        else if extradata.[0] = 'I' then
				  begin
				    if List.length !netconns < !Config.maxconns && ((String.length extradata) > 4) then
				      begin
				        let ip0 = Char.code extradata.[1] in
				        let ip1 = Char.code extradata.[2] in
				        let ip2 = Char.code extradata.[3] in
				        let ip3 = Char.code extradata.[4] in
				        let peer = Printf.sprintf "%d.%d.%d.%d:20805" ip0 ip1 ip2 ip3 in
                                        if not (Hashtbl.mem donotretrypeer peer) then
                                          begin
                                            Hashtbl.add donotretrypeer peer ();
                                            try
					      ignore (tryconnectpeer peer);
					      ignore (addknownpeer (Int64.of_float (Unix.time())) peer);
                                            with BannedPeer -> ()
                                          end
				      end
				  end
			        else if extradata.[0] = 'i' then
				  begin
				    if List.length !netconns < !Config.maxconns && ((String.length extradata) > 6) then
				      begin
				        let ip0 = Char.code extradata.[1] in
				        let ip1 = Char.code extradata.[2] in
				        let ip2 = Char.code extradata.[3] in
				        let ip3 = Char.code extradata.[4] in
				        let port = (Char.code extradata.[5]) * 256 + Char.code extradata.[6] in
				        let peer = Printf.sprintf "%d.%d.%d.%d:%d" ip0 ip1 ip2 ip3 port in
                                        if not (Hashtbl.mem donotretrypeer peer) then
                                          begin
                                            Hashtbl.add donotretrypeer peer ();
                                            try
					      ignore (tryconnectpeer peer);
					      ignore (addknownpeer (Int64.of_float (Unix.time())) peer);
                                            with BannedPeer -> ()
                                          end
				      end
				  end
			    end;
			    let lblkh =
			      begin
			        try
				  match List.assoc "blockhash" bl with
				  | JsonStr(lblkh) -> Some(lblkh)
				  | _ -> None
			        with Not_found -> None
			      end
			    in
			    let confs =
			      begin
			        try
				  match List.assoc "confirmations" bl with
				  | JsonNum(c) -> Some(int_of_string c)
				  | _ -> None
			        with _ -> None
			      end
			    in
                            match List.assoc "vin" bl with
	                    | JsonArr(JsonObj(vin1)::_) ->
                               let txid1 = json_assoc_string "txid" vin1 in
                               let vout1 = json_assoc_int "vout" vin1 in
			       (litoshisburned,lprevtx,dnxt,lblkh,confs,txid1,vout1)
                            | _ ->
	                       (* (Utils.log_string (Printf.sprintf "problem getting first utxo spent by ltc getrawtransaction:\n%s\n" l)); *)
			       raise NotAnLtcBurnTx
			  end
		        else
			  begin
                            (*			    (Utils.log_string (Printf.sprintf "problem return from ltc getrawtransaction:\n%s\n" l)); *)
			    raise NotAnLtcBurnTx
			  end
		     | _ ->
                        (*		        (Utils.log_string (Printf.sprintf "problem return from ltc getrawtransaction:\n%s\n" l)); *)
		        raise NotAnLtcBurnTx
		   end
	        | _ ->
                   (*		   (Utils.log_string (Printf.sprintf "problem return from ltc getrawtransaction:\n%s\n" l)); *)
		   raise NotAnLtcBurnTx
	      end
	   | _ ->
              (*	      (Utils.log_string (Printf.sprintf "problem return from ltc getrawtransaction:\n%s\n" l)); *)
	      raise NotAnLtcBurnTx
         end
      | _ ->
         (*         (Utils.log_string (Printf.sprintf "problem return from ltc getrawtransaction:\n%s\n" l)); *)
         raise NotAnLtcBurnTx
    end
  with JsonParseFail(_,_) -> raise NotAnLtcBurnTx

let ltc_getburntransactioninfo2 h =
  let l =
    if !Config.ltcoffline then
      begin
	Printf.printf "call getrawtransaction %s in ltc\n>> " h; flush stdout;
	read_line()
      end
    else
      let call = "{\"jsonrpc\": \"1.0\", \"id\":\"grtx\", \"method\": \"getrawtransaction\", \"params\": [\"" ^ h ^ "\",1] }" in
      begin
        try
          if !Config.ltcrpcavoidcurl then
              begin
                let (s,sin,sout) = ltcrpc_connect () in
                Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                Printf.fprintf sout "%s\n" call;
                flush sout;
                skip_to_blankline sin;
                let l = input_line sin in
                shutdown_close s;
                l
              end
          else
            raise Exit
        with Exit -> (* fall back on curl *)
          let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
          let url = ltcrpc_url() in
          let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
          let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
          let l = input_line inc in
          ignore (Unix.close_process_full (inc,outc,errc));
          l
      end
  in
  try
    begin
      match parse_jsonval l with
      | (JsonObj(al),_) ->
         begin
	   match List.assoc "result" al with
	   | JsonObj(bl) ->
	      begin
	        match List.assoc "vout" bl with
	        | JsonArr(_::JsonObj(vout2)::_) ->
		   begin
		     match List.assoc "scriptPubKey" vout2 with
		     | JsonObj(cl) ->
		        let addrs = List.assoc "addresses" cl in
                        begin
                          match addrs with
                          | JsonArr([JsonStr(alpha)]) -> Some alpha
                          | _ -> None
                        end
		     | _ -> None
		   end
	        | _ -> None
	      end
	   | _ -> None
         end
      | _ -> None
    end
  with JsonParseFail(_,_) -> None


let ltc_getburntransactioninfo2cache =
  let cache = Hashtbl.create 1000 in
  fun h ->
  try Hashtbl.find cache h
  with Not_found ->
    let ret = ltc_getburntransactioninfo2 h in
    Hashtbl.add cache h ret; ret
;;

module DbLtcBurnTx = Dbmbasic (struct type t = int64 * hashval * hashval * hashval * int32 let basedir = "ltcburntx" let seival = sei_prod5 sei_int64 sei_hashval sei_hashval sei_hashval sei_int32 seis let seoval = seo_prod5 seo_int64 seo_hashval seo_hashval seo_hashval seo_int32 seosb end)

module DbLtcBlock = Dbmbasic (struct type t = hashval * int64 * int64 * hashval list let basedir = "ltcblock" let seival = sei_prod4 sei_hashval sei_int64 sei_int64 (sei_list sei_hashval) seis let seoval = seo_prod4 seo_hashval seo_int64 seo_int64 (seo_list seo_hashval) seosb end)

let rec remdups_pfg_status_height_entries l r =
  match l with
  | [] -> r
  | e::lr ->
     if List.mem e r then
       remdups_pfg_status_height_entries lr r
     else
       remdups_pfg_status_height_entries lr (e::r)

let rec merge_pfg_status bds =
  match bds with
  | [] -> []
  | (dh1,l1)::(dh2,l2)::bdr when dh1 = dh2 -> merge_pfg_status ((dh1,l1 @ l2)::bdr)
  | (dh1,l1)::bdr -> (dh1,remdups_pfg_status_height_entries l1 [])::merge_pfg_status bdr

let rec ltc_process_block h =
  let hh = hexstring_hashval h in
  if not (hh = !ltc_oldest_to_consider) && not (DbLtcBlock.dbexists hh) then
    begin
      let (prev,tm,hght,txhs,_) = ltc_getblock h in
      ltc_process_block prev;
      let prevh = hexstring_hashval prev in
      let genl = ref [] in
      let succl = ref [] in
      let txhhs = ref [] in
      List.iter
	(fun txh ->
	  let txhh = hexstring_hashval txh in
	  let handle txid1 vout1 burned lprevtx dnxt =
              insert_blockburn dnxt (hh,txhh);
	      if lprevtx = zerohashval then
		begin
		  (Utils.log_string (Printf.sprintf "Adding burn %s for genesis header %s\n" txh (hashval_hexstring dnxt)));
		  txhhs := txhh :: !txhhs;
		  genl := (txhh,burned,dnxt)::!genl;
                  let lblktx = hashpair hh txhh in
		  if not (Db_outlinevals.dbexists (hashpair hh txhh)) then
		    begin
		      Db_outlinevals.dbput (hashpair hh txhh) (dnxt,tm,burned,(txid1,vout1),None,hashpair hh txhh,1L);
		      (*** since the burn is presumably new, add to missing lists; this should never happen since the genesis phase has passed. ***)
		      missingheaders := List.merge (fun (i,_,_) (j,_,_) -> compare i j) [(1L,dnxt,Some(lblktx))] !missingheaders;
		      missingdeltas := List.merge (fun (i,_,_) (j,_,_) -> compare i j) [(1L,dnxt,Some(lblktx))] !missingdeltas;
		      begin
			try
			  Hashtbl.find unburned_headers dnxt (hh,txhh);
			  Hashtbl.remove unburned_headers dnxt
			with _ -> ()
		      end;
		      begin
			try
			  Hashtbl.find unburned_deltas dnxt (hh,txhh);
			  Hashtbl.remove unburned_deltas dnxt
			with _ -> ()
		      end
		    end
		end
	      else
		begin
		  try
                    if not (DbLtcBurnTx.dbexists lprevtx) then raise NotAnLtcBurnTx; (** if we do not already know about the alleged previous burn tx, then do not accept the new one. **)
		    let (_,_,dprev,lprevblkh,_,_,_) = ltc_getburntransactioninfo (hashval_hexstring lprevtx) in
		    (Utils.log_string (Printf.sprintf "Adding burn %s for header %s (txid1 %s vout1 %ld)\n" txh (hashval_hexstring dnxt) (hashval_hexstring txid1) vout1));
		    DbLtcBurnTx.dbput txhh (burned,lprevtx,dnxt,txid1,vout1);
		    txhhs := txhh :: !txhhs;
		    succl := (dprev,txhh,burned,dnxt)::!succl;
		    if not (Db_outlinevals.dbexists (hashpair hh txhh)) then
		      begin
			try
			  match lprevblkh with
			  | Some(lprevblkh) ->
			      let lprevblkh = hexstring_hashval lprevblkh in
			      let (_,_,_,_,_,_,dhght) = Db_outlinevals.dbget (hashpair lprevblkh lprevtx) in
			      let currhght = Int64.add 1L dhght in
			      Db_outlinevals.dbput (hashpair hh txhh) (dnxt,tm,burned,(txid1,vout1),Some(lprevblkh,lprevtx),hashpair hh txhh,currhght);
                              insert_outlinesucc (lprevblkh,lprevtx) (hh,txhh);
                              begin (** check if it's building on a block we've thrown out **)
                                if DbBlacklist.dbexists dprev then
                                  DbBlacklist.dbput dnxt true;
                                if DbInvalidatedBlocks.dbexists dprev then
                                  DbInvalidatedBlocks.dbput dnxt true;
                              end;
			      (*** since the burn is presumably new, add to missing lists (unless it was staked by the current node which is handled in staking module) ***)
                                if not (DbBlacklist.dbexists dprev || DbInvalidatedBlocks.dbexists dprev) then (** unless it's being thrown out in advance, put it on the missing lists **)
                                begin
                                  let lblktx = hashpair hh txhh in
			          missingheaders := List.merge (fun (i,_,_) (j,_,_) -> compare i j) [(currhght,dnxt,Some(lblktx))] !missingheaders;
			          missingdeltas := List.merge (fun (i,_,_) (j,_,_) -> compare i j) [(currhght,dnxt,Some(lblktx))] !missingdeltas;
                                end;
			      begin
				try
				  Hashtbl.find unburned_headers dnxt (hh,txhh);
				  Hashtbl.remove unburned_headers dnxt
				with _ -> ()
			      end;
			      begin
				try
				  Hashtbl.find unburned_deltas dnxt (hh,txhh);
				  Hashtbl.remove unburned_deltas dnxt
				with _ -> ()
			      end;
			  | None -> ()
			with Not_found -> ()
		      end
		  with
                  | NotAnLtcBurnTx ->
		     DbLtcBurnTx.dbdelete txhh
                  | Not_found ->
		     Utils.log_string (Printf.sprintf "Could not find parent ltc burn tx %s for burn %s for header %s\n" (hashval_hexstring lprevtx) txh (hashval_hexstring dnxt))
		end
	    in
	    try
	      let (burned,lprevtx,dnxt,txid1,vout1) = DbLtcBurnTx.dbget txhh in
	      handle txid1 vout1 burned lprevtx dnxt
	    with Not_found ->
	      begin
		try
		  let (burned,lprevtx,dnxt,_,_,txid1,vout1) = ltc_getburntransactioninfo txh in
                  let txid1 = hexstring_hashval txid1 in
                  let vout1 = Int32.of_int vout1 in
		  DbLtcBurnTx.dbput txhh (burned,lprevtx,dnxt,txid1,vout1);
		  handle txid1 vout1 burned lprevtx dnxt
		with NotAnLtcBurnTx ->
		  Utils.log_string (Printf.sprintf "Ignoring tx %s which does not appear to be a Proofgold burn tx\n" txh)
	      end)
	txhs;
      begin
	let (prevkey,pbds) = ltcpfgstatus_dbget prevh in
	let change = ref false in
	let bds = ref [] in
	if not (!genl = []) then
	  begin
	    if tm > Int64.add !Config.genesistimestamp 604800L then
	      begin
		(Utils.log_string (Printf.sprintf "Ignoring unexpected genesis blocks burned during what appears to be after the genesis phase:\n"));
		List.iter (fun (txhh,burned,dnxt) -> Printf.printf "%s %Ld %s\n" (hashval_hexstring txhh) burned (hashval_hexstring dnxt)) !genl
	      end
	    else (*** there has already been a genesis block created during the genesis phase, but a competing one (or more) was created; include it too ***)
	      begin
		(Utils.log_string (Printf.sprintf "%d genesis block(s) found.\n" (List.length !genl)));
		let pbdl = List.map (fun (txhh,burned,dnxt) -> (dnxt,hh,txhh,tm,hght)) !genl in
		change := true;
		bds := [(1L,pbdl)]
	      end
	  end;
	List.iter
	  (fun (dhght,pbdl) ->
	    let pbdl2 =
	      List.filter
		(fun (bh,lbh,ltx,ltm,lhght) -> if Int64.sub tm ltm <= 604800L || Int64.sub hght lhght <= 4032L then true else (change := true; false)) (*** only allow building on blocks from the past week (either <= 604800 seconds in ltc median block time or 4032 ltc blocks) ***)
		pbdl
	    in
	    if not (pbdl2 = []) then
	      begin
		let pbdl2b = List.sort (fun (_,_,_,_,lhght1) (_,_,_,_,lhght2) -> compare lhght1 lhght2) pbdl2 in
		bds := (dhght,pbdl2b) :: !bds;
	      end;
	    let pbdl3 = ref [] in
	    List.iter
	      (fun (bh,lbh,ltx,ltm,lhght) ->
		List.iter
		  (fun (dprev,txhh,burned,dnxt) ->
		    if bh = dprev then
		      begin
			pbdl3 := (dnxt,hh,txhh,tm,hght)::!pbdl3;
			change := true
		      end)
		  !succl)
	      pbdl2;
	    if not (!pbdl3 = []) then
	      begin
		pbdl3 := List.sort (fun (_,_,_,_,lhght1) (_,_,_,_,lhght2) -> compare lhght1 lhght2) !pbdl3;
		bds := (Int64.add dhght 1L,!pbdl3) :: !bds
	      end)
	  (List.rev pbds);
	if !change then
	  begin
	    let bds2 = List.sort (fun (dh1,_) (dh2,_) -> compare dh2 dh1) !bds in
	    let bds3 = merge_pfg_status bds2 in
	    DbLtcPfgStatus.dbput hh (LtcPfgStatusNew(bds3))
	  end
	else if not (prevkey = !ltc_oldest_to_consider) then
	  DbLtcPfgStatus.dbput hh (LtcPfgStatusPrev(prevkey)) (*** pointer to last ltc block where proofgold status changed ***)
      end;
      DbLtcBlock.dbput hh (prevh,tm,hght,!txhhs);
      let datadir = if !Config.testnet then (Filename.concat !Config.datadir "testnet") else !Config.datadir in
      let f = open_out (Filename.concat datadir "lastltcblock") in
      Printf.fprintf f "%s\n" h;
      close_out_noerr f
    end

let ltc_medtime () =
  try
    let (_,mtm,_,_) = DbLtcBlock.dbget !ltc_bestblock in
    mtm
  with Not_found -> Int64.of_float (Unix.time())

let ltc_synced () =
  try
    Utils.log_string (Printf.sprintf "Checking if ltc synced; bestblock %s\n" (hashval_hexstring !ltc_bestblock));
    let (_,tm,_,_) = DbLtcBlock.dbget !ltc_bestblock in
    Utils.log_string (Printf.sprintf "tm of ltc bestblock %Ld offset from now %f\n" tm (Unix.time() -. Int64.to_float tm));
    if Unix.time() -. Int64.to_float tm < 3600.0 then
      true
    else
      false
  with Not_found -> false

let ltc_tx_confirmed h =
  try
    let l =
      if !Config.ltcoffline then
        begin
	  Printf.printf "call getrawtransaction %s in ltc\n>> " h; flush stdout;
	  read_line()
        end
      else
        let call = "{\"jsonrpc\": \"1.0\", \"id\":\"grtx\", \"method\": \"getrawtransaction\", \"params\": [\"" ^ h ^ "\",1] }" in
        begin
          try
            if !Config.ltcrpcavoidcurl then
              begin
                let (s,sin,sout) = ltcrpc_connect () in
                Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                Printf.fprintf sout "%s\n" call;
                flush sout;
                skip_to_blankline sin;
                let l = input_line sin in
                shutdown_close s;
                l
              end
            else
              raise Exit
          with Exit -> (* fall back on curl *)
            let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
            let url = ltcrpc_url() in
            let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
            let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
            let l = input_line inc in
            ignore (Unix.close_process_full (inc,outc,errc));
            l
        end
    in
    match parse_jsonval l with
    | (JsonObj(al),_) ->
       begin
	 match List.assoc "result" al with
	 | JsonObj(bl) ->
	    begin
	      match List.assoc "confirmations" bl with
	      | JsonNum(c) -> Some(int_of_string c)
	      | _ -> None
            end
         | _ -> None
       end
    | _ -> None
  with _ -> None

let ltc_tx_confirmed2 h =
  try
    let l =
      if !Config.ltcoffline then
        begin
	  Printf.printf "call getrawtransaction %s in ltc\n>> " h; flush stdout;
	  read_line()
        end
      else
        let call = "{\"jsonrpc\": \"1.0\", \"id\":\"grtx\", \"method\": \"getrawtransaction\", \"params\": [\"" ^ h ^ "\",1] }" in
        begin
          try
            if !Config.ltcrpcavoidcurl then
              begin
                let (s,sin,sout) = ltcrpc_connect () in
                Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                Printf.fprintf sout "%s\n" call;
                flush sout;
                skip_to_blankline sin;
                let l = input_line sin in
                shutdown_close s;
                l
              end
            else
              raise Exit
          with Exit -> (* fall back on curl *)
            let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
            let url = ltcrpc_url() in
            let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
            let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
            let l = input_line inc in
            ignore (Unix.close_process_full (inc,outc,errc));
            l
        end
    in
    match parse_jsonval l with
    | (JsonObj(al),_) ->
       begin
	 match List.assoc "result" al with
	 | JsonObj(bl) ->
	    begin
	      match List.assoc "confirmations" bl with
	      | JsonNum(c) ->
                 begin
		   let tm = json_assoc_int64 "blocktime" bl in
                   match List.assoc "vin" bl with
	           | JsonArr(JsonObj(vin1)::_) ->
                      let txid1 = json_assoc_string "txid" vin1 in
                      let vout1 = json_assoc_int "vout" vin1 in
                      if vout1 = 1 then
                        Some(int_of_string c,Some(txid1,tm))
                      else
                        Some(int_of_string c,None)
                   | _ ->
                      Some(int_of_string c,None)
                 end
	      | _ -> None
            end
         | _ -> None
       end
    | _ -> None
  with _ -> None

let ltc_tx_poburn h =
  try
    let (u,h1,h2,lblkh,confs,txid1,vout1) = ltc_getburntransactioninfo h in
    match lblkh with
    | Some(lbh) ->
	let (prev,tm,hght,txhs,_) = ltc_getblock lbh in
	Poburn(hexstring_hashval lbh,hexstring_hashval h,tm,u,hexstring_hashval txid1,Int32.of_int vout1)
    | _ -> raise Not_found
  with _ -> raise Not_found

let ltc_best_chaintips () =
  let (lastchangekey,ctips0l) = ltcpfgstatus_dbget !ltc_bestblock in
  let ctips1l =
    List.map (fun (_,ctips) -> List.filter (fun (h,_,_,_,_) -> not (DbBlacklist.dbexists h) && not (DbInvalidatedBlocks.dbexists h)) ctips) ctips0l
  in
  let ctips2l = List.filter (fun ctips -> not (ctips = [])) ctips1l in
  List.map (fun ctips -> List.map (fun (h,_,_,_,_) -> h) ctips) ctips2l

let find_pfg_header_ltc_burn h =
  let tried : (hashval,unit) Hashtbl.t = Hashtbl.create 100 in
  let rec find_pfg_header_ltc_burn_rec lbhl =
    match lbhl with
    | [] -> raise Not_found
    | lbh::lbhr ->
	if Hashtbl.mem tried lbh then
	  find_pfg_header_ltc_burn_rec lbhr
	else
	  let (lastchangekey,ctips0l) = ltcpfgstatus_dbget lbh in
	  let ctips1l =
	    List.map (fun (_,ctips) -> List.filter (fun (h,_,_,_,_) -> not (DbBlacklist.dbexists h) && not (DbInvalidatedBlocks.dbexists h)) ctips) ctips0l
	  in
	  let ctips2l = List.filter (fun ctips -> not (ctips = [])) ctips1l in
	  match ctips2l with
	  | [] -> raise Not_found
	  | (bestctips::_) ->
	      try
		let (dbh,lbh,ltx,ltm,lhght) = List.find (fun (dbh,_,_,_,_) -> dbh = h) bestctips in
		let (burned,lprevtx,dnxt,_,_) = DbLtcBurnTx.dbget ltx in
		let pob = ltc_tx_poburn (hashval_hexstring ltx) in
		let optionprevdalblock =
		  if lprevtx = zerohashval then
		    None
		  else
		    let (_,_,dprev,_,_) = DbLtcBurnTx.dbget lprevtx in
		    Some(dprev)
		in
		(pob,optionprevdalblock)
	      with Not_found ->
		let lbhlr = ref lbhl in
		List.iter
		  (fun (_,lbh,_,_,_) ->
		    try
		      let (prevlbh,_,_,_) = DbLtcBlock.dbget lbh in
		      lbhlr := prevlbh :: !lbhlr
		    with Not_found -> ())
		  bestctips;
		Hashtbl.add tried lbh ();
		find_pfg_header_ltc_burn_rec !lbhlr
  in
  find_pfg_header_ltc_burn_rec [!ltc_bestblock]

let rec delete_to_ltc_block kfrom k =
  if not (k = kfrom) then 
    begin
      try
        let (prevh,_,_,_) = DbLtcBlock.dbget k in
        DbLtcPfgStatus.dbdelete k;
        DbLtcBlock.dbdelete k;
        delete_to_ltc_block kfrom prevh
      with Not_found ->
        let (prev,_,_,_,_) = ltc_getblock (hashval_hexstring k) in
        let prevh = hexstring_hashval prev in
        DbLtcPfgStatus.dbdelete k;
        delete_to_ltc_block kfrom prevh
    end

let retractltcblock h =
  let k = hexstring_hashval h in
  let hnow = ltc_getbestblockhash () in
  let know = hexstring_hashval hnow in
  delete_to_ltc_block k know

let rec ltc_forward_from_block lbh =
  ltc_process_block lbh;
  let (prev,tm,hght,txhs,nbh) = ltc_getblock lbh in
  match nbh with
  | Some(nbh) -> ltc_forward_from_block nbh
  | None -> ()

(** if the oldest possible ltc block has not been processed (initial sync), then start from there **)
let rec ltc_forward_from_oldest_possible () =
  let h = !ltc_oldest_to_consider in
  let (_,_,_,_,nbh) = ltc_getblock (hashval_hexstring h) in
  match nbh with
  | None -> ()
  | Some(nbh) ->
     if not (DbLtcBlock.dbexists (hexstring_hashval nbh)) then ltc_forward_from_block nbh

let rec ltc_forward_from_oldest () =
  let datadir = if !Config.testnet then (Filename.concat !Config.datadir "testnet") else !Config.datadir in
  let fn = Filename.concat datadir "lastltcblock" in
  if Sys.file_exists fn then
    let f = open_in (Filename.concat datadir "lastltcblock") in
    try
      let l = input_line f in
      close_in_noerr f;
      ltc_forward_from_block l
    with _ ->
      close_in_noerr f;
      ltc_forward_from_oldest_possible()
  else
    begin
      try
        if !Config.independentbootstrap then
	  ltc_forward_from_oldest_possible()
        else
          begin
            let fullcall = Printf.sprintf "%s %s/lastltcblock" !Config.curl !Config.bootstrapurl in
            let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
            try
              let l = input_line inc in
              ignore (Unix.close_process_full (inc,outc,errc));
              if String.length l = 64 then
                ltc_forward_from_block l
              else
                raise Exit
            with _ ->
              ignore (Unix.close_process_full (inc,outc,errc));
              raise Exit
          end
      with Exit ->
        ltc_forward_from_oldest_possible()
    end

(** swap orders coordinated via ltc **)
let ltc_createswapoffertx_spec u pbeta litoshis atoms =
  let createswapoffertx lbeta txid vout spk amt redeemfn =
    let changeamt = Int64.sub amt (Int64.add litoshis !Config.ltctxfee) in
    let txs1b = Buffer.create 100 in
    let txs2b = Buffer.create 100 in
    let txs3b = Buffer.create 100 in
    Buffer.add_string txs1b "\001"; (*** assume one input ***)
    let txidrh = hashval_rev (hexstring_hashval txid) in
    ignore (seo_hashval seosb txidrh (txs1b,None));
    List.iter (fun z -> Buffer.add_char txs1b (Char.chr z)) (blnum32 (Int32.of_int vout));
    let txs1 = Buffer.contents txs1b in
    redeemfn txs1b;
    if changeamt >= ltcdust then (** only create change if it is not dust **)
      Buffer.add_string txs2b "\255\255\255\255\003"
    else
      Buffer.add_string txs2b "\255\255\255\255\002";
    List.iter (fun z -> Buffer.add_char txs2b (Char.chr z)) (blnum64 0L); (** burning nothing here **)
    let (bp,bs) = pbeta in
    if not (bp = 0) then raise (Failure "Proofgold address for swap must be p2pkh");
    let datasb = Buffer.create 28 in
    let c = seosb_be160 bs (datasb,None) in
    seosbf (seo_int64 seosb atoms c);
    let data = Buffer.contents datasb in
    let datalen = 4 + String.length data in (** 1 'header byte' + 3 extra bytes for the nonce **)
    if datalen >= 76 then raise (Failure "swap order too big; should never happen");
    Buffer.add_char txs2b (Char.chr (datalen+2));
    Buffer.add_char txs2b (Char.chr 0x6a); (*** OP_RETURN ***)
    Buffer.add_char txs2b (Char.chr datalen); (*** PUSH datalen ***)
    Buffer.add_char txs2b '\000'; (** header byte giving the type of swap offer **)
    for i = 0 to (String.length data) - 1 do
      Buffer.add_char txs2b data.[i]
    done;
    List.iter (fun z -> Buffer.add_char txs3b (Char.chr z)) (blnum64 litoshis);
    let spks = hexstring_string spk in
    Buffer.add_char txs3b (Char.chr (String.length spks));
    Buffer.add_string txs3b spks;
    if changeamt >= ltcdust then
      begin
        List.iter (fun z -> Buffer.add_char txs3b (Char.chr z)) (blnum64 changeamt);
        let spks = hexstring_string spk in
        Buffer.add_char txs3b (Char.chr (String.length spks));
        Buffer.add_string txs3b spks;
      end;
    Buffer.add_string txs3b "\000\000\000\000"; (*** locktime ***)
    let txs2 = Buffer.contents txs2b in
    let txs3 = Buffer.contents txs3b in
    let (i,rtxid,txs) = findpfgswaptx ("\002\000\000\000" ^ (Buffer.contents txs1b) ^ txs2) txs3 in
    let txsb = Buffer.create 100 in
    Buffer.add_string txsb "\002\000\000\000";
    Buffer.add_string txsb txs1;
    Buffer.add_string txsb "\000";
    Buffer.add_string txsb txs2;
    Buffer.add_string txsb (le_num24 i);
    Buffer.add_string txsb txs3;
    let txs = Buffer.contents txsb in
    let txss = ltc_signrawtransaction (string_hexstring txs) in
    ltc_sendrawtransaction txss
  in
  match u with
  | LtcP2shSegwit(txid,vout,ltcaddr,rs,spk,amt) ->
     let rs2 = hexstring_string rs in
     let rsl = String.length rs2 in
     if rsl < 1 || rsl > 75 then raise Not_found;
     createswapoffertx
       ltcaddr txid vout spk amt
       (fun txs1b ->
	 Buffer.add_char txs1b (Char.chr (1 + rsl));
	 Buffer.add_char txs1b (Char.chr rsl);
	 Buffer.add_string txs1b rs2)
  | LtcBech32(txid,vout,ltcaddr,spk,amt) ->
     createswapoffertx
       ltcaddr txid vout spk amt
       (fun txs1b ->
	 Buffer.add_char txs1b '\000')
       
let ltc_createswapoffertx pbeta litoshis atoms =
  let utxol = ltc2_listunspent_gen !Config.ltctradeaddresses in
  let minamt_plus_fee = Int64.add litoshis !Config.ltctxfee in
  if not (p2pkhaddr_p pbeta) then raise (Failure "Proofgold address for swap must be p2pkh");
  try
    (Utils.log_string (Printf.sprintf "Searching for an unspent litecoin tx with at least %Ld litoshis.\n" minamt_plus_fee));
    let u = (*** only consider single spends ***)
      List.find
	(fun u ->
	  match u with
	  | LtcP2shSegwit(txid,vout,_,_,_,amt) -> false (* only allow bech32 here *)
	  | LtcBech32(txid,vout,_,_,amt) -> (* skip those with vout=1 since those might be swap offers waiting to be filled *)
             not (vout = 1) && amt >= minamt_plus_fee)
	utxol
    in
    ltc_createswapoffertx_spec u pbeta litoshis atoms
  with Not_found -> raise InsufficientLtcFunds

let ltc_cancelswapbuyoffer txid =
  if !Config.ltcoffline then raise (Failure "ltcoffline");
  let l =
    begin
      let call = "{\"jsonrpc\": \"1.0\", \"id\":\"gtxout\", \"method\": \"gettxout\", \"params\": [\"" ^ txid ^ "\",1] }" in
      begin
        try
          if !Config.ltcrpcavoidcurl then
            begin
              let (s,sin,sout) = ltcrpc_connect () in
              Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
              Printf.fprintf sout "%s\n" call;
              flush sout;
              skip_to_blankline sin;
              let l = input_line sin in
              shutdown_close s;
              l
            end
          else
            raise Exit
        with Exit -> (* fall back on curl *)
          let url = ltcrpc_url() in
          let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
          let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
          let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
          let l = input_line inc in
          ignore (Unix.close_process_full (inc,outc,errc));
          l
      end
    end
  in
  try
    let createmovetransaction txid vout spk litoshis = (* one input one output *)
      let txsb = Buffer.create 100 in
      Buffer.add_string txsb "\002\000\000\000\001"; (* version 2 one input *)
      let txidrh = hashval_rev (hexstring_hashval txid) in
      ignore (seo_hashval seosb txidrh (txsb,None));
      List.iter (fun z -> Buffer.add_char txsb (Char.chr z)) (blnum32 (Int32.of_int vout));
      Buffer.add_char txsb '\000'; (* empty sig *)
      Buffer.add_string txsb "\255\255\255\255";
      Buffer.add_char txsb '\001'; (* one output *)
      List.iter (fun z -> Buffer.add_char txsb (Char.chr z)) (blnum64 litoshis);
      let spks = hexstring_string spk in
      Buffer.add_char txsb (Char.chr (String.length spks));
      Buffer.add_string txsb spks;
      Buffer.add_string txsb "\000\000\000\000"; (* locktime *)
      let txs = Buffer.contents txsb in
      let txss = ltc_signrawtransaction (string_hexstring txs) in
      ignore (ltc_sendrawtransaction txss)
    in
    match parse_jsonval l with
    | (JsonObj(al),_) ->
       begin
	 match List.assoc "result" al with
	 | JsonObj(bl) ->
	    let litoshis = json_assoc_litoshis "value" bl in
            if litoshis > !Config.ltctxfee then
              begin
                match List.assoc "scriptPubKey" bl with
		| JsonObj(cl) ->
		   let hex = json_assoc_string "hex" cl in
                   createmovetransaction txid 1 hex (Int64.sub litoshis !Config.ltctxfee)
                | _ -> ()
              end
         | _ -> ()
       end
    | _ -> ()
  with _ -> ()

let ltc_getswaptransactioninfo h =
  let hh = hexstring_hashval h in
  if not (List.exists (fun (hh2,_,_) -> hh2 = hh) !swapbuyoffers) then (** if don't already have **)
    begin
      let l =
        if !Config.ltcoffline then
          begin
	    Printf.printf "call getrawtransaction %s in ltc\n>> " h; flush stdout;
	    read_line()
          end
        else
          let call = "{\"jsonrpc\": \"1.0\", \"id\":\"grtx\", \"method\": \"getrawtransaction\", \"params\": [\"" ^ h ^ "\",1] }" in
          begin
            try
              if !Config.ltcrpcavoidcurl then
                begin
                  let (s,sin,sout) = ltcrpc_connect () in
                  Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
                  Printf.fprintf sout "%s\n" call;
                  flush sout;
                  skip_to_blankline sin;
                  let l = input_line sin in
                  shutdown_close s;
                  l
                end
              else
                raise Exit
            with Exit -> (* fall back on curl *)
              let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
              let url = ltcrpc_url() in
              let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
              let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
              let l = input_line inc in
              ignore (Unix.close_process_full (inc,outc,errc));
              l
          end
      in
      try
        begin
          match parse_jsonval l with
          | (JsonObj(al),_) ->
             begin
	       match List.assoc "result" al with
	       | JsonObj(bl) ->
	          begin
	            match List.assoc "vout" bl with
	            | JsonArr(JsonObj(vout1)::JsonObj(vout2)::_) ->
		       let litoshis = json_assoc_litoshis "value" vout2 in
                       begin
		         match List.assoc "scriptPubKey" vout2 with
                         | JsonObj(cl) ->
                            if json_assoc_string "type" cl = "witness_v0_keyhash" then
                              begin
                                match List.assoc "addresses" cl with
                                | JsonArr([JsonStr(lbeta)]) ->
		                   begin
                                     begin
		                       try
			                 match List.assoc "confirmations" bl with
			                 | JsonNum(c) ->
                                            if int_of_string c <= 2 then raise Exit (** wait until three confirmations **)
			                 | _ ->
                                            raise Exit
		                       with exc ->
                                         raise Exit
		                     end;
		                     match List.assoc "scriptPubKey" vout1 with
		                     | JsonObj(cl) ->
		                        let hex = json_assoc_string "hex" cl in
		                        if String.length hex >= 8 && hex.[0] = '6' && hex.[1] = 'a' then
			                  begin
                                            let knd = String.sub hex 4 2 in
                                            if knd = "00" && String.length hex >= 60 then
                                              begin
			                        let hex = String.sub hex 6 ((String.length hex) - 6) in
                                                let datastr = hexstring_string hex in
                                                let c = (datastr,String.length datastr,None,0,0) in
                                                let (bs,c) = sei_be160 seis c in
                                                let (atoms,_) = sei_int64 seis c in
                                                let pbeta = (0,bs) in
                                                let price = Int64.to_float litoshis *. 1000.0 /. Int64.to_float atoms in
                                                (Utils.log_string (Printf.sprintf "New Simple Swap Buy Offer: %s %s %s %Ld %Ld %f\n" h lbeta (Cryptocurr.addr_pfgaddrstr pbeta) atoms litoshis price));
                                                let sbo = SimpleSwapBuyOffer(lbeta,pbeta,atoms,litoshis) in
                                                swapbuyoffers := List.merge (fun (_,p1,_) (_,p2,_) -> compare p2 p1) [(hh,price,sbo)] !swapbuyoffers;
                                                swapcandidatetxs := List.filter (fun sh -> not (sh = h)) !swapcandidatetxs;
		                                let tm = json_assoc_int64 "blocktime" bl in
                                                ltc_insert_swap_buyoffer tm hh price sbo;
                                                let ddir = if !Config.testnet then (Filename.concat !Config.datadir "testnet") else !Config.datadir in
                                                let hswapfn = Filename.concat ddir "swapbuyofferhistory.csv" in
                                                let f = open_out_gen [Open_wronly;Open_creat;Open_append] 0o600 hswapfn in
                                                Printf.fprintf f "%Ld, %s, %s, %s, %Ld, %Ld, %f\n" tm h lbeta (addr_pfgaddrstr pbeta) atoms litoshis price;
                                                close_out f;
			                      end
                                            else
                                              swapcandidatetxs := List.filter (fun sh -> not (sh = h)) !swapcandidatetxs
			                  end
		                        else
			                  begin
                                            swapcandidatetxs := List.filter (fun sh -> not (sh = h)) !swapcandidatetxs
			                  end
		                     | _ ->
                                        swapcandidatetxs := List.filter (fun sh -> not (sh = h)) !swapcandidatetxs
		                   end
                                | _ ->
                                   swapcandidatetxs := List.filter (fun sh -> not (sh = h)) !swapcandidatetxs
                              end
                            else
                              swapcandidatetxs := List.filter (fun sh -> not (sh = h)) !swapcandidatetxs
                         | _ ->
                            swapcandidatetxs := List.filter (fun sh -> not (sh = h)) !swapcandidatetxs
                       end
	            | _ ->
                       swapcandidatetxs := List.filter (fun sh -> not (sh = h)) !swapcandidatetxs
	          end
	       | _ ->
                  swapcandidatetxs := List.filter (fun sh -> not (sh = h)) !swapcandidatetxs
             end
          | _ ->
             swapcandidatetxs := List.filter (fun sh -> not (sh = h)) !swapcandidatetxs
        end
      with _ -> ()
    end

let ltc_unspent txid vout =
  if !Config.ltcoffline then raise (Failure "ltcoffline");
  let l =
    begin
      let call = "{\"jsonrpc\": \"1.0\", \"id\":\"gtxout\", \"method\": \"gettxout\", \"params\": [\"" ^ txid ^ "\"," ^ (string_of_int vout) ^ "] }" in
      try
        if !Config.ltcrpcavoidcurl then
          begin
            let (s,sin,sout) = ltcrpc_connect () in
            Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
            Printf.fprintf sout "%s\n" call;
            flush sout;
            skip_to_blankline sin;
            let l = input_line sin in
            shutdown_close s;
            l
          end
        else
          raise Exit
      with Exit -> (* fall back on curl *)
        let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
        let url = ltcrpc_url() in
        let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
        let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
        let l = input_line inc in
        ignore (Unix.close_process_full (inc,outc,errc));
        l
    end
  in
  try
    match parse_jsonval l with
    | (JsonObj(al),_) ->
       begin
	 match List.assoc "result" al with
	 | JsonObj(bl) -> true
         | _ -> false
       end
    | _ -> false
  with _ -> false
  
let ltc_scanforswapbuyoffers n =
  let rec scanforswapbuyoffers_r n h =
    if n > 0 then
      let (pbh,_,_,_,_) = ltc_getblock h in
      scanforswapbuyoffers_r (n-1) pbh
  in
  scanforswapbuyoffers_r n (ltc_getbestblockhash ())
    
let findpfgalerttx txs1 txs2 =
  let i = ref (-1) in
  let rtxid = ref (0l,0l,0l,0l,0l,0l,0l,0l) in
  let txs = ref "" in
  let pfgswapid ri =
    let (_,_,_,_,_,_,_,x) = ri in
    Int32.logand x 0xffffl = 0x4150l
  in
  while not (pfgswapid !rtxid) do
    incr i;
    if !i >= 16777216 then raise Not_found; (** probably will never happen **)
    txs := txs1 ^ (le_num24 !i) ^ txs2;
    rtxid := Be256.to_int32p8 (Sha256.sha256dstr !txs)
  done;
  (!i,!rtxid,!txs);;

let ltc_createalerttx_spec u k msg =
  let toburn_plus_fee = !Config.ltctxfee in
  let createalerttx txid vout spk amt redeemfn =
    let changeamt = Int64.sub amt toburn_plus_fee in
    let txs1b = Buffer.create 100 in
    let txs2b = Buffer.create 100 in
    let txs3b = Buffer.create 100 in
    Buffer.add_string txs1b "\001"; (*** assume one input ***)
    let txidrh = hashval_rev (hexstring_hashval txid) in
    ignore (seo_hashval seosb txidrh (txs1b,None));
    List.iter (fun z -> Buffer.add_char txs1b (Char.chr z)) (blnum32 (Int32.of_int vout));
    let txs1 = Buffer.contents txs1b in
    redeemfn txs1b;
    if changeamt >= ltcdust then (** only create change if it is not dust **)
      Buffer.add_string txs2b "\255\255\255\255\002"
    else
      Buffer.add_string txs2b "\255\255\255\255\001";
    List.iter (fun z -> Buffer.add_char txs2b (Char.chr z)) (blnum64 0L);
    let datalen = 4 + String.length msg in
    if datalen > 252 then raise (Failure "too much data to burn");
    if datalen < 76 then
      begin
	Buffer.add_char txs2b (Char.chr (datalen+2));
	Buffer.add_char txs2b (Char.chr 0x6a); (*** OP_RETURN ***)
	Buffer.add_char txs2b (Char.chr datalen); (*** PUSH datalen ***)
      end
    else if datalen > 65535 then
      raise (Failure "too much data to burn")
    else if datalen > 255 then
      begin
	Buffer.add_char txs2b (Char.chr (datalen+3));
	Buffer.add_char txs2b (Char.chr 0x6a); (*** OP_RETURN ***)
	Buffer.add_char txs2b (Char.chr 77); (*** PUSH datalen ***)
	Buffer.add_char txs2b (Char.chr (datalen mod 256));
	Buffer.add_char txs2b (Char.chr (datalen / 256));
      end
    else 
      begin
	Buffer.add_char txs2b (Char.chr (datalen+3));
	Buffer.add_char txs2b (Char.chr 0x6a); (*** OP_RETURN ***)
	Buffer.add_char txs2b (Char.chr 76); (*** PUSH datalen ***)
	Buffer.add_char txs2b (Char.chr datalen);
      end;
    Buffer.add_char txs2b k;
    for i = 0 to (String.length msg) - 1 do
      Buffer.add_char txs2b msg.[i]
    done;
    if changeamt >= ltcdust then
      begin
        List.iter (fun z -> Buffer.add_char txs3b (Char.chr z)) (blnum64 changeamt);
        let spks = hexstring_string spk in
        Buffer.add_char txs3b (Char.chr (String.length spks));
        Buffer.add_string txs3b spks;
      end;
    Buffer.add_string txs3b "\000\000\000\000"; (*** locktime ***)
    let txs2 = Buffer.contents txs2b in
    let txs3 = Buffer.contents txs3b in
    let (i,rtxid,txs) = findpfgalerttx ("\002\000\000\000" ^ (Buffer.contents txs1b) ^ txs2) txs3 in
    let txsb = Buffer.create 100 in
    Buffer.add_string txsb "\002\000\000\000";
    Buffer.add_string txsb txs1;
    Buffer.add_string txsb "\000";
    Buffer.add_string txsb txs2;
    Buffer.add_string txsb (le_num24 i);
    Buffer.add_string txsb txs3;
    let s = Buffer.contents txsb in
    s
  in
  match u with
  | LtcP2shSegwit(txid,vout,_,rs,spk,amt) ->
     let rs2 = hexstring_string rs in
     let rsl = String.length rs2 in
     if rsl < 1 || rsl > 75 then raise Not_found;
     createalerttx
       txid vout spk amt
       (fun txs1b ->
	 Buffer.add_char txs1b (Char.chr (1 + rsl));
	 Buffer.add_char txs1b (Char.chr rsl);
	 Buffer.add_string txs1b rs2)
  | LtcBech32(txid,vout,ltcaddr,spk,amt) ->
     createalerttx
       txid vout spk amt
       (fun txs1b ->
	 Buffer.add_char txs1b '\000')

let rec broadcast_alert_via_ltc k msg =
  let utxol = ltc2_listunspent () in
  let toburn_plus_fee = !Config.ltctxfee in
  try
    (Utils.log_string (Printf.sprintf "Searching for an unspent litecoin tx with at least %Ld litoshis.\n" toburn_plus_fee));
    let u = (*** only consider single spends ***)
      List.find
	(fun u ->
	  match u with
	  | LtcP2shSegwit(txid,vout,_,_,_,amt) -> amt >= toburn_plus_fee
	  | LtcBech32(txid,vout,_,_,amt) -> amt >= toburn_plus_fee)
	utxol
    in
    let s = string_hexstring (ltc_createalerttx_spec u k msg) in
    let s = ltc_signrawtransaction s in
    ltc_sendrawtransaction s
  with Not_found -> raise InsufficientLtcFunds

let ltc_process_alert_tx_real h init =
  let l =
    if !Config.ltcoffline then
      begin
	Printf.printf "call getrawtransaction %s in ltc\n>> " h; flush stdout;
	read_line()
      end
    else
      let call = "{\"jsonrpc\": \"1.0\", \"id\":\"grtx\", \"method\": \"getrawtransaction\", \"params\": [\"" ^ h ^ "\",1] }" in
      begin
        try
          if !Config.ltcrpcavoidcurl then
            begin
              let (s,sin,sout) = ltcrpc_connect () in
              Printf.fprintf sout "Content-Length: %d\n\n" (String.length call);
              Printf.fprintf sout "%s\n" call;
              flush sout;
              skip_to_blankline sin;
              let l = input_line sin in
              shutdown_close s;
              l
            end
          else
            raise Exit
        with Exit -> (* fall back on curl *)
          let userpass = !Config.ltcrpcuser ^ ":" ^ !Config.ltcrpcpass in
          let url = ltcrpc_url() in
          let fullcall = !Config.curl ^ " --user " ^ userpass ^ " --data-binary '" ^ call ^ "' -H 'content-type: text/plain;' " ^ url in
          let (inc,outc,errc) = Unix.open_process_full fullcall [| |] in
          let l = input_line inc in
          ignore (Unix.close_process_full (inc,outc,errc));
          l
      end
  in
  try
    begin
      match parse_jsonval l with
      | (JsonObj(al),_) ->
         begin
	   match List.assoc "result" al with
	   | JsonObj(bl) ->
	      begin
	        match List.assoc "vout" bl with
	        | JsonArr(JsonObj(vout1)::_) ->
		   begin
		     match List.assoc "scriptPubKey" vout1 with
		     | JsonObj(cl) ->
		        let hex = json_assoc_string "hex" cl in
		        if String.length hex >= 10 && hex.[0] = '6' && hex.[1] = 'a' then
			  begin
			    let hex =
			      if hex.[2] = '4' && hex.[3] = 'c' then (*** pushing up to 255 bytes ***)
			        String.sub hex 6 ((String.length hex) - 6)
			      else if hex.[2] = '4' && hex.[3] = 'd' then (*** pushing up to 64K bytes ***)
			        String.sub hex 8 ((String.length hex) - 8)
			      else
			        String.sub hex 4 ((String.length hex) - 4)
			    in
                            let datastr = hexstring_string hex in
			    let datastrl = String.length datastr in
                            if datastrl > 3 then
                              if datastr.[0] = 'A' then (** alert **)
                                let msg = String.sub datastr 1 (datastrl - 4) in
                                begin
                                  if not init then Utils.log_string (Printf.sprintf "\nALERT: %s\n" msg);
                                  if not !Config.daemon then
                                    (Printf.printf "\nALERT: %s\n" msg; flush stdout);
                                  let ltctxid = hexstring_hashval h in
                                  if not (Hashtbl.mem allalerts_have ltctxid) then
                                    begin
		                      let tm = json_assoc_int64 "blocktime" bl in
                                      Hashtbl.add allalerts_have ltctxid ();
                                      allalerts := List.merge (fun (tm1,_,_) (tm2,_,_) -> compare tm2 tm1) [(tm,ltctxid,msg)] !allalerts;
                                      let ddir = if !Config.testnet then (Filename.concat !Config.datadir "testnet") else !Config.datadir in
                                      let hfn = Filename.concat ddir "alerthistory.csv" in
                                      let f = open_out_gen [Open_wronly;Open_creat;Open_append] 0o600 hfn in
                                      Printf.fprintf f "%Ld, %s, %s\n" tm h (string_hexstring msg);
                                      close_out f
                                    end
                                end
                              else if datastr.[0] = 'L' then (** listener node **)
                                begin
                                  let n = String.sub datastr 1 (datastrl - 4) in
                                  if not init then Utils.log_string (Printf.sprintf "\nALERT: Listener node: %s\n" n);
                                  record_peer n;
                                  let ltctxid = hexstring_hashval h in
                                  if not (Hashtbl.mem alllisteners_have ltctxid) then
                                    begin
		                      let tm = json_assoc_int64 "blocktime" bl in
                                      Hashtbl.add alllisteners_have ltctxid ();
                                      try
                                        let otm = Hashtbl.find alllisteners n in
                                        if tm > otm then
                                          begin
                                            Hashtbl.replace alllisteners n tm;
                                            let ddir = if !Config.testnet then (Filename.concat !Config.datadir "testnet") else !Config.datadir in
                                            let hfn = Filename.concat ddir "listenerhistory.csv" in
                                            let f = open_out_gen [Open_wronly;Open_creat;Open_append] 0o600 hfn in
                                            Printf.fprintf f "%Ld, %s, %s\n" tm h (string_hexstring n);
                                            close_out f
                                          end
                                      with Not_found ->
                                        Hashtbl.replace alllisteners n tm;
                                        let ddir = if !Config.testnet then (Filename.concat !Config.datadir "testnet") else !Config.datadir in
                                        let hfn = Filename.concat ddir "listenerhistory.csv" in
                                        let f = open_out_gen [Open_wronly;Open_creat;Open_append] 0o600 hfn in
                                        Printf.fprintf f "%Ld, %s, %s\n" tm h (string_hexstring n);
                                        close_out f
                                    end
                                end
                              else if datastr.[0] = 'B' then (** bootstrap url **)
                                begin
                                  let url = String.sub datastr 1 (datastrl - 4) in
                                  if not init then Utils.log_string (Printf.sprintf "\nALERT: Bootstrap url: %s\n" url);
                                  if not (Hashtbl.mem knownbootstrapurl url) then
                                    if Hashtbl.mem ignorebootstrapurl url then
                                      begin
                                        if not !Config.daemon then
                                          (Printf.printf "Ignoring bootstrap url %s due to warning.\n" url; flush stdout)
                                      end
                                    else
                                      begin
                                        Hashtbl.add knownbootstrapurl url ();
                                        bootstrapurls := url::!bootstrapurls;
                                        if not !Config.daemon then
                                          (Printf.printf "Found bootstrap url %s.\n" url; flush stdout)
                                      end
                                end
                              else if datastr.[0] = 'b' then (** warning away from bootstrap url **)
                                begin
                                  let url = String.sub datastr 1 (datastrl - 4) in
                                  if not init then Utils.log_string (Printf.sprintf "\nALERT: Warning away from bootstrap url: %s\n" url);
                                  Hashtbl.add ignorebootstrapurl url ();
                                  if not !Config.daemon then
                                    (Printf.printf "Warned away from bootstrap url %s.\n" url; flush stdout)
                                end
                          end
                     | _ -> ()
                   end
                | _ -> ()
              end
           | _ -> ()
         end
      | _ -> ()
    end
  with _ -> ()

let ltc_process_alert_tx h = ltc_process_alert_tx_real h false

let search_ltc_bootstrap_url () =
  let fn = Printf.sprintf "%s/ltcbootstrap" !Config.datadir in
  let lbh =
    if Sys.file_exists fn then
      begin
        try
          let f = open_in fn in
          let l = input_line f in
          l
        with End_of_file ->
          ltc_getbestblockhash()
      end
    else
      begin
        ltc_getbestblockhash()
      end
  in
  (*  let currtm = Unix.time () in *)
  let h = ref lbh in
  try
    while true do
      let f = open_out fn in
      Printf.fprintf f "%s\n" !h;
      close_out f;
      let (prev,tm,hght,_,_) = ltc_getblock !h in
      if hght <= 2153500L then raise Exit;
      List.iter
        (fun ltx -> ltc_process_alert_tx_real ltx true)
        !alertcandidatetxs;
      alertcandidatetxs := [];
      h := prev;
      match !bootstrapurls with
      | (url::_) -> Config.bootstrapurl := url; raise Exit
      | _ -> ()
    done
  with Exit -> ();;

let parse_csv l =
  let ln = String.length l in
  let rec parse_csv_r i s =
    if i < ln then
      let c = l.[i] in
      if c = ',' then
        s::parse_csv_s (i+1)
      else
        parse_csv_r (i+1) (Printf.sprintf "%s%c" s c)
    else
      [s]
  and parse_csv_s i =
    if i < ln then
      let c = l.[i] in
      if c = ' ' || c = '\t' || c = '\n' || c = '\r' then
        parse_csv_s (i+1)
      else if c = ',' then
        ""::parse_csv_s (i+1)
      else
        parse_csv_r (i+1) (Printf.sprintf "%c" c)
    else
      []
  in
  parse_csv_s 0

let initialize_historic_swap_info_buyoffers ddir =
  let hswapfn = Filename.concat ddir "swapbuyofferhistory.csv" in
  if Sys.file_exists hswapfn then
    let f = open_in hswapfn in
    begin
      try
        while true do
          let l = input_line f in
          let ll = parse_csv l in
          match ll with
          | [tm;ltctxid;ltcaddr;pfgaddr;atms;litoshis;price] ->
             ltc_insert_swap_buyoffer (Int64.of_string tm) (hexstring_hashval ltctxid) (float_of_string price) (SimpleSwapBuyOffer(ltcaddr,pfgaddrstr_addr pfgaddr,Int64.of_string atms,Int64.of_string litoshis))
          | _ ->
            raise (Failure (Printf.sprintf "%d comma separated values, but expected 7" (List.length ll)))
        done
      with
      | End_of_file ->
         close_in f
      | exn ->
         Printf.printf "Unexpected exception when initializing historic swap info:\n%s\nCorrupted swapbuyofferhistory.csv?\n" (Printexc.to_string exn);
         close_in f
    end
  else
    let f = open_out hswapfn in
    begin
      ltc_insert_swap_buyoffer 1606052762L (hexstring_hashval "505320dfc3fcf3bbeffcc6a167e7085c44d1dec364bcc491aa4619ed658d42b2") 0.001 (SimpleSwapBuyOffer("ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea",pfgaddrstr_addr "PrGh2fyyShyx7AsrQiCJxqGQQKSMdLtPYjr",1000000000000L,1000000L));
      Printf.fprintf f "1606052762, 505320dfc3fcf3bbeffcc6a167e7085c44d1dec364bcc491aa4619ed658d42b2, ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea, PrGh2fyyShyx7AsrQiCJxqGQQKSMdLtPYjr, 1000000000000, 1000000, 0.001\n";
      ltc_insert_swap_buyoffer 1606647771L (hexstring_hashval "5053e9b86bb2a756dee1140b21e1a7f278b11ed9b192c28925846505a7d4447f") 0.001 (SimpleSwapBuyOffer("ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea",pfgaddrstr_addr "PrGh2fyyShyx7AsrQiCJxqGQQKSMdLtPYjr",100000000000L,100000L));
      Printf.fprintf f "1606647771, 5053e9b86bb2a756dee1140b21e1a7f278b11ed9b192c28925846505a7d4447f, ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea, PrGh2fyyShyx7AsrQiCJxqGQQKSMdLtPYjr, 100000000000, 100000, 0.001\n";
      ltc_insert_swap_buyoffer 1606725289L (hexstring_hashval "5053aea0ba2e3ce2ac106ec7441b157d5a18efd96102cd9e9e9ecd26208d3d5a") 0.001 (SimpleSwapBuyOffer("ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea",pfgaddrstr_addr "PrGh2fyyShyx7AsrQiCJxqGQQKSMdLtPYjr",100000000000L,100000L));
      Printf.fprintf f "1606725289, 5053aea0ba2e3ce2ac106ec7441b157d5a18efd96102cd9e9e9ecd26208d3d5a, ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea, PrGh2fyyShyx7AsrQiCJxqGQQKSMdLtPYjr, 100000000000, 100000, 0.001\n";
      ltc_insert_swap_buyoffer 1606810780L (hexstring_hashval "5053121b9de82641a7ec1f95c399d7562173b3f96e217a8a49443552c0f23b25") 0.002 (SimpleSwapBuyOffer("ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea",pfgaddrstr_addr "PrGh2fyyShyx7AsrQiCJxqGQQKSMdLtPYjr",50000000000L,100000L));
      Printf.fprintf f "1606810780, 5053121b9de82641a7ec1f95c399d7562173b3f96e217a8a49443552c0f23b25, ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea, PrGh2fyyShyx7AsrQiCJxqGQQKSMdLtPYjr, 50000000000, 100000, 0.002\n";
      ltc_insert_swap_buyoffer 1607241305L (hexstring_hashval "50532b7966e02807a0463166f56b31e896ddd63dde17c72991eada8075522b4e") 1.5e-5 (SimpleSwapBuyOffer("ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea",pfgaddrstr_addr "PrS5npDo1N1U3rkCmAqEEBRaFdj2kYafJp7",10000000000000L,150000L));
      Printf.fprintf f "1607241305, 50532b7966e02807a0463166f56b31e896ddd63dde17c72991eada8075522b4e, ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea, PrS5npDo1N1U3rkCmAqEEBRaFdj2kYafJp7, 10000000000000, 150000, 1.5e-5\n";
      ltc_insert_swap_buyoffer 1607507744L (hexstring_hashval "505319f55e778e1f29fe660a71b878ac906c7d515c8185091d2e49589c98a7c6") 1.5e-5 (SimpleSwapBuyOffer("ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea",pfgaddrstr_addr "PrS5npDo1N1U3rkCmAqEEBRaFdj2kYafJp7",10000000000000L,150000L));
      Printf.fprintf f "1607507744, 505319f55e778e1f29fe660a71b878ac906c7d515c8185091d2e49589c98a7c6, ltc1qpreyg908g38c54lmvl9679wzm2d76v5dg6t3ea, PrS5npDo1N1U3rkCmAqEEBRaFdj2kYafJp7, 10000000000000, 150000, 1.5e-5\n";
      ltc_insert_swap_buyoffer 1607856593L (hexstring_hashval "50533e541459e8426fd5f2885474fde8bfbb16a30d97eb9190c9c168114a61bf") 2.01e-4 (SimpleSwapBuyOffer("ltc1qlsac6x4jgjy9gs3j3z0wnh209ceajwhu2ezw9y",pfgaddrstr_addr "PrDg5A7gw9aMj53NCwJ9UT6NLxYKf8KRTfo",4984245000000L,1000000L));
      Printf.fprintf f "1607856593, 50533e541459e8426fd5f2885474fde8bfbb16a30d97eb9190c9c168114a61bf, ltc1qlsac6x4jgjy9gs3j3z0wnh209ceajwhu2ezw9y, PrDg5A7gw9aMj53NCwJ9UT6NLxYKf8KRTfo, 4984245000000, 1000000, 2.01e-4\n";
      ltc_insert_swap_buyoffer 1607863287L (hexstring_hashval "50533115ccbb548f71c74c78e23405acd898a58036168baed31218944cbc53db") 1.08e-4 (SimpleSwapBuyOffer("ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm",pfgaddrstr_addr "Pr5csnwxavPwCT9U3UnPr6yf2u2x49mzsvy",9279716500000L,1000000L));
      Printf.fprintf f "1607863287, 50533115ccbb548f71c74c78e23405acd898a58036168baed31218944cbc53db, ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm, Pr5csnwxavPwCT9U3UnPr6yf2u2x49mzsvy, 9279716500000, 1000000, 1.08e-4\n";
      ltc_insert_swap_buyoffer 1608133943L (hexstring_hashval "5053d8dbc6f11d99d0fefcce99922950d42e059ad6a44f8c6f710388f9643d03") 2.8e-5 (SimpleSwapBuyOffer("ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm",pfgaddrstr_addr "Pr5csnwxavPwCT9U3UnPr6yf2u2x49mzsvy",110000000000000L,3100000L));
      Printf.fprintf f "1608133943, 5053d8dbc6f11d99d0fefcce99922950d42e059ad6a44f8c6f710388f9643d03, ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm, Pr5csnwxavPwCT9U3UnPr6yf2u2x49mzsvy, 110000000000000, 3100000, 2.8e-5\n";
      ltc_insert_swap_buyoffer 1608332940L (hexstring_hashval "5053eb25d9320f1b24fff5ca59b4050e08611cfe3b74b80ddee412df2b380ba3") 5.2e-5 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "Pr9AJgo49d3byVaHVBCrHV6Gk97LgkbQmZb",9000000000000L,470000L));
      Printf.fprintf f "1608332940, 5053eb25d9320f1b24fff5ca59b4050e08611cfe3b74b80ddee412df2b380ba3, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, Pr9AJgo49d3byVaHVBCrHV6Gk97LgkbQmZb, 9000000000000, 470000, 5.2e-5\n";
      ltc_insert_swap_buyoffer 1608428889L (hexstring_hashval "505345453c918232b5447afd4bc06af52da0fd4c42f037ea7db850551faabd48") 4.4e-5 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "Pr7vLrdBENdmvKsVR5DLUHkALcEairbD8gN",6400000000000L,280000L));
      Printf.fprintf f "1608428889, 505345453c918232b5447afd4bc06af52da0fd4c42f037ea7db850551faabd48, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, Pr7vLrdBENdmvKsVR5DLUHkALcEairbD8gN, 6400000000000, 280000, 4.4e-5\n";
      ltc_insert_swap_buyoffer 1608829601L (hexstring_hashval "505340559b94b2b7a63b29ff32a57e2400b40ec3d9a25ba907e3859e51fa68e9") 8.0e-5 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "Pr3ZxJSPUom1yRwNVLezJiSqCVEHewycTpE",1500000000000L,120000L));
      Printf.fprintf f "1608829601, 505340559b94b2b7a63b29ff32a57e2400b40ec3d9a25ba907e3859e51fa68e9, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, Pr3ZxJSPUom1yRwNVLezJiSqCVEHewycTpE, 1500000000000, 120000, 8.0e-5\n";
      ltc_insert_swap_buyoffer 1608891079L (hexstring_hashval "5053c82080cacff65299bf9cf3ec7b74ef10ea629faf253b3934a1885ca0f42c") 1.5e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrMwHLtLQXuK78o3oYXEkkW3f4KXKZw9UZZ",20000000000000L,3000000L));
      Printf.fprintf f "1608891079, 5053c82080cacff65299bf9cf3ec7b74ef10ea629faf253b3934a1885ca0f42c, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrMwHLtLQXuK78o3oYXEkkW3f4KXKZw9UZZ, 20000000000000, 3000000, 1.5e-4\n";
      ltc_insert_swap_buyoffer 1608894063L (hexstring_hashval "50531cb410a374984e4ac7501fa3f6213dcf2ca5dd45dd4a0c0311429db8bad5") 1.5e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrMwHLtLQXuK78o3oYXEkkW3f4KXKZw9UZZ",10000000000000L,1500000L));
      Printf.fprintf f "1608894063, 50531cb410a374984e4ac7501fa3f6213dcf2ca5dd45dd4a0c0311429db8bad5, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrMwHLtLQXuK78o3oYXEkkW3f4KXKZw9UZZ, 10000000000000, 1500000, 1.5e-4\n";
      ltc_insert_swap_buyoffer 1608918347L (hexstring_hashval "5053b59c96a8f4711a099dcc95388bb59d82fb83a1e96c180cc0ca3bfc3f1bc3") 8.1e-5 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrFgTA6sw6p12mhfCqUKr5hKqYzW4CGZBpP",27000000000000L,2200000L));
      Printf.fprintf f "1608918347, 5053b59c96a8f4711a099dcc95388bb59d82fb83a1e96c180cc0ca3bfc3f1bc3, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrFgTA6sw6p12mhfCqUKr5hKqYzW4CGZBpP, 27000000000000, 2200000, 8.1e-5\n";
      ltc_insert_swap_buyoffer 1608963760L (hexstring_hashval "5053c08127bc9e0b8e27e92333193fd72fef2d8778ea49fe506d26e3a37854aa") 1.5e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrJgh43gNwQLDQTv2R1LovpysvAxV5wG4ad",10000000000000L,1500000L));
      Printf.fprintf f "1608963760, 5053c08127bc9e0b8e27e92333193fd72fef2d8778ea49fe506d26e3a37854aa, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrJgh43gNwQLDQTv2R1LovpysvAxV5wG4ad, 10000000000000, 1500000, 1.5e-4\n";
      ltc_insert_swap_buyoffer 1609048965L (hexstring_hashval "5053132d0255d87e703df7a2cfeabb58c8016ff9485e69225afd5f63946a0874") 7.8e-5 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrEHtsgy3y8RCSMmaRg4YNVAHAB4cFyiiWd",3700000000000L,290000L));
      Printf.fprintf f "1609048965, 5053132d0255d87e703df7a2cfeabb58c8016ff9485e69225afd5f63946a0874, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrEHtsgy3y8RCSMmaRg4YNVAHAB4cFyiiWd, 3700000000000, 290000, 7.8e-5\n";
      ltc_insert_swap_buyoffer 1609114420L (hexstring_hashval "5053aadcaa71b19724e0e3b26ad09e5ef26d45731167bb24ce7e562569aa0075") 1.17e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrD9GPCXJT6tUdVybT38zWHws25uqbBMwf3",30000000000000L,3500000L));
      Printf.fprintf f "1609114420, 5053aadcaa71b19724e0e3b26ad09e5ef26d45731167bb24ce7e562569aa0075, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrD9GPCXJT6tUdVybT38zWHws25uqbBMwf3, 30000000000000, 3500000, 1.17e-4\n";
      ltc_insert_swap_buyoffer 1609403489L (hexstring_hashval "5053831ac2d254d63e1affd96b999c621250e8063344fca0b1245a59dccdcc19") 5.0e-4 (SimpleSwapBuyOffer("ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm",pfgaddrstr_addr "PrESYTwMW7GA54reTSpCGpCKitw21oybmRh",200000000000L,100000L));
      Printf.fprintf f "1609403489, 5053831ac2d254d63e1affd96b999c621250e8063344fca0b1245a59dccdcc19, ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm, PrESYTwMW7GA54reTSpCGpCKitw21oybmRh, 200000000000, 100000, 5.0e-4\n";
      ltc_insert_swap_buyoffer 1609442371L (hexstring_hashval "505313d91f3d00e3ebc40c968ef8fd6c8aead520fe5833bb129d6558eddba534") 1.77e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrJ49dkTEgDRW6KnqMMj7ESaPGD9ffdAcYk",4400000000000L,780000L));
      Printf.fprintf f "1609442371, 505313d91f3d00e3ebc40c968ef8fd6c8aead520fe5833bb129d6558eddba534, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrJ49dkTEgDRW6KnqMMj7ESaPGD9ffdAcYk, 4400000000000, 780000, 1.77e-4\n";
      ltc_insert_swap_buyoffer 1609546663L (hexstring_hashval "5053c822592af257de594353f4b4b9beea819fac9313a109293c261bdecd2fd2") 2.05e-4 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "PrLYFsNSYDFMfD3auBdWpqFEkmBrZkzYycS",38000000000000L,7800000L));
      Printf.fprintf f "1609546663, 5053c822592af257de594353f4b4b9beea819fac9313a109293c261bdecd2fd2, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, PrLYFsNSYDFMfD3auBdWpqFEkmBrZkzYycS, 38000000000000, 7800000, 2.05e-4\n";
      ltc_insert_swap_buyoffer 1609564039L (hexstring_hashval "50536e698c613c7fc039d15182e40ef21659cc06f4adbf9ef4bda78a701c4693") 0.001143 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrMrXUB2mHbkB9zyYd7GWGxvsV4vBiu27yY",140000000000L,160000L));
      Printf.fprintf f "1609564039, 50536e698c613c7fc039d15182e40ef21659cc06f4adbf9ef4bda78a701c4693, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrMrXUB2mHbkB9zyYd7GWGxvsV4vBiu27yY, 140000000000, 160000, 0.001143\n";
      ltc_insert_swap_buyoffer 1609636070L (hexstring_hashval "5053544c8e1be870a478ba57ffe08c54f93585713152318892f6e942015dfc1a") 4.62e-4 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "Pr7HzNUxEDopqcEtTi7tTUo6jKnk8kp2otF",260000000000L,120000L));
      Printf.fprintf f "1609636070, 5053544c8e1be870a478ba57ffe08c54f93585713152318892f6e942015dfc1a, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, Pr7HzNUxEDopqcEtTi7tTUo6jKnk8kp2otF, 260000000000, 120000, 4.62e-4\n";
      ltc_insert_swap_buyoffer 1609708107L (hexstring_hashval "5053d03697c13999219badf4da1ed61ffc10b62bba569d282d577bbce9808528") 4.12e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrCTRRBGxxwKcSGN75qNtAJeHQcMebSrePB",340000000000L,140000L));
      Printf.fprintf f "1609708107, 5053d03697c13999219badf4da1ed61ffc10b62bba569d282d577bbce9808528, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrCTRRBGxxwKcSGN75qNtAJeHQcMebSrePB, 340000000000, 140000, 4.12e-4\n";
      ltc_insert_swap_buyoffer 1609775044L (hexstring_hashval "5053cfbcb128cc762e7a51a085086d751555bb5d1bbc73075e16c99f047c849e") 2.45e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrMggtXQTyDsiJxXLhSUcxTcEs3NA72WEyH",1100000000000L,270000L));
      Printf.fprintf f "1609775044, 5053cfbcb128cc762e7a51a085086d751555bb5d1bbc73075e16c99f047c849e, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrMggtXQTyDsiJxXLhSUcxTcEs3NA72WEyH, 1100000000000, 270000, 2.45e-4\n";
      ltc_insert_swap_buyoffer 1609807916L (hexstring_hashval "505330b1be3919dc065411632b89a033b7824469b96f13ec38345d5a51ae63e5") 2.27e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrQp11VQD2sUqKjXJhuRfMLAXg2oqjgNahP",660000000000L,150000L));
      Printf.fprintf f "1609807916, 505330b1be3919dc065411632b89a033b7824469b96f13ec38345d5a51ae63e5, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrQp11VQD2sUqKjXJhuRfMLAXg2oqjgNahP, 660000000000, 150000, 2.27e-4\n";
      ltc_insert_swap_buyoffer 1610920224L (hexstring_hashval "5053df1d1d5581f8c5119910b07771ee3eff22f39e52e606108931fd02282575") 2.61e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrE8ddG5RPr1sZEQbznt4nayjH5ZBzc5xSL",460000000000L,120000L));
      Printf.fprintf f "1610920224, 5053df1d1d5581f8c5119910b07771ee3eff22f39e52e606108931fd02282575, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrE8ddG5RPr1sZEQbznt4nayjH5ZBzc5xSL, 460000000000, 120000, 2.61e-4\n";
      ltc_insert_swap_buyoffer 1610955850L (hexstring_hashval "5053626632336ac3a67de1b3068bff939b915e110dd85494a956b1f6c9d92939") 2.4e-4 (SimpleSwapBuyOffer("ltc1qg7vg6dqk3sgqtz62ve27d4j2zkqw8kwuw2effp",pfgaddrstr_addr "PrEREbiy42hWqUXQkCaNs7KMNpWFGACNbQp",1000000000000L,240000L));
      Printf.fprintf f "1610955850, 5053626632336ac3a67de1b3068bff939b915e110dd85494a956b1f6c9d92939, ltc1qg7vg6dqk3sgqtz62ve27d4j2zkqw8kwuw2effp, PrEREbiy42hWqUXQkCaNs7KMNpWFGACNbQp, 1000000000000, 240000, 2.4e-4\n";
      ltc_insert_swap_buyoffer 1610979256L (hexstring_hashval "505379016a8738da4c2aeac541529c4f36d01ac46df6f366d49bc7ce5228bba4") 0.001462 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrFRzsGGHyTJYotcZNtGt5a9fF6S8YRx2Wf",130000000000L,189999L));
      Printf.fprintf f "1610979256, 505379016a8738da4c2aeac541529c4f36d01ac46df6f366d49bc7ce5228bba4, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrFRzsGGHyTJYotcZNtGt5a9fF6S8YRx2Wf, 130000000000, 189999, 0.001462\n";
      ltc_insert_swap_buyoffer 1611045542L (hexstring_hashval "505338f081f3b7e87d4334dac922cbe417a56ce472e3973be62baf3467067fdb") 3.09e-4 (SimpleSwapBuyOffer("ltc1qy0gsxf59cdqxmjssdud06jug8q8fyp8wa564a0",pfgaddrstr_addr "PrNAAz8rKyrpkg3z5qA6Kgc6Hg9bjSfFXdt",970000000000L,300000L));
      Printf.fprintf f "1611045542, 505338f081f3b7e87d4334dac922cbe417a56ce472e3973be62baf3467067fdb, ltc1qy0gsxf59cdqxmjssdud06jug8q8fyp8wa564a0, PrNAAz8rKyrpkg3z5qA6Kgc6Hg9bjSfFXdt, 970000000000, 300000, 3.09e-4\n";
      ltc_insert_swap_buyoffer 1611064815L (hexstring_hashval "5053edefc57b6f867e016da6f16411b96a44f2eb8d601f94a02a40802e9e22c3") 6.92e-4 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "Pr73SSPeKR1hqQgjxcz6tLxkQXBQqYn27Ro",5200000000000L,3600000L));
      Printf.fprintf f "1611064815, 5053edefc57b6f867e016da6f16411b96a44f2eb8d601f94a02a40802e9e22c3, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, Pr73SSPeKR1hqQgjxcz6tLxkQXBQqYn27Ro, 5200000000000, 3600000, 6.92e-4\n";
      ltc_insert_swap_buyoffer 1611127000L (hexstring_hashval "50535d3aa590fe81bba82e6de490a7fc51c9d8951b66db434ee6c0a04fea9057") 5.36e-4 (SimpleSwapBuyOffer("ltc1qy0gsxf59cdqxmjssdud06jug8q8fyp8wa564a0",pfgaddrstr_addr "PrMc9LQVRtzo4daQh4EAbxqQ3pi4kUut6Zq",1100000000000L,589999L));
      Printf.fprintf f "1611127000, 50535d3aa590fe81bba82e6de490a7fc51c9d8951b66db434ee6c0a04fea9057, ltc1qy0gsxf59cdqxmjssdud06jug8q8fyp8wa564a0, PrMc9LQVRtzo4daQh4EAbxqQ3pi4kUut6Zq, 1100000000000, 589999, 5.36e-4\n";
      ltc_insert_swap_buyoffer 1611133663L (hexstring_hashval "5053de92f17436503f98d4197e39f88d265e86c91371a7a21ab182b38857acad") 3.0e-4 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "Pr3nU5o2d5EFRjMhe5wWCrPfihEBGPYa4MD",3200000000000L,960000L));
      Printf.fprintf f "1611133663, 5053de92f17436503f98d4197e39f88d265e86c91371a7a21ab182b38857acad, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, Pr3nU5o2d5EFRjMhe5wWCrPfihEBGPYa4MD, 3200000000000, 960000, 3.0e-4\n";
      ltc_insert_swap_buyoffer 1611173951L (hexstring_hashval "5053c74a14a161e033fc7e5fe09e92ff8c493f6598ac54ea7c2a22754d4e2445") 3.67e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrP9fPDps4M8TYVYhaw8P3kqTfc8dnTq3xE",300000000000L,110000L));
      Printf.fprintf f "1611173951, 5053c74a14a161e033fc7e5fe09e92ff8c493f6598ac54ea7c2a22754d4e2445, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrP9fPDps4M8TYVYhaw8P3kqTfc8dnTq3xE, 300000000000, 110000, 3.67e-4\n";
      ltc_insert_swap_buyoffer 1611194799L (hexstring_hashval "5053e01118c77b18051045cf7d9614fa28b57967c66c6e3196045c58e8339ec4") 4.09e-4 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "PrCKGpmF8hWJ2aUKNi1nkV4oJ6D5GmbvXAY",1100000000000L,450000L));
      Printf.fprintf f "1611194799, 5053e01118c77b18051045cf7d9614fa28b57967c66c6e3196045c58e8339ec4, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, PrCKGpmF8hWJ2aUKNi1nkV4oJ6D5GmbvXAY, 1100000000000, 450000, 4.09e-4\n";
      ltc_insert_swap_buyoffer 1611280589L (hexstring_hashval "5053fff9f6c7b843a17f460e583ad00018146d48c59f2e1a9435c90202982093") 5.24e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "Pr9mdSdjRL9ZQT6JafioSRNtUnpyrNLX9Kx",210000000000L,110000L));
      Printf.fprintf f "1611280589, 5053fff9f6c7b843a17f460e583ad00018146d48c59f2e1a9435c90202982093, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, Pr9mdSdjRL9ZQT6JafioSRNtUnpyrNLX9Kx, 210000000000, 110000, 5.24e-4\n";
      ltc_insert_swap_buyoffer 1611321579L (hexstring_hashval "505317874963b682287c606335bd466b439bb1fdf643a78087d63a91622595f3") 9.6e-4 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "PrBG7z1UCtk4TC5PjdphWNmd1VYuYXp3BQD",250000000000L,240000L));
      Printf.fprintf f "1611321579, 505317874963b682287c606335bd466b439bb1fdf643a78087d63a91622595f3, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, PrBG7z1UCtk4TC5PjdphWNmd1VYuYXp3BQD, 250000000000, 240000, 9.6e-4\n";
      ltc_insert_swap_buyoffer 1611358423L (hexstring_hashval "5053c017d5db36ba8b105cb720fc74ec318d2ff03346e2a0df0e4c0d6dac804c") 6.46e-4 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "Pr4Y39JFbRPUqP5nAmtUEFLgHuRPnJe3zZV",1300000000000L,840000L));
      Printf.fprintf f "1611358423, 5053c017d5db36ba8b105cb720fc74ec318d2ff03346e2a0df0e4c0d6dac804c, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, Pr4Y39JFbRPUqP5nAmtUEFLgHuRPnJe3zZV, 1300000000000, 840000, 6.46e-4\n";
      ltc_insert_swap_buyoffer 1611374628L (hexstring_hashval "50534f66a6a4ced360c95730236ad49953ca2d67c8dd36595bd021b9950f7944") 0.001176 (SimpleSwapBuyOffer("ltc1qy0gsxf59cdqxmjssdud06jug8q8fyp8wa564a0",pfgaddrstr_addr "Pr7N15LEaznK21zsTJ6aqAK8hMfraowGu2b",170000000000L,200000L));
      Printf.fprintf f "1611374628, 50534f66a6a4ced360c95730236ad49953ca2d67c8dd36595bd021b9950f7944, ltc1qy0gsxf59cdqxmjssdud06jug8q8fyp8wa564a0, Pr7N15LEaznK21zsTJ6aqAK8hMfraowGu2b, 170000000000, 200000, 0.001176\n";
      ltc_insert_swap_buyoffer 1611441863L (hexstring_hashval "5053d6ab79f0c6a3eb21efbce91e9576a3a944b976c29e47a0b590c2aaa109bd") 0.001513 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "PrKZYxzhLgExDzFadTeYbYmRFw4ZtNxWorc",390000000000L,590000L));
      Printf.fprintf f "1611441863, 5053d6ab79f0c6a3eb21efbce91e9576a3a944b976c29e47a0b590c2aaa109bd, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, PrKZYxzhLgExDzFadTeYbYmRFw4ZtNxWorc, 390000000000, 590000, 0.001513\n";
      ltc_insert_swap_buyoffer 1611486731L (hexstring_hashval "5053a4f2bfd7e0d30d9e19e0f05c0f90d9f6d13cf18730865c77ee13a6af3677") 0.001308 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrKbuJpS1HyggV8yAFf64v8AELGrdJ5DfEV",1300000000000L,1700000L));
      Printf.fprintf f "1611486731, 5053a4f2bfd7e0d30d9e19e0f05c0f90d9f6d13cf18730865c77ee13a6af3677, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrKbuJpS1HyggV8yAFf64v8AELGrdJ5DfEV, 1300000000000, 1700000, 0.001308\n";
      ltc_insert_swap_buyoffer 1611528951L (hexstring_hashval "505383412677700ba8235d5ab9f5673694a0ad936f0ce8632ae0f0cd29513d6f") 0.001429 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "Pr6iYmT4gwCxAt6WpkbCU7esmLRWFMxnB6Z",770000000000L,1100000L));
      Printf.fprintf f "1611528951, 505383412677700ba8235d5ab9f5673694a0ad936f0ce8632ae0f0cd29513d6f, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, Pr6iYmT4gwCxAt6WpkbCU7esmLRWFMxnB6Z, 770000000000, 1100000, 0.001429\n";
      ltc_insert_swap_buyoffer 1611564889L (hexstring_hashval "5053a1dcea3be10ce35781883d849f9429898d3306b4bb3478d08ea7c46149e6") 0.001818 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrBbauTi4t1hKuzoZjHU4TzQ98LZYVPc9YY",110000000000L,200000L));
      Printf.fprintf f "1611564889, 5053a1dcea3be10ce35781883d849f9429898d3306b4bb3478d08ea7c46149e6, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrBbauTi4t1hKuzoZjHU4TzQ98LZYVPc9YY, 110000000000, 200000, 0.001818\n";
      ltc_insert_swap_buyoffer 1611583426L (hexstring_hashval "5053b9932bdf4b3097adc368cf25afe3262298a01e8a2236ae3d997c078e9a58") 0.00124 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrD1yk1B8tVDgYh7DZP6H19ECYVVrz8bx55",2500000000000L,3100000L));
      Printf.fprintf f "1611583426, 5053b9932bdf4b3097adc368cf25afe3262298a01e8a2236ae3d997c078e9a58, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrD1yk1B8tVDgYh7DZP6H19ECYVVrz8bx55, 2500000000000, 3100000, 0.00124\n";
      ltc_insert_swap_buyoffer 1611599639L (hexstring_hashval "5053e82e7dee13b2d00646c0f1addec9e015dc801f3fcaac7238b650789d5cc8") 0.001385 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "PrLy6PHCf5FnbZFd3P5cbgGR5uZj2MGyk7q",2600000000000L,3600000L));
      Printf.fprintf f "1611599639, 5053e82e7dee13b2d00646c0f1addec9e015dc801f3fcaac7238b650789d5cc8, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, PrLy6PHCf5FnbZFd3P5cbgGR5uZj2MGyk7q, 2600000000000, 3600000, 0.001385\n";
      ltc_insert_swap_buyoffer 1611671674L (hexstring_hashval "5053af26d4eedc1d721769643f4cdbb3f6235c463735dd97e12cce10f8e9e3e1") 0.001133 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "Pr66hpQeXeyYG1Bz2s8D3F4q9edJ1JNrQMD",150000000000L,169999L));
      Printf.fprintf f "1611671674, 5053af26d4eedc1d721769643f4cdbb3f6235c463735dd97e12cce10f8e9e3e1, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, Pr66hpQeXeyYG1Bz2s8D3F4q9edJ1JNrQMD, 150000000000, 169999, 0.001133\n";
      ltc_insert_swap_buyoffer 1611688217L (hexstring_hashval "50535a88f5b99340f44c3fd4a257b99352b76914fb49950dc47a779e8eb31444") 0.002333 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "PrS8JGfKcW2AdaNvPM8gSZqyfBdQF1CsToi",330000000000L,769999L));
      Printf.fprintf f "1611688217, 50535a88f5b99340f44c3fd4a257b99352b76914fb49950dc47a779e8eb31444, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, PrS8JGfKcW2AdaNvPM8gSZqyfBdQF1CsToi, 330000000000, 769999, 0.002333\n";
      ltc_insert_swap_buyoffer 1611891928L (hexstring_hashval "505321e1f2e6762d94b79d66a020ccdda6d62f2c43df1bb7f988dab10c9bba58") 7.22e-4 (SimpleSwapBuyOffer("ltc1qg7vg6dqk3sgqtz62ve27d4j2zkqw8kwuw2effp",pfgaddrstr_addr "PrCACPX6vVgoJ3tp6jPJisiErGkVX1gLNsj",180000000000L,130000L));
      Printf.fprintf f "1611891928, 505321e1f2e6762d94b79d66a020ccdda6d62f2c43df1bb7f988dab10c9bba58, ltc1qg7vg6dqk3sgqtz62ve27d4j2zkqw8kwuw2effp, PrCACPX6vVgoJ3tp6jPJisiErGkVX1gLNsj, 180000000000, 130000, 7.22e-4\n";
      ltc_insert_swap_buyoffer 1612019140L (hexstring_hashval "505337c31baae5039156a0582c05c02470346f0a2824acc4f92c6ad64b0fe230") 0.001205 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "PrRkpKnV6jMSCdKRsmi7cLHUKjozhzQuqSh",780000000000L,940000L));
      Printf.fprintf f "1612019140, 505337c31baae5039156a0582c05c02470346f0a2824acc4f92c6ad64b0fe230, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, PrRkpKnV6jMSCdKRsmi7cLHUKjozhzQuqSh, 780000000000, 940000, 0.001205\n";
      ltc_insert_swap_buyoffer 1612033920L (hexstring_hashval "505338341b9bf590b41896cdfc75ab468af53a88cab485216f12261e476e4e11") 7.92e-4 (SimpleSwapBuyOffer("ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32",pfgaddrstr_addr "PrGg8qSJNwhgZ7uo28Rh2AbBv5AiqL36Xo6",240000000000L,189999L));
      Printf.fprintf f "1612033920, 505338341b9bf590b41896cdfc75ab468af53a88cab485216f12261e476e4e11, ltc1q66gu0drn457gm2xdxkushtrlphwem83f9pmn32, PrGg8qSJNwhgZ7uo28Rh2AbBv5AiqL36Xo6, 240000000000, 189999, 7.92e-4\n";
      ltc_insert_swap_buyoffer 1612052315L (hexstring_hashval "505360aba2351d4868e31fa04ab7341c35043f09c6787a25337fcf8f609a8983") 0.001519 (SimpleSwapBuyOffer("ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm",pfgaddrstr_addr "PrF8xo3upFBVmbFQXfUR2GGFm83ntpiuuPB",790000000000L,1200000L));
      Printf.fprintf f "1612052315, 505360aba2351d4868e31fa04ab7341c35043f09c6787a25337fcf8f609a8983, ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm, PrF8xo3upFBVmbFQXfUR2GGFm83ntpiuuPB, 790000000000, 1200000, 0.001519\n";
      ltc_insert_swap_buyoffer 1612379649L (hexstring_hashval "5053ae7ec10f958726c2e5482f69ca1a2e12b5d950946b6462d3dd24f4feafc6") 0.001 (SimpleSwapBuyOffer("ltc1qg7vg6dqk3sgqtz62ve27d4j2zkqw8kwuw2effp",pfgaddrstr_addr "PrFpuPsUCB5mDapgYtx3dvdDHW3VA8ag2eR",280000000000L,279999L));
      Printf.fprintf f "1612379649, 5053ae7ec10f958726c2e5482f69ca1a2e12b5d950946b6462d3dd24f4feafc6, ltc1qg7vg6dqk3sgqtz62ve27d4j2zkqw8kwuw2effp, PrFpuPsUCB5mDapgYtx3dvdDHW3VA8ag2eR, 280000000000, 279999, 0.001\n";
      ltc_insert_swap_buyoffer 1612461231L (hexstring_hashval "5053d8e481694b76889a4fb952f2627ac39a6f9ef683c0f3226985cea5df87e1") 0.001806 (SimpleSwapBuyOffer("ltc1qe9lxtl883zg6u30gna7d9yx3adl44nquca8frp",pfgaddrstr_addr "PrEWQKXH42uL1voUzKBmFMUPiBdk8usAum7",3600000000000L,6500000L));
      Printf.fprintf f "1612461231, 5053d8e481694b76889a4fb952f2627ac39a6f9ef683c0f3226985cea5df87e1, ltc1qe9lxtl883zg6u30gna7d9yx3adl44nquca8frp, PrEWQKXH42uL1voUzKBmFMUPiBdk8usAum7, 3600000000000, 6500000, 0.001806\n";
      ltc_insert_swap_buyoffer 1612532654L (hexstring_hashval "505334c9d41891c5d7d98c620f01e55d7c05c1b66197ae63797e6dae532985ef") 0.001048 (SimpleSwapBuyOffer("ltc1qe9lxtl883zg6u30gna7d9yx3adl44nquca8frp",pfgaddrstr_addr "Pr7NUC66bUHkv4DK6YxPPffwi6gVzabrqxt",4200000000000L,4400000L));
      Printf.fprintf f "1612532654, 505334c9d41891c5d7d98c620f01e55d7c05c1b66197ae63797e6dae532985ef, ltc1qe9lxtl883zg6u30gna7d9yx3adl44nquca8frp, Pr7NUC66bUHkv4DK6YxPPffwi6gVzabrqxt, 4200000000000, 4400000, 0.001048\n";
      ltc_insert_swap_buyoffer 1612564431L (hexstring_hashval "5053a3344d5c8b79e5ffe8213eedbc22e3a2c22221b6b5fc1c0959f7606a536d") 0.001582 (SimpleSwapBuyOffer("ltc1qe9lxtl883zg6u30gna7d9yx3adl44nquca8frp",pfgaddrstr_addr "PrAZsVztrTaVXLbMrwKNJJiS5gizATXe5X4",5500000000000L,8700000L));
      Printf.fprintf f "1612564431, 5053a3344d5c8b79e5ffe8213eedbc22e3a2c22221b6b5fc1c0959f7606a536d, ltc1qe9lxtl883zg6u30gna7d9yx3adl44nquca8frp, PrAZsVztrTaVXLbMrwKNJJiS5gizATXe5X4, 5500000000000, 8700000, 0.001582\n";
      ltc_insert_swap_buyoffer 1612601866L (hexstring_hashval "50536b0a0c88120b597afa0aa3b8ca527ba69f4a5c854b296f50bb1c43e6f32b") 0.001395 (SimpleSwapBuyOffer("ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm",pfgaddrstr_addr "PrKDJFp4s19A4YLcV7CX2PMThrEMMdgZvcT",430000000000L,600000L));
      Printf.fprintf f "1612601866, 50536b0a0c88120b597afa0aa3b8ca527ba69f4a5c854b296f50bb1c43e6f32b, ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm, PrKDJFp4s19A4YLcV7CX2PMThrEMMdgZvcT, 430000000000, 600000, 0.001395\n";
      ltc_insert_swap_buyoffer 1612895234L (hexstring_hashval "5053402a82caafb6231dbf961605bb0c7744318ea00a485f8eacaf56f6d7fc9f") 0.001719 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "PrDi378WCnpVx9kJ2S6m9bcpCxTzNDKRPxn",64000000000L,110000L));
      Printf.fprintf f "1612895234, 5053402a82caafb6231dbf961605bb0c7744318ea00a485f8eacaf56f6d7fc9f, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, PrDi378WCnpVx9kJ2S6m9bcpCxTzNDKRPxn, 64000000000, 110000, 0.001719\n";
      ltc_insert_swap_buyoffer 1612911090L (hexstring_hashval "5053ba54b394ba04d0ae4572da94d307c961e008f52efe465316fbae9e83e7f1") 0.001591 (SimpleSwapBuyOffer("ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm",pfgaddrstr_addr "PrBVTTvrGieRoX1QnrDjtZRmCaoHPe3t88t",2200000000000L,3500000L));
      Printf.fprintf f "1612911090, 5053ba54b394ba04d0ae4572da94d307c961e008f52efe465316fbae9e83e7f1, ltc1q9esaksslpd96yalvxswxrnwsvq0apcyyamcrgm, PrBVTTvrGieRoX1QnrDjtZRmCaoHPe3t88t, 2200000000000, 3500000, 0.001591\n";
      ltc_insert_swap_buyoffer 1615568153L (hexstring_hashval "50538872d801beaaa0134c8fe99caa18f76e1e00d8000d5feb7de94a8bad27b3") 0.003939 (SimpleSwapBuyOffer("ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0",pfgaddrstr_addr "PrCNvt3BgXdV4Qhy8GePv2omr1oVL6mwsgs",99000000000L,390000L));
      Printf.fprintf f "1615568153, 50538872d801beaaa0134c8fe99caa18f76e1e00d8000d5feb7de94a8bad27b3, ltc1q2fxj8hc00myn7dy7w9vq9pf8mvvuzsl8swy7x0, PrCNvt3BgXdV4Qhy8GePv2omr1oVL6mwsgs, 99000000000, 390000, 0.003939\n";
      ltc_insert_swap_buyoffer 1616844566L (hexstring_hashval "5053bfda98ef2a83a71b15a41124074c9918a472a0184c0fd1a907058aee2796") 6.0e-4 (SimpleSwapBuyOffer("ltc1qedr2vxx2d2cg90ft94wwqx7hldpaght7k0tt3f",pfgaddrstr_addr "PrDUqmXCfqasrQ58aGbQtAj6upZSaPMAqYo",1000000000000L,600000L));
      Printf.fprintf f "1616844566, 5053bfda98ef2a83a71b15a41124074c9918a472a0184c0fd1a907058aee2796, ltc1qedr2vxx2d2cg90ft94wwqx7hldpaght7k0tt3f, PrDUqmXCfqasrQ58aGbQtAj6upZSaPMAqYo, 1000000000000, 600000, 6.0e-4\n";
      ltc_insert_swap_buyoffer 1616928239L (hexstring_hashval "50530441f2728305407ebcef9e0192eb99f44387a008c47034de5dbbe82bbe21") 5.5e-4 (SimpleSwapBuyOffer("ltc1qedr2vxx2d2cg90ft94wwqx7hldpaght7k0tt3f",pfgaddrstr_addr "Pr9q9TBs9viPJmmkB2AY76HH7nguQxyk3qL",500010000000000L,275005500L));
      Printf.fprintf f "1616928239, 50530441f2728305407ebcef9e0192eb99f44387a008c47034de5dbbe82bbe21, ltc1qedr2vxx2d2cg90ft94wwqx7hldpaght7k0tt3f, Pr9q9TBs9viPJmmkB2AY76HH7nguQxyk3qL, 500010000000000, 275005500, 5.5e-4\n";
      ltc_insert_swap_buyoffer 1617766602L (hexstring_hashval "5053bf1a3e427b6991353fdebd4fc22ec122e3cf4dcf3757f55ecf447165c010") 4.0e-4 (SimpleSwapBuyOffer("ltc1qedr2vxx2d2cg90ft94wwqx7hldpaght7k0tt3f",pfgaddrstr_addr "Pr6jxmG9BEdsnaoqZMMzdJjW3bJyjdRK5ze",500010000000000L,200100000L));
      Printf.fprintf f "1617766602, 5053bf1a3e427b6991353fdebd4fc22ec122e3cf4dcf3757f55ecf447165c010, ltc1qedr2vxx2d2cg90ft94wwqx7hldpaght7k0tt3f, Pr6jxmG9BEdsnaoqZMMzdJjW3bJyjdRK5ze, 500010000000000, 200100000, 4.0e-4\n";
      ltc_insert_swap_buyoffer 1620245374L (hexstring_hashval "5053a5e45011a1746fa1c290f5801209e86c6e525342daf2a98b992502766632") 5.0e-4 (SimpleSwapBuyOffer("ltc1q9hhxujnvmmz97wcxd2q8snxtavhhjzw7e3c8w0",pfgaddrstr_addr "PrRWBP9rmU3LXsieMUBGVFYKRVGkCLoSQKD",100000000000000L,50000000L));
      Printf.fprintf f "1620245374, 5053a5e45011a1746fa1c290f5801209e86c6e525342daf2a98b992502766632, ltc1q9hhxujnvmmz97wcxd2q8snxtavhhjzw7e3c8w0, PrRWBP9rmU3LXsieMUBGVFYKRVGkCLoSQKD, 100000000000000, 50000000, 5.0e-4\n";
      ltc_insert_swap_buyoffer 1621972668L (hexstring_hashval "5053282382a7919fd14acad4ab3f4eb1153bb462d0ca96475bfbd8da21c39971") 5.0e-4 (SimpleSwapBuyOffer("ltc1q98w7qavl50rvlytl5uw75ljwp5dw4f7cl7t5sy",pfgaddrstr_addr "PrRSiTEMpGaUwKrKXxkHpY2aHq2A2K6pCvu",20000000000000L,10000000L));
      Printf.fprintf f "1621972668, 5053282382a7919fd14acad4ab3f4eb1153bb462d0ca96475bfbd8da21c39971, ltc1q98w7qavl50rvlytl5uw75ljwp5dw4f7cl7t5sy, PrRSiTEMpGaUwKrKXxkHpY2aHq2A2K6pCvu, 20000000000000, 10000000, 5.0e-4\n";
      ltc_insert_swap_buyoffer 1622136908L (hexstring_hashval "50531ff312ae6f57e6737bbbec5a52210e5ddddbec5dbae1f113d11f46911156") 0.001 (SimpleSwapBuyOffer("ltc1q98w7qavl50rvlytl5uw75ljwp5dw4f7cl7t5sy",pfgaddrstr_addr "PrRSiTEMpGaUwKrKXxkHpY2aHq2A2K6pCvu",10000000000000L,10000000L));
      Printf.fprintf f "1622136908, 50531ff312ae6f57e6737bbbec5a52210e5ddddbec5dbae1f113d11f46911156, ltc1q98w7qavl50rvlytl5uw75ljwp5dw4f7cl7t5sy, PrRSiTEMpGaUwKrKXxkHpY2aHq2A2K6pCvu, 10000000000000, 10000000, 0.001\n";
      ltc_insert_swap_buyoffer 1622313185L (hexstring_hashval "50536b3dc7c232f73c4fbf4e3b688080399bb3216cac433ca99cc2e246df90f0") 0.002 (SimpleSwapBuyOffer("ltc1q98w7qavl50rvlytl5uw75ljwp5dw4f7cl7t5sy",pfgaddrstr_addr "PrRSiTEMpGaUwKrKXxkHpY2aHq2A2K6pCvu",5000000000000L,10000000L));
      Printf.fprintf f "1622313185, 50536b3dc7c232f73c4fbf4e3b688080399bb3216cac433ca99cc2e246df90f0, ltc1q98w7qavl50rvlytl5uw75ljwp5dw4f7cl7t5sy, PrRSiTEMpGaUwKrKXxkHpY2aHq2A2K6pCvu, 5000000000000, 10000000, 0.002\n";
      ltc_insert_swap_buyoffer 1622490701L (hexstring_hashval "5053329e2f4badb3aa99a2978038adcdc4a834116f997f8ec2063d16c3d8c5b7") 0.0015 (SimpleSwapBuyOffer("ltc1q98w7qavl50rvlytl5uw75ljwp5dw4f7cl7t5sy",pfgaddrstr_addr "PrRSiTEMpGaUwKrKXxkHpY2aHq2A2K6pCvu",10000000000000L,15000000L));
      Printf.fprintf f "1622490701, 5053329e2f4badb3aa99a2978038adcdc4a834116f997f8ec2063d16c3d8c5b7, ltc1q98w7qavl50rvlytl5uw75ljwp5dw4f7cl7t5sy, PrRSiTEMpGaUwKrKXxkHpY2aHq2A2K6pCvu, 10000000000000, 15000000, 0.0015\n";
      ltc_insert_swap_buyoffer 1626533371L (hexstring_hashval "505357ebf525fccf1c82f4bff2b695efd84a9d28237e0244fccc2fc82441f0bc") 5.0e-4 (SimpleSwapBuyOffer("ltc1q809h3d9yy55yxdrsplwncpq3gr7ms6uazkfpfu",pfgaddrstr_addr "PrEhicEYocQCSXP2Y3fYJngba3JUnbvpAyG",1000000000000L,500000L));
      Printf.fprintf f "1626533371, 505357ebf525fccf1c82f4bff2b695efd84a9d28237e0244fccc2fc82441f0bc, ltc1q809h3d9yy55yxdrsplwncpq3gr7ms6uazkfpfu, PrEhicEYocQCSXP2Y3fYJngba3JUnbvpAyG, 1000000000000, 500000, 5.0e-4\n";
      ltc_insert_swap_buyoffer 1626554291L (hexstring_hashval "50537479e796bfb22f65e533d866b2b1a46b3c4670b2651b2747dcda25044cb4") 4.5e-4 (SimpleSwapBuyOffer("ltc1q809h3d9yy55yxdrsplwncpq3gr7ms6uazkfpfu",pfgaddrstr_addr "PrEhicEYocQCSXP2Y3fYJngba3JUnbvpAyG",1000000000000L,450000L));
      Printf.fprintf f "1626554291, 50537479e796bfb22f65e533d866b2b1a46b3c4670b2651b2747dcda25044cb4, ltc1q809h3d9yy55yxdrsplwncpq3gr7ms6uazkfpfu, PrEhicEYocQCSXP2Y3fYJngba3JUnbvpAyG, 1000000000000, 450000, 4.5e-4\n";
      ltc_insert_swap_buyoffer 1626611677L (hexstring_hashval "50537cc79fa94e6117936c2e3e9e4a236a5d39c0f469d1023df7d15117673ec2") 4.0e-4 (SimpleSwapBuyOffer("ltc1q809h3d9yy55yxdrsplwncpq3gr7ms6uazkfpfu",pfgaddrstr_addr "PrEhicEYocQCSXP2Y3fYJngba3JUnbvpAyG",1000000000000L,400000L));
      Printf.fprintf f "1626611677, 50537cc79fa94e6117936c2e3e9e4a236a5d39c0f469d1023df7d15117673ec2, ltc1q809h3d9yy55yxdrsplwncpq3gr7ms6uazkfpfu, PrEhicEYocQCSXP2Y3fYJngba3JUnbvpAyG, 1000000000000, 400000, 4.0e-4\n";
      ltc_insert_swap_buyoffer 1626641181L (hexstring_hashval "5053cc4bd4db2703152e57217d6bfc10f0b2878916312b0d0bae71e1e7e88764") 3.5e-4 (SimpleSwapBuyOffer("ltc1q809h3d9yy55yxdrsplwncpq3gr7ms6uazkfpfu",pfgaddrstr_addr "PrEhicEYocQCSXP2Y3fYJngba3JUnbvpAyG",1000000000000L,350000L));
      Printf.fprintf f "1626641181, 5053cc4bd4db2703152e57217d6bfc10f0b2878916312b0d0bae71e1e7e88764, ltc1q809h3d9yy55yxdrsplwncpq3gr7ms6uazkfpfu, PrEhicEYocQCSXP2Y3fYJngba3JUnbvpAyG, 1000000000000, 350000, 3.5e-4\n";
      ltc_insert_swap_buyoffer 1632510483L (hexstring_hashval "5053291367be3a13e4ea765d7b815bcfd833699895a3437a07971b4ff12b1294") 4.0e-4 (SimpleSwapBuyOffer("ltc1q84ae27j2c3rdqf6d0tjwnefsc5m442aq4x9dr2",pfgaddrstr_addr "Pr7MrmUUj8e1QSPf6AgMfA5SS8PcAN7chha",1000000000000L,400000L));
      Printf.fprintf f "1632510483, 5053291367be3a13e4ea765d7b815bcfd833699895a3437a07971b4ff12b1294, ltc1q84ae27j2c3rdqf6d0tjwnefsc5m442aq4x9dr2, Pr7MrmUUj8e1QSPf6AgMfA5SS8PcAN7chha, 1000000000000, 400000, 4.0e-4\n";
      ltc_insert_swap_buyoffer 1639516380L (hexstring_hashval "5053d52fb3cdb15afa828152eab3e5d9d92c33e6fb4801fd73034d69e81ab321") 3.0e-4 (SimpleSwapBuyOffer("ltc1qp95ry6wkpxlgamnz92pugyp2p85rv6zt4p2js7",pfgaddrstr_addr "PrRieiHGBxArhoxBwbGQWYyULJfPK6fyTbU",50010000000000L,15000000L));
      Printf.fprintf f "1639516380, 5053d52fb3cdb15afa828152eab3e5d9d92c33e6fb4801fd73034d69e81ab321, ltc1qp95ry6wkpxlgamnz92pugyp2p85rv6zt4p2js7, PrRieiHGBxArhoxBwbGQWYyULJfPK6fyTbU, 50010000000000, 15000000, 3.0e-4\n";
      ltc_insert_swap_buyoffer 1641739287L (hexstring_hashval "5053847e932bc3c5202ffa282918ca266866df9b543bac462906bb64d84a079e") 0.001 (SimpleSwapBuyOffer("ltc1q04h3rs8tnrmermalaz8tpsr8p453ckhcld3dau",pfgaddrstr_addr "PrPGtQwQMi8KR75Y5rna6ydAenqeGEDVnEj",300000000000000L,300000000L));
      Printf.fprintf f "1641739287, 5053847e932bc3c5202ffa282918ca266866df9b543bac462906bb64d84a079e, ltc1q04h3rs8tnrmermalaz8tpsr8p453ckhcld3dau, PrPGtQwQMi8KR75Y5rna6ydAenqeGEDVnEj, 300000000000000, 300000000, 0.001\n";
      ltc_insert_swap_buyoffer 1642612946L (hexstring_hashval "50532ec79a5229be9d6b1f1fd6020428e83d0489de6e6b35feeeb32ee8755c37") 0.002 (SimpleSwapBuyOffer("ltc1q04h3rs8tnrmermalaz8tpsr8p453ckhcld3dau",pfgaddrstr_addr "PrPGtQwQMi8KR75Y5rna6ydAenqeGEDVnEj",150000000000000L,299990000L));
      Printf.fprintf f "1642612946, 50532ec79a5229be9d6b1f1fd6020428e83d0489de6e6b35feeeb32ee8755c37, ltc1q04h3rs8tnrmermalaz8tpsr8p453ckhcld3dau, PrPGtQwQMi8KR75Y5rna6ydAenqeGEDVnEj, 150000000000000, 299990000, 0.002\n";
      ltc_insert_swap_buyoffer 1642888506L (hexstring_hashval "505378c3ce4f84ee60a3a14ff85796878b7aeefe312d093a2d29db8d01dd5053") 0.004 (SimpleSwapBuyOffer("ltc1q04h3rs8tnrmermalaz8tpsr8p453ckhcld3dau",pfgaddrstr_addr "PrPGtQwQMi8KR75Y5rna6ydAenqeGEDVnEj",75000000000000L,299988000L));
      Printf.fprintf f "1642888506, 505378c3ce4f84ee60a3a14ff85796878b7aeefe312d093a2d29db8d01dd5053, ltc1q04h3rs8tnrmermalaz8tpsr8p453ckhcld3dau, PrPGtQwQMi8KR75Y5rna6ydAenqeGEDVnEj, 75000000000000, 299988000, 0.004\n";
      ltc_insert_swap_buyoffer 1643734614L (hexstring_hashval "5053ac30596cc727b392ca5fd8cf0e2037ab1ee1cb062d1a8bd648a8da89c6a2") 0.008 (SimpleSwapBuyOffer("ltc1q04h3rs8tnrmermalaz8tpsr8p453ckhcld3dau",pfgaddrstr_addr "PrPGtQwQMi8KR75Y5rna6ydAenqeGEDVnEj",37500000000000L,299986000L));
      Printf.fprintf f "1643734614, 5053ac30596cc727b392ca5fd8cf0e2037ab1ee1cb062d1a8bd648a8da89c6a2, ltc1q04h3rs8tnrmermalaz8tpsr8p453ckhcld3dau, PrPGtQwQMi8KR75Y5rna6ydAenqeGEDVnEj, 37500000000000, 299986000, 0.008\n";
      ltc_insert_swap_buyoffer 1649099307L (hexstring_hashval "505341d51b6a2c069b2a197a611228de0091ce65057d06596c55c5de98b58d32") 5.0e-4 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrQsoVzhCS2jZKgbBKc8QtR98aQnG5B7yV6",1000000000000L,500000L));
      Printf.fprintf f "1649099307, 505341d51b6a2c069b2a197a611228de0091ce65057d06596c55c5de98b58d32, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrQsoVzhCS2jZKgbBKc8QtR98aQnG5B7yV6, 1000000000000, 500000, 5.0e-4\n";
      ltc_insert_swap_buyoffer 1649100715L (hexstring_hashval "5053dddc266145699c7ab04e1baf2ab0ff249272d06bfa05652173de536f229d") 0.001 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrFGFVYFVoZieNukwfP7EiJMPq9vetJCUKP",1000000000000L,1000000L));
      Printf.fprintf f "1649100715, 5053dddc266145699c7ab04e1baf2ab0ff249272d06bfa05652173de536f229d, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrFGFVYFVoZieNukwfP7EiJMPq9vetJCUKP, 1000000000000, 1000000, 0.001\n";
      ltc_insert_swap_buyoffer 1649175613L (hexstring_hashval "5053d7cbe766226319aed8b42dc2b0e5632ecf4af40240bdf78334bb676bf061") 0.005 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrLwYAF5ixWL48kREP9DcfiPCeDyoJbdUL3",1000000000000L,5000000L));
      Printf.fprintf f "1649175613, 5053d7cbe766226319aed8b42dc2b0e5632ecf4af40240bdf78334bb676bf061, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrLwYAF5ixWL48kREP9DcfiPCeDyoJbdUL3, 1000000000000, 5000000, 0.005\n";
      ltc_insert_swap_buyoffer 1649176003L (hexstring_hashval "50530d91baefd14f1dcfa94506590f8410194a72d832ef1f35e7f867b029f3d3") 0.01 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrNn5CL4sjLpq3YfTpw9nPiLPtykBK2dzGZ",1000000000000L,10000000L));
      Printf.fprintf f "1649176003, 50530d91baefd14f1dcfa94506590f8410194a72d832ef1f35e7f867b029f3d3, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrNn5CL4sjLpq3YfTpw9nPiLPtykBK2dzGZ, 1000000000000, 10000000, 0.01\n";
      ltc_insert_swap_buyoffer 1649271103L (hexstring_hashval "5053a2dc7af39830a3f47cc83ec2cfc682cf24fb76d99a7bd55b7d2609b66813") 0.05 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrDnAEp9haAKyq8QSD9bQ1WYGcqzryzZWjq",200000000000L,10000000L));
      Printf.fprintf f "1649271103, 5053a2dc7af39830a3f47cc83ec2cfc682cf24fb76d99a7bd55b7d2609b66813, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrDnAEp9haAKyq8QSD9bQ1WYGcqzryzZWjq, 200000000000, 10000000, 0.05\n";
      ltc_insert_swap_buyoffer 1649358326L (hexstring_hashval "50532d7224987140174374586ecb1e89422f783b3381f072e9e356fd8c6cdc76") 0.03 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrLwYAF5ixWL48kREP9DcfiPCeDyoJbdUL3",200000000000L,6000000L));
      Printf.fprintf f "1649358326, 50532d7224987140174374586ecb1e89422f783b3381f072e9e356fd8c6cdc76, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrLwYAF5ixWL48kREP9DcfiPCeDyoJbdUL3, 200000000000, 6000000, 0.03\n";
      ltc_insert_swap_buyoffer 1649358326L (hexstring_hashval "505314cd6b73ca3b30c6622804e39781d8a988d69474f627adba7463996fce52") 0.015 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrNn5CL4sjLpq3YfTpw9nPiLPtykBK2dzGZ",200000000000L,3000000L));
      Printf.fprintf f "1649358326, 505314cd6b73ca3b30c6622804e39781d8a988d69474f627adba7463996fce52, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrNn5CL4sjLpq3YfTpw9nPiLPtykBK2dzGZ, 200000000000, 3000000, 0.015\n";
      ltc_insert_swap_buyoffer 1649363297L (hexstring_hashval "5053e4bebf7bdbb26dca7817594a2b7a4248ccc2f5b400763903b56591a57ac6") 0.02 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrNn5CL4sjLpq3YfTpw9nPiLPtykBK2dzGZ",200000000000L,4000000L));
      Printf.fprintf f "1649363297, 5053e4bebf7bdbb26dca7817594a2b7a4248ccc2f5b400763903b56591a57ac6, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrNn5CL4sjLpq3YfTpw9nPiLPtykBK2dzGZ, 200000000000, 4000000, 0.02\n";
      ltc_insert_swap_buyoffer 1649379406L (hexstring_hashval "50531f60f50576bda8629d49b8fdc2bfa2152860af05e27b194d8e31760f5e09") 0.0175 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrQsoVzhCS2jZKgbBKc8QtR98aQnG5B7yV6",200000000000L,3500000L));
      Printf.fprintf f "1649379406, 50531f60f50576bda8629d49b8fdc2bfa2152860af05e27b194d8e31760f5e09, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrQsoVzhCS2jZKgbBKc8QtR98aQnG5B7yV6, 200000000000, 3500000, 0.0175\n";
      ltc_insert_swap_buyoffer 1649430927L (hexstring_hashval "505347bd686f5faa2e8a85159708a6b99ce323ec8ffe32429418131e7051a16a") 0.01625 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrK3vMLvWDs5bSAc3SCXuNgL3TkRAm3wS9Q",200000000000L,3250000L));
      Printf.fprintf f "1649430927, 505347bd686f5faa2e8a85159708a6b99ce323ec8ffe32429418131e7051a16a, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrK3vMLvWDs5bSAc3SCXuNgL3TkRAm3wS9Q, 200000000000, 3250000, 0.01625\n";
      ltc_insert_swap_buyoffer 1649510012L (hexstring_hashval "50538ae71f42d62ad5397fb024fa4f1b6fce1c743a168065cede077b6572238a") 0.01625 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrLuvU71FjmXWjqBdzWhYPyCtr7X5Tr4JgH",10000000000000L,162500000L));
      Printf.fprintf f "1649510012, 50538ae71f42d62ad5397fb024fa4f1b6fce1c743a168065cede077b6572238a, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrLuvU71FjmXWjqBdzWhYPyCtr7X5Tr4JgH, 10000000000000, 162500000, 0.01625\n";
      ltc_insert_swap_buyoffer 1649596121L (hexstring_hashval "50535aa0b5af16fb0e547a4a824ca592fa625eae5a02d81df9a8f3763a5eea9f") 0.01625 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "Pr7xeJvLkAfH13ePqtEBS6UBRx78JUs54th",20000000000000L,325000000L));
      Printf.fprintf f "1649596121, 50535aa0b5af16fb0e547a4a824ca592fa625eae5a02d81df9a8f3763a5eea9f, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, Pr7xeJvLkAfH13ePqtEBS6UBRx78JUs54th, 20000000000000, 325000000, 0.01625\n";
      ltc_insert_swap_buyoffer 1649695104L (hexstring_hashval "505340e95aab1988c11cae61fd070dcc7761367cfc13076bb084d2558f0884ec") 0.01625 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAjPjsh1J5qKYoKa4gk6BscVaTy75wtSUb",40000000000000L,650000000L));
      Printf.fprintf f "1649695104, 505340e95aab1988c11cae61fd070dcc7761367cfc13076bb084d2558f0884ec, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAjPjsh1J5qKYoKa4gk6BscVaTy75wtSUb, 40000000000000, 650000000, 0.01625\n";
      ltc_insert_swap_buyoffer 1649770101L (hexstring_hashval "5053d21bbc16c2d154640ed69f8c453cbec697916e942284830e37bb0f418fab") 0.01625 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAjPjsh1J5qKYoKa4gk6BscVaTy75wtSUb",63300000000000L,1028624900L));
      Printf.fprintf f "1649770101, 5053d21bbc16c2d154640ed69f8c453cbec697916e942284830e37bb0f418fab, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAjPjsh1J5qKYoKa4gk6BscVaTy75wtSUb, 63300000000000, 1028624900, 0.01625\n";
      ltc_insert_swap_buyoffer 1650035216L (hexstring_hashval "50538ee1108ec802886b695668fcc8ff72e9a12bbd7fa1b33d3c4abc3e3f8f20") 0.0175 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAjPjsh1J5qKYoKa4gk6BscVaTy75wtSUb",40000000000000L,700000000L));
      Printf.fprintf f "1650035216, 50538ee1108ec802886b695668fcc8ff72e9a12bbd7fa1b33d3c4abc3e3f8f20, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAjPjsh1J5qKYoKa4gk6BscVaTy75wtSUb, 40000000000000, 700000000, 0.0175\n";
      ltc_insert_swap_buyoffer 1650208861L (hexstring_hashval "50539eff5d6820b550015c119245b141a3e12a9306c1d00c4e3b91f701bef8e7") 0.02 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAjPjsh1J5qKYoKa4gk6BscVaTy75wtSUb",20000000000000L,400000000L));
      Printf.fprintf f "1650208861, 50539eff5d6820b550015c119245b141a3e12a9306c1d00c4e3b91f701bef8e7, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAjPjsh1J5qKYoKa4gk6BscVaTy75wtSUb, 20000000000000, 400000000, 0.02\n";
      ltc_insert_swap_buyoffer 1650292443L (hexstring_hashval "50533d98b80139eae1727f262013cae551eeb8bd9e58c5f24d36f4e69d8e39b2") 0.02 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrEzNHyMBZBi6nLarp9czpeSEHAFCNkoYzR",15000000000000L,300000000L));
      Printf.fprintf f "1650292443, 50533d98b80139eae1727f262013cae551eeb8bd9e58c5f24d36f4e69d8e39b2, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrEzNHyMBZBi6nLarp9czpeSEHAFCNkoYzR, 15000000000000, 300000000, 0.02\n";
      ltc_insert_swap_buyoffer 1650827983L (hexstring_hashval "5053173f7a19ca2881da09a738d81f694207eff495351272844d43cab516a017") 0.03 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrEzNHyMBZBi6nLarp9czpeSEHAFCNkoYzR",7500000000000L,225000000L));
      Printf.fprintf f "1650827983, 5053173f7a19ca2881da09a738d81f694207eff495351272844d43cab516a017, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrEzNHyMBZBi6nLarp9czpeSEHAFCNkoYzR, 7500000000000, 225000000, 0.03\n";
      ltc_insert_swap_buyoffer 1651175182L (hexstring_hashval "5053d59a2c733eddefd53fd9bdb45bd766c16e0613e87b2f174eb2bfe2dab349") 0.02056 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2",90000000000000L,1850400000L));
      Printf.fprintf f "1651175182, 5053d59a2c733eddefd53fd9bdb45bd766c16e0613e87b2f174eb2bfe2dab349, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2, 90000000000000, 1850400000, 0.02056\n";
      ltc_insert_swap_buyoffer 1652381192L (hexstring_hashval "50534d7984f6daeceb2eba830d5104335f1b847da870ac3ae4eacc6763e518a5") 0.03 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2",50000000000000L,1500000000L));
      Printf.fprintf f "1652381192, 50534d7984f6daeceb2eba830d5104335f1b847da870ac3ae4eacc6763e518a5, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2, 50000000000000, 1500000000, 0.03\n";
      ltc_insert_swap_buyoffer 1652382089L (hexstring_hashval "5053ae52e980e5e5c8ebd9bdedf1a8cbe239f96d4e19a443f686cf5b0049c6b9") 0.035 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAjPjsh1J5qKYoKa4gk6BscVaTy75wtSUb",35000000000000L,1225000000L));
      Printf.fprintf f "1652382089, 5053ae52e980e5e5c8ebd9bdedf1a8cbe239f96d4e19a443f686cf5b0049c6b9, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAjPjsh1J5qKYoKa4gk6BscVaTy75wtSUb, 35000000000000, 1225000000, 0.035\n";
      ltc_insert_swap_buyoffer 1652382089L (hexstring_hashval "50534e1e72edf470920682090064f69de94f086e75c296f099449138b688459a") 0.025 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrEzNHyMBZBi6nLarp9czpeSEHAFCNkoYzR",74000000000000L,1850000000L));
      Printf.fprintf f "1652382089, 50534e1e72edf470920682090064f69de94f086e75c296f099449138b688459a, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrEzNHyMBZBi6nLarp9czpeSEHAFCNkoYzR, 74000000000000, 1850000000, 0.025\n";
      ltc_insert_swap_buyoffer 1654883393L (hexstring_hashval "5053a942d8ea1295a2b8605580be1af2e9712498bf44afddcba3418ee85928ac") 0.035 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrEzNHyMBZBi6nLarp9czpeSEHAFCNkoYzR",20000000000000L,700000000L));
      Printf.fprintf f "1654883393, 5053a942d8ea1295a2b8605580be1af2e9712498bf44afddcba3418ee85928ac, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrEzNHyMBZBi6nLarp9czpeSEHAFCNkoYzR, 20000000000000, 700000000, 0.035\n";
      ltc_insert_swap_buyoffer 1655053235L (hexstring_hashval "50531d52ed3f65efb43f30dbcdaaf6ba38e286a1ad9afe722aac4b2d50451b03") 0.04 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2",25000000000000L,1000000000L));
      Printf.fprintf f "1655053235, 50531d52ed3f65efb43f30dbcdaaf6ba38e286a1ad9afe722aac4b2d50451b03, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2, 25000000000000, 1000000000, 0.04\n";
      ltc_insert_swap_buyoffer 1655057624L (hexstring_hashval "50533724333f98e92d8b80b46416960ac1eae8a6fc3f9aeee7bac1fe5f5db65c") 0.06 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrGYTX2uWZPgSxYwquaZuFX5dqD1BNsS9GG",8000000000000L,480000000L));
      Printf.fprintf f "1655057624, 50533724333f98e92d8b80b46416960ac1eae8a6fc3f9aeee7bac1fe5f5db65c, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrGYTX2uWZPgSxYwquaZuFX5dqD1BNsS9GG, 8000000000000, 480000000, 0.06\n";
      ltc_insert_swap_buyoffer 1655179404L (hexstring_hashval "505355b176446df98cc7a5509f4a94e6d92e2f2e09e39f1b73303bc891d4fecb") 0.08 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrEzNHyMBZBi6nLarp9czpeSEHAFCNkoYzR",23500000000000L,1880000000L));
      Printf.fprintf f "1655179404, 505355b176446df98cc7a5509f4a94e6d92e2f2e09e39f1b73303bc891d4fecb, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrEzNHyMBZBi6nLarp9czpeSEHAFCNkoYzR, 23500000000000, 1880000000, 0.08\n";
      ltc_insert_swap_buyoffer 1655314068L (hexstring_hashval "5053503caf17153f5f78af8e08d4ec96b8c149ba186e6f498d166f12afce7239") 0.1 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2",9990000000000L,999000000L));
      Printf.fprintf f "1655314068, 5053503caf17153f5f78af8e08d4ec96b8c149ba186e6f498d166f12afce7239, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2, 9990000000000, 999000000, 0.1\n";
      ltc_insert_swap_buyoffer 1655426613L (hexstring_hashval "5053ba7e59766c5c99ceefcd43dc910e671a1d715e2f67b039ddbeeae43f6999") 0.12 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrGYTX2uWZPgSxYwquaZuFX5dqD1BNsS9GG",19500000000000L,2340000000L));
      Printf.fprintf f "1655426613, 5053ba7e59766c5c99ceefcd43dc910e671a1d715e2f67b039ddbeeae43f6999, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrGYTX2uWZPgSxYwquaZuFX5dqD1BNsS9GG, 19500000000000, 2340000000, 0.12\n";
      ltc_insert_swap_buyoffer 1655478885L (hexstring_hashval "5053f9d17c9b659a25cf8d8bbdc3ff1014bdf400315ee2343bd595d52699f43e") 0.11 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2",9000000000000L,990000000L));
      Printf.fprintf f "1655478885, 5053f9d17c9b659a25cf8d8bbdc3ff1014bdf400315ee2343bd595d52699f43e, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2, 9000000000000, 990000000, 0.11\n";
      ltc_insert_swap_buyoffer 1655749448L (hexstring_hashval "50535b8a078306967d5404579949e01cf909790386b24696b4a9f1d54806b1fc") 0.1 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2",20500000000000L,2050000000L));
      Printf.fprintf f "1655749448, 50535b8a078306967d5404579949e01cf909790386b24696b4a9f1d54806b1fc, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrAWvcAkarzhNSMMugDkJ3rLGXAAMXZv9k2, 20500000000000, 2050000000, 0.1\n";
      ltc_insert_swap_buyoffer 1655957933L (hexstring_hashval "5053915f2e453efe77dce671c6c15c1f73a5997c6679b47c682af07be4fdb905") 0.105 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrFmUv8WUrN2PeVoZMg8TyfEd6tqLnudheA",16200000000000L,1701000000L));
      Printf.fprintf f "1655957933, 5053915f2e453efe77dce671c6c15c1f73a5997c6679b47c682af07be4fdb905, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrFmUv8WUrN2PeVoZMg8TyfEd6tqLnudheA, 16200000000000, 1701000000, 0.105\n";
      ltc_insert_swap_buyoffer 1656184215L (hexstring_hashval "50538aa397e685eaa70265485b70560b450a395d3f511fdc135e9b30e27fcd8a") 0.1025 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrMvbo7yMZ3t9HbcMMt94pWYgBnoLgbNAHZ",17000000000000L,1742500000L));
      Printf.fprintf f "1656184215, 50538aa397e685eaa70265485b70560b450a395d3f511fdc135e9b30e27fcd8a, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrMvbo7yMZ3t9HbcMMt94pWYgBnoLgbNAHZ, 17000000000000, 1742500000, 0.1025\n";
      ltc_insert_swap_buyoffer 1656440379L (hexstring_hashval "50534a8b641419005edb0dcfe7e2d8ca84f6524f96cbeb52d4cba53b93077c40") 0.10125 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "Pr55EpVgNcp2ycSXuByuFD4ZvRCudFCUd84",17200000000000L,1741500000L));
      Printf.fprintf f "1656440379, 50534a8b641419005edb0dcfe7e2d8ca84f6524f96cbeb52d4cba53b93077c40, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, Pr55EpVgNcp2ycSXuByuFD4ZvRCudFCUd84, 17200000000000, 1741500000, 0.10125\n";
      ltc_insert_swap_buyoffer 1656698285L (hexstring_hashval "5053708aa8bd979395daedc9d8a8ae5a564ee4fefbd6a3f3d3aa6d86afc2b6be") 0.102 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "Pr55EpVgNcp2ycSXuByuFD4ZvRCudFCUd84",17000000000000L,1734000000L));
      Printf.fprintf f "1656698285, 5053708aa8bd979395daedc9d8a8ae5a564ee4fefbd6a3f3d3aa6d86afc2b6be, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, Pr55EpVgNcp2ycSXuByuFD4ZvRCudFCUd84, 17000000000000, 1734000000, 0.102\n";
      ltc_insert_swap_buyoffer 1656862822L (hexstring_hashval "5053bdd142a4f42ceafbba586b3ee4812c325c66ebb071e057c56830028c76a5") 0.101625 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "Pr5rDE32Uuj1vyHSNsK9DEL1bXDnSiEGvE5",20100000000000L,2042662600L));
      Printf.fprintf f "1656862822, 5053bdd142a4f42ceafbba586b3ee4812c325c66ebb071e057c56830028c76a5, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, Pr5rDE32Uuj1vyHSNsK9DEL1bXDnSiEGvE5, 20100000000000, 2042662600, 0.101625\n";
      ltc_insert_swap_buyoffer 1656961698L (hexstring_hashval "505361422c82f2edbd8e3afe5e861ee969f77bd035ee0ca07d6615a5d8ecd1c4") 0.102 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "Pr5pM65tTGHPcoAYiuZCt3qVJz6ozdEsKmA",2000000000000L,204000000L));
      Printf.fprintf f "1656961698, 505361422c82f2edbd8e3afe5e861ee969f77bd035ee0ca07d6615a5d8ecd1c4, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, Pr5pM65tTGHPcoAYiuZCt3qVJz6ozdEsKmA, 2000000000000, 204000000, 0.102\n";
      ltc_insert_swap_buyoffer 1657112436L (hexstring_hashval "505384e35805293bdede6cbb30c586c0f7d2bef62f2ba6909835a4724c4c9246") 0.102 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "Pr5pM65tTGHPcoAYiuZCt3qVJz6ozdEsKmA",2500000000000L,255000000L));
      Printf.fprintf f "1657112436, 505384e35805293bdede6cbb30c586c0f7d2bef62f2ba6909835a4724c4c9246, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, Pr5pM65tTGHPcoAYiuZCt3qVJz6ozdEsKmA, 2500000000000, 255000000, 0.102\n";
      ltc_insert_swap_buyoffer 1657905244L (hexstring_hashval "5053d0063d28bcb3688ae5023f3d83a55f74b4108490df66d89b30df0f7876db") 0.1021 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "Pr5rDE32Uuj1vyHSNsK9DEL1bXDnSiEGvE5",20000000000000L,2042000000L));
      Printf.fprintf f "1657905244, 5053d0063d28bcb3688ae5023f3d83a55f74b4108490df66d89b30df0f7876db, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, Pr5rDE32Uuj1vyHSNsK9DEL1bXDnSiEGvE5, 20000000000000, 2042000000, 0.1021\n";
      ltc_insert_swap_buyoffer 1658261253L (hexstring_hashval "5053d6192688f89ffe5f0dd4aa457bfa7c1f7588e9fc34f18c837967faa5c858") 0.10205 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrRLCxDCucUqJZP1ChZuruAxWmM2vuTpxSw",21700000000000L,2214485000L));
      Printf.fprintf f "1658261253, 5053d6192688f89ffe5f0dd4aa457bfa7c1f7588e9fc34f18c837967faa5c858, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrRLCxDCucUqJZP1ChZuruAxWmM2vuTpxSw, 21700000000000, 2214485000, 0.10205\n";
      ltc_insert_swap_buyoffer 1658688668L (hexstring_hashval "5053b2169ae0d133a3e2528c3cd666482bc4d355968d66898146d69f3b479090") 0.103 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "Pr5pM65tTGHPcoAYiuZCt3qVJz6ozdEsKmA",14500000000000L,1493500000L));
      Printf.fprintf f "1658688668, 5053b2169ae0d133a3e2528c3cd666482bc4d355968d66898146d69f3b479090, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, Pr5pM65tTGHPcoAYiuZCt3qVJz6ozdEsKmA, 14500000000000, 1493500000, 0.103\n";
      ltc_insert_swap_buyoffer 1659275586L (hexstring_hashval "5053fca8c596d13b337fcaeff30d6e8a1606a34012abab7b459b1d522dc9b7c0") 0.103 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "Pr5pM65tTGHPcoAYiuZCt3qVJz6ozdEsKmA",14500000000000L,1493500000L));
      Printf.fprintf f "1659275586, 5053fca8c596d13b337fcaeff30d6e8a1606a34012abab7b459b1d522dc9b7c0, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, Pr5pM65tTGHPcoAYiuZCt3qVJz6ozdEsKmA, 14500000000000, 1493500000, 0.103\n";
      ltc_insert_swap_buyoffer 1660162209L (hexstring_hashval "50539bc293f6132f9cce5b4673c65947352a6470c5c2bcb2f0c6eecb90af25ea") 0.103 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "Pr5pM65tTGHPcoAYiuZCt3qVJz6ozdEsKmA",14500000000000L,1493500000L));
      Printf.fprintf f "1660162209, 50539bc293f6132f9cce5b4673c65947352a6470c5c2bcb2f0c6eecb90af25ea, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, Pr5pM65tTGHPcoAYiuZCt3qVJz6ozdEsKmA, 14500000000000, 1493500000, 0.103\n";
      ltc_insert_swap_buyoffer 1660330636L (hexstring_hashval "505325a6a72cd2bdf6bd99b80dec0f07d4755dfbcd8d80ede64bbe62b3fadc60") 0.1025 (SimpleSwapBuyOffer("ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04",pfgaddrstr_addr "PrRLCxDCucUqJZP1ChZuruAxWmM2vuTpxSw",21600000000000L,2214000000L));
      Printf.fprintf f "1660330636, 505325a6a72cd2bdf6bd99b80dec0f07d4755dfbcd8d80ede64bbe62b3fadc60, ltc1qz5v4v3p55967rzaupnsele9quahas8ejj25n04, PrRLCxDCucUqJZP1ChZuruAxWmM2vuTpxSw, 21600000000000, 2214000000, 0.1025\n";
      ltc_insert_swap_buyoffer 1660582869L (hexstring_hashval "5053eff4a0e37fe9f92f4a6a1e6711066fe69f207d8348cf4cd92e9241e36f8d") 0.1023 (SimpleSwapBuyOffer("ltc1qmuq3979zzwnqu0r5n353gsy3ttwd4gfs77dcfv",pfgaddrstr_addr "Pr3kopPfqRcP5Kyx5oV91Yw3ywDicqoj1QN",18200000000000L,1861860000L));
      Printf.fprintf f "1660582869, 5053eff4a0e37fe9f92f4a6a1e6711066fe69f207d8348cf4cd92e9241e36f8d, ltc1qmuq3979zzwnqu0r5n353gsy3ttwd4gfs77dcfv, Pr3kopPfqRcP5Kyx5oV91Yw3ywDicqoj1QN, 18200000000000, 1861860000, 0.1023\n";
      ltc_insert_swap_buyoffer 1660849493L (hexstring_hashval "5053316beccd7b79ef3f3f1c9c542dca5e92f5b8b37c0fa2a50233a0f89d736c") 0.1025 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "Pr53EdGZfa4hUqE7AZu496K6LqxbYEyspRc",17400000000000L,1783500000L));
      Printf.fprintf f "1660849493, 5053316beccd7b79ef3f3f1c9c542dca5e92f5b8b37c0fa2a50233a0f89d736c, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, Pr53EdGZfa4hUqE7AZu496K6LqxbYEyspRc, 17400000000000, 1783500000, 0.1025\n";
      ltc_insert_swap_buyoffer 1661025434L (hexstring_hashval "505391bcc790032f5d25ac86ca1743bd2907d6ab7687a461fc05f290e0f40d16") 0.05 (SimpleSwapBuyOffer("ltc1q62pqzcxx6r8aed43nvjnfww7z0wu0vlq8gs7w3",pfgaddrstr_addr "PrM5opmJf9AFDnQqS2HaZDdmTDHQBG5y86M",2000000000000L,100000000L));
      Printf.fprintf f "1661025434, 505391bcc790032f5d25ac86ca1743bd2907d6ab7687a461fc05f290e0f40d16, ltc1q62pqzcxx6r8aed43nvjnfww7z0wu0vlq8gs7w3, PrM5opmJf9AFDnQqS2HaZDdmTDHQBG5y86M, 2000000000000, 100000000, 0.05\n";
      ltc_insert_swap_buyoffer 1661027514L (hexstring_hashval "5053585e8d93b872e26f018f5676bea6e4a7fe8b96703e34d553e6d358a649d2") 0.01 (SimpleSwapBuyOffer("ltc1q62pqzcxx6r8aed43nvjnfww7z0wu0vlq8gs7w3",pfgaddrstr_addr "PrM5opmJf9AFDnQqS2HaZDdmTDHQBG5y86M",10000000000000L,100000000L));
      Printf.fprintf f "1661027514, 5053585e8d93b872e26f018f5676bea6e4a7fe8b96703e34d553e6d358a649d2, ltc1q62pqzcxx6r8aed43nvjnfww7z0wu0vlq8gs7w3, PrM5opmJf9AFDnQqS2HaZDdmTDHQBG5y86M, 10000000000000, 100000000, 0.01\n";
      ltc_insert_swap_buyoffer 1661092732L (hexstring_hashval "505334dbc80f2f2c4e09675972758a52f26122e9a9961f21acd10b8d310d05dc") 0.1025 (SimpleSwapBuyOffer("ltc1qp0n9vg6v2pvxsywyfdug5v2eyteacjpwmez9zy",pfgaddrstr_addr "Pr3BrNAWAsLFQ9qmyBCQV1iB13F83PvgiHZ",8040000000000L,824100000L));
      Printf.fprintf f "1661092732, 505334dbc80f2f2c4e09675972758a52f26122e9a9961f21acd10b8d310d05dc, ltc1qp0n9vg6v2pvxsywyfdug5v2eyteacjpwmez9zy, Pr3BrNAWAsLFQ9qmyBCQV1iB13F83PvgiHZ, 8040000000000, 824100000, 0.1025\n";
      ltc_insert_swap_buyoffer 1661965754L (hexstring_hashval "5053b579658549576b66a029017b7987bb3772a3962991938c231e5849761add") 0.1025 (SimpleSwapBuyOffer("ltc1qp0n9vg6v2pvxsywyfdug5v2eyteacjpwmez9zy",pfgaddrstr_addr "PrCnVfyxJiz48w3nYGW9Y6daruUEa5SuNza",6760000000000L,692900000L));
      Printf.fprintf f "1661965754, 5053b579658549576b66a029017b7987bb3772a3962991938c231e5849761add, ltc1qp0n9vg6v2pvxsywyfdug5v2eyteacjpwmez9zy, PrCnVfyxJiz48w3nYGW9Y6daruUEa5SuNza, 6760000000000, 692900000, 0.1025\n";
      ltc_insert_swap_buyoffer 1663003199L (hexstring_hashval "5053ce7270c0be506b81d6a607ddccb6fb269600598a6f8b1e6eb486213b3c8d") 0.1025 (SimpleSwapBuyOffer("ltc1qmuq3979zzwnqu0r5n353gsy3ttwd4gfs77dcfv",pfgaddrstr_addr "Pr3kopPfqRcP5Kyx5oV91Yw3ywDicqoj1QN",18100000000000L,1855250000L));
      Printf.fprintf f "1663003199, 5053ce7270c0be506b81d6a607ddccb6fb269600598a6f8b1e6eb486213b3c8d, ltc1qmuq3979zzwnqu0r5n353gsy3ttwd4gfs77dcfv, Pr3kopPfqRcP5Kyx5oV91Yw3ywDicqoj1QN, 18100000000000, 1855250000, 0.1025\n";
      ltc_insert_swap_buyoffer 1663534928L (hexstring_hashval "505342971fc96f3c9adc18f81a18430fd7df6de1c1c49d07f886c8d801f8cdac") 0.1023 (SimpleSwapBuyOffer("ltc1qmuq3979zzwnqu0r5n353gsy3ttwd4gfs77dcfv",pfgaddrstr_addr "Pr3kopPfqRcP5Kyx5oV91Yw3ywDicqoj1QN",13000000000000L,1329900000L));
      Printf.fprintf f "1663534928, 505342971fc96f3c9adc18f81a18430fd7df6de1c1c49d07f886c8d801f8cdac, ltc1qmuq3979zzwnqu0r5n353gsy3ttwd4gfs77dcfv, Pr3kopPfqRcP5Kyx5oV91Yw3ywDicqoj1QN, 13000000000000, 1329900000, 0.1023\n";
      ltc_insert_swap_buyoffer 1665334005L (hexstring_hashval "5053a565338d74f404d668ae340e4f4c88be77af6977deb2af7ae3d450c9d105") 0.103 (SimpleSwapBuyOffer("ltc1qt3mwvhffu6e4ln26tzk20fmyqyayncw06zv9e6",pfgaddrstr_addr "PrKuq93v2kom39eg95BSwLFa2A7u69LvRh2",13400000000000L,1380200000L));
      Printf.fprintf f "1665334005, 5053a565338d74f404d668ae340e4f4c88be77af6977deb2af7ae3d450c9d105, ltc1qt3mwvhffu6e4ln26tzk20fmyqyayncw06zv9e6, PrKuq93v2kom39eg95BSwLFa2A7u69LvRh2, 13400000000000, 1380200000, 0.103\n";
      ltc_insert_swap_buyoffer 1665834959L (hexstring_hashval "50533ec9786ea58f0c86d6875cac4f8c16f03c021610a2941e1fef3e33ba8508") 0.08 (SimpleSwapBuyOffer("ltc1q62pqzcxx6r8aed43nvjnfww7z0wu0vlq8gs7w3",pfgaddrstr_addr "PrM5opmJf9AFDnQqS2HaZDdmTDHQBG5y86M",1250000000000L,100000000L));
      Printf.fprintf f "1665834959, 50533ec9786ea58f0c86d6875cac4f8c16f03c021610a2941e1fef3e33ba8508, ltc1q62pqzcxx6r8aed43nvjnfww7z0wu0vlq8gs7w3, PrM5opmJf9AFDnQqS2HaZDdmTDHQBG5y86M, 1250000000000, 100000000, 0.08\n";
      ltc_insert_swap_buyoffer 1665851326L (hexstring_hashval "505349b4df72d5b5e602589dabb0e442dee5af728cb8b1529ecfde8486b01bf3") 0.103 (SimpleSwapBuyOffer("ltc1qt3mwvhffu6e4ln26tzk20fmyqyayncw06zv9e6",pfgaddrstr_addr "PrKuq93v2kom39eg95BSwLFa2A7u69LvRh2",19436900000000L,2002000000L));
      Printf.fprintf f "1665851326, 505349b4df72d5b5e602589dabb0e442dee5af728cb8b1529ecfde8486b01bf3, ltc1qt3mwvhffu6e4ln26tzk20fmyqyayncw06zv9e6, PrKuq93v2kom39eg95BSwLFa2A7u69LvRh2, 19436900000000, 2002000000, 0.103\n";
      ltc_insert_swap_buyoffer 1667477384L (hexstring_hashval "505345d1b294c1e78fd64c4b47c946bd442dc5e37e6712581f533e749a436f75") 0.1 (SimpleSwapBuyOffer("ltc1q62pqzcxx6r8aed43nvjnfww7z0wu0vlq8gs7w3",pfgaddrstr_addr "PrM5opmJf9AFDnQqS2HaZDdmTDHQBG5y86M",6999950000000L,699995000L));
      Printf.fprintf f "1667477384, 505345d1b294c1e78fd64c4b47c946bd442dc5e37e6712581f533e749a436f75, ltc1q62pqzcxx6r8aed43nvjnfww7z0wu0vlq8gs7w3, PrM5opmJf9AFDnQqS2HaZDdmTDHQBG5y86M, 6999950000000, 699995000, 0.1\n";
      ltc_insert_swap_buyoffer 1667870956L (hexstring_hashval "505359861d72dc9d6d662c1adc2638e10846ccb67c6cd1e3e3301ae59a5d0f1e") 1.0e-4 (SimpleSwapBuyOffer("ltc1q9d4337uyaewmlwncs2z4e2jyud7w9hx2uarj9q",pfgaddrstr_addr "Pr9osHgNJHntmQKSngTFFT2mNepNBTPRjFs",699995000000L,69999L));
      Printf.fprintf f "1667870956, 505359861d72dc9d6d662c1adc2638e10846ccb67c6cd1e3e3301ae59a5d0f1e, ltc1q9d4337uyaewmlwncs2z4e2jyud7w9hx2uarj9q, Pr9osHgNJHntmQKSngTFFT2mNepNBTPRjFs, 699995000000, 69999, 1.0e-4\n";
      ltc_insert_swap_buyoffer 1668420186L (hexstring_hashval "5053df35527a28677debbb22619aa7e630c349fcd44d80a1e238dce8643b2a1f") 0.09 (SimpleSwapBuyOffer("ltc1q62pqzcxx6r8aed43nvjnfww7z0wu0vlq8gs7w3",pfgaddrstr_addr "PrM5opmJf9AFDnQqS2HaZDdmTDHQBG5y86M",7777760000000L,699998000L));
      Printf.fprintf f "1668420186, 5053df35527a28677debbb22619aa7e630c349fcd44d80a1e238dce8643b2a1f, ltc1q62pqzcxx6r8aed43nvjnfww7z0wu0vlq8gs7w3, PrM5opmJf9AFDnQqS2HaZDdmTDHQBG5y86M, 7777760000000, 699998000, 0.09\n";
      ltc_insert_swap_buyoffer 1669201803L (hexstring_hashval "5053749da99ffe19196302c946bc0222875027c5af1bdd2622ea3651eda3d35b") 0.072499 (SimpleSwapBuyOffer("ltc1qzf3utzelax0gtwe7vvevmfmjp5udmfletn3zcy",pfgaddrstr_addr "PrFa6zkR4sAdnEBE9jzc7Z63tEKAXjrNaTJ",1500000000000L,108748500L));
      Printf.fprintf f "1669201803, 5053749da99ffe19196302c946bc0222875027c5af1bdd2622ea3651eda3d35b, ltc1qzf3utzelax0gtwe7vvevmfmjp5udmfletn3zcy, PrFa6zkR4sAdnEBE9jzc7Z63tEKAXjrNaTJ, 1500000000000, 108748500, 0.072499\n";
      ltc_insert_swap_buyoffer 1669206540L (hexstring_hashval "5053cbfa0aad27a6245cad3cc157620bcf25b5e9dc0e45c7dc289b29b7739a0e") 0.06 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT",25000000000000L,1500000000L));
      Printf.fprintf f "1669206540, 5053cbfa0aad27a6245cad3cc157620bcf25b5e9dc0e45c7dc289b29b7739a0e, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT, 25000000000000, 1500000000, 0.06\n";
      ltc_insert_swap_buyoffer 1669413417L (hexstring_hashval "5053884777142064c0303770175a8e4f21a0ebaa62977bcb23528bae19c0d1d0") 0.06 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT",25000000000000L,1500000000L));
      Printf.fprintf f "1669413417, 5053884777142064c0303770175a8e4f21a0ebaa62977bcb23528bae19c0d1d0, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT, 25000000000000, 1500000000, 0.06\n";
      ltc_insert_swap_buyoffer 1669765712L (hexstring_hashval "505329bfc3b065bb02cf2fe45a0d907772775fc4cfa9777c13516bb532eadef4") 0.06 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT",25000000000000L,1500000000L));
      Printf.fprintf f "1669765712, 505329bfc3b065bb02cf2fe45a0d907772775fc4cfa9777c13516bb532eadef4, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT, 25000000000000, 1500000000, 0.06\n";
      ltc_insert_swap_buyoffer 1670255986L (hexstring_hashval "50536c552a23b8e5e9268e1b723a2518b9ed48e391fbf897dc6310601ffc5853") 0.05 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT",30000000000000L,1500000000L));
      Printf.fprintf f "1670255986, 50536c552a23b8e5e9268e1b723a2518b9ed48e391fbf897dc6310601ffc5853, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT, 30000000000000, 1500000000, 0.05\n";
      ltc_insert_swap_buyoffer 1670710432L (hexstring_hashval "5053fb090f4e6476f5a61c2707a7b6751ff69944ba5ba73e0857d753a3e9139f") 0.0525 (SimpleSwapBuyOffer("ltc1qzkfayl75s7dfjkr6w4vxnxsgn2w9zaq9pzfap9",pfgaddrstr_addr "PrJe2Hm69Zsd9QG5xv28RG9zFerYd69wwmr",20100000000000L,1055250000L));
      Printf.fprintf f "1670710432, 5053fb090f4e6476f5a61c2707a7b6751ff69944ba5ba73e0857d753a3e9139f, ltc1qzkfayl75s7dfjkr6w4vxnxsgn2w9zaq9pzfap9, PrJe2Hm69Zsd9QG5xv28RG9zFerYd69wwmr, 20100000000000, 1055250000, 0.0525\n";
      ltc_insert_swap_buyoffer 1670852445L (hexstring_hashval "5053937d16910f3f1169d0400f32ba0870ff036afabe0036d5ca271511d358f2") 0.0525 (SimpleSwapBuyOffer("ltc1qsqfepxmgducdelja4fdw6drn0dxumk2scqp949",pfgaddrstr_addr "PrJe2Hm69Zsd9QG5xv28RG9zFerYd69wwmr",20100000000000L,1055250000L));
      Printf.fprintf f "1670852445, 5053937d16910f3f1169d0400f32ba0870ff036afabe0036d5ca271511d358f2, ltc1qsqfepxmgducdelja4fdw6drn0dxumk2scqp949, PrJe2Hm69Zsd9QG5xv28RG9zFerYd69wwmr, 20100000000000, 1055250000, 0.0525\n";
      ltc_insert_swap_buyoffer 1671131952L (hexstring_hashval "505390eb7b30cf213c14fde9e77f1d2cf7cdc4191e0f8fc161fae8977ff0b4b2") 0.06 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT",25000000000000L,1500000000L));
      Printf.fprintf f "1671131952, 505390eb7b30cf213c14fde9e77f1d2cf7cdc4191e0f8fc161fae8977ff0b4b2, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT, 25000000000000, 1500000000, 0.06\n";
      ltc_insert_swap_buyoffer 1671203475L (hexstring_hashval "5053e00bfa9f6691c037a35e67f988ae1e218ede5dffa809d7f75c423339b4e4") 0.0548 (SimpleSwapBuyOffer("ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0",pfgaddrstr_addr "PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT",27500000000000L,1507000000L));
      Printf.fprintf f "1671203475, 5053e00bfa9f6691c037a35e67f988ae1e218ede5dffa809d7f75c423339b4e4, ltc1q46n458t925yvnn68jm6k9p7qwecmt7m28t28w0, PrS6j2Xp7nxExnus97C7yG33dbf5rrY8wVT, 27500000000000, 1507000000, 0.0548\n";
      ltc_insert_swap_buyoffer 1671457671L (hexstring_hashval "50533ed1c26dfb849dc44add5255bb102f29f4a167193692c2dcad2c43240f7f") 0.028 (SimpleSwapBuyOffer("ltc1qdghsndqwmt3764ywmzkv9z0r76gladsrl6njru",pfgaddrstr_addr "PrJe2Hm69Zsd9QG5xv28RG9zFerYd69wwmr",2600000000000L,72800000L));
      Printf.fprintf f "1671457671, 50533ed1c26dfb849dc44add5255bb102f29f4a167193692c2dcad2c43240f7f, ltc1qdghsndqwmt3764ywmzkv9z0r76gladsrl6njru, PrJe2Hm69Zsd9QG5xv28RG9zFerYd69wwmr, 2600000000000, 72800000, 0.028\n";
      ltc_insert_swap_buyoffer 1671903181L (hexstring_hashval "5053f9d76541e52f5770558688b7beda5c80b7428fe3fc8422d6b796e06ad494") 0.03 (SimpleSwapBuyOffer("ltc1qw9uhjdzzv0ws823hetywynpqdm76txtw7feyqr",pfgaddrstr_addr "PrJnCTQ4btJ2e8C9XYh6ER1nQ79xsWNhZYo",35000000000000L,1050000000L));
      Printf.fprintf f "1671903181, 5053f9d76541e52f5770558688b7beda5c80b7428fe3fc8422d6b796e06ad494, ltc1qw9uhjdzzv0ws823hetywynpqdm76txtw7feyqr, PrJnCTQ4btJ2e8C9XYh6ER1nQ79xsWNhZYo, 35000000000000, 1050000000, 0.03\n";
      ltc_insert_swap_buyoffer 1672090922L (hexstring_hashval "5053ef4f39c23ece700bad5a268cda668adfe97030416f3ae0889e05c8e52488") 0.04 (SimpleSwapBuyOffer("ltc1qw9uhjdzzv0ws823hetywynpqdm76txtw7feyqr",pfgaddrstr_addr "PrJnCTQ4btJ2e8C9XYh6ER1nQ79xsWNhZYo",25000000000000L,1000000000L));
      Printf.fprintf f "1672090922, 5053ef4f39c23ece700bad5a268cda668adfe97030416f3ae0889e05c8e52488, ltc1qw9uhjdzzv0ws823hetywynpqdm76txtw7feyqr, PrJnCTQ4btJ2e8C9XYh6ER1nQ79xsWNhZYo, 25000000000000, 1000000000, 0.04\n";
      ltc_insert_swap_buyoffer 1672582461L (hexstring_hashval "50530b8630f5222a5aa84f0e93f91fc03ab1b7c82ccb33ce8e97cedea9ba2262") 0.05 (SimpleSwapBuyOffer("ltc1qw9uhjdzzv0ws823hetywynpqdm76txtw7feyqr",pfgaddrstr_addr "PrJnCTQ4btJ2e8C9XYh6ER1nQ79xsWNhZYo",20700000000000L,1035000000L));
      Printf.fprintf f "1672582461, 50530b8630f5222a5aa84f0e93f91fc03ab1b7c82ccb33ce8e97cedea9ba2262, ltc1qw9uhjdzzv0ws823hetywynpqdm76txtw7feyqr, PrJnCTQ4btJ2e8C9XYh6ER1nQ79xsWNhZYo, 20700000000000, 1035000000, 0.05\n";
      ltc_insert_swap_buyoffer 1674670290L (hexstring_hashval "5053d6a9538b64ae622de1462abaab6187af802576c76a6addfb9ec247ddd3b9") 0.02887 (SimpleSwapBuyOffer("ltc1qw9uhjdzzv0ws823hetywynpqdm76txtw7feyqr",pfgaddrstr_addr "PrJnCTQ4btJ2e8C9XYh6ER1nQ79xsWNhZYo",1500000000000L,43305000L));
      Printf.fprintf f "1674670290, 5053d6a9538b64ae622de1462abaab6187af802576c76a6addfb9ec247ddd3b9, ltc1qw9uhjdzzv0ws823hetywynpqdm76txtw7feyqr, PrJnCTQ4btJ2e8C9XYh6ER1nQ79xsWNhZYo, 1500000000000, 43305000, 0.02887\n";
      ltc_insert_swap_buyoffer 1674765332L (hexstring_hashval "50535cdcd3fc92c78a2b63cd70898a5a1e46747eb6233e92245745d1abddb025") 0.02907 (SimpleSwapBuyOffer("ltc1qczqs60uydsw6k8dcxa2nsu98sqe5ffdv47r46w",pfgaddrstr_addr "PrJnCTQ4btJ2e8C9XYh6ER1nQ79xsWNhZYo",17200000000000L,500000000L));
      Printf.fprintf f "1674765332, 50535cdcd3fc92c78a2b63cd70898a5a1e46747eb6233e92245745d1abddb025, ltc1qczqs60uydsw6k8dcxa2nsu98sqe5ffdv47r46w, PrJnCTQ4btJ2e8C9XYh6ER1nQ79xsWNhZYo, 17200000000000, 500000000, 0.02907\n";
      ltc_insert_swap_buyoffer 1675005959L (hexstring_hashval "5053a08d0df62fe1a42c4a375595aa6b5b9d85d386e21c582ba2bffa2c3ba028") 0.02498 (SimpleSwapBuyOffer("ltc1qsn92d6waxj2rck363rsspww3cha6ylqqld7wf8",pfgaddrstr_addr "Pr8tXHKcDXTpJTcLX28Gz4KASJUy6a8k2Kn",20000000000000L,499600000L));
      Printf.fprintf f "1675005959, 5053a08d0df62fe1a42c4a375595aa6b5b9d85d386e21c582ba2bffa2c3ba028, ltc1qsn92d6waxj2rck363rsspww3cha6ylqqld7wf8, Pr8tXHKcDXTpJTcLX28Gz4KASJUy6a8k2Kn, 20000000000000, 499600000, 0.02498\n";
      ltc_insert_swap_buyoffer 1675617750L (hexstring_hashval "50538ce1e88e00f7536b4e44d1c79e000ce1d629cf2b0fd1992595356a526502") 0.027 (SimpleSwapBuyOffer("ltc1qsn92d6waxj2rck363rsspww3cha6ylqqld7wf8",pfgaddrstr_addr "Pr8tXHKcDXTpJTcLX28Gz4KASJUy6a8k2Kn",18500000000000L,499500000L));
      Printf.fprintf f "1675617750, 50538ce1e88e00f7536b4e44d1c79e000ce1d629cf2b0fd1992595356a526502, ltc1qsn92d6waxj2rck363rsspww3cha6ylqqld7wf8, Pr8tXHKcDXTpJTcLX28Gz4KASJUy6a8k2Kn, 18500000000000, 499500000, 0.027\n";
      ltc_insert_swap_buyoffer 1675858163L (hexstring_hashval "5053df2567d552b7ce5101665719f96590e39644c08711638d792f82b6014e36") 0.016602 (SimpleSwapBuyOffer("ltc1qdghsndqwmt3764ywmzkv9z0r76gladsrl6njru",pfgaddrstr_addr "PrLVxreqxPeQmopkbW4TKiLH4ZBCNNmSfqK",30080000000000L,499400000L));
      Printf.fprintf f "1675858163, 5053df2567d552b7ce5101665719f96590e39644c08711638d792f82b6014e36, ltc1qdghsndqwmt3764ywmzkv9z0r76gladsrl6njru, PrLVxreqxPeQmopkbW4TKiLH4ZBCNNmSfqK, 30080000000000, 499400000, 0.016602\n";
      ltc_insert_swap_buyoffer 1676219832L (hexstring_hashval "5053d46e611988ba32d31a349df6b4df5d87eb2f30b6353e71a0f72c2a04f064") 0.025 (SimpleSwapBuyOffer("ltc1qpkyw9k54avccnscddcyk29cmpqnqnkzdttxe3e",pfgaddrstr_addr "PrAa9Rmdq6nWxfGEuQdJHMLe3oZuHNww77E",592000000000L,14800000L));
      Printf.fprintf f "1676219832, 5053d46e611988ba32d31a349df6b4df5d87eb2f30b6353e71a0f72c2a04f064, ltc1qpkyw9k54avccnscddcyk29cmpqnqnkzdttxe3e, PrAa9Rmdq6nWxfGEuQdJHMLe3oZuHNww77E, 592000000000, 14800000, 0.025\n";
      ltc_insert_swap_buyoffer 1676381624L (hexstring_hashval "5053ef009c2d05196252c50de0b9d1afc9cec24405c7cd1511fcc2113f78e400") 0.027 (SimpleSwapBuyOffer("ltc1q8nqrs4akxjj3ynuyzuac7xp7gh2urkjsv3vtzk",pfgaddrstr_addr "Pr6rTrbe4xAUm7qDCJB3cT9FkmLp15UzA2s",48000000000000L,1296000000L));
      Printf.fprintf f "1676381624, 5053ef009c2d05196252c50de0b9d1afc9cec24405c7cd1511fcc2113f78e400, ltc1q8nqrs4akxjj3ynuyzuac7xp7gh2urkjsv3vtzk, Pr6rTrbe4xAUm7qDCJB3cT9FkmLp15UzA2s, 48000000000000, 1296000000, 0.027\n";
      ltc_insert_swap_buyoffer 1676482026L (hexstring_hashval "50532edf900d0669a9aec4d97beee716da987d39fb999a31c708a3c62a8741df") 0.027 (SimpleSwapBuyOffer("ltc1qpkyw9k54avccnscddcyk29cmpqnqnkzdttxe3e",pfgaddrstr_addr "PrAa9Rmdq6nWxfGEuQdJHMLe3oZuHNww77E",548000000000L,14796000L));
      Printf.fprintf f "1676482026, 50532edf900d0669a9aec4d97beee716da987d39fb999a31c708a3c62a8741df, ltc1qpkyw9k54avccnscddcyk29cmpqnqnkzdttxe3e, PrAa9Rmdq6nWxfGEuQdJHMLe3oZuHNww77E, 548000000000, 14796000, 0.027\n";
      ltc_insert_swap_buyoffer 1676886328L (hexstring_hashval "505367c833d586fb9f0af6bca5f53b2201903d94005809b51e1fcae91d17091f") 0.025997 (SimpleSwapBuyOffer("ltc1q5h7gde5xdfgakhm32w4yqk4yk0vxv8lk5nsx89",pfgaddrstr_addr "Pr5326f6ScRkrQcMAxifjrAngiaPFExTwyW",39000000000000L,1013900000L));
      Printf.fprintf f "1676886328, 505367c833d586fb9f0af6bca5f53b2201903d94005809b51e1fcae91d17091f, ltc1q5h7gde5xdfgakhm32w4yqk4yk0vxv8lk5nsx89, Pr5326f6ScRkrQcMAxifjrAngiaPFExTwyW, 39000000000000, 1013900000, 0.025997\n";
      ltc_insert_swap_buyoffer 1677078802L (hexstring_hashval "505351c39a527f9f64f4306273d0d240ca36eadc73fedb85f64161dc2c0d79a6") 0.026001 (SimpleSwapBuyOffer("ltc1qssn3dje404g0jfjwa57aaetvl67ur0sfjvafq5",pfgaddrstr_addr "PrACRVyLrctrE9WfRHaq7DUqvuGwJvyGpPz",20710000000000L,538477000L));
      Printf.fprintf f "1677078802, 505351c39a527f9f64f4306273d0d240ca36eadc73fedb85f64161dc2c0d79a6, ltc1qssn3dje404g0jfjwa57aaetvl67ur0sfjvafq5, PrACRVyLrctrE9WfRHaq7DUqvuGwJvyGpPz, 20710000000000, 538477000, 0.026001\n";
      ltc_insert_swap_buyoffer 1677088112L (hexstring_hashval "505312709e2a4bf9e69d649cc8c99170e7cef857209326009995ffd931ee019c") 0.020018 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "PrLJX4nR6E6TT7GjVxYZhQPk9c2qif9XAB8",26900000000000L,538475000L));
      Printf.fprintf f "1677088112, 505312709e2a4bf9e69d649cc8c99170e7cef857209326009995ffd931ee019c, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, PrLJX4nR6E6TT7GjVxYZhQPk9c2qif9XAB8, 26900000000000, 538475000, 0.020018\n";
      ltc_insert_swap_buyoffer 1677240720L (hexstring_hashval "505305527608e8d17f2f119163ecb1593407a2879c81dd0790e27736369fa753") 0.025 (SimpleSwapBuyOffer("ltc1qxx44zvnw984zphek762dck88tk27lfk2nwq557",pfgaddrstr_addr "PrRfVxsPYNXHnrW45q74o3zQr76ypKxjk4J",30000000000000L,750000000L));
      Printf.fprintf f "1677240720, 505305527608e8d17f2f119163ecb1593407a2879c81dd0790e27736369fa753, ltc1qxx44zvnw984zphek762dck88tk27lfk2nwq557, PrRfVxsPYNXHnrW45q74o3zQr76ypKxjk4J, 30000000000000, 750000000, 0.025\n";
      ltc_insert_swap_buyoffer 1677248165L (hexstring_hashval "505347b5afa9366754ae8c1bd7eb2cc047183298af71ec704c95c878b99fa85d") 0.025296 (SimpleSwapBuyOffer("ltc1q27gvft89ussllfn0cahh9my8uyrqcls8jqqpr0",pfgaddrstr_addr "PrC8GrxdmeyiTmddcyxY4TzWjGWYDcaytcT",40000000000000L,1011830000L));
      Printf.fprintf f "1677248165, 505347b5afa9366754ae8c1bd7eb2cc047183298af71ec704c95c878b99fa85d, ltc1q27gvft89ussllfn0cahh9my8uyrqcls8jqqpr0, PrC8GrxdmeyiTmddcyxY4TzWjGWYDcaytcT, 40000000000000, 1011830000, 0.025296\n";
      ltc_insert_swap_buyoffer 1677256465L (hexstring_hashval "5053b3ba58f5d237dc22ed9e86d5266c80e293a3fb7422c7b18c018e000e31b9") 0.019001 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "PrHhWAuxcctgNy3ZZRpZ1R9Gkn7f8uG2yJv",53250000000000L,1011828000L));
      Printf.fprintf f "1677256465, 5053b3ba58f5d237dc22ed9e86d5266c80e293a3fb7422c7b18c018e000e31b9, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, PrHhWAuxcctgNy3ZZRpZ1R9Gkn7f8uG2yJv, 53250000000000, 1011828000, 0.019001\n";
      ltc_insert_swap_buyoffer 1677259800L (hexstring_hashval "5053e94c099860fa02ebae6ac3a6b6004d6389402b591785262006e24c99df91") 0.018 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "PrAqq8UkkKKAndPfr4k24UKexQNqh7D7UYh",41667000000000L,749998000L));
      Printf.fprintf f "1677259800, 5053e94c099860fa02ebae6ac3a6b6004d6389402b591785262006e24c99df91, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, PrAqq8UkkKKAndPfr4k24UKexQNqh7D7UYh, 41667000000000, 749998000, 0.018\n";
      ltc_insert_swap_buyoffer 1677340450L (hexstring_hashval "5053ac8c7297d409b91c5a97e3e6d4f7b08e9215d9f991083bb8e41bfe4739ec") 0.022499 (SimpleSwapBuyOffer("ltc1qax3ekgct0ykujwp68v752q4wayhcv7rxw57ckc",pfgaddrstr_addr "Pr8HpajzmKE5XDjvgmPgQkdRptFKU68UtPB",33100000000000L,744714517L));
      Printf.fprintf f "1677340450, 5053ac8c7297d409b91c5a97e3e6d4f7b08e9215d9f991083bb8e41bfe4739ec, ltc1qax3ekgct0ykujwp68v752q4wayhcv7rxw57ckc, Pr8HpajzmKE5XDjvgmPgQkdRptFKU68UtPB, 33100000000000, 744714517, 0.022499\n";
      ltc_insert_swap_buyoffer 1677503176L (hexstring_hashval "505304e75970a66108f5137a0ebd0349ee5851faeb93c955a243a86076e9c5c4") 0.023748 (SimpleSwapBuyOffer("ltc1q8kra3mslrenjr3qcx952mvnusaatwaauumgycv",pfgaddrstr_addr "PrRBXenZQMwt7pgiicN9AWrSGsVEc5zsVTW",32500000000000L,771824319L));
      Printf.fprintf f "1677503176, 505304e75970a66108f5137a0ebd0349ee5851faeb93c955a243a86076e9c5c4, ltc1q8kra3mslrenjr3qcx952mvnusaatwaauumgycv, PrRBXenZQMwt7pgiicN9AWrSGsVEc5zsVTW, 32500000000000, 771824319, 0.023748\n";
      ltc_insert_swap_buyoffer 1677582095L (hexstring_hashval "5053e9742e1b888cf70bd189caa17878f882ef1602d5fed15b1918a06b5d1592") 0.017152 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "PrNashWpMq8Pnqt4kE4Ws6JNZA2em9rCnab",45000000000000L,771822319L));
      Printf.fprintf f "1677582095, 5053e9742e1b888cf70bd189caa17878f882ef1602d5fed15b1918a06b5d1592, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, PrNashWpMq8Pnqt4kE4Ws6JNZA2em9rCnab, 45000000000000, 771822319, 0.017152\n";
      ltc_insert_swap_buyoffer 1678446743L (hexstring_hashval "50534b8a40fd982dbdc854fafb0d3366b581c8acd5d32b2b360a7d05cbae1963") 0.023056 (SimpleSwapBuyOffer("ltc1qax3ekgct0ykujwp68v752q4wayhcv7rxw57ckc",pfgaddrstr_addr "Pr8HpajzmKE5XDjvgmPgQkdRptFKU68UtPB",32300000000000L,744712517L));
      Printf.fprintf f "1678446743, 50534b8a40fd982dbdc854fafb0d3366b581c8acd5d32b2b360a7d05cbae1963, ltc1qax3ekgct0ykujwp68v752q4wayhcv7rxw57ckc, Pr8HpajzmKE5XDjvgmPgQkdRptFKU68UtPB, 32300000000000, 744712517, 0.023056\n";
      ltc_insert_swap_buyoffer 1678535172L (hexstring_hashval "50538cfb14497b7b7ac4053749429dc0b9d88238cdae7c9faf0f470ab1b89582") 0.024023 (SimpleSwapBuyOffer("ltc1qax3ekgct0ykujwp68v752q4wayhcv7rxw57ckc",pfgaddrstr_addr "Pr8HpajzmKE5XDjvgmPgQkdRptFKU68UtPB",31000000000000L,744710517L));
      Printf.fprintf f "1678535172, 50538cfb14497b7b7ac4053749429dc0b9d88238cdae7c9faf0f470ab1b89582, ltc1qax3ekgct0ykujwp68v752q4wayhcv7rxw57ckc, Pr8HpajzmKE5XDjvgmPgQkdRptFKU68UtPB, 31000000000000, 744710517, 0.024023\n";
      ltc_insert_swap_buyoffer 1678556638L (hexstring_hashval "5053b5a38e076c79a8fa0a1f17c666cd1f58f9d428d5142dbafa07d72c2b843c") 0.02707 (SimpleSwapBuyOffer("ltc1qhph6qn7wzc4d0dsqf3tgep7ty8jp238yflk037",pfgaddrstr_addr "PrRw5vV9GDZYEqWcSXhGs3hhpJ7y96Rk1WA",21000000000000L,568475500L));
      Printf.fprintf f "1678556638, 5053b5a38e076c79a8fa0a1f17c666cd1f58f9d428d5142dbafa07d72c2b843c, ltc1qhph6qn7wzc4d0dsqf3tgep7ty8jp238yflk037, PrRw5vV9GDZYEqWcSXhGs3hhpJ7y96Rk1WA, 21000000000000, 568475500, 0.02707\n";
      ltc_insert_swap_buyoffer 1678634347L (hexstring_hashval "5053f2b8a47919f58249c5d71af7d89029f8b86e7ed61c3cd9a166d1717b4f07") 0.024088 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "PrRMcgdVBcrfxVNPzWuX4pfyx8qMRF7K5Sp",23600000000000L,568473500L));
      Printf.fprintf f "1678634347, 5053f2b8a47919f58249c5d71af7d89029f8b86e7ed61c3cd9a166d1717b4f07, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, PrRMcgdVBcrfxVNPzWuX4pfyx8qMRF7K5Sp, 23600000000000, 568473500, 0.024088\n";
      ltc_insert_swap_buyoffer 1679340426L (hexstring_hashval "505375a1e15277785cf2f6e99981f73fee59940508db7eb78440ddeb4ce1ca80") 0.02708 (SimpleSwapBuyOffer("ltc1qax3ekgct0ykujwp68v752q4wayhcv7rxw57ckc",pfgaddrstr_addr "Pr8HpajzmKE5XDjvgmPgQkdRptFKU68UtPB",27500000000000L,744708517L));
      Printf.fprintf f "1679340426, 505375a1e15277785cf2f6e99981f73fee59940508db7eb78440ddeb4ce1ca80, ltc1qax3ekgct0ykujwp68v752q4wayhcv7rxw57ckc, Pr8HpajzmKE5XDjvgmPgQkdRptFKU68UtPB, 27500000000000, 744708517, 0.02708\n";
      ltc_insert_swap_buyoffer 1679481630L (hexstring_hashval "505317ff9153c276e6a4d04d0722abf83c7e61450cc615a67109cf1e4d011ad7") 0.030028 (SimpleSwapBuyOffer("ltc1qax3ekgct0ykujwp68v752q4wayhcv7rxw57ckc",pfgaddrstr_addr "Pr8HpajzmKE5XDjvgmPgQkdRptFKU68UtPB",24800000000000L,744706517L));
      Printf.fprintf f "1679481630, 505317ff9153c276e6a4d04d0722abf83c7e61450cc615a67109cf1e4d011ad7, ltc1qax3ekgct0ykujwp68v752q4wayhcv7rxw57ckc, Pr8HpajzmKE5XDjvgmPgQkdRptFKU68UtPB, 24800000000000, 744706517, 0.030028\n";
      ltc_insert_swap_buyoffer 1679651339L (hexstring_hashval "505391bf901dd2d8f8d83c86d06380f5ba42fb6ac710ea9b512c321f2fdbbc5c") 0.02708 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr4s2XxvsMMb8RptYcTKhsg1vZ874rqQpU6",27500000000000L,744703517L));
      Printf.fprintf f "1679651339, 505391bf901dd2d8f8d83c86d06380f5ba42fb6ac710ea9b512c321f2fdbbc5c, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr4s2XxvsMMb8RptYcTKhsg1vZ874rqQpU6, 27500000000000, 744703517, 0.02708\n";
      ltc_insert_swap_buyoffer 1679839199L (hexstring_hashval "5053594a6d7af5200e305eb654a743461b20308faec8d8d4f025cd5b240cdf01") 0.026996 (SimpleSwapBuyOffer("ltc1qx00xwl5svpjhw3c5jd7j38zek4jwwqe874d7ep",pfgaddrstr_addr "Pr3WKxs7m61sJM1KsstcD7teY3T7TkE4awu",21000000000000L,566913000L));
      Printf.fprintf f "1679839199, 5053594a6d7af5200e305eb654a743461b20308faec8d8d4f025cd5b240cdf01, ltc1qx00xwl5svpjhw3c5jd7j38zek4jwwqe874d7ep, Pr3WKxs7m61sJM1KsstcD7teY3T7TkE4awu, 21000000000000, 566913000, 0.026996\n";
      ltc_insert_swap_buyoffer 1679948481L (hexstring_hashval "5053ac3510361789dd74e947ab06434be596c3c38e3dcf857eb469b015b04e71") 0.026027 (SimpleSwapBuyOffer("ltc1qsysrtlgvlu8eqsjta0g6vlhq79njujp7j2kkc3",pfgaddrstr_addr "PrBWy67VR7SXMAMei1R8eyRkAjy6H6QNNrB",23300000000000L,606424400L));
      Printf.fprintf f "1679948481, 5053ac3510361789dd74e947ab06434be596c3c38e3dcf857eb469b015b04e71, ltc1qsysrtlgvlu8eqsjta0g6vlhq79njujp7j2kkc3, PrBWy67VR7SXMAMei1R8eyRkAjy6H6QNNrB, 23300000000000, 606424400, 0.026027\n";
      ltc_insert_swap_buyoffer 1680178640L (hexstring_hashval "5053c87d0190644b23b2418e5c6304666f1e99967b0c46eb7320c1582fbb966a") 0.027068 (SimpleSwapBuyOffer("ltc1qsysrtlgvlu8eqsjta0g6vlhq79njujp7j2kkc3",pfgaddrstr_addr "PrBWy67VR7SXMAMei1R8eyRkAjy6H6QNNrB",22400000000000L,606324400L));
      Printf.fprintf f "1680178640, 5053c87d0190644b23b2418e5c6304666f1e99967b0c46eb7320c1582fbb966a, ltc1qsysrtlgvlu8eqsjta0g6vlhq79njujp7j2kkc3, PrBWy67VR7SXMAMei1R8eyRkAjy6H6QNNrB, 22400000000000, 606324400, 0.027068\n";
      ltc_insert_swap_buyoffer 1680263905L (hexstring_hashval "5053bb504733c4a0c8a40b9770b3de6f14da4bd7a94ff7d5c26e60314f0d3847") 0.028029 (SimpleSwapBuyOffer("ltc1qkjk02a0qlxlp0tzlfaueed3ft4s4qs9qz58l22",pfgaddrstr_addr "PrBWy67VR7SXMAMei1R8eyRkAjy6H6QNNrB",43300000000000L,1213675000L));
      Printf.fprintf f "1680263905, 5053bb504733c4a0c8a40b9770b3de6f14da4bd7a94ff7d5c26e60314f0d3847, ltc1qkjk02a0qlxlp0tzlfaueed3ft4s4qs9qz58l22, PrBWy67VR7SXMAMei1R8eyRkAjy6H6QNNrB, 43300000000000, 1213675000, 0.028029\n";
      ltc_insert_swap_buyoffer 1680264525L (hexstring_hashval "5053065b37daab8f37bebbc85a1eee6829beaf0d05ad99b7ad6033cf035cfe36") 0.02803 (SimpleSwapBuyOffer("ltc1qkjk02a0qlxlp0tzlfaueed3ft4s4qs9qz58l22",pfgaddrstr_addr "PrBWy67VR7SXMAMei1R8eyRkAjy6H6QNNrB",43300000000000L,1213678500L));
      Printf.fprintf f "1680264525, 5053065b37daab8f37bebbc85a1eee6829beaf0d05ad99b7ad6033cf035cfe36, ltc1qkjk02a0qlxlp0tzlfaueed3ft4s4qs9qz58l22, PrBWy67VR7SXMAMei1R8eyRkAjy6H6QNNrB, 43300000000000, 1213678500, 0.02803\n";
      ltc_insert_swap_buyoffer 1680281708L (hexstring_hashval "5053b6aba3c38beb4f580b8df1333cfe359e36a891ccc0342dc239cd27ec4faf") 0.025024 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9Wq4G52T3K8rUEpkwcAM33CPTQf6aYyw4",48500000000000L,1213676500L));
      Printf.fprintf f "1680281708, 5053b6aba3c38beb4f580b8df1333cfe359e36a891ccc0342dc239cd27ec4faf, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9Wq4G52T3K8rUEpkwcAM33CPTQf6aYyw4, 48500000000000, 1213676500, 0.025024\n";
      ltc_insert_swap_buyoffer 1680345705L (hexstring_hashval "5053803b94b424b403e7da076a47059a62ea1087dad33617bb5dc90c06965228") 0.025 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9Wq4G52T3K8rUEpkwcAM33CPTQf6aYyw4",24400000000000L,610000000L));
      Printf.fprintf f "1680345705, 5053803b94b424b403e7da076a47059a62ea1087dad33617bb5dc90c06965228, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9Wq4G52T3K8rUEpkwcAM33CPTQf6aYyw4, 24400000000000, 610000000, 0.025\n";
      ltc_insert_swap_buyoffer 1680345881L (hexstring_hashval "5053af9279f58471ec17a68004d34f58e2e934494f2af146c010104a3b940e4c") 0.02602 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9Wq4G52T3K8rUEpkwcAM33CPTQf6aYyw4",23200000000000L,603673500L));
      Printf.fprintf f "1680345881, 5053af9279f58471ec17a68004d34f58e2e934494f2af146c010104a3b940e4c, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9Wq4G52T3K8rUEpkwcAM33CPTQf6aYyw4, 23200000000000, 603673500, 0.02602\n";
      ltc_insert_swap_buyoffer 1686209224L (hexstring_hashval "5053e30e20b21b7991a327f49c2a4142bc3aed6722ce0a12488859a734daa140") 0.02 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr2zVTzvYCBMGhvwheb8RR2SF6BLV7ktuVN",25000000000000L,500000000L));
      Printf.fprintf f "1686209224, 5053e30e20b21b7991a327f49c2a4142bc3aed6722ce0a12488859a734daa140, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr2zVTzvYCBMGhvwheb8RR2SF6BLV7ktuVN, 25000000000000, 500000000, 0.02\n";
      ltc_insert_swap_buyoffer 1686937288L (hexstring_hashval "505361909e02009b24b87ef5e4d587acdb57a6760b1cecf0cb5d4bc70620e8e1") 0.001 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",100000000000000L,100000000L));
      Printf.fprintf f "1686937288, 505361909e02009b24b87ef5e4d587acdb57a6760b1cecf0cb5d4bc70620e8e1, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 100000000000000, 100000000, 0.001\n";
      ltc_insert_swap_buyoffer 1687019044L (hexstring_hashval "50534fcadab32ae3c0a824ee7246458886567e19d5ff7e0002319cdf9f36f7a1") 0.01 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",10000000000000L,100000000L));
      Printf.fprintf f "1687019044, 50534fcadab32ae3c0a824ee7246458886567e19d5ff7e0002319cdf9f36f7a1, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 10000000000000, 100000000, 0.01\n";
      ltc_insert_swap_buyoffer 1687091390L (hexstring_hashval "5053ff8755e916ddf5e21f2f2a461d84c6ef9f5ea317fdee1d9f733382bf0de4") 0.1 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",1000000000000L,100000000L));
      Printf.fprintf f "1687091390, 5053ff8755e916ddf5e21f2f2a461d84c6ef9f5ea317fdee1d9f733382bf0de4, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 1000000000000, 100000000, 0.1\n";
      ltc_insert_swap_buyoffer 1687116088L (hexstring_hashval "50536a69f3b4a32bba10c8579ff4afc036224db49dc952ac5c9f49f1727434d1") 0.05 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",2000000000000L,100000000L));
      Printf.fprintf f "1687116088, 50536a69f3b4a32bba10c8579ff4afc036224db49dc952ac5c9f49f1727434d1, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 2000000000000, 100000000, 0.05\n";
      ltc_insert_swap_buyoffer 1687189326L (hexstring_hashval "5053bc11ae649a7259fdced224acb8163879091573a6f681cace0b2c63b1258e") 0.076923 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",1300000000000L,100000000L));
      Printf.fprintf f "1687189326, 5053bc11ae649a7259fdced224acb8163879091573a6f681cace0b2c63b1258e, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 1300000000000, 100000000, 0.076923\n";
      ltc_insert_swap_buyoffer 1687279099L (hexstring_hashval "5053f47e9e17c6991ce49df6e9299c8f7fde06648a074be97a889f358301cdab") 0.066667 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",1500000000000L,100000000L));
      Printf.fprintf f "1687279099, 5053f47e9e17c6991ce49df6e9299c8f7fde06648a074be97a889f358301cdab, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 1500000000000, 100000000, 0.066667\n";
      ltc_insert_swap_buyoffer 1687362736L (hexstring_hashval "505307260f136d177380e4e3586be4d8e04c564ee0ad3ff05e5990883e4870dd") 0.071429 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",1400000000000L,100000000L));
      Printf.fprintf f "1687362736, 505307260f136d177380e4e3586be4d8e04c564ee0ad3ff05e5990883e4870dd, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 1400000000000, 100000000, 0.071429\n";
      ltc_insert_swap_buyoffer 1687446367L (hexstring_hashval "5053c9becb32928aaf21f163b120230f0f79aa4bc274f2fc477575cb7f843af1") 0.075 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",12000000000000L,900000000L));
      Printf.fprintf f "1687446367, 5053c9becb32928aaf21f163b120230f0f79aa4bc274f2fc477575cb7f843af1, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 12000000000000, 900000000, 0.075\n";
      ltc_insert_swap_buyoffer 1687520368L (hexstring_hashval "50533d03635b5ecd4942a926cf800978dcaf5c79cb94282275597625624f41fb") 0.073171 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",12300000000000L,900000000L));
      Printf.fprintf f "1687520368, 50533d03635b5ecd4942a926cf800978dcaf5c79cb94282275597625624f41fb, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 12300000000000, 900000000, 0.073171\n";
      ltc_insert_swap_buyoffer 1687616990L (hexstring_hashval "5053aba61daa7cacda97829f5429dc293e6e9b1b566cdee562af796c173129c8") 0.072 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",12500000000000L,900000000L));
      Printf.fprintf f "1687616990, 5053aba61daa7cacda97829f5429dc293e6e9b1b566cdee562af796c173129c8, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 12500000000000, 900000000, 0.072\n";
      ltc_insert_swap_buyoffer 1687695846L (hexstring_hashval "50531260205c92d0b8d30e36e86e761194a57e314e2722d58bf8ea56650ee638") 0.071942 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",13900000000000L,1000000000L));
      Printf.fprintf f "1687695846, 50531260205c92d0b8d30e36e86e761194a57e314e2722d58bf8ea56650ee638, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 13900000000000, 1000000000, 0.071942\n";
      ltc_insert_swap_buyoffer 1688318858L (hexstring_hashval "50531ae55d6bba0cf26fe6c32c6a8d21c911fe7519091c25ce92f6cc3b121995") 0.065 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",6300000000000L,409500000L));
      Printf.fprintf f "1688318858, 50531ae55d6bba0cf26fe6c32c6a8d21c911fe7519091c25ce92f6cc3b121995, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 6300000000000, 409500000, 0.065\n";
      ltc_insert_swap_buyoffer 1688319636L (hexstring_hashval "50533addb7e8268a805435ab48ec1f46f4ffb3ed02cd5f5b0343700ad9b72117") 0.07169 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",5680000000000L,407200000L));
      Printf.fprintf f "1688319636, 50533addb7e8268a805435ab48ec1f46f4ffb3ed02cd5f5b0343700ad9b72117, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 5680000000000, 407200000, 0.07169\n";
      ltc_insert_swap_buyoffer 1688497292L (hexstring_hashval "50535c11244b2a3c6634f86ba2605da893e98248d0a2f2f549ffe43479acf41a") 0.071939 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",9800000000000L,705000000L));
      Printf.fprintf f "1688497292, 50535c11244b2a3c6634f86ba2605da893e98248d0a2f2f549ffe43479acf41a, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 9800000000000, 705000000, 0.071939\n";
      ltc_insert_swap_buyoffer 1688565143L (hexstring_hashval "5053df2609de089a381d40d1d4d5c1e9e8ac7748909aa58126f6b24850cf6741") 0.071939 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",9800000000000L,705000000L));
      Printf.fprintf f "1688565143, 5053df2609de089a381d40d1d4d5c1e9e8ac7748909aa58126f6b24850cf6741, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 9800000000000, 705000000, 0.071939\n";
      ltc_insert_swap_buyoffer 1688645524L (hexstring_hashval "5053378d1e0c320a4e207f522f345cbba4335b4a64e4906b23538e386e27cb23") 0.071939 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",9800000000000L,705000000L));
      Printf.fprintf f "1688645524, 5053378d1e0c320a4e207f522f345cbba4335b4a64e4906b23538e386e27cb23, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 9800000000000, 705000000, 0.071939\n";
      ltc_insert_swap_buyoffer 1688663001L (hexstring_hashval "5053c67dc7307fae6aec9ff6a330e55fafef9476d0a6b30c3ad1c260faae8ccd") 0.071939 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",9800000000000L,705000000L));
      Printf.fprintf f "1688663001, 5053c67dc7307fae6aec9ff6a330e55fafef9476d0a6b30c3ad1c260faae8ccd, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 9800000000000, 705000000, 0.071939\n";
      ltc_insert_swap_buyoffer 1688728926L (hexstring_hashval "50537636c1fc46f6e99cefd1df879763bee2aa66f60904b6f199deb5fe462321") 0.071939 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",9800000000000L,705000000L));
      Printf.fprintf f "1688728926, 50537636c1fc46f6e99cefd1df879763bee2aa66f60904b6f199deb5fe462321, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 9800000000000, 705000000, 0.071939\n";
      ltc_insert_swap_buyoffer 1688750504L (hexstring_hashval "505393f9e869332f48284c75fdebd7522edd9e8850f17596dd23a6d46272f148") 0.071939 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",9800000000000L,705000000L));
      Printf.fprintf f "1688750504, 505393f9e869332f48284c75fdebd7522edd9e8850f17596dd23a6d46272f148, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 9800000000000, 705000000, 0.071939\n";
      ltc_insert_swap_buyoffer 1688818836L (hexstring_hashval "50530b54198c918b8379baadf53503bc8e7f3dba6cdb342207df7098952c7d27") 0.071939 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",9800000000000L,705000000L));
      Printf.fprintf f "1688818836, 50530b54198c918b8379baadf53503bc8e7f3dba6cdb342207df7098952c7d27, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 9800000000000, 705000000, 0.071939\n";
      ltc_insert_swap_buyoffer 1688824399L (hexstring_hashval "5053687b2e20ee1c2047eecf61ec948e5c73d49dbb55e382dec0374cd01475b4") 0.071939 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",10325000000000L,742770000L));
      Printf.fprintf f "1688824399, 5053687b2e20ee1c2047eecf61ec948e5c73d49dbb55e382dec0374cd01475b4, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 10325000000000, 742770000, 0.071939\n";
      ltc_insert_swap_buyoffer 1688831836L (hexstring_hashval "5053b62c680c37c3af3b395e318325148dde88111ef161cda42a6f90733c1bbf") 0.071939 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",9800000000000L,705000000L));
      Printf.fprintf f "1688831836, 5053b62c680c37c3af3b395e318325148dde88111ef161cda42a6f90733c1bbf, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 9800000000000, 705000000, 0.071939\n";
      ltc_insert_swap_buyoffer 1689438357L (hexstring_hashval "505395d43710cbc9ef956da1715d3ad5763fe8bb9c124faf1461ca4bbf1b3e4a") 0.058 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",13000000000000L,754000000L));
      Printf.fprintf f "1689438357, 505395d43710cbc9ef956da1715d3ad5763fe8bb9c124faf1461ca4bbf1b3e4a, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 13000000000000, 754000000, 0.058\n";
      ltc_insert_swap_buyoffer 1690058544L (hexstring_hashval "50533451640a0cd5c2a0a9e2d301266d53bd8b4ba1471a8a61cd6d49eaa272fd") 0.057672 (SimpleSwapBuyOffer("ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",13400000000000L,772800000L));
      Printf.fprintf f "1690058544, 50533451640a0cd5c2a0a9e2d301266d53bd8b4ba1471a8a61cd6d49eaa272fd, ltc1quct8x7ndvn3qwzn9zg4yd8h546e90mflguguzl, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 13400000000000, 772800000, 0.057672\n";
      ltc_insert_swap_buyoffer 1690195221L (hexstring_hashval "50536703df4d4d958852146b2ab015b1a41ab931af5e80879b56a639df34df77") 0.045459 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr6Dwh98c4v8APoxAwGCfkyPRcehNQhgX3J",17000000000000L,772799400L));
      Printf.fprintf f "1690195221, 50536703df4d4d958852146b2ab015b1a41ab931af5e80879b56a639df34df77, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr6Dwh98c4v8APoxAwGCfkyPRcehNQhgX3J, 17000000000000, 772799400, 0.045459\n";
      ltc_insert_swap_buyoffer 1692379754L (hexstring_hashval "5053d9afb3938ee0c793adb7b48e4b360ff5db089b7d0b5b12430b479468075e") 0.08 (SimpleSwapBuyOffer("ltc1qncduc7hm4uwjukzd2n4a72dg9pspwcay8qyv0w",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",11312500000000L,905000000L));
      Printf.fprintf f "1692379754, 5053d9afb3938ee0c793adb7b48e4b360ff5db089b7d0b5b12430b479468075e, ltc1qncduc7hm4uwjukzd2n4a72dg9pspwcay8qyv0w, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 11312500000000, 905000000, 0.08\n";
      ltc_insert_swap_buyoffer 1692450692L (hexstring_hashval "5053a5ddafd7e8092a0bd1e194333c96f6d2c8397920abd58baeb8d6c0aa2144") 0.07126 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "PrPN3nCpL1zbESWWndJ2unmxwKWYHQCQAaA",12700000000000L,904999425L));
      Printf.fprintf f "1692450692, 5053a5ddafd7e8092a0bd1e194333c96f6d2c8397920abd58baeb8d6c0aa2144, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, PrPN3nCpL1zbESWWndJ2unmxwKWYHQCQAaA, 12700000000000, 904999425, 0.07126\n";
      ltc_insert_swap_buyoffer 1692534401L (hexstring_hashval "5053434bdb41d3c9fbab5bcdd08aef502ae0e2934686a95e3c8219846f764284") 0.075408 (SimpleSwapBuyOffer("ltc1qxw4hrzxx96r8v2a5mc2gpnzcwg5d2r6wfdrj75",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",12000000000000L,904900000L));
      Printf.fprintf f "1692534401, 5053434bdb41d3c9fbab5bcdd08aef502ae0e2934686a95e3c8219846f764284, ltc1qxw4hrzxx96r8v2a5mc2gpnzcwg5d2r6wfdrj75, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 12000000000000, 904900000, 0.075408\n";
      ltc_insert_swap_buyoffer 1692609876L (hexstring_hashval "50539fc06a496e7e5e68a91d1a8ef6047324e73a216b1235014223e3ca56c2ed") 0.060327 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr4u25CCVsTV44E7F6eS1YEpDqBND9it1m3",15000000000000L,904899425L));
      Printf.fprintf f "1692609876, 50539fc06a496e7e5e68a91d1a8ef6047324e73a216b1235014223e3ca56c2ed, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr4u25CCVsTV44E7F6eS1YEpDqBND9it1m3, 15000000000000, 904899425, 0.060327\n";
      ltc_insert_swap_buyoffer 1694348947L (hexstring_hashval "50531e32eb721bd94931d5eabf65793fb52d0ca77e1f15de04ada0ad2806f975") 0.0754 (SimpleSwapBuyOffer("ltc1qpwfqf2su364e9tzdcyzmx68jraqsgs6mjkalj0",pfgaddrstr_addr "PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR",10700000000000L,806780000L));
      Printf.fprintf f "1694348947, 50531e32eb721bd94931d5eabf65793fb52d0ca77e1f15de04ada0ad2806f975, ltc1qpwfqf2su364e9tzdcyzmx68jraqsgs6mjkalj0, PrCz1bAgrvrHgNEdqC2RxXVybzuTECo7JfR, 10700000000000, 806780000, 0.0754\n";
      ltc_insert_swap_buyoffer 1694419689L (hexstring_hashval "505398235831f812815a99e659d8b27c23dcf0e5cc6890a3eee6426f59fa6a38") 0.05 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr4u25CCVsTV44E7F6eS1YEpDqBND9it1m3",14000000000000L,700000000L));
      Printf.fprintf f "1694419689, 505398235831f812815a99e659d8b27c23dcf0e5cc6890a3eee6426f59fa6a38, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr4u25CCVsTV44E7F6eS1YEpDqBND9it1m3, 14000000000000, 700000000, 0.05\n";
      ltc_insert_swap_buyoffer 1694720027L (hexstring_hashval "5053ad5ef22ff77167924272a5beb95f174f74583245fe6edaff0bd60c95c1e7") 0.050071 (SimpleSwapBuyOffer("ltc1qpwfqf2su364e9tzdcyzmx68jraqsgs6mjkalj0",pfgaddrstr_addr "PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW",14000000000000L,701000000L));
      Printf.fprintf f "1694720027, 5053ad5ef22ff77167924272a5beb95f174f74583245fe6edaff0bd60c95c1e7, ltc1qpwfqf2su364e9tzdcyzmx68jraqsgs6mjkalj0, PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW, 14000000000000, 701000000, 0.050071\n";
      ltc_insert_swap_buyoffer 1694961526L (hexstring_hashval "5053d97141933cac925d2b50a26d7c92c19276fb69945867c2cd037a1b59b654") 0.04 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr8vk9QsnKV5XNfNT8xgkjSN2kVzMvSXL7z",17525000000000L,700999425L));
      Printf.fprintf f "1694961526, 5053d97141933cac925d2b50a26d7c92c19276fb69945867c2cd037a1b59b654, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr8vk9QsnKV5XNfNT8xgkjSN2kVzMvSXL7z, 17525000000000, 700999425, 0.04\n";
      ltc_insert_swap_buyoffer 1695497183L (hexstring_hashval "5053ee630f1ecba6975cb5fb8cc09ffb9f2124fde824cc6d040df144df9b575a") 0.045128 (SimpleSwapBuyOffer("ltc1q83vcchmjl9a35ym8er2zxywsrqdapv26el53ks",pfgaddrstr_addr "PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW",31200000000000L,1408000000L));
      Printf.fprintf f "1695497183, 5053ee630f1ecba6975cb5fb8cc09ffb9f2124fde824cc6d040df144df9b575a, ltc1q83vcchmjl9a35ym8er2zxywsrqdapv26el53ks, PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW, 31200000000000, 1408000000, 0.045128\n";
      ltc_insert_swap_buyoffer 1695565662L (hexstring_hashval "5053b93bf2e7dd7c0b25c77d06d85267692f50fa490f5198fb1a994b1807df78") 0.04508 (SimpleSwapBuyOffer("ltc1q83vcchmjl9a35ym8er2zxywsrqdapv26el53ks",pfgaddrstr_addr "PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW",31100000000000L,1402000000L));
      Printf.fprintf f "1695565662, 5053b93bf2e7dd7c0b25c77d06d85267692f50fa490f5198fb1a994b1807df78, ltc1q83vcchmjl9a35ym8er2zxywsrqdapv26el53ks, PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW, 31100000000000, 1402000000, 0.04508\n";
      ltc_insert_swap_buyoffer 1695630072L (hexstring_hashval "505369d651dc9dd38d696db0289d7164393df9d628725ce292db4fff8cb522f3") 0.03505 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr4DsD7aZHQiF4jABz14URj4d5eAd39Dm3t",40000000000000L,1401999425L));
      Printf.fprintf f "1695630072, 505369d651dc9dd38d696db0289d7164393df9d628725ce292db4fff8cb522f3, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr4DsD7aZHQiF4jABz14URj4d5eAd39Dm3t, 40000000000000, 1401999425, 0.03505\n";
      ltc_insert_swap_buyoffer 1695745901L (hexstring_hashval "505342a276c4b2f01748bd5f2f9f4f59f17d9a5c3af57a07fb38b43af983faba") 0.04508 (SimpleSwapBuyOffer("ltc1qy9tkc502268e0akr6rgyx69rjecjg8qhfstxrs",pfgaddrstr_addr "PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW",31100000000000L,1402000000L));
      Printf.fprintf f "1695745901, 505342a276c4b2f01748bd5f2f9f4f59f17d9a5c3af57a07fb38b43af983faba, ltc1qy9tkc502268e0akr6rgyx69rjecjg8qhfstxrs, PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW, 31100000000000, 1402000000, 0.04508\n";
      ltc_insert_swap_buyoffer 1695802831L (hexstring_hashval "5053b49d6b50afee17bd6c8d7d65751541189e56bb4bdb63d150cf8add7978ce") 0.03505 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr7p1TprXr9iDo9iohLcN6uzGy9c3wv3nAM",40000000000000L,1401999425L));
      Printf.fprintf f "1695802831, 5053b49d6b50afee17bd6c8d7d65751541189e56bb4bdb63d150cf8add7978ce, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr7p1TprXr9iDo9iohLcN6uzGy9c3wv3nAM, 40000000000000, 1401999425, 0.03505\n";
      ltc_insert_swap_buyoffer 1696002379L (hexstring_hashval "505390426ed820feadc026ef13c3a89eece5966d8f4ff4459854fb7fe2d77641") 0.040853 (SimpleSwapBuyOffer("ltc1q0qep6paazql3dacka55kuhq7g8anx30jhzz4s4",pfgaddrstr_addr "PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW",34000000000000L,1389000000L));
      Printf.fprintf f "1696002379, 505390426ed820feadc026ef13c3a89eece5966d8f4ff4459854fb7fe2d77641, ltc1q0qep6paazql3dacka55kuhq7g8anx30jhzz4s4, PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW, 34000000000000, 1389000000, 0.040853\n";
      ltc_insert_swap_buyoffer 1696092989L (hexstring_hashval "50536862920db25723e972b7ea8106f283422b8409ee373cb4fe5532cc3a6772") 0.030065 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr5UQ923Zpc9rEsdJa12okUxW7qwAARuopr",46200000000000L,1388999425L));
      Printf.fprintf f "1696092989, 50536862920db25723e972b7ea8106f283422b8409ee373cb4fe5532cc3a6772, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr5UQ923Zpc9rEsdJa12okUxW7qwAARuopr, 46200000000000, 1388999425, 0.030065\n";
      ltc_insert_swap_buyoffer 1696101493L (hexstring_hashval "50536e53436acf86fe65dffd7fb8dd9f58c1d984a08b6ebfb2602f39bde5da15") 0.03125 (SimpleSwapBuyOffer("ltc1q7dcr9sq7gx7rykkue70ktr8g0wgsu7d096c9qw",pfgaddrstr_addr "Pr5g7cTyPo8LXgznWn78XehVqAJ6fXVZne5",1600000000000L,50000000L));
      Printf.fprintf f "1696101493, 50536e53436acf86fe65dffd7fb8dd9f58c1d984a08b6ebfb2602f39bde5da15, ltc1q7dcr9sq7gx7rykkue70ktr8g0wgsu7d096c9qw, Pr5g7cTyPo8LXgznWn78XehVqAJ6fXVZne5, 1600000000000, 50000000, 0.03125\n";
      ltc_insert_swap_buyoffer 1696163275L (hexstring_hashval "5053332ba6401d70155687d92f1f05c1adc700d3202d42e2f2e1b4e21aac1ccf") 0.033333 (SimpleSwapBuyOffer("ltc1q7dcr9sq7gx7rykkue70ktr8g0wgsu7d096c9qw",pfgaddrstr_addr "Pr5g7cTyPo8LXgznWn78XehVqAJ6fXVZne5",600000000000L,20000000L));
      Printf.fprintf f "1696163275, 5053332ba6401d70155687d92f1f05c1adc700d3202d42e2f2e1b4e21aac1ccf, ltc1q7dcr9sq7gx7rykkue70ktr8g0wgsu7d096c9qw, Pr5g7cTyPo8LXgznWn78XehVqAJ6fXVZne5, 600000000000, 20000000, 0.033333\n";
      ltc_insert_swap_buyoffer 1696164894L (hexstring_hashval "5053679b401dd2bee971cfbad6b6299d7ae90c07f8e034b05ec69ec41cfc8879") 0.036667 (SimpleSwapBuyOffer("ltc1q7dcr9sq7gx7rykkue70ktr8g0wgsu7d096c9qw",pfgaddrstr_addr "Pr5g7cTyPo8LXgznWn78XehVqAJ6fXVZne5",300000000000L,11000000L));
      Printf.fprintf f "1696164894, 5053679b401dd2bee971cfbad6b6299d7ae90c07f8e034b05ec69ec41cfc8879, ltc1q7dcr9sq7gx7rykkue70ktr8g0wgsu7d096c9qw, Pr5g7cTyPo8LXgznWn78XehVqAJ6fXVZne5, 300000000000, 11000000, 0.036667\n";
      ltc_insert_swap_buyoffer 1696166738L (hexstring_hashval "5053c6ee5bae04c2ba5529e7023ac0a55ac0990bfe60e407ca4990197f7030fa") 0.04 (SimpleSwapBuyOffer("ltc1q7dcr9sq7gx7rykkue70ktr8g0wgsu7d096c9qw",pfgaddrstr_addr "Pr5g7cTyPo8LXgznWn78XehVqAJ6fXVZne5",300000000000L,12000000L));
      Printf.fprintf f "1696166738, 5053c6ee5bae04c2ba5529e7023ac0a55ac0990bfe60e407ca4990197f7030fa, ltc1q7dcr9sq7gx7rykkue70ktr8g0wgsu7d096c9qw, Pr5g7cTyPo8LXgznWn78XehVqAJ6fXVZne5, 300000000000, 12000000, 0.04\n";
      ltc_insert_swap_buyoffer 1696357348L (hexstring_hashval "505386043b7dc0086d3953fe7814b387517dbf91bd92d5283c7f91b74a14405b") 0.040029 (SimpleSwapBuyOffer("ltc1q0qep6paazql3dacka55kuhq7g8anx30jhzz4s4",pfgaddrstr_addr "PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW",35000000000000L,1401000000L));
      Printf.fprintf f "1696357348, 505386043b7dc0086d3953fe7814b387517dbf91bd92d5283c7f91b74a14405b, ltc1q0qep6paazql3dacka55kuhq7g8anx30jhzz4s4, PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW, 35000000000000, 1401000000, 0.040029\n";
      ltc_insert_swap_buyoffer 1696582362L (hexstring_hashval "5053c777eb90e4a296f51f18875c322f28020872fd72ab2bfd16d27069d4e8b8") 0.032965 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr5UQ923Zpc9rEsdJa12okUxW7qwAARuopr",42500000000000L,1400999425L));
      Printf.fprintf f "1696582362, 5053c777eb90e4a296f51f18875c322f28020872fd72ab2bfd16d27069d4e8b8, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr5UQ923Zpc9rEsdJa12okUxW7qwAARuopr, 42500000000000, 1400999425, 0.032965\n";
      ltc_insert_swap_buyoffer 1697144830L (hexstring_hashval "5053768d4b7e513df8b2f5c9b6f22548e5274fd3f8b3f0b7da5156355fa3ca4b") 0.040029 (SimpleSwapBuyOffer("ltc1q0qep6paazql3dacka55kuhq7g8anx30jhzz4s4",pfgaddrstr_addr "PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW",35000000000000L,1401000000L));
      Printf.fprintf f "1697144830, 5053768d4b7e513df8b2f5c9b6f22548e5274fd3f8b3f0b7da5156355fa3ca4b, ltc1q0qep6paazql3dacka55kuhq7g8anx30jhzz4s4, PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW, 35000000000000, 1401000000, 0.040029\n";
      ltc_insert_swap_buyoffer 1697191238L (hexstring_hashval "50535cd7d8e3d89381387cf771dffe4bb34f0be5aaaf0a1c51a7aac50453ff24") 0.03 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr5UQ923Zpc9rEsdJa12okUxW7qwAARuopr",46700000000000L,1400999425L));
      Printf.fprintf f "1697191238, 50535cd7d8e3d89381387cf771dffe4bb34f0be5aaaf0a1c51a7aac50453ff24, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr5UQ923Zpc9rEsdJa12okUxW7qwAARuopr, 46700000000000, 1400999425, 0.03\n";
      ltc_insert_swap_buyoffer 1697308531L (hexstring_hashval "505364453ccc2c61d860768ba74e14be58e0382366b594ddb8b177a72b39fee1") 0.040029 (SimpleSwapBuyOffer("ltc1qmupp0679khw0aerre2ewy6k25m78r6edj6klqv",pfgaddrstr_addr "PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW",35000000000000L,1401000000L));
      Printf.fprintf f "1697308531, 505364453ccc2c61d860768ba74e14be58e0382366b594ddb8b177a72b39fee1, ltc1qmupp0679khw0aerre2ewy6k25m78r6edj6klqv, PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW, 35000000000000, 1401000000, 0.040029\n";
      ltc_insert_swap_buyoffer 1697362196L (hexstring_hashval "5053c06b0aaeaf6d1b3a8d6cce7b157a822c9d9b3560afb3ed6c33ba10edf9ac") 0.032965 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr4VYdXUkkxs6NZ9tM77rZN54zaXgzqtRWD",42500000000000L,1400999425L));
      Printf.fprintf f "1697362196, 5053c06b0aaeaf6d1b3a8d6cce7b157a822c9d9b3560afb3ed6c33ba10edf9ac, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr4VYdXUkkxs6NZ9tM77rZN54zaXgzqtRWD, 42500000000000, 1400999425, 0.032965\n";
      ltc_insert_swap_buyoffer 1697905931L (hexstring_hashval "5053ee1123106f0a3197f24dbc55bcfd5b571b919be1a791ed971d30363563af") 0.040066 (SimpleSwapBuyOffer("ltc1qz04qwneh7jve7zuxgxcuz3qm3ej8rx6m39d2ft",pfgaddrstr_addr "PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW",34800000000000L,1394286000L));
      Printf.fprintf f "1697905931, 5053ee1123106f0a3197f24dbc55bcfd5b571b919be1a791ed971d30363563af, ltc1qz04qwneh7jve7zuxgxcuz3qm3ej8rx6m39d2ft, PrBNNFp4M5z1S5Xft848PxHr6EEkG95EBQW, 34800000000000, 1394286000, 0.040066\n";
      ltc_insert_swap_buyoffer 1697970831L (hexstring_hashval "5053c908178d2a1b5990b55862b099198f495ada08c4e5002dda48b8eb5f204e") 0.036028 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "PrBSRj9GEGJQdKtHpTazpmFn2ntYpPnZPVv",38700000000000L,1394285425L));
      Printf.fprintf f "1697970831, 5053c908178d2a1b5990b55862b099198f495ada08c4e5002dda48b8eb5f204e, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, PrBSRj9GEGJQdKtHpTazpmFn2ntYpPnZPVv, 38700000000000, 1394285425, 0.036028\n";
      ltc_insert_swap_buyoffer 1697984161L (hexstring_hashval "5053a35575883d6a810840f5e8bc55951bacdd38a2b12361f61a6963c37b685e") 0.038071 (SimpleSwapBuyOffer("ltc1qxx9j6xnqk909m7gzjdufnpfhwas76wf5fswk67",pfgaddrstr_addr "PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH",36800000000000L,1401000000L));
      Printf.fprintf f "1697984161, 5053a35575883d6a810840f5e8bc55951bacdd38a2b12361f61a6963c37b685e, ltc1qxx9j6xnqk909m7gzjdufnpfhwas76wf5fswk67, PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH, 36800000000000, 1401000000, 0.038071\n";
      ltc_insert_swap_buyoffer 1698081075L (hexstring_hashval "5053bb765bb7b8d0ef69b28a4cd97531a1b981617fcba103a086aedeedd14973") 0.040026 (SimpleSwapBuyOffer("ltc1qxx9j6xnqk909m7gzjdufnpfhwas76wf5fswk67",pfgaddrstr_addr "PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH",35000000000000L,1400900000L));
      Printf.fprintf f "1698081075, 5053bb765bb7b8d0ef69b28a4cd97531a1b981617fcba103a086aedeedd14973, ltc1qxx9j6xnqk909m7gzjdufnpfhwas76wf5fswk67, PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH, 35000000000000, 1400900000, 0.040026\n";
      ltc_insert_swap_buyoffer 1698246780L (hexstring_hashval "505361d90eb38e0facff516b29f052bbbf1fdc9f8ee57438fa9dbd4a05b63002") 0.037061 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "PrRiDutSEswNi5zg6xnfwDxKaYWmStDo95B",37800000000000L,1400899425L));
      Printf.fprintf f "1698246780, 505361d90eb38e0facff516b29f052bbbf1fdc9f8ee57438fa9dbd4a05b63002, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, PrRiDutSEswNi5zg6xnfwDxKaYWmStDo95B, 37800000000000, 1400899425, 0.037061\n";
      ltc_insert_swap_buyoffer 1698702729L (hexstring_hashval "50534ec39800b0b2bb0457cb5bfa4efa18fe15d07a94069e4b90773d2c00489c") 0.040029 (SimpleSwapBuyOffer("ltc1qwvscc6qjt2a2n6pudjr5vhsav2e4kjplkgyrl3",pfgaddrstr_addr "PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH",34950000000000L,1399000000L));
      Printf.fprintf f "1698702729, 50534ec39800b0b2bb0457cb5bfa4efa18fe15d07a94069e4b90773d2c00489c, ltc1qwvscc6qjt2a2n6pudjr5vhsav2e4kjplkgyrl3, PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH, 34950000000000, 1399000000, 0.040029\n";
      ltc_insert_swap_buyoffer 1699708285L (hexstring_hashval "5053a6980fa0d9c3b49126fcd808985a78c9b6dcc64a19c656c6ed7aa8c9b8ca") 0.045097 (SimpleSwapBuyOffer("ltc1qwvscc6qjt2a2n6pudjr5vhsav2e4kjplkgyrl3",pfgaddrstr_addr "PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH",31000000000000L,1398000000L));
      Printf.fprintf f "1699708285, 5053a6980fa0d9c3b49126fcd808985a78c9b6dcc64a19c656c6ed7aa8c9b8ca, ltc1qwvscc6qjt2a2n6pudjr5vhsav2e4kjplkgyrl3, PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH, 31000000000000, 1398000000, 0.045097\n";
      ltc_insert_swap_buyoffer 1699811403L (hexstring_hashval "50532f97af3798f906cb41ce598aa2a9289376dd2ca822703085b9c7b8bf5ca4") 0.040057 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",34900000000000L,1397999425L));
      Printf.fprintf f "1699811403, 50532f97af3798f906cb41ce598aa2a9289376dd2ca822703085b9c7b8bf5ca4, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 34900000000000, 1397999425, 0.040057\n";
      ltc_insert_swap_buyoffer 1700928422L (hexstring_hashval "5053aaa8ed34264088077444a2485190ef122cb1bd16b38cbee54690cea9f3a6") 0.044903 (SimpleSwapBuyOffer("ltc1qhz72nw3lh99w24n0q56c42fu8jnhg5dcfyvfmm",pfgaddrstr_addr "PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH",31000000000000L,1392000000L));
      Printf.fprintf f "1700928422, 5053aaa8ed34264088077444a2485190ef122cb1bd16b38cbee54690cea9f3a6, ltc1qhz72nw3lh99w24n0q56c42fu8jnhg5dcfyvfmm, PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH, 31000000000000, 1392000000, 0.044903\n";
      ltc_insert_swap_buyoffer 1701173055L (hexstring_hashval "5053b4f72b577b7bf10231ac57958cc85964dd32fff4f09bc20b23f68b00729d") 0.04606 (SimpleSwapBuyOffer("ltc1qhz72nw3lh99w24n0q56c42fu8jnhg5dcfyvfmm",pfgaddrstr_addr "PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH",30200000000000L,1391000000L));
      Printf.fprintf f "1701173055, 5053b4f72b577b7bf10231ac57958cc85964dd32fff4f09bc20b23f68b00729d, ltc1qhz72nw3lh99w24n0q56c42fu8jnhg5dcfyvfmm, PrDFzEnGohLkUoLS1VtqYhe9qy68vRDx9SH, 30200000000000, 1391000000, 0.04606\n";
      ltc_insert_swap_buyoffer 1701341612L (hexstring_hashval "5053bb08f31133cab662f0d68f83786b40f50bdda2cb1196ac25702d3109419e") 0.017002 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",82400000000000L,1400998875L));
      Printf.fprintf f "1701341612, 5053bb08f31133cab662f0d68f83786b40f50bdda2cb1196ac25702d3109419e, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 82400000000000, 1400998875, 0.017002\n";
      ltc_insert_swap_buyoffer 1701602224L (hexstring_hashval "505365b5fde716c2ae499a9f9735741f7b08d6dd06f40806e5072785f87d4884") 0.017002 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",82400000000000L,1400998875L));
      Printf.fprintf f "1701602224, 505365b5fde716c2ae499a9f9735741f7b08d6dd06f40806e5072785f87d4884, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 82400000000000, 1400998875, 0.017002\n";
      ltc_insert_swap_buyoffer 1702897638L (hexstring_hashval "505340a7260394f75a008604588e1d255f01e7e7f3cdee869810fc20c16e2e15") 0.016 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",25000000000000L,400000000L));
      Printf.fprintf f "1702897638, 505340a7260394f75a008604588e1d255f01e7e7f3cdee869810fc20c16e2e15, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 25000000000000, 400000000, 0.016\n";
      ltc_insert_swap_buyoffer 1702924231L (hexstring_hashval "5053f92fdcd4d692ce99e2a05372795fb6c3dada64657aaacd60d07cdeb750a9") 0.015 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",20000000000000L,300000000L));
      Printf.fprintf f "1702924231, 5053f92fdcd4d692ce99e2a05372795fb6c3dada64657aaacd60d07cdeb750a9, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 20000000000000, 300000000, 0.015\n";
      ltc_insert_swap_buyoffer 1703342278L (hexstring_hashval "505302d3844f8d46d8d18a776247ac38257435154e1e4012f2cc2c382119c2bc") 0.0155 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",19000000000000L,294500000L));
      Printf.fprintf f "1703342278, 505302d3844f8d46d8d18a776247ac38257435154e1e4012f2cc2c382119c2bc, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 19000000000000, 294500000, 0.0155\n";
      ltc_insert_swap_buyoffer 1704019383L (hexstring_hashval "50538fb5f2dd8cfb0f75d2dee53027b3809b49bddfa5382863c178a57def87c9") 0.0152 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",100000000000000L,1520000000L));
      Printf.fprintf f "1704019383, 50538fb5f2dd8cfb0f75d2dee53027b3809b49bddfa5382863c178a57def87c9, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 100000000000000, 1520000000, 0.0152\n";
      ltc_insert_swap_buyoffer 1704564671L (hexstring_hashval "50539ee413a94087a844ded585e37359da2634e9d769ade76ce945658a862cc1") 0.0151 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",100000000000000L,1510000000L));
      Printf.fprintf f "1704564671, 50539ee413a94087a844ded585e37359da2634e9d769ade76ce945658a862cc1, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 100000000000000, 1510000000, 0.0151\n";
      ltc_insert_swap_buyoffer 1704878797L (hexstring_hashval "5053e4aea587bc3d2567ce7c0db59fc0ccfd393fab26edfffdc2616bcea803db") 0.0152 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",100000000000000L,1520000000L));
      Printf.fprintf f "1704878797, 5053e4aea587bc3d2567ce7c0db59fc0ccfd393fab26edfffdc2616bcea803db, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 100000000000000, 1520000000, 0.0152\n";
      ltc_insert_swap_buyoffer 1705153626L (hexstring_hashval "505353a8b569caaecc333c8fcba2087a9d7da7701e9e51a983a9a60f681943c2") 0.015304 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",98600000000000L,1509000000L));
      Printf.fprintf f "1705153626, 505353a8b569caaecc333c8fcba2087a9d7da7701e9e51a983a9a60f681943c2, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 98600000000000, 1509000000, 0.015304\n";
      ltc_insert_swap_buyoffer 1709723459L (hexstring_hashval "505345a41cb5d451f6f14933b5807dd2958d752ce3acbb93155e8a49c909f164") 0.012567 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",120000000000000L,1508000000L));
      Printf.fprintf f "1709723459, 505345a41cb5d451f6f14933b5807dd2958d752ce3acbb93155e8a49c909f164, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 120000000000000, 1508000000, 0.012567\n";
      ltc_insert_swap_buyoffer 1710591657L (hexstring_hashval "5053d5eb7c918a1d438c79c2ee7d5f13597e195a6a3254aa39360fb2851cf31a") 0.0137 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",110000000000000L,1507000000L));
      Printf.fprintf f "1710591657, 5053d5eb7c918a1d438c79c2ee7d5f13597e195a6a3254aa39360fb2851cf31a, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 110000000000000, 1507000000, 0.0137\n";
      ltc_insert_swap_buyoffer 1710594614L (hexstring_hashval "50531183160ab3f2634de005f2f5e28337488ffb511dfbbdc25fce8492ce7304") 0.013996 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",107600000000000L,1506000000L));
      Printf.fprintf f "1710594614, 50531183160ab3f2634de005f2f5e28337488ffb511dfbbdc25fce8492ce7304, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 107600000000000, 1506000000, 0.013996\n";
      ltc_insert_swap_buyoffer 1710608794L (hexstring_hashval "5053a1bee372b9355f544d0eea8125a463c47f1f5a752c2d53a243a76636bc19") 0.020002 (SimpleSwapBuyOffer("ltc1q8ylr8f324ytanyw9ejrkmgmmse6wgjs0q528w5",pfgaddrstr_addr "PrQbKwmwDVynAnHSQ6vWNd2ZpvdcN6yFa2x",50000000000000L,1000096800L));
      Printf.fprintf f "1710608794, 5053a1bee372b9355f544d0eea8125a463c47f1f5a752c2d53a243a76636bc19, ltc1q8ylr8f324ytanyw9ejrkmgmmse6wgjs0q528w5, PrQbKwmwDVynAnHSQ6vWNd2ZpvdcN6yFa2x, 50000000000000, 1000096800, 0.020002\n";
      ltc_insert_swap_buyoffer 1710758755L (hexstring_hashval "50531bad8897c0b9cb9fb8d7a25d7dc6ad2ed30813613ace6e3256754630269f") 0.02102 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",71600000000000L,1505000000L));
      Printf.fprintf f "1710758755, 50531bad8897c0b9cb9fb8d7a25d7dc6ad2ed30813613ace6e3256754630269f, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 71600000000000, 1505000000, 0.02102\n";
      ltc_insert_swap_buyoffer 1710866264L (hexstring_hashval "5053bba5efc1edbf906ee07d7451054d91548c11f972de39ceddc7ba7589a7a3") 0.02202 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",68300000000000L,1504000000L));
      Printf.fprintf f "1710866264, 5053bba5efc1edbf906ee07d7451054d91548c11f972de39ceddc7ba7589a7a3, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 68300000000000, 1504000000, 0.02202\n";
      ltc_insert_swap_buyoffer 1710866450L (hexstring_hashval "5053d78ecd83dfc905adb61da4e6a33a17d8792a7b6425ab2318ae23071be1fe") 0.022006 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",68300000000000L,1503000000L));
      Printf.fprintf f "1710866450, 5053d78ecd83dfc905adb61da4e6a33a17d8792a7b6425ab2318ae23071be1fe, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 68300000000000, 1503000000, 0.022006\n";
      ltc_insert_swap_buyoffer 1711010514L (hexstring_hashval "505386428057e5f81da1dd1dbb8124b115c511e84d95bc0c3e697aebf77468d4") 0.021525 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",63800000000000L,1373274324L));
      Printf.fprintf f "1711010514, 505386428057e5f81da1dd1dbb8124b115c511e84d95bc0c3e697aebf77468d4, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 63800000000000, 1373274324, 0.021525\n";
      ltc_insert_swap_buyoffer 1711300355L (hexstring_hashval "5053f3c9344815157d8f498a32312b4a1873aa3020bc655ebfdb65e83e98a553") 0.022008 (SimpleSwapBuyOffer("ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k",pfgaddrstr_addr "Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm",62400000000000L,1373273774L));
      Printf.fprintf f "1711300355, 5053f3c9344815157d8f498a32312b4a1873aa3020bc655ebfdb65e83e98a553, ltc1qymp5prfxhehd7s3a67nva445u3z6el4l2tpe9k, Pr9PyTGr984XU45Vmm7oJhA2rCDxykD73fm, 62400000000000, 1373273774, 0.022008\n";
      ltc_insert_swap_buyoffer 1711454340L (hexstring_hashval "5053124039d1401f195ca4c805f46f7f16cc8ca47c37a9d6be413cf38e8615cc") 0.025007 (SimpleSwapBuyOffer("ltc1q8ylr8f324ytanyw9ejrkmgmmse6wgjs0q528w5",pfgaddrstr_addr "PrQbKwmwDVynAnHSQ6vWNd2ZpvdcN6yFa2x",36390000000000L,909999000L));
      Printf.fprintf f "1711454340, 5053124039d1401f195ca4c805f46f7f16cc8ca47c37a9d6be413cf38e8615cc, ltc1q8ylr8f324ytanyw9ejrkmgmmse6wgjs0q528w5, PrQbKwmwDVynAnHSQ6vWNd2ZpvdcN6yFa2x, 36390000000000, 909999000, 0.025007\n";
      ltc_insert_swap_buyoffer 1711738677L (hexstring_hashval "5053015d8c72a1528cfe5b61c1f3011db34a04cf3090a74ff3b0692ae5df3c7a") 0.030033 (SimpleSwapBuyOffer("ltc1q8ylr8f324ytanyw9ejrkmgmmse6wgjs0q528w5",pfgaddrstr_addr "PrQbKwmwDVynAnHSQ6vWNd2ZpvdcN6yFa2x",33300000000000L,1000097000L));
      Printf.fprintf f "1711738677, 5053015d8c72a1528cfe5b61c1f3011db34a04cf3090a74ff3b0692ae5df3c7a, ltc1q8ylr8f324ytanyw9ejrkmgmmse6wgjs0q528w5, PrQbKwmwDVynAnHSQ6vWNd2ZpvdcN6yFa2x, 33300000000000, 1000097000, 0.030033\n";
      ltc_insert_swap_buyoffer 1712078680L (hexstring_hashval "50538af045f3a9c8c4ea0ebc45ac1787206ef470769ad47ca1dbc22d21af28d9") 0.035091 (SimpleSwapBuyOffer("ltc1q8ylr8f324ytanyw9ejrkmgmmse6wgjs0q528w5",pfgaddrstr_addr "PrQbKwmwDVynAnHSQ6vWNd2ZpvdcN6yFa2x",28500000000000L,1000094800L));
      Printf.fprintf f "1712078680, 50538af045f3a9c8c4ea0ebc45ac1787206ef470769ad47ca1dbc22d21af28d9, ltc1q8ylr8f324ytanyw9ejrkmgmmse6wgjs0q528w5, PrQbKwmwDVynAnHSQ6vWNd2ZpvdcN6yFa2x, 28500000000000, 1000094800, 0.035091\n";
      ltc_insert_swap_buyoffer 1712662593L (hexstring_hashval "50531cdc5364ec881fd991d191269464788a0d9c06b0614905010ae850c2beb2") 0.040099 (SimpleSwapBuyOffer("ltc1q8ylr8f324ytanyw9ejrkmgmmse6wgjs0q528w5",pfgaddrstr_addr "PrQbKwmwDVynAnHSQ6vWNd2ZpvdcN6yFa2x",20200000000000L,809998000L));
      Printf.fprintf f "1712662593, 50531cdc5364ec881fd991d191269464788a0d9c06b0614905010ae850c2beb2, ltc1q8ylr8f324ytanyw9ejrkmgmmse6wgjs0q528w5, PrQbKwmwDVynAnHSQ6vWNd2ZpvdcN6yFa2x, 20200000000000, 809998000, 0.040099\n";
      close_out f;
    end

let initialize_historic_swap_info_execs ddir =
  let hswapfn = Filename.concat ddir "swapexechistory.csv" in
  if Sys.file_exists hswapfn then
    let f = open_in hswapfn in
    begin
      try
        while true do
          let l = input_line f in
          let ll = parse_csv l in
          match ll with
          | [tm;pfgtxid;ltctxid;ltctxofferid] ->
             begin
               let tm = Int64.of_string tm in
               let pfgtxidh = hexstring_hashval pfgtxid in
               let ltctxidh = hexstring_hashval ltctxid in
               let ltctxofferidh = hexstring_hashval ltctxofferid in
               if not (Hashtbl.mem allswapexec_have ltctxidh) then
                 begin
                   Hashtbl.add allswapexec_have ltctxidh ();
                   Hashtbl.add allswapexec ltctxofferidh (tm,pfgtxidh,ltctxidh);
                 end
             end
          | _ ->
             raise (Failure (Printf.sprintf "%d comma separated values, but expected 4" (List.length ll)))
        done
      with
      | End_of_file ->
         close_in f
      | exn ->
         Printf.printf "Unexpected exception when initializing historic swap info:\n%s\nCorrupted swapexechistory.csv?\n" (Printexc.to_string exn);
         close_in f
    end

let initialize_historic_alerts ddir =
  let hfn = Filename.concat ddir "alerthistory.csv" in
  if Sys.file_exists hfn then
    let f = open_in hfn in
    begin
      try
        while true do
          let l = input_line f in
          let ll = parse_csv l in
          match ll with
          | [tm;ltctxid;hexmsg] ->
             begin
               let tm = Int64.of_string tm in
               let ltctxidh = hexstring_hashval ltctxid in
               let msg = hexstring_string hexmsg in
               if not (Hashtbl.mem allalerts_have ltctxidh) then
                 begin
                   Hashtbl.add allalerts_have ltctxidh ();
                   allalerts := List.merge (fun (tm1,_,_) (tm2,_,_) -> compare tm2 tm1) [(tm,ltctxidh,msg)] !allalerts;
                 end
             end
          | _ ->
             raise (Failure (Printf.sprintf "%d comma separated values, but expected 3" (List.length ll)))
        done
      with
      | End_of_file ->
         close_in f
      | exn ->
         Printf.printf "Unexpected exception when initializing historic alerts info:\n%s\nCorrupted alerthistory.csv?\n" (Printexc.to_string exn);
         close_in f
    end

let initialize_historic_listeners ddir =
  let hfn = Filename.concat ddir "listenerhistory.csv" in
  if Sys.file_exists hfn then
    let f = open_in hfn in
    begin
      try
        while true do
          let l = input_line f in
          let ll = parse_csv l in
          match ll with
          | [tm;ltctxid;hexmsg] ->
             begin
               let tm = Int64.of_string tm in
               let ltctxidh = hexstring_hashval ltctxid in
               let msg = hexstring_string hexmsg in
               try
                 let otm = Hashtbl.find alllisteners msg in
                 if tm > otm then
                   Hashtbl.replace alllisteners msg tm
               with Not_found ->
                     Hashtbl.add alllisteners msg tm
             end
          | _ ->
             raise (Failure (Printf.sprintf "%d comma separated values, but expected 3" (List.length ll)))
        done
      with
      | End_of_file ->
         close_in f
      | exn ->
         Printf.printf "Unexpected exception when initializing historic listeners info:\n%s\nCorrupted listenerhistory.csv?\n" (Printexc.to_string exn);
         close_in f
    end

let initialize_historic_swap_info () =
  let ddir = if !Config.testnet then (Filename.concat !Config.datadir "testnet") else !Config.datadir in
  initialize_historic_swap_info_buyoffers ddir;
  initialize_historic_swap_info_execs ddir;
  initialize_historic_alerts ddir;
  initialize_historic_listeners ddir
