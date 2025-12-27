OCAMLOPTARGS=-annot
OCAMLC=/usr/bin/ocamlc
# Add -g to ocamlopt for backtrace recording
OCAMLOPT=/usr/bin/ocamlopt
all: opt

ZARITH=+zarith
# For OPAM do instead
# ZARITH=/home/cek/.opam/5.0.0/lib/zarith/

opt: bin/proofgold bin/proofgoldcli
bytecode: bin/proofgoldbc bin/proofgoldclibc

bin:
	mkdir -p bin

bin/proofgold: bin bin/proofgold.cmx bin/json.cmx bin/config.cmx bin/hashaux.cmx bin/sha256.cmx bin/version.cmx bin/utils.cmx bin/ser.cmx bin/hash.cmx bin/htree.cmx bin/db.cmx bin/logic.cmx bin/mathdata.cmx bin/checking.cmx bin/assets.cmx bin/tx.cmx bin/ctre.cmx bin/ctregraft.cmx bin/secp256k1.cmx bin/cryptocurr.cmx bin/signat.cmx bin/ltcrpc.cmx bin/script.cmx bin/block.cmx bin/net.cmx bin/blocktree.cmx bin/setconfig.cmx bin/commands.cmx bin/inputdraft.cmx bin/staking.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/proofgold unix.cmxa threads.cmxa zarith.cmxa pgc.cmxa zarithint.cmx json.cmx config.cmx version.cmx utils.cmx ser.cmx hashaux.cmx sha256.cmx hash.cmx htree.cmx db.cmx net.cmx secp256k1.cmx cryptocurr.cmx signat.cmx ltcrpc.cmx script.cmx logic.cmx mathdata.cmx checking.cmx assets.cmx tx.cmx ctre.cmx ctregraft.cmx block.cmx blocktree.cmx setconfig.cmx commands.cmx inputdraft.cmx staking.cmx proofgold.cmx

bin/proofgoldcli: bin bin/proofgoldcli.cmx bin/zarithint.cmx bin/json.cmx bin/config.cmx bin/hashaux.cmx bin/sha256.cmx bin/version.cmx bin/utils.cmx bin/ser.cmx bin/hash.cmx bin/htree.cmx bin/db.cmx bin/logic.cmx bin/mathdata.cmx bin/checking.cmx bin/assets.cmx bin/tx.cmx bin/ctre.cmx bin/ctregraft.cmx bin/secp256k1.cmx bin/cryptocurr.cmx bin/signat.cmx bin/script.cmx bin/block.cmx bin/net.cmx bin/ltcrpc.cmx bin/blocktree.cmx bin/setconfig.cmx bin/commands.cmx bin/inputdraft.cmx bin/staking.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/proofgoldcli unix.cmxa threads.cmxa zarith.cmxa pgc.cmxa zarithint.cmx json.cmx config.cmx version.cmx utils.cmx ser.cmx hashaux.cmx sha256.cmx hash.cmx htree.cmx db.cmx net.cmx secp256k1.cmx cryptocurr.cmx signat.cmx ltcrpc.cmx script.cmx logic.cmx mathdata.cmx checking.cmx assets.cmx tx.cmx ctre.cmx ctregraft.cmx block.cmx blocktree.cmx setconfig.cmx commands.cmx inputdraft.cmx staking.cmx proofgoldcli.cmx

bin/proofgoldbc: bin bin/proofgold.cmo bin/zarithint.cmo bin/json.cmo bin/config.cmo bin/hashaux.cmo bin/sha256.cmo bin/version.cmo bin/utils.cmo bin/ser.cmo bin/hash.cmo bin/htree.cmo bin/db.cmo bin/logic.cmo bin/mathdata.cmo bin/checking.cmo bin/assets.cmo bin/tx.cmo bin/ctre.cmo bin/ctregraft.cmo bin/secp256k1.cmo bin/cryptocurr.cmo bin/signat.cmo bin/script.cmo bin/block.cmo bin/net.cmo bin/ltcrpc.cmo bin/blocktree.cmo bin/setconfig.cmo bin/commands.cmo bin/inputdraft.cmo bin/staking.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/proofgoldbc unix.cma threads.cma zarith.cma pgc.cma zarithint.cmo json.cmo config.cmo version.cmo utils.cmo ser.cmo hashaux.cmo sha256.cmo hash.cmo htree.cmo db.cmo net.cmo secp256k1.cmo cryptocurr.cmo signat.cmo ltcrpc.cmo script.cmo logic.cmo mathdata.cmo checking.cmo assets.cmo tx.cmo ctre.cmo ctregraft.cmo block.cmo blocktree.cmo setconfig.cmo commands.cmo inputdraft.cmo staking.cmo proofgold.cmo

bin/proofgoldclibc: bin bin/zarithint.cmo bin/json.cmo bin/config.cmo bin/hashaux.cmo bin/sha256.cmo bin/version.cmo bin/utils.cmo bin/ser.cmo bin/hash.cmo bin/htree.cmo bin/db.cmo bin/logic.cmo bin/mathdata.cmo bin/checking.cmo bin/assets.cmo bin/tx.cmo bin/ctre.cmo bin/ctregraft.cmo bin/secp256k1.cmo bin/cryptocurr.cmo bin/signat.cmo bin/script.cmo bin/block.cmo bin/net.cmo bin/ltcrpc.cmo bin/blocktree.cmo bin/setconfig.cmo bin/commands.cmo bin/inputdraft.cmo bin/staking.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/proofgoldclibc unix.cma threads.cma zarith.cma pgc.cma zarithint.cmo json.cmo config.cmo version.cmo utils.cmo ser.cmo hashaux.cmo sha256.cmo hash.cmo htree.cmo db.cmo net.cmo secp256k1.cmo cryptocurr.cmo signat.cmo ltcrpc.cmo script.cmo logic.cmo mathdata.cmo checking.cmo assets.cmo tx.cmo ctre.cmo setconfig.cmo proofgoldcli.cmo

bin/version.cmi: src/version.mli
	$(OCAMLC) -I bin -o bin/version.cmi -c src/version.mli

bin/utils.cmi: src/utils.mli
	$(OCAMLC) -I bin -o bin/utils.cmi -c src/utils.mli

bin/ser.cmi: src/ser.mli bin/zarithint.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/ser.cmi -c src/ser.mli

bin/zarithint.cmi: src/zarithint.mli
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/zarithint.cmi -c src/zarithint.mli

bin/json.cmi: src/json.mli bin/zarithint.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/json.cmi -c src/json.mli

bin/config.cmi: src/config.mli
	$(OCAMLC) -I bin -o bin/config.cmi -c src/config.mli

bin/hashaux.cmi: src/hashaux.mli bin/zarithint.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/hashaux.cmi -c src/hashaux.mli

bin/sha256.cmi: src/sha256.mli bin/ser.cmi bin/zarithint.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -I +threads -I ../pgc/bin -o bin/sha256.cmi -c src/sha256.mli

bin/hash.cmi: src/hash.mli bin/sha256.cmi bin/json.cmi bin/zarithint.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/hash.cmi -c src/hash.mli

bin/htree.cmi: src/htree.mli bin/hash.cmi
	$(OCAMLC) -I bin -o bin/htree.cmi -c src/htree.mli

bin/db.cmi: src/db.mli bin/ser.cmi bin/hash.cmi
	$(OCAMLC) -I bin -o bin/db.cmi -c src/db.mli

bin/logic.cmi: src/logic.mli bin/htree.cmi bin/hash.cmi bin/json.cmi
	$(OCAMLC) -I bin -o bin/logic.cmi -c src/logic.mli

bin/mathdata.cmi: src/mathdata.mli bin/htree.cmi bin/hash.cmi bin/logic.cmi bin/db.cmi
	$(OCAMLC) -I bin -o bin/mathdata.cmi -c src/mathdata.mli

bin/checking.cmi: src/checking.mli bin/htree.cmi bin/hash.cmi bin/logic.cmi bin/mathdata.cmi bin/zarithint.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/checking.cmi -c src/checking.mli

bin/assets.cmi: src/assets.mli bin/hash.cmi bin/logic.cmi bin/mathdata.cmi bin/checking.cmi bin/db.cmi bin/json.cmi
	$(OCAMLC) -I bin -o bin/assets.cmi -c src/assets.mli

bin/secp256k1.cmi: src/secp256k1.mli
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/secp256k1.cmi -c src/secp256k1.mli

bin/cryptocurr.cmi: src/cryptocurr.mli bin/hash.cmi bin/secp256k1.cmi bin/json.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/cryptocurr.cmi -c src/cryptocurr.mli

bin/signat.cmi: src/signat.mli bin/hash.cmi bin/sha256.cmi bin/secp256k1.cmi bin/zarithint.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/signat.cmi -c src/signat.mli

bin/script.cmi: src/script.mli bin/hash.cmi bin/secp256k1.cmi bin/signat.cmi bin/json.cmi bin/zarithint.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/script.cmi -c src/script.mli

bin/tx.cmi: src/tx.mli bin/hash.cmi bin/logic.cmi bin/mathdata.cmi bin/checking.cmi bin/assets.cmi bin/script.cmi bin/db.cmi bin/json.cmi bin/zarithint.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/tx.cmi -c src/tx.mli

bin/ctre.cmi: src/ctre.mli bin/hash.cmi bin/logic.cmi bin/mathdata.cmi bin/checking.cmi bin/assets.cmi bin/tx.cmi bin/db.cmi bin/json.cmi bin/zarithint.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/ctre.cmi -c src/ctre.mli

bin/ctregraft.cmi: src/ctregraft.mli bin/hash.cmi bin/ctre.cmi
	$(OCAMLC) -I bin -I ../pgc/bin -o bin/ctregraft.cmi -c src/ctregraft.mli

bin/block.cmi: src/block.mli bin/hash.cmi bin/logic.cmi bin/mathdata.cmi bin/checking.cmi bin/assets.cmi bin/signat.cmi bin/tx.cmi bin/ctre.cmi bin/ctregraft.cmi bin/db.cmi bin/zarithint.cmi bin/ltcrpc.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/block.cmi -c src/block.mli

bin/ltcrpc.cmi: src/ltcrpc.mli bin/hash.cmi bin/sha256.cmi
	$(OCAMLC) -I bin -I +threads -o bin/ltcrpc.cmi -c src/ltcrpc.mli

bin/net.cmi: src/net.mli bin/hash.cmi bin/zarithint.cmi bin/db.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -I +threads -o bin/net.cmi -c src/net.mli

bin/blocktree.cmi: src/blocktree.mli bin/hash.cmi bin/signat.cmi bin/tx.cmi bin/ctre.cmi bin/block.cmi bin/net.cmi bin/ltcrpc.cmi bin/mathdata.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/blocktree.cmi -c src/blocktree.mli

bin/setconfig.cmi: src/setconfig.mli bin/json.cmi bin/hash.cmi
	$(OCAMLC) -I bin -o bin/setconfig.cmi -c src/setconfig.mli

bin/commands.cmi: src/commands.mli bin/ctre.cmi bin/json.cmi bin/zarithint.cmi bin/ltcrpc.cmi
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/commands.cmi -c src/commands.mli

bin/inputdraft.cmi: src/inputdraft.mli bin/logic.cmi bin/mathdata.cmi bin/hash.cmi bin/checking.cmi
	$(OCAMLC) -I bin -o bin/inputdraft.cmi -c src/inputdraft.mli

bin/staking.cmi: src/staking.mli bin/hash.cmi bin/mathdata.cmi bin/assets.cmi bin/ltcrpc.cmi bin/commands.cmi
	$(OCAMLC) -I bin -o bin/staking.cmi -c src/staking.mli

bin/version.cmx: src/version.ml bin/version.cmi
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -o bin/version.cmx -c src/version.ml

bin/utils.cmx: src/utils.ml bin/utils.cmi bin/config.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -o bin/utils.cmx -c src/utils.ml

bin/ser.cmx: src/ser.ml bin/ser.cmi bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/ser.cmx -c src/ser.ml

bin/secp256k1.cmx: src/secp256k1.ml bin/secp256k1.cmi bin/zarithint.cmx bin/sha256.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/secp256k1.cmx -c src/secp256k1.ml

bin/cryptocurr.cmx: src/cryptocurr.ml bin/cryptocurr.cmi bin/ser.cmx bin/hashaux.cmx bin/sha256.cmx bin/hash.cmx bin/secp256k1.cmx bin/config.cmx bin/json.cmx bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/cryptocurr.cmx -c src/cryptocurr.ml

bin/signat.cmx: src/signat.ml bin/signat.cmi bin/config.cmx bin/ser.cmx bin/sha256.cmx bin/hash.cmx bin/secp256k1.cmx bin/cryptocurr.cmx bin/net.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -o bin/signat.cmx -c src/signat.ml

bin/script.cmx: src/script.ml bin/script.cmi bin/cryptocurr.cmx bin/secp256k1.cmx bin/hash.cmx bin/sha256.cmx bin/signat.cmx bin/json.cmx bin/ltcrpc.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/script.cmx -c src/script.ml

bin/zarithint.cmx: src/zarithint.ml bin/zarithint.cmi
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -o bin/zarithint.cmx -c src/zarithint.ml

bin/json.cmx: src/json.ml bin/json.cmi bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -o bin/json.cmx -c src/json.ml

bin/config.cmx: src/config.ml bin/config.cmi
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -o bin/config.cmx -c src/config.ml

bin/hashaux.cmx: src/hashaux.ml bin/hashaux.cmi bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/hashaux.cmx -c src/hashaux.ml

bin/sha256.cmx: src/sha256.ml bin/sha256.cmi bin/hashaux.cmx bin/ser.cmx bin/utils.cmx bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/sha256.cmx -c src/sha256.ml

bin/hash.cmx: src/hash.ml bin/hash.cmi bin/hashaux.cmx bin/sha256.cmx bin/ser.cmx bin/json.cmx bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/hash.cmx -c src/hash.ml

bin/htree.cmx: src/htree.ml bin/htree.cmi bin/hash.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -o bin/htree.cmx -c src/htree.ml

bin/db.cmx: src/db.ml bin/db.cmi bin/ser.cmx bin/hash.cmx bin/config.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I ../pgc/bin -o bin/db.cmx -c src/db.ml

bin/logic.cmx: src/logic.ml bin/logic.cmi bin/htree.cmx bin/hash.cmx bin/ser.cmx bin/json.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -o bin/logic.cmx -c src/logic.ml

bin/mathdata.cmx: src/mathdata.ml bin/mathdata.cmi bin/logic.cmx bin/htree.cmx bin/hash.cmx bin/ser.cmx bin/db.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -o bin/mathdata.cmx -c src/mathdata.ml

bin/checking.cmx: src/checking.ml bin/checking.cmi bin/logic.cmx bin/mathdata.cmx bin/htree.cmx bin/hash.cmx bin/ser.cmx bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/checking.cmx -c src/checking.ml

bin/assets.cmx: src/assets.ml bin/assets.cmi bin/hash.cmx bin/logic.cmx bin/mathdata.cmx bin/checking.cmx bin/ser.cmx bin/db.cmx bin/net.cmx bin/cryptocurr.cmx bin/json.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -o bin/assets.cmx -c src/assets.ml

bin/tx.cmx: src/tx.ml bin/tx.cmi bin/ser.cmx bin/sha256.cmx bin/hash.cmx bin/logic.cmx bin/mathdata.cmx bin/checking.cmx bin/assets.cmx bin/secp256k1.cmx bin/cryptocurr.cmx bin/signat.cmx bin/script.cmx bin/db.cmx bin/net.cmx bin/json.cmx bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -o bin/tx.cmx -c src/tx.ml

bin/ctre.cmx: src/ctre.ml bin/ctre.cmi bin/hash.cmx bin/logic.cmx bin/mathdata.cmx bin/checking.cmx bin/assets.cmx bin/tx.cmx bin/ser.cmx bin/config.cmx bin/db.cmx bin/net.cmx bin/json.cmx bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/ctre.cmx -c src/ctre.ml

bin/ctregraft.cmx: src/ctregraft.ml bin/ctregraft.cmi bin/ser.cmx bin/hash.cmx bin/ctre.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I ../pgc/bin -o bin/ctregraft.cmx -c src/ctregraft.ml

bin/block.cmx: src/block.ml bin/block.cmi bin/hash.cmx bin/logic.cmx bin/mathdata.cmx bin/checking.cmx bin/assets.cmx bin/signat.cmx bin/tx.cmx bin/ctre.cmx bin/ctregraft.cmx bin/db.cmx bin/net.cmx bin/zarithint.cmx bin/ltcrpc.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/block.cmx -c src/block.ml

bin/ltcrpc.cmx: src/ltcrpc.ml bin/ltcrpc.cmi bin/hash.cmx bin/json.cmx bin/net.cmx bin/db.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I ../pgc/bin -o bin/ltcrpc.cmx -c src/ltcrpc.ml

bin/net.cmx: src/net.ml bin/net.cmi bin/ser.cmx bin/hash.cmx bin/version.cmx bin/utils.cmx bin/zarithint.cmx bin/db.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -o bin/net.cmx -c src/net.ml

bin/blocktree.cmx: src/blocktree.ml bin/blocktree.cmi bin/ser.cmx bin/hash.cmx bin/version.cmx bin/utils.cmx bin/db.cmx bin/assets.cmx bin/signat.cmx bin/tx.cmx bin/ctre.cmx bin/block.cmx bin/net.cmx bin/ltcrpc.cmx bin/mathdata.cmx bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/blocktree.cmx -c src/blocktree.ml

bin/setconfig.cmx: src/setconfig.ml bin/setconfig.cmi bin/config.cmx bin/json.cmx bin/hash.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -o bin/setconfig.cmx -c src/setconfig.ml

bin/commands.cmx: src/commands.ml bin/commands.cmi bin/config.cmx bin/ser.cmx bin/hash.cmx bin/signat.cmx bin/net.cmx bin/ctre.cmx bin/cryptocurr.cmx bin/ctre.cmx bin/blocktree.cmx bin/json.cmx bin/zarithint.cmx bin/ltcrpc.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/commands.cmx -c src/commands.ml

bin/inputdraft.cmx: src/inputdraft.ml bin/inputdraft.cmi bin/hash.cmx bin/logic.cmx bin/mathdata.cmx bin/cryptocurr.cmx bin/checking.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -o bin/inputdraft.cmx -c src/inputdraft.ml

bin/staking.cmx: src/staking.ml bin/staking.cmi bin/config.cmx bin/ser.cmx bin/hash.cmx bin/signat.cmx bin/net.cmx bin/ctre.cmx bin/secp256k1.cmx bin/cryptocurr.cmx bin/block.cmx bin/blocktree.cmx bin/json.cmx bin/zarithint.cmx bin/ltcrpc.cmx bin/commands.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/staking.cmx -c src/staking.ml

bin/proofgold.cmx: src/proofgold.ml bin/assets.cmx bin/tx.cmx bin/ctre.cmx bin/block.cmx bin/version.cmx bin/utils.cmx bin/net.cmx bin/setconfig.cmx bin/commands.cmx bin/inputdraft.cmx bin/staking.cmx bin/db.cmx bin/blocktree.cmx bin/ltcrpc.cmx bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/proofgold.cmx -c src/proofgold.ml

bin/proofgoldcli.cmx: src/proofgoldcli.ml bin/setconfig.cmx bin/ltcrpc.cmx bin/zarithint.cmx
	$(OCAMLOPT) $(OCAMLOPTARGS) -I bin -I +threads -I $(ZARITH) -o bin/proofgoldcli.cmx -c src/proofgoldcli.ml

bin/version.cmo: src/version.ml bin/version.cmi
	$(OCAMLC) -I bin -o bin/version.cmo -c src/version.ml

bin/utils.cmo: src/utils.ml bin/utils.cmi bin/config.cmo
	$(OCAMLC) -I bin -I +threads -o bin/utils.cmo -c src/utils.ml

bin/ser.cmo: src/ser.ml bin/ser.cmi bin/zarithint.cmo
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/ser.cmo -c src/ser.ml

bin/secp256k1.cmo: src/secp256k1.ml bin/secp256k1.cmi bin/zarithint.cmo bin/sha256.cmo
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/secp256k1.cmo -c src/secp256k1.ml

bin/cryptocurr.cmo: src/cryptocurr.ml bin/cryptocurr.cmi bin/ser.cmo bin/hashaux.cmo bin/sha256.cmo bin/hash.cmo bin/secp256k1.cmo bin/config.cmo bin/json.cmo bin/zarithint.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/cryptocurr.cmo -c src/cryptocurr.ml

bin/signat.cmo: src/signat.ml bin/signat.cmi bin/config.cmo bin/ser.cmo bin/sha256.cmo bin/hash.cmo bin/secp256k1.cmo bin/cryptocurr.cmo bin/net.cmo bin/zarithint.cmo
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/signat.cmo -c src/signat.ml

bin/script.cmo: src/script.ml bin/script.cmi bin/cryptocurr.cmo bin/secp256k1.cmo bin/hash.cmo bin/sha256.cmo bin/signat.cmo bin/json.cmo bin/zarithint.cmo bin/ltcrpc.cmo
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/script.cmo -c src/script.ml

bin/zarithint.cmo: src/zarithint.ml
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/zarithint.cmo -c src/zarithint.ml

bin/json.cmo: src/json.ml bin/json.cmi bin/zarithint.cmo
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/json.cmo -c src/json.ml

bin/config.cmo: src/config.ml bin/config.cmi
	$(OCAMLC) -I bin -o bin/config.cmo -c src/config.ml

bin/hashaux.cmo: src/hashaux.ml bin/hashaux.cmi bin/zarithint.cmo
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/hashaux.cmo -c src/hashaux.ml

bin/sha256.cmo: src/sha256.ml bin/sha256.cmi bin/hashaux.cmo bin/ser.cmo bin/utils.cmo bin/zarithint.cmo bin/zarithint.cmo
	$(OCAMLC) -I bin -I +threads -I ../pgc/bin -o bin/sha256.cmo -c src/sha256.ml

bin/hash.cmo: src/hash.ml bin/hash.cmi bin/hashaux.cmo bin/sha256.cmo bin/ser.cmo bin/json.cmo bin/zarithint.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/hash.cmo -c src/hash.ml

bin/htree.cmo: src/htree.ml bin/htree.cmi bin/hash.cmo
	$(OCAMLC) -I bin -o bin/htree.cmo -c src/htree.ml

bin/db.cmo: src/db.ml bin/db.cmi bin/ser.cmo bin/hash.cmo bin/config.cmo
	$(OCAMLC) -I bin -I +threads -I ../pgc/bin -o bin/db.cmo -c src/db.ml

bin/logic.cmo: src/logic.ml bin/logic.cmi bin/htree.cmo bin/hash.cmo bin/ser.cmo bin/json.cmo
	$(OCAMLC) -I bin -o bin/logic.cmo -c src/logic.ml

bin/mathdata.cmo: src/mathdata.ml bin/mathdata.cmi bin/logic.cmo bin/htree.cmo bin/hash.cmo bin/ser.cmo bin/db.cmo
	$(OCAMLC) -I bin -o bin/mathdata.cmo -c src/mathdata.ml

bin/checking.cmo: src/checking.ml bin/checking.cmi bin/mathdata.cmo bin/logic.cmo bin/htree.cmo bin/hash.cmo bin/ser.cmo bin/zarithint.cmo
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/checking.cmo -c src/checking.ml

bin/assets.cmo: src/assets.ml bin/assets.cmi bin/hash.cmo bin/logic.cmo bin/mathdata.cmo bin/checking.cmo bin/ser.cmo bin/db.cmo bin/net.cmo bin/cryptocurr.cmo bin/json.cmo
	$(OCAMLC) -I bin -o bin/assets.cmo -c src/assets.ml

bin/tx.cmo: src/tx.ml bin/tx.cmi bin/ser.cmo bin/sha256.cmo bin/hash.cmo bin/logic.cmo bin/mathdata.cmo bin/checking.cmo bin/assets.cmo bin/secp256k1.cmo bin/cryptocurr.cmo bin/signat.cmo bin/script.cmo bin/db.cmo bin/net.cmo bin/json.cmo bin/zarithint.cmo
	$(OCAMLC) -I bin -I $(ZARITH) -o bin/tx.cmo -c src/tx.ml

bin/ctre.cmo: src/ctre.ml bin/ctre.cmi bin/hash.cmo bin/logic.cmo bin/mathdata.cmo bin/checking.cmo bin/assets.cmo bin/tx.cmo bin/ser.cmo bin/config.cmo bin/db.cmo bin/net.cmo bin/json.cmo bin/zarithint.cmo
	$(OCAMLC) -I bin -I $(ZARITH) -I ../pgc/bin -o bin/ctre.cmo -c src/ctre.ml

bin/ctregraft.cmo: src/ctregraft.ml bin/ctregraft.cmi bin/ser.cmo bin/hash.cmo bin/ctre.cmo
	$(OCAMLC) -I bin -I ../pgc/bin -o bin/ctregraft.cmo -c src/ctregraft.ml

bin/block.cmo: src/block.ml bin/block.cmi bin/hash.cmo bin/logic.cmo bin/mathdata.cmo bin/checking.cmo bin/assets.cmo bin/signat.cmo bin/tx.cmo bin/ctre.cmo bin/ctregraft.cmo bin/db.cmo bin/net.cmo bin/zarithint.cmo bin/ltcrpc.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/block.cmo -c src/block.ml

bin/ltcrpc.cmo: src/ltcrpc.ml bin/ltcrpc.cmi bin/hash.cmo bin/json.cmo
	$(OCAMLC) -I bin -I +threads -I ../pgc/bin -o bin/ltcrpc.cmo -c src/ltcrpc.ml

bin/net.cmo: src/net.ml bin/net.cmi bin/ser.cmo bin/hash.cmo bin/version.cmo bin/utils.cmo bin/zarithint.cmo bin/db.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -o bin/net.cmo -c src/net.ml

bin/blocktree.cmo: src/blocktree.ml bin/blocktree.cmi bin/ser.cmo bin/hash.cmo bin/version.cmo bin/utils.cmo bin/db.cmo bin/assets.cmo bin/signat.cmo bin/tx.cmo bin/ctre.cmo bin/block.cmo bin/net.cmo bin/ltcrpc.cmo bin/mathdata.cmo bin/zarithint.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/blocktree.cmo -c src/blocktree.ml

bin/setconfig.cmo: src/setconfig.ml bin/setconfig.cmi bin/config.cmo bin/json.cmo bin/hash.cmo
	$(OCAMLC) -I bin -o bin/setconfig.cmo -c src/setconfig.ml

bin/commands.cmo: src/commands.ml bin/commands.cmi bin/config.cmo bin/ser.cmo bin/hash.cmo bin/signat.cmo bin/net.cmo bin/ctre.cmo bin/cryptocurr.cmo bin/ctre.cmo bin/blocktree.cmo bin/json.cmo bin/zarithint.cmo bin/ltcrpc.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/commands.cmo -c src/commands.ml

bin/inputdraft.cmo: src/inputdraft.ml bin/inputdraft.cmi bin/hash.cmo bin/logic.cmo bin/mathdata.cmo bin/cryptocurr.cmo bin/checking.cmo
	$(OCAMLC) -I bin -o bin/inputdraft.cmo -c src/inputdraft.ml

bin/staking.cmo: src/staking.ml bin/staking.cmi bin/config.cmo bin/ser.cmo bin/hash.cmo bin/signat.cmo bin/net.cmo bin/ctre.cmo bin/secp256k1.cmo bin/cryptocurr.cmo bin/block.cmo bin/blocktree.cmo bin/json.cmo bin/zarithint.cmo bin/ltcrpc.cmo bin/commands.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/staking.cmo -c src/staking.ml

bin/proofgold.cmo: src/proofgold.ml bin/assets.cmo bin/tx.cmo bin/ctre.cmo bin/block.cmo bin/version.cmo bin/utils.cmo bin/net.cmo bin/setconfig.cmo bin/commands.cmo bin/inputdraft.cmo bin/staking.cmo bin/db.cmo bin/blocktree.cmo bin/ltcrpc.cmo bin/zarithint.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -I ../pgc/bin -o bin/proofgold.cmo -c src/proofgold.ml

bin/proofgoldcli.cmo: src/proofgoldcli.ml bin/setconfig.cmo bin/ltcrpc.cmo bin/zarithint.cmo
	$(OCAMLC) -I bin -I +threads -I $(ZARITH) -o bin/proofgoldcli.cmo -c src/proofgoldcli.ml

clean:
	rm src/config.ml
	rm bin/*

INSTALLDIR=/usr/local/bin

install:
	cp bin/proofgold $(INSTALLDIR)
