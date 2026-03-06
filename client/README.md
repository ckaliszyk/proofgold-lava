# proofgold

Proofgold is a cryptocurrency that rewards the best theorem provers.
Information about proofgold can be found at proofgold.net.

* System Requirements

Proofgold requires linux, the ocaml programming language, the Zarith module
and litecoin.

On debian, installing the requirements (except Zarith) can be done as follows:

apt-get install build-essential ocaml libgmp-dev libgdbm-dev

Zarith is available here:

https://github.com/ocaml/Zarith

The README.md file explains how to compile and install Zarith.
   (In many case this may be enough: ./configure; make; make install)

Litecoin is available from litecoin.org. It needs to be run in a way
so that RPC calls can be made from Proofgold. This means the litecoin.conf
file needs to have some settings described below.

* Installation

```
./configure
make
```

Sometimes ocaml cannot find zarith. In that case, manually
edit Makefile (or Makefile.in and rerun ./configure)
to replace each occurrence of +zarith with the full path
to the directory where zarith was installed.

The configure script can be given some parameters.
For example, the default data directory is .proofgold in the
user's home directory. This can be changed as follows:

```
./configure -datadir=<fullpathtodir>
```

The configure script will create the data directory if it does not already exist.

* Database snapshot

If you start from scratch, it may take a very long time to get into
sync with the network. A faster alternative is to download a recent snapshot
of the database. One should be available at http://proofgold.net/dbm

http://proofgold.net/dbm/

After downloading a recent snapshot, e.g., dbm_20250228.tgz,
you should untar it into the data directory. First remove
any existing directory dbm and file lastltcblock.

```
cd ~/.proofgold
rm -rf dbm lastltcblock
tar xzvf dbm_20252402.tgz
```

This ensures that when you start Proofgold the first time
it will only need to sync with the network since the last snapshot.

* Configuration file

For proofgold to run properly, it needs to communicate with a litecoin daemon.

First set up your litecoin.conf file (in .litecoin) to contain the following lines:

```
txindex=1
server=1
rpcuser=litecoinrpcusername
rpcpassword=replacewithrealpassword
rpcallowip=127.0.0.1
```

where of course `replacewithrealpassword` should be replaced with a
serious password (to protect litecoins in your local wallet).
You should put some litecoins in a segwit address in the local wallet.

Now create a file `proofgold.conf` in your proofgold data directory.

```
ltcrpcuser=litecoinrpcusername
ltcrpcpass=replacewithrealpassword
ltcrpcport=9332
ltcrpcuser2=litecoinrpcusername
ltcrpcpass2=replacewithrealpassword
ltcrpcport2=9332
ltcaddress=yourltcsegwitaddress
```

In the example above, ltcrpcuser2, ltcrpcpass2 and ltcrpcport2
are given the same values as ltcrpcuser, ltcrpcpass and ltcrpcport
so that they refer to the same ltc node. In principle parameters
like ltcrpc[user|pass|port]2 can refer to a different
ltc node than ltcrpcuser[user|pass|port]. If so, ltcrpc[user|pass|port]2
should refer to the ltc node with a nonempty wallet (if you plan to stake,
swap or send alerts). Note that this also applies to the configuration
parameters ltcrpcip, ltcrpcip2, ltcrpconion and ltcrpconion2
if one or both of your ltc nodes is running on a different machine or
as a hidden service.

There are many other configuration parameters you might want to set
in `proofgold.conf` (see `src/setconfig.ml`).  The ones above should
suffice for proofgold to interact with your litecoin node.

Here are a few examples of other configuration parameters.

If you want your node to listen for connections, give your IP and port
number by setting `ip=xx.xx.xx.xx` and `port=..`. The default port
number is 21805. There is no default IP address, and if none is given
then proofgold will not listen for incoming connections. You can have
proofgold listen for connections via a tor hidden service by setting
`onion=xxyouronionaddrxx.onion` `onionremoteport=..` and
`onionlocalport=..`.

Connections will only be created over tor (via socks proxies) if
`socks=4` is included in the configuration file.

After putting the proofgold/bin/ directory into your PATH,
proofgold can be run with a console interface as follows:

```
proofgold
```

For a full list of available commands use the command `help`.

Proofgold can also be run as a daemon using `proofgold -daemon`
and then RPC commands can be issued via `proofgoldcli`.

If you run proofgold under the tails linux distribution, you may
want to consider running it under `torify`.

* Staking

Proofgold blocks are created by burning litecoins, possibly in
combination with staking proofgold currency (proofgold bars).  The
node will attempt to stake if `staking=1` is included in the
proofgold.conf file, or if -staking is included as a command line
argument.

### Running on ARM architectures (e.g. Raspberry Pi)

- On Ubuntu-ARM64:
  1) apt install g++ ocaml make zlib1g-dev libgdbm-dev libgmp-dev libzarith-ocaml-dev
  2) cd pgc; rm s2n; ln -s s2n_arm s2n; make; cd ..
  3) cd client; make

- To get a 'DBM', either get one from the network (slow), download an ARM one or convert from x86_64.
  To convert:
    1) Install 'gdbmtool' (sudo apt install dgbmtool) both on the x86 and on the ARM systems.
    2) Go to "dbm" and: for i in *; do mkdir -p ../dump/$i; done
    3) find . -type f | while read i; do gdbm_dump $i | gzip > ../dump/$i.dump.gz; done
  On the ARM64 Machine:
    4) for i in *; do mkdir -p ../dbm/$i; done
    5) for i in */db4.pag.dump.gz; do gzip -d $i; gdbm_load ${i%.gz} ../dbm/${i%.dump.gz}; done

