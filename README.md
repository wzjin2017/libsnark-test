# libsnark-test


## prerequisites
```
sudo apt install build-essential cmake git libgmp3-dev libprocps-dev python3-markdown libboost-program-options-dev libssl-dev python3 pkg-config
git submodule update --init --recursive
pushd depends/libsnark
mkdir build && cd build && cmake .. && make
DESTDIR=snark make install
popd
make
```
