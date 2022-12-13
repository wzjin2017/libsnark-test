# libsnark-test


## prerequisites
```
sudo apt install build-essential cmake git libgmp3-dev libprocps-dev python3-markdown libboost-program-options-dev libssl-dev python3 pkg-config
git submodule update --init --recursive
pushd depends/libsnark
mkdir build && cd build && cmake .. -DWITH_PROCPS=OFF && make
DESTDIR=snark make install
popd
make
```
## Unit Test
To test NIZK part with libsnark, run 
```
./zktest 0.secret 1.secret proof proof.hash verifyKey
```
