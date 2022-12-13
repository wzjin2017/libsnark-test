CPP = g++
CFLAGS  = -g -Wall -Wextra -Werror


all: prover verify zktest
prover: src/main.cpp
	$(CPP) $(CFLAGS) \
		-DCURVE_ALT_BN128 \
		-Idepends/libsnark/depends/libfqfft \
		-Idepends/libsnark/depends/libff \
		-Idepends/libsnark/build/snark/usr/local/include \
		-Ldepends/libsnark/build/snark/usr/local/lib \
		-Ldepends/libsnark/build/snark/usr/local/lib \
		-o prover src/main.cpp \
		depends/libsnark/build/depends/libff/libff/libff.a \
		-lsnark -lgmpxx -lgmp

verify: src/verify.cpp
	$(CPP) $(CFLAGS) \
		-DCURVE_ALT_BN128 \
		-Idepends/libsnark/depends/libfqfft \
		-Idepends/libsnark/depends/libff \
		-Idepends/libsnark/build/snark/usr/local/include \
		-Ldepends/libsnark/build/snark/usr/local/lib \
		-Ldepends/libsnark/build/snark/usr/local/lib \
		-o verify src/verify.cpp \
		depends/libsnark/build/depends/libff/libff/libff.a \
		-lsnark -lgmpxx -lgmp

zktest: src/test_zk.cpp
	$(CPP) $(CFLAGS) \
		-DCURVE_ALT_BN128 \
		-Idepends/libsnark/depends/libfqfft \
		-Idepends/libsnark/depends/libff \
		-Idepends/libsnark/build/snark/usr/local/include \
		-Ldepends/libsnark/build/snark/usr/local/lib \
		-Ldepends/libsnark/build/snark/usr/local/lib \
		-o zktest src/test_zk.cpp \
		depends/libsnark/build/depends/libff/libff/libff.a \
		-lsnark -lgmpxx -lgmp