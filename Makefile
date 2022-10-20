CPP = g++
CFLAGS  = -g -Wall -Wextra -Werror


all: prover verify gensecret hashtest

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

gensecret: src/gensecret.cpp
	$(CPP) $(CFLAGS) \
		-DCURVE_ALT_BN128 \
		-Idepends/libsnark/depends/libfqfft \
		-Idepends/libsnark/depends/libff \
		-Idepends/libsnark/build/snark/usr/local/include \
		-Ldepends/libsnark/build/snark/usr/local/lib \
		-Ldepends/libsnark/build/snark/usr/local/lib \
		-I/usr/include/openssl \
		-o gensecret src/gensecret.cpp \
		depends/libsnark/build/depends/libff/libff/libff.a \
		-lsnark -lgmpxx -lgmp -lcrypto

hashtest: src/hashtest.cpp
	$(CPP) $(CFLAGS) \
		-DCURVE_ALT_BN128 \
		-Idepends/libsnark/depends/libfqfft \
		-Idepends/libsnark/depends/libff \
		-Idepends/libsnark/build/snark/usr/local/include \
		-Ldepends/libsnark/build/snark/usr/local/lib \
		-Ldepends/libsnark/build/snark/usr/local/lib \
		-I/usr/include/openssl \
		-o hashtest src/hashtest.cpp \
		depends/libsnark/build/depends/libff/libff/libff.a \
		-lsnark -lgmpxx -lgmp -lcrypto

clean:
	$(RM) prover verify gensecret hashtest
