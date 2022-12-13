include_directories(.)


add_executable(
  keygen

  keygen.cpp
)
target_link_libraries(
  keygen

  snark
)
target_include_directories(
  keygen

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)


add_executable(
  prover

  main.cpp
)
target_link_libraries(
  prover

  snark
)
target_include_directories(
  prover

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)


add_executable(
  verifier

  verify.cpp
)
target_link_libraries(
  verifier

  snark
)
target_include_directories(
  verifier

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)





add_executable(gensecret gensecret.cpp)

target_link_libraries(gensecret crypto)

add_executable(hashtest hashtest.cpp)

target_link_libraries(hashtest crypto)

