include_directories(.)

add_executable(
  main

  main.cpp
)
target_link_libraries(
  main

  snark
)
target_include_directories(
  main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)


add_executable(
  verify

  verify.cpp
)
target_link_libraries(
  verify

  snark
)
target_include_directories(
  verify

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)


add_executable(gensecret gensecret.cpp)

target_link_libraries(gensecret crypto)

add_executable(hashtest hashtest.cpp)

target_link_libraries(hashtest crypto)

