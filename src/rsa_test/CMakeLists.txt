PROJECT (rsa_test)

SET(RSA_TEST_SOURCE rsa_test.c)

ADD_EXECUTABLE(rsa_test ${RSA_TEST_SOURCE})
TARGET_LINK_LIBRARIES(rsa_test libssl.a libcrypto.a gmp dl)
