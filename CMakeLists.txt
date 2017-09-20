CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(quicly)

FIND_PACKAGE(OpenSSL REQUIRED)
IF (OPENSSL_FOUND AND (OPENSSL_VERSION VERSION_LESS "1.0.2"))
    MESSAGE(FATAL "OpenSSL 1.0.2 or above is missing")
ENDIF ()

SET(CMAKE_C_FLAGS "-std=c99 -Wall -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR} deps/klib deps/picotls/include deps/picotest include)

SET(PICOTLS_OPENSSL_FILES
    deps/picotls/lib/openssl.c
    deps/picotls/lib/pembase64.c
    deps/picotls/lib/picotls.c)

SET(QUICLY_LIBRARY_FILES
    lib/ack.c
    lib/buffer.c
    lib/frame.c
    lib/loss.c
    lib/maxsender.c
    lib/quicly.c
    lib/ranges.c
    lib/recvbuf.c
    lib/sendbuf.c)

SET(UNITTEST_SOURCE_FILES
    deps/picotest/picotest.c
    t/ack.c
    t/frame.c
    t/maxsender.c
    t/loss.c
    t/ranges.c
    t/simple.c
    t/stream-concurrency.c
    t/test.c)

ADD_LIBRARY(quicly ${QUICLY_LIBRARY_FILES})

ADD_EXECUTABLE(cli ${PICOTLS_OPENSSL_FILES} src/cli.c)
TARGET_LINK_LIBRARIES(cli quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(test.t ${PICOTLS_OPENSSL_FILES} ${UNITTEST_SOURCE_FILES})
TARGET_LINK_LIBRARIES(test.t quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_CUSTOM_TARGET(check prove --exec "sh -c" -v ./*.t DEPENDS test.t)
