INCLUDE_DIRS+=$(SOURCE_PATH)
CPPSRC+=main.cpp

INCLUDE_DIRS+=\
	$(SOURCE_PATH)/include-quicly \
	$(SOURCE_PATH)/include-picotls \
	$(SOURCE_PATH)/include-klib \

QUICLY_SRC+=\
	lib-picotls/hpke.c \
	lib-picotls/picotls.c \
	lib-quicly/cc-reno.c \
	lib-quicly/defaults.c \
	lib-quicly/frame.c \
	lib-quicly/local_cid.c \
	lib-quicly/loss.c \
	lib-quicly/quicly.c \
	lib-quicly/ranges.c \
	lib-quicly/rate.c \
	lib-quicly/recvstate.c \
	lib-quicly/remote_cid.c \
	lib-quicly/retire_cid.c \
	lib-quicly/sendstate.c \
	lib-quicly/sentmap.c \
	lib-quicly/streambuf.c \

CSRC+=$(QUICLY_SRC) quic.c

EXTRA_CFLAGS+=-Wno-undef -Wno-pointer-to-int-cast -Wno-unused-variable -Wno-unused-but-set-variable -Werror
EXTRA_CFLAGS+=-fstack-usage -ffast-math
EXTRA_CFLAGS+=-DNDEBUG -DQUICLY_CLIENT -DPICOTLS_CLIENT

# TODO: figure out how to do this using make rules
$(shell	cd $(SOURCE_PATH) && ln -sf ../../deps/klib ./include-klib)
$(shell	cd $(SOURCE_PATH) && ln -sf ../../deps/picotls/include ./include-picotls)
$(shell	cd $(SOURCE_PATH) && ln -sf ../../deps/picotls/lib ./lib-picotls)
$(shell	cd $(SOURCE_PATH) && ln -sf ../../include ./include-quicly)
$(shell	cd $(SOURCE_PATH) && ln -sf ../../lib ./lib-quicly)
