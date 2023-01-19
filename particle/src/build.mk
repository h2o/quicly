INCLUDE_DIRS+=$(SOURCE_PATH)
CPPSRC+=$(USRSRC)/main.cpp

INCLUDE_DIRS+=\
	$(SOURCE_PATH)/../include \
	$(SOURCE_PATH)/../deps/picotls/include \
	$(SOURCE_PATH)/../deps/klib \

QUICLY_SRC+=\
	$(SOURCE_PATH)/../deps/picotls/lib/hpke.c \
	$(SOURCE_PATH)/../deps/picotls/lib/picotls.c \
	$(SOURCE_PATH)/../lib/cc-reno.c \
	$(SOURCE_PATH)/../lib/defaults.c \
	$(SOURCE_PATH)/../lib/frame.c \
	$(SOURCE_PATH)/../lib/local_cid.c \
	$(SOURCE_PATH)/../lib/loss.c \
	$(SOURCE_PATH)/../lib/quicly.c \
	$(SOURCE_PATH)/../lib/ranges.c \
	$(SOURCE_PATH)/../lib/rate.c \
	$(SOURCE_PATH)/../lib/recvstate.c \
	$(SOURCE_PATH)/../lib/remote_cid.c \
	$(SOURCE_PATH)/../lib/retire_cid.c \
	$(SOURCE_PATH)/../lib/sendstate.c \
	$(SOURCE_PATH)/../lib/sentmap.c \
	$(SOURCE_PATH)/../lib/streambuf.c \

CSRC+=$(QUICLY_SRC) $(USRSRC)/quic.c

EXTRA_CFLAGS+=-Wno-undef -Wno-pointer-to-int-cast -Wno-unused-variable -Wno-unused-but-set-variable -Werror
EXTRA_CFLAGS+=-fstack-usage -ffast-math
# EXTRA_CFLAGS+=-DNDEBUG
EXTRA_CFLAGS+=-DQUICLY_CLIENT -DPICOTLS_CLIENT
