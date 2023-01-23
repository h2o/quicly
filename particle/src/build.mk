# .PHONY:
# 	$(SOURCE_PATH)/../misc/probe2trace.pl -a particle < $(SOURCE_PATH)/../quicly-probes.d > $(SOURCE_PATH)/src/quicly-tracer.h

$(shell $(SOURCE_PATH)/../misc/probe2trace.pl -a particle < $(SOURCE_PATH)/../quicly-probes.d > $(SOURCE_PATH)/src/quicly-tracer.h)

INCLUDE_DIRS+=\
	$(SOURCE_PATH)../deps/picotls/deps/cifra/src \
	$(SOURCE_PATH)/../deps/klib \
	$(SOURCE_PATH)/../deps/picotls/deps/cifra/src/ext \
	$(SOURCE_PATH)/../deps/picotls/deps/micro-ecc \
	$(SOURCE_PATH)/../deps/picotls/include \
	$(SOURCE_PATH)/../include \
	$(SOURCE_PATH)/src \

CSRC+=\
	../deps/picotls/deps/cifra/src/aes.c \
	../deps/picotls/deps/cifra/src/blockwise.c \
	../deps/picotls/deps/cifra/src/chacha20.c \
	../deps/picotls/deps/cifra/src/gcm.c \
	../deps/picotls/deps/cifra/src/gf128.c \
	../deps/picotls/deps/cifra/src/modes.c \
	../deps/picotls/deps/cifra/src/poly1305.c \
	../deps/picotls/deps/cifra/src/sha256.c \
	../deps/picotls/deps/cifra/src/sha512.c \
	../deps/picotls/deps/micro-ecc/uECC.c \
	../deps/picotls/lib/cifra.c \
	../deps/picotls/lib/cifra/aes128.c \
	../deps/picotls/lib/cifra/aes256.c \
	../deps/picotls/lib/cifra/chacha20.c \
	../deps/picotls/lib/hpke.c \
	../deps/picotls/lib/picotls.c \
	../deps/picotls/lib/uecc.c \
	../lib/cc-cubic.c \
	../lib/cc-pico.c \
	../lib/cc-reno.c \
	../lib/defaults.c \
	../lib/frame.c \
	../lib/local_cid.c \
	../lib/loss.c \
	../lib/quicly.c \
	../lib/ranges.c \
	../lib/rate.c \
	../lib/recvstate.c \
	../lib/remote_cid.c \
	../lib/retire_cid.c \
	../lib/sendstate.c \
	../lib/sentmap.c \
	../lib/streambuf.c \

CSRC+=../src/cli.c
CPPSRC+=$(USRSRC)/main.cpp

EXTRA_CFLAGS+=-Wno-undef -Wno-pointer-to-int-cast -Werror
EXTRA_CFLAGS+=-fstack-usage -Wstack-usage=500 -Wno-error=stack-usage=
# EXTRA_CFLAGS+=-DMINIMIZE_STACK
EXTRA_CFLAGS+=-DAVOID_64BIT
EXTRA_CFLAGS+=-DQUICLY_USE_TRACER
# EXTRA_CFLAGS+=-finstrument-functions -finstrument-functions-exclude-file-list=deps/micro-ecc,deps/cifra
# EXTRA_CFLAGS+=-DNDEBUG
EXTRA_CFLAGS+=-DQUICLY_CLIENT -DPICOTLS_CLIENT
EXTRA_CFLAGS+=-DFULL_FAT_ASSERT

