RESULT ?= dtls_client_demo

DEFINES =

INCLUDES = \
	-I../src \
	-I../../../../common \
	-I../../../../cyclone_ssl \
	-I../../../../cyclone_crypto

SOURCES = \
	../src/main.c \
	../../../../common/cpu_endian.c \
	../../../../common/os_port_posix.c \
	../../../../common/date_time.c \
	../../../../common/debug.c \
	../../../../cyclone_ssl/tls.c \
	../../../../cyclone_ssl/tls_cipher_suites.c \
	../../../../cyclone_ssl/tls_handshake.c \
	../../../../cyclone_ssl/tls_client.c \
	../../../../cyclone_ssl/tls_client_fsm.c \
	../../../../cyclone_ssl/tls_client_extensions.c \
	../../../../cyclone_ssl/tls_client_misc.c \
	../../../../cyclone_ssl/tls_server.c \
	../../../../cyclone_ssl/tls_server_fsm.c \
	../../../../cyclone_ssl/tls_server_extensions.c \
	../../../../cyclone_ssl/tls_server_misc.c \
	../../../../cyclone_ssl/tls_common.c \
	../../../../cyclone_ssl/tls_extensions.c \
	../../../../cyclone_ssl/tls_certificate.c \
	../../../../cyclone_ssl/tls_sign_generate.c \
	../../../../cyclone_ssl/tls_sign_verify.c \
	../../../../cyclone_ssl/tls_sign_misc.c \
	../../../../cyclone_ssl/tls_key_material.c \
	../../../../cyclone_ssl/tls_transcript_hash.c \
	../../../../cyclone_ssl/tls_cache.c \
	../../../../cyclone_ssl/tls_ticket.c \
	../../../../cyclone_ssl/tls_ffdhe.c \
	../../../../cyclone_ssl/tls_record.c \
	../../../../cyclone_ssl/tls_record_encryption.c \
	../../../../cyclone_ssl/tls_record_decryption.c \
	../../../../cyclone_ssl/tls_misc.c \
	../../../../cyclone_ssl/tls13_client.c \
	../../../../cyclone_ssl/tls13_client_extensions.c \
	../../../../cyclone_ssl/tls13_client_misc.c \
	../../../../cyclone_ssl/tls13_server.c \
	../../../../cyclone_ssl/tls13_server_extensions.c \
	../../../../cyclone_ssl/tls13_server_misc.c \
	../../../../cyclone_ssl/tls13_common.c \
	../../../../cyclone_ssl/tls13_sign_generate.c \
	../../../../cyclone_ssl/tls13_sign_verify.c \
	../../../../cyclone_ssl/tls13_key_material.c \
	../../../../cyclone_ssl/tls13_ticket.c \
	../../../../cyclone_ssl/tls13_misc.c \
	../../../../cyclone_ssl/dtls_record.c \
	../../../../cyclone_ssl/dtls_misc.c \
	../../../../cyclone_crypto/hash/md5.c \
	../../../../cyclone_crypto/hash/sha1.c \
	../../../../cyclone_crypto/hash/sha224.c \
	../../../../cyclone_crypto/hash/sha256.c \
	../../../../cyclone_crypto/hash/sha384.c \
	../../../../cyclone_crypto/hash/sha512.c \
	../../../../cyclone_crypto/mac/hmac.c \
	../../../../cyclone_crypto/cipher/rc4.c \
	../../../../cyclone_crypto/cipher/idea.c \
	../../../../cyclone_crypto/cipher/des.c \
	../../../../cyclone_crypto/cipher/des3.c \
	../../../../cyclone_crypto/cipher/aes.c \
	../../../../cyclone_crypto/cipher/camellia.c \
	../../../../cyclone_crypto/cipher/seed.c \
	../../../../cyclone_crypto/cipher/aria.c \
	../../../../cyclone_crypto/cipher_modes/cbc.c \
	../../../../cyclone_crypto/aead/ccm.c \
	../../../../cyclone_crypto/aead/gcm.c \
	../../../../cyclone_crypto/cipher/chacha.c \
	../../../../cyclone_crypto/mac/poly1305.c \
	../../../../cyclone_crypto/aead/chacha20_poly1305.c \
	../../../../cyclone_crypto/pkc/dh.c \
	../../../../cyclone_crypto/pkc/rsa.c \
	../../../../cyclone_crypto/pkc/dsa.c \
	../../../../cyclone_crypto/ecc/ec.c \
	../../../../cyclone_crypto/ecc/ec_curves.c \
	../../../../cyclone_crypto/ecc/ecdh.c \
	../../../../cyclone_crypto/ecc/ecdsa.c \
	../../../../cyclone_crypto/ecc/eddsa.c \
	../../../../cyclone_crypto/ecc/curve25519.c \
	../../../../cyclone_crypto/ecc/curve448.c \
	../../../../cyclone_crypto/ecc/x25519.c \
	../../../../cyclone_crypto/ecc/x448.c \
	../../../../cyclone_crypto/ecc/ed25519.c \
	../../../../cyclone_crypto/ecc/ed448.c \
	../../../../cyclone_crypto/mpi/mpi.c \
	../../../../cyclone_crypto/encoding/base64.c \
	../../../../cyclone_crypto/encoding/asn1.c \
	../../../../cyclone_crypto/encoding/oid.c \
	../../../../cyclone_crypto/pkix/pem_import.c \
	../../../../cyclone_crypto/pkix/pem_decrypt.c \
	../../../../cyclone_crypto/pkix/pem_common.c \
	../../../../cyclone_crypto/pkix/pkcs5_decrypt.c \
	../../../../cyclone_crypto/pkix/pkcs5_common.c \
	../../../../cyclone_crypto/pkix/pkcs8_key_parse.c \
	../../../../cyclone_crypto/pkix/x509_key_parse.c \
	../../../../cyclone_crypto/pkix/x509_cert_parse.c \
	../../../../cyclone_crypto/pkix/x509_cert_ext_parse.c \
	../../../../cyclone_crypto/pkix/x509_cert_validate.c \
	../../../../cyclone_crypto/pkix/x509_crl_parse.c \
	../../../../cyclone_crypto/pkix/x509_crl_ext_parse.c \
	../../../../cyclone_crypto/pkix/x509_crl_validate.c \
	../../../../cyclone_crypto/pkix/x509_sign_parse.c \
	../../../../cyclone_crypto/pkix/x509_sign_verify.c \
	../../../../cyclone_crypto/pkix/x509_common.c \
	../../../../cyclone_crypto/kdf/hkdf.c \
	../../../../cyclone_crypto/kdf/pbkdf.c \
	../../../../cyclone_crypto/xof/keccak.c \
	../../../../cyclone_crypto/xof/shake.c \
	../../../../cyclone_crypto/rng/yarrow.c

HEADERS = \
	../src/os_port_config.h \
	../src/tls_config.h \
	../src/crypto_config.h \
	../../../../common/cpu_endian.h \
	../../../../common/os_port.h \
	../../../../common/os_port_posix.h \
	../../../../common/date_time.h \
	../../../../common/error.h \
	../../../../common/debug.h \
	../../../../cyclone_ssl/tls.h \
	../../../../cyclone_ssl/tls_cipher_suites.h \
	../../../../cyclone_ssl/tls_handshake.h \
	../../../../cyclone_ssl/tls_client.h \
	../../../../cyclone_ssl/tls_client_fsm.h \
	../../../../cyclone_ssl/tls_client_extensions.h \
	../../../../cyclone_ssl/tls_client_misc.h \
	../../../../cyclone_ssl/tls_server.h \
	../../../../cyclone_ssl/tls_server_fsm.h \
	../../../../cyclone_ssl/tls_server_extensions.h \
	../../../../cyclone_ssl/tls_server_misc.h \
	../../../../cyclone_ssl/tls_common.h \
	../../../../cyclone_ssl/tls_extensions.h \
	../../../../cyclone_ssl/tls_certificate.h \
	../../../../cyclone_ssl/tls_sign_generate.h \
	../../../../cyclone_ssl/tls_sign_verify.h \
	../../../../cyclone_ssl/tls_sign_misc.h \
	../../../../cyclone_ssl/tls_key_material.h \
	../../../../cyclone_ssl/tls_transcript_hash.h \
	../../../../cyclone_ssl/tls_cache.h \
	../../../../cyclone_ssl/tls_ticket.h \
	../../../../cyclone_ssl/tls_ffdhe.h \
	../../../../cyclone_ssl/tls_record.h \
	../../../../cyclone_ssl/tls_record_encryption.h \
	../../../../cyclone_ssl/tls_record_decryption.h \
	../../../../cyclone_ssl/tls_misc.h \
	../../../../cyclone_ssl/tls13_client.h \
	../../../../cyclone_ssl/tls13_client_extensions.h \
	../../../../cyclone_ssl/tls13_client_misc.h \
	../../../../cyclone_ssl/tls13_server.h \
	../../../../cyclone_ssl/tls13_server_extensions.h \
	../../../../cyclone_ssl/tls13_server_misc.h \
	../../../../cyclone_ssl/tls13_common.h \
	../../../../cyclone_ssl/tls13_sign_generate.h \
	../../../../cyclone_ssl/tls13_sign_verify.h \
	../../../../cyclone_ssl/tls13_key_material.h \
	../../../../cyclone_ssl/tls13_ticket.h \
	../../../../cyclone_ssl/tls13_misc.h \
	../../../../cyclone_ssl/dtls_record.h \
	../../../../cyclone_ssl/dtls_misc.h \
	../../../../cyclone_crypto/core/crypto.h \
	../../../../cyclone_crypto/hash/md5.h \
	../../../../cyclone_crypto/hash/sha1.h \
	../../../../cyclone_crypto/hash/sha224.h \
	../../../../cyclone_crypto/hash/sha256.h \
	../../../../cyclone_crypto/hash/sha384.h \
	../../../../cyclone_crypto/hash/sha512.h \
	../../../../cyclone_crypto/mac/hmac.h \
	../../../../cyclone_crypto/cipher/rc4.h \
	../../../../cyclone_crypto/cipher/idea.h \
	../../../../cyclone_crypto/cipher/des.h \
	../../../../cyclone_crypto/cipher/des3.h \
	../../../../cyclone_crypto/cipher/aes.h \
	../../../../cyclone_crypto/cipher/camellia.h \
	../../../../cyclone_crypto/cipher/seed.h \
	../../../../cyclone_crypto/cipher/aria.h \
	../../../../cyclone_crypto/cipher_modes/cbc.h \
	../../../../cyclone_crypto/aead/ccm.h \
	../../../../cyclone_crypto/aead/gcm.h \
	../../../../cyclone_crypto/cipher/chacha.h \
	../../../../cyclone_crypto/mac/poly1305.h \
	../../../../cyclone_crypto/aead/chacha20_poly1305.h \
	../../../../cyclone_crypto/pkc/dh.h \
	../../../../cyclone_crypto/pkc/rsa.h \
	../../../../cyclone_crypto/pkc/dsa.h \
	../../../../cyclone_crypto/ecc/ec.h \
	../../../../cyclone_crypto/ecc/ec_curves.h \
	../../../../cyclone_crypto/ecc/ecdh.h \
	../../../../cyclone_crypto/ecc/ecdsa.h \
	../../../../cyclone_crypto/ecc/eddsa.h \
	../../../../cyclone_crypto/ecc/curve25519.h \
	../../../../cyclone_crypto/ecc/curve448.h \
	../../../../cyclone_crypto/ecc/x25519.h \
	../../../../cyclone_crypto/ecc/x448.h \
	../../../../cyclone_crypto/ecc/ed25519.h \
	../../../../cyclone_crypto/ecc/ed448.h \
	../../../../cyclone_crypto/mpi/mpi.h \
	../../../../cyclone_crypto/encoding/base64.h \
	../../../../cyclone_crypto/encoding/asn1.h \
	../../../../cyclone_crypto/encoding/oid.h \
	../../../../cyclone_crypto/pkix/pem_import.h \
	../../../../cyclone_crypto/pkix/pem_decrypt.h \
	../../../../cyclone_crypto/pkix/pem_common.h \
	../../../../cyclone_crypto/pkix/pkcs5_decrypt.h \
	../../../../cyclone_crypto/pkix/pkcs5_common.h \
	../../../../cyclone_crypto/pkix/pkcs8_key_parse.h \
	../../../../cyclone_crypto/pkix/x509_key_parse.h \
	../../../../cyclone_crypto/pkix/x509_cert_parse.h \
	../../../../cyclone_crypto/pkix/x509_cert_ext_parse.h \
	../../../../cyclone_crypto/pkix/x509_cert_validate.h \
	../../../../cyclone_crypto/pkix/x509_crl_parse.h \
	../../../../cyclone_crypto/pkix/x509_crl_ext_parse.h \
	../../../../cyclone_crypto/pkix/x509_crl_validate.h \
	../../../../cyclone_crypto/pkix/x509_sign_parse.h \
	../../../../cyclone_crypto/pkix/x509_sign_verify.h \
	../../../../cyclone_crypto/pkix/x509_common.h \
	../../../../cyclone_crypto/kdf/hkdf.h \
	../../../../cyclone_crypto/kdf/pbkdf.h \
	../../../../cyclone_crypto/xof/keccak.h \
	../../../../cyclone_crypto/xof/shake.h \
	../../../../cyclone_crypto/rng/yarrow.h

LIBS = -lpthread

OBJECTS = $(patsubst %.c, %.o, $(SOURCES))

OBJ_DIR = obj

CFLAGS += -Wall
CFLAGS += $(DEFINES)
CFLAGS += $(INCLUDES)

CC = gcc
LD = ld
OBJDUMP = objdump
OBJCOPY = objcopy
SIZE = size

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

all: build

build: $(RESULT)

$(RESULT): $(OBJECTS) $(HEADERS) $(THIS_MAKEFILE)
	$(CC) -Wl,-M=$(RESULT).map $(CFLAGS) $(addprefix $(OBJ_DIR)/, $(notdir $(OBJECTS))) $(LIBS) -o $@

$(OBJECTS): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir -p $@

%.o: %.c $(HEADERS) $(THIS_MAKEFILE)
	$(CC) $(CFLAGS) -c $< -o $(addprefix $(OBJ_DIR)/, $(notdir $@))

clean:
	rm -f $(RESULT)
	rm -f $(RESULT).map
	rm -f $(OBJ_DIR)/*.o
