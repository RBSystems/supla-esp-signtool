//
// The MIT License (MIT)
//
// Copyright (c) 2015-2016 Jeff Kent
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// https://www.lysator.liu.se/~nisse/nettle/

#include <linux/limits.h>
#include <nettle/bignum.h>
#include <nettle/blowfish.h>
#include <nettle/buffer.h>
#include <nettle/rsa.h>
#include <nettle/sexp.h>
#include <nettle/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#define RSA_PUBLIC_EXPONENT 65537
#define RSA_NUM_BITS 4096
#define RSA_NUM_BYTES (RSA_NUM_BITS / 8)

#define min(a, b)           \
  ({                        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a < _b ? _a : _b;      \
  })

struct rsa_public_key public_key;
struct rsa_private_key private_key;

#define UNUSED __attribute__((unused))
static void nettle_random(void *ctx UNUSED, size_t length, uint8_t *dst) {
  unsigned done = 0;
  FILE *f;

  f = fopen("/dev/urandom", "rb");
  if (!f) {
    fprintf(stderr, "could not open /dev/urandom\n");
    exit(EXIT_FAILURE);
  }

  while (done != length) {
    done += fread(dst + done, 1, length - done, f);
  }

  fclose(f);
}

static void set_raw_term(bool b) {
  static struct termios cooked;
  static bool state = false;

  if (state == b) return;
  if (b) {
    struct termios raw;

    tcgetattr(STDIN_FILENO, &cooked);
    raw = cooked;
    cfmakeraw(&raw);
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
  } else {
    tcsetattr(STDIN_FILENO, TCSANOW, &cooked);
  }
  state = b;
}

static void password_prompt(char *password, int size) {
  int i = 0;

  printf("password: ");
  set_raw_term(true);
  while (true) {
    char c = getchar();
    if (c == '\b' || c == '\x7f') {
      if (i) {
        i--;
      }
      continue;
    }
    if (c == '\x03' || c == '\x04') {
      set_raw_term(false);
      printf("\n");
      exit(EXIT_FAILURE);
    }
    if (c == '\r') {
      break;
    }
    if (i < size - 1) {
      password[i++] = c;
    }
  }
  set_raw_term(false);
  password[i + 1] = '\0';
  printf("\n");
}

static bool write_private_key(const char *key_path, bool encrypt) {
  struct nettle_buffer key_buffer;
  FILE *f;
  bool is_ok = false;

  nettle_buffer_init(&key_buffer);
  if (!rsa_keypair_to_sexp(&key_buffer, NULL, &public_key, &private_key)) {
    goto error;
  }

  int old_umask = umask(0077);
  f = fopen(key_path, "wb");
  umask(old_umask);

  if (!f) {
    goto error;
  }

  if (encrypt) {
    struct blowfish_ctx blowfish;
    char password[BLOWFISH_MAX_KEY_SIZE + 1] = {0};
    int len =
        ((key_buffer.size + BLOWFISH_BLOCK_SIZE - 1) / BLOWFISH_BLOCK_SIZE) *
        BLOWFISH_BLOCK_SIZE;
    char *buf = malloc(len);

    memset(buf + len - BLOWFISH_BLOCK_SIZE, 0, BLOWFISH_BLOCK_SIZE);
    memcpy(buf, key_buffer.contents, key_buffer.size);

    while (true) {
      password_prompt(password, sizeof(password));
      if (strlen(password) < BLOWFISH_MIN_KEY_SIZE) {
        fprintf(stderr, "Password is too short, try again\n");
        continue;
      }
      if (blowfish_set_key(&blowfish, strlen(password), password)) {
        break;
      }
      fprintf(stderr, "Password is weak, try again\n");
    }

    blowfish_encrypt(&blowfish, len, buf, buf);

    if (fwrite(buf, 1, len, f) == 0) {
      free(buf);
      goto error2;
    }

    free(buf);
  } else {
    if (fwrite(key_buffer.contents, 1, key_buffer.size, f) == 0) {
      goto error2;
    }
  }

  is_ok = true;

error2:
  fclose(f);
error:
  nettle_buffer_clear(&key_buffer);
  return is_ok;
}

static bool write_public_key(const char *key_path) {
  struct nettle_buffer key_buffer;
  FILE *f;
  bool is_ok = false;

  nettle_buffer_init(&key_buffer);
  if (!rsa_keypair_to_sexp(&key_buffer, NULL, &public_key, NULL)) {
    goto error;
  }

  f = fopen(key_path, "wb");
  if (!f) {
    goto error;
  }

  if (fwrite(key_buffer.contents, 1, key_buffer.size, f) == 0) {
    goto error2;
  }

  is_ok = true;

error2:
  fclose(f);
error:
  nettle_buffer_clear(&key_buffer);
  return is_ok;
}

static void unload_keys(void) {
  rsa_public_key_clear(&public_key);
  rsa_private_key_clear(&private_key);
}

static bool generate_keypair(const char *key_path, bool encrypt) {
  char public_key_path[PATH_MAX];

  rsa_public_key_init(&public_key);
  rsa_private_key_init(&private_key);

  mpz_set_ui(public_key.e, RSA_PUBLIC_EXPONENT);
  if (!rsa_generate_keypair(&public_key, &private_key, NULL, nettle_random,
                            NULL, NULL, RSA_NUM_BITS, 0)) {
    return false;
  }

  if (!write_private_key(key_path, encrypt)) {
    unload_keys();
    return false;
  }

  snprintf(public_key_path, sizeof(public_key_path), "%s.pub", key_path);
  if (!write_public_key(public_key_path)) {
    unload_keys();
    return false;
  }

  return true;
}

static int rsa_keypair_from_sexp_custom(struct rsa_public_key *pub,
                                        struct rsa_private_key *priv,
                                        unsigned limit, size_t length,
                                        const uint8_t *expr) {
  struct sexp_iterator i;
  static const char *const types[2] = {"private-key", "public-key"};
  static const char *const names[3] = {"rsa", "rsa-pkcs1", "rsa-pkcs1-sha1"};

  if (!sexp_iterator_first(&i, length, expr)) return 0;

  if (priv && !sexp_iterator_check_type(&i, types[0])) return 0;

  if (!priv && !sexp_iterator_check_types(&i, 2, types)) return 0;

  if (!sexp_iterator_check_types(&i, 3, names)) return 0;

  return rsa_keypair_from_sexp_alist(pub, priv, limit, &i);
}

static bool load_key(const char *key_path, bool private) {
  long len;
  FILE *f;
  uint8_t *buf;
  bool is_ok = false;

  rsa_public_key_init(&public_key);
  rsa_private_key_init(&private_key);

  f = fopen(key_path, "rb");
  if (!f) {
    goto error;
  }

  if (fseek(f, 0L, SEEK_END) != 0) {
    goto error2;
  }

  len = ftell(f);
  rewind(f);

  buf = malloc(len);
  if (!buf) {
    goto error2;
  }

  if (fread(buf, 1, len, f) == 0) {
    goto error3;
  }

  if (memcmp(buf, "(10:public-key", 14) != 0 &&
      memcmp(buf, "(11:private-key", 15) != 0) {
    struct blowfish_ctx blowfish;
    char password[BLOWFISH_MAX_KEY_SIZE + 1] = {0};

    if (len % BLOWFISH_BLOCK_SIZE) {
      goto error3;
    }

    const char *env_password = getenv("SIGTOOL_PASSWORD");
    if (env_password) {
      if (strlen(env_password) < BLOWFISH_MIN_KEY_SIZE) {
        fprintf(stderr,
                "length of SIGTOOL_PASSWORD does not meet minimum key size\n");
        exit(EXIT_FAILURE);
      }
      strncpy(password, env_password, sizeof(password) - 1);
      password[sizeof(password) - 1] = '\0';
    } else {
      while (strlen(password) < BLOWFISH_MIN_KEY_SIZE) {
        password_prompt(password, sizeof(password));
      }
    }

    blowfish_set_key(&blowfish, strlen(password), password);
    blowfish_decrypt(&blowfish, len, buf, buf);
  }

  if (!rsa_keypair_from_sexp_custom(&public_key, private ? &private_key : NULL,
                                    0, len, buf)) {
    goto error3;
  }

  memset(buf, 0, len);

  is_ok = true;

error3:
  free(buf);
error2:
  fclose(f);
error:
  return is_ok;
}

static bool output_c_source(const char *data_path) {
  FILE *f;
  bool is_ok = false;
  uint8_t key_bytes[RSA_NUM_BYTES];

  f = fopen(data_path, "w");
  if (!f) {
    goto error;
  }

  nettle_mpz_get_str_256(sizeof(key_bytes), key_bytes, public_key.n);

  fprintf(f, "#include <stdint.h>\n");
  fprintf(f, "\n");
  fprintf(f, "const uint8_t rsa_public_key_bytes[%d] = {\n", RSA_NUM_BYTES);
  for (int i = 0; i < RSA_NUM_BYTES; i++) {
    if (i % 8 == 0) {
      fprintf(f, "    ");
    }
    fprintf(f, "0x%02x", key_bytes[i]);
    if (i + 1 < RSA_NUM_BYTES) {
      fprintf(f, ",");
    }
    if ((i + 1) % 8 == 0) {
      fprintf(f, "\n");
    } else {
      fprintf(f, " ");
    }
  }
  fprintf(f, "};\n");

  is_ok = true;

  fclose(f);
error:
  return is_ok;
}

static bool hash_file(const char *data_path, struct sha256_ctx *hash) {
  FILE *f;
  bool is_ok = false;
  uint8_t buf[0x8000];
  unsigned char footer[16];
  size_t data_length;
  int chunk;

  f = fopen(data_path, "rb");
  if (!f) {
    fprintf(stderr, "could not open data file\n");
    goto error;
  }

  fseek(f, -16, SEEK_END);
  if (fread(footer, sizeof(footer), 1, f) == 1 && footer[0] == 0xBA &&
      footer[1] == 0xBE && footer[2] == 0x2B && footer[3] == 0xED) {
    fseek(f, 0, SEEK_END);
    data_length = ftell(f) - (16 + (footer[6] << 8) + footer[7]);
  } else {
    fseek(f, 0, SEEK_END);
    data_length = ftell(f);
  }
  fseek(f, 0, SEEK_SET);

  sha256_init(hash);
  do {
    chunk = min(sizeof(buf), data_length);
    if (fread(buf, chunk, 1, f) == 0) {
      goto error2;
    }
    sha256_update(hash, chunk, buf);
    data_length -= chunk;
  } while (data_length > 0);

  is_ok = true;

error2:
  fclose(f);
error:
  return is_ok;
}

static bool remove_signature(const char *data_path) {
  FILE *f;
  bool is_ok = false;
  uint8_t footer[16];

  f = fopen(data_path, "rb+");
  if (!f) {
    fprintf(stderr, "could not open data file\n");
    goto error;
  }

  fseek(f, -16, SEEK_END);
  if (fread(footer, sizeof(footer), 1, f) == 1 && footer[0] == 0xBA &&
      footer[1] == 0xBE && footer[2] == 0x2B && footer[3] == 0xED) {
    long new_size;
    fseek(f, 0, SEEK_END);
    new_size = ftell(f) - (16 + (footer[6] << 8) + footer[7]);
    fseek(f, 0, SEEK_SET);
    fflush(f);
    ftruncate(fileno(f), new_size);

    is_ok = true;
  }

  fclose(f);
error:
  return is_ok;
}

static bool sign_file(const char *data_path) {
  struct sha256_ctx hash;
  mpz_t signature;
  FILE *f;
  uint8_t digest[SHA256_DIGEST_SIZE];
  uint8_t sig[RSA_NUM_BYTES];
  bool is_ok = false;
  unsigned char footer[16];

  remove_signature(data_path);

  if (!hash_file(data_path, &hash)) {
    fprintf(stderr, "could not hash data file\n");
    goto error;
  }

  sha256_digest(&hash, sizeof(digest), digest);
  for (size_t i = 0; i < sizeof(digest); i++) {
    printf("%02x", digest[i]);
  }
  printf("\n");

  mpz_init(signature);
  if (!rsa_sha256_sign_digest(&private_key, digest, signature)) {
    goto error2;
  }

  f = fopen(data_path, "ab+");
  if (!f) {
    fprintf(stderr, "could not open data file\n");
    goto error2;
  }

  nettle_mpz_get_str_256(RSA_NUM_BYTES, sig, signature);

  if (fwrite(sig, RSA_NUM_BYTES, 1, f) == 0) {
    goto error3;
    fprintf(stderr, "could not write signature\n");
  }

  memset(footer, 0, sizeof(footer));
  footer[0] = 0xBA;
  footer[1] = 0xBE;
  footer[2] = 0x2B;
  footer[3] = 0xED;

  footer[4] = 0;
  footer[5] = 1; /* version field */

  footer[6] = (RSA_NUM_BYTES >> 8) & 0xFF; /* number of signature bytes */
  footer[7] = RSA_NUM_BYTES & 0xFF;

  footer[8] = (RSA_NUM_BITS >> 8) & 0xFF; /* number of key bits */
  footer[9] = RSA_NUM_BITS & 0xFF;

  if (fwrite(footer, sizeof(footer), 1, f) == 0) {
    goto error3;
    fprintf(stderr, "could not write footer\n");
  }

  is_ok = true;

error3:
  fclose(f);
error2:
  mpz_clear(signature);
error:
  return is_ok;
}

static bool verify_file(const char *data_path) {
  struct sha256_ctx hash;
  FILE *f;
  mpz_t signature;
  uint8_t *buf;
  int len;
  bool is_ok = false;
  unsigned char footer[16];

  f = fopen(data_path, "rb");
  if (!f) {
    goto error;
  }

  fseek(f, -16, SEEK_END);
  if (fread(footer, sizeof(footer), 1, f) == 0) {
    fprintf(stderr, "unable to read footer\n");
    goto error;
  }

  if (footer[0] != 0xBA || footer[1] != 0xBE || footer[2] != 0x2B ||
      footer[3] != 0xED) {
    fprintf(stderr, "magic not found\n");
    goto error;
  }

  if ((footer[4] << 8) + footer[5] != 1) {
    fprintf(stderr, "unrecognized footer version\n");
    goto error;
  }

  if ((footer[8] << 8) + footer[9] != RSA_NUM_BITS) {
    fprintf(stderr, "wrong number of bits\n");
    goto error;
  }

  len = (footer[6] << 8) + footer[7];

  fseek(f, -16 - len, SEEK_END);
  buf = malloc(len);
  if (!buf) {
    goto error;
  }

  if (fread(buf, len, 1, f) == 0) {
    fprintf(stderr, "could not read signature\n");
    goto error2;
  }

  fclose(f);
  f = NULL;

  if (!hash_file(data_path, &hash)) {
    fprintf(stderr, "could not hash file\n");
    goto error2;
  }

  mpz_init(signature);
  nettle_mpz_set_str_256_u(signature, len, buf);

  if (!rsa_sha256_verify(&public_key, &hash, signature)) {
    goto error3;
  }

  is_ok = true;

error3:
  mpz_clear(signature);
error2:
  free(buf);
error:
  if (f) {
    fclose(f);
  }
  return is_ok;
}

static void show_usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s -k keyfile { -g [-e] | -c file | "
          "-s file | -v file }\n",
          argv0);
  fprintf(stderr, "       %s -r file\n", argv0);
  fprintf(stderr, "\n");
  fprintf(stderr, "  -k keyfile    public or private key file\n");
  fprintf(stderr,
          "  -g            generate key pair               "
          "(private and public key)\n");
  fprintf(stderr, "  -e            encrypt private key\n");
  fprintf(stderr,
          "  -c file       output public key in c code     "
          "(private or public key)\n");
  fprintf(stderr,
          "  -r file       remove signature                "
          "(no key required)\n");
  fprintf(stderr,
          "  -s file       sign file                       "
          "(private key only)\n");
  fprintf(stderr,
          "  -v file       verify file                     "
          "(private or public key)\n");
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  int opt;
  char operation = 0;
  char *key_path = NULL;
  char *data_path = NULL;
  bool result;
  bool encrypt = false;

  extern char *optarg;

  while ((opt = getopt(argc, argv, "eghc:k:s:v:r:")) != -1) {
    switch (opt) {
      case 'e':
        encrypt = true;
        break;

      case 'c':
      case 'g':
      case 's':
      case 'v':
      case 'r':
        if (operation) {
          fprintf(stderr, "only one operation may be specified\n");
          show_usage(argv[0]);
        }
        operation = opt;
        data_path = optarg;
        break;

      case 'k':
        if (key_path) {
          fprintf(stderr, "only one keyfile allowed\n");
          show_usage(argv[0]);
        }
        key_path = optarg;
        break;

      case 'h':
      default:
        show_usage(argv[0]);
    }
  }

  if (!operation) {
    fprintf(stderr, "no operation specified\n");
    show_usage(argv[0]);
  }

  if (!key_path && operation != 'r') {
    fprintf(stderr, "key file must be specified\n");
    show_usage(argv[0]);
  }

  switch (operation) {
    case 'g':
      if (!generate_keypair(key_path, encrypt)) {
        fprintf(stderr, "key generation failed\n");
        exit(EXIT_FAILURE);
      }
      unload_keys();
      break;

    case 'c':
      if (!load_key(key_path, false)) {
        fprintf(stderr, "unable to load public key\n");
        exit(EXIT_FAILURE);
      }
      if (!output_c_source(data_path)) {
        fprintf(stderr, "could not write c file\n");
      }
      unload_keys();
      break;

    case 's':
      if (!load_key(key_path, true)) {
        fprintf(stderr, "unable to load private key\n");
        exit(EXIT_FAILURE);
      }
      if (!sign_file(data_path)) {
        fprintf(stderr, "unable to sign file\n");
        unload_keys();
        exit(EXIT_FAILURE);
      }
      unload_keys();
      break;

    case 'v':
      if (!load_key(key_path, false)) {
        fprintf(stderr, "unable to load public key\n");
        exit(EXIT_FAILURE);
      }
      result = verify_file(data_path);
      unload_keys();

      if (!result) {
        printf("not verified\n");
        exit(EXIT_FAILURE);
      }

      printf("verified\n");
      break;
    case 'r':
      if (!remove_signature(data_path)) {
        fprintf(stderr, "no signature found\n");
        exit(EXIT_FAILURE);
      }
      break;
  }

  return 0;
}
