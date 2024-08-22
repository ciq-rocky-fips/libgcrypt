

# should be all algorithms except SM3 and SM4
export DIGESTS='crc gostr3411-94 md4 md5 rmd160 sha1 sha256 sha512 sha3 tiger whirlpool stribog blake2'
export CIPHERS='arcfour blowfish cast5 des aes twofish serpent rfc2268 seed camellia idea salsa20 gost28147 chacha20'
export FIPS_MODULE_NAME="Rocky Linux 8 Libgcrypt Cryptographic Module"
export gcrylibdir=%{_libdir}
export gcrysoname=libgcrypt.so.20
export hmackey=orboDeJITITejsirpADONivirpUkvarP
make clean
./autogen.sh
export LIBS=-lpthread

./configure --disable-static \
     --enable-hmac-binary-check=%{hmackey} \
     --disable-brainpool \
     --disable-jent-support \
     --enable-digests="$DIGESTS" \
     --enable-ciphers="$CIPHERS" \
     --enable-marvin-workaround \
     --disable-avx-support \
     --disable-avx2-support \
     --disable-aesni-support \
     --disable-asm \
     --with-fips-module-version="$FIPS_MODULE_NAME %{version}-%{srpmhash}" \
     --disable-avx-support \
     --prefix=`pwd`/install

sed -i -e '/^sys_lib_dlsearch_path_spec/s,/lib /usr/lib,/usr/lib /lib64 /usr/lib64 /lib,g' libtool
make
make install

# try in faked FIPS mode too
#LIBGCRYPT_FORCE_FIPS_MODE=1 make check

#libcrypt has a section in the binary that contains the hmac. The hmac is written to the lib by objcopy
#export libpath=$RPM_BUILD_ROOT%{gcrylibdir}/%{gcrysoname}.?.?
#%define __spec_install_post \
#    %{?__debug_package:%{__debug_install_post}} \
#    %{__arch_install_post} \
#    %{__os_install_post} \
#    dd if=/dev/zero of=%{libpath}.hmac bs=32 count=1 \
#    objcopy --update-section .rodata1=%{libpath}.hmac %{libpath} %{libpath}.empty \
#    src/hmac256 --binary %{hmackey} %{libpath}.empty > %{libpath}.hmac \
#    objcopy --update-section .rodata1=%{libpath}.hmac %{libpath}.empty %{libpath}.new \
#    mv -f %{libpath}.new %{libpath} \
#    rm -f %{libpath}.hmac %{libpath}.empty
