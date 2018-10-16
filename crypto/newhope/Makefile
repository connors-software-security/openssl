#
# OpenSSL/crypto/newhope/Makefile
#

DIR=	newhope
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST= newhopetest.c newhope_responder.c newhope_initiator.c newhope_speed.c
APPS= 

LIB=$(TOP)/libcrypto.a
LIBSRC= newhope_err.c newhope_lib.c newhope_poly.c 
LIBOBJ= newhope_err.o newhope_lib.o newhope_poly.o $(NH_ASM)

SRC= $(LIBSRC)

EXHEADER= newhope.h
HEADER=	newhope_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

newhope-x86_64.s: asm/newhope-x86_64.pl
	$(PERL) asm/newhope-x86_64.pl $(PERLASM_SCHEME) > $@

newhope-%.S:		asm/newhope-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@
newhope-neon.o:		newhope-neon.S

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

newhope_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
newhope_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
newhope_err.o: ../../include/openssl/lhash.h ../../include/openssl/newhope.h
newhope_err.o: ../../include/openssl/opensslconf.h
newhope_err.o: ../../include/openssl/opensslv.h
newhope_err.o: ../../include/openssl/ossl_typ.h
newhope_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
newhope_err.o: ../../include/openssl/symhacks.h newhope_err.c
newhope_lib.o: ../../e_os.h ../../include/openssl/aes.h
newhope_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
newhope_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
newhope_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
newhope_lib.o: ../../include/openssl/lhash.h ../../include/openssl/newhope.h
newhope_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
newhope_lib.o: ../../include/openssl/opensslconf.h
newhope_lib.o: ../../include/openssl/opensslv.h
newhope_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
newhope_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
newhope_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
newhope_lib.o: ../constant_time_locl.h newhope_a.h newhope_lib.c newhope_locl.h
newhope_lib.o: rlwe_table.h
newhope_poly.o: ../../e_os.h ../../include/openssl/e_os2.h
newhope_poly.o: ../../include/openssl/newhope.h
newhope_poly.o: ../../include/openssl/opensslconf.h ../constant_time_locl.h
newhope_poly.o: newhope_locl.h newhope_poly.c ntt_tables.h
