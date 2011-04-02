# SoftEther UT-VPN SourceCode
# 
# Copyright (C) 2004-2010 SoftEther Corporation.
# Copyright (C) 2004-2010 University of Tsukuba, Japan.
# Copyright (C) 2003-2010 Daiyuu Nobori.
# All Rights Reserved.
# 
# http://utvpn.tsukuba.ac.jp/
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License version 2
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# 
# Platform: os=Linux, bits=32bit, language=Japanese

# Variables
CC=gcc

OPTIONS_COMPILE_DEBUG=-D_DEBUG -DDEBUG -DUNIX -DUNIX_LINUX -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -I./src/ -I./src/Cedar/ -I./src/Mayaqua/ -g -fsigned-char

OPTIONS_LINK_DEBUG=-g -fsigned-char -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz

OPTIONS_COMPILE_RELEASE=-DNDEBUG -DVPN_SPEED -DUNIX -DUNIX_LINUX -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -I./src/ -I./src/Cedar/ -I./src/Mayaqua/ -O2 -fsigned-char

OPTIONS_LINK_RELEASE=-O2 -fsigned-char -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz

INSTALL_BINDIR=/usr/bin/
INSTALL_UTVPNSERVER_DIR=/usr/utvpnserver/
INSTALL_UTVPNCLIENT_DIR=/usr/utvpnclient/
INSTALL_UTVPNCMD_DIR=/usr/utvpncmd/

ifeq ($(DEBUG),YES)
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_DEBUG)
	OPTIONS_LINK=$(OPTIONS_LINK_DEBUG)
else
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_RELEASE)
	OPTIONS_LINK=$(OPTIONS_LINK_RELEASE)
endif

# Files
HEADERS_MAYAQUA=src/Mayaqua/Cfg.h src/Mayaqua/cryptoki.h src/Mayaqua/Encrypt.h src/Mayaqua/FileIO.h src/Mayaqua/Internat.h src/Mayaqua/Kernel.h src/Mayaqua/Mayaqua.h src/Mayaqua/MayaType.h src/Mayaqua/Memory.h src/Mayaqua/Microsoft.h src/Mayaqua/Network.h src/Mayaqua/Object.h src/Mayaqua/openssl/aes.h src/Mayaqua/openssl/asn1.h src/Mayaqua/openssl/asn1_mac.h src/Mayaqua/openssl/asn1t.h src/Mayaqua/openssl/bio.h src/Mayaqua/openssl/blowfish.h src/Mayaqua/openssl/bn.h src/Mayaqua/openssl/buffer.h src/Mayaqua/openssl/cast.h src/Mayaqua/openssl/comp.h src/Mayaqua/openssl/conf.h src/Mayaqua/openssl/conf_api.h src/Mayaqua/openssl/crypto.h src/Mayaqua/openssl/des.h src/Mayaqua/openssl/des_old.h src/Mayaqua/openssl/dh.h src/Mayaqua/openssl/dsa.h src/Mayaqua/openssl/dso.h src/Mayaqua/openssl/dtls1.h src/Mayaqua/openssl/e_os2.h src/Mayaqua/openssl/ebcdic.h src/Mayaqua/openssl/ec.h src/Mayaqua/openssl/ecdh.h src/Mayaqua/openssl/ecdsa.h src/Mayaqua/openssl/engine.h src/Mayaqua/openssl/err.h src/Mayaqua/openssl/evp.h src/Mayaqua/openssl/fips.h src/Mayaqua/openssl/fips_rand.h src/Mayaqua/openssl/hmac.h src/Mayaqua/openssl/idea.h src/Mayaqua/openssl/krb5_asn.h src/Mayaqua/openssl/kssl.h src/Mayaqua/openssl/lhash.h src/Mayaqua/openssl/md2.h src/Mayaqua/openssl/md4.h src/Mayaqua/openssl/md5.h src/Mayaqua/openssl/mdc2.h src/Mayaqua/openssl/obj_mac.h src/Mayaqua/openssl/objects.h src/Mayaqua/openssl/ocsp.h src/Mayaqua/openssl/opensslconf.h src/Mayaqua/openssl/opensslv.h src/Mayaqua/openssl/ossl_typ.h src/Mayaqua/openssl/pem.h src/Mayaqua/openssl/pem2.h src/Mayaqua/openssl/pkcs12.h src/Mayaqua/openssl/pkcs7.h src/Mayaqua/openssl/pq_compat.h src/Mayaqua/openssl/pqueue.h src/Mayaqua/openssl/rand.h src/Mayaqua/openssl/rc2.h src/Mayaqua/openssl/rc4.h src/Mayaqua/openssl/rc5.h src/Mayaqua/openssl/ripemd.h src/Mayaqua/openssl/rsa.h src/Mayaqua/openssl/safestack.h src/Mayaqua/openssl/sha.h src/Mayaqua/openssl/ssl.h src/Mayaqua/openssl/ssl2.h src/Mayaqua/openssl/ssl23.h src/Mayaqua/openssl/ssl3.h src/Mayaqua/openssl/stack.h src/Mayaqua/openssl/store.h src/Mayaqua/openssl/symhacks.h src/Mayaqua/openssl/tls1.h src/Mayaqua/openssl/tmdiff.h src/Mayaqua/openssl/txt_db.h src/Mayaqua/openssl/ui.h src/Mayaqua/openssl/ui_compat.h src/Mayaqua/openssl/x509.h src/Mayaqua/openssl/x509_vfy.h src/Mayaqua/openssl/x509v3.h src/Mayaqua/OS.h src/Mayaqua/Pack.h src/Mayaqua/pkcs11.h src/Mayaqua/pkcs11f.h src/Mayaqua/pkcs11t.h src/Mayaqua/Secure.h src/Mayaqua/Str.h src/Mayaqua/Table.h src/Mayaqua/Tick64.h src/Mayaqua/Tracking.h src/Mayaqua/TunTap.h src/Mayaqua/Unix.h src/Mayaqua/Win32.h src/Mayaqua/zlib/zconf.h src/Mayaqua/zlib/zlib.h
HEADERS_CEDAR=src/Cedar/Account.h src/Cedar/Admin.h src/Cedar/Bridge.h src/Cedar/BridgeUnix.h src/Cedar/BridgeWin32.h src/Cedar/Cedar.h src/Cedar/CedarPch.h src/Cedar/CedarType.h src/Cedar/Client.h src/Cedar/CM.h src/Cedar/CMInner.h src/Cedar/Command.h src/Cedar/Connection.h src/Cedar/Console.h src/Cedar/Database.h src/Cedar/Hub.h src/Cedar/Layer3.h src/Cedar/Link.h src/Cedar/Listener.h src/Cedar/Logging.h src/Cedar/Nat.h src/Cedar/NM.h src/Cedar/NMInner.h src/Cedar/NullLan.h src/Cedar/Protocol.h src/Cedar/Remote.h src/Cedar/Sam.h src/Cedar/SecureNAT.h src/Cedar/Server.h src/Cedar/Session.h src/Cedar/SM.h src/Cedar/SMInner.h src/Cedar/TcpIp.h src/Cedar/UT.h src/Cedar/Virtual.h src/Cedar/VLan.h src/Cedar/VLanUnix.h src/Cedar/VLanWin32.h src/Cedar/Win32Html.h src/Cedar/WinUi.h
OBJECTS_MAYAQUA=tmp/objs/Mayaqua/Cfg.o tmp/objs/Mayaqua/Encrypt.o tmp/objs/Mayaqua/FileIO.o tmp/objs/Mayaqua/Internat.o tmp/objs/Mayaqua/Kernel.o tmp/objs/Mayaqua/Mayaqua.o tmp/objs/Mayaqua/Memory.o tmp/objs/Mayaqua/Microsoft.o tmp/objs/Mayaqua/Network.o tmp/objs/Mayaqua/Object.o tmp/objs/Mayaqua/OS.o tmp/objs/Mayaqua/Pack.o tmp/objs/Mayaqua/Secure.o tmp/objs/Mayaqua/Str.o tmp/objs/Mayaqua/Table.o tmp/objs/Mayaqua/Tick64.o tmp/objs/Mayaqua/Tracking.o tmp/objs/Mayaqua/Unix.o tmp/objs/Mayaqua/Win32.o
OBJECTS_CEDAR=tmp/objs/Cedar/Account.o tmp/objs/Cedar/Admin.o tmp/objs/Cedar/Bridge.o tmp/objs/Cedar/BridgeUnix.o tmp/objs/Cedar/BridgeWin32.o tmp/objs/Cedar/Cedar.o tmp/objs/Cedar/CedarPch.o tmp/objs/Cedar/Client.o tmp/objs/Cedar/CM.o tmp/objs/Cedar/Command.o tmp/objs/Cedar/Connection.o tmp/objs/Cedar/Console.o tmp/objs/Cedar/Database.o tmp/objs/Cedar/Hub.o tmp/objs/Cedar/Layer3.o tmp/objs/Cedar/Link.o tmp/objs/Cedar/Listener.o tmp/objs/Cedar/Logging.o tmp/objs/Cedar/Nat.o tmp/objs/Cedar/NM.o tmp/objs/Cedar/NullLan.o tmp/objs/Cedar/Protocol.o tmp/objs/Cedar/Remote.o tmp/objs/Cedar/Sam.o tmp/objs/Cedar/SecureNAT.o tmp/objs/Cedar/Server.o tmp/objs/Cedar/Session.o tmp/objs/Cedar/SM.o tmp/objs/Cedar/TcpIp.o tmp/objs/Cedar/UT.o tmp/objs/Cedar/Virtual.o tmp/objs/Cedar/VLan.o tmp/objs/Cedar/VLanUnix.o tmp/objs/Cedar/VLanWin32.o tmp/objs/Cedar/WinUi.o

# Build Action
default:	build

build:	$(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) output/ham/ham output/utvpnserver/utvpnserver output/utvpnclient/utvpnclient output/utvpncmd/utvpncmd

# Mayaqua Kernel Code
tmp/objs/Mayaqua/Cfg.o: src/Mayaqua/Cfg.c $(HEADERS_MAYAQUA)
	@mkdir -p tmp/
	@mkdir -p tmp/objs/
	@mkdir -p tmp/objs/Mayaqua/
	@mkdir -p tmp/objs/Cedar/
	@mkdir -p tmp/as/
	@mkdir -p output/
	@mkdir -p output/ham/
	@mkdir -p output/utvpnserver/
	@mkdir -p output/utvpnclient/
	@mkdir -p output/utvpncmd/
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Cfg.c -o tmp/objs/Mayaqua/Cfg.o

tmp/objs/Mayaqua/Encrypt.o: src/Mayaqua/Encrypt.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Encrypt.c -o tmp/objs/Mayaqua/Encrypt.o

tmp/objs/Mayaqua/FileIO.o: src/Mayaqua/FileIO.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/FileIO.c -o tmp/objs/Mayaqua/FileIO.o

tmp/objs/Mayaqua/Internat.o: src/Mayaqua/Internat.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Internat.c -o tmp/objs/Mayaqua/Internat.o

tmp/objs/Mayaqua/Kernel.o: src/Mayaqua/Kernel.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Kernel.c -o tmp/objs/Mayaqua/Kernel.o

tmp/objs/Mayaqua/Mayaqua.o: src/Mayaqua/Mayaqua.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Mayaqua.c -o tmp/objs/Mayaqua/Mayaqua.o

tmp/objs/Mayaqua/Memory.o: src/Mayaqua/Memory.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Memory.c -o tmp/objs/Mayaqua/Memory.o

tmp/objs/Mayaqua/Microsoft.o: src/Mayaqua/Microsoft.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Microsoft.c -o tmp/objs/Mayaqua/Microsoft.o

tmp/objs/Mayaqua/Network.o: src/Mayaqua/Network.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Network.c -o tmp/objs/Mayaqua/Network.o

tmp/objs/Mayaqua/Object.o: src/Mayaqua/Object.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Object.c -o tmp/objs/Mayaqua/Object.o

tmp/objs/Mayaqua/OS.o: src/Mayaqua/OS.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/OS.c -o tmp/objs/Mayaqua/OS.o

tmp/objs/Mayaqua/Pack.o: src/Mayaqua/Pack.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Pack.c -o tmp/objs/Mayaqua/Pack.o

tmp/objs/Mayaqua/Secure.o: src/Mayaqua/Secure.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Secure.c -o tmp/objs/Mayaqua/Secure.o

tmp/objs/Mayaqua/Str.o: src/Mayaqua/Str.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Str.c -o tmp/objs/Mayaqua/Str.o

tmp/objs/Mayaqua/Table.o: src/Mayaqua/Table.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Table.c -o tmp/objs/Mayaqua/Table.o

tmp/objs/Mayaqua/Tick64.o: src/Mayaqua/Tick64.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Tick64.c -o tmp/objs/Mayaqua/Tick64.o

tmp/objs/Mayaqua/Tracking.o: src/Mayaqua/Tracking.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Tracking.c -o tmp/objs/Mayaqua/Tracking.o

tmp/objs/Mayaqua/Unix.o: src/Mayaqua/Unix.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Unix.c -o tmp/objs/Mayaqua/Unix.o

tmp/objs/Mayaqua/Win32.o: src/Mayaqua/Win32.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Win32.c -o tmp/objs/Mayaqua/Win32.o

# Cedar Communication Module Code
tmp/objs/Cedar/Account.o: src/Cedar/Account.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Account.c -o tmp/objs/Cedar/Account.o

tmp/objs/Cedar/Admin.o: src/Cedar/Admin.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Admin.c -o tmp/objs/Cedar/Admin.o

tmp/objs/Cedar/Bridge.o: src/Cedar/Bridge.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) src/Cedar/BridgeUnix.c
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Bridge.c -o tmp/objs/Cedar/Bridge.o

tmp/objs/Cedar/BridgeUnix.o: src/Cedar/BridgeUnix.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/BridgeUnix.c -o tmp/objs/Cedar/BridgeUnix.o

tmp/objs/Cedar/BridgeWin32.o: src/Cedar/BridgeWin32.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/BridgeWin32.c -o tmp/objs/Cedar/BridgeWin32.o

tmp/objs/Cedar/Cedar.o: src/Cedar/Cedar.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Cedar.c -o tmp/objs/Cedar/Cedar.o

tmp/objs/Cedar/CedarPch.o: src/Cedar/CedarPch.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/CedarPch.c -o tmp/objs/Cedar/CedarPch.o

tmp/objs/Cedar/Client.o: src/Cedar/Client.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Client.c -o tmp/objs/Cedar/Client.o

tmp/objs/Cedar/CM.o: src/Cedar/CM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/CM.c -o tmp/objs/Cedar/CM.o

tmp/objs/Cedar/Command.o: src/Cedar/Command.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Command.c -o tmp/objs/Cedar/Command.o

tmp/objs/Cedar/Connection.o: src/Cedar/Connection.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Connection.c -o tmp/objs/Cedar/Connection.o

tmp/objs/Cedar/Console.o: src/Cedar/Console.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Console.c -o tmp/objs/Cedar/Console.o

tmp/objs/Cedar/Database.o: src/Cedar/Database.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Database.c -o tmp/objs/Cedar/Database.o

tmp/objs/Cedar/Hub.o: src/Cedar/Hub.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Hub.c -o tmp/objs/Cedar/Hub.o

tmp/objs/Cedar/Layer3.o: src/Cedar/Layer3.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Layer3.c -o tmp/objs/Cedar/Layer3.o

tmp/objs/Cedar/Link.o: src/Cedar/Link.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Link.c -o tmp/objs/Cedar/Link.o

tmp/objs/Cedar/Listener.o: src/Cedar/Listener.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Listener.c -o tmp/objs/Cedar/Listener.o

tmp/objs/Cedar/Logging.o: src/Cedar/Logging.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Logging.c -o tmp/objs/Cedar/Logging.o

tmp/objs/Cedar/Nat.o: src/Cedar/Nat.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Nat.c -o tmp/objs/Cedar/Nat.o

tmp/objs/Cedar/NM.o: src/Cedar/NM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/NM.c -o tmp/objs/Cedar/NM.o

tmp/objs/Cedar/NullLan.o: src/Cedar/NullLan.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/NullLan.c -o tmp/objs/Cedar/NullLan.o

tmp/objs/Cedar/Protocol.o: src/Cedar/Protocol.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Protocol.c -o tmp/objs/Cedar/Protocol.o

tmp/objs/Cedar/Remote.o: src/Cedar/Remote.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Remote.c -o tmp/objs/Cedar/Remote.o

tmp/objs/Cedar/Sam.o: src/Cedar/Sam.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Sam.c -o tmp/objs/Cedar/Sam.o

tmp/objs/Cedar/SecureNAT.o: src/Cedar/SecureNAT.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SecureNAT.c -o tmp/objs/Cedar/SecureNAT.o

tmp/objs/Cedar/Server.o: src/Cedar/Server.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Server.c -o tmp/objs/Cedar/Server.o

tmp/objs/Cedar/Session.o: src/Cedar/Session.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Session.c -o tmp/objs/Cedar/Session.o

tmp/objs/Cedar/SM.o: src/Cedar/SM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SM.c -o tmp/objs/Cedar/SM.o

tmp/objs/Cedar/TcpIp.o: src/Cedar/TcpIp.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/TcpIp.c -o tmp/objs/Cedar/TcpIp.o

tmp/objs/Cedar/UT.o: src/Cedar/UT.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/UT.c -o tmp/objs/Cedar/UT.o

tmp/objs/Cedar/Virtual.o: src/Cedar/Virtual.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Virtual.c -o tmp/objs/Cedar/Virtual.o

tmp/objs/Cedar/VLan.o: src/Cedar/VLan.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VLan.c -o tmp/objs/Cedar/VLan.o

tmp/objs/Cedar/VLanUnix.o: src/Cedar/VLanUnix.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VLanUnix.c -o tmp/objs/Cedar/VLanUnix.o

tmp/objs/Cedar/VLanWin32.o: src/Cedar/VLanWin32.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VLanWin32.c -o tmp/objs/Cedar/VLanWin32.o

tmp/objs/Cedar/WinUi.o: src/Cedar/WinUi.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/WinUi.c -o tmp/objs/Cedar/WinUi.o

# Ham
output/ham/ham: tmp/as/Ham.a output/ham/hamcore.utvpn $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) tmp/as/Ham.a $(OPTIONS_LINK) -o output/ham/ham

tmp/as/Ham.a: tmp/objs/Ham.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/Ham.a
	ar r tmp/as/Ham.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/Ham.o
	ranlib tmp/as/Ham.a

output/ham/hamcore.utvpn: src/bin/BuiltHamcoreFiles/unix_ja/hamcore.utvpn
	cp src/bin/BuiltHamcoreFiles/unix_ja/hamcore.utvpn output/ham/hamcore.utvpn

tmp/objs/Ham.o: src/Ham/Ham.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Ham/Ham.c -o tmp/objs/Ham.o

# utvpnserver
output/utvpnserver/utvpnserver: tmp/as/utvpnserver.a output/utvpnserver/hamcore.utvpn $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) tmp/as/utvpnserver.a $(OPTIONS_LINK) -o output/utvpnserver/utvpnserver

tmp/as/utvpnserver.a: tmp/objs/utvpnserver.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/utvpnserver.a
	ar r tmp/as/utvpnserver.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/utvpnserver.o
	ranlib tmp/as/utvpnserver.a

output/utvpnserver/hamcore.utvpn: src/bin/BuiltHamcoreFiles/unix_ja/hamcore.utvpn
	cp src/bin/BuiltHamcoreFiles/unix_ja/hamcore.utvpn output/utvpnserver/hamcore.utvpn

tmp/objs/utvpnserver.o: src/utvpnserver/utvpnserver.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/utvpnserver/utvpnserver.c -o tmp/objs/utvpnserver.o

# utvpnclient
output/utvpnclient/utvpnclient: tmp/as/utvpnclient.a output/utvpnclient/hamcore.utvpn $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) tmp/as/utvpnclient.a $(OPTIONS_LINK) -o output/utvpnclient/utvpnclient

tmp/as/utvpnclient.a: tmp/objs/utvpnclient.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/utvpnclient.a
	ar r tmp/as/utvpnclient.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/utvpnclient.o
	ranlib tmp/as/utvpnclient.a

output/utvpnclient/hamcore.utvpn: src/bin/BuiltHamcoreFiles/unix_ja/hamcore.utvpn
	cp src/bin/BuiltHamcoreFiles/unix_ja/hamcore.utvpn output/utvpnclient/hamcore.utvpn

tmp/objs/utvpnclient.o: src/utvpnclient/utvpnclient.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/utvpnclient/utvpnclient.c -o tmp/objs/utvpnclient.o

# utvpncmd
output/utvpncmd/utvpncmd: tmp/as/utvpncmd.a output/utvpncmd/hamcore.utvpn $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) tmp/as/utvpncmd.a $(OPTIONS_LINK) -o output/utvpncmd/utvpncmd

tmp/as/utvpncmd.a: tmp/objs/utvpncmd.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/utvpncmd.a
	ar r tmp/as/utvpncmd.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/utvpncmd.o
	ranlib tmp/as/utvpncmd.a

output/utvpncmd/hamcore.utvpn: src/bin/BuiltHamcoreFiles/unix_ja/hamcore.utvpn
	cp src/bin/BuiltHamcoreFiles/unix_ja/hamcore.utvpn output/utvpncmd/hamcore.utvpn

tmp/objs/utvpncmd.o: src/utvpncmd/utvpncmd.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/utvpncmd/utvpncmd.c -o tmp/objs/utvpncmd.o

# Install
install: $(INSTALL_BINDIR)utvpnserver $(INSTALL_BINDIR)utvpnclient $(INSTALL_BINDIR)utvpncmd
	@echo
	@echo "--------------------------------------------------------------------"
	@echo "Installation completed successfully."
	@echo
	@echo "Please execute 'utvpnserver start' to run UT-VPN Server Background Service."
	@echo "Or please execute 'utvpnclient start' to run UT-VPN Client Background Service."
	@echo "And please execute 'utvpncmd' to run UT-VPN Command-Line Utility to configure UT-Server or UT-VPN Client."
	@echo "--------------------------------------------------------------------"
	@echo

$(INSTALL_BINDIR)utvpnserver: output/utvpnserver/hamcore.utvpn output/utvpnserver/utvpnserver
	@mkdir -p $(INSTALL_UTVPNSERVER_DIR)
	cp output/utvpnserver/hamcore.utvpn $(INSTALL_UTVPNSERVER_DIR)hamcore.utvpn
	cp output/utvpnserver/utvpnserver $(INSTALL_UTVPNSERVER_DIR)utvpnserver
	echo "#!/bin/sh" > $(INSTALL_BINDIR)utvpnserver
	echo $(INSTALL_UTVPNSERVER_DIR)utvpnserver '"$$@"' >> $(INSTALL_BINDIR)utvpnserver
	echo 'exit $$?' >> $(INSTALL_BINDIR)utvpnserver
	chmod 755 $(INSTALL_BINDIR)utvpnserver

$(INSTALL_BINDIR)utvpnclient: output/utvpnclient/hamcore.utvpn output/utvpnclient/utvpnclient
	@mkdir -p $(INSTALL_UTVPNCLIENT_DIR)
	cp output/utvpnclient/hamcore.utvpn $(INSTALL_UTVPNCLIENT_DIR)hamcore.utvpn
	cp output/utvpnclient/utvpnclient $(INSTALL_UTVPNCLIENT_DIR)utvpnclient
	echo "#!/bin/sh" > $(INSTALL_BINDIR)utvpnclient
	echo $(INSTALL_UTVPNCLIENT_DIR)utvpnclient '"$$@"' >> $(INSTALL_BINDIR)utvpnclient
	echo 'exit $$?' >> $(INSTALL_BINDIR)utvpnclient
	chmod 755 $(INSTALL_BINDIR)utvpnclient

$(INSTALL_BINDIR)utvpncmd: output/utvpncmd/hamcore.utvpn output/utvpncmd/utvpncmd
	@mkdir -p $(INSTALL_UTVPNCMD_DIR)
	cp output/utvpncmd/hamcore.utvpn $(INSTALL_UTVPNCMD_DIR)hamcore.utvpn
	cp output/utvpncmd/utvpncmd $(INSTALL_UTVPNCMD_DIR)utvpncmd
	echo "#!/bin/sh" > $(INSTALL_BINDIR)utvpncmd
	echo $(INSTALL_UTVPNCMD_DIR)utvpncmd '"$$@"' >> $(INSTALL_BINDIR)utvpncmd
	echo 'exit $$?' >> $(INSTALL_BINDIR)utvpncmd
	chmod 755 $(INSTALL_BINDIR)utvpncmd

# Clean
clean:
	-rm -f $(OBJECTS_MAYAQUA)
	-rm -f $(OBJECTS_CEDAR)
	-rm -f tmp/objs/Ham.o
	-rm -f tmp/as/Ham.a
	-rm -f output/ham/ham
	-rm -f tmp/objs/utvpnserver.o
	-rm -f tmp/as/utvpnserver.a
	-rm -f output/utvpnserver/utvpnserver
	-rm -f tmp/objs/utvpnclient.o
	-rm -f tmp/as/utvpnclient.a
	-rm -f output/utvpnclient/utvpnclient
	-rm -f tmp/objs/utvpncmd.o
	-rm -f tmp/as/utvpncmd.a
	-rm -f output/utvpncmd/utvpncmd

# Help Strings
help:
	@echo "make [DEBUG=YES]"

