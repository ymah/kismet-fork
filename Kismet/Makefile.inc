INSTGRP 	?= "root"
MANGRP 		?= "root"
INSTUSR 	?= "root"

ZAURUS 		= @zaurus@

PCAPLNK 	= -lpcap

THREADL 	= 

BLDHOME		= .
CXX			= g++
CC			= gcc
LD			= g++
LDFLAGS		=  -rdynamic
INSTALL		= /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = @INSTALL_STRIP_PROGRAM@
LIBS		= -lcap  -ldl -lm -lpcre
CLIBS   	= 
CXXLIBS		=  -lstdc++
KSLIBS		=   -lnl-genl-3 -lnl-3 
CFLAGS		=  -pthread -I/usr/include/ncurses -I/usr/include/libnl3 
CLIENTLIBS 	=  -ldl -lncurses -lpanel
CAPLIBS		= -lcap
CLIENTFLAGS = 
CXXFLAGS 	= -Wall -g -O2
CPPFLAGS 	=  -pthread -I/usr/include/ncurses -I/usr/include/libnl3 
SUIDGROUP 	= kismet

prefix 		= /usr/local
exec_prefix = ${prefix}
plugindir	= ${exec_prefix}/lib/kismet
ETC			= ${DESTDIR}${prefix}/etc
BIN			= ${DESTDIR}${exec_prefix}/bin
SHARE 		= ${DESTDIR}${prefix}/share/kismet/
MAN 		= ${DESTDIR}${prefix}/share/man
LIB			= ${DESTDIR}${exec_prefix}/lib
WAV 		= ${DESTDIR}${prefix}/share/kismet/wav/

PLUGINLDFLAGS =   -rdynamic

