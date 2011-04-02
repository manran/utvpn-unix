// SoftEther UT-VPN SourceCode
// 
// Copyright (C) 2004-2010 SoftEther Corporation.
// Copyright (C) 2004-2010 University of Tsukuba, Japan.
// Copyright (C) 2003-2010 Daiyuu Nobori.
// All Rights Reserved.
// 
// http://utvpn.tsukuba.ac.jp/
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// このファイルは GPL バージョン 2 ライセンスで公開されています。
// 誰でもこのファイルの内容を複製、改変したり、改変したバージョンを再配布
// することができます。ただし、原著作物を改変した場合は、原著作物の著作権表示
// を除去することはできません。改変した著作物を配布する場合は、改変実施者の
// 著作権表示を原著作物の著作権表示に付随して記載するようにしてください。
// 
// この SoftEther UT-VPN オープンソース・プロジェクトは、日本国の
// ソフトイーサ株式会社 (SoftEther Corporation, http://www.softether.co.jp/ )
// および筑波大学 (University of Tsukuba, http://www.tsukuba.ac.jp/ ) によって
// ホストされています。
// 本プログラムの配布者は、本プログラムを、業としての利用以外のため、
// および、試験または研究のために利用が行われることを想定して配布
// しています。
// SoftEther UT-VPN プロジェクトの Web サイトは http://utvpn.tsukuba.ac.jp/ に
// あります。
// 本ソフトウェアの不具合の修正、機能改良、セキュリティホールの修復などのコード
// の改変を行った場合で、その成果物を SoftEther UT-VPN プロジェクトに提出して
// いただける場合は、 http://utvpn.tsukuba.ac.jp/ までソースコードを送付して
// ください。SoftEther UT-VPN プロジェクトの本体リリースまたはブランチリリース
// に組み込みさせていただきます。
// 
// GPL に基づいて原著作物が提供される本ソフトウェアの改良版を配布、販売する
// 場合は、そのソースコードを GPL に基づいて誰にでも開示する義務が生じます。
// 
// 本ソフトウェアに関連する著作権、特許権、商標権はソフトイーサ株式会社
// (SoftEther Corporation) およびその他の著作権保持者が保有しています。
// ソフトイーサ株式会社等はこれらの権利を放棄していません。本ソフトウェアの
// 二次著作物を配布、販売する場合は、これらの権利を侵害しないようにご注意
// ください。
// 
// お願い: どのような通信ソフトウェアにも通常は必ず未発見の
// セキュリティホールが潜んでいます。本ソースコードをご覧いただいた結果、
// UT-VPN にセキュリティホールを発見された場合は、当該セキュリティホールの
// 情報を不特定多数に開示される前に、必ず、ソフトイーサ株式会社
// および脆弱性情報の届出を受け付ける公的機関まで通報いただき、
// 公益保護にご協力いただきますようお願い申し上げます。
// 
// ソフトイーサ株式会社は、当該セキュリティホールについて迅速に対処を
// 行い、UT-VPN および UT-VPN に関連するソフトウェアのユーザー・顧客
// を保護するための努力を行います。
// 
// ソフトイーサへの届出先: http://www.softether.co.jp/jp/contact/
// 日本国内の脆弱性情報届出受付公的機関:
//         独立行政法人 情報処理推進機構
//         http://www.ipa.go.jp/security/vuln/report/
// 
// 上記各事項について不明な点は、ソフトイーサ株式会社までご連絡ください。
// 連絡先: http://www.softether.co.jp/jp/contact/

// -----------------------------------------------
// [ChangeLog]
// 2010.05.20
//  新規リリース by SoftEther
// -----------------------------------------------

#ifndef	TUNTAP_H
#define	TUNTAP_H

#ifdef	UNIX_LINUX

// -----------------------------------------------------------------
// Linux 用 tap ヘッダ
// -----------------------------------------------------------------
/*
 *  Universal TUN/TAP device driver.
 *  Copyright (C) 1999-2000 Maxim Krasnyansky <max_mk@yahoo.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  $Id: if_tun.h,v 1.2 2001/10/31 15:27:57 arjanv Exp $
 */

#ifndef __IF_TUN_H
#define __IF_TUN_H

/* Uncomment to enable debugging */
/* #define TUN_DEBUG 1 */



/* Read queue size */
#define TUN_READQ_SIZE  10

/* TUN device flags */
#define TUN_TUN_DEV     0x0001  
#define TUN_TAP_DEV     0x0002
#define TUN_TYPE_MASK   0x000f

#define TUN_FASYNC      0x0010
#define TUN_NOCHECKSUM  0x0020
#define TUN_NO_PI       0x0040
#define TUN_ONE_QUEUE   0x0080
#define TUN_PERSIST     0x0100  

/* Ioctl defines */
#define TUNSETNOCSUM  _IOW('T', 200, int) 
#define TUNSETDEBUG   _IOW('T', 201, int) 
#define TUNSETIFF     _IOW('T', 202, int) 
#define TUNSETPERSIST _IOW('T', 203, int) 
#define TUNSETOWNER   _IOW('T', 204, int)

/* TUNSETIFF ifr flags */
#define IFF_TUN         0x0001
#define IFF_TAP         0x0002
#define IFF_NO_PI       0x1000
#define IFF_ONE_QUEUE   0x2000

struct tun_pi {
        unsigned short flags;
        unsigned short proto;
};
#define TUN_PKT_STRIP   0x0001

#endif /* __IF_TUN_H */
#else	// UNIX_LINUX

#ifdef	UNIX_SOLARIS

// -----------------------------------------------------------------
// Solaris 用 tap ヘッダ
// -----------------------------------------------------------------
/*
 *  Universal TUN/TAP device driver.
 *
 *  Multithreaded STREAMS tun pseudo device driver.
 *
 *  Copyright (C) 1999-2000 Maxim Krasnyansky <max_mk@yahoo.com>
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  $Id: if_tun.h,v 1.4 2000/05/01 12:23:27 maxk Exp $
 */

#ifndef _SYS_IF_TUN_H
#define _SYS_IF_TUN_H

#ifdef _KERNEL
/* Uncomment to enable debuging */
/* #define TUN_DEBUG 1 */

#ifdef TUN_DEBUG
#define DBG      cmn_err
#else
#define DBG( a... )
#endif

/* PPA structure, one per TUN iface */ 
struct tunppa {
  unsigned int id;              /* Iface number         */
  queue_t *rq;                  /* Control Stream RQ    */
  struct tunstr * p_str;        /* Protocol Streams     */
}; 
#define TUNMAXPPA       20

/* Stream structure, one per Stream */
struct tunstr {
  struct tunstr *s_next;        /* next in streams list */
  struct tunstr *p_next;        /* next in ppa list */
  queue_t *rq;                  /* pointer to rq */

  struct tunppa *ppa;           /* assigned PPA */
  u_long flags;                 /* flags */
  u_long state;                 /* DL state */
  u_long sap;                   /* bound sap */
  u_long minor;                 /* minor device number */
};

/* Flags */
#define TUN_CONTROL     0x0001

#define TUN_RAW         0x0100
#define TUN_FAST        0x0200

#define TUN_ALL_PHY     0x0010
#define TUN_ALL_SAP     0x0020
#define TUN_ALL_MUL     0x0040

#define SNIFFER(a) ( (a & TUN_ALL_SAP) || (a & TUN_ALL_PHY) )

struct tundladdr {
  u_short sap;
};
#define TUN_ADDR_LEN    (sizeof(struct tundladdr))

#define TUN_QUEUE       0
#define TUN_DROP        1

#endif /* _KERNEL */

/* IOCTL defines */
#define TUNNEWPPA       (('T'<<16) | 0x0001)
#define TUNSETPPA       (('T'<<16) | 0x0002)

#endif  /* _SYS_IF_TUN_H */

#else	// UNIX_SOLARIS

#ifdef	UNIX_BSD

// -----------------------------------------------------------------
// FreeBSD 用 tap ヘッダ
// -----------------------------------------------------------------
/*      $NetBSD: if_tun.h,v 1.5 1994/06/29 06:36:27 cgd Exp $   */

/*
 * Copyright (c) 1988, Julian Onions <jpo@cs.nott.ac.uk>
 * Nottingham University 1987.
 *
 * This source may be freely distributed, however I would be interested
 * in any changes that are made.
 *
 * This driver takes packets off the IP i/f and hands them up to a
 * user process to have its wicked way with. This driver has it's
 * roots in a similar driver written by Phil Cockcroft (formerly) at
 * UCL. This driver is based much more on read/write/select mode of
 * operation though.
 *
 * $FreeBSD: src/sys/net/if_tun.h,v 1.17 2000/01/23 01:47:12 brian Exp $
 */

#ifndef _NET_IF_TUN_H_
#define _NET_IF_TUN_H_

/* Refer to if_tunvar.h for the softc stuff */

/* Maximum transmit packet size (default) */
#define TUNMTU          1500

/* Maximum receive packet size (hard limit) */
#define TUNMRU          16384

struct tuninfo {
        int     baudrate;               /* linespeed */
        short   mtu;                    /* maximum transmission unit */
        u_char  type;                   /* ethernet, tokenring, etc. */
        u_char  dummy;                  /* place holder */
};

/* ioctl's for get/set debug */
#define TUNSDEBUG       _IOW('t', 90, int)
#define TUNGDEBUG       _IOR('t', 89, int)
#define TUNSIFINFO      _IOW('t', 91, struct tuninfo)
#define TUNGIFINFO      _IOR('t', 92, struct tuninfo)
#define TUNSLMODE       _IOW('t', 93, int)
#define TUNSIFMODE      _IOW('t', 94, int)
#define TUNSIFPID       _IO('t', 95)
#define TUNSIFHEAD      _IOW('t', 96, int)
#define TUNGIFHEAD      _IOR('t', 97, int)

#endif /* !_NET_IF_TUN_H_ */

#else	// UNIX_BSD

#ifdef	UNIX_MACOS

// -----------------------------------------------------------------
// MacOS 用 tap ヘッダ
// -----------------------------------------------------------------

#else	// UNIX_MACOS

#endif	// UNIX_MACOS

#endif	// UNIX_BSD

#endif	// UNIX_SOLARIS

#endif	// UNIX_LINUX

#endif	// TUNTAP_H
