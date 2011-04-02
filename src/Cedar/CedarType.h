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

// CedarType.h
// Cedar が使用している型の一覧

#ifndef	CEDARTYPE_H
#define	CEDARTYPE_H


// ==============================================================
//   Remote Procedure Call
// ==============================================================

typedef struct RPC RPC;


// ==============================================================
//   Account
// ==============================================================

typedef struct POLICY_ITEM POLICY_ITEM;
typedef struct POLICY POLICY;
typedef struct USERGROUP USERGROUP;
typedef struct USER USER;
typedef struct AUTHPASSWORD AUTHPASSWORD;
typedef struct AUTHUSERCERT AUTHUSERCERT;
typedef struct AUTHROOTCERT AUTHROOTCERT;
typedef struct AUTHRADIUS AUTHRADIUS;
typedef struct AUTHNT AUTHNT;


// ==============================================================
//   Listener
// ==============================================================

typedef struct LISTENER LISTENER;
typedef struct TCP_ACCEPTED_PARAM TCP_ACCEPTED_PARAM;
typedef struct UDP_ENTRY UDP_ENTRY;


// ==============================================================
//   Logging
// ==============================================================

typedef struct PACKET_LOG PACKET_LOG;
typedef struct HUB_LOG HUB_LOG;
typedef struct RECORD RECORD;
typedef struct LOG LOG;
typedef struct ERASER ERASER;
typedef struct SLOG SLOG;


// ==============================================================
//   Connection
// ==============================================================

typedef struct KEEP KEEP;
typedef struct SECURE_SIGN SECURE_SIGN;
typedef struct RC4_KEY_PAIR RC4_KEY_PAIR;
typedef struct CLIENT_OPTION CLIENT_OPTION;
typedef struct CLIENT_AUTH CLIENT_AUTH;
typedef struct TCPSOCK TCPSOCK;
typedef struct TCP TCP;
typedef struct UDP UDP;
typedef struct BLOCK BLOCK;
typedef struct CONNECTION CONNECTION;


// ==============================================================
//   Session
// ==============================================================

typedef struct NODE_INFO NODE_INFO;
typedef struct PACKET_ADAPTER PACKET_ADAPTER;
typedef struct SESSION SESSION;
typedef struct UI_PASSWORD_DLG UI_PASSWORD_DLG;
typedef struct UI_MSG_DLG UI_MSG_DLG;
typedef struct UI_NICINFO UI_NICINFO;
typedef struct UI_CONNECTERROR_DLG UI_CONNECTERROR_DLG;
typedef struct UI_CHECKCERT UI_CHECKCERT;


// ==============================================================
//   Hub
// ==============================================================

typedef struct SE_LINK SE_LINK;
typedef struct TEST_HISTORY TEST_HISTORY;
typedef struct SE_TEST SE_TEST;
typedef struct HUBDB HUBDB;
typedef struct TRAFFIC_LIMITER TRAFFIC_LIMITER;
typedef struct STORM STORM;
typedef struct HUB_PA HUB_PA;
typedef struct HUB_OPTION HUB_OPTION;
typedef struct MAC_TABLE_ENTRY MAC_TABLE_ENTRY;
typedef struct IP_TABLE_ENTRY IP_TABLE_ENTRY;
typedef struct LOOP_LIST LOOP_LIST;
typedef struct ACCESS ACCESS;
typedef struct TICKET TICKET;
typedef struct TRAFFIC_DIFF TRAFFIC_DIFF;
typedef struct HUB HUB;
typedef struct ADMIN_OPTION ADMIN_OPTION;
typedef struct CRL CRL;
typedef struct AC AC;


// ==============================================================
//   Protocol
// ==============================================================

typedef struct CHECK_CERT_THREAD_PROC CHECK_CERT_THREAD_PROC;
typedef struct SECURE_SIGN_THREAD_PROC SECURE_SIGN_THREAD_PROC;
typedef struct RAND_CACHE RAND_CACHE;
typedef struct HTTP_VALUE HTTP_VALUE;
typedef struct HTTP_HEADER HTTP_HEADER;
typedef struct SEND_SIGNATURE_PARAM SEND_SIGNATURE_PARAM;


// ==============================================================
//   Link
// ==============================================================

typedef struct LINK LINK;


// ==============================================================
//   Virtual
// ==============================================================

typedef struct ARP_ENTRY ARP_ENTRY;
typedef struct ARP_WAIT ARP_WAIT;
typedef struct IP_WAIT IP_WAIT;
typedef struct IP_PART IP_PART;
typedef struct IP_COMBINE IP_COMBINE;
typedef struct NAT_ENTRY NAT_ENTRY;
typedef struct TCP_OPTION TCP_OPTION;
typedef struct VH VH;
typedef struct VH_OPTION VH_OPTION;
typedef struct DHCP_OPTION DHCP_OPTION;
typedef struct DHCP_OPTION_LIST DHCP_OPTION_LIST;
typedef struct DHCP_LEASE DHCP_LEASE;


// ==============================================================
//   VLAN
// ==============================================================

typedef struct ROUTE_TRACKING ROUTE_TRACKING;
typedef struct VLAN VLAN;
typedef struct INSTANCE_LIST INSTANCE_LIST;
typedef struct VLAN_PARAM VLAN_PARAM;

#ifdef	OS_UNIX
typedef struct UNIX_VLAN_LIST UNIX_VLAN_LIST;
#endif	// OS_UNIX

// ==============================================================
//   Null LAN
// ==============================================================

typedef struct NULL_LAN NULL_LAN;


// ==============================================================
//   Bridge
// ==============================================================

typedef struct ETH ETH;
typedef struct BRIDGE BRIDGE;
typedef struct LOCALBRIDGE LOCALBRIDGE;


// ==============================================================
//   Layer-3 Switch
// ==============================================================

typedef struct L3IF L3IF;
typedef struct L3SW L3SW;
typedef struct L3TABLE L3TABLE;
typedef struct L3ARPENTRY L3ARPENTRY;
typedef struct L3ARPWAIT L3ARPWAIT;
typedef struct L3PACKET L3PACKET;


// ==============================================================
//   Client
// ==============================================================

typedef struct ACCOUNT ACCOUNT;
typedef struct CLIENT_CONFIG CLIENT_CONFIG;
typedef struct RPC_CLIENT_VERSION RPC_CLIENT_VERSION;
typedef struct RPC_CLIENT_PASSWORD RPC_CLIENT_PASSWORD;
typedef struct RPC_CLIENT_PASSWORD_SETTING RPC_CLIENT_PASSWORD_SETTING;
typedef struct RPC_CLIENT_ENUM_CA_ITEM RPC_CLIENT_ENUM_CA_ITEM;
typedef struct RPC_CLIENT_ENUM_CA RPC_CLIENT_ENUM_CA;
typedef struct RPC_CERT RPC_CERT;
typedef struct RPC_CLIENT_DELETE_CA RPC_CLIENT_DELETE_CA;
typedef struct RPC_GET_CA RPC_GET_CA;
typedef struct RPC_GET_ISSUER RPC_GET_ISSUER;
typedef struct RPC_CLIENT_ENUM_SECURE_ITEM RPC_CLIENT_ENUM_SECURE_ITEM;
typedef struct RPC_CLIENT_ENUM_SECURE RPC_CLIENT_ENUM_SECURE;
typedef struct RPC_USE_SECURE RPC_USE_SECURE;
typedef struct RPC_ENUM_OBJECT_IN_SECURE RPC_ENUM_OBJECT_IN_SECURE;
typedef struct RPC_CLIENT_CREATE_VLAN RPC_CLIENT_CREATE_VLAN;
typedef struct RPC_CLIENT_GET_VLAN RPC_CLIENT_GET_VLAN;
typedef struct RPC_CLIENT_SET_VLAN RPC_CLIENT_SET_VLAN;
typedef struct RPC_CLIENT_ENUM_VLAN_ITEM RPC_CLIENT_ENUM_VLAN_ITEM;
typedef struct RPC_CLIENT_ENUM_VLAN RPC_CLIENT_ENUM_VLAN;
typedef struct RPC_CLIENT_CREATE_ACCOUNT RPC_CLIENT_CREATE_ACCOUNT;
typedef struct RPC_CLIENT_ENUM_ACCOUNT_ITEM RPC_CLIENT_ENUM_ACCOUNT_ITEM;
typedef struct RPC_CLIENT_ENUM_ACCOUNT RPC_CLIENT_ENUM_ACCOUNT;
typedef struct RPC_CLIENT_DELETE_ACCOUNT RPC_CLIENT_DELETE_ACCOUNT;
typedef struct RPC_RENAME_ACCOUNT RPC_RENAME_ACCOUNT;
typedef struct RPC_CLIENT_GET_ACCOUNT RPC_CLIENT_GET_ACCOUNT;
typedef struct RPC_CLIENT_CONNECT RPC_CLIENT_CONNECT;
typedef struct RPC_CLIENT_GET_CONNECTION_STATUS RPC_CLIENT_GET_CONNECTION_STATUS;
typedef struct CLIENT_RPC_CONNECTION CLIENT_RPC_CONNECTION;
typedef struct CLIENT CLIENT;
typedef struct RPC_CLIENT_NOTIFY RPC_CLIENT_NOTIFY;
typedef struct REMOTE_CLIENT REMOTE_CLIENT;
typedef struct NOTIFY_CLIENT NOTIFY_CLIENT;
typedef struct UNIX_VLAN UNIX_VLAN;
typedef struct CM_SETTING CM_SETTING;


// ==============================================================
//   Server
// ==============================================================

typedef struct HUB_LIST HUB_LIST;
typedef struct FARM_TASK FARM_TASK;
typedef struct FARM_MEMBER FARM_MEMBER;
typedef struct FARM_CONTROLLER FARM_CONTROLLER;
typedef struct SERVER_LISTENER SERVER_LISTENER;
typedef struct SERVER SERVER;
typedef struct RPC_ENUM_SESSION RPC_ENUM_SESSION;
typedef struct RPC_SESSION_STATUS RPC_SESSION_STATUS;
typedef struct CAPS CAPS;
typedef struct CAPSLIST CAPSLIST;
typedef struct LOG_FILE LOG_FILE;
typedef struct SYSLOG_SETTING SYSLOG_SETTING;
typedef struct HUB_SNAPSHOT HUB_SNAPSHOT;
typedef struct SERVER_SNAPSHOT SERVER_SNAPSHOT;
typedef struct SERVER_HUB_CREATE_HISTORY SERVER_HUB_CREATE_HISTORY;

// ==============================================================
//   Server Admin Tool
// ==============================================================

typedef struct ADMIN ADMIN;
typedef struct RPC_TEST RPC_TEST;
typedef struct RPC_SERVER_INFO RPC_SERVER_INFO;
typedef struct RPC_SERVER_STATUS RPC_SERVER_STATUS;
typedef struct RPC_LISTENER RPC_LISTENER;
typedef struct RPC_LISTENER_LIST RPC_LISTENER_LIST;
typedef struct RPC_STR RPC_STR;
typedef struct RPC_SET_PASSWORD RPC_SET_PASSWORD;
typedef struct RPC_FARM RPC_FARM;
typedef struct RPC_FARM_HUB RPC_FARM_HUB;
typedef struct RPC_FARM_INFO RPC_FARM_INFO;
typedef struct RPC_ENUM_FARM_ITEM RPC_ENUM_FARM_ITEM;
typedef struct RPC_ENUM_FARM RPC_ENUM_FARM;
typedef struct RPC_FARM_CONNECTION_STATUS RPC_FARM_CONNECTION_STATUS;
typedef struct RPC_KEY_PAIR RPC_KEY_PAIR;
typedef struct RPC_HUB_OPTION RPC_HUB_OPTION;
typedef struct RPC_RADIUS RPC_RADIUS;
typedef struct RPC_HUB RPC_HUB;
typedef struct RPC_CREATE_HUB RPC_CREATE_HUB;
typedef struct RPC_ENUM_HUB_ITEM RPC_ENUM_HUB_ITEM;
typedef struct RPC_ENUM_HUB RPC_ENUM_HUB;
typedef struct RPC_DELETE_HUB RPC_DELETE_HUB;
typedef struct RPC_ENUM_CONNECTION_ITEM RPC_ENUM_CONNECTION_ITEM;
typedef struct RPC_ENUM_CONNECTION RPC_ENUM_CONNECTION;
typedef struct RPC_DISCONNECT_CONNECTION RPC_DISCONNECT_CONNECTION;
typedef struct RPC_CONNECTION_INFO RPC_CONNECTION_INFO;
typedef struct RPC_SET_HUB_ONLINE RPC_SET_HUB_ONLINE;
typedef struct RPC_HUB_STATUS RPC_HUB_STATUS;
typedef struct RPC_HUB_LOG RPC_HUB_LOG;
typedef struct RPC_HUB_ADD_CA RPC_HUB_ADD_CA;
typedef struct RPC_HUB_ENUM_CA_ITEM RPC_HUB_ENUM_CA_ITEM;
typedef struct RPC_HUB_ENUM_CA RPC_HUB_ENUM_CA;
typedef struct RPC_HUB_GET_CA RPC_HUB_GET_CA;
typedef struct RPC_HUB_DELETE_CA RPC_HUB_DELETE_CA;
typedef struct RPC_CREATE_LINK RPC_CREATE_LINK;
typedef struct RPC_ENUM_LINK_ITEM RPC_ENUM_LINK_ITEM;
typedef struct RPC_ENUM_LINK RPC_ENUM_LINK;
typedef struct RPC_LINK_STATUS RPC_LINK_STATUS;
typedef struct RPC_LINK RPC_LINK;
typedef struct RPC_ENUM_ACCESS_LIST RPC_ENUM_ACCESS_LIST;
typedef struct RPC_ADD_ACCESS RPC_ADD_ACCESS;
typedef struct RPC_DELETE_ACCESS RPC_DELETE_ACCESS;
typedef struct RPC_SET_USER RPC_SET_USER;
typedef struct RPC_ENUM_USER_ITEM RPC_ENUM_USER_ITEM;
typedef struct RPC_ENUM_USER RPC_ENUM_USER;
typedef struct RPC_SET_GROUP RPC_SET_GROUP;
typedef struct RPC_ENUM_GROUP_ITEM RPC_ENUM_GROUP_ITEM;
typedef struct RPC_ENUM_GROUP RPC_ENUM_GROUP;
typedef struct RPC_DELETE_USER RPC_DELETE_USER;
typedef struct RPC_ENUM_SESSION_ITEM RPC_ENUM_SESSION_ITEM;
typedef struct RPC_DELETE_SESSION RPC_DELETE_SESSION;
typedef struct RPC_ENUM_MAC_TABLE_ITEM RPC_ENUM_MAC_TABLE_ITEM;
typedef struct RPC_ENUM_MAC_TABLE RPC_ENUM_MAC_TABLE;
typedef struct RPC_ENUM_IP_TABLE_ITEM RPC_ENUM_IP_TABLE_ITEM;
typedef struct RPC_ENUM_IP_TABLE RPC_ENUM_IP_TABLE;
typedef struct RPC_DELETE_TABLE RPC_DELETE_TABLE;
typedef struct RPC_KEEP RPC_KEEP;
typedef struct RPC_ENUM_ETH_ITEM RPC_ENUM_ETH_ITEM;
typedef struct RPC_ENUM_ETH RPC_ENUM_ETH;
typedef struct RPC_LOCALBRIDGE RPC_LOCALBRIDGE;
typedef struct RPC_ENUM_LOCALBRIDGE RPC_ENUM_LOCALBRIDGE;
typedef struct RPC_BRIDGE_SUPPORT RPC_BRIDGE_SUPPORT;
typedef struct RPC_CONFIG RPC_CONFIG;
typedef struct RPC_ADMIN_OPTION RPC_ADMIN_OPTION;
typedef struct RPC_L3SW RPC_L3SW;
typedef struct RPC_L3IF RPC_L3IF;
typedef struct RPC_L3TABLE RPC_L3TABLE;
typedef struct RPC_ENUM_L3SW_ITEM RPC_ENUM_L3SW_ITEM;
typedef struct RPC_ENUM_L3SW RPC_ENUM_L3SW;
typedef struct RPC_ENUM_L3IF RPC_ENUM_L3IF;
typedef struct RPC_ENUM_L3TABLE RPC_ENUM_L3TABLE;
typedef struct RPC_CRL RPC_CRL;
typedef struct RPC_ENUM_CRL_ITEM RPC_ENUM_CRL_ITEM;
typedef struct RPC_ENUM_CRL RPC_ENUM_CRL;
typedef struct RPC_INT RPC_INT;
typedef struct RPC_AC_LIST RPC_AC_LIST;
typedef struct RPC_ENUM_LOG_FILE_ITEM RPC_ENUM_LOG_FILE_ITEM;
typedef struct RPC_ENUM_LOG_FILE RPC_ENUM_LOG_FILE;
typedef struct RPC_READ_LOG_FILE RPC_READ_LOG_FILE;
typedef struct DOWNLOAD_PROGRESS DOWNLOAD_PROGRESS;
typedef struct RPC_RENAME_LINK RPC_RENAME_LINK;
typedef struct RPC_ENUM_LICENSE_KEY RPC_ENUM_LICENSE_KEY;
typedef struct RPC_ENUM_LICENSE_KEY_ITEM RPC_ENUM_LICENSE_KEY_ITEM;
typedef struct RPC_LICENSE_STATUS RPC_LICENSE_STATUS;
typedef struct RPC_ENUM_ETH_VLAN_ITEM RPC_ENUM_ETH_VLAN_ITEM;
typedef struct RPC_ENUM_ETH_VLAN RPC_ENUM_ETH_VLAN;
typedef struct RPC_MSG RPC_MSG;
typedef struct RPC_WINVER RPC_WINVER;


// ==============================================================
//  NAT
// ==============================================================

typedef struct NAT NAT;
typedef struct NAT_ADMIN NAT_ADMIN;
typedef struct RPC_DUMMY RPC_DUMMY;
typedef struct RPC_NAT_STATUS RPC_NAT_STATUS;
typedef struct RPC_NAT_INFO RPC_NAT_INFO;
typedef struct RPC_ENUM_NAT_ITEM RPC_ENUM_NAT_ITEM;
typedef struct RPC_ENUM_NAT RPC_ENUM_NAT;
typedef struct RPC_ENUM_DHCP_ITEM RPC_ENUM_DHCP_ITEM;
typedef struct RPC_ENUM_DHCP RPC_ENUM_DHCP;


// ==============================================================
//  SecureNAT
// ==============================================================

typedef struct SNAT SNAT;


// ==============================================================
//  TcpIp
// ==============================================================

typedef struct MAC_HEADER MAC_HEADER;
typedef struct ARPV4_HEADER ARPV4_HEADER;
typedef struct IPV4_HEADER IPV4_HEADER;
typedef struct TAGVLAN_HEADER TAGVLAN_HEADER;
typedef struct UDP_HEADER UDP_HEADER;
typedef struct UDPV4_PSEUDO_HEADER UDPV4_PSEUDO_HEADER;
typedef struct TCPV4_PSEUDO_HEADER TCPV4_PSEUDO_HEADER;
typedef struct TCP_HEADER TCP_HEADER;
typedef struct ICMP_HEADER ICMP_HEADER;
typedef struct ICMP_ECHO ICMP_ECHO;
typedef struct DHCPV4_HEADER DHCPV4_HEADER;
typedef struct DNSV4_HEADER DNSV4_HEADER;
typedef struct BPDU_HEADER BPDU_HEADER;
typedef struct LLC_HEADER LLC_HEADER;
typedef struct PKT PKT;
typedef struct IPV6_HEADER_PACKET_INFO IPV6_HEADER_PACKET_INFO;
typedef struct IPV6_HEADER IPV6_HEADER;
typedef struct IPV6_OPTION_HEADER IPV6_OPTION_HEADER;
typedef struct IPV6_FRAGMENT_HEADER IPV6_FRAGMENT_HEADER;
typedef struct IPV6_PSEUDO_HEADER IPV6_PSEUDO_HEADER;
typedef struct ICMPV6_ROUTER_SOLICIATION_HEADER ICMPV6_ROUTER_SOLICIATION_HEADER;
typedef struct ICMPV6_ROUTER_ADVERTISEMENT_HEADER ICMPV6_ROUTER_ADVERTISEMENT_HEADER;
typedef struct ICMPV6_NEIGHBOR_SOLICIATION_HEADER ICMPV6_NEIGHBOR_SOLICIATION_HEADER;
typedef struct ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER;
typedef struct ICMPV6_OPTION_LIST ICMPV6_OPTION_LIST;
typedef struct ICMPV6_OPTION ICMPV6_OPTION;
typedef struct ICMPV6_OPTION_LINK_LAYER ICMPV6_OPTION_LINK_LAYER;
typedef struct ICMPV6_OPTION_PREFIX ICMPV6_OPTION_PREFIX;
typedef struct ICMPV6_OPTION_MTU ICMPV6_OPTION_MTU;
typedef struct IPV6_HEADER_INFO IPV6_HEADER_INFO;
typedef struct ICMPV6_HEADER_INFO ICMPV6_HEADER_INFO;


// ==============================================================
//  Console
// ==============================================================

typedef struct PARAM PARAM;
typedef struct PARAM_VALUE PARAM_VALUE;
typedef struct CONSOLE CONSOLE;
typedef struct LOCAL_CONSOLE_PARAM LOCAL_CONSOLE_PARAM;
typedef struct CMD CMD;
typedef struct CMD_EVAL_MIN_MAX CMD_EVAL_MIN_MAX;


// ==============================================================
//  Command
// ==============================================================

typedef struct PS PS;
typedef struct PC PC;
typedef struct CT CT;
typedef struct CTC CTC;
typedef struct CTR CTR;
typedef struct TTC TTC;
typedef struct TTS TTS;
typedef struct TT_RESULT TT_RESULT;
typedef struct TTS_SOCK TTS_SOCK;
typedef struct TTC_SOCK TTC_SOCK;
typedef struct PT PT;

// ==============================================================
//  EtherLogger
// ==============================================================

typedef struct EL EL;
typedef struct EL_DEVICE EL_DEVICE;
typedef struct EL_LICENSE_STATUS EL_LICENSE_STATUS;
typedef struct RPC_ADD_DEVICE RPC_ADD_DEVICE;
typedef struct RPC_DELETE_DEVICE RPC_DELETE_DEVICE;
typedef struct RPC_ENUM_DEVICE_ITEM RPC_ENUM_DEVICE_ITEM;
typedef struct RPC_ENUM_DEVICE RPC_ENUM_DEVICE;
typedef struct RPC_EL_LICENSE_STATUS RPC_EL_LICENSE_STATUS;


// ==============================================================
//  Database
// ==============================================================

typedef struct LICENSE_SYSTEM LICENSE_SYSTEM;
typedef struct LICENSE_DATA LICENSE_DATA;
typedef struct LICENSE LICENSE;
typedef struct LICENSE_STATUS LICENSE_STATUS;




#endif	// CEDARTYPE_H
