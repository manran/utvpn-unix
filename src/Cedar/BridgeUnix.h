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

// BridgeUnix.h
// BridgeUnix.c のヘッダ

#ifndef	BRIDGEUNIX_H
#define	BRIDGEUNIX_H

// マクロ
#ifndef SOL_PACKET
#define	SOL_PACKET	263
#endif
#ifndef ifr_newname
#define ifr_newname     ifr_ifru.ifru_slave
#endif

// 定数
#define	UNIX_ETH_TMP_BUFFER_SIZE		(2000)
#define	SOLARIS_MAXDLBUF				(32768)
#define BRIDGE_MAX_QUEUE_SIZE			(4096*1500)

// ETH 構造体
struct ETH
{
	char *Name;					// アダプタ名
	char *Title;				// アダプタタイトル
	CANCEL *Cancel;				// キャンセルオブジェクト
	int IfIndex;				// インデックス
	int Socket;					// ソケット
	UINT InitialMtu;			// 初期の MTU 値
	UINT CurrentMtu;			// 現在の MTU 値
	int SocketBsdIf;			// BSD インターフェイス操作用ソケット

#ifdef BRIDGE_PCAP
	void *Pcap;					// Pcap 記述子
	QUEUE *Queue;				// 中継スレッド用のキュー
	UINT QueueSize;				// Queue 中のバイト数
	THREAD *CaptureThread;			// Pcap 中継用スレッド
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
	UINT BufSize;				// BPF を read するときのバッファサイズ（これ以外だとエラー）
#ifdef BRIDGE_BPF_THREAD
	QUEUE *Queue;				// 中継スレッド用のキュー
	UINT QueueSize;				// Queue 中のバイト数
	THREAD *CaptureThread;			// BPF 中継用スレッド
#else // BRIDGE_BPF_THREAD
	UCHAR *Buffer;				// BPF を read するときのバッファ
	UCHAR *Next;
	int Rest;
#endif // BRIDGE_BPF_THREAD
#endif // BRIDGE_BPF

	VLAN *Tap;					// tap
};

#if defined( BRIDGE_BPF ) || defined( BRIDGE_PCAP )
struct CAPTUREBLOCK{
	UINT Size;
	UCHAR *Buf;
};
#endif // BRIDGE_BPF


// 関数プロトタイプ
void InitEth();
void FreeEth();
bool IsEthSupported();
bool IsEthSupportedLinux();
bool IsEthSupportedSolaris();
bool IsEthSupportedPcap();
TOKEN_LIST *GetEthList();
TOKEN_LIST *GetEthListLinux();
TOKEN_LIST *GetEthListSolaris();
TOKEN_LIST *GetEthListPcap();
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthLinux(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthSolaris(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthPcap(char *name, bool local, bool tapmode, char *tapaddr);
bool ParseUnixEthDeviceName(char *dst_devname, UINT dst_devname_size, UINT *dst_devid, char *src_name);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
UINT EthGetPacketLinux(ETH *e, void **data);
UINT EthGetPacketSolaris(ETH *e, void **data);
UINT EthGetPacketPcap(ETH *e, void **data);
UINT EthGetPacketBpf(ETH *e, void **data);
void EthPutPacket(ETH *e, void *data, UINT size);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
UINT EthGetMtu(ETH *e);
bool EthSetMtu(ETH *e, UINT mtu);
bool EthIsChangeMtuSupported(ETH *e);
bool EthGetInterfaceDescriptionUnix(char *name, char *str, UINT size);
bool EthIsInterfaceDescriptionSupportedUnix();

#ifdef	UNIX_SOLARIS
// Solaris 用関数プロトタイプ
bool DlipAttatchRequest(int fd, UINT devid);
bool DlipReceiveAck(int fd);
bool DlipPromiscuous(int fd, UINT level);
bool DlipBindRequest(int fd);
#endif	// OS_SOLARIS

int UnixEthOpenRawSocket();

#endif	// BRIDGEUNIX_H


