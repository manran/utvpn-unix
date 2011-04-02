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

// BridgeWin32.h
// BridgeWin32.c のヘッダ

#ifndef	BRIDGEWIN32_H
#define	BRIDGEWIN32_H

#define	BRIDGE_WIN32_PACKET_DLL		"Packet.dll"
#define	BRIDGE_WIN32_PCD_DLL		"|sep.dll"
#define	BRIDGE_WIN32_PCD_SYS		"|sep.sys"
#define	BRIDGE_WIN32_PCD_DLL_X64	"|sep_x64.dll"
#define	BRIDGE_WIN32_PCD_SYS_X64	"|sep_x64.sys"
#define	BRIDGE_WIN32_PCD_DLL_IA64	"|sep_ia64.dll"
#define	BRIDGE_WIN32_PCD_SYS_IA64	"|sep_ia64.sys"
#define	BRIDGE_WIN32_PCD_REGKEY		"SYSTEM\\CurrentControlSet\\services\\SEP"
#define	BRIDGE_WIN32_PCD_BUILDVALUE	"CurrentInstalledBuild"

#define	BRIDGE_WIN32_ETH_BUFFER		(1048576)


typedef void *HANDLE;

#ifdef	BRIDGE_C

// 内部向け関数ヘッダ (BridgeWin32.c 用)
typedef struct WP
{
	bool Inited;
	HINSTANCE hPacketDll;
	PCHAR (*PacketGetVersion)();
	PCHAR (*PacketGetDriverVersion)();
	BOOLEAN (*PacketSetMinToCopy)(LPADAPTER AdapterObject,int nbytes);
	BOOLEAN (*PacketSetNumWrites)(LPADAPTER AdapterObject,int nwrites);
	BOOLEAN (*PacketSetMode)(LPADAPTER AdapterObject,int mode);
	BOOLEAN (*PacketSetReadTimeout)(LPADAPTER AdapterObject,int timeout);
	BOOLEAN (*PacketSetBpf)(LPADAPTER AdapterObject,struct bpf_program *fp);
	INT (*PacketSetSnapLen)(LPADAPTER AdapterObject,int snaplen);
	BOOLEAN (*PacketGetStats)(LPADAPTER AdapterObject,struct bpf_stat *s);
	BOOLEAN (*PacketGetStatsEx)(LPADAPTER AdapterObject,struct bpf_stat *s);
	BOOLEAN (*PacketSetBuff)(LPADAPTER AdapterObject,int dim);
	BOOLEAN (*PacketGetNetType)(LPADAPTER AdapterObject,NetType *type);
	LPADAPTER (*PacketOpenAdapter)(PCHAR AdapterName);
	BOOLEAN (*PacketSendPacket)(LPADAPTER AdapterObject,LPPACKET pPacket,BOOLEAN Sync);
	INT (*PacketSendPackets)(LPADAPTER AdapterObject,PVOID PacketBuff,ULONG Size, BOOLEAN Sync);
	LPPACKET (*PacketAllocatePacket)(void);
	VOID (*PacketInitPacket)(LPPACKET lpPacket,PVOID  Buffer,UINT  Length);
	VOID (*PacketFreePacket)(LPPACKET lpPacket);
	BOOLEAN (*PacketReceivePacket)(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync);
	BOOLEAN (*PacketSetHwFilter)(LPADAPTER AdapterObject,ULONG Filter);
	BOOLEAN (*PacketGetAdapterNames)(PTSTR pStr,PULONG  BufferSize);
	BOOLEAN (*PacketGetNetInfoEx)(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries);
	BOOLEAN (*PacketRequest)(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA  OidData);
	HANDLE (*PacketGetReadEvent)(LPADAPTER AdapterObject);
	BOOLEAN (*PacketSetDumpName)(LPADAPTER AdapterObject, void *name, int len);
	BOOLEAN (*PacketSetDumpLimits)(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks);
	BOOLEAN (*PacketIsDumpEnded)(LPADAPTER AdapterObject, BOOLEAN sync);
	BOOL (*PacketStopDriver)();
	VOID (*PacketCloseAdapter)(LPADAPTER lpAdapter);
	BOOLEAN (*PacketSetLoopbackBehavior)(LPADAPTER AdapterObject, UINT LoopbackBehavior);
} WP;

// アダプタリスト
typedef struct WP_ADAPTER
{
	char Name[MAX_SIZE];
	char Title[MAX_SIZE];
	char Guid[MAX_SIZE];
} WP_ADAPTER;

// 内部向け関数プロトタイプ
void InitEthAdaptersList();
void FreeEthAdaptersList();
int CompareWpAdapter(void *p1, void *p2);
LIST *GetEthAdapterList();
LIST *GetEthAdapterListInternal();
bool InitWpWithLoadLibrary(WP *wp, HINSTANCE h);
bool IsPcdSupported();
HINSTANCE InstallPcdDriver();
HINSTANCE InstallPcdDriverInternal();
UINT LoadPcdDriverBuild();
void SavePcdDriverBuild(UINT build);

#endif	// BRIDGE_C

typedef struct _ADAPTER ADAPTER;
typedef struct _PACKET PACKET;

// ETH 構造体
struct ETH
{
	char *Name;					// アダプタ名
	char *Title;				// アダプタタイトル
	ADAPTER *Adapter;			// アダプタ
	CANCEL *Cancel;				// キャンセルオブジェクト
	UCHAR *Buffer;				// バッファ
	UINT BufferSize;			// バッファサイズ
	PACKET *Packet;				// パケット
	PACKET *PutPacket;			// 書き込みパケット
	QUEUE *PacketQueue;			// パケットキュー
	UINT64 LastSetSingleCpu;	// 最後にシングル CPU に設定した日時
	bool LoopbackBlock;			// ループバックパケットを遮断するかどうか
	bool Empty;					// 空である
};

// 関数プロトタイプ
void InitEth();
void FreeEth();
bool IsEthSupported();
TOKEN_LIST *GetEthList();
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthInternal(char *name, bool local, bool tapmode, char *tapaddr);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
void EthPutPacket(ETH *e, void *data, UINT size);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
void GetEthNetworkConnectionName(wchar_t *dst, UINT size, char *device_name);
bool IsWin32BridgeWithSep();
UINT EthGetMtu(ETH *e);
bool EthSetMtu(ETH *e, UINT mtu);
bool EthIsChangeMtuSupported(ETH *e);

bool EnumEthVLanWin32(RPC_ENUM_ETH_VLAN *t);
bool GetClassRegKeyWin32(char *key, UINT key_size, char *short_key, UINT short_key_size, char *guid);
int CmpRpcEnumEthVLan(void *p1, void *p2);
void GetVLanSupportStatus(RPC_ENUM_ETH_VLAN_ITEM *e);
void GetVLanEnableStatus(RPC_ENUM_ETH_VLAN_ITEM *e);
bool SetVLanEnableStatus(char *title, bool enable);
RPC_ENUM_ETH_VLAN_ITEM *FindEthVLanItem(RPC_ENUM_ETH_VLAN *t, char *name);
char *SearchDeviceInstanceIdFromShortKey(char *short_key);

#endif	// BRIDGEWIN32_H


