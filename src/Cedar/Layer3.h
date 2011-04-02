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

// Layer3.h
// Layer3.c のヘッダ

#ifndef	LAYER3_H
#define	LAYER3_H

// 定数
#define	L3_USERNAME					"L3SW_"


// L3 ARP テーブルエントリ
struct L3ARPENTRY
{
	UINT IpAddress;					// IP アドレス
	UCHAR MacAddress[6];			// MAC アドレス
	UCHAR Padding[2];
	UINT64 Expire;					// 有効期限
};

// L3 ARP 解決待ちリストエントリ
struct L3ARPWAIT
{
	UINT IpAddress;					// IP アドレス
	UINT64 LastSentTime;			// 最後に ARP を送信した時刻
	UINT64 Expire;					// 有効期限
};

// L3 IP パケットテーブル
struct L3PACKET
{
	PKT *Packet;					// パケットデータ本体
	UINT64 Expire;					// 有効期限
	UINT NextHopIp;					// ローカル配信宛先 IP アドレス
};

// L3 ルーティングテーブル定義
struct L3TABLE
{
	UINT NetworkAddress;			// ネットワークアドレス
	UINT SubnetMask;				// サブネットマスク
	UINT GatewayAddress;			// ゲートウェイアドレス
	UINT Metric;					// メトリック
};

// L3 インターフェイス定義
struct L3IF
{
	L3SW *Switch;					// Layer-3 スイッチ
	char HubName[MAX_HUBNAME_LEN + 1];	// 仮想 HUB 名
	UINT IpAddress;					// IP アドレス
	UINT SubnetMask;				// サブネットマスク

	HUB *Hub;						// 仮想 HUB
	SESSION *Session;				// セッション
	LIST *ArpTable;					// ARP テーブル
	LIST *ArpWaitTable;				// ARP 待機テーブル
	QUEUE *IpPacketQueue;			// IP パケットキュー (他のインターフェイスからの受信用)
	LIST *IpWaitList;				// IP 待機リスト
	QUEUE *SendQueue;				// 送信キュー
	UCHAR MacAddress[6];			// MAC アドレス
	UCHAR Padding[2];
	UINT64 LastDeleteOldArpTable;	// 古い ARP テーブルを清掃した時刻
	LIST *CancelList;				// キャンセルリスト
	UINT64 LastBeaconSent;			// 最後にビーコンを送信した時刻
};

// L3 スイッチ定義
struct L3SW
{
	char Name[MAX_HUBNAME_LEN + 1];	// 名前
	LOCK *lock;						// ロック
	REF *ref;						// 参照カウンタ
	CEDAR *Cedar;					// Cedar
	bool Active;					// 動作中フラグ
	bool Online;					// オンラインフラグ
	volatile bool Halt;				// 停止フラグ
	LIST *IfList;					// インターフェイスリスト
	LIST *TableList;				// ルーティングテーブルリスト
	THREAD *Thread;					// スレッド
};



// 関数プロトタイプ
int CmpL3Sw(void *p1, void *p2);
int CmpL3ArpEntry(void *p1, void *p2);
int CmpL3ArpWaitTable(void *p1, void *p2);
int CmpL3Table(void *p1, void *p2);
int CmpL3If(void *p1, void *p2);
void InitCedarLayer3(CEDAR *c);
void FreeCedarLayer3(CEDAR *c);
L3SW *NewL3Sw(CEDAR *c, char *name);
void ReleaseL3Sw(L3SW *s);
void CleanupL3Sw(L3SW *s);
bool L3AddIf(L3SW *s, char *hubname, UINT ip, UINT subnet);
bool L3DelIf(L3SW *s, char *hubname);
bool L3AddTable(L3SW *s, L3TABLE *tbl);
bool L3DelTable(L3SW *s, L3TABLE *tbl);
L3IF *L3SearchIf(L3SW *s, char *hubname);
L3SW *L3GetSw(CEDAR *c, char *name);
L3SW *L3AddSw(CEDAR *c, char *name);
bool L3DelSw(CEDAR *c, char *name);
void L3FreeAllSw(CEDAR *c);
void L3SwStart(L3SW *s);
void L3SwStop(L3SW *s);
void L3SwThread(THREAD *t, void *param);
void L3Test(SERVER *s);
void L3InitAllInterfaces(L3SW *s);
void L3FreeAllInterfaces(L3SW *s);
void L3IfThread(THREAD *t, void *param);
void L3InitInterface(L3IF *f);
void L3FreeInterface(L3IF *f);
L3IF *L3GetNextIf(L3SW *s, UINT ip, UINT *next_hop);
L3TABLE *L3GetBestRoute(L3SW *s, UINT ip);
UINT L3GetNextPacket(L3IF *f, void **data);
void L3Polling(L3IF *f);
void L3PollingBeacon(L3IF *f);
void L3DeleteOldArpTable(L3IF *f);
void L3DeleteOldIpWaitList(L3IF *f);
void L3PollingArpWaitTable(L3IF *f);
void L3SendL2Now(L3IF *f, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size);
void L3SendArpRequestNow(L3IF *f, UINT dest_ip);
void L3SendArpResponseNow(L3IF *f, UCHAR *dest_mac, UINT dest_ip, UINT src_ip);
void L3GenerateMacAddress(L3IF *f);
L3ARPENTRY *L3SearchArpTable(L3IF *f, UINT ip);
void L3SendIpNow(L3IF *f, L3ARPENTRY *a, L3PACKET *p);
void L3SendIp(L3IF *f, L3PACKET *p);
void L3RecvArp(L3IF *f, PKT *p);
void L3RecvArpRequest(L3IF *f, PKT *p);
void L3RecvArpResponse(L3IF *f, PKT *p);
void L3KnownArp(L3IF *f, UINT ip, UCHAR *mac);
void L3SendArp(L3IF *f, UINT ip);
void L3InsertArpTable(L3IF *f, UINT ip, UCHAR *mac);
void L3SendWaitingIp(L3IF *f, UCHAR *mac, UINT ip, L3ARPENTRY *a);
void L3PutPacket(L3IF *f, void *data, UINT size); 
void L3RecvL2(L3IF *f, PKT *p);
void L3StoreIpPacketToIf(L3IF *src_if, L3IF *dst_if, L3PACKET *p);
void L3RecvIp(L3IF *f, PKT *p, bool self);
void L3PollingIpQueue(L3IF *f);


#endif	// LAYER3_H



