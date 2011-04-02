// SoftEther UT-VPN SourceCode
// 
// Copyright (C) 2004-2010 SoftEther Corporation.
// Copyright (C) 2004-2010 University of Tsukuba.
// Copyright (C) 2003-2010 Daiyuu Nobori.
// All Rights Reserved.
// 
// http://utvpn.tsukuba.ac.jp/
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// このファイルは GPL バージョン 2 ライセンスで公開されています。
// 誰でもこのファイルの内容を複製、改変したり、改変したバージョンを再配布
// することができます。ただし、原著作物を改変した場合は、原著作物の著作権表示
// を除去することはできません。改変した著作物を配布する場合は、改変実施者の
// 著作権表示を原著作物の著作権表示に付随して記載するようにしてください。
// 
// この SoftEther UT-VPN オープンソース・プロジェクトは、
// ソフトイーサ株式会社 (SoftEther Corporation, http://www.softether.co.jp/ )
// および筑波大学 (University of Tsukuba, http://www.tsukuba.ac.jp/ ) によって
// ホストされています。
// SoftEther UT-VPN プロジェクトの Web サイトは http://utvpn.tsukuba.ac.jp/ に
// あります。
// 本ソフトウェアの不具合の修正、機能改良、セキュリティホールの修復などのコード
// の改変を行った場合で、その成果物を SoftEther UT-VPN プロジェクトに提出して
// いただける場合は、 http://utvpn.tsukuba.ac.jp/ までソースコードを送付して
// ください。SoftEther UT-VPN プロジェクトの本体リリースまたはブランチリリース
// に組み込みさせていただきます。
// 
// 本ソフトウェアを本オープンソース・プロジェクトの運営主体以外が改変した場合、
// それを複製、配布、販売することは GPL ライセンスに基づいて可能ですが、
// その場合、"SoftEther UT-VPN" の名前を勝手に騙り使用することはできません。
// 事前にソフトイーサ株式会社に許諾を求めるか、または、別の名称として
// ソフトウェアを配布、販売してください。
// 
// GPL に基づいて原著作物が提供される本ソフトウェアの改良版を配布、販売する
// 場合は、そのソースコードを GPL に基づいて誰にでも開示する義務が生じます。
// 
// 本ソフトウェアに関連する著作権、特許権、商標権はソフトイーサ株式会社
// (SoftEther Corporation) およびその他の著作権保持者が保有しています。
// ソフトイーサ株式会社はこれらの権利を放棄していません。本ソフトウェアの
// 二次著作物を配布、販売する場合は、これらの権利を侵害しないようにご注意
// ください。
// 
// 不明な点は、ソフトイーサ株式会社までご連絡ください。
// 連絡先: http://www.softether.co.jp/jp/contact/

// -----------------------------------------------
// [ChangeLog]
// 2010.05.20
//  新規リリース by SoftEther
// -----------------------------------------------

/*
**   File Name: Sen.h
** Description: Sen.c のヘッダ
*/

#ifndef	SEN_H
#define	SEN_H


// 識別文字列 (NDIS)
#define	NDIS_SEN_HARDWARE_ID				"VPN Client Adapter - %s"
#define	NDIS_SEN_DEVICE_NAME				"\\Device\\SEN_%s_DEVICE"
#define	NDIS_SEN_DEVICE_NAME_WIN32			"\\DosDevices\\SEN_%s_DEVICE"
#define	NDIS_SEN_DEVICE_FILE_NAME			"\\\\.\\SEN_SENADAPTER_%s_DEVICE"
#define	NDIS_SEN_EVENT_NAME					"\\BaseNamedObjects\\SEN_EVENT_%s"
#define	NDIS_SEN_EVENT_NAME_WIN32			"Global\\SEN_EVENT_SENADAPTER_%s"

// 定数
#define	SEN_MAX_PACKET_SIZE			1560
#define	SEN_MAX_PACKET_SIZE_ANNOUNCE	1514
#define	SEN_MIN_PACKET_SIZE			14
#define	SEN_PACKET_HEADER_SIZE		14
#define	SEN_MAX_FRAME_SIZE			(SEN_MAX_PACKET_SIZE - SEN_MIN_PACKET_SIZE)
#define	SEN_MAX_SPEED_DEFAULT		1000000
#define	SEN_MAC_ADDRESS_SIZE		6
#define	SEN_MAX_MULTICASE			32


// IOCTL 定数
#define	SEN_IOCTL_SET_EVENT			CTL_CODE(0x8000, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	SEN_IOCTL_PUT_PACKET		CTL_CODE(0x8000, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	SEN_IOCTL_GET_PACKET		CTL_CODE(0x8000, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)


// パケットデータ交換関係
#define	SEN_MAX_PACKET_EXCHANGE		256			// 一度に交換できるパケット数
#define	SEN_MAX_PACKET_QUEUED		4096		// キューに入れることができるパケット数
#define	SEN_EX_SIZEOF_NUM_PACKET	4			// パケット数データ (UINT)
#define	SEN_EX_SIZEOF_LENGTH_PACKET	4			// パケットデータの長さデータ (UINT)
#define	SEN_EX_SIZEOF_LEFT_FLAG		4			// まだパケットが残っていることを示すフラグ
#define	SEN_EX_SIZEOF_ONE_PACKET	1600		// 1 つのパケットデータが占有するデータ領域
#define	SEN_EXCHANGE_BUFFER_SIZE	(SEN_EX_SIZEOF_NUM_PACKET + SEN_EX_SIZEOF_LEFT_FLAG +	\
	(SEN_EX_SIZEOF_LENGTH_PACKET + SEN_EX_SIZEOF_ONE_PACKET) * (SEN_MAX_PACKET_EXCHANGE + 1))
#define	SEN_NUM_PACKET(buf)			(*((UINT *)((UCHAR *)buf + 0)))
#define	SEN_SIZE_OF_PACKET(buf, i)	(*((UINT *)((UCHAR *)buf + SEN_EX_SIZEOF_NUM_PACKET + \
									(i * (SEN_EX_SIZEOF_LENGTH_PACKET + SEN_EX_SIZEOF_ONE_PACKET)))))
#define	SEN_ADDR_OF_PACKET(buf, i)	(((UINT *)((UCHAR *)buf + SEN_EX_SIZEOF_NUM_PACKET + \
									SEN_EX_SIZEOF_LENGTH_PACKET +	\
									(i * (SEN_EX_SIZEOF_LENGTH_PACKET + SEN_EX_SIZEOF_ONE_PACKET)))))
#define	SEN_LEFT_FLAG(buf)			SEN_SIZE_OF_PACKET(buf, SEN_MAX_PACKET_EXCHANGE)



// デバイスドライバとしてコンパイルする際に必要な定義
#ifdef	SEN_DEVICE_DRIVER

// OS 判定
#ifdef	WIN32
#define	OS_WIN32	// Microsoft Windows
#else
#define	OS_UNIX		// UNIX / Linux
#endif


// 型宣言
#ifndef	WINDOWS_H_INCLUDED
#ifndef	WIN9X
typedef	unsigned long		BOOL;
#endif	// WIN9X
#define	TRUE				1
#define	FALSE				0
#endif
typedef	unsigned long		bool;
#define	true				1
#define	false				0
typedef	unsigned long long	UINT64;
typedef	signed long long	INT64;
typedef	unsigned short		WORD;
typedef	unsigned short		USHORT;
typedef	signed short		SHORT;
typedef	unsigned char		BYTE;
typedef	unsigned char		UCHAR;
typedef signed char			CHAR;
typedef	unsigned long		DWORD;
#define	INFINITE			0xFFFFFFFF

#define	LESS(a, max_value)	((a) < (max_value) ? (a) : (max_value))
#define	MORE(a, min_value)	((a) > (min_value) ? (a) : (min_value))
#define	INNER(a, b, c)		(((b) <= (c) && (a) >= (b) && (a) <= (c)) || ((b) >= (c) && (a) >= (c) && (a) <= (b)))
#define	OUTER(a, b, c)		(!INNER((a), (b), (c)))
#define	MAKESURE(a, b, c)		(((b) <= (c)) ? (MORE(LESS((a), (c)), (b))) : (MORE(LESS((a), (b)), (c))))
#define	MIN(a, b)			((a) >= (b) ? (b) : (a))
#define	MAX(a, b)			((a) >= (b) ? (a) : (b))

#ifdef	OS_WIN32
// NDIS 5.0 関係
#include "NDIS5.h"
#endif	// OS_WIN32

// ロック
typedef struct _SEN_LOCK
{
#ifdef	OS_WIN32
	NDIS_SPIN_LOCK spin_lock;
#endif
} SEN_LOCK;

// イベント
typedef struct _SEN_EVENT
{
#ifdef	OS_WIN32
#ifndef	WIN9X
	KEVENT *event;
	HANDLE event_handle;
#else	// WIN9X
	DWORD win32_event;
#endif	// WIN9X
#endif
} SEN_EVENT;

// パケットキュー
typedef struct _SEN_QUEUE
{
	struct _SEN_QUEUE *Next;
	UINT Size;
	void *Buf;
} SEN_QUEUE;

// ステータス
typedef struct _SEN_STATUS
{
	UINT NumPacketSend;
	UINT NumPacketRecv;
	UINT NumPacketSendError;
	UINT NumPacketRecvError;
	UINT NumPacketRecvNoBuffer;
} SEN_STATUS;

// NDIS パケットバッファ
typedef struct _PACKET_BUFFER
{
	void *Buf;							// バッファ
	NDIS_PACKET *NdisPacket;			// NDIS パケット
	NDIS_BUFFER *NdisBuffer;			// NDIS パケットバッファ
	NDIS_HANDLE PacketPool;				// パケットプール
	NDIS_HANDLE BufferPool;				// バッファプール
} PACKET_BUFFER;

// コンテキスト
typedef struct _SEN_CTX
{
	SEN_EVENT *Event;					// パケット受信通知イベント
	BOOL Opened;						// Open されているか否かのフラグ
	BOOL Inited;						// 初期化フラグ
	BOOL Initing;						// 起動中フラグ
	volatile BOOL Halting;				// 停止中フラグ
	BYTE MacAddress[6];					// MAC アドレス
	BYTE padding[2];					// padding
	SEN_QUEUE *PacketQueue;				// 送信パケットキュー
	SEN_QUEUE *Tail;					// 送信パケットキューの末尾
	UINT NumPacketQueue;				// パケットキュー数
	SEN_LOCK *PacketQueueLock;			// 送信パケットキュー用ロック
	SEN_STATUS Status;					// ステータス
	BOOL Connected, ConnectedOld;		// ケーブル接続状態
	BOOL ConnectedForce;				// 接続状態強制通知
#ifdef	OS_WIN32
	NDIS_HANDLE NdisWrapper;			// NDIS ラッパーハンドル
	NDIS_HANDLE NdisControl;			// NDIS コントロールハンドル
	NDIS_HANDLE NdisMiniport;			// NDIS ミニポートハンドル
	NDIS_HANDLE NdisContext;			// NDIS コンテキストハンドル
	NDIS_HANDLE NdisConfig;				// NDIS Config ハンドル
	DEVICE_OBJECT *NdisControlDevice;	// NDIS コントロールデバイス
	PDRIVER_DISPATCH DispatchTable[IRP_MJ_MAXIMUM_FUNCTION];
	PACKET_BUFFER *PacketBuffer[SEN_MAX_PACKET_EXCHANGE];		// NDIS パケットバッファ
	NDIS_PACKET *PacketBufferArray[SEN_MAX_PACKET_EXCHANGE];	// NDIS パケットバッファ配列
	NDIS_HARDWARE_STATUS HardwareStatus;	// ハードウェア状態
	char HardwareID[MAX_SIZE];			// ハードウェア ID
	char HardwareID_Raw[MAX_SIZE];		// 元のハードウェア ID
	char HardwarePrintableID[MAX_SIZE];	// ハードウェア ID (表示用)
#endif
} SEN_CTX;

extern SEN_CTX *ctx;


// Sen.c ルーチン
void SenNewStatus(SEN_STATUS *s);
void SenFreeStatus(SEN_STATUS *s);
BOOL SenInit();
void SenShutdown();
void SenInitPacketQueue();
void SenFreePacketQueue();
void SenClearPacketQueue();
void SenLockPacketQueue();
void SenUnlockPacketQueue();
SEN_QUEUE *SenGetNextQueue();
void SenFreeQueue(SEN_QUEUE *q);
void SenInsertQueue(void *buf, UINT size);
UINT SenGetNumQueue();
void SenStartAdapter();
void SenStopAdapter();
void SenRead(void *buf);
void SenWrite(void *buf);

// 共通ルーチン (プラットフォーム依存)
void *SenMalloc(UINT size);
void *SenZeroMalloc(UINT size);
void SenFree(void *p);
void SenCopy(void *dst, void *src, UINT size);
void SenZero(void *dst, UINT size);
SEN_LOCK *SenNewLock();
void SenLock(SEN_LOCK *lock);
void SenUnlock(SEN_LOCK *lock);
void SenFreeLock(SEN_LOCK *lock);
SEN_EVENT *SenNewEvent(char *name);
SEN_EVENT *SenCreateWin9xEvent(DWORD h);
void SenFreeEvent(SEN_EVENT *event);
void SenSet(SEN_EVENT *event);
void SenReset(SEN_EVENT *event);
BOOL SenIsKernelAddress(void *addr);

#endif	// SEN_DEVICE_DRIVER


#endif	// SEN_H



