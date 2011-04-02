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

// Remote.c
// リモートプロシージャーコール

#include "CedarPch.h"

// RPC の終了
void EndRpc(RPC *rpc)
{
	RpcFree(rpc);
}

// RPC の解放
void RpcFree(RPC *rpc)
{
	// 引数チェック
	if (rpc == NULL)
	{
		return;
	}

	Disconnect(rpc->Sock);
	ReleaseSock(rpc->Sock);

	DeleteLock(rpc->Lock);

	Free(rpc);
}

// エラーの取得
UINT RpcGetError(PACK *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return ERR_DISCONNECTED;
	}

	return PackGetInt(p, "error_code");
}

// エラーチェック
bool RpcIsOk(PACK *p)
{
	// 引数チェック
	if (p == NULL)
	{
		return false;
	}

	if (PackGetInt(p, "error") == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// エラーコード設定
void RpcError(PACK *p, UINT err)
{
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	PackAddInt(p, "error", 1);
	PackAddInt(p, "error_code", err);
}

// RPC ディスパッチャを起動する
PACK *CallRpcDispatcher(RPC *r, PACK *p)
{
	char func_name[MAX_SIZE];
	// 引数チェック
	if (r == NULL || p == NULL)
	{
		return NULL;
	}

	if (PackGetStr(p, "function_name", func_name, sizeof(func_name)) == false)
	{
		return NULL;
	}

	return r->Dispatch(r, func_name, p);
}

// 次の RPC 呼び出しを待機する
bool RpcRecvNextCall(RPC *r)
{
	UINT size;
	void *tmp;
	SOCK *s;
	BUF *b;
	PACK *p;
	PACK *ret;
	// 引数チェック
	if (r == NULL)
	{
		return false;
	}

	s = r->Sock;

	if (RecvAll(s, &size, sizeof(UINT), s->SecureMode) == false)
	{
		return false;
	}

	size = Endian32(size);

	if (size > MAX_PACK_SIZE)
	{
		return false;
	}

	tmp = MallocEx(size, true);

	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		return false;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	SeekBuf(b, 0, 0);
	Free(tmp);

	p = BufToPack(b);
	FreeBuf(b);

	if (p == NULL)
	{
		return false;
	}

	ret = CallRpcDispatcher(r, p);
	FreePack(p);

	if (ret == NULL)
	{
		ret = PackError(ERR_NOT_SUPPORTED);
	}

	b = PackToBuf(ret);
	FreePack(ret);

	size = Endian32(b->Size);
	SendAdd(s, &size, sizeof(UINT));
	SendAdd(s, b->Buf, b->Size);

	if (SendNow(s, s->SecureMode) == false)
	{
		FreeBuf(b);
		return false;
	}

	FreeBuf(b);

	return true;
}

// RPC サーバー動作
void RpcServer(RPC *r)
{
	SOCK *s;
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	s = r->Sock;

	while (true)
	{
		// 次の RPC 呼び出しを待機する
		if (RpcRecvNextCall(r) == false)
		{
			// 通信エラー
			break;
		}
	}
}

// RPC 呼び出し
PACK *RpcCall(RPC *r, char *function_name, PACK *p)
{
	PACK *ret;
	UINT num_retry = 0;
	UINT err = 0;
	// 引数チェック
	if (r == NULL || function_name == NULL)
	{
		return NULL;
	}

//	Debug("RpcCall: %s\n", function_name);

	Lock(r->Lock);
	{
		if (p == NULL)
		{
			p = NewPack();
		}

		PackAddStr(p, "function_name", function_name);

RETRY:
		err = 0;
		ret = RpcCallInternal(r, p);

		if (ret == NULL)
		{
			if (r->IsVpnServer && r->Sock != NULL)
			{
				if (num_retry < 1)
				{
					num_retry++;

					// VPN Server に RPC 再接続を試みる
					err = AdminReconnect(r);

					if (err == ERR_NO_ERROR)
					{
						goto RETRY;
					}
				}
			}
		}

		FreePack(p);

		if (ret == NULL)
		{
			if (err == 0)
			{
				err = ERR_DISCONNECTED;
			}

			ret = PackError(err);
			PackAddInt(ret, "error_code", err);
		}
	}
	Unlock(r->Lock);

	return ret;
}

// RPC 内部呼び出し
PACK *RpcCallInternal(RPC *r, PACK *p)
{
	BUF *b;
	UINT size;
	PACK *ret;
	void *tmp;
	// 引数チェック
	if (r == NULL || p == NULL)
	{
		return NULL;
	}

	if (r->Sock == NULL)
	{
		return NULL;
	}

	b = PackToBuf(p);

	size = Endian32(b->Size);
	SendAdd(r->Sock, &size, sizeof(UINT));
	SendAdd(r->Sock, b->Buf, b->Size);
	FreeBuf(b);

	if (SendNow(r->Sock, r->Sock->SecureMode) == false)
	{
		return NULL;
	}

	if (RecvAll(r->Sock, &size, sizeof(UINT), r->Sock->SecureMode) == false)
	{
		return NULL;
	}

	size = Endian32(size);
	if (size > MAX_PACK_SIZE)
	{
		return NULL;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(r->Sock, tmp, size, r->Sock->SecureMode) == false)
	{
		Free(tmp);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	SeekBuf(b, 0, 0);
	Free(tmp);

	ret = BufToPack(b);
	if (ret == NULL)
	{
		FreeBuf(b);
		return NULL;
	}

	FreeBuf(b);

	return ret;
}

// RPC サーバーの開始
RPC *StartRpcServer(SOCK *s, RPC_DISPATCHER *dispatch, void *param)
{
	RPC *r;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	r = ZeroMallocEx(sizeof(RPC), true);
	r->Sock = s;
	r->Param = param;
	r->Lock = NewLock();
	AddRef(s->ref);

	r->ServerMode = true;
	r->Dispatch = dispatch;

	// 名前の生成
	Format(r->Name, sizeof(r->Name), "RPC-%u", s->socket);

	return r;
}

// RPC クライアントの開始
RPC *StartRpcClient(SOCK *s, void *param)
{
	RPC *r;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	r = ZeroMalloc(sizeof(RPC));
	r->Sock = s;
	r->Param = param;
	r->Lock = NewLock();
	AddRef(s->ref);

	r->ServerMode = false;

	return r;
}

