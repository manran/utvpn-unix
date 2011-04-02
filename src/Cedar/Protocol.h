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

// Protocol.h
// Protocol.c のヘッダ

#ifndef	PROTOCOL_H
#define	PROTOCOL_H

// 証明書確認用スレッドに渡すパラメータ
struct CHECK_CERT_THREAD_PROC
{
	CONNECTION *Connection;
	X *ServerX;
	CHECK_CERT_PROC *CheckCertProc;
	bool UserSelected;
	bool Exipred;
	bool Ok;
};

// セキュアデバイス署名用スレッドに渡すパラメータ
struct SECURE_SIGN_THREAD_PROC
{
	SECURE_SIGN_PROC *SecureSignProc;
	CONNECTION *Connection;
	SECURE_SIGN *SecureSign;
	bool UserFinished;
	bool Ok;
};

// ランダムサイズキャッシュ
struct RAND_CACHE
{
	IP Ip;							// IP アドレス
	UINT RandSize;					// ランダムサイズ
	UINT64 LastTime;				// 最終使用日時
};

// HTTP 値
struct HTTP_VALUE
{
	char *Name;						// 名前
	char *Data;						// データ
};

// HTTP ヘッダ
struct HTTP_HEADER
{
	char *Method;					// メソッド
	char *Target;					// ターゲット
	char *Version;					// バージョン
	LIST *ValueList;				// 値リスト
};

// シグネチャ送信スレッド用パラメータ
struct SEND_SIGNATURE_PARAM
{
	char Hostname[MAX_PATH];		// ホスト名
	UINT Port;						// ポート番号
	BUF *Buffer;					// パケット内容
};


// 関数プロトタイプ
bool ServerAccept(CONNECTION *c);
bool ClientConnect(CONNECTION *c);
SOCK *ClientConnectToServer(CONNECTION *c);
SOCK *TcpIpConnect(char *hostname, UINT port);
SOCK *TcpIpConnectEx(char *hostname, UINT port, bool *cancel_flag, void *hWnd);
bool ClientUploadSignature(SOCK *s);
bool ClientDownloadHello(CONNECTION *c, SOCK *s);
bool ServerDownloadSignature(CONNECTION *c);
bool ServerUploadHello(CONNECTION *c);
bool ClientUploadAuth(CONNECTION *c);
SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect);
SOCK *TcpConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd);

void InitProtocol();
void FreeProtocol();

bool HttpServerSend(SOCK *s, PACK *p);
PACK *HttpServerRecv(SOCK *s);
PACK *HttpClientRecv(SOCK *s);
bool HttpClientSend(SOCK *s, PACK *p);

bool HttpSendForbidden(SOCK *s, char *target, char *server_id);
bool HttpSendNotFound(SOCK *s, char *target);
bool HttpSendNotImplemented(SOCK *s, char *method, char *target, char *version);

char *RecvLine(SOCK *s, UINT max_size);
HTTP_HEADER *RecvHttpHeader(SOCK *s);
void FreeHttpHeader(HTTP_HEADER *header);
void FreeHttpValue(HTTP_VALUE *value);
HTTP_HEADER *NewHttpHeader(char *method, char *target, char *version);
void AddHttpValue(HTTP_HEADER *header, HTTP_VALUE *value);
int CompareHttpValue(void *p1, void *p2);
HTTP_VALUE *GetHttpValue(HTTP_HEADER *header, char *name);
HTTP_VALUE *NewHttpValue(char *name, char *data);
char *HttpHeaderToStr(HTTP_HEADER *header);
bool SendHttpHeader(SOCK *s, HTTP_HEADER *header);
bool PostHttp(SOCK *s, HTTP_HEADER *header, void *post_data, UINT post_size);
UINT GetContentLength(HTTP_HEADER *header);
void GetHttpDateStr(char *str, UINT size, UINT64 t);
void CreateDummyValue(PACK *p);

X *PackGetX(PACK *p, char *name);
K *PackGetK(PACK *p, char *name);
void PackAddX(PACK *p, char *name, X *x);
void PackAddK(PACK *p, char *name, K *k);
void PackAddStr(PACK *p, char *name, char *str);
void PackAddStrEx(PACK *p, char *name, char *str, UINT index, UINT total);
void PackAddUniStr(PACK *p, char *name, wchar_t *unistr);
void PackAddUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT index, UINT total);
void PackAddInt(PACK *p, char *name, UINT i);
void PackAddNum(PACK *p, char *name, UINT num);
void PackAddIntEx(PACK *p, char *name, UINT i, UINT index, UINT total);
void PackAddInt64(PACK *p, char *name, UINT64 i);
void PackAddInt64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total);
void PackAddData(PACK *p, char *name, void *data, UINT size);
void PackAddDataEx(PACK *p, char *name, void *data, UINT size, UINT index, UINT total);
void PackAddBuf(PACK *p, char *name, BUF *b);
void PackAddBufEx(PACK *p, char *name, BUF *b, UINT index, UINT total);
bool PackGetStr(PACK *p, char *name, char *str, UINT size);
bool PackGetStrEx(PACK *p, char *name, char *str, UINT size, UINT index);
bool PackGetUniStr(PACK *p, char *name, wchar_t *unistr, UINT size);
bool PackGetUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT size, UINT index);
UINT PackGetIndexCount(PACK *p, char *name);
UINT PackGetInt(PACK *p, char *name);
UINT PackGetNum(PACK *p, char *name);
UINT PackGetIntEx(PACK *p, char *name, UINT index);
UINT64 PackGetInt64(PACK *p, char *name);
UINT64 PackGetInt64Ex(PACK *p, char *name, UINT index);
UINT PackGetDataSizeEx(PACK *p, char *name, UINT index);
UINT PackGetDataSize(PACK *p, char *name);
bool PackGetData(PACK *p, char *name, void *data);
bool PackGetDataEx(PACK *p, char *name, void *data, UINT index);
BUF *PackGetBuf(PACK *p, char *name);
BUF *PackGetBufEx(PACK *p, char *name, UINT index);
POLICY *PackGetPolicy(PACK *p);
void PackAddPolicy(PACK *p, POLICY *y);
bool PackGetBool(PACK *p, char *name);
void PackAddBool(PACK *p, char *name, bool b);
void PackAddBoolEx(PACK *p, char *name, bool b, UINT index, UINT total);
bool PackGetBoolEx(PACK *p, char *name, UINT index);
void PackAddIp(PACK *p, char *name, IP *ip);
void PackAddIpEx(PACK *p, char *name, IP *ip, UINT index, UINT total);
bool PackGetIp(PACK *p, char *name, IP *ip);
bool PackGetIpEx(PACK *p, char *name, IP *ip, UINT index);
UINT PackGetIp32(PACK *p, char *name);
UINT PackGetIp32Ex(PACK *p, char *name, UINT index);
void PackAddIp32(PACK *p, char *name, UINT ip32);
void PackAddIp32Ex(PACK *p, char *name, UINT ip32, UINT index, UINT total);
void PackAddIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index, UINT total);
bool PackGetIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index);
void PackAddIp6Addr(PACK *p, char *name, IPV6_ADDR *addr);
bool PackGetIp6Addr(PACK *p, char *name, IPV6_ADDR *addr);

PACK *PackWelcome(SESSION *s);
PACK *PackHello(void *random, UINT ver, UINT build, char *server_str);
bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size);
PACK *PackLoginWithAnonymous(char *hubname, char *username);
PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password);
PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password);
PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size);
bool GetMethodFromPack(PACK *p, char *method, UINT size);
bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
								   char *hubname, UINT hubname_size);
PACK *PackAdditionalConnect(UCHAR *session_key);
UINT GetAuthTypeFromPack(PACK *p);
UINT GetErrorFromPack(PACK *p);
PACK *PackError(UINT error);
UINT GetProtocolFromPack(PACK *p);
bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
						  char *connection_name, UINT connection_name_size,
						  POLICY **policy);

bool SendPack(SOCK *s, PACK *p);
PACK *RecvPack(SOCK *s);

bool ClientAdditionalConnect(CONNECTION *c, THREAD *t);
SOCK *ClientAdditionalConnectToServer(CONNECTION *c);
bool ClientUploadAuth2(CONNECTION *c, SOCK *s);
bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32);
void GenerateRC4KeyPair(RC4_KEY_PAIR *k);

SOCK *ProxyConnect(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, char *password, bool additional_connect);
SOCK *ProxyConnectEx(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
					 char *server_host_name, UINT server_port,
					 char *username, char *password, bool additional_connect,
					 bool *cancel_flag, void *hWnd);
SOCK *SocksConnect(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, bool additional_connect);
SOCK *SocksConnectEx(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
					 char *server_host_name, UINT server_port,
					 char *username, bool additional_connect,
					 bool *cancel_flag, void *hWnd);
bool SocksSendRequestPacket(CONNECTION *c, SOCK *s, UINT dest_port, IP *dest_ip, char *userid);
bool SocksRecvResponsePacket(CONNECTION *c, SOCK *s);
void CreateNodeInfo(NODE_INFO *info, CONNECTION *c);
UINT SecureSign(SECURE_SIGN *sign, UINT device_id, char *pin);
void ClientUploadNoop(CONNECTION *c);
bool ClientCheckServerCert(CONNECTION *c, bool *expired);
void ClientCheckServerCertThread(THREAD *thread, void *param);
bool ClientSecureSign(CONNECTION *c, UCHAR *sign, UCHAR *random, X **x);
void ClientSecureSignThread(THREAD *thread, void *param);
UINT SecureWrite(UINT device_id, char *cert_name, X *x, char *key_name, K *k, char *pin);
UINT SecureEnum(UINT device_id, char *pin, TOKEN_LIST **cert_list, TOKEN_LIST **key_list);
UINT SecureDelete(UINT device_id, char *pin, char *cert_name, char *key_name);
bool PackGetData2(PACK *p, char *name, void *data, UINT size);
bool PackGetDataEx2(PACK *p, char *name, void *data, UINT size, UINT index);
TOKEN_LIST *EnumHub(SESSION *s);
UINT ChangePasswordAccept(CONNECTION *c, PACK *p);
UINT ChangePassword(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, char *username, char *old_pass, char *new_pass);
void PackAddClientVersion(PACK *p, CONNECTION *c);
void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info);
void GenerateMachineUniqueHash(void *data);
void SendSignatureByUdp(CONNECTION *c, IP *ip);
void SendSignatureByTcp(CONNECTION *c, IP *ip);
void SendSignatureByTcpThread(THREAD *thread, void *param);


#endif	// PROTOCOL_H
