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

// Win32Html.h
// Win32Html.c のヘッダ

#ifndef	WIN32HTML_H
#define	WIN32HTML_H

#ifdef	WIN32HTML_CPP

// 内部向け関数

#endif	// WIN32HTML_CPP

// 外部向け関数

#pragma comment(lib,"htmlhelp.lib")
#pragma comment(lib,"Urlmon.lib")

#if	defined(__cplusplus)
extern "C"
{
#endif

	void ShowHtml(HWND hWnd, char *url, wchar_t *option);
	bool CreateLink(wchar_t *filename, wchar_t *target, wchar_t *workdir, wchar_t *args,
		wchar_t *comment, wchar_t *icon, UINT icon_index);
	wchar_t *FolderDlgW(HWND hWnd, wchar_t *title, wchar_t *default_dir);
	char *FolderDlgA(HWND hWnd, wchar_t *title, char *default_dir);

	//////////////////////////////////////////////////////////////////////////
	//JumpList


	typedef void* JL_PCustomDestinationList;
	typedef void* JL_PObjectArray;
	typedef void* JL_PShellLink;
	typedef void* JL_PObjectCollection;
	typedef long JL_HRESULT;

	JL_HRESULT JL_CreateCustomDestinationList(JL_PCustomDestinationList* poc, wchar_t* appID);
	JL_HRESULT JL_ReleaseCustomDestinationList(JL_PCustomDestinationList poc);

	JL_HRESULT JL_BeginList(JL_PCustomDestinationList poc, JL_PObjectArray* oaRemoved);
	JL_HRESULT JL_CommitList(JL_PCustomDestinationList cdl);


	JL_HRESULT JL_CreateObjectCollection(JL_PObjectCollection* poc);
	JL_HRESULT JL_ReleaseObjectCollection(JL_PObjectCollection poc);
	JL_HRESULT JL_ObjectCollectionAddShellLink(JL_PObjectCollection poc, JL_PShellLink ppsl);

	JL_HRESULT JL_AddCategoryToList(JL_PCustomDestinationList pcdl, 
		JL_PObjectCollection poc, 
		wchar_t* categoryName,
		JL_PObjectArray poaRemoved);
	JL_HRESULT JL_DeleteJumpList(JL_PCustomDestinationList jpcdl,wchar_t* appID);


	JL_HRESULT JL_CreateShellLink(
		wchar_t* pszPath, 
		wchar_t* pszArguments, 
		wchar_t* pszTitle, 
		wchar_t* iconLocation,
		int iconIndex,
		wchar_t* description, JL_PShellLink *ppsl);
	JL_HRESULT JL_ReleaseShellLink(JL_PShellLink ppsl);


	//SetApplicationID for Windows 7
	JL_HRESULT JL_SetCurrentProcessExplicitAppUserModelID(wchar_t* appID);

#if	defined(__cplusplus)
}
#endif


#if defined(__cplusplus)

// 注意: このあたりの宣言文は Windows SDK からのコピーである。
//       しかし創作性に乏しい (単なる宣言であるため) ので GPL のコード中にペーストしても
//       支障はないと解釈している。

#ifndef	__IObjectArray_INTERFACE_DEFINED__
#define	__IObjectArray_INTERFACE_DEFINED__

MIDL_INTERFACE("92CA9DCD-5622-4bba-A805-5E9F541BD8C9")
IObjectArray : public IUnknown
{
public:
	virtual HRESULT STDMETHODCALLTYPE GetCount( 
		/* [out] */ __RPC__out UINT *pcObjects) = 0;

	virtual HRESULT STDMETHODCALLTYPE GetAt( 
		/* [in] */ UINT uiIndex,
		/* [in] */ __RPC__in REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out_opt void **ppv) = 0;

};

MIDL_INTERFACE("5632b1a4-e38a-400a-928a-d4cd63230295")
IObjectCollection : public IObjectArray
{
public:
	virtual HRESULT STDMETHODCALLTYPE AddObject( 
		/* [in] */ __RPC__in_opt IUnknown *punk) = 0;

	virtual HRESULT STDMETHODCALLTYPE AddFromArray( 
		/* [in] */ __RPC__in_opt IObjectArray *poaSource) = 0;

	virtual HRESULT STDMETHODCALLTYPE RemoveObjectAt( 
		/* [in] */ UINT uiIndex) = 0;

	virtual HRESULT STDMETHODCALLTYPE Clear( void) = 0;

};

#endif	// __IObjectArray_INTERFACE_DEFINED__

#ifndef	__ICustomDestinationList_INTERFACE_DEFINED__
#define	__ICustomDestinationList_INTERFACE_DEFINED__

typedef /* [v1_enum] */ 
enum KNOWNDESTCATEGORY
{	
	KDC_FREQUENT	= 1,
	KDC_RECENT	= ( KDC_FREQUENT + 1 ) 
} 	KNOWNDESTCATEGORY;

MIDL_INTERFACE("6332debf-87b5-4670-90c0-5e57b408a49e")
ICustomDestinationList : public IUnknown
{
public:
	virtual HRESULT STDMETHODCALLTYPE SetAppID( 
		/* [string][in] */ __RPC__in_string LPCWSTR pszAppID) = 0;

	virtual HRESULT STDMETHODCALLTYPE BeginList( 
		/* [out] */ __RPC__out UINT *pcMinSlots,
		/* [in] */ __RPC__in REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out_opt void **ppv) = 0;

	virtual HRESULT STDMETHODCALLTYPE AppendCategory( 
		/* [string][in] */ __RPC__in_string LPCWSTR pszCategory,
		/* [in] */ __RPC__in_opt IObjectArray *poa) = 0;

	virtual HRESULT STDMETHODCALLTYPE AppendKnownCategory( 
		/* [in] */ KNOWNDESTCATEGORY category) = 0;

	virtual HRESULT STDMETHODCALLTYPE AddUserTasks( 
		/* [in] */ __RPC__in_opt IObjectArray *poa) = 0;

	virtual HRESULT STDMETHODCALLTYPE CommitList( void) = 0;

	virtual HRESULT STDMETHODCALLTYPE GetRemovedDestinations( 
		/* [in] */ __RPC__in REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out_opt void **ppv) = 0;

	virtual HRESULT STDMETHODCALLTYPE DeleteList( 
		/* [string][unique][in] */ __RPC__in_opt_string LPCWSTR pszAppID) = 0;

	virtual HRESULT STDMETHODCALLTYPE AbortList( void) = 0;

};


#endif	// __ICustomDestinationList_INTERFACE_DEFINED__


#endif //defined(__cplusplus)



#endif	// WIN32HTML_H
