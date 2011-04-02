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

// Win32.c
// Microsoft Windows 依存コード

#ifdef	WIN32

#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <Dbghelp.h>
#include <commctrl.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

static HANDLE heap_handle = NULL;
static HANDLE hstdout = INVALID_HANDLE_VALUE;
static HANDLE hstdin = INVALID_HANDLE_VALUE;

// Win32 用スレッドデータ
typedef struct WIN32THREAD
{
	HANDLE hThread;
	DWORD thread_id;
} WIN32THREAD;

// Win32 用スレッド起動情報
typedef struct WIN32THREADSTARTUPINFO
{
	THREAD_PROC *thread_proc;
	void *param;
	THREAD *thread;
} WIN32THREADSTARTUPINFO;

// Win32 用関数プロトタイプ
DWORD CALLBACK Win32DefaultThreadProc(void *param);

// 現在のプロセスハンドル
static HANDLE hCurrentProcessHandle = NULL;
static CRITICAL_SECTION fasttick_lock;
static UINT64 start_tick = 0;
static bool use_heap_api = false;
static bool win32_is_nt = false;

// Win32 用ファイル I/O データ
typedef struct WIN32IO
{
	HANDLE hFile;
	bool WriteMode;
} WIN32IO;

// Win32 用ミューテックスデータ
typedef struct WIN32MUTEX
{
	HANDLE hMutex;
} WIN32MUTEX;

// ディスパッチテーブルの作成
OS_DISPATCH_TABLE *Win32GetDispatchTable()
{
	static OS_DISPATCH_TABLE t =
	{
		Win32Init,
		Win32Free,
		Win32MemoryAlloc,
		Win32MemoryReAlloc,
		Win32MemoryFree,
		Win32GetTick,
		Win32GetSystemTime,
		Win32Inc32,
		Win32Dec32,
		Win32Sleep,
		Win32NewLock,
		Win32Lock,
		Win32Unlock,
		Win32DeleteLock,
		Win32InitEvent,
		Win32SetEvent,
		Win32ResetEvent,
		Win32WaitEvent,
		Win32FreeEvent,
		Win32WaitThread,
		Win32FreeThread,
		Win32InitThread,
		Win32ThreadId,
		Win32FileOpen,
		Win32FileOpenW,
		Win32FileCreate,
		Win32FileCreateW,
		Win32FileWrite,
		Win32FileRead,
		Win32FileClose,
		Win32FileFlush,
		Win32FileSize,
		Win32FileSeek,
		Win32FileDelete,
		Win32FileDeleteW,
		Win32MakeDir,
		Win32MakeDirW,
		Win32DeleteDir,
		Win32DeleteDirW,
		Win32GetCallStack,
		Win32GetCallStackSymbolInfo,
		Win32FileRename,
		Win32FileRenameW,
		Win32Run,
		Win32RunW,
		Win32IsSupportedOs,
		Win32GetOsInfo,
		Win32Alert,
		Win32AlertW,
		Win32GetProductId,
		Win32SetHighPriority,
		Win32RestorePriority,
		Win32NewSingleInstance,
		Win32FreeSingleInstance,
		Win32GetMemInfo,
		Win32Yield,
	};

	return &t;
}

// 新しいスレッド用の初期化関数
void Win32InitNewThread()
{
	static HINSTANCE hDll = NULL;
	static bool (WINAPI *_SetThreadLocale)(LCID) = NULL;

	if (hDll == NULL)
	{
		hDll = LoadLibrary("kernel32.dll");

		_SetThreadLocale =
			(bool (__stdcall *)(LCID))
			GetProcAddress(hDll, "SetThreadLocale");
	}

	if (_SetThreadLocale != NULL)
	{
		_SetThreadLocale(LOCALE_USER_DEFAULT);
	}
}

// フォルダの圧縮フラグを設定する
bool Win32SetFolderCompressW(wchar_t *path, bool compressed)
{
	HANDLE h;
	UINT retsize = 0;
	USHORT flag;
	wchar_t tmp[MAX_PATH];
	// 引数チェック
	if (path == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char *path_a = CopyUniToStr(path);
		bool ret = Win32SetFolderCompress(path_a, compressed);

		Free(path_a);

		return ret;
	}

	InnerFilePathW(tmp, sizeof(tmp), path);

	// フォルダを開く
	h = CreateFileW(tmp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	flag = compressed ? COMPRESSION_FORMAT_DEFAULT : COMPRESSION_FORMAT_NONE;

	if (DeviceIoControl(h, FSCTL_SET_COMPRESSION, &flag, sizeof(USHORT),
		NULL, 0, &retsize, NULL) == false)
	{
		return false;
	}

	CloseHandle(h);

	return true;
}
bool Win32SetFolderCompress(char *path, bool compressed)
{
	HANDLE h;
	UINT retsize = 0;
	USHORT flag;
	char tmp[MAX_PATH];
	// 引数チェック
	if (path == NULL)
	{
		return false;
	}

	InnerFilePath(tmp, sizeof(tmp), path);

	// フォルダを開く
	h = CreateFile(tmp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	flag = compressed ? COMPRESSION_FORMAT_DEFAULT : COMPRESSION_FORMAT_NONE;

	if (DeviceIoControl(h, FSCTL_SET_COMPRESSION, &flag, sizeof(USHORT),
		NULL, 0, &retsize, NULL) == false)
	{
		return false;
	}

	CloseHandle(h);

	return true;
}

// ディスクの空き容量を取得する
bool Win32GetDiskFreeW(wchar_t *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	wchar_t tmp[MAX_SIZE];
	UINT count = 0;
	UINT i, n, len;
	ULARGE_INTEGER v1, v2, v3;
	bool ret = false;
	// 引数チェック
	if (path == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		bool ret;
		char *path_a = CopyUniToStr(path);

		ret = Win32GetDiskFree(path_a, free_size, used_size, total_size);

		Free(path_a);

		return ret;
	}

	Zero(&v1, sizeof(v1));
	Zero(&v2, sizeof(v2));
	Zero(&v3, sizeof(v3));

	NormalizePathW(tmp, sizeof(tmp), path);

	// ディレクトリ名を取得
	if (UniStartWith(path, L"\\\\"))
	{
		count = 4;
	}
	else
	{
		count = 1;
	}

	len = UniStrLen(tmp);
	n = 0;
	for (i = 0;i < len;i++)
	{
		if (tmp[i] == L'\\')
		{
			n++;
			if (n >= count)
			{
				tmp[i + 1] = 0;
				break;
			}
		}
	}

	if (GetDiskFreeSpaceExW(tmp, &v1, &v2, &v3))
	{
		ret = true;
	}

	if (free_size != NULL)
	{
		*free_size = v1.QuadPart;
	}

	if (total_size != NULL)
	{
		*total_size = v2.QuadPart;
	}

	if (used_size != NULL)
	{
		*used_size = v2.QuadPart - v1.QuadPart;
	}

	return ret;
}
bool Win32GetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	char tmp[MAX_SIZE];
	UINT count = 0;
	UINT i, n, len;
	ULARGE_INTEGER v1, v2, v3;
	bool ret = false;
	// 引数チェック
	if (path == NULL)
	{
		return false;
	}

	Zero(&v1, sizeof(v1));
	Zero(&v2, sizeof(v2));
	Zero(&v3, sizeof(v3));

	NormalizePath(tmp, sizeof(tmp), path);

	// ディレクトリ名を取得
	if (StartWith(path, "\\\\"))
	{
		count = 4;
	}
	else
	{
		count = 1;
	}

	len = StrLen(tmp);
	n = 0;
	for (i = 0;i < len;i++)
	{
		if (tmp[i] == '\\')
		{
			n++;
			if (n >= count)
			{
				tmp[i + 1] = 0;
				break;
			}
		}
	}

	if (GetDiskFreeSpaceEx(tmp, &v1, &v2, &v3))
	{
		ret = true;
	}

	if (free_size != NULL)
	{
		*free_size = v1.QuadPart;
	}

	if (total_size != NULL)
	{
		*total_size = v2.QuadPart;
	}

	if (used_size != NULL)
	{
		*used_size = v2.QuadPart - v1.QuadPart;
	}

	return ret;
}

// ディレクトリの列挙
DIRLIST *Win32EnumDirEx(char *dirname, COMPARE *compare)
{
	DIRLIST *ret;
	wchar_t *dirname_w = CopyStrToUni(dirname);

	ret = Win32EnumDirExW(dirname_w, compare);

	Free(dirname_w);

	return ret;
}
DIRLIST *Win32EnumDirExW(wchar_t *dirname, COMPARE *compare)
{
	WIN32_FIND_DATAA data_a;
	WIN32_FIND_DATAW data_w;
	HANDLE h;
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MAX_PATH];
	wchar_t dirname2[MAX_PATH];
	LIST *o;
	DIRLIST *d;

	UniStrCpy(tmp2, sizeof(tmp2), dirname);

	if (UniStrLen(tmp2) >= 1 && tmp[UniStrLen(tmp2) - 1] == L'\\')
	{
		tmp2[UniStrLen(tmp2) - 1] = 0;
	}

	UniFormat(tmp, sizeof(tmp), L"%s\\*.*", tmp2);
	NormalizePathW(tmp, sizeof(tmp), tmp);
	NormalizePathW(dirname2, sizeof(dirname2), tmp2);

	o = NewListFast(compare);

	Zero(&data_a, sizeof(data_a));
	Zero(&data_w, sizeof(data_w));

	if (IsNt())
	{
		h = FindFirstFileW(tmp, &data_w);
	}
	else
	{
		char *tmp_a = CopyUniToStr(tmp);

		h = FindFirstFileA(tmp_a, &data_a);

		Free(tmp_a);
	}

	if (h != INVALID_HANDLE_VALUE)
	{
		bool b = true;

		do
		{
			if (IsNt() == false)
			{
				Zero(&data_w, sizeof(data_w));
				StrToUni(data_w.cFileName, sizeof(data_w.cFileName), data_a.cFileName);
				data_w.dwFileAttributes = data_a.dwFileAttributes;
				data_w.ftCreationTime = data_a.ftCreationTime;
				data_w.ftLastWriteTime = data_a.ftLastWriteTime;
				data_w.nFileSizeHigh = data_a.nFileSizeHigh;
				data_w.nFileSizeLow = data_a.nFileSizeLow;
			}

			if (UniStrCmpi(data_w.cFileName, L"..") != 0 &&
				UniStrCmpi(data_w.cFileName, L".") != 0)
			{
				DIRENT *f = ZeroMalloc(sizeof(DIRENT));
				SYSTEMTIME t1, t2;
				wchar_t fullpath[MAX_SIZE];
				bool ok = false;

				f->FileNameW = UniCopyStr(data_w.cFileName);
				f->FileName = CopyUniToStr(f->FileNameW);
				f->Folder = (data_w.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? true : false;

				CombinePathW(fullpath, sizeof(fullpath), dirname2, f->FileNameW);

				// ファイル情報の取得を試行する
				if (MsIsNt())
				{
					HANDLE h = CreateFileW(fullpath, 0,
						FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL, OPEN_EXISTING, 0, NULL);

					if (h != INVALID_HANDLE_VALUE)
					{
						BY_HANDLE_FILE_INFORMATION info;

						Zero(&info, sizeof(info));

						if (MsGetFileInformation(h, &info))
						{
							Zero(&t1, sizeof(t1));
							Zero(&t2, sizeof(t2));
							FileTimeToSystemTime(&info.ftCreationTime, &t1);
							FileTimeToSystemTime(&info.ftLastWriteTime, &t2);
							f->CreateDate = SystemToUINT64(&t1);
							f->UpdateDate = SystemToUINT64(&t2);

							if (f->Folder == false)
							{
								f->FileSize = ((UINT64)info.nFileSizeHigh * (UINT64)((UINT64)MAXDWORD + (UINT64)1)) + (UINT64)info.nFileSizeLow;
							}

							ok = true;
						}

						CloseHandle(h);
					}
				}

				if (ok == false)
				{
					Zero(&t1, sizeof(t1));
					Zero(&t2, sizeof(t2));
					FileTimeToSystemTime(&data_w.ftCreationTime, &t1);
					FileTimeToSystemTime(&data_w.ftLastWriteTime, &t2);
					f->CreateDate = SystemToUINT64(&t1);
					f->UpdateDate = SystemToUINT64(&t2);

					if (f->Folder == false)
					{
						f->FileSize = ((UINT64)data_w.nFileSizeHigh * (UINT64)((UINT64)MAXDWORD + (UINT64)1)) + (UINT64)data_w.nFileSizeLow;
					}
				}

				Add(o, f);
			}

			Zero(&data_w, sizeof(data_w));
			Zero(&data_a, sizeof(data_a));

			if (IsNt())
			{
				b = FindNextFileW(h, &data_w);
			}
			else
			{
				b = FindNextFileA(h, &data_a);
			}
		}
		while (b);

		FindClose(h);
	}

	Sort(o);

	d = ZeroMalloc(sizeof(DIRLIST));
	d->NumFiles = LIST_NUM(o);
	d->File = ToArray(o);

	ReleaseList(o);

	return d;
}

// EXE ファイル名を取得
void Win32GetExeNameW(wchar_t *name, UINT size)
{
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	if (IsNt() == false)
	{
		char name_a[MAX_PATH];

		Win32GetExeName(name_a, sizeof(name_a));

		StrToUni(name, size, name_a);

		return;
	}

	UniStrCpy(name, size, L"");

	GetModuleFileNameW(NULL, name, size);
}
void Win32GetExeName(char *name, UINT size)
{
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	StrCpy(name, size, "");

	GetModuleFileName(NULL, name, size);
}

// 現在のディレクトリの取得
void Win32GetCurrentDirW(wchar_t *dir, UINT size)
{
	// 引数チェック
	if (dir == NULL)
	{
		return;
	}

	if (IsNt() == false)
	{
		char dir_a[MAX_PATH];

		Win32GetCurrentDir(dir_a, sizeof(dir_a));

		StrToUni(dir, size, dir_a);

		return;
	}

	GetCurrentDirectoryW(size, dir);
}
void Win32GetCurrentDir(char *dir, UINT size)
{
	// 引数チェック
	if (dir == NULL)
	{
		return;
	}

	GetCurrentDirectory(size, dir);
}

// イールド
void Win32Yield()
{
	Sleep(0);
}

// メモリ情報の取得
void Win32GetMemInfo(MEMINFO *info)
{
	MEMORYSTATUS st;
	// 引数チェック
	if (info == NULL)
	{
		return;
	}

	Zero(info, sizeof(MEMINFO));
	Zero(&st, sizeof(st));
	st.dwLength = sizeof(st);

	GlobalMemoryStatus(&st);

	// 論理メモリ量
	info->TotalMemory = (UINT64)st.dwTotalPageFile;
	info->FreeMemory = (UINT64)st.dwAvailPageFile;
	info->UsedMemory = info->TotalMemory - info->FreeMemory;

	// 物理メモリ量
	info->TotalPhys = (UINT64)st.dwTotalPhys;
	info->FreePhys = (UINT64)st.dwAvailPhys;
	info->UsedPhys = info->TotalPhys - info->FreePhys;
}

// シングルインスタンスの作成
void *Win32NewSingleInstance(char *instance_name)
{
	WIN32MUTEX *ret;
	char tmp[MAX_SIZE];
	HANDLE hMutex;
	// 引数チェック
	if (instance_name == NULL)
	{
		char exe_path[MAX_PATH];
		GetModuleFileName(NULL, exe_path, sizeof(exe_path));
		HashInstanceName(tmp, sizeof(tmp), exe_path);
		instance_name = tmp;
	}

	hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, instance_name);
	if (hMutex != NULL)
	{
		CloseHandle(hMutex);
		return NULL;
	}

	hMutex = CreateMutex(NULL, FALSE, instance_name);
	if (hMutex == NULL)
	{
		CloseHandle(hMutex);
		return NULL;
	}

	ret = Win32MemoryAlloc(sizeof(WIN32MUTEX));
	ret->hMutex = hMutex;

	return (void *)ret;
}

// シングルインスタンスの解放
void Win32FreeSingleInstance(void *data)
{
	WIN32MUTEX *m;
	// 引数チェック
	if (data == NULL)
	{
		return;
	}

	m = (WIN32MUTEX *)data;
	ReleaseMutex(m->hMutex);
	CloseHandle(m->hMutex);

	Win32MemoryFree(m);
}

// 優先順位を高くする
void Win32SetHighPriority()
{
	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
}

// 優先順位を戻す
void Win32RestorePriority()
{
	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
}

// ノード情報を取得
char* Win32GetProductId()
{
	char *product_id;

	return CopyStr("--");

	// プロダクト ID
	product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	if (product_id == NULL)
	{
		product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId");
	}

	return product_id;
}

// 現在サポートされている OS かどうか取得
bool Win32IsSupportedOs()
{
	if (Win32GetOsType() == 0)
	{
		Win32Alert(
			"SoftEther UT-VPN doesn't support this Windows Operating System.\n"
			"SoftEther UT-VPN requires " SUPPORTED_WINDOWS_LIST ".\n\n"
			"Please contact your system administrator.", NULL);
		return false;
	}

	return true;
}

// アラートの表示
void Win32AlertW(wchar_t *msg, wchar_t *caption)
{
	char *s;
	// 引数チェック
	if (msg == NULL)
	{
		msg = L"Alert";
	}
	if (caption == NULL)
	{
		caption = L"SoftEther UT-VPN Kernel";
	}

	s = GetCommandLineStr();

	if (SearchStr(s, "win9x_uninstall", 0) == INFINITE && SearchStr(s, "win9x_install", 0) == INFINITE)
	{
		// Win9x サービスモードのアンインストール時には非表示とする
		MessageBoxW(NULL, msg, caption, MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
	}

	Free(s);
}
void Win32Alert(char *msg, char *caption)
{
	char *s;
	// 引数チェック
	if (msg == NULL)
	{
		msg = "Alert";
	}
	if (caption == NULL)
	{
		caption = "SoftEther UT-VPN Kernel";
	}

	s = GetCommandLineStr();

	if (SearchStr(s, "win9x_uninstall", 0) == INFINITE && SearchStr(s, "win9x_install", 0) == INFINITE)
	{
		// Win9x サービスモードのアンインストール時には非表示とする
		MessageBox(NULL, msg, caption, MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
	}

	Free(s);
}
void Win32DebugAlert(char *msg)
{
	// 引数チェック
	if (msg == NULL)
	{
		msg = "Alert";
	}

	MessageBox(NULL, msg, "Debug", MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
}

// OS 情報の取得
void Win32GetOsInfo(OS_INFO *info)
{
	UINT type = Win32GetOsType();
	OSVERSIONINFOEX os;
	char tmp[MAX_SIZE];
	// 引数チェック
	if (info == NULL)
	{
		return;
	}

	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);
	GetVersionEx((LPOSVERSIONINFOA)&os);

	info->OsType = Win32GetOsType();
	info->OsServicePack = os.wServicePackMajor;
	if (OS_IS_WINDOWS_NT(info->OsType))
	{
		char *s;
		char *keyname = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
		info->OsSystemName = CopyStr("Windows NT");
		Format(tmp, sizeof(tmp), "Build %u", os.dwBuildNumber);
		if (s = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "CurrentType"))
		{
			char str[MAX_SIZE];
			Format(str, sizeof(str), ", %s", s);
			StrCat(tmp, sizeof(tmp), str);
			Free(s);
		}
		if (os.wServicePackMajor != 0)
		{
			char str[MAX_SIZE];
			Format(str, sizeof(str), ", Service Pack %u", os.wServicePackMajor);
			StrCat(tmp, sizeof(tmp), str);
		}
		if (s = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "BuildLab"))
		{
			char str[MAX_SIZE];
			Format(str, sizeof(str), " (%s)", s);
			StrCat(tmp, sizeof(tmp), str);
			Free(s);
		}
		info->OsVersion = CopyStr(tmp);
		info->KernelName = CopyStr("NTOS Kernel");
		Format(tmp, sizeof(tmp), "Build %u", os.dwBuildNumber);
		if (s = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "CurrentType"))
		{
			char str[MAX_SIZE];
			Format(str, sizeof(str), " %s", s);
			StrCat(tmp, sizeof(tmp), str);
			Free(s);
		}
		info->KernelVersion = CopyStr(tmp);
	}
	else
	{
		OSVERSIONINFO os;
		Zero(&os, sizeof(os));
		os.dwOSVersionInfoSize = sizeof(os);
		GetVersionEx(&os);
		Format(tmp, sizeof(tmp), "Build %u %s", LOWORD(os.dwBuildNumber), os.szCSDVersion);
		Trim(tmp);
		info->OsVersion = CopyStr(tmp);
		info->OsSystemName = CopyStr("Windows");
		info->KernelName = CopyStr("Windows 9x Kernel");
		info->KernelVersion = CopyStr(tmp);
	}

	info->OsProductName = CopyStr(OsTypeToStr(info->OsType));
	info->OsVendorName = CopyStr("Microsoft Corporation");
}

// Windows NT かどうか取得
bool Win32IsNt()
{
	OSVERSIONINFO os;
	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);

	if (GetVersionEx(&os) == FALSE)
	{
		// 失敗?
		return false;
	}

	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		// NT
		return true;
	}

	// 9x
	return false;
}

// OS 種類の取得
UINT Win32GetOsType()
{
	OSVERSIONINFO os;
	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);

	if (GetVersionEx(&os) == FALSE)
	{
		// 失敗?
		return 0;
	}

	if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
	{
		// Windows 9x 系
		if (os.dwMajorVersion == 4)
		{
			if (os.dwMinorVersion == 0)
			{
				return OSTYPE_WINDOWS_95;
			}
			else if (os.dwMinorVersion == 10)
			{
				return OSTYPE_WINDOWS_98;
			}
			else if (os.dwMinorVersion == 90)
			{
				return OSTYPE_WINDOWS_ME;
			}
			else
			{
				return OSTYPE_WINDOWS_UNKNOWN;
			}
		}
		else if (os.dwMajorVersion >= 5)
		{
			return OSTYPE_WINDOWS_UNKNOWN;
		}
	}
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		UINT sp = Win32GetSpVer(os.szCSDVersion);
		if (os.dwMajorVersion == 4)
		{
			if (sp < 6)
			{
				// SP6 以前
				return 0;
			}
		}
		if (os.dwMajorVersion < 4)
		{
			// NT 3.51 以前
			return 0;
		}
		else
		{
			OSVERSIONINFOEX os;
			Zero(&os, sizeof(os));
			os.dwOSVersionInfoSize = sizeof(os);
			GetVersionEx((LPOSVERSIONINFOA)&os);

			if (os.dwMajorVersion == 4)
			{
				// Windows NT 4.0
				if (os.wProductType == VER_NT_DOMAIN_CONTROLLER || os.wProductType == VER_NT_SERVER)
				{
					if ((os.wSuiteMask & VER_SUITE_TERMINAL) || (os.wSuiteMask & VER_SUITE_SINGLEUSERTS))
					{
						return OSTYPE_WINDOWS_NT_4_TERMINAL_SERVER;
					}
					if (os.wSuiteMask & VER_SUITE_ENTERPRISE)
					{
						return OSTYPE_WINDOWS_NT_4_SERVER_ENTERPRISE;
					}
					if (os.wSuiteMask & VER_SUITE_BACKOFFICE)
					{
						return OSTYPE_WINDOWS_NT_4_BACKOFFICE;
					}
					if ((os.wSuiteMask & VER_SUITE_SMALLBUSINESS) || (os.wSuiteMask & VER_SUITE_SMALLBUSINESS_RESTRICTED))
					{
						return OSTYPE_WINDOWS_NT_4_SMS;
					}
					else
					{
						return OSTYPE_WINDOWS_NT_4_SERVER;
					}
				}
				else
				{
					return OSTYPE_WINDOWS_NT_4_WORKSTATION;
				}
			}
			else if (os.dwMajorVersion == 5)
			{
				// Windows 2000, XP, Server 2003
				if (os.dwMinorVersion == 0)
				{
					// Windows 2000
					if (os.wProductType == VER_NT_DOMAIN_CONTROLLER || os.wProductType == VER_NT_SERVER)
					{
						// Server
						if (os.wSuiteMask & VER_SUITE_DATACENTER)
						{
							return OSTYPE_WINDOWS_2000_DATACENTER_SERVER;
						}
						else if ((os.wSuiteMask & VER_SUITE_SMALLBUSINESS) || (os.wSuiteMask & VER_SUITE_SMALLBUSINESS_RESTRICTED))
						{
							return OSTYPE_WINDOWS_2000_SBS;
						}
						else if (os.wSuiteMask & VER_SUITE_BACKOFFICE)
						{
							return OSTYPE_WINDOWS_2000_BACKOFFICE;
						}
						else if (os.wSuiteMask & VER_SUITE_ENTERPRISE)
						{
							return OSTYPE_WINDOWS_2000_ADVANCED_SERVER;
						}
						else
						{
							return OSTYPE_WINDOWS_2000_SERVER;
						}
					}
					else
					{
						// Client
						return OSTYPE_WINDOWS_2000_PROFESSIONAL;
					}
				}
				else if (os.dwMinorVersion == 1)
				{
					// Windows XP
					if (os.wSuiteMask & VER_SUITE_PERSONAL)
					{
						return OSTYPE_WINDOWS_XP_HOME;
					}
					else
					{
						return OSTYPE_WINDOWS_XP_PROFESSIONAL;
					}
				}
				else if (os.dwMinorVersion == 2)
				{
					// Windows Server 2003
					if (os.wProductType == VER_NT_DOMAIN_CONTROLLER || os.wProductType == VER_NT_SERVER)
					{
						// Server
						if (os.wSuiteMask & VER_SUITE_DATACENTER)
						{
							return OSTYPE_WINDOWS_2003_DATACENTER;
						}
						else if ((os.wSuiteMask & VER_SUITE_SMALLBUSINESS) || (os.wSuiteMask & VER_SUITE_SMALLBUSINESS_RESTRICTED))
						{
							return OSTYPE_WINDOWS_2003_SBS;
						}
						else if (os.wSuiteMask & VER_SUITE_BACKOFFICE)
						{
							return OSTYPE_WINDOWS_2003_BACKOFFICE;
						}
						else if (os.wSuiteMask & VER_SUITE_ENTERPRISE)
						{
							return OSTYPE_WINDOWS_2003_ENTERPRISE;
						}
						else if (os.wSuiteMask & VER_SUITE_BLADE)
						{
							return OSTYPE_WINDOWS_2003_WEB;
						}
						else
						{
							return OSTYPE_WINDOWS_2003_STANDARD;
						}
					}
					else
					{
						// Client (Unknown XP?)
						return OSTYPE_WINDOWS_XP_PROFESSIONAL;
					}
				}
				else
				{
					// Windows Longhorn
					if (os.wProductType == VER_NT_DOMAIN_CONTROLLER || os.wProductType == VER_NT_SERVER)
					{
						return OSTYPE_WINDOWS_LONGHORN_SERVER;
					}
					else
					{
						return OSTYPE_WINDOWS_LONGHORN_PROFESSIONAL;
					}
				}
			}
			else
			{
				if (os.dwMajorVersion == 6 && os.dwMinorVersion == 0)
				{
					// Windows Vista, Server 2008
					if (os.wProductType == VER_NT_DOMAIN_CONTROLLER || os.wProductType == VER_NT_SERVER)
					{
						return OSTYPE_WINDOWS_LONGHORN_SERVER;
					}
					else
					{
						return OSTYPE_WINDOWS_LONGHORN_PROFESSIONAL;
					}
				}
				else if (os.dwMajorVersion == 6 && os.dwMinorVersion == 1)
				{
					if (os.wProductType == VER_NT_WORKSTATION)
					{
						// Windows 7
						return OSTYPE_WINDOWS_7;
					}
					else
					{
						// Windows Server 2008 R2
						return OSTYPE_WINDOWS_SERVER_2008_R2;
					}
				}
				else
				{
					if (os.wProductType == VER_NT_WORKSTATION)
					{
						// Windows 8
						return OSTYPE_WINDOWS_8;
					}
					else
					{
						// Windows Server 8
						return OSTYPE_WINDOWS_SERVER_2008_R2;
					}
				}
			}
		}
	}

	// 判別できない
	return 0;
}

// 文字列から SP のバージョンを取得する
UINT Win32GetSpVer(char *str)
{
	UINT ret, i;
	TOKEN_LIST *t;
	// 引数チェック
	if (str == NULL)
	{
		return 0;
	}

	t = ParseToken(str, NULL);
	if (t == NULL)
	{
		return 0;
	}

	ret = 0;
	for (i = 0;i < t->NumTokens;i++)
	{
		ret = ToInt(t->Token[i]);
		if (ret != 0)
		{
			break;
		}
	}

	FreeToken(t);

	return ret;
}

// プロセスの強制終了
bool Win32TerminateProcess(void *handle)
{
	HANDLE h;
	// 引数チェック
	if (handle == NULL)
	{
		return false;
	}

	h = (HANDLE)handle;

	TerminateProcess(h, 0);

	return true;
}

// プロセスを閉じる
void Win32CloseProcess(void *handle)
{
	// 引数チェック
	if (handle == NULL)
	{
		return;
	}

	CloseHandle((HANDLE)handle);
}

// 指定されたプロセスが生きているかどうかチェック
bool Win32IsProcessAlive(void *handle)
{
	HANDLE h;
	// 引数チェック
	if (handle == NULL)
	{
		return false;
	}

	h = (HANDLE)handle;

	if (WaitForSingleObject(h, 0) == WAIT_OBJECT_0)
	{
		return false;
	}

	return true;
}

// プロセスの終了を待機する
bool Win32WaitProcess(void *h, UINT timeout)
{
	// 引数チェック
	if (h == NULL)
	{
		return false;
	}
	if (timeout == 0)
	{
		timeout = INFINITE;
	}

	if (WaitForSingleObject((HANDLE)h, timeout) == WAIT_TIMEOUT)
	{
		return false;
	}

	return true;
}

// プロセスの起動 (ハンドルを返す)
void *Win32RunExW(wchar_t *filename, wchar_t *arg, bool hide)
{
	return Win32RunEx2W(filename, arg, hide, NULL);
}
void *Win32RunEx2W(wchar_t *filename, wchar_t *arg, bool hide, UINT *process_id)
{
	return Win32RunEx3W(filename, arg, hide, process_id, false);
}
void *Win32RunEx3W(wchar_t *filename, wchar_t *arg, bool hide, UINT *process_id, bool disableWow)
{
	STARTUPINFOW info;
	PROCESS_INFORMATION ret;
	wchar_t cmdline[MAX_SIZE];
	wchar_t name[MAX_PATH];
	void *p;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	if (IsNt() == false)
	{
		char *filename_a = CopyUniToStr(filename);
		char *arg_a = CopyUniToStr(arg);
		void *ret = Win32RunEx(filename_a, arg_a, hide);

		Free(filename_a);
		Free(arg_a);

		return ret;
	}

	UniStrCpy(name, sizeof(name), filename);
	UniTrim(name);

	if (UniSearchStr(name, L"\"", 0) == INFINITE)
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s %s", name, arg);
		}
	}
	else
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\"", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\" %s", name, arg);
		}
	}

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	UniTrim(cmdline);

	if (disableWow)
	{
		p = MsDisableWow64FileSystemRedirection();
	}

	if (CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW | CREATE_NEW_CONSOLE) | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &info, &ret) == FALSE)
	{
		if (disableWow)
		{
			MsRestoreWow64FileSystemRedirection(p);
		}
		return NULL;
	}

	if (disableWow)
	{
		MsRestoreWow64FileSystemRedirection(p);
	}

	if (process_id != NULL)
	{
		*process_id = ret.dwProcessId;
	}

	CloseHandle(ret.hThread);
	return ret.hProcess;
}
void *Win32RunEx(char *filename, char *arg, bool hide)
{
	return Win32RunEx2(filename, arg, hide, NULL);
}
void *Win32RunEx2(char *filename, char *arg, bool hide, UINT *process_id)
{
	return Win32RunEx3(filename, arg, hide, process_id, false);
}
void *Win32RunEx3(char *filename, char *arg, bool hide, UINT *process_id, bool disableWow)
{
	STARTUPINFO info;
	PROCESS_INFORMATION ret;
	char cmdline[MAX_SIZE];
	char name[MAX_PATH];
	void *p = NULL;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	StrCpy(name, sizeof(name), filename);
	Trim(name);

	if (SearchStr(name, "\"", 0) == INFINITE)
	{
		if (arg == NULL)
		{
			Format(cmdline, sizeof(cmdline), "%s", name);
		}
		else
		{
			Format(cmdline, sizeof(cmdline), "%s %s", name, arg);
		}
	}
	else
	{
		if (arg == NULL)
		{
			Format(cmdline, sizeof(cmdline), "\"%s\"", name);
		}
		else
		{
			Format(cmdline, sizeof(cmdline), "\"%s\" %s", name, arg);
		}
	}

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	Trim(cmdline);

	if (disableWow)
	{
		p = MsDisableWow64FileSystemRedirection();
	}

	if (CreateProcess(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW | CREATE_NEW_CONSOLE) | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &info, &ret) == FALSE)
	{
		if (disableWow)
		{
			MsRestoreWow64FileSystemRedirection(p);
		}
		return NULL;
	}
	if (disableWow)
	{
		MsRestoreWow64FileSystemRedirection(p);
	}

	if (process_id != NULL)
	{
		*process_id = ret.dwProcessId;
	}

	CloseHandle(ret.hThread);
	return ret.hProcess;
}

// プロセスの起動
bool Win32RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	STARTUPINFOW info;
	PROCESS_INFORMATION ret;
	wchar_t cmdline[MAX_SIZE];
	wchar_t name[MAX_PATH];
	// 引数チェック
	if (filename == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char *filename_a = CopyUniToStr(filename);
		char *arg_a = CopyUniToStr(arg);
		bool ret;

		ret = Win32Run(filename_a, arg_a, hide, wait);

		Free(filename_a);
		Free(arg_a);

		return ret;
	}

	UniStrCpy(name, sizeof(name), filename);
	UniTrim(name);

	if (UniSearchStr(name, L"\"", 0) == INFINITE)
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s %s", name, arg);
		}
	}
	else
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\"", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\" %s", name, arg);
		}
	}

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	UniTrim(cmdline);

	if (CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW | CREATE_NEW_CONSOLE) | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &info, &ret) == FALSE)
	{
		return false;
	}

	if (wait)
	{
		WaitForSingleObject(ret.hProcess, INFINITE);
	}

	CloseHandle(ret.hThread);
	CloseHandle(ret.hProcess);

	return true;
}
bool Win32Run(char *filename, char *arg, bool hide, bool wait)
{
	STARTUPINFO info;
	PROCESS_INFORMATION ret;
	char cmdline[MAX_SIZE];
	char name[MAX_PATH];
	// 引数チェック
	if (filename == NULL)
	{
		return false;
	}

	StrCpy(name, sizeof(name), filename);
	Trim(name);

	if (SearchStr(name, "\"", 0) == INFINITE)
	{
		if (arg == NULL)
		{
			Format(cmdline, sizeof(cmdline), "%s", name);
		}
		else
		{
			Format(cmdline, sizeof(cmdline), "%s %s", name, arg);
		}
	}
	else
	{
		if (arg == NULL)
		{
			Format(cmdline, sizeof(cmdline), "\"%s\"", name);
		}
		else
		{
			Format(cmdline, sizeof(cmdline), "\"%s\" %s", name, arg);
		}
	}

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	Trim(cmdline);

	if (CreateProcess(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW | CREATE_NEW_CONSOLE) | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &info, &ret) == FALSE)
	{
		return false;
	}

	if (wait)
	{
		WaitForSingleObject(ret.hProcess, INFINITE);
	}

	CloseHandle(ret.hThread);
	CloseHandle(ret.hProcess);

	return true;
}

// スレッド ID の取得
UINT Win32ThreadId()
{
	return GetCurrentThreadId();
}

// ファイル名の変更
bool Win32FileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	// 引数チェック
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char *old_name_a = CopyUniToStr(old_name);
		char *new_name_a = CopyUniToStr(new_name);
		bool ret = Win32FileRename(old_name_a, new_name_a);

		Free(old_name_a);
		Free(new_name_a);

		return ret;
	}

	// リネーム
	if (MoveFileW(old_name, new_name) == FALSE)
	{
		return false;
	}

	return true;
}
bool Win32FileRename(char *old_name, char *new_name)
{
	// 引数チェック
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	// リネーム
	if (MoveFile(old_name, new_name) == FALSE)
	{
		return false;
	}

	return true;
}

// EXE ファイルが存在しているディレクトリ名を取得する
void Win32GetExeDirW(wchar_t *name, UINT size)
{
	wchar_t exe_path[MAX_SIZE];
	wchar_t exe_dir[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	if (IsNt() == false)
	{
		char name_a[MAX_PATH];

		Win32GetExeDir(name_a, sizeof(name_a));

		StrToUni(name, size, name_a);

		return;
	}

	// EXE ファイル名を取得
	GetModuleFileNameW(NULL, exe_path, sizeof(exe_path));

	// ディレクトリ名を取得
	Win32GetDirFromPathW(exe_dir, sizeof(exe_dir), exe_path);

	UniStrCpy(name, size, exe_dir);
}
void Win32GetExeDir(char *name, UINT size)
{
	char exe_path[MAX_SIZE];
	char exe_dir[MAX_SIZE];
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	// EXE ファイル名を取得
	GetModuleFileName(NULL, exe_path, sizeof(exe_path));

	// ディレクトリ名を取得
	Win32GetDirFromPath(exe_dir, sizeof(exe_dir), exe_path);

	StrCpy(name, size, exe_dir);
}

// 終端の \ を抜く
void Win32NukuEnW(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t str[MAX_SIZE];
	int i;
	if (src)
	{
		UniStrCpy(str, sizeof(str), src);
	}
	else
	{
		UniStrCpy(str, sizeof(str), dst);
	}
	i = UniStrLen(str);
	if (str[i - 1] == L'\\')
	{
		str[i - 1] = 0;
	}
	UniStrCpy(dst, size, str);
}
void Win32NukuEn(char *dst, UINT size, char *src)
{
	char str[MAX_SIZE];
	int i;
	if (src)
	{
		StrCpy(str, sizeof(str), src);
	}
	else
	{
		StrCpy(str, sizeof(str), dst);
	}
	i = StrLen(str);
	if (str[i - 1] == '\\')
	{
		str[i - 1] = 0;
	}
	StrCpy(dst, size, str);
}

// ディレクトリ名をパスから取得
void Win32GetDirFromPathW(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t str[MAX_SIZE];
	int i,len;
	wchar_t c;
	wchar_t tmp[MAX_SIZE];
	int wp;
	if (src)
	{
		UniStrCpy(str, sizeof(str), src);
	}
	else
	{
		UniStrCpy(str, sizeof(str), dst);
	}
	Win32NukuEnW(str, sizeof(str), NULL);
	wp = 0;
	len = UniStrLen(str);
	dst[0] = 0;
	for (i = 0;i < len;i++)
	{
		c = str[i];
		switch (c)
		{
		case L'\\':
			tmp[wp] = 0;
			wp = 0;
			UniStrCat(dst, size, tmp);
			UniStrCat(dst, size, L"\\");
			break;
		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}
	Win32NukuEnW(dst, size, NULL);
}
void Win32GetDirFromPath(char *dst, UINT size, char *src)
{
	char str[MAX_SIZE];
	int i,len;
	char c;
	char tmp[MAX_SIZE];
	int wp;
	if (src)
	{
		StrCpy(str, sizeof(str), src);
	}
	else
	{
		StrCpy(str, sizeof(str), dst);
	}
	Win32NukuEn(str, sizeof(str), NULL);
	wp = 0;
	len = StrLen(str);
	dst[0] = 0;
	for (i = 0;i < len;i++)
	{
		c = str[i];
		switch (c)
		{
		case '\\':
			tmp[wp] = 0;
			wp = 0;
			StrCat(dst, size, tmp);
			StrCat(dst, size, "\\");
			break;
		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}
	Win32NukuEn(dst, size, NULL);
}

// ディレクトリの削除
bool Win32DeleteDirW(wchar_t *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char *name_a = CopyUniToStr(name);
		bool ret = Win32DeleteDir(name_a);

		Free(name_a);

		return ret;
	}

	if (RemoveDirectoryW(name) == FALSE)
	{
		return false;
	}
	return true;
}
bool Win32DeleteDir(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (RemoveDirectory(name) == FALSE)
	{
		return false;
	}
	return true;
}

// ディレクトリの作成
bool Win32MakeDirW(wchar_t *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char *name_a = CopyUniToStr(name);
		bool ret = Win32MakeDir(name_a);

		Free(name_a);

		return ret;
	}

	if (CreateDirectoryW(name, NULL) == FALSE)
	{
		return false;
	}

	return true;
}
bool Win32MakeDir(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (CreateDirectory(name, NULL) == FALSE)
	{
		return false;
	}

	return true;
}

// ファイルの削除
bool Win32FileDeleteW(wchar_t *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		bool ret;
		char *name_a = CopyUniToStr(name);

		ret = Win32FileDelete(name_a);

		Free(name_a);

		return ret;
	}

	if (DeleteFileW(name) == FALSE)
	{
		return false;
	}
	return true;
}
bool Win32FileDelete(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	if (DeleteFile(name) == FALSE)
	{
		return false;
	}
	return true;
}

// ファイルのシーク
bool Win32FileSeek(void *pData, UINT mode, int offset)
{
	WIN32IO *p;
	DWORD ret;
	// 引数チェック
	if (pData == NULL)
	{
		return false;
	}
	if (mode != FILE_BEGIN && mode != FILE_END && mode != FILE_CURRENT)
	{
		return false;
	}

	p = (WIN32IO *)pData;
	ret = SetFilePointer(p->hFile, (LONG)offset, NULL, mode);
	if (ret == INVALID_SET_FILE_POINTER || ret == ERROR_NEGATIVE_SEEK)
	{
		return false;
	}
	return true;
}

// ファイルサイズの取得
UINT64 Win32FileSize(void *pData)
{
	WIN32IO *p;
	UINT64 ret;
	DWORD tmp;
	// 引数チェック
	if (pData == NULL)
	{
		return 0;
	}

	p = (WIN32IO *)pData;
	tmp = 0;
	ret = GetFileSize(p->hFile, &tmp);
	if (ret == (DWORD)-1)
	{
		return 0;
	}

	if (tmp != 0)
	{
		ret += (UINT64)tmp * 4294967296ULL;
	}

	return ret;
}

// ファイルに書き込む
bool Win32FileWrite(void *pData, void *buf, UINT size)
{
	WIN32IO *p;
	DWORD write_size;
	// 引数チェック
	if (pData == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	p = (WIN32IO *)pData;
	if (WriteFile(p->hFile, buf, size, &write_size, NULL) == FALSE)
	{
		return false;
	}

	if (write_size != size)
	{
		return false;
	}

	return true;
}

// ファイルから読み込む
bool Win32FileRead(void *pData, void *buf, UINT size)
{
	WIN32IO *p;
	DWORD read_size;
	// 引数チェック
	if (pData == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	p = (WIN32IO *)pData;
	if (ReadFile(p->hFile, buf, size, &read_size, NULL) == FALSE)
	{
		return false;
	}

	if (read_size != size)
	{
		return false;
	}
	
	return true;;
}

// ファイルを閉じる
void Win32FileClose(void *pData, bool no_flush)
{
	WIN32IO *p;
	// 引数チェック
	if (pData == NULL)
	{
		return;
	}

	p = (WIN32IO *)pData;
	if (p->WriteMode && no_flush == false)
	{
		FlushFileBuffers(p->hFile);
	}
	CloseHandle(p->hFile);
	p->hFile = NULL;

	// メモリ解放
	Win32MemoryFree(p);
}

// ファイルをフラッシュする
void Win32FileFlush(void *pData)
{
	WIN32IO *p;
	// 引数チェック
	if (pData == NULL)
	{
		return;
	}

	p = (WIN32IO *)pData;
	if (p->WriteMode)
	{
		FlushFileBuffers(p->hFile);
	}
}

// ファイルを開く
void *Win32FileOpenW(wchar_t *name, bool write_mode, bool read_lock)
{
	WIN32IO *p;
	HANDLE h;
	DWORD lock_mode;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	if (IsNt() == false)
	{
		void *ret;
		char *name_a = CopyUniToStr(name);

		ret = Win32FileOpen(name_a, write_mode, read_lock);

		Free(name_a);

		return ret;
	}

	if (write_mode)
	{
		lock_mode = FILE_SHARE_READ;
	}
	else
	{
		if (read_lock == false)
		{
			lock_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
		}
		else
		{
			lock_mode = FILE_SHARE_READ;
		}
	}

	// ファイルを開く
	h = CreateFileW(name,
		(write_mode ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ),
		lock_mode,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		UINT ret = GetLastError();
		// 失敗
		return NULL;
	}

	// メモリ確保
	p = Win32MemoryAlloc(sizeof(WIN32IO));
	// ハンドル格納
	p->hFile = h;

	p->WriteMode = write_mode;

	return (void *)p;
}
void *Win32FileOpen(char *name, bool write_mode, bool read_lock)
{
	WIN32IO *p;
	HANDLE h;
	DWORD lock_mode;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	if (write_mode)
	{
		lock_mode = FILE_SHARE_READ;
	}
	else
	{
		if (read_lock == false)
		{
			lock_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
		}
		else
		{
			lock_mode = FILE_SHARE_READ;
		}
	}

	// ファイルを開く
	h = CreateFile(name,
		(write_mode ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ),
		lock_mode,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		UINT ret = GetLastError();
		// 失敗
		return NULL;
	}

	// メモリ確保
	p = Win32MemoryAlloc(sizeof(WIN32IO));
	// ハンドル格納
	p->hFile = h;

	p->WriteMode = write_mode;

	return (void *)p;
}

// ファイルを作成する
void *Win32FileCreateW(wchar_t *name)
{
	WIN32IO *p;
	HANDLE h;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	if (IsNt() == false)
	{
		void *ret;
		char *name_a = CopyUniToStr(name);

		ret = Win32FileCreate(name_a);

		Free(name_a);

		return ret;
	}

	// ファイルを作成する
	h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN,
			NULL);
		if (h == INVALID_HANDLE_VALUE)
		{
			return NULL;
		}
	}

	// メモリ確保
	p = Win32MemoryAlloc(sizeof(WIN32IO));
	// ハンドル格納
	p->hFile = h;

	p->WriteMode = true;

	return (void *)p;
}
void *Win32FileCreate(char *name)
{
	WIN32IO *p;
	HANDLE h;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	// ファイルを作成する
	h = CreateFile(name, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		h = CreateFile(name, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN,
			NULL);
		if (h == INVALID_HANDLE_VALUE)
		{
			return NULL;
		}
	}

	// メモリ確保
	p = Win32MemoryAlloc(sizeof(WIN32IO));
	// ハンドル格納
	p->hFile = h;

	p->WriteMode = true;

	return (void *)p;
}

#define	SIZE_OF_CALLSTACK_SYM	10000
#define	CALLSTACK_DEPTH			12

// コールスタックの取得
CALLSTACK_DATA *Win32GetCallStack()
{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
	DWORD current_eip32 = 0, current_esp32 = 0, current_ebp32 = 0;
	UINT64 current_eip = 0, current_esp = 0, current_ebp = 0;
	STACKFRAME64 sf;
	CALLSTACK_DATA *cs = NULL, *s;

#ifdef	CPU_64
	CONTEXT context;
#endif	// CPU_64

	bool ret;
	UINT depth = 0;

#ifndef	CPU_64
	// レジスタ取得 (32 bit)
	__asm
	{
		mov current_esp32, esp
		mov current_ebp32, ebp
	};

	current_eip32 = (DWORD)Win32GetCallStack;

	current_eip = (UINT64)current_eip32;
	current_esp = (UINT64)current_esp32;
	current_ebp = (UINT64)current_ebp32;
#else	// CPU_64
	// レジスタ取得 (64 bit)
	Zero(&context, sizeof(context));
	context.ContextFlags = CONTEXT_FULL;
	RtlCaptureContext(&context);
#endif	// CPU_64

	Zero(&sf, sizeof(sf));

#ifndef	CPU_64
	sf.AddrPC.Offset = current_eip;
	sf.AddrStack.Offset = current_esp;
	sf.AddrFrame.Offset = current_ebp;
#else	// CPU_64
	sf.AddrPC.Offset = context.Rip;
	sf.AddrStack.Offset = context.Rsp;
	sf.AddrFrame.Offset = context.Rsp;
#endif	// CPU_64

	sf.AddrPC.Mode = AddrModeFlat;
	sf.AddrStack.Mode = AddrModeFlat;
	sf.AddrFrame.Mode = AddrModeFlat;

	while (true)
	{
		DWORD type = IMAGE_FILE_MACHINE_I386;

#ifdef	CPU_64
		type = IMAGE_FILE_MACHINE_AMD64;
#endif	// CPU_64

		if ((depth++) >= CALLSTACK_DEPTH)
		{
			break;
		}

#ifndef	CPU_64
		ret = StackWalk64(type,
			hCurrentProcessHandle,
			GetCurrentThread(),
			&sf,
			NULL, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);
#else	// CPU_64
		ret = StackWalk64(type,
			hCurrentProcessHandle,
			GetCurrentThread(),
			&sf,
			&context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);
#endif	// CPU_64
		if (ret == false || sf.AddrFrame.Offset == 0)
		{
			break;
		}

		if (cs == NULL)
		{
			cs = OSMemoryAlloc(sizeof(CALLSTACK_DATA));
			s = cs;
		}
		else
		{
			s->next = OSMemoryAlloc(sizeof(CALLSTACK_DATA));
			s = s->next;
		}
		s->symbol_cache = false;
		s->next = NULL;
		s->offset = sf.AddrPC.Offset;
		s->disp = 0;
		s->name = NULL;
		s->line = 0;
		s->filename[0] = 0;
	}

	return cs;
#else	// WIN32_NO_DEBUG_HELP_DLL
	return NULL;
#endif	// WIN32_NO_DEBUG_HELP_DLL
}

// コールスタックからシンボル情報を取得
bool Win32GetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
#ifdef	WIN32_NO_DEBUG_HELP_DLL
	return false;
#else	// WIN32_NO_DEBUG_HELP_DLL
	UINT64 disp;
	UINT disp32, len;
	IMAGEHLP_SYMBOL64 *sym;
	IMAGEHLP_LINE64 line;
	char tmp[MAX_PATH];
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	if (s->symbol_cache)
	{
		return true;
	}

	sym = OSMemoryAlloc(SIZE_OF_CALLSTACK_SYM);
	sym->SizeOfStruct = SIZE_OF_CALLSTACK_SYM;
	sym->MaxNameLength = SIZE_OF_CALLSTACK_SYM - sizeof(IMAGEHLP_SYMBOL64);

	if (SymGetSymFromAddr64(hCurrentProcessHandle, s->offset, &disp, sym))
	{
		s->disp = disp;
		s->name = OSMemoryAlloc((UINT)strlen(sym->Name) + 1);
		lstrcpy(s->name, sym->Name);
	}
	else
	{
		s->disp = 0;
		s->name = NULL;
	}

	Zero(&line, sizeof(line));
	line.SizeOfStruct = sizeof(line);
	if (SymGetLineFromAddr64(hCurrentProcessHandle, s->offset, &disp32, &line))
	{
		disp = (UINT64)disp32;
		s->line = line.LineNumber;
		lstrcpy(s->filename, line.FileName);
		Win32GetDirFromPath(tmp, sizeof(tmp), s->filename);
		len = lstrlen(tmp);
		lstrcpy(tmp, &s->filename[len + 1]);
		lstrcpy(s->filename, tmp);
	}
	else
	{
		s->line = 0;
		s->filename[0] = 0;
	}

	OSMemoryFree(sym);

	s->symbol_cache = true;

	return true;
#endif	// WIN32_NO_DEBUG_HELP_DLL
}

// デフォルトの Win32 スレッド
DWORD CALLBACK Win32DefaultThreadProc(void *param)
{
	WIN32THREADSTARTUPINFO *info = (WIN32THREADSTARTUPINFO *)param;
	// 引数チェック
	if (info == NULL)
	{
		return 0;
	}

	Win32InitNewThread();

	// スレッド関数の呼び出し
	info->thread_proc(info->thread, info->param);

	// 参照の解放
	ReleaseThread(info->thread);

	Win32MemoryFree(info);

	FreeOpenSSLThreadState();

	_endthreadex(0);
	return 0;
}

// スレッドの終了を待機
bool Win32WaitThread(THREAD *t)
{
	WIN32THREAD *w;
	// 引数チェック
	if (t == NULL)
	{
		return false;
	}
	w = (WIN32THREAD *)t->pData;
	if (w == NULL)
	{
		return false;
	}

	// スレッドイベントを待機する
	if (WaitForSingleObject(w->hThread, INFINITE) == WAIT_OBJECT_0)
	{
		// スレッドがシグナル状態になった
		return true;
	}

	// 待機失敗 (タイムアウト等)
	return false;
}

// スレッドの解放
void Win32FreeThread(THREAD *t)
{
	WIN32THREAD *w;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}
	w = (WIN32THREAD *)t->pData;
	if (w == NULL)
	{
		return;
	}

	// ハンドルを閉じる
	CloseHandle(w->hThread);

	// メモリ解放
	Win32MemoryFree(t->pData);
	t->pData = NULL;
}

// スレッドの初期化
bool Win32InitThread(THREAD *t)
{
	WIN32THREAD *w;
	HANDLE hThread;
	DWORD thread_id;
	WIN32THREADSTARTUPINFO *info;
	// 引数チェック
	if (t == NULL)
	{
		return false;
	}
	if (t->thread_proc == NULL)
	{
		return false;
	}

	// スレッドデータ生成
	w = Win32MemoryAlloc(sizeof(WIN32THREAD));

	// 起動情報生成
	info = Win32MemoryAlloc(sizeof(WIN32THREADSTARTUPINFO));
	info->param = t->param;
	info->thread_proc = t->thread_proc;
	info->thread = t;
	AddRef(t->ref);

	// スレッド作成
	t->pData = w;
	hThread = (HANDLE)_beginthreadex(NULL, 0, Win32DefaultThreadProc, info, 0, &thread_id);
	if (hThread == NULL)
	{
		// スレッド作成失敗
		t->pData = NULL;
		Release(t->ref);
		Win32MemoryFree(info);
		Win32MemoryFree(w);
		return false;
	}

	// スレッド情報の保存
	w->hThread = hThread;
	w->thread_id = thread_id;

	return true;
}

// Win32 用ライブラリの初期化
void Win32Init()
{
	INITCOMMONCONTROLSEX c;
	OSVERSIONINFO os;

	// Windows NT かどうか取得する
	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);
	GetVersionEx(&os);

	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		// NT 系
		win32_is_nt = true;
	}
	else
	{
		// 9x 系
		win32_is_nt = false;
	}

	// stdout を開く
	if (hstdout == INVALID_HANDLE_VALUE)
	{
		hstdout = GetStdHandle(STD_OUTPUT_HANDLE);
	}

	// stdin を開く
	if (hstdin == INVALID_HANDLE_VALUE)
	{
		hstdin = GetStdHandle(STD_INPUT_HANDLE);
	}

	Win32InitNewThread();

	CoInitialize(NULL);

	InitializeCriticalSection(&fasttick_lock);

#ifdef	WIN32_USE_HEAP_API_FOR_MEMORY
	use_heap_api = true;
#else	// WIN32_USE_HEAP_API_FOR_MEMORY
	use_heap_api = false;
#endif	// WIN32_USE_HEAP_API_FOR_MEMORY

	if (MayaquaIsDotNetMode())
	{
		// .NET API 内からヒープ関係の API を呼び出すとクラッシュする
		use_heap_api = false;
	}

	if (IsNt() == false)
	{
		// Win9x ではヒープ関係の API は使用しない
		use_heap_api = false;
	}

	if (use_heap_api)
	{
		heap_handle = HeapCreate(0, 0, 0);
	}

	// プロセス擬似ハンドルの取得
	hCurrentProcessHandle = GetCurrentProcess();

	// カレントディレクトリの初期化
	// Win32InitCurrentDir(); /* 行わない */

	// シンボルハンドラの初期化
	if (IsMemCheck())
	{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
		SymInitialize(hCurrentProcessHandle, NULL, TRUE);
#endif	// WIN32_NO_DEBUG_HELP_DLL
	}

	// Common Control の初期化
	Zero(&c, sizeof(INITCOMMONCONTROLSEX));
	c.dwSize = sizeof(INITCOMMONCONTROLSEX);
	c.dwICC = ICC_ANIMATE_CLASS | ICC_BAR_CLASSES | ICC_COOL_CLASSES |
		ICC_DATE_CLASSES | ICC_HOTKEY_CLASS | ICC_INTERNET_CLASSES |
		ICC_LISTVIEW_CLASSES | ICC_NATIVEFNTCTL_CLASS |
		ICC_PAGESCROLLER_CLASS | ICC_PROGRESS_CLASS |
		ICC_TAB_CLASSES | ICC_TREEVIEW_CLASSES | ICC_UPDOWN_CLASS | ICC_USEREX_CLASSES |
		ICC_WIN95_CLASSES;
	InitCommonControlsEx(&c);
}

// Win32 用ライブラリの解放
void Win32Free()
{
	// シンボルハンドラを閉じる
	if (IsMemCheck())
	{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
		SymCleanup(hCurrentProcessHandle);
#endif	// WIN32_NO_DEBUG_HELP_DLL
	}

	if (use_heap_api)
	{
		HeapDestroy(heap_handle);
		heap_handle = NULL;
	}

	CoUninitialize();

	DeleteCriticalSection(&fasttick_lock);
}

// メモリ確保
void *Win32MemoryAlloc(UINT size)
{
	if (use_heap_api)
	{
		return HeapAlloc(heap_handle, 0, size);
	}
	else
	{
		return malloc(size);
	}
}

// メモリ再確保
void *Win32MemoryReAlloc(void *addr, UINT size)
{
	if (use_heap_api)
	{
		return HeapReAlloc(heap_handle, 0, addr, size);
	}
	else
	{
		return realloc(addr, size);
	}
}

// メモリ確報
void Win32MemoryFree(void *addr)
{
	if (use_heap_api)
	{
		HeapFree(heap_handle, 0, addr);
	}
	else
	{
		free(addr);
	}
}

// システムタイマの取得
UINT Win32GetTick()
{
	return (UINT)timeGetTime();
}

// システム時刻の取得
void Win32GetSystemTime(SYSTEMTIME *system_time)
{
	// システム時刻の取得
	GetSystemTime(system_time);
}

// 32bit 整数のインクリメント
void Win32Inc32(UINT *value)
{
	InterlockedIncrement(value);
}

// 32bit 整数のデクリメント
void Win32Dec32(UINT *value)
{
	InterlockedDecrement(value);
}

// スレッドの休止
void Win32Sleep(UINT time)
{
	Sleep(time);
}

// ロックの作成
LOCK *Win32NewLock()
{
	// メモリ確保
	LOCK *lock = Win32MemoryAlloc(sizeof(LOCK));

	// クリティカルセクション確保
	CRITICAL_SECTION *critical_section = Win32MemoryAlloc(sizeof(CRITICAL_SECTION));

	if (lock == NULL || critical_section == NULL)
	{
		Win32MemoryFree(lock);
		Win32MemoryFree(critical_section);
		return NULL;
	}

	// クリティカルセクション初期化
	InitializeCriticalSection(critical_section);

	lock->pData = (void *)critical_section;
	lock->Ready = true;

	return lock;
}

// ロック
bool Win32Lock(LOCK *lock)
{
	CRITICAL_SECTION *critical_section;
	if (lock->Ready == false)
	{
		// 状態が不正
		return false;
	}

	// クリティカルセクションに入る
	critical_section = (CRITICAL_SECTION *)lock->pData;
	EnterCriticalSection(critical_section);

	return true;
}

// ロック解除
void Win32Unlock(LOCK *lock)
{
	Win32UnlockEx(lock, false);
}
void Win32UnlockEx(LOCK *lock, bool inner)
{
	CRITICAL_SECTION *critical_section;
	if (lock->Ready == false && inner == false)
	{
		// 状態が不正
		return;
	}

	// クリティカルセクションから出る
	critical_section = (CRITICAL_SECTION *)lock->pData;
	LeaveCriticalSection(critical_section);
}

// ロックの削除
void Win32DeleteLock(LOCK *lock)
{
	CRITICAL_SECTION *critical_section;
	// Ready フラグを安全に解除する
	Win32Lock(lock);
	lock->Ready = false;
	Win32UnlockEx(lock, true);

	// クリティカルセクションの削除
	critical_section = (CRITICAL_SECTION *)lock->pData;
	DeleteCriticalSection(critical_section);

	// メモリ解放
	Win32MemoryFree(critical_section);
	Win32MemoryFree(lock);
}

// イベントの初期化
void Win32InitEvent(EVENT *event)
{
	// 自動リセットイベントの作成
	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	event->pData = hEvent;
}

// イベントのセット
void Win32SetEvent(EVENT *event)
{
	HANDLE hEvent = (HANDLE)event->pData;
	if (hEvent == NULL)
	{
		return;
	}

	SetEvent(hEvent);
}

// イベントのリセット
void Win32ResetEvent(EVENT *event)
{
	HANDLE hEvent = (HANDLE)event->pData;
	if (hEvent == NULL)
	{
		return;
	}

	ResetEvent(hEvent);
}

// イベントを待機する
bool Win32WaitEvent(EVENT *event, UINT timeout)
{
	HANDLE hEvent = (HANDLE)event->pData;
	UINT ret;
	if (hEvent == NULL)
	{
		return false;
	}

	// オブジェクトを待機
	ret = WaitForSingleObject(hEvent, timeout);
	if (ret == WAIT_TIMEOUT)
	{
		// タイムアウト
		return false;
	}
	else
	{
		// シグナル状態
		return true;
	}
}

// イベントの解放
void Win32FreeEvent(EVENT *event)
{
	HANDLE hEvent = (HANDLE)event->pData;
	if (hEvent == NULL)
	{
		return;
	}

	CloseHandle(hEvent);
}

// Win32 専用の高速な 64 bit Tick 取得関数
UINT64 Win32FastTick64()
{
	static UINT last_tick = 0;
	static UINT counter = 0;
	UINT64 ret;
	UINT tick;

	EnterCriticalSection(&fasttick_lock);

	// 現在の tick 値を取得する
	tick = Win32GetTick();

	if (last_tick > tick)
	{
		// 前回取得した tick 値のほうが今回取得した値よりも大きい場合
		// カウンタが 1 回りしたと考えることができる

		counter++;
	}

	last_tick = tick;

	ret = (UINT64)tick + (UINT64)counter * 4294967296ULL;

	LeaveCriticalSection(&fasttick_lock);

	if (start_tick == 0)
	{
		start_tick = ret;
		ret = 0;
	}
	else
	{
		ret -= start_tick;
	}

	return ret + 1;
}

// 文字列をコンソールから読み込む
bool Win32InputW(wchar_t *str, UINT size)
{
	bool ret = false;
	// 引数チェック
	if (str == NULL)
	{
		return false;
	}
	if (size == 0)
	{
		size = 0x7fffffff;
	}

	if (str == NULL || size <= sizeof(wchar_t))
	{
		if (str != NULL)
		{
			Zero(str, size);
		}

		return Win32InputFromFileW(NULL, 0);
	}

	if (IsNt())
	{
		DWORD read_size = 0;

		if (ReadConsoleW(hstdin, str, (size - sizeof(wchar_t)), &read_size, NULL))
		{
			str[read_size] = 0;

			UniTrimCrlf(str);

			ret = true;
		}
		else
		{
			ret = Win32InputFromFileW(str, size);
		}
	}
	else
	{
		DWORD read_size = 0;
		UINT a_size = size / sizeof(wchar_t) + 16;
		char *a;

		a = ZeroMalloc(a_size);

		if (ReadConsoleA(hstdin, a, a_size - 1, &read_size, NULL))
		{
			a[read_size] = 0;

			StrToUni(str, size, a);

			UniTrimCrlf(str);

			ret = true;
		}
		else
		{
			ret = Win32InputFromFileW(str, size);
		}

		Free(a);
	}

	return ret;
}
// 1 行を標準入力から取得
bool Win32InputFromFileW(wchar_t *str, UINT size)
{
	char *a;
	if (str == NULL)
	{
		wchar_t tmp[MAX_SIZE];
		Win32InputFromFileW(tmp, sizeof(tmp));
		return false;
	}

	a = Win32InputFromFileLineA();
	if (a == NULL)
	{
		UniStrCpy(str, size, L"");
		return false;
	}

	UtfToUni(str, size, a);

	UniTrimCrlf(str);

	Free(a);

	return true;
}
char *Win32InputFromFileLineA()
{
	BUF *b = NewBuf();
	char zero = 0;
	char *ret = NULL;
	bool ok = true;

	while (true)
	{
		char c;
		UINT read_size = 0;

		if (ReadFile(hstdin, &c, 1, &read_size, NULL) == false)
		{
			ok = false;
			break;
		}
		if (read_size != 1)
		{
			ok = false;
			break;
		}

		WriteBuf(b, &c, 1);

		if (c == 10)
		{
			break;
		}
	}

	WriteBuf(b, &zero, 1);

	if (ok)
	{
		ret = CopyStr(b->Buf);
	}

	FreeBuf(b);

	return ret;
}

// 文字列をコンソールにプリントする
void Win32PrintW(wchar_t *str)
{
	DWORD write_size = 0;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	if (IsNt())
	{
		if (WriteConsoleW(hstdout, str, UniStrLen(str), &write_size, NULL) == false)
		{
			Win32PrintToFileW(str);
		}
	}
	else
	{
		char *ansi_str = CopyUniToStr(str);

		if (WriteConsoleA(hstdout, ansi_str, StrLen(ansi_str), &write_size, NULL) == false)
		{
			Win32PrintToFileW(str);
		}

		Free(ansi_str);
	}
}
void Win32PrintToFileW(wchar_t *str)
{
	char *utf;
	DWORD size = 0;
	// 引数チェック
	if (str == NULL)
	{
		return;
	}

	utf = CopyUniToUtf(str);

	WriteFile(hstdout, utf, StrLen(utf), &size, NULL);

	Free(utf);
}


#endif	// WIN32


