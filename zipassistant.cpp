// zipassistant.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <shlwapi.h>
#include <locale.h>
#include <io.h>
#include "zip.h"
#include "unzip.h"
#include "aes.h"

void AddFiles(HZIP hz, const TCHAR *lpPath)
{
	if (!hz || !lpPath || !wcslen(lpPath))
	{
		return;
	}

	static const TCHAR *lpDir = lpPath;
	TCHAR szFind[MAX_PATH] = {0};
	wcscpy(szFind, lpPath);
	wcscat(szFind, L"*.*");

	WIN32_FIND_DATA ffd;
	memset(&ffd, 0, sizeof(WIN32_FIND_DATA));

	HANDLE hFind = ::FindFirstFile(szFind, &ffd);
	if (INVALID_HANDLE_VALUE == hFind) return;

	while (TRUE)
	{
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (ffd.cFileName[0] != '.')
			{
				memset(szFind, 0, MAX_PATH);
				swprintf(szFind, L"%s%s\\", lpPath, ffd.cFileName);
				AddFiles(hz, szFind);
			}
		}
		else
		{
			TCHAR file[MAX_PATH] = {0}, zfn[MAX_PATH] = {0};
			swprintf(file, L"%s%s", lpPath, ffd.cFileName);

			if (wcsicmp(lpDir, lpPath))
			{
				int s = wcslen(lpDir);
				wcsncpy(zfn, &lpPath[s], wcslen(lpPath) - s);
				wcscat(zfn, ffd.cFileName);
			}
			else
			{
				wcscpy(zfn, ffd.cFileName);
			}

			ZipAdd(hz, zfn, file);
		}

		if (!FindNextFile(hFind, &ffd)) break;
	}

	FindClose(hFind);
}

ZRESULT AppendFile(const TCHAR *zipfn, const TCHAR *zename, const TCHAR *zefn)
{ 
	if (GetFileAttributes(zipfn)==0xFFFFFFFF || (zefn && GetFileAttributes(zefn)==0xFFFFFFFF)) 
		return ZR_NOFILE;

	// Expected size of the new zip will be the size of the old zip plus the size of the new file
	HANDLE hf=CreateFile(zipfn,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0); 
	if (hf==INVALID_HANDLE_VALUE) 
		return ZR_NOFILE; 

	DWORD size=GetFileSize(hf,0); 
	CloseHandle(hf);
	if (zefn!=0) 
	{
		hf=CreateFile(zefn,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0); 
		if (hf==INVALID_HANDLE_VALUE) 
			return ZR_NOFILE; 
		size+=GetFileSize(hf,0); 
		CloseHandle(hf);
	}

	size*=2; // just to be on the safe side.
	HZIP hzsrc=OpenZip(zipfn,0); 
	if (hzsrc==0) 
		return ZR_READ;
	HZIP hzdst=CreateZip(0,size,0); 
	if (hzdst==0) 
	{
		CloseZip(hzsrc); 
		return ZR_WRITE;
	}

	// hzdst is created in the system pagefile
	// Now go through the old zip, unzipping each item into a memory buffer, and adding it to the new one
	char *buf=0; 
	unsigned int bufsize=0; // we'll unzip each item into this memory buffer
	ZIPENTRY ze; 
	ZRESULT zr=GetZipItem(hzsrc,-1,&ze); 
	int numitems=ze.index; 
	if (zr!=ZR_OK) 
	{
		CloseZip(hzsrc); 
		CloseZip(hzdst); 
		return zr;
	}

	for (int i=0; i<numitems; i++)
	{ 
		zr=GetZipItem(hzsrc,i,&ze); 
		if (zr!=ZR_OK) 
		{
			CloseZip(hzsrc); 
			CloseZip(hzdst); 
			return zr;
		}
		if (wcsicmp(ze.name,zename)==0) 
			continue; // don't copy over the old version of the file we're changing
		if (ze.attr&FILE_ATTRIBUTE_DIRECTORY) 
		{
			zr=ZipAddFolder(hzdst,ze.name); 
			if (zr!=ZR_OK) 
			{
				CloseZip(hzsrc); 
				CloseZip(hzdst); 
				return zr;
			} 
			continue;
		}
		if (ze.unc_size>(long)bufsize) 
		{
			if (buf!=0) 
				delete[] buf;
			bufsize=ze.unc_size;
			buf=new char[bufsize];
			memset(buf, 0, bufsize);
		}
		zr=UnzipItem(hzsrc,i,buf,bufsize); 
		if (zr!=ZR_OK) 
		{
			CloseZip(hzsrc); 
			CloseZip(hzdst); 
			return zr;
		}
		zr=ZipAdd(hzdst,ze.name,buf,bufsize); 
		if (zr!=ZR_OK) 
		{
			CloseZip(hzsrc); 
			CloseZip(hzdst); 
			return zr;
		}
		bufsize = 0;
	}

	delete[] buf;

	// Now add the new file
	if (zefn!=0) 
	{
		zr=ZipAdd(hzdst,zename,zefn); 
		if (zr!=ZR_OK) 
		{
			CloseZip(hzsrc); 
			CloseZip(hzdst); 
			return zr;
		}
	}

	zr=CloseZip(hzsrc); 
	if (zr!=ZR_OK) 
	{
		CloseZip(hzdst); 
		return zr;
	}

	//
	// The new file has been put into pagefile memory. Let's store it to disk, overwriting the original zip
	zr=ZipGetMemory(hzdst,(void**)&buf,&size); 
	if (zr!=ZR_OK) 
	{
		CloseZip(hzdst); 
		return zr;
	}

	hf=CreateFile(zipfn,GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0); 
	if (hf==INVALID_HANDLE_VALUE) 
	{
		CloseZip(hzdst); 
		return ZR_WRITE;
	}

	DWORD writ; 
	WriteFile(hf,buf,size,&writ,0); 
	CloseHandle(hf);

	zr=CloseZip(hzdst); 
	if (zr!=ZR_OK) 
		return zr;

	return ZR_OK;
}

BOOL IsPicture(const TCHAR *filename)
{
	const TCHAR *suf = wcsrchr(filename, '.');
	if (!wcsicmp(suf, L".png") || !wcsicmp(suf, L".jpg") || !wcsicmp(suf, L".jpeg") 
		|| !wcsicmp(suf, L".bmp") || !wcsicmp(suf, L".tif") || !wcsicmp(suf, L".tiff"))
	{
		return TRUE;
	}

	return FALSE;
}

const TCHAR *getFileName(TCHAR *filename, TCHAR *name)
{
	TCHAR *suf = wcsrchr(filename, '\\');

	if (!suf)
	{
		wcscpy(name, filename);
	}
	else
	{
		wcscpy(name, &suf[1]);
	}

	return name;
}

const TCHAR *getNewName(TCHAR *filename, TCHAR *name)
{
	TCHAR *suf = wcsrchr(filename, '\\');

	if (!suf)
	{
		swprintf(name, L".%ls", filename);
	}
	else
	{
		int l = wcslen(filename) - wcslen(suf) + 1;
		wcsncpy(name, filename, l);
		name[l] = '.';
		wcscat(name, &suf[1]);
	}

	return name;
}

void ClearTemp()
{
	int i = 0;
	char fmt[6][6] = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"};

	while (i < 6)
	{
		char tmp[MAX_PATH] = {0};
		sprintf(tmp, "%s\\DDECF6B7F103CFC11B2%s", getenv("TEMP"), fmt[i]);
		if (!_access(tmp, 0))
		{
			remove(tmp);
		}
		i++;
	}
}

void FinishCrypt(HANDLE hFile, HANDLE hNewFile, char* Buff1, char* Buff2, const TCHAR *file, const TCHAR *tmp)
{
	CloseHandle(hFile);  
	CloseHandle(hNewFile);  

	free(Buff1);
	free(Buff2);

	if (!_wremove(file))
	{
		_wrename(tmp, file);
	}
}

int EncryptZip(TCHAR *filename, const char *password)  
{  
	if (!filename || !password || !strlen(password))
	{
		return 1;
	}

	DWORD FileSize;  
	HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);  
	if (hFile == INVALID_HANDLE_VALUE)  
	{  
		CloseHandle(hFile);  
		return -1;
	}  

	FileSize = GetFileSize(hFile, NULL);  
	if (FileSize == INVALID_FILE_SIZE)  
	{  
		CloseHandle(hFile);  
		return 1;
	}  

	//动态分配待加密字符串  
	char * Buff1 = (char*)malloc(sizeof(char) * FileSize);
	memset(Buff1, 0, sizeof(Buff1)); 

	DWORD dwSizeOfRead = 0;  
	BOOL b = ReadFile(hFile, Buff1, FileSize, &dwSizeOfRead, NULL);  
	//读取文件内容  
	if ((dwSizeOfRead != FileSize) || (!b))  
	{  
		CloseHandle(hFile);  
		free(Buff1);
		return 1;
	}  

	//字符串补位操作  
	int add;  
	if (FileSize / 16 == 0)  
		add = 16;  
	else  
		add = 16 - FileSize % 16;  

	//动态分配补位后待加密字符串  
	char * Buff2 = (char*) malloc(sizeof(char) * (FileSize + add));  
	memset(Buff2, 0, sizeof(Buff2));  

	//进行补齐  
	for(int i = 0; i < FileSize + add; i++)  
	{  
		if(i < FileSize)  
			Buff2[i] = Buff1[i];  
		else  
			Buff2[i] = (char)add;  
	}  

	//加密操作  
	//Aes aes(16, (unsigned char *)password);
	Aes aes(password);
	TCHAR tmp[MAX_PATH] = {0};

	//将缓存区里面的数据加密,放入新的缓存区里面  
	HANDLE hNewFile = CreateFile(getNewName(filename, tmp), 
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);  
	DWORD count = 0;  
	char Temp1[16];  
	char Temp2[16];  

	while (count <= FileSize)  
	{  
		memset(Temp1, 0 ,sizeof(Temp1));  
		memset(Temp2, 0, sizeof(Temp2));  
		for (int i = 0; i <=15; i++)  
			Temp1[i] = Buff2[i + count];  
		aes.Cipher((unsigned char*)Temp1, (unsigned char*)Temp2);  
		//将新缓存区的数据写入新的文件里面  
		DWORD dwSizeOfWrite = 0;  
		WriteFile(hNewFile, Temp2, sizeof(Temp2), &dwSizeOfWrite, 0);  
		SetFilePointer(hNewFile, 0, NULL, FILE_END);  
		count +=16;  
	}  

	FinishCrypt(hFile, hNewFile, Buff1, Buff2, filename, tmp);

	return 0;  
}  

int DecryptZip(TCHAR *filename, const char *password)
{
	if (!filename || !password || !strlen(password))
	{
		return 1;
	}

	DWORD FileSize;  
	HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);  
	if (hFile == INVALID_HANDLE_VALUE)  
	{ 
		CloseHandle(hFile);  
		return -1;  
	}  

	//获取文件大小  
	FileSize = GetFileSize(hFile, NULL);  
	if (FileSize == INVALID_FILE_SIZE && FileSize % 16)  
	{  
		CloseHandle(hFile);  
		return 1; 
	}  

	//动态分配内存  
	char* Buff1 = (char*)malloc(sizeof(char) * FileSize);  
	char* Buff2 = (char*)malloc(sizeof(char) * FileSize);  
	DWORD dwSizeOfRead = 0;  
	BOOL b = ReadFile(hFile, Buff1, FileSize, &dwSizeOfRead, NULL); 

	//读取文件内容  
	if ((dwSizeOfRead != FileSize) || (!b))  
	{  
		CloseHandle(hFile);  
		free(Buff1);
		free(Buff2);
		return 2;  
	}  

	//解密操作  
	//Aes aes(16, (unsigned char *)password);  
	Aes aes(password);

	//将缓存区里面的数据加密,放入新的缓存区里面
	TCHAR tmp[MAX_PATH] = {0};
	HANDLE hNewFile = CreateFile(getNewName(filename, tmp), 
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);  
	DWORD count = 0;  
	char Temp1[16];  
	char Temp2[16];  
	for (int j = 0; j < FileSize / 16; j++)  
	{  
		memset(Temp1, 0 ,sizeof(Temp1));  
		memset(Temp2, 0, sizeof(Temp2));  
		for (int i = 0; i <=15; i++)  
			Temp1[i] = Buff1[i + count];  
		aes.InvCipher((unsigned char*)Temp1, (unsigned char*)Temp2);  
		if (j == FileSize / 16 - 1) //最后一次写文件  
		{  
			int add = (int)Temp2[15];//获得最后一次要写入的16-add个字节  
			DWORD dwSizeOfWrite = 0;  
			WriteFile(hNewFile, Temp2, sizeof(char) * (16 - add), &dwSizeOfWrite, 0);  
			SetFilePointer(hNewFile, 0, NULL, FILE_END);  
		}  
		else  
		{  
			//将新缓存区的数据写入新的文件里面  
			DWORD dwSizeOfWrite = 0;  
			WriteFile(hNewFile, Temp2, sizeof(Temp2), &dwSizeOfWrite, 0);  
			SetFilePointer(hNewFile, 0, NULL, FILE_END);  
			count +=16;  
		}  
	}  

	FinishCrypt(hFile, hNewFile, Buff1, Buff2, filename, tmp);

	return 0;  
}

char *U2A(const char *szSrc)
{
	CHAR *szRes = NULL;

	if (szSrc && strlen(szSrc))
	{
		int i = MultiByteToWideChar(CP_UTF8, 0, szSrc, -1, NULL, 0);
		WCHAR *wszSrc = new WCHAR[i + 1];
		if (!wszSrc)
		{
			return NULL;
		}

		memset(wszSrc, 0, i + 1);
		MultiByteToWideChar(CP_UTF8, 0, szSrc, -1, wszSrc, i);

		i = WideCharToMultiByte(CP_ACP, 0, wszSrc, -1, NULL, 0, NULL, NULL);
		szRes = new CHAR[i + 1];
		if (szRes)
		{
			memset(szRes, 0, i + 1);
			WideCharToMultiByte(CP_ACP, 0, wszSrc, -1, szRes, i, NULL, NULL);
		}

		delete []wszSrc;
	}

	return szRes;
}

// Usage: 
// zipassistant -c pack.zip dir/file
// zipassistant -a pack.zip file
// zipassistant -x pack.zip file
// zipassistant -u pack.zip
// zipassistant -l pack.zip
// zipassistant -r pack.zip file
// zipassistant -e pack.zip password
// zipassistant -d pack.zip password
int _tmain(int argc, _TCHAR* argv[])
{
	argc = 4;
	argv[0] = L"tmaker.exe";
	argv[1] = L"-a";
	argv[2] = L"\"D:\\UPX Shell\\test_psd\\20130712\\1_png\\\"";
	//argv[2] = L"G:\\Projects\\zipassistant\\Debug\\pkg.xcmb";
	//argv[3] = L"G:\\Projects\\zipassistant\\Debug\\pkg";
	//argv[3] = L"\"D:\\UPX Shell\\test_psd\\20130712\\1_png\\1.psd.png\"";
	//argv[3] = L"page.dat";
	//argv[3] = L"123123";
	//argv[3] = L"新建文本文档.txt";
	argv[3] = L"娴嬭瘯鍥";
	

	TCHAR opt[8] = {0}, file[2][MAX_PATH] = {0}, name[MAX_PATH] = {0};
	HZIP hz = NULL;

	setlocale(LC_CTYPE, "chs");

	//printf("options: %d\n", argc);
	//printf("%ls\n", argv[3]);
	char *szRes = U2A("娴嬭瘯鍥");
	printf("data:%s", szRes);
	delete [] szRes;

	if (3 > argc || 4 < argc)
	{
		printf("invalid parameter options.\n");
		return 1;
	}

	wcsncpy(opt, argv[1], 2);
	if (wcsicmp(opt, L"-c") && wcsicmp(opt, L"-a") && wcsicmp(opt, L"-x") && wcsicmp(opt, L"-u") 
		&& wcsicmp(opt, L"-l") && wcsicmp(opt, L"-r") && wcsicmp(opt, L"-e") && wcsicmp(opt, L"-d"))
	{
		printf("invalid options: %ls\n", opt);
		return 1;
	}

	for (int i = 2; i < argc; i++)
	{
		TCHAR buf[MAX_PATH] = {0};
		const TCHAR *p = argv[i];
		int j = '"' == p[0] ? 1 : 0, k = j;
		while (p[k]){k++;}
		wcsncpy(file[i - 2], &p[j], 0 < j ? wcslen(p) - 2 : k);
	}

	//printf("files: %ls, %ls\n", file[0], file[1]);

	if ('C' == opt[1] || 'c' == opt[1])
	{
		if (NULL == (hz = CreateZip(file[0], 0)))
		{
			printf("unable to compress \"%ls\"\n", file[0]);
			return 1;
		}

		if (PathIsDirectory(file[1]))
		{
			int s = wcslen(file[1]);
			if ('\\' != file[1][s - 1])
			{
				wcscat(file[1], L"\\");
			}
			AddFiles(hz, file[1]);
		}
		else
		{
			ZipAdd(hz, getFileName(file[1], name), file[1]);
		}

		printf("compress:%ls", file[1]);
	}

	if (('A' == opt[1] || 'a' == opt[1]) && !PathIsDirectory(file[1]))
	{
		TCHAR *suf = wcsrchr(file[1], '\\');
		if (!suf)
		{
			suf = wcsrchr(file[0], '\\');
			if (suf)
			{
				TCHAR tmp[MAX_PATH] = {0};
				wcsncpy(tmp, file[0], wcslen(file[0]) - wcslen(suf) + 1);
				wcscat(tmp, file[1]);
				return AppendFile(file[0], file[1], tmp);
			}
		}
		else
		{
			wcscpy(name, &suf[1]);
			return AppendFile(file[0], name, file[1]);
		}
	}

	if (('X' == opt[1] || 'x' == opt[1]) && !PathIsDirectory(file[1]))
	{
		return AppendFile(file[0], getFileName(file[1], name), 0);
	}

	if ('U' == opt[1] || 'u' == opt[1])
	{
		if (!(hz = OpenZip(file[0], 0)))
			return ZR_READ;

		TCHAR *suf = wcsrchr(file[0], '.');
		if (!suf)
		{
			wcscpy(name, L"\\");
		}
		else
		{
			wcsncpy(name, file[0], wcslen(file[0]) - wcslen(suf));
		}

		SetUnzipBaseDir(hz, name);

		ZIPENTRY ze;
		if (ZR_OK == GetZipItem(hz, -1, &ze))
		{
			int numitems = ze.index;
			for (int i = 0; i < numitems; i++)
			{
				if (ZR_OK != GetZipItem(hz, i, &ze))
				{
					continue;
				}

				UnzipItem(hz, i, ze.name);
				printf("%ls\n", ze.name);
			}
		}
	}

	if ('L' == opt[1] || 'l' == opt[1])
	{
		if (!(hz = OpenZip(file[0], 0)))
			return ZR_READ;

		ZIPENTRY ze;
		if (ZR_OK == GetZipItem(hz, -1, &ze) )
		{
			int numitems = ze.index;
			for (int zi = 0; zi < numitems; zi++)
			{ 
				GetZipItem(hz, zi, &ze);
				printf("%ls\n", ze.name);
			}
		}
	}

	if ('R' == opt[1] || 'r' == opt[1])
	{
		if (!(hz = OpenZip(file[0], 0)))
			return ZR_READ;

		int i;
		ZIPENTRY ze;
		if (ZR_OK == GetZipItem(hz, -1, &ze) && ZR_OK == FindZipItem(hz, file[1], true, &i, &ze))
		{
			UnzipItem(hz, i, ze.name);
			char *buf = new char[ze.unc_size + 1];
			memset(buf, 0, ze.unc_size + 1);
			UnzipItem(hz, i, buf, ze.unc_size);
			_wremove(ze.name);

			if (IsPicture(ze.name))
			{
				ClearTemp();

				char suf[10] = {0}, tmp[MAX_PATH] = {0};
				TCHAR *fs = wcsrchr(ze.name, '.');
				WideCharToMultiByte(CP_ACP, 0, fs, -1, suf, 10, 0, 0);
				sprintf(tmp, "%s\\DDECF6B7F103CFC11B2%s", getenv("TEMP"), suf);

				FILE *fp = fopen(tmp, "wb");
				if (fp)
				{
					fwrite(buf, 1, ze.unc_size, fp);
					fclose(fp);
				}

				printf("picture:%s", tmp);
			}
			else
			{
				char *szRes = U2A(buf);
				printf("data:%s", szRes);
				delete [] szRes;
			}

			delete[] buf;
		}
	}

	if ('E' == opt[1] || 'e' == opt[1])
	{
		char psswd[32] = {0};
		WideCharToMultiByte(CP_ACP, 0, file[1], -1, psswd, 32, 0, 0);
		EncryptZip(file[0], psswd);
	}

	if ('D' == opt[1] || 'd' == opt[1])
	{
		char psswd[32] = {0};
		WideCharToMultiByte(CP_ACP, 0, file[1], -1, psswd, 32, 0, 0);
		DecryptZip(file[0], psswd);
	}

	if (hz)
	{
		CloseZip(hz);
	}

	return 0;
}
