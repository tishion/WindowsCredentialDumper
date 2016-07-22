// CredDump.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <wincred.h>
#include <vector>

#define DUMP_STRING(p, name)   do {                                         \
        if (p->name) _tprintf(_T("  % 18s: %s\r\n"), _T(#name), p->name);   \
        else _tprintf(_T("  % 18s:\r\n"), _T(#name));                          \
} while (0);

#define DUMP_DWORD(p, name) do {                                            \
        _tprintf(_T("  % 18s: 0x%08X\r\n"), _T(#name), pCred->name);        \
    } while (0);

void DumpBinary(unsigned char* p, DWORD count)
{
    if (!p || !count)
    {
        _tprintf(_T("\r\n"));

    }

    if (p)
    {
        std::vector<unsigned char> row;
        for (int i = 0; i < count;)
        {
            row.push_back(*(p + i++));
            if (0 == i % 8)
            {
                _tprintf(_T("0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X | %c %c %c %c %c %c %c %c\r\n"),
                    row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7],
                    isprint(row[0]) ? row[0] : _T('.'),
                    isprint(row[1]) ? row[1] : _T('.'),
                    isprint(row[2]) ? row[2] : _T('.'),
                    isprint(row[3]) ? row[3] : _T('.'),
                    isprint(row[4]) ? row[4] : _T('.'),
                    isprint(row[5]) ? row[5] : _T('.'),
                    isprint(row[6]) ? row[6] : _T('.'),
                    isprint(row[7]) ? row[7] : _T('.'));
                row.clear();   
                _tprintf(_T("                      "));
            }
        }

        if (!row.empty())
        {
            row.resize(8, 0);
            _tprintf(_T("0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X | %c %c %c %c %c %c %c %c\r\n"),
                row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7],
                isprint(row[0]) ? row[0] : _T('.'),
                isprint(row[1]) ? row[1] : _T('.'),
                isprint(row[2]) ? row[2] : _T('.'),
                isprint(row[3]) ? row[3] : _T('.'),
                isprint(row[4]) ? row[4] : _T('.'),
                isprint(row[5]) ? row[5] : _T('.'),
                isprint(row[6]) ? row[6] : _T('.'),
                isprint(row[7]) ? row[7] : _T('.'));
            row.clear();
        }
    }
}

void DumpCredential(PCREDENTIAL pCred)
{
    if (pCred)
    {
        DUMP_STRING(pCred, TargetName);

        DUMP_STRING(pCred, UserName);

        DUMP_STRING(pCred, TargetAlias);

        DUMP_STRING(pCred, Comment);

        DUMP_DWORD(pCred, Flags);

        DUMP_DWORD(pCred, Type);

        DUMP_DWORD(pCred, Persist);

        DUMP_DWORD(pCred, AttributeCount);

        DUMP_DWORD(pCred, CredentialBlobSize);

        _tprintf(_T("      CredentialBlob: "));
        DumpBinary(pCred->CredentialBlob, pCred->CredentialBlobSize);
    }
}

void PrintHeader()
{
    _tprintf(
        _T("*=============================================================================*\r\n")
        _T("*              oooooo   oooooo     oooo   .oooooo.   oooooooooo.              *\r\n")
        _T("*               `888.    `888.     .8'   d8P'  `Y8b  `888'   `Y8b             *\r\n")
        _T("*                `888.   .8888.   .8'   888           888      888            *\r\n")
        _T("*                 `888  .8'`888. .8'    888           888      888            *\r\n")
        _T("*                  `888.8'  `888.8'     888           888      888            *\r\n")
        _T("*                   `888'    `888'      `88b    ooo   888     d88'            *\r\n")
        _T("*                    `8'      `8'        `Y8bood8P'  o888bood8P'              *\r\n")
        _T("*                                                                             *\r\n")
        _T("*                        Windows Credential Dumper (c) Sheen                  *\r\n")
        _T("*Usage:                                                                       *\r\n")
        _T("*    wcd [filter]                                                             *\r\n")
        _T("*E.G:                                                                         *\r\n")
        _T("*    wcd ms.outlook*                                                          *\r\n")
        _T("*=============================================================================*\r\n")
    );
}

LPCTSTR GetFilter(int argc, TCHAR *argv[])
{
    if (argc >= 2)
    {
        return argv[1];
    }

    return NULL;
}

int _tmain(int argc, TCHAR *argv[])
{
    PrintHeader();
    LPCTSTR pFilter = GetFilter(argc, argv);

    DWORD dwCount = 0;
    PCREDENTIAL* ppCredentialList = nullptr;
    BOOL bRet = FALSE;
    if (::CredEnumerate(pFilter, 0, &dwCount, &ppCredentialList))
    {
        if (dwCount <= 0)
        {
            _tprintf(_T("No credential found on current context.\r\n"));
        }

        for (int i = 0; i < dwCount; i++)
        {
            _tprintf(_T("--------- Credential: %d\r\n"), i);
            DumpCredential(ppCredentialList[i]);
            _tprintf(_T("\r\n"), i);
        }
    }
    else
    {
        _tprintf(_T("No credential exists matching the specified filter in current context."));
    }

    return 0;
}

