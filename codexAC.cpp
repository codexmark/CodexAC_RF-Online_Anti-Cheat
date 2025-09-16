#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>

// --- implementação minima de SHA-256 (codigo conhecido da comunidade já patrimonio da humanidade praticamente)
typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned long long uint64;


#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

struct SHA256_CTX {
    uint64 tot_len;
    uint32 len;
    uint8 block[64];
    uint32 h[8];
};

static const uint32 K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8 data[]) {
    uint32 a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for (i=0,j=0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->len = 0;
    ctx->tot_len = 0;
    ctx->h[0]=0x6a09e667; ctx->h[1]=0xbb67ae85; ctx->h[2]=0x3c6ef372; ctx->h[3]=0xa54ff53a;
    ctx->h[4]=0x510e527f; ctx->h[5]=0x9b05688c; ctx->h[6]=0x1f83d9ab; ctx->h[7]=0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8 data[], size_t len) {
    for (size_t i=0; i<len; ++i) {
        ctx->block[ctx->len++] = data[i];
        if (ctx->len == 64) {
            sha256_transform(ctx, ctx->block);
            ctx->tot_len += 512;
            ctx->len = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8 hash[32]) {
    uint32 i = ctx->len;

      // Pad
    if (ctx->len < 56) {
        ctx->block[i++] = 0x80;
        while (i < 56) ctx->block[i++] = 0x00;
    } else {
        ctx->block[i++] = 0x80;
        while (i < 64) ctx->block[i++] = 0x00;
        sha256_transform(ctx, ctx->block);
        memset(ctx->block, 0, 56);
    }
    ctx->tot_len += ctx->len * 8;
    // Append length
    ctx->block[63] = ctx->tot_len;
    ctx->block[62] = ctx->tot_len >> 8;
    ctx->block[61] = ctx->tot_len >> 16;
    ctx->block[60] = ctx->tot_len >> 24;
    ctx->block[59] = ctx->tot_len >> 32;
    ctx->block[58] = ctx->tot_len >> 40;
    ctx->block[57] = ctx->tot_len >> 48;
    ctx->block[56] = ctx->tot_len >> 56;
    sha256_transform(ctx, ctx->block);
    for (i = 0; i < 8; ++i) {
        hash[i*4]   = (ctx->h[i] >> 24) & 0xFF;
        hash[i*4+1] = (ctx->h[i] >> 16) & 0xFF;
        hash[i*4+2] = (ctx->h[i] >> 8) & 0xFF;
        hash[i*4+3] = (ctx->h[i]) & 0xFF;
    }
}

std::string hexify(const uint8 *buf, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string s; s.reserve(len*2);
    for (size_t i=0;i<len;i++){
        s.push_back(hex[buf[i]>>4]);
        s.push_back(hex[buf[i]&0xF]);
    }
    return s;
}

std::string sha256_of_buffer(const std::vector<uint8>& data) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data.data(), data.size());
    uint8 out[32]; sha256_final(&ctx, out);
    return hexify(out, 32);
}

bool read_file_to_vector(const std::wstring& path, std::vector<uint8>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamoff size = f.tellg();
    if (size <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize((size_t)size);
    f.read(reinterpret_cast<char*>(out.data()), size);
    return true;
}
void write_log(const std::string& s) {
    // criando um log simples na pasta do executavél.
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring wpath(path);
    size_t pos = wpath.find_last_of(L"\\/");
    std::wstring dir = (pos==std::wstring::npos) ? L"." : wpath.substr(0,pos);
    std::wstring logfile = dir + L"\\codexAC_log.txt";
    std::ofstream ofs(logfile, std::ios::app);
    if (ofs) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buftime[128];
        sprintf_s(buftime, "%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        ofs << "[" << buftime << "] " << s << std::endl;
    }
}

// --- Alguns helpers para comparar a memoria com os dados brutos slavos no disco ---
bool compare_file_vs_memory_sections(const std::vector<uint8>& fileData, HMODULE moduleBase, std::string& outReason) {
    if (fileData.size() < sizeof(IMAGE_DOS_HEADER)) { outReason = "file too small"; return false; }
    auto dos = (IMAGE_DOS_HEADER*)fileData.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { outReason = "invalid DOS signature"; return false; }
    if (fileData.size() < (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)) { outReason = "file truncated"; return false; }
    auto nt = (IMAGE_NT_HEADERS*)((uint8*)fileData.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { outReason = "invalid NT signature"; return false; }

    IMAGE_FILE_HEADER& fh = nt->FileHeader;
    IMAGE_OPTIONAL_HEADER& oh = nt->OptionalHeader;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < fh.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER& s = sections[i];
        // If no raw data, skip
        if (s.SizeOfRawData == 0) continue;
        // bounds check
        if ((size_t)s.PointerToRawData + s.SizeOfRawData > fileData.size()) {
            outReason = "section raw out of bounds";
            return false;
        }

        uint8* memPtr = (uint8*)moduleBase + s.VirtualAddress;
        uint8* filePtr = (uint8*)fileData.data() + s.PointerToRawData;
        // Compare min(size in memory, raw data)
        SIZE_T cmpSize = s.SizeOfRawData;
        // However memory may be larger (VirtualSize) but we compare raw bytes
        if (memcmp(memPtr, filePtr, cmpSize) != 0) {
            // find first differing byte for better log
            size_t diffIndex = 0;
            for (size_t b=0; b<cmpSize; ++b) {
                if (memPtr[b] != filePtr[b]) { diffIndex = b; break; }
            }
            std::ostringstream ss;
            ss << "Section " << std::string((char*)s.Name, strnlen((char*)s.Name, IMAGE_SIZEOF_SHORT_NAME))
               << " modified at offset 0x" << std::hex << (s.VirtualAddress + diffIndex);
            outReason = ss.str();
            return false;
        }
    }
    return true;
}

// --- helper de enumeração de modulos ---
std::vector<std::wstring> enumerate_loaded_modules() {
    std::vector<std::wstring> result;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        size_t count = cbNeeded / sizeof(HMODULE);
        for (size_t i=0;i<count;i++) {
            wchar_t name[MAX_PATH];
            if (GetModuleFileNameW(hMods[i], name, MAX_PATH)) {
                result.emplace_back(name);
            }
        }
    }
    return result;
}

// ---  thread  de monitoramento---
DWORD WINAPI monitor_thread(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);
    // pega o caminho 
    wchar_t exePathW[MAX_PATH];
    GetModuleFileNameW(NULL, exePathW, MAX_PATH);
    std::wstring exePath(exePathW);

    // primeira leitura do arquivo
    std::vector<uint8> fileData;
    if (!read_file_to_vector(exePath, fileData)) {
        write_log("codexAC: failed to read executable file at startup.");
        // Not fatal; continua tentando periodicamente
    }
    std::string initialHash = fileData.size() ? sha256_of_buffer(fileData) : std::string();

    std::ostringstream startmsg;
    startmsg << "codexAC started. initial file SHA256=" << initialHash;
    write_log(startmsg.str());

    HMODULE hModule = GetModuleHandleW(NULL); //  address base do executavél
    const DWORD pollMs = 2000;

    while (true) {
        // Sleep a bit
        Sleep(pollMs);

        // 1) le novamente os arquivos no disco e compara as hashes
        std::vector<uint8> newFile;
        if (!read_file_to_vector(exePath, newFile)) {
            write_log("codexAC: failed to read file during monitoring.");
            continue;
        }
        std::string newHash = sha256_of_buffer(newFile);
        if (initialHash.empty()) initialHash = newHash; // set if first time failed earlier

        if (newHash != initialHash) {
            std::ostringstream ss;
            ss << "INTEGRITY FAIL: file hash changed! previous=" << initialHash << " now=" << newHash;
            write_log(ss.str());
            // Action: matando o processo
            write_log("codexAC: terminating process due to file modification.");
            TerminateProcess(GetCurrentProcess(), 1);
            return 0;
        }

        // 2) compara o arquivo com as seções de memoria
        std::string reason;
        if (!compare_file_vs_memory_sections(newFile, hModule, reason)) {
            std::ostringstream ss;
            ss << "INTEGRITY FAIL: in-memory differs from on-disk: " << reason;
            write_log(ss.str());
            write_log("codexAC: terminating process due to in-memory modification.");
            TerminateProcess(GetCurrentProcess(), 2);
            return 0;
        }

        // 3) enumera os modulos carregados e anota os novos desconhecidos de vez em quando
        static DWORD tickCount = 0;
        tickCount++;
        if (tickCount % 15 == 0) { // every ~30s (15 * 2s)
            auto modules = enumerate_loaded_modules();
            std::ostringstream ss;
            ss << "Modules loaded: count=" << modules.size();
            write_log(ss.str());
            // todo: implementar uma whitelist check aqui
        }

        
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Cria uma thread de monitoramento. Tamebém muito simples.
        {
            HANDLE h = CreateThread(NULL, 0, monitor_thread, NULL, 0, NULL);
            if (h) CloseHandle(h);
            
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}