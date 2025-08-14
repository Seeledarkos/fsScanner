#define CRT_SECURE_NO_WARNINGS 1

#include <iostream>
#include <fstream>
#include <string>
#include <iomanip> // Для форматирования вывода
#include <cstdint> // Для типов uint64_t
#include <vector>

// Хранение сигнатуры
struct FileSignature {
    uint64_t signature; // Первые 8 байт файла
    std::string type;
};


void helpPage() {
    std::cout << "fsScanner | version 0.8\n";
    std::cout << "Usage: ./fsScanner.exe <path_to_file>\n";
}

// Функция для определения типа файла по сигнатуре
void determineFileType(uint64_t signature) {
std::vector<FileSignature> knownSignatures = {
{0xFFD8FFE000104A46ULL, "JPEG"},
{0xFFD8FFDB0043ULL,     "JPEG/DCT"},
{0x89504E470D0A1A0AULL, "PNG"},
{0x474946383961ULL,     "GIF"},
{0x424DULL,             "BMP"},
{0x504B030414000600ULL, "ZIP"},
{0x504B03040A000000ULL, "ZIP"},
{0x526172211A0700CFULL, "RAR v4.x"},
{0x526172211A070100ULL, "RAR v5.x"},
{0x7573746172003030ULL, "TAR"},
{0x7573746172202000ULL, "GNU tar"},
{0xD0CF11E0A1B11AE1ULL, "MS Word Binary Document"},
{0x504B030414000600ULL, "Office Open XML"},
{0x255044462D312EULL,   "PDF"},
{0xCFBFA7BDULL,         "PowerPoint Binary Presentation"},
{0x504B030414000600ULL, "Excel Spreadsheet"},
{0x494433ULL,           "MP3 ID3 tag"},
{0xFFFBULL,             "MP3 MPEG-1 Layer III"},
{0x52494646ULL,         "WAV"},
{0x4F67675300020000ULL, "OGG Vorbis"},
{0x464C4143ULL,         "FLAC"},
{0x0000001866747970ULL, "QuickTime MOV/iTunes M4V"},
{0x1A45DFA3ULL,         "Matroska MKV"},
{0x000001BAULL,         "MPEG-PS"},
{0x3026B2758E66CF11ULL, "ASF/WMA/WMV"},
{0x6674797069736F6DULL, "MP4"},
{0x4D5AULL,             "DOS EXE (PE-file)"},
{0xCAFEBABEULL,         "Java Class file"},
{0x7F454C46ULL,         "Linux ELF executable"},
{0x4D5A900003000000ULL, "DLL"},
{0xEFBBBFULL,           "UTF-8 BOM"},
{0xFEFFULL,             "UTF-16BE BOM"},
{0xFFFEULL,             "UTF-16LE BOM"},
{0x0A1A0A0D474E5089ULL, "PNG"},
{0x0000000100785A4DULL, "Google executable installer"},
{0x2E736E64ULL,         "WAVE (WAV)"},
{0x4D53434CULL,         "MS Access Database"},
{0x7B5C7274ULL,         "Rich Text Format (RTF)"},
{0x4D5A900003000000ULL, "Windows PE Executable"},
{0x5A4DULL,             "DOS MZ Executable"},
{0x3C3F786D6CULL,       "XML"},
{0x4D524D6CULL,         "MIDI"},
{0x4D5A900003000000ULL, "Windows DLL"},
{0x5A4DULL,             "Windows Executable (PE)"},
{0x0A0D0A0DULL,         "Text File (CRLF)"},
{0x0A0A0A0DULL,         "Text File (LF)"},
{0x2E2E2E2EULL,         "Text File (ASCII)"},
{0x7F454C46ULL,         "ELF Executable"},
{0x53494E442AULL,       "SQLite Database"},
{0x4D5AULL,             "Windows Executable (PE)"},
{0x5A4DULL,             "DOS Executable"},
{0x4D5AULL,             "Windows PE"},
{0x41433130ULL,         "AC3 Audio"},
{0x52494646ULL,         "RIFF"},
{0x52494646ULL,         "AVI"},
{0x52494646ULL,         "WAV"},
{0x7B5C7274ULL,         "Rich Text Format"},
{0xFFD8FFE0ULL,         "JPEG"},
{0xFFD8FFE1ULL,         "JPEG"},
{0xFFD8FFE2ULL,         "JPEG"},
{0xFFD8FFE3ULL,         "JPEG"},
{0xFFD8FFE4ULL,         "JPEG"},
{0xFFD8FFE5ULL,         "JPEG"},
{0xFFD8FFE6ULL,         "JPEG"},
{0xFFD8FFE7ULL,         "JPEG"},
{0xFFD8FFE8ULL,         "JPEG"},
{0xFFD8FFE9ULL,         "JPEG"},
{0xFFD8FFEAULL,         "JPEG"},
{0xFFD8FFEBULL,         "JPEG"},
{0xFFD8FFECULL,         "JPEG"},
{0xFFD8FFEDULL,         "JPEG"},
{0xFFD8FFEEULL,         "JPEG"},
{0xFFD8FFEFULL,         "JPEG"},
{0xFFD8FFFDULL,         "JPEG"},
{0xFFD8FFFBULL,         "JPEG"},
{0x207265746C69665B,    "Gitconfig source"},
{0x6E61745300000100,    "Microfost access database"},
{0x6564756C636E6923,    "C++ source code"},
{0x0000000006054B50,    "7-Zip archive"}
};


    for (const auto& entry : knownSignatures) {
        if ((signature & 0xFFFFFFFFFFFF0000) == entry.signature) {
            std::cout << "File type: " << entry.type << std::endl;
            return;
        }
        if (signature == entry.signature) {
            std::cout << "File type: " << entry.type << std::endl;
            return;
        }
    }

    std::cout << "File type: Unknown" << std::endl;
}

// Функция для чтения первых 8 байт
uint64_t reader(const char* file_path) {
    std::ifstream file_stream;
    file_stream.open(file_path, std::ios::binary | std::ios::in);

    if (!file_stream) {
        std::cerr << "Error: Failed to open file '" << file_path << "'" << std::endl;
        return 0;
    }

    std::cout << "File '" << file_path << "' loaded successfully." << std::endl;

    uint64_t signature = 0;

    // Само чтение
    file_stream.read(reinterpret_cast<char*>(&signature), sizeof(signature));

    // Проверка чтения
    if (file_stream.gcount() < sizeof(signature)) {
        std::cerr << "Warning: Read only " << file_stream.gcount() << " bytes. File may be too small." << std::endl;
    }

    std::cout << "File signature: " << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << signature << std::endl;

    file_stream.close();

    return signature;
}
// памЯтка
// Путь до файла = argv[1]
//
//

int main(int argc, char** argv) {
    // Проверка на грязного нваха
    if (argc < 2) {
        helpPage();
        return 1;
    }

    const char* filePath = argv[1];

    uint64_t signature = reader(filePath);


    if (signature != 0) {
        determineFileType(signature);
    }

    return 0;
}