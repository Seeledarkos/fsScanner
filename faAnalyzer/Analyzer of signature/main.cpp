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
    std::cout << "File type analyzer | version 0.8\n";
    std::cout << "Usage: ./faAnalyzer.exe <path_to_file>\n";
    std::cout << "Example: ./faAnalyzer.exe image.jpg\n";
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
    {0x0A1A0A0D474E5089,    "PNG"}
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