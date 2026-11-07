#ifndef AMASTATIC_RZ_JSON_DATA_H
#define AMASTATIC_RZ_JSON_DATA_H

#include <glaze/forward.hpp>
#include <string>
#include <cstdint>
#include <glaze/glaze.hpp>
#include <magic_enum/magic_enum.hpp>

namespace AMAStatic {

namespace __INTERNAL__::string {
    inline std::string to_lower(std::string str) {
        std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
            return std::tolower(c);
        });
        return str;
    }
}

namespace INT = __INTERNAL__;

enum class ExecFormat {
    UNKNOWN, PE, ELF32, ELF64, MACHO
};

enum class Arch {
    UNKNOWN, X86, X64, ARM32, ARM64, MIPS, RISCV32, RISCV64
};

enum class OsType {
    UNKNOWN, WINDOWS, LINUX, MACOS, ANDROID
};

enum class Language {
    UNKNOWN, C, CXX, RUST, GO, SWIFT, OBJC, JAVA, DART, DLANG, GROOVY,
};

enum class Compiler {
    UNKNOWN, GCC, CLANG, MSVC, RUSTC
};

struct ImportData {
    int ordinal{};
    std::string bind;
    std::string type;
    std::string name;
};

struct SectionData {
    std::string name;
    int size{};
    int vsize{};
    std::string perm;
    std::string type;
    std::vector<std::string> flags;
    uint64_t paddr;
    uint64_t vaddr;
};

struct StringData {
    uint64_t vaddr{};
    uint64_t paddr{};
    int ordinal{};
    int size{};
    int length{};
    std::string section;
    std::string type;
    std::string text;
    std::vector<std::string> blocks;
};

struct SymbolData {
    std::string name;
    std::string flagname;
    std::string realname;
    int ordinal{};
    std::string bind;
    int size{};
    std::string type;
    bool is_imported;
    std::string lib;
    uint64_t vaddr{};
    uint64_t paddr{};
};

struct BaseInfo {
    struct Core {
        std::string file;
        int fd;
        int size;
        std::string humansz;
        bool iorw;
        std::string mode;
        int block;
        std::string format;
    };
    struct Bin {
        std::string arch;
        int bits;
        std::string bintype;
        std::string rpath;
        std::string _class;
        std::string machine;
        std::string os;
        std::string subsys;
        std::string endian;
        std::string compiler;
        std::string intrp;
        std::string lang;
        uint64_t baddr;
        uint64_t laddr;
        uint64_t binsz;
        int maxopsz;
        int minopsz;
        int pcalign;
        bool va;
        bool havecode;
        bool stripped;
        bool linenum;
        bool lsyms;
        bool _static;
        bool canary;
        bool pie;
        bool nx;
        std::string relro;
        bool relrocs;
        bool crypto;
        bool sanitiz;
    };

    Core core;
    Bin bin;

    ExecFormat ParseExecFormat() {
        using EF = ExecFormat;
        auto fmt = INT::string::to_lower(core.format);
        if (fmt == "elf64")     return EF::ELF64;
        if (fmt == "elf32")     return EF::ELF32;
        if (fmt.find("pe") != std::string::npos) return EF::PE;
        if (fmt.find("mach") != std::string::npos) return EF::MACHO;
        return EF::UNKNOWN;
    }

    Arch ParseArch() {
        auto arch = INT::string::to_lower(bin.arch);
        int bits = bin.bits;
        if (arch == "x86") {
            return (bits == 64) ? Arch::X64 : Arch::X86;
        }
        if (arch == "arm") {
            return (bits == 64) ? Arch::ARM64 : Arch::ARM32;
        }
        if (arch == "riscv") {
            return (bits == 64) ? Arch::RISCV64 : Arch::RISCV32;
        }

        auto casted = magic_enum::enum_cast<Arch>(arch, magic_enum::case_insensitive);
        return casted.value_or(Arch::UNKNOWN);
    }

    OsType ParseOS() {
        auto os = INT::string::to_lower(bin.os);
        if (os == "windows") return OsType::WINDOWS;
        if (os == "macos" || os == "darwin") return OsType::MACOS;

        auto casted = magic_enum::enum_cast<OsType>(os, magic_enum::case_insensitive);
        return casted.value_or(OsType::UNKNOWN);
    }

    Language ParseLanguage() {
        auto lang = INT::string::to_lower(bin.lang);
        if (lang == "c++") return Language::CXX;
        if (lang == "objective-c") return Language::OBJC;

        auto casted = magic_enum::enum_cast<Language>(lang, magic_enum::case_insensitive);
        return casted.value_or(Language::UNKNOWN);
    }

    Compiler ParseCompiler() {
        auto comp = INT::string::to_lower(bin.compiler);
        if (comp.find("gcc") != std::string::npos)   return Compiler::GCC;
        if (comp.find("clang") != std::string::npos) return Compiler::CLANG;
        if (comp.find("msvc") != std::string::npos || comp.find("microsoft") != std::string::npos) return Compiler::MSVC;
        if (comp.find("rustc") != std::string::npos) return Compiler::RUSTC;
        return Compiler::UNKNOWN;
    }
};

}

namespace AMS = AMAStatic;

template <>
struct glz::meta<AMS::StringData> {
    using T = AMS::StringData;
    static constexpr auto value = glz::object(
        "vaddr", &T::vaddr,
        "paddr", &T::paddr,
        "ordinal", &T::ordinal,
        "size", &T::size,
        "length", &T::length,
        "section", &T::section,
        "type", &T::type,
        "string", &T::text,
        "blocks", &T::blocks
    );
};

template<>
struct glz::meta<AMS::BaseInfo> {
    using T = AMS::BaseInfo;
    static constexpr auto value = glz::object(
        "core", &T::core,
        "bin", &T::bin
    );
};

template<>
struct glz::meta<AMS::BaseInfo::Core> {
    using T = AMS::BaseInfo::Core;
    static constexpr auto value = glz::object(
        "file", &T::file,
        "fd", &T::fd,
        "size", &T::size,
        "humansz", &T::humansz,
        "iorw", &T::iorw,
        "mode", &T::mode,
        "block", &T::block,
        "format", &T::format
    );
};

template<>
struct glz::meta<AMS::BaseInfo::Bin> {
    using T = AMS::BaseInfo::Bin;
    static constexpr auto value = glz::object(
        "arch", &T::arch,
        "bits", &T::bits,
        "bintype", &T::bintype,
        "rpath", &T::rpath,
        "class", &T::_class,
        "machine", &T::machine,
        "os", &T::os,
        "subsys", &T::subsys,
        "endian", &T::endian,
        "compiler", &T::compiler,
        "intrp", &T::intrp,
        "lang", &T::lang,
        "baddr", &T::baddr,
        "laddr", &T::laddr,
        "binsz", &T::binsz,
        "maxopsz", &T::maxopsz,
        "minopsz", &T::minopsz,
        "pcalign", &T::pcalign,
        "va", &T::va,
        "havecode", &T::havecode,
        "stripped", &T::stripped,
        "linenum", &T::linenum,
        "lsyms", &T::lsyms,
        "static", &T::_static,
        "canary", &T::canary,
        "PIE", &T::pie,
        "RELROCS", &T::relrocs,
        "NX", &T::nx,
        "relro", &T::relro,
        "crypto", &T::crypto,
        "sanitiz", &T::sanitiz
    );
};

#endif // AMASTATIC_RZ_JSON_DATA_H