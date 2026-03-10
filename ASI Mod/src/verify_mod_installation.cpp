// ReSharper disable CppUseAuto
// ReSharper disable IdentifierTypo
#include "stdafx.h"
#include "verify_mod_installation.hpp"

#include "common.hpp"
#include "logging.hpp"
#include "helper.hpp"

constexpr CtxrHashEntry kFirstVersionCorruptUiTextures[] =
{
    {"00232162", "f6c2e6b1a58c668ca5f1aab021a4e047f1d5641d" },
    {"003155d8", "29cdca4c0be2cde96c8e6870d51dd2ceec4ada94" },
    {"005155d8", "e84562a28491dc4620b69e7b330c2e6ef6ba7f24" },
    {"005255d8", "936dc1a80b5ee47e29d64c4488bac3cbcfc85ee4" },
    {"005355d8", "b2399aa22d25f8245bf8b228eff2cd73f9de1309" },
    {"005be756", "54166a3d2f7a28f1d49a5395db83b88f7567d27c" },
    {"006209d0", "4497ccdb51b7ab02b87336f9225b37583521f5fc" },
    {"00678eb1", "4b93167721352d2fc69bf3d763c77f3e19f73d54" },
    {"00696652", "2ca78c8283409cfe7bec010dd8bce60639083cd8" },
    {"006b325b", "80990d6788bb2bbf5d80183744e00dd44ba29522" },
    {"006b5ae3", "4f875aa399bcf411418c058964c79865fb29deaa" },
    {"008c21a4", "dc2058da5c46f024a9c774273dcf47d7553f3f2f" },
    {"00919e1e", "e09824934e78696fafe6887f86abda1e502a4eea" },
    {"009e0995", "ab385326bac77e087c8a3ee2a41aeaaa75f2e9e9" },
    {"009f0995", "066c14f3c84e43630284f272beaa0ec3e9140b91" },
    {"00a225a6", "6a268957e14660ffae3b77113a7a0916c5110107" },
    {"00a325a6", "8077007a96cf282c4e0da50fa429a3c8a3ac2a01" },
    {"00c5a254", "2b348f8c98f3c063db8ae51f5d5e31f2aeac0b04" },
    {"00c87354", "1d2a546f51d69678151c864142e43cf2308e50a8" },
    {"00cb303d", "64581f623dcb69f533d82e83a4f4af5017519895" },
    {"00cda6c1", "603f37025bdc7dfdbe979ef78d8cb0a65a6b3499" },
    {"00eb32b4", "b2fc89f9f199e381367f9c5a2bfd5e3ce50c0d5b" },
    {"00eb5f92", "12d7adee23e5ea25818be5c4bb1e821c2be2f8a6" },
    {"00eb7512", "6e54982d64c5c100310e8a4bc592e81db874f029" },
    {"animal_alp_ovl.bmp", "b64ab566f1b856c94f432e0a29b253e9d5c7e2e4" },
    {"fiction_e_alp_ovl.bmp", "e705a1d84c0dfe4aa6a4adb2e125e940310af599" },
    {"kcej_logo_alp_ovl.bmp", "e740ef61691f09048d5fa54e1a3fbc1af73209dc" },
    {"museum_de_alp_ovl.bmp", "0d6a883f1b41d27ddd4082a77a1e569200297b68" },
    {"museum_e_alp_ovl.bmp", "15c16c7e78f920fdaf7f5e9831107df9169f3388" },
    {"museum_es_alp_ovl.bmp", "00b3a5aab3ea100499237b55a109389f7256932e" },
    {"museum_fr_alp_ovl.bmp", "badb4c85722e524624caadecc44b51c1010f0be4" },
    {"museum_it_alp_ovl.bmp", "f53092ca3e7d1b92eb996a8f906c09edb4316c21" },
    {"museum_j_alp_ovl.bmp", "aabb789f382d7a800dbe3d4d87fd68140e518d2e" },
    {"00238df3", "3e0d8455ca8f41a6a3bfffaffd9bfb0dac64fa96" }, //always have the smallest file at the end to minimize time spent sha1 checking
};

void VerifyInstallation::Check()
{
    if (!(eGameType & MGS2))
    {
        return;
    }

    {   // v1.0.1 -> v1.0.2 corrupt UI texture cleanup
        static_assert(std::size(kFirstVersionCorruptUiTextures) == 34, "kFirstVersionCorruptUiTextures count changed");

        const std::filesystem::path baseDir = sExePath / "textures" / "flatlist" / "ovr_stm" / "_win";

        Util::RemoveMatchedCtxrFilesWithSentinelLast(baseDir, std::span<const CtxrHashEntry>(kFirstVersionCorruptUiTextures), "corrupt UI textures from v1.0.1 -> v1.0.2 update");
    }
}
