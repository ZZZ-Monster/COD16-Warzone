#pragma once

// Version  1.43.2.10430694

namespace offsets
{
    constexpr auto camera_base = 0x1B6CEC30;
    constexpr auto camera_pos = 0x1E8;
    constexpr auto game_mode = 0x1D89217C;
    constexpr auto local_index = 0x44B60;
    constexpr auto local_index_pos = 0x204;
    constexpr auto name_array = 0x1DD69EC0;
    constexpr auto name_array_padding = 0x4C70; //name_array_list 
    constexpr auto name_array_size = 0xD0;//无
    constexpr auto ref_def_ptr = 0x1DD5DA50;
    constexpr auto score_base = 0x0;
    constexpr auto weapon_definition = 0x1B7940C0;
    constexpr auto visible = 0x6347BB0;
    
    namespace bones
    {
        constexpr auto bone_base = 0x15A3C;
        constexpr auto distribute = 0x0;
        constexpr auto size = 0x150;
        constexpr auto visible = 0x0; 
    }

    namespace directx {
        //constexpr auto command_queue = 0x19A8AD28;//无
        //constexpr auto swap_chain = 0x19A900A0;//无
    }

    namespace other
    {
        //constexpr auto recoil = 0x19B88;//无
    }

    namespace player {
        constexpr auto size = 0x60E8;
        constexpr auto valid = 0x94; 
        constexpr auto pos = 0x288;
        constexpr auto team = 0x54C; 
        constexpr auto stance = 0x5284;
        constexpr auto weapon_index = 0x6FA; 
        constexpr auto dead_1 = 0x4E0;
        constexpr auto dead_2 = 0x550;
    }
}