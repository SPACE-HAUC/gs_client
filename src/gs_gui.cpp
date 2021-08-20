/**
 * @file gs_gui.cpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief Contains function definitions for GUI-specific functions.
 * 
 * Mainly this file contains function declarations for _window functions, which control the display and handle data of specific ImGui windows.
 * 
 * @version 0.1
 * @date 2021.06.30
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <cmath>
#include <sys/stat.h>
#include <fcntl.h>
#include "gs.hpp"
#include "gs_gui.hpp"
#include "meb_debug.hpp"
#include "sw_update_packdef.h"

int gs_gui_gs2sh_tx_handler(NetDataClient *network_data, int access_level, cmd_input_t *command_input, bool allow_transmission)
{
    if (!allow_transmission)
    {
        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "TRANSMISSIONS LOCKED");
        ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
    }

    if (access_level <= 1)
    {
        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
        ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
    }

    ImGui::Text("Send Command");
    ImGui::Indent();

    ImGui::Text("Queued Transmission");
    ImGui::Text("Module ID ----- 0x%02x", command_input->mod);
    ImGui::Text("Command ID ---- 0x%02x", command_input->cmd);
    ImGui::Text("Unused -------- 0x%02x", command_input->unused);
    ImGui::Text("Data size ----- 0x%02x", command_input->data_size);
    ImGui::Text("Data ---------- ");

    for (int i = 0; i < command_input->data_size; i++)
    {
        ImGui::SameLine(0.0F, 0.0F);
        ImGui::Text("%02x", command_input->data[i]);
    }

    ImGui::Unindent();
    if (ImGui::Button("SEND DATA-UP TRANSMISSION") && access_level > 1 && allow_transmission)
    {
        // Send the transmission.
        // gs_transmit(network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, command_input, sizeof(cmd_input_t));
        NetFrame *network_frame = new NetFrame((unsigned char *)command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
        network_frame->sendFrame(network_data);
        delete network_frame;
    }

    if (access_level <= 1)
    {
        ImGui::PopStyleColor();
    }

    if (!allow_transmission)
    {
        ImGui::PopStyleColor();
    }

    return 1;
}

void gs_gui_authentication_control_panel_window(bool *AUTH_control_panel, auth_t *auth, global_data_t *global)
{
    static pthread_t auth_thread_id;

    // ImVec2 m_dim = ImGui::GetWindowSize();
    // ImGui::SetNextWindowPos(ImVec2(m_dim.x / 2, m_dim.y / 2));
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    if (ImGui::Begin("Authentication Control Panel", AUTH_control_panel, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus))
    {
        if (auth->busy)
        {
            char loading_icon[8][6 + 1] = {
                ".     ",
                "..    ",
                "...   ",
                " ...  ",
                "  ... ",
                "   ...",
                "    ..",
                "     ."};

            static int li = -1;
            li = (li + 1) % 80;

            ImGui::Text("PROCESSING%s", loading_icon[li / 10]);
            ImGui::InputTextWithHint("", "Enter Password", auth->password, 64, ImGuiInputTextFlags_Password | ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_ReadOnly);
        }
        else
        {
            switch (auth->access_level)
            {
            case 0:
                ImGui::Text("LOW LEVEL ACCESS");
                break;
            case 1:
                ImGui::Text("TEAM MEMBER ACCESS GRANTED");
                break;
            case 2:
                ImGui::Text("PRIORITY ACCESS GRANTED");
                break;
            case 3:
                ImGui::Text("PROJECT MANAGER ACCESS GRANTED");
                break;
            default:
                ImGui::Text("ERROR: UNKNOWN ACCESS");
                break;
            }

            if (ImGui::InputTextWithHint("", "Enter Password", auth->password, 64, ImGuiInputTextFlags_Password | ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_EnterReturnsTrue))
            {
                pthread_create(&auth_thread_id, NULL, gs_check_password, auth);
            }
        }

        int access_level = auth->access_level;
        if (access_level == 0)
        {
            ImGui::PushStyleColor(0, ImVec4(0.6f, 0.6f, 0.6f, 1.0f));
        }
        if (ImGui::Button("REVOKE ACCESS"))
        {
            auth->access_level = 0;
        }
        if (access_level == 0)
        {
            ImGui::PopStyleColor();
        }

        if (ImGui::IsItemHovered() && global->settings->tooltips)
        {
            ImGui::BeginTooltip();
            ImGui::SetTooltip("Resets access to lowest level.");
            ImGui::EndTooltip();
        }
    }
    ImGui::End();
}

void gs_gui_settings_window(bool *SETTINGS_window, int access_level, global_data_t *global)
{
    ImGui::SetNextWindowPos(ImVec2(450, 0));
    if (ImGui::Begin("Settings", SETTINGS_window, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus))
    {
        ImGui::Text("Split ACS update graphs into multiple windows?");
        ImGui::Checkbox("ACS Multiple Windows", &global->settings->acs_multiple_windows);
        ImGui::Checkbox("Show Tooltips", &global->settings->tooltips);
    }
    ImGui::End();
}

void gs_gui_acs_window(global_data_t *global, bool *ACS_window, int access_level, bool allow_transmission)
{
    ImGuiInputTextFlags_ flag = (ImGuiInputTextFlags_)0;

    static int ACS_command = ACS_INVALID_ID;
    static cmd_input_t ACS_command_input = {.mod = INVALID_ID, .cmd = ACS_INVALID_ID, .unused = 0, .data_size = 0};
    static acs_set_data_t acs_set_data = {0};
    static acs_set_data_holder_t acs_set_data_holder = {0};

    static bool acs_rxtx_automated = false;
    static pthread_t acs_thread_id;

    if (ImGui::Begin("ACS Operations", ACS_window))
    {
        if (ImGui::CollapsingHeader("Data-down Commands", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (access_level <= 0)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            if (!allow_transmission)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "TRANSMISSIONS LOCKED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            if (ImGui::ArrowButton("get_moi_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                ACS_command_input.mod = ACS_ID;
                ACS_command_input.cmd = ACS_GET_MOI;
                ACS_command_input.unused = 0x0;
                ACS_command_input.data_size = 0x0;
                memset(ACS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &ACS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&ACS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Moment of Intertia (MOI)");

            if (ImGui::ArrowButton("get_imoi_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                ACS_command_input.mod = ACS_ID;
                ACS_command_input.cmd = ACS_GET_IMOI;
                ACS_command_input.unused = 0x0;
                ACS_command_input.data_size = 0x0;
                memset(ACS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &ACS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&ACS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Inverse Moment of Inertia (IMOI)");

            if (ImGui::ArrowButton("get_dipole_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                ACS_command_input.mod = ACS_ID;
                ACS_command_input.cmd = ACS_GET_DIPOLE;
                ACS_command_input.unused = 0x0;
                ACS_command_input.data_size = 0x0;
                memset(ACS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &ACS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&ACS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Dipole");

            if (ImGui::ArrowButton("get_timestep_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                ACS_command_input.mod = ACS_ID;
                ACS_command_input.cmd = ACS_GET_TSTEP;
                ACS_command_input.unused = 0x0;
                ACS_command_input.data_size = 0x0;
                memset(ACS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &ACS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&ACS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Timestep");

            if (ImGui::ArrowButton("get_measure_time_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                ACS_command_input.mod = ACS_ID;
                ACS_command_input.cmd = ACS_GET_MEASURE_TIME;
                ACS_command_input.unused = 0x0;
                ACS_command_input.data_size = 0x0;
                memset(ACS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &ACS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&ACS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Measure Time");

            if (ImGui::ArrowButton("get_leeway_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                ACS_command_input.mod = ACS_ID;
                ACS_command_input.cmd = ACS_GET_LEEWAY;
                ACS_command_input.unused = 0x0;
                ACS_command_input.data_size = 0x0;
                memset(ACS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &ACS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&ACS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Leeway (Z-Angular Momentum Target Tolerable Error)");

            if (ImGui::ArrowButton("get_wtarget_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                ACS_command_input.mod = ACS_ID;
                ACS_command_input.cmd = ACS_GET_WTARGET;
                ACS_command_input.unused = 0x0;
                ACS_command_input.data_size = 0x0;
                memset(ACS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &ACS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&ACS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get W-Target (Angular Momentum Target Vector");

            if (ImGui::ArrowButton("get_detumble_angle_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                ACS_command_input.mod = ACS_ID;
                ACS_command_input.cmd = ACS_GET_DETUMBLE_ANG;
                ACS_command_input.unused = 0x0;
                ACS_command_input.data_size = 0x0;
                memset(ACS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &ACS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&ACS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Detumble Angle");

            if (ImGui::ArrowButton("get_sun_angle_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                ACS_command_input.mod = ACS_ID;
                ACS_command_input.cmd = ACS_GET_SUN_ANGLE;
                ACS_command_input.unused = 0x0;
                ACS_command_input.data_size = 0x0;
                memset(ACS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &ACS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&ACS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Sun Angle");

            if (!allow_transmission)
            {
                ImGui::PopStyleColor();
            }

            if (access_level <= 0)
            {
                ImGui::PopStyleColor();
            }
        }

        ImGui::Separator();

        if (ImGui::CollapsingHeader("Data-up Commands", ImGuiTreeNodeFlags_DefaultOpen))
        {

            if (access_level <= 1)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
                flag = ImGuiInputTextFlags_ReadOnly;
            }

            ImGui::RadioButton("Set MOI", &ACS_command, ACS_SET_MOI);                  // 9x floats
            ImGui::InputFloat3("MOI [0] [1] [2]", &acs_set_data.moi[0], "%.3e", flag); // Sets 3 at a time.
            ImGui::InputFloat3("MOI [3] [4] [5]", &acs_set_data.moi[3], "%.3e", flag);
            ImGui::InputFloat3("MOI [6] [7] [8]", &acs_set_data.moi[6], "%.3e", flag);
            ImGui::RadioButton("Set IMOI", &ACS_command, ACS_SET_IMOI); // 9x floats
            ImGui::InputFloat3("IMOI [0] [1] [2]", &acs_set_data.imoi[0], "%.3e", flag);
            ImGui::InputFloat3("IMOI [3] [4] [5]", &acs_set_data.imoi[3], "%.3e", flag);
            ImGui::InputFloat3("IMOI [6] [7] [8]", &acs_set_data.imoi[6], "%.3e", flag);
            ImGui::RadioButton("Set Dipole", &ACS_command, ACS_SET_DIPOLE); // 1x float
            ImGui::InputFloat("Dipole Moment", &acs_set_data.dipole, 0.0f, 0.0f, "%.3e", flag);
            ImGui::RadioButton("Set Timestep", &ACS_command, ACS_SET_TSTEP); // 1x uint8_t
            if (ImGui::InputInt("Timestep (ms)", &acs_set_data_holder.tstep, 1, 100, flag))
            {
                if (acs_set_data_holder.tstep > 255)
                {
                    acs_set_data_holder.tstep = 255;
                }
                else if (acs_set_data_holder.tstep < 0)
                {
                    acs_set_data_holder.tstep = 0;
                }
                acs_set_data.tstep = (uint8_t)acs_set_data_holder.tstep;
            }

            ImGui::RadioButton("Set Measure Time", &ACS_command, ACS_SET_MEASURE_TIME); // 1x uint8_t
            if (ImGui::InputInt("Measure Time (ms)", &acs_set_data_holder.measure_time, 1, 100, flag))
            {
                if (acs_set_data_holder.measure_time > 255)
                {
                    acs_set_data_holder.measure_time = 255;
                }
                else if (acs_set_data_holder.measure_time < 0)
                {
                    acs_set_data_holder.measure_time = 0;
                }
                acs_set_data.measure_time = (uint8_t)acs_set_data_holder.measure_time;
            }

            ImGui::RadioButton("Set Leeway", &ACS_command, ACS_SET_LEEWAY); // 1x uint8_t
            if (ImGui::InputInt("Leeway Factor", &acs_set_data_holder.leeway, 1, 100, flag))
            {
                if (acs_set_data_holder.leeway > 255)
                {
                    acs_set_data_holder.leeway = 255;
                }
                else if (acs_set_data_holder.leeway < 0)
                {
                    acs_set_data_holder.leeway = 0;
                }
                acs_set_data.leeway = (uint8_t)acs_set_data_holder.leeway;
            }

            ImGui::RadioButton("Set W-Target", &ACS_command, ACS_SET_WTARGET); // 1x float
            ImGui::InputFloat("W-Target", &acs_set_data.wtarget, 0.0f, 0.0f, "%.3e", flag);
            ImGui::RadioButton("Set Detumble Angle", &ACS_command, ACS_SET_DETUMBLE_ANG); // 1x uint8_t
            if (ImGui::InputInt("Angle", &acs_set_data_holder.detumble_angle, 1, 100, flag))
            {
                if (acs_set_data_holder.detumble_angle > 255)
                {
                    acs_set_data_holder.detumble_angle = 255;
                }
                else if (acs_set_data_holder.detumble_angle < 0)
                {
                    acs_set_data_holder.detumble_angle = 0;
                }
                acs_set_data.detumble_angle = (uint8_t)acs_set_data_holder.detumble_angle;
            }
            ImGui::RadioButton("Set Sun Angle", &ACS_command, ACS_SET_SUN_ANGLE); // 1x uint8_t
            if (ImGui::InputInt("Sun Angle", &acs_set_data_holder.sun_angle, 1, 100, flag))
            {
                if (acs_set_data_holder.sun_angle > 255)
                {
                    acs_set_data_holder.sun_angle = 255;
                }
                else if (acs_set_data_holder.sun_angle < 0)
                {
                    acs_set_data_holder.sun_angle = 0;
                }
                acs_set_data.sun_angle = (uint8_t)acs_set_data_holder.sun_angle;
            }
            if (access_level <= 1)
            {
                ImGui::PopStyleColor();
                flag = (ImGuiInputTextFlags_)0;
            }
        }

        ACS_command_input.mod = ACS_ID;
        ACS_command_input.cmd = ACS_command;

        ImGui::Separator();

        if (ImGui::CollapsingHeader("Transmit", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (!allow_transmission)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "TRANSMISSIONS LOCKED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            if (ImGui::Button("Send One ACS Update Request") && allow_transmission)
            {
                // Spawn a new thread to run
                if (pthread_mutex_trylock(&global->acs_rolbuf->acs_upd_inhibitor) == 0)
                {
                    pthread_create(&acs_thread_id, NULL, gs_acs_update_thread, global);
                }
            }

            ImGui::Text("ACS Data-down Update (every 100ms)");
            if (ImGui::Button("Toggle ACS Update") && allow_transmission)
            {
                acs_rxtx_automated = !acs_rxtx_automated;
            }

            if (acs_rxtx_automated)
            {
                ImGui::PushStyleColor(0, ImVec4(0.0f, 1.0f, 0.0f, 1.0f));
                ImGui::SameLine();
                ImGui::Text("ACTIVE");
                ImGui::PopStyleColor();

                // Spawn a thread to execute gs_acs_update_data_handler(...) once.
                if (pthread_mutex_trylock(&global->acs_rolbuf->acs_upd_inhibitor) == 0)
                {
                    pthread_create(&acs_thread_id, NULL, gs_acs_update_thread, global);
                }
            }
            else
            {
                ImGui::PushStyleColor(0, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
                ImGui::SameLine();
                ImGui::Text("INACTIVE");
                ImGui::PopStyleColor();
            }

            if (!allow_transmission)
            {
                ImGui::PopStyleColor();
            }

            ImGui::Separator();

            if (access_level > 1)
            {
                // Move the data into ACS_command_input.data
                switch (ACS_command_input.cmd)
                {
                case ACS_SET_MOI:
                {
                    memcpy(ACS_command_input.data, acs_set_data.moi, sizeof(float) * 9);
                    ACS_command_input.data_size = sizeof(float) * 9;
                    break;
                }
                case ACS_SET_IMOI:
                {
                    memcpy(ACS_command_input.data, acs_set_data.imoi, sizeof(float) * 9);
                    ACS_command_input.data_size = sizeof(float) * 9;
                    break;
                }
                case ACS_SET_DIPOLE:
                {
                    ACS_command_input.data_size = sizeof(float);
                    memcpy(ACS_command_input.data, &acs_set_data.dipole, ACS_command_input.data_size);
                    break;
                }
                case ACS_SET_TSTEP:
                {
                    ACS_command_input.data[0] = (uint8_t)acs_set_data.tstep;
                    ACS_command_input.data_size = sizeof(uint8_t);
                    break;
                }
                case ACS_SET_MEASURE_TIME:
                {
                    ACS_command_input.data[0] = (uint8_t)acs_set_data.measure_time;
                    ACS_command_input.data_size = sizeof(uint8_t);
                    break;
                }
                case ACS_SET_LEEWAY:
                {
                    ACS_command_input.data[0] = (uint8_t)acs_set_data.leeway;
                    ACS_command_input.data_size = sizeof(uint8_t);
                    break;
                }
                case ACS_SET_WTARGET:
                {
                    ACS_command_input.data_size = sizeof(float);
                    memcpy(ACS_command_input.data, &acs_set_data.wtarget, ACS_command_input.data_size);
                    break;
                }
                case ACS_SET_DETUMBLE_ANG:
                {
                    ACS_command_input.data[0] = (uint8_t)acs_set_data.detumble_angle;
                    ACS_command_input.data_size = sizeof(uint8_t);
                    break;
                }
                case ACS_SET_SUN_ANGLE:
                {
                    ACS_command_input.data[0] = (uint8_t)acs_set_data.sun_angle;
                    ACS_command_input.data_size = sizeof(uint8_t);
                    break;
                }
                default:
                {
                    ACS_command_input.data_size = -1;
                    break;
                }
                }
            }

            gs_gui_gs2sh_tx_handler(global->network_data, access_level, &ACS_command_input, allow_transmission);
        }
    }
    ImGui::End();
}

void gs_gui_eps_window(NetDataClient *network_data, bool *EPS_window, int access_level, bool allow_transmission)
{
    ImGuiInputTextFlags_ flag = (ImGuiInputTextFlags_)0;

    static int EPS_command = EPS_INVALID_ID;
    static cmd_input_t EPS_command_input = {.mod = INVALID_ID, .cmd = EPS_INVALID_ID, .unused = 0, .data_size = 0};
    static eps_set_data_t eps_set_data = {0};

    if (ImGui::Begin("EPS Operations", EPS_window))
    {
        if (ImGui::CollapsingHeader("Data-down Commands", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (access_level <= 0)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            if (!allow_transmission)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "TRANSMISSIONS LOCKED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            if (ImGui::ArrowButton("get_min_hk_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                EPS_command_input.mod = EPS_ID;
                EPS_command_input.cmd = EPS_GET_MIN_HK;
                EPS_command_input.unused = 0x0;
                EPS_command_input.data_size = 0x0;
                memset(EPS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &EPS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&EPS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Minimal Housekeeping");

            if (ImGui::ArrowButton("get_vbatt_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                EPS_command_input.mod = EPS_ID;
                EPS_command_input.cmd = EPS_GET_VBATT;
                EPS_command_input.unused = 0x0;
                EPS_command_input.data_size = 0x0;
                memset(EPS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &EPS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&EPS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Battery Voltage");

            if (ImGui::ArrowButton("get_sys_curr_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                EPS_command_input.mod = EPS_ID;
                EPS_command_input.cmd = EPS_GET_SYS_CURR;
                EPS_command_input.unused = 0x0;
                EPS_command_input.data_size = 0x0;
                memset(EPS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &EPS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&EPS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get System Current");

            if (ImGui::ArrowButton("get_power_out_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                EPS_command_input.mod = EPS_ID;
                EPS_command_input.cmd = EPS_GET_OUTPOWER;
                EPS_command_input.unused = 0x0;
                EPS_command_input.data_size = 0x0;
                memset(EPS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &EPS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&EPS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Power Out");

            if (ImGui::ArrowButton("get_solar_voltage_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                EPS_command_input.mod = EPS_ID;
                EPS_command_input.cmd = EPS_GET_VSUN;
                EPS_command_input.unused = 0x0;
                EPS_command_input.data_size = 0x0;
                memset(EPS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &EPS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&EPS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Solar Voltage");

            if (ImGui::ArrowButton("get_all_solar_voltage_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                EPS_command_input.mod = EPS_ID;
                EPS_command_input.cmd = EPS_GET_VSUN_ALL;
                EPS_command_input.unused = 0x0;
                EPS_command_input.data_size = 0x0;
                memset(EPS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &EPS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&EPS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Solar Voltage (All)");

            if (ImGui::ArrowButton("get_isun_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                EPS_command_input.mod = EPS_ID;
                EPS_command_input.cmd = EPS_GET_ISUN;
                EPS_command_input.unused = 0x0;
                EPS_command_input.data_size = 0x0;
                memset(EPS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &EPS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&EPS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Solar Generated Current (ISUN)");

            if (ImGui::ArrowButton("get_loop_timer_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                EPS_command_input.mod = EPS_ID;
                EPS_command_input.cmd = EPS_GET_LOOP_TIMER;
                EPS_command_input.unused = 0x0;
                EPS_command_input.data_size = 0x0;
                memset(EPS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &EPS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&EPS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Loop Timer");

            if (!allow_transmission)
            {
                ImGui::PopStyleColor();
            }

            if (access_level <= 0)
            {
                ImGui::PopStyleColor();
            }
        }

        ImGui::Separator();

        if (ImGui::CollapsingHeader("Data-up Commands", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (access_level <= 1)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
                flag = ImGuiInputTextFlags_ReadOnly;
            }

            ImGui::RadioButton("Set Loop Timer", &EPS_command, EPS_SET_LOOP_TIMER);
            ImGui::InputInt("Loop Time (seconds)", &eps_set_data.loop_timer, 1, 100, flag);

            if (access_level <= 1)
            {
                ImGui::PopStyleColor();
                flag = (ImGuiInputTextFlags_)0;
            }
        }

        EPS_command_input.mod = EPS_ID;
        EPS_command_input.cmd = EPS_command;

        ImGui::Separator();

        if (ImGui::CollapsingHeader("Transmit", ImGuiTreeNodeFlags_DefaultOpen))
        {

            if (!allow_transmission)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            ImGui::Indent();

            if (access_level <= 1)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            switch (EPS_command_input.cmd)
            {
            case EPS_SET_LOOP_TIMER:
            {
                // TODO: Remove all .data[0] = some_variable, because this will only set the first byte of .data because its in section of bytes.
                // TODO: ~DO NOT REMOVE~ UNLESS it is a one-byte kind of data, ie uint8_t.
                EPS_command_input.data_size = sizeof(int);
                memcpy(EPS_command_input.data, &eps_set_data.loop_timer, EPS_command_input.data_size);
                break;
            }
            default:
            {
                EPS_command_input.data_size = -1;
                break;
            }
            }
            ImGui::Unindent();

            if (access_level <= 1)
            {
                ImGui::PopStyleColor();
            }

            if (!allow_transmission)
            {
                ImGui::PopStyleColor();
            }

            gs_gui_gs2sh_tx_handler(network_data, access_level, &EPS_command_input, allow_transmission);
        }
    }
    ImGui::End();
}

void gs_gui_xband_window(global_data_t *global, bool *XBAND_window, int access_level, bool allow_transmission)
{
    ImGuiInputTextFlags_ flag = (ImGuiInputTextFlags_)0;
    NetDataClient *network_data = global->network_data;

    static int XBAND_command = XBAND_INVALID_ID;
    static cmd_input_t XBAND_command_input = {.mod = INVALID_ID, .cmd = XBAND_INVALID_ID, .unused = 0, .data_size = 0};
    static xband_set_data_array_t xband_set_data = {0};
    static xband_tx_data_t xband_tx_data = {0};
    static xband_tx_data_holder_t xband_tx_data_holder = {0};
    static xband_rxtx_data_t xband_rxtx_data = {0};
    static xband_rxtx_data_holder_t xband_rxtx_data_holder = {0};

    if (ImGui::Begin("X-Band Operations", XBAND_window))
    {
        if (ImGui::CollapsingHeader("Data-down Commands", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (access_level <= 0)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            if (!allow_transmission)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "TRANSMISSIONS LOCKED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            if (ImGui::ArrowButton("get_max_on_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                XBAND_command_input.mod = XBAND_ID;
                XBAND_command_input.cmd = XBAND_GET_MAX_ON;
                XBAND_command_input.unused = 0x0;
                XBAND_command_input.data_size = 0x0;
                memset(XBAND_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &XBAND_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&XBAND_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Max On");

            if (ImGui::ArrowButton("get_tmp_shdn_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                XBAND_command_input.mod = XBAND_ID;
                XBAND_command_input.cmd = XBAND_GET_TMP_SHDN;
                XBAND_command_input.unused = 0x0;
                XBAND_command_input.data_size = 0x0;
                memset(XBAND_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &XBAND_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&XBAND_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Shutdown Temperature (TMP SHDN)");

            if (ImGui::ArrowButton("get_tmp_op_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                XBAND_command_input.mod = XBAND_ID;
                XBAND_command_input.cmd = XBAND_GET_TMP_OP;
                XBAND_command_input.unused = 0x0;
                XBAND_command_input.data_size = 0x0;
                memset(XBAND_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &XBAND_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&XBAND_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Return to Operation Temperature (TMP OP)");

            if (ImGui::ArrowButton("get_loop_time_button", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                XBAND_command_input.mod = XBAND_ID;
                XBAND_command_input.cmd = XBAND_GET_LOOP_TIME;
                XBAND_command_input.unused = 0x0;
                XBAND_command_input.data_size = 0x0;
                memset(XBAND_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &XBAND_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&XBAND_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Loop Time");

            if (!allow_transmission)
            {
                ImGui::PopStyleColor();
            }

            if (access_level <= 0)
            {
                ImGui::PopStyleColor();
            }
        }

        ImGui::Separator();

        if (ImGui::CollapsingHeader("Data-up Commands", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (access_level <= 1)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
                flag = ImGuiInputTextFlags_ReadOnly;
            }
            ImGui::Indent();

            ImGui::RadioButton("Set Transmit", &XBAND_command, XBAND_SET_TX);
            ImGui::InputFloat("TX LO", &xband_set_data.TX.LO, 0.0f, 0.0f, "%.3e", flag);
            ImGui::InputFloat("TX bw", &xband_set_data.TX.bw, 0.0f, 0.0f, "%.3e", flag);
            ImGui::InputInt("TX Samp", &xband_set_data.TXH.samp, 1, 100, flag);
            if (xband_set_data.TXH.samp > 0xFFFF)
            {
                xband_set_data.TXH.samp = 0xFFFF;
            }
            else if (xband_set_data.TXH.samp < 0)
            {
                xband_set_data.TXH.samp = 0;
            }
            xband_set_data.TX.samp = (uint16_t)xband_set_data.TXH.samp;

            ImGui::InputInt("TX Phy Gain", &xband_set_data.TXH.phy_gain, 1, 100, flag);
            if (xband_set_data.TXH.phy_gain > 0xFF)
            {
                xband_set_data.TXH.phy_gain = 0xFF;
            }
            else if (xband_set_data.TXH.phy_gain < 0)
            {
                xband_set_data.TXH.phy_gain = 0;
            }
            xband_set_data.TX.phy_gain = (uint8_t)xband_set_data.TXH.phy_gain;

            ImGui::InputInt("TX Adar Gain", &xband_set_data.TXH.adar_gain, 1, 100, flag);
            if (xband_set_data.TXH.adar_gain > 0xFF)
            {
                xband_set_data.TXH.adar_gain = 0xFF;
            }
            else if (xband_set_data.TXH.adar_gain < 0)
            {
                xband_set_data.TXH.adar_gain = 0;
            }
            xband_set_data.TX.adar_gain = (uint8_t)xband_set_data.TXH.adar_gain;

            ImGui::Combo("TX Filter", &xband_set_data.TXH.ftr, "m_6144.ftr\0m_3072.ftr\0m_1000.ftr\0m_lte5.ftr\0m_lte1.ftr\0\0");
            xband_set_data.TX.ftr = (uint8_t)xband_set_data.TXH.ftr;

            ImGui::InputInt4("TX Phase [0]  [1]  [2]  [3]", &xband_set_data.TXH.phase[0], flag);
            ImGui::InputInt4("TX Phase [4]  [5]  [6]  [7]", &xband_set_data.TXH.phase[4], flag);
            ImGui::InputInt4("TX Phase [8]  [9]  [10] [11]", &xband_set_data.TXH.phase[8], flag);
            ImGui::InputInt4("TX Phase [12] [13] [14] [15]", &xband_set_data.TXH.phase[12], flag);
            for (int i = 0; i < 16; i++)
            {
                if (xband_set_data.TXH.phase[i] > 32767)
                {
                    xband_set_data.TXH.phase[i] = 32767;
                }
                else if (xband_set_data.TXH.phase[i] < -32768)
                {
                    xband_set_data.TXH.phase[i] = -32768;
                }
                xband_set_data.TX.phase[i] = (short)xband_set_data.TXH.phase[i];
            }

            ImGui::Separator();

            ImGui::RadioButton("Set Receive", &XBAND_command, XBAND_SET_RX);
            ImGui::InputFloat("RX LO", &xband_set_data.RX.LO, 0.0f, 0.0f, "%.3e", flag);
            ImGui::InputFloat("RX bw", &xband_set_data.RX.bw, 0.0f, 0.0f, "%.3e", flag);
            ImGui::InputInt("RX Samp", &xband_set_data.RXH.samp, 1, 100, flag);
            if (xband_set_data.RXH.samp > 0xFFFF)
            {
                xband_set_data.RXH.samp = 0xFFFF;
            }
            else if (xband_set_data.RXH.samp < 0)
            {
                xband_set_data.RXH.samp = 0;
            }
            xband_set_data.RX.samp = (uint16_t)xband_set_data.RXH.samp;

            ImGui::InputInt("RX Phy Gain", &xband_set_data.RXH.phy_gain, 1, 100, flag);
            if (xband_set_data.RXH.phy_gain > 0xFF)
            {
                xband_set_data.RXH.phy_gain = 0xFF;
            }
            else if (xband_set_data.RXH.phy_gain < 0)
            {
                xband_set_data.RXH.phy_gain = 0;
            }
            xband_set_data.RX.phy_gain = (uint8_t)xband_set_data.RXH.phy_gain;

            ImGui::InputInt("RX Adar Gain", &xband_set_data.RXH.adar_gain, 1, 100, flag);
            if (xband_set_data.RXH.adar_gain > 0xFF)
            {
                xband_set_data.RXH.adar_gain = 0xFF;
            }
            else if (xband_set_data.RXH.adar_gain < 0)
            {
                xband_set_data.RXH.adar_gain = 0;
            }
            xband_set_data.RX.adar_gain = (uint8_t)xband_set_data.RXH.adar_gain;

            ImGui::Combo("RX Filter", &xband_set_data.RXH.ftr, "m_6144.ftr\0m_3072.ftr\0m_1000.ftr\0m_lte5.ftr\0m_lte1.ftr\0\0");
            xband_set_data.RX.ftr = (uint8_t)xband_set_data.RXH.ftr;

            ImGui::InputInt4("RX Phase [0]  [1]  [2]  [3]", &xband_set_data.RXH.phase[0], flag);
            ImGui::InputInt4("RX Phase [4]  [5]  [6]  [7]", &xband_set_data.RXH.phase[4], flag);
            ImGui::InputInt4("RX Phase [8]  [9]  [10] [11]", &xband_set_data.RXH.phase[8], flag);
            ImGui::InputInt4("RX Phase [12] [13] [14] [15]", &xband_set_data.RXH.phase[12], flag);
            for (int i = 0; i < 16; i++)
            {
                if (xband_set_data.RXH.phase[i] > 32767)
                {
                    xband_set_data.RXH.phase[i] = 32767;
                }
                else if (xband_set_data.RXH.phase[i] < -32768)
                {
                    xband_set_data.RXH.phase[i] = -32768;
                }
                xband_set_data.RX.phase[i] = (short)xband_set_data.RXH.phase[i];
            }

            ImGui::Separator();

            ImGui::RadioButton("Set MAX ON", &XBAND_command, XBAND_SET_MAX_ON);
            ImGui::InputInt("Max On", &xband_rxtx_data_holder.max_on, 1, 100, flag);
            if (xband_rxtx_data_holder.max_on > 0xFF)
            {
                xband_rxtx_data_holder.max_on = 0xFF;
            }
            else if (xband_rxtx_data_holder.max_on < 0)
            {
                xband_rxtx_data_holder.max_on = 0;
            }
            xband_rxtx_data.max_on = (uint8_t)xband_rxtx_data_holder.max_on;

            ImGui::Separator();

            ImGui::RadioButton("Set Shutdown Temperature (TMP SHDN)", &XBAND_command, XBAND_SET_TMP_SHDN);
            ImGui::InputInt("TMP SHDN", &xband_rxtx_data_holder.tmp_shdn, 1, 100, flag);
            if (xband_rxtx_data_holder.tmp_shdn > 0xFF)
            {
                xband_rxtx_data_holder.tmp_shdn = 0xFF;
            }
            else if (xband_rxtx_data_holder.tmp_shdn < 0)
            {
                xband_rxtx_data_holder.tmp_shdn = 0;
            }
            xband_rxtx_data.tmp_shdn = (uint8_t)xband_rxtx_data_holder.tmp_shdn;

            ImGui::Separator();

            ImGui::RadioButton("Set Return to Operation Temperature (TMP OP)", &XBAND_command, XBAND_SET_TMP_OP);
            ImGui::InputInt("TMP OP", &xband_rxtx_data_holder.tmp_op, 1, 100, flag);
            if (xband_rxtx_data_holder.tmp_op > 0xFF)
            {
                xband_rxtx_data_holder.tmp_op = 0xFF;
            }
            else if (xband_rxtx_data_holder.tmp_op < 0)
            {
                xband_rxtx_data_holder.tmp_op = 0;
            }
            xband_rxtx_data.tmp_op = (uint8_t)xband_rxtx_data_holder.tmp_op;

            ImGui::Separator();

            ImGui::RadioButton("Set Loop Time", &XBAND_command, XBAND_SET_LOOP_TIME);
            ImGui::InputInt("Loop Time", &xband_rxtx_data_holder.loop_time, 1, 100, flag);
            if (xband_rxtx_data_holder.loop_time > 0xFF)
            {
                xband_rxtx_data_holder.loop_time = 0xFF;
            }
            else if (xband_rxtx_data_holder.loop_time < 0)
            {
                xband_rxtx_data_holder.loop_time = 0;
            }
            xband_rxtx_data.loop_time = (uint8_t)xband_rxtx_data_holder.loop_time;

            ImGui::Unindent();

            if (access_level <= 1)
            {
                ImGui::PopStyleColor();
                flag = (ImGuiInputTextFlags_)0;
            }
        }

        ImGui::Separator();

        if (ImGui::CollapsingHeader("Executable Commands", ImGuiTreeNodeFlags_DefaultOpen))
        {

            if (access_level <= 1)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
                flag = ImGuiInputTextFlags_ReadOnly;
            }

            ImGui::RadioButton("Transmit", &XBAND_command, XBAND_DO_TX);
            ImGui::InputInt("TX type", &xband_tx_data_holder.type, 1, 100, flag);
            if (xband_tx_data_holder.type > 255)
            {
                xband_tx_data_holder.type = 255;
            }
            else if (xband_tx_data_holder.type < 0)
            {
                xband_tx_data_holder.type = 0;
            }
            xband_tx_data.type = (uint8_t)xband_tx_data_holder.type;

            ImGui::InputInt("TX f_id", &xband_tx_data.f_id, 1, 100, flag);
            ImGui::InputInt("TX mtu", &xband_tx_data.mtu, 1, 100, flag);

            ImGui::Separator();

            ImGui::RadioButton("Receive", &XBAND_command, XBAND_DO_RX);
            ImGui::SameLine();
            ImGui::Text("(NYI)");

            ImGui::Separator();

            ImGui::RadioButton("Disable", &XBAND_command, XBAND_DISABLE);
            ImGui::SameLine();
            ImGui::Text("(NYI)");

            if (access_level <= 1)
            {
                ImGui::PopStyleColor();
                flag = (ImGuiInputTextFlags_)0;
            }
        }
    }

    XBAND_command_input.mod = XBAND_ID;
    XBAND_command_input.cmd = XBAND_command;

    ImGui::Separator();

    if (ImGui::CollapsingHeader("Transmit", ImGuiTreeNodeFlags_DefaultOpen))
    {
        switch (XBAND_command_input.cmd)
        {
        case XBAND_SET_TX:
        {
            memcpy(XBAND_command_input.data, &xband_set_data.TX, sizeof(xband_set_data_t));
            XBAND_command_input.data_size = sizeof(xband_set_data_t);
            break;
        }
        case XBAND_SET_RX:
        {
            memcpy(XBAND_command_input.data, &xband_set_data.RX, sizeof(xband_set_data_t));
            XBAND_command_input.data_size = sizeof(xband_set_data_t);
            break;
        }
        case XBAND_DO_TX:
        {
            memcpy(XBAND_command_input.data, &xband_tx_data, sizeof(xband_tx_data_t));
            XBAND_command_input.data_size = sizeof(xband_tx_data_t);
            break;
        }
        case XBAND_DO_RX:
        {
            // Not yet implemented on SPACE-HAUC.
            printf("This functionality is not implemented as it does not yet exist on SPACE-HAUC.\n");
            break;
        }
        case XBAND_DISABLE:
        {
            // Not yet implemented on SPACE-HAUC.
            printf("This functionality is not implemented as it does not yet exist on SPACE-HAUC.\n");
            break;
        }
        case XBAND_SET_MAX_ON:
        {
            // cmd_parser expects an int8_t for data.
            XBAND_command_input.data[0] = (uint8_t)xband_rxtx_data.max_on;
            XBAND_command_input.data_size = sizeof(xband_tx_data_t);
            break;
        }
        case XBAND_SET_TMP_SHDN:
        {
            // cmd_parser expects an int8_t for data.
            XBAND_command_input.data[0] = (uint8_t)xband_rxtx_data.tmp_shdn;
            XBAND_command_input.data_size = sizeof(xband_tx_data_t);
            break;
        }
        case XBAND_SET_TMP_OP:
        {
            // cmd_parser expects an int8_t for data.
            XBAND_command_input.data[0] = (uint8_t)xband_rxtx_data.tmp_op;
            XBAND_command_input.data_size = sizeof(xband_tx_data_t);
            break;
        }
        case XBAND_SET_LOOP_TIME:
        {
            // cmd_parser expects an int8_t for data.
            // XBAND_command_input is a structure that is transmitted.
            // .data contains the data expected by SH's cmd_parser
            // xband_rxtx_data is just a convenient structure for collecting user input
            XBAND_command_input.data[0] = (uint8_t)xband_rxtx_data.tmp_op;
            break;
        }
        default:
        {
            XBAND_command_input.data_size = -1;
        }
        }

        gs_gui_gs2sh_tx_handler(network_data, access_level, &XBAND_command_input, allow_transmission);
    }

    ImGui::End();
}

// BOOKMARK

// BOOKMARK

// BOOKMARK

void gs_gui_xband_tx_window(global_data_t *global, bool *XBAND_TX_window, int access_level, bool allow_transmission)
{
    static char refreshing_icon[5][11] =
        {
            "    ||    ",
            "   |  |   ",
            "  |    |  ",
            " |      | ",
            "|        |",
        };

    NetData *network_data = global->network_data;
    char *recv_status_buffer = global->recv_status_buffer;
    char *read_status_buffer = global->read_status_buffer;
    phy_config_t *rxphy = global->rxphy;
    phy_config_t *txphy = global->txphy;

    static char *mode_str[] = {"sleep", "fdd  ", "tdd  "};

    static bool first_pass = true;
    if (first_pass)
    {
        global->refresh_rx_ui_data = true;
        global->refresh_tx_ui_data = true;
        first_pass = false;
    }
    

    if (ImGui::Begin("Rooftop X-Band Configuration", NULL))
    {
        if (!global->xbrx_avail)
            rxphy->pll_lock = false;
        if (!global->xbtx_avail)
            txphy->pll_lock = false;
        if (rxphy->mode && txphy->mode && (rxphy->pll_freq == txphy->pll_freq) && (fabs(txphy->LO - rxphy->LO) < 1000))
        {
            rxphy->rssi = 40;
        }
        if (ImGui::Checkbox("Receiver Connection", &global->xbrx_avail))
        {
            // rxmode = 0;
            // rxphy->mode = 0; // sleep
            // snprintf(rxphy->curr_gainmode, sizeof(rxphy->curr_gainmode), "slow_attack");
            // rxphy->temp = 20570;
            // rxphy->rssi = 102;
            // rxphy->bw = MHZ(10);
            // rxphy->LO = GHZ(2.4);
            // rxphy->samp = MHZ(10);
            // rx_samp = HZ_M(rxphy->samp);
            // rx_lo = HZ_M(rxphy->LO);
            // rx_bw = HZ_M(rxphy->bw);
            // rxphy->pll_lock = 0;
            // rxphy->gain = -60; // set gain to low for RX
        }
        ImGui::SameLine();

        if (ImGui::Checkbox("Transmitter Connection", &global->xbtx_avail))
        {
            // dbprintlf(GREEN_FG "XBTX AVAILABLE!");
            // txmode = 0;
            // txphy->mode = 0; // sleep
            // txphy->temp = 22630;
            // txphy->rssi = 0;
            // txphy->bw = MHZ(10);
            // txphy->LO = GHZ(2.45);
            // txphy->samp = MHZ(10);
            // tx_samp = HZ_M(txphy->samp);
            // tx_lo = HZ_M(txphy->LO);
            // tx_bw = HZ_M(txphy->bw);
            // txphy->pll_lock = 0;
            // txphy->gain = 0;
            // tx_gain = 0;
        }
        ImGui::Separator();
        ImGui::Separator();
        ImGui::Text("Receiver Configuration");
        ImGui::Columns(5, "xb_rx_sensors", true);
        ImGui::Text("PLL Lock: %s", rxphy->pll_lock ? "YES" : "NO ");
        ImGui::NextColumn();
        ImGui::Text("System Mode: %s", mode_str[rxphy->mode]);
        ImGui::NextColumn();
        ImGui::Text("Temperature: %.3f °C", rxphy->temp * 0.001);
        ImGui::NextColumn();
        ImGui::Text("RSSI: -%.2lf dB", rxphy->rssi);
        ImGui::NextColumn();
        ImGui::Text("Gain Control: %s", rxphy->curr_gainmode);
        ImGui::Columns(1);
        ImGui::Separator();
        ImGui::Columns(3, "xb_rx_freqs", true);
        ImGui::Text("LO: %lld Hz", rxphy->LO);
        ImGui::NextColumn();
        ImGui::Text("Samp: %lld Hz", rxphy->bw);
        ImGui::NextColumn();
        ImGui::Text("BW: %lld Hz", rxphy->samp);
        ImGui::Columns(1);
        ImGui::Separator();
        ImGui::Combo("PLL Frequency##RX", &(rxphy->pll_freq), pll_freq_str, IM_ARRAYSIZE(pll_freq_str));
        if (ImGui::Button("Initialize PLL##RX") && global->xbrx_avail)
        {
            rxphy->pll_lock = true;

            XBAND_COMMAND command = XBC_INIT_PLL;
            NetFrame *network_frame = new NetFrame((unsigned char *)&command, sizeof(command), NetType::XBAND_COMMAND, NetVertex::HAYSTACK);
            network_frame->sendFrame(network_data);
            delete network_frame;
        }
        ImGui::SameLine();
        if (ImGui::Button("Disable PLL##RX"))
        {
            rxphy->pll_lock = false;

            XBAND_COMMAND command = XBC_DISABLE_PLL;
            NetFrame *network_frame = new NetFrame((unsigned char *)&command, sizeof(command), NetType::XBAND_COMMAND, NetVertex::HAYSTACK);
            network_frame->sendFrame(network_data);
            delete network_frame;
        }
        ImGui::Separator();
        ImGui::InputFloat("RX Sample Rate (MHz)", &global->rx_samp, 0, 0, "%.3f", ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::InputFloat("RX LO (MHz)", &global->rx_lo, 0, 0, "%.3f", ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::InputFloat("RX BW (MHz)", &global->rx_bw, 0, 0, "%.3f", ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::InputText("RX Filter", rxphy->ftr_name, sizeof(rxphy->ftr_name), ImGuiInputTextFlags_AutoSelectAll);
        ImGui::Combo("Mode##RX", (int *)&global->rxmode, mode_str, IM_ARRAYSIZE(mode_str));
        if (ImGui::Button("Apply Configuration##RX"))
        {
            global->refresh_rx_ui_data = true;

            if (global->rxmode)
            {
                rxphy->mode = global->rxmode;
                rxphy->samp = MHZ(global->rx_samp);
                rxphy->LO = MHZ(global->rx_lo);
                rxphy->bw = MHZ(global->rx_bw);
            }
            else if (!global->rx_armed)
                rxphy->mode = global->rxmode;

            NetFrame *network_frame = new NetFrame((unsigned char *)&rxphy, sizeof(phy_config_t), NetType::XBAND_CONFIG, NetVertex::HAYSTACK);
            network_frame->sendFrame(network_data);
            delete network_frame;
        }
        if (ImGui::Button("Refresh RX Data"))
        {
            global->refresh_rx_ui_data = true;
            // dbprintlf("RX UI marked for refresh.");
        }

        static int r_rx_i = 0;
        static int r_rx_factor = 10;
        if (global->refresh_rx_ui_data)
        {
            ImGui::SameLine();
            r_rx_i = (r_rx_i + 1) % (5 * r_rx_factor);
            ImGui::Text("%s", refreshing_icon[r_rx_i / r_rx_factor]);
        }
        else
        {
            if (r_rx_i)
            {
                r_rx_i = 0;
            }
        }

        ImGui::Separator();
        ImGui::Separator();

        ImGui::Text("Transmitter Configuration");
        ImGui::Columns(3, "xb_tx_sensors", true);
        ImGui::Text("PLL Lock: %s", txphy->pll_lock ? "YES" : "NO ");
        ImGui::NextColumn();
        ImGui::Text("System Mode: %s", mode_str[txphy->mode]);
        ImGui::NextColumn();
        ImGui::Text("Temperature: %.3f °C", txphy->temp * 0.001);
        ImGui::Columns(1);
        ImGui::Separator();
        ImGui::Columns(3, "xb_tx_freqs", true);
        ImGui::Text("LO: %lld Hz", txphy->LO);
        ImGui::NextColumn();
        ImGui::Text("Samp: %lld Hz", txphy->bw);
        ImGui::NextColumn();
        ImGui::Text("BW: %lld Hz", txphy->samp);
        ImGui::Columns(1);
        ImGui::Separator();
        ImGui::Combo("PLL Frequency##TX", &(txphy->pll_freq), pll_freq_str, IM_ARRAYSIZE(pll_freq_str));
        if (ImGui::Button("Initialize PLL##TX") && global->xbtx_avail)
        {
            txphy->pll_lock = true;

            XBAND_COMMAND command = XBC_INIT_PLL;
            NetFrame *network_frame = new NetFrame((unsigned char *)&command, sizeof(command), NetType::XBAND_COMMAND, NetVertex::ROOFXBAND);
            network_frame->sendFrame(network_data);
            delete network_frame;
        }
        ImGui::SameLine();
        if (ImGui::Button("Disable PLL##TX"))
        {
            txphy->pll_lock = false;

            XBAND_COMMAND command = XBC_DISABLE_PLL;
            NetFrame *network_frame = new NetFrame((unsigned char *)&command, sizeof(command), NetType::XBAND_COMMAND, NetVertex::ROOFXBAND);
            network_frame->sendFrame(network_data);
            delete network_frame;
        }
        ImGui::Separator();
        ImGui::InputFloat("TX Sample Rate (MHz)", &global->tx_samp, 0, 0, "%.3f", ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::InputFloat("TX LO (MHz)", &global->tx_lo, 0, 0, "%.3f", ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::InputFloat("TX BW (MHz)", &global->tx_bw, 0, 0, "%.3f", ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::InputText("TX Filter", txphy->ftr_name, sizeof(txphy->ftr_name), ImGuiInputTextFlags_AutoSelectAll);
        ImGui::InputFloat("TX Gain", &global->tx_gain, 0, 0, "%.2f", ImGuiInputTextFlags_AutoSelectAll);
        ImGui::Combo("Mode##TX", (int *)&global->txmode, mode_str, IM_ARRAYSIZE(mode_str));

        if (ImGui::InputInt("MTU", &global->MTU, 0, 0, ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_EnterReturnsTrue))
        {
            txphy->MTU = global->MTU;
            // dbprintlf(RED_BG "UI: %u, txphy: %u", MTU, txphy->MTU);
        }
        if (ImGui::Button("Apply Configuration##TX"))
        {
            global->refresh_tx_ui_data = true;

            if (global->txmode)
            {
                txphy->mode = global->txmode;
                txphy->samp = MHZ(global->tx_samp);
                txphy->LO = MHZ(global->tx_lo);
                txphy->bw = MHZ(global->tx_bw);
                txphy->gain = global->tx_gain;
            }
            else
            {
                txphy->mode = global->txmode;
            }

            // dbprintlf(RED_BG "Sending MTU of %u", txphy->MTU);

            NetFrame *network_frame = new NetFrame((unsigned char *)&txphy, sizeof(phy_config_t), NetType::XBAND_CONFIG, NetVertex::ROOFXBAND);
            network_frame->sendFrame(network_data);
            delete network_frame;
        }
        if (ImGui::Button("Refresh TX Data"))
        {
            global->refresh_tx_ui_data = true;
            // dbprintlf("TX UI marked for refresh.");
        }

        static int r_tx_i = 0;
        static int r_tx_factor = 10;
        if (global->refresh_tx_ui_data)
        {
            ImGui::SameLine();
            r_tx_i = (r_tx_i + 1) % (5 * r_tx_factor);
            ImGui::Text("%s", refreshing_icon[r_tx_i / r_tx_factor]);
        }
        else
        {
            if (r_tx_i)
            {
                r_tx_i = 0;
            }
        }

        ImGui::Separator();
        ImGui::Separator();
        if (global->xbrx_avail && (rxphy->mode > 0) && !global->rx_armed)
            ImGui::PushStyleColor(0, COLOR_GREEN);
        else if (global->rx_armed)
            ImGui::PushStyleColor(0, COLOR_YLW);
        else
            ImGui::PushStyleColor(0, COLOR_RED);
        if (ImGui::Button("Arm Receiver") && global->xbrx_avail && (rxphy->mode > 0))
        {
            // TODO: The RX being armed should not be assumed; fill this value by polling for status!
            global->rx_armed = true;

            XBAND_COMMAND command = XBC_ARM_RX;
            NetFrame *network_frame = new NetFrame((unsigned char *)&command, sizeof(command), NetType::XBAND_COMMAND, NetVertex::HAYSTACK);
            network_frame->sendFrame(network_data);
            delete network_frame;
        }
        ImGui::PopStyleColor();
        if (global->rx_armed)
            ImGui::PushStyleColor(0, COLOR_GREEN);
        else
            ImGui::PushStyleColor(0, COLOR_RED);
        if (ImGui::Button("Disarm Receiver") && global->rx_armed)
        {
            // TODO: The RX being disarmed should not be assumed; fill this value by polling for status!
            global->rx_armed = false;

            XBAND_COMMAND command = XBC_DISARM_RX;
            NetFrame *network_frame = new NetFrame((unsigned char *)&command, sizeof(command), NetType::XBAND_COMMAND, NetVertex::HAYSTACK);
            network_frame->sendFrame(network_data);
            delete network_frame;
        }
        ImGui::PopStyleColor();
        if (global->xbtx_avail && (txphy->mode > 0))
            ImGui::PushStyleColor(0, COLOR_GREEN);
        else
            ImGui::PushStyleColor(0, COLOR_RED);
        if (ImGui::Button("Transmit Test Packet"))
        {
            global->last_xbread_status = -100;
            global->last_xbrx_status = -100;

            // Sends a test packet (ACS update) to SPACE-HAUC.

            NetFrame *network_frame = new NetFrame((unsigned char *)test_cmd, sizeof(test_cmd), NetType::DATA, NetVertex::ROOFXBAND);
            network_frame->sendFrame(network_data);
            delete network_frame;
        }
        if (ImGui::Button("Transmit MEGA PACKET"))
        {
            global->last_xbread_status = -100;
            global->last_xbrx_status = -100;

            // NetFrame *network_frame = new NetFrame((unsigned char *)mega_packet, sizeof(mega_packet), NetType::DATA, NetVertex::ROOFXBAND);
            // network_frame->sendFrame(network_data);
            // delete network_frame;

            char *buffer;

            int fd = open("amontillado.txt", O_RDONLY);

            if (fd > 2)
            {
                ssize_t size = global->mega_packet_file_size = (
                    {
                        struct stat s;
                        fstat(fd, &s);
                        s.st_size;
                    });
                // ssize_t size = mega_packet_file_size = sizeof(mega_packet);
                ssize_t page_sz = sysconf(_SC_PAGESIZE);
                ssize_t malloc_sz = page_sz * (size / page_sz) + (size % page_sz ? page_sz : 0);
                buffer = (char *)malloc(malloc_sz);
                ssize_t rd_sz = /*malloc_sz;*/ read(fd, buffer, size); // - 5924 works, -5923 does not
                // memcpy(buffer, mega_packet, sizeof(mega_packet));
                close(fd);
                dbprintlf(GREEN_FG "MEGA PACKET: File size: %ld, malloc size: %ld, read: %ld", size, malloc_sz, rd_sz);
                global->mega_packet_crc = internal_crc16((uint8_t *)buffer, rd_sz);

                NetFrame *network_frame2 = new NetFrame((uint8_t *)buffer, rd_sz, NetType::DATA, NetVertex::ROOFXBAND);
                dbprintlf(GREEN_FG "MEGA PACKET: Sent: %ld bytes", network_frame2->sendFrame(network_data));
                free(buffer);

                for (int i = 0; i < sizeof(NetFrameHeader); i++)
                {
                }

                delete network_frame2;
            }
            else
            {
                dbprintlf(RED_FG "File pointer NULL.");
            }
        }
        ImGui::PopStyleColor();

        if (ImGui::Button("Clear Statuses"))
        {
            global->last_xbread_status = -100;
            global->last_xbrx_status = -100;
        }

        if (global->last_xbread_status == -100)
        {
            snprintf(read_status_buffer, 256, "N/A");
        }
        else if (global->last_xbread_status > 0)
        {
            snprintf(read_status_buffer, 256, "Read %d bytes.", global->last_xbread_status);
        }
        else
        {
            snprintf(read_status_buffer, 256, "UNKNOWN STATUS: %d", global->last_xbread_status);
        }

        if (global->last_xbrx_status == -100)
        {
            snprintf(recv_status_buffer, 256, "N/A");
        }
        else if (global->last_xbrx_status > 0)
        {
            snprintf(recv_status_buffer, 256, "Received %d bytes.", global->last_xbrx_status);
        }
        else
        {
            switch (global->last_xbrx_status)
            {
            case RX_FRAME_INVALID:
            {
                snprintf(recv_status_buffer, 256, "RX_FRAME_INVALID (%d)", global->last_xbrx_status);
                break;
            }
            case RX_INVALID_GUID:
            {
                snprintf(recv_status_buffer, 256, "RX_INVALID_GUID (%d)", global->last_xbrx_status);
                break;
            }
            case RX_PACK_SZ_ZERO:
            {
                snprintf(recv_status_buffer, 256, "RX_PACK_SZ_ZERO (%d)", global->last_xbrx_status);
                break;
            }
            case RX_NUM_FRAMES_ZERO:
            {
                snprintf(recv_status_buffer, 256, "RX_NUM_FRAMES_ZERO (%d)", global->last_xbrx_status);
                break;
            }
            case RX_FRAME_SZ_ZERO:
            {
                snprintf(recv_status_buffer, 256, "RX_FRAME_SZ_ZERO (%d)", global->last_xbrx_status);
                break;
            }
            case RX_THREAD_SPAWN:
            {
                snprintf(recv_status_buffer, 256, "RX_THREAD_SPAWN (%d)", global->last_xbrx_status);
                break;
            }
            case RX_FRAME_CRC_FAILED:
            {
                snprintf(recv_status_buffer, 256, "RX_FRAME_CRC_FAILED (%d)", global->last_xbrx_status);
                break;
            }
            case RX_MALLOC_FAILED:
            {
                snprintf(recv_status_buffer, 256, "RX_MALLOC_FAILED (%d)", global->last_xbrx_status);
                break;
            }
            case -110:
            {
                snprintf(recv_status_buffer, 256, "Receiver timed out (DON'T PANIC!).", global->last_xbrx_status);
                break;
            }
            case 0:
            {
                snprintf(recv_status_buffer, 256, "Receiver not armed, cannot receive.", global->last_xbrx_status);
                break;
            }
            default:
            {
                snprintf(recv_status_buffer, 256, "UNKNOWN STATUS: %d", global->last_xbrx_status);
                break;
            }
            }
        }
        ImGui::InputText("RX Status", recv_status_buffer, 256, ImGuiInputTextFlags_ReadOnly);
        ImGui::InputText("Read Status", read_status_buffer, 256, ImGuiInputTextFlags_ReadOnly);
    }
    ImGui::End();
}

void gs_gui_xband_rx_window(global_data_t *global, bool *XBAND_RX_window, int access_level, bool allow_transmission)
{
}

void gs_gui_xband_test_window(global_data_t *global, bool *XBAND_TEST_window, int access_level, bool allow_transmission)
{
}

void gs_gui_sw_upd_window(global_data_t *global, bool *SW_UPD_window, int access_level, bool allow_transmission)
{
    // TODO: Make this work, currently this has little to no functionality.

    ImGuiInputTextFlags_ flag = (ImGuiInputTextFlags_)0;
    static cmd_input_t UPD_command_input = {.mod = INVALID_ID, .cmd = INVALID_ID, .unused = 0, .data_size = 0};
    static char upd_filename_buffer[SW_UPD_FN_SIZE] = {0};

    if (ImGui::Begin("Software Updater Control Panel", SW_UPD_window, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar))
    {
        // Needs buttons. Values are just #defines and magic values

        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "WARNING: NOT YET IMPLEMENTED");

        ImGui::Text("Name of the file to send:");
        ImGui::InputTextWithHint("", "Name of File", upd_filename_buffer, 256, ImGuiInputTextFlags_EnterReturnsTrue);

        // NOTE: Queued file name not sent with software update command, needs to be here to select what file to send.
        ImGui::Text("Queued file name: %s", upd_filename_buffer);

        ImGui::Text("Selected File");
        ImGui::Text("%s", upd_filename_buffer);
        ImGui::Text("In progress? %s", global->sw_updating ? "Yes" : "No");

        if (global->sw_upd_total_packets != 0)
        {
            ImGui::ProgressBar((float)global->sw_upd_packet / (float)global->sw_upd_total_packets);
        }

        ImGui::Separator();

        if (access_level <= 2)
        {
            ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
            ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
        }

        if (!allow_transmission)
        {
            ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "TRANSMISSIONS LOCKED");
            ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
        }

        if (global->sw_updating)
        {
            if (ImGui::Button("ABORT UPDATE") && access_level > 2 && allow_transmission)
            {
                global->sw_updating = false;
            }

            if (!global->network_data->connection_ready)
            {
                dbprintf(FATAL "Update canceled due to loss of connection with server!");
                global->sw_updating = false;
            }
        }
        else
        {
            if (ImGui::Button("BEGIN UPDATE") && access_level > 2 && allow_transmission)
            {
                global->sw_updating = true;

                static pthread_t sw_upd_tid;

                strcpy(global->directory, "sendables/");
                snprintf(global->filename, 20, upd_filename_buffer);

                pthread_create(&sw_upd_tid, NULL, gs_sw_send_file_thread, global);
            }
        }

        if (!allow_transmission)
        {
            ImGui::PopStyleColor();
        }

        if (access_level <= 2)
        {
            ImGui::PopStyleColor();
        }
    }
    ImGui::End();
}

void gs_gui_sys_ctrl_window(NetDataClient *network_data, bool *SYS_CTRL_window, int access_level, bool allow_transmission)
{
    // static int SYS_command = INVALID_ID;
    static cmd_input_t SYS_command_input = {.mod = INVALID_ID, .cmd = INVALID_ID, .unused = 0, .data_size = 0};
    static cmd_input_holder_t SYS_command_input_holder = {0};

    if (ImGui::Begin("System Control Panel", SYS_CTRL_window, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar))
    {
        if (ImGui::CollapsingHeader("Data-down Commands", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (access_level <= 0)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            if (!allow_transmission)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "TRANSMISSIONS LOCKED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            if (ImGui::ArrowButton("get_version_magic", ImGuiDir_Right) && access_level > 0 && allow_transmission)
            {
                SYS_command_input.mod = SYS_VER_MAGIC;
                SYS_command_input.cmd = 0x0;
                SYS_command_input.unused = 0x0;
                SYS_command_input.data_size = 0x0;
                memset(SYS_command_input.data, 0x0, MAX_DATA_SIZE);
                // gs_transmit(network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, &SYS_command_input, sizeof(cmd_input_t));
                NetFrame *network_frame = new NetFrame((unsigned char *)&SYS_command_input, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
            ImGui::SameLine();
            ImGui::Text("Get Version Magic");

            if (!allow_transmission)
            {
                ImGui::PopStyleColor();
            }

            if (access_level <= 0)
            {
                ImGui::PopStyleColor();
            }
        }

        ImGui::Separator();

        if (ImGui::CollapsingHeader("Data-up Commands", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (access_level <= 2)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
            }

            // NOTE: Since IMGUI only accepts full integers, we have to use a temporary full integer structure to hold them before converting to uint8_t, which is what SPACE-HAUC requires.
            ImGui::RadioButton("Restart Program", &SYS_command_input_holder.mod, SYS_RESTART_PROG);
            ImGui::RadioButton("Reboot Flight", &SYS_command_input_holder.mod, SYS_REBOOT);
            ImGui::RadioButton("Clean SHBYTES", &SYS_command_input_holder.mod, SYS_CLEAN_SHBYTES);

            SYS_command_input.mod = (uint8_t)SYS_command_input_holder.mod;

            if (access_level <= 2)
            {
                ImGui::PopStyleColor();
            }
        }

        ImGui::Separator();

        if (ImGui::CollapsingHeader("Transmit", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (allow_transmission)
            {
                ImGui::Indent();

                if (access_level <= 2)
                {
                    ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "ACCESS DENIED");
                    ImGui::PushStyleColor(0, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
                }

                switch (SYS_command_input.mod)
                {
                case SYS_RESTART_PROG:
                {
                    SYS_command_input.data_size = 0;
                    break;
                }
                case SYS_REBOOT:
                {
                    SYS_command_input.data_size = sizeof(uint64_t);
                    SYS_command_input.cmd = SYS_REBOOT_FUNC_MAGIC;
                    long temp = SYS_REBOOT_FUNC_VAL;
                    memcpy(SYS_command_input.data, &temp, SYS_command_input.data_size);

                    SYS_command_input.unused = 0x0;

                    break;
                }
                case SYS_CLEAN_SHBYTES:
                {
                    SYS_command_input.data_size = 0;
                    SYS_command_input.cmd = SYS_CLEAN_SHBYTES;

                    SYS_command_input.unused = 0x0;
                    memset(SYS_command_input.data, 0x0, MAX_DATA_SIZE);
                    break;
                }
                default:
                {
                    SYS_command_input.data_size = -1;
                    break;
                }
                }
                ImGui::Unindent();

                gs_gui_gs2sh_tx_handler(network_data, access_level, &SYS_command_input, allow_transmission);

                if (access_level <= 2)
                {
                    ImGui::PopStyleColor();
                }
            }
            else
            {
                ImGui::Text("TRANSMISSIONS LOCKED");
            }
        }
    }
    ImGui::End();
}

void gs_gui_rx_display_window(bool *RX_display, global_data_t *global)
{
    if (ImGui::Begin("Plaintext RX Display"), RX_display)
    {
        ImGui::Text("ACKNOWLEDGEMENT");
        ImGui::Separator();
        ImGui::Text("N/ACK ------------ %d", global->cs_ack->ack);
        ImGui::Text("Code ------------- %d", global->cs_ack->code);
        ImGui::Separator();
        ImGui::Separator();

        ImGui::Text("UHF CONFIGURATION");
        ImGui::Separator();
        ImGui::Text("WIP");
        ImGui::Separator();
        ImGui::Separator();

        ImGui::Text("X-BAND CONFIGURATION");
        ImGui::Separator();
        ImGui::Text("WIP");
        ImGui::Separator();
        ImGui::Separator();

        ImGui::Text("SPACE-HAUC COMMAND OUTPUT");
        ImGui::Separator();
        ImGui::Text("Module ----------- %d", global->cmd_output->mod);
        ImGui::Text("Command ---------- %d", global->cmd_output->cmd);
        ImGui::Text("Return Value ----- %d", global->cmd_output->retval);
        ImGui::Text("Data Size -------- %d", global->cmd_output->data_size);
        ImGui::Text("Data (hex) ------- ");
        for (int i = 0; i < global->cmd_output->data_size; i++)
        {
            ImGui::SameLine(0.0F, 0.0F);
            ImGui::Text("%2x", global->cmd_output->data[i]);
        }
        ImGui::Separator();
        ImGui::Separator();

        ImGui::Text("RADIOS STATUS");

        ImGui::Text("GUI Client ------- %d", ((global->netstat & 0x80) == 0x80) ? 1 : 0);
        ImGui::Text("Roof UHF --------- %d", ((global->netstat & 0x40) == 0x40) ? 1 : 0);
        ImGui::Text("Roof X-Band ------ %d", ((global->netstat & 0x20) == 0x20) ? 1 : 0);
        ImGui::Text("Haystack --------- %d", ((global->netstat & 0x10) == 0x10) ? 1 : 0);
        ImGui::Text("Track ------------ %d", ((global->netstat & 0x8) == 0x8) ? 1 : 0);
    }
    ImGui::End();
}

void gs_gui_conns_manager_window(bool *CONNS_manager, int access_level, bool allow_transmission, global_data_t *global, pthread_t *rx_thread_id)
{
    NetDataClient *network_data = global->network_data;

    if (ImGui::Begin("Connections Manager", CONNS_manager, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar))
    {

        // static int port = LISTENING_PORT;
        // static char ipaddr[16] = LISTENING_IP_ADDRESS;

        if (!network_data->recv_active)
        {
            if (ImGui::Button("Start Receive Thread"))
            {
                network_data->recv_active = true;
                pthread_create(rx_thread_id, NULL, gs_rx_thread, global);
            }
        }
        else
        {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Receive Thread Active");
        }

        auto flag = ImGuiInputTextFlags_ReadOnly;
        if (!(network_data->connection_ready))
        {
            flag = (ImGuiInputTextFlags_)0;
        }

        static char destination_ipv4[32];
        static bool first_pass = true;
        if (first_pass)
        {
            strcpy(destination_ipv4, SERVER_IP); // defaults to our own RX ip
            first_pass = false;
        }
        static int destination_port = (int)NetPort::CLIENT; // defaults to the correct server listening port
        ImGui::InputText("IP Address", destination_ipv4, sizeof(destination_ipv4), flag);
        ImGui::InputInt("Port", &destination_port, 0, 0, flag);

        ImGui::SameLine();
        ImGui::Text("(?)");
        if (ImGui::IsItemHovered() && global->settings->tooltips)
        {
            ImGui::BeginTooltip();
            ImGui::Text("Server Ports");
            ImGui::Text("54200: GUI Client");
            ImGui::Text("54210: Roof UHF");
            ImGui::Text("54220: Roof X-Band");
            ImGui::Text("54230: Haystack");
            ImGui::EndTooltip();
        }

        static int gui_connect_status = 0;
        static float last_connect_attempt_time = -1;

        if (!(network_data->connection_ready) || network_data->socket < 0)
        {
            if (ImGui::Button("Connect"))
            {
                last_connect_attempt_time = ImGui::GetTime();

                gui_connect_status = gs_connect_to_server(network_data);
                // network_data->server_ip->sin_port = htons(destination_port);
                // if ((network_data->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                // {
                //     dbprintlf(RED_FG "Socket creation error.");
                //     gui_connect_status = 0;
                // }
                // else if (inet_pton(AF_INET, destination_ipv4, &network_data->server_ip->sin_addr) <= 0)
                // {
                //     dbprintlf(RED_FG "Invalid address; address not supported.");
                //     gui_connect_status = 1;
                // }
                // else if (gs_connect(network_data->socket, (struct sockaddr *)network_data->server_ip, sizeof(network_data->server_ip), 1) < 0)
                // {
                //     dbprintlf(RED_FG "Connection failure.");
                //     gui_connect_status = 2;
                // }
                // else
                // {
                //     // If the socket is closed, but recv(...) was already called, it will be stuck trying to receive forever from a socket that is no longer active. One way to fix this is to close the RX thread and restart it. Alternatively, we could implement a recv(...) timeout, ensuring a fresh socket value is used.
                //     // Here, we implement a recv(...) timeout.
                //     struct timeval timeout;
                //     timeout.tv_sec = RECV_TIMEOUT;
                //     timeout.tv_usec = 0;
                //     setsockopt(network_data->socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

                //     network_data->connection_ready = true;
                //     gui_connect_status = -1;

                //     // Send a null frame to populate our status data.
                //     // NetworkFrame *null_frame = new NetworkFrame(CS_TYPE_NULL, 0x0);
                //     // null_frame->storePayload(CS_ENDPOINT_SERVER, NULL, 0);

                //     // send(network_data->socket, null_frame, sizeof(NetworkFrame), 0);
                //     // delete null_frame;
                // }
            }

            switch (gui_connect_status)
            {
            case -1:
            {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(1.0, 0.0, 0.0, 1.0), "SOCKET CREATION ERROR");
            }
            case -2:
            {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(1.0, 0.0, 0.0, 1.0), "INVALID ADDRESS");
            }
            case -3:
            {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(1.0, 0.0, 0.0, 1.0), "CONNECTION FAILURE (%.2f).", last_connect_attempt_time);
            }
            case 0:
            default:
            {
                break;
            }
            }
        }
        else
        {
            if (ImGui::Button("Disconnect"))
            {
                close(network_data->socket);
                network_data->socket = -1;
                strcpy(network_data->disconnect_reason, "USER");
                network_data->connection_ready = false;
            }
        }

        ImGui::Separator();
        ImGui::Separator();

        ImVec4 offline = ImVec4(1.0, 0.0, 0.0, 1.0);
        ImVec4 online = ImVec4(0.0, 1.0, 0.0, 1.0);
        ImVec4 con = ImVec4(0.0, 0.5, 1.0, 1.0);
        ImVec4 discon = ImVec4(0.5, 0.5, 0.5, 1.0);

        if (global->last_contact > 0)
        {
            if (global->network_data->connection_ready)
            {
                ImGui::Text("Current Status (%.0f seconds ago)", ImGui::GetTime() - global->last_contact);
            }
            else
            {
                ImGui::Text("Last Known Status (%.0f seconds ago)", ImGui::GetTime() - global->last_contact);
            }
        }
        else
        {
            ImGui::Text("Last Known Status (No Data)");
        }

        ImGui::Separator();

        ImGui::Text("Server");
        ImGui::SameLine(125.0);
        network_data->connection_ready ? ImGui::TextColored(con, "CONNECTED") : ImGui::TextColored(discon, "DISCONNECTED (%s)", network_data->disconnect_reason);

        ImGui::Text("GUI Client");
        ImGui::SameLine(125.0);
        ((global->netstat & 0x80) == 0x80) ? ImGui::TextColored(online, "ONLINE") : ImGui::TextColored(offline, "OFFLINE");

        ImGui::Text("Roof UHF");
        ImGui::SameLine(125.0);
        ((global->netstat & 0x40) == 0x40) ? ImGui::TextColored(online, "ONLINE") : ImGui::TextColored(offline, "OFFLINE");

        ImGui::Text("Roof X-Band");
        ImGui::SameLine(125.0);
        ((global->netstat & 0x20) == 0x20) ? ImGui::TextColored(online, "ONLINE") : ImGui::TextColored(offline, "OFFLINE");

        ImGui::Text("Haystack");
        ImGui::SameLine(125.0);
        ((global->netstat & 0x10) == 0x10) ? ImGui::TextColored(online, "ONLINE") : ImGui::TextColored(offline, "OFFLINE");

        ImGui::Text("Track");
        ImGui::SameLine(125.0);
        ((global->netstat & 0x8) == 0x8) ? ImGui::TextColored(online, "ONLINE") : ImGui::TextColored(offline, "OFFLINE");

        if (network_data->connection_ready && network_data->socket > 0)
        {
            if (ImGui::Button("SEND TEST FRAME"))
            {
                NetFrame *network_frame = new NetFrame(NULL, 0, NetType::POLL, NetVertex::SERVER);
                network_frame->sendFrame(network_data);
                delete network_frame;
            }
        }

        ImGui::End();
    }
}

void gs_gui_acs_upd_display_window(ACSRollingBuffer *acs_rolbuf, bool *ACS_UPD_display, global_data_t *global)
{
    double start_time = acs_rolbuf->x_index - 60;
    if (start_time < 0)
    {
        start_time = 0;
    }

    if (global->settings->acs_multiple_windows)
    {
        if (ImGui::Begin("ACS Update: CT / Mode Graph", ACS_UPD_display))
        {
            ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->mode.Min(), acs_rolbuf->ct.Min()), getMax(acs_rolbuf->mode.Max(), acs_rolbuf->ct.Max()), ImGuiCond_Always);
            if (ImPlot::BeginPlot("CT / Mode Graph"))
            {

                ImPlot::PlotLine("CT", &acs_rolbuf->ct.data[0].x, &acs_rolbuf->ct.data[0].y, acs_rolbuf->ct.data.size(), acs_rolbuf->ct.ofst, 2 * sizeof(float));

                ImPlot::PlotLine("Mode", &acs_rolbuf->mode.data[0].x, &acs_rolbuf->mode.data[0].y, acs_rolbuf->mode.data.size(), acs_rolbuf->mode.ofst, 2 * sizeof(float));

                ImPlot::EndPlot();
            }
        }
        ImGui::End();

        if (ImGui::Begin("ACS Update: B (x, y, z) Graph", ACS_UPD_display))
        {
            ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->bx.Min(), acs_rolbuf->by.Min(), acs_rolbuf->bz.Min()), getMax(acs_rolbuf->bx.Max(), acs_rolbuf->by.Max(), acs_rolbuf->bz.Max()), ImGuiCond_Always);
            if (ImPlot::BeginPlot("B (x, y, z) Graph"))
            {

                ImPlot::PlotLine("x", &acs_rolbuf->bx.data[0].x, &acs_rolbuf->bx.data[0].y, acs_rolbuf->bx.data.size(), acs_rolbuf->bx.ofst, 2 * sizeof(float));

                ImPlot::PlotLine("y", &acs_rolbuf->by.data[0].x, &acs_rolbuf->by.data[0].y, acs_rolbuf->by.data.size(), acs_rolbuf->by.ofst, 2 * sizeof(float));

                ImPlot::PlotLine("z", &acs_rolbuf->bz.data[0].x, &acs_rolbuf->bz.data[0].y, acs_rolbuf->bz.data.size(), acs_rolbuf->bz.ofst, 2 * sizeof(float));

                ImPlot::EndPlot();
            }
        }
        ImGui::End();

        if (ImGui::Begin("ACS Update: W (x, y, z) Graph", ACS_UPD_display))
        {
            ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->wx.Min(), acs_rolbuf->wy.Min(), acs_rolbuf->wz.Min()), getMax(acs_rolbuf->wx.Max(), acs_rolbuf->wy.Max(), acs_rolbuf->wz.Max()), ImGuiCond_Always);
            if (ImPlot::BeginPlot("W (x, y, z) Graph"))
            {

                ImPlot::PlotLine("x", &acs_rolbuf->wx.data[0].x, &acs_rolbuf->wx.data[0].y, acs_rolbuf->wx.data.size(), acs_rolbuf->wx.ofst, 2 * sizeof(float));

                ImPlot::PlotLine("y", &acs_rolbuf->wy.data[0].x, &acs_rolbuf->wy.data[0].y, acs_rolbuf->wy.data.size(), acs_rolbuf->wy.ofst, 2 * sizeof(float));

                ImPlot::PlotLine("z", &acs_rolbuf->wz.data[0].x, &acs_rolbuf->wz.data[0].y, acs_rolbuf->wz.data.size(), acs_rolbuf->wz.ofst, 2 * sizeof(float));

                ImPlot::EndPlot();
            }
        }
        ImGui::End();

        if (ImGui::Begin("ACS Update: S (x, y, z) Graph", ACS_UPD_display))
        {
            ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->sx.Min(), acs_rolbuf->sy.Min(), acs_rolbuf->sz.Min()), getMax(acs_rolbuf->sx.Max(), acs_rolbuf->sy.Max(), acs_rolbuf->sz.Max()), ImGuiCond_Always);
            if (ImPlot::BeginPlot("S (x, y, z) Graph"))
            {

                ImPlot::PlotLine("x", &acs_rolbuf->sx.data[0].x, &acs_rolbuf->sx.data[0].y, acs_rolbuf->sx.data.size(), acs_rolbuf->sx.ofst, 2 * sizeof(float));

                ImPlot::PlotLine("y", &acs_rolbuf->sy.data[0].x, &acs_rolbuf->sy.data[0].y, acs_rolbuf->sy.data.size(), acs_rolbuf->sy.ofst, 2 * sizeof(float));

                ImPlot::PlotLine("z", &acs_rolbuf->sz.data[0].x, &acs_rolbuf->sz.data[0].y, acs_rolbuf->sz.data.size(), acs_rolbuf->sz.ofst, 2 * sizeof(float));

                ImPlot::EndPlot();
            }
        }
        ImGui::End();

        if (ImGui::Begin("ACS Update: Battery Graph", ACS_UPD_display))
        {
            ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->vbatt.Min(), acs_rolbuf->vboost.Min()), getMax(acs_rolbuf->vbatt.Max(), acs_rolbuf->vbatt.Max()), ImGuiCond_Always);
            if (ImPlot::BeginPlot("Battery Graph"))
            {

                ImPlot::PlotLine("VBatt", &acs_rolbuf->vbatt.data[0].x, &acs_rolbuf->vbatt.data[0].y, acs_rolbuf->vbatt.data.size(), acs_rolbuf->vbatt.ofst, 2 * sizeof(float));

                ImPlot::PlotLine("VBoost", &acs_rolbuf->vboost.data[0].x, &acs_rolbuf->vboost.data[0].y, acs_rolbuf->vboost.data.size(), acs_rolbuf->vboost.ofst, 2 * sizeof(float));

                ImPlot::EndPlot();
            }
        }
        ImGui::End();

        if (ImGui::Begin("ACS Update: Solar Current Graph", ACS_UPD_display))
        {
            ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->cursun.Min(), acs_rolbuf->cursun.Min()), getMax(acs_rolbuf->cursys.Max(), acs_rolbuf->cursys.Max()), ImGuiCond_Always);
            if (ImPlot::BeginPlot("Solar Current Graph"))
            {

                ImPlot::PlotLine("CurSun", &acs_rolbuf->cursun.data[0].x, &acs_rolbuf->cursun.data[0].y, acs_rolbuf->cursun.data.size(), acs_rolbuf->cursun.ofst, 2 * sizeof(float));

                ImPlot::PlotLine("CurSys", &acs_rolbuf->cursys.data[0].x, &acs_rolbuf->cursys.data[0].y, acs_rolbuf->cursys.data.size(), acs_rolbuf->cursys.ofst, 2 * sizeof(float));

                ImPlot::EndPlot();
            }
        }
        ImGui::End();
    }
    else
    {
        if (ImGui::Begin("ACS Update Display", ACS_UPD_display))
        {
            // The implemented method of displaying the ACS update data includes a locally-global class (ACSDisplayData) with data that this window will display. The data is set by gs_receive.
            // NOTE: This window must be opened independent of ACS's automated data retrieval option.

            if (ImGui::CollapsingHeader("CT / Mode Graph", ImGuiTreeNodeFlags_DefaultOpen))
            {
                ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->mode.Min(), acs_rolbuf->ct.Min()), getMax(acs_rolbuf->mode.Max(), acs_rolbuf->ct.Max()), ImGuiCond_Always);
                if (ImPlot::BeginPlot("CT / Mode Graph"))
                {

                    ImPlot::PlotLine("CT", &acs_rolbuf->ct.data[0].x, &acs_rolbuf->ct.data[0].y, acs_rolbuf->ct.data.size(), acs_rolbuf->ct.ofst, 2 * sizeof(float));

                    ImPlot::PlotLine("Mode", &acs_rolbuf->mode.data[0].x, &acs_rolbuf->mode.data[0].y, acs_rolbuf->mode.data.size(), acs_rolbuf->mode.ofst, 2 * sizeof(float));

                    ImPlot::EndPlot();
                }
            }

            if (ImGui::CollapsingHeader("B (x, y, z) Graph", ImGuiTreeNodeFlags_DefaultOpen))
            {
                ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->bx.Min(), acs_rolbuf->by.Min(), acs_rolbuf->bz.Min()), getMax(acs_rolbuf->bx.Max(), acs_rolbuf->by.Max(), acs_rolbuf->bz.Max()), ImGuiCond_Always);
                if (ImPlot::BeginPlot("B (x, y, z) Graph"))
                {

                    ImPlot::PlotLine("x", &acs_rolbuf->bx.data[0].x, &acs_rolbuf->bx.data[0].y, acs_rolbuf->bx.data.size(), acs_rolbuf->bx.ofst, 2 * sizeof(float));

                    ImPlot::PlotLine("y", &acs_rolbuf->by.data[0].x, &acs_rolbuf->by.data[0].y, acs_rolbuf->by.data.size(), acs_rolbuf->by.ofst, 2 * sizeof(float));

                    ImPlot::PlotLine("z", &acs_rolbuf->bz.data[0].x, &acs_rolbuf->bz.data[0].y, acs_rolbuf->bz.data.size(), acs_rolbuf->bz.ofst, 2 * sizeof(float));

                    ImPlot::EndPlot();
                }
            }

            if (ImGui::CollapsingHeader("W (x, y, z) Graph", ImGuiTreeNodeFlags_DefaultOpen))
            {
                ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->wx.Min(), acs_rolbuf->wy.Min(), acs_rolbuf->wz.Min()), getMax(acs_rolbuf->wx.Max(), acs_rolbuf->wy.Max(), acs_rolbuf->wz.Max()), ImGuiCond_Always);
                if (ImPlot::BeginPlot("W (x, y, z) Graph"))
                {

                    ImPlot::PlotLine("x", &acs_rolbuf->wx.data[0].x, &acs_rolbuf->wx.data[0].y, acs_rolbuf->wx.data.size(), acs_rolbuf->wx.ofst, 2 * sizeof(float));

                    ImPlot::PlotLine("y", &acs_rolbuf->wy.data[0].x, &acs_rolbuf->wy.data[0].y, acs_rolbuf->wy.data.size(), acs_rolbuf->wy.ofst, 2 * sizeof(float));

                    ImPlot::PlotLine("z", &acs_rolbuf->wz.data[0].x, &acs_rolbuf->wz.data[0].y, acs_rolbuf->wz.data.size(), acs_rolbuf->wz.ofst, 2 * sizeof(float));

                    ImPlot::EndPlot();
                }
            }

            if (ImGui::CollapsingHeader("S (x, y, z) Graph", ImGuiTreeNodeFlags_DefaultOpen))
            {
                ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->sx.Min(), acs_rolbuf->sy.Min(), acs_rolbuf->sz.Min()), getMax(acs_rolbuf->sx.Max(), acs_rolbuf->sy.Max(), acs_rolbuf->sz.Max()), ImGuiCond_Always);
                if (ImPlot::BeginPlot("S (x, y, z) Graph"))
                {

                    ImPlot::PlotLine("x", &acs_rolbuf->sx.data[0].x, &acs_rolbuf->sx.data[0].y, acs_rolbuf->sx.data.size(), acs_rolbuf->sx.ofst, 2 * sizeof(float));

                    ImPlot::PlotLine("y", &acs_rolbuf->sy.data[0].x, &acs_rolbuf->sy.data[0].y, acs_rolbuf->sy.data.size(), acs_rolbuf->sy.ofst, 2 * sizeof(float));

                    ImPlot::PlotLine("z", &acs_rolbuf->sz.data[0].x, &acs_rolbuf->sz.data[0].y, acs_rolbuf->sz.data.size(), acs_rolbuf->sz.ofst, 2 * sizeof(float));

                    ImPlot::EndPlot();
                }
            }

            if (ImGui::CollapsingHeader("Battery Graph", ImGuiTreeNodeFlags_DefaultOpen))
            {
                ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->vbatt.Min(), acs_rolbuf->vboost.Min()), getMax(acs_rolbuf->vbatt.Max(), acs_rolbuf->vbatt.Max()), ImGuiCond_Always);
                if (ImPlot::BeginPlot("Battery Graph"))
                {

                    ImPlot::PlotLine("VBatt", &acs_rolbuf->vbatt.data[0].x, &acs_rolbuf->vbatt.data[0].y, acs_rolbuf->vbatt.data.size(), acs_rolbuf->vbatt.ofst, 2 * sizeof(float));

                    ImPlot::PlotLine("VBoost", &acs_rolbuf->vboost.data[0].x, &acs_rolbuf->vboost.data[0].y, acs_rolbuf->vboost.data.size(), acs_rolbuf->vboost.ofst, 2 * sizeof(float));

                    ImPlot::EndPlot();
                }
            }

            if (ImGui::CollapsingHeader("Solar Current Graph", ImGuiTreeNodeFlags_DefaultOpen))
            {
                ImPlot::SetNextPlotLimits(start_time, acs_rolbuf->x_index, getMin(acs_rolbuf->cursun.Min(), acs_rolbuf->cursun.Min()), getMax(acs_rolbuf->cursys.Max(), acs_rolbuf->cursys.Max()), ImGuiCond_Always);
                if (ImPlot::BeginPlot("Solar Current Graph"))
                {

                    ImPlot::PlotLine("CurSun", &acs_rolbuf->cursun.data[0].x, &acs_rolbuf->cursun.data[0].y, acs_rolbuf->cursun.data.size(), acs_rolbuf->cursun.ofst, 2 * sizeof(float));

                    ImPlot::PlotLine("CurSys", &acs_rolbuf->cursys.data[0].x, &acs_rolbuf->cursys.data[0].y, acs_rolbuf->cursys.data.size(), acs_rolbuf->cursys.ofst, 2 * sizeof(float));

                    ImPlot::EndPlot();
                }
            }
        }
        ImGui::End();
    }
}

void gs_gui_disp_control_panel_window(bool *DISP_control_panel, bool *ACS_window, bool *EPS_window, bool *XBAND_window, bool *XBAND_TX_window, bool *XBAND_RX_window, bool *XBAND_TEST_window, bool *SW_UPD_window, bool *SYS_CTRL_window, bool *RX_display, bool *ACS_UPD_display, bool *allow_transmission, int access_level, global_data_t *global)
{
    if (ImGui::Begin("SPACE-HAUC I/O Displays", DISP_control_panel, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar))
    {
        ImGui::Text("Input");

        ImGui::Separator();

        ImGui::Checkbox("Attitude Control System   ", ACS_window); // Contains ACS and ACS_UPD
        ImGui::Checkbox("Electrical Power Supply", EPS_window);
        ImGui::Checkbox("X-Band", XBAND_window);
        ImGui::Checkbox("Software Updater", SW_UPD_window);
        ImGui::Checkbox("System Control", SYS_CTRL_window); // Contains SYS_VER, SYS_REBOOT, SYS_CLEAN_SHBYTES

        ImGui::Separator();
        ImGui::Separator();

        ImGui::Text("Output");

        ImGui::Separator();

        ImGui::Checkbox("Plaintext RX Display", RX_display);
        ImGui::Checkbox("ACS Update Display", ACS_UPD_display);

        ImGui::Separator();
        ImGui::Separator();

        ImGui::Text("Ground Station");

        ImGui::Checkbox("X-Band TX (Rooftop) Config", XBAND_TX_window);
        ImGui::Checkbox("X-Band RX (Haystack) Config", XBAND_RX_window);
        ImGui::Checkbox("X-Band Test Panel", XBAND_TEST_window);

        ImGui::Separator();

        ImGui::Separator();
        ImGui::Separator();

        if (ImGui::Button("Toggle Transmissions Lock"))
        {
            *allow_transmission = !(*allow_transmission);
        }
        if (ImGui::IsItemHovered() && global->settings->tooltips)
        {
            ImGui::BeginTooltip();
            ImGui::SetTooltip("Toggle transmission lock safety. Disables all transmissions from this terminal when locked.");
            ImGui::EndTooltip();
        }
        ImGui::SameLine();
        *allow_transmission ? ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), " UNLOCKED ") : ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "  LOCKED  ");
    }
    ImGui::End();
}

void gs_gui_user_manual_window(bool *User_Manual)
{
    if (ImGui::Begin("User Manual", User_Manual, ImGuiWindowFlags_AlwaysVerticalScrollbar /* | ImGuiWindowFlags_HorizontalScrollbar*/))
    {
        ImGui::BeginTabBar("Help Menu Tab Bar", ImGuiTabBarFlags_FittingPolicyScroll | ImGuiTabBarFlags_NoCloseWithMiddleMouseButton);
        if (ImGui::BeginTabItem("Getting Started"))
        {
            ImGui::TextWrapped("Overview");
            ImGui::Separator();
            ImGui::Indent();

            // TODO: Implement a display to show the data retrieved when a data-down command is sent.
            ImGui::TextWrapped("The SPACE-HAUC Ground Station Client is provided to allow an operator to interface with the SPACE-HAUC satellite.");

            ImGui::TextWrapped("Data-retrieval commands, referred to as 'data-down,' are sent automatically when the corresponding Arrow Button is pressed. These can be found in the corresponding 'Data-down' drop-down sections of the three 'Operations' panels (ACS, EPS, or XBAND). Once the data is received, it is displayed in the Plaintext RX Display window.");

            ImGui::TextWrapped("Value-setting commands, referred to as 'data-up,' are accessed in the 'Data-up' drop-down sections of the three 'Operations' panels. Unlike the 'data-down' commands, 'data-up' commands do not send automatically. Instead, the operator must choose which 'data-up' command they would like to make active using the Radio Buttons. Any number of 'data-up' command arguments can be edited simultaneously, but only one 'data-up' command can be selected for transmission at a time. The arguments are not cleared until the program is restarted.");

            ImGui::TextWrapped("Once the transmit functionality is unlocked via the 'SPACE-HAUC I/O Displays' panel, the operator can check the currently queued command in the 'Transmit' drop-down sections. Pressing 'SEND DATA-UP TRANSMISSION' will confirm and send the queued transmission. Any return value or data received as a result of the 'data-up' transmission will also be displayed in the Plaintext RX Display window.");

            ImGui::Unindent();
            ImGui::Separator();
            ImGui::Separator();
            ImGui::TextWrapped("Window Interaction");
            ImGui::Separator();
            ImGui::Indent();

            ImGui::TextWrapped("The Menu Bar at the top of the screen has buttons to toggle the visibility of various windows and drop-down menus. Within the SPACE-HAUC I/O Displays window are checkboxes to toggle the visibility of 'Input' windows, which allow the operator to send commands, and 'Output' windows, which present the operator with data from SPACE-HAUC.");

            ImGui::TextWrapped("Some windows are a fixed size, while larger windows are able to be resized by the user. All windows have an 'X' in the top right-hand corner to hide the window. Windows can also be hidden the same way they are shown as previously mentioned.");

            ImGui::Unindent();

            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Authentication"))
        {
            ImGui::TextWrapped("Authentication Control Panel Window");
            ImGui::Separator();
            ImGui::Indent();

            ImGui::TextWrapped("The Authentication Control Panel window is visible by default. Its visibility can be toggled by pressing the Authentication button in the Main Toolbar at the top of the screen.");

            ImGui::TextWrapped("This window displays the current access level, a password-entry field, and a <DEAUTHENTICATE> button.");

            ImGui::TextWrapped("Elements of the Ground Station graphical program which are blocked due to insufficient access level will display the following text: \"ACCESS DENIED\".");

            ImGui::TextWrapped("To enter your password, click on the text entry field and press [ENTER] when finished. The system will process your input and update your access level accordingly. Please note that incorrect inputs are punished with a 2.5 second delay.");

            ImGui::TextWrapped("To revoke authentication, press the <DEAUTHENTICATE> button. This will not reset any previously set values within the program, but will simply deny further access. This should be used by the operator to lock the application when they are not present to prohibit accidental or malicious acts.");

            ImGui::TextWrapped("The Authentication Control Panel does not need to be visible to maintain access, and it is recommended to toggle the visibility off once it is no longer needed by pressing the 'Authentication' button on the Menu Bar at the top of the screen.");

            ImGui::Unindent();
            ImGui::Separator();
            ImGui::Separator();

            ImGui::TextWrapped("Access Levels");
            ImGui::Separator();
            ImGui::Indent();

            ImGui::TextWrapped("0 - Low Level Access");
            ImGui::Indent();
            ImGui::TextWrapped("The lowest level of access, this is granted immediately upon startup of the program. Only the basic ACS data update is available.");
            ImGui::Unindent();

            ImGui::TextWrapped("1 - Team Member Access");
            ImGui::Indent();
            ImGui::TextWrapped("This level is granted access to data-down commands.");
            ImGui::Unindent();

            ImGui::TextWrapped("2 - Priority Access");
            ImGui::Indent();
            ImGui::TextWrapped("This level is granted access to some non-mission-critical data-up commands.");
            ImGui::Unindent();

            ImGui::TextWrapped("3 - Project Manager Access");
            ImGui::Indent();
            ImGui::TextWrapped("This level of access is the highest possible, and is granted the ability to perform a software update and set mission critical values.");
            ImGui::Unindent();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("SPACE-HAUC I/O Displays"))
        {
            ImGui::TextWrapped("SPACE-HAUC I/O Displays Window");
            ImGui::Separator();
            ImGui::Indent();

            ImGui::TextWrapped("The Displays Control window is unique, as it is the only window which allows for toggling the visibility of other windows. The Displays Control window itself can be toggled by the 'Displays Control' button on the Menu Bar at the top of the screen.");

            ImGui::TextWrapped("The checkboxes each enable or disable the visibility of their respective windows. From top to bottom, the first section of checkboxes control the visibility of the Attitude Control System, Electrical Power Supply, X-Band, Software Updater, and System Control input windows. The second section of checkboxes controls the visibility of data output windows, which display the data the Client receives from SPACE-HAUC. Toggling the visibility has no effect on the data or actions being performed, except that it disallows any further user interaction with that window's elements (until it is made visible again, of course).");

            ImGui::TextWrapped("Also in this window is the 'Enable Transmissions' checkbox. This acts as a safety which disallows all data-up transmissions when it is unchecked. This should remain unchecked at ALL TIMES unless one or more data-up transmissions are being made.");

            ImGui::Unindent();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Connections"))
        {
            ImGui::TextWrapped("Connections Manager Window");
            ImGui::Separator();
            ImGui::Indent();

            ImGui::TextWrapped("The Connections Manager window's visibility is toggled via the 'Connections' button along the main menu bar at the top of the screen.");

            ImGui::TextWrapped("This window allows connection to an IP and Port and presents the operator with the last known status of the Ground Station Network. The Ground Station client can only be connected to one network device at any time, and should only ever be connected to the Ground Station Network's central server via port 54200.");

            ImGui::TextWrapped("At the top of the window should appear, in green letters, 'Receive Thread Active.' This should always be the case, however, in the event that the receive thread stops working, red text indicating this and a 'Restart Thread' button will appear. If the receive thread is inactive, no data will be received by the client. Below this is the IP and Port input fields. These can only be edited when not connected to another device. Pressing 'Connect' will attempt a connection to the given IP and Port. If the connection attempt succeeds, the button will change to show 'Disconnect,' and status data will be updated at the bottom of the window. If the connection fails, a red 'CONNECTION FAILED' notice will appear next to the 'Connect' button followed by the time in seconds after Client boot-up that the attempt failed. At the bottom of the window is the 'Last Known Status' area, where the last received status of all network devices is shown. Also shown is the current Server connection status, followed in parentheses by the reason for disconnection.");

            ImGui::Unindent();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Radio Configs"))
        {
            ImGui::TextWrapped("Radios Configuration Manager Window");
            ImGui::Separator();
            ImGui::Indent();

            ImGui::Unindent();
            ImGui::Separator();
            ImGui::Separator();
            ImGui::TextWrapped("X-Band");
            ImGui::Separator();
            ImGui::Indent();

            ImGui::Unindent();
            ImGui::Separator();
            ImGui::Separator();
            ImGui::TextWrapped("UHF");
            ImGui::Indent();
            ImGui::Separator();

            ImGui::TextWrapped("No UHF radio configuration exists at this time.");

            ImGui::Unindent();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Communications"))
        {
            ImGui::TextWrapped("Command Types");
            ImGui::Separator();
            ImGui::Indent();

            ImGui::TextWrapped("Data-down");
            ImGui::Indent();
            ImGui::TextWrapped("Commands where data will be sent down from SPACE-HAUC to the Ground Station. Typically, these are commands that poll one or more values.");
            ImGui::Unindent();

            ImGui::TextWrapped("Data-up");
            ImGui::Indent();
            ImGui::TextWrapped("Commands where data will be sent up from the Ground Station to SPACE-HAUC. Typically, these are commands that will set values on-board the spacecraft.");
            ImGui::Unindent();

            ImGui::TextWrapped("Executable");
            ImGui::Indent();
            ImGui::TextWrapped("Commands that instruct SPACE-HAUC to perform some action.");
            ImGui::Unindent();

            ImGui::Unindent();

            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("About"))
        {
            ImGui::TextWrapped("SPACE-HAUC Ground Station: Graphical User Interface Client designed for use with the SPACE-HAUC spacecraft and as a part of the SPACE-HAUC Ground Station Network.");
            ImGui::TextWrapped("Mit Bailey Copyright (c) 2021");

            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }
    ImGui::End();
}