/**
 * @file gs.cpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief Contains class and function defintions.
 * 
 * Contains data-handling code and does not create or augment the GUI directly.
 * 
 * @version 0.1
 * @date 2021.07.26
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#include "gs.hpp"
#include "meb_debug.hpp"
#include "sw_update_packdef.h"
#include "phy.hpp"

void glfw_error_callback(int error, const char *description)
{
    fprintf(stderr, "GLFW error %d: %s\n", error, description);
}

float getMin(float a, float b)
{
    if (a > b)
    {
        return b;
    }
    else
    {
        return a;
    }
}

float getMin(float a, float b, float c)
{
    if (a < b)
    {
        if (a < c)
        {
            return a;
        }
        else
        {
            return c;
        }
    }
    else
    {
        if (b < c)
        {
            return b;
        }
        else
        {
            return c;
        }
    }
}

float getMax(float a, float b)
{
    if (a > b)
    {
        return a;
    }
    else
    {
        return b;
    }
}

float getMax(float a, float b, float c)
{
    if (a > b)
    {
        if (a > c)
        {
            return a;
        }
        else
        {
            return c;
        }
    }
    else
    {
        if (b > c)
        {
            return b;
        }
        else
        {
            return c;
        }
    }
}

void *gs_check_password(void *auth)
{
    auth_t *lauth = (auth_t *)auth;
    lauth->busy = true;

    // Generate hash.
    // Check hash against valid hashes.
    // If valid, grant access.
    // Return access level granted.

    if (gs_helper(lauth->password) == -07723727136)
    {
        usleep(0.25 SEC);
        lauth->access_level = 1;
    }
    else if (gs_helper(lauth->password) == 013156200030)
    {
        usleep(0.25 SEC);
        lauth->access_level = 2;
    }
    else if (gs_helper(lauth->password) == 05657430216)
    {
        usleep(0.25 SEC);
        lauth->access_level = 3;
    }
    else
    {
        usleep(2.5 SEC);
        lauth->access_level = 0;
    }

    memset(lauth->password, 0x0, strlen(lauth->password));

    lauth->busy = false;
    return auth;
}

// Mildly Obfuscated
int gs_helper(void *aa)
{
    char *a = (char *)aa;

    int b, c;
    unsigned int d, e, f;

    b = 0;
    e = (unsigned int)4294967295U;
    while (b[a] != 0)
    {
        d = b[a];
        e = e ^ d;
        for (c = 7; c >= 0; c--)
        {
            f = -(e & 1);
            e = (e >> 1) ^ ((unsigned int)3988292384U & f);
        }
        b = b + 1;
    }
    return ~e;
}

void *gs_acs_update_thread(void *global_data_vp)
{
    global_data_t *global = (global_data_t *)global_data_vp;

    cmd_input_t acs_cmd[1];
    memset(acs_cmd, 0x0, sizeof(cmd_input_t));

    acs_cmd->mod = ACS_UPD_ID;
    acs_cmd->unused = 0x0;
    acs_cmd->data_size = 0x0;
    memset(acs_cmd->data, 0x0, MAX_DATA_SIZE);

    // Transmit an ACS update request to the server.
    // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, acs_cmd, sizeof(cmd_input_t));
    NetFrame *network_frame = new NetFrame((unsigned char *)acs_cmd, sizeof(cmd_input_t), NetType::DATA, NetVertex::ROOFUHF);
    network_frame->sendFrame(global->network_data);
    delete network_frame;

    // !WARN! Any faster than 0.5 seconds seems to break the Network.
    usleep(ACS_UPDATE_FREQUENCY SEC);

    pthread_mutex_unlock(&global->acs_rolbuf->acs_upd_inhibitor);

    return NULL;
}

// Updated, referenced "void *rcv_thr(void *sock)" from line 338 of: https://github.com/sunipkmukherjee/comic-mon/blob/master/guimain.cpp
// Also see: https://github.com/mitbailey/socket_server
void *gs_rx_thread(void *args)
{
    // Convert the passed void pointer into something useful; in this case, global_data_t.
    global_data_t *global = (global_data_t *)args;
    NetDataClient *network_data = global->network_data;

    while (network_data->recv_active && network_data->thread_status > 0)
    {
        if (!network_data->connection_ready)
        {
            global->xbtx_avail = false;
            global->xbrx_avail = false;
            sleep(5);
            continue;
        }

        int read_size = 0;

        while (read_size >= 0 && network_data->recv_active && network_data->thread_status > 0)
        {
            dbprintlf(BLUE_BG "Waiting to receive...");

            NetFrame *netframe = new NetFrame();
            read_size = netframe->recvFrame(network_data);

            dbprintlf("Read %d bytes.", read_size);

            if (read_size >= 0)
            {
                dbprintlf("Received the following NetFrame:");
                netframe->print();
                netframe->printNetstat();

                // Extract the payload into a buffer.
                int payload_size = netframe->getPayloadSize();
                unsigned char *payload = (unsigned char *)malloc(payload_size);
                if (netframe->retrievePayload(payload, payload_size) < 0)
                {
                    dbprintlf("Error retrieving data.");
                    continue;
                }

                global->netstat = netframe->getNetstat();

                (global->netstat & 0x20) == 0x20 ? global->xbtx_avail = true : global->xbtx_avail = false;
                (global->netstat & 0x10) == 0x10 ? global->xbrx_avail = true : global->xbtx_avail = false;

                global->last_contact = ImGui::GetTime();

                // Based on what we got, set things to display the data.
                switch (netframe->getType())
                {
                case NetType::POLL:
                { // Will have status data.
                    dbprintlf("Received NULL frame.");
                    break;
                }
                case NetType::ACK:
                {
                    dbprintlf("Received ACK.");
                    memcpy(global->cs_ack, payload, payload_size);

                    break;
                }
                case NetType::NACK:
                {
                    dbprintlf("Received N/ACK.");
                    memcpy(global->cs_ack, payload, payload_size);

                    if (((cs_ack_t *)payload)->code == NACK_NO_UHF)
                    {
                        // Immediately cancel all ongoing software updates, since the Roof UHF is complaining that it cannot use the UHF.
                        dbprintlf(RED_FG "Roof UHF responded saying that it cannot access UHF communications at this time. Halting all software updates.");
                        global->sw_upd_in_progress = false;
                    }

                    break;
                }
                case NetType::UHF_CONFIG:
                {
                    dbprintlf("Received UHF Config.");
                    memcpy(global->cs_config_uhf, payload, payload_size);
                    break;
                }
                case NetType::XBAND_DATA:
                {
                    dbprintlf(BLUE_FG "Received a XBAND DATA frame!");

                    phy_status_t *status = (phy_status_t *)payload;

                    if (netframe->getOrigin() == NetVertex::HAYSTACK)
                    {
                        dbprintlf(BLUE_FG "Config frame is from HAYSTACK.");

                        // Copies the status into rxphy because rxphy is used for UI display.
                        // Copies only sizeof(phy_config_t) bytes, which copies over the status data not including the end-booleans.
                        // TODO: Look into setting status' end booleans manually.
                        // memcpy(rxphy, status, sizeof(phy_config_t));

                        // Update always.
                        global->rxphy->pll_lock = status->pll_lock;
                        global->rxphy->mode = status->mode;
                        global->rxphy->temp = status->temp;
                        global->rxphy->rssi = status->rssi;
                        memcpy(global->rxphy->curr_gainmode, status->curr_gainmode, 16);
                        global->rxphy->LO = status->LO;
                        global->rxphy->bw = status->bw;
                        global->rxphy->samp = status->samp;
                        global->rx_armed = status->rx_armed;
                        global->last_xbrx_status = status->last_rx_status;
                        global->last_xbread_status = status->last_read_status;

                        // dbprintlf(RED_BG "%d \t %d", status->last_rx_status, last_xbrx_status);
                        // dbprintlf(RED_BG "%d \t %d", status->last_read_status, last_xbread_status);

                        if (global->refresh_rx_ui_data)
                        { // Only update when asked.
                            global->rx_samp = HZ_M(status->samp);
                            global->rx_lo = HZ_M(status->LO);
                            global->rx_bw = HZ_M(status->bw);
                            memcpy(global->rxphy->ftr_name, status->ftr_name, 64);
                            global->rxmode = status->mode;

                            global->refresh_rx_ui_data = false;
                        }
                    }
                    else
                    {
                        dbprintlf(BLUE_FG "Config frame is from ROOF XBAND.");

                        // Copies the status into rxphy because rxphy is used for UI display.
                        // Copies only sizeof(phy_config_t) bytes, which copies over the status data not including the end-booleans.
                        // TODO: Look into setting status' end booleans manually.
                        // memcpy(txphy, status, sizeof(phy_config_t));

                        // Update always.
                        global->txphy->pll_lock = status->pll_lock;
                        global->txphy->mode = status->mode;
                        global->txphy->temp = status->temp;
                        global->txphy->LO = status->LO;
                        global->txphy->bw = status->bw;
                        global->txphy->samp = status->samp;

                        if (global->refresh_tx_ui_data)
                        { // Only update when asked.
                            dbprintf(RED_BG "Setting refresh TX (%d) to false ", global->refresh_tx_ui_data);
                            global->tx_samp = HZ_M(status->samp);
                            global->tx_lo = HZ_M(status->LO);
                            global->tx_bw = HZ_M(status->bw);
                            memcpy(global->txphy->ftr_name, status->ftr_name, 64);
                            global->txmode = status->mode;
                            global->tx_gain = status->gain;
                            // dbprintlf(RED_BG "Received MTU status: %d", status->MTU);
                            global->txphy->MTU = status->MTU;
                            global->MTU = status->MTU;

                            global->refresh_tx_ui_data = false;
                            printf(RED_BG "(%d)." RESET_ALL "\n", global->refresh_tx_ui_data);
                        }
                    }

                    break;
                }
                case NetType::XBAND_CONFIG:
                {
                    dbprintlf("Received X-Band Config.");
                    memcpy(global->cs_config_xband, payload, payload_size);
                    break;
                }
                case NetType::SW_UPDATE:
                {
                    dbprintlf("Received SW_UPDATE information.");

                    // sw_update_info_t
                    sw_update_info_t *info = (sw_update_info_t *)payload;

                    global->sw_upd_packet = info->current_packet;
                    if (global->sw_upd_total_packets != info->total_packets)
                    {
                        dbprintlf(RED_BG "UHF thinks the total packets for the current transfer is %d vs our %d!", info->total_packets, global->sw_upd_total_packets);
                    }
                    
                    if (info->finished)
                    {
                        dbprintlf(BLUE_BG "UHF reports finishing software update.");
                        global->sw_upd_in_progress = false;
                    }

                    break;
                }
                case NetType::DATA: // Data type is just cmd_output_t (SH->GS)
                {

                    dbprintlf(BLUE_FG "Received a DATA frame!");

                    if (netframe->getOrigin() == NetVertex::HAYSTACK)
                    {
                        dbprintlf(BLUE_FG "DATA frame from HAYSTACK.");
                        if (memcmp(test_cmd, payload, sizeof(test_cmd)) == 0)
                        {
                            dbprintlf(GREEN_FG "DATA frame is identical to previously sent small test frame.");
                        }
                        else
                        {
                            if (global->mega_packet_crc == internal_crc16(payload, global->mega_packet_file_size + 1))
                            {
                                dbprintlf(GREEN_FG "DATA frame is identical to previously sent MEGA PACKET.");
                            }
                            else
                            {
                                dbprintlf(RED_FG "DATA frame is not identical to previously sent test frame.");
                            }
                        }
                    }
                    // else if (((cmd_output_t *)payload)->mod == SW_UPD_ID)
                    // { // If this is part of an sw_update...
                    //     // If we can't get the lock, only wait for one second.
                    //     struct timespec timeout;
                    //     clock_gettime(CLOCK_REALTIME, &timeout);
                    //     timeout.tv_sec += 1;

                    //     if (pthread_mutex_timedlock(global->sw_output_lock, &timeout) == 0)
                    //     {
                    //         memcpy(global->sw_output, payload, payload_size);
                    //         global->sw_output_fresh = true;
                    //         pthread_mutex_unlock(global->sw_output_lock);
                    //     }
                    //     else
                    //     {
                    //         dbprintlf(RED_FG "Failed to acquire sw_data_lock.");
                    //     }
                    // }
                    else if (((cmd_output_t *)payload)->mod != ACS_UPD_ID)
                    { // If this is not an ACS Update...
                        memcpy(global->cmd_output, payload, payload_size);
                    }
                    else
                    { // If it is an ACS update...
                        global->acs_rolbuf->addValueSet(*((acs_upd_output_t *)payload));
                    }
                    break;
                }
                default:
                {
                    break;
                }
                }
                free(payload);
            }
            else
            {
                break;
            }

            delete netframe;
        }
        if (read_size == -404)
        {
            dbprintlf(RED_BG "Connection forcibly closed by the server.");
            strcpy(network_data->disconnect_reason, "SERVER-FORCED");
            network_data->connection_ready = false;
            continue;
        }
        else if (errno == EAGAIN)
        {
            dbprintlf(YELLOW_BG "Active connection timed-out (%d).", read_size);
            strcpy(network_data->disconnect_reason, "TIMED-OUT");
            network_data->connection_ready = false;
            continue;
        }
        erprintlf(errno);
    }

    network_data->recv_active = false;
    dbprintlf(FATAL "DANGER! RECEIVE THREAD IS RETURNING!");

    global->xbtx_avail = false;
    global->xbrx_avail = false;

    if (global->network_data->thread_status > 0)
    {
        global->network_data->thread_status = 0;
    }
    return NULL;
}