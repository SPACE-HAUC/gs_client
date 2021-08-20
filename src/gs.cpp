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
                        global->sw_updating = false;
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
                    else if (((cmd_output_t *)payload)->mod == SW_UPD_ID)
                    { // If this is part of an sw_update...
                        // If we can't get the lock, only wait for one second.
                        struct timespec timeout;
                        clock_gettime(CLOCK_REALTIME, &timeout);
                        timeout.tv_sec += 1;

                        if (pthread_mutex_timedlock(global->sw_output_lock, &timeout) == 0)
                        {
                            memcpy(global->sw_output, payload, payload_size);
                            global->sw_output_fresh = true;
                            pthread_mutex_unlock(global->sw_output_lock);
                        }
                        else
                        {
                            dbprintlf(RED_FG "Failed to acquire sw_data_lock.");
                        }
                    }
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

// TODO: Make this into a thread so that the rest of the program will continue running.
// NOTE: The RX thread copies all SW-related data into global_data->sw_output and sets the new_sw_data flag.
void *gs_sw_send_file_thread(void *args)
{
    global_data_t *global = (global_data_t *)args;
    dbprintlf("Checkpoint 1.");
    char directory[20];
    snprintf(directory, 20, global->directory);
    dbprintlf("Checkpoint 2.");
    char filename[20];
    snprintf(filename, 20, global->filename);
    dbprintlf("Checkpoint 3.");

    // int gs_sw_send_file(global_data_t *global_data, const char directory[], const char filename[], bool *done_upld)
    // {
    if (!global->network_data->connection_ready)
    {
        dbprintlf("Checkpoint 4.");
        dbprintlf(RED_FG "Connection is not ready: update aborted.");
        global->sw_updating = false;
        return NULL;
    }
    if (filename == NULL)
    {
        dbprintlf("Checkpoint 4.");
        dbprintlf(RED_FG "File name not supplied.");
        global->sw_updating = false;
        return NULL;
    }
    else if (strlen(filename) >= SW_UPD_FN_SIZE)
    {
        dbprintlf("Checkpoint 4.");
        dbprintlf(RED_FG "File name too long.");
        global->sw_updating = false;
        return NULL;
    }
    dbprintlf("Checkpoint 4.");
    char directory_filename[SW_UPD_FN_SIZE + 32];
    snprintf(directory_filename, sizeof(directory_filename), "%s%s", directory, filename);
    FILE *bin_fp = fopen(directory_filename, "rb");

    if (bin_fp == NULL)
    {
        dbprintlf(RED_FG "Could not open %s.", directory_filename);
        global->sw_updating = false;
        return NULL;
    }

    // Find the size of the binary file.
    fseek(bin_fp, 0, SEEK_END);
    ssize_t file_size = ftell(bin_fp);
    fseek(bin_fp, 0, SEEK_SET);

    dbprintlf("Beginning send of %s (%d bytes).", directory_filename, file_size);

    ssize_t sent_bytes = gs_sw_get_sent_bytes(filename);

    if (sent_bytes < 0)
    {
        dbprintlf(RED_FG "Failed to retrieve sent bytes for %s (%d).", directory_filename, sent_bytes);
        global->sw_updating = false;
        return NULL;
    }

    volatile int sent_packets = (sent_bytes / SW_UPD_DATA_SIZE_MAX) + ((sent_bytes % SW_UPD_DATA_SIZE_MAX) > 0);
    ssize_t fn_sz = strlen(filename) + 1;
    int send_attempts = 0;
    int max_packets = (file_size / SW_UPD_DATA_SIZE_MAX) + ((file_size % SW_UPD_DATA_SIZE_MAX) > 0);
    ssize_t retval = 0;

    // Out initial state is to begin by sending primers until we get a good reply.
    sw_upd_mode mode = primer;

    // Primers, headers, and buffers.
    char rd_buf[SW_UPD_PACKET_SIZE];
    char wr_buf[SW_UPD_PACKET_SIZE];

    dbprintlf("Entering file transfer phase.");

    // Outer loop. Runs until we have sent the entire file.
    while ((mode != finish) && global->sw_updating)
    {
        // Each loop we should set sent_bytes and sent_packets.
        sent_bytes = gs_sw_get_sent_bytes(filename);
        sent_packets = (sent_bytes / SW_UPD_DATA_SIZE_MAX) + ((sent_bytes % SW_UPD_DATA_SIZE_MAX) > 0);
        global->sw_upd_packet = sent_packets;

        ssize_t in_sz = 0;

        // Remember to clean your memory and drink your Ovaltine.
        memset(wr_buf, 0x0, SW_UPD_PACKET_SIZE);

        switch (mode)
        {
        case primer:
        {
            sw_upd_startresume_t *sr_pmr = (sw_upd_startresume_t *)wr_buf;
            sw_upd_startresume_reply_t *sr_rep = (sw_upd_startresume_reply_t *)rd_buf;

            sr_pmr->cmd = SW_UPD_SRID;
            strcpy(sr_pmr->filename, filename);
            sr_pmr->fid = 1;
            sr_pmr->sent_bytes = sent_bytes;
            sr_pmr->total_bytes = file_size;

            // Send the START/RESUME primer, and get back a reply
            for (send_attempts = 0; (send_attempts < SW_UPD_MAX_SEND_ATTEMPTS) && global->sw_updating; send_attempts++)
            {
                dbprintlf("Sending S/R primer.");

                // retval = gs_transmit(global->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, wr_buf, SW_UPD_PACKET_SIZE);
                NetFrame *network_frame = new NetFrame((unsigned char *)wr_buf, SW_UPD_PACKET_SIZE, NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;

                if (retval <= 0)
                {
                    dbprintlf(RED_FG "S/R primer writing failed (%d).", retval);
                    continue;
                }

                dbprintlf("Will await N/ACK.");
                memset(rd_buf, 0x0, SW_UPD_PACKET_SIZE);

                // TODO: Figure out a better way to wait for new data.
                while (!global->sw_output_fresh && global->sw_updating)
                {
                    dbprintlf("Waiting for response...");
                    usleep(0.1 SEC);
                }
                if (!global->sw_updating)
                {
                    // Update aborted.
                    dbprintlf(YELLOW_FG "Update aborted.");
                    return NULL;
                }

                // Timeout after waiting for 15 seconds.
                struct timespec timeout;
                clock_gettime(CLOCK_REALTIME, &timeout);
                timeout.tv_sec += 15;

                int retval = pthread_mutex_timedlock(global->sw_output_lock, &timeout);

                if (retval == 0)
                {
                    memcpy(rd_buf, global->sw_output->data, global->sw_output->data_size);
                    global->sw_output_fresh = false;
                    pthread_mutex_unlock(global->sw_output_lock);
                }
                else if (retval == ETIMEDOUT)
                {
                    // NOTE: Continues if timeout.
                    dbprintlf(YELLOW_FG "Lock acquisition timed out: failed to receive a response from SPACE-HAUC.");
                    continue;
                }
                else
                {
                    dbprintlf(FATAL "Failed to acquire sw_data_lock.");
                    continue;
                }

                // TODO: Figure out how to ask for a repeat if necessary.
                // Repeats are sent like so:
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, rept_cmd, sizeof(rept_cmd));

                if (!memcmp(rept_cmd, rd_buf, 5))
                { // We read in a REPT CMD, so repeat last.
                    dbprintlf(YELLOW_FG "Repeat of previous transmission requested.");
                    continue;
                }

                if (sr_rep->cmd != SW_UPD_SRID)
                {
                    continue;
                }
                else if (memcmp((char *)sr_rep->filename, filename, fn_sz) != 0)
                {
                    continue;
                }
                else if (sr_rep->recv_bytes != sent_bytes)
                {
                    // We should yield to SH here.
                    gs_sw_set_sent_bytes(filename, sr_rep->recv_bytes);
                    sent_bytes = sr_rep->recv_bytes;
                    sent_packets = (sent_bytes / SW_UPD_DATA_SIZE_MAX) + ((sent_bytes % SW_UPD_DATA_SIZE_MAX) > 0);

                    continue;
                }
                else if (sr_rep->total_packets != max_packets)
                {
                    continue;
                }
                else
                {
                    mode = data;
                    break;
                }
            }
            if (!global->sw_updating)
            {
                // Update aborted.
                dbprintlf(YELLOW_FG "Update aborted.");
                return NULL;
            }

            break; // case primer
        }

        case data:
        {

            memset(wr_buf, 0x0, SW_UPD_PACKET_SIZE);
            sw_upd_data_t *dt_hdr = (sw_upd_data_t *)wr_buf;

            sw_upd_data_reply_t *dt_rep = (sw_upd_data_reply_t *)rd_buf;

            for (send_attempts = 0; (send_attempts < SW_UPD_MAX_SEND_ATTEMPTS) && global->sw_updating; send_attempts++)
            {
                fseek(bin_fp, sent_packets * SW_UPD_DATA_SIZE_MAX, SEEK_SET);
                in_sz = fread(wr_buf + sizeof(sw_upd_data_t), 0x1, SW_UPD_DATA_SIZE_MAX, bin_fp);

                if (in_sz <= 0)
                {
                    dbprintlf(RED_FG "Reached EOF when retrieving packet %d.", sent_packets);
                    break;
                }

                dt_hdr->cmd = SW_UPD_DTID;
                dt_hdr->packet_number = sent_packets;
                dt_hdr->total_bytes = file_size;
                dt_hdr->data_size = in_sz;

                memcpy(wr_buf, dt_hdr, sizeof(sw_upd_data_t));

                // retval = gs_transmit(global->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, wr_buf, SW_UPD_PACKET_SIZE);
                NetFrame *network_frame = new NetFrame((unsigned char *)wr_buf, SW_UPD_PACKET_SIZE, NetType::DATA, NetVertex::ROOFUHF);
                network_frame->sendFrame(global->network_data);
                delete network_frame;

                if (retval <= 0)
                {
                    dbprintlf(RED_FG "DATA packet writing failed (%d).", retval);
                    continue;
                }

                dbprintlf("Will await N/ACK.");
                memset(rd_buf, 0x0, SW_UPD_PACKET_SIZE);

                // TODO: Figure out a better way to wait for new data.
                while (!global->sw_output_fresh && global->sw_updating)
                {
                    dbprintlf("Waiting for response...");
                    usleep(0.1 SEC);
                }

                // Timeout after waiting for 15 seconds.
                struct timespec timeout;
                clock_gettime(CLOCK_REALTIME, &timeout);
                timeout.tv_sec += 15;

                int retval = pthread_mutex_timedlock(global->sw_output_lock, &timeout);

                if (retval == 0)
                {
                    memcpy(rd_buf, global->sw_output->data, global->sw_output->data_size);
                    global->sw_output_fresh = false;
                    pthread_mutex_unlock(global->sw_output_lock);
                }
                else if (retval == ETIMEDOUT)
                {
                    // NOTE: Continues if timeout.
                    dbprintlf(YELLOW_FG "Lock acquisition timed out: failed to receive a response from SPACE-HAUC.");
                    continue;
                }
                else
                {
                    dbprintlf(FATAL "Failed to acquire sw_data_lock.");
                    continue;
                }

                // TODO: Figure out how to ask for a repeat if necessary.
                // Repeats are sent like so:
                // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, rept_cmd, sizeof(rept_cmd));

                if (!memcmp(rept_cmd, rd_buf, 5))
                { // We read in a REPT CMD, so repeat last.
                    dbprintlf(YELLOW_FG "Repeat of previous transmission requested.");
                    continue;
                }

                if (dt_rep->cmd != SW_UPD_DTID)
                {
                    continue;
                }
                else if (dt_rep->packet_number != sent_packets)
                {
                    mode = primer;
                    break;
                }
                else if (dt_rep->total_packets != max_packets)
                {
                    continue;
                }
                else
                {
                    sent_bytes += dt_hdr->data_size;
                    gs_sw_set_sent_bytes(filename, sent_bytes);
                    sent_packets++;

                    if (sent_bytes >= file_size)
                    {
                        mode = transfer_complete;
                    }

                    break;
                }
            }
            if (!global->sw_updating)
            {
                // Update aborted.
                dbprintlf(YELLOW_FG "Update aborted.");
                return NULL;
            }
            break; // case data
        }

        case transfer_complete:
        {
            if (sent_bytes == file_size)
            {
                // Complete
                dbprintlf("File transfer complete with %ld/%ld bytes of %s having been successfully sent and confirmed per packet.", sent_bytes, file_size, filename);
            }
            else if (global->sw_updating)
            {
                // Interrupted
                dbprintlf(YELLOW_FG "File transfer interrupted with %ld/%ld bytes of %s having been successfully sent and confirmed per packet.", sent_bytes, file_size, filename);
            }
            else if (sent_bytes <= 0)
            {
                // Error
                dbprintlf(RED_FG "An error has been encountered with %ld/%ld bytes of %s sent.", sent_bytes, file_size, filename);
                global->sw_updating = false;
                return NULL;
            }
            else
            {
                /// NOTE: Will reach this case if (recv_bytes != file_size).
                // ???
                dbprintlf(FATAL "Confused.");
                global->sw_updating = false;
                return NULL;
            }

            mode = confirmation;

            break; // case transfer_complete
        }

        case confirmation:
        {
            sw_upd_conf_t *cf_hdr = (sw_upd_conf_t *)wr_buf;
            sw_upd_conf_reply_t *cf_rep = (sw_upd_conf_reply_t *)rd_buf;

            cf_hdr->cmd = SW_UPD_CFID;
            cf_hdr->packet_number = sent_packets;
            cf_hdr->total_packets = max_packets;

            checksum_md5(directory_filename, cf_hdr->hash, 32);

            // retval = gs_transmit(global->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, wr_buf, SW_UPD_PACKET_SIZE);
            NetFrame *network_frame = new NetFrame((unsigned char *)wr_buf, SW_UPD_PACKET_SIZE, NetType::DATA, NetVertex::ROOFUHF);
            network_frame->sendFrame(global->network_data);
            delete network_frame;

            if (retval <= 0)
            {
                dbprintlf(RED_FG "CF header writing failed (%d).", retval);
                continue;
            }

            dbprintlf("Will await N/ACK.");
            memset(rd_buf, 0x0, SW_UPD_PACKET_SIZE);

            // TODO: Figure out a better way to wait for new data.
            while (!global->sw_output_fresh && global->sw_updating)
            {
                dbprintlf("Waiting for response...");
                usleep(0.1 SEC);
            }
            if (!global->sw_updating)
            {
                // Update aborted.
                dbprintlf(YELLOW_FG "Update aborted.");
                return NULL;
            }

            // Timeout after waiting for 15 seconds.
            struct timespec timeout;
            clock_gettime(CLOCK_REALTIME, &timeout);
            timeout.tv_sec += 15;

            int retval = pthread_mutex_timedlock(global->sw_output_lock, &timeout);

            if (retval == 0)
            {
                memcpy(rd_buf, global->sw_output->data, global->sw_output->data_size);
                global->sw_output_fresh = false;
                pthread_mutex_unlock(global->sw_output_lock);
            }
            else if (retval == ETIMEDOUT)
            {
                // NOTE: Continues if timeout.
                dbprintlf(YELLOW_FG "Lock acquisition timed out: failed to receive a response from SPACE-HAUC.");
                continue;
            }
            else
            {
                dbprintlf(FATAL "Failed to acquire sw_data_lock.");
                continue;
            }

            // TODO: Figure out how to ask for a repeat if necessary.
            // Repeats are sent like so:
            // gs_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_ROOFUHF, rept_cmd, sizeof(rept_cmd));

            if (!memcmp(rept_cmd, rd_buf, 5))
            { // We read in a REPT CMD, so repeat last.
                dbprintlf(YELLOW_FG "Repeat of previous transmission requested.");
                continue;
            }

            if (cf_rep->cmd != SW_UPD_CFID)
            {
                break;
            }
            else if (cf_rep->total_packets != max_packets)
            {
                break;
            }
            else if (cf_rep->request_packet == REQ_PKT_RESEND)
            {
                break;
            }
            else if (cf_rep->request_packet >= 0)
            {
                if (cf_rep->request_packet > max_packets)
                {
                    break;
                }
                else if (cf_rep->request_packet <= max_packets)
                {
                    sent_packets = cf_rep->request_packet;
                    sent_bytes = SW_UPD_DATA_SIZE_MAX * sent_packets;
                    gs_sw_set_sent_bytes(filename, sent_bytes);
                    mode = primer;
                    break;
                }
            }
            else if (memcmp(cf_rep->hash, cf_hdr->hash, SW_UPD_HASH_SIZE) != 0)
            {
                dbprintlf(FATAL "Restarting file transfer.");
                sent_packets = 0;
                sent_bytes = 0;
                gs_sw_set_sent_bytes(filename, 0);
                mode = primer;
            }
            else
            {
                dbprintlf(BLUE_BG "File transfer complete.");
                mode = finish;
            }

            break; // case confirmation
        }

        case finish:
        {
            dbprintlf("The file transfer is now complete.");
            global->sw_upd_packet = -1;
            break; // case finish
        }
        }
    }

    global->sw_updating = false;
    return NULL;
}

ssize_t gs_sw_get_sent_bytes(const char filename[])
{
    // Read from {filename}.sent_bytes to see if this file was already mid-transfer and needs to continue at some specific point.
    char filename_bytes[128];
    snprintf(filename_bytes, 128, "%s.%s", filename, "gsbytes");

    int bytes_fp = -1;
    ssize_t sent_bytes = 0;

    if (access(filename_bytes, F_OK) == 0)
    {
        // File exists.
        bytes_fp = open(filename_bytes, O_RDONLY);
        if (bytes_fp < 3)
        {
            dbprintlf(RED_FG "%s exists but could not be opened.", filename_bytes);
            return ERR_FILE_OPEN;
        }
        lseek(bytes_fp, 0, SEEK_SET);
        if (read(bytes_fp, &sent_bytes, sizeof(ssize_t)) != sizeof(ssize_t))
        {
            dbprintlf(RED_FG "Error reading sent_bytes.");
        }
        dbprintlf(YELLOW_FG "%ld bytes of current transfer previously received by SH.", sent_bytes);
        close(bytes_fp);
    }
    else
    {
        // File does not exist.
        bytes_fp = open(filename_bytes, O_CREAT | O_EXCL, 0755);
        if (bytes_fp < 3)
        {
            dbprintlf(RED_FG "%s does not exist and could not be created.", filename_bytes);
            return ERR_FILE_OPEN;
        }
        lseek(bytes_fp, 0, SEEK_SET);
        int retval = write(bytes_fp, &sent_bytes, sizeof(ssize_t));
        if (retval != sizeof(ssize_t))
        {
            dbprintlf(RED_FG "Error %d", retval);
        }
        dbprintlf(YELLOW_FG "%s does not exist. Assuming transfer should start at packet 0.", filename_bytes);
        close(bytes_fp);
    }
    sync();
    return sent_bytes;
}

int gs_sw_set_sent_bytes(const char filename[], ssize_t sent_bytes)
{
    // Overwrite {filename}.bytes to contain {sent_bytes}.
    char filename_bytes[128];
    snprintf(filename_bytes, 128, "%s.%s", filename, "gsbytes");

    int bytes_fp = -1;
    bytes_fp = open(filename_bytes, O_RDWR | O_TRUNC);
    if (bytes_fp < 3)
    {
        dbprintlf(RED_FG "Could not open %s for overwriting.", filename_bytes);
        return ERR_FILE_OPEN;
    }
    lseek(bytes_fp, 0, SEEK_SET);
    if (write(bytes_fp, &sent_bytes, sizeof(ssize_t)) != sizeof(ssize_t))
    {
        dbprintlf(RED_FG "Could not write to %s", filename_bytes);
    }
    close(bytes_fp);

    sync();
    return 1;
}
