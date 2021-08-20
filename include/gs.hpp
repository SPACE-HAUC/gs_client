/**
 * @file gs.hpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief Contains class and function declarations, enums, structs, and constants.
 * 
 * Contains data-handling code and does not create or augment the GUI directly.
 * 
 * @version 0.1
 * @date 2021.07.26
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef GS_HPP
#define GS_HPP

#include <arpa/inet.h>
#include <GLFW/glfw3.h>
#include "implot/implot.h"
#include "network.hpp"
#include "buffer.hpp"
#include "phy.hpp"

#define SEC *1000000
#define ACS_UPDATE_FREQUENCY 0.5 // seconds
#define MAX_DATA_SIZE 46
#define ACS_UPD_DATARATE 100
#define RECV_TIMEOUT 15    // seconds
#define SERVER_POLL_RATE 5 // once per this many seconds

#define MHZ(x) ((long long)(x * 1000000.0 + .5))
#define GHZ(x) ((long long)(x * 1000000000.0 + .5))
#define HZ_M(x) (((double)x) * 1e-6)
#define HZ_G(x) (((double)x) * 1e-9)

#define COLOR_RED ImVec4(0xff, 0, 0, 0xff)
#define COLOR_GREEN ImVec4(0x0, 0xff, 0x0, 0xff)
#define COLOR_YLW ImVec4(0xff, 0xff, 0x0, 0xff)

#define NACK_NO_UHF 0x756866 // Roof UHF says it cannot access UHF communications.

// Function magic for system restart command, replaces .cmd value.
#define SYS_RESTART_FUNC_MAGIC 0x3c
// Data value for system restart command, replaces .data[] values.
#define SYS_RESTART_FUNC_VAL 0x2fa45d2002d54af2

// Function magic for system reboot command, replaces .cmd value.
#define SYS_REBOOT_FUNC_MAGIC 0x9d
// Data value for system restart command, replaces .data[] values.
#define SYS_REBOOT_FUNC_VAL 0x36a45d2002d54af0

// Data value for software update command, replaces .data[] values.
#define SW_UPD_VALID_MAGIC 0x2489f750228d2e4fL

/**
 * @brief Numeric identifiers for determining what module a command is for.
 * 
 */
enum MODULE_ID
{
    INVALID_ID = 0x0,
    ACS_ID = 0x1,
    EPS_ID = 0x2,
    XBAND_ID = 0x3,
    SW_UPD_ID = 0xf,
    ACS_UPD_ID = 0xe,
    SYS_VER_MAGIC = 0xd,
    SYS_RESTART_PROG = 0xff,
    SYS_REBOOT = 0xfe,
    SYS_CLEAN_SHBYTES = 0xfd
};

/**
 * @brief Function magic for software update command, replaces .cmd value.
 * 
 */
enum SW_UPD_FUNC_ID
{
    SW_UPD_FUNC_MAGIC = 0x87,
};

/**
 * @brief ID values for each ACS command.
 * 
 */
enum ACS_FUNC_ID
{
    ACS_INVALID_ID = 0x0,
    ACS_GET_MOI,
    ACS_SET_MOI,
    ACS_GET_IMOI,
    ACS_SET_IMOI,
    ACS_GET_DIPOLE,
    ACS_SET_DIPOLE,
    ACS_GET_TSTEP,
    ACS_SET_TSTEP,
    ACS_GET_MEASURE_TIME,
    ACS_SET_MEASURE_TIME,
    ACS_GET_LEEWAY,
    ACS_SET_LEEWAY,
    ACS_GET_WTARGET,
    ACS_SET_WTARGET,
    ACS_GET_DETUMBLE_ANG,
    ACS_SET_DETUMBLE_ANG,
    ACS_GET_SUN_ANGLE,
    ACS_SET_SUN_ANGLE
};

/**
 * @brief ID values for each EPS command.
 * 
 */
enum EPS_FUNC_ID
{
    EPS_INVALID_ID = 0x0,
    EPS_GET_MIN_HK = 0x1,
    EPS_GET_VBATT,
    EPS_GET_SYS_CURR,
    EPS_GET_OUTPOWER,
    EPS_GET_VSUN,
    EPS_GET_VSUN_ALL,
    EPS_GET_ISUN,
    EPS_GET_LOOP_TIMER,
    EPS_SET_LOOP_TIMER,
};

/**
 * @brief ID values for each XBAND command.
 * 
 */
enum XBAND_FUNC_ID
{
    XBAND_INVALID_ID = 0x0,
    XBAND_SET_TX,
    XBAND_SET_RX,
    XBAND_DO_TX,
    XBAND_DO_RX,
    XBAND_DISABLE,
    XBAND_SET_MAX_ON,
    XBAND_GET_MAX_ON,
    XBAND_SET_TMP_SHDN,
    XBAND_GET_TMP_SHDN,
    XBAND_SET_TMP_OP,
    XBAND_GET_TMP_OP,
    XBAND_GET_LOOP_TIME,
    XBAND_SET_LOOP_TIME,
};

/**
 * @brief Command structure that SPACE-HAUC receives.
 * 
 */
typedef struct __attribute__((packed))
{
    uint8_t mod;
    uint8_t cmd;
    int unused;
    int data_size;
    unsigned char data[46];
} cmd_input_t;

/**
 * @brief ImGui full-size integer interface; holds integers until cast.
 * 
 */
typedef struct
{
    int mod;
    int cmd;
} cmd_input_holder_t;

/**
 * @brief Command structure that SPACE-HAUC transmits to Ground.
 * 
 */
typedef struct __attribute__((packed))
{
    uint8_t mod;            // 1
    uint8_t cmd;            // 1
    int retval;             // 4
    int data_size;          // 4
    unsigned char data[46]; // 46
} cmd_output_t;

/**
 * @brief Set of possible data ACS can set.
 * 
 */
typedef struct
{
    float moi[9];
    float imoi[9];
    float dipole;
    uint8_t tstep;
    uint8_t measure_time;
    uint8_t leeway;
    float wtarget;
    uint8_t detumble_angle;
    uint8_t sun_angle;
} acs_set_data_t;

/**
 * @brief ImGui full-size integer interface; holds integers until cast.
 * 
 */
typedef struct
{
    int tstep;
    int measure_time;
    int leeway;
    int detumble_angle;
    int sun_angle;
} acs_set_data_holder_t;

/**
 * @brief Set of possible booleans ACS can use.
 * 
 */
typedef struct
{
    bool moi;
    bool imoi;
    bool dipole;
    bool tstep;
    bool measure_time;
    bool leeway;
    bool wtarget;
    bool detumble_angle;
    bool sun_angle;
} acs_get_bool_t;

/**
 * @brief Set of possible data EPS can set.
 * 
 */
typedef struct
{
    int loop_timer;
} eps_set_data_t;

/**
 * @brief Set of possible booleans EPS can use.
 * 
 */
typedef struct
{
    bool min_hk;
    bool vbatt;
    bool sys_curr;
    bool outpower;
    bool vsun;
    bool vsun_all;
    bool isun;
    bool loop_timer;
} eps_get_bool_t;

// /**
//  * @brief For configuring Roof X-Band / Haystack.
//  * 
//  */
// typedef struct
// {
//     int mode;               // SLEEP, FDD, TDD
//     int pll_freq;           // PLL Frequency
//     uint64_t LO;            // LO freq
//     uint64_t samp;          // sampling rate
//     uint64_t bw;            // bandwidth
//     char ftr_name[64];      // filter name
//     int temp;               // temperature
//     double rssi;            // RSSI
//     double gain;            // TX Gain
//     char curr_gainmode[16]; // fast_attack or slow_attack
//     bool pll_lock;
// } phy_config_t;

/**
 * @brief X-Band data structure.
 * 
 * From line 113 of https://github.com/SPACE-HAUC/shflight/blob/flight_test/src/cmd_parser.c
 * Used for:
 *  XBAND_SET_TX
 *  XBAND_SET_RX
 * 
 * FOR SPACE-HAUC USE ONLY
 * 
 */
typedef struct __attribute__((packed))
{
    float LO;
    float bw;
    uint16_t samp;
    uint8_t phy_gain;
    uint8_t adar_gain;
    uint8_t ftr;
    short phase[16];
} xband_set_data_t;

/**
 * @brief ImGui full-size integer interface; holds integers until cast.
 * 
 */
typedef struct
{
    int samp;
    int phy_gain;
    int adar_gain;
    int ftr;
    int phase[16];
} xband_set_data_holder_t;

/**
 * @brief Set of possible data XBAND can set.
 * 
 */
typedef struct
{
    xband_set_data_t RX;
    xband_set_data_holder_t RXH;
    xband_set_data_t TX;
    xband_set_data_holder_t TXH;
} xband_set_data_array_t;

typedef struct
{
    uint8_t ack; // 0 = NAck, 1 = Ack
    int code;    // Error code or some other info.
} cs_ack_t;      // (N/ACK)

// Config types.
// NOTE: cs_config_xband_t == xband_set_data_array_t
// typedef xband_set_data_array_t cs_config_xband_t;

// NOTE: No UHF configurations exist at this time.
typedef struct
{

} cs_config_uhf_t;

/**
 * @brief X-Band TX structure.
 * 
 * Used for:
 *  XBAND_DO_TX
 * 
 * Packed (see line 126: https://github.com/SPACE-HAUC/shflight/blob/flight_test/src/cmd_parser.c)
 * 
 */
typedef struct __attribute__((packed))
{
    uint8_t type; // 0 -> text, 1 -> image          1
    int f_id;     // -1 -> random, 0 -> max         4
    int mtu;      // 0 -> 128                       4
} xband_tx_data_t;

/**
 * @brief ImGui full-size integer interface; holds integers until cast.
 * 
 */
typedef struct
{
    int type;
} xband_tx_data_holder_t;

/**
 * @brief General data for X-Band.
 * 
 * Used for:
 *  XBAND_SET_MAX_ON
 *  XBAND_SET_TMP_SHDN
 *  XBAND_SET_TMP_OP
 *  XBAND_SET_LOOP_TIME
 * 
 */
typedef struct __attribute__((packed))
{
    uint8_t max_on;
    uint8_t tmp_shdn;
    uint8_t tmp_op;
    uint8_t loop_time;
} xband_rxtx_data_t;

/**
 * @brief ImGui full-size integer interface; holds integers until cast. 
 * 
 */
typedef struct
{
    int max_on;
    int tmp_shdn;
    int tmp_op;
    int loop_time;
} xband_rxtx_data_holder_t;

/// X-Band ///

enum TRX_MODE
{
    MODE_TX = 0,
    MODE_RX = 1,
};

enum ensm_mode
{
    SLEEP,
    FDD,
    TDD
};

static char *pll_freq_str[] = {"5900 MHz", "4750 MHz"};

static unsigned char test_cmd[56] = "This is a test of the emergency alert broadcast system.";

typedef enum
{
    RX_FRAME_INVALID = -30,
    RX_INVALID_GUID,
    RX_PACK_SZ_ZERO,
    RX_NUM_FRAMES_ZERO,
    RX_FRAME_SZ_ZERO,
    RX_THREAD_SPAWN,
    RX_FRAME_CRC_FAILED,
    RX_MALLOC_FAILED,
} RXMODEM_ERROR;

/**
 * @brief Authentication structure, used to store auth-related information.
 * 
 */
typedef struct
{
    bool busy;
    uint8_t access_level;
    char password[64];
} auth_t;

typedef struct
{
    bool acs_multiple_windows;
    bool tooltips;
} settings_t;

/**
 * @brief Contains structures and classes that will be populated with data by the receive thread; these structures and classes also provide the data which the client will display.
 * 
 */
typedef struct
{
    // Data
    NetDataClient *network_data;
    ACSRollingBuffer *acs_rolbuf;

    settings_t settings[1];
    cs_ack_t cs_ack[1];
    cs_config_uhf_t cs_config_uhf[1];
    // TODO: Delete cs_config_xband because we will be using phy_config_t (see below) instead.
    xband_set_data_t cs_config_xband[1];
    cmd_output_t cmd_output[1];

    uint8_t netstat;
    double last_contact;

    // sw_update
    cmd_output_t sw_output[1];
    pthread_mutex_t sw_output_lock[1];
    bool sw_output_fresh;
    bool sw_updating;
    int sw_upd_packet;        // Current packet number for GUI loading bar.
    int sw_upd_total_packets; // Total packets for the transfer.
    char directory[20];
    char filename[20];

    // x-band
    bool xbrx_avail; // Is HAYSTACK connected?
    bool xbtx_avail; // Is ROOFUHF connected?
    phy_config_t rxphy[1]; // Receiver configuration.
    phy_config_t txphy[1]; // Transmitter configuration.
    char recv_status_buffer[256];
    char read_status_buffer[256];
    int last_xbrx_status;
    int last_xbread_status;
    bool refresh_rx_ui_data;
    bool refresh_tx_ui_data;
    bool rx_armed;
    float rx_samp;
    float rx_lo;
    float rx_bw;
    int rxmode;
    float tx_samp;
    float tx_lo;
    float tx_bw;
    int txmode;
    float tx_gain;
    int MTU;
    uint16_t mega_packet_crc;
    int mega_packet_file_size;
} global_data_t; 

enum XBAND_COMMAND
{
    XBC_INIT_PLL = 0,
    XBC_DISABLE_PLL = 1,
    XBC_ARM_RX = 2,
    XBC_DISARM_RX = 3,
};

// typedef struct
// {
//     global_data_t **global_data;
//     char directory[20];
//     char filename[20];
// } sw_upd_args_t;

// /**
//  * @brief 
//  * 
//  * @param socket 
//  * @param address 
//  * @param socket_size 
//  * @param tout_s 
//  * @return int 
//  */
// int gs_connect(int socket, const struct sockaddr *address, socklen_t socket_size, int tout_s);

/**
 * @brief Get the Min object
 * 
 * @param a 
 * @param b 
 * @return float 
 */
float getMin(float a, float b);

/**
 * @brief Get the Min object
 * 
 * @param a 
 * @param b 
 * @param c 
 * @return float 
 */
float getMin(float a, float b, float c);

/**
 * @brief Get the Max object
 * 
 * @param a 
 * @param b 
 * @return float 
 */
float getMax(float a, float b);

/**
 * @brief Get the Max object
 * 
 * @param a 
 * @param b 
 * @param c 
 * @return float 
 */
float getMax(float a, float b, float c);

/**
 * @brief Default ImGui callback function.
 * 
 * @param error 
 * @param description 
 */
void glfw_error_callback(int error, const char *description);

/**
 * @brief Checks the validity of the user-input password candidate.
 * 
 * @param arg The entered password candidate.
 * @return void* Pointer to the original argument.
 */
void *gs_check_password(void *arg);

/**
 * @brief Does the actual password checking.
 * 
 * @param message Data to be checked.
 * @return unsigned int 
 */
int gs_helper(void *aa);

/**
 * @brief Handles the asynchronous sending of the ACS update data retrieval command.
 * 
 * @param vp Pointer to the acs_upd_input_t structure.
 * @return void* Pointer to the original argument.
 */
void *gs_acs_update_thread(void *vp);

// /**
//  * @brief Transmits data to SPACE-HAUC.
//  * 
//  * @param input The data to transmit.
//  * @return int Positive on success, negative on failure.
//  */
// int gs_transmit(NetData *network_data, NETWORK_FRAME_TYPE type, NETWORK_FRAME_ENDPOINT endpoint, void *data, int data_size);

// /**
//  * @brief 
//  * 
//  * @param args 
//  * @return void* 
//  */
// void *gs_polling_thread(void *args);

/**
 * @brief 
 * 
 * @param args 
 * @return void* 
 */
void *gs_rx_thread(void *args);

/**
 * @brief 
 * 
 * @param args_vp 
 * @return void* 
 */
void *gs_sw_send_file_thread(void *args_vp);
// int gs_sw_send_file(global_data_t *global_data, const char directory[], const char filename[], bool *done_upld);

/**
 * @brief 
 * 
 * @param filename 
 * @return ssize_t 
 */
ssize_t gs_sw_get_sent_bytes(const char filename[]);

/**
 * @brief 
 * 
 * @param filename 
 * @param sent_bytes 
 * @return int 
 */
int gs_sw_set_sent_bytes(const char filename[], ssize_t sent_bytes);

/**
 * @brief Generates a 16-bit CRC for the given data.
 * 
 * This is the CCITT CRC 16 polynomial X^16  + X^12  + X^5  + 1.
 * This works out to be 0x1021, but the way the algorithm works
 * lets us use 0x8408 (the reverse of the bit pattern).  The high
 * bit is always assumed to be set, thus we only use 16 bits to
 * represent the 17 bit value.
 * 
 * This is the same crc16 function used on-board SPACE-HAUC (line 116):
 * https://github.com/SPACE-HAUC/uhf_modem/blob/aa361d13cf1cef9b295a6cd5e2d51c7ae6d59637/uhf_modem.h
 * 
 * @param data_p 
 * @param length 
 * @return uint16_t 
 */
static inline uint16_t crc16(unsigned char *data_p, uint16_t length)
{
#define CRC16_POLY 0x8408
    unsigned char i;
    unsigned int data;
    unsigned int crc = 0xffff;

    if (length == 0)
        return (~crc);

    do
    {
        for (i = 0, data = (unsigned int)0xff & *data_p++;
             i < 8;
             i++, data >>= 1)
        {
            if ((crc & 0x0001) ^ (data & 0x0001))
                crc = (crc >> 1) ^ CRC16_POLY;
            else
                crc >>= 1;
        }
    } while (--length);

    crc = ~crc;
    data = crc;
    crc = (crc << 8) | (data >> 8 & 0xff);

    return (crc);
}

#endif // GS_HPP