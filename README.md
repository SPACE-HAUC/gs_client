# SPACE-HAUC Ground Station GUI Client
Graphical user interface for SPACE-HAUC Ground Station operations. Intended to be used with the SPACE-HAUC Ground Station Network.

#SPACE-HAUC Ground Station

## The Network
[GUI Client](https://github.com/SPACE-HAUC/gs_client) (SPACE-HAUC/gs_client)

[Server](https://github.com/SPACE-HAUC/gs_server) (SPACE-HAUC/gs_server)

[Roof UHF](https://github.com/SPACE-HAUC/gs_uhf) (SPACE-HAUC/gs_uhf)

[Roof X-Band](https://github.com/SPACE-HAUC/gs_xband) (SPACE-HAUC/gs_xband)

[Haystack](https://github.com/SPACE-HAUC/gs_haystack) (SPACE-HAUC/gs_haystack)

[Tracker](https://github.com/SPACE-HAUC/gs_track) (SPACE-HAUC/gs_track)
  
## Current State
_GUI Client_ (beta, tested)

The Client packages and sends NetworkFrames over a socket connection. The outbound connection is opened by the operator via the Connections Manager window. Currently, sent and received data can be viewed either through the Linux Terminal or in the 'Plaintext RX Display' and 'ACS Update Display' windows. NetworkFrames undergo an integrity check prior to leaving and when they are received. The Client will periodically send null NetworkFrames to the Ground Station Network Server for status information on the devices connected to the Network. The other Network devices should connect to the server automatically. 

_Server_ (release, tested)

The server successfully handles connections and disconnections, including unexpected losses of signal, reliably transferring data.

_Roof UHF_ (release, tested)

The UHF transmit / receive system operates nominally, successfully sending and receiving data, ensuring its integrity.

_Roof X-Band_ (release, tested)

_Haystack_ (release, tested)

_Track_ (requires integration)   

## Connections Testing  

__*2021.08.18*__

All but Track connected and tested with new Network API, everything works well. X-Band sends / receives 56-byte test packet.

__*2021.08.13*__

X-Band and Haystack programs tested, work within the network, transmitting / receiving may need tweaking. ground_station_track created to move the positioner on which the radio is mounted to track the satellite. Tested a smaller version with the hardware, properly listened to commands.

__*2021.08.12*__

Server (ground_station_server v3.0-release) running on qe.locsst.uml.edu, UHF client (ground_station_uhf v3.0-release) running on Raspberry Pi 4, and GUI Client (ground_station v2.0-beta) tested together with the faux_space-hauc repository, which runs on a Raspberry Pi 4 with Si446x UHF radio and simulates SPACE-HAUC. Test showed that the Attitude Control System data updates cannot be polled faster than once every half-second, else the Ground Station Network loses a significant number of packets. At this reduced (from ten per second) rate, the Network successfully polled faux_space-hauc for mock ACS data via UHF radio communication, passing it through the Server to the GUI Client. The Client then successfully displayed the data in graph form. When programs are shutdown or lose connection, proper communications resume when they are restarted. Non-user-operated programs successfully automatically connect to the Server, and the server times the connection out if necessary (ie connection is lost). 

__*2021.08.09*__

Connected all clients to the server; the server hosted on the LoCCST server (IP: 129.63.134.29). Connection successfully held open, frames delivered to correct recipients, for over one hour. At one point some frames were failing integrity checks once at the server (likely a network issue), but this did not disconnect any clients. It recovered after approximately 5 seconds of this.


__*2021.08.04*__

Tested connection to the server with all other clients, everything connected and displayed status correctly. Versions below. 
```
GUI Client --- v1.3-alpha 
Server ------- v1.1.0-alpha
Roof UHF ----- v1.0-alpha 
Roof X-Band -- v0.1-alpha 
Haystack ----- v0.1-alpha
```
__*2021.08.03*__

Tested connection to the server with preliminary version of Roof UHF program (v1.3-alpha). Correctly receives the status of all parties, stays connected, and the Roof UHF program also stays connected. Roof UHF successfully reconnects if the server crashes, and does not crash itself trying to get the UHF Radio up and running.  

__*2021.07.29b*__  

Port connection issue fixed, see ground_station_server repository for more information.  

__*2021.07.29*__  

Failing to connect to server via port 54210, all others work. Successfully sends, receives, and displays status info.  
  
__*2021.07.27*__

Successfully connected to server (see: ground_station_server repo), sends ClientServerFrames, and receives ClientServerFrames.  
  
__*2021.07.26*__

The receive thread automatically finds and binds to the local IPv4 address, with a port of 51934. If the auto-detect fails, a default address of 127.0.0.1 is used. The receive thread will attempt to bind infinitely until it does successfully.   
  
The Connections Manager fills in its own receiver thread IPv4 address and port in the IP Address and Port fields. This enables the operator to press 'Connect,' and connect back into the client's own receiver thread. In the Connections Manager window, a JPEG Quality field should appear. The '+' and '-' buttons can be used to send sample data over this connection. The results of this are viewable in the Linux Terminal. The JPEG example should cause an integrity failure, however if data is sent using the Data-down Arrow Buttons the integrity check should return successfully.  
  
## Known Issues
- The GUI Client's X-Band infrastructure is lacking; xb_gs_test's UI and back-end will be integrated into the GUI Client once finished. 
-  

## IP & Ports
```
Server   
  IP:               TBD  
  Ports:  
    (GUI Client)    54200  
    (Roof UHF)      54210  
    (Roof X-Band)   54220  
    (Haystack)      54230  
``` 
 
  
  
    
   
  
  
Splitting into Columns~

    // static int test1 = 0, test2 = 0, test3 = 0;
    // ImGui::Columns(3, "first_column_set", true);
    // ImGui::InputInt("test1", &test1);
    // ImGui::NextColumn();
    // ImGui::InputInt("test2", &test2);
    // ImGui::NextColumn();
    // ImGui::InputInt("test3", &test3);
