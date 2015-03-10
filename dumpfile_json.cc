/*

  This file is part of Kismet

  Kismet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  Kismet is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with Kismet; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  extension created by Yaker Mahieddine


*/

#include "config.h"

#include <errno.h>

#include "globalregistry.h"
#include "alertracker.h"
#include "dumpfile_json.h"
#include "packetsource.h"
#include "packetsourcetracker.h"
#include "netracker.h"



Dumpfile_Json::Dumpfile_Json() {
  fprintf(stderr, "FATAL OOPS: Dumpfile_Json called with no globalreg\n");
  exit(1);
}




Dumpfile_Json::Dumpfile_Json(GlobalRegistry *in_globalreg) :
  Dumpfile(in_globalreg) {
  globalreg = in_globalreg;

  jsonfile = NULL;

  type = "json";
  logclass = "json";

  if (globalreg->netracker == NULL) {
    _MSG("Deprecated netracker core disabled, disabling json logfile.",
         MSGFLAG_INFO);
    // fprintf(stderr, "FATAL OOPS:  Netracker missing before Dumpfile_Nettxt\n");
    // exit(1);
    return;
  }

  if (globalreg->kismet_config == NULL) {
    fprintf(stderr, "FATAL OOPS:  Config file missing before Dumpfile_Json\n");
    exit(1);
  }

  if (globalreg->alertracker == NULL) {
    fprintf(stderr, "FATAL OOPS:  Alertacker missing before Dumpfile_Json\n");
    exit(1);
  }

  // Find the file name
  if ((fname = ProcessConfigOpt()) == "" ||
      globalreg->fatal_condition) {
    return;
  }

  if ((jsonfile = fopen(fname.c_str(), "w")) == NULL) {
    _MSG("Failed to open json log file '" + fname + "': " + strerror(errno),
         MSGFLAG_FATAL);
    globalreg->fatal_condition = 1;
    return;
  }

  globalreg->RegisterDumpFile(this);

  _MSG("Opened json log file '" + fname + "'", MSGFLAG_INFO);

}



Dumpfile_Json::~Dumpfile_Json() {
  // Close files
  if (jsonfile != NULL) {
    Flush();
  }

  jsonfile = NULL;

  if (export_filter != NULL)
    delete export_filter;
}


int Dumpfile_Json::Flush(){

  if (jsonfile != NULL)
    fclose(jsonfile);

  string tempname = fname + ".temp";
  if ((jsonfile = fopen(tempname.c_str(), "w")) == NULL) {
    _MSG("Failed to open temporary nettxt file for writing: " +
         string(strerror(errno)), MSGFLAG_ERROR);
    return -1;
  }


  // Get the tracked network and client->ap maps
  const map<mac_addr, Netracker::tracked_network *> tracknet =
    globalreg->netracker->FetchTrackedNets();

  // Get the alerts
  const vector<kis_alert_info *> *alerts =
    globalreg->alertracker->FetchBacklog();

  map<mac_addr, Netracker::tracked_network *>::const_iterator x,finalIte;
  map<mac_addr, Netracker::tracked_client *>::const_iterator y;

  int netnum = 0;
  // Dump all the networks
  fprintf(jsonfile,"\"Networks\" : [\n");
  finalIte = tracknet.end();
  finalIte--;
  for (x = tracknet.begin(); x != tracknet.end(); ++x) {
    netnum++;

    if (export_filter->RunFilter(x->second->bssid, mac_addr(0), mac_addr(0)))
      continue;

    Netracker::tracked_network *net = x->second;

    if (net->type == network_remove)
      continue;


    string ntype;
    switch (net->type) {
    case network_ap:
      ntype = "infrastructure";
      break;
    case network_adhoc:
      ntype = "ad-hoc";
      break;
    case network_probe:
      ntype = "probe";
      break;
    case network_data:
      ntype = "data";
      break;
    case network_turbocell:
      ntype = "turbocell";
      break;
    default:
      ntype = "unknown";
      break;
    }
    fprintf(jsonfile,"{\n");

    fprintf(jsonfile,"\"Network\":%d,\n",netnum);
    fprintf(jsonfile,"\"détails\" : {\n");
    fprintf(jsonfile, "\"Manuf\"      : \"%s\",\n", net->manuf.c_str());
    fprintf(jsonfile, "\"First\"      : \"%.24s\",\n", ctime(&(net->first_time)));
    fprintf(jsonfile, "\"Last\"       : \"%.24s\",\n", ctime(&(net->last_time)));
    fprintf(jsonfile, "\"Type\"       : \"%s\",\n", ntype.c_str());
    fprintf(jsonfile, "\"BSSID\"      : \"%s\",\n", net->bssid.Mac2String().c_str());

    int ssidnum = 1;
    fprintf(jsonfile,"\"détail_BSSID\":{\n");
    for (map<uint32_t, Netracker::adv_ssid_data *>::iterator m  =
           net->ssid_map.begin(); m != net->ssid_map.end(); ++m) {

      fprintf(jsonfile,"\"SSID_Num\":%d,\n",ssidnum);
      fprintf(jsonfile,"\"SSID_Info\":{\n");
      string typestr;
      switch(m->second->type){
      case ssid_beacon:
        typestr = "Beacon";
        break;
      case ssid_proberesp:
        typestr = "Probe Response";
        break;
      case ssid_probereq:
        typestr = "Probe Request";
        break;
      case ssid_file:
        typestr = ssid_file;
        break;
      default:
        break;
      }
      fprintf(jsonfile, "\"SSID_num\" :%d,\n", ssidnum);
      fprintf(jsonfile, "\"Type\": \"%s\",\n", typestr.c_str());
      fprintf(jsonfile, "\"SSID\": \"%s %s\" ,\n", m->second->ssid.c_str(),
              m->second->ssid_cloaked ? "(Cloaked)" : "");

      if (m->second->beacon_info.length() > 0)
        fprintf(jsonfile, "    \"Info\"       : \"%s\",\n", 
                m->second->beacon_info.c_str());
      fprintf(jsonfile, "    \"First\"      : \"%.24s\",\n", 
              ctime(&(m->second->first_time)));
      fprintf(jsonfile, "    \"Last\"       : \"%.24s\",\n", 
              ctime(&(m->second->last_time)));
      fprintf(jsonfile, "    \"Max_Rate\"   : %2.1f,\n", m->second->maxrate);
      if (m->second->beaconrate != 0)
        fprintf(jsonfile, "    \"Beacon\"     : %d,\n", m->second->beaconrate);
      fprintf(jsonfile, "    \"Packets\"    : %d,\n", m->second->packets);

      if (m->second->dot11d_vec.size() > 0) {
        fprintf(jsonfile, "    \"Country\"    : \"%s\"\n", 
                m->second->dot11d_country.c_str());
      }
      fprintf(jsonfile,"\"Encryption\" : [");

      int i;
      int listeCrypt[20];

      for(i = 0;i<20;i++)
        listeCrypt[i] = 0;

      i = -1;
      if (m->second->cryptset == 0){
        // fprintf(jsonfile, "  \"None\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset == crypt_wep){
        //fprintf(jsonfile, "  \"WEP\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_layer3){
        //fprintf(jsonfile, "    \"Layer3\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_wpa_migmode){
        //fprintf(jsonfile, "    \"WPA Migration Mode\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_wep40){
        //fprintf(jsonfile, "   \"WEP40\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_wep104){
        //fprintf(jsonfile, "    \"WEP104\"");
        i++;
        listeCrypt[i] = 1;
      }
      /*
        if (m->second->cryptset & crypt_wpa)
        fprintf(jsonfile, "    Encryption : WPA\n");
      */


      if (m->second->cryptset & crypt_psk){
        //fprintf(jsonfile, "    \"WPA+PSK\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_tkip){
        //fprintf(jsonfile, "    \"WPA+TKIP\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_aes_ocb){
        //fprintf(jsonfile, "    \"WPA+AES-OCB\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_aes_ccm){
        //fprintf(jsonfile, "    \"WPA+AES-CCM\"");
        i++; 
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_leap){
        //fprintf(jsonfile, "    \"WPA+LEAP\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_ttls){
        //fprintf(jsonfile, "    \"WPA+TTLS\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_tls){
        //fprintf(jsonfile, "    \"WPA+TLS\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_peap){
        //fprintf(jsonfile, "    \"WPA+PEAP\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_isakmp){
        //fprintf(jsonfile, "    \"ISAKMP\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_pptp){
        //fprintf(jsonfile, "    \"PPTP\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_fortress){
        //fprintf(jsonfile, "    \"Fortress\"");
        i++;
        listeCrypt[i] = 1;

      }
      if (m->second->cryptset & crypt_keyguard){
        //fprintf(jsonfile, "    \"Keyguard\"");
        i++;
        listeCrypt[i] = 1;

      }
      int j;

      for(j=0;j<=i;j++){
        // if(i == -1)
        //   break;
        switch(j){
        case 0:
          if(listeCrypt[j])
            fprintf(jsonfile, "  \"None\"");
          break;
        case 1:
          if(listeCrypt[j])
            fprintf(jsonfile, "  \"WEP\"");
          break;
        case 2:
          if(listeCrypt[j])
            fprintf(jsonfile, "    \"Layer3\"");
          break;
        case 3:
          if(listeCrypt[j])
            fprintf(jsonfile, "    \"WPA Migration Mode\"");
          break;
        case 4:
          if (listeCrypt[j] ){
            fprintf(jsonfile, "    \"WPA Migration Mode\"");
          }

          break;
        case 5:
          if (listeCrypt[j]){
            fprintf(jsonfile, "   \"WEP40\"");
          }

          break;
        case 6:
          if (listeCrypt[j]){
            fprintf(jsonfile, "   \"WEP40\"");
          }
          break;
        case 7:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WEP104\"");
          }
          break;
        case 8:

          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+PSK\"");
          }
          break;
        case 9:

          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+TKIP\"");
          }
          break;
        case 10:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+AES-OCB\"");
          }
        case 11:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+AES-CCM\"");
          }
          break;
        case 12:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+LEAP\"");
          }
        case 13:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+TTLS\"");
          }
          break;
        case 14:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+TLS\"");
          }
          break;
        case 15:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+PEAP\"");
          }
        case 16:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"ISAKMP\"");
          }
          break;
        case 17:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"PPTP\"");
          }
          break;
        case 18:
          if (listeCrypt[j] ){
            fprintf(jsonfile, "    \"Fortress\"");
          }
          break;
        case 19:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"Keyguard\"");
          }
          break;
        default:
          break;
        }
        if(j < i)
          fprintf(jsonfile, ",");
      }
      fprintf(jsonfile, " ],\n");
      ssidnum++;

    }
    fprintf(jsonfile, " \"Max Seen\"   : %d,\n", net->snrdata.maxseenrate * 100);

    int listeCarrier[8];
    int i;
    for(i=0;i<8;i++)
      listeCarrier[i]=0;


    fprintf(jsonfile, " \"Carrier\"    : [");
    i = -1;
    if (net->snrdata.carrierset & (1 << (int) carrier_80211b))
      {
        i++;
        listeCarrier[i] = 1;
      }

    if (net->snrdata.carrierset & (1 << (int) carrier_80211bplus))
      {
        i++;
        listeCarrier[i] = 1;
      }
    if (net->snrdata.carrierset & (1 << (int) carrier_80211a))
      {
        i++;
        listeCarrier[i] = 1;
      }
    if (net->snrdata.carrierset & (1 << (int) carrier_80211g))
      {
        i++;
        listeCarrier[i] = 1;
      }
    if (net->snrdata.carrierset & (1 << (int) carrier_80211fhss))
      {
        i++;
        listeCarrier[i] = 1;
      }
    if (net->snrdata.carrierset & (1 << (int) carrier_80211dsss))
      {
        i++;
        listeCarrier[i] = 1;
      }
    if (net->snrdata.carrierset & (1 << (int) carrier_80211n20))
      {
        i++;
        listeCarrier[i] = 1;
      }
    if (net->snrdata.carrierset & (1 << (int) carrier_80211n40))
      {
        i++;
        listeCarrier[i] = 1;
      }

    int j;

    for(j=0;j<=i;j++){
      switch(j){
      case 0:
        if (listeCarrier[j])
          fprintf(jsonfile, " \"IEEE 802.11b\"");
        break;
      case 1:
        if (listeCarrier[j])
          fprintf(jsonfile, " \"IEEE 802.11b+\"");
        break;
      case 2:
        if (listeCarrier[j])
          fprintf(jsonfile, " \"IEEE 802.11a\"");
        break;
      case 3:
        if ((net->snrdata.carrierset & (1 << (int) carrier_80211g)) & listeCarrier[j])
          fprintf(jsonfile, " \"IEEE 802.11g\"");
        break;
      case 4:
        if (listeCarrier[j])
          fprintf(jsonfile, " \"IEEE 802.11 FHSS\"");
        break;
      case 5:
        if (listeCarrier[j])
          fprintf(jsonfile, " \"IEEE 802.11 DSSS\"");
        break;
      case 6:
        if( listeCarrier[j])
          fprintf(jsonfile, " \"IEEE 802.11n 20MHz\"");
        break;
      case 7:
        if( listeCarrier[j])
          fprintf(jsonfile, " \"IEEE 802.11n 40MHz\"");
        break;
      }
      if(j < i)
        fprintf(jsonfile, ",");
    }
    fprintf(jsonfile, " ],\n");

    int listeEnco[5];
    i = 0;
    for(i=0;i<5;i++)
      listeEnco[i] = 0;
    i = -1;
    if (net->snrdata.encodingset & (1 << (int) encoding_cck)){
      i++;
      listeEnco[i] = 1;
    }
    if (net->snrdata.encodingset & (1 << (int) encoding_pbcc)){
      i++;
      listeEnco[i] = 1;
    }
    if (net->snrdata.encodingset & (1 << (int) encoding_ofdm)){
      i++;
      listeEnco[i] = 1;
    }

    if (net->snrdata.encodingset & (1 << (int) encoding_dynamiccck)){
      i++;
      listeEnco[i] = 1;
    }

    if (net->snrdata.encodingset & (1 << (int) encoding_gfsk)){
      i++;
      listeEnco[i] = 1;
      if(j < i)
        fprintf(jsonfile, ",");
    }

    fprintf(jsonfile, " \"Enconding\"    : [");

    for(j=0;j<i;j++){
      switch(j){
      case 0:
        if (listeEnco[j])
          fprintf(jsonfile, " \"CCK\",\n");
        break;
      case 1:
        if(listeEnco[j])
          fprintf(jsonfile, " \"PBCC\",\n");
        break;
      case 2:
        if(listeEnco[j])
          fprintf(jsonfile, " \"OFDM\",\n");
        break;
      case 3:
        if(listeEnco[j])
          fprintf(jsonfile, " \"Dynamic CCK-OFDM\",\n");
        break;
      case 4:
        if(listeEnco[j])
          fprintf(jsonfile, " GFSK,\n");
        break;
      }

    }
    fprintf(jsonfile, " ],\n");

    fprintf(jsonfile, " \"LLC\"        : %d,\n", net->llc_packets);
    fprintf(jsonfile, " \"Data\"       : %d,\n", net->data_packets);
    fprintf(jsonfile, " \"Crypt\"      : %d,\n", net->crypt_packets);
    fprintf(jsonfile, " \"Fragments\"  : %d,\n", net->fragments);
    fprintf(jsonfile, " \"Retries\"    : %d,\n", net->retries);
    fprintf(jsonfile, " \"Total\"      : %d,\n", net->llc_packets + net->data_packets);
    fprintf(jsonfile, " \"Datasize\"   : %llu",
            (long long unsigned int) net->datasize);

    if (net->gpsdata.gps_valid) {
      fprintf(jsonfile, " \"Min Pos\"    : \"at %f Lon %f Alt %f Spd %f\",\n", 
              net->gpsdata.min_lat, net->gpsdata.min_lon,
              net->gpsdata.min_alt, net->gpsdata.min_spd);
      fprintf(jsonfile, " \"Max Pos\"    : \"Lat %f Lon %f Alt %f Spd %f\",\n", 
              net->gpsdata.max_lat, net->gpsdata.max_lon,
              net->gpsdata.max_alt, net->gpsdata.max_spd);
      fprintf(jsonfile, " \"Peak Pos\"   : \"Lat %f Lon %f Alt %f\"\n", 
              net->snrdata.peak_lat, net->snrdata.peak_lon,
              net->snrdata.peak_alt);
      fprintf(jsonfile, " \"Avg Pos\"    : \"AvgLat %f AvgLon %f AvgAlt %f\"\n",
              net->gpsdata.aggregate_lat, net->gpsdata.aggregate_lon, 
              net->gpsdata.aggregate_alt);
    }


    if (net->guess_ipdata.ip_type > ipdata_factoryguess && 
        net->guess_ipdata.ip_type < ipdata_group) {
      string iptype;
      fprintf(jsonfile,",");
      switch (net->guess_ipdata.ip_type) {
      case ipdata_udptcp:
        iptype = "UDP/TCP";
        break;
      case ipdata_arp:
        iptype = "ARP";
        break;
      case ipdata_dhcp:
        iptype = "DHCP";
        break;
      default:
        iptype = "Unknown";
        break;
      }

      fprintf(jsonfile, " \"IP Type\"    : %s,\n", iptype.c_str());
      fprintf(jsonfile, " \"IP Block\"   : %s,\n", 
              inet_ntoa(net->guess_ipdata.ip_addr_block));
      fprintf(jsonfile, " \"IP Netmask\" : %s,\n", 
              inet_ntoa(net->guess_ipdata.ip_netmask));
      fprintf(jsonfile, " \"IP Gateway\" : %s,\n", 
              inet_ntoa(net->guess_ipdata.ip_gateway));

      fprintf(jsonfile, " \"Last BSSTS\" : %llu\n", 
              (long long unsigned int) net->bss_timestamp);

    }

    fprintf(jsonfile,"}\n");
    fprintf(jsonfile,"}\n");
    fprintf(jsonfile,"}\n");
    fprintf(jsonfile,"}");
    if((x != finalIte) & (x != tracknet.end()))
      fprintf(jsonfile,",");
  }
  fprintf(jsonfile,"]");


  fflush(jsonfile);
  
  fclose(jsonfile);

  jsonfile = NULL;

  if (rename(tempname.c_str(), fname.c_str()) < 0) {
    _MSG("Failed to rename nettxt temp file " + tempname + " to " + fname + ":" +
         string(strerror(errno)), MSGFLAG_ERROR);
    return -1;
  }

  dumped_frames = netnum;

  return 1;

}


