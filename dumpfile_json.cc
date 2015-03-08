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
    created by Yaker Mahieddine

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

        txtfile = NULL;

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

        if ((txtfile = fopen(fname.c_str(), "w")) == NULL) {
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
        if (txtfile != NULL) {
                Flush();
        }

        txtfile = NULL;

        if (export_filter != NULL)
                delete export_filter;
}


int Dumpfile_Json::Flush(){

  if (txtfile != NULL)
    fclose(txtfile);

  string tempname = fname + ".temp";
  if ((txtfile = fopen(tempname.c_str(), "w")) == NULL) {
    _MSG("Failed to open temporary nettxt file for writing: " +
         string(strerror(errno)), MSGFLAG_ERROR);
    return -1;
  }


  // Get the tracked network and client->ap maps
  const map<mac_addr, Netracker::tracked_network *> tracknet =
    globalreg->netracker->FetchTrackedNets();


  const vector<kis_alert_info *> *alerts =
    globalreg->alertracker->FetchBacklog();
  map<mac_addr, Netracker::tracked_network *>::const_iterator x;
  map<mac_addr, Netracker::tracked_client *>::const_iterator y;

  int netnum = 0;


  for(x = tracknet.begin(); x != tracknet.end();++x){
    netnum++;
    if (export_filter->RunFilter(x->second->bssid, mac_addr(0), mac_addr(0)))
      continue;

    Netracker::tracked_network *net = x->second;

    if(net->type == network_remove)
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
    fprintf(txtfile,"{\n");

    fprintf(txtfile,"\"Network\":%d,\n",netnum);
    fprintf(txtfile,"\"détails\" : {\n");
    fprintf(txtfile, "\"Manuf\"      : \"%s\",\n", net->manuf.c_str());
    fprintf(txtfile, "\"First\"      : \"%.24s\",\n", ctime(&(net->first_time)));
    fprintf(txtfile, "\"Last\"       : \"%.24s\",\n", ctime(&(net->last_time)));
    fprintf(txtfile, "\"Type\"       : \"%s\",\n", ntype.c_str());
    fprintf(txtfile, "\"BSSID\"      : \"%s\",\n", net->bssid.Mac2String().c_str());
    int ssidnum = 1;
    fprintf(txtfile,"\"détail_BSSID\":{\n");
    for (map<uint32_t, Netracker::adv_ssid_data *>::iterator m =
           net->ssid_map.begin(); m != net->ssid_map.end(); ++m) {
      fprintf(txtfile,"\"SSID_num\":%d,\n",ssidnum);
      fprintf(txtfile,"\"SSID_info\":{\n");
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
      fprintf(txtfile, "\"SSID\" :%d,\n", ssidnum);
      fprintf(txtfile, "\"Type\": \"%s\",\n", typestr.c_str());
      fprintf(txtfile, "\"SSID\": \"%s %s\" ,\n", m->second->ssid.c_str(),
              m->second->ssid_cloaked ? "(Cloaked)" : "");



      fprintf(txtfile,"}\n");
    }
    fprintf(txtfile,"}\n");


    fprintf(txtfile,"}\n");
    fprintf(txtfile,"}\n");

  }

}
