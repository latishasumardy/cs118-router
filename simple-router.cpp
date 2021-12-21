/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */


#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  /*check ethernet header */
  //std::cerr << "check ethernet header" << std::endl;
  ethernet_hdr* ethHdr = (ethernet_hdr*)packet.data();
  //check destination
  bool flag_match = true;
  static const uint8_t BroadcastEtherAddr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  const uint8_t* my_addr = iface->addr.data();
  const uint8_t* dest_addr = ethHdr->ether_dhost;

  for(int i = 0; i < 6; i++) { // check if broadcast message
    if(dest_addr[i] != BroadcastEtherAddr[i] ) {
      flag_match = false;
      i = 6;
    }
  }

  if (flag_match == false) {
    flag_match = true;

    for(int i = 0; i < 6; i++) { // check if i am the destination
      if(dest_addr[i] != my_addr[i] ) {
        flag_match = false;
        i = 6;
      }
    }

    if(flag_match == false) {
      std::cerr << "packet not destined for this router " << std::endl;
      return;
    }

  }
  

  //check type
  //(following victor's slides)
  if(ethHdr->ether_type != htons(ethertype_ip)) {
    std::cerr << "packet type is not IPv4" << std::endl;
    return;
  }
  //std::cerr << "check ip header" << std::endl;
  /*check ip header*/
  ip_hdr* ipHdr = (ip_hdr*)(packet.data() + sizeof(ethernet_hdr));

  //min length check
  //(following victor's slides)
  if(ipHdr->ip_len < 20) {
    std::cerr << "IP total length field is less than 20" << std::endl;
    return;
  } 

  //ttl field??

  //check checksum
  //(following victor's slides)
  uint16_t initial_checksum = ipHdr->ip_sum;
  ipHdr->ip_sum = 0; 
  uint16_t generated_sum = cksum(ipHdr, sizeof(ip_hdr));

  if(initial_checksum != generated_sum){
    std::cerr << "Checksums do not match" << std::endl;
    return;
  }
  //std::cerr << "check if for one of our interfaces" << std::endl;
  /*check if packet is for one of our interfaces*/
  //(following victor's slides)
  const Interface* My_Interface = findIfaceByIp(ipHdr->ip_dst);
  if(My_Interface != nullptr) { //PACKET IS FOR US
    //std::cerr << "check icmp header" << std::endl;
    if(ipHdr->ip_p == ip_protocol_icmp) { // PACKET IS ICMP
      icmp_hdr* icmpHdr = (icmp_hdr*)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

      //check if icmp checksum is correct
      //(following victor's slides)
      uint16_t initial_icmp_checksum = icmpHdr->icmp_sum;
      icmpHdr->icmp_sum = 0;
      uint16_t generated_icmp_sum = cksum(icmpHdr, packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr));

      if(initial_icmp_checksum != generated_icmp_sum) { 
        std::cerr << "ICMP checksums do not match" << std::endl;
        return;
      }

      //check type of ICMP packet to make sure its an echo
      //(following victor's slides)
      if(icmpHdr->icmp_type != 8) { // not type 8
        std::cerr << "ICMP packet is not an echo" << std::endl;
        return;
      }
      //std::cerr << "send out packet" << std::endl;
      /*Send out packet*/ 
      //(following victor's slides)
      Buffer OutgoingPacket(packet);

      //get new pointers for headers (structure taken from victor's slides)
      ethernet_hdr* new_ethHdr = (ethernet_hdr*)OutgoingPacket.data();
      ip_hdr* new_ipHdr = (ip_hdr*)(OutgoingPacket.data() + sizeof(ethernet_hdr));
      icmp_hdr* new_icmpHdr = (icmp_hdr*)(OutgoingPacket.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

      /*reassign fields*/
      //reassign ethernet header values
      uint8_t original_dest_addr[6];
      for(int i = 0; i < 6; i++) {
        original_dest_addr[i] = new_ethHdr->ether_dhost[i];
      }

      for(int i = 0; i < 6; i++) {
        new_ethHdr->ether_dhost[i] = new_ethHdr->ether_shost[i];
        new_ethHdr->ether_shost[i] = original_dest_addr[i];
      }

      //reassign ip header values
      uint32_t original_ip_dest_addr = new_ipHdr->ip_dst;

      new_ipHdr->ip_dst = new_ipHdr->ip_src;
      new_ipHdr->ip_src = original_ip_dest_addr;

      new_ipHdr->ip_ttl = 64;
      new_ipHdr->ip_sum = 0;
      new_ipHdr->ip_sum = cksum(new_ipHdr, sizeof(ip_hdr));

      //reassign icmp header values
      new_icmpHdr->icmp_type = 0;
      new_icmpHdr->icmp_code = 0;
      new_icmpHdr->icmp_sum = 0;
      new_icmpHdr->icmp_sum = cksum(new_icmpHdr, packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr));

      //std::cerr << "send out packet now" << std::endl;
      sendPacket(OutgoingPacket, iface->name);
      //std::cerr << "finished sending packet" << std::endl;

    } // END PACKET IS ICMP
    else { //not icmp
      std::cerr << "Packet is for us but not ICMP" << std::endl;
      return;
    } 
  } // END PACKET IS FOR US
  else { // FORWARD, PACKET IS NOT FOR US 
    //std::cerr << "forward packet" << std::endl;
    // Check ttl field
    ipHdr->ip_ttl -= 1;
    if (ipHdr->ip_ttl <= 0) { 
      std::cerr << "TTL is 0" << std::endl;
      return;
    }
    // Check routing table to find next hop
    ipHdr->ip_sum = cksum(ipHdr, sizeof(ip_hdr));
    RoutingTableEntry nexthop;
    try {
      nexthop = m_routingTable.lookup(ipHdr->ip_dst);
    } catch(const std::exception& err) {
      std::cerr << "Could not find nexthop in routing table" << std::endl; 
      return; 
    }
    // Look up IP in ARP cache
    const Interface* OutgoingInterface = findIfaceByName(nexthop.ifName);
    auto arpEntry = m_arp.lookup(nexthop.gw);
    
    // Rerequest or send
    if (arpEntry) { // entry is found-- send the packet
      // modify dest/source
      for(int i = 0; i < 6; i++) {
        ethHdr->ether_dhost[i] = arpEntry->mac.data()[i];
        ethHdr->ether_shost[i] = OutgoingInterface->addr.data()[i];
      }
      ethHdr->ether_type = htons(ethertype_ip);
      //send the packet
      sendPacket(packet, nexthop.ifName);
    } else { // entry is not found-- rerequest
      m_arp.queueRequest(nexthop.gw, packet, nexthop.ifName);
    }
    return;
  }  // END FORWARD PACKET SINCE IT'S NOT FOR US


}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
