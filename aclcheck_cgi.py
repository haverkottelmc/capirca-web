#!/usr/bin/env python

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

capirca_base = '/home/charl/capirca/'
import sys
sys.path.append(capirca_base)

from cgi import FieldStorage
from dns import resolver, reversename
from glob import glob
from json import dumps
from lib import aclcheck, policy, nacaddr, naming
from os import path
from traceback import format_exc

class AclCheckCgiException(Exception):
  pass

class AclCheckCgi:
  def __init__(self, capirca_base):
    self.capirca_base = capirca_base
    self.definitions = naming.Naming(capirca_base + 'def')

  def check_acl(self, policy_file, protocol, source_address, source_port, destination_address, destination_port):
    policy_dir = self.capirca_base + 'policies'
    policy_path = policy_dir + '/' + policy_file + '.pol'
    if path.dirname(policy_path) != policy_dir:
      raise AclCheckCgiException('Policy path does not exist within policy directory.')
    policy_object = policy.ParsePolicy(open(self.capirca_base + 'policies/' + policy_file + '.pol').read(), self.definitions, True, self.capirca_base)
    result = str(aclcheck.AclCheck(policy_object, proto=protocol, src=source_address, sport=source_port, dst=destination_address, dport=destination_port)) + '\n'
    for header in policy_object.headers:
      for comment in header.comment:
        result += '\n' + comment

    result_data = {}
    result_data['protocol'] = protocol
    result_data['source_address'] = source_address
    result_data['source_port'] = source_port
    result_data['destination_address'] = destination_address
    result_data['destination_port'] = destination_port
    result_data['policy_file'] = policy_file
    result_data['result'] = result

    return result_data

  def check_utnet(self, protocol, address1, port1, address2, port2):
    utnet = self.definitions.GetNetAddr('UTNET')

    ip1 = nacaddr.IP(address1)
    ip2 = nacaddr.IP(address2)

    if type(ip1) is not type(ip2):
      raise AclCheckCgiException('Both addresses need to be of the same type.')

    ip1_is_internal = bool(sum([range.Contains(ip1) for range in utnet]))
    ip2_is_internal = bool(sum([range.Contains(ip2) for range in utnet]))

    if ip1_is_internal and ip2_is_internal:
      raise AclCheckCgiException('Both addresses belong inside the UTNET.')
    elif ip1_is_internal:
      internal_address = address1
      external_address = address2
      internal_port = port1
      external_port = port2
    elif ip2_is_internal:
      internal_address = address2
      external_address = address1
      internal_port = port2
      external_port = port1
    else:
      raise AclCheckCgiException('Both addresses belong outside the UTNET.')

    ip_version = ip1.__class__.__name__[2:4]
    results = []
    results.append(self.check_acl('utwente-inbound_' + ip_version, protocol, external_address, external_port, internal_address, internal_port))
    results.append(self.check_acl('utwente-outbound_' + ip_version, protocol, internal_address, internal_port, external_address, external_port))
    return results

  def check_all(self, action, policy_file, protocols, addresses1, ports1, addresses2, ports2):
    ipv4_addresses1, ipv6_addresses1 = self.resolve_addresses(addresses1)
    ipv4_addresses2, ipv6_addresses2 = self.resolve_addresses(addresses2)

    if len(ipv4_addresses1) == 0 and len(ipv4_addresses2) == 0 and len(ipv6_addresses1) == 0 and len(ipv6_addresses2) == 0:
      raise AclCheckCgiException('No hosts have been specified.')

    if len(ipv4_addresses1) > 0 and len(ipv4_addresses2) == 0 and len(ipv6_addresses2) == 0:
      ipv4_addresses2.append('any')
    elif len(ipv4_addresses2) > 0 and len(ipv4_addresses1) == 0 and len(ipv6_addresses1) == 0:
      ipv4_addresses1.append('any')

    if len(ipv6_addresses1) > 0 and len(ipv6_addresses2) == 0 and len(ipv4_addresses2) == 0:
      ipv6_addresses2.append('any')
    elif len(ipv6_addresses2) > 0 and len(ipv6_addresses1) == 0 and len(ipv4_addresses1) == 0:
      ipv6_addresses1.append('any')
    
    results = self.check_all_type(action, policy_file, protocols, ipv4_addresses1, ports1, ipv4_addresses2, ports2)
    results += self.check_all_type(action, policy_file, protocols, ipv6_addresses1, ports1, ipv6_addresses2, ports2)

    return results

  def check_all_type(self, action, policy_file, protocols, addresses1, ports1, addresses2, ports2):
    results = []

    for protocol in protocols.split():
      for address1 in addresses1:
        for address2 in addresses2:
          if protocol == 'icmp':
            if action == 'check_utnet':
              results += self.check_utnet(protocol, address1, 0, address2, 0)
            elif action == 'check_acl':
              results.append(self.check_acl(policy_file, protocol, address1, 0, address2, 0))
          else:
            if ports1 is None or ports2 is None:
              raise AclCheckCgiException('No ports have been specified for TCP / UDP.')
            for port1 in ports1.split():
              for port2 in ports2.split():
                if action == 'check_utnet':
                  results += self.check_utnet(protocol, address1, port1, address2, port2)
                elif action == 'check_acl':
                  results.append(self.check_acl(policy_file, protocol, address1, port1, address2, port2))

    return results

  def resolve_addresses(self, addresses):
    ipv4_addresses = []
    ipv6_addresses = []

    if addresses is not None and addresses != 'any':
      for address in addresses.split():
        try:
          ip = nacaddr.IP(address)
          if isinstance(ip, nacaddr.IPv4):
            ipv4_addresses.append(address)
          elif isinstance(ip, nacaddr.IPv6):
            ipv6_addresses.append(address)
        except ValueError:
          try:
            ipv4_addresses += [str(answer) for answer in resolver.query(address, 'a')]
          except resolver.NoAnswer:
            pass
          try:
            ipv6_addresses += [str(answer) for answer in resolver.query(address, 'aaaa')]
          except resolver.NoAnswer:
            pass

    return (ipv4_addresses, ipv6_addresses)

  def reverse_dns(self, ip_address):
    return str(resolver.query(reversename.from_address(ip_address), 'PTR')[0]).rstrip('.')

  def policies(self):
    return sorted([path.splitext(path.basename(policy_file))[0] for policy_file in glob(self.capirca_base + 'policies/*.pol')])

  def handle_request(self):
    field_storage = FieldStorage()
    action = field_storage.getvalue('action')

    try:
      if action == 'policies':
        result = self.policies()
      elif action == 'check_acl':
        policy_file = field_storage.getvalue('policy_file')
        protocols = field_storage.getvalue('protocols')
        source_addresses = field_storage.getvalue('source_addresses')
        source_ports = field_storage.getvalue('source_ports')
        destination_addresses = field_storage.getvalue('destination_addresses')
        destination_ports = field_storage.getvalue('destination_ports')
        result = self.check_all(action, policy_file, protocols, source_addresses, source_ports, destination_addresses, destination_ports)
      elif action == 'check_utnet':
        protocols = field_storage.getvalue('protocols')
        addresses1 = field_storage.getvalue('addresses1')
        ports1 = field_storage.getvalue('ports1')
        addresses2 = field_storage.getvalue('addresses2')
        ports2 = field_storage.getvalue('ports2')
        result = self.check_all(action, None, protocols, addresses1, ports1, addresses2, ports2)
      elif action == 'reverse_dns':
        address = field_storage.getvalue('address')
        try:
          result = self.reverse_dns(address)
        except:
          result = ''
    except Exception as e:
      result = format_exc()

    print 'Content-type: application/json\n\n'
    print dumps(result)

acl_check_cgi = AclCheckCgi(capirca_base)
acl_check_cgi.handle_request()
