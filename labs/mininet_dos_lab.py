#!/usr/bin/env python3
# Mininet lab to test Ryu DoS Guard

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import argparse


def build_topology(controller_ip: str, controller_port: int, hosts: int = 4, scenario: str = 'none', duration: int = 20):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True, autoStaticArp=True)

    info('*** Adding remote controller\n')
    c0 = RemoteController('c0', ip=controller_ip, port=controller_port)
    net.addController(c0)

    info('*** Adding switch\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    info('*** Adding hosts\n')
    host_list = []
    for i in range(1, hosts + 1):
        h = net.addHost(f'h{i}')
        host_list.append(h)
        net.addLink(h, s1)

    info('*** Starting network\n')
    net.start()

    info('*** Basic connectivity test\n')
    net.pingAll(timeout=1)

    if scenario and scenario != 'none':
        info('*** Running scenario: %s\n' % scenario)
        try:
            h1 = net.get('h1')
            h2 = net.get('h2')
            victim = h2.IP()
            if scenario == 'normal':
                h1.cmd('ping -i 0.2 -c 20 %s &' % victim)
            elif scenario == 'syn_flood':
                h1.cmd('timeout %d hping3 -S -p 80 --flood -q %s &' % (duration, victim))
            elif scenario == 'udp_flood':
                h1.cmd('timeout %d hping3 -2 -p 80 --flood -q %s &' % (duration, victim))
            elif scenario == 'portscan':
                h1.cmd('for p in $(seq 1 200); do hping3 -S -p $p -c 1 %s >/dev/null 2>&1; done &' % victim)
            elif scenario == 'mixed':
                h1.cmd('ping -i 0.2 -c %d %s &' % (duration * 5, victim))
                h1.cmd('timeout %d hping3 -S -p 80 --flood -q %s &' % (duration, victim))
        except Exception as e:
            info('Scenario error: %s\n' % e)

    info('''\nLab ready. Suggestions:\n'
    - Normal traffic: h1 ping -i 0.2 -c 20 h2\n'
    - DoS (if hping3 installed): h1 hping3 -S -p 80 --flood -V h2\n'
    - HTTP flood example: h1 hping3 -p 80 --flood -d 120 -2 h2\n'
    - Throughput: h2 iperf3 -s & ; h1 iperf3 -c $(h2 IP) -u -b 50M -t 10\n'
    - View flows: sh ovs-ofctl -O OpenFlow13 dump-flows s1\n\n''')

    CLI(net)

    info('*** Stopping network\n')
    net.stop()


def main():
    parser = argparse.ArgumentParser(description='Mininet DoS Guard Lab')
    parser.add_argument('--controller-ip', default='127.0.0.1', help='Ryu controller IP')
    parser.add_argument('--controller-port', type=int, default=6653, help='Ryu controller OpenFlow port')
    parser.add_argument('--hosts', type=int, default=4, help='Number of hosts')
    parser.add_argument('--scenario', choices=['none', 'normal', 'syn_flood', 'udp_flood', 'portscan', 'mixed'], default='none', help='Traffic scenario to run')
    parser.add_argument('--duration', type=int, default=20, help='Scenario duration seconds (where applicable)')
    args = parser.parse_args()

    setLogLevel('info')
    build_topology(args.controller_ip, args.controller_port, hosts=args.hosts, scenario=args.scenario, duration=args.duration)


if __name__ == '__main__':
    main()
