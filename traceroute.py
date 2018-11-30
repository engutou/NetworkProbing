#! python

from scapy.all import *
import time

from craft_packets import *
from global_config import *


def dst_reached(pkt, dst):
    """
    判断探测包是否抵达目的IP
    :param pkt:
    :param dst:
    :return:
    """
    # todo: 抵达目的IP的条件应该包括“目标端口不可达”的情况
    if pkt.sprintf('%IP.src%') == dst \
            or pkt.sprintf('{ICMP:%ICMP.type%}') in ['echo-reply']:
        return True
    return False


def traceroute(dst, proto='icmp', dport=DefaultDPort, ttl=range(1, 31)):
    if proto.lower() == 'icmp':
        pkts = [probe_icmp(dst=dst, ttl=t)[0] for t in ttl]
    elif proto.lower() == 'tcp':
        pkts = [probe_tcp(dst=dst, dport=dport, ttl=t)[0] for t in ttl]
    elif proto.lower() == 'udp':
        pkts = [probe_tcp(dst=dst, dport=dport, ttl=t)[0] for t in ttl]
    else:
        print('Unknown protocol...')
        return None

    result = ''
    for i in range(len(ttl)):
        t = ttl[i]
        ans = sr1(pkts[i], timeout=1, verbose=0)
        if ans:
            result += 'ttl=%d\t%s\n' % (t, ans.sprintf('%IP.src%'))
            if dst_reached(ans, dst):
                result += 'We have reached our destination\n'
                break
        else:
            result += 'ttl=%d\t*\n' % t
    print('Traceroute %s using %s:' % (dst, proto))
    print(result)
    return result


def traceroutefast(dst, proto='icmp', dport=DefaultDPort, ttl=range(1, 31), ostr=True):
    if proto.lower() == 'icmp':
        pkts = [probe_icmp(dst=dst, ttl=t)[0] for t in ttl]
    else:
        if proto.lower() == 'tcp':
            print('Fast traceroute with tcp is not supported now...')
        elif proto.lower() == 'udp':
            print('Fast traceroute with udp is not supported now...')
        else:
            print('Unknown protocol...')
        return None

    hops = ['*'] * len(ttl)
    ans, unans = sr(pkts, timeout=2, verbose=0)
    if len(ans) > 0:
        for r in ans.res:
            t = int(r[0].sprintf('%IP.ttl%'))
            hops[t-1] = r[1].sprintf('%IP.src%')
            if dst_reached(r[1], dst):
                # 探测包抵达目的IP，添加'-dr'作为标识
                hops[t-1] += '-dr'
    if ostr:
        result = ''
        for h in hops:
            # todo: 以字符形式输出
            pass
        return result
    else:
        return hops


if __name__ == "__main__":
    test = ['202.112.14.178', '202.97.85.14', '202.97.37.74']
    for d in test:
        traceroute(d, proto='icmp', ttl=range(1, 21))

