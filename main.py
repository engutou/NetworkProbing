#! python

from scapy.all import *
from craft_packets import *
import time

default_dport = 33433


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


def iffinder(dst_list, dport=default_dport, count=1):
    """
    :param dst_list:
    :param dport:
    :param count:
    :return:
    """
    c = count
    while c > 0:
        pkts = [probe_udp(dst=dst, dport=dport, count=1)[0] for dst in dst_list]
        ans, unans = sr(pkts, timeout=1, verbose=0)
        if len(ans) > 0:
            for r in ans.res:
                target_ip = r[0].sprintf('%IP.dst%')
                answer_ip = r[1].sprintf('%IP.src%')
                print('iffinder:\ttarget_ip=%s\tanswer_ip=%s\n' % (target_ip, answer_ip))
        c -= 1


def ping(dst, proto='icmp', dport=default_dport, count=1):
    """
    普通版本的ping，即使对目标IP的探测次数>count<大于1，每次也只发送一个探测包
    :param dst: 目的IP
    :param proto: 协议类型，{icmp, tcp, udp}
    :param dport: 目的端口
    :param count: 探测次数
    :return result: string
    """
    # 一次性产生>count<个探测包
    if proto.lower() == 'icmp':
        pkts = probe_icmp(dst=dst, count=count)
    elif proto.lower() == 'tcp':
        pkts = probe_tcp(dst=dst, dport=dport, count=count)
    elif proto.lower() == 'udp':
        pkts = probe_udp(dst=dst, dport=dport, count=count)
    else:
        print('Unknown protocol...')
        return None

    result = ''
    for i in range(0, count):
        ans = sr1(pkts[i], timeout=1, verbose=0)
        if ans:
            ans_str = ans.sprintf('ttl=%IP.ttl%\tanswer_ip=%IP.src%')
            result += '%d:\t%s\n' % (i + 1, ans_str)
        else:
            result += '%d:\ttime out\n' % (i + 1)
    return result


def traceroute(dst, proto='icmp', dport=default_dport, ttl=range(1, 31)):
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
    return result


def traceroutefast(dst, proto='icmp', dport=default_dport, ttl=range(1, 31), ostr=True):
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


def rtt_strip(dsts, n_strips=1, inter_gap=100):
    """
    向一系列目标IP地址发送包组，测量其rtt时延
    :param dsts: list of destinations
        目标IP地址列表
    """
    pass


if __name__ == "__main__":
    uestc = '202.112.14.178'
    local = ['192.168.1.1', '202.97.85.14', '202.97.37.74']
    for d in local:
        print(ping(d, proto='udp', count=2))
    iffinder(local, count=4)

    # print('====ICMP ping %s\n' % uestc + ping(uestc, proto='icmp', count=4))
    # print('====TCP ping\n' + ping(uestc, proto='tcp', dport=80, count=4))
    # print('====UDP ping\n' + ping(uestc, proto='udp', count=4))

    # print('====ICMP traceroute\n' + traceroute(uestc, proto='icmp', ttl=range(1, 21)))
    # print('====TCP traceroute\n' + traceroute(uestc, proto='tcp', dport=80, ttl=range(1, 21)))
    # print('====UDP traceroute\n' + traceroute(uestc, proto='udp', ttl=range(1, 21)))

    # for h in traceroutefast(uestc, proto='icmp', ttl=range(1, 21), ostr=False):
    #     print(h)




