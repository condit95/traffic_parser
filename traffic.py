import sys
import os
from scapy.all import *
from scapy.layers.http import HTTP

global telnet_var
flag_telnet = False


def check_list(list_telnet):
    list_bufer = []
    last_symbol = list_telnet[0]
    for i, j in zip(list_telnet, list_telnet[1:]):
        if i == j:
            list_bufer.append(i)
    return list_bufer


def rename_file(file):
    part1, part2 = os.path.splitext(file)
    new_file = part1 + part2[1:] + '.pcap'
    os.rename(file, new_file)
    return new_file


def output_traffic(file_name, http, ftp, telnet, output_file):
    with open(output_file, 'a') as file:
        file.write(f'\n\n====================================[{file_name}]====================================\n\n')
        if http:
            file.write('[HTTP]\n' + '\n'.join(http))
        elif ftp:
            # for i in range(len(ftp), 1):
            #     if ftp[i]
            #next(zip(*itertools.groupby(ftp)))
            file.write('[FTP]\n' + '\n'.join(next(zip(*itertools.groupby(ftp)))))
        elif telnet:
            file.write('[TELNET]\n' + '\n'.join(telnet))
        else:
            file.write('\nEmpty\n')


def pars_http(http_pkt):
    req = http_pkt.getlayer('HTTP Request')
    auth = req.Authorization
    if auth and auth.startswith(b'Basic '):
        login_http, password_http = base64_bytes(auth.split(None, 1)[1]).split(b':', 1)
        return [login_http, password_http, http_pkt[IP].src, http_pkt[IP].dst]


def pars_ftp(ftp_pkt):
    raw_ftp = ftp_pkt.sprintf('%Raw.load%')   #после FTP пакета, идет пакет TCP, в котором в пэйлоаде лежит полезная нагрузка прошлого пакета (поэтому получается двойная запись)
    user_ftp = re.findall('(?i)USER (.*)', raw_ftp)
    pswd_ftp = re.findall('(?i)PASS (.*)', raw_ftp)
    if user_ftp:
        return ('Username: ' + user_ftp[0].split('\\', maxsplit=1)[0] + '          ' + str(ftp_pkt.payload))
    elif pswd_ftp:
        return ('Password: ' + pswd_ftp[0].split('\\', maxsplit=1)[0] + '          ' + str(ftp_pkt.payload))


def pars_telnet(telnet_pkt):
    #global flag_telnet
    raw_telnet = telnet_pkt.sprintf('%Raw.load%')
    if raw_telnet and raw_telnet is not None and raw_telnet != '??':
        if '\\r\\n' in raw_telnet:
            return 'razdel' + '     ' + str(telnet_pkt.payload)
        elif len(raw_telnet) == 3:
            string = raw_telnet.replace("'", "")
            return string + '          ' + str(telnet_pkt.payload)
    else:
        return ''


def pars_pcap(pcap_file, output_file):
    traffic_file = ''
    if pcap_file.endswith('.pcapng'):
        traffic_file = PcapNgReader(pcap_file)
    elif pcap_file.endswith('.pcap'):
        traffic_file = PcapReader(pcap_file)
    else:
        try:
            pcap_file = rename_file(pcap_file)
            traffic_file = PcapReader(pcap_file)
        except Exception:
            print(f'[-] Attention! Это не подходящий файл {pcap_file}')
            return
    #     print('[-] Uncorrected expansion file')
    ftp_list = []
    http_list = []
    telnet_list = []
    telnet_data = ''
    #for pkt in sorted(traffic_file, key=lambda ts: ts.time):
    for pkt in traffic_file:
        # tcp = i.getlayer('TCP')
        if pkt.getlayer("TCP"):
            # req = i.getlayer('HTTP Request')
            if pkt.getlayer("HTTP Request"):
                if pars_http(pkt) is not None:
                    login, password, http_src, http_dst = pars_http(pkt)
                    http_list.append("Username: %r - password: %r || source: %r destination: %r" % (login.decode(), password.decode(), http_src, http_dst))
            elif pkt['TCP'].dport == 21:
                payload_ftp = ''
                payload_ftp = pars_ftp(pkt)
                if payload_ftp:
                    ftp_list.append(payload_ftp)
            elif pkt['TCP'].dport == 23 or pkt['TCP'].dport == 3005:
                bufer_telnet_data = pars_telnet(pkt)
                if bufer_telnet_data:
                    telnet_list.append(bufer_telnet_data)
    output_traffic(pcap_file, http_list, ftp_list, telnet_list, output_file)


def main(arguments):
    if arguments[1] == '--f' and arguments[3] == '--output':
        pars_pcap(arguments[2], arguments[4])
    elif arguments[1] == '--d' and arguments[3] == '--output':
        directory = arguments[2]
        for file_on_directory in os.listdir(directory):
            #file_in = directory + file_on_directory
            pars_pcap(os.path.join(directory, file_on_directory), arguments[4])


if __name__ == "__main__":
    main(sys.argv)  # [1] --input, [2] pcap_path, [3] --output, [4]output_path
