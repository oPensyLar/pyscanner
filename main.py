from netaddr import IPNetwork
import dns.resolver
import requests
import socket
import export_csv
import concurrent.futures


def parse_result(cols, dats_vector):
    class_csv = export_csv.ToCsv()
    class_csv.export_csv("nslookup.csv", cols, dats_vector)
    return 0x0


def http_get(hst, ports):

    ret_data = []
    resp = None
    for port in ports:

        if port == 443:
            protocol = "https"

        else:
            protocol = "http"

        try:
            url = protocol + "://" + hst + ":" + str(port)
            resp = requests.get(url, verify=False)
            http_code = resp.status_code

        except requests.exceptions.ConnectionError:
            if resp is None:
                http_code = "N/A"
            else:
                if port == 80:
                    http_code = "N/A"

                else:
                    http_code = resp.status_code

        dat_obj = {"host": hst, "port": port, "code": http_code}
        ret_data.append(dat_obj)

    return ret_data


def parse_scan(host_name, ports):
    array_result = []

    for c_type in ports:
        if ports[c_type] is not None:
            dict_result = {"type": c_type, "count_ports": len(ports[c_type])}
            array_result.append(dict_result)

    count_ports_max = 0x0
    real_type = None
    for c_result in array_result:
        if count_ports_max is 0x0:
            count_ports_max = c_result["count_ports"]

        else:
            if count_ports_max < c_result["count_ports"]:
                count_ports_max = c_result["count_ports"]
                real_type = c_result["type"]

    return real_type


def dns_resolver(ip_addr):
    my_resolver = dns.resolver.Resolver()
    nam = None

    try:
        answer = my_resolver.resolve_address(ip_addr)

    except dns.exception.Timeout:
        return None

    except dns.resolver.NXDOMAIN:
        return None

    for g in answer.response.answer:
        for a in g.items:
            nam = a.target
            return str(nam)


def test_open_port(hst, ports):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    open_ports = []

    for port in ports:
        server_address = (hst, port)

        try:
            s.connect(server_address)
            open_ports.append(port)

        except TimeoutError:
            continue

        except OSError:
            continue

    s.close()

    return open_ports


def scan_ports(hst):
    total_ports = {"web": None, "linux": None, "win": None, "db": None, "proxy": None}
    result = {"host": hst, "up": "Dead", "type": None}

    # firebird 3050
    # mysql 3306
    db_ports = [3050, 3306]
    web_ports = [80, 443]
    proxy_ports = [8080, 3128]
    win_ports = [3389, 445, 135]
    linux_ports = [22]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        print("[+] Scanning " + hst)
        web_scan = executor.submit(test_open_port, hst, web_ports)
        proxy_scan = executor.submit(test_open_port, hst, proxy_ports)
        win_scan = executor.submit(test_open_port, hst, win_ports)
        linux_scan = executor.submit(test_open_port, hst, linux_ports)
        db_scan = executor.submit(test_open_port, hst, db_ports)

        web_result = web_scan.result()

        if len(web_result) > 0x0:
            total_ports["web"] = web_result
            result["up"] = "Live"

        proxy_result = proxy_scan.result()

        if len(proxy_result) > 0x0:
            total_ports["proxy"] = proxy_result
            result["up"] = "Live"

        win_result = win_scan.result()

        if len(win_result) > 0x0:
            total_ports["win"] = win_ports
            result["up"] = "Live"

        linux_result = linux_scan.result()

        if len(linux_result) > 0x0:
            total_ports["linux"] = linux_ports
            result["up"] = "Live"

        db_result = db_scan.result()

        if len(db_result) > 0x0:
            total_ports["linux"] = linux_ports
            result["up"] = "Live"

        result["type"] = parse_scan(hst, total_ports)

        return result


def is_cidr(input):
    if input.find("/") > 0x0:
        return True

    else:
        return False


def deploy():
    with open("srv.lst", "r") as fp:
        colums_name = ["dns", "ip", "status", "type"]
        all_hosts = []
        lines = fp.readlines()

        for ip_addr in lines:
            ip_addr = ip_addr.replace("\n", "")
            ip_addr = ip_addr.replace("\r", "")

            one_host = {"dns": None, "ip": None, "status": None, "type": None}

            if is_cidr(ip_addr) is False:
                one_host["ip"] = ip_addr
                one_host["dns"] = dns_resolver(ip_addr)
                results = scan_ports(ip_addr)
                one_host["status"] = results["up"]
                one_host["type"] = results["type"]
                all_hosts.append(one_host)

            else:
                for ip in IPNetwork(ip_addr):

                    if ip.words[3] is 0:
                        continue

                    ip = str(ip)
                    one_host["dns"] = dns_resolver(ip)
                    one_host["ip"] = ip
                    results = scan_ports(ip)
                    one_host["status"] = results["up"]
                    one_host["type"] = results["type"]
                    all_hosts.append(one_host)

        parse_result(colums_name, all_hosts)


deploy()
