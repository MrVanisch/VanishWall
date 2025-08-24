from enum import Enum
from typing import List, Optional

class ThreatType(Enum):
    """Typy wykrywanych zagrożeń"""
    PORT_SCAN = "Port Scan"
    SYN_FLOOD = "SYN Flood"
    UDP_FLOOD = "UDP Flood"
    ICMP_FLOOD = "ICMP Flood"
    DOS_ATTACK = "DoS Attack"
    DDOS_ATTACK = "DDoS Attack"
    BRUTE_FORCE = "Brute Force"
    SUSPICIOUS_ACTIVITY = "Suspicious Activity"

class ServiceType(Enum):
    """Rozszerzona lista usług sieciowych z lepszą detekcją"""
    
    # Web services
    HTTP = ("HTTP", [80, 8080, 8000, 8008, 8081, 9080, 8090, 3000])
    HTTPS = ("HTTPS", [443, 8443, 9443, 8834, 10443])
    
    # Remote access
    SSH = ("SSH", [22, 2222, 2200])
    TELNET = ("Telnet", [23])
    RDP = ("RDP", [3389])
    VNC = ("VNC", [5900, 5901, 5902, 5903, 5904, 5905])
    
    # File transfer
    FTP = ("FTP", [21, 20, 990, 989])
    SFTP = ("SFTP", [22, 115])
    FTPS = ("FTPS", [990, 989])
    
    # Email services
    SMTP = ("SMTP", [25, 587, 465, 2525])
    IMAP = ("IMAP", [143, 993])
    POP3 = ("POP3", [110, 995])
    
    # DNS and network
    DNS = ("DNS", [53])
    DHCP = ("DHCP", [67, 68])
    NTP = ("NTP", [123])
    SNMP = ("SNMP", [161, 162])
    
    # Databases
    MYSQL = ("MySQL", [3306])
    POSTGRESQL = ("PostgreSQL", [5432])
    MONGODB = ("MongoDB", [27017, 27018, 27019])
    REDIS = ("Redis", [6379])
    MSSQL = ("MS SQL", [1433, 1434])
    ORACLE = ("Oracle", [1521, 1522])
    
    # Microsoft services
    SMB = ("SMB/CIFS", [445, 139])
    NETBIOS = ("NetBIOS", [137, 138, 139])
    LDAP = ("LDAP", [389, 636, 3268, 3269])
    KERBEROS = ("Kerberos", [88])
    
    # Development
    GIT = ("Git", [9418])
    SVN = ("SVN", [3690])
    
    # Monitoring
    PROMETHEUS = ("Prometheus", [9090])
    GRAFANA = ("Grafana", [3000])
    ZABBIX = ("Zabbix", [10050, 10051])
    ELASTICSEARCH = ("Elasticsearch", [9200, 9300])
    KIBANA = ("Kibana", [5601])
    
    # VPN/Tunneling
    OPENVPN = ("OpenVPN", [1194])
    PPTP = ("PPTP", [1723])
    L2TP = ("L2TP", [1701])
    IPSEC = ("IPSec", [500, 4500])
    WIREGUARD = ("WireGuard", [51820])
    
    # Media/Gaming
    RTSP = ("RTSP", [554])
    SIP = ("SIP", [5060, 5061])
    MINECRAFT = ("Minecraft", [25565])
    STEAM = ("Steam", [27015, 27036])
    
    # Proxy/Load Balancer
    PROXY = ("Proxy", [8080, 3128, 1080, 8888])
    NGINX = ("Nginx", [80, 443, 8080])
    APACHE = ("Apache", [80, 443, 8080])
    
    # Common application ports
    TOMCAT = ("Tomcat", [8080, 8443, 9090])
    JENKINS = ("Jenkins", [8080, 8443])
    DOCKER = ("Docker", [2375, 2376])
    KUBERNETES = ("Kubernetes", [6443, 8080, 10250])
    
    # Backup/Storage
    RSYNC = ("Rsync", [873])
    NFS = ("NFS", [2049])
    
    # High ports for applications
    EPHEMERAL = ("Ephemeral", list(range(32768, 65536)))  # Linux ephemeral range
    HIGH_PORTS = ("High Ports", list(range(1024, 32768)))
    
    # Unknown/Other
    UNKNOWN = ("Unknown", [])

    def __init__(self, service_name: str, ports: List[int]):
        self.service_name = service_name
        self.ports = ports

    @classmethod
    def get_service_by_port(cls, port: int) -> 'ServiceType':
        """Zwraca typ usługi na podstawie portu z lepszą klasyfikacją"""
        if port <= 0:
            return cls.UNKNOWN
            
        # Sprawdź dokładne dopasowanie najpierw
        for service in cls:
            if service != cls.EPHEMERAL and service != cls.HIGH_PORTS and service != cls.UNKNOWN:
                if port in service.ports:
                    return service
        
        # Klasyfikacja na podstawie zakresu portów
        if 1 <= port <= 1023:
            return cls.UNKNOWN  # Well-known ports nie znalezione wyżej
        elif 1024 <= port <= 32767:
            return cls.HIGH_PORTS
        elif port >= 32768:
            return cls.EPHEMERAL
        
        return cls.UNKNOWN

    def is_critical_service(self) -> bool:
        """Sprawdza czy usługa jest krytyczna (wymagająca szczególnej ochrony)"""
        critical_services = {
            self.SSH, self.RDP, self.TELNET, self.FTP, self.MYSQL, 
            self.POSTGRESQL, self.MSSQL, self.MONGODB, self.REDIS,
            self.LDAP, self.SMB, self.NETBIOS
        }
        return self in critical_services

    def is_web_service(self) -> bool:
        """Sprawdza czy to usługa webowa"""
        web_services = {
            self.HTTP, self.HTTPS, self.NGINX, self.APACHE, self.TOMCAT
        }
        return self in web_services

    def get_typical_protocols(self) -> List[str]:
        """Zwraca typowe protokoły dla tej usługi"""
        protocol_map = {
            self.HTTP: ["TCP"],
            self.HTTPS: ["TCP"],
            self.SSH: ["TCP"],
            self.FTP: ["TCP"],
            self.DNS: ["UDP", "TCP"],
            self.DHCP: ["UDP"],
            self.NTP: ["UDP"],
            self.SNMP: ["UDP"],
            self.SIP: ["UDP", "TCP"],
            self.OPENVPN: ["UDP", "TCP"],
        }
        return protocol_map.get(self, ["TCP", "UDP"])

class AttackPattern:
    """Wzorce ataków dla lepszej detekcji"""
    
    # Port scan patterns
    SEQUENTIAL_SCAN = "sequential"  # 22, 23, 24, 25...
    COMMON_PORTS_SCAN = "common_ports"  # 22, 80, 443, 3389...
    RANDOM_SCAN = "random"  # losowe porty
    
    # Traffic patterns
    BURST_TRAFFIC = "burst"  # nagły wzrost ruchu
    SUSTAINED_TRAFFIC = "sustained"  # ciągły wysoki ruch
    PERIODIC_TRAFFIC = "periodic"  # regularny ruch (bot)
    
    @staticmethod
    def detect_scan_pattern(ports: List[int]) -> str:
        """Wykrywa wzorzec skanowania portów"""
        if len(ports) < 3:
            return AttackPattern.RANDOM_SCAN
            
        sorted_ports = sorted(ports)
        
        # Sprawdź czy porty są sekwencyjne
        sequential_count = 0
        for i in range(1, len(sorted_ports)):
            if sorted_ports[i] - sorted_ports[i-1] <= 3:
                sequential_count += 1
        
        if sequential_count / len(sorted_ports) > 0.7:
            return AttackPattern.SEQUENTIAL_SCAN
        
        # Sprawdź czy to popularne porty
        common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306}
        common_count = sum(1 for port in ports if port in common_ports)
        
        if common_count / len(ports) > 0.5:
            return AttackPattern.COMMON_PORTS_SCAN
            
        return AttackPattern.RANDOM_SCAN