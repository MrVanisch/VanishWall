CONFIG = {
    "enable_traffic_monitor": True,
    "enable_bandwidth_limiter": True,
    "enable_syn_flood_protection": True,
    "enable_udp_flood_protection": True,
    "enable_dns_amplification_protection": True,
    "enable_ntp_protection": True,
    "enable_bypass_protection": True,
    "enable_ai_protection": True,
    "BANDWIDTH_LIMIT": 104857600,
    "CHECK_INTERVAL": 10,
    "SYN_LIMIT": 100,
    "CHECK_INTERVAL_SYN": 1,
    "UDP_LIMIT": 200,
    "CHECK_INTERVAL_UDP": 1,
    "NTP_RESPONSE_LIMIT": 50,
    "NTP_SIZE_THRESHOLD": 468,
    "CHECK_INTERVAL_NTP": 10,
    "DNS_RESPONSE_LIMIT": 100,
    "DNS_SIZE_THRESHOLD": 500,
    "CHECK_INTERVAL_DNS": 10,
    "BYPASS_PORTS": [80, 443, 53, 22],
    "CHECK_INTERVAL_BYPASS": 10,
    "THREAT_THRESHOLD": 100,
    "SSH_THRESHOLD": 250,
    "DECAY_FACTOR": 0.9,
    "CHECK_INTERVAL_TRAFFIC": 10,
}
