"""PiOS firewall service: the only component that may change nftables. Narrow, validated, self-reverting."""
FIREWALL_API = 1
TABLE = "pios_fw"
