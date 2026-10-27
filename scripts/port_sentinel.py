import ctypes
from ctypes import wintypes
import socket

iphlpapi = ctypes.WinDLL('iphlpapi.dll')

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]

TCP_STATE_MAP = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RCVD",
    5: "ESTABLISHED",
    6: "FIN_WAIT1",
    7: "FIN_WAIT2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB"
}

def decode_port(port_dword):
    return ((port_dword >> 8) & 0xFF) | ((port_dword & 0xFF) << 8)

def decode_ip(ip_dword):
    return socket.inet_ntoa(ctypes.c_uint32(ip_dword).value.to_bytes(4, 'little'))

def get_active_tcp_connections():
    table_size = wintypes.DWORD(0)
    # First call to get required buffer size
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(table_size), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    
    buffer = (ctypes.c_byte * table_size.value)()
    connections = []
    
    ret = iphlpapi.GetExtendedTcpTable(buffer, ctypes.byref(table_size), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if ret == 0:
        dw_num_entries = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0]
        row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
        offset = 4 # skip dwNumEntries
        
        for i in range(dw_num_entries):
            row_ptr = ctypes.byref(buffer, offset + (i * row_size))
            row = ctypes.cast(row_ptr, ctypes.POINTER(MIB_TCPROW_OWNER_PID)).contents
            
            connections.append({
                "pid": row.dwOwningPid,
                "state": TCP_STATE_MAP.get(row.dwState, "UNKNOWN"),
                "local_addr": f"{decode_ip(row.dwLocalAddr)}:{decode_port(row.dwLocalPort)}",
                "remote_addr": f"{decode_ip(row.dwRemoteAddr)}:{decode_port(row.dwRemotePort)}"
            })
            
    return connections

if __name__ == '__main__':
    print("[Port-Sentinel] Windows Low-Level TCP Port & Connection Auditor")
    conns = get_active_tcp_connections()
    print(f"Total active TCP sockets captured: {len(conns)}\n")
    print(f"{'PID':<8} {'STATE':<14} {'LOCAL ADDRESS':<24} {'REMOTE ADDRESS'}")
    print("-" * 65)
    for c in conns[:15]:
        print(f"{c['pid']:<8} {c['state']:<14} {c['local_addr']:<24} {c['remote_addr']}")
