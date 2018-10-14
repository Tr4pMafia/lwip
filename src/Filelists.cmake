# This file is indended to be included in end-user CMakeLists.txt
# include(/path/to/Filelists.cmake)
# It assumes the variable LWIP_DIR is defined pointing to the
# root path of lwIP sources.
#
# This file is NOT designed (on purpose) to be used as cmake
# subdir via add_subdirectory()
# The intention is to provide greater flexibility to users to
# create their own targets using the *_SRCS variables.

set(LWIP_VERSION_MAJOR    "2")
set(LWIP_VERSION_MINOR    "1")
set(LWIP_VERSION_REVISION "0")
# LWIP_VERSION_RC is set to LWIP_RC_RELEASE for official releases
# LWIP_VERSION_RC is set to LWIP_RC_DEVELOPMENT for Git versions
# Numbers 1..31 are reserved for release candidates
set(LWIP_VERSION_RC       "LWIP_RC_RELEASE")

if ("${LWIP_VERSION_RC}" STREQUAL "LWIP_RC_RELEASE")
    set(LWIP_VERSION_STRING
        "${LWIP_VERSION_MAJOR}.${LWIP_VERSION_MINOR}.${LWIP_VERSION_REVISION}"
    )
elseif ("${LWIP_VERSION_RC}" STREQUAL "LWIP_RC_DEVELOPMENT")
    set(LWIP_VERSION_STRING
        "${LWIP_VERSION_MAJOR}.${LWIP_VERSION_MINOR}.${LWIP_VERSION_REVISION}.dev"
    )
else ("${LWIP_VERSION_RC}" STREQUAL "LWIP_RC_RELEASE")
    set(LWIP_VERSION_STRING
        "${LWIP_VERSION_MAJOR}.${LWIP_VERSION_MINOR}.${LWIP_VERSION_REVISION}.rc${LWIP_VERSION_RC}"
    )
endif ("${LWIP_VERSION_RC}" STREQUAL "LWIP_RC_RELEASE")

# The minimum set of files needed for lwIP.
set(lwipcore_SRCS
    src/core/init.c
    src/core/def.c
    src/core/dns.c
    src/core/inet_chksum.c
    src/core/ip.c
    src/core/mem.c
    src/core/memp.c
    src/core/netif.c
    src/core/pbuf.c
    src/core/raw.c
    src/core/stats.c
    src/core/sys.c
    src/core/altcp.c
    src/core/altcp_alloc.c
    src/core/altcp_tcp.c
    src/core/tcp.c
    src/core/tcp_in.c
    src/core/tcp_out.c
    src/core/timeouts.c
    src/core/udp.c
)
set(lwipcore4_SRCS
    src/core/ipv4/autoip.c
    src/core/ipv4/dhcp.c
    src/core/ipv4/etharp.c
    src/core/ipv4/icmp.c
    src/core/ipv4/igmp.c
    src/core/ipv4/ip4_frag.c
    src/core/ipv4/ip4.c
    src/core/ipv4/ip4_addr.c
)
set(lwipcore6_SRCS
    src/core/ipv6/dhcp6.c
    src/core/ipv6/ethip6.c
    src/core/ipv6/icmp6.c
    src/core/ipv6/inet6.c
    src/core/ipv6/ip6.c
    src/core/ipv6/ip6_addr.c
    src/core/ipv6/ip6_frag.c
    src/core/ipv6/mld6.c
    src/core/ipv6/nd6.c
)

# APIFILES: The files which implement the sequential and socket APIs.
set(lwipapi_SRCS
    src/api/api_lib.c
    src/api/api_msg.c
    src/api/err.c
    src/api/if_api.c
    src/api/netbuf.c
    src/api/netdb.c
    src/api/netifapi.c
    src/api/sockets.c
    src/api/tcpip.c
)

# Files implementing various generic network interface functions
set(lwipnetif_SRCS
    src/netif/ethernet.c
    src/netif/bridgeif.c
    src/netif/bridgeif_fdb.c
    src/netif/slipif.c
)

# 6LoWPAN
set(lwipsixlowpan_SRCS
    src/netif/lowpan6_common.c
    src/netif/lowpan6.c
    src/netif/lowpan6_ble.c
    src/netif/zepif.c
)

# PPP
set(lwipppp_SRCS
    src/netif/ppp/auth.c
    src/netif/ppp/ccp.c
    src/netif/ppp/chap-md5.c
    src/netif/ppp/chap_ms.c
    src/netif/ppp/chap-new.c
    src/netif/ppp/demand.c
    src/netif/ppp/eap.c
    src/netif/ppp/ecp.c
    src/netif/ppp/eui64.c
    src/netif/ppp/fsm.c
    src/netif/ppp/ipcp.c
    src/netif/ppp/ipv6cp.c
    src/netif/ppp/lcp.c
    src/netif/ppp/magic.c
    src/netif/ppp/mppe.c
    src/netif/ppp/multilink.c
    src/netif/ppp/ppp.c
    src/netif/ppp/pppapi.c
    src/netif/ppp/pppcrypt.c
    src/netif/ppp/pppoe.c
    src/netif/ppp/pppol2tp.c
    src/netif/ppp/pppos.c
    src/netif/ppp/upap.c
    src/netif/ppp/utils.c
    src/netif/ppp/vj.c
    src/netif/ppp/polarssl/arc4.c
    src/netif/ppp/polarssl/des.c
    src/netif/ppp/polarssl/md4.c
    src/netif/ppp/polarssl/md5.c
    src/netif/ppp/polarssl/sha1.c
)

# SNMPv3 agent
set(lwipsnmp_SRCS
    src/apps/snmp/snmp_asn1.c
    src/apps/snmp/snmp_core.c
    src/apps/snmp/snmp_mib2.c
    src/apps/snmp/snmp_mib2_icmp.c
    src/apps/snmp/snmp_mib2_interfaces.c
    src/apps/snmp/snmp_mib2_ip.c
    src/apps/snmp/snmp_mib2_snmp.c
    src/apps/snmp/snmp_mib2_system.c
    src/apps/snmp/snmp_mib2_tcp.c
    src/apps/snmp/snmp_mib2_udp.c
    src/apps/snmp/snmp_snmpv2_framework.c
    src/apps/snmp/snmp_snmpv2_usm.c
    src/apps/snmp/snmp_msg.c
    src/apps/snmp/snmpv3.c
    src/apps/snmp/snmp_netconn.c
    src/apps/snmp/snmp_pbuf_stream.c
    src/apps/snmp/snmp_raw.c
    src/apps/snmp/snmp_scalar.c
    src/apps/snmp/snmp_table.c
    src/apps/snmp/snmp_threadsync.c
    src/apps/snmp/snmp_traps.c
)

# HTTP server + client
set(lwiphttp_SRCS
    src/apps/http/altcp_proxyconnect.c
    src/apps/http/fs.c
    src/apps/http/http_client.c
    src/apps/http/httpd.c
)

# MAKEFSDATA HTTP server host utility
set(lwipmakefsdata_SRCS
    src/apps/http/makefsdata/makefsdata.c
)

# IPERF server
set(lwipiperf_SRCS
    src/apps/lwiperf/lwiperf.c
)

# SMTP client
set(lwipsmtp_SRCS
    src/apps/smtp/smtp.c
)

# SNTP client
set(lwipsntp_SRCS
    src/apps/sntp/sntp.c
)

# MDNS responder
set(lwipmdns_SRCS
    src/apps/mdns/mdns.c
)

# NetBIOS name server
set(lwipnetbios_SRCS
    src/apps/netbiosns/netbiosns.c
)

# TFTP server files
set(lwiptftp_SRCS
    src/apps/tftp/tftp_server.c
)

# MQTT client files
set(lwipmqtt_SRCS
    src/apps/mqtt/mqtt.c
)

# ARM MBEDTLS related files of lwIP rep
set(lwipmbedtls_SRCS
    src/apps/altcp_tls/altcp_tls_mbedtls.c
    src/apps/altcp_tls/altcp_tls_mbedtls_mem.c
    src/apps/snmp/snmpv3_mbedtls.c
)

# All LWIP files without apps
set(lwipnoapps_SRCS
    ${lwipcore_SRCS}
    ${lwipcore4_SRCS}
    ${lwipcore6_SRCS}
    ${lwipapi_SRCS}
    ${lwipnetif_SRCS}
    ${lwipsixlowpan_SRCS}
    ${lwipppp_SRCS}
)

# LWIPAPPFILES: All LWIP APPs
set(lwipallapps_SRCS
    ${lwipsnmp_SRCS}
    ${lwiphttp_SRCS}
    ${lwipiperf_SRCS}
    ${lwipsmtp_SRCS}
    ${lwipsntp_SRCS}
    ${lwipmdns_SRCS}
    ${lwipnetbios_SRCS}
    ${lwiptftp_SRCS}
    ${lwipmqtt_SRCS}
    ${lwipmbedtls_SRCS}
)

# Generate lwip/init.h (version info)
configure_file(src/include/lwip/init.h.cmake.in src/include/lwip/init.h)

include_directories(src/include)

# lwIP libraries
## static
add_library(lwipcorestatic STATIC ${lwipnoapps_SRCS})
target_compile_options(lwipcorestatic PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwipcorestatic PRIVATE ${LWIP_DEFINITIONS}  ${LWIP_MBEDTLS_DEFINITIONS})
target_include_directories(lwipcorestatic PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
set_property(TARGET lwipcorestatic PROPERTY OUTPUT_NAME lwipcore_static)

## shared
add_library(lwipcoreshared SHARED ${lwipnoapps_SRCS})
target_compile_options(lwipcoreshared PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwipcoreshared PRIVATE ${LWIP_DEFINITIONS}  ${LWIP_MBEDTLS_DEFINITIONS})
target_include_directories(lwipcoreshared PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
set_property(TARGET lwipcoreshared PROPERTY OUTPUT_NAME lwipcore_shared)

# installation
## header files
install(DIRECTORY src/include/arch DESTINATION include)
install(DIRECTORY src/include/compat DESTINATION include)
install(DIRECTORY src/include/lwip DESTINATION include)
install(DIRECTORY src/include/netif DESTINATION include)
install(FILES src/include/lwipopts.h DESTINATION include)
set(INSTALL_LIB_DIR     lib CACHE PATH "Installation directory for libraries")
mark_as_advanced(INSTALL_LIB_DIR)

## binaries
install(TARGETS lwipcorestatic
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION ${INSTALL_LIB_DIR}
        ARCHIVE DESTINATION ${INSTALL_LIB_DIR})
install(TARGETS lwipcoreshared
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION ${INSTALL_LIB_DIR}
        ARCHIVE DESTINATION ${INSTALL_LIB_DIR})

