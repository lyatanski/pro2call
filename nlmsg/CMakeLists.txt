# The netlink family: modules that configure the kernel by exchanging
# messages over an AF_NETLINK socket, each carrying its own message
# builders and transactions and sharing only the TLV codec (task).
#
#   xfrm   IPsec SA/policy management  (NETLINK_XFRM)
#   rtnl   interface address add/del   (NETLINK_ROUTE, RTM_*ADDR)
add_subdirectory(xfrm)
add_subdirectory(rtnl)
