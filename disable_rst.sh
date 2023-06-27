#! /bin/bash

iptables -I INPUT -p tcp --tcp-flags ALL RST -j DROP
iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP