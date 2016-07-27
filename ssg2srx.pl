#!/usr/bin/perl
use warnings;
#use strict;
#use Data::Dumper;
#The script's main job is translate juniper ssg config to juniper srx config

my $text;
my $SET_POLICY;
my @nat_addr_book;
my $POLICY_ACTION;
my %ssg_zone_interfaces;
my $IP                      = "unit 0 family inet address";
my $APP                     = "match application";
my $ADDR                    = "address";
my $SNAT                    = "then static-nat prefix";
my $DADDR                   = "match destination-address";
my $DPORT                   = "destination-port" ;
my $SADDR                   = "match source-address";
my $SPORT                   = "source-port" ;
my $TO_ZONE                 = "to-zone";
my $ADDR_SET                = "address-set";
my $ADDR_BOOK               = "address-book" ;
my $CMD_NAT                 = "set security nat";
my $EXIT_STATUS             = 0;
my $CMD_ZONE                = "set security zones security-zone";
my $ZONE_SERVICE            = "host-inbound-traffic system-services all";
my $CMD_ROUTE               = "set routing-options static route";
my $CMD_POLICY              = "set security policies from-zone";
my $CMD_APPLICATION         = "set applications application";
my $CMD_DST_NAT_POOL        = "set security nat destination pool";
my $CMD_DST_NAT_RULE_SET    = "set security nat destination rule-set";
my %ssg_srx_services    = (
    ANY     => "any",           Any     => "any",
    FTP     => "junos-ftp",
    HTTP    => "junos-http",    HTTPS   => "junos-https",
    IKE     => "junos-ike",     IMAP    => "junos-imap",
    LDAP    => "junos-ldap",    MSN     => "junos-msn",
    MAIL    => "junos-mail",    NTP     => "junos-ntp",
    PING    => "junos-ping",    POP3    => "junos-pop3",
    PPTP    => "junos-pptp",    RTSP    => "junos-rtsp",
    RSH     => "junos-rsh",     SIP     => "junos-sip",
    SMTP    => "junos-smtp",    SMB     => "junos-smb",
    SSH     => "junos-ssh",     SYSLOG  => "junos-syslog",
    TFTP    => "junos-tftp",    TELNET  => "junos-telnet",
    WHOIS   => "junos-whois",
    'MS-RPC-EPM'    => "junos-ms-rpc-epm",
    'MS-RPC-ANY'    => "junos-ms-rpc",
    'MS-RPC-any'    => "junos-ms-rpc",
    'MS-SQL'        => "junos-ms-sql",
    'ICMP-ANY'      => "junos-icmp-all",
    'ICMP-any'      => "junos-icmp-all",
    'Internet Locator Service'  => "junos-internet-locator-service",
    'HTTP-EXT'      => "junos-http-ext",
    'Real-Media'    => "junos-realaudio",
    'Real Media'    => "junos-realaudio",
    'SQL\*Net_V1'   => "junos-sqlnet-v1",
    'SQL\*Net_V2'   => "junos-sqlnet-v2",
    'SQL\*Net V1'   => "junos-sqlnet-v1",
    'SQL\*Net V2'   => "junos-sqlnet-v2",
    'X-WINDOWS'     => "junos-x-windows",
    "H.323"         => "junos-h323",
);

# change form like 255.255.255.0 to 24
sub get_netmask {
    my $netmask = "@_";
    my @temp = split (/\./, $netmask);
    my $num_array = scalar @temp;# get the length of the array
    my $bit_num = 0;
    RETRUN_BIT_NUM:
    for (my $i=0; $i<$num_array; $i++) {
        my $factor = 7;
        my $sum = 0;
        if ($temp[$i] != 0) {
            while ($temp[$i] != $sum) {
                $sum += 2**$factor;
                $factor--;
                $bit_num++;
            } 
        }
        elsif ($temp[$i] == 0) {
            last RETRUN_BIT_NUM;
        }
    }
    return $bit_num;
}

#The BEGIN part process some staff
BEGIN {
    my %srx_zone_interfaces; # save the srx's zone and interfaces mapping
    my %ssg_srx_interfaces;  # save the ssg's zone and interfaces mapping
    if (system("/usr/bin/dos2unix $ARGV[0]") != 0) {
        print "command failed!: dos2unix:\n";
        exit;
    }
    # save all content of config to a variable, we will process the variable instead of <>
    open my $config, '<', $ARGV[0] or die "can't open file:$!\n"; #open the config filehandle
    $text = do {local $/; <$config>};
    close $config;

    while (<>) {
        if (/zone/ && /\binterface\b/ && !/(HA|Null)/) { #get interface & zone relationship
        # We will use hash reference here, the zone name as hash's key, a reference of array as hash's value, that point to the array of interfaces
            chomp;
            s/\"//g;
            my ($ssg_interface, $zone) = (split/\s+/)[2, 4];
            print "Please enter a replacement of $ssg_interface:";
            chomp (my $srx_interface = <STDIN>); # get new interface from user's input
            $ssg_srx_interfaces{$ssg_interface} = $srx_interface;
            # test the zone exists?
            if (exists $srx_zone_interfaces{$zone}) {
                push @{"srx_$zone"}, $srx_interface;
                push @{"ssg_$zone"}, $ssg_interface;
            }
            else { # add new zone to the keys
                push @{"srx_$zone"}, $srx_interface;
                push @{"ssg_$zone"}, $ssg_interface;
                $ssg_zone_interfaces{$zone} = \@{"ssg_$zone"};
                $srx_zone_interfaces{$zone} = \@{"srx_$zone"};
                $RULE_NUM_{$zone} = 0;
            }
            next;
        }
        elsif (!/unset/ && /\binterface\b/ && /\bip\b/ && /(?:\d{1,3}\.){3}\d{1,3}/) {
            chomp;
            my ($interface, $ip) = (split/\s+/)[2, 4];
            START:
            for my $tmp (keys %ssg_srx_interfaces) {
                while ($tmp eq $interface) {
                    print "set interfaces $ssg_srx_interfaces{$interface} unit 0 family inet address $ip\n";
                    last START;
                }
            }
        }
        elsif (/\binterface\b/ && /\bmip\b/) { #get MIP address mapping
            chomp;
            if (/255\.255\.255\.255/) {
                my ($mip, $host) = (split/\s+/)[4, 6];
                $text =~ s#MIP\($mip\)#Host_$host#gm; #replace nat's virtual address with it's real address
                next;
            }
            else {
                my ($mip, $net) = (split/\s+/)[4, 6];
                $text =~ s#MIP\($mip\)#Net_$net#gm; #replace nat's virtual address with it's real address
                next;
            }
        }
        elsif (/\binterface\b/ && /\bvip\b/) {
            chomp;
            my ($vip, $host) = (split/\s+/)[4, -2];
            $text =~ s#VIP\($vip\)#Host_$host#gm;
            next;
        }
    }
    # find each zone and print its interfaces
    foreach my $zone (sort keys %srx_zone_interfaces) {
        print "set security zones security-zone $zone host-inbound-traffic system-services all\n";
        for my $srx_interface (@{${srx_zone_interfaces{$zone}}}) {
            print "set security zones security-zone $zone interfaces $srx_interface\n";
        }
    }
}

# replace the blank betwen two " with _, the same to &
$text =~ s{\&}{_}xgm;

# replace the ssg's predefine services with srx's predefine applications
while (($key, $value) = each %ssg_srx_services) {
    $text =~ s/\b$key\b/$value/gm;
}

#print Dumper(\%ssg_zone_interfaces);
my @text = split(/\n/, $text);
foreach (@text) {
    s#\"##g;
    my @code = split/\s+/;
    my $length = scalar @code;
    if (/set service/ && /(protocol|\+)/) { #set applications
        my ($service_name, $protocol, $sport, $dport) = (split/\s+/)[2, 4, 6, 8];
        $service_name =~ s/\//-/g;
        print "$CMD_APPLICATION $service_name term $protocol\_$dport protocol $protocol $SPORT $sport $DPORT $dport\n";
        next;
    }
    elsif (/\binterface\b/ && /\bmip\b/) { # set static nat 
        my ($interface, $out_ip, $int_ip, $netmask) = (split/\s+/)[2, 4, 6, -3];
        for my $zone (sort keys %ssg_zone_interfaces) {
            for my $tmp (@{${ssg_zone_interfaces{$zone}}}) { 
                if ($tmp eq $interface && $netmask eq "255.255.255.255") {
                    print "$CMD_NAT static rule-set $zone rule $zone\_$RULE_NUM_{$zone} $DADDR $out_ip\n";
                    print "$CMD_NAT static rule-set $zone rule $zone\_$RULE_NUM_{$zone} $SNAT $int_ip\n";
                    push @nat_addr_book, "$CMD_ZONE $zone $ADDR_BOOK $ADDR Host_$int_ip $int_ip\n";
                    $RULE_NUM_{$zone}++;
                    last;
                }
                elsif ($tmp eq $interface && $netmask ne "255.255.255.255") {
                    my $netmask = get_netmask($netmask);
                    print "$CMD_NAT static rule-set $zone rule $zone\_$RULE_NUM_{$zone} $DADDR $out_ip\/$netmask\n";
                    print "$CMD_NAT static rule-set $zone rule $zone\_$RULE_NUM_{$zone} $SNAT $int_ip\/$netmask\n";
                    push @nat_addr_book, "$CMD_ZONE $zone $ADDR_BOOK $ADDR Net_$int_ip $int_ip\/$netmask\n";
                    $RULE_NUM_{$zone}++;
                    last;
                }
            }
        }
        next;
    }
    elsif (/\binterface\b/ && /\bvip\b/) { #set destination nat
        my ($interface, $ext_ip, $virtual_port, $real_port, $intr_ip) = (split/\s+/)[2, 4, -3, -2, -1];
        print "set security nat destination pool pool_$intr_ip\_$real_port\n";
        if (/\+/) {
            for my $zone (sort keys %ssg_zone_interfaces) {
                for my $tmp (@{${ssg_zone_interfaces{$zone}}}) {
                    if ($tmp eq $interface) {
                        print "$CMD_DST_NAT_RULE_SET $zone rule $zone\_$RULE_NUM_{$zone} $DADDR $ext_ip\n"; 
                        print "$CMD_DST_NAT_RULE_SET $zone rule $zone\_$RULE_NUM_{$zone} match $DPORT $virtual_port\n"; 
                        print "$CMD_DST_NAT_RULE_SET $zone rule $zone\_$RULE_NUM_{$zone} then destination-nat pool pool_$intr_ip\_$real_port\n"; 
                        $RULE_NUM_{$zone}++;
                        last;
                    }
                }
            }
        }
        else {
            for my $zone (sort keys %ssg_zone_interfaces) {
                for my $tmp (@{${ssg_zone_interfaces{$zone}}}) {
                    if ($tmp eq $interface) {
                        print "$CMD_DST_NAT_RULE_SET $zone from zone $zone\n"; 
                        print "$CMD_DST_NAT_RULE_SET $zone rule $zone\_$RULE_NUM_{$zone} $DADDR $ext_ip\n"; 
                        print "$CMD_DST_NAT_RULE_SET $zone rule $zone\_$RULE_NUM_{$zone} match $DPORT $virtual_port\n"; 
                        print "$CMD_DST_NAT_RULE_SET $zone rule $zone\_$RULE_NUM_{$zone} then destination-nat pool pool_$intr_ip\_$real_port\n"; 
                        $RULE_NUM_{$zone}++;
                        last;
                    }
                }
            }
        }
    }
    elsif (/\baddress\b/ && $length > 3) { 	#set address & address-set
        if (/255\.255\.255\.255/) { 		# the netmask is /32
            my ($zone, $addr_name, $ip) = (split/\s+/)[2, 3, 4];
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR $addr_name $ip\n";
        }
        elsif (!/(group)/ && /[0-9]{1,3}(\.[0-9]{1,3}){3}/) { #the netmask is not /32
            my ($zone, $addr_name, $ip, $netmask) = (split/\s+/)[2, 3, 4, 5];
            $netmask = get_netmask($netmask);
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR $addr_name $ip\/$netmask\n";
        }
        elsif (/group/ && /\badd\b/) { # the address group
            my ($zone, $addr_set, $addr_name) = (split/\s+/)[3, 4, -1];
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR_SET $addr_set $ADDR $addr_name\n";
        }
        elsif (!/group/ && /\w(\.\w)+/) {
            my ($zone, $addr_name, $fdnq) = (split/\s+/)[2, 3, 4];
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR $addr_name dns-name $fdnq\n";
        }
        next;
    #set policy, the most important part
    }
    elsif (/set policy id/ && /from/ && !/\bname\b/) {
        $EXIT_STATUS = 1; # add an switch for the action statement
        my ($policy_id, $src_zone, $dst_zone, $src_addr, $dst_addr, $service) = (split/\s+/)[3, 5, 7, 8, 9, 10];
        $service =~ s/\//-/g;
        $SET_POLICY = "$CMD_POLICY $src_zone $TO_ZONE $dst_zone policy $src_zone-to-$dst_zone-$policy_id";
        print "$SET_POLICY $SADDR $src_addr\n";
        print "$SET_POLICY $DADDR $dst_addr\n";
        print "$SET_POLICY $APP $service\n";
        if (/permit/) {
            $POLICY_ACTION = "$SET_POLICY then permit";
        }
        elsif (/deny/) {
            $POLICY_ACTION = "$SET_POLICY then deny";
        }
        next;
    }
    elsif (/set policy id/ && /from/ && /\bname\b/) {
        $EXIT_STATUS = 1; # add an switch for the action statement
        my ($policy_id, $policy_name, $src_zone, $dst_zone, $src_addr, $dst_addr, $service) = (split/\s+/)[3, 5, 7, 9, 10, 11, 12];
        $service =~ s/\//-/g;
        $SET_POLICY = "$CMD_POLICY $src_zone $TO_ZONE $dst_zone policy $policy_name-$policy_id";
        print "$SET_POLICY $SADDR $src_addr\n";
        print "$SET_POLICY $DADDR $dst_addr\n";
        print "$SET_POLICY $APP $service\n";
        if (/permit/) {
            $POLICY_ACTION = "$SET_POLICY then permit";
        }
        elsif (/deny/) {
            $POLICY_ACTION = "$SET_POLICY then deny";
        }
        next;
    }
    elsif ($length == 3 && /src-address/) {
        my $src_addr = (split/\s+/)[-1];
        print "$SET_POLICY $SADDR $src_addr\n";
        next;
    }
    elsif ($length == 3 && /dst-address/) {
        my $dst_addr = (split/\s+/)[-1];
        print "$SET_POLICY $DADDR $dst_addr\n";
        next;
    }
    elsif ($length == 3 && /service/) {
        my $service = (split/\s+/)[-1];
        $service =~ s/\//-/g;
        print "$SET_POLICY $APP $service\n";
        next;
    }
    elsif (/exit/ && $EXIT_STATUS == 1) { # check the switch, and confirm is on
        print "$POLICY_ACTION\n";
        $EXIT_STATUS = 0; # turn off the switch
        next;
    }
    elsif (/set route/ && /([0-9]{1,3}\.){3}[0-9]{1,3}/) { # set routes
        my ($droute, $gateway) = (split/\s+/)[2, 6];
        print "$CMD_ROUTE $droute next-hop $gateway\n";
        next;
    }
    elsif (/set group service/ && /\badd\b/) {
        my ($service_group_name, $service) = (split/\s+/)[3, -1];
        $service_group_name =~ s/\//-/g;
        $service =~ s/\//-/g;
        print "set applications application-set $service_group_name application $service\n";
        next;
    }
}

# print the nat address
END {
    print @nat_addr_book;
    print "set applications application SNMP term 1 protocol udp\n";
    print "set applications application SNMP term 1 destination-port 161-162\n";
    print "set applications application SNMP term 1\n";
    print "set applications application SNMP term 2 protocol tcp\n";
    print "set applications application SNMP term 2 destination-port 161-162\n";
    print "set applications application SNMP term 2 inactivity-timeout 30\n";
    print "set applications application DNS term t1 alg dns\n";
    print "set applications application DNS term t1 protocol udp\n";
    print "set applications application DNS term t1 destination-port 53\n";
    print "set applications application DNS term t2 alg dns\n";
    print "set applications application DNS term t2 protocol tcp\n";
    print "set applications application DNS term t2 destination-port 53\n";
}
