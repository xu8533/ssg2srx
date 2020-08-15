#!/usr/bin/perl
use warnings;
#use strict;
use Data::Dumper;
#The major aim of the script is translate juniper's ssg config to juniper srx config

# define variable
my $DIP_ACTION;
my $DISABLE_POLICY;
my $DST_IP_ACTION;
my $GLOBAL_ADDRESS_BOOKS;
my $NAT_SOURCE_ACTION;
my $POLICY_ACTION;
my $SET_POLICY;
my $text;
my $dip_id;
my $dst_pool_name;
my $dst_real_address;
my $dst_real_addr;
my $dst_real_zone;
my $policy_id_icmp;
my $src_real_zone;
my $src_zone_icmp;
my @destination_nat;
my @destination_nat_icmp;
my @destination_nat_zone;
my @dst_ip_address_books;
my @dst_real_zones;
my @global_address_books;
my @global_disable_policy;
my @global_dst_address;
my @global_policy;
my @global_policy_action;
my @global_services;
my @global_src_address;
my @global_zones;
my @mip_address_books;
my @nat_src_addr_icmp;
my @nat_dst_addr_icmp;
my @service;
my @source_nat;
my @source_nat_icmp;
my @source_nat_zone;
my %dip_pool;
my %mip_address_pairs;
my %ssg_zone_interfaces;
my $DIP_STATUS                  = 0;
my $DST_IP_STATUS               = 0;
my $GLOBAL_POLICY_DST_ADDR_ANY  = 0;
my $GLOBAL_POLICY_STATUS        = 0;
my $MIP_EXIST                   = 0;
my $NAT_ICMP                    = 0;
my $NAT_SOURCE_STATUS           = 0;
my $POLICY_STATUS               = 0;
my $APP                     = "match application";
my $ADDR                    = "address";
my $ADDR_BOOK               = "address-book" ;
my $ADDR_SET                = "address-set";
my $CMD_APPLICATION         = "set applications application";
my $CMD_DST_NAT_POOL        = "set security nat destination pool";
my $CMD_DST_NAT_RULE_SET    = "set security nat destination rule-set";
my $CMD_NAT                 = "set security nat";
my $CMD_POLICY              = "security policies from-zone";
my $CMD_ROUTE               = "set routing-options static route";
my $CMD_ZONE                = "set security zones security-zone";
my $DADDR                   = "match destination-address";
my $DPORT                   = "destination-port" ;
my $DST_PORT                = "match destination-port";
my $IP                      = "unit 0 family inet address";
my $SADDR                   = "match source-address";
my $SNAT                    = "then static-nat prefix";
my $SPORT                   = "source-port" ;
my $TO_ZONE                 = "to-zone";
my $ZONE_SERVICE            = "host-inbound-traffic system-services all";
my %srx_zone_interfaces; # save the srx's zone and interfaces mapping
my %ssg_srx_interfaces;  # save the ssg's zone and interfaces mapping
my %zone_network;        # save zone, network segment, netmask
my %ssg_srx_services        = (
    ANY     => "any",           Any     => "any",
    FTP     => "junos-ftp",
    HTTP    => "junos-http",    HTTPS   => "junos-https",
    IKE     => "junos-ike",     IMAP    => "junos-imap",
    LDAP    => "junos-ldap",    MSN     => "junos-msn",
    MAIL    => "junos-mail",    NBDS    => "junos-nbds",
    NBNAME  => "junos-nbname",  NTP     => "junos-ntp",
    PING    => "junos-ping",    POP3    => "junos-pop3",
    PPTP    => "junos-pptp",    RADIUS  => "junos-radius",
    RTSP    => "junos-rtsp",
    RSH     => "junos-rsh",     SIP     => "junos-sip",
    SMTP    => "junos-smtp",    SMB     => "junos-smb",
    SSH     => "junos-ssh",     SYSLOG  => "junos-syslog",
    TFTP    => "junos-tftp",    TELNET  => "junos-telnet",
    WHOIS   => "junos-whois",
    'MS-RPC-EPM'    => "junos-ms-rpc-epm",
    'MS-RPC-ANY'    => "junos-ms-rpc",
    'MS-RPC-any'    => "junos-ms-rpc",
    'MS-SQL'        => "junos-ms-sql",
    #'ICMP-ANY'      => "junos-icmp-all",
    #'ICMP-any'      => "junos-icmp-all",
    'ICMP-ANY'      => "junos-ping",
    'ICMP-any'      => "junos-ping",
    'HTTP-EXT'      => "junos-http-ext",
    'Real-Media'    => "junos-realaudio",
    'Real Media'    => "junos-realaudio",
    'SQL\*Net_V1'   => "junos-sqlnet-v1",
    'SQL\*Net_V2'   => "junos-sqlnet-v2",
    'SQL\*Net V1'   => "junos-sqlnet-v1",
    'SQL\*Net V2'   => "junos-sqlnet-v2",
    'SQL Monitor'   => "junos-sql-monitor",
    'X-WINDOWS'     => "junos-x-windows",
    "H.323"         => "junos-h323",
    'Internet Locator Service'  => "junos-internet-locator-service",
);
my %srx_application_port_number = (
    http    => 80,     https    => 443,     ftp     => 21,
    ssh     => 22,     mail     => 25,      telnet  => 23,
    Terminal => 3389,  SNMP    => "161 to 162",
);

my @Trust = ("192.168.200.0/24",);

my @Untrust = ("10.0.0.0/8",);

#my @DMZ  = ("56.16.71.22/32", "56.16.71.57/32", "56.16.71.183/32",
#);

my %zone_ip = (
        Trust   =>  \@Trust,    'Untrust' =>  \@Untrust,
); 

#determine whether a IP is in a network segment, and return corresponding zone
sub return_ip_zone {
         local @Untrust_nonnumeric_name = ();
         local %zone_ip_name = 
                (   Trust      => \@Trust_nonnumeric_name, 
                    Untrust    => \@Untrust_nonnumeric_name,
                    #'DMZ-2'    => \@DMZ2_nonnumeric_name,
             ); 
    local $test_ip_zone;
    local $real_ip = "@_";    
    $real_ip    = (split/\//, $real_ip)[0];
    $real_ip    =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
    local $ip   = $1;
    if ($ip) {
        local $real_ip_bit  = unpack("B32", pack("C4", (split/\./, $ip)));
        RETURN_IP_ZONE:
        foreach my $zone (keys %zone_network) {
            #print "1st cycle\nzone is $zone\n";
            for my $i (0..$#{$zone_network{ $zone }}) {
                my $netbit  = $zone_network{ $zone }[$i][0];
                my $netmask = $zone_network{ $zone }[$i][1];
                my $testipbit = substr("$real_ip_bit", 0, "$netmask");
                #        print "netbit is $netbit\ntestipbit is $testipbit\nnetmask is $netmask\n";
                if ($netbit == $testipbit) {
                    $test_ip_zone = $zone;
                    #                print "test ip zone is $test_ip_zone\n";
                    last RETURN_IP_ZONE;
                }
            }
        }
    }
    else {
        RETURN_IP_ZONE_NAME:
        foreach my $zone (keys %zone_ip_name) {
            for my $i (0..$#{$zone_ip_name{ $zone }}) {
                my $address_name = $zone_ip_name{ $zone }[$i];
                if ($address_name eq $real_ip) {
                    $test_ip_zone = $zone;
                    last RETURN_IP_ZONE_NAME;
                }
            }
        }
    }
    if (defined$test_ip_zone) {
        return $test_ip_zone;
    }
    else {
        return "Untrust";
    }
    undef $ip;
    undef $test_ip_zone;
}

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

#get zone and network relationship
foreach my $zone (keys %zone_ip) {
    for my $i (0..$#{$zone_ip{ $zone }}) {
        my $dec = $zone_ip{ $zone }[ $i ];
        chomp $dec;
        my ($ip, $netmask) = (split/\//, $dec);
        my $ipbit          = unpack("B32", pack("C4", (split/\./, $ip)));
        my $netbit         = substr("$ipbit", 0, "$netmask");
        push  @{$zone_network{ $zone }}, [$netbit, $netmask];
    }
}

#The BEGIN part process some staff
BEGIN {
    if (system("/usr/bin/dos2unix $ARGV[0]") != 0) {
        print "command failed!: dos2unix:\n";
        exit;
    }
    # save all content of config to a variable, we will process the variable instead of <>
    open my $config, '<', $ARGV[0] or die "can't open file:$!\n"; #open the config filehandle
    $text = do { local $/; <$config> };
    close $config;

    while (<>) {
        if (/zone/ && /\binterface\b/ && !/(HA|Null)/) { #get interface & zone relationship
        #use hash reference, the zone name as hash's key, a reference of array as hash's value, that point to the array of the same zone's interfaces
            my $ssg_interface;
            my $zone;
            chomp;
            s/\"//g;
            if (/\d+\.\d+/) {
                ($ssg_interface, $zone) = (split/\s+/)[2, 6];
            }
            else {
                ($ssg_interface, $zone) = (split/\s+/)[2, 4];
            }
            print "Please enter a replacement of $ssg_interface:";
            chomp (my $srx_interface = <STDIN>); # get new interface from user's input
            $ssg_srx_interfaces{ $ssg_interface } = $srx_interface;
            # test the zone exists?
            if (exists $srx_zone_interfaces{ $zone }) {
                push @{"srx_$zone"}, $srx_interface;
                push @{"ssg_$zone"}, $ssg_interface;
            }
            else { # add new zone to the keys
                push @{"srx_$zone"}, $srx_interface;
                push @{"ssg_$zone"}, $ssg_interface;
                $ssg_zone_interfaces{ $zone } = \@{"ssg_$zone"};
                $srx_zone_interfaces{ $zone } = \@{"srx_$zone"};
                $RULE_NUM_{ $zone } = 0;
            }
            next;
        }
        elsif (!/unset/ && /\binterface\b/ && /\bip\b/ && !/\bdip\b/ && /(?:\d{1,3}\.){3}\d{1,3}/) {
            chomp;
            my ($interface, $ip) = (split/\s+/)[2, 4];
            START:
            for my $tmp (keys %ssg_srx_interfaces) {
                while ($tmp eq $interface) {
                    my ($tmp_srx_interface, $unit) = split/\./, $ssg_srx_interfaces{$interface};
                    #print "set interfaces $ssg_srx_interfaces{$interface} ".
                    #       "unit 0 family inet address $ip\n";
                       print "set interfaces $tmp_srx_interface ".
                           "unit $unit family inet address $ip\n";
                    last START;
                }
            }
        }
        elsif (/\binterface\b/ && /\bmip\b/) { #get MIP address mapping
            chomp;
            if (/255\.255\.255\.255/) {
                my ($mip, $host) = (split/\s+/)[4, 6];
                #$text =~ s#MIP\($mip\)#Host_$host#gm; #replace nat's virtual address with it's real address
                $mip_address_pairs{ "$mip" } = $host;
            }
            else {
                my ($mip, $net) = (split/\s+/)[4, 6];
                #$text =~ s#MIP\($mip\)#Net_$net#gm; #replace nat's virtual address with it's real address
                $mip_address_pairs{ "$mip" } = $net;
            }
            next;
        }
        elsif (/\binterface\b/ && /\bdip\b/) { #get DIP pool address
            chomp;
            if (/ext/) {
                ($dip_id, $dip_address) = (split/\s+/)[8, -1];
            }
            else {
                ($dip_id, $dip_address) = (split/\s+/)[4, -1];
            }
            $dip_pool{$dip_id} = $dip_address;
            next;
        }
#        elsif (/\binterface\b/ && /\bvip\b/) {
#            chomp;
#            my ($vip, $host) = (split/\s+/)[4, -2];
#            $text =~ s#VIP\($vip\)#Host_$host#gm;
#            next;
#        }
        elsif (/policy id/ && /name/) {
            chomp;
            $text =~ s#name\ \"[^"]*\"##; #remove policy name, no need
            next;
        }
    }
    # find each zone and print its interfaces
    foreach my $zone (sort keys %srx_zone_interfaces) {
        push @global_zones, $zone;
        print "set security zones security-zone $zone ".
               "host-inbound-traffic system-services all\n";
        for my $srx_interface (@{${ srx_zone_interfaces{ $zone } }}) {
            print "set security zones security-zone $zone ".
                  "interfaces $srx_interface\n";
        }
    }
}

# replace the blank betwen two " with _, the same to &
#$text =~ s{\&}{_}xgm;

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
        my ($service_name, $protocol, $sport, $dport) 
            = (split/\s+/)[2, 4, 6, 8];
        $service_name =~ s!\/!-!g;
        print "$CMD_APPLICATION $service_name term $protocol\_$dport ".
              "protocol $protocol $SPORT $sport $DPORT $dport\n";
        next;
    }
    elsif (/\binterface\b/ && /\bmip\b/) { # set static nat rule
        my ($interface, $out_ip, $int_ip, $netmask) 
            = (split/\s+/)[2, 4, 6, -3];
        local $temp_srx_interface = $ssg_srx_interfaces{ $interface };
        $temp_srx_interface =~ s/\./_/;
        for my $zone (sort keys %ssg_zone_interfaces) {
            for my $tmp (@{${ssg_zone_interfaces{ $zone }}}) { 
                if (($tmp eq $interface) && ($netmask eq "255.255.255.255")) {
                    print "$CMD_NAT static rule-set $zone\_$temp_srx_interface " .
                          "rule $zone\_$RULE_NUM_{ $zone } " . 
                          "$DADDR $out_ip\n";
                    print "$CMD_NAT static rule-set $zone\_$temp_srx_interface " .
                          "rule $zone\_$RULE_NUM_{ $zone } " .
                          "$SNAT $int_ip\n";
                          my $mip_real_zone = return_ip_zone($int_ip);
                          push @mip_address_books, 
                              "$CMD_ZONE $mip_real_zone $ADDR_BOOK $ADDR " .
                              "Host_$int_ip $int_ip\n";
                    $RULE_NUM_{ $zone }++;
                    last;
                }
                elsif (($tmp eq $interface) && ($netmask ne "255.255.255.255")) {
                    my $netmask = get_netmask($netmask);
                    print "$CMD_NAT static rule-set $zone\_$temp_srx_interface " .
                          "rule $zone\_$RULE_NUM_{ $zone } " .
                          "$DADDR $out_ip\/$netmask\n"
                          ;
                    print "$CMD_NAT static rule-set $zone\_$temp_srx_interface " .
                          "rule $zone\_$RULE_NUM_{ $zone } " .
                          "$SNAT $int_ip\/$netmask\n"
                          ;
                    foreach $mip_other_zone (@global_zones) {
                        if ($mip_other_zone ne $zone) {
                            push @mip_address_books, 
                                "$CMD_ZONE $mip_other_zone $ADDR_BOOK " .
                                "$ADDR Host_$int_ip $int_ip\n"
                                ;
                        }
                    }
                    $RULE_NUM_{ $zone }++;
                    last;
                }
            }
        }
        undef $temp_srx_interface;
        next;
    }
    elsif (/\baddress\b/ && $length > 3 && !/\bGlobal\b/) { 	#set address & address-set
        if (/255\.255\.255\.255/ && !/(group)/) { 		# the netmask is /32
            my ($zone, $addr_name, $ip) = (split/\s+/)[2, 3, 4];
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR $addr_name $ip\n";
        }
        elsif (!/(group)/ && /\d{1,3}(\.\d{1,3}){3}/) { #the netmask is not /32
            my ($zone, $addr_name, $ip, $netmask) = (split/\s+/)[2, 3, 4, 5];
            $netmask = get_netmask($netmask);
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR " .
                  "$addr_name $ip\/$netmask\n";
        }
        elsif (/group/ && /\badd\b/) { # the address group
            my ($zone, $addr_set, $addr_name) = (split/\s+/)[3, 4, -1];
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR_SET $addr_set " .
                  "$ADDR $addr_name\n";
        }
        elsif (!/group/ && /\w(\.\w)+/) {
            my ($zone, $addr_name, $fdnq) = (split/\s+/)[2, 3, 4];
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR $addr_name " .
                  "dns-name $fdnq\n";
        }
        next;
    }
    elsif (/\baddress\b/ && $length > 3 && /\bGlobal\b/) {
        if (!/(group)/ && /255\.255\.255\.255/) { 		# the netmask is /32
           my ($addr_name, $ip) = (split/\s+/)[3, 4];
           if (exists $mip_address_pairs{ $ip }) {
               $ip = $mip_address_pairs{ $ip };
               $addr_name = "Host_$ip";
           }
           $zone = return_ip_zone($ip);
           print "$CMD_ZONE $zone $ADDR_BOOK $ADDR $addr_name $ip\n";
        }
        elsif (!/(group)/ && /\d{1,3}(\.\d{1,3}){3}/) { #the netmask is not /32
            my ($addr_name, $ip, $netmask) = (split/\s+/)[3, 4, 5];
            $zone = return_ip_zone($ip);
            $netmask = get_netmask($netmask);
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR " .
                  "$addr_name $ip\/$netmask\n";
        }
        elsif (/group/ && /\badd\b/) { # the address group
            my ($addr_set, $addr_name) = (split/\s+/)[4, -1];
            $addr_name  =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
            local $ip   = $1;
            if (exists $mip_address_pairs{ $ip }) {
                $ip = $mip_address_pairs{ $ip };
                $addr_name = "Host_$ip";
            }
            $zone = return_ip_zone($addr_name);
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR_SET " .
                  "$addr_set $ADDR $addr_name\n";
        }
        elsif (!/group/ && /\w(\.\w)+/) {
            my ($addr_name, $fdnq) = (split/\s+/)[3, 4];
            $zone = return_ip_zone($fdnq);
            print "$CMD_ZONE $zone $ADDR_BOOK $ADDR " .
                  "$addr_name dns-name $fdnq\n";
        }
        next;
    }
    elsif (/set group service/ && /\badd\b/) {
        my ($service_group_name, $service) = (split/\s+/)[3, -1];
        $service_group_name =~ s!\/!-!g;
        $service =~ s!\/!-!g;
        print "set applications application-set $service_group_name " .
              "application $service\n";
        next;
    }
    elsif (/\bnat src\b/ && !/\bdip-id\b/ && !/\bGlobal\b/) { # set nat source interface
        $NAT_SOURCE_STATUS = 1; # a flag of all souce and destination address 
        (local $src_zone, local $dst_zone, local $src_address, local $dst_address, local $policy_id, local $dst_port) 
            = (split/\s+/)[5, 7, 8, 9, 3, 10];
        if (/\bdst ip\b/) {
            $DST_IP_STATUS = 1;
            local $dst_ip_id;
            local $dst_port;
            ($dst_ip_id, $src_zone, $src_address, $dst_address, $dst_port, $dst_real_address_temp) 
                = (split/\s+/)[3, 5, 8, 9, 10, 15];
            $dst_real_address = $dst_real_address_temp;
            $dst_real_address_temp =~ s!\.!_!g;
            $dst_pool_name = $dst_real_address_temp;
            $dst_port =~ s/\D+[_-]//g;
            $src_address =~ 
                s/(?:\D+[_-]){1,}([0-9]{1,3}(\.[0-9]{1,3}){3})/$1/g;
            $dst_address =~ 
                s/(?:\D+[_-]){1,}([0-9]{1,3}(\.[0-9]{1,3}){3})/$1/g;
            if ($dst_port eq "ping") {
                $NAT_ICMP = 1; 
            }
            push @nat_src_addr_icmp, $src_address;
            push @nat_dst_addr_icmp, $dst_address;
            push @destination_nat, 
                "$CMD_NAT destination pool host_$dst_pool_name address $dst_real_address\n";
            $DST_IP_ACTION 
                = "$CMD_NAT destination rule-set $src_zone rule dst-$dst_ip_id";
            push @destination_nat_zone, 
                "$CMD_NAT destination rule-set $src_zone from zone $src_zone\n";
            push @destination_nat, 
                "$DST_IP_ACTION $SADDR $src_address\n";
            push @destination_nat, 
                "$DST_IP_ACTION $DADDR $dst_address\n";
            push @destination_nat, 
                "$DST_IP_ACTION $DST_PORT $dst_port\n";
            $dst_address = $dst_real_address;
        }
        $dst_port =~ s/\D+[_-]//g;
        $src_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        $dst_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_src_addr_icmp, $src_address;
        push @nat_dst_addr_icmp, $dst_address;
        if ($dst_port eq "ping") {
            $NAT_ICMP = 1;
        }
        $NAT_SOURCE_ACTION 
            = "$CMD_NAT source rule-set $src_zone-to-$dst_zone rule src-$policy_id";
        push @source_nat_zone, 
            "$CMD_NAT source rule-set $src_zone-to-$dst_zone from zone $src_zone\n";
        push @source_nat_zone, 
            "$CMD_NAT source rule-set $src_zone-to-$dst_zone to zone $dst_zone\n";
        push @source_nat, 
            "$NAT_SOURCE_ACTION $SADDR $src_address\n";
        push @source_nat, 
            "$NAT_SOURCE_ACTION $DADDR $dst_address\n";
        push @source_nat, 
            "$NAT_SOURCE_ACTION match destination-port $dst_port\n";
    }
    elsif ($length == 3 && /\bsrc-address\b/ && $NAT_SOURCE_STATUS == 1 && $DST_IP_STATUS ne 1) {
        my $src_address = (split/\s+/)[2];
        $src_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_src_addr_icmp, $src_address;
        push @source_nat, 
            "$NAT_SOURCE_ACTION $SADDR $src_address\n";
    }
    elsif ($length == 3 && /\bsrc-address\b/ && $NAT_SOURCE_STATUS == 1 && $DST_IP_STATUS eq 1) {
        my $src_address = (split/\s+/)[2];
        $src_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_src_addr_icmp, $src_address;
        push @source_nat, 
            "$NAT_SOURCE_ACTION $SADDR $src_address\n";
        push @destination_nat, 
            "$DST_IP_ACTION $SADDR $src_address\n";
    }
    elsif ($length == 3 && /\bdst-address\b/ && $NAT_SOURCE_STATUS == 1 && $DST_IP_STATUS ne 1) {
        my $dst_address = (split/\s+/)[-1];
        $dst_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_dst_addr_icmp, $dst_address;
        push @source_nat, 
            "$NAT_SOURCE_ACTION $DADDR $dst_address\n";
    }
    elsif ($length == 3 && /\bdst-address\b/ && $NAT_SOURCE_STATUS == 1 && $DST_IP_STATUS eq 1) {
        my $dst_address = (split/\s+/)[-1];
        $dst_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_dst_addr_icmp, $dst_address;
        #push @source_nat, 
        #    "$NAT_SOURCE_ACTION $DADDR $dst_address\n";
        push @destination_nat, 
            "$DST_IP_ACTION $DADDR $dst_address\n";
    }
    elsif ($length == 3 && /\bservice\b/ && $NAT_SOURCE_STATUS == 1 && $DST_IP_STATUS ne 1) {
        local $dst_port = (split/\s+/)[2];
        $dst_port =~ s/\D+[_-]//g;
        if ($dst_port eq "ping") {
            $NAT_ICMP = 1;
        }
        push @source_nat, 
            "$NAT_SOURCE_ACTION match destination-port $dst_port\n";
    }
    elsif ($length == 3 && /\bservice\b/ && $NAT_SOURCE_STATUS == 1 && $DST_IP_STATUS eq 1) {
        local $dst_port = (split/\s+/)[2];
        $dst_port =~ s/\D+[_-]//g;
        if ($dst_port eq "ping") {
            $NAT_ICMP = 1;
        }
        push @destination_nat, 
            "$DST_IP_ACTION $DST_PORT $dst_port\n";
        push @source_nat, 
            "$NAT_SOURCE_ACTION match destination-port $dst_port\n";
    }
    elsif (/exit/ && $NAT_SOURCE_STATUS == 1 && $DST_IP_STATUS != 1) { # check the switch, and confirm is on
        push @source_nat, 
            "$NAT_SOURCE_ACTION then source-nat interface\n";
        if ($NAT_ICMP == 1) {
            $NAT_SOURCE_ACTION = "$NAT_SOURCE_ACTION-icmp";
            foreach my $tmp_src_addr (@nat_src_addr_icmp) {
                push @source_nat, 
                    "$NAT_SOURCE_ACTION $SADDR $tmp_src_addr\n";
            }
            foreach my $tmp_dst_addr (@nat_dst_addr_icmp) {
                push @source_nat, 
                    "$NAT_SOURCE_ACTION $DADDR $tmp_dst_addr\n";
            }
            push @source_nat,
                "$NAT_SOURCE_ACTION match protocol icmp\n". 
                "$NAT_SOURCE_ACTION then source-nat interface\n";
        }
        $NAT_ICMP = 0;
        $NAT_SOURCE_STATUS = 0; # turn off the switch
        undef @nat_src_addr_icmp;
        undef @nat_dst_addr_icmp;
    }
    elsif (/exit/ && $NAT_SOURCE_STATUS == 1 && $DST_IP_STATUS == 1) { # check the switch, and confirm is on
        push @source_nat, 
            "$NAT_SOURCE_ACTION then source-nat interface\n";
        push @destination_nat, 
            "$DST_IP_ACTION then destination-nat pool host_$dst_pool_name\n";
        if ($NAT_ICMP == 1) {
            $NAT_SOURCE_ACTION = "$NAT_SOURCE_ACTION-icmp";
            $DST_IP_ACTION = "$DST_IP_ACTION-icmp";
            foreach my $tmp_src_addr (@nat_src_addr_icmp) {
                push @source_nat, 
                    "$NAT_SOURCE_ACTION $SADDR $tmp_src_addr\n";
                push @destination_nat,
                    "$DST_IP_ACTION $SADDR $tmp_src_addr\n";
            }
            foreach my $tmp_dst_addr (@nat_dst_addr_icmp) {
                push @destination_nat,
                    "$DST_IP_ACTION $DADDR $tmp_dst_addr\n";
            }
            push @source_nat, 
                "$NAT_SOURCE_ACTION $DADDR $dst_real_address\n";
            push @source_nat,
                "$NAT_SOURCE_ACTION match protocol icmp\n". 
                "$NAT_SOURCE_ACTION then source-nat interface\n";
            push @destination_nat, 
                "$DST_IP_ACTION match protocol icmp\n".
                "$DST_IP_ACTION then destination-nat pool host_$dst_pool_name\n";
        }
        $NAT_ICMP = 0;
        $NAT_SOURCE_STATUS = 0; # turn off the switch
        #$DST_IP_STATUS = 0; # don't turn off the switch, policy need it
        undef @nat_src_addr_icmp;
        undef @nat_dst_addr_icmp;
    }
    elsif (/\bdip-id\b/ && !/\bGlobal\b/) { # set source nat
        $DIP_STATUS = 1; # a flag of all souce and destination address 
        (local $policy_id, local $src_zone, local $dst_zone, local $src_address, local $dst_address, local $dst_port, $dip_id) 
            = (split/\s+/)[3, 5, 7, 8, 9, 10, 14];
        if (/\bdst ip\b/) {
            $DST_IP_STATUS = 1;
            #local $src_zone;
            local $dst_ip_id;
            #local $src_address;
            #local $dst_address;
            local $dst_port;
            ($dst_ip_id, $src_zone, $src_address, $dst_address, $dst_port, $dst_real_address_temp) 
                = (split/\s+/)[3, 5, 8, 9, 10, 17];
            $dst_real_address = $dst_real_address_temp;
            $dst_real_address_temp =~ s!\.!_!g;
            $dst_pool_name = $dst_real_address_temp;
            $dst_port =~ s/\D+[_-]//g;
            $src_address =~ 
                s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
            $dst_address =~ 
                s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
            if ($dst_port eq "ping") {
                $NAT_ICMP = 1; 
            }
            push @nat_src_addr_icmp, $src_address;
            push @nat_dst_addr_icmp, $dst_address;
            push @destination_nat, 
                "$CMD_NAT destination pool host_$dst_pool_name " .
                "address $dst_real_address\n"
                ;
            $DST_IP_ACTION 
                = "$CMD_NAT destination rule-set $src_zone " .
                  "rule dst-$dst_ip_id"
                  ;
            push @destination_nat_zone, 
                "$CMD_NAT destination rule-set $src_zone " .
                "from zone $src_zone\n"
                ;
            push @destination_nat, 
                "$DST_IP_ACTION $SADDR $src_address\n";
            push @destination_nat, 
                "$DST_IP_ACTION $DADDR $dst_address\n";
            push @destination_nat, 
                "$DST_IP_ACTION $DST_PORT $dst_port\n";
            $dst_address = $dst_real_address;
        }
        $dst_port =~ s/\D+[_-]//g;
        $src_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        $dst_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_src_addr_icmp, $src_address;
        push @nat_dst_addr_icmp, $dst_address;
        if ($dst_port eq "ping") {
            $NAT_ICMP = 1;
        }
        push @source_nat, 
            "$CMD_NAT source pool $dip_id address $dip_pool{ $dip_id }\n";
        $DIP_ACTION 
            = "$CMD_NAT source rule-set $src_zone-to-$dst_zone " .
              "rule $dip_id-$policy_id"
              ;
        push @source_nat_zone, 
            "$CMD_NAT source rule-set $src_zone-to-$dst_zone " .
            "from zone $src_zone\n"
            ;
        push @source_nat_zone, 
            "$CMD_NAT source rule-set $src_zone-to-$dst_zone " .
            "to zone $dst_zone\n"
            ;
        push @source_nat, 
            "$DIP_ACTION $SADDR $src_address\n";
        push @source_nat, 
            "$DIP_ACTION $DADDR $dst_address\n";
        push @source_nat, 
            "$DIP_ACTION match destination-port $dst_port\n";
    }
    elsif ($length == 3 && /\bsrc-address\b/ && $DIP_STATUS == 1 && $DST_IP_STATUS ne 1) {
        my $src_address = (split/\s+/)[2];
        $src_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_src_addr_icmp, $src_address;
        push @source_nat, 
            "$DIP_ACTION $SADDR $src_address\n";
    }
    elsif ($length == 3 && /\bsrc-address\b/ && $DIP_STATUS == 1 && $DST_IP_STATUS eq 1) {
        my $src_address = (split/\s+/)[2];
        $src_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_src_addr_icmp, $src_address;
        push @source_nat, 
            "$DIP_ACTION $SADDR $src_address\n";
        push @destination_nat, 
            "$DST_IP_ACTION $SADDR $src_address\n";
    }
    elsif ($length == 3 && /\bdst-address\b/ && $DIP_STATUS == 1 && $DST_IP_STATUS ne 1) {
        my $dst_address = (split/\s+/)[-1];
        $dst_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_dst_addr_icmp, $dst_address;
        push @source_nat, 
            "$DIP_ACTION $DADDR $dst_address\n";
    }
    elsif ($length == 3 && /\bdst-address\b/ && $DIP_STATUS == 1 && $DST_IP_STATUS eq 1) {
        my $dst_address = (split/\s+/)[-1];
        $dst_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_dst_addr_icmp, $dst_address;
        # push @source_nat, 
        #    "$DIP_ACTION $DADDR $dst_address\n";
        push @destination_nat, 
            "$DST_IP_ACTION $DADDR $dst_address\n";
    }
    elsif ($length == 3 && /\bservice\b/ && $DIP_STATUS == 1 && $DST_IP_STATUS ne 1) {
        local $dst_port = (split/\s+/)[2];
        $dst_port =~ s/\D+[_-]//g;
        if ($dst_port eq "ping") {
            $NAT_ICMP = 1;
        }
        push @source_nat, 
            "$DIP_ACTION match destination-port $dst_port\n";
    }
    elsif ($length == 3 && /\bservice\b/ && $DIP_STATUS == 1 && $DST_IP_STATUS eq 1) {
        local $dst_port = (split/\s+/)[2];
        $dst_port =~ s/\D+[_-]//g;
        if ($dst_port eq "ping") {
            $NAT_ICMP = 1;
        }
        push @destination_nat, 
            "$DST_IP_ACTION $DST_PORT $dst_port\n";
        push @source_nat, 
            "$DIP_ACTION match destination-port $dst_port\n";
    }
    elsif (/exit/ && $DIP_STATUS == 1 && $DST_IP_STATUS ne 1) { # check the switch, and confirm is on
        push @source_nat, 
            "$DIP_ACTION then source-nat pool $dip_id\n";
        if ($NAT_ICMP == 1) {
            $DIP_ACTION = "$DIP_ACTION-icmp";
            foreach my $tmp_src_addr (@nat_src_addr_icmp) {
                push @source_nat, 
                    "$DIP_ACTION $SADDR $tmp_src_addr\n";
            }
            foreach my $tmp_dst_addr (@nat_dst_addr_icmp) {
                push @source_nat, 
                    "$DIP_ACTION $DADDR $tmp_dst_addr\n";
            }
            push @source_nat,
                "$DIP_ACTION match protocol icmp\n". 
                "$DIP_ACTION then source-nat pool $dip_id\n";
        }
        $NAT_ICMP = 0;
        $DIP_STATUS = 0; # turn off the switch
        undef @nat_src_addr_icmp;
        undef @nat_dst_addr_icmp;
    }
    elsif (/exit/ && $DIP_STATUS == 1 && $DST_IP_STATUS eq 1) { # check the switch, and confirm is on
        push @source_nat, 
            "$DIP_ACTION then source-nat pool $dip_id\n";
        push @destination_nat, 
            "$DST_IP_ACTION then destination-nat pool host_$dst_pool_name\n";
        if ($NAT_ICMP == 1) {
            $DIP_ACTION = "$DIP_ACTION-icmp";
            $DST_IP_ACTION = "$DST_IP_ACTION-icmp";
            foreach my $tmp_src_addr (@nat_src_addr_icmp) {
                push @source_nat, 
                    "$DIP_ACTION $SADDR $tmp_src_addr\n";
                push @destination_nat,
                    "$DST_IP_ACTION $SADDR $tmp_src_addr\n";
            }
            foreach my $tmp_dst_addr (@nat_dst_addr_icmp) {
                push @source_nat, 
                    "$DIP_ACTION $DADDR $dst_address\n";
                push @destination_nat,
                    "$DST_IP_ACTION $DADDR $tmp_dst_addr\n";
            }
            push @source_nat,
                "$DIP_ACTION match protocol icmp\n". 
                "$DIP_ACTION then source-nat pool $dip_id\n";
            push @destination_nat, 
                "$DST_IP_ACTION match protocol icmp\n".
                "$DST_IP_ACTION then destination-nat pool host_$dst_pool_name\n";
        }
        $NAT_ICMP = 0;
        $DIP_STATUS = 0; # turn off the switch
        #$DST_IP_STATUS = 0; # turn off the switch
        undef @nat_src_addr_icmp;
        undef @nat_dst_addr_icmp;
    }
    elsif (/\bdst ip\b/ && !/\bGlobal\b/ && $DST_IP_STATUS == 0) {
        $DST_IP_STATUS = 1;
        local $src_zone;
        local $dst_ip_id;
        local $src_address;
        local $dst_address;
        local $dst_port;
        ($dst_ip_id, $src_zone, $src_address, $dst_address, $dst_port, $dst_real_address_temp) 
            = (split/\s+/)[3, 5, 8, 9, 10, 14];
        $dst_real_address = $dst_real_address_temp;
        $dst_real_address_temp =~ s!\.!_!g;
        $dst_pool_name = $dst_real_address_temp;
        $dst_port =~ s/\D+[_-]//g;
        $src_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        $dst_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_src_addr_icmp, $src_address;
        push @nat_dst_addr_icmp, $dst_address;
        if ($dst_port eq "ping") {
            $NAT_ICMP = 1;
        }
        push @destination_nat, 
            "$CMD_NAT destination pool host_$dst_pool_name " .
            "address $dst_real_address\n"
            ;
        $DST_IP_ACTION 
            = "$CMD_NAT destination rule-set $src_zone rule dst-$dst_ip_id";
        push @destination_nat_zone, 
            "$CMD_NAT destination rule-set $src_zone from zone $src_zone\n";
        push @destination_nat, 
            "$DST_IP_ACTION $SADDR $src_address\n";
        push @destination_nat, 
            "$DST_IP_ACTION $DADDR $dst_address\n";
        push @destination_nat, 
            "$DST_IP_ACTION $DST_PORT $dst_port\n";
    }
    elsif ($length == 3 && /\bsrc-address\b/ && $DST_IP_STATUS == 1) {
        local $src_address = (split/\s+/)[2];
        $src_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_src_addr_icmp, $src_address;
        push @destination_nat, 
            "$DST_IP_ACTION $SADDR $src_address\n";
    }
    elsif ($length == 3 && /\bdst-address\b/ && $DST_IP_STATUS == 1) {
        local $dst_address = (split/\s+/)[-1];
        $dst_address =~ 
            s/(?:\D+[_-]){1,}(\d{1,3}(?:\.\d{1,3}){3})/$1/g;
        push @nat_dst_addr_icmp, $dst_address;
        push @destination_nat, 
            "$DST_IP_ACTION $DADDR $dst_address\n";
    }
    elsif ($length == 3 && /\bservice\b/ && $DST_IP_STATUS == 1) {
        local $dst_port = (split/\s+/)[2];
        $dst_port =~ s/\D+[_-]//g;
        if ($dst_port eq "ping") {
            $NAT_ICMP = 1;
        }
        push @destination_nat, 
            "$DST_IP_ACTION $DST_PORT $dst_port\n";
    }
    elsif (/exit/ && $DST_IP_STATUS == 1) { # check the switch, and confirm is on
        push @destination_nat, 
            "$DST_IP_ACTION then destination-nat pool host_$dst_pool_name\n";
        if ($NAT_ICMP == 1) {
            $DST_IP_ACTION = "$DST_IP_ACTION-icmp";
            foreach my $tmp_src_addr (@nat_src_addr_icmp) {
                #        push @source_nat,
                #    "$DIP_ACTION $SADDR $tmp_src_addr\n";
                push @destination_nat,
                    "$DST_IP_ACTION $SADDR $tmp_src_addr\n";
            }
            foreach my $tmp_dst_addr (@nat_dst_addr_icmp) {
                #        push @source_nat, 
                #    "$DIP_ACTION $DADDR $tmp_dst_addr\n";
                push @destination_nat,
                    "$DST_IP_ACTION $DADDR $tmp_dst_addr\n";
            }
            push @destination_nat, 
                "$DST_IP_ACTION match protocol icmp\n".
                "$DST_IP_ACTION then destination-nat pool host_$dst_pool_name\n";
        }
        $NAT_ICMP = 0;
        #$DST_IP_STATUS = 0; # turn off the switch
        undef @nat_src_addr_icmp;
        undef @nat_dst_addr_icmp;
    }
    #set policy, the most important part
    if (/set policy id/ && /from/ && !/\bGlobal\b/) {
        $POLICY_STATUS = 1; # add an switch for the action statement
        if (/\bschedule\b/) {
            if (/\blog\b/) {
                local ($policy_id, $src_zone, $dst_zone, $scheduler_name) 
                    = (split/\s+/)[3, 5, 7, -2];
                print "set $CMD_POLICY $src_zone $TO_ZONE $dst_zone policy " .
                    "$src_zone-to-$dst_zone-$policy_id scheduler-name $scheduler_name\n"
            }
            else {
                local ($policy_id, $src_zone, $dst_zone, $scheduler_name) 
                    = (split/\s+/)[3, 5, 7, -1];
                print "set $CMD_POLICY $src_zone $TO_ZONE $dst_zone policy " .
                    "$src_zone-to-$dst_zone-$policy_id scheduler-name $scheduler_name\n"
            } 
        }
        local ($policy_id, $src_zone, $dst_zone, $src_addr, $dst_addr, $service) 
            = (split/\s+/)[3, 5, 7, 8, 9, 10];
        $dst_addr    =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
        local $nat_test_ip   = $&;
        if (exists $mip_address_pairs{ $nat_test_ip }) {
            $MIP_EXIST = 1;
            $dst_addr = "Host_$mip_address_pairs{ $nat_test_ip }";
        }
        elsif (/\bdst ip\b/ && $MIP_EXIST == 0) { 
            # set dst ip address-book
            $dst_addr = "host_$dst_real_address";
            push @dst_ip_address_books, 
                "set security zones security-zone $dst_zone " .
                "address-book address $dst_addr $dst_real_address\n"
                ;
        }
        elsif (/\bdst ip\b/ && $MIP_EXIST == 1) { 
            # set dst ip address-book
            $dst_real_addr = "host_$dst_real_address";
            push @dst_ip_address_books, 
                "set security zones security-zone $dst_zone " .
                "address-book address $dst_real_addr $dst_real_address\n"
                ;
        }
        $service =~ s!\/!-!g;
        $SET_POLICY 
            = "set $CMD_POLICY $src_zone $TO_ZONE $dst_zone policy " .
              "$src_zone-to-$dst_zone-$policy_id"
              ;
        $DISABLE_POLICY 
            = "deactive $CMD_POLICY $src_zone $TO_ZONE $dst_zone policy " .
              "$src_zone-to-$dst_zone-$policy_id"
              ;
        print "$SET_POLICY $SADDR $src_addr\n";
        print "$SET_POLICY $DADDR $dst_addr\n";
        print "$SET_POLICY $APP $service\n";
        if (/[Pp]ermit/ && /log/) {
            $POLICY_ACTION 
                = "$SET_POLICY then permit\n" .
                #"$SET_POLICY then log session-init\n" .
                  "$SET_POLICY then log session-close\n"
                  ;
        }
        elsif (/[Dd]eny/ && /log/) {
            $POLICY_ACTION 
                = "$SET_POLICY then deny\n" .
                  "$SET_POLICY then log session-init\n" 
                  ;
                  #"$SET_POLICY then log session-close\n"
        }
        elsif (/[Pp]ermit/) {
            $POLICY_ACTION = "$SET_POLICY then permit\n";
        }
        elsif (/[Dd]eny/) {
            $POLICY_ACTION = "$SET_POLICY then deny\n";
        }
        next;
    }
    #    elsif (/set policy id/ && /from/ && /\bname\b/ && !/\bGlobal\b/) {
    #        $POLICY_STATUS = 1; # add an switch for the action statement
    #        local ($policy_id, $src_zone, $dst_zone, $src_addr, $dst_addr, $service) 
    #            = (split/\s+/)[3, 7, 9, 10, 11, 12];
    #        if (/\bdst ip\b/ && $DST_IP_STATUS == 1) { # set dst ip address-book
    #            $dst_addr = "host_$dst_real_address";
    #            push @dst_ip_address_books, 
    #                "set security zones security-zone $dst_zone " .
    #                "address-book address $dst_addr $dst_real_address\n"
    #                ;
    #        }
    #        $service =~ s!\/!-!g;
    #        $SET_POLICY = 
    #            "set $CMD_POLICY $src_zone $TO_ZONE $dst_zone policy " .
    #            "$src_zone-to-$dst_zone-$policy_id"
    #            ;
    #        $DISABLE_POLICY 
    #            = "deactive $CMD_POLICY $src_zone $TO_ZONE $dst_zone policy " .
    #              "$src_zone-to-$dst_zone-$policy_id"
    #              ;
    #        print "$SET_POLICY $SADDR $src_addr\n";
    #        print "$SET_POLICY $DADDR $dst_addr\n";
    #        print "$SET_POLICY $APP $service\n";
    #        if (/[Pp]ermit/ && /log/) {
    #            $POLICY_ACTION 
    #                = "$SET_POLICY then permit\n" .
    #                  "$SET_POLICY then log session-init\n" .
    #                  "$SET_POLICY then log session-close\n"
    #                  ;
    #        }
    #        elsif (/[Dd]eny/ && /log/) {
    #            $POLICY_ACTION  
    #                = "$SET_POLICY then deny\n" .
    #                  "$SET_POLICY then log session-init\n" .
    #                  "$SET_POLICY then log session-close\n"
    #                  ;
    #        }
    #        elsif (/[Pp]ermit/) {
    #            $POLICY_ACTION = "$SET_POLICY then permit\n";
    #        }
    #        elsif (/[Dd]eny/) {
    #            $POLICY_ACTION = "$SET_POLICY then deny\n";
    #        }
    #        next;
    #    }
    elsif (/set policy id/ && /from/ && /\bGlobal\b/) {
        $GLOBAL_POLICY_STATUS = 1;
        my ($policy_id,  $src_zone,  $dst_zone, $src_addr, $dst_addr, $service) 
            = (split/\s+/)[3, 5, 7, 8, 9, 10];
        $policy_id_icmp = $policy_id;
        $src_zone_icmp = $src_zone;
        push @global_src_address, $src_addr;
        $service =~ s!\/!-!g;
        push @global_services, $service;
        if ($src_zone eq "Global") {
            #            my $src_real_zone = return_ip_zone($src_addr);
            #            if (/\bdst ip\b/ && $DST_IP_STATUS == 1) { 
            #                # set dst ip address-book
            #                $dst_addr = "host_$dst_real_address";
            #                push @dst_ip_address_books, 
            #                    "set security zones security-zone $dst_zone " .
            #                    "address-book address $dst_addr $dst_real_address\n"
            #                    ;
            #            }
            #            $service =~ s!\/!-!g;
            #                   #local $src_address_book = $src_addr;
            #                    #$src_address_book =~ 
            #                    #    s/(?:\D+[_-]){1,}([0-9]{1,3}(?:\.[0-9]{1,3}){3})/$1/g;
            #                    #$GLOBAL_ADDRESS_BOOKS 
            #                    #    = "$CMD_ZONE $src_real_zone address-book address";
            #            $SET_POLICY 
            #                = "set $CMD_POLICY $src_real_zone $TO_ZONE $dst_zone " .
            #                  "policy $src_real_zone-to-$dst_zone-$policy_id"
            #                  ;
            #                          #push @global_policy, $SET_POLICY;
            #                          #push @global_disable_policy, 
            #                          #"deactive $CMD_POLICY $real_zone $TO_ZONE $dst_zone " .
            #                          #"policy $real_zone-to-$dst_zone-$policy_id"
            #                          #;
            #                          #push @global_address_books, 
            #                          #"$GLOBAL_ADDRESS_BOOKS $src_addr $src_address_book\n";
            #            print "$SET_POLICY $SADDR $src_addr\n";
            #            print "$SET_POLICY $DADDR $dst_addr\n";
            #            print "$SET_POLICY $APP $service\n";
            #            if (/[Pp]ermit/ && /log/) {
            #                push @global_policy_action, 
            #                    "$SET_POLICY then permit\n" .
            #                    "$SET_POLICY then log session-init\n".
            #                    "$SET_POLICY then log session-close\n"
            #                    ;
            #            }
            #            elsif (/[Dd]eny/ && /log/) {
            #                push @global_policy_action, 
            #                     "$SET_POLICY then deny\n" .
            #                     "$SET_POLICY then log session-init\n" .
            #                     "$SET_POLICY then log session-close\n"
            #                     ;
            #            }
            #            elsif (/[Pp]ermit/) {
            #                push @global_policy_action, 
            #                     "$SET_POLICY then permit\n";
            #            }
            #            elsif (/[Dd]eny/) {
            #                push @global_policy_action, 
            #                     "$SET_POLICY then deny\n";
            #            }
        }
        else {
            if ($dst_addr eq "any") {
                for my $real_zone (@global_zones) {
                    if ($real_zone ne $src_zone) {
                        push @dst_real_zones, $real_zone;
                    }
                }
            }
            elsif (/\bdst ip\b/ && $DST_IP_STATUS == 1) { 
                $dst_addr    =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
                local $nat_test_ip   = $&;
                if (exists $mip_address_pairs{ $nat_test_ip }) {
                    $MIP_EXIST = 1;
                    $dst_addr = "Host_$mip_address_pairs{ $nat_test_ip }";
                    $dst_real_zone = return_ip_zone($dst_addr);
                }
                elsif ($MIP_EXIST == 0) { 
                    $dst_addr = "host_$dst_real_address";
                    $dst_real_zone = return_ip_zone($dst_addr);
                    push @dst_ip_address_books, 
                        "set security zones security-zone $dst_real_zone " .
                        "address-book address $dst_addr " .
                        "$dst_real_address\n"
                        ;
                }
                elsif ($MIP_EXIST == 1) { 
                    $dst_real_addr = "host_$dst_real_address";
                    $dst_real_zone = return_ip_zone($dst_real_addr);
                    push @dst_ip_address_books, 
                        "set security zones security-zone $dst_real_zone " .
                        "address-book address $dst_real_addr " .
                        "$dst_real_address\n"
                        ;
                }
            }
            else {
                #print "dst addr is $dst_addr\n";
                $dst_addr    =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
                local $nat_test_ip   = $&;
                #print "nat test ip is $nat_test_ip\n";
                if (exists $mip_address_pairs{ $nat_test_ip }) {
                    $dst_addr = "Host_$mip_address_pairs{ $nat_test_ip }";
                }
                #print "dst addr is $dst_addr\n";
                $dst_real_zone = return_ip_zone($dst_addr);
            }
            if (@dst_real_zones) {
                foreach my $dst_real_zone (@dst_real_zones) {
                    #print "dst real zone no empty, dst addr is $dst_addr\ndst real zone is $dst_real_zone\n";
                    $SET_POLICY =
                        "set $CMD_POLICY $src_zone $TO_ZONE $dst_real_zone " .
                        "policy $src_zone-to-$dst_real_zone-$policy_id"
                        ;
                    push @global_policy, $SET_POLICY;
                    push @global_disable_policy,
                        "deactive $CMD_POLICY $src_zone $TO_ZONE $dst_real_zone " .
                        "policy $src_zone-to-$dst_real_zone-$policy_id\n"
                        ;
                    push @global_dst_address, "any";
                        #print "$SET_POLICY $SADDR $src_addr\n";
                        #print "$SET_POLICY $DADDR $dst_addr\n";
                        #print "$SET_POLICY $APP $service\n";
                    if (/[Pp]ermit/ && /log/) {
                        push @global_policy_action, 
                            "$SET_POLICY then permit\n" .
                            #"$SET_POLICY then log session-init\n" .
                            "$SET_POLICY then log session-close\n"
                            ;
                    }
                    elsif (/[Dd]eny/ && /log/) {
                        push @global_policy_action, 
                            "$SET_POLICY then deny\n" .
                            "$SET_POLICY then log session-init\n" 
                            ;
                            #"$SET_POLICY then log session-close\n"
                    }
                    elsif (/[Pp]ermit/) {
                        push @global_policy_action, 
                            "$SET_POLICY then permit\n";
                    }
                    elsif (/[Dd]eny/) {
                        push @global_policy_action, 
                            "$SET_POLICY then deny\n";
                    }
                }
            }
            else { 
                #print "dst addr is $dst_addr\ndst real zone is $dst_real_zone\n";
                local $dst_address_book = $dst_addr;
                $dst_address_book =~ 
                    s#(?:\D+[_-]?){0,}(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{0,2})?)#$1#g;
                $GLOBAL_ADDRESS_BOOKS 
                    = "$CMD_ZONE $dst_real_zone address-book address";
                $SET_POLICY =
                    "set $CMD_POLICY $src_zone $TO_ZONE $dst_real_zone " .
                    "policy $src_zone-to-$dst_real_zone-$policy_id"
                    ;
                push @global_policy, $SET_POLICY;
                push @global_disable_policy,
                    "deactive $CMD_POLICY $src_zone $TO_ZONE $dst_real_zone " .
                    "policy $src_zone-to-$dst_real_zone-$policy_id\n"
                    ;
                push @global_address_books, 
                    "$GLOBAL_ADDRESS_BOOKS $dst_addr $dst_address_book\n"
                    ;
                push @global_dst_address, $dst_addr;
                      #print "$SET_POLICY $SADDR $src_addr\n";
                      #push @service, $service;
                      #print "$SET_POLICY $DADDR $dst_addr\n";
                #print "$SET_POLICY $APP $service\n";
                if (/[Pp]ermit/ && /log/) {
                    push @global_policy_action, 
                        "$SET_POLICY then permit\n" .
                        #"$SET_POLICY then log session-init\n" .
                        "$SET_POLICY then log session-close\n"
                        ;
                }
                elsif (/[Dd]eny/ && /log/) {
                    push @global_policy_action, 
                        "$SET_POLICY then deny\n" .
                        "$SET_POLICY then log session-init\n" 
                        #"$SET_POLICY then log session-close\n"
                        ;
                }
                elsif (/[Pp]ermit/) {
                    push @global_policy_action, 
                        "$SET_POLICY then permit\n";
                }
                elsif (/[Dd]eny/) {
                    push @global_policy_action, 
                        "$SET_POLICY then deny\n";
                }
            }
        }
        next;
    }
    elsif (/set policy id/ && /disable/ && $GLOBAL_POLICY_STATUS == 0) {
        $POLICY_ACTION 
            = "$POLICY_ACTION\n" .
              "$DISABLE_POLICY\n"
              ;
        next;
    }
    elsif ($length == 3 && /src-address/ && $GLOBAL_POLICY_STATUS == 0) {
        my $src_addr = (split/\s+/)[-1];
        print "$SET_POLICY $SADDR $src_addr\n";
        next;
    }
    elsif ($length == 3 && /dst-address/ && $DST_IP_STATUS == 0 && $GLOBAL_POLICY_STATUS == 0) {
        my $dst_addr = (split/\s+/)[-1];
        $dst_addr    =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
        local $nat_test_ip   = $&;
        if (exists $mip_address_pairs{ $nat_test_ip }) {
            $dst_addr = "Host_$mip_address_pairs{ $nat_test_ip }";
        }
        print "$SET_POLICY $DADDR $dst_addr\n";
        next;
    }
    elsif ($length == 3 && /dst-address/ && $DST_IP_STATUS == 1 && $GLOBAL_POLICY_STATUS == 0) {
        my $dst_addr = (split/\s+/)[-1];
        $dst_addr    =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
        local $nat_test_ip   = $&;
        if (exists $mip_address_pairs{ $nat_test_ip }) {
            $dst_addr = "Host_$mip_address_pairs{ $nat_test_ip }";
            print "$SET_POLICY $DADDR $dst_addr\n";
        }
        else {
            print "$SET_POLICY $DADDR host_$dst_real_address\n";
        }
        next;
    }
    elsif ($length == 3 && /service/ && $GLOBAL_POLICY_STATUS == 0) {
        my $service = (split/\s+/)[-1];
        $service =~ s!\/!-!g;
        print "$SET_POLICY $APP $service\n";
        next;
    }
    elsif (/exit/ && $POLICY_STATUS == 1 && $GLOBAL_POLICY_STATUS == 0) { # check the switch, and confirm is on
        print "$POLICY_ACTION";
        $POLICY_STATUS = 0; # turn off the switch
        $DST_IP_STATUS = 0; # turn off the switch
        $MIP_EXIST     = 0;
        next;
    }
    elsif (/set policy id/ && /disable/ && $GLOBAL_POLICY_STATUS == 1) {
        $POLICY_ACTION 
            = "$POLICY_ACTION\n" .
              "$DISABLE_POLICY\n"
              ;
        next;
    }
    elsif ($length == 3 && /src-address/ && $GLOBAL_POLICY_STATUS == 1) {
        my $src_addr = (split/\s+/)[-1];
        push @global_src_address, $src_addr;
        next;
    }
    elsif ($length == 3 && /dst-address/ && $DST_IP_STATUS == 0 && $GLOBAL_POLICY_STATUS == 1) {
        my $dst_addr = (split/\s+/)[-1];
        if (!@dst_real_zones) {
            #print "enter sub dst addr, dst is $dst_addr\n";
            $dst_addr    =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
            local $nat_test_ip   = $&;
            if (exists $mip_address_pairs{ $nat_test_ip }) {
               $dst_addr = "Host_$mip_address_pairs{ $nat_test_ip }";
            } 
            $dst_real_zone = return_ip_zone($dst_addr);
            local $dst_address_book = $dst_addr;
            $dst_address_book =~ 
                 s#(?:\D+[_-]){0,}(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{0,2})?)#$1#g;
            $GLOBAL_ADDRESS_BOOKS 
                 = "$CMD_ZONE $dst_real_zone address-book address";
            $SET_POLICY 
                 = "set $CMD_POLICY $src_zone_icmp $TO_ZONE $dst_real_zone " .
                   "policy $src_zone_icmp-to-$dst_real_zone-$policy_id_icmp"
                   ;
            push @global_policy, $SET_POLICY;
            push @global_disable_policy,
                 "deactive $CMD_POLICY $src_zone_icmp $TO_ZONE $dst_real_zone " .
                 "policy $src_zone_icmp-to-$dst_real_zone-$policy_id_icmp\n"
                 ;
            push @global_address_books, 
                 "$GLOBAL_ADDRESS_BOOKS $dst_addr $dst_address_book\n"
                 ;
            push @global_dst_address, $dst_addr;
        }
        next;
    }
    elsif ($length == 3 && /dst-address/ && $DST_IP_STATUS == 1 && $GLOBAL_POLICY_STATUS == 1) {
        my $dst_addr = (split/\s+/)[-1];
        if (!@dst_real_zones) {
            $dst_addr    =~ /(\d{1,3}(?:\.\d{1,3}){3})/;
            local $nat_test_ip   = $&;
            if (exists $mip_address_pairs{ $nat_test_ip }) { #dst address is mip address
               $dst_addr = "Host_$mip_address_pairs{ $nat_test_ip }";
               $dst_real_zone = return_ip_zone($dst_addr);
               local $dst_address_book = $dst_addr;
               $dst_address_book =~ 
                   s#(?:\D+[_-]){0,}(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{0,2})?)#$1#g;
               $GLOBAL_ADDRESS_BOOKS 
                   = "$CMD_ZONE $dst_real_zone address-book address";
               $SET_POLICY 
                   = "set $CMD_POLICY $src_zone_icmp $TO_ZONE $dst_real_zone " .
                     "policy $src_zone_icmp-to-$dst_real_zone-$policy_id_icmp"
                     ;
               push @global_policy, $SET_POLICY;
               push @global_disable_policy,
                   "deactive $CMD_POLICY $src_zone_icmp $TO_ZONE $dst_real_zone " .
                   "policy $src_zone_icmp-to-$dst_real_zone-$policy_id_icmp\n"
                   ;
               push @global_address_books, 
                   "$GLOBAL_ADDRESS_BOOKS $dst_addr $dst_address_book\n"
                   ;
               push @global_dst_address, $dst_addr;
            }
            else {                                         #dst address is no mip address
                $dst_real_zone = return_ip_zone($dst_real_address);
                #local $dst_address_book = $dst_real_addr;
                #$dst_address_book =~ 
                #    s#(?:\D+[_-]?){0,}(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{0,2})?)#$1#g;
                #$GLOBAL_ADDRESS_BOOKS 
                #    = "$CMD_ZONE $dst_real_zone address-book address";
                $SET_POLICY 
                    = "set $CMD_POLICY $src_zone_icmp $TO_ZONE $dst_real_zone " .
                      "policy $src_zone_icmp-to-$dst_real_zone-$policy_id_icmp"
                      ;
                push @global_policy, $SET_POLICY;
                push @global_disable_policy,
                    "deactive $CMD_POLICY $src_zone_icmp $TO_ZONE $dst_real_zone " .
                    "policy $src_zone_icmp-to-$dst_real_zone-$policy_id_icmp\n"
                    ;
                    #push @global_address_books, 
                    #"$GLOBAL_ADDRESS_BOOKS $dst_real_addr $dst_address_book\n"
                    #;
                push @global_dst_address, $dst_real_addr;
             } 
        }
        next;
    }
    elsif ($length == 3 && /service/ && $GLOBAL_POLICY_STATUS == 1) {
        my $service = (split/\s+/)[-1];
        $service =~ s!\/!-!g;
        push @global_services, $service;
        next;
    }
    elsif (/exit/ && $GLOBAL_POLICY_STATUS == 1) { # check the switch, and confirm is on
        my @g_policy 
            = do { my %tmp_global_policy;
                grep { !$tmp_global_policy{$_}++ } @global_policy
            }
        ;
        my @tmp_global_dst_address
            = do { my %tmp_global_dst_address;
                grep { !$tmp_global_dst_address{$_}++ } @global_dst_address
            }
        ;
        foreach my $tmp_global_policy (@g_policy) {
            foreach my $tmp_src_address (@global_src_address) {
                print "$tmp_global_policy $SADDR $tmp_src_address\n";
            }
            foreach my $tmp_dst_address (@tmp_global_dst_address) {
                print "$tmp_global_policy $DADDR $tmp_dst_address\n";
            }
            foreach my $tmp_service (@global_services) {
                print "$tmp_global_policy $APP $tmp_service\n";
            }
        }
        print @global_policy_action;
        $GLOBAL_POLICY_STATUS = 0;
        $DST_IP_STATUS        = 0; # turn off the switch
        $MIP_EXIST            = 0;
        undef @g_policy;
        undef @tmp_global_dst_address;
        undef @dst_real_zones;
        undef @global_services;
        undef @global_src_address;
        undef @global_dst_address;
        undef @global_policy;
        undef @global_policy_action;
        undef @global_disable_policy;
        next;
    }
    #elsif (/set route/ && /([0-9]{1,3}\.){3}[0-9]{1,3}/ && /) { # set routes
    elsif (/\bset route\b/ && /\binterface\b/ && /\bgateway\b/) {
        if (/\bpreference\b/) {
            my ($droute, $gateway, $preference) = (split/\s+/)[2, 6, 8];
            print "$CMD_ROUTE $droute next-hop $gateway " .
                  "preference $preference\n";
        }
        else {
            my ($droute, $gateway) = (split/\s+/)[2, 6];
            print "$CMD_ROUTE $droute next-hop $gateway\n";
        }
        next;
    }
    elsif (/\bset route\b/ && /\binterface\b/) {
        if (/\bpreference\b/) {
            my ($droute, $gateway, $preference) = (split/\s+/)[2, 4, 6];
            print "$CMD_ROUTE $droute next-hop $gateway " .
                  "preference $preference\n";
        }
        else {
            my ($droute, $gateway) = (split/\s+/)[2, 4];
            print "$CMD_ROUTE $droute next-hop $gateway\n";
        }
        next;
    }
    elsif (/\bset route\b/ && /\bgateway\b/) {
        if (/\bpreference\b/) {
            my ($droute, $gateway, $preference) = (split/\s+/)[2, 4, 6];
            print "$CMD_ROUTE $droute next-hop $gateway " .
                  "preference $preference\n";
        }
        else {
            my ($droute, $gateway) = (split/\s+/)[2, 4];
            print "$CMD_ROUTE $droute next-hop $gateway\n";
        }
        next;
    }
}

# the last jobs
END {
    #replace nat port name with port number
    while (my ($junos_app, $real_port_number) = each %srx_application_port_number) {
        map { s/\b$junos_app\b/$real_port_number/g } @destination_nat;
        map { s/\b$junos_app\b/$real_port_number/g } @source_nat;
    }
    #merge all address books
    local @all_address_books_tmp 
        = (@dst_ip_address_books,
           @global_address_books,
           @mip_address_books
        ); 
    #my @source_nat_rule_set_direction = keys { map { $_ => 1 } @source_nat_zone };
    #my @destination_nat_rule_set_direction = keys { map { $_ => 1 } @destination_nat_zone };
    #remove duplicate source and destination nat rule-set condition 
    my @source_nat_rule_set_direction 
        = do { my %tmp_src;
               grep { !$tmp{$_}++ } @source_nat_zone
             }
        ;
    my @destination_nat_rule_set_direction 
        = do { my %tmp_dst;
               grep { !$tmp{$_}++ } @destination_nat_zone 
             }
        ;
    local @all_address_books 
        = do { my %tmp_all_address_books;
               grep { !$tmp_all_address_books{$_}++ } 
               @all_address_books_tmp
             }
        ;
    @source_nat 
        = grep !/\bdestination-port ping\b/, @source_nat;
    @destination_nat
        = grep !/\bdestination-port ping\b/, @destination_nat;
    foreach (@source_nat) {
        $_ =~ s!\bany\b!0.0.0.0/0!g;
    }
    foreach (@destination_nat) {
        $_ =~ s!\bany\b!0.0.0.0/0!g;
    }
    print @source_nat_rule_set_direction;
    print @source_nat;
    print @destination_nat_rule_set_direction;
    print @destination_nat;
    print @all_address_books;
    print "set applications application traceroute-icmp term t1 protocol icmp\n";
    print "set applications application traceroute-icmp term t1 icmp-type 8\n";
    print "set applications application traceroute-icmp term t1 icmp-code 0\n";
    print "set applications application traceroute-udp term t1 protocol udp\n";
    print "set applications application traceroute-udp term t1 destination-port 33400-34000\n";
    print "set applications application SNMP term 1 protocol udp\n";
    print "set applications application SNMP term 1 destination-port 161-162\n";
    print "set applications application SNMP term 1 inactivity-timeout 30\n";
    print "set applications application SNMP term 2 protocol tcp\n";
    print "set applications application SNMP term 2 destination-port 161-162\n";
    print "set applications application SNMP term 2 inactivity-timeout 30\n";
    print "set applications application DNS term t1 alg dns\n";
    print "set applications application DNS term t1 protocol udp\n";
    print "set applications application DNS term t1 destination-port 53\n";
    print "set applications application DNS term t2 alg dns\n";
    print "set applications application DNS term t2 protocol tcp\n";
    print "set applications application DNS term t2 destination-port 53\n";
    print "set applications application-set TRACEROUTE application traceroute-icmp\n";
    print "set applications application-set TRACEROUTE application traceroute-udp\n";
}
