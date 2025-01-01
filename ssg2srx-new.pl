#!/usr/bin/perl

# use Cwd 'abs_path';
# use Excel::Writer::XLSX;
use strict;
use Switch;
use warnings;
use NetAddr::IP;
use Net::IP::LPM;
use Getopt::Long;
use File::Basename;
use Spreadsheet::Read;
use Lingua::Han::PinYin;
use DateTime::Format::Flexible;
use Data::Dumper   qw(Dumper);
use Regexp::Common qw(net time);

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# rewrite ssg2srx.pl                                                                        #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# 定义变量
my $workbook;                   # 保存excel文件
my $worksheet;                  # 保存excel文件中的工作表
my $excel_row = 0;              # excel对比文件行数
my $lpm;                        # 用于查找ip所在zone
my @ssg_config_file;            # 保存ssg配置文件，不赋值，否则正文循环时会清空配置
my @ssg_policy_context = ();    # 临时保存ssg策略单条策略内容
my %lpm_pairs;                  # 保存接口与zone的映射关系，用于设置路由下一跳为接口时对应zone
my %services;                   # 保存ssg服务名与srx服务名的映射关系

# 保存命令选项值
our ( $opt_c, $opt_d, $opt_o, $opt_s ) = ();

# 保存ssg接口与srx接口和zone的映射关系
my %zones_interfaces;

# 保存ssg接口和ip映射关系, tunnel接口设置源时需要
my %ssg_interface_ip;

# 保存ssg接口和srx接口映射关系, tunnel接口设置unnumbered-address时需要
my %ssg_srx_interface;

# 保存static nat的虚地址和实际地址
my %mip_address_pairs;

# 保存source nat的id和pool
my %dip_pool;

# 保存每个zone的MIP规则id
my %RULE_NUM;

my %srx_application_port_number = (
    http     => 80,
    https    => 443,
    ftp      => 21,
    ssh      => 22,
    mail     => 25,
    telnet   => 23,
    Terminal => 3389,
    SNMP     => "161 to 162",
);

# 使用方法
sub usage {
    my $err = shift and select STDERR;
    print
"usage: $0 [-c ssg_config_file] [-d compare_file] [-o file] [-s srx_to_ssg_service_mapping_table.xlsx] ssg_file\n",
      "\t-c --config    file        ssg configuration file\n",
      "\t-d --compare   file        ssg and srx configuration compare file\n",
      "\t-o --output    file        srx configuration output file\n",
      "\t-s --service   file        ssg to srx service mapping file\n",
      "\t-h --help                  print usage\n";
    exit $err;
}

# 设置zone与interface的映射关系
sub set_zone_interface {
    my ( $ssg_interface, $zone, $tag ) = ();

    # 删除双引号,split后ssg接口和zone还是会多出双引号,故禁用
    # $ssg_config_line =~ s{"}{}g;

    if ( /\d+\.\d+/ && /\btag\b/ ) {
        ( $ssg_interface, $tag, $zone ) =
          ( split /\s+/ )[ 2, 4, 6 ];
        print
          "Please enter a replacement of $ssg_interface with vlan tag $tag:";
    }
    else {
        ( $ssg_interface, $zone ) =
          ( split /\s+/ )[ 2, 4 ];
        print "Please enter a replacement of $ssg_interface:";
    }

    # 删除双引号,前处split后ssg接口和zone会多出双引号,
    # 导致set_interface_ip_zone函数不能正确取出srx接口
    $ssg_interface =~ s{"}{}g;
    $zone          =~ s{"}{}g;

    chomp( my $srx_interface = <STDIN> );          # 用户输入新的srx接口
    push @{ $zones_interfaces{$zone} }, { $ssg_interface => $srx_interface };
    $ssg_srx_interface{$ssg_interface} = $srx_interface;
    $lpm_pairs{"$ssg_interface"}       = $zone;    # 接口和zone映射（某些路由的下一跳是ssg接口）

    return $zone;
}

# 设置接口模式
sub set_interface_mode {
    my ($mode) = ( split /\s+/ )[-1];

    # nat模式需要配置源nat
    if ( $mode eq "nat" ) {

    }
}

# 设置interface的ip和zone
sub set_interface_ip_zone {

    my $ssg_config_line = "@_";
    my ( $ssg_interface, $ip ) = ( split /\s+/ )[ 2, -1 ];

# 获取ssg接口和ip
# 循环%zones_interfaces,找到ssg接口对应的srx接口
# print
# "set security zones security-zone $zone host-inbound-traffic system-services all\n";
  START:
    foreach my $zone ( sort keys %zones_interfaces ) {

        # 查找具体zone下的每一个数组，
        # 如果找到ssg接口对应的srx接口则输出相关设置并跳出循环
        foreach my $href ( @{ $zones_interfaces{$zone} } ) {
            if ( exists $href->{$ssg_interface} ) {
                unless ( $href->{$ssg_interface} =~ m{\bgr-0\/0\/0\.\d+\b} )
                {    # 处理非tunnel接口
                    print
"set interfaces $href->{$ssg_interface} family inet address $ip\n";
                    print
"set security zones security-zone $zone interfaces $href->{$ssg_interface}\n";

                    # 将ip绑定到srx接口
                    # my $srx_interface = $href->{$ssg_interface};
                    # $href->{$ssg_interface} = { $srx_interface => $ip };

                    # 将ip绑定到ssg接口的简写方式
                    $href->{$ssg_interface} =
                      { $href->{$ssg_interface} => $ip };
                    $ssg_interface_ip{$ssg_interface} = $ip;

                    $lpm->add( "$ip", "$zone" );    # 添加接口ip和zone映射
                    last START;
                }
                else {                              # 处理tunnel接口
                    if ( $ssg_config_line =~ /\bip unnumbered\b/ ) {
                        print
"set interfaces $href->{$ssg_interface} family inet unnumbered-address $ssg_srx_interface{$ip}\n";
                        last START;
                    }
                    elsif ( $ssg_config_line =~ /\bdst-ip\b/ ) {
                        my ($source) =
                          ( ( split /\s+/ )[-3], $ssg_config_line );
                        if ( $source =~ /$RE{net}{IPv4}/ ) {    # source为ip
                            print "
set interfaces $href->{$ssg_interface} tunnel source $source\n";
                        }
                        else {                                  # source为ssg接口
                            my $source_ip =
                              NetAddr::IP->new( $ssg_interface_ip{$source} );
                            print
"set interfaces $href->{$ssg_interface} tunnel source ",
                              $source_ip->addr;
                        }
                        print "
set interfaces $href->{$ssg_interface} tunnel destination $ip\n";
                        last START;
                    }
                }
            }
        }
    }
}

# 设置路由
sub set_route {
    my @route  = ( split /\s+/ );
    my $length = scalar @route;
    if (   /\bset route\b/
        && /\binterface\b/
        && /\bgateway\b/
        && !/\bsource\b/ )
    {
        if (/\bpreference\b/) {
            my ( $droute, $gateway, $preference ) = ( split /\s+/ )[ 2, 6, 8 ];
            print
"set routing-options static route $droute next-hop $gateway preference $preference\n";
            my $zone = $lpm->lookup("$gateway");
            $lpm->add( "$droute", "$zone" );
        }
        else {
            my ( $droute, $gateway ) = ( split /\s+/ )[ 2, 6 ];
            print
              "set routing-options static route $droute next-hop $gateway\n";
            my $zone = $lpm->lookup("$gateway");
            $lpm->add( "$droute", "$zone" );
        }
    }
    elsif ( /\bset route\b/ && /\bsource\b/ && /\b(interface|gateway)\b/ )
    {    # 源路由(fbf)
        if (/\bin-interface\b/) {    # 基于源接口的路由
            my ( $source_interface, $source, $gateway ) =
              ( split /\s+/ )[ 4, 5, 9 ];
            print
"set firewall family inet filter fbf_$gateway term $source from source-address $source\n";
            print
"set firewall family inet filter fbf_$gateway term $source from source-interface $ssg_srx_interface{source_interface}\n";
        }
        else {                       # 源路由
            my ( $source, $gateway ) = ( split /\s+/ )[ 3, 7 ];
            print
              " set firewall family inet filter fbf_ $gateway term $source from
          source-address $source\n ";
            print
              " set firewall family inet filter fbf_ $gateway term $source then
          next -hop $gateway\n ";
        }
    }
    elsif ( /\bset route\b/ && /\b(interface|gateway)\b/ && $length == 5 ) {
        my ( $droute, $gateway ) = ( split /\s+/ )[ 2, 4 ];
        if ( $gateway =~ /$RE{net}{IPv4}/ ) {    # 下一跳是ip
            print
              " set routing-options static route $droute next -hop $gateway\n ";
            my $zone = $lpm->lookup("$gateway ");
            $lpm->add( "$droute ", "$zone " );
        }
        else {                                   # 下一跳是接口
            my $srx_interface_gateway = $ssg_srx_interface{$gateway};
            print
" set routing-options static route $droute next -hop $srx_interface_gateway\n ";
            my $zone = $lpm_pairs{"$gateway "};
            $lpm->add( "$droute ", "$zone " );
        }
    }
}

# 设置scheduler
sub set_scheduler {
    my @schedulers = split /\s+/;
    switch ( $schedulers[3] ) {
        case (" once ") {
            my $start_date = $schedulers[5];
            my $start_time = $schedulers[6];
            my $stop_date  = $schedulers[8];
            my $stop_time  = $schedulers[9];
            if ( $start_date =~ $RE{time}{mdy} && $stop_date =~ $RE{time}{mdy} )
            {    # ssg使用美式风格时间，srx使用ISO-8601格式时间，但T分隔符需替换成.号
                $start_time = "$start_time : 0 ";    # 补足时间，否则会出现无法解析的错误
                $stop_time  = "$stop_time : 0 ";
                $start_date = DateTime::Format::Flexible->parse_datetime(
                    "$start_date $start_time ");
                $stop_date = DateTime::Format::Flexible->parse_datetime(
                    "$stop_date $stop_time ");
                $start_date =~ s{T}{\.};
                $stop_date  =~ s{T}{\.};
            }
            print " set schedulers scheduler $schedulers[2]
          start-date $start_date stop-date $stop_date\n ";
            return;
        }
        case (" recurrent ") {
            my $some_day   = $schedulers[4];
            my $start_time = $schedulers[6];
            my $stop_time  = $schedulers[8];
            print " set schedulers scheduler $schedulers[2] $some_day start-
          time $start_time stop-time $stop_time \n ";
        }
        return;
    }
}

# 设置地址簿
sub set_address_book {
    my ( $zone, $address_book_name, $ip ) = ( split /\s+/ )[ 2, 3, 4 ];
    $zone =~ s{"}{}g;    #删除双引号
    if ( $zone ne "Global" ) {
        unless ( ( $ip =~ /(?!\s+)$RE{net}{domain}/ ) ) {    # 常规zone地址簿
            my $netmask = ( split /\s+/ )[5];
            print
"set security zones security-zone $zone address-book address $address_book_name "
              . NetAddr::IP->new( $ip, $netmask ) . "\n";
        }
        else {                                               # 匹配域名，支持带空格的域名
            print
"set security zones security-zone $zone address-book address $address_book_name dns-name $ip\n";
        }
    }
    else {                                                   # 全局地址簿
        if ( exists $mip_address_pairs{$ip} ) {              # 检查是否为mip地址
            $ip                = $mip_address_pairs{$ip};
            $address_book_name = "Host_$ip";
        }
        unless ( ( $ip =~ /(?!\s+)$RE{net}{domain}/ ) ) {    # 常规zone地址簿
            my $netmask = ( split /\s+/ )[5];
            $zone = $lpm->lookup("$ip");
            print
"set security zones security-zone $zone address-book address $address_book_name "
              . NetAddr::IP->new( $ip, $netmask ) . "\n";
        }
        else {                                               # 匹配域名，支持带空格的域名
            $zone = $lpm->lookup("0.0.0.0");                 # 域名统一使用默认路由对应的zone
            print
"set security zones security-zone $zone address-book address $address_book_name dns-name $ip\n";
        }
    }
}

# 设置地址集合
sub set_address_set {
    my ( $zone, $address_set_name, $address_book_name ) =
      ( split /\s+/ )[ 3, 4, -1 ];
    $zone =~ s{"}{}g;             #删除双引号
    if ( $zone ne "Global" ) {    # 非全局地址集合
        print
"set security zones security-zone $zone address-book address-set $address_set_name address $address_book_name\n";
    }
    else {                        # 全局地址簿集
        if ( $address_book_name =~ /$RE{net}{IPv4}/ ) {
            my $ip = $&;                               # 匹配到的ip部分赋值给$ip
            if ( exists $mip_address_pairs{$ip} ) {    # 检查是否为mip地址
                $ip                = $mip_address_pairs{$ip};
                $address_book_name = "Host_$ip";
            }
            $zone = $lpm->lookup("$ip");
        }
        elsif ( ( $address_book_name =~ /(?!\s+)$RE{net}{domain}/ ) ) {  # 域名地址簿
            $zone = $lpm->lookup("0.0.0.0");    # 域名统一使用默认路由对应的zone
        }
        print
"set security zones security-zone $zone address-book address-set $address_set_name address $address_book_name\n";
    }
}

# 设置服务
sub set_service {
    my ( $service_name, $protocol, $sport, $dport ) =
      ( split /\s+/ )[ 2, 4, 6, 8 ];
    $service_name =~ s{\/}{-}g;
    print
"set applications application $service_name term $protocol\_$dport protocol $protocol source-port $sport destination-port $dport\n";
}

# 设置服务集合
sub set_service_set {
    my ( $service_group_name, $service ) = ( split /\s+/ )[ 3, -1 ];
    $service            =~ s{\/}{-}g;
    $service_group_name =~ s{\/}{-}g;
    print
"set applications application-set $service_group_name application $service\n";
}

# 设置screen
sub set_screen {
    my ( $zone, $screen_name ) = ( split /\s+/ )[ 2, 4 ];
    if ( $screen_name eq "tear-drop" ) {
        print "set security screen ids-option $zone ip tear-drop\n";
    }
    elsif ( $screen_name eq "syn-flood" ) {
        print "set security screen ids-option $zone tcp syn-flood\n";
    }
    elsif ( $screen_name eq "ping-death" ) {
        print "set security screen ids-option $zone icmp ping-death\n";
    }
    elsif ( $screen_name eq "ip-filter-src" ) {
        print "set security screen ids-option $zone ip tear-drop\n";
    }
    elsif ( $screen_name eq "land" ) {
        print "set security screen ids-option $zone tcp land\n";
    }
}

# 设置静态nat
sub set_mip {

    # 获取MIP绑定的接口，实部和虚部地址以及子网掩码
    my ( $ssg_interface, $virtual_ip, $real_ip, $netmask ) =
      ( split /\s+/ )[ 2, 4, 6, -3 ];
    $ssg_interface =~ s{"}{}g;
    foreach my $zone ( sort keys %zones_interfaces ) {
        foreach my $href ( @{ $zones_interfaces{$zone} } ) {
            if ( exists $href->{$ssg_interface}
                && ( $netmask eq "255.255.255.255" ) )    # MIP为单个ip
            {
                my $tag               = "host";
                my $tmp_srx_interface = $ssg_srx_interface{$ssg_interface};
                $tmp_srx_interface =~ s/\./_/;
                print
"set security nat static rule-set $zone\_$tmp_srx_interface rule $zone\_$RULE_NUM{$zone}  match destination-address $virtual_ip\n";
                print
"set security nat static rule-set $zone\_$tmp_srx_interface rule $zone\_$RULE_NUM{$zone} then static-nat prefix $real_ip\n";
                $RULE_NUM{$zone}++;
                $mip_address_pairs{"$virtual_ip"} = $real_ip;
                return $virtual_ip, $real_ip, $tag;
            }
            elsif ( exists $href->{$ssg_interface}
                && ( $netmask ne "255.255.255.255" ) )    # MIP为子网
            {
                my $tag               = "net";
                my $tmp_srx_interface = $ssg_srx_interface{$ssg_interface};
                $tmp_srx_interface =~ s/\./_/;

                # 重构地址形式
                $virtual_ip = NetAddr::IP->new( $virtual_ip, $netmask );
                $real_ip    = NetAddr::IP->new( $real_ip,    $netmask );
                print
"set security nat static rule-set $zone\_$tmp_srx_interface rule $zone\_$RULE_NUM{$zone}  match destination-address $virtual_ip\n";
                print
"set security nat static rule-set $zone\_$tmp_srx_interface rule $zone\_$RULE_NUM{$zone} then static-nat prefix $real_ip\n";
                $RULE_NUM{$zone}++;
                $mip_address_pairs{"$virtual_ip"} = $real_ip;
                return $virtual_ip, $real_ip, $tag;
            }
        }
    }
}

# 设置源nat(dip)
sub set_dip {
    my ( $dip_id, $start_dip_address, $stop_dip_address ) = ();
    my $ssg_config_line = "@_";

    # dip配置分为常规和ext两种模式
    if ( $ssg_config_line =~ /\bext\b/ ) {    # ext模式
        ( $dip_id, $start_dip_address, $stop_dip_address ) =
          ( split /\s+/ )[ 8, -2, -1 ];
    }
    else {                                    # 常规模式
        ( $dip_id, $start_dip_address, $stop_dip_address ) =
          ( split /\s+/ )[ 4, -2, -1 ];
    }
    if ( $ssg_config_line =~ /\bfix-port\b/ ) {
        $dip_pool{$dip_id} =
          ("$start_dip_address to $stop_dip_address fix-port");    # 不进行端口转换
    }
    else {
        $dip_pool{$dip_id} = ("$start_dip_address to $stop_dip_address");
    }
}

# 设置目的nat(virtual ip)
sub set_vip {

}

# 设置源nat, 策略中的nat src
sub set_nat_src {
    my (
        $nat_src_policy_id, $nat_src_zone, $nat_dst_zone,
        @nat_src_address,   @nat_src_dst_address
    ) = @_;

}

# 设置目的nat, 策略中的nat src
sub set_nat_dst {
    my (
        $policy_id,       $nat_src_zone, $dst_real_ip,
        $nat_src_address, $nat_dst_address
    ) = @_;
    my ( $tmp_dst_real_ip, $pool_name ) = ();

    $tmp_dst_real_ip = $dst_real_ip;
    $tmp_dst_real_ip =~ tr{\.}{_};
    $pool_name = "dst-pool-$tmp_dst_real_ip";
    print
"set security nat destination rule-set $nat_src_zone from zone $nat_src_zone\n";
    print "set security nat destination pool $pool_name address $dst_real_ip\n";

    # 控制源地址和目的地址数量，junos nat中每条rule最多支持8个源和目的地址
    for ( my $n = 0 ; $n <= ( scalar @$nat_src_address ) / 8 ; $n++ ) {
        for (
            my $i = 0 ;
            ( $n * 8 + $i ) < scalar @$nat_src_address && $i <= 7 ;
            $i++
          )
        {
            print
"set security nat destination rule-set $nat_src_zone rule dst-$policy_id-$n match source-address $nat_src_address->[$n*8+$i]\n";
        }
        for ( my $x = 0 ; $x <= ( scalar @$nat_dst_address ) / 8 ; $x++ ) {
            for (
                my $y = 0 ;
                ( $x * 8 + $y ) < scalar @$nat_dst_address && $y <= 7 ;
                $y++
              )
            {
                print
"set security nat destination rule-set $nat_src_zone rule dst-$policy_id-$n match destination-address $nat_dst_address->[$x*8+$y]\n";
            }
        }
        print
"set security nat destination rule-set $nat_src_zone rule dst-$policy_id-$n then destination-nat pool $pool_name\n";
    }
}

# 设置策略
sub set_policy {
    my ( @src_address, @dst_address, @service ) = ();
    my (
        $policy_id,         $src_zone,       $dst_zone,
        $action,            $log,            $dip_id,
        $src_nat_toggle,    $dip_toggle,     $vip_toogle,
        $policy_toggle,     $dst_nat_toggle, $src_global_toggle,
        $dst_global_toggle, $dst_nat_real_address
    ) = ();

    # 删除元素中的双引号
    my @policy_context = map { $_ =~ s{"}{}g; $_ } @_;

    # 获取策略元素
    (
        $policy_id, $src_zone, $dst_zone, $src_address[0], $dst_address[0],
        $service[0]
    ) = ( ( split /\s+/, $policy_context[0] )[ 3, 5, 7, 8, 9, 10 ] );

    # 检测是否为全局策略
    $src_global_toggle = 1 if ( $src_zone eq "Global" );
    $dst_global_toggle = 1 if ( $dst_zone eq "Global" );

    foreach (@policy_context) {
        if ( /\b([Pp]ermit|[Dd]eny)\b/ && /\blog\b/ ) {    # 获取策略动作和日志开启状态
            $action = ( split /\s+/ )[-2];
            $log    = ( split /\s+/ )[-1];
        }
        elsif (/\b([Pp]ermit|[Dd]eny)\b/) {                # 获取策略动作
            $action = ( split /\s+/ )[-1];
        }
        elsif (/\bset src-address\b/) {                    # 获取策略源地址
            push @src_address, ( split /\s+/ )[-1];
            next;
        }
        elsif (/\bset dst-address\b/) {                    # 获取策略目的地址
            push @dst_address, ( split /\s+/ )[-1];
            next;
        }
        elsif (/\bset service\b/) {                        # 获取策略服务
            push @service, ( split /\s+/ )[-1];
            next;
        }
        elsif (/\bset log (session-init|session-close)\b/) {    # 获取日志选项
            $log = ( split /\s+/ )[-1];
            next;
        }
        elsif (/\bset policy id \d+ disable\b/) {               # 是否禁用策略
            $policy_toggle = ( split /\s+/ )[-1];
            next;
        }

        if (/\b(?:nat src dst ip\s+)$RE{net}{IPv4}\b/) {    # 同时配置接口源nat和目的nat
            $src_nat_toggle       = 1;
            $dst_nat_toggle       = 1;
            $dst_nat_real_address = ( split /\s+/, $& )[-1];
            print "dst nat real addr is $dst_nat_real_address\n";
        }
        elsif (/\b(?:nat src dip-id\s+\d+\s+dst ip\s+)$RE{net}{IPv4}\b/)
        {                                                   # 同时配置DIP和目的nat
            $dip_toggle           = 1;
            $dst_nat_toggle       = 1;
            $dst_nat_real_address = ( split /\s+/, $& )[-1];
        }
        elsif (/\b(?:nat src dip-id\s+)\d+\b/) {            # 只有DIP
            $dip_toggle     = 1;
            $dst_nat_toggle = 1;
            $dip_id         = ( split /\s+/, $& )[-1];
        }
        elsif (/\bnat src\b/) {                             # 接口源nat
            $src_nat_toggle = 1;
        }
        elsif (/\bVIP\(.*\)\b/) {                           # 只有目的nat
            $vip_toogle = 1;
        }
    }

    # 先进行目的nat，再进行源nat
    set_nat_dst( $policy_id, $src_zone, $dst_nat_real_address, \@src_address,
        \@dst_address )
      if ($dst_nat_toggle);
    set_vip( $policy_id, $src_zone, \@src_address, \@dst_address )
      if ($vip_toogle);
    set_nat_src( $policy_id, $src_zone, $dst_zone, \@src_address,
        \@dst_address )
      if ($src_nat_toggle);
    set_dip( $dip_id, $src_zone, $dst_zone, \@src_address, \@dst_address )
      if ($dip_toggle);

    # 输出策略
    foreach (@src_address) {
        print
"set security policies from-zone $src_zone to-zone $dst_zone policy $src_zone-to-$dst_zone-$policy_id match source-address $_\n";
    }
    foreach (@dst_address) {
        print
"set security policies from-zone $src_zone to-zone $dst_zone policy $src_zone-to-$dst_zone-$policy_id match destination-address $_\n";
    }
    foreach (@service) {
        print
"set security policies from-zone $src_zone to-zone $dst_zone policy $src_zone-to-$dst_zone-$policy_id match application $_\n";
    }
    print
"set security policies from-zone $src_zone to-zone $dst_zone policy $src_zone-to-$dst_zone-$policy_id then $action\n";

    # 配置log
    if ( ( defined $log ) && ( $log eq "(session-init|session-close)" ) ) {
        print
"set security policies from-zone $src_zone to-zone $dst_zone policy $src_zone-to-$dst_zone-$policy_id then log $log\n";
    }
    elsif ( ( defined $log ) && ( $log eq "log" ) ) {
        print
"set security policies from-zone $src_zone to-zone $dst_zone policy $src_zone-to-$dst_zone-$policy_id then log session-init\n";
    }

    # 禁用策略
    print
"deactive security policies from-zone $src_zone to-zone $dst_zone policy $src_zone-to-$dst_zone-$policy_id\n"
      if ($policy_toggle);

    return;
}

# 中文翻译成拼音
# sub zh2pinyin {
#
# }

# 输入输出报错支持中文
binmode( STDOUT, ":encoding(gbk)" );
binmode( STDIN,  ":encoding(gbk)" );
binmode( STDERR, ":encoding(gbk)" );

BEGIN {

    #处理命令行参数
    GetOptions(
        "help|h"      => sub { usage(0); },
        "c|config:s"  => \$opt_c,
        "d|compare:s" => \$opt_d,
        "o|output:s"  => \$opt_o,
        "s|service=s" => \$opt_s,
    ) or usage(1);

    # 读取ssg和srx服务映射
    if ($opt_s) {

        # 读取excel内容，并删除单元格前导和末尾空格
        my $services_file =
          Spreadsheet::Read->new( $opt_s, strip => 3, clip => 3 )
          or die "无法打开$opt_s";
        my $sheet = $services_file->sheet("ssg2srx");

        # 读取exel每一行数据，并创建services哈希表
        foreach my $row ( $sheet->{minrow} .. $sheet->{maxrow} ) {
            my @data = $sheet->cellrow($row);
            $services{ $data[0] } = $data[-1];
        }
    }

    # 打开ssg配置文件
    if ( $#ARGV < -1 || $#ARGV > 1 ) {
        usage(1);
    }

    if ($opt_c) {
        if ( system("/usr/bin/dos2unix $opt_c") != 0 ) {
            print "command failed!: dos2unix $opt_c:\n";
            exit;
        }
    }
    else {
        if ( system("/usr/bin/dos2unix $ARGV[0]") != 0 ) {
            print "command failed!: dos2unix $ARGV[0]:\n";
            exit;
        }
    }

    # 打开ssg配置文件
    open my $config, '<', ( $opt_c || $ARGV[0] )
      or die "can't open file:$!\n";
    my $tmp_ssg_config_file = do { local $/; <$config> };
    close $config;

    # 如果使用-c参数，将参数传递给ARGV
    if ($opt_c) {
        unshift @ARGV, $opt_c;

        # 去除ARGV中的重复项，防止同时使用-c和<ssg配置文件>
        @ARGV = do {
            my %tmp;
            grep { !$tmp{$_}++ } @ARGV;
        };
    }

    my $h2p        = Lingua::Han::PinYin->new();
    my $han2pinyin = $h2p->han2pinyin($tmp_ssg_config_file);    # 将汉字转换成拼音

    while ( my ( $key, $value ) = each %services ) {    # ssg预定义服务替换成srx预定义服务
        $han2pinyin =~ s{$key}{$value}gm;
    }

    $lpm             = Net::IP::LPM->new();             # 初始化最长前缀匹配
    @ssg_config_file = split( /\n/, $han2pinyin );

    # 第一次循环，处理接口，zone，ip，路由，nat，服务
    foreach (@ssg_config_file) {
        chomp;
        if ( /set service/ && /(protocol|\+)/ ) {       # 配置服务
            set_service($_);
            next;
        }
        elsif ( /set group service/ && /\badd\b/ ) {    # 配置服务集合
            set_service_set($_);
            next;
        }
        elsif (/\bset scheduler\b/) {                   # 设置时间调度器
            set_scheduler($_);
            next;
        }
        elsif ( /\bset zone\b/ && /\bscreen\b/ ) {
            set_screen($_);
            next;
        }

        # 获取zone与interface的映射关系
        elsif ( /\bset interface\b/ && /\bzone\b/ && !/\b(HA|Null)\b/ ) {
            my $zone = set_zone_interface($_);

            # 设置每个zone的MIP初始id为0
            $RULE_NUM{$zone} = 0 unless ( exists $RULE_NUM{$zone} );
            next;
        }

        # 配置接口ip
        elsif (/\bset interface\b/
            && /\bip\b/
            && !/\bdip\b/
            && /(?:$RE{net}{IPv4})/ )    # 配置常规接口
        {
            set_interface_ip_zone($_);
            next;
        }
        elsif ( /\bset interface\b/ && /\bnat\b/ ) {    # 配置接口模式
            set_interface_mode($_);
            next;
        }
        elsif ( /\bset interface\b/ && /\btunnel\.\d+\b/ && !/\bgre\b/ )
        {                                               # 配置tunnel接口
            set_interface_ip_zone($_);
            next;
        }
        elsif ( /\bset interface\b/ && /\bdip\b/ ) {    # 获取DIP的id和pool
            set_dip($_);
            next;
        }
        elsif (/\bset route\b/) {                       # 设置路由
            set_route($_);
            next;
        }
    }

    # 第二次循环，处理MIP，地址簿
    foreach (@ssg_config_file) {
        if ( /\binterface\b/ && /\bmip\b/ ) {           # 获取MIP的实地址和虚地址
            my ( $mip, $host, $mip_type ) = set_mip($_);    # 通过返回值确定host还是net
            $han2pinyin =~ s{MIP\($mip\)}{$mip_type\_$host}gm;    # 用MIP实地址替换虚地址
            my $strip_ip  = split( /\//, $host );
            my $real_zone = $lpm->lookup("$strip_ip");
            print
"set security zones security-zone $real_zone address-book address $mip_type\_$host $host\n";
            next;
        }
        elsif (/\bset address\b/) {    # 配置地址簿
            set_address_book($_);
            next;
        }
        elsif ( /\bset group address\b/ && /\badd\b/ ) {    # 配置地址簿集
            set_address_set($_);
            next;
        }
    }
    @ssg_config_file = split( /\n/, $han2pinyin );          # 替换了MIP的实地址，需要重新分割

    # 删除空行
    @ssg_config_file = grep { !/(^$|^\n$|^\s+$)/ } @ssg_config_file;

    # 删除行首尾空格
    @ssg_config_file = map { s/^\s+|\s+$//gr } @ssg_config_file;
}

# 加入lpm，后期ip通过lpm找到zone
# my $ref = $lpm->dump();
# print Dumper($ref);
# print Dumper( \%lpm_pairs );

# 第三次循环，处理策略
foreach (@ssg_config_file) {
    chomp;

    # 将策略内容保存到数组，最后调用set_policy统一处理
    if ( /\bset policy id \d+\b/ && /\b([Pp]ermit|[Dd]eny)\b/ ) {
        if (@ssg_policy_context) {    # 处理上一条策略只有一行的情况
            set_policy(@ssg_policy_context);
            @ssg_policy_context = ();
        }
        $_ =~ s{\s+name\ \"[^"]*\"}{};    # 删除策略名称，只使用策略ID
        push @ssg_policy_context, $_;
    }
    elsif (/\bset policy id \d+ disable\b/) {    # 是否禁用策略
        push @ssg_policy_context, $_;
    }
    elsif (/\b(set service|set dst-address|set src-address)\b/) {
        push @ssg_policy_context, $_;            # 策略中间内容也保存到数组
    }
    elsif (/\bexit\b/) {                         # 策略结束,调用set_policy处理
        set_policy(@ssg_policy_context);
        @ssg_policy_context = ()                 # 每条策略处理完后清空数组
    }
}

# set_policy(@ssg_policy_context);

# print Dumper( \%zones_interfaces );
# print Dumper( \%lpm_pairs );
# print Dumper( \$lpm );
# print Dumper( \%services );
# print Dumper(\%RULE_NUM);

__END__
=encoding utf8
=head2 数据结构
=item %zones_interfaces
%zones_interfaces=> {
    zone1=>[
              { ssg接口1=>
                   { srx接口1=> ip }
              }
              { ssg接口2=>
                   { srx接口2=> ip }
              }
           ]
    zone2=>[
              { ssg接口3=>
                   { srx接口3 => ip }
              }
              { ssg接口4=>
                   { srx接口4 => ip }
              }
           ]
}

=item %ssg_interface_ip
%ssg_interface_ip=> {
    { ssg接口1 => ip1 },
    { ssg接口2 => ip2 },
}

=item %ssg_srx_interface
%ssg_srx_interface=> {
    { ssg接口1 => srx接口1 },
    { ssg接口2 => srx接口2 },
}

=item %mip_address_pairs
%mip_address_pairs=> {
    {虚拟地址1 => 实地址1},
    {虚拟地址2 => 实地址2},
}

=item %dip_pool
%dip_pool=>{
    {pool_id1 => ip1}
    {pool_id2 => ip2}
}

=item %RULE_NUM
%RULE_NUM=>{
    {zone1 => rule_id1}
    {zone2 => rule_id2}
}

=item %lpm_pairs
%lpm_pairs=>{
    {ssg接口1 => zone1}
    {ssg接口2 => zone2}
}

=item $lpm
$lpm=>{
    {route1 => zone1},
    {route2 => zone2},
}
}
    {route1 => zone1},
    {route2 => zone2},
}
}
