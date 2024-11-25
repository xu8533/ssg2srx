#!/usr/bin/perl

# use Scalar::Util qw(looks_like_number);
# use Cwd 'abs_path';
# use Excel::Writer::XLSX;
use strict;
use warnings;
use NetAddr::IP;
use Net::IP::LPM;
use Getopt::Long;
use File::Basename;
use Spreadsheet::Read;
use Lingua::Han::PinYin;
use DateTime::Format::Flexible;
use Regexp::Common qw(net);
use Data::Dumper   qw(Dumper);

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# rewrite ssg2srx.pl                                                                        #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# 定义变量
my $workbook        = ();    # 保存excel文件
my $worksheet       = ();    # 保存excel文件中的工作表
my $excel_row       = 0;     # excel对比文件行数
my $lpm             = ();
my @ssg_config_file = ();    # 保存ssg配置文件
my %lpm_pairs;               # 保存路由/ip与zone的映射关系，供lpm使用
my %services;                # 保存ssg服务名与srx服务名的映射关系

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
    my $ssg_config_line = "@_";

    # 删除双引号,split后ssg接口和zone还是会多出双引号,故禁用
    # $ssg_config_line =~ s{"}{}g;

    if ( /\d+\.\d+/ && /\btag\b/ ) {
        ( $ssg_interface, $tag, $zone ) =
          ( ( split /\s+/ )[ 2, 4, 6 ], $ssg_config_line );
        print
          "Please enter a replacement of $ssg_interface with vlan tag $tag:";
    }
    else {
        ( $ssg_interface, $zone ) =
          ( ( split /\s+/ )[ 2, 4 ], $ssg_config_line );
        print "Please enter a replacement of $ssg_interface:";
    }

    # 删除双引号,前处split后ssg接口和zone会多出双引号,
    # 导致set_interface_ip_zone函数不能正确取出srx接口
    $ssg_interface =~ s{"}{}g;
    $zone          =~ s{"}{}g;

    chomp( my $srx_interface = <STDIN> );    # 用户输入新的srx接口
    push @{ $zones_interfaces{$zone} }, { $ssg_interface => $srx_interface };
    $ssg_srx_interface{$ssg_interface} = $srx_interface;

   # print "set security zones security-zone $zone interfaces $srx_interface\n";
    return $zone;
}

# 设置接口模式
sub set_interface_mode {
    my $ssg_config_line = "@_";
    my ($mode) = ( ( split /\s+/ )[-1], $ssg_config_line );

    # nat模式需要配置源nat
    if ( $mode eq "nat" ) {

    }
}

# 设置interface的ip和zone
sub set_interface_ip_zone {
    my $ssg_config_line = "@_";
    my ( $ssg_interface, $ip ) = ( ( split /\s+/ )[ 2, -1 ], $ssg_config_line );

    # 获取ssg接口和ip
    # 循环%zones_interfaces,找到ssg接口对应的srx接口
  START:
    foreach my $zone ( sort keys %zones_interfaces ) {

        # 查找具体zone下的每一个数组，
        # 如果找到ssg接口对应的srx接口则输出相关设置并跳出循环
        foreach my $href ( @{ $zones_interfaces{$zone} } ) {
            if ( exists $href->{$ssg_interface} ) {
                unless ( $href->{$ssg_interface} =~ m{\bgr-0\/0\/0\.\d+\b} )
                {    # 处理非tunnel接口

# print
# "set security zones security-zone $zone host-inbound-traffic system-services all\n";
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
                    $lpm_pairs{"$ip"} = $zone;
                    last START;
                }
                else {    # 处理tunnel接口
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
                            my $ip =
                              NetAddr::IP->new( $ssg_interface_ip{$source} );
                            print
"set interfaces $href->{$ssg_interface} tunnel source ",
                              $ip->addr;
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
    my $ssg_config_line = "@_";
    my ( $ssg_interface, $ip ) = ( ( split /\s+/ )[ 2, -1 ], $ssg_config_line );

}

# 设置scheduler
sub set_scheduler {

}

# 设置地址簿
sub set_address_book {

}

# 设置地址集合
sub set_address_set {

}

# 设置服务
sub set_service {

}

# 设置服务集合
sub set_service_set {

}

# 设置screen
sub set_screen {

}

sub set_nat {

}

# 设置静态nat
sub set_mip {
    my $ssg_config_line = "@_";
    my ( $ssg_interface, $virtual_ip, $real_ip, $netmask ) =
      ( ( split /\s+/ )[ 2, 4, 6, -3 ], $ssg_config_line )
      ;    # 获取MIP绑定的接口，实部和虚部地址以及子网掩码
    $ssg_interface =~ s{"}{}g;
    foreach my $zone ( sort keys %zones_interfaces ) {
        foreach my $href ( @{ $zones_interfaces{$zone} } ) {
            if ( exists $href->{$ssg_interface}
                && ( $netmask eq "255.255.255.255" ) )
            {    # MIP为单个ip
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
                && ( $netmask ne "255.255.255.255" ) )
            {    # MIP为子网

                my $tag               = "net";
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
        }
    }
}

# 设置源nat
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
    $dip_pool{$dip_id} = "$start_dip_address to $stop_dip_address";
}

# 设置目的nat
sub set_vip {

}

# 设置策略
sub set_policy {

}

# 中文翻译成拼音
sub zh2pinyin {

}

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

    while (<>) {
        chomp;

        # 获取zone与interface的映射关系
        if ( /\bset interface\b/ && /\bzone\b/ && !/\b(HA|Null)\b/ ) {
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
        elsif ( /\binterface\b/ && /\bmip\b/ ) {        # 获取MIP的实地址和虚地址
            my ( $mip, $host, $mip_type ) = set_mip($_);    # 通过返回值确定host还是net
            $tmp_ssg_config_file =~
              s#MIP\($mip\)#$mip_type\_$host#gm;            # 用MIP实地址替换虚地址
            next;
        }
        elsif ( /\bset interface\b/ && /\bdip\b/ ) {        # 获取DIP的id和pool
            set_dip($_);
            next;
        }
        elsif ( /policy id/ && /name/ ) {
            $tmp_ssg_config_file =~ s{name\ \"[^"]*\"}{}gm;    # 删除策略名称，只使用策略ID
            next;
        }
        elsif ( /set route/ && /interface/ && !/\bsource\b/ ) {
            set_route($_);
            next;
        }
    }
    my $h2p        = Lingua::Han::PinYin->new();
    my $han2pinyin = $h2p->han2pinyin($tmp_ssg_config_file);    # 将汉字转换成拼音
    @ssg_config_file = split( /\n/, $han2pinyin );
}

# 删除空行
@ssg_config_file = grep { !/(^$|^\n$|^\s+$)/ } @ssg_config_file;

# 删除行首尾空格
@ssg_config_file = map { s/^\s+|\s+$//gr } @ssg_config_file;

# $Data::Dumper::Pair = " : ";
print Dumper(%zones_interfaces);

# print Dumper(%services);
# print Dumper(%RULE_NUM);

# foreach my $key ( keys %zones_interfaces ) {
#     print "key: $key\n";
#     foreach my $value ( @{ $zones_interfaces{$key} } ) {
#         my ( $srx_interface, $ssg_interface ) = each %$value;
#         print "$srx_interface $ssg_interface\n";
#     }
# }
__END__
=encoding utf8
=head1 数据结构
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
my %dip_pool=>{
    {pool_id1 => ip1}
    {pool_id2 => ip2}
}

=item %RULE_NUM
my %RULE_NUM=>{
    {zone1 => rule_id1}
    {zone2 => rule_id2}
}
