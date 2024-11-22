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
our ( $opt_c, $opt_d, $opt_o, $opt_s ) = '';

# 保存ssg接口与srx接口和zone的映射关系
my %zones_interfaces;

# %zones_interfaces=>{
#     zone1=>[
#          { srx接口1=>ssg接口1 }
#          { srx接口2=>ssg接口2 }
#            ]
#     zone2=>[
#          { srx接口3=>ssg接口3 }
#          { srx接口4=>ssg接口4 }
#            ]
# }

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
"usage: $0 [-c ssg_config_file] [-o file] [-s srx_to_ssg_service_mapping_table.xlsx] ssg_file\n",
      "\t-c --config    file        ssg configuration file\n",
      "\t-o --output    file        srx configuration output file\n",
      "\t-s --service   file        ssg to srx service mapping file\n",
      "\t-h --help                  print usage\n";
    exit $err;
}

# 设置zone与interface的映射关系
sub set_zone_interface {
    my ( $ssg_interface, $zone, $tag ) = ();
    my $ssg_config_line = "@_";

    # 删除双引号
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

    # 删除双引号
    $ssg_interface =~ s{"}{}g;
    $zone          =~ s{"}{}g;

    chomp( my $srx_interface = <STDIN> );    # 用户输入新的srx接口
    push @{ $zones_interfaces{$zone} }, { $ssg_interface => $srx_interface };

    # my $ref_ssg_srx_interface = { $srx_interface => $ssg_interface };
    # push @{ $zones_interfaces{$zone} }, $ref_ssg_srx_interface;
    # return $zone, %ssg_srx_interfaces;
}

# 设置interface的ip和zone
sub set_interface_ip_zone {
    my ( $ssg_interface, $ip ) = ();
    my $ssg_config_line = "@_";

    # 获取ssg接口和ip
    if ( !/\btunnel\.\d+\b/ ) {    # 处理非tunnel接口
        ( $ssg_interface, $ip ) = ( split /\s+/ )[ 2, 4 ];

        # 循环%zones_interfaces,找到ssg接口对应的srx接口
      START:
        foreach my $zone ( sort keys %zones_interfaces ) {

            # 查找具体zone下的每一个数组，如果找到ssg接口对应的srx接口则输出相关设置并跳出循环
            foreach my $href ( @{ $zones_interfaces{$zone} } ) {
                if ( exists $href->{$ssg_interface} ) {
                    print
"set interfaces $href->{$ssg_interface} unit 0 family inet address $ip\n";
                    print
"set security zones security-zone $zone host-inbound-traffic system-services all\n";
                    print
"set security zones security-zone $zone interfaces $href->{$ssg_interface}\n";
                    $lpm_pairs{"$ip"} = $zone;
                    last START;
                }
            }
        }
    }
    else {    # 处理tunnel接口

    }
}

# 设置路由
sub set_route {

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

}

# 设置目的nat
sub set_vip {

}

# 设置源nat
sub set_dip {

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

    use Spreadsheet::Read;

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
    if ( $#ARGV < -1 || $#ARGV > 5 ) {
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
    @ssg_config_file = split( /\n/, $tmp_ssg_config_file );

    # 删除空行
    @ssg_config_file = grep { !/(^$|^\n$|^\s+$)/ } @ssg_config_file;

    # 删除行首尾空格
    @ssg_config_file = map { s/^\s+|\s+$//gr } @ssg_config_file;

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
            set_zone_interface($_);
            next;
        }

        # 配置接口ip
        elsif (/\bset interface\b/
            && /\bip\b/
            && /(?:$RE{net}{IPv4})/ )
        {
            set_interface_ip_zone($_);
            next;
        }
    }

}

# $Data::Dumper::Pair = " : ";
# print Dumper(%zones_interfaces);
# print Dumper(%services);

# foreach my $key ( keys %zones_interfaces ) {
#     print "key: $key\n";
#     foreach my $value ( @{ $zones_interfaces{$key} } ) {
#         my ( $srx_interface, $ssg_interface ) = each %$value;
#         print "$srx_interface $ssg_interface\n";
#     }
# }
