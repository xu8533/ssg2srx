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

my $lpm = Net::IP::LPM->new();

# add prefixes
$lpm->add( '0.0.0.0/0',                    'default' );
$lpm->add( '::/0',                         'defaultv6' );
$lpm->add( '147.229.0.0/16',               'net1' );
$lpm->add( '147.229.3.0/24',               'net2' );
$lpm->add( '147.229.3.10/32',              'host3' );
$lpm->add( '147.229.3.11',                 'host4' );
$lpm->add( '2001:67c:1220::/32',           'net16' );
$lpm->add( '2001:67c:1220:f565::/64',      'net26' );
$lpm->add( '2001:67c:1220:f565::1235/128', 'host36' );
$lpm->add( '2001:67c:1220:f565::1236',     'host46' );
printf $lpm->lookup('147.229.100.100');     # returns net1
printf $lpm->lookup('147.229.3.10');        # returns host3
printf $lpm->lookup('2001:67c:1220::1');    # returns net16
printf $lpm->lookup('0.0.0.0');             # returns net16
printf $lpm->lookup('147.229.0.0/16');      # returns net16
