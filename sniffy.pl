#Author: Luis Mayorga
#Description: Capture Traffic based on a filter
#Based on https://www.perlmonks.org/?node_id=170648
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use MIME::Base64;
use Term::ANSIColor qw(:constants);
use strict;

my $err;
my $dev = $ARGV[0]; #pass the nic if needed default should be eth0 in an opentack vm
#https://wiki.wireshark.org/CaptureFilters
my $my_filter = "dst net 10.0.1.10/32"; #filtering destination traffic on a single ip the netmask supports more options

unless (defined $dev) {
  $dev = Net::Pcap::lookupdev(\$err); #select interface
  if (defined $err) {
    die 'Unable to determine network device for monitoring - ', $err;
  }
}

my ($address, $netmask);
if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
	die 'Unable to look up device information for ', $dev, ' - ', $err;
}

my $object;
#open_live(nic, package length, promisc, millisecs) opens a capture descriptor
$object = Net::Pcap::open_live($dev, 1500, 1, 5000, \$err); 

unless (defined $object) {
   die 'Unable to create packet capture on device ', $dev, ' - ', $err;
}

my $filter;
Net::Pcap::compile( $object, \$filter, $my_filter , 0, $netmask) && die 'Unable to compile packet capture filter';
Net::Pcap::setfilter($object, $filter) &&
  die 'Unable to set packet capture filter';

#capture 1000 packets
Net::Pcap::loop($object, 1000, \&syn_packets, '') ||
  die 'Unable to perform packet capture';

Net::Pcap::close($object);

sub syn_packets {
  my ($user_data, $header, $packet) = @_;
  my $ether_data = NetPacket::Ethernet::strip($packet);
  my $ip = NetPacket::IP->decode($ether_data);
  my $tcp = NetPacket::TCP->decode($ip->{'data'});

  print $ip->{'src_ip'}, ":", $tcp->{'src_port'}, " -> ", $ip->{'dest_ip'}, ":", $tcp->{'dest_port'}, "\n";

  my $hexstring = $tcp->{'data'};
  $hexstring =~ s/[^[:print:]]+/ /g;
#  while ($hexstring =~ /(cg[A-Z] +[A-Za-z0-9+]+=*\s*)?/g) {
  while ($hexstring =~ /(cg[A-Z] +(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?)?/g) {
    (my $cat, my $encoded) = split(/\s+/,$1);
    #print YELLOW, "encoded:$1\n", RESET unless ($encoded eq "");
    my $decoded = decode_base64($encoded);
    $decoded =~ s/[^[:print:]]+/ /g;
    print GREEN, "decoded:$cat $decoded\n-\n", RESET unless ($decoded eq "");
  };
  print BLUE, "***next packet***\n", RESET;
}
