#!/usr/bin/perl
#small script to generate a fake mac address everytime it is run.
$possible = "ABCDEF0123456789";
for($a = 0;$a < 5;$a++){
	$mac .= substr($possible,(int(rand(length($possible)))), 1);
	$mac .= substr($possible,(int(rand(length($possible)))), 1);
	$mac .= ":";
}
$mac .= substr($possible,(int(rand(length($possible)))), 1);
$mac .= substr($possible,(int(rand(length($possible)))), 1);
print "$mac\n";
