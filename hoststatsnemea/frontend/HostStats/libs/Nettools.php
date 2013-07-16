<?php

/**
 * Simple network tools
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
class Nettools {


    public static function getIp4Prefix($ip, $prefixLength, $basePrefixLength = null) {
        $addr = ip2long($ip);
        if($basePrefixLength)
            $addr = $addr & pow(2,(32-$basePrefixLength))-1;

        $addr = $addr >> 32-$basePrefixLength-$prefixLength;
        return $addr;
    }

    public static function getIp4RangeByPrefix($prefix, $prefixLength) {
        $length = 32-$prefixLength;

        $min = ($prefix << (32-$prefixLength)); // doplnen 0 do 32bitu
        $max = ($prefix << (32-$prefixLength)) + (pow(2, 32-$prefixLength)-1); // doplnen 1 do 32bitu
        return array(long2ip($min),long2ip($max));
    }


    /**
     * Validate IP adress (IPv4 or IPv6)
     * @param string IP address
     * @return mixed
     */
    public static function isIP($string) {
        return filter_var($string, FILTER_VALIDATE_IP);
    }
    /**
     * Validate IPv4 adress
     * @param string IP address
     * @return mixed
     */
    public static function isIPv4($string) {
        return filter_var($string, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }
    /**
     * Validate IPv6 adress
     * @param string IP address
     * @return mixed
     */
    public static function isIPv6($string) {
        return filter_var($string, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }


    /**
     * Get host by ipv4 address
     * @param string IP address
     * @return mixed
     */
    public static function hostbyaddr($addr) {
        $addr = trim($addr);
        return gethostbyaddr($addr);
    }

    /**
     * Get host by ipv6 address
     * @param string IP address
     * @return mixed
     */
    public static function hostbyaddr6($ip6) {
        $ip6 = escapeshellarg(trim($ip6));
        return trim(exec("dig +short -x $ip6"));
    }

    /**
     * Get WHOIS record
     * @param string IP address
     * @param string|null WHOIS server
     * @return mixed
     */
    public static function whois($query, $host = null) {

        $ip = escapeshellcmd($query);
        if($host)
            $host = "-h ".escapeshellcmd($host);

        $output = '';
        $f = popen("whois $host $ip", 'r');
        while(!feof($f))
            $output .= fgets($f, 128);
        pclose($f);

        return $output;

    }


}