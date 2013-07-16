<?php

/**
* Exception for all errors HSConnection
*/
class HSCException extends Exception {
}
/**
 * Exception for connection errors
 */
class HSCConnectException extends HSCException {
}
/**
 * Exception for errors from HostStats server
 */
class HSCBadCommandException extends HSCException {
}



/**
 * HostStats connection client-side protocol implementation.
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
class HSConnection {

    // All profile
    const ALL                       = 'all';

    // Request code
    const NEW_DATA                  = 1;
    const GET_STATUS                = 10;
    const GET_HOST_CNT_HISTORY      = 11;
    const GET_FLOW_CNT_HISTORY      = 12;
    const GET_PROFILES              = 20;
    const GET_FIELD_LIST            = 30;
    const GET_TIMESLOT_DATA         = 31;
    const GET_TIMESLOT_IPMAP        = 32;
    const GET_HOST_HISTORY          = 35;
    const GET_DETECTION_LOG_LIST    = 40;
    const GET_DETECTION_LOG         = 41;


    protected $socket;
    public $host;
    public $port;

    public function __construct($host, $port) {
        $this->host = $host;
        $this->port = $port;
    }
    public function __destructor() {
        $this->close();
    }

    /**
     * Open socket
     * @throw HSCConnectException
     * @return void
     */
    protected function connect() {
        $this->socket = @fsockopen($this->host, $this->port, $errno, $errstr);
        if (!$this->socket)
            throw new HSCConnectException($errno.": ".$errstr." [$this->host:$this->port]");
    }
    /**
     * Close socket
     * @return void
     */
    protected function close() {
        if($this->socket)
            fclose($this->socket);
        $this->socket = null;
    }

    /**
     * Send request with parameter
     * @param int Request code
     * @param string Parameters separate by semicolon
     * @return void
     */
    protected function send($code,$param = null) {
        fwrite($this->socket, chr($code) . ($param ? $param : ""));
        fwrite($this->socket, "\000");
        fflush($this->socket);
    }


    /**
     * Waiting for response
     * @throw HSCBadCommandException
     * @return string response
     */
    protected function read() {
        $response = null;
        while (!feof($this->socket))
            $response .= fread($this->socket,1024);

        if(preg_match('/^ERROR:(.*)/i',$response, $matches)) {
            $err = (string) trim($matches[1]);
            if(preg_match('/(.+)\(error code: ([+-]?\d+)\)/i',$err, $matches))
                throw new HSCBadCommandException((string) trim($matches[1]), (int) trim($matches[2]));
            else
                throw new HSCBadCommandException($err, 1);
        }

        return trim($response); //implode($lines,"\n");
    }

    /**
     * Send request and waiting for response
     * @param int Request code
     * @param string|null Parameters separate by semicolon
     * @param bool Waiting for response?
     * @return string response
     */
    protected function sendRequest($code, $param = null, $waitForResponse = true) {
        $this->connect();
        $this->send($code,$param);
        if($waitForResponse)
            $response = $this->read();
        $this->close();
        return $response;
    }

    /**
     * Parse values from response string
     * @param string response (format key1=value1;key2=value2;...)
     * @return array values
     */
    protected function parseValues($response) {
        $result = array();
        foreach(explode(";", $response) as $item) {
            list($key,$val) = explode('=',$item);
            $result[$key] = $val;
        }
        return $result;
    }

    /**
     * Parse table from response string
     * @param string response (rows separated by "/n", cols by ";")
     * @return array values
     */
    protected function parseTable($response) {
        $return = array();
        foreach(explode("\n",$response) as $line)
            $return[] = array_map('trim', explode(";",$line));
        return $return;
    }


    /**
     * Send new timeslot to HostStats server
     * @param Timeslot New timeslot to proccessing
     * @return string
     * @deprecated Method is not universal
     */
    public function sendNewData(Timeslot $timeslot) {
        $PROFILEDIR = '/usr/local/nfsen/profiles-data';
        $profilepath = 'live';
        $channel = 'vut';

        $year = $timeslot->format('Y');
        $month = $timeslot->format('m');
        $day = $timeslot->format('d');

        $hour = $timeslot->format('H');

        $ts = $timeslot->getName();

        $files = null;
        $files .= "$PROFILEDIR/$profilepath/$channel/$year-$month-$day/$hour/nfcapd.$ts\n";

        $response = $this->sendRequest(self::NEW_DATA, $files, false);
        return $response;
    }

    /**
     * Get HostStats status
     * @return array
     */
    public function getStatus() {
        $response =  $this->sendRequest(self::GET_STATUS);
        $response = $this->parseValues($response);

        $response['timeslot'] = ($response['timeslot'] != 'none') ? $response['timeslot'] : null;

        return $response;
    }

    /**
     * Get history of host count
     * @param string Profile
     * @param string Timeslot from (format yyyymmddhhiiss)
     * @param string Timeslot to (format yyyymmddhhiiss)
     * @return array|null
     */
    public function getHostCntHistory($profile = self::ALL, $timeslotFrom, $timeslotTo) {
        $response =  $this->sendRequest(self::GET_HOST_CNT_HISTORY, "{$profile};{$timeslotFrom};{$timeslotTo}");
        if(empty($response))
            return null;

        $response = $this->parseValues($response);
        return $response;
    }

    /**
     * Get history of host flows
     * @param string Profile
     * @param string Timeslot from (format yyyymmddhhiiss)
     * @param string Timeslot to (format yyyymmddhhiiss)
     * @return array|null
     */
    public function getFlowCntHistory($profile = self::ALL, $timeslotFrom, $timeslotTo) {
        $response =  $this->sendRequest(self::GET_FLOW_CNT_HISTORY, "{$profile};{$timeslotFrom};{$timeslotTo}");
        if(empty($response))
            return null;

        $response = $this->parseValues($response);
        return $response;
    }

    /**
     * Get available profiles
     * @return array
     */
    public function getProfiles() {
        $response =  $this->sendRequest(self::GET_PROFILES);
        $response =  explode(';',$response);
        return $response;
    }

    /**
     * Get fields of TimeslotData table
     * @param string Profile
     * @return array
     */
    public function getFieldList($profile = self::ALL) {
        $response =  $this->sendRequest(self::GET_FIELD_LIST, "{$profile}");
        $response =  explode(';',$response);
        return $response;
    }

    /**
     * Get stats in one timeslot
     * @param string Timeslot (format yyyymmddhhiiss)
     * @param string Profile
     * @param string|null Filter rules
     * @param int Number of results
     * @param string|null Sorted by column
     * @param int Sorted as: 0 for ascendent, 1 for descendent
     * @return array
     */
    public function getTimeslotData($timeslot, $profile = self::ALL, $filter = null, $limit = 10, $sort = null, $asc = 0) {
        $response = $this->sendRequest(self::GET_TIMESLOT_DATA, "{$profile};{$timeslot};{$filter};{$limit};{$sort};{$asc}");
        return $this->parseTable($response);
    }

    /**
     * Get stats in one timeslot grouped by /16 prefix
     * @param string Timeslot (format yyyymmddhhiiss)
     * @param string Profile
     * @return array
     */
    public function getTimeslotIpMap($timeslot, $profile = self::ALL, $baseAddress="0.0.0.0", $basePrefixLength=0) {
        $response = $this->sendRequest(self::GET_TIMESLOT_IPMAP, "{$profile};{$timeslot};{$baseAddress};{$basePrefixLength}");
        return $this->parseTable($response);
    }

    /**
     * Get history of one host
     * @param string Host IP address
     * @param string Profile
     * @param string Timeslot from (format yyyymmddhhiiss)
     * @param string Timeslot to (format yyyymmddhhiiss)
     * @return array
     */
    public function getHostHistory($ipAddress, $profile = self::ALL, $timeslotFrom, $timeslotTo) {
        $response = $this->sendRequest(self::GET_HOST_HISTORY, "{$profile};{$ipAddress};{$timeslotFrom};{$timeslotTo}");
        return $this->parseTable($response);
    }

    /**
     * List of days in which they were detected attacks
     * @return array
     */
    public function getDetectionLogList() {
        $response = $this->sendRequest(self::GET_DETECTION_LOG_LIST);
        $response = explode("\n",$response);
        return $response;
    }

    /**
     * List of detected attacks in one day
     * @param Date in format yymmdd
     * @return array|null
     */
    public function getDetectionLog($date) {
        $response = $this->sendRequest(self::GET_DETECTION_LOG,"{$date}");
        if(empty($response))
            return null;
        return $this->parseTable($response);
    }



}
