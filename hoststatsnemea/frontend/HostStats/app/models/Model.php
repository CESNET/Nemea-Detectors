<?php

/**
 * Application HostStats data model
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
class Model
{
    /** @var HSConnecion Connection with HostStats server */
    public $conn;

    public function __construct( $conn ) {
       $this->conn = $conn;
    }

    /**
     * Make right datatypes to status
     * @return ArrayHash
     */
    public function getStatus() {
        $response =  $this->conn->getStatus();

        $response['processing'] = (bool) $response['processing'];
        $response['timeslot'] = !empty($response['timeslot']) ? new Timeslot($response['timeslot']) : null;
        $response['flows'] = (int) $response['flows'];
        $response['hosts'] = (int) $response['hosts'];

        return ArrayHash::from($response);
    }

    /**
     * History of count hosts
     * @param string Profile
     * @param Timeslot|null Timeslot from
     * @param Timeslot|null Timeslot to
     * @return array
     */
    public function getHostCntHistory($profile = HSConnection::ALL, Timeslot $from = null, Timeslot $to = null) {

        if(!$to)
            $to = new Timeslot();
        if(!$from)
            $from = $to->getModify("-12 hour");


        $timewindow = new Timewindow($from, $to);

        $data = $this->conn->getHostCntHistory($profile,  $timewindow->from->getName(), $timewindow->to->getName());

        // Pokud data chybi nahradime je nulami
        $result = array();
        $slot = clone $timewindow->from;
        do {
            $result[$slot->getTimestamp()] = isset($data[$slot->getName()]) ? $data[$slot->getName()] : 0;
            $slot->next();
        } while ($slot->getTimestamp() <= $timewindow->to->getTimestamp());

        return $result;
    }

    /**
     * History of count flows
     * @param string Profile
     * @param Timeslot|null Timeslot from
     * @param Timeslot|null Timeslot to
     * @return array
     */
    public function getFlowCntHistory($profile = HSConnection::ALL, Timeslot $from = null, Timeslot $to = null) {

        if(!$to)
            $to = new Timeslot();
        if(!$from)
            $from = $to->getModify("-12 hour");


        $timewindow = new Timewindow($from, $to);

        $data = $this->conn->getFlowCntHistory($profile, $timewindow->from->getName(), $timewindow->to->getName());

        // Pokud data chybi nahradime je nulami
        $result = array();
        $slot = clone $timewindow->from;
        do {
            $result[$slot->getTimestamp()] = isset($data[$slot->getName()]) ? $data[$slot->getName()] : 0;
            $slot->next();
        } while ($slot->getTimestamp() <= $timewindow->to->getTimestamp());


        return $result;
    }

    /**
     * Get available profiles
     * @return array
     */
    public function getProfiles() {
        $profiles = $this->conn->getProfiles();
        // Translate name to human form
        foreach($profiles as $profile) {
            $res[$profile] = $profile;
        }
        return $res;
    }


    /**
     * Get stats in one timeslot
     * @param Timeslot Timeslot (format yyyymmddhhiiss)
     * @param string Profile
     * @param string|null Filter rules
     * @param int Number of results
     * @param string|null Sorted by column
     * @param int Sorted as: 0 for ascendent, 1 for descendent
     * @return array Asociative table (without header)
     */
    public function getTimeslotData(Timeslot $timeslot, $profile = HSConnection::ALL, $filter = null, $limit = 100, $sort = null, $asc = 0) {
        $data = $this->conn->getTimeslotData( $timeslot->getName(), $profile, $filter, $limit, $sort, $asc );
        return $this->_getTable($data);
    }

    /**
     * Get stats in one timeslot
     * @param Timeslot Timeslot (format yyyymmddhhiiss)
     * @param string Profile
     * @param string|null Filter rules
     * @param int Number of results
     * @param string|null Sorted by column
     * @param int Sorted as: 0 for ascendent, 1 for descendent
     * @return array Asociative table (without header)
     */
    public function getTimeslotIpMap(Timeslot $timeslot, $profile = HSConnection::ALL, $baseAddress="0.0.0.0", $basePrefixLength=0) {
        $data = $this->conn->getTimeslotIpMap( $timeslot->getName(), $profile, $baseAddress, $basePrefixLength);
        return $this->_getTable($data);
    }
    /**
     * Get history of one host
     * @param string Host IP address
     * @param string Profile
     * @param Timeslot Timeslot from (format yyyymmddhhiiss)
     * @param Timeslot Timeslot to (format yyyymmddhhiiss)
     * @return array Asociative table (without header)
     */
    public function getHostHistory($ip, $profile = HSConnection::ALL, Timeslot $from = null, Timeslot $to = null) {
        $data = $this->conn->getHostHistory($ip, $profile, $from->getName(), $to->getName());
        return $this->_getTable($data);
    }

    /**
     * List of days in which they were detected attacks
     * @param string Sorted as: asc for ascendent, desc for descendent
     * @param int Number of results
     * @return array Asociative table (without header)
     */
    public function getDetectionLogList($sort = "asc", $limit = 10) {
        $data = $this->conn->getDetectionLogList();
        if(empty($data))
            return array();

        if($sort == "desc")
            $data = array_reverse($data);
        if($limit)
            $data = array_splice($data, 0, $limit);

        $return = array();
        foreach($data as $date) {
            $year = substr($date, 0, 4);
            $month = substr($date, 4, 2);
            $day = substr($date, 6, 2);
            $date = new DateTime53("{$year}-{$month}-{$day}");

            $return[] = ArrayHash::from(array(
                'date' => $date,
                'count' => count( $this->getDetectionLog( $date ) ),
            ));
        }
        return $return;
    }

    /**
     * List of detected attacks in one day
     * @param DateTime Date
     * @return array Asociative table (without header)
     */
    public function getDetectionLog(DateTime $date) {
        $data = $this->conn->getDetectionLog( $date->format('Ymd') );
        if(empty($data))
            return array();

        $list = array();
        $types = array(
            'portscan' => 'Portscan',
            'portscan_h' => 'Horizontal portscan',
            'portscan_v' => 'Vertical portscan',
            'bruteforce' => 'Bruteforce',
            'dos' => 'DoS',
            'other' => 'Other'
        );
        $protocols = array(
            1 => 'ICMP',
            6 => 'TCP',
            17 => 'UDP',
        );

        $header = array('timeslot', 'type', 'protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'intensity', 'note');
        $list = $this->_getTable($data, $header);
        foreach($list as &$row) {
            $row['type'] = isset($types[$row['type']]) ? $types[$row['type']] : $row['type'];
            $row['protocol'] = isset($protocols[$row['protocol']]) ? $protocols[$row['protocol']] : $row['protocol'];
        };

        return $list;
    }

    /**
     * Create asociative table from array with header
     * @param array Data
     * @param array|null Header
     * @return array
     */
    private function _getTable($data, $header = null) {
        if(!is_array($header))
            $header = array_shift($data);
        $return = array();
        foreach($data as $row) {
            $item = new ArrayHash();
            foreach($header as $i => $col) {
                if($col == 'timeslot')
                    $item->$col = new Timeslot($row[$i]);
                else
                    $item->$col = $row[$i] == "" ? null : $row[$i];
            }
            $return[] = $item;
        }
        return $return;
    }

}
