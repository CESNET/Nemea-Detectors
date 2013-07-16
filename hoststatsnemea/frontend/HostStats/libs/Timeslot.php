<?php

/**
 * Timeslot
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
class Timeslot extends DateTime {

    const LENGHT = 300; // Length of timeslotu in seconds

    public function __construct($input=null) {
        // Input 12 number represents the timeslot
        if(preg_match("/\d{12}+/",$input)) {
            $year = substr($input, 0, 4);
            $month = substr($input, 4, 2);
            $day = substr($input, 6, 2);
            $hour = substr($input, 8, 2);
            $minute = substr($input, 10, 2);

            $input = "$year-$month-$day $hour:$minute:00";
        }
        // Input date in czech format dd.mm.yyyy hh:ii:ss
        elseif(preg_match("/^([0-9]+)\. ?([0-9]+)\. ?([0-9]+)( ([0-9]+):([0-9]+)(:([0-9]+))?)?$/",$input,$matches)) {
            list(, $day,$month,$year, , $hour, $minute) = $matches;
            $input = "$year-$month-$day $hour:$minute:00";
        }
        parent::__construct($input);
        // align to smaller value timeslot
        $this->justification();
    }

    /**
     * Align time of timeslot to smaller value by length of timeslot
     */
    protected function justification() {
        $timestamp = parent::getTimestamp();
        $x = $timestamp % self::LENGHT;
        $timestamp = $timestamp-$x;
        parent::setTimestamp($timestamp);
        return $this;
    }

    /**
     * Modify timeslot value and align
     * @param string new value
     * @return Timeslot
     */
    public function modify($value) {
        parent::modify($value);
        $this->justification();
        return $this;
    }
    /**
     * Clone and modify timeslot
     * @param string new value
     * @return Timeslot
     */
    public function getModify($value) {
        $obj = clone $this;
        return $obj->modify($value);
    }

    /**
     * Get name in format yyyymmdddhhiiss
     * @return string
     */
    public function getName() {
        return $this->format("YmdHi");
    }

    /**
     * Get formatted time
     * @param string Format
     * @return string
     */
    public function getFormatted($format = "Y-m-d H:i") {
        return $this->format($format);
    }

    /**
     * Move to next
     * @return Timeslot
     */
    public function next() {
        $LENGTH = self::LENGHT;
        $this->modify("+ {$LENGTH} seconds");
        return $this;
    }
    /**
     * Move to previous
     * @return Timeslot
     */
    public function prev() {
        $LENGTH = self::LENGHT;
        $this->modify("- {$LENGTH} seconds");
        return $this;
    }

    /**
     * Clone timeslot and move to next
     * @return Timeslot
     */
    public function getNext() {
        $ts = clone $this;
        return $ts->next();
    }
    /**
     * Clone timeslot and move to previus
     * @return Timeslot
     */
    public function getPrev() {
        $ts = clone $this;
        return $ts->prev();
    }

    /**
     * Is timeslot in future
     * @return bool
     */
    public function isLast() {
        if($this->getNext()->getTimestamp() > time() )
            return true;
        return false;
    }

    /**
     * Convert to string
     * @return string
     */
    public function __toString() {
        return $this->getFormatted();
    }

}
