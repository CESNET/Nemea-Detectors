<?php


class TimewindowException extends Exception {};

/**
 * Timewindow
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */

class Timewindow extends Object {

    /** @var Timeslot */
    public $from;
    /** @var Timeslot */
    public $to;
    /** @var Int Window lenght in seconds */
    private $length;

    public function __construct(Timeslot $from, Timeslot $to) {
        if($to < $from)
            throw new TimewindowException("Timeslot FROM must be lower then Timelot TO");
        $this->from = clone $from;
        $this->to = clone $to;
        $this->length = abs($to->getTimestamp() - $from->getTimestamp());
    }

    /**
     * String from - to in format
     * @param string Format
     * @return string
     */
    public function getFormatted($format = "Y-m-d H:i") {
        return sprintf("%s - %s", $this->from->format($format), $this->to->format($format)) ;
    }
    /**
     * Move to next
     * @return Timewindow
     */
    public function next() {
        $this->from->modify("+ {$this->length} seconds");
        $this->to->modify("+ {$this->length} seconds");
        return $this;
    }
    /**
     * Move to previous
     * @return Timewindow
     */
    public function prev() {
        $this->from->modify("- {$this->length} seconds");
        $this->to->modify("- {$this->length} seconds");
        return $this;
    }

    /**
     * Clone timewidow and move to next
     * @return Timeslot
     */
    public function getNext() {
        $tw = clone $this;
        return $tw->next();
    }
    /**
     * Clone timewidow and move to previus
     * @return Timeslot
     */
    public function getPrev() {
        $tw = clone $this;
        return $tw->prev();
    }

    /**
     * @return Timeslot
     */
    public function getFrom() {
        return $this->from;
    }
    /**
     * @return Timeslot
     */
    public function getTo() {
        return $this->to;
    }

    /**
     * Is to timeslot in future
     * @return bool
     */
    public function isLast() {
        if($this->getNext()->to->isLast())
            return true; // dalsi okno uz nejde otevrit
        return false;
    }

    /**
     * Get title
     * @return string
     */
    public function getTitle() {
        $now = new Timeslot();
        $toNow = ($this->to == $now);


        $isMinute = ($this->length % 60 == 0);
        $minute = $this->length / 60;

        $isHours = ($this->length % 3600 == 0);
        $hours = $this->length / 3600;

        $isDays = ($this->length % (3600*24) == 0);
        $days = $this->length / (3600*24);

        $isWeeks = ($this->length % (3600*24*7) == 0);
        $weeks = $this->length / (3600*24*7);

        $isMonth = ($this->length % (3600*24*7*30) == 0);
        $moths = $this->length / (3600*24*7*30);

        if($this->length == 0)
            return $toNow ? "Last timeslot" : "One timeslot";
        elseif($isMonth && $moths == 1)
            return $toNow ? "Last month" : "Month";
        elseif($isMonth)
            return $toNow ? "Last {$moths} months" : "{$moths} months";
        elseif($isWeeks && $weeks == 1)
            return $toNow ? "Last week" : "Week";
        elseif($isWeeks)
            return $toNow ? "Last {$weeks} weeks" : "{$weeks} weeks";
        elseif($isDays && $days == 1)
            return $toNow ? "Last day" : "Day";
        elseif($isDays)
            return $toNow ? "Last {$days} days" : "{$moths} days";
        elseif($isHours && $hours == 1)
            return $toNow ? "Last hour": "Hour";
        elseif($isHours)
            return $toNow ? "Last {$hours} hours" : "{$hours} hours";
        elseif($isMinute && $minute == 1)
            return $toNow ? "Last minute": "Minute";
        elseif($isMinute)
            return $toNow ? "Last {$minute} minutes" : "{$minute} minutes";
        else
            return 'Custom window';
    }

    /**
     * Convert to string
     * @return string
     */
    public function __toString() {
        return $this->getFormated();
    }

}
