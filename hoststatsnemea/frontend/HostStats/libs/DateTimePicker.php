<?php

/**
 * DateTime picker to Nette Form
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
 class DateTimePicker extends /*Nette\Forms\*/TextInput
 {
   const regexpInput =  '/^([0-9]+)\. ?([0-9]+)\. ?([0-9]+)( ([0-9]+):([0-9]+)(:([0-9]+))?)?$/';  
   const regexpOutput = '~([0-9]{4})-([0-9]{2})-([0-9]{2}) ?([0-9]+):([0-9]+)(:([0-9]+))?~';
     
   /**
    * @param string $label label
    * @param int lenght of element
    * @param int max lenght
    */
   public function __construct($label, $cols = null, $maxLenght = null)
   {
     parent::__construct($label, $cols, $maxLenght);
   }
   
   public static function addDateTimePicker($form, $name, $label,  $cols = NULL, $maxLength = NULL)
   {
        return $form[$name] = new DateTimePicker($label, $cols, $maxLength);
   }
   
   public static function formatValue($value) {
        $value = trim($value);
        if (!strlen($value))
            return null;

            
        if(preg_match(self::regexpInput, $value, $matches)) {
           $datetime = new DateTime53;
           $datetime->setTimestamp( mktime(
                empty($matches[5]) ? 0 : $matches[5], // hour
                empty($matches[6]) ? 0 : $matches[6], // minute
                empty($matches[8]) ? 0 : $matches[8], // second
                $matches[2], // month
                $matches[1], // day
                $matches[3] // year
            ) );
            return $datetime->format('Y-m-d H:i:s');
        } else {
            return null;
        }
   }
   

   /**
    * Return value in database format
    * @return string|null
    */
   public function getValue()
   {
     return self::formatValue($this->value);
   }

   /**
    * Set value in human format
    * @param string Value
    * @return void
    */
   public function setValue($value)
   {
     if($value instanceof DateTime)
        $value = $value->format('j.n.Y H:i');
     else
        $value = preg_replace(self::regexpOutput, '$3.$2.$1 $4:$5', $value);
     
     parent::setValue($value);
   }

   /**
    * Generate HTML element
    * @return Html
    */
   public function getControl()
   {
     $control = parent::getControl();

     $control->class[] = 'datetimepicker';
     $control->class[] = 'text';
     //$control->id = $control->id . time();

     return $control;
   }
 }
?>