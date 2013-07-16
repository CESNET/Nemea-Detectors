<?php

/**
 * Date picker to Nette Form
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
class DatePicker extends /*Nette\Forms\*/TextInput
{
    
    public static function addDatePicker($form, $name, $label,  $cols = NULL, $maxLength = NULL)
   {
        return $form[$name] = new DatePicker($label, $cols, $maxLength);
   }

	/**
	 * @param  string  label
	 * @param  int  width of the control
	 * @param  int  maximum number of characters the user may enter
	 */
	public function __construct($label, $cols = NULL, $maxLenght = NULL)
	{
		parent::__construct($label, $cols, $maxLenght);
	}


	/**
	 * Returns control's value.
	 * @return mixed 
	 */
	public function getValue()
	{
        $value = trim($this->value);
		if (strlen($value)) {
			$tmp = preg_replace('~([[:space:]])~', '', $value);
			$tmp = explode('.', $tmp);
            if(empty($tmp[2]) || empty($tmp[1]) || empty($tmp[0]))
                return null;
			// database format Y-m-d
			return new DateTime53($tmp[2] . '-' . $tmp[1] . '-' . $tmp[0]);
		}
		
		return $value;
	}


	/**
	 * Sets control's value.
	 * @param  string
	 * @return void
	 */
	public function setValue($value)
	{
        if($value instanceof DateTime)
            $value = $value->format('j.n.Y');
        else
		    $value = preg_replace('~([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})~', '$3.$2.$1', $value);
		parent::setValue($value);
	}


	/**
	 * Generates control's HTML element.
	 * @return Html
	 */
	public function getControl()
	{		
		$control = parent::getControl();
        $control->class[] = 'datepicker';
        $control->class[] = 'text';
		//$control->id = $control->id . time();
		return $control;
	}

}