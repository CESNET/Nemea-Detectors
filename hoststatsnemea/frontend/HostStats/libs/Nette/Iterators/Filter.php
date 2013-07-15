<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Iterators
 */



/**
 * Callback iterator filter.
 *
 * @author     David Grudl
 * @package Nette\Iterators
 */
class NCallbackFilterIterator extends FilterIterator
{
	/** @var callable */
	private $callback;


	public function __construct(Iterator $iterator, $callback)
	{
		parent::__construct($iterator);
		$this->callback = new Callback($callback);
	}



	public function accept()
	{
		return $this->callback->invoke($this);
	}

}
