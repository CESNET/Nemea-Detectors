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
 * Applies the callback to the elements of the inner iterator.
 *
 * @author     David Grudl
 * @package Nette\Iterators
 */
class MapIterator extends IteratorIterator
{
	/** @var callable */
	private $callback;


	public function __construct(Traversable $iterator, $callback)
	{
		parent::__construct($iterator);
		$this->callback = new Callback($callback);
	}



	public function current()
	{
		return $this->callback->invoke(parent::current(), parent::key());
	}

}
