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
 * Callback recursive iterator filter.
 *
 * @author     David Grudl
 * @package Nette\Iterators
 */
class NRecursiveCallbackFilterIterator extends FilterIterator implements RecursiveIterator
{
	/** @var callable */
	private $callback;

	/** @var callable */
	private $childrenCallback;


	public function __construct(RecursiveIterator $iterator, $callback, $childrenCallback = NULL)
	{
		parent::__construct($iterator);
		$this->callback = $callback === NULL ? NULL : new Callback($callback);
		$this->childrenCallback = $childrenCallback === NULL ? NULL : new Callback($childrenCallback);
	}



	public function accept()
	{
		return $this->callback === NULL || $this->callback->invoke($this);
	}



	public function hasChildren()
	{
		return $this->getInnerIterator()->hasChildren()
			&& ($this->childrenCallback === NULL || $this->childrenCallback->invoke($this));
	}



	public function getChildren()
	{
		return new self($this->getInnerIterator()->getChildren(), $this->callback, $this->childrenCallback);
	}

}
