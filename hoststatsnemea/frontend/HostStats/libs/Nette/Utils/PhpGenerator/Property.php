<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Utils\PhpGenerator
 */



/**
 * Class property description.
 *
 * @author     David Grudl
 *
 * @method Property setName(string $name)
 * @method Property setValue(mixed $value)
 * @method Property setStatic(bool $on)
 * @method Property setVisibility(string $access)
 * @method Property addDocument(string $doc)
 * @package Nette\Utils\PhpGenerator
 */
class PhpProperty extends Object
{
	/** @var string */
	public $name;

	/** @var mixed */
	public $value;

	/** @var bool */
	public $static;

	/** @var string  public|protected|private */
	public $visibility = 'public';

	/** @var array of string */
	public $documents = array();


	public function __call($name, $args)
	{
		return ObjectMixin::callProperty($this, $name, $args);
	}

}
