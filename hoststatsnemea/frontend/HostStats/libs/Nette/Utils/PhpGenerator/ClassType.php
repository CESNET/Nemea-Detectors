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
 * Class/Interface/Trait description.
 *
 * @author     David Grudl
 *
 * @method ClassType setName(string $name)
 * @method ClassType setType(string $type)
 * @method ClassType setFinal(bool $on)
 * @method ClassType setAbstract(bool $on)
 * @method ClassType addExtend(string $class)
 * @method ClassType addImplement(string $interface)
 * @method ClassType addTrait(string $trait)
 * @method ClassType addDocument(string $doc)
 * @package Nette\Utils\PhpGenerator
 */
class PhpClassType extends Object
{
	/** @var string */
	public $name;

	/** @var string  class|interface|trait */
	public $type = 'class';

	/** @var bool */
	public $final;

	/** @var bool */
	public $abstract;

	/** @var string[] */
	public $extends = array();

	/** @var string[] */
	public $implements = array();

	/** @var string[] */
	public $traits = array();

	/** @var string[] */
	public $documents = array();

	/** @var mixed[] name => value */
	public $consts = array();

	/** @var PhpProperty[] name => Property */
	public $properties = array();

	/** @var PhpMethod[] name => Method */
	public $methods = array();


	public function __construct($name = NULL)
	{
		$this->name = $name;
	}



	/** @return PhpClassType */
	public function addConst($name, $value)
	{
		$this->consts[$name] = $value;
		return $this;
	}



	/** @return PhpProperty */
	public function addProperty($name, $value = NULL)
	{
		$property = new PhpProperty;
		return $this->properties[$name] = $property->setName($name)->setValue($value);
	}



	/** @return PhpMethod */
	public function addMethod($name)
	{
		$method = new PhpMethod;
		if ($this->type === 'interface') {
			$method->setVisibility('')->setBody(FALSE);
		} else {
			$method->setVisibility('public');
		}
		return $this->methods[$name] = $method->setName($name);
	}



	public function __call($name, $args)
	{
		return ObjectMixin::callProperty($this, $name, $args);
	}



	/** @return string  PHP code */
	public function __toString()
	{
		$consts = array();
		foreach ($this->consts as $name => $value) {
			$consts[] = "const $name = " . PhpHelpers::dump($value) . ";\n";
		}
		$properties = array();
		foreach ($this->properties as $property) {
			$properties[] = ($property->documents ? str_replace("\n", "\n * ", "/**\n" . implode("\n", (array) $property->documents)) . "\n */\n" : '')
				. $property->visibility . ($property->static ? ' static' : '') . ' $' . $property->name
				. ($property->value === NULL ? '' : ' = ' . PhpHelpers::dump($property->value))
				. ";\n";
		}
		return Strings::normalize(
			($this->documents ? str_replace("\n", "\n * ", "/**\n" . implode("\n", (array) $this->documents)) . "\n */\n" : '')
			. ($this->abstract ? 'abstract ' : '')
			. ($this->final ? 'final ' : '')
			. $this->type . ' '
			. $this->name . ' '
			. ($this->extends ? 'extends ' . implode(', ', (array) $this->extends) . ' ' : '')
			. ($this->implements ? 'implements ' . implode(', ', (array) $this->implements) . ' ' : '')
			. "\n{\n\n"
			. Strings::indent(
				($this->traits ? "use " . implode(', ', (array) $this->traits) . ";\n\n" : '')
				. ($this->consts ? implode('', $consts) . "\n\n" : '')
				. ($this->properties ? implode("\n", $properties) . "\n\n" : '')
				. implode("\n\n\n", $this->methods), 1)
			. "\n\n}") . "\n";
	}

}
