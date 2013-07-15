<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Reflection
 */



/**
 * Reports information about a method's parameter.
 *
 * @author     David Grudl
 * @property-read ClassReflection $class
 * @property-read string $className
 * @property-read ClassReflection $declaringClass
 * @property-read MethodReflection $declaringFunction
 * @property-read string $name
 * @property-read bool $passedByReference
 * @property-read bool $array
 * @property-read int $position
 * @property-read bool $optional
 * @property-read bool $defaultValueAvailable
 * @property-read mixed $defaultValue
 * @package Nette\Reflection
 */
class ParameterReflection extends ReflectionParameter
{
	/** @var mixed */
	private $function;


	public function __construct($function, $parameter)
	{
		parent::__construct($this->function = $function, $parameter);
	}



	/**
	 * @return ClassReflection
	 */
	public function getClass()
	{
		return ($ref = parent::getClass()) ? new ClassReflection($ref->getName()) : NULL;
	}



	/**
	 * @return string
	 */
	public function getClassName()
	{
		try {
			return ($ref = parent::getClass()) ? $ref->getName() : NULL;
		} catch (ReflectionException $e) {
			if (preg_match('#Class (.+) does not exist#', $e->getMessage(), $m)) {
				return $m[1];
			}
			throw $e;
		}
	}



	/**
	 * @return ClassReflection
	 */
	public function getDeclaringClass()
	{
		return ($ref = parent::getDeclaringClass()) ? new ClassReflection($ref->getName()) : NULL;
	}



	/**
	 * @return MethodReflection|FunctionReflection
	 */
	public function getDeclaringFunction()
	{
		return is_array($this->function)
			? new MethodReflection($this->function[0], $this->function[1])
			: new FunctionReflection($this->function);
	}



	/**
	 * @return bool
	 */
	public function isDefaultValueAvailable()
	{
		if (PHP_VERSION_ID === 50316) { // PHP bug #62988
			try {
				$this->getDefaultValue();
				return TRUE;
			} catch (ReflectionException $e) {
				return FALSE;
			}
		}
		return parent::isDefaultValueAvailable();
	}



	public function __toString()
	{
		return 'Parameter $' . parent::getName() . ' in ' . $this->getDeclaringFunction();
	}



	/********************* Object behaviour ****************d*g**/



	/**
	 * @return ClassReflection
	 */
	public function getReflection()
	{
		return new ClassReflection($this);
	}



	public function __call($name, $args)
	{
		return ObjectMixin::call($this, $name, $args);
	}



	public function &__get($name)
	{
		return ObjectMixin::get($this, $name);
	}



	public function __set($name, $value)
	{
		return ObjectMixin::set($this, $name, $value);
	}



	public function __isset($name)
	{
		return ObjectMixin::has($this, $name);
	}



	public function __unset($name)
	{
		ObjectMixin::remove($this, $name);
	}

}
