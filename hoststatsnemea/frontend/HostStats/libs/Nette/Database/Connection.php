<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Database
 */



/**
 * Represents a connection between PHP and a database server.
 *
 * @author     David Grudl
 *
 * @property       IReflection          $databaseReflection
 * @property-read  ISupplementalDriver  $supplementalDriver
 * @property-read  string               $dsn
 * @package Nette\Database
 */
class Connection extends PDO
{
	/** @var string */
	private $dsn;

	/** @var ISupplementalDriver */
	private $driver;

	/** @var SqlPreprocessor */
	private $preprocessor;

	/** @var IReflection */
	private $databaseReflection;

	/** @var Cache */
	private $cache;

	/** @var array of function(Statement $result, $params); Occurs after query is executed */
	public $onQuery;



	public function __construct($dsn, $username = NULL, $password = NULL, array $options = NULL, $driverClass = NULL)
	{
		parent::__construct($this->dsn = $dsn, $username, $password, $options);
		$this->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$this->setAttribute(PDO::ATTR_STATEMENT_CLASS, array('Statement', array($this)));

		$driverClass = ($tmp=$driverClass) ? $tmp : '' . ucfirst(str_replace('sql', 'Sql', $this->getAttribute(PDO::ATTR_DRIVER_NAME))) . 'Driver';
		$this->driver = new $driverClass($this, (array) $options);
		$this->preprocessor = new SqlPreprocessor($this);
	}



	public function getDsn()
	{
		return $this->dsn;
	}



	/** @return ISupplementalDriver */
	public function getSupplementalDriver()
	{
		return $this->driver;
	}



	/**
	 * Sets database reflection.
	 * @return Connection   provides a fluent interface
	 */
	public function setDatabaseReflection(IReflection $databaseReflection)
	{
		$databaseReflection->setConnection($this);
		$this->databaseReflection = $databaseReflection;
		return $this;
	}



	/** @return IReflection */
	public function getDatabaseReflection()
	{
		if (!$this->databaseReflection) {
			$this->setDatabaseReflection(new ConventionalReflection);
		}
		return $this->databaseReflection;
	}



	/**
	 * Sets cache storage engine.
	 * @return Connection   provides a fluent interface
	 */
	public function setCacheStorage(ICacheStorage $storage = NULL)
	{
		$this->cache = $storage ? new Cache($storage, 'Nette.Database.' . md5($this->dsn)) : NULL;
		return $this;
	}



	public function getCache()
	{
		return $this->cache;
	}



	/**
	 * Generates and executes SQL query.
	 * @param  string  statement
	 * @param  mixed   [parameters, ...]
	 * @return Statement
	 */
	public function query($statement)
	{
		$args = func_get_args();
		return $this->queryArgs(array_shift($args), $args);
	}



	/**
	 * Generates and executes SQL query.
	 * @param  string  statement
	 * @param  mixed   [parameters, ...]
	 * @return int     number of affected rows
	 */
	public function exec($statement)
	{
		$args = func_get_args();
		return $this->queryArgs(array_shift($args), $args)->rowCount();
	}



	/**
	 * @param  string  statement
	 * @param  array
	 * @return Statement
	 */
	public function queryArgs($statement, $params)
	{
		foreach ($params as $value) {
			if (is_array($value) || is_object($value)) {
				$need = TRUE; break;
			}
		}
		if (isset($need) && $this->preprocessor !== NULL) {
			list($statement, $params) = $this->preprocessor->process($statement, $params);
		}

		return $this->prepare($statement)->execute($params);
	}



	/********************* shortcuts ****************d*g**/



	/**
	 * Shortcut for query()->fetch()
	 * @param  string  statement
	 * @param  mixed   [parameters, ...]
	 * @return Row
	 */
	public function fetch($args)
	{
		$args = func_get_args();
		return $this->queryArgs(array_shift($args), $args)->fetch();
	}



	/**
	 * Shortcut for query()->fetchColumn()
	 * @param  string  statement
	 * @param  mixed   [parameters, ...]
	 * @return mixed
	 */
	public function fetchColumn($args)
	{
		$args = func_get_args();
		return $this->queryArgs(array_shift($args), $args)->fetchColumn();
	}



	/**
	 * Shortcut for query()->fetchPairs()
	 * @param  string  statement
	 * @param  mixed   [parameters, ...]
	 * @return array
	 */
	public function fetchPairs($args)
	{
		$args = func_get_args();
		return $this->queryArgs(array_shift($args), $args)->fetchPairs();
	}



	/**
	 * Shortcut for query()->fetchAll()
	 * @param  string  statement
	 * @param  mixed   [parameters, ...]
	 * @return array
	 */
	public function fetchAll($args)
	{
		$args = func_get_args();
		return $this->queryArgs(array_shift($args), $args)->fetchAll();
	}



	/********************* selector ****************d*g**/



	/**
	 * Creates selector for table.
	 * @param  string
	 * @return TableSelection
	 */
	public function table($table)
	{
		return new TableSelection($table, $this);
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
