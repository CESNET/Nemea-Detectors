<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Utils
 */



/**
 * Finder allows searching through directory trees using iterator.
 *
 * <code>
 * Finder::findFiles('*.php')
 *     ->size('> 10kB')
 *     ->from('.')
 *     ->exclude('temp');
 * </code>
 *
 * @author     David Grudl
 * @package Nette\Utils
 */
class Finder extends Object implements IteratorAggregate
{
	/** @var array */
	private $paths = array();

	/** @var array of filters */
	private $groups;

	/** @var filter for recursive traversing */
	private $exclude = array();

	/** @var int */
	private $order = RecursiveIteratorIterator::SELF_FIRST;

	/** @var int */
	private $maxDepth = -1;

	/** @var array */
	private $cursor;



	/**
	 * Begins search for files matching mask and all directories.
	 * @param  mixed
	 * @return Finder
	 */
	public static function find($mask)
	{
		if (!is_array($mask)) {
			$mask = func_get_args();
		}
		$finder = new self;
		return $finder->select(array(), 'isDir')->select($mask, 'isFile');
	}



	/**
	 * Begins search for files matching mask.
	 * @param  mixed
	 * @return Finder
	 */
	public static function findFiles($mask)
	{
		if (!is_array($mask)) {
			$mask = func_get_args();
		}
		$finder = new self;
		return $finder->select($mask, 'isFile');
	}



	/**
	 * Begins search for directories matching mask.
	 * @param  mixed
	 * @return Finder
	 */
	public static function findDirectories($mask)
	{
		if (!is_array($mask)) {
			$mask = func_get_args();
		}
		$finder = new self;
		return $finder->select($mask, 'isDir');
	}



	/**
	 * Creates filtering group by mask & type selector.
	 * @param  array
	 * @param  string
	 * @return Finder  provides a fluent interface
	 */
	private function select($masks, $type)
	{
		$this->cursor = & $this->groups[];
		$pattern = self::buildPattern($masks);
		if ($type || $pattern) {
			$this->filter(create_function('$file', 'extract($GLOBALS[0]['.array_push($GLOBALS[0], array('type'=>$type,'pattern'=> $pattern)).'-1], EXTR_REFS);
				return !$file->isDot()
					&& (!$type || $file->$type())
					&& (!$pattern || preg_match($pattern, \'/\' . strtr($file->getSubPathName(), \'\\\\\', \'/\')));
			'));
		}
		return $this;
	}



	/**
	 * Searchs in the given folder(s).
	 * @param  string|array
	 * @return Finder  provides a fluent interface
	 */
	public function in($path)
	{
		if (!is_array($path)) {
			$path = func_get_args();
		}
		$this->maxDepth = 0;
		return $this->from($path);
	}



	/**
	 * Searchs recursively from the given folder(s).
	 * @param  string|array
	 * @return Finder  provides a fluent interface
	 */
	public function from($path)
	{
		if ($this->paths) {
			throw new InvalidStateException('Directory to search has already been specified.');
		}
		if (!is_array($path)) {
			$path = func_get_args();
		}
		$this->paths = $path;
		$this->cursor = & $this->exclude;
		return $this;
	}



	/**
	 * Shows folder content prior to the folder.
	 * @return Finder  provides a fluent interface
	 */
	public function childFirst()
	{
		$this->order = RecursiveIteratorIterator::CHILD_FIRST;
		return $this;
	}



	/**
	 * Converts Finder pattern to regular expression.
	 * @param  array
	 * @return string
	 */
	private static function buildPattern($masks)
	{
		$pattern = array();
		// TODO: accept regexp
		foreach ($masks as $mask) {
			$mask = rtrim(strtr($mask, '\\', '/'), '/');
			$prefix = '';
			if ($mask === '') {
				continue;

			} elseif ($mask === '*') {
				return NULL;

			} elseif ($mask[0] === '/') { // absolute fixing
				$mask = ltrim($mask, '/');
				$prefix = '(?<=^/)';
			}
			$pattern[] = $prefix . strtr(preg_quote($mask, '#'),
				array('\*\*' => '.*', '\*' => '[^/]*', '\?' => '[^/]', '\[\!' => '[^', '\[' => '[', '\]' => ']', '\-' => '-'));
		}
		return $pattern ? '#/(' . implode('|', $pattern) . ')\z#i' : NULL;
	}



	/********************* iterator generator ****************d*g**/



	/**
	 * Returns iterator.
	 * @return Iterator
	 */
	public function getIterator()
	{
		if (!$this->paths) {
			throw new InvalidStateException('Call in() or from() to specify directory to search.');

		} elseif (count($this->paths) === 1) {
			return $this->buildIterator($this->paths[0]);

		} else {
			$iterator = new AppendIterator();
			$iterator->append($workaround = new ArrayIterator(array('workaround PHP bugs #49104, #63077')));
			foreach ($this->paths as $path) {
				$iterator->append($this->buildIterator($path));
			}
			unset($workaround[0]);
			return $iterator;
		}
	}



	/**
	 * Returns per-path iterator.
	 * @param  string
	 * @return Iterator
	 */
	private function buildIterator($path)
	{
		if (PHP_VERSION_ID < 50301) {
			$iterator = new RecursiveDirectoryIteratorFixed($path);
		} else {
			$iterator = new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::FOLLOW_SYMLINKS);
		}

		if ($this->exclude) {
			$filters = $this->exclude;
			$iterator = new NRecursiveCallbackFilterIterator($iterator, create_function('$file', 'extract($GLOBALS[0]['.array_push($GLOBALS[0], array('filters'=>$filters)).'-1], EXTR_REFS);
				if (!$file->isDot() && !$file->isFile()) {
					foreach ($filters as $filter) {
						if (!call_user_func($filter, $file)) {
							return FALSE;
						}
					}
				}
				return TRUE;
			'));
		}

		if ($this->maxDepth !== 0) {
			$iterator = new RecursiveIteratorIterator($iterator, $this->order);
			$iterator->setMaxDepth($this->maxDepth);
		}

		if ($this->groups) {
			$groups = $this->groups;
			$iterator = new NCallbackFilterIterator($iterator, create_function('$file', 'extract($GLOBALS[0]['.array_push($GLOBALS[0], array('groups'=>$groups)).'-1], EXTR_REFS);
				foreach ($groups as $filters) {
					foreach ($filters as $filter) {
						if (!call_user_func($filter, $file)) {
							continue 2;
						}
					}
					return TRUE;
				}
				return FALSE;
			'));
		}

		return $iterator;
	}



	/********************* filtering ****************d*g**/



	/**
	 * Restricts the search using mask.
	 * Excludes directories from recursive traversing.
	 * @param  mixed
	 * @return Finder  provides a fluent interface
	 */
	public function exclude($masks)
	{
		if (!is_array($masks)) {
			$masks = func_get_args();
		}
		$pattern = self::buildPattern($masks);
		if ($pattern) {
			$this->filter(create_function('$file', 'extract($GLOBALS[0]['.array_push($GLOBALS[0], array('pattern'=>$pattern)).'-1], EXTR_REFS);
				return !preg_match($pattern, \'/\' . strtr($file->getSubPathName(), \'\\\\\', \'/\'));
			'));
		}
		return $this;
	}



	/**
	 * Restricts the search using callback.
	 * @param  callable
	 * @return Finder  provides a fluent interface
	 */
	public function filter($callback)
	{
		$this->cursor[] = $callback;
		return $this;
	}



	/**
	 * Limits recursion level.
	 * @param  int
	 * @return Finder  provides a fluent interface
	 */
	public function limitDepth($depth)
	{
		$this->maxDepth = $depth;
		return $this;
	}



	/**
	 * Restricts the search by size.
	 * @param  string  "[operator] [size] [unit]" example: >=10kB
	 * @param  int
	 * @return Finder  provides a fluent interface
	 */
	public function size($operator, $size = NULL)
	{
		if (func_num_args() === 1) { // in $operator is predicate
			if (!preg_match('#^(?:([=<>!]=?|<>)\s*)?((?:\d*\.)?\d+)\s*(K|M|G|)B?\z#i', $operator, $matches)) {
				throw new InvalidArgumentException('Invalid size predicate format.');
			}
			list(, $operator, $size, $unit) = $matches;
			static $units = array('' => 1, 'k' => 1e3, 'm' => 1e6, 'g' => 1e9);
			$size *= $units[strtolower($unit)];
			$operator = $operator ? $operator : '=';
		}
		return $this->filter(create_function('$file', 'extract($GLOBALS[0]['.array_push($GLOBALS[0], array('operator'=>$operator,'size'=> $size)).'-1], EXTR_REFS);
			return Finder::compare($file->getSize(), $operator, $size);
		'));
	}



	/**
	 * Restricts the search by modified time.
	 * @param  string  "[operator] [date]" example: >1978-01-23
	 * @param  mixed
	 * @return Finder  provides a fluent interface
	 */
	public function date($operator, $date = NULL)
	{
		if (func_num_args() === 1) { // in $operator is predicate
			if (!preg_match('#^(?:([=<>!]=?|<>)\s*)?(.+)\z#i', $operator, $matches)) {
				throw new InvalidArgumentException('Invalid date predicate format.');
			}
			list(, $operator, $date) = $matches;
			$operator = $operator ? $operator : '=';
		}
		$date = DateTime53::from($date)->format('U');
		return $this->filter(create_function('$file', 'extract($GLOBALS[0]['.array_push($GLOBALS[0], array('operator'=>$operator,'date'=> $date)).'-1], EXTR_REFS);
			return Finder::compare($file->getMTime(), $operator, $date);
		'));
	}



	/**
	 * Compares two values.
	 * @param  mixed
	 * @param  mixed
	 * @return bool
	 */
	public static function compare($l, $operator, $r)
	{
		switch ($operator) {
		case '>':
			return $l > $r;
		case '>=':
			return $l >= $r;
		case '<':
			return $l < $r;
		case '<=':
			return $l <= $r;
		case '=':
		case '==':
			return $l == $r;
		case '!':
		case '!=':
		case '<>':
			return $l != $r;
		}
		throw new InvalidArgumentException("Unknown operator $operator.");
	}

}



if (PHP_VERSION_ID < 50301) {
	/** @internal */
	class RecursiveDirectoryIteratorFixed extends RecursiveDirectoryIterator
	{
		function hasChildren()
		{
			return parent::hasChildren(TRUE);
		}
	}
}
