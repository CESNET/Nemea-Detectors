<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Templating
 */



/**
 * Template stored in file.
 *
 * @author     David Grudl
 * @package Nette\Templating
 */
class FileTemplate extends Template implements IFileTemplate
{
	/** @var string */
	private $file;



	/**
	 * Constructor.
	 * @param  string  template file path
	 */
	public function __construct($file = NULL)
	{
		if ($file !== NULL) {
			$this->setFile($file);
		}
	}



	/**
	 * Sets the path to the template file.
	 * @param  string  template file path
	 * @return FileTemplate  provides a fluent interface
	 */
	public function setFile($file)
	{
		$this->file = realpath($file);
		if (!$this->file) {
			throw new FileNotFoundException("Missing template file '$file'.");
		}
		return $this;
	}



	/**
	 * Returns the path to the template file.
	 * @return string  template file path
	 */
	public function getFile()
	{
		return $this->file;
	}



	/**
	 * Returns template source code.
	 * @return string
	 */
	public function getSource()
	{
		return file_get_contents($this->file);
	}



	/********************* rendering ****************d*g**/



	/**
	 * Renders template to output.
	 * @return void
	 */
	public function render()
	{
		if ($this->file == NULL) { // intentionally ==
			throw new InvalidStateException("Template file name was not specified.");
		}

		$cache = new Cache($storage = $this->getCacheStorage(), 'Nette.FileTemplate');
		if ($storage instanceof PhpFileStorage) {
			$storage->hint = str_replace(dirname(dirname($this->file)), '', $this->file);
		}
		$cached = $compiled = $cache->load($this->file);

		if ($compiled === NULL) {
			try {
				$compiled = "<?php\n\n// source file: $this->file\n\n?>" . $this->compile();

			} catch (TemplateException $e) {
				$e->setSourceFile($this->file);
				throw $e;
			}

			$cache->save($this->file, $compiled, array(
				Cache::FILES => $this->file,
				Cache::CONSTS => 'Framework::REVISION',
			));
			$cached = $cache->load($this->file);
		}

		if ($cached !== NULL && $storage instanceof PhpFileStorage) {
			LimitedScope::load($cached['file'], $this->getParameters());
		} else {
			LimitedScope::evaluate($compiled, $this->getParameters());
		}
	}

}
