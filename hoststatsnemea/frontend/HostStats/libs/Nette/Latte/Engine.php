<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Latte
 */



/**
 * Templating engine Latte.
 *
 * @author     David Grudl
 * @package Nette\Latte
 */
class LatteFilter extends Object
{
	/** @var Parser */
	private $parser;

	/** @var LatteCompiler */
	private $compiler;



	public function __construct()
	{
		$this->parser = new Parser;
		$this->compiler = new LatteCompiler;
		$this->compiler->defaultContentType = LatteCompiler::CONTENT_XHTML;

		CoreMacros::install($this->compiler);
		$this->compiler->addMacro('cache', new CacheMacro($this->compiler));
		UIMacros::install($this->compiler);
		FormMacros::install($this->compiler);
	}



	/**
	 * Invokes filter.
	 * @param  string
	 * @return string
	 */
	public function __invoke($s)
	{
		return $this->compiler->compile($this->parser->parse($s));
	}



	/**
	 * @return Parser
	 */
	public function getParser()
	{
		return $this->parser;
	}



	/**
	 * @return LatteCompiler
	 */
	public function getCompiler()
	{
		return $this->compiler;
	}

}
