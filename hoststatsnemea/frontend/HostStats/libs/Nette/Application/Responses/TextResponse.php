<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Application\Responses
 */



/**
 * String output response.
 *
 * @author     David Grudl
 *
 * @property-read mixed $source
 * @package Nette\Application\Responses
 */
class TextResponse extends Object implements IPresenterResponse
{
	/** @var mixed */
	private $source;



	/**
	 * @param  mixed  renderable variable
	 */
	public function __construct($source)
	{
		$this->source = $source;
	}



	/**
	 * @return mixed
	 */
	final public function getSource()
	{
		return $this->source;
	}



	/**
	 * Sends response to output.
	 * @return void
	 */
	public function send(IHttpRequest $httpRequest, IHttpResponse $httpResponse)
	{
		if ($this->source instanceof ITemplate) {
			$this->source->render();

		} else {
			echo $this->source;
		}
	}

}
