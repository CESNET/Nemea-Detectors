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
 * Redirects to new URI.
 *
 * @author     David Grudl
 *
 * @property-read string $url
 * @property-read int $code
 * @package Nette\Application\Responses
 */
class RedirectResponse extends Object implements IPresenterResponse
{
	/** @var string */
	private $url;

	/** @var int */
	private $code;



	/**
	 * @param  string  URI
	 * @param  int     HTTP code 3xx
	 */
	public function __construct($url, $code = IHttpResponse::S302_FOUND)
	{
		$this->url = (string) $url;
		$this->code = (int) $code;
	}



	/**
	 * @return string
	 */
	final public function getUrl()
	{
		return $this->url;
	}



	/**
	 * @return int
	 */
	final public function getCode()
	{
		return $this->code;
	}



	/**
	 * Sends response to output.
	 * @return void
	 */
	public function send(IHttpRequest $httpRequest, IHttpResponse $httpResponse)
	{
		$httpResponse->redirect($this->url, $this->code);
	}

}
