<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Http
 */



/**
 * HTTP-specific tasks.
 *
 * @author     David Grudl
 *
 * @property-read bool $modified
 * @property-read IHttpRequest $request
 * @property-read IHttpResponse $response
 * @package Nette\Http
 */
class HttpContext extends Object
{
	/** @var IHttpRequest */
	private $request;

	/** @var IHttpResponse */
	private $response;



	public function __construct(IHttpRequest $request, IHttpResponse $response)
	{
		$this->request = $request;
		$this->response = $response;
	}



	/**
	 * Attempts to cache the sent entity by its last modification date.
	 * @param  string|int|DateTime  last modified time
	 * @param  string  strong entity tag validator
	 * @return bool
	 */
	public function isModified($lastModified = NULL, $etag = NULL)
	{
		if ($lastModified) {
			$this->response->setHeader('Last-Modified', $this->response->date($lastModified));
		}
		if ($etag) {
			$this->response->setHeader('ETag', '"' . addslashes($etag) . '"');
		}

		$ifNoneMatch = $this->request->getHeader('If-None-Match');
		if ($ifNoneMatch === '*') {
			$match = TRUE; // match, check if-modified-since

		} elseif ($ifNoneMatch !== NULL) {
			$etag = $this->response->getHeader('ETag');

			if ($etag == NULL || strpos(' ' . strtr($ifNoneMatch, ",\t", '  '), ' ' . $etag) === FALSE) {
				return TRUE;

			} else {
				$match = TRUE; // match, check if-modified-since
			}
		}

		$ifModifiedSince = $this->request->getHeader('If-Modified-Since');
		if ($ifModifiedSince !== NULL) {
			$lastModified = $this->response->getHeader('Last-Modified');
			if ($lastModified != NULL && strtotime($lastModified) <= strtotime($ifModifiedSince)) {
				$match = TRUE;

			} else {
				return TRUE;
			}
		}

		if (empty($match)) {
			return TRUE;
		}

		$this->response->setCode(IHttpResponse::S304_NOT_MODIFIED);
		return FALSE;
	}



	/**
	 * @return IHttpRequest
	 */
	public function getRequest()
	{
		return $this->request;
	}



	/**
	 * @return IHttpResponse
	 */
	public function getResponse()
	{
		return $this->response;
	}

}
