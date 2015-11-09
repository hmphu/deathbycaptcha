<?php
/**
 * @Author: Phu Hoang
 * @Date:   2015-11-09 15:49:03
 * @Last Modified by:   Phu Hoang
 * @Last Modified time: 2015-11-09 15:58:49
 */
namespace hmphu\deathbycaptcha;

/**
 * Exception to throw on invalid CAPTCHA image payload: on empty images, on images too big, on non-image payloads.
 *
 * @package DBCAPI
 * @subpackage PHP
 */
class InvalidCaptchaException extends ClientException
{}