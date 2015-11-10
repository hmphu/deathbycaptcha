<?php
/**
 * @Author: Phu Hoang
 * @Date:   2015-11-09 16:09:25
 * @Last Modified by:   Phu Hoang
 * @Last Modified time: 2015-11-09 16:12:28
 */

namespace hmphu\deathbycaptcha;

/**
 * Exception to throw on invalid CAPTCHA image payload: on empty images, on images too big, on non-image payloads.
 *
 * @package DBCAPI
 * @subpackage PHP
 */
class DeathByCaptchaInvalidCaptchaException extends DeathByCaptchaClientException
{}
