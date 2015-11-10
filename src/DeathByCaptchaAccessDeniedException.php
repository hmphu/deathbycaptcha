<?php
/**
 * @Author: Phu Hoang
 * @Date:   2015-11-09 16:09:25
 * @Last Modified by:   Phu Hoang
 * @Last Modified time: 2015-11-09 16:12:20
 */

namespace hmphu\deathbycaptcha;

/**
 * Exception to throw on rejected login attemts due to invalid DBC credentials, low balance, or when account being banned.
 *
 * @package DBCAPI
 * @subpackage PHP
 */
class DeathByCaptchaAccessDeniedException extends DeathByCaptchaClientException
{}