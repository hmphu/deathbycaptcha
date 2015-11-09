<?php
/**
 * @Author: Phu Hoang
 * @Date:   2015-11-09 15:49:03
 * @Last Modified by:   Phu Hoang
 * @Last Modified time: 2015-11-09 15:58:49
 */
namespace hmphu\deathbycaptcha;

/**
 * Exception to throw on rejected login attemts due to invalid DBC credentials, low balance, or when account being banned.
 *
 * @package DBCAPI
 * @subpackage PHP
 */
class AccessDeniedException extends ClientException
{}