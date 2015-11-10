<?php
/**
 * @Author: Phu Hoang
 * @Date:   2015-11-09 16:09:25
 * @Last Modified by:   Phu Hoang
 * @Last Modified time: 2015-11-09 16:13:04
 */

namespace hmphu\deathbycaptcha;

/**
 * Base Death by Captcha API client
 *
 * @property-read array|null $user    User's details
 * @property-read float|null $balance User's balance (in US cents)
 *
 * @package DBCAPI
 * @subpackage PHP
 */
abstract class DeathByCaptchaClient
{
    const API_VERSION = 'DBC/PHP v4.1.1';

    const DEFAULT_TIMEOUT = 60;
    const POLLS_INTERVAL = 5;


    /**
     * DBC account credentials
     *
     * @var array
     */
    protected $_userpwd = array();


    /**
     * Verbosity flag.
     * When it's set to true, the client will produce debug output on every API call.
     *
     * @var bool
     */
    public $is_verbose = false;


    /**
     * Parses URL query encoded responses
     *
     * @param string $s
     * @return array
     */
    static public function parse_plain_response($s)
    {
        parse_str($s, $a);
        return $a;
    }

    /**
     * Parses JSON encoded response
     *
     * @param string $s
     * @return array
     */
    static public function parse_json_response($s)
    {
        return json_decode(rtrim($s), true);
    }


    /**
     * Checks if CAPTCHA is valid (not empty)
     *
     * @param string $img Raw CAPTCHA image
     * @throws DeathByCaptchaInvalidCaptchaException On invalid CAPTCHA images
     */
    protected function _is_valid_captcha($img)
    {
        if (0 == strlen($img)) {
            throw new DeathByCaptchaInvalidCaptchaException(
                'CAPTCHA image file is empty'
            );
        } else {
            return true;
        }
    }

    protected function _load_captcha($captcha)
    {
        if (is_resource($captcha)) {
            $img = '';
            rewind($captcha);
            while ($s = fread($captcha, 8192)) {
                $img .= $s;
            }
            return $img;
        } else if (is_array($captcha)) {
            return implode('', array_map('chr', $captcha));
        } else if ('base64:' == substr($captcha, 0, 7)) {
            return base64_decode(substr($captcha, 7));
        } else {
            return file_get_contents($captcha);
        }
    }


    /**
     * Closes opened connection (if any), as gracefully as possible
     *
     * @return DeathByCaptchaClient
     */
    abstract public function close();

    /**
     * Returns user details
     *
     * @return array|null
     */
    abstract public function get_user();

    /**
     * Returns user's balance (in US cents)
     *
     * @uses DeathByCaptchaClient::get_user()
     * @return float|null
     */
    public function get_balance()
    {
        return ($user = $this->get_user()) ? $user['balance'] : null;
    }

    /**
     * Returns CAPTCHA details
     *
     * @param int $cid CAPTCHA ID
     * @return array|null
     */
    abstract public function get_captcha($cid);

    /**
     * Returns CAPTCHA text
     *
     * @uses DeathByCaptchaClient::get_captcha()
     * @param int $cid CAPTCHA ID
     * @return string|null
     */
    public function get_text($cid)
    {
        return ($captcha = $this->get_captcha($cid)) ? $captcha['text'] : null;
    }

    /**
     * Reports an incorrectly solved CAPTCHA
     *
     * @param int $cid CAPTCHA ID
     * @return bool
     */
    abstract public function report($cid);

    /**
     * Uploads a CAPTCHA
     *
     * @param string|array|resource $captcha CAPTCHA image file name, vector of bytes, or file handle
     * @return array|null Uploaded CAPTCHA details on success
     * @throws DeathByCaptchaInvalidCaptchaException On invalid CAPTCHA file
     */
    abstract public function upload($captcha);

    /**
     * Tries to solve CAPTCHA by uploading it and polling for its status/text
     * with arbitrary timeout. See {@link DeathByCaptchaClient::upload()} for
     * $captcha param details.
     *
     * @uses DeathByCaptchaClient::upload()
     * @uses DeathByCaptchaClient::get_captcha()
     * @param int $timeout Optional solving timeout (in seconds)
     * @return array|null CAPTCHA details hash on success
     */
    public function decode($captcha, $timeout=self::DEFAULT_TIMEOUT)
    {
        $deadline = time() + (0 < $timeout ? $timeout : self::DEFAULT_TIMEOUT);
        if ($c = $this->upload($captcha)) {
            while ($deadline > time() && $c && !$c['text']) {
                sleep(self::POLLS_INTERVAL);
                $c = $this->get_captcha($c['captcha']);
            }
            if ($c && $c['text'] && $c['is_correct']) {
                return $c;
            }
        }
        return null;
    }

    /**
     * @param string $username DBC account username
     * @param string $password DBC account password
     * @throws DeathByCaptchaRuntimeException On missing/empty DBC account credentials
     * @throws DeathByCaptchaRuntimeException When required extensions/functions not found
     */
    public function __construct($username, $password)
    {
        foreach (array('username', 'password') as $k) {
            if (!$$k) {
                throw new DeathByCaptchaRuntimeException(
                    "Account {$k} is missing or empty"
                );
            }
        }
        $this->_userpwd = array($username, $password);
    }

    /**
     * @ignore
     */
    public function __destruct()
    {
        $this->close();
    }

    /**
     * @ignore
     */
    public function __get($key)
    {
        switch ($key) {
        case 'user':
            return $this->get_user();
        case 'balance':
            return $this->get_balance();
        }
    }
}
