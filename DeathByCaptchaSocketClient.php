<?php
/**
 * @Author: Phu Hoang
 * @Date:   2015-11-09 16:09:25
 * @Last Modified by:   Phu Hoang
 * @Last Modified time: 2015-11-09 16:13:18
 */

namespace hmphu\deathbycaptcha;

/**
 * Death by Captcha socket API Client
 *
 * @see DeathByCaptchaClient
 * @package DBCAPI
 * @subpackage PHP
 */
class DeathByCaptchaSocketClient extends DeathByCaptchaClient
{
    const HOST = 'api.dbcapi.me';
    const FIRST_PORT = 8123;
    const LAST_PORT = 8130;

    const TERMINATOR = "\r\n";


    protected $_sock = null;


    /**
     * Opens a socket connection to the API server
     *
     * @throws DeathByCaptchaIOException When API connection fails
     * @throws DeathByCaptchaRuntimeException When socket operations fail
     */
    protected function _connect()
    {
        if (null === $this->_sock) {
            if ($this->is_verbose) {
                fputs(STDERR, time() . " CONN\n");
            }

            $errno = 0;
            $error = '';
            $port = rand(self::FIRST_PORT, self::LAST_PORT);
            $sock = null;

            if (!($sock = @fsockopen(self::HOST, $port, $errno, $error, self::DEFAULT_TIMEOUT))) {
                throw new DeathByCaptchaIOException(
                    'Failed connecting to ' . self::HOST . ":{$port}: fsockopen(): [{$errno}] {$error}"
                );
            } else if (!@stream_set_timeout($sock, self::DEFAULT_TIMEOUT / 4)) {
                fclose($sock);
                throw new DeathByCaptchaIOException(
                    'Failed setting socket timeout'
                );
            } else {
                $this->_sock = $sock;
            }
        }

        return $this;
    }

    /**
     * Socket send()/recv() wrapper
     *
     * @param string $buf Raw API request to send
     * @return string Raw API response on success
     * @throws DeathByCaptchaIOException On network failures
     */
    protected function _sendrecv($buf)
    {
        if ($this->is_verbose) {
            fputs(STDERR, time() . ' SEND: ' . strlen($buf) . ' ' . rtrim($buf) . "\n");
        }

        $buf .= self::TERMINATOR;
        $response = '';
        while (true) {
            if ($buf) {
                if (!($n = fwrite($this->_sock, $buf))) {
                    throw new DeathByCaptchaIOException(
                        'Connection lost while sending API request'
                    );
                } else {
                    $buf = substr($buf, $n);
                }
            }
            if (!$buf) {
                if (!($s = fread($this->_sock, 4096))) {
                    throw new DeathByCaptchaIOException(
                        'Connection lost while receiving API response'
                    );
                } else {
                    $response .= $s;
                    if (self::TERMINATOR == substr($s, strlen($s) - 2)) {
                        $response = rtrim($response, self::TERMINATOR);
                        if ($this->is_verbose) {
                            fputs(STDERR, time() . ' RECV: ' . strlen($response) . " {$response}\n");
                        }
                        return $response;
                    }
                }
            }
        }

        throw new DeathByCaptchaIOException('API request timed out');
    }

    /**
     * Makes an API call
     *
     * @param string $cmd     API command to call
     * @param array  $payload API request payload
     * @return array|null API response hash map on success
     * @throws DeathByCaptchaIOException On network errors
     * @throws DeathByCaptchaAccessDeniedException On failed login attempt
     * @throws DeathByCaptchaInvalidCaptchaException On invalid CAPTCHAs rejected by the service
     * @throws DeathByCaptchaServerException On API server errors
     */
    protected function _call($cmd, $payload=null)
    {
        if (null === $payload) {
            $payload = array();
        }
        $payload = array_merge($payload, array(
            'cmd' => $cmd,
            'version' => self::API_VERSION,
        ));
        $payload = json_encode($payload);

        $response = null;
        for ($attempt = 2; 0 < $attempt && null === $response; $attempt--) {
            if (null === $this->_sock && 'login' != $cmd) {
                $this->_call('login', array(
                    'username' => $this->_userpwd[0],
                    'password' => $this->_userpwd[1],
                ));
            }
            $this->_connect();
            try {
                $response = $this->_sendrecv($payload);
            } catch (DeathByCaptchaException $e) {
                $this->close();
            }
        }

        try {
            if (null === $response) {
                throw new DeathByCaptchaIOException(
                    'API connection lost or timed out'
                );
            } else if (!($response = $this->parse_json_response($response))) {
                throw new DeathByCaptchaServerException(
                    'Invalid API response'
                );
            }

            if (!empty($response['error'])) {
                switch ($response['error']) {
                case 'not-logged-in':
                    throw new DeathByCaptchaAccessDeniedException(
                        'Access denied, check your credentials'
                    );
                case 'banned':
                    throw new DeathByCaptchaAccessDeniedException(
                        'Access denied, account suspended'
                    );
                case 'insufficient-funds':
                    throw new DeathByCaptchaAccessDeniedException(
                        'Access denied, balance is too low'
                    );
                case 'invalid-captcha':
                    throw new DeathByCaptchaInvalidCaptchaException(
                        "CAPTCHA was rejected by the service, check if it's a valid image"
                    );
                case 'service-overload':
                    throw new DeathByCaptchaServiceOverloadException(
                        'CAPTCHA was rejected due to service overload, try again later'
                    );
                default:
                    throw new DeathByCaptchaServerException(
                        'API server error occured: ' . $error
                    );
                }
            } else {
                return $response;
            }
        } catch (Exception $e) {
            $this->close();
            throw $e;
        }
    }


    /**
     * @see DeathByCaptchaClient::__construct()
     */
    public function __construct($username, $password)
    {
        // PHP for Windows lacks EAGAIN errno constant
        if (!defined('SOCKET_EAGAIN')) {
            define('SOCKET_EAGAIN', 11);
        }

        foreach (array('json', ) as $k) {
            if (!extension_loaded($k)) {
                throw new DeathByCaptchaRuntimeException(
                    "Required {$k} extension not found, check your PHP configuration"
                );
            }
        }
        foreach (array('json_encode', 'json_decode', 'base64_encode') as $k) {
            if (!function_exists($k)) {
                throw new DeathByCaptchaRuntimeException(
                    "Required {$k}() function not found, check your PHP configuration"
                );
            }
        }

        parent::__construct($username, $password);
    }

    /**
     * @see DeathByCaptchaClient::close()
     */
    public function close()
    {
        if (null !== $this->_sock) {
            if ($this->is_verbose) {
                fputs(STDERR, time() . " CLOSE\n");
            }

            fclose($this->_sock);
            $this->_sock = null;
        }

        return $this;
    }

    /**
     * @see DeathByCaptchaClient::get_user()
     */
    public function get_user()
    {
        $user = $this->_call('user');
        return (0 < ($id = (int)@$user['user']))
            ? array('user' => $id,
                    'balance' => (float)@$user['balance'],
                    'is_banned' => (bool)@$user['is_banned'])
            : null;
    }

    /**
     * @see DeathByCaptchaClient::get_user()
     */
    public function upload($captcha)
    {
        $img = $this->_load_captcha($captcha);
        if ($this->_is_valid_captcha($img)) {
            $captcha = $this->_call('upload', array(
                'captcha' => base64_encode($img),
            ));
            if (0 < ($cid = (int)@$captcha['captcha'])) {
                return array(
                    'captcha' => $cid,
                    'text' => (!empty($captcha['text']) ? $captcha['text'] : null),
                    'is_correct' => (bool)@$captcha['is_correct'],
                );
            }
        }
        return null;
    }

    /**
     * @see DeathByCaptchaClient::get_captcha()
     */
    public function get_captcha($cid)
    {
        $captcha = $this->_call('captcha', array('captcha' => (int)$cid));
        return (0 < ($cid = (int)@$captcha['captcha']))
            ? array('captcha' => $cid,
                    'text' => (!empty($captcha['text']) ? $captcha['text'] : null),
                    'is_correct' => (bool)$captcha['is_correct'])
            : null;
    }

    /**
     * @see DeathByCaptchaClient::report()
     */
    public function report($cid)
    {
        $captcha = $this->_call('report', array('captcha' => (int)$cid));
        return !@$captcha['is_correct'];
    }
}
