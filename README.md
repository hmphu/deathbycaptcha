# DeathByCaptcha PHP Wrapper

Unofficial PHP wrapper for [DeathByCaptcha API](http://www.deathbycaptcha.com/user/api)

## Installation

The preferred way to install this extension is through composer.

Either run

```
php composer.phar require --prefer-dist hmphu/deathbycaptcha
```

or add

```
"hmphu/deathbycaptcha": "*"
```

to the require section of your composer.json.

## Usage

```
use hmphu\deathbycaptcha\DeathByCaptchaSocketClient;
use hmphu\deathbycaptcha\DeathByCaptchaClient;

$deathByCaptchaUser = 'Your DBC API Username Here';
$deathByCaptchaPassword = 'Your DBC API Password Here';
$client = new DeathByCaptchaSocketClient($deathByCaptchaUser, $deathByCaptchaPassword);

try {
    $balance = $client->get_balance();
    if($balance > 0){
        /* Put your CAPTCHA file name or opened file handler, and optional solving timeout (in seconds) here: */
        $captcha = $client->decode($img, DeathByCaptchaClient::DEFAULT_TIMEOUT * 2);
        if ($captcha) {
            $text = $captcha['text'];
        }
    }
} catch (DeathByCaptchaAccessDeniedException $e) {
    /* Access to DBC API denied, check your credentials and/or balance */
}
```

##  Authors and Contributors

Make with love to DeathByCaptcha service

In 2016, PhuHM ([@hmphu][1]), [http://hmphu.com][2]

##  Support or Contact

Having trouble? [contact me][3]

[1]: https://github.com/hmphu
[2]: http://www.hnphu.com
[3]: mailto:me@hmphu.com