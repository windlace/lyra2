Lyra2
---
**Lyra2. Pure PHP-implementation**

#### Install:
```php
composer require cast/lyra2
```

#### Usage:
```php
<?php
use Cast\Crypto\unit64\Uint64 as uint64;
use function Cast\Crypto\Lyra2\lyra2;
use function Cast\Crypto\Lyra2\padBlock;

$pwd  = hex2bin('3632b64528815b66875e7feb9be68fe3e0e502dd405d7910c23f16e6b6ffeef7');
$salt = hex2bin('3632b64528815b66875e7feb9be68fe3e0e502dd405d7910c23f16e6b6ffeef7');
$lyra2result = padBlock('', 32);
lyra2($lyra2result, $pwd, $salt, uint64::new(0, 1), 4, 4);

var_dump(bin2hex($lyra2result)); // 48b0451a8d5afcfe0b8622f6bdb1945fde5d7945b24c6bf04212d11788629b1e

```

Based on https://github.com/bitgoin/lyra2rev2/blob/master/lyra2.go.

Links:
* http://lyra-2.net
* https://github.com/leocalm/Lyra
* https://en.wikipedia.org/wiki/Lyra2
