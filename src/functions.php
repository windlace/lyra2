<?php

declare(strict_types=1);

namespace Cast\Crypto\Lyra2;

function lyra2(&$k, $pwd, $salt, $timeCost, $nRows, $nCols)
{
    Lyra2::lyra2($k, $pwd, $salt, $timeCost, $nRows, $nCols);
}

function swapEndianness($value)
{
    return implode('', array_reverse(str_split($value, 2)));
}

function swapEndiannessBin($value)
{
    return hex2bin(swapEndianness(bin2hex($value)));
}

function padBlock($input, $blockSizeBytes)
{
    $blockSize = $blockSizeBytes * 2;
    $input = bin2hex($input);
//    if (strlen($input) > $blockSize) throw new \InvalidArgumentException("Input data should not be more than {$blockSizeBytes} bytes");
    $input = str_repeat('0', $blockSize - ((strlen($input) % $blockSize) ?: $blockSize)) . $input;
    $input = !strlen($input) ? str_repeat('0', $blockSize) : $input;
    return hex2bin($input);
}
