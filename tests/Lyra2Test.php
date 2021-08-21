<?php

namespace Cast\Crypto\Lyra2\Tests;

use Cast\Crypto\Lyra2\Lyra2;
use Cast\Crypto\uint64\Uint64 as uint64;
use PHPUnit\Framework\TestCase;
use function Cast\Crypto\Lyra2\lyra2;
use function Cast\Crypto\Lyra2\padBlock;

class Lyra2Test extends TestCase
{
    public function test_g()
    {
        $this->assertEquals(
            [
                '8ce204475ab87240',
                'e65eecf17679dbd8',
                'b304778e7470e038',
                '226faa68e2fac701',
            ],
            array_map(
                function (uint64 $el) {
                    return $el->getHex();
                },
                Lyra2::g(
                    uint64::new(1717272872, 1169568310),
                    uint64::new(1717272872, 1169568310),
                    uint64::new(1779033703, 4089235720),
                    uint64::new(1359893119, 2917565137)
                )
            )
        );
    }

    public function test_roundLyra()
    {
        $v = \SplFixedArray::fromArray(
            [
                uint64::new(1717272872, 1169568310),
                uint64::new(3817858715, 3950993031),
                uint64::new( 276389184, 3707954656),
                uint64::new(4159635382, 3860217794),
                uint64::new(1717272872, 1169568310),
                uint64::new(3817858715, 3950993031),
                uint64::new( 276389184, 3707954656),
                uint64::new(4159635382, 3860217794),
                uint64::new(1779033703, 4089235720),
                uint64::new(3144134277, 2227873595),
                uint64::new(1013904242, 4271175723),
                uint64::new(2773480762, 1595750129),
                uint64::new(1359893119, 2917565137),
                uint64::new(2600822924,  725511199),
                uint64::new( 528734635, 4215389547),
                uint64::new(1541459225,  327033209),
            ]
        );

        Lyra2::roundLyra($v);

        $this->assertEquals(
            [
                'f92b180ac14ca61b',
                '1f57e82ad7b21e8d',
                '355a9f7ec8ce416c',
                '1d51062b4dd3409e',
                '184915665871b67d',
                '25831cd1be261868',
                '294b5bceab4a1be9',
                '1c1965b62792c19c',
                'fbd0bf6da71e8584',
                '7699f8eb92b98d73',
                '1457b674a9a262fe',
                'a385197c4b84ce1b',
                '876a443d75b51dea',
                '4c56c92fe1d19812',
                'b7b98b44573626c9',
                '9a934bac83be0fd5',
            ],
            array_map(
                function (uint64 $el) {
                    return $el->getHex();
                },
                $v->toArray()
            )
        );
    }

    public function test_blake2bLyra()
    {
        $state = \SplFixedArray::fromArray(
            [
                uint64::new(1717272872, 1169568310),
                uint64::new(3817858715, 3950993031),
                uint64::new(276389184, 3707954656),
                uint64::new(4159635382, 3860217794),
                uint64::new(1717272872, 1169568310),
                uint64::new(3817858715, 3950993031),
                uint64::new(276389184, 3707954656),
                uint64::new(4159635382, 3860217794),
                uint64::new(1779033703, 4089235720),
                uint64::new(3144134277, 2227873595),
                uint64::new(1013904242, 4271175723),
                uint64::new(2773480762, 1595750129),
                uint64::new(1359893119, 2917565137),
                uint64::new(2600822924, 725511199),
                uint64::new(528734635, 4215389547),
                uint64::new(1541459225, 327033209),
            ]
        );

        Lyra2::blake2bLyra($state);

        $this->assertEquals(
            [
                '42fa1f3db640892a',
                'ada30cf4f20d302f',
                '1003d105db1c162c',
                '10493dd974a328b3',
                'd0d6b7484bc1844d',
                'f9314559731d322d',
                'a16ec71211b33f9b',
                '7471c398aa9399af',
                '70d53bfdca81aa32',
                '368184282f8b89c8',
                '8ba2ab026e41598a',
                '23668e1287ac50b5',
                '7d90a33614bffc81',
                'a933faf137490245',
                'aea5106f8d0c6af8',
                'a504e64099aebb7b',
            ],
            array_map(
                function (uint64 $el) {
                    return $el->getHex();
                },
                $state->toArray()
            )
        );
    }

    public function test_absorbBlockBlake2Safe()
    {
        $state = \SplFixedArray::fromArray(
            [
                uint64::new(0, 0),
                uint64::new(0, 0),
                uint64::new(0, 0),
                uint64::new(0, 0),
                uint64::new(0, 0),
                uint64::new(0, 0),
                uint64::new(0, 0),
                uint64::new(0, 0),
                uint64::new(1779033703, 4089235720),
                uint64::new(3144134277, 2227873595),
                uint64::new(1013904242, 4271175723),
                uint64::new(2773480762, 1595750129),
                uint64::new(1359893119, 2917565137),
                uint64::new(2600822924, 725511199),
                uint64::new(528734635, 4215389547),
                uint64::new(1541459225, 327033209),
            ]
        );

        $wholeMatrix = \SplFixedArray::fromArray(
            array_merge(
                [
                    uint64::new(1717272872, 1169568310),
                    uint64::new(3817858715, 3950993031),
                    uint64::new(276389184, 3707954656),
                    uint64::new(4159635382, 3860217794),
                    uint64::new(1717272872, 1169568310),
                    uint64::new(3817858715, 3950993031),
                    uint64::new(276389184, 3707954656),
                    uint64::new(4159635382, 3860217794),
                    uint64::new(0, 32),
                    uint64::new(0, 32),
                    uint64::new(0, 32),
                    uint64::new(0, 1),
                    uint64::new(0, 4),
                    uint64::new(0, 4),
                    uint64::new(0, 128),
                    uint64::new(16777216, 0),
                ],
                array_fill(0, 176, uint64::new(0, 0))
            )
        );

        $ptrWord = 0;

        Lyra2::absorbBlockBlake2Safe($state, array_slice($wholeMatrix->toArray(), $ptrWord));

        $this->assertEquals(
            [
                '42fa1f3db640892a',
                'ada30cf4f20d302f',
                '1003d105db1c162c',
                '10493dd974a328b3',
                'd0d6b7484bc1844d',
                'f9314559731d322d',
                'a16ec71211b33f9b',
                '7471c398aa9399af',
                '70d53bfdca81aa32',
                '368184282f8b89c8',
                '8ba2ab026e41598a',
                '23668e1287ac50b5',
                '7d90a33614bffc81',
                'a933faf137490245',
                'aea5106f8d0c6af8',
                'a504e64099aebb7b',
            ],
            array_map(
                function (uint64 $el) {
                    return $el->getHex();
                },
                $state->toArray()
            )
        );
    }

    public function test_lyra2()
    {
        $pwd  = hex2bin('3632b64528815b66875e7feb9be68fe3e0e502dd405d7910c23f16e6b6ffeef7');
        $salt = hex2bin('3632b64528815b66875e7feb9be68fe3e0e502dd405d7910c23f16e6b6ffeef7');
        $lyra2result = padBlock('', 32);
        lyra2($lyra2result, $pwd, $salt, uint64::new(0, 1), 4, 4);
        $this->assertEquals(hex2bin('48b0451a8d5afcfe0b8622f6bdb1945fde5d7945b24c6bf04212d11788629b1e'), $lyra2result);
    }
}
