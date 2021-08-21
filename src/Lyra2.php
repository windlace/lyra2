<?php

// based on https://github.com/bitgoin/lyra2rev2/blob/master/lyra2.go

namespace Cast\Crypto\Lyra2;

use Cast\Crypto\uint64\Uint64 as uint64;
use function Cast\Crypto\ECDSA\Conv\convBase;
use function Cast\Crypto\uint64\_and;
use function Cast\Crypto\uint64\_xor;
use function Cast\Crypto\uint64\add;
use function Cast\Crypto\uint64\mul;
use function Cast\Crypto\uint64\neg;
use function Cast\Crypto\uint64\mod2;
use function Cast\Crypto\uint64\ROTR;
use function Cast\Crypto\uint64\sub;
use function Cast\Crypto\uint64\uint64;
use const Cast\BaseConv\BASE_10;
use const Cast\Crypto\ECDSA\Conv\BASE_16;

class Lyra2
{
    //Block length: 768 bits (=96 bytes, =12 uint64_t)
    const BLOCK_LEN_INT_64 = 12;

    //Block length, in bytes
    const BLOCK_LEN_BYTES = self::BLOCK_LEN_INT_64 * 8;

    //512 bits (=64 bytes, =8 uint64_t)
    const BLOCK_LEN_BLAKE2_SAFE_INT_64 = 8;

    //same as above, in bytes
    const BLOCK_LEN_BLAKE2_SAFE_BYTES = 8 * 8; // BLOCK_LEN_BLAKE2_SAFE_INT_64 * 8

    // uint64[]
    const BLAKE2B_IV = [
        "6a09e667f3bcc908", "bb67ae8584caa73b",
        "3c6ef372fe94f82b", "a54ff53a5f1d36f1",
        "510e527fade682d1", "9b05688c2b3e6c1f",
        "1f83d9abfb41bd6b", "5be0cd19137e2179",
    ];

    /*Blake2b's rotation*/
    /**
     * @param uint64 $w
     * @param byte $c
     * @return uint64
     */
    public static function rotr64($w, $c)
    {
        return (w >> c) | (w << (64 - c));
    }

    /**
     * g is Blake2b's G function
     *
     * @param uint64 $a
     * @param uint64 $b
     * @param uint64 $c
     * @param uint64 $d
     * @return array (uint64, uint64, uint64, uint64)
     */
    public static function g(uint64 $a, uint64 $b, uint64 $c, uint64 $d)
    {
        $a = add($a, $b);
        $d = ROTR(_xor($d, $a), 32);
        $c = add($c, $d);
        $b = ROTR(_xor($b, $c), 24);
        $a = add($a, $b);
        $d = ROTR(_xor($d, $a), 16);
        $c = add($c, $d);
        $b = ROTR(_xor($b, $c), 63);
        return [$a, $b, $c, $d];
    }

    /**
     * roundLyra is One Round of the Blake2b's compression function
     *
     * @param uint64 $v
     */
    public static function roundLyra($v)
    {
        [$v[0], $v[4], $v[8],  $v[12]] = self::g($v[0], $v[4], $v[8],  $v[12]);
        [$v[1], $v[5], $v[9],  $v[13]] = self::g($v[1], $v[5], $v[9],  $v[13]);
        [$v[2], $v[6], $v[10], $v[14]] = self::g($v[2], $v[6], $v[10], $v[14]);
        [$v[3], $v[7], $v[11], $v[15]] = self::g($v[3], $v[7], $v[11], $v[15]);
        [$v[0], $v[5], $v[10], $v[15]] = self::g($v[0], $v[5], $v[10], $v[15]);
        [$v[1], $v[6], $v[11], $v[12]] = self::g($v[1], $v[6], $v[11], $v[12]);
        [$v[2], $v[7], $v[8],  $v[13]] = self::g($v[2], $v[7], $v[8],  $v[13]);
        [$v[3], $v[4], $v[9],  $v[14]] = self::g($v[3], $v[4], $v[9],  $v[14]);
    }

    /**
     * initState Initializes the Sponge State. The first 512 bits are set to zeros and the remainder
     * receive Blake2b's IV as per Blake2b's specification. <b>Note:</b> Even though sponges
     * typically have their internal state initialized with zeros, Blake2b's G function
     * has a fixed point: if the internal state and message are both filled with zeros. the
     * resulting permutation will always be a block filled with zeros; this happens because
     * Blake2b does not use the constants originally employed in Blake2 inside its G function,
     * relying on the IV for avoiding possible fixed points.
     *
     * state         The 1024-bit array to be initialized
     * @return \SplFixedArray
     */
    public static function initState(): \SplFixedArray
    {
        $state = new \SplFixedArray(16);
        $state[0]  = uint64();
        $state[1]  = uint64();
        $state[2]  = uint64();
        $state[3]  = uint64();
        $state[4]  = uint64();
        $state[5]  = uint64();
        $state[6]  = uint64();
        $state[7]  = uint64();
        $state[8]  = uint64(self::BLAKE2B_IV[0]);
        $state[9]  = uint64(self::BLAKE2B_IV[1]);
        $state[10] = uint64(self::BLAKE2B_IV[2]);
        $state[11] = uint64(self::BLAKE2B_IV[3]);
        $state[12] = uint64(self::BLAKE2B_IV[4]);
        $state[13] = uint64(self::BLAKE2B_IV[5]);
        $state[14] = uint64(self::BLAKE2B_IV[6]);
        $state[15] = uint64(self::BLAKE2B_IV[7]);

        return $state;
    }

    /**
     * Eblake2bLyraxecute Blake2b's G function, with all 12 rounds.
     *
     * @param uint64[] $v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
     */
    public static function blake2bLyra($v) {
        for ($i = 0; $i < 12; $i++) {
            self::roundLyra($v);
        }
    }

    /**
     * reducedBlake2bLyra Executes a reduced version of Blake2b's G function with only one round
     * @param uint64[] $v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
     */
    public static function reducedBlake2bLyra($v) {
        self::roundLyra($v);
    }

    public static function swapEndianness($value)
    {
        return implode('', array_reverse(str_split($value, 2)));
    }

    public static function signed2hex($value, $reverseEndianness = true)
    {
        $packed = pack('qq', $value->hi, $value->lo);
        $hex='';
        for ($i=0; $i < 16; $i++){
            $ord = ord($packed[$i]);
            $h = dechex($ord);
            $hex .= str_pad( $h , 2, '0', STR_PAD_LEFT);
        }

        return $reverseEndianness ? self::swapEndianness($hex) : $hex;
    }

    /**
     * squeeze Performs a squeeze operation, using Blake2b's G function as the
     * internal permutation
     *
     * @param uint64[] state      The current state of the sponge
     * @param byte[] out        Array that will receive the data squeezed
     * @param len        The number of bytes to be squeezed into the "out" array
     */
    public static function squeeze($state, &$out)
    {
        $tmp = '';
        for ($j = 0; $j < floor(strlen($out) / self::BLOCK_LEN_BYTES + 1); $j++) {
            for ($i = 0; $i < self::BLOCK_LEN_INT_64; $i++) {
                $tmp .= self::swapEndianness($state[$i]->getHex());
//                binary . LittleEndian . PutUint64($tmp[$i * 8], $state[$i]);
            }
            //be care in case of len(out[i:])<len(tmp)
            $r = str_split($tmp, 2);
            for ($m = 0; $m < strlen($out); $m += 1) {
                $out[($j * self::BLOCK_LEN_BYTES) + $m] = hex2bin($r[$m]);
            }

            self::blake2bLyra($state);
        }
    }

    /**
     * absorbBlock Performs an absorb operation for a single block (BLOCK_LEN_INT64 words
     * of type uint64_t), using Blake2b's G function as the internal permutation
     *
     * @param uint64[] $state The current state of the sponge
     * @param uint64[] $in    The block to be absorbed (BLOCK_LEN_INT64 words)
     */
    public static function absorbBlock($state, $in)
    {
        //XORs the first BLOCK_LEN_INT64 words of "in" with the current state
        $state[0]->xor($in[0]);
        $state[1]->xor($in[1]);
        $state[2]->xor($in[2]);
        $state[3]->xor($in[3]);
        $state[4]->xor($in[4]);
        $state[5]->xor($in[5]);
        $state[6]->xor($in[6]);
        $state[7]->xor($in[7]);
        $state[8]->xor($in[8]);
        $state[9]->xor($in[9]);
        $state[10]->xor($in[10]);
        $state[11]->xor($in[11]);

        //Applies the transformation f to the sponge's state
        self::blake2bLyra($state);
    }

    /**
     * absorbBlockBlake2Safe  Performs an absorb operation for a single block (BLOCK_LEN_BLAKE2_SAFE_INT64
     * words of type uint64_t), using Blake2b's G function as the internal permutation
     *
     * @param uint64[] $state The current state of the sponge
     * @param uint64[] $in    The block to be absorbed (BLOCK_LEN_BLAKE2_SAFE_INT64 words)
     */
    public static function absorbBlockBlake2Safe($state, $in)
    {
        //XORs the first BLOCK_LEN_BLAKE2_SAFE_INT64 words of "in" with the current state

        $state[0]->xor($in[0]);
        $state[1]->xor($in[1]);
        $state[2]->xor($in[2]);
        $state[3]->xor($in[3]);
        $state[4]->xor($in[4]);
        $state[5]->xor($in[5]);
        $state[6]->xor($in[6]);
        $state[7]->xor($in[7]);

        //Applies the transformation f to the sponge's state
        self::blake2bLyra($state);

    }

    /**
     * reducedSqueezeRow0 performs a reduced squeeze operation for a single row, from the highest to
     * the lowest index, using the reduced-round Blake2b's G function as the
     * internal permutation
     *
     * @param \SplFixedArray    $state  The current state of the sponge. Array of uint64
     * @param array             $rowOut Row to receive the data squeezed
     * @param int $nCols
     */
    public static function reducedSqueezeRow0(\SplFixedArray $state, $rowOut,  $nCols)
    {
        [$memMatrix, $idx] = $rowOut;
        // Indirect modification of overloaded element of SplFixedArray has no effect, we follow
        $row = $memMatrix[$idx];
        $ptr = ($nCols - 1) * self::BLOCK_LEN_INT_64;
        //M[row][C-1-col] = H.reduced_squeeze()
        /** @var uint64[] $state */
        for ($i = 0; $i < $nCols; $i++) {
//            $ptrWord = array_slice($rowOut, $ptr); //In Lyra2: pointer to M[0][C-1]
            $row[$ptr + 0] = $state[0];
            $row[$ptr + 1] = $state[1];
            $row[$ptr + 2] = $state[2];
            $row[$ptr + 3] = $state[3];
            $row[$ptr + 4] = $state[4];
            $row[$ptr + 5] = $state[5];
            $row[$ptr + 6] = $state[6];
            $row[$ptr + 7] = $state[7];
            $row[$ptr + 8] = $state[8];
            $row[$ptr + 9] = $state[9];
            $row[$ptr + 10] = $state[10];
            $row[$ptr + 11] = $state[11];

            //Goes to next block (column) that will receive the squeezed data
            $ptr -= self::BLOCK_LEN_INT_64;

            //Applies the reduced-round transformation f to the sponge's state
            self::reducedBlake2bLyra($state);
        }
        $memMatrix[$idx] = $row;
    }

    /**
     * reducedDuplexRow1 Performs a reduced duplex operation for a single row, from the highest to
     * the lowest index, using the reduced-round Blake2b's G function as the
     * internal permutation
     *
     * @param \SplFixedArray    $state  The current state of the sponge. Array of uint64
     * @param array             $rows   The matrix and rowIn/rowOut indexes
     * @param int $nCols
     */
    public static function reducedDuplexRow1(\SplFixedArray $state, array $rows, $nCols) {
        [$memMatrix, $idxRowIn, $idxRowOut] = $rows;
        // Indirect modification of overloaded element of SplFixedArray has no effect, we follow
        $rowIn = $memMatrix[$idxRowIn]; // Row to feed the sponge
        $rowOut = $memMatrix[$idxRowOut]; // Row to receive the sponge's output
        $ptrIn = 0;
        $ptrOut = ($nCols - 1) * self::BLOCK_LEN_INT_64;

        for ($i = 0; $i < $nCols; $i++) {
//            $ptrWordIn = array_slice($rowIn, $ptrIn);    //In Lyra2: pointer to prev
//            $ptrWordOut = array_slice($rowOut, $ptrOut); //In Lyra2: pointer to row
            //Absorbing "M[prev][col]"
            $state[0]->xor($rowIn[$ptrIn + 0]);
            $state[1]->xor($rowIn[$ptrIn + 1]);
            $state[2]->xor($rowIn[$ptrIn + 2]);
            $state[3]->xor($rowIn[$ptrIn + 3]);
            $state[4]->xor($rowIn[$ptrIn + 4]);
            $state[5]->xor($rowIn[$ptrIn + 5]);
            $state[6]->xor($rowIn[$ptrIn + 6]);
            $state[7]->xor($rowIn[$ptrIn + 7]);
            $state[8]->xor($rowIn[$ptrIn + 8]);
            $state[9]->xor($rowIn[$ptrIn + 9]);
            $state[10]->xor($rowIn[$ptrIn + 10]);
            $state[11]->xor($rowIn[$ptrIn + 11]);

            //Applies the reduced-round transformation f to the sponge's state
            self::reducedBlake2bLyra($state);

            //M[row][C-1-col] = M[prev][col] XOR rand
            $rowOut[$ptrOut + 0] = _xor($rowIn[$ptrIn + 0], $state[0]);
            $rowOut[$ptrOut + 1] = _xor($rowIn[$ptrIn + 1], $state[1]);
            $rowOut[$ptrOut + 2] = _xor($rowIn[$ptrIn + 2], $state[2]);
            $rowOut[$ptrOut + 3] = _xor($rowIn[$ptrIn + 3], $state[3]);
            $rowOut[$ptrOut + 4] = _xor($rowIn[$ptrIn + 4], $state[4]);
            $rowOut[$ptrOut + 5] = _xor($rowIn[$ptrIn + 5], $state[5]);
            $rowOut[$ptrOut + 6] = _xor($rowIn[$ptrIn + 6], $state[6]);
            $rowOut[$ptrOut + 7] = _xor($rowIn[$ptrIn + 7], $state[7]);
            $rowOut[$ptrOut + 8] = _xor($rowIn[$ptrIn + 8], $state[8]);
            $rowOut[$ptrOut + 9] = _xor($rowIn[$ptrIn + 9], $state[9]);
            $rowOut[$ptrOut + 10] = _xor($rowIn[$ptrIn + 10], $state[10]);
            $rowOut[$ptrOut + 11] = _xor($rowIn[$ptrIn + 11], $state[11]);

            // append rowIn (php workaround)
            $ix = ($ptrOut + ($nCols - 1) * self::BLOCK_LEN_INT_64) + self::BLOCK_LEN_INT_64;
            $rowIn[$ix + 0] = $rowOut[$ptrOut + 0];
            $rowIn[$ix + 1] = $rowOut[$ptrOut + 1];
            $rowIn[$ix + 2] = $rowOut[$ptrOut + 2];
            $rowIn[$ix + 3] = $rowOut[$ptrOut + 3];
            $rowIn[$ix + 4] = $rowOut[$ptrOut + 4];
            $rowIn[$ix + 5] = $rowOut[$ptrOut + 5];
            $rowIn[$ix + 6] = $rowOut[$ptrOut + 6];
            $rowIn[$ix + 7] = $rowOut[$ptrOut + 7];
            $rowIn[$ix + 8] = $rowOut[$ptrOut + 8];
            $rowIn[$ix + 9] = $rowOut[$ptrOut + 9];
            $rowIn[$ix + 10] = $rowOut[$ptrOut + 10];
            $rowIn[$ix + 11] = $rowOut[$ptrOut + 11];

            //Input: next column (i.e., next block in sequence)
            $ptrIn += self::BLOCK_LEN_INT_64;
            //Output: goes to previous column
            $ptrOut -= self::BLOCK_LEN_INT_64;

        }
        $memMatrix[$idxRowIn] = $rowIn;
        $memMatrix[$idxRowOut] = $rowOut;
    }

    /**
     * reducedDuplexRowSetup Performs a duplexing operation over "M[rowInOut][col] [+] M[rowIn][col]" (i.e.,
     * the wordwise addition of two columns, ignoring carries between words). The
     * output of this operation, "rand", is then used to make
     * "M[rowOut][(N_COLS-1)-col] = M[rowIn][col] XOR rand" and
     * "M[rowInOut][col] =  M[rowInOut][col] XOR rotW(rand)", where rotW is a 64-bit
     * rotation to the left and N_COLS is a system parameter.
     *
     * @param uint64[]  $state          The current state of the sponge
     * @param array     $rows           The matrix and rowIn/rowInOut/rowOut indexes
     * @param int       $nCols
     *
     */
//    public static function reducedDuplexRowSetup($state, $rowIn, $rowInOut, $rowOut, $nCols) {
    public static function reducedDuplexRowSetup($state, array $rows, $nCols) {
        [$memMatrix, $idxRowIn, $idxRowInOut, $idxRowOut] = $rows;
        $rowIn = $memMatrix[$idxRowIn]; // Row used only as input
        $rowInOut = $memMatrix[$idxRowInOut]; // Row used as input and to receive output after rotation
        $rowOut = $memMatrix[$idxRowOut]; // Row receiving the output
        $ptrIn = 0;
        $ptrInOut = 0;
        $ptrOut = ($nCols - 1) * self::BLOCK_LEN_INT_64;

        for ($i = 0; $i < $nCols; $i++) {
//            $ptrWordIn = array_slice($rowIn, $ptrIn);          //In Lyra2: pointer to prev
//            $ptrWordOut = array_slice($rowOut, $ptrOut);       //In Lyra2: pointer to row
//            $ptrWordInOut = array_slice($rowInOut, $ptrInOut); //In Lyra2: pointer to row

            //Absorbing "M[prev] [+] M[row*]"
            $state[0]->xor(add($rowIn[$ptrIn + 0], $rowInOut[$ptrInOut + 0]));
            $state[1]->xor(add($rowIn[$ptrIn + 1], $rowInOut[$ptrInOut + 1]));
            $state[2]->xor(add($rowIn[$ptrIn + 2], $rowInOut[$ptrInOut + 2]));
            $state[3]->xor(add($rowIn[$ptrIn + 3], $rowInOut[$ptrInOut + 3]));
            $state[4]->xor(add($rowIn[$ptrIn + 4], $rowInOut[$ptrInOut + 4]));
            $state[5]->xor(add($rowIn[$ptrIn + 5], $rowInOut[$ptrInOut + 5]));
            $state[6]->xor(add($rowIn[$ptrIn + 6], $rowInOut[$ptrInOut + 6]));
            $state[7]->xor(add($rowIn[$ptrIn + 7], $rowInOut[$ptrInOut + 7]));
            $state[8]->xor(add($rowIn[$ptrIn + 8], $rowInOut[$ptrInOut + 8]));
            $state[9]->xor(add($rowIn[$ptrIn + 9], $rowInOut[$ptrInOut + 9]));
            $state[10]->xor(add($rowIn[$ptrIn + 10], $rowInOut[$ptrInOut + 10]));
            $state[11]->xor(add($rowIn[$ptrIn + 11], $rowInOut[$ptrInOut + 11]));

            //Applies the reduced-round transformation f to the sponge's state
            self::reducedBlake2bLyra($state);

            //M[row][col] = M[prev][col] XOR rand
            $rowOut[$ptrOut + 0] = _xor($rowIn[$ptrIn + 0], $state[0]);
            $rowOut[$ptrOut + 1] = _xor($rowIn[$ptrIn + 1], $state[1]);
            $rowOut[$ptrOut + 2] = _xor($rowIn[$ptrIn + 2], $state[2]);
            $rowOut[$ptrOut + 3] = _xor($rowIn[$ptrIn + 3], $state[3]);
            $rowOut[$ptrOut + 4] = _xor($rowIn[$ptrIn + 4], $state[4]);
            $rowOut[$ptrOut + 5] = _xor($rowIn[$ptrIn + 5], $state[5]);
            $rowOut[$ptrOut + 6] = _xor($rowIn[$ptrIn + 6], $state[6]);
            $rowOut[$ptrOut + 7] = _xor($rowIn[$ptrIn + 7], $state[7]);
            $rowOut[$ptrOut + 8] = _xor($rowIn[$ptrIn + 8], $state[8]);
            $rowOut[$ptrOut + 9] = _xor($rowIn[$ptrIn + 9], $state[9]);
            $rowOut[$ptrOut + 10] = _xor($rowIn[$ptrIn + 10], $state[10]);
            $rowOut[$ptrOut + 11] = _xor($rowIn[$ptrIn + 11], $state[11]);

            //M[row*][col] = M[row*][col] XOR rotW(rand)
            $rowInOut[$ptrInOut + 0]->xor($state[11]);
            $rowInOut[$ptrInOut + 1]->xor($state[0]);
            $rowInOut[$ptrInOut + 2]->xor($state[1]);
            $rowInOut[$ptrInOut + 3]->xor($state[2]);
            $rowInOut[$ptrInOut + 4]->xor($state[3]);
            $rowInOut[$ptrInOut + 5]->xor($state[4]);
            $rowInOut[$ptrInOut + 6]->xor($state[5]);
            $rowInOut[$ptrInOut + 7]->xor($state[6]);
            $rowInOut[$ptrInOut + 8]->xor($state[7]);
            $rowInOut[$ptrInOut + 9]->xor($state[8]);
            $rowInOut[$ptrInOut + 10]->xor($state[9]);
            $rowInOut[$ptrInOut + 11]->xor($state[10]);

            //Inputs: next column (i.e., next block in sequence)
            $ptrInOut += self::BLOCK_LEN_INT_64;
            $ptrIn += self::BLOCK_LEN_INT_64;
            //Output: goes to previous column
            $ptrOut -= self::BLOCK_LEN_INT_64;
        }
        $memMatrix[$idxRowIn] = $rowIn;
        $memMatrix[$idxRowInOut] = $rowInOut;
        $memMatrix[$idxRowOut] = $rowOut;
    }

    /**
     * reducedDuplexRow Performs a duplexing operation over "M[rowInOut][col] [+] M[rowIn][col]" (i.e.,
     * the wordwise addition of two columns, ignoring carries between words). The
     * output of this operation, "rand", is then used to make
     * "M[rowOut][col] = M[rowOut][col] XOR rand" and
     * "M[rowInOut][col] =  M[rowInOut][col] XOR rotW(rand)", where rotW is a 64-bit
     * rotation to the left.
     *
     * @param uint64[] $state          The current state of the sponge
     * @param uint64[] $rowIn          Row used only as input
     * @param uint64[] $rowInOut       Row used as input and to receive output after rotation
     * @param uint64[] $rowOut         Row receiving the output
     * @param int $nCols
     *
     */
    public static function reducedDuplexRow( $state, $rowIn, $rowInOut, $rowOut, $nCols) {
        $ptrIn = 0;
        $ptrInOut = 0;
        $ptrOut = 0;
        for ($i = 0; $i < $nCols; $i++) {
            $ptrWordIn = array_slice($rowIn, $ptrIn);          //In Lyra2: pointer to prev
            $ptrWordOut = array_slice($rowOut, $ptrOut);       //In Lyra2: pointer to row
            $ptrWordInOut = array_slice($rowInOut, $ptrInOut); //In Lyra2: pointer to row
            //Absorbing "M[prev] [+] M[row*]"
            $state[0]->xor(add($ptrWordIn[0], $ptrWordInOut[0]));
            $state[1]->xor(add($ptrWordIn[1], $ptrWordInOut[1]));
            $state[2]->xor(add($ptrWordIn[2], $ptrWordInOut[2]));
            $state[3]->xor(add($ptrWordIn[3], $ptrWordInOut[3]));
            $state[4]->xor(add($ptrWordIn[4], $ptrWordInOut[4]));
            $state[5]->xor(add($ptrWordIn[5], $ptrWordInOut[5]));
            $state[6]->xor(add($ptrWordIn[6], $ptrWordInOut[6]));
            $state[7]->xor(add($ptrWordIn[7], $ptrWordInOut[7]));
            $state[8]->xor(add($ptrWordIn[8], $ptrWordInOut[8]));
            $state[9]->xor(add($ptrWordIn[9], $ptrWordInOut[9]));
            $state[10]->xor(add($ptrWordIn[10], $ptrWordInOut[10]));
            $state[11]->xor(add($ptrWordIn[11], $ptrWordInOut[11]));

            //Applies the reduced-round transformation f to the sponge's state
            self::reducedBlake2bLyra($state);

            //M[rowOut][col] = M[rowOut][col] XOR rand
            $ptrWordOut[0]->xor($state[0]);
            $ptrWordOut[1]->xor($state[1]);
            $ptrWordOut[2]->xor($state[2]);
            $ptrWordOut[3]->xor($state[3]);
            $ptrWordOut[4]->xor($state[4]);
            $ptrWordOut[5]->xor($state[5]);
            $ptrWordOut[6]->xor($state[6]);
            $ptrWordOut[7]->xor($state[7]);
            $ptrWordOut[8]->xor($state[8]);
            $ptrWordOut[9]->xor($state[9]);
            $ptrWordOut[10]->xor($state[10]);
            $ptrWordOut[11]->xor($state[11]);

            //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
            $ptrWordInOut[0]->xor($state[11]);
            $ptrWordInOut[1]->xor($state[0]);
            $ptrWordInOut[2]->xor($state[1]);
            $ptrWordInOut[3]->xor($state[2]);
            $ptrWordInOut[4]->xor($state[3]);
            $ptrWordInOut[5]->xor($state[4]);
            $ptrWordInOut[6]->xor($state[5]);
            $ptrWordInOut[7]->xor($state[6]);
            $ptrWordInOut[8]->xor($state[7]);
            $ptrWordInOut[9]->xor($state[8]);
            $ptrWordInOut[10]->xor($state[9]);
            $ptrWordInOut[11]->xor($state[10]);

            //Goes to next block
            $ptrOut += self::BLOCK_LEN_INT_64;
            $ptrInOut += self::BLOCK_LEN_INT_64;
            $ptrIn += self::BLOCK_LEN_INT_64;
        }
    }

    // lyra2 Executes Lyra2 based on the G function from Blake2b. This version supports salts and passwords
    // whose combined length is smaller than the size of the memory matrix, (i.e., (nRows x nCols x b) bits,
    // where "b" is the underlying sponge's bitrate). In this implementation, the "basil" is composed by all
    // integer parameters (treated as type "unsigned int") in the order they are provided, plus the value
    // of nCols, (i.e., basil = kLen || pwdlen || saltlen || timeCost || nRows || nCols).
    //
    // @param K The derived key to be output by the algorithm
    // @param kLen Desired key length
    // @param pwd User password
    // @param pwdlen Password length
    // @param salt Salt
    // @param saltlen Salt length
    // @param timeCost Parameter to determine the processing time (T)
    // @param nRows Number or rows of the memory matrix (R)
    // @param nCols Number of columns of the memory matrix (C)
    //
    // @return 0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
    /**
     * @param byte[] $k
     * @param byte[] $pwd
     * @param byte[] $salt
     * @param uint64 $timeCost
     * @param int $nRows
     * @param int $nCols
     */
    public static function lyra2(&$k, $pwd, $salt, uint64 $timeCost, $nRows, $nCols) {

        //============================= Basic variables ============================//

        /**
         * Index of row to be processed
         * @var int $row
         */
        $row = 2;

        /**
         * Index of prev (last row ever computed/modified)
         * @var int $prev
         */
        $prev = 1;

        /**
         * Index of row* (a previous row, deterministically picked during Setup and randomly picked while Wandering)
         * @var uint64 $rowa
         */
        $rowa = uint64();

        /**
         * Time Loop iterator
         * @var uint64 $tau
         */
        $tau = uint64();

        /**
         * Visitation step (used during Setup and Wandering phases)
         * @var int $step
         */
        $step = 1;

        /**
         * Visitation window (used to define which rows can be revisited during Setup)
         * @var uint64 $window
         */
        $window = uint64::new(0, 2);

        /**
         * Modifier to the step, assuming the values 1 or -1
         * @var uint64 $gap
         */
        $gap = uint64::new(0, 1);

        /**
         * Auxiliary iteration counter
         * @var int
         */
        $i = null;
        //==========================================================================/

        //========== Initializing the Memory Matrix and pointers to it =============//
        //Tries to allocate enough space for the whole memory matrix

        $rowLenInt64 = self::BLOCK_LEN_INT_64 * $nCols;
        //rowLenBytes := rowLenInt64 * 8

        $matrixSize = $nRows * $rowLenInt64;

        $wholeMatrix = []; // []uint64
        for ($i = 0; $i < $matrixSize; $i++ ) {
            $wholeMatrix[$i] = new uint64();
        }
        //Allocates pointers to each row of the matrix
        $memMatrix = new \SplFixedArray($nRows); // [][]uint64

        //Places the pointers in the correct positions
        $ptrWord = 0;
        for ($i = 0; $i < $nRows; $i++) {
            $word = [];
            for ($j = 0; $j < count($wholeMatrix)-$ptrWord; $j++) {
                $word[] = &$wholeMatrix[$ptrWord+$j];
            }
            $memMatrix[$i] = $word;
            $ptrWord += $rowLenInt64;
        }
        //==========================================================================/

        //============= Getting the password + salt + basil padded with 10*1 ===============//
        //OBS.:The memory matrix will temporarily hold the password: not for saving memory,
        //but this ensures that the password copied locally will be overwritten as soon as possible

        //First, we clean enough blocks for the password, salt, basil and padding
        $nBlocksInput = floor((strlen($salt) + strlen($pwd) + 6 * 8) / self::BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;
        $ptrByte = 0; // (byte*) wholeMatrix;


        //Prepends the password

//    665b812845b63236
//    e38fe69beb7f5e87
//    10795d40dd02e5e0
//    f7eeffb6e6163fc2
//
//    7375630824717562422
//    7174206288769801863
//    1187082509956081120
//    8642125895979909058


        for ($j = 0; $j < strlen($pwd)/8; $j++) {
//            $wholeMatrix[$ptrByte + $j] = /* binary . LittleEndian . */ uint64(dechex($pwd[$j * 8]));
//            var_dump(bin2hex(substr($pwd, 0,$j*8)));exit;
            $wholeMatrix[$ptrByte + $j] = uint64(bin2hex(swapEndiannessBin(substr($pwd,$j*8, 8))));
        }
        $ptrByte += strlen($pwd) / 8;

        //Concatenates the salt
        for ($j = 0; $j < strlen($salt)/8; $j++) {
//            $wholeMatrix[$ptrByte + $j] = /* binary . LittleEndian . */ uint64(dechex($salt[$j * 8]));
            $wholeMatrix[$ptrByte + $j] = uint64(bin2hex(swapEndiannessBin(substr($salt,$j*8, 8))));
        }
        $ptrByte += strlen($salt) / 8;

        //Concatenates the basil: every integer passed as parameter, in the order they are provided by the interface
        $wholeMatrix[$ptrByte] = uint64(dechex(strlen($k)));
        $ptrByte++;
        $wholeMatrix[$ptrByte] = uint64(dechex(strlen($pwd)));
        $ptrByte++;
        $wholeMatrix[$ptrByte] = uint64(dechex(strlen($salt)));
        $ptrByte++;
        $wholeMatrix[$ptrByte] = $timeCost;
        $ptrByte++;
        $wholeMatrix[$ptrByte] = uint64(dechex($nRows));
        $ptrByte++;
        $wholeMatrix[$ptrByte] = uint64(dechex($nCols));
        $ptrByte++;

        //Now comes the padding
        $wholeMatrix[$ptrByte] = uint64('80'); //first byte of padding: right after the password
        //resets the pointer to the start of the memory matrix
        $ptrByte = ($nBlocksInput * self::BLOCK_LEN_BLAKE2_SAFE_BYTES) / 8 - 1; //sets the pointer to the correct position: end of incomplete block
        $wholeMatrix[$ptrByte]->xor(uint64('0100000000000000'));             //last byte of padding: at the end of the last incomplete block00
        //==========================================================================/

        //======================= Initializing the Sponge State ====================//
        //Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
        $state = self::initState();
        //==========================================================================/

        //================================ Setup Phase =============================//
        //Absorbing salt, password and basil: this is the only place in which the block length is hard-coded to 512 bits
        $ptrWord = 0;
        for ($i = 0; $i < $nBlocksInput; $i++) {
            self::absorbBlockBlake2Safe($state, array_slice($wholeMatrix, $ptrWord));  //absorbs each block of pad(pwd || salt || basil)
            $ptrWord += self::BLOCK_LEN_BLAKE2_SAFE_INT_64;               //goes to next block of pad(pwd || salt || basil)
        }

        // ok!!!

        //Initializes M[0] and M[1]
        self::reducedSqueezeRow0($state, [$memMatrix, 0] , $nCols); //The locally copied password is most likely overwritten here

        // ok !!!

        self::reducedDuplexRow1($state, [$memMatrix, 0, 1], $nCols);

        // ok !!!

        while ($row < $nRows) {
            //M[row] = rand; //M[row*] = M[row*] XOR rotW(rand)
            self::reducedDuplexRowSetup($state, [$memMatrix, $prev, hexdec($rowa->getHex()), $row], $nCols);

            //updates the value of row* (deterministically picked during Setup))
            $rowa = _and(add($rowa, uint64(dechex($step))), sub($window, uint64::new(0, 1)));
            //update prev: it now points to the last row ever computed
            $prev = $row;
            //updates row: goes to the next row to be computed
            $row++;

            //Checks if all rows in the window where visited.
            if ($rowa->isZero()) {
                $step = add($window, $gap)->getInt64(); //changes the step: approximately doubles its value
                $window = mul($window, uint64::new(0, 2));                //doubles the size of the re-visitation window
                $gap = neg($gap);                 //inverts the modifier to the step
            }
        }
        //==========================================================================/

        // ok !!!

        //============================ Wandering Phase =============================//
        $row = 0; //Resets the visitation to the first row of the memory matrix
        for ($tau->set(0, 1); $tau->lessThan($timeCost) || $tau->equalTo($timeCost); $tau->inc()) {
            //Step is approximately half the number of all rows of the memory matrix for an odd tau; otherwise, it is -1
            $step = $nRows / 2 - 1;
            if (mod2($tau)->isZero()) {
                $step = -1;
            }

            for ($row0 = false; !$row0; $row0 = ($row == 0)) {
                //Selects a pseudorandom index row*
                //------------------------------------------------------------------------------------------
                $rowa = _and($state[0], uint64(dechex($nRows-1)));	//(USE THIS IF nRows IS A POWER OF 2)
//                $rowa = $state[0] % uint64(dechex($nRows)); //(USE THIS FOR THE "GENERIC" CASE)
                //------------------------------------------------------------------------------------------

                //Performs a reduced-round duplexing operation over M[row*] XOR M[prev], updating both M[row*] and M[row]
                self::reducedDuplexRow($state, $memMatrix[$prev], $memMatrix[$rowa->getInt64()], $memMatrix[$row], $nCols);

                //update prev: it now points to the last row ever computed
                $prev = $row;

                //updates row: goes to the next row to be computed
                //------------------------------------------------------------------------------------------
                $row = ($row + $step) & ($nRows-1);	//(USE THIS IF nRows IS A POWER OF 2)
//                $row = ($row + $step) % $nRows; //(USE THIS FOR THE "GENERIC" CASE)
                //------------------------------------------------------------------------------------------
            }
        }
        //==========================================================================/

        // ok !!!

        //============================ Wrap-up Phase ===============================//
        //Absorbs the last block of the memory matrix
        self::absorbBlock($state, $memMatrix[$rowa->getInt64()]);

        // ok !!!

        //Squeezes the key
        self::squeeze($state, $k);
        //==========================================================================/
    }
}
