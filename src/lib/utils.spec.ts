// tslint:disable:no-expression-statement no-magic-numbers no-unsafe-any
import test from 'ava';
import * as fc from 'fast-check';
import {
  bigIntToBinUint64LE,
  binToBigIntUint64LE,
  binToHex,
  binToNumberUint16LE,
  binToNumberUint32LE,
  hexToBin,
  numberToBinUint16LE,
  numberToBinUint32LE,
  range,
  splitEvery
} from './utils';

const maxUint8Number = 255;
const fcUint8Array = (minLength: number, maxLength: number) =>
  fc
    .array(fc.integer(0, maxUint8Number), minLength, maxLength)
    .map(a => Uint8Array.from(a));

test('range', t => {
  t.deepEqual(range(3), [0, 1, 2]);
  t.deepEqual(range(3, 1), [1, 2, 3]);
});

test('splitEvery', t => {
  t.deepEqual(splitEvery('abcd', 2), ['ab', 'cd']);
  t.deepEqual(splitEvery('abcde', 2), ['ab', 'cd', 'e']);
});

test('hexToBin', t => {
  t.deepEqual(
    hexToBin('0001022a646566ff'),
    new Uint8Array([0, 1, 2, 42, 100, 101, 102, 255])
  );
});

test('binToHex', t => {
  t.deepEqual(
    binToHex(new Uint8Array([0, 1, 2, 42, 100, 101, 102, 255])),
    '0001022a646566ff'
  );
});

test('hexToBin <-> binToHex', t => {
  const inverse = fc.property(
    fcUint8Array(0, 100),
    input => binToHex(hexToBin(binToHex(input))) === binToHex(input)
  );
  t.notThrows(() => {
    fc.assert(inverse);
  });
});

test('numberToBinUint16LE', t => {
  t.deepEqual(numberToBinUint16LE(0x1234), new Uint8Array([0x34, 0x12]));
});

test('binToNumberUint16LE', t => {
  t.deepEqual(binToNumberUint16LE(new Uint8Array([0x34, 0x12])), 0x1234);
});

test('numberToBinUint32LE', t => {
  t.deepEqual(
    numberToBinUint32LE(0x12345678),
    new Uint8Array([0x78, 0x56, 0x34, 0x12])
  );
});

test('binToNumberUint32LE', t => {
  t.deepEqual(
    binToNumberUint32LE(new Uint8Array([0x78, 0x56, 0x34, 0x12])),
    0x12345678
  );
});

// TODO: When BigInt lands in TypeScript, include more cases here
test('bigIntToBinUint64LE', t => {
  t.deepEqual(
    bigIntToBinUint64LE(BigInt(0x12345678)),
    new Uint8Array([0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0])
  );
});

test('binToBigIntUint64LE', t => {
  t.deepEqual(
    binToBigIntUint64LE(new Uint8Array([0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0])),
    BigInt(0x12345678)
  );
});
