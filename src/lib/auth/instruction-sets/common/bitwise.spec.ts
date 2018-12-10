// tslint:disable:no-expression-statement no-magic-numbers readonly-array

import { testOperator } from '../instruction-sets.spec.helper';
import { opEqual } from './bitwise';
import { bigIntToScriptNumber } from './common';
import { clone, emptyStack } from './common.spec.helper';

const pass = bigIntToScriptNumber(BigInt(1));
const fail = bigIntToScriptNumber(BigInt(0));

const opEqualDescription =
  'Pop the top two elements off the stack and compare them byte-by-byte. If they are the same, push a Script Number 1, otherwise push a Script Number 0.';

// tslint:disable-next-line:no-unused-expression
testOperator(
  opEqual(),
  'OP_EQUAL: works',
  'OP_EQUAL',
  opEqualDescription,
  [
    {
      ...emptyStack(),
      stack: [new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])]
    },
    {
      stack: [pass]
    }
  ],
  clone
);

testOperator(
  opEqual(),
  'OP_EQUAL: fails on different length elements',
  'OP_EQUAL',
  opEqualDescription,
  [
    {
      ...emptyStack(),
      stack: [new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])]
    },
    {
      stack: [fail]
    }
  ],
  clone
);

testOperator(
  opEqual(),
  'OP_EQUAL: fails on different length elements (2)',
  'OP_EQUAL',
  opEqualDescription,
  [
    {
      ...emptyStack(),
      stack: [new Uint8Array([1, 2, 3]), new Uint8Array([1, 2])]
    },
    {
      stack: [fail]
    }
  ],
  clone
);

testOperator(
  opEqual(),
  'OP_EQUAL: fails on different elements of same length',
  'OP_EQUAL',
  opEqualDescription,
  [
    {
      ...emptyStack(),
      stack: [new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 5])]
    },
    {
      stack: [fail]
    }
  ],
  clone
);
