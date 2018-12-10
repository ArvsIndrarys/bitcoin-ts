// tslint:disable:no-expression-statement no-magic-numbers readonly-array

import { range } from '../../../utils';
import { AuthenticationVirtualMachine } from '../../virtual-machine';
import { BitcoinCashAuthenticationProgramState } from '../bitcoin-cash/bitcoin-cash';
import { BitcoinCashOpCodes } from '../bitcoin-cash/bitcoin-cash-opcodes';
import { BitcoinAuthenticationProgramState } from '../bitcoin/bitcoin';
import { testVMOperation } from '../instruction-sets.spec.helper';
import {
  bigIntToScriptNumber,
  cloneStack,
  ErrorState,
  MinimumProgramState,
  pushNumberOpCodes,
  StackMachineState
} from './common';
import { pushDataConstantOpCodes } from './push';

const scriptNum = (value: number) => bigIntToScriptNumber(BigInt(value));

type commonVirtualMachine = AuthenticationVirtualMachine<
  BitcoinAuthenticationProgramState | BitcoinCashAuthenticationProgramState
>;

export const emptyStack = () => ({
  stack: []
});

export const fullBase = () => ({
  ip: 1,
  script: new Uint8Array(),
  ...emptyStack()
});

export const clone = (state: StackMachineState & ErrorState<{}>) => ({
  // tslint:disable-next-line:readonly-array
  stack: cloneStack(state.stack),
  ...(state.error !== undefined ? { error: state.error } : {})
});

export const fullClone = (
  state: MinimumProgramState & StackMachineState & ErrorState<{}>
) => ({
  ip: state.ip,
  script: state.script.slice(),
  ...clone(state)
});

const fullState = {
  blockHeight: 0,
  blockTime: 0,
  correspondingOutputHash: new Uint8Array(),
  ip: 0,
  lastCodeSeparator: -1,
  locktime: 0,
  operationCount: 0,
  operations: [],
  outpointIndex: 0,
  outpointTransactionHash: new Uint8Array(),
  outpointValue: BigInt(0),
  script: new Uint8Array(),
  sequenceNumber: 0,
  stack: [],
  transactionOutpointsHash: new Uint8Array(),
  transactionOutputsHash: new Uint8Array(),
  transactionSequenceNumbersHash: new Uint8Array(),
  version: 2
};

const pushNumberTests = (getVm: () => commonVirtualMachine) => {
  pushNumberOpCodes.map((opcode, index) => {
    const num = index - 1;
    const base = {
      ...fullState,
      script: new Uint8Array([opcode])
    };
    testVMOperation(`OP_${num}`, getVm, [
      [base, { ip: 1, stack: [scriptNum(num)] }],
      [
        { ...base, stack: [scriptNum(42)] },
        { ip: 1, stack: [scriptNum(42), scriptNum(num)] }
      ],
      [
        {
          ...fullState,
          script: new Uint8Array([opcode, opcode])
        },
        { ip: 2, stack: [scriptNum(num), scriptNum(num)] }
      ]
    ]);
  });
};

const pushDataConstantTests = (getVm: () => commonVirtualMachine) => {
  pushDataConstantOpCodes.map((opcode, index) => {
    const num = index + 1;
    const script1 = new Uint8Array([opcode, ...range(num, 1)]);
    const script2 = new Uint8Array([
      BitcoinCashOpCodes.OP_5,
      opcode,
      ...range(num, 1),
      BitcoinCashOpCodes.OP_5
    ]);
    testVMOperation(`OP_PUSHBYTES_${num}`, getVm, [
      [
        {
          ...fullState,
          script: script1
        },
        { ip: script1.length, stack: [new Uint8Array(range(num, 1))] }
      ],
      [
        {
          ...fullState,
          script: script2
        },
        {
          ip: script2.length,
          stack: [scriptNum(5), new Uint8Array(range(num, 1)), scriptNum(5)]
        }
      ]
    ]);
  });
};

const pushDataVariableTests = (getVm: () => commonVirtualMachine) => {
  const script = new Uint8Array([
    BitcoinCashOpCodes.OP_PUSHDATA1,
    100,
    ...range(100)
  ]);
  testVMOperation(`OP_PUSHDATA1`, getVm, [
    [
      {
        ...fullState,
        script
      },
      { ip: script.length, stack: [new Uint8Array(range(100))] }
    ]
  ]);
};

export const commonTests = (getVm: () => commonVirtualMachine) => {
  pushNumberTests(getVm);
  pushDataConstantTests(getVm);
  pushDataVariableTests(getVm);
};
