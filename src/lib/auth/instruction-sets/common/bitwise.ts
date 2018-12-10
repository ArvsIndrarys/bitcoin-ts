import { CommonProgramState, StackMachineState } from '../../state';
import { Operator } from '../../virtual-machine';
import { BitcoinCashOpCodes } from '../bitcoin-cash/bitcoin-cash-opcodes';
import {
  applyError,
  booleanToScriptNumber,
  CommonAuthenticationError,
  ErrorState
} from './common';
import { opVerify } from './flow-control';

const areEqual = (a: Uint8Array, b: Uint8Array) => {
  // tslint:disable-next-line:no-if-statement
  if (a.length !== b.length) {
    return false;
  }
  // tslint:disable-next-line:no-let
  for (let i = 0; i < a.length; i++) {
    // tslint:disable-next-line:no-if-statement
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
};

export const opEqual = <
  ProgramState extends StackMachineState & ErrorState<InstructionSetError>,
  InstructionSetError
>(): Operator<ProgramState> => ({
  asm: 'OP_EQUAL',
  description:
    'Pop the top two elements off the stack and compare them byte-by-byte. If they are the same, push a Script Number 1, otherwise push a Script Number 0.',
  operation: (state: ProgramState) => {
    const element1 = state.stack.pop();
    const element2 = state.stack.pop();
    // tslint:disable-next-line:no-if-statement
    if (!element1 || !element2) {
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.emptyStack,
        state
      );
    }
    const result = booleanToScriptNumber(areEqual(element1, element2));
    // tslint:disable-next-line:no-expression-statement
    state.stack.push(result);
    return state;
  }
});

export const opEqualVerify = <
  ProgramState extends StackMachineState & ErrorState<InstructionSetError>,
  InstructionSetError
>(): Operator<ProgramState> => {
  const equal = opEqual<ProgramState, InstructionSetError>().operation;
  const verify = opVerify<ProgramState, InstructionSetError>().operation;
  return {
    asm: 'OP_EQUALVERIFY',
    description:
      'Pop the top two elements off the stack and compare them byte-by-byte. If they are the different, error.',
    operation: (state: ProgramState) => verify(equal(state))
  };
};

export const bitwiseOperators = <
  ProgramState extends CommonProgramState<InstructionSetError>,
  InstructionSetError
>() => ({
  [BitcoinCashOpCodes.OP_EQUAL]: opEqual<ProgramState, InstructionSetError>(),
  [BitcoinCashOpCodes.OP_EQUALVERIFY]: opEqualVerify<
    ProgramState,
    InstructionSetError
  >()
});
