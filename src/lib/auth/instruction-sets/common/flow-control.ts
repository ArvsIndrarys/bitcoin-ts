import { CommonProgramState, StackMachineState } from '../../state';
import { Operator } from '../../virtual-machine';
import { BitcoinCashOpCodes } from '../bitcoin-cash/bitcoin-cash-opcodes';
import {
  applyError,
  CommonAuthenticationError,
  ErrorState,
  stackElementIsTruthy
} from './common';

export const opVerify = <
  ProgramState extends StackMachineState & ErrorState<InstructionSetError>,
  InstructionSetError
>(): Operator<ProgramState> => ({
  asm: 'OP_VERIFY',
  description: `Pop the top element from the stack and error if it isn't "truthy".`,
  operation: (state: ProgramState) => {
    const element = state.stack.pop();
    // tslint:disable-next-line:no-if-statement
    if (!element) {
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.emptyStack,
        state
      );
    }
    return stackElementIsTruthy(element)
      ? state
      : applyError<ProgramState, InstructionSetError>(
          CommonAuthenticationError.failedVerify,
          state
        );
  }
});

export const flowControlOperators = <
  ProgramState extends CommonProgramState<InstructionSetError>,
  InstructionSetError
>() => ({
  [BitcoinCashOpCodes.OP_VERIFY]: opVerify<ProgramState, InstructionSetError>()
});
