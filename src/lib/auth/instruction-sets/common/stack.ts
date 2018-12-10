import { Operator } from '../../virtual-machine';
import { BitcoinCashOpCodes } from '../bitcoin-cash/bitcoin-cash-opcodes';
import {
  applyError,
  CommonAuthenticationError,
  ErrorState,
  MinimumProgramState,
  StackMachineState
} from './common';

// TODO: unit test:
// empty stack
// element is clone (mutations to one element don't affect the other)
// duplicates
export const opDup = <
  ProgramState extends StackMachineState & ErrorState<InstructionSetError>,
  InstructionSetError
>(): Operator<ProgramState> => ({
  asm: `OP_DUP`,
  description: `Duplicate the top element on the stack.`,
  operation: (state: ProgramState) => {
    // tslint:disable-next-line:no-if-statement
    if (state.stack.length < 1) {
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.emptyStack,
        state
      );
    }
    const element = state.stack[state.stack.length - 1];
    const clone = element.slice();
    // tslint:disable-next-line:no-expression-statement
    state.stack.push(clone);
    return state;
  }
});

export const stackOperators = <
  ProgramState extends StackMachineState &
    MinimumProgramState &
    ErrorState<InstructionSetError>,
  InstructionSetError
>() => ({
  [BitcoinCashOpCodes.OP_DUP]: opDup<ProgramState, InstructionSetError>()
});
