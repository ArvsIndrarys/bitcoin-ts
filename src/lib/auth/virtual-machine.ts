import { range } from '../utils';
import { BitcoinCashAuthenticationProgramState } from './instruction-sets/instruction-sets';
import { MinimumProgramState } from './state';

export interface DebuggingStep<ProgramState> {
  readonly asm: string;
  readonly description: string;
  readonly state: ProgramState;
}

/**
 * Operators define the behavior of an opcode in an InstructionSet.
 *
 * Operations should be written as efficiently as possible, and may safely
 * mutate the ProgramState. If needed, the AuthenticationVirtualMachine
 * will clone the ProgramState before providing it to an operation.
 */
// tslint:disable no-mixed-interface
export interface Operator<ProgramState> {
  /**
   * Either a string containing an asm representation of the operator, or a
   * method which accepts a copy of ProgramState and returns a string containing
   * an asm representation of the operator and any other bytes it consumes (e.g.
   * its parameters).
   */
  readonly asm: string | ((state: ProgramState) => string);
  /**
   * Either a description of the operation, or a method which accepts a
   * copy of ProgramState and returns a description of the operation.
   */
  readonly description: string | ((state: ProgramState) => string);
  /**
   * Operations receive a ProgramState immediately after `before` is executed,
   * so if `before` advances the instruction pointer, operators can consume
   * further bytes by moving the instruction pointer forward.
   *
   * When an operation is complete, the instruction pointer should be pointing
   * to the next opcode.
   *
   * If an operation consumes additional bytes, the instruction pointer should
   * be moved to the byte representing the next instruction (the byte after the
   * last byte consumed by the operator). If a script is fully executed, `ip`
   * should be equal to its length, such that script[ip] is out of bounds.
   */
  readonly operation: (state: ProgramState) => ProgramState;
}
// tslint:enable no-mixed-interface

/**
 * An `InstructionSet` defines the mechanics of an authentication definition
 * language, and is specific to a single network (e.g. BCH).
 */
// tslint:disable no-mixed-interface
export interface InstructionSet<ProgramState> {
  /**
   * Operators are called when the AuthenticationVirtualMachine encounters an
   * instance of `opcode` in `script`.
   */
  readonly [opcode: number]: Operator<ProgramState>;

  /**
   * This method is called after the codepoint is selected and immediately
   * before each operation is executed. This method should usually increment an
   * instruction pointer (e.g. `state.ip`) and perform any other actions which
   * occur between operators.
   */
  readonly before: (state: ProgramState) => ProgramState;

  /**
   * This method should take a ProgramState and return a new copy of that
   * ProgramState. It's used internally by `evaluate`, `step`, and `debug` to
   * prevent the AuthenticationVirtualMachine from mutating an input when
   * mutation is not desirable (e.g. when performance is not a priority).
   */
  readonly clone: (state: ProgramState) => ProgramState;

  /**
   * This method should test the ProgramState to determine if execution should
   * continue. It's used internally by the `evaluate` and `debug` methods, and
   * should usually test for errors or program completion.
   *
   * When checking the location of the instruction pointer, keep in mind that
   * the each call to `operation(next(state))` will move the instruction pointer
   * to the next opcode. If the last opcode in a script advances the instruction
   * pointer forward, `ip` should be equal to the length of the script, and
   * `script[ip]` should be out of bounds.
   */
  readonly continue: (state: ProgramState) => boolean;

  /**
   * This Operator is called when an undefined opcode is encountered. It should
   * usually mark the ProgramState with an error.
   */
  readonly undefined: Operator<ProgramState>;
}
// tslint:enable no-mixed-interface

/**
 * A set of pure-functions allowing authentication programs to be evaluated and
 * inspected.
 */
export interface AuthenticationVirtualMachine<ProgramState> {
  /**
   * Fully evaluate and return an array of steps performed on the program state
   * with additional debugging information.
   */
  readonly debug: (
    state: Readonly<ProgramState>,
    firstDescription?: string
  ) => // tslint:disable-next-line:readonly-array
  Array<DebuggingStep<ProgramState>>;

  /**
   * Return a new program state by cloning and fully evaluating `state`.
   * @param state the program state to evaluate
   */
  readonly evaluate: (state: Readonly<ProgramState>) => ProgramState;

  /**
   * Return a new program state advanced by one step.
   * @param state the program state to advance
   */
  readonly step: (state: Readonly<ProgramState>) => ProgramState;

  /**
   * A faster, less-safe version of `step` which directly modifies the provided
   * program state.
   * @param state the program state to mutate
   */
  readonly stepMutate: (state: ProgramState) => ProgramState;
}

/**
 * Create an AuthenticationVirtualMachine to evaluate authentication programs
 * constructed from operations in the `instructionSet`.
 * @param instructionSet an set of instruction set
 */
export const createAuthenticationVirtualMachine = <
  ProgramState extends MinimumProgramState = BitcoinCashAuthenticationProgramState
>(
  instructionSet: InstructionSet<ProgramState>
): AuthenticationVirtualMachine<ProgramState> => {
  const availableOpcodes = 256;
  const operators = range(availableOpcodes).map(codepoint =>
    instructionSet.hasOwnProperty(codepoint)
      ? instructionSet[codepoint]
      : instructionSet.undefined
  );

  const getCodepoint = (state: ProgramState) => state.script[state.ip];

  const getOperator = (state: ProgramState) => operators[getCodepoint(state)];

  const applyOperation = (
    state: ProgramState,
    operator: Operator<ProgramState>
  ) => operator.operation(instructionSet.before(state));

  const stepMutate = (state: ProgramState) =>
    applyOperation(state, getOperator(state));

  /**
   * When we get real tail call optimization, this can be replaced
   * with recursion.
   */
  const untilComplete = (
    state: ProgramState,
    stepFunction: (state: ProgramState) => ProgramState
  ) => {
    while (instructionSet.continue(state)) {
      // tslint:disable-next-line:no-parameter-reassignment no-expression-statement
      state = stepFunction(state);
    }
    return state;
  };

  const clone = (state: ProgramState) => instructionSet.clone(state);

  const evaluate = (state: ProgramState) =>
    untilComplete(clone(state), stepMutate);

  const stepDebug = (state: ProgramState): DebuggingStep<ProgramState> => {
    const operator = getOperator(state);
    const nextState = applyOperation(clone(state), operator);
    return {
      asm:
        typeof operator.asm === 'function'
          ? operator.asm(instructionSet.before(clone(state)))
          : operator.asm,
      description:
        typeof operator.description === 'function'
          ? operator.description(instructionSet.before(clone(state)))
          : operator.description,
      state: nextState
    };
  };

  const debug = (state: ProgramState, firstDescription?: string) => {
    // tslint:disable-next-line:prefer-const no-let readonly-array
    let trace: Array<DebuggingStep<ProgramState>> = [
      {
        asm: '',
        description:
          firstDescription !== undefined
            ? firstDescription
            : 'Begin script evaluation.',
        state
      }
    ];
    untilComplete(state, (currentState: ProgramState) => {
      const traceItem = stepDebug(currentState);
      // tslint:disable-next-line:no-expression-statement
      trace.push(traceItem);
      return traceItem.state;
    });
    return trace;
  };

  const step = (state: ProgramState) => stepMutate(clone(state));

  return { debug, evaluate, step, stepMutate };
};
