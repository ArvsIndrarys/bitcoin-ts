// TODO: unimplemented consensus rules – sig op count, max script length, etc.
import { Secp256k1 } from '../../../crypto/crypto';
import {
  AuthenticationVirtualMachine,
  DebuggingStep,
  InstructionSet
} from '../../virtual-machine';
import {
  applyError,
  AuthenticationProgram,
  cloneStack,
  CommonConsensus,
  commonOperators,
  CommonProgramExternalState,
  CommonProgramInternalState,
  Ripemd160,
  Sha256,
  stackElementIsTruthy
} from '../common/common';
import { BitcoinCashOpCodes } from './bitcoin-cash-opcodes';

export { BitcoinCashOpCodes };

export enum BitcoinCashAuthenticationError {
  exceededMaximumOperationCount = 'Script exceeded the maximum operation count (201 operations).'
}

// tslint:disable-next-line:no-empty-interface
export interface BitcoinCashAuthenticationProgramExternalState
  extends CommonProgramExternalState {}

export interface BitcoinCashAuthenticationProgramInternalState
  extends CommonProgramInternalState<BitcoinCashAuthenticationError> {}

export interface BitcoinCashAuthenticationProgramState
  extends BitcoinCashAuthenticationProgramExternalState,
    BitcoinCashAuthenticationProgramInternalState {}

export const bitcoinCashInstructionSet = (
  sha256: Sha256,
  ripemd160: Ripemd160,
  secp256k1: Secp256k1
): InstructionSet<BitcoinCashAuthenticationProgramState> => ({
  before: (state: BitcoinCashAuthenticationProgramState) => {
    // tslint:disable-next-line:no-object-mutation no-expression-statement
    state.ip++;
    const operation = state.script[state.ip];
    // tslint:disable-next-line:no-if-statement strict-type-predicates
    if (operation !== undefined) {
      // tslint:disable-next-line:no-expression-statement no-object-mutation
      state.operationCount++;
      // tslint:disable-next-line:no-if-statement
      if (state.operationCount > CommonConsensus.maximumOperationCount) {
        return applyError(
          BitcoinCashAuthenticationError.exceededMaximumOperationCount,
          state
        );
      }
      // tslint:disable-next-line:no-object-mutation no-expression-statement
      state.operations.push(operation);
    }
    return state;
  },
  clone: (state: BitcoinCashAuthenticationProgramState) => ({
    ...(state.error !== undefined ? { error: state.error } : {}),
    blockHeight: state.blockHeight,
    blockTime: state.blockTime,
    correspondingOutputHash: state.correspondingOutputHash.slice(),
    ip: state.ip,
    lastCodeSeparator: state.lastCodeSeparator,
    locktime: state.locktime,
    operationCount: state.operationCount,
    operations: state.operations.slice(),
    outpointIndex: state.outpointIndex,
    outpointTransactionHash: state.outpointTransactionHash.slice(),
    outpointValue: state.outpointValue,
    script: state.script.slice(),
    sequenceNumber: state.sequenceNumber,
    stack: state.stack.slice(),
    transactionOutpointsHash: state.transactionOutpointsHash.slice(),
    transactionOutputsHash: state.transactionOutputsHash.slice(),
    transactionSequenceNumbersHash: state.transactionSequenceNumbersHash.slice(),
    version: state.version
  }),
  continue: (state: BitcoinCashAuthenticationProgramState) =>
    state.error === undefined && state.ip < state.script.length,
  ...commonOperators<
    BitcoinCashAuthenticationProgramState,
    BitcoinCashAuthenticationError
  >(sha256, ripemd160, secp256k1)
});

const enum PayToScriptHash {
  length = 23,
  lastElement = 22
}

const isPayToScriptHash = (lockingScript: Uint8Array) =>
  lockingScript.length === PayToScriptHash.length &&
  lockingScript[0] === BitcoinCashOpCodes.OP_HASH160 &&
  lockingScript[1] === BitcoinCashOpCodes.OP_PUSHBYTES_20 &&
  lockingScript[PayToScriptHash.lastElement] === BitcoinCashOpCodes.OP_EQUAL;

const enum Phase {
  unlocking = 'Begin unlocking script evaluation.',
  locking = 'Begin locking script evaluation.',
  p2sh = 'Begin Pay-to-Script-Hash (P2SH) script evaluation.'
}

const enum P2shError {
  asm = '[P2SH error]',
  pushOnly = 'P2SH error: unlockingScript must be push-only.',
  emptyStack = 'P2SH error: unlockingScript must not leave an empty stack.'
}

/**
 * From C++ implementation:
 * Note that IsPushOnly() *does* consider OP_RESERVED to be a push-type
 * opcode, however execution of OP_RESERVED fails, so it's not relevant to
 * P2SH/BIP62 as the scriptSig would fail prior to the P2SH special
 * validation code being executed.
 */
const isPushOnly = (operations: ReadonlyArray<number>) =>
  operations.every(value => value < BitcoinCashOpCodes.OP_16);

export const createBitcoinCashProgramState = (
  program: AuthenticationProgram<BitcoinCashAuthenticationProgramExternalState>,
  script: Uint8Array,
  // tslint:disable-next-line:readonly-array
  stack: Uint8Array[]
) => ({
  ip: 0,
  lastCodeSeparator: -1,
  operationCount: 0,
  // tslint:disable-next-line:readonly-array
  operations: [],
  script,
  stack,
  ...program.state
});

const debugPhase = (
  vm: AuthenticationVirtualMachine<BitcoinCashAuthenticationProgramState>,
  program: AuthenticationProgram<BitcoinCashAuthenticationProgramExternalState>,
  script: Uint8Array,
  message: string,
  // tslint:disable-next-line:readonly-array
  stack: Uint8Array[] = []
) => {
  const state = createBitcoinCashProgramState(program, script, stack);
  const steps = vm.debug(state, message);
  const result = steps[steps.length - 1].state;
  return {
    result,
    steps
  };
};

const evaluateP2sh = <T>(
  // tslint:disable-next-line:readonly-array
  unlockingStack: Uint8Array[],
  // tslint:disable-next-line:readonly-array
  evaluate: (p2shScript: Uint8Array, p2shStack: Uint8Array[]) => T
) => {
  const p2shStack = cloneStack(unlockingStack);
  const p2shScript = p2shStack.pop() as Uint8Array;
  return evaluate(p2shScript, p2shStack);
};

// tslint:disable-next-line:cyclomatic-complexity
export const debugBitcoinCashAuthenticationProgram = (
  vm: AuthenticationVirtualMachine<BitcoinCashAuthenticationProgramState>,
  program: AuthenticationProgram<BitcoinCashAuthenticationProgramExternalState>
  // tslint:disable-next-line:readonly-array
): Array<DebuggingStep<BitcoinCashAuthenticationProgramState>> => {
  const { steps: unlockingSteps, result: unlockingResult } = debugPhase(
    vm,
    program,
    program.unlockingScript,
    Phase.unlocking
  );
  // tslint:disable-next-line:no-if-statement
  if (unlockingResult.error !== undefined) {
    return unlockingSteps;
  }
  const { steps: lockingSteps, result: lockingResult } = debugPhase(
    vm,
    program,
    program.lockingScript,
    Phase.locking,
    unlockingResult.stack
  );
  return lockingResult.error !== undefined ||
    !isPayToScriptHash(program.lockingScript)
    ? [...unlockingSteps, ...lockingSteps]
    : !isPushOnly(unlockingResult.operations)
    ? [
        ...unlockingSteps,
        ...lockingSteps,
        {
          asm: P2shError.asm,
          description: P2shError.pushOnly,
          state: lockingResult
        }
      ]
    : unlockingResult.stack.length === 0
    ? [
        ...unlockingSteps,
        ...lockingSteps,
        {
          asm: P2shError.asm,
          description: P2shError.emptyStack,
          state: lockingResult
        }
      ]
    : [
        ...unlockingSteps,
        ...lockingSteps,
        ...evaluateP2sh(unlockingResult.stack, (p2shScript, p2shStack) =>
          debugPhase(vm, program, p2shScript, Phase.p2sh, p2shStack)
        ).steps
      ];
};

/**
 * Check whether a resulting `BitcoinCashAuthenticationProgramState` is valid
 * according to network consensus rules.
 *
 * @param state the `BitcoinCashAuthenticationProgramState` to test
 */
export const validateBitcoinCashAuthenticationProgramState = (
  state: BitcoinCashAuthenticationProgramState
) =>
  state.error !== undefined &&
  state.stack.length === 1 &&
  stackElementIsTruthy(state.stack[0]);

// tslint:disable-next-line:cyclomatic-complexity
export const evaluateBitcoinCashAuthenticationProgram = (
  vm: AuthenticationVirtualMachine<BitcoinCashAuthenticationProgramState>,
  program: AuthenticationProgram<BitcoinCashAuthenticationProgramExternalState>
): BitcoinCashAuthenticationProgramState => {
  const unlockingResult = vm.evaluate(
    createBitcoinCashProgramState(program, program.unlockingScript, [])
  );
  // tslint:disable-next-line:no-if-statement
  if (unlockingResult.error !== undefined) {
    return unlockingResult;
  }
  const lockingResult = vm.evaluate(
    createBitcoinCashProgramState(
      program,
      program.lockingScript,
      unlockingResult.stack
    )
  );
  return isPayToScriptHash(program.lockingScript)
    ? evaluateP2sh(unlockingResult.stack, (p2shScript, p2shStack) =>
        vm.evaluate(
          createBitcoinCashProgramState(program, p2shScript, p2shStack)
        )
      )
    : lockingResult;
};
