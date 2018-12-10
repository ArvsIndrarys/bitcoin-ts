import { Sha256 } from '../crypto/sha256';
import {
  getOutpointsHash,
  getOutputHash,
  getOutputsHash,
  getSequenceNumbersHash,
  Output,
  Transaction
} from '../transaction';
import { CommonAuthenticationError } from './instruction-sets/common/common';
import { NetworkState } from './state';

export interface NetworkState {
  readonly blockHeight: number;
  readonly blockTime: number;
}

/**
 * State which applies to every input in a given transaction.
 */
export interface TransactionState {
  /**
   * A time or block height at which the transaction is considered valid (and
   * can be added to the block chain). This allows signers to create time-locked
   * transactions which may only become valid in the future.
   */
  readonly locktime: number;
  /**
   * A.K.A. `hashPrevouts`
   *
   * The double SHA256 of the serialization of all input outpoints. (See
   * BIP143 or Bitcoin Cash's Replay Protected Sighash spec for details.)
   */
  readonly transactionOutpointsHash: Uint8Array;
  /*
   * A.K.A. `hashOutputs` with `SIGHASH_ALL`
   *
   * The double SHA256 of the serialization of output amounts and locking
   * scripts. (See BIP143 or Bitcoin Cash's Replay Protected Sighash spec for
   * details.)
   */
  readonly transactionOutputsHash: Uint8Array;
  /*
   * A.K.A. `hashSequence`
   *
   * The double SHA256 of the serialization of all input sequence numbers. (See
   * BIP143 or Bitcoin Cash's Replay Protected Sighash spec for details.)
   */
  readonly transactionSequenceNumbersHash: Uint8Array;
  readonly version: number;
}

/**
 * The state of a single transaction input.
 *
 * Note: this implementation does not attempt to allow for lazy evaluation of
 * hashes. More performance-critical applications may choose to reimplement this
 * interface (and subsequent VM operations) by declaring the
 * `transactionOutpointsHash`, `transactionOutputHash`,
 * `transactionOutputsHash`, and `transactionSequenceNumbersHash` properties to
 * be of type `() => Uint8Array` to avoid pre-calculating unused hashes.
 */
export interface TransactionInputState extends TransactionState {
  /*
   * A.K.A. `hashOutputs` with `SIGHASH_SINGLE`
   *
   * The double SHA256 of the serialization of the output at the same index as
   * this input. If this input's index is larger than the total number of
   * outputs (such that there is no corresponding output), 32 bytes of zero
   * padding should be used instead. (See BIP143 or Bitcoin Cash's Replay
   * Protected Sighash spec for details.)
   */
  readonly correspondingOutputHash: Uint8Array;
  /**
   * The index (within the previous transaction) of the outpoint being spent by
   * this input.
   */
  readonly outpointIndex: number;
  /**
   * The hash/ID of the transaction from which the outpoint being spent by this
   * input originated.
   */
  readonly outpointTransactionHash: Uint8Array;
  /**
   * The value of the outpoint being spent by this input.
   */
  readonly outpointValue: bigint;
  /**
   * An additional number associated with every transaction input. It was
   * intended for use in time-locked transaction scenarios, but is now
   * superceded by other methods.
   *
   * Currently, it's only use is to disable locktime in transactions. (If all
   * inputs in a transaction have a sequence number equal to 0xFFFFFFFF,
   * locktime is ignored in transaction validation.)
   */
  readonly sequenceNumber: number;
}

export interface MinimumProgramState {
  /**
   * Instruction Pointer – the array index of `script` which will be read to
   * identify the next instruction. Once `ip` exceeds the length of `script`,
   * evaluation is complete.
   */
  // tslint:disable-next-line:readonly-keyword
  ip: number;
  readonly script: Uint8Array;
}

export interface StackMachineState<StackType = Uint8Array> {
  // tslint:disable-next-line:readonly-array readonly-keyword
  stack: StackType[];
}
export interface ErrorState<
  InstructionSetError,
  CommonError = CommonAuthenticationError
> {
  // tslint:disable-next-line:readonly-keyword
  error?: CommonError | InstructionSetError;
}

export interface CommonProgramExternalState
  extends TransactionInputState,
    NetworkState {}

export interface AuthenticationProgram<
  ExternalState = CommonProgramExternalState
> {
  readonly lockingScript: Uint8Array;
  readonly state: ExternalState;
  readonly unlockingScript: Uint8Array;
}

export interface CommonProgramInternalState<InstructionSetError>
  extends MinimumProgramState,
    StackMachineState,
    ErrorState<InstructionSetError> {
  // tslint:disable-next-line:readonly-keyword
  lastCodeSeparator: number;
  // tslint:disable-next-line:readonly-keyword
  operationCount: number;
  // tslint:disable-next-line:readonly-array readonly-keyword
  operations: number[];
}

export interface CommonProgramState<InstructionSetError>
  extends CommonProgramInternalState<InstructionSetError>,
    CommonProgramExternalState {}

export const createAuthenticationProgram = (
  spendingTransaction: Transaction,
  inputIndex: number,
  sourceOutput: Output,
  networkState: NetworkState,
  sha256: Sha256
) => ({
  lockingScript: sourceOutput.lockingScript,
  state: {
    ...networkState,
    correspondingOutputHash: getOutputHash(
      spendingTransaction.outputs[inputIndex],
      sha256
    ),
    locktime: spendingTransaction.locktime,
    outpointIndex: spendingTransaction.inputs[inputIndex].outpointIndex,
    outpointTransactionHash:
      spendingTransaction.inputs[inputIndex].outpointTransactionHash,
    outpointValue: sourceOutput.satoshis,
    sequenceNumber: spendingTransaction.inputs[inputIndex].sequenceNumber,
    transactionOutpointsHash: getOutpointsHash(
      spendingTransaction.inputs,
      sha256
    ),
    transactionOutputsHash: getOutputsHash(spendingTransaction.outputs, sha256),
    transactionSequenceNumbersHash: getSequenceNumbersHash(
      spendingTransaction.inputs,
      sha256
    ),
    version: spendingTransaction.version
  },
  unlockingScript: spendingTransaction.inputs[inputIndex].unlockingScript
});
