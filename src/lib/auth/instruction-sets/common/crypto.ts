import { Ripemd160, Secp256k1, Sha256 } from '../../../crypto/crypto';
import { bigIntToBitcoinVarInt } from '../../../utils';
import { CommonProgramState, StackMachineState } from '../../state';
import { Operator } from '../../virtual-machine';
import { BitcoinCashOpCodes } from '../bitcoin-cash/bitcoin-cash-opcodes';
import {
  applyError,
  booleanToScriptNumber,
  CommonAuthenticationError,
  CommonConsensus,
  ErrorState,
  isScriptNumberError,
  MinimumProgramState,
  parseBytesAsScriptNumber
} from './common';
import {
  decodeBitcoinSignature,
  isValidPublicKeyEncoding,
  isValidSignatureEncoding
} from './encoding';
import { generateBitcoinCashSigningSerialization } from './signing-serialization';

export { Ripemd160, Sha256, Secp256k1 };

// export const codeSeparator = <
// todo  ProgramState extends MinimumProgramState & CommonProgramState
// >(): Operator<ProgramState> => ({
//   asm: 'OP_CODESEPARATOR',
//   description: 'Mark this byte as the beginning of this scripts signed data.',
//   operation: (state: ProgramState) => {
//     // tslint:disable-next-line:no-expression-statement no-object-mutation
//     state.lastCodeSeparator = state.ip;
//     return state;
//   }
// });

export const opHash160 = <
  ProgramState extends MinimumProgramState &
    StackMachineState &
    ErrorState<InstructionSetError>,
  InstructionSetError
>(
  sha256: Sha256,
  ripemd160: Ripemd160
): Operator<ProgramState> => ({
  asm: 'OP_HASH160',
  description:
    'Pop the top element off the stack and pass it through sha256, then ripemd160, pushing the result onto the stack.',
  operation: (state: ProgramState) => {
    const element = state.stack.pop();
    // tslint:disable-next-line:no-if-statement
    if (!element) {
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.emptyStack,
        state
      );
    }
    // tslint:disable-next-line:no-expression-statement
    state.stack.push(ripemd160.hash(sha256.hash(element)));
    return state;
  }
});

export const opCheckSig = <
  ProgramState extends CommonProgramState<InstructionSetError>,
  InstructionSetError
>(
  sha256: Sha256,
  secp256k1: Secp256k1
): Operator<ProgramState> => ({
  asm: 'OP_CHECKSIG',
  description:
    'Pop the top two elements off the stack. Treat the first as a public key and the second as a signature. If the signature is valid, push a Script Number 1, otherwise push a Script Number 0.',
  operation: (state: ProgramState) => {
    const publicKey = state.stack.pop();
    const bitcoinEncodedSignature = state.stack.pop();
    // tslint:disable-next-line:no-if-statement
    if (publicKey === undefined || bitcoinEncodedSignature === undefined) {
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.emptyStack,
        state
      );
    }
    // tslint:disable-next-line:no-if-statement
    if (!isValidPublicKeyEncoding(publicKey)) {
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.invalidPublicKeyEncoding,
        state
      );
    }
    // tslint:disable-next-line:no-if-statement
    if (!isValidSignatureEncoding(bitcoinEncodedSignature)) {
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.invalidSignatureEncoding,
        state
      );
    }
    const script = state.script.subarray(state.lastCodeSeparator + 1);
    const scriptCode = Uint8Array.from([
      ...bigIntToBitcoinVarInt(BigInt(script.length)),
      ...script
    ]);
    const { signingSerializationType, signature } = decodeBitcoinSignature(
      bitcoinEncodedSignature
    );

    const serialization = generateBitcoinCashSigningSerialization(
      state.version,
      state.transactionOutpointsHash,
      state.transactionSequenceNumbersHash,
      state.outpointTransactionHash,
      state.outpointIndex,
      scriptCode,
      state.outpointValue,
      state.sequenceNumber,
      state.correspondingOutputHash,
      state.transactionOutputsHash,
      state.locktime,
      signingSerializationType
    );
    const digest = sha256.hash(sha256.hash(serialization));
    // tslint:disable-next-line:no-expression-statement
    state.stack.push(
      booleanToScriptNumber(
        secp256k1.verifySignatureDERLowS(signature, publicKey, digest)
      )
    );
    return state;
  }
});

const enum Multisig {
  maximumPublicKeys = 20
}

export const opCheckMultiSig = <
  ProgramState extends CommonProgramState<InstructionSetError>,
  InstructionSetError
>(
  sha256: Sha256,
  secp256k1: Secp256k1
): Operator<ProgramState> => ({
  asm: 'OP_CHECKMULTISIG',
  description:
    'Pop elements off the stack: first the number of public keys, followed by the public keys, then the required number of signatures, followed by the signatures, then a final value which is ignored (due to a protocol bug). Checking each signature against each public key in order, if the required number of signatures are valid, push a Script Number 1, otherwise push a Script Number 0.',
  // tslint:disable-next-line:cyclomatic-complexity
  operation: (state: ProgramState) => {
    const potentialPublicKeysBytes = state.stack.pop();

    if (potentialPublicKeysBytes === undefined) {
      // tslint:disable-line:no-if-statement
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.emptyStack,
        state
      );
    }
    const potentialPublicKeysParsed = parseBytesAsScriptNumber(
      potentialPublicKeysBytes
    );
    const potentialPublicKeys = Number(potentialPublicKeysParsed);

    if (
      // tslint:disable-line:no-if-statement
      isScriptNumberError(potentialPublicKeysParsed) ||
      potentialPublicKeys < 0
    ) {
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.invalidNaturalNumber,
        state
      );
    }
    if (potentialPublicKeys > Multisig.maximumPublicKeys) {
      // tslint:disable-line:no-if-statement
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.exceedsMaximumMultisigPublicKeyCount,
        state
      );
    }
    const publicKeys = state.stack.splice(-potentialPublicKeys);

    // in OP_CHECKMULTISIG, each public key is counted as another operation
    state.operationCount += potentialPublicKeys; // tslint:disable-line:no-expression-statement no-object-mutation
    if (state.operationCount > CommonConsensus.maximumOperationCount) {
      // tslint:disable-line:no-if-statement
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.exceededMaximumOperationCount,
        state
      );
    }

    const requiredApprovingPublicKeysBytes = state.stack.pop();
    if (requiredApprovingPublicKeysBytes === undefined) {
      // tslint:disable-line:no-if-statement
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.emptyStack,
        state
      );
    }
    const requiredApprovingPublicKeysParsed = parseBytesAsScriptNumber(
      requiredApprovingPublicKeysBytes
    );
    const requiredApprovingPublicKeys = Number(
      requiredApprovingPublicKeysParsed
    );

    if (
      // tslint:disable-line:no-if-statement
      isScriptNumberError(requiredApprovingPublicKeysParsed) ||
      requiredApprovingPublicKeys < 0
    ) {
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.invalidNaturalNumber,
        state
      );
    }

    if (requiredApprovingPublicKeys > potentialPublicKeys) {
      // tslint:disable-line:no-if-statement
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.insufficientPublicKeys,
        state
      );
    }

    const signatures = state.stack.splice(-requiredApprovingPublicKeys);

    const protocolBugValue = state.stack.pop();

    if (protocolBugValue === undefined) {
      // tslint:disable-line:no-if-statement
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.emptyStack,
        state
      );
    }

    // TODO: is this currently enforced in BCH?
    if (protocolBugValue.length !== 0) {
      // tslint:disable-line:no-if-statement
      return applyError<ProgramState, InstructionSetError>(
        CommonAuthenticationError.invalidProtocolBugValue,
        state
      );
    }

    const script = state.script.subarray(state.lastCodeSeparator + 1);
    const scriptCode = Uint8Array.from([
      ...bigIntToBitcoinVarInt(BigInt(script.length)),
      ...script
    ]);

    let approvingPublicKeys = 0; // tslint:disable-line:no-let
    let remainingSignatures = signatures.length; // tslint:disable-line:no-let
    let remainingPublicKeys = publicKeys.length; // tslint:disable-line:no-let
    while (
      remainingSignatures > 0 &&
      remainingPublicKeys >= approvingPublicKeys + remainingSignatures &&
      approvingPublicKeys !== requiredApprovingPublicKeys
    ) {
      const publicKey = publicKeys[remainingPublicKeys - 1];
      const bitcoinEncodedSignature = signatures[remainingSignatures - 1];

      if (!isValidPublicKeyEncoding(publicKey)) {
        // tslint:disable-line:no-if-statement
        return applyError<ProgramState, InstructionSetError>(
          CommonAuthenticationError.invalidPublicKeyEncoding,
          state
        );
      }

      if (!isValidSignatureEncoding(bitcoinEncodedSignature)) {
        // tslint:disable-line:no-if-statement
        return applyError<ProgramState, InstructionSetError>(
          CommonAuthenticationError.invalidSignatureEncoding,
          state
        );
      }

      const { signingSerializationType, signature } = decodeBitcoinSignature(
        bitcoinEncodedSignature
      );

      const serialization = generateBitcoinCashSigningSerialization(
        state.version,
        state.transactionOutpointsHash,
        state.transactionSequenceNumbersHash,
        state.outpointTransactionHash,
        state.outpointIndex,
        scriptCode,
        state.outpointValue,
        state.sequenceNumber,
        state.correspondingOutputHash,
        state.transactionOutputsHash,
        state.locktime,
        signingSerializationType
      );
      const digest = sha256.hash(sha256.hash(serialization));

      const signed = secp256k1.verifySignatureDERLowS(
        signature,
        publicKey,
        digest
      );

      // tslint:disable-next-line:no-if-statement
      if (signed) {
        approvingPublicKeys++; // tslint:disable-line:no-expression-statement
        remainingSignatures--; // tslint:disable-line:no-expression-statement
      }
      remainingPublicKeys--; // tslint:disable-line:no-expression-statement
    }

    // tslint:disable-next-line:no-expression-statement
    state.stack.push(
      booleanToScriptNumber(approvingPublicKeys === requiredApprovingPublicKeys)
    );
    return state;
  }
});

export const cryptoOperators = <
  ProgramState extends CommonProgramState<InstructionSetError>,
  InstructionSetError
>(
  sha256: Sha256,
  ripemd160: Ripemd160,
  secp256k1: Secp256k1
) => ({
  [BitcoinCashOpCodes.OP_HASH160]: opHash160<ProgramState, InstructionSetError>(
    sha256,
    ripemd160
  ),
  [BitcoinCashOpCodes.OP_CHECKSIG]: opCheckSig<
    ProgramState,
    InstructionSetError
  >(sha256, secp256k1),
  [BitcoinCashOpCodes.OP_CHECKMULTISIG]: opCheckMultiSig<
    ProgramState,
    InstructionSetError
  >(sha256, secp256k1)
});
