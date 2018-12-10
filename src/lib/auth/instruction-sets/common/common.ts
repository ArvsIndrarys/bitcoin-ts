import {
  CommonProgramState,
  ErrorState,
  MinimumProgramState
} from '../../state';
import { Operator } from '../../virtual-machine';
import { bitwiseOperators } from './bitwise';
import { cryptoOperators, Ripemd160, Secp256k1, Sha256 } from './crypto';
import { flowControlOperators } from './flow-control';
import {
  pushDataConstantOperators,
  pushDataVariableOperators,
  pushNumberOperators
} from './push';
import { stackOperators } from './stack';

export * from './push';
export * from '../../state';
export * from './stack';

export { Ripemd160, Sha256, Secp256k1 };

export enum CommonAuthenticationError {
  emptyStack = 'Tried to read from an empty stack.',
  malformedPush = 'Script must be long enough to push the requested number of bytes.',
  nonMinimalPush = 'Push operations must use the smallest possible encoding.',
  exceedsMaximumPush = 'Push exceeds the push size limit of 520 bytes.',
  unknownOpcode = 'Called an unknown or unimplemented opcode.',
  failedVerify = 'Script failed an OP_VERIFY operation.',
  calledReturn = 'Script called an OP_RETURN operation.',
  invalidPublicKeyEncoding = 'Encountered an improperly encoded public key.',
  invalidSignatureEncoding = 'Encountered an improperly encoded signature.',
  invalidNaturalNumber = 'Invalid input: this parameter requires a natural number.',
  insufficientPublicKeys = 'An OP_CHECKMULTISIG operation requires signatures from more public keys than are provided.',
  invalidProtocolBugValue = 'The protocol bug value must be a Script Number 0.',
  exceededMaximumOperationCount = 'Script exceeded the maximum operation count (201 operations).',
  exceedsMaximumMultisigPublicKeyCount = 'Script called an OP_CHECKMULTISIG which exceeds the maximum public key count (20 public keys).'
}

export enum CommonConsensus {
  maximumOperationCount = 201
}

export const undefinedOperator = <
  ProgramState extends MinimumProgramState & ErrorState<InstructionSetError>,
  InstructionSetError
>(): { readonly undefined: Operator<ProgramState> } => ({
  undefined: {
    asm: (state: ProgramState) => `OP_UNKNOWN${state.script[state.ip - 1]}`,
    description: (state: ProgramState) =>
      `An undefined or unimplemented opcode (${
        state.script[state.ip - 1]
      }) was called.`,
    operation: (state: ProgramState) => {
      // tslint:disable-next-line:no-object-mutation no-expression-statement
      state.error = CommonAuthenticationError.unknownOpcode;
      return state;
    }
  }
});

export const commonOperators = <
  AuthenticationProgramState extends CommonProgramState<AuthenticationError>,
  AuthenticationError
>(
  sha256: Sha256,
  ripemd160: Ripemd160,
  secp256k1: Secp256k1
): {
  readonly [opcodes: number]: Operator<AuthenticationProgramState>;
  readonly undefined: Operator<AuthenticationProgramState>;
} => ({
  ...undefinedOperator<AuthenticationProgramState, AuthenticationError>(),
  ...pushNumberOperators<AuthenticationProgramState>(),
  ...pushDataConstantOperators<
    AuthenticationProgramState,
    AuthenticationError
  >(),
  ...pushDataVariableOperators<
    AuthenticationProgramState,
    AuthenticationError
  >(),
  ...bitwiseOperators<AuthenticationProgramState, AuthenticationError>(),
  ...cryptoOperators<AuthenticationProgramState, AuthenticationError>(
    sha256,
    ripemd160,
    secp256k1
  ),
  ...flowControlOperators<AuthenticationProgramState, AuthenticationError>(),
  ...stackOperators<AuthenticationProgramState, AuthenticationError>()
});

export const applyError = <
  ProgramState extends ErrorState<InstructionSetError>,
  InstructionSetError
>(
  error: CommonAuthenticationError | InstructionSetError,
  state: ProgramState
) =>
  // tslint:disable-next-line:no-object-literal-type-assertion
  ({
    ...(state as {}),
    error
  } as ProgramState);

export const cloneStack = (stack: ReadonlyArray<Readonly<Uint8Array>>) =>
  // tslint:disable-next-line:readonly-array
  stack.reduce<Uint8Array[]>((newStack, element) => {
    // tslint:disable-next-line:no-expression-statement
    newStack.push(element.slice());
    return newStack;
  }, []);

export enum ScriptNumberError {
  outOfRange = 'Failed to parse Script Number: overflows Script Number range.',
  requiresMinimal = 'Failed to parse Script Number: the number is not minimally-encoded.'
}

// tslint:disable-next-line:no-any
export const isScriptNumberError = (
  value: BigInt | ScriptNumberError
): value is ScriptNumberError =>
  value === ScriptNumberError.outOfRange ||
  value === ScriptNumberError.requiresMinimal;

/**
 * This method attempts to parse a "Script Number", a format with which numeric
 * values are represented on the stack. (The Satoshi implementation calls this
 * `CScriptNum`.)
 *
 * If `bytes` is a valid Script Number, this method returns the represented
 * number in BigInt format. If `bytes` is not valid, a `ScriptNumberError` is
 * returned.
 *
 * All common operations accepting numeric parameters or pushing numeric values
 * to the stack currently use the Script Number format. The binary format of
 * numbers wouldn't be important if they could only be operated on by arithmetic
 * operators, but since the results of these operations may become input to
 * other operations (e.g. hashing), the specific representation is consensus-
 * critical.
 *
 * Parsing of Script Numbers is limited to 4 bytes (with the exception of
 * OP_CHECKLOCKTIMEVERIFY, which reads up to 5-bytes). The bytes are read as a
 * signed integer (for 32-bits: inclusive range from -2^31 + 1 to 2^31 - 1) in
 * little-endian byte order. It must further be encoded as minimally as possible
 * (no zero-padding). See code/tests for details.
 *
 * ### Notes
 *
 * Operators may push numeric results to the stack which exceed the current
 * 4-byte length limit of Script Numbers. While these stack elements would
 * otherwise be valid Script Numbers, because of the 4-byte length limit, they
 * can only be used as none-numeric values in later operations.
 *
 * Most other implementations currently parse Script Numbers into 64-bit
 * integers to operate on them (rather than integers of arbitrary size like
 * BigInt). Currently, no operators are at risk of overflowing 64-bit integers
 * given 32-bit integer inputs, but future operators may require additional
 * refactoring in those implementations.
 *
 * This implementation always requires minimal encoding of script numbers.
 * Applications trying to validate (historical) transactions without this
 * requirement will need a modified method.
 *
 * @param bytes a Uint8Array from the stack
 */
// tslint:disable-next-line:cyclomatic-complexity
export const parseBytesAsScriptNumber = (
  bytes: Uint8Array
): bigint | ScriptNumberError => {
  const maximumScriptNumberByteLength = 4;
  // tslint:disable-next-line:no-if-statement
  if (bytes.length === 0) {
    return BigInt(0);
  }
  // tslint:disable-next-line:no-if-statement
  if (bytes.length > maximumScriptNumberByteLength) {
    return ScriptNumberError.outOfRange;
  }
  const mostSignificantByte = bytes[bytes.length - 1];
  const secondMostSignificantByte = bytes[bytes.length - 1 - 1];
  const allButTheSignBit = 0b1111_111;
  const justTheSignBit = 0b1000_0000;

  // tslint:disable-next-line:no-if-statement no-bitwise
  if (
    // tslint:disable-next-line:no-bitwise
    (mostSignificantByte & allButTheSignBit) === 0 &&
    // tslint:disable-next-line:no-bitwise
    (bytes.length <= 1 || (secondMostSignificantByte & justTheSignBit) === 0)
  ) {
    return ScriptNumberError.requiresMinimal;
  }

  const bitsPerByte = 8;
  const signFlippingByte = 0x80;
  // tslint:disable-next-line:prefer-const no-let
  let result = BigInt(0);
  // tslint:disable-next-line:prefer-for-of no-let
  for (let byte = 0; byte < bytes.length; byte++) {
    // tslint:disable-next-line:no-expression-statement no-bitwise
    result |= BigInt(bytes[byte]) << BigInt(byte * bitsPerByte);
  }

  // tslint:disable-next-line:no-bitwise
  const isNegative = (bytes[bytes.length - 1] & signFlippingByte) !== 0;
  return isNegative
    ? -// tslint:disable-next-line:no-bitwise
      (
        result &
        // tslint:disable-next-line:no-bitwise
        BigInt(~(signFlippingByte << (bitsPerByte * (bytes.length - 1))))
      )
    : result;
};

/**
 * Convert a BigInt into the "Script Number" format. See
 * `parseBytesAsScriptNumber` for more information.
 *
 * @param integer the BigInt to encode as a Script Number
 */
// tslint:disable-next-line:cyclomatic-complexity
export const bigIntToScriptNumber = (integer: bigint): Uint8Array => {
  // tslint:disable-next-line:no-if-statement
  if (integer === BigInt(0)) {
    return new Uint8Array();
  }

  // tslint:disable-next-line:readonly-array
  const bytes: number[] = [];
  const isNegative = integer < 0;
  const byteStates = 0xff;
  const bitsPerByte = 8;
  // tslint:disable-next-line:prefer-const no-let
  let remaining = isNegative ? -integer : integer;
  while (remaining > 0) {
    // tslint:disable-next-line:no-expression-statement no-bitwise
    bytes.push(Number(remaining & BigInt(byteStates)));
    // tslint:disable-next-line:no-expression-statement no-bitwise
    remaining >>= BigInt(bitsPerByte);
  }

  const signFlippingByte = 0x80;
  // tslint:disable-next-line:no-if-statement no-bitwise
  if ((bytes[bytes.length - 1] & signFlippingByte) > 0) {
    // tslint:disable-next-line:no-expression-statement
    bytes.push(isNegative ? signFlippingByte : 0x00);
    // tslint:disable-next-line:no-if-statement
  } else if (isNegative) {
    // tslint:disable-next-line:no-expression-statement no-object-mutation no-bitwise
    bytes[bytes.length - 1] |= signFlippingByte;
  }
  return new Uint8Array(bytes);
};

/**
 * Returns true if the provided stack element is "truthy" in the sense required
 * by several operations (anything but zero and "negative zero").
 *
 * The Satoshi implementation calls this method `CastToBool`.
 *
 * @param element the stack element to check for truthiness
 */
export const stackElementIsTruthy = (element: Uint8Array) => {
  const signFlippingByte = 0x80;
  // tslint:disable-next-line:no-let
  for (let i = 0; i < element.length; i++) {
    // tslint:disable-next-line:no-if-statement
    if (element[i] !== 0) {
      // tslint:disable-next-line:no-if-statement
      if (i === element.length - 1 && element[i] === signFlippingByte) {
        return false;
      }
      return true;
    }
  }
  return false;
};

/**
 * Convert a boolean into Script Number format (the type used to express
 * boolean values emitted by several operations).
 *
 * @param value the boolean value to convert
 */
export const booleanToScriptNumber = (value: boolean) =>
  value ? bigIntToScriptNumber(BigInt(1)) : bigIntToScriptNumber(BigInt(0));
