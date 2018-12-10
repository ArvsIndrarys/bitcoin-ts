/**
 * Authentication Templating Language:
 *
 * TODO:
 * - letter: [a-zA-Z]
 * - digit: [0-9]
 * - hex: [0-9a-f]
 *
 * - hexString: hex | hex hex
 *
 * - integer: digit | digit integer
 * - binary: `0x` hex
 *
 * - validIdentifierCharacter: [a-zA-Z0-9_]
 *
 * - opcode: [all the "OP_CODE" identifiers]
 * - identifier: letter validIdentifierCharacter
 * - single line comment: `\/\/.*`
 * - multi-line comment: `\/\*[\s\S]*\*\/`
 * - evaluation: `$(` expression `)`
 * - push: `<` expression `>`
 *
 */

type Parser<T> = (source: string) => ReadonlyArray<[T, string]>;
