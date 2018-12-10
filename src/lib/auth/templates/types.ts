export interface AuthenticationTemplate {
  /**
   * An optionally multi-line, free-form, human-readable description of this
   * authentication template (for use in user interfaces).
   */
  readonly description?: string;
  /**
   * An array of entities defined in this authentication template. See
   * `AuthenticationTemplateEntity` for more information.
   */
  readonly entities: ReadonlyArray<AuthenticationTemplateEntity>;

  /**
   * A single-line, Title Case, human-readable name for this authentication template (for
   * use in user interfaces).
   */
  readonly name?: string;

  /**
   * An object detailing the inline, locking, and unlocking scripts used in this
   * template.
   */
  readonly scripts: AuthenticationTemplateScripts;

  /**
   * A list of supported AuthenticationVirtualMachines for this template.
   */
  readonly supported: ReadonlyArray<AuthenticationVirtualMachineIdentifier>;

  /**
   * A number identifying the format of this AuthenticationTemplate.
   * Currently, this implementation requires `version` be set to `1`.
   */
  readonly version: 0;
}

export type AuthenticationVirtualMachineIdentifier =
  | 'BCH_2018Nov'
  | 'BCH_2019May'
  | 'BSV_2018Nov'
  | 'BTC_2017Aug';

export interface AuthenticationTemplateEntity {
  /**
   * A single-line, Title Case, human-readable identifier for this entity, e.g.: `Trusted Third-Party`
   */
  readonly name: string;
  /**
   * The names of the unlocking scripts which are intended for use by this
   * entity.
   *
   * Provided the necessary variables, any entity can construct an unlocking
   * script, but this option allows us to hint to more advanced wallets which
   * unlocking scripts to recommend to users. (Especially when all unlocking
   * scripts require inter-entity communication initiated by a user.)
   */
  readonly unlockOptions?: ReadonlyArray<string>;
  /**
   * An array of variables which must be provided by this entity for use in the
   * this template's scripts. Some variables are required before locking script
   * generation, while some variables can or must be resolved only before
   * unlocking script generation.
   */
  readonly variables?: ReadonlyArray<AuthenticationTemplateVariable>;
}

export interface AuthenticationTemplateScripts {
  /**
   * Inline scripts can be referenced from locking and unlocking scripts to
   * abstract and simplify complex operations.
   */
  readonly inline?: AuthenticationTemplateInlineScripts;
  /**
   * An expression which describes the locking script for this authentication
   * template.
   */
  readonly lock: AuthenticationTemplateLockingScript;
  /**
   * An array of macros which describe how to construct globally-available
   * unlocking scripts for this authentication template (unlocking scripts
   * which can be constructed by all entities).
   */
  readonly unlock: ReadonlyArray<AuthenticationTemplateUnlockingScript>;
}

export interface AuthenticationTemplateScript {
  /**
   * The script definition in BitAuth Script.
   */
  readonly script: string;
}

interface AuthenticationTemplateLockingScript
  extends AuthenticationTemplateScript {
  /**
   * The locking script must have an id of `lock`.
   */
  readonly id: 'lock';
}

interface AuthenticationTemplateUnlockingScript
  extends AuthenticationTemplateScript {
  /**
   * A single-line, human-readable name for this unlocking script (for use in user interfaces).
   */
  readonly name: string;
}

type AuthenticationTemplateInlineScripts = ReadonlyArray<
  AuthenticationTemplateChecksumScript | AuthenticationTemplateInlineScript
>;

export interface AuthenticationTemplateInlineScript
  extends AuthenticationTemplateScript {
  /**
   * The identifier used to refer to this script in other scripts.
   */
  readonly id: string;
  /**
   * One or more tests which can be used during development and during template
   * validation to confirm the correctness of this inline script.
   */
  readonly tests?: ReadonlyArray<AuthenticationTemplateInlineScriptTest>;
}

export interface AuthenticationTemplateChecksumScript
  extends AuthenticationTemplateInlineScript {
  /**
   * If provided, the `checksum` script should digest all variable data provided
   * at wallet creation time.
   *
   * When using a template with a checksum script, each entity must first
   * compute the checksum and compare its result with the results of each other
   * entity. This allows clients to avoid creating wallets using malicious or
   * corrupted data.
   */
  readonly id: 'checksum';
}

export interface AuthenticationTemplateInlineScriptTest {
  /**
   * The script to evaluate after the script being tested. The test passes if
   * this script leaves only a 1 (ScriptNumber) on the stack.
   */
  readonly check: string;
  /**
   * A single-line, Title Case, human-readable name for this test (for use in user interfaces).
   */
  readonly name?: string;
  /**
   * A script to evaluate before the script being tested. This can be used to
   * push values to the stack which are operated on by the inline script.
   */
  readonly setup?: string;
}

export interface AuthenticationTemplateVariableBase {
  /**
   * The identifier used to refer to this variable in the scripts.
   */
  readonly id: string;
  /**
   * The hexadecimal string-encoded test value for this variable. This test
   * value is used during development and can provide validation when
   * importing this template into a new system.
   *
   * When testing, all variables for all entities are initialized to their
   * `testValue` and each unlocking script is tested against the locking script,
   * ensuring it is able to unlock it. For inline scripts, variables are also
   * initialized to their `testValue`s when evaluating inline script tests.
   */
  readonly testValue?: string;
  readonly type: string;
}

/**
 * Separated from `AuthenticationTemplateVariableBase` to provide better
 * contextual TypeDocs.
 */
export interface AuthenticationTemplateVariableKey
  extends AuthenticationTemplateVariableBase {
  /**
   * The identifier used as a prefix when referring to this key in the scripts.
   *
   * Each Key exports its own `public`, `private`, and `signature`
   * properties. The `signature` property contains a property for each possible
   * signature serialization flag: `all`, `single`, `none`
   *
   * For example, with an id of `keyA`, the following are all valid data pushes:
   * `<keyA.private>`, `<keyA.public>`, `<keyA.signature.all>`,
   * `<keyA.signature.single>`, `<keyA.signature.none>`
   *
   * TODO: for data signatures, accept any identifier after signature, e.g.
   * `<keyA.signature.myTXData>`
   */
  readonly id: string;
}

export interface HDKey extends AuthenticationTemplateVariableKey {
  /**
   * A "hardened" child key is derived using an extended *private key*, while a
   * non-hardened child key is derived using only an extended *public key*.
   *
   * Non-hardened keys are more useful for some templates, e.g. to allow for
   * new locking scripts to be generated without communicating new public keys
   * between entities for each. **However, using a non-hardened key has critical
   * security implications.** If an attacker gains possession of both a parent
   * extended *public key* and any child private key, the attacker can easily
   * derive the parent extended *private key*, and with it, all hardened and
   * non-hardened child keys.
   *
   * Because this security consideration should be evaluated for any template
   * using `HDKey`s, `derivationHardened` defaults to `true`.
   */
  readonly derivationHardened?: boolean;
  /**
   * All `HDKey`s are hardened-derivations of the entity's root `HDKey`. The
   * resulting branches are then used to generate child keys scripts:
   *
   * `m / HDKey derivation index' / script index`
   *
   * By default, `derivationIndex` is `0`. For a single entity to use multiple
   * `HDKey`s, a different `derivationIndex` must be used for each.
   *
   * For greater control over key generation and mapping, use `Key`.
   */
  readonly derivationIndex?: number;
  /**
   * The `HDKey` (Hierarchical-Deterministic Key) type automatically manages key
   * generation and mapping in a standard way. For greater control, use `Key`.
   */
  readonly type: 'HDKey';
}

export interface Key extends AuthenticationTemplateVariableKey {
  /**
   * The `Key` type provides fine-grained control over key generation and mapping.
   * Most templates should instead use `HDKey`.
   *
   * Any HD (Hierarchical-Deterministic) derivation must be completed outside of
   * the templating system and provided at the time of use.
   */
  readonly type: 'Key';
}

export interface WalletData extends AuthenticationTemplateVariableBase {
  /**
   * A single-line, human readable description for this wallet data.
   */
  readonly description: string;
  /**
   * A single-line, Title Case, human-readable label for this wallet data.
   */
  readonly label: string;
  /**
   * The `WalletData` type provides a static piece of data which should be
   * collected once and stored at the time of wallet creation. `WalletData`
   * should be persistent for the life of the wallet, rather than changing from
   * locking script to locking script.
   *
   * For transaction-specific data, use `TransactionData`.
   */
  readonly type: 'WalletData';
}

export interface TransactionData extends AuthenticationTemplateVariableBase {
  /**
   * A single-line, human readable description for this transaction data.
   */
  readonly description: string;
  /**
   * A single-line, Title Case, human-readable label for this transaction data.
   */
  readonly label: string;

  /**
   * `TransactionData` is the most low-level variable type. It must be collected
   * and stored each time a script is generated (usually, a locking script).
   * `TransactionData` can include any type of data, and can be used in any way.
   *
   * For more persistent data, use `WalletData`.
   */
  readonly type: 'TransactionData';
}

export interface CurrentBlockTime extends AuthenticationTemplateVariableBase {
  /**
   * The `CurrentBlockTime` type provides the current block time as a Script
   * Number. This is useful when computing a time for OP_CHECKLOCKTIMEVERIFY
   * which is relative to the current time when a script is created (usually, a
   * locking script).
   */
  readonly type: 'CurrentBlockTime';
}

export interface CurrentBlockHeight extends AuthenticationTemplateVariableBase {
  /**
   * The `CurrentBlockHight` type provides the current block height as a Script
   * Number. This is useful when computing a height for OP_CHECKLOCKTIMEVERIFY
   * which is relative to the height at the moment a script is created (usually,
   * a locking script).
   */
  readonly type: 'CurrentBlockHeight';
}

export type AuthenticationTemplateVariable =
  | HDKey
  | Key
  | WalletData
  | TransactionData
  | CurrentBlockTime
  | CurrentBlockHeight;
