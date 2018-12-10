// tslint:disable:no-expression-statement no-magic-numbers no-unsafe-any readonly-array
import { AuthenticationTemplate, AuthenticationTemplateEntity } from './types';

export const singleSig: AuthenticationTemplate = {
  ...{
    description:
      'A standard single-factor authentication template which uses Pay-to-Public-Key-Hash (P2PKH).\nThis is currently the most common template in use on the network.',
    name: 'Single-Factor'
  },
  entities: [
    {
      name: 'Owner',
      variables: [
        {
          derivationHardened: false,
          derivationIndex: 0,
          id: 'key',
          type: 'HDKey'
        }
      ]
    },
    {
      name: 'Observer (Watch-Only)'
    }
  ],
  scripts: {
    lock: {
      id: 'lock',
      script:
        'OP_DUP OP_HASH160 <$(<key.public> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG'
    },
    unlock: [
      {
        name: 'Standard',
        script: '<key.signature.all> <key.public>'
      }
    ]
  },
  supported: ['BCH_2018Nov', 'BCH_2019May'],
  version: 0
};

const createCosigner = (
  id: string,
  suffix: string,
  unlockOptions: string[]
): AuthenticationTemplateEntity => ({
  name: id,
  unlockOptions,
  variables: [
    {
      derivationHardened: false,
      derivationIndex: 0,
      id: `key${suffix}`,
      type: 'HDKey'
    }
  ]
});

/**
 * 2-of-3 P2SH
 * This is a mostly-hard-coded 2-of-3 example. A more general function could be written to generate m-of-n wallets
 */
export const twoOfThree: AuthenticationTemplate = {
  ...{
    description:
      'A multi-factor template using standard 2-of-3 P2SH authentication template',
    name: 'Multi-Factor (2-of-3)'
  },
  entities: [
    createCosigner('Cosigner 1', '1', ['1 & 2', '1 & 3']),
    createCosigner('Cosigner 2', '2', ['1 & 2', '2 & 3']),
    createCosigner('Cosigner 3', '3', ['1 & 3', '2 & 3'])
  ],
  scripts: {
    inline: [
      {
        id: 'checksum',
        script:
          '$(<key1.public> OP_SHA256 <key2.public> OP_SHA256 OP_CAT OP_SHA256 <key3.public> OP_SHA256 OP_CAT OP_SHA256 OP_HASH160)',
        tests: [
          {
            check: '<TODO:checksum> OP_EQUAL'
          }
        ]
      },
      {
        id: 'redeem_script',
        script:
          'OP_2 <key2.public> <key2.public> <key3.public> OP_3 OP_CHECKMULTISIG'
      }
    ],
    lock: {
      id: 'lock',
      script: 'OP_HASH160 <$(<redeem_script> OP_HASH160)> OP_EQUAL'
    },
    unlock: [
      {
        name: '1 & 2',
        script: 'OP_0 <key1.signature.all> <key2.signature.all> <redeem_script>'
      },
      {
        name: '1 & 3',
        script: 'OP_0 <key1.signature.all> <key3.signature.all> <redeem_script>'
      },
      {
        name: '2 & 3',
        script: 'OP_0 <key2.signature.all> <key3.signature.all> <redeem_script>'
      }
    ]
  },
  supported: ['BCH_2018Nov', 'BCH_2019May'],
  version: 0
};

/**
 * 1-of-8 tree signature, very similar to: https://www.yours.org/content/tree-signature-variations-using-commutative-hash-trees-8a898830203a
 *
 *         root
 *        /    \
 *       a1     a2
 *      / \     / \
 *    b1  b2   b3  b4
 *    /\  /\   /\   /\
 * c | |  | |  | |  | |
 *   1 2  3 4  5 6  7 8
 *
 * The tree contains 5 levels:
 * - root
 * - a - concat and hash of b
 * - b - concat and hash of c
 * - c - hash of each respective public key
 * - # - each respective public key
 *
 * This is a mostly-hard-coded 1-of-8 example. A more general function could
 * be written to generate m-of-n wallets.
 */

const treeSigner = (
  id: string,
  suffix: string
): AuthenticationTemplateEntity => ({
  name: id,
  unlockOptions: [`Key ${id}`],
  variables: [
    {
      derivationHardened: false,
      derivationIndex: 0,
      id: `key${suffix}`,
      type: 'HDKey'
    }
    // if this was a non-HD wallet, and we were ok with clients needing to
    // communicate for every interaction, we could use a `localExpression`
    // to hide the publicKeys from each other until spending (requiring only
    // public key hashes as dependencies):
    // {
    //   expression: `<pubkeyhash_${suffix}> OP_HASH160`,
    //   id: `pubkeyhash_${suffix}`,
    //   type: 'localExpression',
    // }
  ]
});

export const treeSig: AuthenticationTemplate = {
  ...{
    description: 'A 1-of-8 P2SH tree signature authentication template',
    name: '1-of-8 Tree Signature'
  },
  entities: [1, 2, 3, 4, 5, 6, 7, 8].map(x =>
    treeSigner(`Signer ${x}`, `${x}`)
  ),
  scripts: {
    inline: [
      {
        id: 'checksum',
        script:
          '$(<key1.public> OP_SHA256 <key2.public> OP_SHA256 OP_CAT OP_SHA256 <key3.public> OP_SHA256 OP_CAT OP_SHA256 <key4.public> OP_SHA256 OP_CAT OP_SHA256 <key5.public> OP_SHA256 OP_CAT OP_SHA256 <key6.public> OP_SHA256 OP_CAT OP_SHA256 <key7.public> OP_SHA256 OP_CAT OP_SHA256 <key8.public> OP_SHA256 OP_CAT OP_SHA256 OP_HASH160)'
      },
      ...[
        ['root', 'a1', 'a2'],
        ['a1', 'b1', 'b2'],
        ['a2', 'b3', 'b4'],
        ['b1', 'c1', 'c2'],
        ['b2', 'c3', 'c4'],
        ['b3', 'c5', 'c6'],
        ['b4', 'c7', 'c8']
      ].map(([id, left, right]) => ({
        id,
        script: `${left} ${right} hash_node`
      })),
      ...[1, 2, 3, 4, 5, 6, 7, 8].map(i => ({
        id: `c${i}`,
        script: `<key${i}.public> OP_HASH160`
      })),
      {
        id: 'hash_node',
        script: 'sort_cat OP_HASH160'
      },
      {
        id: 'sort_cat',
        script: 'OP_LESSTHAN OP_IF OP_SWAP OP_ENDIF OP_CAT'
      },
      {
        id: 'redeem_script',
        script:
          'OP_4 OP_PICK OP_HASH160 sort_cat OP_HASH160 sort_cat OP_HASH160 sort_cat OP_HASH160 <$(root)> OP_EQUALVERIFY OP_CHECKSIG'
      },
      {
        id: 'redeem_script_hash',
        script: '<redeem_script> OP_HASH160'
      }
    ],
    lock: {
      id: 'lock',
      script: 'OP_HASH160 <$(redeem_script_hash)> OP_EQUAL'
    },
    unlock: [
      [1, 2, 2, 2],
      [2, 1, 2, 2],
      [3, 4, 1, 2],
      [4, 3, 1, 2],
      [5, 6, 4, 1],
      [6, 5, 4, 1],
      [7, 8, 3, 1],
      [8, 7, 3, 1]
    ].map(([key, sibling, bSibling, aSibling]) => ({
      name: `Key ${key}`,
      script: `<key${key}.signature.all> <key${key}.public> <$(a${aSibling})> <$(b${bSibling})> <$(c${sibling})> <redeemScript>`
    }))
  },
  supported: ['BCH_2018Nov', 'BCH_2019May'],
  version: 0
};

export const sigOfSig: AuthenticationTemplate = {
  ...{
    description:
      'A contrived example of a template which must be signed in a specific order',
    name: 'Sig-of-Sig Example (2-of-2)'
  },
  entities: [
    {
      name: 'First Signer',
      variables: [
        {
          derivationHardened: false,
          derivationIndex: 0,
          id: 'first',
          type: 'HDKey'
        }
      ]
    },
    {
      name: 'Second Signer',
      variables: [
        {
          derivationHardened: false,
          derivationIndex: 0,
          id: 'second',
          type: 'HDKey'
        }
      ]
    }
  ],
  scripts: {
    inline: [
      {
        id: 'checksum',
        script:
          '$(<key1.public> OP_SHA256 <key2.public> OP_SHA256 OP_CAT OP_SHA256 OP_HASH160)'
      },
      {
        id: 'redeem_script',
        script:
          'OP_2 OP_PICK <second.public> OP_CHECKDATASIGVERIFY OP_DUP OP_HASH160 <$(<key.public> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG'
      }
    ],
    lock: {
      id: 'lock',
      script: 'OP_HASH160 <$(<redeem_script> OP_HASH160)> OP_EQUAL'
    },
    unlock: [
      {
        name: 'Spend',
        script:
          '<first.signature.all> <first.public> <second.signature.data.first.signature.all> <redeem_script>'
      }
    ]
  },
  supported: ['BCH_2018Nov', 'BCH_2019May'],
  version: 0
};

export const trustedRecovery: AuthenticationTemplate = {
  ...{
    description:
      'A 2-of-2 wallet, which after a specified delay, can be recovered by either of the original two keys and a signature from a trusted user (e.g. an attorney).\nThis scheme is described in more detail in BIP-65.',
    name: '2-of-2 with Business Continuity'
  },
  entities: [
    {
      name: 'Signer 1',
      unlockOptions: ['Standard Spend', 'Delayed Recovery (Signer 1)'],
      variables: [
        {
          derivationHardened: false,
          derivationIndex: 0,
          id: `first`,
          type: 'HDKey'
        },
        {
          id: 'block_time',
          type: 'CurrentBlockTime'
        },
        {
          description:
            'The waiting period (from the time the wallet is created) after which the Delayed Recovery Wallet can spend funds. The delay is measured in seconds, e.g. 1 day is `86400`.',
          id: 'delay_seconds',
          label: 'Recovery Delay (Seconds)',
          type: 'WalletData'
        }
      ]
    },
    {
      name: 'Signer 2',
      unlockOptions: ['Standard Spend', 'Delayed Recovery (Signer 2)'],
      variables: [
        {
          derivationHardened: false,
          derivationIndex: 0,
          id: `second`,
          type: 'HDKey'
        }
      ]
    },
    {
      name: 'Trusted Party',
      unlockOptions: [
        'Delayed Recovery (Signer 1)',
        'Delayed Recovery (Signer 2)'
      ],
      variables: [
        {
          derivationHardened: false,
          derivationIndex: 0,
          id: `trusted`,
          type: 'HDKey'
        }
      ]
    }
  ],
  scripts: {
    inline: [
      {
        id: 'checksum',
        script:
          '$(<hot.public> OP_SHA256 <delayed.public> OP_SHA256 OP_CAT OP_SHA256 OP_HASH160)'
      },
      {
        id: 'redeem_script',
        script:
          'OP_IF <$(<block_time> <delay_seconds> OP_ADD)> OP_CHECKLOCKTIMEVERIFY OP_DROP <trusted.public> OP_CHECKSIGVERIFY <1> OP_ELSE <2> OP_ENDIF <first.public> <second.public> <2> OP_CHECKMULTISIG'
      }
    ],
    lock: {
      id: 'lock',
      script: 'OP_HASH160 <$(<redeem_script> OP_HASH160)> OP_EQUAL'
    },
    unlock: [
      {
        name: 'Standard Spend',
        script: '<0> <first.signature.all> <second.signature.all> <0>'
      },
      {
        name: 'Delayed Recovery (Signer 1)',
        script: '<0> <first.signature.all> <trusted.signature.all> <1>'
      },
      {
        name: 'Delayed Recovery (Signer 2)',
        script: '<0> <second.signature.all> <trusted.signature.all> <1>'
      }
    ]
  },
  supported: ['BCH_2018Nov', 'BCH_2019May'],
  version: 0
};

// tslint:disable-next-line:no-console
console.log(JSON.stringify(singleSig, undefined, 2));

// TODO: Mini proof of work: <pow_hash> OP_SIZE OP_5 OP_SUB OP_SPLIT <0x01FFFFFFFF> OP_AND OP_IF OP_RETURN OP_ELSE  // from https://www.yours.org/content/use-cases-for-re-enabled-op-codes-8b150b6a0deb – good use case for externally generated variables being using in a script (and being validated with the `validation` script)

// TODO: Zero Confirmation Forfeits example https://gist.github.com/awemany/619a5722d129dec25abf5de211d971bd

(async () => {
  //
})().catch(error => {
  // tslint:disable-next-line:no-console
  console.error(error);
});
