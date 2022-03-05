import { encoder, concat, uint32be, lengthAndInput, concatKdf } from '../../lib/buffer_utils.js'
import crypto, { isCryptoKey } from './webcrypto.js'
import { checkEncCryptoKey } from '../../lib/crypto_key.js'
import invalidKeyInput from '../../lib/invalid_key_input.js'
import { types } from './is_key_like.js'
import exportJWK from './key_to_jwk.js'
import { decode } from './base64url.js'
import digest from './digest.js'

async function getPublicKey(key: CryptoKey) {
  const { kty, x, y } = await exportJWK(key)
  if (kty === 'OKP') {
    return decode(x!)
  }
  return concat(new Uint8Array([0x04]), decode(x!), decode(y!))
}

function ensureExtractableCryptoKey(input: unknown) {
  if (!isCryptoKey(input)) {
    throw new TypeError(invalidKeyInput(input, ...types))
  }
  checkEncCryptoKey(input, 'ECDH')
  if (input.extractable !== true) {
    throw new Error()
  }
  return input
}

/**
 * SHA-256 hash of the concatenation of the sender's static public key and the ephemeral public key
 */
export async function default1PUApu(senderPublicKey: unknown, ephemeralPublicKey: unknown) {
  const [a, b] = await Promise.all([
    getPublicKey(ensureExtractableCryptoKey(senderPublicKey)),
    getPublicKey(ensureExtractableCryptoKey(ephemeralPublicKey)),
  ])

  return digest('sha256', concat(a, b))
}

/**
 * SHA-256 hash of the recipient's static public key
 */
export async function default1PUApv(recipientPublicKey: unknown) {
  return digest('sha256', await getPublicKey(ensureExtractableCryptoKey(recipientPublicKey)))
}

export async function deriveKey(
  publicKey: unknown,
  privateKey: unknown,
  algorithm: string,
  keyLength: number,
  apu: Uint8Array = new Uint8Array(0),
  apv: Uint8Array = new Uint8Array(0),
  opuKey?: unknown,
) {
  if (!isCryptoKey(publicKey)) {
    throw new TypeError(invalidKeyInput(publicKey, ...types))
  }
  checkEncCryptoKey(publicKey, 'ECDH')

  if (!isCryptoKey(privateKey)) {
    throw new TypeError(invalidKeyInput(privateKey, ...types))
  }
  checkEncCryptoKey(privateKey, 'ECDH', 'deriveBits')

  if (opuKey !== undefined) {
    if (!isCryptoKey(opuKey)) {
      throw new TypeError(invalidKeyInput(opuKey, ...types))
    }

    switch (opuKey.type) {
      case 'private':
        checkEncCryptoKey(opuKey, 'ECDH', 'deriveBits')
        break
      case 'public':
        checkEncCryptoKey(opuKey, 'ECDH')
        break
      default:
        throw new Error()
    }
  }

  const value = concat(
    lengthAndInput(encoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLength),
  )

  let Z: Uint8Array

  if (opuKey) {
    const [Ze, Zs] = await Promise.all([
      crypto.subtle
        .deriveBits(
          {
            name: 'ECDH',
            public: publicKey,
          },
          privateKey,
          Math.ceil(
            parseInt((<EcKeyAlgorithm>privateKey.algorithm).namedCurve.slice(-3), 10) / 8,
          ) << 3,
        )
        .then((ab) => new Uint8Array(ab)),
      crypto.subtle
        .deriveBits(
          {
            name: 'ECDH',
            public: opuKey.type === 'private' ? publicKey : opuKey,
          },
          opuKey.type === 'private' ? opuKey : privateKey,
          Math.ceil(parseInt((<EcKeyAlgorithm>opuKey.algorithm).namedCurve.slice(-3), 10) / 8) << 3,
        )
        .then((ab) => new Uint8Array(ab)),
    ])
    Z = concat(Ze, Zs)
  } else {
    Z = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          public: publicKey,
        },
        privateKey,
        Math.ceil(parseInt((<EcKeyAlgorithm>privateKey.algorithm).namedCurve.slice(-3), 10) / 8) <<
          3,
      ),
    )
  }

  return concatKdf(Z, keyLength, value)
}

export async function generateEpk(key: unknown) {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalidKeyInput(key, ...types))
  }

  return crypto.subtle.generateKey(<EcKeyAlgorithm>key.algorithm, true, ['deriveBits'])
}

export function ecdhAllowed(key: unknown) {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalidKeyInput(key, ...types))
  }
  return ['P-256', 'P-384', 'P-521'].includes((<EcKeyAlgorithm>key.algorithm).namedCurve)
}
