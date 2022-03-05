import { createHash, diffieHellman, generateKeyPair as generateKeyPairCb, KeyObject } from 'crypto'
import { promisify } from 'util'

import getNamedCurve from './get_named_curve.js'
import { encoder, concat, uint32be, lengthAndInput, concatKdf } from '../../lib/buffer_utils.js'
import { JOSENotSupported } from '../../util/errors.js'
import { isCryptoKey } from './webcrypto.js'
import { checkEncCryptoKey } from '../../lib/crypto_key.js'
import isKeyObject from './is_key_object.js'
import invalidKeyInput from '../../lib/invalid_key_input.js'
import { types } from './is_key_like.js'
import { decode } from './base64url.js'

function getPublicKey(key: KeyObject) {
  const { kty, x, y } = key.export({ format: 'jwk' })
  if (kty === 'OKP') {
    return decode(x!)
  }
  return concat(new Uint8Array([0x04]), decode(x!), decode(y!))
}

function ensureKeyObject(input: unknown) {
  let key: KeyObject
  if (isCryptoKey(input)) {
    checkEncCryptoKey(input, 'ECDH')
    key = KeyObject.from(input)
  } else if (isKeyObject(input)) {
    key = input
  } else {
    throw new TypeError(invalidKeyInput(input, ...types))
  }
  return key
}

/**
 * SHA-256 hash of the concatenation of the sender's static public key and the ephemeral public key
 */
export function default1PUApu(senderPublicKey: unknown, ephemeralPublicKey: unknown) {
  return createHash('sha256')
    .update(
      concat(
        getPublicKey(ensureKeyObject(senderPublicKey)),
        getPublicKey(ensureKeyObject(ephemeralPublicKey)),
      ),
    )
    .digest()
}

/**
 * SHA-256 hash of the recipient's static public key
 */
export function default1PUApv(recipientPublicKey: unknown) {
  return createHash('sha256')
    .update(getPublicKey(ensureKeyObject(recipientPublicKey)))
    .digest()
}

const generateKeyPair = promisify(generateKeyPairCb)

export async function deriveKey(
  publicKee: unknown,
  privateKee: unknown,
  algorithm: string,
  keyLength: number,
  apu: Uint8Array = new Uint8Array(0),
  apv: Uint8Array = new Uint8Array(0),
  opuKee?: unknown,
) {
  let publicKey: KeyObject
  if (isCryptoKey(publicKee)) {
    checkEncCryptoKey(publicKee, 'ECDH')
    publicKey = KeyObject.from(publicKee)
  } else if (isKeyObject(publicKee)) {
    publicKey = publicKee
  } else {
    throw new TypeError(invalidKeyInput(publicKee, ...types))
  }

  let privateKey: KeyObject
  if (isCryptoKey(privateKee)) {
    checkEncCryptoKey(privateKee, 'ECDH', 'deriveBits')
    privateKey = KeyObject.from(privateKee)
  } else if (isKeyObject(privateKee)) {
    privateKey = privateKee
  } else {
    throw new TypeError(invalidKeyInput(privateKee, ...types))
  }

  let opuKey!: KeyObject
  if (opuKee !== undefined) {
    if (isCryptoKey(opuKee)) {
      switch (opuKee.type) {
        case 'private':
          checkEncCryptoKey(opuKee, 'ECDH', 'deriveBits')
          break
        case 'public':
          checkEncCryptoKey(opuKee, 'ECDH')
          break
        default:
          throw new Error()
      }
      opuKey = KeyObject.from(opuKee)
    } else if (isKeyObject(opuKee)) {
      opuKey = opuKee
    } else {
      throw new TypeError(invalidKeyInput(opuKee, ...types))
    }
  }

  const value = concat(
    lengthAndInput(encoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLength),
  )

  let Z: Buffer
  if (opuKey) {
    Z = Buffer.concat([
      diffieHellman({ privateKey, publicKey }),
      diffieHellman(
        opuKey.type === 'private'
          ? { privateKey: opuKey, publicKey }
          : { privateKey, publicKey: opuKey },
      ),
    ])
  } else {
    Z = diffieHellman({ privateKey, publicKey })
  }

  return concatKdf(Z, keyLength, value)
}

export async function generateEpk(kee: unknown) {
  let key: KeyObject
  if (isCryptoKey(kee)) {
    key = KeyObject.from(kee)
  } else if (isKeyObject(kee)) {
    key = kee
  } else {
    throw new TypeError(invalidKeyInput(kee, ...types))
  }

  switch (key.asymmetricKeyType) {
    case 'x25519':
      return generateKeyPair('x25519')
    case 'x448': {
      return generateKeyPair('x448')
    }
    case 'ec': {
      const namedCurve = getNamedCurve(key)
      return generateKeyPair('ec', { namedCurve })
    }
    default:
      throw new JOSENotSupported('Invalid or unsupported EPK')
  }
}

export const ecdhAllowed = (key: unknown) =>
  ['P-256', 'P-384', 'P-521', 'X25519', 'X448'].includes(getNamedCurve(key))
