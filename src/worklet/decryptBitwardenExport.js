import { cbc } from '@noble/ciphers/aes.js'
import { argon2id } from '@noble/hashes/argon2.js'
import crypto from 'bare-crypto'
import sodium from 'sodium-native'

import { workletLogger } from './utils/workletLogger'

const fromB64 = (s) => Buffer.from(s, 'base64')

const hexHead = (buf, n = 8) => Buffer.from(buf).slice(0, n).toString('hex')

const deriveMasterKey = ({
  kdfType,
  password,
  salt,
  kdfIterations,
  kdfMemory,
  kdfParallelism
}) => {
  // Bitwarden treats the base64 salt string as raw UTF-8 bytes — it does NOT base64-decode it.
  const passwordBuf = Buffer.from(password, 'utf8')
  const saltBuf = Buffer.from(salt, 'utf8')

  workletLogger.info(
    `[bw-worklet] deriveMasterKey kdfType=${kdfType} iters=${kdfIterations} pwLen=${passwordBuf.length} saltLen=${saltBuf.length} saltHead=${saltBuf.slice(0, 8).toString('hex')}`
  )

  if (kdfType === 0) {
    const t = Date.now()
    const key = crypto.pbkdf2Sync(
      passwordBuf,
      saltBuf,
      kdfIterations,
      32,
      'sha256'
    )
    workletLogger.info(
      `[bw-worklet] PBKDF2 done in ${Date.now() - t}ms keyHead=${hexHead(key)} keyLen=${key.length}`
    )
    return key
  }

  if (kdfType === 1) {
    // Bitwarden pre-hashes the salt with SHA-256 (32 bytes) and defaults to
    // parallelism=4. libsodium's crypto_pwhash requires 16-byte salts and
    // pins p=1, so it cannot produce a matching key. Use @noble/hashes/argon2
    // here — pure JS, but the worklet runs on Bare's V8 with JIT.
    const saltHashed = crypto.createHash('sha256').update(saltBuf).digest()
    const t = Date.now()
    const out = Buffer.from(
      argon2id(passwordBuf, saltHashed, {
        t: kdfIterations,
        m: (kdfMemory ?? 64) * 1024,
        p: kdfParallelism ?? 4,
        dkLen: 32
      })
    )
    workletLogger.info(
      `[bw-worklet] Argon2id done in ${Date.now() - t}ms keyHead=${hexHead(out)}`
    )
    return out
  }

  throw new Error(`Unsupported KDF type: ${kdfType}`)
}

const hkdfExpandOneBlock = (prk, info) => {
  // Bitwarden only needs 32-byte outputs → single HMAC block, no loop.
  const h = crypto.createHmac('sha256', prk)
  h.update(info)
  h.update(Buffer.from([0x01]))
  return h.digest()
}

const parseCipherString = (s) => {
  const dot = s.indexOf('.')
  const type = parseInt(s.slice(0, dot), 10)
  if (type !== 2) {
    throw new Error(`Unsupported CipherString type: ${type}`)
  }
  const p1 = s.indexOf('|', dot + 1)
  const p2 = s.indexOf('|', p1 + 1)
  return {
    iv: fromB64(s.slice(dot + 1, p1)),
    ct: fromB64(s.slice(p1 + 1, p2)),
    mac: fromB64(s.slice(p2 + 1))
  }
}

export const decryptBitwardenExport = ({
  password,
  salt,
  kdfType,
  kdfIterations,
  kdfMemory,
  kdfParallelism,
  cipherString
}) => {
  workletLogger.info(
    `[bw-worklet] received kdfType=${kdfType} iters=${kdfIterations} mem=${kdfMemory} para=${kdfParallelism} saltLen=${salt?.length} cipherPrefix=${cipherString?.slice(0, 30)} cipherLen=${cipherString?.length}`
  )

  const masterKey = deriveMasterKey({
    kdfType,
    password,
    salt,
    kdfIterations,
    kdfMemory,
    kdfParallelism
  })

  try {
    const encKey = hkdfExpandOneBlock(masterKey, Buffer.from('enc'))
    const macKey = hkdfExpandOneBlock(masterKey, Buffer.from('mac'))
    workletLogger.info(
      `[bw-worklet] HKDF encKeyHead=${hexHead(encKey)} macKeyHead=${hexHead(macKey)}`
    )

    const { iv, ct, mac } = parseCipherString(cipherString)
    workletLogger.info(
      `[bw-worklet] parsed ivLen=${iv.length} ctLen=${ct.length} macLen=${mac.length} macHead=${hexHead(mac)}`
    )

    const expected = crypto
      .createHmac('sha256', macKey)
      .update(iv)
      .update(ct)
      .digest()
    workletLogger.info(
      `[bw-worklet] expectedMacHead=${hexHead(expected)} expectedLen=${expected.length}`
    )

    if (
      expected.length !== mac.length ||
      !sodium.sodium_memcmp(expected, mac)
    ) {
      workletLogger.info('[bw-worklet] MAC mismatch -> Incorrect password')
      throw new Error('Incorrect password')
    }

    // bare-crypto's Decipheriv wrapper has an output-buffer-sizing bug that
    // crashes the worklet for any ciphertext > one block. Use @noble/ciphers
    // (pure JS) here instead — it runs on Bare's V8 with JIT, so a few KB of
    // AES-CBC is a couple of ms, not a regression vs native.
    workletLogger.info('[bw-worklet] AES-CBC: start decrypt')
    const tAes = Date.now()
    const plain = Buffer.from(cbc(encKey, iv).decrypt(ct))
    workletLogger.info(
      `[bw-worklet] AES-CBC done in ${Date.now() - tAes}ms plainLen=${plain.length}`
    )

    try {
      return plain.toString('utf8')
    } finally {
      plain.fill(0)
    }
  } finally {
    masterKey.fill(0)
  }
}
